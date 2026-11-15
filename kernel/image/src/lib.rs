//! The Ichor read-only image format (brief: "Storage and images").
//!
//! The control plane converts each OCI layer *once* into this format: a flat
//! table of directory entries plus file content laid out in page-sized,
//! content-addressed chunks. The kernel mounts an image directly and reads it
//! in place. Because every chunk is identified by the hash of its bytes,
//! identical content — a shared base layer across cells, or a duplicated file
//! within one — maps to the same chunk, and the page cache can map that one
//! physical page into many cells (a per-cell policy; ADR-0002 §4).
//!
//! This crate is the on-disk format and a *reader*. The reader works from the
//! image's metadata alone (everything before the chunk data, which the
//! kernel reads eagerly) and fetches file data through a [`ChunkSource`]:
//! the kernel's page cache, which reads chunks from a device on demand, or
//! [`SliceSource`] for an image in memory. Every offset is bounds-checked, so
//! a corrupt image yields an [`Error`], never a panic.
//!
//! # Integrity
//!
//! Hashes are BLAKE3 (hash kind 1, the only kind version 2 accepts). The
//! header carries a root hash: BLAKE3 of the metadata `[0, data_offset)` with
//! the root-hash field zeroed. [`Image::mount`] checks it, so a mounted
//! image's tree and chunk table are exactly what was hashed. Each chunk-table
//! entry carries its chunk's hash, and a [`ChunkSource`] must verify the
//! bytes it returns against it, so the root hash authenticates every byte.
//! Whoever hands the kernel an image vouches for its root hash (the control
//! plane, later from a signed manifest); [`Image::root_hash`] exposes it.
//!
//! # Layout
//!
//! ```text
//! magic "ICHRIMG\0" | version:u32 = 3 | hash kind:u32 = 1 (BLAKE3)
//! node_count:u64 | nodes_offset:u64
//! chunk_count:u64 | chunk_table_offset:u64
//! dirents_offset:u64 | dirents_count:u64
//! strings_offset:u64 | strings_len:u64
//! data_offset:u64 | root hash:[u8; 32]
//! --- nodes[node_count] (64 bytes each: kind, mode, size, first, count,
//!     name offset, name length, uid:u32, gid:u32, mtime:u64) ---
//! --- dirents[dirents_count] (u64 child node index each) ---
//! --- chunk table[chunk_count] (48 bytes each: data offset, length, hash) ---
//! --- string table (name bytes) ---
//! --- padding to CHUNK_SIZE ---
//! --- chunk data: each chunk starts on a CHUNK_SIZE boundary ---
//! ```
//!
//! A directory's `first`/`count` index the dirents table; a file's index the
//! chunk table; a symlink's index the string table. Because chunks are
//! page-aligned, each one is a single aligned device read.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "builder"))]
extern crate alloc;

#[cfg(any(test, feature = "builder"))]
pub mod builder;

/// Content-chunk size: one page. Files are split into chunks so identical
/// pages across files and layers dedupe.
pub const CHUNK_SIZE: u64 = 4096;

/// A BLAKE3 content hash.
pub type Hash = [u8; 32];

const MAGIC: &[u8; 8] = b"ICHRIMG\0";
/// Current format version.
pub const VERSION: u32 = 3;
/// Header hash kind: BLAKE3.
pub const HASH_KIND_BLAKE3: u32 = 1;

const ROOT_HASH_AT: usize = 8 + 4 + 4 + 8 * 9;
/// Bytes of the fixed header (the part needed to find the metadata).
pub const HEADER_LEN: usize = ROOT_HASH_AT + 32;
const NODE_LEN: usize = 64;
const CHUNK_LEN: usize = 48;

/// Why an image was rejected, or a read failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadMagic,
    BadVersion,
    Corrupt,
    /// The metadata or a chunk does not match its hash.
    BadHash,
    /// The device behind a [`ChunkSource`] failed.
    Io,
}

/// Where one chunk of a file lives in the image, and its hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    /// Byte offset of the chunk in the image (a multiple of
    /// [`CHUNK_SIZE`]).
    pub offset: u64,
    /// Bytes of data (at most [`CHUNK_SIZE`]; the rest of the page is zero).
    pub len: u64,
    /// BLAKE3 of those bytes.
    pub hash: Hash,
}

/// Fetches chunk data. Implementations must return only bytes that match
/// `ext.hash` (or fail with [`Error::BadHash`]).
pub trait ChunkSource: core::fmt::Debug {
    /// Copies bytes `[at, at + out.len())` of the chunk `ext` into `out`;
    /// returns how many (fewer at the chunk's end).
    fn read_chunk(&self, ext: &Extent, at: usize, out: &mut [u8]) -> Result<usize, Error>;
}

/// A [`ChunkSource`] over a whole image in memory, verifying every read.
#[derive(Clone, Copy, Debug)]
pub struct SliceSource<'a>(pub &'a [u8]);

impl ChunkSource for SliceSource<'_> {
    fn read_chunk(&self, ext: &Extent, at: usize, out: &mut [u8]) -> Result<usize, Error> {
        let start = usize::try_from(ext.offset).map_err(|_| Error::Corrupt)?;
        let len = usize::try_from(ext.len).map_err(|_| Error::Corrupt)?;
        let end = start.checked_add(len).ok_or(Error::Corrupt)?;
        let bytes = self.0.get(start..end).ok_or(Error::Truncated)?;
        if blake3::hash(bytes) != ext.hash {
            return Err(Error::BadHash);
        }
        let n = out.len().min(len.saturating_sub(at));
        out[..n].copy_from_slice(&bytes[at..at + n]);
        Ok(n)
    }
}

/// The metadata length (`data_offset`) from an image's first
/// [`HEADER_LEN`] bytes: how much to read before [`Image::mount`].
pub fn metadata_len(header: &[u8]) -> Result<usize, Error> {
    if header.len() < HEADER_LEN {
        return Err(Error::Truncated);
    }
    if &header[0..8] != MAGIC {
        return Err(Error::BadMagic);
    }
    if u32_at(header, 8)? != VERSION || u32_at(header, 12)? != HASH_KIND_BLAKE3 {
        return Err(Error::BadVersion);
    }
    let n = usize_at(header, 80)?;
    if n < HEADER_LEN {
        return Err(Error::Corrupt);
    }
    Ok(n)
}

/// BLAKE3 of the metadata with the root-hash field zeroed.
fn metadata_hash(meta: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&meta[..ROOT_HASH_AT]);
    h.update(&[0u8; 32]);
    h.update(&meta[HEADER_LEN..]);
    h.finalize()
}

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    let s = b.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    let lo = u32_at(b, at)? as u64;
    let hi = u32_at(b, at + 4)? as u64;
    Ok(lo | (hi << 32))
}
fn usize_at(b: &[u8], at: usize) -> Result<usize, Error> {
    usize::try_from(u64_at(b, at)?).map_err(|_| Error::Corrupt)
}

/// A node (file, directory, or symlink) in a mounted image.
#[derive(Clone, Copy, Debug)]
pub struct Node<'a> {
    image: Image<'a>,
    index: usize,
    kind: Kind,
    /// Mode bits (permissions).
    pub mode: u32,
    /// Owner and group (cell-local ids; ADR-0009).
    pub uid: u32,
    pub gid: u32,
    /// Modification time, seconds since the epoch.
    pub mtime: u64,
    size: u64,
    /// For a file: first chunk index and count. For a directory: first child
    /// node index and count. For a symlink: string offset/len of the target.
    first: u64,
    count: u64,
}

impl<'a> Node<'a> {
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Size in bytes (file length, or symlink target length).
    pub fn size(&self) -> u64 {
        self.size
    }

    /// A number unique to this node within its image (for `st_ino`).
    pub fn inode(&self) -> u64 {
        self.index as u64 + 1
    }

    /// The node's own name.
    pub fn name(&self) -> &'a str {
        self.image.node_name(self.index).unwrap_or("")
    }

    /// Directory entries, if this is a directory.
    pub fn entries(&self) -> impl Iterator<Item = Node<'a>> + 'a {
        let (image, first, count) = (self.image, self.first as usize, self.count as usize);
        let is_dir = self.kind == Kind::Directory;
        (0..count).filter_map(move |i| {
            if !is_dir {
                return None;
            }
            let child = image.dirent(first + i)?;
            image.node(child).ok()
        })
    }

    /// Looks up a direct child by name.
    pub fn child(&self, name: &str) -> Option<Node<'a>> {
        self.entries().find(|n| n.name() == name)
    }

    /// The symlink target, if this is a symlink.
    pub fn symlink_target(&self) -> Option<&'a str> {
        (self.kind == Kind::Symlink).then(|| {
            self.image
                .string(self.first as usize, self.count as usize)
                .unwrap_or("")
        })
    }

    /// Reads file bytes `[offset, offset+out.len())` through `src`,
    /// returning how many were read (short at end of file). Reads across
    /// chunk boundaries.
    pub fn read_at(
        &self,
        offset: u64,
        out: &mut [u8],
        src: &dyn ChunkSource,
    ) -> Result<usize, Error> {
        if self.kind != Kind::File || offset >= self.size {
            return Ok(0);
        }
        let end = (offset + out.len() as u64).min(self.size);
        let mut pos = offset;
        let mut done = 0;
        while pos < end {
            let Some(ext) = self.extent(pos / CHUNK_SIZE) else {
                return Err(Error::Corrupt);
            };
            let in_chunk = (pos % CHUNK_SIZE) as usize;
            let want = ((end - pos) as usize).min(CHUNK_SIZE as usize - in_chunk);
            let n = src.read_chunk(&ext, in_chunk, &mut out[done..done + want])?;
            if n == 0 {
                break;
            }
            done += n;
            pos += n as u64;
        }
        Ok(done)
    }

    /// Where the file's chunk `i` lives, and its hash.
    pub fn extent(&self, i: u64) -> Option<Extent> {
        (self.kind == Kind::File && i < self.count)
            .then(|| self.image.extent(self.first as usize + i as usize))
            .flatten()
    }

    /// The content hash of the file's chunk `i`.
    pub fn chunk_hash(&self, i: u64) -> Option<Hash> {
        self.extent(i).map(|e| e.hash)
    }
}

/// A mounted read-only image (a borrowed view over its metadata).
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    bytes: &'a [u8],
    root_hash: Hash,
    node_count: usize,
    nodes_offset: usize,
    chunk_count: usize,
    chunk_table_offset: usize,
    dirents_offset: usize,
    dirents_count: usize,
    strings_offset: usize,
    strings_len: usize,
    data_offset: usize,
}

impl<'a> Image<'a> {
    /// Mounts an image from its metadata: at least the first
    /// [`metadata_len`] bytes (a whole image works too). Checks the root
    /// hash; the tables are validated lazily on access, with every read
    /// bounds-checked.
    pub fn mount(image: &'a [u8]) -> Result<Image<'a>, Error> {
        let meta_len = metadata_len(image)?;
        let bytes = image.get(..meta_len).ok_or(Error::Truncated)?;
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&bytes[ROOT_HASH_AT..HEADER_LEN]);
        if metadata_hash(bytes) != root_hash {
            return Err(Error::BadHash);
        }
        let node_count = usize_at(bytes, 16)?;
        let nodes_offset = usize_at(bytes, 24)?;
        let chunk_count = usize_at(bytes, 32)?;
        let chunk_table_offset = usize_at(bytes, 40)?;
        let dirents_offset = usize_at(bytes, 48)?;
        let dirents_count = usize_at(bytes, 56)?;
        let strings_offset = usize_at(bytes, 64)?;
        let strings_len = usize_at(bytes, 72)?;
        let data_offset = usize_at(bytes, 80)?;
        // Validate that the tables fit.
        let ok = nodes_offset
            .checked_add(node_count.checked_mul(NODE_LEN).ok_or(Error::Corrupt)?)
            .is_some_and(|e| e <= bytes.len())
            && chunk_table_offset
                .checked_add(chunk_count.checked_mul(CHUNK_LEN).ok_or(Error::Corrupt)?)
                .is_some_and(|e| e <= bytes.len())
            && dirents_offset
                .checked_add(dirents_count.checked_mul(8).ok_or(Error::Corrupt)?)
                .is_some_and(|e| e <= bytes.len())
            && strings_offset
                .checked_add(strings_len)
                .is_some_and(|e| e <= bytes.len())
            && data_offset == bytes.len();
        if !ok {
            return Err(Error::Corrupt);
        }
        Ok(Image {
            bytes,
            root_hash,
            node_count,
            nodes_offset,
            chunk_count,
            chunk_table_offset,
            dirents_offset,
            dirents_count,
            strings_offset,
            strings_len,
            data_offset,
        })
    }

    /// The image's root hash (BLAKE3 of its metadata).
    pub fn root_hash(&self) -> Hash {
        self.root_hash
    }

    /// The root directory (node 0).
    pub fn root(&self) -> Result<Node<'a>, Error> {
        if self.node_count == 0 {
            return Err(Error::Corrupt);
        }
        self.node(0)
    }

    /// Resolves an absolute path (symlinks are not followed here; the VFS
    /// does that with a bounded loop).
    pub fn lookup(&self, path: &str) -> Option<Node<'a>> {
        let mut node = self.root().ok()?;
        for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
            node = node.child(part)?;
        }
        Some(node)
    }

    fn node(&self, index: usize) -> Result<Node<'a>, Error> {
        if index >= self.node_count {
            return Err(Error::Corrupt);
        }
        let at = self.nodes_offset + index * NODE_LEN;
        let kind = match u32_at(self.bytes, at)? {
            0 => Kind::File,
            1 => Kind::Directory,
            2 => Kind::Symlink,
            _ => return Err(Error::Corrupt),
        };
        Ok(Node {
            // Re-borrow through a fresh Image copy so the Node's lifetime is
            // the image's, not this call's.
            image: *self,
            index,
            kind,
            mode: u32_at(self.bytes, at + 4)?,
            uid: u32_at(self.bytes, at + 48)?,
            gid: u32_at(self.bytes, at + 52)?,
            mtime: u64_at(self.bytes, at + 56)?,
            size: u64_at(self.bytes, at + 8)?,
            first: u64_at(self.bytes, at + 16)?,
            count: u64_at(self.bytes, at + 24)?,
        })
    }

    fn dirent(&self, index: usize) -> Option<usize> {
        if index >= self.dirents_count {
            return None;
        }
        usize::try_from(u64_at(self.bytes, self.dirents_offset + index * 8).ok()?).ok()
    }

    fn node_name(&self, index: usize) -> Option<&'a str> {
        let at = self.nodes_offset + index * NODE_LEN;
        let name_off = usize_at(self.bytes, at + 32).ok()?;
        let name_len = usize_at(self.bytes, at + 40).ok()?;
        self.string(name_off, name_len)
    }

    fn string(&self, offset: usize, len: usize) -> Option<&'a str> {
        let start = self.strings_offset.checked_add(offset)?;
        let end = start.checked_add(len)?;
        if end > self.strings_offset + self.strings_len {
            return None;
        }
        core::str::from_utf8(self.bytes.get(start..end)?).ok()
    }

    fn extent(&self, index: usize) -> Option<Extent> {
        if index >= self.chunk_count {
            return None;
        }
        let at = self.chunk_table_offset + index * CHUNK_LEN;
        let data_rel = u64_at(self.bytes, at).ok()?;
        let len = u64_at(self.bytes, at + 8).ok()?;
        let offset = (self.data_offset as u64).checked_add(data_rel)?;
        if len > CHUNK_SIZE || !offset.is_multiple_of(CHUNK_SIZE) {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(self.bytes.get(at + 16..at + 48)?);
        Some(Extent { offset, len, hash })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    use crate::builder::Builder;

    fn sample() -> Vec<u8> {
        let mut bld = Builder::new();
        let page = std::vec![0xABu8; CHUNK_SIZE as usize];
        let mut sh = page.clone();
        sh.extend_from_slice(b"#!script");
        let sh_i = bld.file("sh", &sh, 0o755);
        let host_i = bld.file("hostname", b"ichor\n", 0o644);
        let bin_i = bld.dir("bin", &[sh_i], 0o755);
        let etc_i = bld.dir("etc", &[host_i], 0o755);
        let link_i = bld.symlink("lib", "/usr/lib");
        let root = bld.dir("/", &[bin_i, etc_i, link_i], 0o755);
        bld.finish(root)
    }

    #[test]
    fn mounts_and_looks_up() {
        let img = sample();
        let image = Image::mount(&img).unwrap();
        let root = image.root().unwrap();
        assert_eq!(root.kind(), Kind::Directory);
        let names: Vec<&str> = root.entries().map(|n| n.name()).collect();
        assert_eq!(names, ["bin", "etc", "lib"]);

        let sh = image.lookup("/bin/sh").unwrap();
        assert_eq!(sh.kind(), Kind::File);
        assert_eq!(sh.mode, 0o755);
        assert_eq!(sh.size(), CHUNK_SIZE + 8);

        let host = image.lookup("/etc/hostname").unwrap();
        let mut buf = [0u8; 16];
        let n = host.read_at(0, &mut buf, &SliceSource(&img)).unwrap();
        assert_eq!(&buf[..n], b"ichor\n");

        let link = image.lookup("/lib").unwrap();
        assert_eq!(link.symlink_target(), Some("/usr/lib"));

        assert!(image.lookup("/bin/nope").is_none());
        assert_eq!(image.lookup("/etc").unwrap().kind(), Kind::Directory);
    }

    #[test]
    fn nodes_carry_owners_and_times() {
        let mut bld = Builder::new();
        let f = bld.file("shadow", b"x", 0o640);
        bld.set_owner(f, 0, 42, 1_700_000_000);
        let root = bld.dir("/", &[f], 0o755);
        let img = bld.finish(root);
        let image = Image::mount(&img).unwrap();
        let n = image.lookup("/shadow").unwrap();
        assert_eq!(
            (n.uid, n.gid, n.mtime, n.mode),
            (0, 42, 1_700_000_000, 0o640)
        );
        assert_eq!(image.root().unwrap().uid, 0);
    }

    #[test]
    fn reads_across_chunk_boundaries() {
        let mut bld = Builder::new();
        let mut content = Vec::new();
        for i in 0..(CHUNK_SIZE as usize * 2 + 100) {
            content.push((i % 251) as u8);
        }
        let f = bld.file("big", &content, 0o644);
        let root = bld.dir("/", &[f], 0o755);
        let img = bld.finish(root);
        let image = Image::mount(&img).unwrap();
        let big = image.lookup("/big").unwrap();
        assert_eq!(big.size(), content.len() as u64);
        let mut buf = std::vec![0u8; content.len()];
        let src = SliceSource(&img);
        let n = big.read_at(0, &mut buf, &src).unwrap();
        assert_eq!(n, content.len());
        assert_eq!(buf, content);
        let mut tail = [0u8; 256];
        let n = big
            .read_at(content.len() as u64 - 50, &mut tail, &src)
            .unwrap();
        assert_eq!(n, 50);
        assert_eq!(&tail[..50], &content[content.len() - 50..]);
    }

    #[test]
    fn identical_pages_share_data() {
        let mut bld = Builder::new();
        let page = std::vec![0x5Au8; CHUNK_SIZE as usize];
        let a = bld.file("a", &page, 0o644);
        let b = bld.file("b", &page, 0o644);
        let root = bld.dir("/", &[a, b], 0o755);
        let img = bld.finish(root);
        let image = Image::mount(&img).unwrap();
        let fa = image.lookup("/a").unwrap();
        let fb = image.lookup("/b").unwrap();
        assert_eq!(fa.chunk_hash(0), fb.chunk_hash(0));
        assert_eq!(fa.extent(0), fb.extent(0));
        assert_eq!(img.len(), image.data_offset + CHUNK_SIZE as usize);
        assert_eq!(fa.chunk_hash(0), Some(blake3::hash(&page)));
    }

    #[test]
    fn root_hash_covers_metadata_and_chunks_are_verified() {
        let img = sample();
        let image = Image::mount(&img).unwrap();
        // Mounting from the metadata alone works the same.
        let meta = metadata_len(&img).unwrap();
        assert_eq!(meta % CHUNK_SIZE as usize, 0);
        let m = Image::mount(&img[..meta]).unwrap();
        assert_eq!(m.root_hash(), image.root_hash());
        // Any change to the metadata is caught.
        let mut bad = img.clone();
        let at = image.nodes_offset + 4; // a node's mode
        bad[at] ^= 1;
        assert_eq!(Image::mount(&bad).unwrap_err(), Error::BadHash);
        // A changed data byte is caught when the chunk is read.
        let mut bad = img.clone();
        let host = image.lookup("/etc/hostname").unwrap();
        let ext = host.extent(0).unwrap();
        bad[ext.offset as usize] ^= 1;
        let image = Image::mount(&bad).unwrap();
        let host = image.lookup("/etc/hostname").unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(
            host.read_at(0, &mut buf, &SliceSource(&bad)),
            Err(Error::BadHash)
        );
    }

    #[test]
    fn rejects_bad_images() {
        assert_eq!(Image::mount(b"").unwrap_err(), Error::Truncated);
        let mut img = sample();
        img[0] = b'X';
        assert_eq!(Image::mount(&img).unwrap_err(), Error::BadMagic);
        let mut img = sample();
        img[8] = 9;
        assert_eq!(Image::mount(&img).unwrap_err(), Error::BadVersion);
        let mut img = sample();
        img[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(Image::mount(&img), Err(Error::BadHash)));
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 3;
        for len in 0..400 {
            let g: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            if let Ok(image) = Image::mount(&g) {
                if let Ok(root) = image.root() {
                    let _ = root.entries().take(1000).count();
                }
                let _ = image.lookup("/a/b/c");
            }
        }
    }
}
