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
//! magic "ICHRIMG\0" | version:u32 = 4 | hash kind:u32 = 1 (BLAKE3)
//! node_count:u64 | nodes_offset:u64
//! chunk_count:u64 | chunk_table_offset:u64
//! dirents_offset:u64 | dirents_count:u64
//! strings_offset:u64 | strings_len:u64
//! data_offset:u64 | root hash:[u8; 32]
//! --- string table (name bytes; no string crosses a SEGMENT boundary) ---
//! --- padding to 8 ---
//! --- nodes[node_count] (64 bytes each: kind, mode, size, first, count,
//!     name offset, name length, uid:u32, gid:u32, mtime:u64) ---
//! --- dirents[dirents_count] (u64 child node index each) ---
//! --- chunk table[chunk_count] (48 bytes each: data offset, length, hash) ---
//! --- padding to CHUNK_SIZE ---
//! --- chunk data: each chunk starts on a CHUNK_SIZE boundary ---
//! ```
//!
//! A directory's `first`/`count` index the dirents table; a file's index the
//! chunk table (files may share a range: hard links do); a symlink's index
//! the string table. Because chunks are
//! page-aligned, each one is a single aligned device read.
//!
//! The metadata of a large image (hundreds of thousands of files or chunks)
//! is megabytes, more than the kernel should need in one piece, so it can be
//! mounted from pieces of [`SEGMENT`] bytes ([`Image::mount_segments`]).
//! Table entries may lie across two pieces; names may not, so they can be
//! borrowed.

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
pub const VERSION: u32 = 4;
/// The pieces metadata can be mounted from.
pub const SEGMENT: usize = 64 * 1024;
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
    let h = Meta::Whole(header);
    if h.u32_at(8)? != VERSION || h.u32_at(12)? != HASH_KIND_BLAKE3 {
        return Err(Error::BadVersion);
    }
    let n = h.usize_at(80)?;
    if n < HEADER_LEN {
        return Err(Error::Corrupt);
    }
    Ok(n)
}

/// BLAKE3 of the metadata (its first piece, then the rest) with the
/// root-hash field zeroed.
fn metadata_hash<'a>(first: &[u8], rest: impl Iterator<Item = &'a [u8]>) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&first[..ROOT_HASH_AT]);
    h.update(&[0u8; 32]);
    h.update(&first[HEADER_LEN..]);
    for s in rest {
        h.update(s);
    }
    h.finalize()
}

/// An image's metadata: in one piece, or in [`SEGMENT`]-byte pieces (the
/// last one shorter) of a total length.
#[derive(Clone, Copy, Debug)]
enum Meta<'a> {
    Whole(&'a [u8]),
    Segments(&'a [&'a [u8]], usize),
}

impl<'a> Meta<'a> {
    fn len(&self) -> usize {
        match *self {
            Meta::Whole(b) => b.len(),
            Meta::Segments(_, len) => len,
        }
    }

    /// The piece holding byte `at`, and where in it.
    fn piece(&self, at: usize) -> Option<(&'a [u8], usize)> {
        match *self {
            Meta::Whole(b) => Some((b, at)),
            Meta::Segments(s, _) => Some((s.get(at / SEGMENT)?, at % SEGMENT)),
        }
    }

    /// The `N` bytes at `at`, wherever they lie.
    fn bytes<const N: usize>(&self, at: usize) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        let mut done = 0;
        while done < N {
            let (p, i) = at
                .checked_add(done)
                .and_then(|a| self.piece(a))
                .ok_or(Error::Truncated)?;
            let have = p
                .get(i..)
                .filter(|r| !r.is_empty())
                .ok_or(Error::Truncated)?;
            let n = have.len().min(N - done);
            out[done..done + n].copy_from_slice(&have[..n]);
            done += n;
        }
        Ok(out)
    }

    /// `len` bytes at `at`, if they do not cross a [`SEGMENT`] boundary
    /// (whichever way the metadata is held, so an image reads the same).
    fn borrow(&self, at: usize, len: usize) -> Option<&'a [u8]> {
        let end = at.checked_add(len)?;
        if len > 0 && at / SEGMENT != (end - 1) / SEGMENT {
            return None;
        }
        let (p, i) = self.piece(at)?;
        p.get(i..i + len)
    }

    fn u32_at(&self, at: usize) -> Result<u32, Error> {
        self.bytes(at).map(u32::from_le_bytes)
    }

    fn u64_at(&self, at: usize) -> Result<u64, Error> {
        self.bytes(at).map(u64::from_le_bytes)
    }

    fn usize_at(&self, at: usize) -> Result<usize, Error> {
        usize::try_from(self.u64_at(at)?).map_err(|_| Error::Corrupt)
    }
}

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
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
    meta: Meta<'a>,
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
        Image::checked(
            Meta::Whole(bytes),
            metadata_hash(bytes, core::iter::empty()),
        )
    }

    /// Mounts an image from its metadata in pieces: [`SEGMENT`] bytes each,
    /// the last one what is left, [`metadata_len`] bytes in all.
    pub fn mount_segments(segments: &'a [&'a [u8]]) -> Result<Image<'a>, Error> {
        let first = segments.first().ok_or(Error::Truncated)?;
        let len = metadata_len(first)?;
        let sizes = segments.iter().enumerate();
        for (i, s) in sizes {
            let want = len.saturating_sub(i * SEGMENT).min(SEGMENT);
            if s.len() != want || want == 0 {
                return Err(Error::Truncated);
            }
        }
        if segments.len() != len.div_ceil(SEGMENT) {
            return Err(Error::Truncated);
        }
        Image::checked(
            Meta::Segments(segments, len),
            metadata_hash(first, segments[1..].iter().copied()),
        )
    }

    /// An image whose metadata hashes to `hash`, if that is its root hash
    /// and its tables fit.
    fn checked(meta: Meta<'a>, hash: Hash) -> Result<Image<'a>, Error> {
        let root_hash: Hash = meta.bytes(ROOT_HASH_AT)?;
        if hash != root_hash {
            return Err(Error::BadHash);
        }
        let node_count = meta.usize_at(16)?;
        let nodes_offset = meta.usize_at(24)?;
        let chunk_count = meta.usize_at(32)?;
        let chunk_table_offset = meta.usize_at(40)?;
        let dirents_offset = meta.usize_at(48)?;
        let dirents_count = meta.usize_at(56)?;
        let strings_offset = meta.usize_at(64)?;
        let strings_len = meta.usize_at(72)?;
        let data_offset = meta.usize_at(80)?;
        let fits = |offset: usize, count: usize, each: usize| {
            count
                .checked_mul(each)
                .and_then(|n| offset.checked_add(n))
                .is_some_and(|e| e <= meta.len())
        };
        let ok = fits(nodes_offset, node_count, NODE_LEN)
            && fits(chunk_table_offset, chunk_count, CHUNK_LEN)
            && fits(dirents_offset, dirents_count, 8)
            && fits(strings_offset, strings_len, 1)
            && data_offset == meta.len();
        if !ok {
            return Err(Error::Corrupt);
        }
        Ok(Image {
            meta,
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

    /// Bytes of metadata (what the root hash covers).
    pub fn metadata_len(&self) -> usize {
        self.meta.len()
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
        // Read whole: a node is looked at field by field all the time, and
        // may lie across two pieces of the metadata.
        let raw: [u8; NODE_LEN] = self.meta.bytes(at)?;
        let raw = Meta::Whole(&raw);
        let kind = match raw.u32_at(0)? {
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
            mode: raw.u32_at(4)?,
            uid: raw.u32_at(48)?,
            gid: raw.u32_at(52)?,
            mtime: raw.u64_at(56)?,
            size: raw.u64_at(8)?,
            first: raw.u64_at(16)?,
            count: raw.u64_at(24)?,
        })
    }

    fn dirent(&self, index: usize) -> Option<usize> {
        if index >= self.dirents_count {
            return None;
        }
        self.meta.usize_at(self.dirents_offset + index * 8).ok()
    }

    fn node_name(&self, index: usize) -> Option<&'a str> {
        let at = self.nodes_offset + index * NODE_LEN;
        let name_off = self.meta.usize_at(at + 32).ok()?;
        let name_len = self.meta.usize_at(at + 40).ok()?;
        self.string(name_off, name_len)
    }

    fn string(&self, offset: usize, len: usize) -> Option<&'a str> {
        let start = self.strings_offset.checked_add(offset)?;
        let end = start.checked_add(len)?;
        if end > self.strings_offset + self.strings_len {
            return None;
        }
        core::str::from_utf8(self.meta.borrow(start, len)?).ok()
    }

    fn extent(&self, index: usize) -> Option<Extent> {
        if index >= self.chunk_count {
            return None;
        }
        let at = self.chunk_table_offset + index * CHUNK_LEN;
        let data_rel = self.meta.u64_at(at).ok()?;
        let len = self.meta.u64_at(at + 8).ok()?;
        let offset = (self.data_offset as u64).checked_add(data_rel)?;
        if len > CHUNK_SIZE || !offset.is_multiple_of(CHUNK_SIZE) {
            return None;
        }
        let hash = self.meta.bytes(at + 16).ok()?;
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

    /// An image whose metadata spans several segments (6,000 files).
    fn large() -> Vec<u8> {
        let mut bld = Builder::new();
        let mut kids = Vec::new();
        for i in 0..6000u32 {
            let name = std::format!("file-{i:05}-{}", "n".repeat((i % 97) as usize));
            kids.push(bld.file(&name, &i.to_le_bytes(), 0o644));
        }
        kids.push(bld.symlink("link", &"t/".repeat(2000)));
        let root = bld.dir("/", &kids, 0o755);
        bld.finish(root)
    }

    #[test]
    fn large_metadata_mounts_in_segments_and_whole_alike() {
        let img = large();
        let len = metadata_len(&img).unwrap();
        assert!(len > 10 * SEGMENT, "{len}");
        let segments: Vec<&[u8]> = img[..len].chunks(SEGMENT).collect();
        let whole = Image::mount(&img).unwrap();
        let parts = Image::mount_segments(&segments).unwrap();
        assert_eq!(whole.root_hash(), parts.root_hash());
        let (a, b) = (whole.root().unwrap(), parts.root().unwrap());
        assert_eq!(a.entries().count(), 6001);
        for (x, y) in a.entries().zip(b.entries()) {
            assert_eq!((x.name(), x.mode, x.size()), (y.name(), y.mode, y.size()));
            assert!(!x.name().is_empty());
            assert_eq!(x.extent(0), y.extent(0));
            assert_eq!(x.symlink_target(), y.symlink_target());
        }
        let f = parts.lookup(&std::format!("/file-04242-{}", "n".repeat(4242 % 97)));
        let mut got = [0u8; 4];
        f.unwrap().read_at(0, &mut got, &SliceSource(&img)).unwrap();
        assert_eq!(u32::from_le_bytes(got), 4242);
        assert_eq!(
            parts
                .lookup("/link")
                .unwrap()
                .symlink_target()
                .map(str::len),
            Some(4000)
        );
        // Every piece counts, whole.
        assert!(Image::mount_segments(&segments[..segments.len() - 1]).is_err());
        assert!(Image::mount_segments(&[]).is_err());
        let mut short = segments.clone();
        short[2] = &short[2][..SEGMENT - 1];
        assert!(Image::mount_segments(&short).is_err());
        let mut bad = img.clone();
        bad[len - 1 - CHUNK_SIZE as usize] ^= 1;
        let segments: Vec<&[u8]> = bad[..len].chunks(SEGMENT).collect();
        assert_eq!(
            Image::mount_segments(&segments).unwrap_err(),
            Error::BadHash
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
