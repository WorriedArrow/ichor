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
//! This crate is the on-disk format and a zero-copy *reader*. It parses a
//! byte slice (which the kernel maps from a volume) and answers path lookups
//! and chunk reads without copying. Every offset is bounds-checked, so a
//! corrupt image yields an [`Error`], never a panic. The writer (used by the
//! control plane) is behind the `alloc` builder; the kernel only needs the
//! reader.
//!
//! # Layout
//!
//! ```text
//! magic "ICHRIMG\0" | version:u32 | flags:u32
//! node_count:u64 | nodes_offset:u64
//! chunk_count:u64 | chunk_table_offset:u64
//! dirents_offset:u64 | dirents_count:u64
//! strings_offset:u64 | strings_len:u64
//! data_offset:u64
//! --- nodes[node_count] (48 bytes each) ---
//! --- dirents[dirents_count] (u64 child node index each) ---
//! --- chunk table[chunk_count] (48 bytes each) ---
//! --- string table (name bytes) ---
//! --- chunk data (page-aligned) ---
//!
//! A directory's `first`/`count` index the dirents table; a file's index the
//! chunk table; a symlink's index the string table.
//! ```

#![no_std]
#![forbid(unsafe_code)]

/// Content-chunk size: one page. Files are split into chunks so identical
/// pages across files and layers dedupe.
pub const CHUNK_SIZE: u64 = 4096;

/// A 256-bit content hash (BLAKE3-style; the exact function is chosen by the
/// writer and recorded in the header flags).
pub type Hash = [u8; 32];

const MAGIC: &[u8; 8] = b"ICHRIMG\0";
/// Current format version.
pub const VERSION: u32 = 1;

const HEADER_LEN: usize = 8 + 4 + 4 + 8 * 9;
const NODE_LEN: usize = 48;
const CHUNK_LEN: usize = 48;

/// Why an image was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadMagic,
    BadVersion,
    Corrupt,
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

    /// Reads file bytes `[offset, offset+out.len())`, returning how many were
    /// read (short at end of file). Reads across chunk boundaries.
    pub fn read_at(&self, offset: u64, out: &mut [u8]) -> usize {
        if self.kind != Kind::File || offset >= self.size {
            return 0;
        }
        let end = (offset + out.len() as u64).min(self.size);
        let mut pos = offset;
        let mut done = 0;
        while pos < end {
            let chunk_idx = self.first as usize + (pos / CHUNK_SIZE) as usize;
            let in_chunk = pos % CHUNK_SIZE;
            let Some(bytes) = self.image.chunk_bytes(chunk_idx) else {
                break;
            };
            let avail = bytes.len() as u64;
            if in_chunk >= avail {
                break;
            }
            let n = ((avail - in_chunk).min(end - pos)) as usize;
            out[done..done + n].copy_from_slice(&bytes[in_chunk as usize..in_chunk as usize + n]);
            done += n;
            pos += n as u64;
        }
        done
    }

    /// The content hash of the file's chunk `i`, for dedup / page-cache
    /// sharing decisions.
    pub fn chunk_hash(&self, i: u64) -> Option<Hash> {
        (self.kind == Kind::File && i < self.count)
            .then(|| self.image.chunk_hash(self.first as usize + i as usize))
            .flatten()
    }
}

/// A mounted read-only image (a borrowed view over its bytes).
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    bytes: &'a [u8],
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
    /// Parses and validates an image header. The body is validated lazily on
    /// access, with every read bounds-checked.
    pub fn mount(bytes: &'a [u8]) -> Result<Image<'a>, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if &bytes[0..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        if u32_at(bytes, 8)? != VERSION {
            return Err(Error::BadVersion);
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
            && data_offset <= bytes.len();
        if !ok {
            return Err(Error::Corrupt);
        }
        Ok(Image {
            bytes,
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

    fn chunk_entry(&self, index: usize) -> Option<(u64, u64, Hash)> {
        if index >= self.chunk_count {
            return None;
        }
        let at = self.chunk_table_offset + index * CHUNK_LEN;
        let data_rel = u64_at(self.bytes, at).ok()?;
        let len = u64_at(self.bytes, at + 8).ok()?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(self.bytes.get(at + 16..at + 48)?);
        Some((data_rel, len, hash))
    }

    fn chunk_bytes(&self, index: usize) -> Option<&'a [u8]> {
        let (data_rel, len, _) = self.chunk_entry(index)?;
        let start = self
            .data_offset
            .checked_add(usize::try_from(data_rel).ok()?)?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.bytes.get(start..end)
    }

    fn chunk_hash(&self, index: usize) -> Option<Hash> {
        self.chunk_entry(index).map(|(_, _, h)| h)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    /// A test builder mirroring the control-plane writer. Each file records a
    /// contiguous run of chunk-table entries; entries with identical content
    /// share the same data bytes (dedup), and carry the content hash so the
    /// page cache can share physical pages.
    #[derive(Default)]
    struct Builder {
        nodes: Vec<NodeRec>,
        strings: Vec<u8>,
        chunk_table: Vec<(u64, u64, Hash)>, // (data_rel, len, hash)
        dirents: Vec<u64>,
        data: Vec<u8>,
        data_by_hash: BTreeMap<Hash, u64>,
    }

    struct NodeRec {
        kind: u32,
        mode: u32,
        size: u64,
        first: u64,
        count: u64,
        name_off: u64,
        name_len: u64,
    }

    fn fake_hash(bytes: &[u8]) -> Hash {
        let mut h = [0u8; 32];
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        for (i, &b) in bytes.iter().enumerate() {
            acc = (acc ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
            h[i % 32] ^= (acc >> (i % 8)) as u8;
        }
        h[0] ^= bytes.len() as u8;
        h
    }

    impl Builder {
        fn string(&mut self, s: &str) -> (u64, u64) {
            let off = self.strings.len() as u64;
            self.strings.extend_from_slice(s.as_bytes());
            (off, s.len() as u64)
        }

        fn push_chunk(&mut self, page: &[u8]) {
            let hash = fake_hash(page);
            let data = &mut self.data;
            let data_rel = *self.data_by_hash.entry(hash).or_insert_with(|| {
                let at = data.len() as u64;
                data.extend_from_slice(page);
                at
            });
            self.chunk_table.push((data_rel, page.len() as u64, hash));
        }

        fn file(&mut self, name: &str, content: &[u8], mode: u32) -> usize {
            let (name_off, name_len) = self.string(name);
            let first = self.chunk_table.len() as u64;
            let mut count = 0;
            for page in content.chunks(CHUNK_SIZE as usize) {
                self.push_chunk(page);
                count += 1;
            }
            self.nodes.push(NodeRec {
                kind: 0,
                mode,
                size: content.len() as u64,
                first,
                count,
                name_off,
                name_len,
            });
            self.nodes.len() - 1
        }

        fn symlink(&mut self, name: &str, target: &str) -> usize {
            let (name_off, name_len) = self.string(name);
            let (t_off, t_len) = self.string(target);
            self.nodes.push(NodeRec {
                kind: 2,
                mode: 0o777,
                size: t_len,
                first: t_off,
                count: t_len,
                name_off,
                name_len,
            });
            self.nodes.len() - 1
        }

        fn dir(&mut self, name: &str, children: &[usize], mode: u32) -> usize {
            let (name_off, name_len) = self.string(name);
            let first = self.dirents.len() as u64;
            for &c in children {
                self.dirents.push(c as u64);
            }
            self.nodes.push(NodeRec {
                kind: 1,
                mode,
                size: children.len() as u64,
                first,
                count: children.len() as u64,
                name_off,
                name_len,
            });
            self.nodes.len() - 1
        }

        fn finish(mut self, root: usize) -> Vec<u8> {
            // Ensure node 0 is the root: swap, and remap dirents that point
            // at node 0 or `root`.
            self.nodes.swap(0, root);
            for d in &mut self.dirents {
                if *d == 0 {
                    *d = root as u64;
                } else if *d == root as u64 {
                    *d = 0;
                }
            }
            let node_count = self.nodes.len();
            let chunk_count = self.chunk_table.len();
            let dirents_count = self.dirents.len();
            let nodes_offset = HEADER_LEN;
            let dirents_offset = nodes_offset + node_count * NODE_LEN;
            let chunk_table_offset = dirents_offset + dirents_count * 8;
            let strings_offset = chunk_table_offset + chunk_count * CHUNK_LEN;
            let data_offset = strings_offset + self.strings.len();

            let mut b = Vec::new();
            b.extend_from_slice(MAGIC);
            b.extend_from_slice(&VERSION.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            for v in [
                node_count as u64,
                nodes_offset as u64,
                chunk_count as u64,
                chunk_table_offset as u64,
                dirents_offset as u64,
                dirents_count as u64,
                strings_offset as u64,
                self.strings.len() as u64,
                data_offset as u64,
            ] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            assert_eq!(b.len(), HEADER_LEN);
            for n in &self.nodes {
                b.extend_from_slice(&n.kind.to_le_bytes());
                b.extend_from_slice(&n.mode.to_le_bytes());
                b.extend_from_slice(&n.size.to_le_bytes());
                b.extend_from_slice(&n.first.to_le_bytes());
                b.extend_from_slice(&n.count.to_le_bytes());
                b.extend_from_slice(&n.name_off.to_le_bytes());
                b.extend_from_slice(&n.name_len.to_le_bytes());
            }
            for d in &self.dirents {
                b.extend_from_slice(&d.to_le_bytes());
            }
            for (rel, len, hash) in &self.chunk_table {
                b.extend_from_slice(&rel.to_le_bytes());
                b.extend_from_slice(&len.to_le_bytes());
                b.extend_from_slice(hash);
            }
            b.extend_from_slice(&self.strings);
            b.extend_from_slice(&self.data);
            b
        }
    }

    fn sample() -> Vec<u8> {
        let mut bld = Builder::default();
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
        let n = host.read_at(0, &mut buf);
        assert_eq!(&buf[..n], b"ichor\n");

        let link = image.lookup("/lib").unwrap();
        assert_eq!(link.symlink_target(), Some("/usr/lib"));

        assert!(image.lookup("/bin/nope").is_none());
        assert_eq!(image.lookup("/etc").unwrap().kind(), Kind::Directory);
    }

    #[test]
    fn reads_across_chunk_boundaries() {
        let mut bld = Builder::default();
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
        let n = big.read_at(0, &mut buf);
        assert_eq!(n, content.len());
        assert_eq!(buf, content);
        let mut tail = [0u8; 256];
        let n = big.read_at(content.len() as u64 - 50, &mut tail);
        assert_eq!(n, 50);
        assert_eq!(&tail[..50], &content[content.len() - 50..]);
    }

    #[test]
    fn identical_pages_share_data() {
        let mut bld = Builder::default();
        let page = std::vec![0x5Au8; CHUNK_SIZE as usize];
        let a = bld.file("a", &page, 0o644);
        let b = bld.file("b", &page, 0o644);
        let root = bld.dir("/", &[a, b], 0o755);
        let img = bld.finish(root);
        let image = Image::mount(&img).unwrap();
        let fa = image.lookup("/a").unwrap();
        let fb = image.lookup("/b").unwrap();
        assert_eq!(fa.chunk_hash(0), fb.chunk_hash(0));
        assert!(image.data_offset + CHUNK_SIZE as usize <= img.len());
        assert!(img.len() < image.data_offset + 2 * CHUNK_SIZE as usize);
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
        assert!(matches!(Image::mount(&img), Err(Error::Corrupt)));
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
