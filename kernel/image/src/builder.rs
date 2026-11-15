//! Image writer, for the control plane (and the kernel's self-tests).
//!
//! Add files, symlinks and directories in any order, then [`Builder::finish`]
//! with the root. File content is split into [`CHUNK_SIZE`] chunks. Identical
//! chunks share one data region: a chunk is reused only when both its hash
//! and its bytes match, so a hash collision can never make two different
//! pages alias.
//!
//! Chunk hashes are BLAKE3, and `finish` writes the root hash over the
//! metadata (see the crate docs). Every chunk's data starts on a
//! `CHUNK_SIZE` boundary.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{
    CHUNK_LEN, CHUNK_SIZE, HASH_KIND_BLAKE3, HEADER_LEN, Hash, MAGIC, NODE_LEN, ROOT_HASH_AT,
    VERSION,
};

/// Identifies a node added to a [`Builder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeId(usize);

#[derive(Debug)]
struct NodeRec {
    kind: u32,
    mode: u32,
    size: u64,
    first: u64,
    count: u64,
    name_off: u64,
    name_len: u64,
    uid: u32,
    gid: u32,
    mtime: u64,
}

/// Builds an image in memory.
#[derive(Debug, Default)]
pub struct Builder {
    nodes: Vec<NodeRec>,
    dirents: Vec<u64>,
    strings: Vec<u8>,
    /// `(data offset, length, hash)` per chunk-table entry.
    chunk_table: Vec<(u64, u64, Hash)>,
    data: Vec<u8>,
    /// Data regions by hash, for dedup.
    data_by_hash: BTreeMap<Hash, Vec<(u64, u64)>>,
}

/// A chunk's content hash (BLAKE3).
pub fn content_hash(bytes: &[u8]) -> Hash {
    blake3::hash(bytes)
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    fn string(&mut self, s: &str) -> (u64, u64) {
        let off = self.strings.len() as u64;
        self.strings.extend_from_slice(s.as_bytes());
        (off, s.len() as u64)
    }

    fn push_chunk(&mut self, page: &[u8]) {
        let hash = content_hash(page);
        let existing = self.data_by_hash.get(&hash).and_then(|regions| {
            regions.iter().copied().find(|&(off, len)| {
                len as usize == page.len()
                    && self.data.get(off as usize..(off + len) as usize) == Some(page)
            })
        });
        let (off, len) = match existing {
            Some(region) => region,
            None => {
                let off = self.data.len() as u64;
                self.data.extend_from_slice(page);
                // The next chunk starts on a page boundary.
                let padded = self.data.len().next_multiple_of(CHUNK_SIZE as usize);
                self.data.resize(padded, 0);
                let region = (off, page.len() as u64);
                self.data_by_hash.entry(hash).or_default().push(region);
                region
            }
        };
        self.chunk_table.push((off, len, hash));
    }

    /// Sets a node's owner, group and modification time (default: root,
    /// root, the epoch).
    pub fn set_owner(&mut self, node: NodeId, uid: u32, gid: u32, mtime: u64) {
        if let Some(n) = self.nodes.get_mut(node.0) {
            n.uid = uid;
            n.gid = gid;
            n.mtime = mtime;
        }
    }

    fn push_node(&mut self, rec: NodeRec) -> NodeId {
        self.nodes.push(rec);
        NodeId(self.nodes.len() - 1)
    }

    /// Adds a regular file.
    pub fn file(&mut self, name: &str, content: &[u8], mode: u32) -> NodeId {
        let (name_off, name_len) = self.string(name);
        let first = self.chunk_table.len() as u64;
        let mut count = 0;
        for page in content.chunks(CHUNK_SIZE as usize) {
            self.push_chunk(page);
            count += 1;
        }
        self.push_node(NodeRec {
            kind: 0,
            mode,
            size: content.len() as u64,
            first,
            count,
            name_off,
            name_len,
            uid: 0,
            gid: 0,
            mtime: 0,
        })
    }

    /// Adds a symbolic link.
    pub fn symlink(&mut self, name: &str, target: &str) -> NodeId {
        let (name_off, name_len) = self.string(name);
        let (t_off, t_len) = self.string(target);
        self.push_node(NodeRec {
            kind: 2,
            mode: 0o777,
            size: t_len,
            first: t_off,
            count: t_len,
            name_off,
            name_len,
            uid: 0,
            gid: 0,
            mtime: 0,
        })
    }

    /// Adds a directory containing `children`.
    pub fn dir(&mut self, name: &str, children: &[NodeId], mode: u32) -> NodeId {
        let (name_off, name_len) = self.string(name);
        let first = self.dirents.len() as u64;
        self.dirents.extend(children.iter().map(|c| c.0 as u64));
        self.push_node(NodeRec {
            kind: 1,
            mode,
            size: children.len() as u64,
            first,
            count: children.len() as u64,
            name_off,
            name_len,
            uid: 0,
            gid: 0,
            mtime: 0,
        })
    }

    /// Serializes the image with `root` as its root directory.
    pub fn finish(mut self, root: NodeId) -> Vec<u8> {
        // Node 0 must be the root: swap it into place and remap dirents.
        let root = root.0;
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
        let data_offset =
            (strings_offset + self.strings.len()).next_multiple_of(CHUNK_SIZE as usize);

        let mut b = Vec::with_capacity(data_offset + self.data.len());
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&VERSION.to_le_bytes());
        b.extend_from_slice(&HASH_KIND_BLAKE3.to_le_bytes());
        for v in [
            node_count,
            nodes_offset,
            chunk_count,
            chunk_table_offset,
            dirents_offset,
            dirents_count,
            strings_offset,
            self.strings.len(),
            data_offset,
        ] {
            b.extend_from_slice(&(v as u64).to_le_bytes());
        }
        b.extend_from_slice(&[0u8; 32]); // root hash, filled in below
        for n in &self.nodes {
            for v in [
                u64::from(n.kind) | (u64::from(n.mode) << 32),
                n.size,
                n.first,
                n.count,
                n.name_off,
                n.name_len,
                u64::from(n.uid) | (u64::from(n.gid) << 32),
                n.mtime,
            ] {
                b.extend_from_slice(&v.to_le_bytes());
            }
        }
        for d in &self.dirents {
            b.extend_from_slice(&d.to_le_bytes());
        }
        for (off, len, hash) in &self.chunk_table {
            b.extend_from_slice(&off.to_le_bytes());
            b.extend_from_slice(&len.to_le_bytes());
            b.extend_from_slice(hash);
        }
        b.extend_from_slice(&self.strings);
        b.resize(data_offset, 0);
        let root = crate::metadata_hash(&b);
        b[ROOT_HASH_AT..HEADER_LEN].copy_from_slice(&root);
        b.extend_from_slice(&self.data);
        b
    }
}
