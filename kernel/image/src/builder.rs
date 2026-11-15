//! Image writer, for the control plane (and the kernel's self-tests).
//!
//! Add files, symlinks and directories in any order, then [`Builder::finish`]
//! with the root. File content is split into [`CHUNK_SIZE`] chunks. Identical
//! chunks share one data region: a chunk is reused only when both its hash
//! and its bytes match, so a hash collision can never make two different
//! pages alias.
//!
//! The chunk hash is currently a placeholder (FNV-1a spread over 32 bytes,
//! recorded as hash kind 0 in the header flags). The control plane will
//! switch to BLAKE3 (hash kind 1) when it starts verifying OCI layers
//! (milestone 6); readers treat the hash only as a sharing hint.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{CHUNK_LEN, CHUNK_SIZE, HEADER_LEN, Hash, MAGIC, NODE_LEN, VERSION};

/// Header flag value for the placeholder hash.
pub const HASH_KIND_PLACEHOLDER: u32 = 0;

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

/// The placeholder content hash: FNV-1a 64, spread over 32 bytes, mixed
/// with the length.
pub fn content_hash(bytes: &[u8]) -> Hash {
    let mut h = [0u8; 32];
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, &b) in bytes.iter().enumerate() {
        acc = (acc ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
        h[i % 32] ^= (acc >> (i % 8)) as u8;
    }
    let len = (bytes.len() as u64).to_le_bytes();
    for (slot, b) in h.iter_mut().zip(len) {
        *slot ^= b;
    }
    h
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
                let region = (off, page.len() as u64);
                self.data_by_hash.entry(hash).or_default().push(region);
                region
            }
        };
        self.chunk_table.push((off, len, hash));
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
        let data_offset = strings_offset + self.strings.len();

        let mut b = Vec::with_capacity(data_offset + self.data.len());
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&VERSION.to_le_bytes());
        b.extend_from_slice(&HASH_KIND_PLACEHOLDER.to_le_bytes());
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
        for n in &self.nodes {
            for v in [
                u64::from(n.kind) | (u64::from(n.mode) << 32),
                n.size,
                n.first,
                n.count,
                n.name_off,
                n.name_len,
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
        b.extend_from_slice(&self.data);
        b
    }
}
