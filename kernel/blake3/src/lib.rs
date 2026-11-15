//! BLAKE3 (the default hash mode, 32-byte output), portable and
//! allocation-free, written from the specification.
//!
//! Used for the image format's content hashes and root hash: chunks are
//! verified against it when read from a device, and only verified hashes
//! may key cross-image page sharing.
//!
//! [`hash`] hashes a slice; [`Hasher`] hashes incrementally with a fixed
//! chaining-value stack (54 levels: enough for 2^64 bytes).

#![no_std]
#![forbid(unsafe_code)]

/// A BLAKE3 digest.
pub type Hash = [u8; 32];

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];
const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;
const MAX_DEPTH: usize = 54;

#[allow(clippy::many_single_char_names)]
fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(x);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(y);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

fn round(s: &mut [u32; 16], m: &[u32; 16]) {
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
}

fn compress(
    cv: &[u32; 8],
    block: &[u8; BLOCK_LEN],
    counter: u64,
    len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    let mut s = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        len,
        flags,
    ];
    for r in 0..7 {
        round(&mut s, &m);
        if r < 6 {
            m = core::array::from_fn(|i| m[PERMUTATION[i]]);
        }
    }
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

fn first8(w: &[u32; 16]) -> [u32; 8] {
    core::array::from_fn(|i| w[i])
}

/// A compression not yet done: it becomes a chaining value, or the root.
#[derive(Clone, Copy)]
struct Output {
    cv: [u32; 8],
    block: [u8; BLOCK_LEN],
    counter: u64,
    len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first8(&compress(
            &self.cv,
            &self.block,
            self.counter,
            self.len,
            self.flags,
        ))
    }

    fn root(&self) -> Hash {
        let w = compress(&self.cv, &self.block, 0, self.len, self.flags | ROOT);
        let mut out = [0u8; 32];
        for (i, word) in w.iter().take(8).enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

fn parent(left: &[u32; 8], right: &[u32; 8]) -> Output {
    let mut block = [0u8; BLOCK_LEN];
    for i in 0..8 {
        block[4 * i..4 * i + 4].copy_from_slice(&left[i].to_le_bytes());
        block[32 + 4 * i..32 + 4 * i + 4].copy_from_slice(&right[i].to_le_bytes());
    }
    Output {
        cv: IV,
        block,
        counter: 0,
        len: BLOCK_LEN as u32,
        flags: PARENT,
    }
}

#[derive(Clone, Copy)]
struct ChunkState {
    cv: [u32; 8],
    counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    blocks_done: usize,
}

impl ChunkState {
    fn new(counter: u64) -> Self {
        ChunkState {
            cv: IV,
            counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_done: 0,
        }
    }

    fn len(&self) -> usize {
        self.blocks_done * BLOCK_LEN + self.block_len
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_done == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len == BLOCK_LEN {
                let w = compress(
                    &self.cv,
                    &self.block,
                    self.counter,
                    BLOCK_LEN as u32,
                    self.start_flag(),
                );
                self.cv = first8(&w);
                self.blocks_done += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let take = (BLOCK_LEN - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            cv: self.cv,
            block: self.block,
            counter: self.counter,
            len: self.block_len as u32,
            flags: self.start_flag() | CHUNK_END,
        }
    }
}

/// An incremental BLAKE3 hasher.
#[derive(Clone)]
pub struct Hasher {
    chunk: ChunkState,
    stack: [[u32; 8]; MAX_DEPTH],
    depth: usize,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("blake3::Hasher")
    }
}

impl Hasher {
    pub fn new() -> Self {
        Hasher {
            chunk: ChunkState::new(0),
            stack: [[0; 8]; MAX_DEPTH],
            depth: 0,
        }
    }

    fn push_chunk_cv(&mut self, mut cv: [u32; 8], mut total: u64) {
        while total & 1 == 0 && self.depth > 0 {
            self.depth -= 1;
            cv = parent(&self.stack[self.depth], &cv).chaining_value();
            total >>= 1;
        }
        if self.depth < MAX_DEPTH {
            self.stack[self.depth] = cv;
            self.depth += 1;
        }
    }

    /// Adds `input`.
    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        while !input.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                let total = self.chunk.counter + 1;
                self.push_chunk_cv(cv, total);
                self.chunk = ChunkState::new(total);
            }
            let take = (CHUNK_LEN - self.chunk.len()).min(input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
        self
    }

    /// The digest of everything added so far.
    pub fn finalize(&self) -> Hash {
        let mut out = self.chunk.output();
        let mut d = self.depth;
        while d > 0 {
            d -= 1;
            out = parent(&self.stack[d], &out.chaining_value());
        }
        out.root()
    }
}

/// The BLAKE3 digest of `input`.
pub fn hash(input: &[u8]) -> Hash {
    Hasher::new().update(input).finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(h: &Hash) -> [u8; 64] {
        const D: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 64];
        for (i, b) in h.iter().enumerate() {
            out[2 * i] = D[usize::from(b >> 4)];
            out[2 * i + 1] = D[usize::from(b & 15)];
        }
        out
    }

    fn input(n: usize) -> [u8; 32768] {
        core::array::from_fn(|i| if i < n { (i % 251) as u8 } else { 0 })
    }

    /// The official test-vector input (bytes 0..250 repeating), first 32
    /// bytes of output. 0, 1, 1024 and 1025 are from the BLAKE3 test
    /// vectors; the rest were cross-checked with an independent reference
    /// implementation written from the specification.
    const VECTORS: &[(usize, &str)] = &[
        (
            0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        ),
        (
            2048,
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        ),
        (
            2049,
            "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
        ),
        (
            3072,
            "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
        ),
        (
            3073,
            "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
        ),
        (
            4096,
            "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
        ),
        (
            4097,
            "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
        ),
        (
            8193,
            "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b",
        ),
        (
            31744,
            "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
        ),
    ];

    #[test]
    fn test_vectors() {
        for &(n, want) in VECTORS {
            let data = input(n);
            assert_eq!(&hex(&hash(&data[..n])), want.as_bytes(), "len {n}");
        }
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data = input(31744);
        for &(n, _) in VECTORS {
            for step in [1, 7, 64, 65, 1000, 1024, 4096] {
                let mut h = Hasher::new();
                for piece in data[..n].chunks(step) {
                    h.update(piece);
                }
                assert_eq!(h.finalize(), hash(&data[..n]), "len {n} step {step}");
            }
        }
    }
}
