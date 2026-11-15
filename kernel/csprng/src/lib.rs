//! The kernel's random generator: ChaCha20 (RFC 8439) as a keyed
//! generator with fast key erasure.
//!
//! The whole state is one 256-bit key. Entropy is absorbed 12 bytes at a
//! time: the new key is the first half of the ChaCha20 block under the old
//! key, with block counter `0xffff_ffff` and the input as the nonce. That is
//! a PRF of the input under the old key, so the key stays secret if either
//! the old key or the input was, and unknown input makes a known key
//! unknown again.
//!
//! Output for one request is ChaCha20 under the current key with an
//! all-zero nonce and block counters 1, 2, ...; block 0 becomes the next
//! key, so the key that produced a request's output is gone once the
//! request returns (backtracking resistance). Absorbing never uses a
//! counter output can reach, because one request is capped well below
//! 2^32 blocks.
//!
//! The generator does not decide what counts as entropy: callers credit
//! bits with [`Csprng::absorb`], and [`Csprng::seeded`] says whether 256
//! have been credited.

#![no_std]
#![forbid(unsafe_code)]

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
/// Counter value reserved for absorbing input.
const ABSORB_COUNTER: u32 = u32::MAX;
/// Bytes of output one request may produce (keeps counters below
/// [`ABSORB_COUNTER`]).
pub const MAX_REQUEST: usize = 1 << 30;
/// Credited bits after which the generator counts as seeded.
pub const SEEDED_BITS: u32 = 256;

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// The ChaCha20 block function: 16 output words.
pub fn block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&CONSTANTS);
    init[4..12].copy_from_slice(key);
    init[12] = counter;
    init[13..].copy_from_slice(nonce);
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    for (w, i) in s.iter_mut().zip(init) {
        *w = w.wrapping_add(i);
    }
    s
}

fn word(b: &[u8], i: usize) -> u32 {
    let mut w = [0u8; 4];
    for (k, x) in w.iter_mut().enumerate() {
        *x = b.get(i * 4 + k).copied().unwrap_or(0);
    }
    u32::from_le_bytes(w)
}

/// The generator.
#[derive(Debug, Clone)]
pub struct Csprng {
    key: [u32; 8],
    credited: u32,
}

impl Default for Csprng {
    fn default() -> Self {
        Self::new()
    }
}

impl Csprng {
    /// A generator with an all-zero key and nothing credited.
    pub const fn new() -> Csprng {
        Csprng {
            key: [0; 8],
            credited: 0,
        }
    }

    /// Mixes `input` into the key and credits `bits` of entropy to it.
    pub fn absorb(&mut self, input: &[u8], bits: u32) {
        for chunk in input.chunks(12) {
            let nonce = [word(chunk, 0), word(chunk, 1), word(chunk, 2)];
            let b = block(&self.key, ABSORB_COUNTER, &nonce);
            self.key.copy_from_slice(&b[..8]);
        }
        self.credited = self.credited.saturating_add(bits);
    }

    /// Whether at least [`SEEDED_BITS`] have been credited.
    pub fn seeded(&self) -> bool {
        self.credited >= SEEDED_BITS
    }

    /// Fills `out` (at most [`MAX_REQUEST`] bytes; the rest is left as is)
    /// and replaces the key.
    pub fn fill(&mut self, out: &mut [u8]) {
        let len = out.len().min(MAX_REQUEST);
        let nonce = [0u32; 3];
        for (i, chunk) in out[..len].chunks_mut(64).enumerate() {
            let b = block(&self.key, i as u32 + 1, &nonce);
            for (k, byte) in chunk.iter_mut().enumerate() {
                *byte = b[k / 4].to_le_bytes()[k % 4];
            }
        }
        let next = block(&self.key, 0, &nonce);
        self.key.copy_from_slice(&next[..8]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(words: &[u32]) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, w) in words.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    #[test]
    fn rfc8439_block_vector() {
        // RFC 8439 section 2.3.2.
        let key_bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let key: [u32; 8] = core::array::from_fn(|i| word(&key_bytes, i));
        let nonce = [0x0900_0000, 0x4a00_0000, 0];
        let out = bytes(&block(&key, 1, &nonce));
        let want = "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
                    d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
        let digit = |c: u8| (c as char).to_digit(16).unwrap() as u8;
        let w = want.as_bytes();
        let want: [u8; 64] = core::array::from_fn(|i| digit(w[2 * i]) << 4 | digit(w[2 * i + 1]));
        assert_eq!(out, want);
    }

    #[test]
    fn output_is_keystream_then_key_is_erased() {
        let mut g = Csprng::new();
        g.absorb(b"some seed material", 0);
        let key = g.key;
        let mut out = [0u8; 100];
        g.fill(&mut out);
        let b1 = bytes(&block(&key, 1, &[0; 3]));
        let b2 = bytes(&block(&key, 2, &[0; 3]));
        assert_eq!(&out[..64], &b1);
        assert_eq!(&out[64..], &b2[..36]);
        assert_eq!(&g.key[..], &block(&key, 0, &[0; 3])[..8]);
        // The next request differs.
        let mut again = [0u8; 100];
        g.fill(&mut again);
        assert_ne!(out, again);
    }

    #[test]
    fn absorbing_changes_the_key_and_credits() {
        let mut a = Csprng::new();
        let mut b = Csprng::new();
        assert!(!a.seeded());
        a.absorb(&[1; 32], 128);
        b.absorb(&[2; 32], 128);
        assert_ne!(a.key, b.key);
        assert!(!a.seeded());
        a.absorb(&[3; 8], 128);
        assert!(a.seeded());
        let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
        a.fill(&mut x);
        b.fill(&mut y);
        assert_ne!(x, y);
    }

    #[test]
    fn same_seed_same_stream() {
        let mut a = Csprng::new();
        let mut b = Csprng::new();
        a.absorb(b"deterministic", 0);
        b.absorb(b"deterministic", 0);
        let (mut x, mut y) = ([0u8; 200], [0u8; 200]);
        a.fill(&mut x);
        b.fill(&mut y);
        assert_eq!(x, y);
    }
}
