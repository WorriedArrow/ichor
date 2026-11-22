//! AES-128-GCM (NIST SP 800-38D) with 96-bit nonces, over the bitsliced
//! AES of [`crate::aes`]. GHASH multiplies without tables: carry-less
//! products out of integer ones, whose carries have holes to go to (a
//! technique of Thomas Pornin's).

use alloc::vec::Vec;

use crate::aead::TAG;
use crate::aes::{Aes128, BLOCKS};

/// The hash of GCM, keyed.
struct Ghash {
    /// The key's halves (the second first), and their sum, each as it is
    /// and bit-reversed.
    h: [u64; 3],
    r: [u64; 3],
    y0: u64,
    y1: u64,
}

fn be64(b: &[u8]) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[..8]);
    u64::from_be_bytes(w)
}

/// The low 64 bits of the carry-less product: each operand's bits are taken
/// four apart, so that the integer products' carries fall between them.
fn low_product(x: u64, y: u64) -> u64 {
    const EVERY_FOURTH: u64 = 0x1111_1111_1111_1111;
    let parts = |v: u64| [0, 1, 2, 3].map(|i| v & (EVERY_FOURTH << i));
    let (x, y) = (parts(x), parts(y));
    let mut z = 0;
    for i in 0..4 {
        let mut sum = 0;
        for (j, x) in x.iter().enumerate() {
            sum ^= x.wrapping_mul(y[(i + 4 - j) % 4]);
        }
        z |= sum & (EVERY_FOURTH << i);
    }
    z
}

impl Ghash {
    fn new(key: &[u8; 16]) -> Ghash {
        let (h1, h0) = (be64(&key[..8]), be64(&key[8..]));
        let (r0, r1) = (h0.reverse_bits(), h1.reverse_bits());
        Ghash {
            h: [h0, h1, h0 ^ h1],
            r: [r0, r1, r0 ^ r1],
            y0: 0,
            y1: 0,
        }
    }

    /// Hashes `data`, padded with zeros to whole blocks.
    fn update(&mut self, data: &[u8]) {
        let (blocks, rest) = data.as_chunks::<16>();
        for b in blocks {
            self.block(b);
        }
        if !rest.is_empty() {
            let mut last = [0u8; 16];
            last[..rest.len()].copy_from_slice(rest);
            self.block(&last);
        }
    }

    fn block(&mut self, b: &[u8; 16]) {
        let y1 = self.y1 ^ be64(&b[..8]);
        let y0 = self.y0 ^ be64(&b[8..]);
        // Karatsuba; the high halves are the low ones of the operands
        // reversed, reversed.
        let product = |y: [u64; 3], h: &[u64; 3]| {
            let z0 = low_product(y[0], h[0]);
            let z1 = low_product(y[1], h[1]);
            let z2 = low_product(y[2], h[2]) ^ z0 ^ z1;
            [z0, z1, z2]
        };
        let (r0, r1) = (y0.reverse_bits(), y1.reverse_bits());
        let low = product([y0, y1, y0 ^ y1], &self.h);
        let high = product([r0, r1, r0 ^ r1], &self.r).map(|z| z.reverse_bits() >> 1);
        let v0 = low[0];
        let v1 = high[0] ^ low[2];
        let v2 = low[1] ^ high[2];
        let v3 = high[1];
        // GCM's bits run the other way round: the product is one bit up.
        let v3 = (v3 << 1) | (v2 >> 63);
        let mut v2 = (v2 << 1) | (v1 >> 63);
        let mut v1 = (v1 << 1) | (v0 >> 63);
        let v0 = v0 << 1;
        // Modulo x^128 + x^7 + x^2 + x + 1.
        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        let v3 = v3 ^ v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
        self.y0 = v2;
        self.y1 = v3;
    }

    fn finish(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.y1.to_be_bytes());
        out[8..].copy_from_slice(&self.y0.to_be_bytes());
        out
    }
}

/// The AEAD.
pub struct Aes128Gcm {
    aes: Aes128,
    hash_key: [u8; 16],
}

impl core::fmt::Debug for Aes128Gcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes128Gcm").finish_non_exhaustive()
    }
}

impl Aes128Gcm {
    pub fn new(key: &[u8; 16]) -> Self {
        let aes = Aes128::new(key);
        let mut zero = [0u8; BLOCKS];
        aes.encrypt(&mut zero);
        let mut hash_key = [0u8; 16];
        hash_key.copy_from_slice(&zero[..16]);
        Aes128Gcm { aes, hash_key }
    }

    /// Four blocks of key stream, from counter `counter` on.
    fn stream(&self, nonce: &[u8; 12], counter: u32) -> [u8; BLOCKS] {
        let mut blocks = [0u8; BLOCKS];
        for (i, b) in blocks.as_chunks_mut::<16>().0.iter_mut().enumerate() {
            b[..12].copy_from_slice(nonce);
            b[12..].copy_from_slice(&counter.wrapping_add(i as u32).to_be_bytes());
        }
        self.aes.encrypt(&mut blocks);
        blocks
    }

    fn crypt(&self, nonce: &[u8; 12], data: &mut [u8]) {
        for (i, piece) in data.chunks_mut(BLOCKS).enumerate() {
            let counter = (i as u32).wrapping_mul(4).wrapping_add(2);
            for (d, s) in piece.iter_mut().zip(self.stream(nonce, counter)) {
                *d ^= s;
            }
        }
    }

    fn tag(&self, nonce: &[u8; 12], aad: &[u8], cipher: &[u8]) -> [u8; TAG] {
        let mut h = Ghash::new(&self.hash_key);
        h.update(aad);
        h.update(cipher);
        let mut lengths = [0u8; 16];
        lengths[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&(cipher.len() as u64 * 8).to_be_bytes());
        h.update(&lengths);
        let mut tag = h.finish();
        for (t, s) in tag.iter_mut().zip(self.stream(nonce, 1)) {
            *t ^= s;
        }
        tag
    }

    /// Encrypts `data` in place and appends the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut Vec<u8>) {
        self.crypt(nonce, data);
        let tag = self.tag(nonce, aad, data);
        data.extend_from_slice(&tag);
    }

    /// Checks and removes the tag, then decrypts in place. On a bad tag
    /// returns false and leaves `data` as it was.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut Vec<u8>) -> bool {
        let Some(n) = data.len().checked_sub(TAG) else {
            return false;
        };
        let (cipher, tag) = data.split_at(n);
        if !crate::ct_eq(&self.tag(nonce, aad, cipher), tag) {
            return false;
        }
        data.truncate(n);
        self.crypt(nonce, data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// The product against shift-and-add.
    #[test]
    fn low_products() {
        let mut x = 0x0123_4567_89ab_cdefu64;
        for _ in 0..200 {
            let y = x.rotate_left(23).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let slow = (0..64)
                .filter(|i| y >> i & 1 == 1)
                .fold(0, |z, i| z ^ (x << i));
            assert_eq!(low_product(x, y), slow);
            x = y ^ (x >> 5);
        }
        assert_eq!(low_product(u64::MAX, u64::MAX) & 0xff, 0x55);
    }

    /// The test cases 1 to 4 of the GCM specification (McGrew and Viega).
    #[test]
    fn gcm_vectors() {
        let check = |key: &str, nonce: &str, aad: &str, plain: &str, cipher: &str, tag: &str| {
            let g = Aes128Gcm::new(hex(key).as_slice().try_into().unwrap());
            let nonce: [u8; 12] = hex(nonce).as_slice().try_into().unwrap();
            let mut data = hex(plain);
            g.seal(&nonce, &hex(aad), &mut data);
            let mut want = hex(cipher);
            want.extend(hex(tag));
            assert_eq!(data, want);
            assert!(g.open(&nonce, &hex(aad), &mut data));
            assert_eq!(data, hex(plain));
            for i in 0..want.len() {
                let mut bad = want.clone();
                bad[i] ^= 1 << (i % 8);
                assert!(!g.open(&nonce, &hex(aad), &mut bad));
            }
            let mut other = hex(aad);
            other.push(0);
            assert!(!g.open(&nonce, &other, &mut want.clone()));
            assert!(!g.open(&nonce, &[], &mut want[..15.min(want.len())].to_vec()));
        };
        let zero = "00000000000000000000000000000000";
        let iv = "000000000000000000000000";
        check(zero, iv, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
        check(
            zero,
            iv,
            "",
            zero,
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        );
        let key = "feffe9928665731c6d6a8f9467308308";
        let iv = "cafebabefacedbaddecaf888";
        let plain = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
                     1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
        let cipher = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                      21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
        let tag = "4d5c2af327cd64a62cf35abd2ba6fab4";
        check(key, iv, "", plain, cipher, tag);
        check(
            key,
            iv,
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            &plain[..plain.len() - 8],
            &cipher[..cipher.len() - 8],
            "5bc94fbc3221a5db94fae95ae7121a47",
        );
    }

    #[test]
    fn every_length_round_trips() {
        let g = Aes128Gcm::new(&[7; 16]);
        for n in 0..200usize {
            let plain: Vec<u8> = (0..n).map(|i| (i * 3) as u8).collect();
            let mut data = plain.clone();
            g.seal(&[n as u8; 12], &plain[..n / 2], &mut data);
            assert!(n < 8 || data[..n] != plain[..]);
            assert!(g.open(&[n as u8; 12], &plain[..n / 2], &mut data));
            assert_eq!(data, plain);
        }
    }
}
