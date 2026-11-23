//! SHA-3's sponge (FIPS 202): Keccak-f[1600], the SHAKE128 and SHAKE256
//! extendable-output functions, and SHA3-256. ML-DSA hashes and samples
//! with SHAKE ([`crate::mldsa`]).

use alloc::vec::Vec;

const ROUNDS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation of lane `x + 5y` (ρ), and the lane it moves to (π).
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Keccak-f[1600] on the state's 25 lanes (lane `x + 5y`).
fn keccak_f(a: &mut [u64; 25]) {
    for rc in ROUNDS {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // ρ and π: lane (x, y) goes to (y, 2x + 3y).
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(RHO[x + 5 * y]);
            }
        }
        // χ
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // ι
        a[0] ^= rc;
    }
}

/// A sponge being absorbed into, then squeezed.
#[derive(Clone, Debug)]
pub struct Sponge {
    state: [u64; 25],
    /// Bytes per block.
    rate: usize,
    /// Domain-separation and first padding bits.
    pad: u8,
    /// Position in the current block.
    at: usize,
    squeezing: bool,
}

impl Sponge {
    fn new(rate: usize, pad: u8) -> Sponge {
        Sponge {
            state: [0; 25],
            rate,
            pad,
            at: 0,
            squeezing: false,
        }
    }

    /// SHAKE128 (rate 168 bytes).
    pub fn shake128() -> Sponge {
        Sponge::new(168, 0x1f)
    }

    /// SHAKE256 (rate 136 bytes).
    pub fn shake256() -> Sponge {
        Sponge::new(136, 0x1f)
    }

    fn xor_byte(&mut self, i: usize, b: u8) {
        self.state[i / 8] ^= u64::from(b) << (8 * (i % 8));
    }

    fn byte(&self, i: usize) -> u8 {
        (self.state[i / 8] >> (8 * (i % 8))) as u8
    }

    /// Absorbs `data` (before any squeezing).
    pub fn absorb(&mut self, data: &[u8]) {
        debug_assert!(!self.squeezing);
        for &b in data {
            self.xor_byte(self.at, b);
            self.at += 1;
            if self.at == self.rate {
                keccak_f(&mut self.state);
                self.at = 0;
            }
        }
    }

    /// Fills `out` with the next output bytes.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.xor_byte(self.at, self.pad);
            self.xor_byte(self.rate - 1, 0x80);
            keccak_f(&mut self.state);
            self.at = 0;
            self.squeezing = true;
        }
        for o in out {
            if self.at == self.rate {
                keccak_f(&mut self.state);
                self.at = 0;
            }
            *o = self.byte(self.at);
            self.at += 1;
        }
    }
}

/// SHAKE256 of the concatenation of `parts`, `len` bytes of it.
pub fn shake256(parts: &[&[u8]], len: usize) -> Vec<u8> {
    let mut s = Sponge::shake256();
    for p in parts {
        s.absorb(p);
    }
    let mut out = alloc::vec![0; len];
    s.squeeze(&mut out);
    out
}

/// SHA3-256.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut s = Sponge::new(136, 0x06);
    s.absorb(data);
    let mut out = [0; 32];
    s.squeeze(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            sha3_256(b"").to_vec(),
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        let mut s = Sponge::shake128();
        let mut out = [0; 32];
        s.squeeze(&mut out);
        assert_eq!(
            out.to_vec(),
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );
        assert_eq!(
            shake256(&[], 64),
            hex(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
            )
        );
    }

    /// 500 bytes of `a`, past several blocks each way (OpenSSL 3.5.2's
    /// `dgst -shake128 -xoflen 200`, `-shake256 -xoflen 300`).
    #[test]
    fn several_blocks_in_and_out() {
        let input = [b'a'; 500];
        let mut s = Sponge::shake128();
        // In pieces, and out in pieces.
        s.absorb(&input[..7]);
        s.absorb(&input[7..300]);
        s.absorb(&input[300..]);
        let mut out = [0; 200];
        s.squeeze(&mut out[..1]);
        s.squeeze(&mut out[1..170]);
        s.squeeze(&mut out[170..]);
        assert_eq!(
            out.to_vec(),
            hex(
                "94dad312c54406c13475df8f970c27b8ce91724b5316eb8985b4f0d80317cada96bdf30a96f54696e0a28895838ff45708f05cdc01d2beb3bf694229b2ab92ddc639b49489c21769e87712f787fbefb707dad4e1596689c7e45f3e90a0c144d9c516a340be933762b4d0232516e8803afbe004bf51b315745e7e6e7fb6e375e67b767bd6f32158176b8d8eab5c322842e1b8f70e16848cb203720efc660c75bf6e397d30cb9df268d50447bd3a12b6f32e3f72398bec3b0772435bd5a576293ecd86218c1d0b6562"
            )
        );
        assert_eq!(
            shake256(&[&input[..136], &input[136..]], 300),
            hex(
                "18bd6ee3fdab56bab909a585def0cc4d979b7ee5ac77e7f65ebf5c808b83dd67d57dccff97c0e03bfd76cf6eac24fa68e58f133675a98bb75fbf0dcdaabe73ee5f2b4b6cad5831ac36a3bc3b7bf4f7e638b62fb1d6542a8b66c6ce296c4343c714676364cc5dc4021aa547f88c8689f188c0bf73d29723c82aa28c9b1c3ae7625b22abf6d028a6458f0eab899b8be6697a84aa6b61e6380ad93a48054ebab93d74b1debc3a3819a577c04dc4397f3475377329d84a4e4bc27e9a922a09f0685bba36dac465bc4bfd4046c115c6b9fbd02cb9f919e57522516f38fd5b4da7a6535e89c6a0ae16efc7056fba0c10a51a1572d2b2fc07e735248164e680aad5fa93a8bb9414996c10e07c260b74a14495e864dabd003cea9bc6d08cc37e52691a0c5b63aa44f187e0e4527551ca"
            )
        );
    }
}
