//! AES-128 encryption (FIPS 197), bitsliced: four blocks at a time, as
//! eight words of one bit each from all 64 bytes. No table is indexed and no
//! branch taken by key or data.
//!
//! Bit `16 * block + byte` of word `b` is bit `b` of that block's byte;
//! bytes are numbered by column (byte = 4 * column + row), as they are read.

/// Bytes the cipher works on at once.
pub(crate) const BLOCKS: usize = 64;

type Planes = [u64; 8];

/// An AES-128 key, expanded.
pub(crate) struct Aes128 {
    /// The eleven round keys, each the same for all four blocks.
    round_keys: [Planes; 11],
}

impl Aes128 {
    pub(crate) fn new(key: &[u8; 16]) -> Aes128 {
        let mut words = [[0u8; 4]; 44];
        for (w, k) in words.iter_mut().zip(key.as_chunks::<4>().0) {
            *w = *k;
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut w = words[i - 1];
            if i % 4 == 0 {
                w.rotate_left(1);
                w = sub_word(w);
                w[0] ^= rcon;
                // (The round constants are public.)
                rcon = (rcon << 1) ^ (0x1b * (rcon >> 7));
            }
            for (b, old) in w.iter_mut().zip(words[i - 4]) {
                *b ^= old;
            }
            words[i] = w;
        }
        let mut round_keys = [[0u64; 8]; 11];
        for (k, w) in round_keys.iter_mut().zip(words.as_chunks::<4>().0) {
            let mut four = [0u8; BLOCKS];
            for block in four.as_chunks_mut::<16>().0 {
                for (to, from) in block.as_chunks_mut::<4>().0.iter_mut().zip(w) {
                    *to = *from;
                }
            }
            *k = slice(&four);
        }
        Aes128 { round_keys }
    }

    /// Encrypts four blocks.
    pub(crate) fn encrypt(&self, blocks: &mut [u8; BLOCKS]) {
        let mut q = slice(blocks);
        add_key(&mut q, &self.round_keys[0]);
        for k in &self.round_keys[1..10] {
            sub_bytes(&mut q);
            shift_rows(&mut q);
            mix_columns(&mut q);
            add_key(&mut q, k);
        }
        sub_bytes(&mut q);
        shift_rows(&mut q);
        add_key(&mut q, &self.round_keys[10]);
        *blocks = unslice(&q);
    }
}

fn add_key(q: &mut Planes, k: &Planes) {
    for (q, k) in q.iter_mut().zip(k) {
        *q ^= k;
    }
}

/// The S-box on one word of the key schedule.
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let mut blocks = [0u8; BLOCKS];
    blocks[..4].copy_from_slice(&w);
    let mut q = slice(&blocks);
    sub_bytes(&mut q);
    let out = unslice(&q);
    [out[0], out[1], out[2], out[3]]
}

/// Transposes the 8x8 bits of `x` (byte `i` bit `j` goes to byte `j` bit
/// `i`).
fn transpose(mut x: u64) -> u64 {
    let mut t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
    x ^ t ^ (t << 28)
}

fn slice(bytes: &[u8; BLOCKS]) -> Planes {
    let mut q = [0u64; 8];
    for (i, eight) in bytes.as_chunks::<8>().0.iter().enumerate() {
        let t = transpose(u64::from_le_bytes(*eight));
        for (b, q) in q.iter_mut().enumerate() {
            *q |= ((t >> (8 * b)) & 0xff) << (8 * i);
        }
    }
    q
}

fn unslice(q: &Planes) -> [u8; BLOCKS] {
    let mut bytes = [0u8; BLOCKS];
    for (i, eight) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let mut t = 0u64;
        for (b, q) in q.iter().enumerate() {
            t |= ((q >> (8 * i)) & 0xff) << (8 * b);
        }
        *eight = transpose(t).to_le_bytes();
    }
    bytes
}

/// Row `r` of every column moves `r` columns to the left.
fn shift_rows(q: &mut Planes) {
    const LANES: u64 = 0x0001_0001_0001_0001;
    for x in q {
        let mut out = *x & (0x1111 * LANES);
        for r in 1..4u32 {
            let row = *x & ((0x1111 << r) * LANES);
            let s = 4 * r;
            out |= (row >> s) & ((0xffff >> s) * LANES);
            out |= (row << (16 - s)) & (((0xffff << (16 - s)) & 0xffff) * LANES);
        }
        *x = out;
    }
}

fn mix_columns(q: &mut Planes) {
    // The byte one, and two, rows down, for every byte.
    let down1 = |x: u64| ((x >> 1) & 0x7777_7777_7777_7777) | ((x << 3) & 0x8888_8888_8888_8888);
    let down2 = |x: u64| ((x >> 2) & 0x3333_3333_3333_3333) | ((x << 2) & 0xcccc_cccc_cccc_cccc);
    // 2a + 3r1 + r2 + r3 = 2(a + r1) + r1 + (r2 + r3).
    let r1 = q.map(down1);
    let mut t = [0u64; 8];
    for (t, (a, b)) in t.iter_mut().zip(q.iter().zip(&r1)) {
        *t = a ^ b;
    }
    let twice = [
        t[7],
        t[0] ^ t[7],
        t[1],
        t[2] ^ t[7],
        t[3] ^ t[7],
        t[4],
        t[5],
        t[6],
    ];
    for i in 0..8 {
        q[i] = twice[i] ^ r1[i] ^ down2(t[i]);
    }
}

/// The S-box on every byte: Boyar and Peralta's circuit ("A depth-16
/// circuit for the AES S-box"), with its names.
fn sub_bytes(q: &mut Planes) {
    let [x7, x6, x5, x4, x3, x2, x1, x0] = *q;
    // The linear map before the inversion.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;
    // The inversion.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;
    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;
    // The linear map after it.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let t67 = t64 ^ t65;
    let s0 = t59 ^ t63;
    let s3 = t53 ^ t66;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    *q = [s7, s6, s5, s4, s3, s2, s1, s0];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn slicing_round_trips() {
        let mut bytes = [0u8; BLOCKS];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i * 37 + 11) as u8;
        }
        let q = slice(&bytes);
        assert_eq!(unslice(&q), bytes);
        for (i, b) in bytes.iter().enumerate() {
            for (bit, plane) in q.iter().enumerate() {
                assert_eq!(plane >> i & 1, u64::from(b >> bit & 1));
            }
        }
    }

    /// The circuit against the S-box's definition: the inverse in GF(2^8),
    /// then the affine map.
    #[test]
    fn the_sbox_is_the_sbox() {
        let mul = |mut a: u8, mut b: u8| {
            let mut r = 0;
            while b != 0 {
                r ^= a * (b & 1);
                a = (a << 1) ^ (0x1b * (a >> 7));
                b >>= 1;
            }
            r
        };
        for start in (0..256).step_by(64) {
            let mut bytes = [0u8; BLOCKS];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = (start + i) as u8;
            }
            let mut q = slice(&bytes);
            sub_bytes(&mut q);
            for (x, got) in bytes.iter().zip(unslice(&q)) {
                let inv = (1..=255).find(|&y| mul(*x, y) == 1).unwrap_or(0);
                let s = (0..5).fold(0x63, |s, r| s ^ inv.rotate_left(r));
                assert_eq!(got, s, "S({x:#04x})");
            }
        }
    }

    #[test]
    fn fips_197_vectors() {
        let check = |key: &str, plain: &str, cipher: &str| {
            let aes = Aes128::new(hex(key).as_slice().try_into().unwrap());
            let mut blocks = [0u8; BLOCKS];
            for b in blocks.as_chunks_mut::<16>().0 {
                b.copy_from_slice(&hex(plain));
            }
            aes.encrypt(&mut blocks);
            for b in blocks.as_chunks::<16>().0 {
                assert_eq!(b.as_slice(), hex(cipher));
            }
        };
        // Appendix B and C.1.
        check(
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3243f6a8885a308d313198a2e0370734",
            "3925841d02dc09fbdc118597196a0b32",
        );
        check(
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        );
    }
}
