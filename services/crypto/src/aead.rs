//! ChaCha20-Poly1305 (RFC 8439). ChaCha20's block function is
//! `csprng::block`; Poly1305 here uses 26-bit limbs with no secret-dependent
//! branches.

use alloc::vec::Vec;

/// Poly1305 tag length.
pub const TAG: usize = 16;

/// A one-time Poly1305 authenticator.
#[derive(Debug)]
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    n: usize,
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

const MASK: u32 = 0x3ff_ffff;

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Poly1305 {
        let (t0, t1, t2, t3) = (
            le32(&key[0..]),
            le32(&key[4..]),
            le32(&key[8..]),
            le32(&key[12..]),
        );
        let r = [
            t0 & 0x3ff_ffff,
            ((t0 >> 26) | (t1 << 6)) & 0x3ff_ff03,
            ((t1 >> 20) | (t2 << 12)) & 0x3ff_c0ff,
            ((t2 >> 14) | (t3 << 18)) & 0x3f0_3fff,
            (t3 >> 8) & 0x00f_ffff,
        ];
        Poly1305 {
            s: [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5],
            r,
            h: [0; 5],
            pad: [
                le32(&key[16..]),
                le32(&key[20..]),
                le32(&key[24..]),
                le32(&key[28..]),
            ],
            buf: [0; 16],
            n: 0,
        }
    }

    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let (t0, t1, t2, t3) = (le32(&m[0..]), le32(&m[4..]), le32(&m[8..]), le32(&m[12..]));
        let h = &mut self.h;
        h[0] += t0 & MASK;
        h[1] += ((t0 >> 26) | (t1 << 6)) & MASK;
        h[2] += ((t1 >> 20) | (t2 << 12)) & MASK;
        h[3] += ((t2 >> 14) | (t3 << 18)) & MASK;
        h[4] += (t3 >> 8) | hibit;
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let [s1, s2, s3, s4] = self.s.map(u64::from);
        let [h0, h1, h2, h3, h4] = h.map(u64::from);
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        let m = u64::from(MASK);
        let mut c = d0 >> 26;
        let mut n0 = d0 & m;
        d1 += c;
        c = d1 >> 26;
        let mut n1 = d1 & m;
        d2 += c;
        c = d2 >> 26;
        let n2 = d2 & m;
        d3 += c;
        c = d3 >> 26;
        let n3 = d3 & m;
        d4 += c;
        c = d4 >> 26;
        let n4 = d4 & m;
        n0 += c * 5;
        c = n0 >> 26;
        n0 &= m;
        n1 += c;
        *h = [n0 as u32, n1 as u32, n2 as u32, n3 as u32, n4 as u32];
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (16 - self.n).min(data.len());
            self.buf[self.n..self.n + take].copy_from_slice(&data[..take]);
            self.n += take;
            data = &data[take..];
            if self.n == 16 {
                let b = self.buf;
                self.block(&b, 1 << 24);
                self.n = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; TAG] {
        if self.n > 0 {
            let mut b = [0u8; 16];
            b[..self.n].copy_from_slice(&self.buf[..self.n]);
            b[self.n] = 1;
            self.block(&b, 0);
        }
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= MASK;
        h2 += c;
        c = h2 >> 26;
        h2 &= MASK;
        h3 += c;
        c = h3 >> 26;
        h3 &= MASK;
        h4 += c;
        c = h4 >> 26;
        h4 &= MASK;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= MASK;
        h1 += c;
        // g = h + 5 - 2^130; take g if it did not go negative.
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= MASK;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= MASK;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= MASK;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= MASK;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
        let take_g = (g4 >> 31).wrapping_sub(1);
        let keep_h = !take_g;
        h0 = (h0 & keep_h) | (g0 & take_g);
        h1 = (h1 & keep_h) | (g1 & take_g);
        h2 = (h2 & keep_h) | (g2 & take_g);
        h3 = (h3 & keep_h) | (g3 & take_g);
        h4 = (h4 & keep_h) | (g4 & take_g);
        let w = [
            h0 | (h1 << 26),
            (h1 >> 6) | (h2 << 20),
            (h2 >> 12) | (h3 << 14),
            (h3 >> 18) | (h4 << 8),
        ];
        let mut out = [0u8; TAG];
        let mut f = 0u64;
        for i in 0..4 {
            f = u64::from(w[i]) + u64::from(self.pad[i]) + (f >> 32);
            out[i * 4..i * 4 + 4].copy_from_slice(&(f as u32).to_le_bytes());
        }
        out
    }
}

/// The ChaCha20-Poly1305 AEAD.
#[derive(Clone, Debug)]
pub struct ChaCha20Poly1305 {
    key: [u32; 8],
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut k = [0u32; 8];
        for (w, b) in k.iter_mut().zip(key.as_chunks::<4>().0) {
            *w = u32::from_le_bytes(*b);
        }
        ChaCha20Poly1305 { key: k }
    }

    fn nonce_words(nonce: &[u8; 12]) -> [u32; 3] {
        [le32(&nonce[0..]), le32(&nonce[4..]), le32(&nonce[8..])]
    }

    /// XORs the keystream from block `counter` into `data`.
    fn xor(&self, nonce: &[u32; 3], mut counter: u32, data: &mut [u8]) {
        for chunk in data.chunks_mut(64) {
            let ks = csprng::block(&self.key, counter, nonce);
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= ks[i / 4].to_le_bytes()[i % 4];
            }
            counter = counter.wrapping_add(1);
        }
    }

    fn tag(&self, nonce: &[u32; 3], aad: &[u8], ct: &[u8]) -> [u8; TAG] {
        let block = csprng::block(&self.key, 0, nonce);
        let mut otk = [0u8; 32];
        for (o, w) in otk.as_chunks_mut::<4>().0.iter_mut().zip(block) {
            *o = w.to_le_bytes();
        }
        let mut p = Poly1305::new(&otk);
        let zeros = [0u8; 16];
        p.update(aad);
        p.update(&zeros[..(16 - aad.len() % 16) % 16]);
        p.update(ct);
        p.update(&zeros[..(16 - ct.len() % 16) % 16]);
        p.update(&(aad.len() as u64).to_le_bytes());
        p.update(&(ct.len() as u64).to_le_bytes());
        p.finish()
    }

    /// Encrypts `data` in place and appends the tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut Vec<u8>) {
        let n = Self::nonce_words(nonce);
        self.xor(&n, 1, data);
        let t = self.tag(&n, aad, data);
        data.extend_from_slice(&t);
    }

    /// Checks the tag at the end of `data` and decrypts in place, removing
    /// it; false (and `data` untouched) if it does not verify.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut Vec<u8>) -> bool {
        if data.len() < TAG {
            return false;
        }
        let n = Self::nonce_words(nonce);
        let split = data.len() - TAG;
        let t = self.tag(&n, aad, &data[..split]);
        if !crate::ct_eq(&t, &data[split..]) {
            return false;
        }
        data.truncate(split);
        self.xor(&n, 1, data);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn poly1305_rfc8439_2_5_2() {
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        let mut p = Poly1305::new(&key);
        p.update(b"Cryptographic Forum Research Group");
        assert_eq!(p.finish().to_vec(), hex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    #[test]
    fn poly1305_wraps_modulus() {
        // RFC 8439 A.3 #5: h reaches 2^130 - 5 + 1 and must reduce.
        let mut key = [0u8; 32];
        key[0] = 2;
        let mut p = Poly1305::new(&key);
        p.update(&[0xff; 16]);
        assert_eq!(p.finish().to_vec(), hex("03000000000000000000000000000000"));
    }

    #[test]
    fn aead_rfc8439_2_8_2() {
        let key: [u8; 32] = (0x80..0xa0).collect::<Vec<u8>>().try_into().unwrap();
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let a = ChaCha20Poly1305::new(&key);
        let mut data = pt.to_vec();
        a.seal(&nonce, &aad, &mut data);
        let want = hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116\
             1ae10b594f09e26a7e902ecbd0600691",
        );
        assert_eq!(data, want);
        assert!(a.open(&nonce, &aad, &mut data));
        assert_eq!(data, pt);
        let mut bad = want.clone();
        bad[5] ^= 1;
        assert!(!a.open(&nonce, &aad, &mut bad));
        assert_eq!(bad.len(), want.len(), "a forged message is left alone");
    }
}
