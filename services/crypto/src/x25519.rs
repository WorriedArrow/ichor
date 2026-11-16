//! X25519 (RFC 7748): the Montgomery ladder over GF(2^255 - 19) with
//! 51-bit limbs. The scalar only steers constant-time swaps; field
//! arithmetic has no data-dependent branches or indices.

/// A field element, five 51-bit limbs (little-endian).
#[derive(Clone, Copy, Debug)]
struct Fe([u64; 5]);

const M51: u64 = (1 << 51) - 1;

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn from_bytes(b: &[u8; 32]) -> Fe {
        let load = |i: usize| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(w)
        };
        Fe([
            load(0) & M51,
            (load(6) >> 3) & M51,
            (load(12) >> 6) & M51,
            (load(19) >> 1) & M51,
            (load(24) >> 12) & M51,
        ])
    }

    fn carry(mut self) -> Fe {
        let f = &mut self.0;
        for i in 0..4 {
            f[i + 1] += f[i] >> 51;
            f[i] &= M51;
        }
        f[0] += 19 * (f[4] >> 51);
        f[4] &= M51;
        f[1] += f[0] >> 51;
        f[0] &= M51;
        self
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut h = self.carry().0;
        // q = 1 if h >= p, found by adding 19 and seeing whether it carries
        // past 2^255.
        let mut q = (h[0] + 19) >> 51;
        for limb in &h[1..] {
            q = (limb + q) >> 51;
        }
        h[0] += 19 * q;
        for i in 0..4 {
            h[i + 1] += h[i] >> 51;
            h[i] &= M51;
        }
        h[4] &= M51;
        let w = [
            h[0] | (h[1] << 51),
            (h[1] >> 13) | (h[2] << 38),
            (h[2] >> 26) | (h[3] << 25),
            (h[3] >> 39) | (h[4] << 12),
        ];
        let mut out = [0u8; 32];
        for (o, x) in out.as_chunks_mut::<8>().0.iter_mut().zip(w) {
            *o = x.to_le_bytes();
        }
        out
    }

    fn add(self, b: Fe) -> Fe {
        let mut r = self.0;
        for (x, y) in r.iter_mut().zip(b.0) {
            *x += y;
        }
        Fe(r).carry()
    }

    /// `self - b`, adding 2p first so no limb goes negative.
    fn sub(self, b: Fe) -> Fe {
        let two_p = [
            0xf_ffff_ffff_ffda,
            0xf_ffff_ffff_fffe,
            0xf_ffff_ffff_fffe,
            0xf_ffff_ffff_fffe,
            0xf_ffff_ffff_fffe,
        ];
        let b = b.carry();
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + two_p[i] - b.0[i];
        }
        Fe(r).carry()
    }

    fn mul(self, b: Fe) -> Fe {
        let a = self.0.map(u128::from);
        let b = b.0.map(u128::from);
        let r0 = a[0] * b[0] + 19 * (a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1]);
        let r1 = a[0] * b[1] + a[1] * b[0] + 19 * (a[2] * b[4] + a[3] * b[3] + a[4] * b[2]);
        let r2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + 19 * (a[3] * b[4] + a[4] * b[3]);
        let r3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + 19 * (a[4] * b[4]);
        let r4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];
        let mut r = [r0, r1, r2, r3, r4];
        let m = u128::from(M51);
        for i in 0..4 {
            r[i + 1] += r[i] >> 51;
            r[i] &= m;
        }
        r[0] += 19 * (r[4] >> 51);
        r[4] &= m;
        let mut out = [0u64; 5];
        for (o, x) in out.iter_mut().zip(r) {
            *o = x as u64;
        }
        Fe(out).carry()
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    fn square_n(mut self, n: u32) -> Fe {
        for _ in 0..n {
            self = self.square();
        }
        self
    }

    fn mul_small(self, k: u64) -> Fe {
        let mut r = [0u128; 5];
        for (o, x) in r.iter_mut().zip(self.0) {
            *o = u128::from(x) * u128::from(k);
        }
        let m = u128::from(M51);
        for i in 0..4 {
            r[i + 1] += r[i] >> 51;
            r[i] &= m;
        }
        r[0] += 19 * (r[4] >> 51);
        r[4] &= m;
        let mut out = [0u64; 5];
        for (o, x) in out.iter_mut().zip(r) {
            *o = x as u64;
        }
        Fe(out).carry()
    }

    /// `self^(p-2)`, the inverse (0 for 0).
    fn invert(self) -> Fe {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(z2);
        let z_5_0 = z11.square().mul(z9);
        let z_10_0 = z_5_0.square_n(5).mul(z_5_0);
        let z_20_0 = z_10_0.square_n(10).mul(z_10_0);
        let z_40_0 = z_20_0.square_n(20).mul(z_20_0);
        let z_50_0 = z_40_0.square_n(10).mul(z_10_0);
        let z_100_0 = z_50_0.square_n(50).mul(z_50_0);
        let z_200_0 = z_100_0.square_n(100).mul(z_100_0);
        let z_250_0 = z_200_0.square_n(50).mul(z_50_0);
        z_250_0.square_n(5).mul(z11)
    }
}

/// Swaps `a` and `b` when `swap` is 1, in constant time.
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= t;
        b.0[i] ^= t;
    }
}

/// X25519(scalar, u): the shared u-coordinate.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let mut ub = *u;
    ub[31] &= 127;
    let x1 = Fe::from_bytes(&ub);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let bit = u64::from((k[t / 8] >> (t % 8)) & 1);
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;
        let a = x2.add(z2);
        let aa = a.square();
        let b = x2.sub(z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x3.add(z3);
        let d = x3.sub(z3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x3 = da.add(cb).square();
        z3 = x1.mul(da.sub(cb).square());
        x2 = aa.mul(bb);
        z2 = e.mul(aa.add(e.mul_small(121_665)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    x2.mul(z2.invert()).to_bytes()
}

/// The base point's u-coordinate (9).
pub const BASE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// The public key for `secret`.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    x25519(secret, &BASE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn h32(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    #[test]
    fn rfc7748_5_2_vector() {
        let k = h32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = h32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        assert_eq!(
            x25519(&k, &u),
            h32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
    }

    #[test]
    fn rfc7748_one_iteration() {
        assert_eq!(
            x25519(&BASE, &BASE),
            h32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
    }

    #[test]
    fn rfc7748_6_1_diffie_hellman() {
        let a = h32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = h32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let pa = public_key(&a);
        let pb = public_key(&b);
        assert_eq!(
            pa,
            h32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            pb,
            h32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let s = h32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&a, &pb), s);
        assert_eq!(x25519(&b, &pa), s);
    }
}
