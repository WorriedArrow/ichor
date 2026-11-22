//! GF(2^255 - 19), shared by X25519 and Ed25519: 51-bit limbs, no
//! data-dependent branches or indices.

/// A field element, five 51-bit limbs (little-endian).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fe([u64; 5]);

const M51: u64 = (1 << 51) - 1;

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// The low 255 bits of `b`, little-endian (the top bit is ignored).
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Fe {
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

    /// The canonical encoding.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
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

    pub(crate) fn add(self, b: Fe) -> Fe {
        let mut r = self.0;
        for (x, y) in r.iter_mut().zip(b.0) {
            *x += y;
        }
        Fe(r).carry()
    }

    /// `self - b`, adding 2p first so no limb goes negative.
    pub(crate) fn sub(self, b: Fe) -> Fe {
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

    pub(crate) fn mul(self, b: Fe) -> Fe {
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

    pub(crate) fn square(self) -> Fe {
        self.mul(self)
    }

    fn square_n(mut self, n: u32) -> Fe {
        for _ in 0..n {
            self = self.square();
        }
        self
    }

    pub(crate) fn mul_small(self, k: u64) -> Fe {
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

    /// `self^(2^250 - 1)`, and `self^11`.
    fn pow_250(self) -> (Fe, Fe) {
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
        (z_200_0.square_n(50).mul(z_50_0), z11)
    }

    /// `self^(p-2)`, the inverse (0 for 0).
    pub(crate) fn invert(self) -> Fe {
        let (z_250_0, z11) = self.pow_250();
        z_250_0.square_n(5).mul(z11)
    }

    /// `self^((p-5)/8)` = `self^(2^252 - 3)`, for square roots.
    pub(crate) fn pow_p58(self) -> Fe {
        let (z_250_0, _) = self.pow_250();
        z_250_0.square_n(2).mul(self)
    }

    /// `b` where `bit` is 1, `a` where it is 0, in constant time.
    pub(crate) fn select(bit: u64, a: Fe, b: Fe) -> Fe {
        let mask = 0u64.wrapping_sub(bit);
        let mut r = a.0;
        for (x, y) in r.iter_mut().zip(b.0) {
            *x ^= mask & (*x ^ y);
        }
        Fe(r)
    }

    /// Swaps `a` and `b` when `swap` is 1, in constant time.
    pub(crate) fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }
}
