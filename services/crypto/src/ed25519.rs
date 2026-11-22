//! Ed25519 signatures (RFC 8032), for the control API's TLS certificate.
//!
//! Signing is constant-time: one complete addition formula for every point
//! operation (so doubling and the identity are not special), a ladder that
//! always adds and selects the result with a mask, and scalar arithmetic
//! modulo the group order with masked subtractions. Verification handles
//! only public values but uses the same code.

use crate::field::Fe;
use crate::sha2::{Digest, Sha512};

/// The order of the base point's group, little-endian limbs.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

/// The curve's `d`, `-121665/121666`.
const D: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// A square root of -1.
const SQRT_M1: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// The base point, encoded: y = 4/5, x even.
const BASE: [u8; 32] = {
    let mut b = [0x66; 32];
    b[0] = 0x58;
    b
};

/// A curve point in extended coordinates (x = X/Z, y = Y/Z, xy = T/Z).
#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// `self + o`, for any two points (RFC 8032 §5.1.4; the formula is
    /// complete, so it doubles too).
    fn add(&self, o: &Point, d2: Fe) -> Point {
        let a = self.y.sub(self.x).mul(o.y.sub(o.x));
        let b = self.y.add(self.x).mul(o.y.add(o.x));
        let c = self.t.mul(d2).mul(o.t);
        let d = self.z.add(self.z).mul(o.z);
        let (e, f, g, h) = (b.sub(a), d.sub(c), d.add(c), b.add(a));
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn neg(&self) -> Point {
        Point {
            x: Fe::ZERO.sub(self.x),
            t: Fe::ZERO.sub(self.t),
            ..*self
        }
    }

    /// `b` where `bit` is 1, `a` where it is 0, in constant time.
    fn select(bit: u64, a: &Point, b: &Point) -> Point {
        Point {
            x: Fe::select(bit, a.x, b.x),
            y: Fe::select(bit, a.y, b.y),
            z: Fe::select(bit, a.z, b.z),
            t: Fe::select(bit, a.t, b.t),
        }
    }

    /// `[k] self` for a little-endian scalar, in constant time.
    fn mul(&self, k: &[u8; 32]) -> Point {
        let d2 = d2();
        let mut r = Point::IDENTITY;
        for i in (0..256).rev() {
            r = r.add(&r, d2);
            let with = r.add(self, d2);
            let bit = u64::from((k[i / 8] >> (i % 8)) & 1);
            r = Point::select(bit, &r, &with);
        }
        r
    }

    fn encode(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let mut out = self.y.mul(zi).to_bytes();
        out[31] |= (self.x.mul(zi).to_bytes()[0] & 1) << 7;
        out
    }

    /// The point `b` encodes, if it is canonical and on the curve.
    fn decode(b: &[u8; 32]) -> Option<Point> {
        let sign = b[31] >> 7;
        let mut yb = *b;
        yb[31] &= 0x7f;
        let y = Fe::from_bytes(&yb);
        if y.to_bytes() != yb {
            return None;
        }
        // x^2 = u/v with u = y^2 - 1, v = d y^2 + 1.
        let y2 = y.square();
        let u = y2.sub(Fe::ONE);
        let v = y2.mul(Fe::from_bytes(&D)).add(Fe::ONE);
        let v3 = v.square().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v3.square()).mul(v).pow_p58());
        let vx2 = v.mul(x.square()).to_bytes();
        if vx2 != u.to_bytes() {
            if vx2 != Fe::ZERO.sub(u).to_bytes() {
                return None;
            }
            x = x.mul(Fe::from_bytes(&SQRT_M1));
        }
        let xb = x.to_bytes();
        if xb == [0; 32] && sign == 1 {
            return None;
        }
        if xb[0] & 1 != sign {
            x = Fe::ZERO.sub(x);
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }
}

/// 2d.
fn d2() -> Fe {
    let d = Fe::from_bytes(&D);
    d.add(d)
}

fn base() -> Point {
    // Encodes a point of the curve by definition (checked by the tests).
    Point::decode(&BASE).unwrap_or(Point::IDENTITY)
}

/// `a - L` where `a >= L`, else `a`, without branching on the values.
fn sub_l(a: [u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (x, b1) = a[i].overflowing_sub(L[i]);
        let (x, b2) = x.overflowing_sub(borrow);
        r[i] = x;
        borrow = u64::from(b1) | u64::from(b2);
    }
    // All ones when the subtraction borrowed: keep `a`.
    let keep = 0u64.wrapping_sub(borrow);
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = (a[i] & keep) | (r[i] & !keep);
    }
    out
}

/// A 512-bit little-endian number modulo L, bit by bit.
fn reduce(n: &[u64; 8]) -> [u64; 4] {
    let mut acc = [0u64; 4];
    for i in (0..512).rev() {
        let mut carry = (n[i / 64] >> (i % 64)) & 1;
        for limb in &mut acc {
            let top = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = top;
        }
        // acc < 2L < 2^254, so nothing was carried out.
        acc = sub_l(acc);
    }
    acc
}

fn limbs<const N: usize>(b: &[u8]) -> [u64; N] {
    let mut out = [0u64; N];
    for (o, c) in out.iter_mut().zip(b.as_chunks::<8>().0) {
        *o = u64::from_le_bytes(*c);
    }
    out
}

fn bytes(n: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, x) in out.as_chunks_mut::<8>().0.iter_mut().zip(n) {
        *o = x.to_le_bytes();
    }
    out
}

/// `(k * a + r) mod L`.
fn mul_add(k: &[u64; 4], a: &[u64; 4], r: &[u64; 4]) -> [u64; 4] {
    let mut n = [0u64; 8];
    n[..4].copy_from_slice(r);
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = u128::from(k[i]) * u128::from(a[j]) + u128::from(n[i + j]) + carry;
            n[i + j] = t as u64;
            carry = t >> 64;
        }
        // Limb i + 4 is still zero: rows so far reach limb i + 3.
        n[i + 4] = carry as u64;
    }
    reduce(&n)
}

/// SHA-512 of the parts, modulo L.
fn hash_mod_l(parts: &[&[u8]]) -> [u64; 4] {
    let mut h = Sha512::default();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 64];
    h.finish_into(&mut out);
    reduce(&limbs(&out))
}

/// A signing key.
#[derive(Clone)]
pub struct SigningKey {
    /// The clamped secret scalar.
    a: [u8; 32],
    /// What makes each signature's nonce.
    prefix: [u8; 32],
    public: [u8; 32],
}

impl core::fmt::Debug for SigningKey {
    /// Only the public half.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// The key made from a 32-byte seed (RFC 8032 §5.1.5; what PKCS #8
    /// stores).
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        let mut h = [0u8; 64];
        let mut d = Sha512::default();
        d.update(seed);
        d.finish_into(&mut h);
        let mut a = [0u8; 32];
        let mut prefix = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        prefix.copy_from_slice(&h[32..]);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        let public = base().mul(&a).encode();
        SigningKey { a, prefix, public }
    }

    /// The public key.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Signs `msg`.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let r = hash_mod_l(&[&self.prefix, msg]);
        let rb = base().mul(&bytes(r)).encode();
        let k = hash_mod_l(&[&rb, &self.public, msg]);
        let s = mul_add(&k, &limbs(&self.a), &r);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&rb);
        sig[32..].copy_from_slice(&bytes(s));
        sig
    }
}

/// Whether `sig` is `public`'s signature of `msg` (RFC 8032 §5.1.7, with
/// the unmultiplied equation; non-canonical points and scalars refused).
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(public), Ok(sig)) = (<&[u8; 32]>::try_from(public), <&[u8; 64]>::try_from(sig)) else {
        return false;
    };
    let mut rb = [0u8; 32];
    let mut sb = [0u8; 32];
    rb.copy_from_slice(&sig[..32]);
    sb.copy_from_slice(&sig[32..]);
    let s: [u64; 4] = limbs(&sb);
    // S < L: the subtraction changes nothing.
    if sub_l(s) != s {
        return false;
    }
    let Some(a) = Point::decode(public) else {
        return false;
    };
    let k = hash_mod_l(&[&rb, public, msg]);
    let sum = base().mul(&sb).add(&a.neg().mul(&bytes(k)), d2());
    sum.encode() == rb
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    #[test]
    fn constants() {
        let d = Fe::from_bytes(&D);
        let k = |v: u64| Fe::ONE.mul_small(v);
        assert_eq!(
            d.mul(k(121_666)).to_bytes(),
            Fe::ZERO.sub(k(121_665)).to_bytes()
        );
        let i = Fe::from_bytes(&SQRT_M1);
        assert_eq!(i.square().to_bytes(), Fe::ZERO.sub(Fe::ONE).to_bytes());
        let b = Point::decode(&BASE).unwrap();
        assert_eq!(b.y.mul(k(5)).to_bytes(), k(4).to_bytes());
        assert_eq!(b.encode(), BASE);
        // [L] B is the identity and [L - 1] B is -B.
        assert_eq!(b.mul(&bytes(L)).encode(), Point::IDENTITY.encode());
        let mut less = L;
        less[0] -= 1;
        assert_eq!(b.mul(&bytes(less)).encode(), b.neg().encode());
    }

    #[test]
    fn scalars() {
        let mut n = [0u64; 8];
        n[..4].copy_from_slice(&L);
        assert_eq!(reduce(&n), [0; 4]);
        n[0] += 5;
        assert_eq!(reduce(&n), [5, 0, 0, 0]);
        // (L - 1)^2 + 1 = 2 mod L.
        let mut m1 = L;
        m1[0] -= 1;
        assert_eq!(mul_add(&m1, &m1, &[1, 0, 0, 0]), [2, 0, 0, 0]);
        // 2^512 - 1 = (2^256 mod L)^2 - 1 mod L.
        let mut two256 = [0u64; 8];
        two256[4] = 1;
        let r = reduce(&two256);
        let sq = mul_add(&r, &r, &[0; 4]);
        assert_eq!(
            reduce(&[u64::MAX; 8]),
            mul_add(&m1, &[1, 0, 0, 0], &sq) // sq + (L - 1)
        );
    }

    /// RFC 8032 §7.1, tests 1-3 and SHA(abc).
    #[test]
    fn rfc8032_vectors() {
        for (seed, public, msg, sig) in [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
            (
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            ),
        ] {
            let key = SigningKey::from_seed(&h(seed));
            assert_eq!(key.public(), h(public));
            let msg = hex(msg);
            assert_eq!(key.sign(&msg), h(sig));
            assert!(verify(&h::<32>(public), &msg, &h::<64>(sig)));
        }
    }

    #[test]
    fn altered_signatures_are_refused() {
        let key = SigningKey::from_seed(&[7; 32]);
        let msg = b"ichor";
        let sig = key.sign(msg);
        assert!(verify(&key.public(), msg, &sig));
        assert!(!verify(&key.public(), b"ichos", &sig));
        assert!(!verify(
            &SigningKey::from_seed(&[8; 32]).public(),
            msg,
            &sig
        ));
        for i in 0..64 {
            let mut bad = sig;
            bad[i] ^= 1 << (i % 8);
            assert!(!verify(&key.public(), msg, &bad), "byte {i}");
        }
        // S + L is the same scalar, but not canonical.
        let mut s: [u64; 4] = limbs(&sig[32..]);
        let mut carry = 0u128;
        for (x, l) in s.iter_mut().zip(L) {
            let t = u128::from(*x) + u128::from(l) + carry;
            *x = t as u64;
            carry = t >> 64;
        }
        let mut bad = sig;
        bad[32..].copy_from_slice(&bytes(s));
        assert!(!verify(&key.public(), msg, &bad));
        assert!(!verify(&key.public()[..31], msg, &sig));
        assert!(!verify(&key.public(), msg, &sig[..63]));
        // Not a canonical y, and -0.
        assert!(Point::decode(&[0xff; 32]).is_none());
        let mut minus_zero = [0u8; 32];
        minus_zero[0] = 1;
        minus_zero[31] = 0x80;
        assert!(Point::decode(&minus_zero).is_none());
    }
}
