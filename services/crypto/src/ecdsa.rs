//! ECDSA signature verification (FIPS 186-4, SEC 1) on P-256 and P-384,
//! in Jacobian coordinates with Montgomery field arithmetic. Public data
//! only.

use alloc::vec::Vec;

use crate::bignum::{Mont, Nat};

/// A NIST prime curve `y^2 = x^3 - 3x + b`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

struct Params {
    p: &'static str,
    b: &'static str,
    n: &'static str,
    gx: &'static str,
    gy: &'static str,
}

const P256: Params = Params {
    p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
};

const P384: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
};

fn unhex(s: &str) -> Nat {
    let b: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect();
    Nat::from_be(&b)
}

/// A curve ready for arithmetic: field and scalar Montgomery contexts.
struct Ctx {
    f: Mont,
    s: Mont,
    b: Vec<u64>,
    g: Point,
    /// Field element and scalar length in bytes.
    len: usize,
}

/// A point in Jacobian coordinates (Montgomery form); `z == 0` is the
/// point at infinity.
#[derive(Clone, Debug)]
struct Point {
    x: Vec<u64>,
    y: Vec<u64>,
    z: Vec<u64>,
}

impl Ctx {
    fn new(c: Curve) -> Option<Ctx> {
        let (pr, len) = match c {
            Curve::P256 => (&P256, 32),
            Curve::P384 => (&P384, 48),
        };
        let f = Mont::new(&unhex(pr.p))?;
        let s = Mont::new(&unhex(pr.n))?;
        let b = f.to(&unhex(pr.b));
        let one = f.to(&Nat::from_u64(1));
        let g = Point {
            x: f.to(&unhex(pr.gx)),
            y: f.to(&unhex(pr.gy)),
            z: one,
        };
        Some(Ctx { f, s, b, g, len })
    }

    fn is_zero(v: &[u64]) -> bool {
        v.iter().all(|&l| l == 0)
    }

    fn infinity(&self) -> Point {
        let z = alloc::vec![0u64; self.g.x.len()];
        Point {
            x: z.clone(),
            y: z.clone(),
            z,
        }
    }

    /// Whether affine (x, y), in Montgomery form, satisfies the equation.
    fn on_curve(&self, x: &[u64], y: &[u64]) -> bool {
        let f = &self.f;
        let y2 = f.mul(y, y);
        let x3 = f.mul(&f.mul(x, x), x);
        let three_x = f.add(&f.add(x, x), x);
        let rhs = f.add(&f.sub(&x3, &three_x), &self.b);
        y2 == rhs
    }

    fn double(&self, p: &Point) -> Point {
        if Self::is_zero(&p.z) {
            return p.clone();
        }
        let f = &self.f;
        let delta = f.mul(&p.z, &p.z);
        let gamma = f.mul(&p.y, &p.y);
        let beta = f.mul(&p.x, &gamma);
        let t = f.mul(&f.sub(&p.x, &delta), &f.add(&p.x, &delta));
        let alpha = f.add(&f.add(&t, &t), &t);
        let beta2 = f.add(&beta, &beta);
        let beta4 = f.add(&beta2, &beta2);
        let beta8 = f.add(&beta4, &beta4);
        let x3 = f.sub(&f.mul(&alpha, &alpha), &beta8);
        let yz = f.add(&p.y, &p.z);
        let z3 = f.sub(&f.sub(&f.mul(&yz, &yz), &gamma), &delta);
        let gg = f.mul(&gamma, &gamma);
        let gg2 = f.add(&gg, &gg);
        let gg4 = f.add(&gg2, &gg2);
        let gg8 = f.add(&gg4, &gg4);
        let y3 = f.sub(&f.mul(&alpha, &f.sub(&beta4, &x3)), &gg8);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, p: &Point, q: &Point) -> Point {
        if Self::is_zero(&p.z) {
            return q.clone();
        }
        if Self::is_zero(&q.z) {
            return p.clone();
        }
        let f = &self.f;
        let z1z1 = f.mul(&p.z, &p.z);
        let z2z2 = f.mul(&q.z, &q.z);
        let u1 = f.mul(&p.x, &z2z2);
        let u2 = f.mul(&q.x, &z1z1);
        let s1 = f.mul(&f.mul(&p.y, &q.z), &z2z2);
        let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
        let h = f.sub(&u2, &u1);
        let r = f.sub(&s2, &s1);
        if Self::is_zero(&h) {
            return if Self::is_zero(&r) {
                self.double(p)
            } else {
                self.infinity()
            };
        }
        let h2 = f.add(&h, &h);
        let i = f.mul(&h2, &h2);
        let j = f.mul(&h, &i);
        let r = f.add(&r, &r);
        let v = f.mul(&u1, &i);
        let x3 = f.sub(&f.sub(&f.mul(&r, &r), &j), &f.add(&v, &v));
        let s1j = f.mul(&s1, &j);
        let y3 = f.sub(&f.mul(&r, &f.sub(&v, &x3)), &f.add(&s1j, &s1j));
        let zz = f.add(&p.z, &q.z);
        let z3 = f.mul(&f.sub(&f.sub(&f.mul(&zz, &zz), &z1z1), &z2z2), &h);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn mul(&self, k: &Nat, p: &Point) -> Point {
        let mut acc = self.infinity();
        for i in (0..k.bits()).rev() {
            acc = self.double(&acc);
            if k.bit(i) {
                acc = self.add(&acc, p);
            }
        }
        acc
    }

    /// The affine x coordinate as a plain number.
    fn affine_x(&self, p: &Point) -> Nat {
        let f = &self.f;
        let zi = f.inv(&p.z);
        f.from(&f.mul(&p.x, &f.mul(&zi, &zi)))
    }
}

/// Verifies an ECDSA signature `(r, s)` (big-endian integers) by the
/// public key `public` (SEC 1 uncompressed: `04 || x || y`) over a message
/// whose digest is `digest`.
pub fn verify(curve: Curve, public: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
    let Some(c) = Ctx::new(curve) else {
        return false;
    };
    if public.len() != 1 + 2 * c.len || public[0] != 4 {
        return false;
    }
    let (qx, qy) = (
        Nat::from_be(&public[1..1 + c.len]),
        Nat::from_be(&public[1 + c.len..]),
    );
    if qx.cmp(&c.f.n).is_ge() || qy.cmp(&c.f.n).is_ge() {
        return false;
    }
    let (qx, qy) = (c.f.to(&qx), c.f.to(&qy));
    if !c.on_curve(&qx, &qy) {
        return false;
    }
    let q = Point {
        x: qx,
        y: qy,
        z: c.f.to(&Nat::from_u64(1)),
    };
    let (r, s) = (Nat::from_be(r), Nat::from_be(s));
    let n = &c.s.n;
    if r.is_zero() || s.is_zero() || r.cmp(n).is_ge() || s.cmp(n).is_ge() {
        return false;
    }
    // The leftmost bits of the digest, as many as the order has.
    let e = Nat::from_be(&digest[..digest.len().min(c.len)]).rem(n);
    let w = c.s.inv(&c.s.to(&s));
    let u1 = c.s.from(&c.s.mul(&c.s.to(&e), &w));
    let u2 = c.s.from(&c.s.mul(&c.s.to(&r), &w));
    let x = c.add(&c.mul(&u1, &c.g), &c.mul(&u2, &q));
    if Ctx::is_zero(&x.z) {
        return false;
    }
    c.affine_x(&x).rem(n) == r
}

/// Verifies a DER-encoded signature (`SEQUENCE { INTEGER r, INTEGER s }`).
pub fn verify_der(curve: Curve, public: &[u8], digest: &[u8], sig: &[u8]) -> bool {
    match parse_der(sig) {
        Some((r, s)) => verify(curve, public, digest, r, s),
        None => false,
    }
}

/// The two INTEGERs of a DER ECDSA signature.
fn parse_der(sig: &[u8]) -> Option<(&[u8], &[u8])> {
    let (body, rest) = der_tlv(sig, 0x30)?;
    if !rest.is_empty() {
        return None;
    }
    let (r, body) = der_tlv(body, 0x02)?;
    let (s, body) = der_tlv(body, 0x02)?;
    if !body.is_empty() || r.is_empty() || s.is_empty() || r[0] & 0x80 != 0 || s[0] & 0x80 != 0 {
        return None;
    }
    Some((r, s))
}

/// One DER value with tag `tag`: (contents, the rest).
fn der_tlv(b: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if b.len() < 2 || b[0] != tag {
        return None;
    }
    let (len, head): (usize, usize) = match b[1] {
        l if l < 0x80 => (usize::from(l), 2),
        0x81 if b.len() > 2 && b[2] >= 0x80 => (usize::from(b[2]), 3),
        _ => return None,
    };
    let end = head.checked_add(len)?;
    (b.len() >= end).then(|| (&b[head..end], &b[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HashAlg, hex};

    const MSG: &[u8] = b"ichor signs this";

    // Made with OpenSSL (`ecparam -genkey`, `dgst -sha256/-sha384 -sign`);
    // the points are the last bytes of the SubjectPublicKeyInfo.
    #[test]
    fn p256_sha256_openssl_signature() {
        let spki = hex(
            "3059301306072a8648ce3d020106082a8648ce3d0301070342000422a1912d316fe401b919a1524ea90966f2a3274fbda1594aacf293f6e7ff8098867ac123bfd092b580f9fa64e707c8d7c802cd6cc769b52559aa94e5da1de967",
        );
        let q = &spki[spki.len() - 65..];
        let sig = hex(
            "3045022022ff4358bc452bfb34ae6ca0958540f19da0119069a377b1e0faaba83498496c022100ed4e5bc798f07473ae16135b65d1253e2cb51c22df9275187a923dc117269943",
        );
        let d = HashAlg::Sha256.digest(MSG);
        assert!(verify_der(Curve::P256, q, &d, &sig));
        assert!(!verify_der(
            Curve::P256,
            q,
            &HashAlg::Sha256.digest(b"other"),
            &sig
        ));
        let mut bad = sig.clone();
        bad[10] ^= 1;
        assert!(!verify_der(Curve::P256, q, &d, &bad));
        let mut off = q.to_vec();
        off[40] ^= 1;
        assert!(
            !verify_der(Curve::P256, &off, &d, &sig),
            "a point off the curve"
        );
    }

    #[test]
    fn p384_sha384_openssl_signature() {
        let spki = hex(
            "3076301006072a8648ce3d020106052b810400220362000486c469c3ccb341715ab28becf47cbda30c5ff2cf3102aa9926148bba492dcd4768f3d39f24aff5a0c5e4bce0f4016452efd36ab54d61d21e1be924c922918ae6120e718969de8e7cfdfcbc0c8146728255c315c6996035d9a69b46e14d34c046",
        );
        let q = &spki[spki.len() - 97..];
        let sig = hex(
            "306402301a002bd3e3217474bd6aba0835dc2b257481e46ccde447ad9f8c762f385b2e7188fffc8e45d152bf26c116c25b04652a023054d90e3ba2c6d4ac9ab79a04e9a740043d636accc05f575fceed3dc05f06c920ea69ab58b8dca388ce3a7d104f70e0ba",
        );
        let d = HashAlg::Sha384.digest(MSG);
        assert!(verify_der(Curve::P384, q, &d, &sig));
        assert!(!verify_der(
            Curve::P384,
            q,
            &HashAlg::Sha384.digest(b"other"),
            &sig
        ));
        assert!(!verify_der(Curve::P256, q, &d, &sig), "the wrong curve");
    }

    #[test]
    fn base_points_are_on_their_curves_and_have_order_n() {
        for c in [Curve::P256, Curve::P384] {
            let ctx = Ctx::new(c).unwrap();
            assert!(ctx.on_curve(&ctx.g.x, &ctx.g.y), "{c:?}");
            let ng = ctx.mul(&ctx.s.n, &ctx.g);
            assert!(Ctx::is_zero(&ng.z), "{c:?}: n*G is not infinity");
            let n1 = ctx.s.n.sub(&Nat::from_u64(1)).unwrap();
            let p = ctx.mul(&n1, &ctx.g);
            assert_eq!(ctx.affine_x(&p), ctx.f.from(&ctx.g.x), "{c:?}: (n-1)G = -G");
        }
    }
}
