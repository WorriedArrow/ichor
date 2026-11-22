//! Key agreement on NIST P-256 (SEC 1, SP 800-56A). The scalar is a secret:
//! unlike [`crate::ecdsa`]'s arithmetic, which only sees public values, this
//! takes the same steps whatever it is (complete addition formulas, every
//! bit the same work, masks instead of branches).

/// The field's prime and the curve's `b`, little-endian limbs.
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0,
    0xffff_ffff_0000_0001,
];
const B: [u64; 4] = [
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
];
/// The base point.
const GX: [u64; 4] = [
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
];
const GY: [u64; 4] = [
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
];
/// 2^512 modulo the prime: into Montgomery form.
const R2: [u64; 4] = [
    0x0000_0000_0000_0003,
    0xffff_fffb_ffff_ffff,
    0xffff_ffff_ffff_fffe,
    0x0000_0004_ffff_fffd,
];

/// A field element in Montgomery form, less than the prime.
#[derive(Clone, Copy)]
struct Fe([u64; 4]);

/// `a - b`, and all ones if that borrowed.
fn sub4(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let t = u128::from(a[i])
            .wrapping_sub(u128::from(b[i]))
            .wrapping_sub(u128::from(borrow));
        out[i] = t as u64;
        borrow = (t >> 64) as u64 & 1;
    }
    (out, borrow.wrapping_neg())
}

/// `a + b`, and the carry.
fn add4(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let t = u128::from(a[i]) + u128::from(b[i]) + u128::from(carry);
        out[i] = t as u64;
        carry = (t >> 64) as u64;
    }
    (out, carry)
}

/// `a` where `mask` is all ones, `b` where it is zero.
fn select4(mask: u64, a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = (a[i] & mask) | (b[i] & !mask);
    }
    out
}

/// `(high, a)` less the prime once if it is not less than it.
fn reduce(a: [u64; 4], high: u64) -> Fe {
    let (less, borrow) = sub4(a, P);
    // Below the prime: it borrowed, and there was nothing above.
    Fe(select4(borrow & high.wrapping_sub(1), a, less))
}

impl Fe {
    const ZERO: Fe = Fe([0; 4]);

    /// `None` if the bytes (big-endian) are not less than the prime.
    fn from_bytes(b: &[u8; 32]) -> Option<Fe> {
        let mut limbs = [0u64; 4];
        for (l, c) in limbs.iter_mut().rev().zip(b.as_chunks::<8>().0) {
            *l = u64::from_be_bytes(*c);
        }
        let (_, borrow) = sub4(limbs, P);
        (borrow != 0).then(|| Fe::from_limbs(limbs))
    }

    fn from_limbs(l: [u64; 4]) -> Fe {
        Fe(l).mul(Fe(R2))
    }

    fn one() -> Fe {
        Fe::from_limbs([1, 0, 0, 0])
    }

    fn to_bytes(self) -> [u8; 32] {
        let plain = self.mul(Fe([1, 0, 0, 0]));
        let mut b = [0u8; 32];
        for (c, l) in b
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(plain.0.iter().rev())
        {
            *c = l.to_be_bytes();
        }
        b
    }

    fn add(self, o: Fe) -> Fe {
        let (sum, carry) = add4(self.0, o.0);
        reduce(sum, carry)
    }

    fn sub(self, o: Fe) -> Fe {
        let (d, borrow) = sub4(self.0, o.0);
        Fe(add4(d, select4(borrow, P, [0; 4])).0)
    }

    /// Montgomery multiplication, by 64-bit words. The prime's low word is
    /// all ones, so each word's multiplier is the word itself.
    fn mul(self, o: Fe) -> Fe {
        let mut t = [0u64; 6];
        for &a in &self.0 {
            let mut carry = 0u64;
            for (t, &b) in t.iter_mut().zip(&o.0) {
                let v = u128::from(a) * u128::from(b) + u128::from(*t) + u128::from(carry);
                *t = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(t[4]) + u128::from(carry);
            t[4] = v as u64;
            t[5] = (v >> 64) as u64;

            let m = t[0];
            let v = u128::from(m) * u128::from(P[0]) + u128::from(t[0]);
            let mut carry = (v >> 64) as u64;
            for j in 1..4 {
                let v = u128::from(m) * u128::from(P[j]) + u128::from(t[j]) + u128::from(carry);
                t[j - 1] = v as u64;
                carry = (v >> 64) as u64;
            }
            let v = u128::from(t[4]) + u128::from(carry);
            t[3] = v as u64;
            t[4] = t[5] + (v >> 64) as u64;
        }
        reduce([t[0], t[1], t[2], t[3]], t[4])
    }

    /// The inverse (of zero: zero), by Fermat.
    fn invert(self) -> Fe {
        let (e, _) = sub4(P, [2, 0, 0, 0]);
        let mut r = Fe::one();
        for i in (0..256).rev() {
            r = r.mul(r);
            // (The exponent is public.)
            if e[i / 64] >> (i % 64) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    fn eq(self, o: Fe) -> bool {
        let d = self.0.iter().zip(&o.0).fold(0, |d, (a, b)| d | (a ^ b));
        d == 0
    }
}

/// A point in projective coordinates; infinity is (0 : 1 : 0).
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    fn infinity() -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::one(),
            z: Fe::ZERO,
        }
    }

    fn base() -> Point {
        Point {
            x: Fe::from_limbs(GX),
            y: Fe::from_limbs(GY),
            z: Fe::one(),
        }
    }

    /// A point from its affine coordinates, if they are the curve's.
    fn affine(x: Fe, y: Fe) -> Option<Point> {
        let three_x = x.add(x).add(x);
        let right = x.mul(x).mul(x).sub(three_x).add(Fe::from_limbs(B));
        y.mul(y).eq(right).then(|| Point { x, y, z: Fe::one() })
    }

    /// The sum, whatever the points are: Renes, Costello and Batina's
    /// algorithm 4 ("Complete addition formulas for prime order elliptic
    /// curves"), for a = -3.
    fn add(&self, q: &Point, b: Fe) -> Point {
        let mut t0 = self.x.mul(q.x);
        let mut t1 = self.y.mul(q.y);
        let mut t2 = self.z.mul(q.z);
        let mut t3 = self.x.add(self.y).mul(q.x.add(q.y));
        t3 = t3.sub(t0.add(t1));
        let mut t4 = self.y.add(self.z).mul(q.y.add(q.z));
        t4 = t4.sub(t1.add(t2));
        let mut y3 = self.x.add(self.z).mul(q.x.add(q.z));
        y3 = y3.sub(t0.add(t2));
        let mut z3 = b.mul(t2);
        let mut x3 = y3.sub(z3);
        z3 = x3.add(x3);
        x3 = x3.add(z3);
        z3 = t1.sub(x3);
        x3 = t1.add(x3);
        y3 = b.mul(y3);
        t1 = t2.add(t2);
        t2 = t1.add(t2);
        y3 = y3.sub(t2).sub(t0);
        t1 = y3.add(y3);
        y3 = t1.add(y3);
        t1 = t0.add(t0);
        t0 = t1.add(t0).sub(t2);
        t1 = t4.mul(y3);
        t2 = t0.mul(y3);
        y3 = x3.mul(z3).add(t2);
        x3 = t3.mul(x3).sub(t1);
        z3 = t4.mul(z3).add(t3.mul(t0));
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// `k` times the point (`k` big-endian), in the same steps whatever
    /// `k` is.
    fn mul(&self, k: &[u8; 32]) -> Point {
        let b = Fe::from_limbs(B);
        let mut acc = Point::infinity();
        for i in 0..256 {
            acc = acc.add(&acc, b);
            let with = acc.add(self, b);
            let bit = u64::from(k[i / 8] >> (7 - i % 8) & 1);
            let mask = bit.wrapping_neg();
            acc = Point {
                x: Fe(select4(mask, with.x.0, acc.x.0)),
                y: Fe(select4(mask, with.y.0, acc.y.0)),
                z: Fe(select4(mask, with.z.0, acc.z.0)),
            };
        }
        acc
    }

    fn to_affine(self) -> (Fe, Fe) {
        let zi = self.z.invert();
        (self.x.mul(zi), self.y.mul(zi))
    }
}

/// A public key: `04 || x || y`.
pub const PUBLIC: usize = 65;

/// The scalar for 32 random bytes: less than the group's order (its top
/// bit is clear) and not zero, at the cost of two bits of the 256.
fn scalar(secret: &[u8; 32]) -> [u8; 32] {
    let mut k = *secret;
    k[0] &= 0x7f;
    k[31] |= 1;
    k
}

/// The public key of the secret that 32 random bytes are.
pub fn public_key(secret: &[u8; 32]) -> [u8; PUBLIC] {
    let (x, y) = Point::base().mul(&scalar(secret)).to_affine();
    let mut out = [4u8; PUBLIC];
    out[1..33].copy_from_slice(&x.to_bytes());
    out[33..].copy_from_slice(&y.to_bytes());
    out
}

/// The shared secret with a peer's public key; `None` if that is not a
/// point of the curve.
pub fn agree(secret: &[u8; 32], public: &[u8]) -> Option<[u8; 32]> {
    multiply(&scalar(secret), public)
}

fn multiply(k: &[u8; 32], public: &[u8]) -> Option<[u8; 32]> {
    let [4, coordinates @ ..] = public else {
        return None;
    };
    let ([x, y], []) = coordinates.as_chunks::<32>() else {
        return None;
    };
    let q = Point::affine(Fe::from_bytes(x)?, Fe::from_bytes(y)?)?;
    // The group has prime order and the scalar is neither zero nor its
    // multiple: never infinity.
    Some(q.mul(k).to_affine().0.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn key(s: &str) -> [u8; 32] {
        hex(s).as_slice().try_into().unwrap()
    }

    fn point(x: &str, y: &str) -> [u8; PUBLIC] {
        let mut p = [4u8; PUBLIC];
        p[1..33].copy_from_slice(&hex(x));
        p[33..].copy_from_slice(&hex(y));
        p
    }

    /// NIST CAVS, ECC CDH primitive, P-256, count 0.
    #[test]
    fn nist_vector() {
        let d = key("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534");
        let peer = point(
            "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
            "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
        );
        let z = key("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b");
        assert_eq!(multiply(&d, &peer), Some(z));
        let (x, y) = Point::base().mul(&d).to_affine();
        assert_eq!(
            x.to_bytes(),
            key("ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230")
        );
        assert_eq!(
            y.to_bytes(),
            key("28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141")
        );
    }

    #[test]
    fn both_sides_agree() {
        let mut seed = 1u64;
        for _ in 0..8 {
            let mut random = [[0u8; 32]; 2];
            for b in random.as_flattened_mut() {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
            let [a, b] = random;
            let shared = agree(&a, &public_key(&b));
            assert!(shared.is_some());
            assert_eq!(shared, agree(&b, &public_key(&a)));
        }
    }

    /// Scalars around the group's order: what completes the addition
    /// formulas (doubling, a point and its negative, infinity) is right.
    #[test]
    fn the_edges_of_the_group() {
        let g = Point::base();
        let order = key("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let at_order = g.mul(&order);
        assert!(at_order.z.eq(Fe::ZERO));
        let mut k = order;
        k[31] -= 1; // n - 1: minus the base point
        let (x, y) = g.mul(&k).to_affine();
        assert!(x.eq(Fe::from_limbs(GX)));
        assert!(y.add(Fe::from_limbs(GY)).eq(Fe::ZERO));
        k[31] += 2; // n + 1
        let (x, y) = g.mul(&k).to_affine();
        assert!(x.eq(Fe::from_limbs(GX)) && y.eq(Fe::from_limbs(GY)));
        assert!(g.mul(&[0; 32]).z.eq(Fe::ZERO));
    }

    #[test]
    fn refuses_what_is_not_a_point() {
        let good = public_key(&[9; 32]);
        assert!(agree(&[3; 32], &good).is_some());
        for i in [1, 20, 64] {
            let mut bad = good;
            bad[i] ^= 1;
            assert_eq!(agree(&[3; 32], &bad), None);
        }
        let mut bad = good;
        bad[0] = 3;
        assert_eq!(agree(&[3; 32], &bad), None);
        assert_eq!(agree(&[3; 32], &good[..64]), None);
        // The x coordinate plus the prime is not reduced.
        let big = point(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4",
        );
        assert_eq!(agree(&[3; 32], &big), None);
        assert_eq!(agree(&[3; 32], &[4; PUBLIC]), None);
    }

    #[test]
    fn field_arithmetic() {
        // R2 is what it says: 2^512 reduced is 2^256 in Montgomery form.
        let two = Fe::from_limbs([2, 0, 0, 0]);
        let mut x = Fe::one();
        for _ in 0..256 {
            x = x.mul(two);
        }
        let mut shifted = Fe::one();
        for _ in 0..256 {
            shifted = shifted.add(shifted);
        }
        assert!(x.eq(shifted));
        let minus_one = Fe::ZERO.sub(Fe::one());
        assert!(minus_one.mul(minus_one).eq(Fe::one()));
        assert!(minus_one.add(Fe::one()).eq(Fe::ZERO));
        assert!(minus_one.add(minus_one).eq(Fe::ZERO.sub(two)));
        assert!(minus_one.invert().eq(minus_one));
        assert_eq!(two.to_bytes()[31], 2);
    }
}
