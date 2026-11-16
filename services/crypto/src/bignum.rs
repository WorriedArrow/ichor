//! Arbitrary-precision unsigned integers for signature *verification*:
//! Montgomery arithmetic modulo an odd modulus (RSA moduli, the NIST curve
//! primes and orders). Everything here handles public data only, so it is
//! written for clarity, not for constant time.

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// A natural number, little-endian 64-bit limbs, no trailing zero limbs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nat(pub(crate) Vec<u64>);

impl Nat {
    pub fn zero() -> Nat {
        Nat(Vec::new())
    }

    pub fn from_u64(v: u64) -> Nat {
        Nat(vec![v]).norm()
    }

    fn norm(mut self) -> Nat {
        while self.0.last() == Some(&0) {
            self.0.pop();
        }
        self
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    /// From big-endian bytes (leading zeros allowed).
    pub fn from_be(b: &[u8]) -> Nat {
        let mut limbs = Vec::with_capacity(b.len().div_ceil(8));
        for chunk in b.rchunks(8) {
            let mut w = [0u8; 8];
            w[8 - chunk.len()..].copy_from_slice(chunk);
            limbs.push(u64::from_be_bytes(w));
        }
        Nat(limbs).norm()
    }

    /// Big-endian bytes, left-padded to `len`; `None` if it does not fit.
    pub fn to_be(&self, len: usize) -> Option<Vec<u8>> {
        let mut out = vec![0u8; len];
        for (i, limb) in self.0.iter().enumerate() {
            for (j, byte) in limb.to_le_bytes().into_iter().enumerate() {
                let pos = i * 8 + j;
                if pos < len {
                    out[len - 1 - pos] = byte;
                } else if byte != 0 {
                    return None;
                }
            }
        }
        Some(out)
    }

    pub fn bits(&self) -> usize {
        match self.0.last() {
            None => 0,
            Some(&top) => self.0.len() * 64 - top.leading_zeros() as usize,
        }
    }

    pub fn bit(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|l| (l >> (i % 64)) & 1 == 1)
    }

    pub fn is_odd(&self) -> bool {
        self.bit(0)
    }

    pub fn add(&self, o: &Nat) -> Nat {
        let n = self.0.len().max(o.0.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u128;
        for i in 0..n {
            let s = u128::from(*self.0.get(i).unwrap_or(&0))
                + u128::from(*o.0.get(i).unwrap_or(&0))
                + carry;
            out.push(s as u64);
            carry = s >> 64;
        }
        out.push(carry as u64);
        Nat(out).norm()
    }

    /// `self - o`; `self >= o` is required (`None` otherwise).
    pub fn sub(&self, o: &Nat) -> Option<Nat> {
        if self.cmp(o) == Ordering::Less {
            return None;
        }
        let mut out = Vec::with_capacity(self.0.len());
        let mut borrow = 0u64;
        for (i, &a) in self.0.iter().enumerate() {
            let (d1, b1) = a.overflowing_sub(*o.0.get(i).unwrap_or(&0));
            let (d2, b2) = d1.overflowing_sub(borrow);
            out.push(d2);
            borrow = u64::from(b1 || b2);
        }
        Some(Nat(out).norm())
    }

    /// `self mod m` by shift-and-subtract (for inputs a few bits longer
    /// than `m`, such as hashes and coordinates).
    pub fn rem(&self, m: &Nat) -> Nat {
        if m.is_zero() {
            return Nat::zero();
        }
        let mut r = Nat::zero();
        for i in (0..self.bits()).rev() {
            r = r.add(&r);
            if self.bit(i) {
                r = r.add(&Nat::from_u64(1));
            }
            if let Some(d) = r.sub(m) {
                r = d;
            }
        }
        r
    }
}

impl Ord for Nat {
    fn cmp(&self, o: &Nat) -> Ordering {
        self.0
            .len()
            .cmp(&o.0.len())
            .then_with(|| self.0.iter().rev().cmp(o.0.iter().rev()))
    }
}

impl PartialOrd for Nat {
    fn partial_cmp(&self, o: &Nat) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// Montgomery arithmetic modulo an odd `n`.
#[derive(Clone, Debug)]
pub struct Mont {
    pub n: Nat,
    k: usize,
    n0inv: u64,
    r2: Vec<u64>,
}

impl Mont {
    /// `None` for an even or zero modulus.
    pub fn new(n: &Nat) -> Option<Mont> {
        if !n.is_odd() {
            return None;
        }
        let k = n.0.len();
        // -n^-1 mod 2^64 by Newton's iteration.
        let mut inv = 1u64;
        for _ in 0..7 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n.0[0].wrapping_mul(inv)));
        }
        let n0inv = inv.wrapping_neg();
        // R^2 mod n, by doubling 1 2 * 64k times.
        let mut r = Nat::from_u64(1);
        for _ in 0..2 * 64 * k {
            r = r.add(&r);
            if let Some(d) = r.sub(n) {
                r = d;
            }
        }
        let mut r2 = r.0;
        r2.resize(k, 0);
        Some(Mont {
            n: n.clone(),
            k,
            n0inv,
            r2,
        })
    }

    fn limbs(&self, a: &Nat) -> Vec<u64> {
        let mut v = a.rem(&self.n).0;
        v.resize(self.k, 0);
        v
    }

    /// Montgomery product `a * b / R mod n` (CIOS).
    fn mul_limbs(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let k = self.k;
        let n = &self.n.0;
        let mut t = vec![0u64; k + 2];
        for &bi in b.iter().take(k) {
            let mut carry = 0u128;
            for j in 0..k {
                let s = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + carry;
                t[j] = s as u64;
                carry = s >> 64;
            }
            let s = u128::from(t[k]) + carry;
            t[k] = s as u64;
            t[k + 1] = (s >> 64) as u64;
            let m = t[0].wrapping_mul(self.n0inv);
            let s = u128::from(t[0]) + u128::from(m) * u128::from(n[0]);
            let mut carry = s >> 64;
            for j in 1..k {
                let s = u128::from(t[j]) + u128::from(m) * u128::from(n[j]) + carry;
                t[j - 1] = s as u64;
                carry = s >> 64;
            }
            let s = u128::from(t[k]) + carry;
            t[k - 1] = s as u64;
            t[k] = t[k + 1] + (s >> 64) as u64;
            t[k + 1] = 0;
        }
        let mut res = Nat(t).norm();
        if let Some(d) = res.sub(&self.n) {
            res = d;
        }
        let mut v = res.0;
        v.resize(k, 0);
        v
    }

    /// Into Montgomery form.
    pub fn to(&self, a: &Nat) -> Vec<u64> {
        self.mul_limbs(&self.limbs(a), &self.r2)
    }

    /// Out of Montgomery form.
    pub fn from(&self, a: &[u64]) -> Nat {
        let mut one = vec![0u64; self.k];
        one[0] = 1;
        Nat(self.mul_limbs(a, &one)).norm()
    }

    pub fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        self.mul_limbs(a, b)
    }

    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let s = Nat(a.to_vec()).norm().add(&Nat(b.to_vec()).norm());
        let s = s.sub(&self.n).unwrap_or(s);
        let mut v = s.0;
        v.resize(self.k, 0);
        v
    }

    pub fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let (a, b) = (Nat(a.to_vec()).norm(), Nat(b.to_vec()).norm());
        let d = match a.sub(&b) {
            Some(d) => d,
            None => a.add(&self.n).sub(&b).unwrap_or_else(Nat::zero),
        };
        let mut v = d.0;
        v.resize(self.k, 0);
        v
    }

    /// `base^exp mod n` (plain numbers in and out).
    pub fn pow(&self, base: &Nat, exp: &Nat) -> Nat {
        let b = self.to(base);
        let mut acc = self.to(&Nat::from_u64(1));
        for i in (0..exp.bits()).rev() {
            acc = self.mul(&acc, &acc);
            if exp.bit(i) {
                acc = self.mul(&acc, &b);
            }
        }
        self.from(&acc)
    }

    /// The inverse modulo a prime `n` (Fermat), in Montgomery form.
    pub fn inv(&self, a: &[u64]) -> Vec<u64> {
        let e = self.n.sub(&Nat::from_u64(2)).unwrap_or_else(Nat::zero);
        let plain = self.from(a);
        self.to(&self.pow(&plain, &e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip() {
        let b = [0u8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let n = Nat::from_be(&b);
        assert_eq!(n.to_be(12).unwrap(), b);
        assert_eq!(n.to_be(10).unwrap(), &b[2..]);
        assert!(n.to_be(9).is_none());
        assert_eq!(n.bits(), 73);
    }

    #[test]
    fn modular_exponentiation() {
        // 4^13 mod 497 = 445 (a textbook example), and Fermat's little
        // theorem for a 127-bit Mersenne prime.
        let m = Mont::new(&Nat::from_u64(497)).unwrap();
        assert_eq!(
            m.pow(&Nat::from_u64(4), &Nat::from_u64(13)),
            Nat::from_u64(445)
        );
        let p = Nat::from_be(&((1u128 << 127) - 1).to_be_bytes());
        let mp = Mont::new(&p).unwrap();
        let a = Nat::from_u64(0x1234_5678_9abc_def1);
        let e = p.sub(&Nat::from_u64(1)).unwrap();
        assert_eq!(mp.pow(&a, &e), Nat::from_u64(1));
        let ai = mp.inv(&mp.to(&a));
        assert_eq!(mp.from(&mp.mul(&ai, &mp.to(&a))), Nat::from_u64(1));
    }

    #[test]
    fn add_sub_wrap() {
        let m = Mont::new(&Nat::from_u64(101)).unwrap();
        let (a, b) = (m.to(&Nat::from_u64(70)), m.to(&Nat::from_u64(50)));
        assert_eq!(m.from(&m.add(&a, &b)), Nat::from_u64(19));
        assert_eq!(m.from(&m.sub(&b, &a)), Nat::from_u64(81));
    }
}
