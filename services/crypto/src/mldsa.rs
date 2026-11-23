//! ML-DSA signature verification (FIPS 204), the three parameter sets, as
//! certificates carry them (RFC 9881: pure ML-DSA, an empty context).
//! Verification only: every value it handles is public.

use alloc::vec;
use alloc::vec::Vec;

use crate::sha3::{Sponge, shake256};

const Q: i64 = 8_380_417;
const N: usize = 256;
const D: u32 = 13;

/// A parameter set (FIPS 204 table 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    k: usize,
    l: usize,
    tau: usize,
    gamma1: i64,
    gamma2: i64,
    beta: i64,
    omega: usize,
    /// The commitment hash's length, λ/4 bytes.
    c_len: usize,
}

pub const ML_DSA_44: Params = Params {
    k: 4,
    l: 4,
    tau: 39,
    gamma1: 1 << 17,
    gamma2: (Q - 1) / 88,
    beta: 78,
    omega: 80,
    c_len: 32,
};

pub const ML_DSA_65: Params = Params {
    k: 6,
    l: 5,
    tau: 49,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    beta: 196,
    omega: 55,
    c_len: 48,
};

pub const ML_DSA_87: Params = Params {
    k: 8,
    l: 7,
    tau: 60,
    gamma1: 1 << 19,
    gamma2: (Q - 1) / 32,
    beta: 120,
    omega: 75,
    c_len: 64,
};

type Poly = [i64; N];

impl Params {
    /// Bits per coefficient of z (1 + log2 γ1).
    fn z_bits(&self) -> usize {
        1 + self.gamma1.trailing_zeros() as usize
    }

    /// Bits per coefficient of w1 (bitlen((q-1)/(2γ2) - 1)).
    fn w1_bits(&self) -> usize {
        let m = (Q - 1) / (2 * self.gamma2) - 1;
        64 - m.leading_zeros() as usize
    }

    pub fn public_key_len(&self) -> usize {
        32 + self.k * 320
    }

    pub fn signature_len(&self) -> usize {
        self.c_len + self.l * 32 * self.z_bits() + self.omega + self.k
    }
}

/// The NTT's twiddle factors: ζ^brv8(i), ζ = 1753.
fn zetas() -> [i64; N] {
    let mut z = [0i64; N];
    for (i, zi) in z.iter_mut().enumerate() {
        let e = (i as u8).reverse_bits();
        let mut r = 1i64;
        for _ in 0..e {
            r = r * 1753 % Q;
        }
        *zi = r;
    }
    z
}

/// FIPS 204 algorithm 41.
fn ntt(w: &mut Poly, zetas: &[i64; N]) {
    let (mut m, mut len) = (0, 128);
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            let z = zetas[m];
            for j in start..start + len {
                let t = z * w[j + len] % Q;
                w[j + len] = (w[j] - t).rem_euclid(Q);
                w[j] = (w[j] + t) % Q;
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// FIPS 204 algorithm 42.
fn inverse_ntt(w: &mut Poly, zetas: &[i64; N]) {
    let (mut m, mut len) = (N, 1);
    while len < N {
        let mut start = 0;
        while start < N {
            m -= 1;
            let z = Q - zetas[m];
            for j in start..start + len {
                let t = w[j];
                w[j] = (t + w[j + len]) % Q;
                w[j + len] = z * (t - w[j + len]).rem_euclid(Q) % Q;
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in w.iter_mut() {
        *c = *c * 8_347_681 % Q;
    }
}

/// Coefficients of `bits` bits each, little-endian, from `b`.
fn unpack(b: &[u8], bits: usize) -> Poly {
    let mut p = [0i64; N];
    for (i, c) in p.iter_mut().enumerate() {
        let mut v = 0i64;
        for j in 0..bits {
            let at = i * bits + j;
            v |= i64::from(b[at / 8] >> (at % 8) & 1) << j;
        }
        *c = v;
    }
    p
}

/// `p`'s coefficients, `bits` bits each, little-endian.
fn pack(p: &Poly, bits: usize, out: &mut Vec<u8>) {
    let start = out.len();
    out.resize(start + N * bits / 8, 0);
    for (i, &c) in p.iter().enumerate() {
        for j in 0..bits {
            let at = i * bits + j;
            out[start + at / 8] |= (((c >> j) & 1) as u8) << (at % 8);
        }
    }
}

/// RejNTTPoly (algorithm 30): uniform coefficients mod q from SHAKE128.
fn rej_ntt_poly(seed: &[u8]) -> Poly {
    let mut s = Sponge::shake128();
    s.absorb(seed);
    let mut p = [0i64; N];
    let mut i = 0;
    let mut b = [0u8; 3];
    while i < N {
        s.squeeze(&mut b);
        let z = i64::from(b[2] & 0x7f) << 16 | i64::from(b[1]) << 8 | i64::from(b[0]);
        if z < Q {
            p[i] = z;
            i += 1;
        }
    }
    p
}

/// SampleInBall (algorithm 29): τ coefficients ±1, the rest 0.
fn sample_in_ball(c_tilde: &[u8], tau: usize) -> Poly {
    let mut s = Sponge::shake256();
    s.absorb(c_tilde);
    let mut signs = [0u8; 8];
    s.squeeze(&mut signs);
    let signs = u64::from_le_bytes(signs);
    let mut c = [0i64; N];
    for i in N - tau..N {
        let mut j = [0u8; 1];
        loop {
            s.squeeze(&mut j);
            if usize::from(j[0]) <= i {
                break;
            }
        }
        let j = usize::from(j[0]);
        c[i] = c[j];
        c[j] = if signs >> (i + tau - N) & 1 == 1 {
            Q - 1
        } else {
            1
        };
    }
    c
}

/// HintBitUnpack (algorithm 21); `None` if malformed.
fn hints(y: &[u8], p: &Params) -> Option<Vec<[bool; N]>> {
    let mut h = vec![[false; N]; p.k];
    let mut index = 0usize;
    for (i, hi) in h.iter_mut().enumerate() {
        let end = usize::from(y[p.omega + i]);
        if end < index || end > p.omega {
            return None;
        }
        let first = index;
        while index < end {
            if index > first && y[index - 1] >= y[index] {
                return None;
            }
            hi[usize::from(y[index])] = true;
            index += 1;
        }
    }
    y[index..p.omega].iter().all(|&b| b == 0).then_some(h)
}

/// UseHint (algorithm 40) on a coefficient in [0, q).
fn use_hint(hint: bool, r: i64, gamma2: i64) -> i64 {
    let m = (Q - 1) / (2 * gamma2);
    // Decompose (algorithm 36).
    let mut r0 = r % (2 * gamma2);
    if r0 > gamma2 {
        r0 -= 2 * gamma2;
    }
    let (r1, r0) = if r - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / (2 * gamma2), r0)
    };
    match (hint, r0 > 0) {
        (false, _) => r1,
        (true, true) => (r1 + 1).rem_euclid(m),
        (true, false) => (r1 - 1).rem_euclid(m),
    }
}

/// Verifies `sig` over `msg` with public key `pk` (ML-DSA.Verify with an
/// empty context, as certificates use it: RFC 9881).
pub fn verify(p: &Params, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_with_context(p, pk, msg, &[], sig)
}

/// Verifies `sig` over `msg` and the context string `ctx` (at most 255
/// bytes) with public key `pk` (ML-DSA.Verify, FIPS 204 algorithms 3 and
/// 8). A key or signature of the wrong length, or a longer context, is
/// refused.
pub fn verify_with_context(p: &Params, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(ctx_len) = u8::try_from(ctx.len()) else {
        return false;
    };
    if pk.len() != p.public_key_len() || sig.len() != p.signature_len() {
        return false;
    }
    let zetas = zetas();
    let (rho, t1_bytes) = pk.split_at(32);
    let (c_tilde, rest) = sig.split_at(p.c_len);
    let z_len = 32 * p.z_bits();
    let (z_bytes, h_bytes) = rest.split_at(p.l * z_len);
    let Some(h) = hints(h_bytes, p) else {
        return false;
    };
    // z, with its norm checked: ||z||∞ < γ1 - β.
    let mut z: Vec<Poly> = Vec::with_capacity(p.l);
    for chunk in z_bytes.chunks(z_len) {
        let mut zi = unpack(chunk, p.z_bits());
        for c in zi.iter_mut() {
            let v = p.gamma1 - *c;
            if v.abs() >= p.gamma1 - p.beta {
                return false;
            }
            *c = v.rem_euclid(Q);
        }
        ntt(&mut zi, &zetas);
        z.push(zi);
    }
    let tr = shake256(&[pk], 64);
    // M' = 0 (pure), the context's length, the context, the message.
    let mu = shake256(&[&tr, &[0, ctx_len], ctx, msg], 64);
    let mut c = sample_in_ball(c_tilde, p.tau);
    ntt(&mut c, &zetas);
    let mut w1 = Vec::with_capacity(p.k * N * p.w1_bits() / 8);
    for (r, t1_chunk) in t1_bytes.chunks(320).enumerate() {
        // A z - c t1 2^d, in the NTT domain.
        let mut t1 = unpack(t1_chunk, 10);
        for v in t1.iter_mut() {
            *v <<= D;
        }
        ntt(&mut t1, &zetas);
        let mut w = [0i64; N];
        for (s, zs) in z.iter().enumerate() {
            let a = rej_ntt_poly(&[rho, &[s as u8, r as u8]].concat());
            for i in 0..N {
                w[i] = (w[i] + a[i] * zs[i]) % Q;
            }
        }
        for i in 0..N {
            w[i] = (w[i] - c[i] * t1[i] % Q).rem_euclid(Q);
        }
        inverse_ntt(&mut w, &zetas);
        let mut w1_r = [0i64; N];
        for i in 0..N {
            w1_r[i] = use_hint(h[r][i], w[i], p.gamma2);
        }
        pack(&w1_r, p.w1_bits(), &mut w1);
    }
    let c_check = shake256(&[&mu, &w1], p.c_len);
    c_check == c_tilde
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &[u8] = b"Ichor checks ML-DSA signatures on certificates.";

    fn vector(text: &str) -> (Vec<u8>, Vec<u8>) {
        let field = |name: &str| -> Vec<u8> {
            let hex = text
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .unwrap()
                .trim();
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        };
        (field("pk "), field("sig "))
    }

    #[test]
    fn sizes_match_fips_204() {
        assert_eq!(
            (ML_DSA_44.public_key_len(), ML_DSA_44.signature_len()),
            (1312, 2420)
        );
        assert_eq!(
            (ML_DSA_65.public_key_len(), ML_DSA_65.signature_len()),
            (1952, 3309)
        );
        assert_eq!(
            (ML_DSA_87.public_key_len(), ML_DSA_87.signature_len()),
            (2592, 4627)
        );
    }

    #[test]
    fn the_ntt_inverts() {
        let z = zetas();
        let mut p = [0i64; N];
        for (i, c) in p.iter_mut().enumerate() {
            *c = (i as i64 * 7919 + 3) % Q;
        }
        let orig = p;
        ntt(&mut p, &z);
        assert_ne!(p, orig);
        inverse_ntt(&mut p, &z);
        assert_eq!(p, orig);
    }

    /// Signatures OpenSSL 3.5.2 made, and the same with a bit flipped in
    /// the signature, the message or the key.
    #[test]
    fn openssl_signatures_verify() {
        for (p, text) in [
            (ML_DSA_44, include_str!("../testdata/mldsa-44.txt")),
            (ML_DSA_65, include_str!("../testdata/mldsa-65.txt")),
            (ML_DSA_87, include_str!("../testdata/mldsa-87.txt")),
        ] {
            let (pk, sig) = vector(text);
            assert!(verify(&p, &pk, MSG, &sig), "{p:?}");
            let mut bad = sig.clone();
            bad[p.c_len + 5] ^= 1;
            assert!(!verify(&p, &pk, MSG, &bad));
            let mut bad = sig.clone();
            bad[0] ^= 0x80;
            assert!(!verify(&p, &pk, MSG, &bad));
            assert!(!verify(
                &p,
                &pk,
                b"Ichor checks ML-DSA signatures on certificates!",
                &sig
            ));
            let mut bad = pk.clone();
            bad[40] ^= 4;
            assert!(!verify(&p, &bad, MSG, &sig));
            assert!(!verify(&p, &pk, MSG, &sig[1..]));
        }
    }
}
