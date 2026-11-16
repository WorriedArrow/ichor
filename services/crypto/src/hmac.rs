//! HMAC (RFC 2104), HKDF (RFC 5869) and the TLS 1.2 PRF (RFC 5246 §5).

use alloc::vec::Vec;

use crate::sha2::Digest;

/// An HMAC computation keyed once.
#[derive(Clone, Debug)]
pub struct Hmac<D: Digest> {
    inner: D,
    outer: D,
}

impl<D: Digest> Hmac<D> {
    pub fn new(key: &[u8]) -> Self {
        let mut k = alloc::vec![0u8; D::BLOCK];
        if key.len() > D::BLOCK {
            let h = D::digest(key);
            k[..h.len()].copy_from_slice(&h);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = D::default();
        let mut outer = D::default();
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        inner.update(&ipad);
        outer.update(&opad);
        Hmac { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(self) -> Vec<u8> {
        let ih = self.inner.finish_vec();
        let mut o = self.outer;
        o.update(&ih);
        o.finish_vec()
    }

    /// HMAC of `data` under `key`.
    pub fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut h = Self::new(key);
        h.update(data);
        h.finish()
    }
}

/// HKDF-Extract.
pub fn hkdf_extract<D: Digest>(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let zeros = alloc::vec![0u8; D::LEN];
    let salt = if salt.is_empty() { &zeros[..] } else { salt };
    Hmac::<D>::mac(salt, ikm)
}

/// HKDF-Expand: `len` bytes (at most 255 hash lengths).
pub fn hkdf_expand<D: Digest>(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut h = Hmac::<D>::new(prk);
        h.update(&t);
        h.update(info);
        h.update(&[i]);
        t = h.finish();
        let take = (len - out.len()).min(t.len());
        out.extend_from_slice(&t[..take]);
        i = i.wrapping_add(1);
    }
    out
}

/// The TLS 1.2 PRF with hash `D`: `len` bytes of P_hash(secret, label + seed).
pub fn tls12_prf<D: Digest>(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut ls = Vec::with_capacity(label.len() + seed.len());
    ls.extend_from_slice(label);
    ls.extend_from_slice(seed);
    let mut out = Vec::with_capacity(len);
    let mut a = Hmac::<D>::mac(secret, &ls);
    while out.len() < len {
        let mut h = Hmac::<D>::new(secret);
        h.update(&a);
        h.update(&ls);
        let p = h.finish();
        let take = (len - out.len()).min(p.len());
        out.extend_from_slice(&p[..take]);
        a = Hmac::<D>::mac(secret, &a);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;
    use crate::sha2::{Sha256, Sha384, Sha512};

    #[test]
    fn hmac_rfc4231_case_2() {
        let (k, d) = (b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            Hmac::<Sha256>::mac(k, d),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        assert_eq!(
            Hmac::<Sha384>::mac(k, d),
            hex(
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
            )
        );
        assert_eq!(
            Hmac::<Sha512>::mac(k, d),
            hex(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            )
        );
    }

    #[test]
    fn hmac_long_key_is_hashed() {
        // RFC 4231 case 6: a 131-byte key.
        let key = [0xaa; 131];
        assert_eq!(
            Hmac::<Sha256>::mac(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            ),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract::<Sha256>(&salt, &ikm);
        assert_eq!(
            prk,
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        assert_eq!(
            hkdf_expand::<Sha256>(&prk, &info, 42),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn tls12_prf_sha256() {
        let out = tls12_prf::<Sha256>(
            &hex("9bbe436ba940f017b17652849a71db35"),
            b"test label",
            &hex("a0ba9f936cda311827a6f796ffd5198c"),
            100,
        );
        assert_eq!(
            out,
            hex(
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
            )
        );
    }
}
