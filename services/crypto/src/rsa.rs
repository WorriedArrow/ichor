//! RSA signature verification (RFC 8017): RSASSA-PKCS1-v1_5 and
//! RSASSA-PSS with MGF1. Moduli of 2048 to 8192 bits.

use alloc::vec::Vec;

use crate::HashAlg;
use crate::bignum::{Mont, Nat};

/// An RSA public key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    n: Nat,
    e: Nat,
    mont: Mont,
    /// The modulus length in bytes.
    k: usize,
}

impl PublicKey {
    /// From the big-endian modulus and exponent. `None` for a modulus
    /// outside 2048..=8192 bits, an even modulus, or an exponent that is
    /// even or below 3.
    pub fn new(n: &[u8], e: &[u8]) -> Option<PublicKey> {
        let n = Nat::from_be(n);
        let e = Nat::from_be(e);
        if !(2048..=8192).contains(&n.bits()) || !e.is_odd() || e.bits() < 2 {
            return None;
        }
        let mont = Mont::new(&n)?;
        let k = n.bits().div_ceil(8);
        Some(PublicKey { n, e, mont, k })
    }

    /// `sig^e mod n` as `k` bytes, if `sig` is a valid representative.
    fn open(&self, sig: &[u8]) -> Option<Vec<u8>> {
        if sig.len() != self.k {
            return None;
        }
        let s = Nat::from_be(sig);
        if s.cmp(&self.n) != core::cmp::Ordering::Less {
            return None;
        }
        self.mont.pow(&s, &self.e).to_be(self.k)
    }

    /// RSASSA-PKCS1-v1_5 over a message whose `hash`-digest is `digest`.
    pub fn verify_pkcs1(&self, hash: HashAlg, digest: &[u8], sig: &[u8]) -> bool {
        let Some(em) = self.open(sig) else {
            return false;
        };
        let prefix: &[u8] = match hash {
            HashAlg::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            HashAlg::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            HashAlg::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        };
        if digest.len() != hash.output_len() {
            return false;
        }
        let t_len = prefix.len() + digest.len();
        if self.k < t_len + 11 {
            return false;
        }
        // Build the one encoding that is acceptable and compare.
        let mut want = Vec::with_capacity(self.k);
        want.extend_from_slice(&[0x00, 0x01]);
        want.resize(self.k - t_len - 1, 0xff);
        want.push(0x00);
        want.extend_from_slice(prefix);
        want.extend_from_slice(digest);
        crate::ct_eq(&em, &want)
    }

    /// RSASSA-PSS (MGF1 with the same hash) over a message whose digest is
    /// `digest`, with the salt length `salt` (TLS: the hash length), or any
    /// salt length if `None`.
    pub fn verify_pss(
        &self,
        hash: HashAlg,
        digest: &[u8],
        sig: &[u8],
        salt: Option<usize>,
    ) -> bool {
        let Some(m) = self.open(sig) else {
            return false;
        };
        let h_len = hash.output_len();
        let em_bits = self.n.bits() - 1;
        let em_len = em_bits.div_ceil(8);
        // The k-byte value has one leading zero byte when em_bits is a
        // multiple of 8.
        let em = &m[m.len() - em_len..];
        if m[..m.len() - em_len].iter().any(|&b| b != 0) || digest.len() != h_len {
            return false;
        }
        if em_len < h_len + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let (masked_db, rest) = em.split_at(em_len - h_len - 1);
        let h = &rest[..h_len];
        let unused = 8 * em_len - em_bits;
        if unused > 0 && masked_db[0] >> (8 - unused) != 0 {
            return false;
        }
        let mask = mgf1(hash, h, masked_db.len());
        let mut db: Vec<u8> = masked_db.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
        if unused > 0 {
            db[0] &= 0xff >> unused;
        }
        let Some(one) = db.iter().position(|&b| b != 0) else {
            return false;
        };
        if db[one] != 0x01 {
            return false;
        }
        let salt_bytes = &db[one + 1..];
        if salt.is_some_and(|s| s != salt_bytes.len()) {
            return false;
        }
        let mut mp = Vec::with_capacity(8 + h_len + salt_bytes.len());
        mp.extend_from_slice(&[0u8; 8]);
        mp.extend_from_slice(digest);
        mp.extend_from_slice(salt_bytes);
        crate::ct_eq(&hash.digest(&mp), h)
    }
}

/// MGF1 (RFC 8017 B.2.1).
fn mgf1(hash: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.output_len());
    let mut counter = 0u32;
    while out.len() < len {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&hash.digest(&input));
        counter += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    // Made with OpenSSL: `openssl genrsa 2048`, then `openssl dgst -sha256
    // -sign` (PKCS#1 v1.5) and with `rsa_padding_mode:pss`, salt 32.
    const N: &str = "A0BDD7C0E876BFC9FC390C07D348FE1479B8A628367C1886FE90FFD9F15BC0CDF21771E8638FD76759B496AE6BF18DFED1190068F538C0F36C2EB1AE81D14C27F259DAC2A89C40C34FD061C1530CD36B895ED493CA784E10F95827C7D1725EBD34E5FDB71819B308AE437FCF838A3FCE9DF82C8F720A2E2B340AAAFE0517572A94C02E845F25C1647A0B1555CF8C6466EBDE8C4DA12587FCE34192F541EF59C15620EA820B80E948B076AFB589F7500D08F2446076F157BBA485D64AA9E3F167F4B8C2D2C489F8C05A9758952B2D496B300BBDAD41B778E0F50BBF67257B4A6F2CECF58C942CB472A63679E69B8DE99D3718F41B1063738A349495363B5AF377";
    const PKCS1: &str = "3a9fa0ec2a7ead7b75aaa3fd206dcd4150973f23ecc6021f8e51dcfba4c96ddcb22712a57b3cf263767af61600516a54de04e704d98a8d94f74d2289fc1b810540b2295d84765c8923aa83528e385e3093741368eb63ebf4c88ae2d08d4ae0a70494c95d37250090d6932c3d3fb1121f552144a8f8490545e7d50cadde7c751ba81c9618a34d5291ebf11bb13ea3b37b0446648b6930d830a5787cb3708e13ba6efbc89ee46017d24c8ff24f427ccf269ce7856c523a1ef2ae2e54ac862c31df34bcaa6c1eabb2e5764ecd9c72b4a255103a32ce93ba89ac6a30f338532b37e64fa84bee4288778388c13e05d0dafb57d5e2031e6120ee4ba12cc3206dd13071";
    const PSS: &str = "52606429fb00c7abd1cae9e735c951cdfc8e712ee72f69c12e8dac8ac24bc429162bf30da1505014b3db80dea84bf4d0a3ca5ab16d778928538ace937bae7c18e3eecbd70138cb89bd61740f431035aa25e5b678c5b2e187c5cf14fac6272ef30886d65f45226bffe237f269a8a5e4dd0c2ef93bfbcbc44a7587cc42f83e8c5c4eda3df79ff8057866feb993111c2c6d2f9c9fddd02d124ed956574085a2b897f3d1815202697ed4811a8af667292d483c05284428382429ed4b131460b53335ef9f040492e57f3cf855758d44f074157f8ebf955af008a1d7bdfb65ed34694d274105f33b00171c5c0a6880260f60468964c4941ddc9fd9067bed559a64a1bb";
    const MSG: &[u8] = b"ichor signs this";

    fn key() -> PublicKey {
        PublicKey::new(&hex(N), &[1, 0, 1]).unwrap()
    }

    #[test]
    fn pkcs1_v1_5_sha256() {
        let d = HashAlg::Sha256.digest(MSG);
        let sig = hex(PKCS1);
        assert!(key().verify_pkcs1(HashAlg::Sha256, &d, &sig));
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(!key().verify_pkcs1(HashAlg::Sha256, &d, &bad));
        let other = HashAlg::Sha256.digest(b"ichor signs that");
        assert!(!key().verify_pkcs1(HashAlg::Sha256, &other, &sig));
        assert!(!key().verify_pkcs1(HashAlg::Sha384, &HashAlg::Sha384.digest(MSG), &sig));
    }

    #[test]
    fn pss_sha256() {
        let d = HashAlg::Sha256.digest(MSG);
        let sig = hex(PSS);
        assert!(key().verify_pss(HashAlg::Sha256, &d, &sig, Some(32)));
        assert!(key().verify_pss(HashAlg::Sha256, &d, &sig, None));
        assert!(!key().verify_pss(HashAlg::Sha256, &d, &sig, Some(20)));
        let mut bad = sig.clone();
        bad[7] ^= 0x40;
        assert!(!key().verify_pss(HashAlg::Sha256, &d, &bad, Some(32)));
        assert!(
            !key().verify_pkcs1(HashAlg::Sha256, &d, &sig),
            "a PSS signature is not PKCS#1 v1.5"
        );
    }

    #[test]
    fn rejects_weak_keys_and_bad_lengths() {
        assert!(
            PublicKey::new(&[0xff; 128], &[1, 0, 1]).is_none(),
            "1024 bits"
        );
        assert!(PublicKey::new(&hex(N), &[2]).is_none(), "even exponent");
        let d = HashAlg::Sha256.digest(MSG);
        assert!(!key().verify_pkcs1(HashAlg::Sha256, &d, &hex(PKCS1)[1..]));
    }
}
