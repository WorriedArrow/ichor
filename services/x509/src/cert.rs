//! X.509 v3 certificates (RFC 5280): the fields chain verification and
//! TLS need, with the signature checked by `services/crypto`.

use alloc::vec::Vec;

use crypto::HashAlg;
use crypto::ecdsa::Curve;

use crate::Error;
use crate::der::{self, Reader};

// OIDs (contents of the OBJECT IDENTIFIER).
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// `keyCertSign` in the KeyUsage bit string (bit 5).
pub const KEY_CERT_SIGN: u16 = 1 << 5;

/// How a certificate is signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    RsaPkcs1(HashAlg),
    Ecdsa(HashAlg),
}

/// A subject public key.
#[derive(Clone, Copy, Debug)]
pub enum PublicKey<'a> {
    Rsa { n: &'a [u8], e: &'a [u8] },
    Ec { curve: Curve, point: &'a [u8] },
}

impl PublicKey<'_> {
    /// Verifies `sig` over `msg` with this key and `alg`.
    pub fn verify(&self, alg: SigAlg, msg: &[u8], sig: &[u8]) -> bool {
        match (*self, alg) {
            (PublicKey::Rsa { n, e }, SigAlg::RsaPkcs1(h)) => crypto::rsa::PublicKey::new(n, e)
                .is_some_and(|k| k.verify_pkcs1(h, &h.digest(msg), sig)),
            (PublicKey::Ec { curve, point }, SigAlg::Ecdsa(h)) => {
                crypto::ecdsa::verify_der(curve, point, &h.digest(msg), sig)
            }
            _ => false,
        }
    }
}

/// A parsed certificate, borrowing its DER.
#[derive(Clone, Debug)]
pub struct Certificate<'a> {
    pub raw: &'a [u8],
    /// The signed part, as encoded.
    pub tbs: &'a [u8],
    pub sig_alg: SigAlg,
    pub signature: &'a [u8],
    /// Issuer and subject names, as encoded (compared byte for byte).
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    /// Validity, in Unix seconds.
    pub not_before: u64,
    pub not_after: u64,
    pub key: PublicKey<'a>,
    /// BasicConstraints: whether a CA, and its path length limit.
    pub ca: bool,
    pub path_len: Option<u32>,
    /// KeyUsage bits (bit 0 is digitalSignature), if present.
    pub key_usage: Option<u16>,
    /// Subject alternative DNS names.
    pub dns_names: Vec<&'a str>,
    /// ExtendedKeyUsage allows TLS server authentication (true when absent).
    pub server_auth: bool,
}

fn sig_alg(body: &[u8]) -> Result<SigAlg, Error> {
    let mut r = Reader::new(body);
    let oid = r.expect(der::OID).ok_or(Error::Malformed)?;
    Ok(match oid {
        SHA256_RSA => SigAlg::RsaPkcs1(HashAlg::Sha256),
        SHA384_RSA => SigAlg::RsaPkcs1(HashAlg::Sha384),
        SHA512_RSA => SigAlg::RsaPkcs1(HashAlg::Sha512),
        ECDSA_SHA256 => SigAlg::Ecdsa(HashAlg::Sha256),
        ECDSA_SHA384 => SigAlg::Ecdsa(HashAlg::Sha384),
        ECDSA_SHA512 => SigAlg::Ecdsa(HashAlg::Sha512),
        _ => return Err(Error::Unsupported),
    })
}

/// A UTCTime or GeneralizedTime (`...Z`) in Unix seconds.
fn time(t: der::Tlv<'_>) -> Result<u64, Error> {
    let s = t.body;
    let digits = |r: core::ops::Range<usize>| -> Result<u16, Error> {
        let mut v = 0u16;
        for &c in s.get(r).ok_or(Error::Malformed)? {
            if !c.is_ascii_digit() {
                return Err(Error::Malformed);
            }
            v = v * 10 + u16::from(c - b'0');
        }
        Ok(v)
    };
    let (year, at) = match t.tag {
        der::UTC_TIME if s.len() == 13 => {
            let yy = digits(0..2)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
        }
        der::GENERALIZED_TIME if s.len() == 15 => (digits(0..4)?, 4),
        _ => return Err(Error::Malformed),
    };
    if s.last() != Some(&b'Z') {
        return Err(Error::Malformed);
    }
    let field = |i: usize| digits(at + 2 * i..at + 2 * i + 2).map(|v| v as u8);
    let c = civil::Civil {
        year,
        month: field(0)?,
        day: field(1)?,
        hour: field(2)?,
        minute: field(3)?,
        second: field(4)?,
    };
    // Before 1970 reads as 0: such a bound has long passed anyway.
    Ok(c.unix_seconds().unwrap_or(0))
}

fn public_key(spki: &[u8]) -> Result<PublicKey<'_>, Error> {
    let mut r = Reader::new(spki);
    let alg = r.expect(der::SEQUENCE).ok_or(Error::Malformed)?;
    let key = der::bit_string(r.expect(der::BIT_STRING).ok_or(Error::Malformed)?)
        .ok_or(Error::Malformed)?;
    let mut a = Reader::new(alg);
    match a.expect(der::OID).ok_or(Error::Malformed)? {
        RSA_ENCRYPTION => {
            let mut k = Reader::new(
                Reader::new(key)
                    .expect(der::SEQUENCE)
                    .ok_or(Error::Malformed)?,
            );
            let n = der::unsigned(k.expect(der::INTEGER).ok_or(Error::Malformed)?)
                .ok_or(Error::Malformed)?;
            let e = der::unsigned(k.expect(der::INTEGER).ok_or(Error::Malformed)?)
                .ok_or(Error::Malformed)?;
            Ok(PublicKey::Rsa { n, e })
        }
        EC_PUBLIC_KEY => {
            let curve = match a.expect(der::OID).ok_or(Error::Malformed)? {
                PRIME256V1 => Curve::P256,
                SECP384R1 => Curve::P384,
                _ => return Err(Error::Unsupported),
            };
            Ok(PublicKey::Ec { curve, point: key })
        }
        _ => Err(Error::Unsupported),
    }
}

/// Parses one DER certificate.
pub fn parse(raw: &[u8]) -> Result<Certificate<'_>, Error> {
    let mut outer = Reader::new(raw);
    let cert = outer.read().ok_or(Error::Malformed)?;
    if cert.tag != der::SEQUENCE || !outer.is_empty() {
        return Err(Error::Malformed);
    }
    let mut c = Reader::new(cert.body);
    let tbs = c.read().ok_or(Error::Malformed)?;
    let outer_alg = sig_alg(c.expect(der::SEQUENCE).ok_or(Error::Malformed)?)?;
    let signature = der::bit_string(c.expect(der::BIT_STRING).ok_or(Error::Malformed)?)
        .ok_or(Error::Malformed)?;
    if tbs.tag != der::SEQUENCE || !c.is_empty() {
        return Err(Error::Malformed);
    }
    let mut t = Reader::new(tbs.body);
    // version [0] EXPLICIT: only v3 certificates carry the extensions we
    // rely on.
    let version = t.optional(0xa0).ok_or(Error::Unsupported)?;
    if version != [der::INTEGER, 1, 2] {
        return Err(Error::Unsupported);
    }
    t.expect(der::INTEGER).ok_or(Error::Malformed)?;
    let inner_alg = sig_alg(t.expect(der::SEQUENCE).ok_or(Error::Malformed)?)?;
    if inner_alg != outer_alg {
        return Err(Error::Malformed);
    }
    let issuer = t.read().ok_or(Error::Malformed)?;
    let mut validity = Reader::new(t.expect(der::SEQUENCE).ok_or(Error::Malformed)?);
    let not_before = time(validity.read().ok_or(Error::Malformed)?)?;
    let not_after = time(validity.read().ok_or(Error::Malformed)?)?;
    let subject = t.read().ok_or(Error::Malformed)?;
    if issuer.tag != der::SEQUENCE || subject.tag != der::SEQUENCE {
        return Err(Error::Malformed);
    }
    let key = public_key(t.expect(der::SEQUENCE).ok_or(Error::Malformed)?)?;
    let _ = t.optional(0x81);
    let _ = t.optional(0x82);
    let mut out = Certificate {
        raw,
        tbs: tbs.raw,
        sig_alg: outer_alg,
        signature,
        issuer: issuer.raw,
        subject: subject.raw,
        not_before,
        not_after,
        key,
        ca: false,
        path_len: None,
        key_usage: None,
        dns_names: Vec::new(),
        server_auth: true,
    };
    if let Some(exts) = t.optional(0xa3) {
        let mut list = Reader::new(
            Reader::new(exts)
                .expect(der::SEQUENCE)
                .ok_or(Error::Malformed)?,
        );
        while !list.is_empty() {
            let mut e = Reader::new(list.expect(der::SEQUENCE).ok_or(Error::Malformed)?);
            let oid = e.expect(der::OID).ok_or(Error::Malformed)?;
            let critical = e.optional(der::BOOLEAN).is_some_and(|b| b == [0xff]);
            let value = e.expect(der::OCTET_STRING).ok_or(Error::Malformed)?;
            extension(&mut out, oid, critical, value)?;
        }
    }
    if !t.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(out)
}

fn extension<'a>(
    c: &mut Certificate<'a>,
    oid: &[u8],
    critical: bool,
    v: &'a [u8],
) -> Result<(), Error> {
    match oid {
        BASIC_CONSTRAINTS => {
            let mut r = Reader::new(
                Reader::new(v)
                    .expect(der::SEQUENCE)
                    .ok_or(Error::Malformed)?,
            );
            c.ca = r.optional(der::BOOLEAN).is_some_and(|b| b == [0xff]);
            if let Some(n) = r.optional(der::INTEGER) {
                let n = der::unsigned(n).ok_or(Error::Malformed)?;
                c.path_len = Some(n.iter().fold(0u32, |a, &b| {
                    a.saturating_mul(256).saturating_add(u32::from(b))
                }));
            }
        }
        KEY_USAGE => {
            let bits = Reader::new(v)
                .expect(der::BIT_STRING)
                .ok_or(Error::Malformed)?;
            let (_unused, rest) = bits.split_first().ok_or(Error::Malformed)?;
            // Bit 0 is the most significant bit of the first byte.
            let mut ku = 0u16;
            for (i, &byte) in rest.iter().take(2).enumerate() {
                for bit in 0..8 {
                    if byte & (0x80 >> bit) != 0 {
                        ku |= 1 << (i * 8 + bit);
                    }
                }
            }
            c.key_usage = Some(ku);
        }
        SUBJECT_ALT_NAME => {
            let mut r = Reader::new(
                Reader::new(v)
                    .expect(der::SEQUENCE)
                    .ok_or(Error::Malformed)?,
            );
            while !r.is_empty() {
                let gn = r.read().ok_or(Error::Malformed)?;
                if gn.tag == 0x82 {
                    let name = core::str::from_utf8(gn.body).map_err(|_| Error::Malformed)?;
                    c.dns_names.push(name);
                }
            }
        }
        EXT_KEY_USAGE => {
            let mut r = Reader::new(
                Reader::new(v)
                    .expect(der::SEQUENCE)
                    .ok_or(Error::Malformed)?,
            );
            let mut ok = false;
            while !r.is_empty() {
                let purpose = r.expect(der::OID).ok_or(Error::Malformed)?;
                ok |= purpose == SERVER_AUTH || purpose == ANY_EKU;
            }
            c.server_auth = ok;
        }
        // An unknown extension may be ignored unless it is critical.
        _ if critical => return Err(Error::UnknownCritical),
        _ => {}
    }
    Ok(())
}

impl Certificate<'_> {
    /// Whether `issuer` signed this certificate.
    pub fn signed_by(&self, issuer: &Certificate<'_>) -> bool {
        self.issuer == issuer.subject && issuer.key.verify(self.sig_alg, self.tbs, self.signature)
    }

    /// Whether a DNS SAN matches `host` (a `*` only as the whole leftmost
    /// label, matching exactly one label).
    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.');
        self.dns_names.iter().any(|pat| {
            let pat = pat.trim_end_matches('.');
            match pat.strip_prefix("*.") {
                Some(rest) => host.split_once('.').is_some_and(|(label, tail)| {
                    !label.is_empty() && tail.eq_ignore_ascii_case(rest)
                }),
                None => pat.eq_ignore_ascii_case(host),
            }
        })
    }
}
