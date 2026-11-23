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
/// Both the key type and the signature algorithm (RFC 8410).
const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// id-ml-dsa-44, -65 and -87: both key type and signature algorithm
/// (RFC 9881).
const ML_DSA_44: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
const ML_DSA_65: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
const ML_DSA_87: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

/// The ML-DSA parameter set an algorithm OID names.
fn ml_dsa(oid: &[u8]) -> Option<crypto::mldsa::Params> {
    Some(match oid {
        ML_DSA_44 => crypto::mldsa::ML_DSA_44,
        ML_DSA_65 => crypto::mldsa::ML_DSA_65,
        ML_DSA_87 => crypto::mldsa::ML_DSA_87,
        _ => return None,
    })
}
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
const AUTHORITY_INFO_ACCESS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// GeneralName tags (context-specific, primitive).
const GN_DNS: u8 = 0x82;
const GN_IP: u8 = 0x87;

const GN_DIRECTORY: u8 = 0xa4;

/// Name-constraint subtrees: each base's GeneralName tag and contents.
pub type Subtrees<'a> = Vec<(u8, &'a [u8])>;

/// Smallest RSA modulus accepted, in bits.
const MIN_RSA_BITS: usize = 2048;
/// Most subtrees in one name-constraints list.
const MAX_SUBTREES: usize = 128;
/// Most name comparisons one CA's constraints may take (a certificate
/// with thousands of names and constraints is a denial of service).
const MAX_NC_CHECKS: usize = 1024;

/// A DNS name's syntax (preferred name syntax, RFC 1034 3.5): labels of
/// letters, digits and hyphens, none empty or starting or ending with a
/// hyphen, at most 63 bytes each and 253 in all.
fn valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// A DNS SAN: a name, or `*.` and a name (a wildcard is the whole
/// leftmost label).
fn valid_dns_san(name: &str) -> bool {
    valid_dns_name(name.strip_prefix("*.").unwrap_or(name))
}

/// `keyCertSign` in the KeyUsage bit string (bit 5).
pub const KEY_CERT_SIGN: u16 = 1 << 5;
/// The KeyUsage bits of signing alone: digitalSignature, nonRepudiation,
/// keyCertSign, cRLSign (bits 0, 1, 5, 6).
const SIGNING_USAGES: u16 = 1 | 1 << 1 | KEY_CERT_SIGN | 1 << 6;

/// How a certificate is signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    RsaPkcs1(HashAlg),
    Ecdsa(HashAlg),
    Ed25519,
    MlDsa(crypto::mldsa::Params),
}

/// A subject public key.
#[derive(Clone, Copy, Debug)]
pub enum PublicKey<'a> {
    Rsa { n: &'a [u8], e: &'a [u8] },
    Ec { curve: Curve, point: &'a [u8] },
    Ed25519(&'a [u8; 32]),
    MlDsa(crypto::mldsa::Params, &'a [u8]),
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
            (PublicKey::Ed25519(k), SigAlg::Ed25519) => crypto::ed25519::verify(k, msg, sig),
            (PublicKey::MlDsa(p, k), SigAlg::MlDsa(s)) if p == s => {
                crypto::mldsa::verify(&p, k, msg, sig)
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
    /// Extended key usage, if the certificate has the extension: whether
    /// it allows TLS server authentication explicitly, and whether it
    /// carries `anyExtendedKeyUsage`.
    pub eku: Option<(bool, bool)>,
    /// The serial number is a positive integer of at most 20 octets.
    pub serial_ok: bool,
    /// IP address SANs (4 or 16 bytes).
    pub ip_names: Vec<&'a [u8]>,
    /// SANs of other types than DNS and IP.
    pub other_names: bool,
    /// Name constraints: permitted and excluded subtrees, `(tag, base)`.
    pub name_constraints: Option<(Subtrees<'a>, Subtrees<'a>)>,
    /// Subject alternative DNS names.
    pub dns_names: Vec<&'a str>,
    /// Whether the SubjectAltName extension is marked critical.
    pub san_critical: bool,
    /// Whether BasicConstraints is marked critical.
    pub bc_critical: bool,
    /// Whether ExtendedKeyUsage is marked critical.
    pub eku_critical: bool,
    /// AuthorityKeyIdentifier, if present: its keyIdentifier, and whether
    /// it also names the issuer's issuer or serial number.
    pub aki: Option<(Option<&'a [u8]>, bool)>,
    /// SubjectKeyIdentifier, if present.
    pub ski: Option<&'a [u8]>,
    /// The subject is an empty name.
    pub subject_empty: bool,
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
        // No parameters, not even NULL (RFC 8410 §3, RFC 9881 §2).
        ED25519 if r.is_empty() => SigAlg::Ed25519,
        o if r.is_empty() && ml_dsa(o).is_some() => {
            SigAlg::MlDsa(ml_dsa(o).ok_or(Error::Unsupported)?)
        }
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
            // Weak keys, and moduli that are not a whole number of bytes,
            // are refused (as the Web PKI does).
            let bits = n.len() * 8 - n.first().map_or(8, |b| b.leading_zeros() as usize);
            if bits < MIN_RSA_BITS || bits % 8 != 0 {
                return Err(Error::Unsupported);
            }
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
        ED25519 if a.is_empty() => Ok(PublicKey::Ed25519(
            key.try_into().map_err(|_| Error::Malformed)?,
        )),
        o if a.is_empty() && ml_dsa(o).is_some() => {
            let p = ml_dsa(o).ok_or(Error::Unsupported)?;
            if key.len() != p.public_key_len() {
                return Err(Error::Malformed);
            }
            Ok(PublicKey::MlDsa(p, key))
        }
        _ => Err(Error::Unsupported),
    }
}

/// The seed in a PKCS #8 Ed25519 private key (RFC 8410 §7).
pub fn ed25519_seed(pkcs8: &[u8]) -> Option<[u8; 32]> {
    let mut outer = Reader::new(pkcs8);
    let mut k = Reader::new(outer.expect(der::SEQUENCE)?);
    // Version 0 (v1), or 1 with the public key after the private one.
    let version = k.expect(der::INTEGER)?;
    if !outer.is_empty() || !matches!(version, [0] | [1]) {
        return None;
    }
    let mut alg = Reader::new(k.expect(der::SEQUENCE)?);
    if alg.expect(der::OID)? != ED25519 || !alg.is_empty() {
        return None;
    }
    // An OCTET STRING in the OCTET STRING.
    let mut inner = Reader::new(k.expect(der::OCTET_STRING)?);
    let seed = inner.expect(der::OCTET_STRING)?.try_into().ok()?;
    inner.is_empty().then_some(seed)
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
    // The serial: a positive integer of at most 20 octets (RFC 5280
    // 4.1.2.2). Checked for certificates a server sends, not for trust
    // anchors (old roots, Starfield's G2 among them, have serial 0).
    let serial = t.expect(der::INTEGER).ok_or(Error::Malformed)?;
    let serial_ok = serial.len() <= 21
        && serial.first().is_some_and(|b| b & 0x80 == 0)
        && !serial.iter().all(|&b| b == 0)
        && (serial.len() < 21 || serial[0] == 0);
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
        eku: None,
        serial_ok,
        ip_names: Vec::new(),
        other_names: false,
        name_constraints: None,
        dns_names: Vec::new(),
        san_critical: false,
        bc_critical: false,
        eku_critical: false,
        aki: None,
        ski: None,
        subject_empty: subject.body.is_empty(),
    };
    if let Some(exts) = t.optional(0xa3) {
        let mut list = Reader::new(
            Reader::new(exts)
                .expect(der::SEQUENCE)
                .ok_or(Error::Malformed)?,
        );
        let mut seen: Vec<&[u8]> = Vec::new();
        while !list.is_empty() {
            let mut e = Reader::new(list.expect(der::SEQUENCE).ok_or(Error::Malformed)?);
            let oid = e.expect(der::OID).ok_or(Error::Malformed)?;
            // An extension may appear once (RFC 5280 4.2).
            if seen.contains(&oid) {
                return Err(Error::Malformed);
            }
            seen.push(oid);
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

/// A GeneralName, whole (any tag of its CHOICE).
fn general_name(r: &mut Reader<'_>) -> Result<(), Error> {
    let gn = r.read().ok_or(Error::Malformed)?;
    if gn.tag & 0xc0 != 0x80 || gn.tag & 0x1f > 8 {
        return Err(Error::Malformed);
    }
    Ok(())
}

fn extension<'a>(
    c: &mut Certificate<'a>,
    oid: &[u8],
    critical: bool,
    v: &'a [u8],
) -> Result<(), Error> {
    match oid {
        AUTHORITY_KEY_ID => {
            // Non-critical (RFC 5280 4.2.1.1).
            if critical {
                return Err(Error::Malformed);
            }
            let mut outer = Reader::new(v);
            let mut r = Reader::new(outer.expect(der::SEQUENCE).ok_or(Error::Malformed)?);
            let key_id = r.optional(0x80);
            let issuer = r.optional(0xa1).is_some();
            let serial = r.optional(0x82).is_some();
            if !r.is_empty() || !outer.is_empty() {
                return Err(Error::Malformed);
            }
            c.aki = Some((key_id, issuer || serial));
        }
        SUBJECT_KEY_ID => {
            if critical {
                return Err(Error::Malformed);
            }
            let mut outer = Reader::new(v);
            let id = outer.expect(der::OCTET_STRING).ok_or(Error::Malformed)?;
            if !outer.is_empty() {
                return Err(Error::Malformed);
            }
            c.ski = Some(id);
        }
        // Policies are not processed, so a critical PolicyConstraints is an
        // unknown critical extension; and conforming CAs mark it critical
        // (RFC 5280 4.2.1.11).
        POLICY_CONSTRAINTS if critical => return Err(Error::UnknownCritical),
        POLICY_CONSTRAINTS => return Err(Error::Malformed),
        AUTHORITY_INFO_ACCESS => {
            // Non-critical, and one or more AccessDescriptions (RFC 5280
            // 4.2.2.1).
            if critical {
                return Err(Error::Malformed);
            }
            let mut outer = Reader::new(v);
            let mut r = Reader::new(outer.expect(der::SEQUENCE).ok_or(Error::Malformed)?);
            if r.is_empty() || !outer.is_empty() {
                return Err(Error::Malformed);
            }
            while !r.is_empty() {
                let mut ad = Reader::new(r.expect(der::SEQUENCE).ok_or(Error::Malformed)?);
                ad.expect(der::OID).ok_or(Error::Malformed)?;
                general_name(&mut ad)?;
                if !ad.is_empty() {
                    return Err(Error::Malformed);
                }
            }
        }
        BASIC_CONSTRAINTS => {
            c.bc_critical = critical;
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
            // An ML-DSA key only signs: digitalSignature, nonRepudiation,
            // keyCertSign and cRLSign at most (RFC 9881 §5).
            if matches!(c.key, PublicKey::MlDsa(..)) && ku & !SIGNING_USAGES != 0 {
                return Err(Error::Malformed);
            }
            c.key_usage = Some(ku);
        }
        SUBJECT_ALT_NAME => {
            c.san_critical = critical;
            let mut r = Reader::new(
                Reader::new(v)
                    .expect(der::SEQUENCE)
                    .ok_or(Error::Malformed)?,
            );
            while !r.is_empty() {
                let gn = r.read().ok_or(Error::Malformed)?;
                match gn.tag {
                    GN_DNS => {
                        let name = core::str::from_utf8(gn.body).map_err(|_| Error::Malformed)?;
                        if !valid_dns_san(name) {
                            return Err(Error::Malformed);
                        }
                        c.dns_names.push(name);
                    }
                    GN_IP if gn.body.len() == 4 || gn.body.len() == 16 => c.ip_names.push(gn.body),
                    GN_IP => return Err(Error::Malformed),
                    _ => c.other_names = true,
                }
            }
        }
        EXT_KEY_USAGE => {
            c.eku_critical = critical;
            let mut r = Reader::new(
                Reader::new(v)
                    .expect(der::SEQUENCE)
                    .ok_or(Error::Malformed)?,
            );
            let (mut server, mut any) = (false, false);
            while !r.is_empty() {
                let purpose = r.expect(der::OID).ok_or(Error::Malformed)?;
                server |= purpose == SERVER_AUTH;
                any |= purpose == ANY_EKU;
            }
            c.eku = Some((server, any));
        }
        NAME_CONSTRAINTS => {
            // RFC 5280 4.2.1.10 says always critical; the Web PKI allows it
            // non-critical (CABF BR 7.1.2.5.2), and so do we.
            let mut r = Reader::new(
                Reader::new(v)
                    .expect(der::SEQUENCE)
                    .ok_or(Error::Malformed)?,
            );
            let subtrees = |body: &'a [u8]| -> Result<Vec<(u8, &'a [u8])>, Error> {
                let mut out = Vec::new();
                let mut s = Reader::new(body);
                while !s.is_empty() {
                    let mut st = Reader::new(s.expect(der::SEQUENCE).ok_or(Error::Malformed)?);
                    let base = st.read().ok_or(Error::Malformed)?;
                    // minimum and maximum: RFC 5280 says absent (0, none).
                    if !st.is_empty() {
                        return Err(Error::Unsupported);
                    }
                    // A DNS base is a name, or empty (every name); a leading
                    // period is URI constraints' syntax, not DNS's (RFC 5280
                    // 4.2.1.10).
                    if base.tag == GN_DNS {
                        let b = core::str::from_utf8(base.body).map_err(|_| Error::Malformed)?;
                        if !b.is_empty() && !valid_dns_name(b) {
                            return Err(Error::Malformed);
                        }
                    }
                    out.push((base.tag, base.body));
                }
                // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX)
                if out.is_empty() || out.len() > MAX_SUBTREES {
                    return Err(Error::Malformed);
                }
                Ok(out)
            };
            let permitted = match r.optional(0xa0) {
                Some(b) => subtrees(b)?,
                None => Vec::new(),
            };
            let excluded = match r.optional(0xa1) {
                Some(b) => subtrees(b)?,
                None => Vec::new(),
            };
            if !r.is_empty() || (permitted.is_empty() && excluded.is_empty()) {
                return Err(Error::Malformed);
            }
            c.name_constraints = Some((permitted, excluded));
        }
        // An unknown extension may be ignored unless it is critical.
        _ if critical => return Err(Error::UnknownCritical),
        _ => {}
    }
    Ok(())
}

/// Whether DNS name `name` lies in the subtree `base` (RFC 5280
/// 4.2.1.10): `base` itself or a subdomain; empty, every name. Both are
/// ASCII (checked when parsed).
fn dns_within(name: &str, base: &str) -> bool {
    let name = name.trim_end_matches('.');
    if base.is_empty() {
        return true;
    }
    let (n, b) = (name.len(), base.len());
    name.eq_ignore_ascii_case(base)
        || n > b && name.as_bytes()[n - b - 1] == b'.' && name[n - b..].eq_ignore_ascii_case(base)
}

/// Whether some name a SAN pattern covers lies in `base`. For permitted
/// subtrees every covered name must (`all`); for excluded, any.
fn pattern_within(pat: &str, base: &str, all: bool) -> bool {
    let Some(rest) = pat.strip_prefix("*.") else {
        return dns_within(pat, base);
    };
    // Every `x.rest` is within `B` exactly when `rest` is.
    let below = dns_within(rest, base);
    if all {
        below
    } else {
        // Some `x.rest` is also `B` itself when `B` is one label below
        // `rest`.
        below
            || base
                .split_once('.')
                .is_some_and(|(label, tail)| !label.is_empty() && tail.eq_ignore_ascii_case(rest))
    }
}

fn ip_within(ip: &[u8], base: &[u8]) -> Option<bool> {
    if base.len() != 2 * ip.len() {
        return None; // a constraint for the other address family
    }
    let (addr, mask) = base.split_at(ip.len());
    Some(
        ip.iter()
            .zip(addr)
            .zip(mask)
            .all(|((i, a), m)| i & m == a & m),
    )
}

impl Certificate<'_> {
    /// Whether this CA's name constraints allow `leaf`'s names (DNS and IP
    /// SANs). A constraint of another type, or a leaf name of another type
    /// under a CA with constraints, cannot be checked and is refused.
    pub fn permits(&self, leaf: &Certificate<'_>) -> Result<(), Error> {
        let Some((permitted, excluded)) = &self.name_constraints else {
            return Ok(());
        };
        // directoryName constraints apply to every subject, which we do not
        // compare; constraints of other types (email, URI, ...) only to
        // names of that type, which we cannot compare either.
        let types = || permitted.iter().chain(excluded).map(|(t, _)| *t);
        if types().any(|t| t == GN_DIRECTORY)
            || (leaf.other_names && types().any(|t| t != GN_DNS && t != GN_IP))
        {
            return Err(Error::Unsupported);
        }
        if (leaf.dns_names.len() + leaf.ip_names.len()) * (permitted.len() + excluded.len())
            > MAX_NC_CHECKS
        {
            return Err(Error::TooComplex);
        }
        fn dns(tag: u8, b: &[u8]) -> Option<&str> {
            (tag == GN_DNS)
                .then(|| core::str::from_utf8(b).ok())
                .flatten()
        }
        for name in &leaf.dns_names {
            if excluded
                .iter()
                .filter_map(|(t, b)| dns(*t, b))
                .any(|b| pattern_within(name, b, false))
            {
                return Err(Error::NameConstraint);
            }
            let mut allowed = permitted.iter().filter_map(|(t, b)| dns(*t, b)).peekable();
            if allowed.peek().is_some() && !allowed.any(|b| pattern_within(name, b, true)) {
                return Err(Error::NameConstraint);
            }
        }
        for ip in &leaf.ip_names {
            let of = |list: &[(u8, &[u8])]| -> Vec<bool> {
                list.iter()
                    .filter(|(t, _)| *t == GN_IP)
                    .filter_map(|(_, b)| ip_within(ip, b))
                    .collect()
            };
            if of(excluded).iter().any(|&m| m) {
                return Err(Error::NameConstraint);
            }
            let p = of(permitted);
            if !p.is_empty() && !p.iter().any(|&m| m) {
                return Err(Error::NameConstraint);
            }
        }
        Ok(())
    }

    /// Whether this certificate may be a TLS server's leaf (CABF BR
    /// 7.1.2.7): not a CA, no certificate signing, and a non-critical
    /// extended key usage naming serverAuth and not anyExtendedKeyUsage.
    pub fn may_serve(&self) -> bool {
        !self.ca
            && self.key_usage.is_none_or(|ku| ku & KEY_CERT_SIGN == 0)
            && self.name_constraints.is_none()
            && self.eku == Some((true, false))
            && !self.eku_critical
    }

    /// Whether a leaf's SubjectAltName is critical exactly when its
    /// subject is empty (RFC 5280 4.2.1.6, CABF BR 7.1.2.7.12). The
    /// commonName is not looked at: only DNS SANs name the host, as in
    /// Chrome, Go and rustls.
    pub fn names_consistent(&self) -> bool {
        self.subject_empty == self.san_critical
    }

    /// Whether the certificate names its issuer's key (RFC 5280 4.2.1.1:
    /// an AuthorityKeyIdentifier with a keyIdentifier), unless it is
    /// self-issued.
    pub fn names_issuer_key(&self) -> bool {
        self.issuer == self.subject || self.aki.is_some_and(|(key, _)| key.is_some())
    }

    /// Whether this certificate is formed as a CA's must be (RFC 5280
    /// 4.1.2.6, 4.2.1.9): a subject and a critical BasicConstraints. An
    /// issuing CA also needs a SubjectKeyIdentifier (4.2.1.2,
    /// `has_key_id`); a trust anchor does not, since the SKI is there to
    /// build paths and an anchor ends one (Mozilla's TWCA Global Root CA
    /// has none).
    pub fn ca_well_formed(&self) -> bool {
        !self.subject_empty && self.bc_critical
    }

    /// Whether the certificate carries a SubjectKeyIdentifier.
    pub fn has_key_id(&self) -> bool {
        self.ski.is_some()
    }

    /// Whether this trust anchor is formed as a root CA must be (CABF BR
    /// 7.1.2.1): no extended key usage, and an AuthorityKeyIdentifier, if
    /// any, of only a keyIdentifier, which a self-issued root's own
    /// SubjectKeyIdentifier must equal.
    pub fn root_well_formed(&self) -> bool {
        self.eku.is_none()
            && self.aki.is_none_or(|(key, more)| {
                !more && key.is_some() && (self.issuer != self.subject || key == self.ski)
            })
    }

    /// Whether this CA's extended key usage, if it has one, allows issuing
    /// for TLS servers.
    pub fn may_issue_server(&self) -> bool {
        self.eku.is_none_or(|(server, any)| server || any)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_subtrees() {
        assert!(dns_within("example.com", "example.com"));
        assert!(dns_within("a.b.Example.com", "example.com"));
        assert!(!dns_within("badexample.com", "example.com"));
        assert!(dns_within("anything.test", ""));
    }

    #[test]
    fn wildcards_against_subtrees() {
        // Permitted: every name the wildcard covers must be inside.
        assert!(pattern_within("*.example.com", "example.com", true));
        assert!(!pattern_within("*.example.com", "a.example.com", true));
        // Excluded: any covered name inside is enough.
        assert!(pattern_within("*.example.com", "a.example.com", false));
        assert!(!pattern_within("*.example.com", "b.a.example.com", false));
        assert!(!pattern_within("*.example.com", "other.com", false));
    }

    #[test]
    fn ip_subtrees() {
        let base = [10, 0, 0, 0, 255, 0, 0, 0];
        assert_eq!(ip_within(&[10, 1, 2, 3], &base), Some(true));
        assert_eq!(ip_within(&[11, 1, 2, 3], &base), Some(false));
        assert_eq!(ip_within(&[0; 16], &base), None);
    }

    #[test]
    fn dns_san_syntax() {
        for ok in [
            "example.com",
            "*.example.com",
            "a-b.c0.example",
            "example.com.",
        ] {
            assert!(valid_dns_san(ok), "{ok}");
        }
        for bad in [
            "",
            "a..b",
            "_x.example.com",
            "-a.example",
            "a.*.example",
            "*",
            "ex ample.com",
            "é.example",
        ] {
            assert!(!valid_dns_san(bad), "{bad}");
        }
    }
}
