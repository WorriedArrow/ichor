//! X.509 for the control plane's TLS (ADR-0012 §3, §4): DER, certificate
//! parsing, PEM bundles, and verification of a server's chain to a root
//! store for a host name at a time.
//!
//! Verification walks from the leaf: each certificate must be within its
//! validity, and each issuer a CA (BasicConstraints, KeyUsage keyCertSign
//! if present, path length) whose key verifies the signature. A root
//! whose subject matches is tried first at every step, so cross-signed
//! intermediates end at whichever root is trusted. The leaf must name the
//! host in a DNS SAN and allow server authentication.
//!
//! Partial: RSA-PSS certificate signatures, name constraints and
//! revocation are not handled (a certificate with an unknown critical
//! extension is refused).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub mod cert;
pub mod der;

pub use cert::{Certificate, PublicKey, SigAlg, parse};

/// Why a certificate or chain was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    /// A version, algorithm or key type we do not handle.
    Unsupported,
    UnknownCritical,
    Expired,
    NotYetValid,
    /// No path to a trusted root.
    UnknownIssuer,
    BadSignature,
    NotCa,
    PathTooLong,
    /// The leaf does not name the host.
    WrongHost,
    /// The leaf may not authenticate a TLS server.
    NotServerAuth,
}

/// Most certificates in a path, leaf and root included.
const MAX_DEPTH: usize = 8;

/// Trusted roots, as DER.
#[derive(Clone, Debug, Default)]
pub struct RootStore {
    roots: Vec<Vec<u8>>,
}

impl RootStore {
    /// Every certificate in a PEM bundle that parses (others are skipped:
    /// a bundle carries algorithms we may not handle).
    pub fn from_pem(pem: &str) -> RootStore {
        let roots = pem_certificates(pem)
            .into_iter()
            .filter(|der| parse(der).is_ok())
            .collect();
        RootStore { roots }
    }

    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// The DER of every `CERTIFICATE` block in `pem`.
pub fn pem_certificates(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body: Option<alloc::string::String> = None;
    for line in pem.lines() {
        let line = line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            body = Some(alloc::string::String::new());
        } else if line == "-----END CERTIFICATE-----" {
            if let Some(b) = body.take()
                && let Some(der) = base64(&b)
            {
                out.push(der);
            }
        } else if let Some(b) = body.as_mut() {
            b.push_str(line);
        }
    }
    out
}

/// Standard base64 with padding; `None` if malformed.
pub fn base64(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, q) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - pad]);
    }
    Some(out)
}

fn valid_at(c: &Certificate<'_>, now: u64) -> Result<(), Error> {
    if now < c.not_before {
        return Err(Error::NotYetValid);
    }
    if now > c.not_after {
        return Err(Error::Expired);
    }
    Ok(())
}

fn may_issue(c: &Certificate<'_>, below: usize) -> Result<(), Error> {
    if !c.ca || c.key_usage.is_some_and(|ku| ku & cert::KEY_CERT_SIGN == 0) {
        return Err(Error::NotCa);
    }
    // `below` intermediates sit between this issuer and the leaf.
    if c.path_len.is_some_and(|n| below > n as usize) {
        return Err(Error::PathTooLong);
    }
    Ok(())
}

/// Verifies `chain` (the leaf first, then what the server sent, as DER)
/// for `host` at Unix time `now`.
pub fn verify_chain(chain: &[&[u8]], roots: &RootStore, host: &str, now: u64) -> Result<(), Error> {
    let certs: Vec<Certificate<'_>> = chain.iter().map(|d| parse(d)).collect::<Result<_, _>>()?;
    let leaf = certs.first().ok_or(Error::Malformed)?;
    if !leaf.matches_host(host) {
        return Err(Error::WrongHost);
    }
    if !leaf.server_auth {
        return Err(Error::NotServerAuth);
    }
    let roots: Vec<Certificate<'_>> = roots.roots.iter().filter_map(|d| parse(d).ok()).collect();
    let mut current = leaf.clone();
    let mut used = alloc::vec![false; certs.len()];
    used[0] = true;
    for depth in 0..MAX_DEPTH {
        valid_at(&current, now)?;
        // A trusted root that signed it ends the path.
        if let Some(root) = roots.iter().find(|r| current.signed_by(r)) {
            valid_at(root, now)?;
            if depth > 0 {
                may_issue(root, depth)?;
            } else if !root.ca {
                return Err(Error::NotCa);
            }
            return Ok(());
        }
        // Otherwise an intermediate the server sent.
        let next = certs
            .iter()
            .enumerate()
            .find(|(i, c)| !used[*i] && current.issuer == c.subject)
            .ok_or(Error::UnknownIssuer)?;
        let (i, issuer) = next;
        if !current.signed_by(issuer) {
            return Err(Error::BadSignature);
        }
        may_issue(issuer, depth)?;
        used[i] = true;
        current = issuer.clone();
    }
    Err(Error::PathTooLong)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOTS: &str = include_str!("../testdata/roots.pem");
    const REGISTRY: &str = include_str!("../testdata/registry.pem");
    const AUTH: &str = include_str!("../testdata/auth.pem");
    const CLOUDFLARE: &str = include_str!("../testdata/cloudflare.pem");
    /// When the chains were captured (2026-11-15).
    const NOW: u64 = 1_794_786_687;

    fn check(pem: &str, host: &str, now: u64) -> Result<(), Error> {
        let ders = pem_certificates(pem);
        let chain: Vec<&[u8]> = ders.iter().map(Vec::as_slice).collect();
        verify_chain(&chain, &RootStore::from_pem(ROOTS), host, now)
    }

    #[test]
    fn base64_round_trips() {
        assert_eq!(base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64("aGVsbG8h").unwrap(), b"hello!");
        assert_eq!(base64("aGVsbA==").unwrap(), b"hell");
        assert!(base64("aGVsbG8").is_none());
        assert!(base64("aG=sbG8h").is_none());
    }

    #[test]
    fn docker_hub_chains_verify() {
        let roots = RootStore::from_pem(ROOTS);
        assert_eq!(roots.len(), 3);
        // RSA, ending in a cross-signed Amazon root under Starfield G2.
        assert_eq!(check(REGISTRY, "registry-1.docker.io", NOW), Ok(()));
        // ECDSA P-256 and P-384 under ISRG Root X2.
        assert_eq!(check(AUTH, "auth.docker.io", NOW), Ok(()));
        assert_eq!(
            check(CLOUDFLARE, "production.cloudflare.docker.com", NOW),
            Ok(())
        );
    }

    #[test]
    fn the_wrong_host_time_or_root_is_refused() {
        assert_eq!(check(AUTH, "auth.docker.com", NOW), Err(Error::WrongHost));
        // The leaf names auth.docker.io and *.auth.docker.io: a wildcard
        // covers one label, not two.
        assert_eq!(check(AUTH, "x.auth.docker.io", NOW), Ok(()));
        assert_eq!(
            check(AUTH, "x.y.auth.docker.io", NOW),
            Err(Error::WrongHost)
        );
        assert_eq!(
            check(AUTH, "auth.docker.io", NOW + 400 * 86_400),
            Err(Error::Expired)
        );
        assert_eq!(
            check(AUTH, "auth.docker.io", 1_600_000_000),
            Err(Error::NotYetValid)
        );
        let ders = pem_certificates(AUTH);
        let chain: Vec<&[u8]> = ders.iter().map(Vec::as_slice).collect();
        assert_eq!(
            verify_chain(&chain, &RootStore::default(), "auth.docker.io", NOW),
            Err(Error::UnknownIssuer)
        );
    }

    #[test]
    fn a_tampered_certificate_is_refused() {
        let mut ders = pem_certificates(AUTH);
        // Flip a bit inside the leaf's signed part (well past the header).
        let at = ders[0].len() / 2;
        ders[0][at] ^= 1;
        let chain: Vec<&[u8]> = ders.iter().map(Vec::as_slice).collect();
        let r = verify_chain(&chain, &RootStore::from_pem(ROOTS), "auth.docker.io", NOW);
        assert!(r.is_err(), "{r:?}");
    }

    #[test]
    fn wildcards_match_one_label() {
        let ders = pem_certificates(REGISTRY);
        let leaf = parse(&ders[0]).unwrap();
        assert!(leaf.dns_names.iter().any(|n| n.starts_with("*.")));
        assert!(leaf.matches_host("registry-1.docker.io"));
        assert!(!leaf.matches_host("a.b.docker.io"));
        assert!(!leaf.matches_host("docker.io.evil"));
    }
}
