//! X.509 for the control plane's TLS (ADR-0012 §3, §4): DER, certificate
//! parsing, PEM bundles, and verification of a server's chain to a root
//! store for a host name at a time.
//!
//! Verification walks from the leaf: each certificate must be within its
//! validity, and each issuer a CA (BasicConstraints, KeyUsage keyCertSign
//! if present, path length, name constraints) whose key verifies the
//! signature. A root whose subject matches is tried first at every step,
//! so cross-signed intermediates end at whichever root is trusted. The
//! leaf must name the host in a DNS SAN and allow server authentication,
//! and every certificate must follow the profile CAs issue to (RFC 5280
//! and the Web PKI's; `docs/tls-and-x509.md` lists the rules).
//!
//! Not handled: RSA-PSS certificate signatures and revocation (a
//! certificate with an unknown critical extension is refused).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

pub mod cert;
pub mod der;
pub mod suffix;

pub use cert::{Certificate, PublicKey, SigAlg, ed25519_seed, parse};
pub use suffix::PublicSuffixes;

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
    /// A CA's name constraints exclude (or do not permit) the leaf's names.
    NameConstraint,
    /// Path building gave up (too many candidate issuers).
    TooComplex,
    /// A certificate breaks a rule of RFC 5280's or the Web PKI's profile
    /// (CABF Baseline Requirements) that conforming CAs follow.
    Nonconforming,
}

/// Most certificates in a path, leaf and root included.
const MAX_DEPTH: usize = 8;

/// Trusted roots, as DER, and the public suffixes no wildcard may cover.
#[derive(Clone, Debug, Default)]
pub struct RootStore {
    roots: Vec<Vec<u8>>,
    suffixes: PublicSuffixes,
}

impl RootStore {
    /// Every certificate in a PEM bundle that parses (others are skipped:
    /// a bundle carries algorithms we may not handle), with no public
    /// suffixes.
    pub fn from_pem(pem: &str) -> RootStore {
        let roots = pem_certificates(pem)
            .into_iter()
            .filter(|der| parse(der).is_ok())
            .collect();
        RootStore {
            roots,
            suffixes: PublicSuffixes::default(),
        }
    }

    /// The store with the Public Suffix List's rules (its own text format,
    /// as `public_suffix_list.dat`; the boot volume's `\ichor\suffixes.dat`
    /// has its ICANN section), against which no wildcard may stand for a
    /// whole public suffix.
    pub fn with_public_suffixes(mut self, rules: &str) -> RootStore {
        self.suffixes = PublicSuffixes::parse(rules);
        self
    }

    /// How many roots cannot anchor a path whatever the date: not formed as
    /// a trust anchor must be, or not a CA for TLS servers.
    pub fn unusable(&self) -> usize {
        self.roots
            .iter()
            .filter(|der| {
                parse(der).is_ok_and(|c| {
                    may_issue(&c, 0).is_err()
                        || !c.ca_well_formed()
                        || !c.root_well_formed()
                        || !c.may_issue_server()
                })
            })
            .count()
    }

    /// How many public suffix rules the store has.
    pub fn public_suffixes(&self) -> usize {
        self.suffixes.len()
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
    pem_blocks(pem, "CERTIFICATE")
}

/// The DER of every `label` block in `pem`.
pub fn pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let is = |line: &str, edge: &str| {
        line.strip_prefix("-----")
            .and_then(|l| l.strip_prefix(edge))
            .and_then(|l| l.strip_prefix(label))
            == Some("-----")
    };
    let mut out = Vec::new();
    let mut body: Option<alloc::string::String> = None;
    for line in pem.lines() {
        let line = line.trim();
        if is(line, "BEGIN ") {
            body = Some(alloc::string::String::new());
        } else if is(line, "END ") {
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

/// Most signature checks one path search may make (a hostile chain could
/// otherwise make the search exponential).
const MAX_SIGNATURE_CHECKS: usize = 64;

struct Search<'s, 'a> {
    leaf: &'s Certificate<'a>,
    pool: &'s [Certificate<'a>],
    roots: &'s [Certificate<'a>],
    now: u64,
    checks: usize,
}

impl Search<'_, '_> {
    /// Whether `issuer` may sign the path below it (`path`: the pool
    /// members between it and the leaf): a CA for TLS servers, valid now,
    /// within its path length (self-issued certificates below do not count,
    /// RFC 5280 6.1.4), its name constraints allowing the leaf's and those
    /// intermediates' names.
    /// A trust anchor (`root`) must also be formed as CABF 7.1.2.1 has a
    /// root CA.
    fn may_extend(
        &self,
        issuer: &Certificate<'_>,
        path: &[usize],
        root: bool,
    ) -> Result<(), Error> {
        valid_at(issuer, self.now)?;
        let self_issued = |i: usize| self.pool[i].issuer == self.pool[i].subject;
        let counted = path.iter().filter(|&&i| !self_issued(i)).count();
        may_issue(issuer, counted)?;
        // A trust anchor's own issuer is not on the path, so it need not
        // name that issuer's key, nor carry a key identifier of its own.
        if !issuer.ca_well_formed()
            || (!root && !(issuer.names_issuer_key() && issuer.has_key_id()))
            || (root && !issuer.root_well_formed())
        {
            return Err(Error::Nonconforming);
        }
        if !issuer.may_issue_server() {
            return Err(Error::NotServerAuth);
        }
        // Name constraints apply to the leaf, and to intermediates that
        // are not self-issued (RFC 5280 4.2.1.10).
        issuer.permits(self.leaf)?;
        for &i in path.iter().filter(|&&i| !self_issued(i)) {
            issuer.permits(&self.pool[i])?;
        }
        Ok(())
    }

    fn signed(&mut self, c: &Certificate<'_>, by: &Certificate<'_>) -> Result<bool, Error> {
        if c.issuer != by.subject {
            return Ok(false);
        }
        self.checks += 1;
        if self.checks > MAX_SIGNATURE_CHECKS {
            return Err(Error::TooComplex);
        }
        Ok(c.signed_by(by))
    }

    /// Extends the path above `current` (`path`: the pool members already
    /// in it, nearest the leaf first) to a trusted root, trying every
    /// candidate issuer in turn. Returns the error of the last failure if
    /// none works.
    fn extend(&mut self, current: &Certificate<'_>, path: &mut Vec<usize>) -> Result<(), Error> {
        if path.len() + 2 > MAX_DEPTH {
            return Err(Error::PathTooLong);
        }
        let mut best = Error::UnknownIssuer;
        // A trusted root ends the path.
        for r in self.roots {
            if !self.signed(current, r)? {
                if current.issuer == r.subject {
                    best = Error::BadSignature;
                }
                continue;
            }
            match self.may_extend(r, path, true) {
                Ok(()) => return Ok(()),
                Err(e) => best = e,
            }
        }
        // Otherwise an intermediate from the pool, then onward.
        for i in 0..self.pool.len() {
            if path.contains(&i) {
                continue;
            }
            let issuer = &self.pool[i];
            if !self.signed(current, issuer)? {
                if current.issuer == issuer.subject {
                    best = Error::BadSignature;
                }
                continue;
            }
            if !issuer.serial_ok {
                best = Error::Malformed;
                continue;
            }
            if let Err(e) = self.may_extend(issuer, path, false) {
                best = e;
                continue;
            }
            path.push(i);
            let r = self.extend(issuer, path);
            path.pop();
            match r {
                Ok(()) => return Ok(()),
                Err(Error::TooComplex) => return Err(Error::TooComplex),
                Err(e) => best = e,
            }
        }
        Err(best)
    }
}

/// Verifies `chain` (the leaf first, then what the server sent, as DER, in
/// any order) for `host` at Unix time `now`: some path from the leaf
/// through the sent certificates to a trusted root must be valid, each
/// issuer a CA within its path length, extended key usage and name
/// constraints.
pub fn verify_chain(chain: &[&[u8]], roots: &RootStore, host: &str, now: u64) -> Result<(), Error> {
    let (leaf, rest) = chain.split_first().ok_or(Error::Malformed)?;
    let leaf = parse(leaf)?;
    // A sent certificate we cannot parse cannot be on the path; it does
    // not spoil the others.
    let pool: Vec<Certificate<'_>> = rest.iter().filter_map(|d| parse(d).ok()).collect();
    let leaf = &leaf;
    if !leaf.matches_host(host) {
        return Err(Error::WrongHost);
    }
    if !leaf.may_serve() {
        return Err(Error::NotServerAuth);
    }
    if !leaf.serial_ok {
        return Err(Error::Malformed);
    }
    // Its names consistent, its issuer's key named, and no wildcard over
    // a whole public suffix.
    if !leaf.names_consistent()
        || !leaf.names_issuer_key()
        || leaf.dns_names.iter().any(|n| {
            n.strip_prefix("*.")
                .is_some_and(|rest| roots.suffixes.is_public_suffix(rest))
        })
    {
        return Err(Error::Nonconforming);
    }
    valid_at(leaf, now)?;
    let roots: Vec<Certificate<'_>> = roots.roots.iter().filter_map(|d| parse(d).ok()).collect();
    Search {
        leaf,
        pool: &pool,
        roots: &roots,
        now,
        checks: 0,
    }
    .extend(leaf, &mut Vec::new())
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
        assert_eq!(roots.len(), 4);
        // RSA, ending in a cross-signed Amazon root under Starfield G2.
        assert_eq!(check(REGISTRY, "registry-1.docker.io", NOW), Ok(()));
        // ECDSA P-256 and P-384 under ISRG Root X2.
        assert_eq!(check(AUTH, "auth.docker.io", NOW), Ok(()));
        assert_eq!(
            check(CLOUDFLARE, "production.cloudflare.docker.com", NOW),
            Ok(())
        );
    }

    /// The boot volume's CA bundle (Mozilla's, which xtask fetches pinned
    /// to `target/roots/`): most of it parses, and Docker Hub's chains
    /// verify against it. `ICHOR_ROOTS=<file> cargo test -p ichor-x509 --
    /// --ignored mozilla`.
    #[test]
    #[ignore = "needs the fetched CA bundle (ICHOR_ROOTS)"]
    fn mozilla_bundle_verifies_docker_hub() {
        extern crate std;
        let path = std::env::var("ICHOR_ROOTS").expect("ICHOR_ROOTS");
        let pem = std::fs::read_to_string(path).unwrap();
        let roots = RootStore::from_pem(&pem);
        let total = pem_certificates(&pem).len();
        std::println!("{} of {total} roots parse", roots.len());
        assert!(roots.len() * 10 >= total * 9);
        for (pem, host) in [
            (REGISTRY, "registry-1.docker.io"),
            (AUTH, "auth.docker.io"),
            (CLOUDFLARE, "production.cloudflare.docker.com"),
        ] {
            let ders = pem_certificates(pem);
            let chain: Vec<&[u8]> = ders.iter().map(Vec::as_slice).collect();
            assert_eq!(verify_chain(&chain, &roots, host, NOW), Ok(()), "{host}");
        }
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
