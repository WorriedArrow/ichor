//! Cryptography for the control plane (ADR-0012 §3), written from the
//! specifications and checked against their published vectors:
//!
//! - [`sha2`]: SHA-256, SHA-384 and SHA-512 (FIPS 180-4);
//! - [`hmac`]: HMAC (RFC 2104), HKDF (RFC 5869) and the TLS 1.2 PRF
//!   (RFC 5246 §5);
//! - [`aead`]: ChaCha20-Poly1305 (RFC 8439);
//! - [`gcm`]: AES-128-GCM (FIPS 197, SP 800-38D);
//! - [`x25519`]: X25519 key agreement (RFC 7748);
//! - [`p256`]: key agreement on P-256 (SEC 1);
//! - [`ed25519`]: Ed25519 signatures (RFC 8032);
//! - [`ecdsa`], [`rsa`], [`mldsa`] (FIPS 204): verification only
//!   (public values);
//! - [`sha3`]: SHAKE128, SHAKE256 and SHA3-256 (FIPS 202).
//!
//! Secrets (keys, the key agreements' scalars) only flow through code whose timing
//! does not depend on them: no secret-indexed tables, no secret branches.
//! Tag comparison is constant-time ([`ct_eq`]).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod aead;
mod aes;
pub mod bignum;
pub mod ecdsa;
pub mod ed25519;
mod field;
pub mod gcm;
pub mod hmac;
pub mod mldsa;
pub mod p256;
pub mod rsa;
pub mod sha2;
pub mod sha3;
pub mod x25519;

/// A hash for signatures and their encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Digest length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
        }
    }

    pub fn digest(self, data: &[u8]) -> alloc::vec::Vec<u8> {
        use sha2::Digest;
        match self {
            HashAlg::Sha256 => sha2::Sha256::digest(data),
            HashAlg::Sha384 => sha2::Sha384::digest(data),
            HashAlg::Sha512 => sha2::Sha512::digest(data),
        }
    }
}

/// Compares two byte strings in time that depends only on their lengths.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

#[cfg(test)]
pub(crate) fn hex(s: &str) -> alloc::vec::Vec<u8> {
    let s: alloc::string::String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
