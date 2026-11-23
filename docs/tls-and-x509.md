# TLS and X.509: what is checked, how, and the deliberate gaps

The control plane pulls images over HTTPS with our own TLS client
(`services/tls`) and certificate verification (`services/x509`), on our
own cryptography (`services/crypto`) (ADR-0012 §3, §4), and serves its API
over TLS 1.3 (`services/tls::server`; ADR-0012's 2026-11-21 amendment).
This page says how that code is tested beyond its unit tests, and what it
deliberately does not do.

## How it is tested

- **Recorded traffic.** Live TLS 1.3 and TLS 1.2 sessions with Docker Hub
  and its CDN, recorded with fixed client randomness, replay offline
  (`services/tls/src/tests.rs`); a whole `hello-world` pull replays through
  the OCI client (`services/oci`).
- **The server** runs against our own client (data both ways, a byte at a
  time, key updates, every unsuitable or tampered client refused), against
  OpenSSL's (`cargo test -p ichor-tls -- --ignored openssl`), and end to
  end: `tests/control.rs` pulls and runs images through the API over TLS,
  after checking that it answers nobody in the clear. Ed25519 is checked
  against RFC 8032's vectors and OpenSSL.
- **Certificate path validation: x509-limbo.** `cargo xtask x509-limbo`
  runs C2SP's x509-limbo suite (pinned to commit `519f4bcf`) through
  `verify_chain` and writes [`x509-limbo.md`](x509-limbo.md): the pass rate
  for cases that must be accepted and for cases that must be refused, the
  cases that do not apply and why, and every disagreement. CI fails below
  **100%** either way (`FLOORS` in `xtask/src/limbo.rs`); every applicable
  case agrees (504 accept, 4,799 refuse). Ten cases contradict another
  case, so that no validator can agree with both: they are listed in
  `CONFLICTS` with the case we side with and why (the Web PKI's rule over
  RFC 5280's, and a real certificate over a stricter rule), and each run
  checks that we still disagree with one and agree with the other.
- **Fuzzing.** `fuzz/` mutation-fuzzes every parser that takes untrusted
  input: the TLS client fed a server's side of a session (records,
  handshake messages, certificates, key exchange), the TLS server fed a
  client's, X.509/DER and PEM (private keys too),
  HPACK, HTTP/2 (both ends) and gRPC, protobuf, HTTP/1.1, the registry
  protocol and its JSON, DNS, gzip, tar and the Ichor image format. Seeds
  are real inputs (the recordings, Docker Hub's chains, RFC vectors,
  generated HTTP/2 and gRPC traffic). A panic, overflow included, or an
  input taking over 5 s fails the run and saves the input to `target/fuzz/`
  (`ICHOR_FUZZ_REPLAY=FILE` replays it). Every test run fuzzes briefly; CI
  runs 20,000 inputs per target; `cargo xtask fuzz [TARGET] --iterations N`
  runs longer.
  The fuzzer is not coverage-guided: libFuzzer (`cargo-fuzz`) needs a
  nightly toolchain, and the project pins stable (AGENTS.md, "Unstable
  features"). The target functions in `fuzz/lib.rs` are what such
  harnesses would call, so adding them later is a small change.

## What verification enforces

`x509::verify_chain(chain, roots, host, now)` accepts a server's chain
when some path from the leaf, through the certificates the server sent
(in any order; ones that do not parse are ignored), reaches a trusted
root, with:

- every certificate on the path valid at `now`, and every signature
  verified (RSA PKCS#1 v1.5 and ECDSA P-256/P-384 with SHA-2, Ed25519,
  and ML-DSA-44/65/87 per RFC 9881, whose keys may only sign);
- path building that backtracks over every candidate issuer, trust
  anchors first, bounded at 8 certificates and 64 signature checks;
- each issuer a CA (basicConstraints `cA`, keyCertSign if keyUsage is
  present) within its path length, self-issued intermediates not counted;
- extended key usage: the leaf's must be non-critical and name
  `serverAuth` and not `anyExtendedKeyUsage`; an issuer with an EKU must
  allow `serverAuth` (or `anyExtendedKeyUsage`); a trust anchor may have
  none (CABF 7.1.2.1);
- name constraints on DNS and IP names, permitted and excluded, applied to
  the leaf's and the non-self-issued intermediates' SANs, wildcard-aware;
  critical or not (the Web PKI allows either), never on the leaf; a DNS
  constraint is a name (no leading period, no wildcard); directoryName
  constraints, and constraints of other types when the certificate has
  names of those types, are refused rather than ignored;
- the leaf: not a CA, no keyCertSign, a DNS SAN matching `host` (the
  subject common name is never used, as in Chrome, Go and rustls); DNS
  SANs must be valid host names (no underscores, empty labels or
  misplaced wildcards); no wildcard over a whole public suffix (`*.com`,
  `*.co.uk`: the Public Suffix List's ICANN section, carried in the
  boot volume's CA bundle); its SAN critical exactly when its subject is
  empty;
- the profile CAs must issue to (RFC 5280, CABF): every certificate but a
  self-issued one or a trust anchor names its issuer's key (an
  authorityKeyIdentifier with a keyIdentifier); every CA on the path has a
  subject, a subjectKeyIdentifier and a critical basicConstraints; a
  trust anchor's own AKI, if any, is a keyIdentifier alone, equal to its
  SKI if self-issued; AKI, SKI and AIA must not be critical and AIA must
  be well formed; policy constraints must be critical (and then, as
  policies are not processed, are an unknown critical extension). Of
  Mozilla's roots (2026-11-05), only TWCA Global Root CA, which has no
  SKI, cannot anchor a path;
- unknown critical extensions refused; duplicate extensions, non-positive
  or over-long serial numbers (in certificates a server sends) and RSA
  keys under 2048 bits or not a whole number of bytes refused.

## Deliberate gaps

Each is a choice, with the reason; changing one is a decision for an ADR
amendment.

| Gap | Why |
|---|---|
| No revocation (CRLs, OCSP, OCSP stapling) | Registry certificates are short-lived (Let's Encrypt: 90 days, with revocation effectively deprecated for the Web PKI); a pull also verifies every blob against a digest the client chose. Revisit with signature verification (cosign/notation). |
| No Certificate Transparency checks | Same reasoning; CT enforcement belongs to browsers' policies. |
| Server validation of DNS names only: no IP-address peer names, no email, no client certificates | The control plane connects to registries by name. x509-limbo's IP and client cases are counted as not applicable. |
| Web PKI policy where x509-limbo's RFC and Web PKI cases conflict | A leaf must have `serverAuth` EKU and must not be a CA, and name constraints may be non-critical; RFC 5280 says otherwise. We follow the Web PKI (rustls-webpki, Chromium). `CONFLICTS` in `xtask/src/limbo.rs` lists every such case. |
| The commonName is not checked against the SANs (CABF 7.1.4.3) | It names nothing we match against; bettertls's suite expects unrelated CNs accepted, x509-limbo's `webpki::cn` cases expect them refused. |
| The Public Suffix List's private section is not used: `*.s3.amazonaws.com` is honored | Amazon's own S3 certificate is that wildcard, and registries serve layers from S3; Chrome does the same. |
| No certificate policies processing | Not used by the Web PKI for path validation. |
| RSA-PSS certificate signatures are not accepted | Not used by any registry we pull from; TLS 1.3 handshake signatures do use RSA-PSS (supported there). |
| The TLS server takes only Ed25519 certificates, TLS 1.3, ChaCha20-Poly1305 and X25519, and no HelloRetryRequest | One constant-time path through a long-lived key (ADR-0012's 2026-11-21 amendment). |
| TLS: AES-128-GCM, not AES-256-GCM; SHA-256 suites only; X25519 and P-256 only | ChaCha20-Poly1305 is offered first; AES-128-GCM (bitsliced, constant-time) is for registries without it (Amazon ECR, Microsoft's, Quay). No registry tried needs the others. |
| TLS: no session resumption, 0-RTT, renegotiation, client certificates or record-size limits negotiation | Simplicity; none is needed for pulls. |
| TLS 1.2: only ECDHE with AEAD suites and extended master secret | The suites without forward secrecy or with CBC are not offered. |
