//! A sans-I/O TLS client (ADR-0012 §3): TLS 1.3 (RFC 8446) and TLS 1.2
//! (RFC 5246, with ECDHE and AEAD only), enough to talk to container
//! registries and their CDNs.
//!
//! The caller moves bytes: [`Client::feed`] takes what arrived from the
//! server, [`Client::take_output`] gives what to send, [`Client::write`]
//! and [`Client::read`] carry application data. Randomness and the time
//! come from the caller, so a session is reproducible from its inputs.
//!
//! Offered: TLS_CHACHA20_POLY1305_SHA256 (1.3) and
//! TLS_ECDHE_{ECDSA,RSA}_WITH_CHACHA20_POLY1305_SHA256 (1.2), X25519 only,
//! ECDSA P-256/P-384, RSA-PSS and (1.2 only) RSA PKCS#1 v1.5 signatures.
//! The server's chain is verified to the caller's roots for the host name
//! (`services/x509`). 1.2 uses the extended master secret when the server
//! offers it and refuses a downgrade signalled by a 1.3-capable server.
//!
//! Not supported: session resumption and 0-RTT, HelloRetryRequest,
//! renegotiation, client certificates, AES-GCM suites.
//!
//! [`server`] is the other end, for the control API.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crypto::HashAlg;
use crypto::aead::{ChaCha20Poly1305, TAG};
use crypto::ecdsa::{self, Curve};
use crypto::hmac::{Hmac, hkdf_expand, hkdf_extract, tls12_prf};
use crypto::sha2::Sha256;
use crypto::x25519;

pub mod server;

/// Why a connection failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The peer sent something malformed.
    Decode,
    /// A message we did not expect in this state.
    Unexpected(u8),
    BadRecordMac,
    /// The server sent a fatal alert (its description).
    Alert(u8),
    /// The server chose something we do not support.
    Unsupported(&'static str),
    Certificate(x509::Error),
    BadSignature,
    BadFinished,
    /// The server closed the connection (close_notify).
    Closed,
}

const CT_CCS: u8 = 20;
const CT_ALERT: u8 = 21;
const CT_HANDSHAKE: u8 = 22;
const CT_APP: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_SERVER_KEY_EXCHANGE: u8 = 12;
const HS_SERVER_HELLO_DONE: u8 = 14;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_CLIENT_KEY_EXCHANGE: u8 = 16;
const HS_FINISHED: u8 = 20;
const HS_KEY_UPDATE: u8 = 24;

const TLS13_CHACHA: u16 = 0x1303;
const ECDHE_ECDSA_CHACHA: u16 = 0xcca9;
const ECDHE_RSA_CHACHA: u16 = 0xcca8;
const X25519: u16 = 0x001d;

const SIG_SCHEMES: [u16; 8] = [
    0x0403, // ecdsa_secp256r1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0804, // rsa_pss_rsae_sha256
    0x0805, // rsa_pss_rsae_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0401, // rsa_pkcs1_sha256 (TLS 1.2)
    0x0501, // rsa_pkcs1_sha384
    0x0601, // rsa_pkcs1_sha512
];

/// The ed25519 signature scheme.
const ED25519: u16 = 0x0807;

/// The ServerHello random of a HelloRetryRequest (RFC 8446 §4.1.3).
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Largest record payload we accept (2^14 plus AEAD and padding slack).
const MAX_RECORD: usize = 16384 + 256;

/// What the caller supplies per connection.
#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub roots: Arc<x509::RootStore>,
    /// Unix seconds, for certificate validity.
    pub now: u64,
    /// 96 random bytes: the client random, the X25519 secret and the
    /// legacy session id.
    pub random: [u8; 96],
    /// Offer Ed25519 signatures too (the control API's server makes them;
    /// public CAs do not issue such certificates).
    pub ed25519: bool,
    /// The application protocol to offer, if any.
    pub alpn: Option<&'static [u8]>,
}

/// One direction's record protection.
struct Protect {
    aead: ChaCha20Poly1305,
    iv: [u8; 12],
    seq: u64,
    tls13: bool,
}

impl Protect {
    fn new(key: &[u8], iv: &[u8], tls13: bool) -> Option<Protect> {
        Some(Protect {
            aead: ChaCha20Poly1305::new(key.try_into().ok()?),
            iv: iv.try_into().ok()?,
            seq: 0,
            tls13,
        })
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        n
    }

    /// A protected record of type `ty` carrying `data`.
    fn seal(&mut self, ty: u8, data: &[u8]) -> Vec<u8> {
        let nonce = self.nonce();
        self.seq += 1;
        let (outer, mut body, aad) = if self.tls13 {
            let mut inner = data.to_vec();
            inner.push(ty);
            let len = (inner.len() + TAG) as u16;
            let mut aad = alloc::vec![CT_APP, 3, 3];
            aad.extend_from_slice(&len.to_be_bytes());
            (CT_APP, inner, aad)
        } else {
            let mut aad = (self.seq - 1).to_be_bytes().to_vec();
            aad.extend_from_slice(&[ty, 3, 3]);
            aad.extend_from_slice(&(data.len() as u16).to_be_bytes());
            (ty, data.to_vec(), aad)
        };
        self.aead.seal(&nonce, &aad, &mut body);
        let mut rec = alloc::vec![outer, 3, 3];
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    /// Opens a record: its real content type and plaintext.
    fn open(&mut self, header: &[u8; 5], body: &[u8]) -> Result<(u8, Vec<u8>), Error> {
        if body.len() < TAG {
            return Err(Error::BadRecordMac);
        }
        let nonce = self.nonce();
        let mut data = body.to_vec();
        let ty = if self.tls13 {
            if !self.aead.open(&nonce, header, &mut data) {
                return Err(Error::BadRecordMac);
            }
            while data.last() == Some(&0) {
                data.pop();
            }
            data.pop().ok_or(Error::Decode)?
        } else {
            let mut aad = self.seq.to_be_bytes().to_vec();
            aad.extend_from_slice(&[header[0], 3, 3]);
            aad.extend_from_slice(&((body.len() - TAG) as u16).to_be_bytes());
            if !self.aead.open(&nonce, &aad, &mut data) {
                return Err(Error::BadRecordMac);
            }
            header[0]
        };
        self.seq += 1;
        Ok((ty, data))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    WaitServerHello,
    EncryptedExtensions,
    Certificate13,
    CertificateVerify13,
    Finished13,
    Certificate12,
    ServerKeyExchange,
    ServerHelloDone,
    ChangeCipherSpec12,
    Finished12,
    Connected,
    Closed,
}

/// A TLS client connection.
pub struct Client {
    cfg: Config,
    stage: Stage,
    tls13: bool,
    server_random: [u8; 32],
    transcript: Vec<u8>,
    inbuf: Vec<u8>,
    hsbuf: Vec<u8>,
    out: Vec<u8>,
    app_in: Vec<u8>,
    pending: Vec<u8>,
    read: Option<Protect>,
    write: Option<Protect>,
    chain: Vec<Vec<u8>>,
    // TLS 1.3 secrets.
    hs_secret: Vec<u8>,
    c_hs: Vec<u8>,
    s_hs: Vec<u8>,
    c_ap: Vec<u8>,
    s_ap: Vec<u8>,
    // TLS 1.2.
    ems: bool,
    server_key: [u8; 32],
    master: Vec<u8>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("host", &self.cfg.host)
            .field("stage", &self.stage)
            .field("tls13", &self.tls13)
            .finish_non_exhaustive()
    }
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes([
        *b.get(at).ok_or(Error::Decode)?,
        *b.get(at + 1).ok_or(Error::Decode)?,
    ]))
}

fn u24_at(b: &[u8], at: usize) -> Result<usize, Error> {
    let s = b.get(at..at + 3).ok_or(Error::Decode)?;
    Ok((usize::from(s[0]) << 16) | (usize::from(s[1]) << 8) | usize::from(s[2]))
}

/// A length-prefixed slice at `*at` (`n`-byte length); advances `*at`.
fn vec_at<'a>(b: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], Error> {
    let len = match n {
        1 => usize::from(*b.get(*at).ok_or(Error::Decode)?),
        2 => usize::from(u16_at(b, *at)?),
        _ => u24_at(b, *at)?,
    };
    let start = *at + n;
    let s = b.get(start..start + len).ok_or(Error::Decode)?;
    *at = start + len;
    Ok(s)
}

fn put_vec(out: &mut Vec<u8>, n: usize, data: &[u8]) {
    let len = data.len();
    match n {
        1 => out.push(len as u8),
        2 => out.extend_from_slice(&(len as u16).to_be_bytes()),
        _ => out.extend_from_slice(&(len as u32).to_be_bytes()[1..]),
    }
    out.extend_from_slice(data);
}

fn ext(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&ty.to_be_bytes());
    put_vec(out, 2, data);
}

fn handshake_msg(ty: u8, body: &[u8]) -> Vec<u8> {
    let mut m = alloc::vec![ty];
    put_vec(&mut m, 3, body);
    m
}

fn plain_record(ty: u8, version: u16, data: &[u8]) -> Vec<u8> {
    let mut r = alloc::vec![ty];
    r.extend_from_slice(&version.to_be_bytes());
    put_vec(&mut r, 2, data);
    r
}

/// HKDF-Expand-Label (RFC 8446 §7.1) with SHA-256.
fn expand_label(secret: &[u8], label: &str, ctx: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(10 + label.len() + ctx.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    put_vec(&mut info, 1, ctx);
    hkdf_expand::<Sha256>(secret, &info, len)
}

fn traffic(secret: &[u8], tls13: bool) -> Option<Protect> {
    Protect::new(
        &expand_label(secret, "key", &[], 32),
        &expand_label(secret, "iv", &[], 12),
        tls13,
    )
}

/// Verifies a handshake signature with the leaf's key.
fn verify_sig(leaf: &[u8], scheme: u16, msg: &[u8], sig: &[u8], tls13: bool) -> bool {
    let Ok(cert) = x509::parse(leaf) else {
        return false;
    };
    if let (ED25519, x509::PublicKey::Ed25519(k)) = (scheme, cert.key) {
        return crypto::ed25519::verify(k, msg, sig);
    }
    let hash = match scheme {
        0x0403 | 0x0804 | 0x0401 => HashAlg::Sha256,
        0x0503 | 0x0805 | 0x0501 => HashAlg::Sha384,
        0x0603 | 0x0806 | 0x0601 => HashAlg::Sha512,
        _ => return false,
    };
    let digest = hash.digest(msg);
    match (scheme, cert.key) {
        (0x0403 | 0x0503 | 0x0603, x509::PublicKey::Ec { curve, point }) => {
            // TLS 1.3 binds the curve to the scheme; 1.2 names the hash only.
            let bound = matches!(
                (scheme, curve),
                (0x0403, Curve::P256) | (0x0503, Curve::P384)
            );
            (bound || !tls13) && ecdsa::verify_der(curve, point, &digest, sig)
        }
        (0x0804..=0x0806, x509::PublicKey::Rsa { n, e }) => crypto::rsa::PublicKey::new(n, e)
            .is_some_and(|k| k.verify_pss(hash, &digest, sig, Some(hash.output_len()))),
        (0x0401 | 0x0501 | 0x0601, x509::PublicKey::Rsa { n, e }) if !tls13 => {
            crypto::rsa::PublicKey::new(n, e).is_some_and(|k| k.verify_pkcs1(hash, &digest, sig))
        }
        _ => false,
    }
}

impl Client {
    /// Starts a connection: the ClientHello is ready in
    /// [`Client::take_output`].
    pub fn new(cfg: Config) -> Client {
        let mut c = Client {
            cfg,
            stage: Stage::WaitServerHello,
            tls13: false,
            server_random: [0; 32],
            transcript: Vec::new(),
            inbuf: Vec::new(),
            hsbuf: Vec::new(),
            out: Vec::new(),
            app_in: Vec::new(),
            pending: Vec::new(),
            read: None,
            write: None,
            chain: Vec::new(),
            hs_secret: Vec::new(),
            c_hs: Vec::new(),
            s_hs: Vec::new(),
            c_ap: Vec::new(),
            s_ap: Vec::new(),
            ems: false,
            server_key: [0; 32],
            master: Vec::new(),
        };
        let hello = handshake_msg(HS_CLIENT_HELLO, &c.client_hello());
        c.transcript.extend_from_slice(&hello);
        c.out
            .extend_from_slice(&plain_record(CT_HANDSHAKE, 0x0301, &hello));
        c
    }

    fn client_random(&self) -> &[u8] {
        &self.cfg.random[..32]
    }

    fn secret(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&self.cfg.random[32..64]);
        s
    }

    fn client_hello(&self) -> Vec<u8> {
        let mut b = alloc::vec![3, 3];
        b.extend_from_slice(self.client_random());
        put_vec(&mut b, 1, &self.cfg.random[64..96]);
        let mut suites = Vec::new();
        for s in [TLS13_CHACHA, ECDHE_ECDSA_CHACHA, ECDHE_RSA_CHACHA] {
            suites.extend_from_slice(&s.to_be_bytes());
        }
        put_vec(&mut b, 2, &suites);
        put_vec(&mut b, 1, &[0]);
        let mut exts = Vec::new();
        let mut sni = alloc::vec![0];
        put_vec(&mut sni, 2, self.cfg.host.as_bytes());
        let mut sni_list = Vec::new();
        put_vec(&mut sni_list, 2, &sni);
        ext(&mut exts, 0, &sni_list);
        ext(&mut exts, 43, &[4, 3, 4, 3, 3]);
        ext(&mut exts, 10, &[0, 2, 0, 0x1d]);
        let mut algs = Vec::new();
        for s in SIG_SCHEMES {
            algs.extend_from_slice(&s.to_be_bytes());
        }
        if self.cfg.ed25519 {
            algs.extend_from_slice(&ED25519.to_be_bytes());
        }
        let mut sa = Vec::new();
        put_vec(&mut sa, 2, &algs);
        ext(&mut exts, 13, &sa);
        let mut share = X25519.to_be_bytes().to_vec();
        put_vec(&mut share, 2, &x25519::public_key(&self.secret()));
        let mut ks = Vec::new();
        put_vec(&mut ks, 2, &share);
        ext(&mut exts, 51, &ks);
        ext(&mut exts, 11, &[1, 0]);
        ext(&mut exts, 23, &[]);
        ext(&mut exts, 0xff01, &[0]);
        if let Some(p) = self.cfg.alpn {
            let mut name = Vec::new();
            put_vec(&mut name, 1, p);
            let mut list = Vec::new();
            put_vec(&mut list, 2, &name);
            ext(&mut exts, 16, &list);
        }
        put_vec(&mut b, 2, &exts);
        b
    }

    /// Whether application data can flow.
    pub fn is_connected(&self) -> bool {
        self.stage == Stage::Connected
    }

    /// Whether the server closed the connection.
    pub fn is_closed(&self) -> bool {
        self.stage == Stage::Closed
    }

    /// Which version was negotiated (`None` before the ServerHello).
    pub fn version(&self) -> Option<u16> {
        (self.stage != Stage::WaitServerHello).then_some(if self.tls13 { 0x0304 } else { 0x0303 })
    }

    /// Bytes to send to the server.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    /// Decrypted application data received so far.
    pub fn read(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Queues application data (sent once the handshake is done).
    pub fn write(&mut self, data: &[u8]) {
        if self.stage == Stage::Connected {
            self.send_app(data);
        } else {
            self.pending.extend_from_slice(data);
        }
    }

    fn send_app(&mut self, data: &[u8]) {
        let Some(w) = self.write.as_mut() else {
            return;
        };
        for chunk in data.chunks(16384) {
            let rec = w.seal(CT_APP, chunk);
            self.out.extend_from_slice(&rec);
        }
    }

    /// Sends close_notify.
    pub fn close(&mut self) {
        if let Some(w) = self.write.as_mut() {
            let rec = w.seal(CT_ALERT, &[1, 0]);
            self.out.extend_from_slice(&rec);
        }
    }

    /// Takes bytes from the server. An error is fatal to the connection.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inbuf.extend_from_slice(data);
        loop {
            if self.stage == Stage::Closed {
                self.inbuf.clear();
                return Ok(());
            }
            if self.inbuf.len() < 5 {
                return Ok(());
            }
            let len = usize::from(u16_at(&self.inbuf, 3)?);
            if len > MAX_RECORD {
                return Err(Error::Decode);
            }
            if self.inbuf.len() < 5 + len {
                return Ok(());
            }
            let rec: Vec<u8> = self.inbuf.drain(..5 + len).collect();
            let mut header = [0u8; 5];
            header.copy_from_slice(&rec[..5]);
            self.record(&header, &rec[5..])?;
        }
    }

    fn record(&mut self, header: &[u8; 5], body: &[u8]) -> Result<(), Error> {
        let ty = header[0];
        if ty == CT_CCS {
            if body != [1] {
                return Err(Error::Decode);
            }
            if self.stage == Stage::ChangeCipherSpec12 {
                self.install_tls12_read()?;
                self.stage = Stage::Finished12;
            }
            // TLS 1.3 servers may send one for middlebox compatibility.
            return Ok(());
        }
        let (ty, data) = match self.read.as_mut() {
            Some(r) => r.open(header, body)?,
            None => (ty, body.to_vec()),
        };
        match ty {
            CT_ALERT => {
                if data.len() != 2 {
                    return Err(Error::Decode);
                }
                if data[1] == 0 {
                    self.stage = Stage::Closed;
                    return Ok(());
                }
                Err(Error::Alert(data[1]))
            }
            CT_HANDSHAKE => {
                self.hsbuf.extend_from_slice(&data);
                while self.hsbuf.len() >= 4 {
                    let len = u24_at(&self.hsbuf, 1)?;
                    if self.hsbuf.len() < 4 + len {
                        break;
                    }
                    let msg: Vec<u8> = self.hsbuf.drain(..4 + len).collect();
                    self.handshake(&msg)?;
                }
                Ok(())
            }
            CT_APP if self.stage == Stage::Connected => {
                self.app_in.extend_from_slice(&data);
                Ok(())
            }
            other => Err(Error::Unexpected(other)),
        }
    }

    fn handshake(&mut self, msg: &[u8]) -> Result<(), Error> {
        let (ty, body) = (msg[0], &msg[4..]);
        match (self.stage, ty) {
            (Stage::WaitServerHello, HS_SERVER_HELLO) => self.server_hello(msg, body),
            (Stage::EncryptedExtensions, HS_ENCRYPTED_EXTENSIONS) => {
                self.transcript.extend_from_slice(msg);
                self.stage = Stage::Certificate13;
                Ok(())
            }
            (Stage::Certificate13, HS_CERTIFICATE) => {
                let mut at = 0;
                if !vec_at(body, &mut at, 1)?.is_empty() {
                    return Err(Error::Decode);
                }
                let list = vec_at(body, &mut at, 3)?;
                let mut i = 0;
                let mut chain = Vec::new();
                while i < list.len() {
                    chain.push(vec_at(list, &mut i, 3)?.to_vec());
                    vec_at(list, &mut i, 2)?; // per-certificate extensions
                }
                self.take_chain(chain)?;
                self.transcript.extend_from_slice(msg);
                self.stage = Stage::CertificateVerify13;
                Ok(())
            }
            (Stage::CertificateVerify13, HS_CERTIFICATE_VERIFY) => {
                let scheme = u16_at(body, 0)?;
                let mut at = 2;
                let sig = vec_at(body, &mut at, 2)?;
                let mut content = alloc::vec![0x20u8; 64];
                content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
                content.extend_from_slice(&Sha256::hash(&self.transcript));
                if !verify_sig(&self.chain[0], scheme, &content, sig, true) {
                    return Err(Error::BadSignature);
                }
                self.transcript.extend_from_slice(msg);
                self.stage = Stage::Finished13;
                Ok(())
            }
            (Stage::Finished13, HS_FINISHED) => self.finished13(msg, body),
            (Stage::Certificate12, HS_CERTIFICATE) => {
                let mut at = 0;
                let list = vec_at(body, &mut at, 3)?;
                let mut i = 0;
                let mut chain = Vec::new();
                while i < list.len() {
                    chain.push(vec_at(list, &mut i, 3)?.to_vec());
                }
                self.take_chain(chain)?;
                self.transcript.extend_from_slice(msg);
                self.stage = Stage::ServerKeyExchange;
                Ok(())
            }
            (Stage::ServerKeyExchange, HS_SERVER_KEY_EXCHANGE) => {
                if body.first() != Some(&3) || u16_at(body, 1)? != X25519 {
                    return Err(Error::Unsupported("key exchange group"));
                }
                let mut at = 3;
                let key = vec_at(body, &mut at, 1)?;
                let params = &body[..at];
                let scheme = u16_at(body, at)?;
                at += 2;
                let sig = vec_at(body, &mut at, 2)?;
                let mut signed = self.client_random().to_vec();
                signed.extend_from_slice(&self.server_random);
                signed.extend_from_slice(params);
                if !verify_sig(&self.chain[0], scheme, &signed, sig, false) {
                    return Err(Error::BadSignature);
                }
                self.server_key = key.try_into().map_err(|_| Error::Decode)?;
                self.transcript.extend_from_slice(msg);
                self.stage = Stage::ServerHelloDone;
                Ok(())
            }
            (Stage::ServerHelloDone, HS_SERVER_HELLO_DONE) => {
                self.transcript.extend_from_slice(msg);
                self.client_flight12()
            }
            (Stage::Finished12, HS_FINISHED) => {
                let want = tls12_prf::<Sha256>(
                    &self.master,
                    b"server finished",
                    &Sha256::hash(&self.transcript),
                    12,
                );
                if !crypto::ct_eq(&want, body) {
                    return Err(Error::BadFinished);
                }
                self.transcript.extend_from_slice(msg);
                self.connected();
                Ok(())
            }
            (Stage::Connected, HS_NEW_SESSION_TICKET) if self.tls13 => Ok(()),
            (Stage::Connected, HS_KEY_UPDATE) if self.tls13 => {
                self.s_ap = expand_label(&self.s_ap, "traffic upd", &[], 32);
                self.read = traffic(&self.s_ap, true);
                if body.first() == Some(&1) {
                    // update_requested: answer, then move our own keys on.
                    if let Some(w) = self.write.as_mut() {
                        let rec = w.seal(CT_HANDSHAKE, &handshake_msg(HS_KEY_UPDATE, &[0]));
                        self.out.extend_from_slice(&rec);
                    }
                    self.c_ap = expand_label(&self.c_ap, "traffic upd", &[], 32);
                    self.write = traffic(&self.c_ap, true);
                }
                Ok(())
            }
            (_, ty) => Err(Error::Unexpected(ty)),
        }
    }

    fn take_chain(&mut self, chain: Vec<Vec<u8>>) -> Result<(), Error> {
        let refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
        x509::verify_chain(&refs, &self.cfg.roots, &self.cfg.host, self.cfg.now)
            .map_err(Error::Certificate)?;
        self.chain = chain;
        Ok(())
    }

    fn server_hello(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Error> {
        let version = u16_at(body, 0)?;
        let random: [u8; 32] = body
            .get(2..34)
            .ok_or(Error::Decode)?
            .try_into()
            .map_err(|_| Error::Decode)?;
        if random == HRR_RANDOM {
            return Err(Error::Unsupported("HelloRetryRequest"));
        }
        let mut at = 34;
        vec_at(body, &mut at, 1)?; // legacy session id
        let suite = u16_at(body, at)?;
        at += 2;
        if body.get(at) != Some(&0) {
            return Err(Error::Decode);
        }
        at += 1;
        let mut selected = None;
        let mut share = None;
        let mut ems = false;
        if at < body.len() {
            let exts = vec_at(body, &mut at, 2)?;
            let mut i = 0;
            while i < exts.len() {
                let ty = u16_at(exts, i)?;
                i += 2;
                let data = vec_at(exts, &mut i, 2)?;
                match ty {
                    43 => selected = Some(u16_at(data, 0)?),
                    51 => {
                        if u16_at(data, 0)? != X25519 {
                            return Err(Error::Unsupported("key share group"));
                        }
                        let mut j = 2;
                        share = Some(vec_at(data, &mut j, 2)?.to_vec());
                    }
                    23 => ems = true,
                    _ => {}
                }
            }
        }
        self.server_random = random;
        self.transcript.extend_from_slice(msg);
        if selected == Some(0x0304) {
            if suite != TLS13_CHACHA {
                return Err(Error::Unsupported("cipher suite"));
            }
            let theirs: [u8; 32] = share
                .ok_or(Error::Decode)?
                .try_into()
                .map_err(|_| Error::Decode)?;
            let shared = x25519::x25519(&self.secret(), &theirs);
            if shared == [0; 32] {
                return Err(Error::Decode);
            }
            self.tls13 = true;
            let early = hkdf_extract::<Sha256>(&[], &[0u8; 32]);
            let empty = Sha256::hash(&[]);
            let derived = expand_label(&early, "derived", &empty, 32);
            self.hs_secret = hkdf_extract::<Sha256>(&derived, &shared);
            let th = Sha256::hash(&self.transcript);
            self.c_hs = expand_label(&self.hs_secret, "c hs traffic", &th, 32);
            self.s_hs = expand_label(&self.hs_secret, "s hs traffic", &th, 32);
            self.read = traffic(&self.s_hs, true);
            self.write = traffic(&self.c_hs, true);
            self.stage = Stage::EncryptedExtensions;
            return Ok(());
        }
        if version != 0x0303 || selected.is_some() {
            return Err(Error::Unsupported("protocol version"));
        }
        // A server that can do 1.3 but answers 1.2 marks its random
        // (RFC 8446 §4.1.3): someone in the middle downgraded us.
        if random[24..] == *b"DOWNGRD\x01" {
            return Err(Error::Unsupported("downgrade"));
        }
        if suite != ECDHE_ECDSA_CHACHA && suite != ECDHE_RSA_CHACHA {
            return Err(Error::Unsupported("cipher suite"));
        }
        self.ems = ems;
        self.stage = Stage::Certificate12;
        Ok(())
    }

    fn finished13(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Error> {
        let th = Sha256::hash(&self.transcript);
        let key = expand_label(&self.s_hs, "finished", &[], 32);
        if !crypto::ct_eq(&Hmac::<Sha256>::mac(&key, &th), body) {
            return Err(Error::BadFinished);
        }
        self.transcript.extend_from_slice(msg);
        let th = Sha256::hash(&self.transcript);
        let empty = Sha256::hash(&[]);
        let derived = expand_label(&self.hs_secret, "derived", &empty, 32);
        let master = hkdf_extract::<Sha256>(&derived, &[0u8; 32]);
        self.c_ap = expand_label(&master, "c ap traffic", &th, 32);
        self.s_ap = expand_label(&master, "s ap traffic", &th, 32);
        // Our Finished, after the compatibility ChangeCipherSpec (we sent a
        // legacy session id).
        self.out
            .extend_from_slice(&plain_record(CT_CCS, 0x0303, &[1]));
        let ckey = expand_label(&self.c_hs, "finished", &[], 32);
        let fin = handshake_msg(HS_FINISHED, &Hmac::<Sha256>::mac(&ckey, &th));
        if let Some(w) = self.write.as_mut() {
            let rec = w.seal(CT_HANDSHAKE, &fin);
            self.out.extend_from_slice(&rec);
        }
        self.transcript.extend_from_slice(&fin);
        self.read = traffic(&self.s_ap, true);
        self.write = traffic(&self.c_ap, true);
        self.connected();
        Ok(())
    }

    fn client_flight12(&mut self) -> Result<(), Error> {
        let mut cke = Vec::new();
        put_vec(&mut cke, 1, &x25519::public_key(&self.secret()));
        let cke = handshake_msg(HS_CLIENT_KEY_EXCHANGE, &cke);
        self.transcript.extend_from_slice(&cke);
        let pms = x25519::x25519(&self.secret(), &self.server_key);
        if pms == [0; 32] {
            return Err(Error::Decode);
        }
        let mut randoms = self.client_random().to_vec();
        randoms.extend_from_slice(&self.server_random);
        self.master = if self.ems {
            tls12_prf::<Sha256>(
                &pms,
                b"extended master secret",
                &Sha256::hash(&self.transcript),
                48,
            )
        } else {
            tls12_prf::<Sha256>(&pms, b"master secret", &randoms, 48)
        };
        let mut sr_cr = self.server_random.to_vec();
        sr_cr.extend_from_slice(self.client_random());
        let kb = tls12_prf::<Sha256>(&self.master, b"key expansion", &sr_cr, 88);
        self.write = Protect::new(&kb[..32], &kb[64..76], false);
        self.out
            .extend_from_slice(&plain_record(CT_HANDSHAKE, 0x0303, &cke));
        self.out
            .extend_from_slice(&plain_record(CT_CCS, 0x0303, &[1]));
        let vd = tls12_prf::<Sha256>(
            &self.master,
            b"client finished",
            &Sha256::hash(&self.transcript),
            12,
        );
        let fin = handshake_msg(HS_FINISHED, &vd);
        if let Some(w) = self.write.as_mut() {
            let rec = w.seal(CT_HANDSHAKE, &fin);
            self.out.extend_from_slice(&rec);
        }
        self.transcript.extend_from_slice(&fin);
        self.stage = Stage::ChangeCipherSpec12;
        Ok(())
    }

    fn install_tls12_read(&mut self) -> Result<(), Error> {
        let mut sr_cr = self.server_random.to_vec();
        sr_cr.extend_from_slice(self.client_random());
        let kb = tls12_prf::<Sha256>(&self.master, b"key expansion", &sr_cr, 88);
        self.read = Some(Protect::new(&kb[32..64], &kb[76..88], false).ok_or(Error::Decode)?);
        Ok(())
    }

    fn connected(&mut self) {
        self.stage = Stage::Connected;
        let pending = core::mem::take(&mut self.pending);
        if !pending.is_empty() {
            self.send_app(&pending);
        }
    }
}

#[cfg(test)]
mod server_tests;
#[cfg(test)]
mod tests;
