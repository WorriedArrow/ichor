//! The server side (the control API's), TLS 1.3 only: one suite
//! (TLS_CHACHA20_POLY1305_SHA256), X25519, an Ed25519 certificate, ALPN.
//! Every current gRPC client's TLS offers all of these.
//!
//! The same shape as [`crate::Client`]: [`Server::feed`] takes what the
//! client sent, [`Server::take_output`] gives what to send, randomness
//! comes from the caller. A failure queues the alert to send before the
//! connection closes.
//!
//! Not supported: HelloRetryRequest (a client that offers X25519 without a
//! key share for it is refused), session tickets, 0-RTT, client
//! certificates, choosing between certificates by SNI.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crypto::ed25519::SigningKey;
use crypto::hmac::{Hmac, hkdf_extract};
use crypto::sha2::Sha256;
use crypto::x25519;

use crate::{
    CT_ALERT, CT_APP, CT_CCS, CT_HANDSHAKE, ED25519, Error, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY,
    HS_CLIENT_HELLO, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_KEY_UPDATE, HS_SERVER_HELLO,
    MAX_RECORD, Protect, TLS13_CHACHA, X25519, expand_label, ext, handshake_msg, plain_record,
    put_vec, traffic, u16_at, u24_at, vec_at,
};

/// Most bytes in one handshake message from a client (a ClientHello with a
/// post-quantum key share is under 2 KiB).
const MAX_HANDSHAKE: usize = 16384;
/// Most plaintext in a record.
const MAX_PLAINTEXT: usize = 16384;

/// Why an identity (certificate chain and key) was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// No `CERTIFICATE` block.
    NoCertificate,
    /// No `PRIVATE KEY` block holding an Ed25519 key (PKCS #8).
    NoKey,
    /// The first certificate does not parse.
    Certificate(x509::Error),
    /// The first certificate's key is not the private key's.
    Mismatch,
}

/// What a server proves itself with.
#[derive(Debug)]
pub struct Identity {
    /// The certificates to send, DER, the server's own first.
    chain: Vec<Vec<u8>>,
    key: SigningKey,
}

impl Identity {
    /// The certificate chain and Ed25519 private key in `pem` (made with
    /// `openssl genpkey -algorithm ed25519`, say).
    pub fn from_pem(pem: &str) -> Result<Identity, IdentityError> {
        let chain = x509::pem_certificates(pem);
        let leaf = chain.first().ok_or(IdentityError::NoCertificate)?;
        let seed = x509::pem_blocks(pem, "PRIVATE KEY")
            .iter()
            .find_map(|d| x509::ed25519_seed(d))
            .ok_or(IdentityError::NoKey)?;
        let key = SigningKey::from_seed(&seed);
        match x509::parse(leaf).map_err(IdentityError::Certificate)?.key {
            x509::PublicKey::Ed25519(k) if *k == key.public() => {}
            _ => return Err(IdentityError::Mismatch),
        }
        Ok(Identity { chain, key })
    }
}

/// What the caller supplies per connection.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub identity: Arc<Identity>,
    /// The application protocol this server speaks: a client that offers
    /// protocols must offer this one.
    pub alpn: &'static [u8],
    /// 64 random bytes: the server random and the X25519 secret.
    pub random: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    ClientHello,
    Finished,
    Connected,
    Closed,
}

/// A TLS server connection.
pub struct Server {
    cfg: ServerConfig,
    stage: Stage,
    transcript: Vec<u8>,
    inbuf: Vec<u8>,
    hsbuf: Vec<u8>,
    out: Vec<u8>,
    app_in: Vec<u8>,
    pending: Vec<u8>,
    read: Option<Protect>,
    write: Option<Protect>,
    c_hs: Vec<u8>,
    c_ap: Vec<u8>,
    s_ap: Vec<u8>,
}

impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Server")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

/// What the server needs of a ClientHello.
struct Hello<'a> {
    session: &'a [u8],
    share: [u8; 32],
    /// The client offered application protocols, ours among them.
    alpn: bool,
}

/// Whether the 2-byte-item list `list` has `v`; it must be whole items.
fn lists(list: &[u8], v: u16) -> Result<bool, Error> {
    let (items, rest) = list.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error::Decode);
    }
    Ok(items.contains(&v.to_be_bytes()))
}

impl<'a> Hello<'a> {
    fn parse(body: &'a [u8], alpn: &[u8]) -> Result<Hello<'a>, Error> {
        if u16_at(body, 0)? != 0x0303 {
            return Err(Error::Unsupported("protocol version"));
        }
        let mut at = 34; // after the client random
        let session = vec_at(body, &mut at, 1)?;
        if session.len() > 32 {
            return Err(Error::Decode);
        }
        let suites = vec_at(body, &mut at, 2)?;
        let compression = vec_at(body, &mut at, 1)?;
        if at == body.len() {
            return Err(Error::Unsupported("protocol version")); // no extensions
        }
        let exts = vec_at(body, &mut at, 2)?;
        if at != body.len() {
            return Err(Error::Decode);
        }
        let (mut tls13, mut ed25519, mut offered, mut share) = (false, false, None, None);
        let mut seen = Vec::new();
        let mut i = 0;
        while i < exts.len() {
            let ty = u16_at(exts, i)?;
            i += 2;
            let data = vec_at(exts, &mut i, 2)?;
            if seen.contains(&ty) || seen.len() > 64 {
                return Err(Error::Decode);
            }
            seen.push(ty);
            let mut j = 0;
            match ty {
                43 => tls13 = lists(vec_at(data, &mut j, 1)?, 0x0304)?,
                13 => ed25519 = lists(vec_at(data, &mut j, 2)?, ED25519)?,
                51 => {
                    let shares = vec_at(data, &mut j, 2)?;
                    let mut k = 0;
                    while k < shares.len() {
                        let group = u16_at(shares, k)?;
                        k += 2;
                        let key = vec_at(shares, &mut k, 2)?;
                        if group == X25519 && share.is_none() {
                            share = Some(key.try_into().map_err(|_| Error::Decode)?);
                        }
                    }
                }
                16 => {
                    let protocols = vec_at(data, &mut j, 2)?;
                    let mut ours = false;
                    let mut k = 0;
                    while k < protocols.len() {
                        ours |= vec_at(protocols, &mut k, 1)? == alpn;
                    }
                    offered = Some(ours);
                }
                _ => continue,
            }
            if j != data.len() {
                return Err(Error::Decode);
            }
        }
        if !tls13 {
            return Err(Error::Unsupported("protocol version"));
        }
        if compression != [0] {
            return Err(Error::Decode);
        }
        if !lists(suites, TLS13_CHACHA)? {
            return Err(Error::Unsupported("cipher suite"));
        }
        if !ed25519 {
            return Err(Error::Unsupported("signature algorithm"));
        }
        if offered == Some(false) {
            return Err(Error::Unsupported("ALPN"));
        }
        Ok(Hello {
            session,
            share: share.ok_or(Error::Unsupported("key share group"))?,
            alpn: offered.is_some(),
        })
    }
}

/// The alert that tells the peer about `e` (RFC 8446 §6.2).
fn alert(e: &Error) -> u8 {
    match e {
        Error::Unexpected(_) => 10,
        Error::BadRecordMac => 20,
        Error::Unsupported("protocol version") => 70,
        Error::Unsupported("ALPN") => 120,
        Error::Unsupported(_) => 40,
        Error::BadFinished => 51,
        _ => 50, // decode_error
    }
}

impl Server {
    pub fn new(cfg: ServerConfig) -> Server {
        Server {
            cfg,
            stage: Stage::ClientHello,
            transcript: Vec::new(),
            inbuf: Vec::new(),
            hsbuf: Vec::new(),
            out: Vec::new(),
            app_in: Vec::new(),
            pending: Vec::new(),
            read: None,
            write: None,
            c_hs: Vec::new(),
            c_ap: Vec::new(),
            s_ap: Vec::new(),
        }
    }

    /// Whether the handshake is done (the client has proven its Finished).
    pub fn is_connected(&self) -> bool {
        self.stage == Stage::Connected
    }

    /// Whether the connection is over (the client closed it, or an error).
    pub fn is_closed(&self) -> bool {
        self.stage == Stage::Closed
    }

    /// Bytes to send to the client.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    /// Decrypted application data received so far.
    pub fn read(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.app_in)
    }

    /// Queues application data (sent once the handshake is done).
    pub fn write(&mut self, data: &[u8]) {
        match self.stage {
            Stage::Connected => self.send(CT_APP, data),
            Stage::Closed => {}
            _ => self.pending.extend_from_slice(data),
        }
    }

    /// Sends close_notify; nothing is sent after it.
    pub fn close(&mut self) {
        if self.stage == Stage::Connected {
            self.send(CT_ALERT, &[1, 0]);
            self.write = None;
        }
    }

    /// Sends `data` in as many records as it takes.
    fn send(&mut self, ty: u8, data: &[u8]) {
        for chunk in data.chunks(MAX_PLAINTEXT) {
            let rec = match self.write.as_mut() {
                Some(w) => w.seal(ty, chunk),
                None if self.stage == Stage::Connected => return, // closed
                None => plain_record(ty, 0x0303, chunk),
            };
            self.out.extend_from_slice(&rec);
        }
    }

    /// Takes bytes from the client. An error is fatal: the alert is queued
    /// and the connection is closed.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.stage == Stage::Closed {
            return Ok(());
        }
        let r = self.advance(data);
        if let Err(e) = &r {
            if !matches!(e, Error::Alert(_)) {
                self.send(CT_ALERT, &[2, alert(e)]);
            }
            self.stage = Stage::Closed;
            self.app_in.clear();
        }
        if self.stage == Stage::Closed {
            self.inbuf.clear();
            self.hsbuf.clear();
        }
        r
    }

    fn advance(&mut self, data: &[u8]) -> Result<(), Error> {
        self.inbuf.extend_from_slice(data);
        while self.stage != Stage::Closed && self.inbuf.len() >= 5 {
            // What cannot be a record is refused before waiting for all of
            // it (plain HTTP/2, say).
            if !(CT_CCS..=CT_APP).contains(&self.inbuf[0]) {
                return Err(Error::Unexpected(self.inbuf[0]));
            }
            let len = usize::from(u16_at(&self.inbuf, 3)?);
            if len > MAX_RECORD {
                return Err(Error::Decode);
            }
            if self.inbuf.len() < 5 + len {
                break;
            }
            let rec: Vec<u8> = self.inbuf.drain(..5 + len).collect();
            let mut header = [0u8; 5];
            header.copy_from_slice(&rec[..5]);
            self.record(&header, &rec[5..])?;
        }
        Ok(())
    }

    fn record(&mut self, header: &[u8; 5], body: &[u8]) -> Result<(), Error> {
        // A client may send one ChangeCipherSpec for middleboxes' sake
        // between the hellos and its Finished; it means nothing.
        if header[0] == CT_CCS {
            return match self.stage {
                Stage::Finished if body == [1] => Ok(()),
                _ => Err(Error::Unexpected(CT_CCS)),
            };
        }
        let (ty, data) = match self.read.as_mut() {
            Some(_) if header[0] != CT_APP => return Err(Error::Unexpected(header[0])),
            Some(r) => r.open(header, body)?,
            None => (header[0], body.to_vec()),
        };
        if data.len() > MAX_PLAINTEXT {
            return Err(Error::Decode);
        }
        match ty {
            CT_ALERT => match data[..] {
                [_, 0] => {
                    self.stage = Stage::Closed;
                    Ok(())
                }
                [_, code] => Err(Error::Alert(code)),
                _ => Err(Error::Decode),
            },
            CT_HANDSHAKE if !data.is_empty() => {
                self.hsbuf.extend_from_slice(&data);
                while self.hsbuf.len() >= 4 {
                    let len = u24_at(&self.hsbuf, 1)?;
                    if len > MAX_HANDSHAKE {
                        return Err(Error::Decode);
                    }
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
        // Each of these changes the keys: nothing may follow it in the
        // records of the old ones (RFC 8446 §5.1).
        if !self.hsbuf.is_empty() {
            return Err(Error::Unexpected(ty));
        }
        match (self.stage, ty) {
            (Stage::ClientHello, HS_CLIENT_HELLO) => self.client_hello(msg, body),
            (Stage::Finished, HS_FINISHED) => {
                let key = expand_label(&self.c_hs, "finished", &[], 32);
                let want = Hmac::<Sha256>::mac(&key, &Sha256::hash(&self.transcript));
                if !crypto::ct_eq(&want, body) {
                    return Err(Error::BadFinished);
                }
                self.read = traffic(&self.c_ap, true);
                self.stage = Stage::Connected;
                self.transcript = Vec::new();
                self.c_hs = Vec::new();
                let pending = core::mem::take(&mut self.pending);
                self.send(CT_APP, &pending);
                Ok(())
            }
            (Stage::Connected, HS_KEY_UPDATE) => {
                if !matches!(body, [0] | [1]) {
                    return Err(Error::Decode);
                }
                self.c_ap = expand_label(&self.c_ap, "traffic upd", &[], 32);
                self.read = traffic(&self.c_ap, true);
                if body == [1] && self.write.is_some() {
                    self.send(CT_HANDSHAKE, &handshake_msg(HS_KEY_UPDATE, &[0]));
                    self.s_ap = expand_label(&self.s_ap, "traffic upd", &[], 32);
                    self.write = traffic(&self.s_ap, true);
                }
                Ok(())
            }
            (_, ty) => Err(Error::Unexpected(ty)),
        }
    }

    /// Sends a handshake message and adds it to the transcript.
    fn send_handshake(&mut self, ty: u8, body: &[u8]) {
        let m = handshake_msg(ty, body);
        self.transcript.extend_from_slice(&m);
        self.send(CT_HANDSHAKE, &m);
    }

    /// Answers a ClientHello with the server's whole flight.
    fn client_hello(&mut self, msg: &[u8], body: &[u8]) -> Result<(), Error> {
        let h = Hello::parse(body, self.cfg.alpn)?;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&self.cfg.random[32..]);
        let shared = x25519::x25519(&secret, &h.share);
        if shared == [0; 32] {
            return Err(Error::Decode);
        }
        self.transcript.extend_from_slice(msg);

        let mut hello = alloc::vec![3, 3];
        hello.extend_from_slice(&self.cfg.random[..32]);
        put_vec(&mut hello, 1, h.session);
        hello.extend_from_slice(&TLS13_CHACHA.to_be_bytes());
        hello.push(0);
        let mut exts = Vec::new();
        ext(&mut exts, 43, &[3, 4]);
        let mut share = X25519.to_be_bytes().to_vec();
        put_vec(&mut share, 2, &x25519::public_key(&secret));
        ext(&mut exts, 51, &share);
        put_vec(&mut hello, 2, &exts);
        self.send_handshake(HS_SERVER_HELLO, &hello);
        if !h.session.is_empty() {
            self.send(CT_CCS, &[1]);
        }

        let empty = Sha256::hash(&[]);
        let early = hkdf_extract::<Sha256>(&[], &[0u8; 32]);
        let derived = expand_label(&early, "derived", &empty, 32);
        let hs = hkdf_extract::<Sha256>(&derived, &shared);
        let th = Sha256::hash(&self.transcript);
        self.c_hs = expand_label(&hs, "c hs traffic", &th, 32);
        let s_hs = expand_label(&hs, "s hs traffic", &th, 32);
        self.read = traffic(&self.c_hs, true);
        self.write = traffic(&s_hs, true);

        let mut exts = Vec::new();
        if h.alpn {
            let mut name = Vec::new();
            put_vec(&mut name, 1, self.cfg.alpn);
            let mut list = Vec::new();
            put_vec(&mut list, 2, &name);
            ext(&mut exts, 16, &list);
        }
        let mut ee = Vec::new();
        put_vec(&mut ee, 2, &exts);
        self.send_handshake(HS_ENCRYPTED_EXTENSIONS, &ee);

        let identity = self.cfg.identity.clone();
        let mut list = Vec::new();
        for c in &identity.chain {
            put_vec(&mut list, 3, c);
            put_vec(&mut list, 2, &[]);
        }
        let mut cert = alloc::vec![0]; // no request context
        put_vec(&mut cert, 3, &list);
        self.send_handshake(HS_CERTIFICATE, &cert);

        let mut content = alloc::vec![0x20u8; 64];
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        content.extend_from_slice(&Sha256::hash(&self.transcript));
        let mut verify = ED25519.to_be_bytes().to_vec();
        put_vec(&mut verify, 2, &identity.key.sign(&content));
        self.send_handshake(HS_CERTIFICATE_VERIFY, &verify);

        let key = expand_label(&s_hs, "finished", &[], 32);
        let fin = Hmac::<Sha256>::mac(&key, &Sha256::hash(&self.transcript));
        self.send_handshake(HS_FINISHED, &fin);

        let derived = expand_label(&hs, "derived", &empty, 32);
        let master = hkdf_extract::<Sha256>(&derived, &[0u8; 32]);
        let th = Sha256::hash(&self.transcript);
        self.c_ap = expand_label(&master, "c ap traffic", &th, 32);
        self.s_ap = expand_label(&master, "s ap traffic", &th, 32);
        self.write = traffic(&self.s_ap, true);
        self.stage = Stage::Finished;
        Ok(())
    }
}
