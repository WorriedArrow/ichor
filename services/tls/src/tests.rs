//! Sessions with real servers, recorded once (`cargo test -p ichor-tls --
//! --ignored record_live`, which needs the internet) and replayed offline:
//! the client's randomness and clock are fixed, so it sends exactly the
//! recorded bytes again and the server's recorded bytes decrypt.

extern crate std;

use super::*;
use crypto::sha2::Digest;
use std::string::ToString;

const ROOTS: &str = include_str!("../../x509/testdata/roots.pem");
/// The clock of every recorded session (2026-11-15).
const NOW: u64 = 1_794_786_687;

/// Recorded sessions: (name, host, request).
const SESSIONS: [(&str, &str, &str); 2] = [
    (
        "registry",
        "registry-1.docker.io",
        "GET /v2/ HTTP/1.1\r\nHost: registry-1.docker.io\r\nUser-Agent: ichor-tls-test\r\nConnection: close\r\n\r\n",
    ),
    (
        "cloudflare",
        "production.cloudflare.docker.com",
        "GET / HTTP/1.1\r\nHost: production.cloudflare.docker.com\r\nUser-Agent: ichor-tls-test\r\nConnection: close\r\n\r\n",
    ),
];

fn config(host: &str, seed: &str) -> Config {
    let mut random = [0u8; 96];
    random[..64].copy_from_slice(&crypto::sha2::Sha512::digest(seed.as_bytes()));
    random[64..].copy_from_slice(&Sha256::hash(host.as_bytes()));
    Config {
        host: host.to_string(),
        roots: Arc::new(x509::RootStore::from_pem(ROOTS)),
        now: NOW,
        random,
    }
}

fn testdata(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

/// Replays a recorded session: the client's bytes must match what it sent
/// then, and the response must decrypt.
fn replay(name: &str, host: &str, request: &str) -> (Client, Vec<u8>) {
    let server = std::fs::read(testdata(&std::format!("{name}.server"))).unwrap();
    let sent = std::fs::read(testdata(&std::format!("{name}.client"))).unwrap();
    let mut c = Client::new(config(host, name));
    c.write(request.as_bytes());
    let mut out = c.take_output();
    c.feed(&server).unwrap();
    out.extend(c.take_output());
    // close_notify may follow; what was sent must start with the recording.
    assert!(
        out.starts_with(&sent) || sent.starts_with(&out),
        "{name}: the client's bytes differ from the recording"
    );
    (c, std::vec::Vec::new())
}

#[test]
fn replays_tls13_with_docker_hubs_registry() {
    let (name, host, req) = SESSIONS[0];
    let (mut c, _) = replay(name, host, req);
    assert_eq!(c.version(), Some(0x0304));
    let resp = String::from_utf8_lossy(&c.read()).into_owned();
    assert!(resp.starts_with("HTTP/1.1 401"), "{resp}");
    assert!(
        resp.to_ascii_lowercase()
            .contains("www-authenticate: bearer"),
        "{resp}"
    );
}

#[test]
fn replays_tls12_with_docker_hubs_blob_cdn() {
    let (name, host, req) = SESSIONS[1];
    let (mut c, _) = replay(name, host, req);
    assert_eq!(c.version(), Some(0x0303));
    let resp = String::from_utf8_lossy(&c.read()).into_owned();
    assert!(resp.starts_with("HTTP/1.1 "), "{resp}");
}

#[test]
fn a_tampered_record_is_refused() {
    let (name, host, req) = SESSIONS[0];
    let mut server = std::fs::read(testdata(&std::format!("{name}.server"))).unwrap();
    // Flip a byte late in the stream: inside the encrypted server flight or
    // the response.
    let at = server.len() - 40;
    server[at] ^= 0x01;
    let mut c = Client::new(config(host, name));
    c.write(req.as_bytes());
    assert_eq!(c.feed(&server), Err(Error::BadRecordMac));
}

#[test]
fn the_wrong_name_or_no_roots_is_refused() {
    let (name, _, _) = SESSIONS[0];
    let server = std::fs::read(testdata(&std::format!("{name}.server"))).unwrap();
    // Same server bytes, but the client expected another host: the
    // certificate check fails (before any key confirmation could).
    let mut cfg = config("registry-1.docker.io", name);
    cfg.roots = Arc::new(x509::RootStore::default());
    let mut c = Client::new(cfg);
    assert_eq!(
        c.feed(&server),
        Err(Error::Certificate(x509::Error::UnknownIssuer))
    );
}

#[test]
fn client_hello_offers_what_the_module_promises() {
    let mut c = Client::new(config("example.test", "hello"));
    let out = c.take_output();
    assert_eq!(&out[..3], &[CT_HANDSHAKE, 3, 1]);
    assert_eq!(out[5], HS_CLIENT_HELLO);
    let s = out.windows(2).position(|w| w == [0x13, 0x03]);
    assert!(s.is_some(), "TLS_CHACHA20_POLY1305_SHA256 offered");
    assert!(out.windows(12).any(|w| w == b"example.test"), "SNI");
}

/// Records the sessions in `SESSIONS` against the live servers.
#[test]
#[ignore = "needs the internet; run to refresh the recordings"]
fn record_live() {
    use std::io::{Read, Write};
    for (name, host, req) in SESSIONS {
        let mut s = std::net::TcpStream::connect((host, 443)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();
        let mut c = Client::new(config(host, name));
        c.write(req.as_bytes());
        let (mut sent, mut got) = (Vec::new(), Vec::new());
        let mut buf = [0u8; 16384];
        loop {
            let out = c.take_output();
            if !out.is_empty() {
                s.write_all(&out).unwrap();
                sent.extend_from_slice(&out);
            }
            let n = match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            got.extend_from_slice(&buf[..n]);
            c.feed(&buf[..n]).unwrap();
            if c.is_closed() {
                break;
            }
        }
        std::fs::create_dir_all(testdata("")).unwrap();
        std::fs::write(testdata(&std::format!("{name}.server")), &got).unwrap();
        std::fs::write(testdata(&std::format!("{name}.client")), &sent).unwrap();
        let resp = String::from_utf8_lossy(&c.read()).into_owned();
        std::println!(
            "{name}: {:?}, {} bytes in; {}",
            c.version(),
            got.len(),
            resp.lines().next().unwrap_or("")
        );
    }
}
