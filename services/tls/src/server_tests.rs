//! The server against this crate's client, and (ignored: it needs an
//! `openssl` on the path) against OpenSSL's.

extern crate std;

use super::server::{Identity, IdentityError, Server, ServerConfig};
use super::*;
use std::string::ToString;
use std::vec;

/// A throwaway chain for these tests alone: `api.pem` is a server's
/// certificate for `ichor-api.test` and its key, `api-ca.pem` the CA that
/// signed it (both Ed25519, made with OpenSSL).
const API: &str = include_str!("../testdata/api.pem");
const CA: &str = include_str!("../testdata/api-ca.pem");
const NOW: u64 = 1_795_400_000;

fn server() -> Server {
    Server::new(ServerConfig {
        identity: Arc::new(Identity::from_pem(API).unwrap()),
        alpn: b"h2",
        random: core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x5a),
    })
}

fn client_config() -> Config {
    Config {
        host: "ichor-api.test".to_string(),
        roots: Arc::new(x509::RootStore::from_pem(CA)),
        now: NOW,
        random: core::array::from_fn(|i| (i as u8).wrapping_mul(13) ^ 0xa5),
        ed25519: true,
        alpn: Some(b"h2"),
    }
}

/// Moves bytes both ways until neither has any left, or one fails.
fn run(c: &mut Client, s: &mut Server) -> (Result<(), Error>, Result<(), Error>) {
    let (mut rc, mut rs) = (Ok(()), Ok(()));
    loop {
        let up = c.take_output();
        if rs.is_ok() && !up.is_empty() {
            rs = s.feed(&up);
        }
        let down = s.take_output();
        if rc.is_ok() && !down.is_empty() {
            rc = c.feed(&down);
        }
        if up.is_empty() && down.is_empty() {
            return (rc, rs);
        }
    }
}

#[test]
fn a_client_and_the_server_exchange_data() {
    let (mut c, mut s) = (Client::new(client_config()), server());
    s.write(b"early server data"); // held until the handshake is done
    c.write(b"hello from the client");
    assert_eq!(run(&mut c, &mut s), (Ok(()), Ok(())));
    assert!(c.is_connected() && s.is_connected());
    assert_eq!(c.version(), Some(0x0304));
    assert_eq!(s.read(), b"hello from the client");
    assert_eq!(c.read(), b"early server data");
    // Several records' worth, both ways.
    let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    c.write(&big);
    s.write(&big);
    assert_eq!(run(&mut c, &mut s), (Ok(()), Ok(())));
    assert_eq!(s.read(), big);
    assert_eq!(c.read(), big);
    // Either side may end it.
    c.close();
    assert_eq!(run(&mut c, &mut s).1, Ok(()));
    assert!(s.is_closed());
}

#[test]
fn a_byte_at_a_time_is_the_same() {
    let (mut c, mut s) = (Client::new(client_config()), server());
    c.write(b"x");
    for _ in 0..4 {
        for b in c.take_output() {
            s.feed(&[b]).unwrap();
        }
        for b in s.take_output() {
            c.feed(&[b]).unwrap();
        }
    }
    assert_eq!(s.read(), b"x");
    s.close();
    assert_eq!(run(&mut c, &mut s).0, Ok(()));
    assert!(c.is_closed());
}

#[test]
fn unsuitable_clients_are_refused_with_the_right_alert() {
    let with = |f: fn(&mut Config)| {
        let mut cfg = client_config();
        f(&mut cfg);
        let (mut c, mut s) = (Client::new(cfg), server());
        let r = run(&mut c, &mut s);
        assert!(s.is_closed() && !c.is_connected());
        r
    };
    assert_eq!(
        with(|c| c.ed25519 = false),
        (
            Err(Error::Alert(40)),
            Err(Error::Unsupported("signature algorithm"))
        )
    );
    assert_eq!(
        with(|c| c.alpn = Some(b"http/1.1")),
        (Err(Error::Alert(120)), Err(Error::Unsupported("ALPN")))
    );
    // No ALPN at all is not a refusal.
    let mut cfg = client_config();
    cfg.alpn = None;
    let (mut c, mut s) = (Client::new(cfg), server());
    assert_eq!(run(&mut c, &mut s), (Ok(()), Ok(())));
    assert!(s.is_connected());
}

#[test]
fn a_client_refuses_the_wrong_server() {
    let with = |f: fn(&mut Config)| {
        let mut cfg = client_config();
        f(&mut cfg);
        let (mut c, mut s) = (Client::new(cfg), server());
        let r = run(&mut c, &mut s).0;
        assert!(!c.is_connected() && !s.is_connected());
        r
    };
    use x509::Error as X;
    assert_eq!(
        with(|c| c.roots = Arc::new(x509::RootStore::default())),
        Err(Error::Certificate(X::UnknownIssuer))
    );
    assert_eq!(
        with(|c| c.host = "other.test".to_string()),
        Err(Error::Certificate(X::WrongHost))
    );
    assert_eq!(with(|c| c.now = 0), Err(Error::Certificate(X::NotYetValid)));
}

#[test]
fn tampering_is_refused() {
    // Every byte of the client's second flight (Finished) matters, but for
    // the version field of the ChangeCipherSpec record, which RFC 8446 §5
    // has us ignore.
    let (mut c, mut s) = (Client::new(client_config()), server());
    s.feed(&c.take_output()).unwrap();
    c.feed(&s.take_output()).unwrap();
    let flight = c.take_output();
    for i in (0..flight.len()).filter(|i| !matches!(i, 1 | 2)) {
        let (mut c2, mut s2) = (Client::new(client_config()), server());
        s2.feed(&c2.take_output()).unwrap();
        let mut bad = flight.clone();
        bad[i] ^= 0x40;
        let r = s2.feed(&bad);
        assert!(!s2.is_connected(), "byte {i}: {r:?}");
        // A length made longer just waits for more; anything else fails.
        assert!(r.is_err() || s2.read().is_empty());
    }
    // And of its data.
    s.feed(&flight).unwrap();
    c.write(b"data");
    let mut rec = c.take_output();
    let last = rec.len() - 1;
    rec[last] ^= 1;
    assert_eq!(s.feed(&rec), Err(Error::BadRecordMac));
    assert!(s.is_closed() && s.read().is_empty());
    // The alert is queued for the client.
    assert!(!s.take_output().is_empty());
}

#[test]
fn junk_and_early_data_are_refused() {
    // Not TLS at all.
    let mut s = server();
    assert!(s.feed(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").is_err());
    assert!(s.is_closed());
    // Application data, a ChangeCipherSpec or a Finished before a hello.
    for rec in [
        plain_record(CT_APP, 0x0303, b"hi"),
        plain_record(CT_CCS, 0x0303, &[1]),
        plain_record(CT_HANDSHAKE, 0x0303, &handshake_msg(HS_FINISHED, &[0; 32])),
        plain_record(CT_HANDSHAKE, 0x0303, &[]),
        plain_record(CT_HANDSHAKE, 0x0303, &[HS_CLIENT_HELLO, 0xff, 0xff, 0xff]),
    ] {
        let mut s = server();
        assert!(s.feed(&rec).is_err(), "{rec:?}");
        assert!(s.is_closed());
    }
    // Two hellos in one record: the second would sit under the first's keys.
    let mut c = Client::new(client_config());
    let hello = c.take_output()[5..].to_vec();
    let mut two = hello.clone();
    two.extend_from_slice(&hello);
    let mut s = server();
    assert_eq!(
        s.feed(&plain_record(CT_HANDSHAKE, 0x0301, &two)),
        Err(Error::Unexpected(HS_CLIENT_HELLO))
    );
    // Unencrypted data after the hello.
    let mut s = server();
    s.feed(&plain_record(CT_HANDSHAKE, 0x0301, &hello)).unwrap();
    assert!(s.feed(&plain_record(CT_HANDSHAKE, 0x0303, &hello)).is_err());
    assert!(!s.is_connected());
}

#[test]
fn mutated_hellos_never_panic() {
    let hello = Client::new(client_config()).take_output();
    let mut x = 0x1234_5678_9abc_def0u64;
    for _ in 0..2_000 {
        let mut b = hello.clone();
        for _ in 0..1 + x % 4 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = x as usize % b.len();
            b[i] = (x >> 32) as u8;
        }
        let mut s = server();
        let _ = s.feed(&b);
        assert!(!s.is_connected());
    }
}

#[test]
fn a_client_key_update_is_followed() {
    let (mut c, mut s) = (Client::new(client_config()), server());
    assert_eq!(run(&mut c, &mut s), (Ok(()), Ok(())));
    // The client moves its sending keys on and asks the server to.
    let w = c.write.as_mut().unwrap();
    let rec = w.seal(CT_HANDSHAKE, &handshake_msg(HS_KEY_UPDATE, &[1]));
    c.c_ap = expand_label(&c.c_ap, "traffic upd", &[], 32);
    c.write = traffic(&c.c_ap, true);
    s.feed(&rec).unwrap();
    c.write(b"after");
    s.write(b"also after");
    assert_eq!(run(&mut c, &mut s), (Ok(()), Ok(())));
    assert_eq!(s.read(), b"after");
    assert_eq!(c.read(), b"also after");
}

#[test]
fn identities_must_be_whole() {
    let err = |pem: &str| Identity::from_pem(pem).unwrap_err();
    assert_eq!(err(""), IdentityError::NoCertificate);
    assert_eq!(err(CA), IdentityError::NoKey);
    // The CA's certificate with the server's key.
    let key = &API[API.find("-----BEGIN PRIVATE KEY").unwrap()..];
    assert_eq!(err(&std::format!("{CA}{key}")), IdentityError::Mismatch);
    // Not an Ed25519 key.
    assert_eq!(
        err(&std::format!(
            "{CA}-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n"
        )),
        IdentityError::NoKey
    );
}

/// OpenSSL's own client completes the handshake, verifies the chain and
/// exchanges data.
#[test]
#[ignore = "needs openssl on the path"]
fn openssl_s_client_connects() {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let ca = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/api-ca.pem");
    let mut child = std::process::Command::new("openssl")
        .args(["s_client", "-connect"])
        .arg(std::format!("127.0.0.1:{port}"))
        .args(["-servername", "ichor-api.test", "-alpn", "h2", "-quiet"])
        .args([
            "-verify_return_error",
            "-verify_hostname",
            "ichor-api.test",
            "-CAfile",
        ])
        .arg(ca)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"from openssl\n")
        .unwrap();
    let (mut sock, _) = l.accept().unwrap();
    sock.set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .unwrap();
    let mut s = server();
    let mut buf = vec![0u8; 16384];
    let mut got = Vec::new();
    s.write(b"to openssl\n");
    while !got.ends_with(b"\n") {
        let n = sock.read(&mut buf).unwrap();
        assert_ne!(n, 0, "openssl hung up: {s:?}");
        s.feed(&buf[..n]).unwrap();
        sock.write_all(&s.take_output()).unwrap();
        got.extend(s.read());
    }
    assert_eq!(got, b"from openssl\n");
    s.close();
    sock.write_all(&s.take_output()).unwrap();
    drop(sock);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.stdout, b"to openssl\n");
}
