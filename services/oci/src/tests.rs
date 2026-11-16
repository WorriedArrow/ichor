//! The pull protocol against a recording of a real pull of Docker Hub's
//! `hello-world` (`cargo test -p ichor-oci -- --ignored record_live`
//! refreshes it, over this workspace's TLS and HTTP), replayed offline.

extern crate std;

use super::*;
use std::vec;

/// The image the recording pulls: `hello-world` by digest of its index
/// (pinned 2026-11-15).
const IMAGE: &str =
    "hello-world@sha256:cf1b20a0c89a666b6950fecda7ccbc1b1a86520e7c53f908f3a21e79d0d60458";

fn testdata(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

#[test]
fn references() {
    let r = Reference::parse("alpine").unwrap();
    assert_eq!(
        (
            r.registry.as_str(),
            r.repository.as_str(),
            r.tag.as_deref(),
            r.digest.as_deref()
        ),
        (
            "registry-1.docker.io",
            "library/alpine",
            Some("latest"),
            None
        )
    );
    let d = "sha256:".to_string() + &"ab".repeat(32);
    let r = Reference::parse(&format!("docker.io/library/alpine:3.20@{d}")).unwrap();
    assert_eq!(
        (r.tag.as_deref(), r.digest.as_deref()),
        (Some("3.20"), Some(d.as_str()))
    );
    let r = Reference::parse("ghcr.io/owner/tool:v1").unwrap();
    assert_eq!(
        (r.registry.as_str(), r.repository.as_str()),
        ("ghcr.io", "owner/tool")
    );
    let r = Reference::parse("localhost:5000/img").unwrap();
    assert_eq!(
        (r.registry.as_str(), r.tag.as_deref()),
        ("localhost:5000", Some("latest"))
    );
    assert!(Reference::parse("Alpine").is_none());
    assert!(Reference::parse("alpine@sha256:abc").is_none());
}

#[test]
fn bearer_challenges() {
    let u = token_url(r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#).unwrap();
    assert_eq!(u.host, "auth.docker.io");
    assert_eq!(
        u.path,
        "/token?service=registry.docker.io&scope=repository:library/alpine:pull"
    );
    assert!(token_url("Basic realm=x").is_none());
}

/// The recorded responses, in order.
fn recorded() -> Vec<Response> {
    let mut out = Vec::new();
    for i in 0.. {
        let Ok(raw) = std::fs::read(testdata(&format!("hello-world/{i:02}.http"))) else {
            break;
        };
        let mut p = http::ResponseParser::new(64 << 20);
        let r = match p.feed(&raw).unwrap() {
            Some(r) => r,
            None => p.eof().unwrap(),
        };
        out.push(r);
    }
    out
}

fn run(responses: Vec<Response>) -> Result<Pulled, Error> {
    let mut p = Puller::new(Reference::parse(IMAGE).unwrap());
    let mut responses = responses.into_iter();
    loop {
        match p.step() {
            Step::Done(pulled) => return Ok(pulled),
            Step::Fetch(_) => {
                p.on_response(responses.next().expect("ran out of recorded responses"))?
            }
        }
    }
}

#[test]
fn replays_a_hello_world_pull() {
    let rs = recorded();
    assert!(rs.len() >= 5, "token, index, manifest, config, layer");
    let pulled = run(rs).unwrap();
    assert_eq!(pulled.layers.len(), 1);
    let cfg = ImageConfig::parse(&pulled.config).unwrap();
    assert_eq!(cfg.argv(&[]), ["/hello"]);
    let img = convert(&pulled).unwrap();
    let image = image::Image::mount(&img).unwrap();
    let hello = image.lookup("/hello").unwrap();
    let mut elf = vec![0u8; 4];
    hello
        .read_at(0, &mut elf, &image::SliceSource(&img))
        .unwrap();
    assert_eq!(elf, b"\x7fELF");
}

#[test]
fn tampered_content_is_refused() {
    // A flipped byte in the last response (the layer blob) breaks its
    // digest; in the platform manifest, the index's pinned digest.
    let mut rs = recorded();
    let last = rs.len() - 1;
    let n = rs[last].body.len() / 2;
    rs[last].body[n] ^= 1;
    assert!(matches!(run(rs), Err(Error::Digest(_))));
    let mut rs = recorded();
    let m = rs
        .iter()
        .position(|r| r.body.windows(6).any(|w| w == b"layers"))
        .unwrap();
    let k = rs[m].body.len() - 3;
    rs[m].body[k] = b' ';
    assert!(matches!(run(rs), Err(Error::Digest(_))));
}

/// Records a pull of `IMAGE` against Docker Hub.
#[test]
#[ignore = "needs the internet; run to refresh the recording"]
fn record_live() {
    use std::io::{Read, Write};
    let roots = std::sync::Arc::new(x509::RootStore::from_pem(include_str!(
        "../../x509/testdata/roots.pem"
    )));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::create_dir_all(testdata("hello-world")).unwrap();
    let mut p = Puller::new(Reference::parse(IMAGE).unwrap());
    for i in 0.. {
        let req = match p.step() {
            Step::Done(pulled) => {
                std::println!(
                    "pulled {} ({} layers)",
                    pulled.manifest_digest,
                    pulled.layers.len()
                );
                return;
            }
            Step::Fetch(r) => r,
        };
        std::println!("GET https://{}{}", req.url.host, req.url.path);
        let mut random = [0u8; 96];
        random[..64].copy_from_slice(&<crypto::sha2::Sha512 as crypto::sha2::Digest>::digest(
            format!("{now}-{i}").as_bytes(),
        ));
        let mut c = tls::Client::new(tls::Config {
            host: req.url.host.clone(),
            roots: roots.clone(),
            now,
            random,
        });
        c.write(&req.encode());
        let mut s = std::net::TcpStream::connect((req.url.host.as_str(), 443)).unwrap();
        let mut plain = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let out = c.take_output();
            if !out.is_empty() {
                s.write_all(&out).unwrap();
            }
            let n = s.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            c.feed(&buf[..n]).unwrap();
            plain.extend(c.read());
            if c.is_closed() {
                break;
            }
        }
        std::fs::write(testdata(&format!("hello-world/{i:02}.http")), &plain).unwrap();
        let mut parser = http::ResponseParser::new(64 << 20);
        let resp = match parser.feed(&plain).unwrap() {
            Some(r) => r,
            None => parser.eof().unwrap(),
        };
        std::println!("  -> {}", resp.status);
        p.on_response(resp).unwrap();
    }
}
