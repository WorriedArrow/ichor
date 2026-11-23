//! Mutation fuzzing for the parsers that take untrusted input (registry
//! servers, API clients, image contents). Dependency-free and on the pinned
//! stable toolchain: a seeded mutator over real seed inputs (recorded
//! Docker Hub sessions, real certificate chains, RFC vectors, generated
//! HTTP/2 and gRPC traffic). A target fails if it panics (overflow checks
//! included: tests build with them) or takes too long on one input; the
//! input is then written to `target/fuzz/` to replay.
//!
//! It is not coverage-guided. Coverage guidance (libFuzzer through
//! `cargo-fuzz`) needs a nightly toolchain; these same target functions are
//! what such harnesses would call.
//!
//! `cargo test -p ichor-fuzz` runs every target briefly (CI);
//! `cargo xtask fuzz [TARGET] [--iterations N]` runs longer, in release
//! mode with overflow checks.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // host tool

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A fuzz target: its seeds and the function that must not panic.
pub struct Target {
    pub name: &'static str,
    pub seeds: fn() -> Vec<Vec<u8>>,
    pub run: fn(&[u8]),
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

/// xorshift64*: fast, seeded, reproducible.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

const INTERESTING: [u8; 9] = [0, 1, 0x7f, 0x80, 0xff, 0xfe, 0x40, 0x3f, 0x20];

/// One mutated input from the corpus.
pub fn mutate(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
    let mut v = corpus[rng.below(corpus.len())].clone();
    for _ in 0..1 + rng.below(8) {
        let len = v.len();
        match rng.below(10) {
            0 if len > 0 => {
                let i = rng.below(len);
                v[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                v[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 if len > 0 => {
                let i = rng.below(len);
                v[i] = rng.next_u64() as u8;
            }
            3 => {
                // Insert random bytes.
                let i = rng.below(len + 1);
                let n = 1 + rng.below(16);
                let bytes: Vec<u8> = (0..n).map(|_| rng.next_u64() as u8).collect();
                v.splice(i..i, bytes);
            }
            4 if len > 0 => {
                // Delete a range.
                let i = rng.below(len);
                let n = 1 + rng.below((len - i).min(64));
                v.drain(i..i + n);
            }
            5 if len > 1 => {
                // Duplicate a range.
                let i = rng.below(len);
                let n = 1 + rng.below((len - i).min(64));
                let dup = v[i..i + n].to_vec();
                let at = rng.below(v.len() + 1);
                v.splice(at..at, dup);
            }
            6 => {
                // Splice in part of another seed.
                let other = &corpus[rng.below(corpus.len())];
                if !other.is_empty() {
                    let i = rng.below(other.len());
                    let n = 1 + rng.below((other.len() - i).min(256));
                    let at = rng.below(len + 1);
                    v.splice(at..at, other[i..i + n].iter().copied());
                }
            }
            7 if len > 0 => {
                v.truncate(rng.below(len));
            }
            8 if len >= 4 => {
                // A big-endian length field: 0, 1, all ones, or off by one.
                let i = rng.below(len - 1);
                let cur = u16::from_be_bytes([v[i], v[i + 1]]);
                let new = match rng.below(4) {
                    0 => 0,
                    1 => u16::MAX,
                    2 => cur.wrapping_add(1),
                    _ => cur.wrapping_sub(1),
                };
                v[i..i + 2].copy_from_slice(&new.to_be_bytes());
            }
            _ if len > 0 => {
                // A run of one interesting byte (varint and length bombs).
                let i = rng.below(len);
                let n = 1 + rng.below((len - i).min(12));
                let b = INTERESTING[rng.below(INTERESTING.len())];
                v[i..i + n].fill(b);
            }
            _ => v.push(rng.next_u64() as u8),
        }
    }
    v
}

/// Where a failing input is written.
pub fn crash_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("target")
        .join("fuzz")
}

/// Runs `t` on its seeds, then `iterations` mutated inputs. Returns the
/// first failure, with the input saved.
pub fn fuzz(t: &Target, iterations: u64, seed: u64) -> Result<(), String> {
    let corpus = (t.seeds)();
    assert!(!corpus.is_empty(), "{}: no seeds", t.name);
    let mut rng = Rng::new(seed ^ fnv(t.name.as_bytes()));
    let limit = std::time::Duration::from_secs(5);
    for i in 0..corpus.len() as u64 + iterations {
        let input = match corpus.get(i as usize) {
            Some(s) => s.clone(),
            None => mutate(&mut rng, &corpus),
        };
        let t0 = std::time::Instant::now();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (t.run)(&input)));
        let slow = t0.elapsed() > limit;
        if r.is_err() || slow {
            let dir = crash_dir();
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join(format!("{}-{:016x}", t.name, fnv(&input)));
            let _ = std::fs::write(&path, &input);
            let what = if slow { "took over 5 s" } else { "panicked" };
            return Err(format!(
                "{}: input {i} {what}; saved to {}",
                t.name,
                path.display()
            ));
        }
    }
    Ok(())
}

/// Runs `t` on one saved input (to reproduce a failure).
pub fn replay(t: &Target, input: &[u8]) {
    (t.run)(input)
}

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325, |h, &x| {
        (h ^ u64::from(x)).wrapping_mul(0x100_0000_01b3)
    })
}

fn root(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel)
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(root(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

// ---------------------------------------------------------------------------
// Seeds.
// ---------------------------------------------------------------------------

const PEMS: [&str; 3] = [
    "services/x509/testdata/registry.pem",
    "services/x509/testdata/auth.pem",
    "services/x509/testdata/cloudflare.pem",
];

fn certificates() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for p in PEMS.iter().chain(&["services/x509/testdata/roots.pem"]) {
        let pem = String::from_utf8(read(p)).unwrap();
        out.extend(x509::pem_certificates(&pem));
    }
    out
}

fn recorded_http() -> Vec<Vec<u8>> {
    (0..8)
        .map(|i| read(&format!("services/oci/testdata/hello-world/{i:02}.http")))
        .collect()
}

fn body(resp: &[u8]) -> Vec<u8> {
    let i = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |i| i + 4);
    resp[i..].to_vec()
}

fn layer_gz() -> Vec<u8> {
    body(&read("services/oci/testdata/hello-world/07.http"))
}

/// A recorded TLS session: its client config, and the server's bytes.
const SESSIONS: [(&str, &str); 4] = [
    ("registry", "registry-1.docker.io"),
    ("cloudflare", "production.cloudflare.docker.com"),
    ("adoptium", "ci.adoptium.net"),
    ("mcr", "mcr.microsoft.com"),
];
const NOW: u64 = 1_795_343_900;

fn tls_config(name: &str, host: &str) -> tls::Config {
    use crypto::sha2::Digest;
    let mut random = [0u8; 128];
    random[..64].copy_from_slice(&crypto::sha2::Sha512::digest(name.as_bytes()));
    random[64..].copy_from_slice(&crypto::sha2::Sha512::digest(host.as_bytes()));
    static ROOTS: std::sync::OnceLock<Arc<x509::RootStore>> = std::sync::OnceLock::new();
    let roots = ROOTS
        .get_or_init(|| {
            let pem = String::from_utf8(read("services/x509/testdata/roots.pem")).unwrap();
            Arc::new(x509::RootStore::from_pem(&pem))
        })
        .clone();
    tls::Config {
        host: host.into(),
        roots,
        now: NOW,
        random,
        ed25519: false,
        alpn: None,
    }
}

fn h2_traffic() -> (Vec<u8>, Vec<u8>) {
    let mut c = grpc::Client::new("ichor");
    let req = grpc::control::PullImageRequest {
        reference: "docker.io/library/alpine:3.20".into(),
        layers: vec![grpc::control::LayerSource {
            url: "http://10.0.2.2:8000/l.tar.gz".into(),
            digest: "sha256:00".into(),
            from: "src/".into(),
            to: "/opt/".into(),
        }],
    };
    c.call(grpc::control::PULL_IMAGE, &req.encode());
    c.call(
        grpc::control::RUN,
        &grpc::control::RunRequest::default().encode(),
    );
    let client = c.conn.take_output();
    let mut s = grpc::Server::new();
    let calls = s.receive(&client).unwrap();
    for call in calls {
        s.reply(
            call.stream,
            &grpc::control::RunEvent::Output(b"out".to_vec()).encode(),
        );
        s.fail(call.stream, grpc::status::NOT_FOUND, "no such image");
    }
    (client, s.conn.take_output())
}

// ---------------------------------------------------------------------------
// Targets.
// ---------------------------------------------------------------------------

fn tls_seeds() -> Vec<Vec<u8>> {
    SESSIONS
        .iter()
        .map(|(n, _)| read(&format!("services/tls/testdata/{n}.server")))
        .collect()
}

/// The server's side of a TLS session: records, handshake messages, the
/// certificate chain (in TLS 1.2 in the clear), key exchange, records.
fn tls_run(input: &[u8]) {
    // Which recording's client to pair it with: the one whose server's
    // random it starts with, so mutations reach past the ServerHello.
    static SEEDS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    let seeds = SEEDS.get_or_init(tls_seeds);
    let random = |b: &[u8]| b.get(11..19).map(<[u8]>::to_vec);
    let (name, host) = SESSIONS
        .into_iter()
        .zip(seeds)
        .find(|(_, seed)| random(seed) == random(input))
        .map_or(SESSIONS[0], |(s, _)| s);
    for cfg in [
        tls_config(name, host),
        tls_config(SESSIONS[1].0, SESSIONS[1].1),
    ] {
        let mut c = tls::Client::new(cfg);
        c.write(b"GET / HTTP/1.1\r\n\r\n");
        let _ = c.take_output();
        // In two pieces, so record reassembly is exercised too.
        let cut = input.len() / 3;
        if c.feed(&input[..cut]).is_ok() {
            let _ = c.feed(&input[cut..]);
        }
        let _ = c.read();
        let _ = c.take_output();
    }
}

/// The control API's identity, and what its clients send: this crate's
/// client with the matching randomness, so the mutations land in a session
/// whose Finished is right.
fn api_identity() -> Arc<tls::server::Identity> {
    static ID: std::sync::OnceLock<Arc<tls::server::Identity>> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        let pem = String::from_utf8(read("services/tls/testdata/api.pem")).unwrap();
        Arc::new(tls::server::Identity::from_pem(&pem).unwrap())
    })
    .clone()
}

fn api_server() -> tls::server::Server {
    tls::server::Server::new(tls::server::ServerConfig {
        identity: api_identity(),
        alpn: b"h2",
        random: [0x42; 64],
    })
}

fn tls_server_seeds() -> Vec<Vec<u8>> {
    let ca = String::from_utf8(read("services/tls/testdata/api-ca.pem")).unwrap();
    let mut c = tls::Client::new(tls::Config {
        host: "ichor-api.test".into(),
        roots: Arc::new(x509::RootStore::from_pem(&ca)),
        now: 1_795_400_000,
        random: [0x17; 128],
        ed25519: true,
        alpn: Some(b"h2"),
    });
    let mut s = api_server();
    let hello = c.take_output();
    s.feed(&hello).unwrap();
    c.feed(&s.take_output()).unwrap();
    c.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    c.close();
    let mut all = hello.clone();
    all.extend(c.take_output());
    s.feed(&all[hello.len()..]).unwrap();
    assert!(s.is_closed() && !s.read().is_empty());
    vec![hello, all]
}

/// What an API client may send before and after the handshake.
fn tls_server_run(input: &[u8]) {
    let mut s = api_server();
    s.write(b"pending");
    let cut = input.len() / 3;
    if s.feed(&input[..cut]).is_ok() {
        let _ = s.feed(&input[cut..]);
    }
    let _ = s.read();
    s.close();
    let _ = s.take_output();
}

fn x509_run(input: &[u8]) {
    if let Ok(cert) = x509::parse(input) {
        let _ = format!("{cert:?}");
    }
    let mut r = x509::der::Reader::new(input);
    while let Some(t) = r.read() {
        let mut inner = x509::der::Reader::new(t.body);
        while inner.read().is_some() {}
    }
    // As a leaf under real intermediates, and as an intermediate.
    let chain = certificates();
    let roots = x509::RootStore::from_pem(
        &String::from_utf8(read("services/x509/testdata/roots.pem")).unwrap(),
    );
    let _ = x509::verify_chain(&[input, &chain[1]], &roots, "registry-1.docker.io", NOW);
    let _ = x509::verify_chain(&[&chain[0], input], &roots, "registry-1.docker.io", NOW);
}

fn pem_run(input: &[u8]) {
    let s = String::from_utf8_lossy(input);
    let _ = x509::RootStore::from_pem(&s);
    let _ = x509::base64(&s);
    let _ = x509::ed25519_seed(input);
    let _ = tls::server::Identity::from_pem(&s);
}

fn pem_seeds() -> Vec<Vec<u8>> {
    PEMS.iter()
        .chain(&["services/tls/testdata/api.pem"])
        .map(|p| read(p))
        .collect()
}

fn hpack_seeds() -> Vec<Vec<u8>> {
    let hex = |s: &str| -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    };
    let mut out: Vec<Vec<u8>> = [
        "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
        "8286 84be 5808 6e6f 2d63 6163 6865",
        "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
        "4882 6402 5885 aec3 771a 4b61",
        "3fe1 1f 400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
    ]
    .iter()
    .map(|s| hex(s))
    .collect();
    let mut e = http::hpack::Encoder::new();
    out.push(e.encode(&[
        (":status", "200"),
        ("content-type", "application/grpc"),
        ("grpc-status", "0"),
    ]));
    out
}

fn hpack_run(input: &[u8]) {
    let mut d = http::hpack::Decoder::new(64 * 1024);
    // Twice: the first block's dynamic-table entries apply to the second.
    let cut = input.len() / 2;
    let _ = d.decode(&input[..cut]);
    let _ = d.decode(&input[cut..]);
}

fn h2_server_seeds() -> Vec<Vec<u8>> {
    vec![h2_traffic().0]
}

/// What an API client may send the control plane: HTTP/2 frames, then
/// gRPC calls.
fn h2_server_run(input: &[u8]) {
    let mut s = grpc::Server::new();
    let mut input = input.to_vec();
    if !input.starts_with(http::h2::PREFACE) {
        input.splice(0..0, http::h2::PREFACE.iter().copied());
    }
    if let Ok(calls) = s.receive(&input) {
        for c in calls {
            let _ = grpc::control::PullImageRequest::decode(&c.message);
            let _ = grpc::control::RunRequest::decode(&c.message);
            s.reply(c.stream, &c.message);
            s.finish(c.stream);
        }
    }
    let _ = s.conn.take_output();
}

fn h2_client_seeds() -> Vec<Vec<u8>> {
    vec![h2_traffic().1]
}

/// What a server may send a gRPC client (the host tests' side).
fn h2_client_run(input: &[u8]) {
    let mut c = grpc::Client::new("ichor");
    c.call("/x/y", b"m");
    c.call("/x/z", b"n");
    let _ = c.conn.take_output();
    let _ = c.receive(input);
}

fn proto_seeds() -> Vec<Vec<u8>> {
    use grpc::control::*;
    vec![
        PullImageResponse {
            digest: "sha256:ab".into(),
            image_id: "cd".into(),
            size: 1 << 40,
            argv: vec!["/bin/sh".into()],
            env: vec!["PATH=/bin".into()],
        }
        .encode(),
        RunRequest {
            cell_id: "1".into(),
            argv: vec!["sh".into(), "-c".into(), "echo".into()],
            env: vec![],
        }
        .encode(),
        RunEvent::ExitStatus(256).encode(),
        CreateCellRequest {
            image_id: "x".into(),
            memory_bytes: 64 << 20,
        }
        .encode(),
    ]
}

fn proto_run(input: &[u8]) {
    use grpc::control::*;
    let mut r = grpc::proto::Reader::new(input);
    while let Ok(Some(_)) = r.field() {}
    let _ = PullImageRequest::decode(input);
    let _ = PullImageResponse::decode(input);
    let _ = CreateCellRequest::decode(input);
    let _ = CreateCellResponse::decode(input);
    let _ = RunRequest::decode(input);
    let _ = RunEvent::decode(input);
    let mut d = grpc::Deframer::default();
    d.push(input);
    while let Ok(Some(_)) = d.next_message() {}
}

fn http1_run(input: &[u8]) {
    let mut p = http::ResponseParser::new(1 << 20);
    let cut = input.len() / 2;
    match p.feed(&input[..cut]) {
        Ok(Some(_)) => return,
        Err(_) => return,
        Ok(None) => {}
    }
    if let Ok(None) = p.feed(&input[cut..]) {
        let _ = p.eof();
    }
}

fn json_seeds() -> Vec<Vec<u8>> {
    recorded_http()
        .iter()
        .map(|r| body(r))
        .filter(|b| b.first() == Some(&b'{'))
        .collect()
}

fn json_run(input: &[u8]) {
    if let Some(v) = oci::json::parse(input) {
        let _ = v.get("manifests");
        let _ = v
            .get("config")
            .and_then(|c| c.get("Env"))
            .and_then(oci::json::Value::strings);
    }
    let _ = oci::ImageConfig::parse(input);
}

/// The registry protocol itself: a pull fed mutated versions of the
/// recorded responses, in order.
fn oci_run(input: &[u8]) {
    let Some(r) = oci::Reference::parse(
        "docker.io/library/hello-world@sha256:cf1b20a0c89a666b6950fecda7ccbc1b1a86520e7c53f908f3a21e79d0d60458",
    ) else {
        return;
    };
    let mut p = oci::Puller::new(r);
    let mut responses: Vec<Vec<u8>> = recorded_http();
    // The input replaces one recorded response, chosen by its first byte.
    let k = usize::from(input.first().copied().unwrap_or(0)) % responses.len();
    responses[k] = input.to_vec();
    for raw in responses {
        let oci::Step::Fetch(_) = p.step() else {
            return;
        };
        let mut parser = http::ResponseParser::new(1 << 20);
        let resp = match parser.feed(&raw) {
            Ok(Some(r)) => r,
            _ => match parser.eof() {
                Ok(r) => r,
                Err(_) => return,
            },
        };
        if p.on_response(resp).is_err() {
            return;
        }
    }
    if let oci::Step::Done(pulled) = p.step() {
        let _ = oci::convert(&pulled);
    }
}

fn dns_seeds() -> Vec<Vec<u8>> {
    let mut m = 7u16.to_be_bytes().to_vec();
    m.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
    m.extend(dns::query(7, "registry-1.docker.io").unwrap()[12..].iter());
    m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 14, 4]);
    m.extend_from_slice(b"edge\x07example\x00");
    let at = (m.len() - 14) as u8;
    m.extend_from_slice(&[0xc0, at, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 52, 1, 2, 3]);
    vec![m]
}

fn dns_run(input: &[u8]) {
    let _ = dns::parse_a(input, 7, "registry-1.docker.io");
}

/// Memory a Hyper-V host writes: a channel's rings.
struct HostMemory(std::cell::RefCell<Vec<u8>>);

impl vmbus::ring::Memory for HostMemory {
    fn read(&self, at: usize, out: &mut [u8]) {
        out.copy_from_slice(&self.0.borrow()[at..at + out.len()]);
    }
    fn write(&self, at: usize, data: &[u8]) {
        self.0.borrow_mut()[at..at + data.len()].copy_from_slice(data);
    }
    fn load(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0.borrow()[at..at + 4].try_into().unwrap())
    }
    fn store(&self, at: usize, v: u32) {
        self.write(at, &v.to_le_bytes());
    }
    fn fence(&self) {}
}

/// The host's ring: how far it wrote, then what (a frame's packet, and a
/// completion); it also stands for a message on every other way in.
fn vmbus_seeds() -> Vec<Vec<u8>> {
    let words = |w: &[u32]| -> Vec<u8> { w.iter().flat_map(|v| v.to_le_bytes()).collect() };
    let mut ring = words(&[0x70 + 0x30, 0x0005_0007, 0x0001_0009, 1, 0]);
    ring.extend(words(&[0xcafe, 2, 100, 0, 60, 1728]));
    ring.extend(words(&[107, 0, 0, 0, 0, 0, 0, 0]));
    ring.extend(words(&[0x0002_000b, 4, 9, 0, 108, 1, 0, 0, 0, 0]));
    let mut frame = vmbus::netvsc::frame_header(60).to_vec();
    frame.extend_from_slice(&[7; 60]);
    let mut answer = words(&[0x8000_0004, 30, 2, 0, 6, 16]);
    answer.extend_from_slice(&[0, 0x15, 0x5d, 1, 2, 3]);
    let mut offer = words(&[1, 0]);
    offer.extend_from_slice(&vmbus::NET.0);
    offer.resize(196, 1);
    vec![
        ring,
        frame,
        answer,
        offer,
        words(&[15, 0, 1, 0x2001]),
        words(&[10, 0, 14, 1, 0]),
        vmbus::storvsc::command(0, 0, 1, &[0x28; 10], 4096).to_vec(),
    ]
}

fn vmbus_run(input: &[u8]) {
    use vmbus::{client, netvsc, ring, storvsc};
    const DATA: usize = 4096;
    const CONTROL: usize = 2 * 4096;
    let size = ring::Rings::<HostMemory>::size(DATA);
    let mut memory = vec![0u8; size];
    let (index, packets) = input.split_at(input.len().min(4));
    memory[CONTROL..CONTROL + index.len()].copy_from_slice(index);
    let packets = &packets[..packets.len().min(DATA)];
    memory[CONTROL + 4096..CONTROL + 4096 + packets.len()].copy_from_slice(packets);
    let mut rings = ring::Rings::new(HostMemory(memory.into()), DATA).unwrap();
    while let Ok(Some((p, _))) = rings.receive() {
        let _ = netvsc::received(&p.payload);
        let _ = rings.complete(p.transaction, &netvsc::taken());
    }
    let _ = client::Client::new(2, 0, [0; 2]).receive(input);
    let _ = netvsc::received(input);
    let _ = netvsc::init_answer(input);
    let _ = netvsc::send_buffer_answer(input);
    let _ = storvsc::ended(input);
    let mut setup = storvsc::Setup::default();
    while let storvsc::Next::Send(_) = setup.answer(input) {}
}

fn metadata_seeds() -> Vec<Vec<u8>> {
    let answer = |h: &str, b: &str| format!("HTTP/1.0 200 OK\r\n{h}\r\n{b}").into_bytes();
    vec![
        answer(
            "Metadata-Flavor: Google\r\nContent-Length: 13\r\n",
            "control=50051",
        ),
        answer("", "AQAEAJ9x=="),
        answer("", "Y29udHJvbD01MDA1MQ=="),
        b"# x\ncontrol=1\napi-token = y\n-----BEGIN A-----\nMIIB\n-----END A-----\n".to_vec(),
    ]
}

fn metadata_run(input: &[u8]) {
    use net::metadata::{Client, Cloud, Config};
    for cloud in Cloud::ALL {
        let mut c = Client::new(cloud);
        let _ = c.answer(input);
        let req = c.request("h");
        // Nothing an answer says makes another request of ours.
        assert_eq!(req.windows(4).filter(|w| w == b"\r\n\r\n").count(), 1);
        let _ = c.answer(input);
    }
    let _ = net::metadata::complete(input);
    let _ = Config::parse(input);
}

const FUZZ_MAC: net::Mac = net::Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);

/// A DHCP reply of `kind` (2 OFFER, 5 ACK) to transaction 7 for
/// `FUZZ_MAC`, in a broadcast frame from QEMU's DHCP server.
fn dhcp_reply(kind: u8) -> Vec<u8> {
    use net::Ipv4Addr;
    let server = Ipv4Addr::new(10, 0, 2, 2);
    let mut m = vec![0u8; 236];
    m[0] = 2;
    m[1] = 1;
    m[2] = 6;
    m[4..8].copy_from_slice(&7u32.to_be_bytes());
    m[16..20].copy_from_slice(&[10, 0, 2, 15]);
    m[28..34].copy_from_slice(&FUZZ_MAC.0);
    m.extend_from_slice(&[99, 130, 83, 99, 53, 1, kind, 54, 4, 10, 0, 2, 2]);
    m.extend_from_slice(&[1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 2, 2]);
    m.extend_from_slice(&[6, 4, 10, 0, 2, 3, 51, 4, 0, 1, 81, 128, 26, 2, 5, 220, 255]);
    let udp = net::wire::udp(server, 67, Ipv4Addr::BROADCAST, 68, &m);
    let ip = net::wire::ipv4(server, Ipv4Addr::BROADCAST, net::wire::PROTO_UDP, 1, &udp);
    net::wire::ethernet(
        net::Mac::BROADCAST,
        net::Mac([2, 0, 0, 0, 0, 2]),
        net::wire::ETHERTYPE_IPV4,
        &ip,
    )
}

/// Ethernet frames off the wire (the uplink's NIC): DHCP replies, ARP,
/// IPv4, ICMP, UDP and TCP segments.
fn ethernet_seeds() -> Vec<Vec<u8>> {
    let arp = net::wire::Arp {
        op: net::wire::ARP_REPLY,
        sender_mac: net::Mac([2, 0, 0, 0, 0, 2]),
        sender_ip: net::Ipv4Addr::new(10, 0, 2, 2),
        target_mac: FUZZ_MAC,
        target_ip: net::Ipv4Addr::new(10, 0, 2, 15),
    };
    let arp = net::wire::ethernet(
        FUZZ_MAC,
        net::Mac([2, 0, 0, 0, 0, 2]),
        net::wire::ETHERTYPE_ARP,
        &arp.emit(),
    );
    vec![dhcp_reply(2), dhcp_reply(5), arp]
}

fn ethernet_run(input: &[u8]) {
    let t = std::time::Duration::from_secs(1);
    // A DHCP client waiting for an offer, and one waiting for its ACK.
    let mut c = net::dhcp::Client::new(FUZZ_MAC, 7);
    let _ = c.poll(t);
    let _ = c.receive(t, input);
    let mut c = net::dhcp::Client::new(FUZZ_MAC, 7);
    let _ = c.poll(t);
    let _ = c.receive(t, &dhcp_reply(2));
    let _ = c.poll(t);
    if let Some(l) = c.receive(t, input) {
        // A lease that bound must make sense.
        assert!(l.prefix <= 32);
    }
    // The uplink's interface.
    let mut ifc = net::iface::Interface::new(
        FUZZ_MAC,
        net::Ipv4Addr::new(10, 0, 2, 15),
        24,
        Some(net::Ipv4Addr::new(10, 0, 2, 2)),
    );
    let _ = ifc.receive(t, input);
    while ifc.transmit().is_some() {}
}

fn gzip_run(input: &[u8]) {
    let _ = layer::gunzip(input);
    let _ = layer::inflate::inflate(input);
}

fn tar_seeds() -> Vec<Vec<u8>> {
    vec![layer::gunzip(&layer_gz()).unwrap()]
}

fn tar_run(input: &[u8]) {
    let mut t = layer::Tree::new();
    if t.add_tar(input).is_ok() {
        let img = t.image();
        image_run(&img);
    }
}

fn image_seeds() -> Vec<Vec<u8>> {
    let mut t = layer::Tree::new();
    t.add_tar(&tar_seeds()[0]).unwrap();
    vec![t.image()]
}

/// The Ichor image format: metadata checks, then lookups and reads.
fn image_run(input: &[u8]) {
    let Ok(img) = image::Image::mount(input) else {
        return;
    };
    let _ = img.root();
    for path in ["/", "/hello", "/a/b/c", "/hello/x"] {
        if let Some(n) = img.lookup(path) {
            let _ = n.kind();
        }
    }
}

/// Every target.
pub const TARGETS: &[Target] = &[
    Target {
        name: "tls",
        seeds: tls_seeds,
        run: tls_run,
    },
    Target {
        name: "tls-server",
        seeds: tls_server_seeds,
        run: tls_server_run,
    },
    Target {
        name: "x509",
        seeds: certificates,
        run: x509_run,
    },
    Target {
        name: "pem",
        seeds: pem_seeds,
        run: pem_run,
    },
    Target {
        name: "hpack",
        seeds: hpack_seeds,
        run: hpack_run,
    },
    Target {
        name: "h2-server",
        seeds: h2_server_seeds,
        run: h2_server_run,
    },
    Target {
        name: "h2-client",
        seeds: h2_client_seeds,
        run: h2_client_run,
    },
    Target {
        name: "protobuf",
        seeds: proto_seeds,
        run: proto_run,
    },
    Target {
        name: "http1",
        seeds: recorded_http,
        run: http1_run,
    },
    Target {
        name: "json",
        seeds: json_seeds,
        run: json_run,
    },
    Target {
        name: "oci",
        seeds: recorded_http,
        run: oci_run,
    },
    Target {
        name: "dns",
        seeds: dns_seeds,
        run: dns_run,
    },
    Target {
        name: "vmbus",
        seeds: vmbus_seeds,
        run: vmbus_run,
    },
    Target {
        name: "metadata",
        seeds: metadata_seeds,
        run: metadata_run,
    },
    Target {
        name: "ethernet",
        seeds: ethernet_seeds,
        run: ethernet_run,
    },
    Target {
        name: "gzip",
        seeds: || vec![layer_gz()],
        run: gzip_run,
    },
    Target {
        name: "tar",
        seeds: tar_seeds,
        run: tar_run,
    },
    Target {
        name: "image",
        seeds: image_seeds,
        run: image_run,
    },
];
