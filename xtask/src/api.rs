//! A host-side client for the control plane's gRPC API
//! (`docs/abi/control.proto`), over the port QEMU forwards to the guest:
//! for the acceptance tests and `cargo xtask workloads`.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use grpc::control::{self, RunEvent};
use grpc::{Client, Response};

use crate::Result;

/// A call's messages so far, and its status once it ended.
type Messages = (Vec<Vec<u8>>, Option<(u32, String)>);

/// The throwaway identity (certificate and key) test boots serve their API
/// with; [`test_trust`] trusts it. Public, so good for nothing else.
pub const TEST_IDENTITY: &str = include_str!("../../services/tls/testdata/api.pem");
const TEST_CA: &str = include_str!("../../services/tls/testdata/api-ca.pem");

/// Whom a session trusts to be the API: a certificate for `host` issued
/// under `roots`.
#[derive(Clone, Debug)]
pub struct Trust {
    pub roots: Arc<x509::RootStore>,
    pub host: String,
}

/// Trust in [`TEST_IDENTITY`].
pub fn test_trust() -> Trust {
    Trust {
        roots: Arc::new(x509::RootStore::from_pem(TEST_CA)),
        host: "ichor-api.test".into(),
    }
}

/// Random bytes from the operating system, by way of the standard
/// library's hash keys (seeded from it).
fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let h = RandomState::new().hash_one((i, SystemTime::now()));
        chunk.copy_from_slice(&h.to_le_bytes()[..chunk.len()]);
    }
    out
}

/// One API session: the socket and the gRPC client over it (through TLS,
/// if the session has someone to trust). Several calls can be in flight
/// ([`Session::start`], [`Session::wait`]).
#[derive(Debug)]
pub struct Session {
    sock: TcpStream,
    tls: Option<Box<tls::Client>>,
    client: Client,
    pending: HashMap<u32, Messages>,
}

impl Session {
    /// Connects once the guest serves: QEMU accepts forwarded connections
    /// at once and drops them until the guest listens, so a session counts
    /// only once the server's HTTP/2 SETTINGS arrive. A server that is not
    /// the one trusted is an error at once.
    pub fn connect(
        port: u16,
        token: Option<&str>,
        trust: Option<&Trust>,
        deadline: Instant,
    ) -> Result<Session> {
        while Instant::now() < deadline {
            if let Ok(sock) = TcpStream::connect(("127.0.0.1", port)) {
                let client = match token {
                    Some(t) => Client::with_token("ichor", t),
                    None => Client::new("ichor"),
                };
                let tls = trust.map(|t| {
                    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
                    Box::new(tls::Client::new(tls::Config {
                        host: t.host.clone(),
                        roots: t.roots.clone(),
                        now: now.map_or(0, |d| d.as_secs()),
                        random: random(),
                        ed25519: true,
                        alpn: Some(b"h2"),
                    }))
                });
                let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
                let mut s = Session {
                    sock,
                    tls,
                    client,
                    pending: HashMap::new(),
                };
                match s.greet() {
                    Ok(true) => return Ok(s),
                    Ok(false) => {}
                    Err(e) => return Err(e),
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("the control plane never answered".into())
    }

    /// Exchanges the first bytes; whether the server's HTTP/2 arrived (a
    /// whole frame header of it: a TLS alert is shorter).
    fn greet(&mut self) -> Result<bool> {
        let mut buf = [0u8; 4096];
        let mut got = 0;
        loop {
            if self.flush().is_err() {
                return Ok(false);
            }
            let n = match self.sock.read(&mut buf) {
                Ok(n) if n > 0 => n,
                _ => return Ok(false), // not up yet, or not this protocol
            };
            let plain = match self.tls.as_mut() {
                Some(t) => {
                    t.feed(&buf[..n]).map_err(|e| format!("TLS: {e:?}"))?;
                    t.read()
                }
                None => buf[..n].to_vec(),
            };
            got += plain.len();
            if self.client.receive(&plain).is_err() {
                return Ok(false);
            }
            if got >= 9 {
                return Ok(true);
            }
        }
    }

    /// Sends what the client has queued.
    fn flush(&mut self) -> Result<()> {
        let mut out = self.client.conn.take_output();
        if let Some(t) = self.tls.as_mut() {
            if !out.is_empty() {
                t.write(&out);
            }
            out = t.take_output();
        }
        self.sock
            .write_all(&out)
            .map_err(|e| format!("sending to the control plane: {e}"))
    }

    /// Makes a call; returns its messages and final status.
    pub fn call(
        &mut self,
        path: &str,
        msg: &[u8],
        timeout: Duration,
    ) -> Result<(Vec<Vec<u8>>, u32, String)> {
        let id = self.start(path, msg);
        self.wait(id, timeout)
    }

    /// Starts a call without waiting for it.
    pub fn start(&mut self, path: &str, msg: &[u8]) -> u32 {
        self.client.call(path, msg)
    }

    /// Waits for call `id` to end; returns its messages and final status.
    /// Other calls' responses are kept for their own `wait`.
    pub fn wait(&mut self, id: u32, timeout: Duration) -> Result<(Vec<Vec<u8>>, u32, String)> {
        let mut kept = Vec::new();
        let (code, message) = self.wait_with(id, timeout, &mut |m| kept.push(m.to_vec()))?;
        Ok((kept, code, message))
    }

    /// Waits for call `id` to end, handing each of its messages to `on` as
    /// it arrives (so a call that fails partway has delivered what came);
    /// returns its final status.
    pub fn wait_with(
        &mut self,
        id: u32,
        timeout: Duration,
        on: &mut dyn FnMut(&[u8]),
    ) -> Result<(u32, String)> {
        let deadline = Instant::now() + timeout;
        let _ = self.sock.set_read_timeout(Some(Duration::from_secs(1)));
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if let Some((messages, _)) = self.pending.get_mut(&id) {
                for m in messages.drain(..) {
                    on(&m);
                }
            }
            if let Some((_, Some(_))) = self.pending.get(&id)
                && let Some((_, Some((code, message)))) = self.pending.remove(&id)
            {
                // Flush acknowledgements before the next call.
                let _ = self.flush();
                return Ok((code, message));
            }
            if Instant::now() >= deadline {
                return Err(format!("call {id} timed out"));
            }
            self.flush()?;
            let n = match self.sock.read(&mut buf) {
                Ok(0) => return Err("the server closed the connection".into()),
                Ok(n) => n,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(e) => return Err(format!("receive: {e}")),
            };
            let plain = match self.tls.as_mut() {
                Some(t) => {
                    t.feed(&buf[..n]).map_err(|e| format!("TLS: {e:?}"))?;
                    t.read()
                }
                None => buf[..n].to_vec(),
            };
            for r in self
                .client
                .receive(&plain)
                .map_err(|e| format!("HTTP/2: {e:?}"))?
            {
                match r {
                    Response::Message { stream, message } => {
                        self.pending.entry(stream).or_default().0.push(message);
                    }
                    Response::Status {
                        stream,
                        code,
                        message,
                    } => {
                        self.pending.entry(stream).or_default().1 = Some((code, message));
                    }
                }
            }
        }
    }

    /// `PullImage`.
    pub fn pull(
        &mut self,
        reference: &str,
        layers: Vec<control::LayerSource>,
        timeout: Duration,
    ) -> Result<control::PullImageResponse> {
        let req = control::PullImageRequest {
            reference: reference.into(),
            layers,
        };
        let (m, code, msg) = self.call(control::PULL_IMAGE, &req.encode(), timeout)?;
        if code != 0 {
            return Err(format!("PullImage failed ({code}): {msg}"));
        }
        control::PullImageResponse::decode(m.first().ok_or("no PullImage reply")?)
            .map_err(|_| "bad PullImageResponse".into())
    }

    /// `CreateCell`.
    pub fn create_cell(
        &mut self,
        image_id: &str,
        memory_bytes: u64,
    ) -> Result<control::CreateCellResponse> {
        let req = control::CreateCellRequest {
            image_id: image_id.into(),
            memory_bytes,
        };
        let (m, code, msg) =
            self.call(control::CREATE_CELL, &req.encode(), Duration::from_secs(60))?;
        if code != 0 {
            return Err(format!("CreateCell failed ({code}): {msg}"));
        }
        control::CreateCellResponse::decode(m.first().ok_or("no CreateCell reply")?)
            .map_err(|_| "bad CreateCellResponse".into())
    }

    /// `Run` to the end: the output and the wait status.
    pub fn run(
        &mut self,
        cell_id: &str,
        argv: &[&str],
        env: &[&str],
        timeout: Duration,
    ) -> Result<(Vec<u8>, u32)> {
        let mut output = Vec::new();
        let status = self.run_with(cell_id, argv, env, timeout, &mut |b| {
            output.extend_from_slice(b)
        })?;
        Ok((output, status))
    }

    /// `Run` to the end, handing output to `out` as it arrives; returns the
    /// wait status.
    pub fn run_with(
        &mut self,
        cell_id: &str,
        argv: &[&str],
        env: &[&str],
        timeout: Duration,
        out: &mut dyn FnMut(&[u8]),
    ) -> Result<u32> {
        let req = control::RunRequest {
            cell_id: cell_id.into(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            env: env.iter().map(|a| a.to_string()).collect(),
        };
        let id = self.start(control::RUN, &req.encode());
        let mut exit = None;
        let mut bad = false;
        let (code, msg) = self.wait_with(id, timeout, &mut |e| match RunEvent::decode(e) {
            Ok(RunEvent::Output(b)) => out(&b),
            Ok(RunEvent::ExitStatus(st)) => exit = Some(st),
            Err(_) => bad = true,
        })?;
        if code != 0 {
            return Err(format!("Run failed ({code}): {msg}"));
        }
        if bad {
            return Err("bad RunEvent".into());
        }
        exit.ok_or_else(|| "no exit status".into())
    }
}
