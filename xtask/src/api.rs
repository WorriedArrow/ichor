//! A host-side client for the control plane's gRPC API
//! (`docs/abi/control.proto`), over the port QEMU forwards to the guest:
//! for the acceptance tests and `cargo xtask workloads`.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use grpc::control::{self, RunEvent};
use grpc::{Client, Response};

use crate::Result;

/// A call's messages so far, and its status once it ended.
type Messages = (Vec<Vec<u8>>, Option<(u32, String)>);

/// One API session: the socket and the gRPC client over it. Several calls
/// can be in flight ([`Session::start`], [`Session::wait`]).
#[derive(Debug)]
pub struct Session {
    sock: TcpStream,
    client: Client,
    pending: HashMap<u32, Messages>,
}

impl Session {
    /// Connects once the guest serves: QEMU accepts forwarded connections
    /// at once and drops them until the guest listens, so a session counts
    /// only once the server's HTTP/2 SETTINGS arrive.
    pub fn connect(port: u16, token: Option<&str>, deadline: Instant) -> Result<Session> {
        while Instant::now() < deadline {
            if let Ok(mut sock) = TcpStream::connect(("127.0.0.1", port)) {
                let mut client = match token {
                    Some(t) => Client::with_token("ichor", t),
                    None => Client::new("ichor"),
                };
                let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
                if sock.write_all(&client.conn.take_output()).is_ok() {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = sock.read(&mut buf)
                        && n > 0
                        && client.receive(&buf[..n]).is_ok()
                    {
                        return Ok(Session {
                            sock,
                            client,
                            pending: HashMap::new(),
                        });
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("the control plane never answered".into())
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
        let deadline = Instant::now() + timeout;
        let _ = self.sock.set_read_timeout(Some(Duration::from_secs(1)));
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if let Some((_, Some(_))) = self.pending.get(&id)
                && let Some((messages, Some((code, message)))) = self.pending.remove(&id)
            {
                // Flush acknowledgements before the next call.
                let out = self.client.conn.take_output();
                let _ = self.sock.write_all(&out);
                return Ok((messages, code, message));
            }
            if Instant::now() >= deadline {
                return Err(format!("call {id} timed out"));
            }
            let out = self.client.conn.take_output();
            if !out.is_empty() {
                self.sock
                    .write_all(&out)
                    .map_err(|e| format!("send: {e}"))?;
            }
            let n = match self.sock.read(&mut buf) {
                Ok(0) => return Err("the server closed the connection".into()),
                Ok(n) => n,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(e) => return Err(format!("receive: {e}")),
            };
            for r in self
                .client
                .receive(&buf[..n])
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
        let req = control::RunRequest {
            cell_id: cell_id.into(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            env: env.iter().map(|a| a.to_string()).collect(),
        };
        let (m, code, msg) = self.call(control::RUN, &req.encode(), timeout)?;
        if code != 0 {
            return Err(format!("Run failed ({code}): {msg}"));
        }
        let mut output = Vec::new();
        let mut exit = None;
        for e in m {
            match RunEvent::decode(&e).map_err(|_| "bad RunEvent")? {
                RunEvent::Output(b) => output.extend(b),
                RunEvent::ExitStatus(st) => exit = Some(st),
            }
        }
        Ok((output, exit.ok_or("no exit status")?))
    }
}
