//! Container start through the control plane's gRPC API, timed by its
//! client, as `docker run --rm` is timed against `dockerd` (`api-bench
//! PORT IMAGE RUNS`, started by the kernel beside the control plane in its
//! own cell when the command line has `api_bench`): the image pulled once,
//! untimed, as Docker's was already present; then for each start
//! `CreateCell`, `Run` of `/bin/true` until its exit status arrives, and
//! `Destroy`, over one HTTP/2 connection to the cell's loopback, `RUNS`
//! times after three to warm up. Logs one `native: api-bench` line with
//! the total and per-start nanoseconds. Closing the connection ends a
//! control plane run with `control_exit`.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use grpc::control::{self, RunEvent};
use grpc::{Client, Response};
use rt::{Error, Handle, WaitItem};

/// A call's messages and, once it is over, its status.
type Pending = (Vec<Vec<u8>>, Option<u32>);

struct Api {
    sock: Handle,
    client: Client,
    pending: BTreeMap<u32, Pending>,
}

/// Waits up to `ns` for `events` on `h`; whether they came.
fn ready(h: &Handle, events: u32, ns: u64) -> bool {
    let mut items = [WaitItem {
        handle: h.raw(),
        events,
        revents: 0,
    }];
    rt::wait(&mut items, ns) == Ok(1)
}

impl Api {
    /// Connects to the control plane on this cell's loopback, retrying
    /// for up to two minutes while it starts.
    fn connect(port: u16) -> Result<Api, &'static str> {
        let deadline = rt::monotonic() + 120_000_000_000;
        while rt::monotonic() < deadline {
            if let Ok(sock) = rt::tcp_connect([127, 0, 0, 1], port) {
                ready(&sock, rt::WRITABLE, 1_000_000_000);
                if rt::sock_error(&sock).is_ok() {
                    return Ok(Api {
                        sock,
                        client: Client::new("ichor"),
                        pending: BTreeMap::new(),
                    });
                }
                // Refused: the control plane is not listening yet.
                ready(&sock, rt::READABLE, 200_000_000);
            }
        }
        Err("api-bench: the control plane never answered")
    }

    fn flush(&mut self) -> Result<(), &'static str> {
        let out = self.client.conn.take_output();
        let mut at = 0;
        while at < out.len() {
            match rt::send(&self.sock, &out[at..]) {
                Ok(n) => at += n,
                Err(Error::WouldBlock) => {
                    ready(&self.sock, rt::WRITABLE, 10_000_000_000);
                }
                Err(_) => return Err("api-bench: send"),
            }
        }
        Ok(())
    }

    /// Makes a call and waits for it to end: its messages and status.
    fn call(&mut self, path: &str, msg: &[u8]) -> Result<(Vec<Vec<u8>>, u32), &'static str> {
        let id = self.client.call(path, msg);
        let mut buf = alloc::vec![0u8; 64 * 1024];
        loop {
            self.flush()?;
            if let Some((_, Some(_))) = self.pending.get(&id)
                && let Some((messages, Some(code))) = self.pending.remove(&id)
            {
                return Ok((messages, code));
            }
            let n = match rt::recv(&self.sock, &mut buf) {
                Ok(0) => return Err("api-bench: the control plane hung up"),
                Ok(n) => n,
                Err(Error::WouldBlock) => {
                    if !ready(&self.sock, rt::READABLE, 60_000_000_000) {
                        return Err("api-bench: a call timed out");
                    }
                    continue;
                }
                Err(_) => return Err("api-bench: receive"),
            };
            let responses = self
                .client
                .receive(&buf[..n])
                .map_err(|_| "api-bench: HTTP/2")?;
            for r in responses {
                match r {
                    Response::Message { stream, message } => {
                        self.pending.entry(stream).or_default().0.push(message);
                    }
                    Response::Status { stream, code, .. } => {
                        self.pending.entry(stream).or_default().1 = Some(code);
                    }
                }
            }
        }
    }

    fn ok(&mut self, path: &str, msg: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        match self.call(path, msg)? {
            (messages, 0) => Ok(messages),
            _ => Err("api-bench: a call failed"),
        }
    }

    /// One container: created (with its address on the cell switch), `argv`
    /// run to its exit, destroyed; what it wrote.
    fn container(&mut self, image_id: &str, argv: &[&str]) -> Result<Vec<u8>, &'static str> {
        let req = control::CreateCellRequest {
            image_id: image_id.to_string(),
            memory_bytes: 64 << 20,
            sysctls: Vec::new(),
        };
        let m = self.ok(control::CREATE_CELL, &req.encode())?;
        let cell = control::CreateCellResponse::decode(m.first().ok_or("api-bench: no cell")?)
            .map_err(|_| "api-bench: bad CreateCellResponse")?
            .cell_id;
        let run = control::RunRequest {
            cell_id: cell.clone(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
            env: Vec::new(),
        };
        let mut output = Vec::new();
        let mut exited = false;
        for e in self.ok(control::RUN, &run.encode())? {
            match RunEvent::decode(&e) {
                Ok(RunEvent::Output(b)) => output.extend_from_slice(&b),
                Ok(RunEvent::ExitStatus(0)) => exited = true,
                _ => {}
            }
        }
        if !exited {
            return Err("api-bench: the program did not exit 0");
        }
        let req = control::CellRequest { cell_id: cell };
        self.ok(control::DESTROY, &req.encode())?;
        Ok(output)
    }

    /// One container running `/bin/true`.
    fn start(&mut self, image_id: &str) -> Result<(), &'static str> {
        self.container(image_id, &["/bin/true"]).map(|_| ())
    }
}

pub(crate) fn run(args: &[&str]) -> Result<(), &'static str> {
    let port: u16 = args
        .get(2)
        .and_then(|p| p.parse().ok())
        .ok_or("api-bench: no port")?;
    let image = args.get(3).ok_or("api-bench: no image")?;
    let runs: u64 = args
        .get(4)
        .and_then(|r| r.parse().ok())
        .ok_or("api-bench: no runs")?;
    let mut api = Api::connect(port)?;
    let req = control::PullImageRequest {
        reference: image.to_string(),
        layers: Vec::new(),
    };
    // Pulled twice: the first right after boot, when a cloud's network may
    // not carry the machine's traffic yet, the second (every request made
    // anew) on a network known to work, as a long-running machine pulls.
    let t = rt::monotonic();
    api.ok(control::PULL_IMAGE, &req.encode())?;
    let first_pull_ns = rt::monotonic() - t;
    let t = rt::monotonic();
    let m = api.ok(control::PULL_IMAGE, &req.encode())?;
    let pull_ns = rt::monotonic() - t;
    let image_id = control::PullImageResponse::decode(m.first().ok_or("api-bench: no image")?)
        .map_err(|_| "api-bench: bad PullImageResponse")?
        .image_id;
    // The first container from the image, on its own: nothing of it has
    // been read yet but what the pull wrote.
    let t = rt::monotonic();
    api.start(&image_id)?;
    let cold_ns = rt::monotonic() - t;
    // The network a container gets: its address on the cell switch, as
    // its own `ip` reports it.
    let out = api.container(&image_id, &["/bin/ip", "-4", "-o", "addr"])?;
    let text = String::from_utf8_lossy(&out);
    let addrs: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split_whitespace().skip_while(|w| *w != "inet").nth(1))
        .collect();
    rt::log!(
        "native: api-bench addresses in a container: {}",
        addrs.join(" ")
    );
    for _ in 0..3 {
        api.start(&image_id)?;
    }
    let t0 = rt::monotonic();
    for _ in 0..runs {
        api.start(&image_id)?;
    }
    let ns = rt::monotonic() - t0;
    rt::log!(
        "native: api-bench first_pull_ns={first_pull_ns} pull_ns={pull_ns} cold_ns={cold_ns} n={runs} ns={ns} per_ns={}",
        ns / runs.max(1)
    );
    Ok(())
}
