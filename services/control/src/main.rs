//! The control plane (ADR-0012): a native service in the system cell that
//! serves `ichor.v1.Control` (`docs/abi/control.proto`) as gRPC over h2c
//! on a published port. `PullImage` pulls from a registry over HTTPS,
//! verifies every blob against its digest, converts the layers into an
//! Ichor image and hands it to the kernel; `CreateCell` makes a cell from
//! one; `Run` starts a process there and streams its output.
//!
//! One thread, one loop over `OBJECT_WAIT`; every protocol under it is a
//! sans-I/O state machine.
//!
//! Arguments (from the kernel): the system cell's handle, the switch's,
//! the CA bundle's (hex), the API port, the DNS resolver, and optionally
//! `exit-on-close` (tests: stop when the first API client hangs up).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

mod fetch;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use grpc::control::{self, RunEvent};
use grpc::{Call, status};
use rt::{Error, Handle, WaitItem};

use fetch::{Fetch, Net};

rt::main!(main);

/// The default cell memory: 256 MiB.
const DEFAULT_CELL_BYTES: u64 = 256 << 20;

struct Api {
    sock: Handle,
    server: grpc::Server,
    out: Vec<u8>,
}

struct Pull {
    conn: usize,
    stream: u32,
    reference: String,
    puller: oci::Puller,
    fetch: Option<Fetch>,
    started: u64,
}

struct Run {
    conn: usize,
    stream: u32,
    process: Handle,
}

struct Image {
    handle: Handle,
    config: oci::ImageConfig,
}

struct CellEntry {
    handle: Handle,
    image: String,
}

struct Control {
    cell: Handle,
    net: Net,
    listener: Handle,
    conns: Vec<Option<Api>>,
    pulls: Vec<Pull>,
    runs: Vec<Run>,
    images: BTreeMap<String, Image>,
    cells: BTreeMap<String, CellEntry>,
    next_cell: u64,
    served: bool,
}

fn handle(arg: Option<&&str>) -> Option<Handle> {
    u64::from_str_radix(arg?, 16).ok().map(Handle::from_raw)
}

fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for o in &mut out {
        *o = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main(args: &[&str]) -> i32 {
    let (Some(cell), Some(switch), Some(roots)) = (
        handle(args.get(1)),
        handle(args.get(2)),
        handle(args.get(3)),
    ) else {
        rt::log("control: missing handles");
        return 2;
    };
    let port: u16 = args.get(4).and_then(|p| p.parse().ok()).unwrap_or(50051);
    let resolver = args
        .get(5)
        .and_then(|s| parse_ip(s))
        .unwrap_or([10, 0, 2, 3]);
    let exit_on_close = args.contains(&"exit-on-close");

    let pem = rt::blob_read(&roots).unwrap_or_default();
    drop(roots);
    let store = x509::RootStore::from_pem(core::str::from_utf8(&pem).unwrap_or(""));
    drop(pem);
    if store.is_empty() {
        rt::log("control: no CA bundle on the boot volume; HTTPS pulls will fail");
    }
    let listener = match rt::tcp_listen(port, 16) {
        Ok(l) => l,
        Err(e) => {
            rt::log!("control: cannot listen on {port}: {e:?}");
            return 1;
        }
    };
    let published = rt::port_publish(&switch, port, &cell, port).is_ok();
    rt::log!(
        "control: serving ichor.v1.Control on port {port} ({} roots{})",
        store.len(),
        if published {
            ", published on the uplink"
        } else {
            ", not published"
        }
    );
    let mut c = Control {
        cell,
        net: Net::new(resolver, Arc::new(store)),
        listener,
        conns: Vec::new(),
        pulls: Vec::new(),
        runs: Vec::new(),
        images: BTreeMap::new(),
        cells: BTreeMap::new(),
        next_cell: 1,
        served: false,
    };
    loop {
        c.wait();
        c.accept();
        for i in 0..c.conns.len() {
            c.pump(i);
        }
        c.advance_pulls();
        c.advance_runs();
        for i in 0..c.conns.len() {
            c.flush(i);
        }
        if exit_on_close && c.served && c.conns.iter().all(Option::is_none) {
            rt::log("control: the API client is gone; exiting");
            return 0;
        }
    }
}

impl Control {
    fn wait(&mut self) {
        let item = |h: &Handle, events| WaitItem {
            handle: h.raw(),
            events,
            revents: 0,
        };
        let mut items = alloc::vec![item(&self.listener, rt::READABLE)];
        for a in self.conns.iter().flatten() {
            let w = if a.out.is_empty() { 0 } else { rt::WRITABLE };
            items.push(item(&a.sock, rt::READABLE | w));
        }
        for p in &self.pulls {
            if let Some(w) = p.fetch.as_ref().and_then(Fetch::wait_item) {
                items.push(w);
            }
        }
        for r in &self.runs {
            items.push(item(&r.process, rt::READABLE));
        }
        items.truncate(256);
        let _ = rt::wait(&mut items, 1_000_000_000);
    }

    fn accept(&mut self) {
        while let Ok(sock) = rt::tcp_accept(&self.listener) {
            self.served = true;
            let api = Api {
                sock,
                server: grpc::Server::new(),
                out: Vec::new(),
            };
            match self.conns.iter().position(Option::is_none) {
                Some(i) => self.conns[i] = Some(api),
                None => self.conns.push(Some(api)),
            }
        }
    }

    /// Reads what an API connection sent and starts its calls.
    fn pump(&mut self, i: usize) {
        let mut calls = Vec::new();
        let mut gone = false;
        if let Some(a) = self.conns[i].as_mut() {
            let mut buf = alloc::vec![0u8; 64 * 1024];
            loop {
                match rt::recv(&a.sock, &mut buf) {
                    Ok(0) => {
                        gone = true;
                        break;
                    }
                    Ok(n) => match a.server.receive(&buf[..n]) {
                        Ok(c) => calls.extend(c),
                        Err(_) => {
                            gone = true;
                            break;
                        }
                    },
                    Err(Error::WouldBlock) => break,
                    Err(_) => {
                        gone = true;
                        break;
                    }
                }
            }
        }
        for call in calls {
            self.dispatch(i, call);
        }
        if gone {
            self.flush(i);
            self.conns[i] = None;
            // Nobody is left to answer (and the slot may be reused).
            self.pulls.retain(|p| p.conn != i);
        }
    }

    fn server(&mut self, conn: usize) -> Option<&mut grpc::Server> {
        self.conns.get_mut(conn)?.as_mut().map(|a| &mut a.server)
    }

    fn reply(&mut self, conn: usize, stream: u32, message: &[u8]) {
        if let Some(s) = self.server(conn) {
            s.reply(stream, message);
            s.finish(stream);
        }
    }

    fn fail(&mut self, conn: usize, stream: u32, code: u32, message: &str) {
        rt::log!("control: call failed ({code}): {message}");
        if let Some(s) = self.server(conn) {
            s.fail(stream, code, message);
        }
    }

    fn dispatch(&mut self, conn: usize, call: Call) {
        let stream = call.stream;
        match call.path.as_str() {
            control::PULL_IMAGE => {
                let Ok(req) = control::PullImageRequest::decode(&call.message) else {
                    return self.fail(
                        conn,
                        stream,
                        status::INVALID_ARGUMENT,
                        "bad PullImageRequest",
                    );
                };
                let Some(r) = oci::Reference::parse(&req.reference) else {
                    let m = format!("bad image reference {:?}", req.reference);
                    return self.fail(conn, stream, status::INVALID_ARGUMENT, &m);
                };
                rt::log!("control: pulling {}", req.reference);
                self.pulls.push(Pull {
                    conn,
                    stream,
                    reference: req.reference,
                    puller: oci::Puller::new(r),
                    fetch: None,
                    started: rt::monotonic(),
                });
            }
            control::CREATE_CELL => {
                let Ok(req) = control::CreateCellRequest::decode(&call.message) else {
                    return self.fail(
                        conn,
                        stream,
                        status::INVALID_ARGUMENT,
                        "bad CreateCellRequest",
                    );
                };
                let Some(image) = self.images.get(&req.image_id) else {
                    let m = format!("no image {}", req.image_id);
                    return self.fail(conn, stream, status::NOT_FOUND, &m);
                };
                let bytes = if req.memory_bytes == 0 {
                    DEFAULT_CELL_BYTES
                } else {
                    req.memory_bytes
                };
                let made = rt::cell_create(&self.cell, &image.handle, bytes.div_ceil(4096))
                    .and_then(|h| rt::cell_addr(&h).map(|a| (h, a)));
                match made {
                    Ok((h, a)) => {
                        let id = self.next_cell.to_string();
                        self.next_cell += 1;
                        let address = format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
                        rt::log!(
                            "control: cell {id} at {address} from image {}",
                            &req.image_id[..12.min(req.image_id.len())]
                        );
                        self.cells.insert(
                            id.clone(),
                            CellEntry {
                                handle: h,
                                image: req.image_id,
                            },
                        );
                        let m = control::CreateCellResponse {
                            cell_id: id,
                            address,
                        };
                        self.reply(conn, stream, &m.encode());
                    }
                    Err(e) => {
                        let m = format!("cell_create: {e:?}");
                        self.fail(conn, stream, status::RESOURCE_EXHAUSTED, &m);
                    }
                }
            }
            control::RUN => {
                let Ok(req) = control::RunRequest::decode(&call.message) else {
                    return self.fail(conn, stream, status::INVALID_ARGUMENT, "bad RunRequest");
                };
                let Some(cell) = self.cells.get(&req.cell_id) else {
                    let m = format!("no cell {}", req.cell_id);
                    return self.fail(conn, stream, status::NOT_FOUND, &m);
                };
                let config = self.images.get(&cell.image).map(|i| &i.config);
                let argv = match config {
                    Some(c) => c.argv(&req.argv),
                    None => req.argv.clone(),
                };
                if argv.is_empty() {
                    return self.fail(conn, stream, status::INVALID_ARGUMENT, "nothing to run");
                }
                let mut env: Vec<String> = config.map(|c| c.env.clone()).unwrap_or_default();
                env.extend(req.env.iter().cloned());
                let a: Vec<&str> = argv.iter().map(String::as_str).collect();
                let e: Vec<&str> = env.iter().map(String::as_str).collect();
                match rt::cell_spawn(&cell.handle, &a, &e) {
                    Ok(process) => {
                        rt::log!("control: cell {} runs {:?}", req.cell_id, a);
                        self.runs.push(Run {
                            conn,
                            stream,
                            process,
                        });
                    }
                    Err(Error::NotFound) => {
                        let m = format!("{} is not in the image", a[0]);
                        self.fail(conn, stream, status::NOT_FOUND, &m);
                    }
                    Err(e) => {
                        let m = format!("cell_spawn: {e:?}");
                        self.fail(conn, stream, status::INTERNAL, &m);
                    }
                }
            }
            other => {
                let m = format!("unknown method {other}");
                self.fail(conn, stream, status::UNIMPLEMENTED, &m);
            }
        }
    }

    fn advance_pulls(&mut self) {
        let mut i = 0;
        while i < self.pulls.len() {
            match self.advance_pull(i) {
                Ok(false) => i += 1,
                Ok(true) => {
                    self.pulls.remove(i);
                }
                Err(e) => {
                    let p = self.pulls.remove(i);
                    let m = format!("pulling {}: {e}", p.reference);
                    self.fail(p.conn, p.stream, status::UNAVAILABLE, &m);
                }
            }
        }
    }

    /// True once the pull is finished (and answered).
    fn advance_pull(&mut self, i: usize) -> Result<bool, String> {
        loop {
            let p = &mut self.pulls[i];
            if let Some(f) = p.fetch.as_mut() {
                match f.advance(&mut self.net)? {
                    None => return Ok(false),
                    Some(resp) => {
                        p.fetch = None;
                        let (status, len) = (resp.status, resp.body.len());
                        p.puller.on_response(resp).map_err(|e| format!("{e:?}"))?;
                        rt::log!("control: {} answered {status} ({len} bytes)", p.reference);
                    }
                }
            }
            match p.puller.step() {
                oci::Step::Fetch(req) => {
                    p.fetch = Some(Fetch::start(req, &mut self.net)?);
                }
                oci::Step::Done(pulled) => {
                    let (conn, stream, started) = (p.conn, p.stream, p.started);
                    let img = oci::convert(&pulled).map_err(|e| format!("converting: {e:?}"))?;
                    let id = image::Image::mount(&img)
                        .map(|m| hex(&m.root_hash()))
                        .map_err(|e| format!("the converted image: {e:?}"))?;
                    let handle =
                        rt::image_create(&img).map_err(|e| format!("IMAGE_CREATE: {e:?}"))?;
                    let config = oci::ImageConfig::parse(&pulled.config).unwrap_or_default();
                    rt::log!(
                        "control: pulled {} ({} layers, image {} of {} KiB) in {} ms",
                        pulled.manifest_digest,
                        pulled.layers.len(),
                        &id[..12],
                        img.len() / 1024,
                        (rt::monotonic() - started) / 1_000_000
                    );
                    let m = control::PullImageResponse {
                        digest: pulled.manifest_digest.clone(),
                        image_id: id.clone(),
                        size: img.len() as u64,
                        argv: config.argv(&[]),
                        env: config.env.clone(),
                    };
                    self.images.insert(id, Image { handle, config });
                    self.reply(conn, stream, &m.encode());
                    return Ok(true);
                }
            }
        }
    }

    fn advance_runs(&mut self) {
        let mut i = 0;
        let mut buf = alloc::vec![0u8; 64 * 1024];
        while i < self.runs.len() {
            let r = &self.runs[i];
            let (conn, stream) = (r.conn, r.stream);
            let mut events = Vec::new();
            let mut done = false;
            loop {
                match rt::process_read(&r.process, &mut buf) {
                    Ok(0) => {
                        if let Ok(st) = rt::process_wait(&r.process) {
                            events.push(RunEvent::ExitStatus(st));
                            done = true;
                        }
                        break;
                    }
                    Ok(n) => events.push(RunEvent::Output(buf[..n].to_vec())),
                    Err(_) => break,
                }
            }
            let open = self.server(conn).is_some_and(|s| s.is_open(stream));
            if let Some(s) = self.server(conn) {
                for e in &events {
                    s.reply(stream, &e.encode());
                }
                if done {
                    s.finish(stream);
                }
            }
            if done || !open {
                // The process keeps running if its caller left; its output
                // is dropped with the handle.
                self.runs.remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Sends what an API connection has queued.
    fn flush(&mut self, i: usize) {
        let Some(a) = self.conns.get_mut(i).and_then(Option::as_mut) else {
            return;
        };
        a.out.extend(a.server.conn.take_output());
        while !a.out.is_empty() {
            match rt::send(&a.sock, &a.out) {
                Ok(n) => {
                    a.out.drain(..n);
                }
                Err(Error::WouldBlock) => break,
                Err(_) => {
                    self.conns[i] = None;
                    return;
                }
            }
        }
    }
}
