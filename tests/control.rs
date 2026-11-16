//! Milestone 6's acceptance test (ADR-0012 §5): the control plane, a
//! native service in the system cell, pulls a real image from Docker Hub
//! through its gRPC API, verifies and converts it, makes a cell from it,
//! runs the image's command there and streams back its output.
//!
//! The guest reaches the internet through QEMU's user network (DNS at
//! 10.0.2.3), so this test needs it; the host reaches the API through a
//! forwarded port published on the uplink.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use grpc::control::{self, RunEvent};
use grpc::{Client, Response};
use ichor_tests::Exit;

/// Docker's `hello-world`, pinned by its index digest (the image the OCI
/// crate's recorded pull is of).
const IMAGE: &str = "docker.io/library/hello-world@sha256:cf1b20a0c89a666b6950fecda7ccbc1b1a86520e7c53f908f3a21e79d0d60458";

/// Alpine 3.20.3 (the release the other tests use), pinned by its index
/// digest: ADR-0012's acceptance image.
const ALPINE: &str = "docker.io/library/alpine@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a";

/// One API session: the socket and the gRPC client over it.
struct Session {
    sock: TcpStream,
    client: Client,
}

impl Session {
    /// Connects once the guest serves: QEMU accepts forwarded connections
    /// at once and drops them until the guest listens, so a session counts
    /// only once the server's HTTP/2 SETTINGS arrive.
    fn connect(port: u16, deadline: Instant) -> Result<Session, String> {
        while Instant::now() < deadline {
            if let Ok(mut sock) = TcpStream::connect(("127.0.0.1", port)) {
                let mut client = Client::new("ichor");
                sock.set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                if sock.write_all(&client.conn.take_output()).is_ok() {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = sock.read(&mut buf)
                        && n > 0
                        && client.receive(&buf[..n]).is_ok()
                    {
                        return Ok(Session { sock, client });
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err("the control plane never answered".into())
    }

    /// Makes a call; returns its messages and final status.
    fn call(
        &mut self,
        path: &str,
        msg: &[u8],
        timeout: Duration,
    ) -> Result<(Vec<Vec<u8>>, u32, String), String> {
        let id = self.client.call(path, msg);
        let deadline = Instant::now() + timeout;
        let mut messages = Vec::new();
        self.sock
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        while Instant::now() < deadline {
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
                    Response::Message { stream, message } if stream == id => messages.push(message),
                    Response::Status {
                        stream,
                        code,
                        message,
                    } if stream == id => {
                        // Flush acknowledgements before the next call.
                        let out = self.client.conn.take_output();
                        let _ = self.sock.write_all(&out);
                        return Ok((messages, code, message));
                    }
                    _ => {}
                }
            }
        }
        Err(format!("{path} timed out"))
    }
}

/// Pulls `reference`, makes a cell of it and runs `argv` (empty: the
/// image's command); returns the pull, the cell's address, the output and
/// the wait status.
fn pull_and_run(
    s: &mut Session,
    reference: &str,
    argv: &[&str],
) -> Result<(control::PullImageResponse, String, Vec<u8>, u32), String> {
    let req = control::PullImageRequest {
        reference: reference.into(),
    };
    let t0 = Instant::now();
    let (m, code, msg) = s.call(control::PULL_IMAGE, &req.encode(), Duration::from_secs(600))?;
    if code != 0 {
        return Err(format!("PullImage failed ({code}): {msg}"));
    }
    let pulled = control::PullImageResponse::decode(m.first().ok_or("no PullImage reply")?)
        .map_err(|_| "bad PullImageResponse")?;
    eprintln!(
        "host: pulled {} as image {} ({} KiB) in {:?}",
        pulled.digest,
        pulled.image_id,
        pulled.size / 1024,
        t0.elapsed()
    );
    let req = control::CreateCellRequest {
        image_id: pulled.image_id.clone(),
        memory_bytes: 64 << 20,
    };
    let (m, code, msg) = s.call(control::CREATE_CELL, &req.encode(), Duration::from_secs(60))?;
    if code != 0 {
        return Err(format!("CreateCell failed ({code}): {msg}"));
    }
    let cell = control::CreateCellResponse::decode(m.first().ok_or("no CreateCell reply")?)
        .map_err(|_| "bad CreateCellResponse")?;
    eprintln!("host: cell {} at {}", cell.cell_id, cell.address);
    let req = control::RunRequest {
        cell_id: cell.cell_id.clone(),
        argv: argv.iter().map(|a| a.to_string()).collect(),
        env: vec![],
    };
    let (m, code, msg) = s.call(control::RUN, &req.encode(), Duration::from_secs(300))?;
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
    Ok((pulled, cell.address, output, exit.ok_or("no exit status")?))
}

type Ran = (control::PullImageResponse, String, Vec<u8>, u32);

/// The whole flow, from the host: hello-world, then Alpine.
fn session(port: u16) -> Result<(Ran, Ran), String> {
    let mut s = Session::connect(port, Instant::now() + Duration::from_secs(600))?;
    eprintln!("host: connected to the control plane");

    // An unknown method and a bad reference are errors, not hangs.
    let (_, code, _) = s.call("/ichor.v1.Control/Nope", b"", Duration::from_secs(60))?;
    if code != grpc::status::UNIMPLEMENTED {
        return Err(format!("an unknown method gave status {code}"));
    }
    let bad = control::PullImageRequest {
        reference: "UPPER/case!".into(),
    };
    let (_, code, _) = s.call(control::PULL_IMAGE, &bad.encode(), Duration::from_secs(60))?;
    if code != grpc::status::INVALID_ARGUMENT {
        return Err(format!("a bad reference gave status {code}"));
    }

    let hello = pull_and_run(&mut s, IMAGE, &[])?;
    let alpine = pull_and_run(
        &mut s,
        ALPINE,
        &[
            "sh",
            "-c",
            "cat /etc/alpine-release; echo \"$((6 * 7)) from $(uname -s)\"; ls /bin/busybox; exit 3",
        ],
    )?;
    // Hanging up ends the control plane (`control_exit`) and the boot.
    drop(s);
    Ok((hello, alpine))
}

/// The API has no authentication yet, so by default it is local to the
/// system cell: with only `control=PORT`, the port QEMU forwards from the
/// host never answers HTTP/2, and the system cell's own switch address
/// (where other cells could reach it) refuses connections.
#[test]
fn the_control_api_is_local_unless_configured() {
    let host_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let halt = stop.clone();
    // Keeps trying for the whole boot; any byte back is a failure.
    let prober = std::thread::spawn(move || {
        let (mut tries, mut answers) = (0u32, 0u32);
        while !halt.load(std::sync::atomic::Ordering::Acquire) {
            tries += 1;
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", host_port)) {
                let mut c = Client::new("ichor");
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                if s.write_all(&c.conn.take_output()).is_ok() {
                    let mut buf = [0u8; 64];
                    if matches!(s.read(&mut buf), Ok(n) if n > 0) {
                        answers += 1;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        (tries, answers)
    });
    let out = ichor_tests::boot_with(
        "control-local",
        "control=50051 control_exit_after=30",
        2,
        |c| {
            c.net_user_opts = format!("hostfwd=tcp:127.0.0.1:{host_port}-:50051");
            c.timeout = Some(Duration::from_secs(600));
        },
    );
    stop.store(true, std::sync::atomic::Ordering::Release);
    let (tries, answers) = prober.join().unwrap();
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "control: serving ichor.v1.Control on 127.0.0.1:50051 (",
        "not published)",
        "control: not reachable at 10.88.",
        ":50051 (refused)",
        "control: exiting after 30 s (no API connections)",
        "ichor: control: exited with Some(0)",
    ]);
    assert!(tries > 10, "the host only tried {tries} times");
    assert_eq!(answers, 0, "the API answered the host {answers} times");
}

#[test]
fn the_control_plane_pulls_and_runs_an_image_from_docker_hub() {
    let host_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = std::thread::spawn(move || session(host_port));
    // Exposure is explicit: published on the uplink.
    let cmdline = "control=50051 control_publish=50051 control_exit";
    let out = ichor_tests::boot_with("control", cmdline, 2, |c| {
        c.net_user_opts = format!("hostfwd=tcp:127.0.0.1:{host_port}-:50051");
        c.timeout = Some(Duration::from_secs(900));
    });
    let result = client.join().unwrap();
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: control: starting (",
        "control: serving ichor.v1.Control on 0.0.0.0:50051 (",
        "published on uplink port 50051)",
        "control: pulling docker.io/library/hello-world@sha256:cf1b20a0",
        "control: pulled sha256:",
        "control: cell 1 at 10.88.",
        "control: cell 1 runs [\"/hello\"]",
        "control: pulling docker.io/library/alpine@sha256:1e42bbe2",
        "control: cell 2 at 10.88.",
        "control: the API client is gone; exiting",
        "ichor: control: exited with Some(0)",
    ]);
    let (hello, alpine) = result.unwrap_or_else(|e| panic!("host: {e}"));

    let (pulled, address, output, exit) = hello;
    assert!(pulled.digest.starts_with("sha256:") && pulled.image_id.len() == 64);
    assert_eq!(pulled.argv, ["/hello"]);
    assert!(address.starts_with("10.88."), "{address}");
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("Hello from Docker!"), "output: {text}");
    assert_eq!(exit, 0);

    let (pulled, _, output, exit) = alpine;
    assert_eq!(pulled.argv, ["/bin/sh"]);
    assert!(
        pulled.env.iter().any(|e| e.starts_with("PATH=")),
        "{:?}",
        pulled.env
    );
    let text = String::from_utf8_lossy(&output);
    assert_eq!(text, "3.20.3\n42 from Linux\n/bin/busybox\n");
    assert_eq!(exit, 3 << 8);
}
