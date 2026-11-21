//! Milestone 6's acceptance test (ADR-0012 §5): the control plane, a
//! native service in the system cell, pulls a real image from Docker Hub
//! through its gRPC API, verifies and converts it, makes a cell from it,
//! runs the image's command there and streams back its output.
//!
//! The guest reaches the internet through QEMU's user network (DNS at
//! 10.0.2.3), so this test needs it; the host reaches the API through a
//! forwarded port published on the uplink.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use grpc::Client;
use grpc::control::{self, RunEvent};
use ichor_tests::Exit;
use xtask::api::Session;

/// Docker's `hello-world`, pinned by its index digest (the image the OCI
/// crate's recorded pull is of).
const IMAGE: &str = "docker.io/library/hello-world@sha256:cf1b20a0c89a666b6950fecda7ccbc1b1a86520e7c53f908f3a21e79d0d60458";

/// Alpine 3.20.3 (the release the other tests use), pinned by its index
/// digest: ADR-0012's acceptance image.
const ALPINE: &str = "docker.io/library/alpine@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a";

/// The API token the pull-and-run boot gets on its boot volume.
const API_TOKEN: &str = "test-token-3f9a1c2b7d4e";

/// Pulls `reference`, makes a cell of it and runs `argv` (empty: the
/// image's command); returns the pull, the cell's address, the output and
/// the wait status.
fn pull_and_run(
    s: &mut Session,
    reference: &str,
    layers: Vec<control::LayerSource>,
    argv: &[&str],
) -> Result<(control::PullImageResponse, String, Vec<u8>, u32), String> {
    let req = control::PullImageRequest {
        reference: reference.into(),
        layers,
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

/// The extra layer the host serves: a source-style archive whose `src/`
/// goes to `/opt/extra/` in the image.
fn extra_layer() -> Vec<u8> {
    xtask::deflate::gzip(&xtask::deflate::tar(
        "src/greeting",
        b"hello from an extra layer\n",
    ))
}

fn sha256(b: &[u8]) -> String {
    format!("sha256:{}", xtask::sha256::hex(&xtask::sha256::digest(b)))
}

/// Serves `body` to every HTTP request on 127.0.0.1 (the guest's
/// 10.0.2.2) until the process ends; returns the port.
fn serve(body: Vec<u8>) -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut req = [0u8; 4096];
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = s.read(&mut req);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/gzip\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
        }
    });
    port
}

/// The whole flow, from the host: hello-world, then Alpine with an extra
/// layer (and, first, the same layer with a wrong digest, refused).
fn session(port: u16, layer_port: u16) -> Result<(Ran, Ran), String> {
    // Without the token, or with a wrong one, every call is refused. (The
    // sessions stay open until the real one is: `control_exit` ends the
    // service when no client is left.)
    let mut refused = Vec::new();
    for token in [None, Some("not-the-token")] {
        let mut s = Session::connect(port, token, Instant::now() + Duration::from_secs(600))?;
        let req = control::PullImageRequest {
            reference: IMAGE.into(),
            layers: vec![],
        };
        let (_, code, _) = s.call(control::PULL_IMAGE, &req.encode(), Duration::from_secs(60))?;
        if code != grpc::status::UNAUTHENTICATED {
            return Err(format!("a call with token {token:?} gave status {code}"));
        }
        refused.push(s);
    }
    eprintln!("host: unauthenticated calls refused");
    let mut s = Session::connect(
        port,
        Some(API_TOKEN),
        Instant::now() + Duration::from_secs(60),
    )?;
    drop(refused);
    eprintln!("host: connected to the control plane");

    // An unknown method and a bad reference are errors, not hangs.
    let (_, code, _) = s.call("/ichor.v1.Control/Nope", b"", Duration::from_secs(60))?;
    if code != grpc::status::UNIMPLEMENTED {
        return Err(format!("an unknown method gave status {code}"));
    }
    let bad = control::PullImageRequest {
        reference: "UPPER/case!".into(),
        layers: vec![],
    };
    let (_, code, _) = s.call(control::PULL_IMAGE, &bad.encode(), Duration::from_secs(60))?;
    if code != grpc::status::INVALID_ARGUMENT {
        return Err(format!("a bad reference gave status {code}"));
    }

    let hello = pull_and_run(&mut s, IMAGE, vec![], &[])?;

    let body = extra_layer();
    let layer = |digest: String| control::LayerSource {
        url: format!("http://10.0.2.2:{layer_port}/extra.tar.gz"),
        digest,
        from: "src/".into(),
        to: "/opt/extra/".into(),
    };
    // A layer that does not hash to its pinned digest fails the pull.
    let wrong = format!("sha256:{}", "0".repeat(64));
    let req = control::PullImageRequest {
        reference: ALPINE.into(),
        layers: vec![layer(wrong.clone())],
    };
    let (_, code, msg) = s.call(control::PULL_IMAGE, &req.encode(), Duration::from_secs(600))?;
    if code == 0 || !msg.contains(&wrong) || !msg.contains(&sha256(&body)) {
        return Err(format!(
            "a layer with the wrong digest was not refused: ({code}) {msg}"
        ));
    }
    eprintln!("host: refused as it should be: {msg}");

    let alpine = pull_and_run(
        &mut s,
        ALPINE,
        vec![layer(sha256(&body))],
        &[
            "sh",
            "-c",
            "cat /etc/alpine-release; echo \"$((6 * 7)) from $(uname -s)\"; ls /bin/busybox; cat /opt/extra/greeting; \
             head -1 /etc/hosts; cat /etc/hostname; exit 3",
        ],
    )?;
    lifecycle(&mut s, "2")?;
    // Hanging up ends the control plane (`control_exit`) and the boot.
    drop(s);
    Ok((hello, alpine))
}

/// Signal, Inspect and Destroy on cell `id`: a long `sleep` runs, Inspect
/// sees it, SIGTERM ends it (its Run ends with that signal), Destroy forgets
/// the cell.
fn lifecycle(s: &mut Session, id: &str) -> Result<(), String> {
    let run = control::RunRequest {
        cell_id: id.into(),
        argv: vec!["sleep".into(), "600".into()],
        env: vec![],
    };
    let sleeper = s.start(control::RUN, &run.encode());
    let inspect = control::CellRequest { cell_id: id.into() }.encode();
    // Wait until the sleeper is up (it starts asynchronously).
    let deadline = Instant::now() + Duration::from_secs(60);
    let info = loop {
        let (m, code, msg) = s.call(control::INSPECT, &inspect, Duration::from_secs(60))?;
        if code != 0 {
            return Err(format!("Inspect failed ({code}): {msg}"));
        }
        let info = control::InspectResponse::decode(m.first().ok_or("no Inspect reply")?)
            .map_err(|_| "bad InspectResponse")?;
        // Counted once registered, charged once its program is loaded.
        if (info.processes >= 1 && info.memory_used_bytes > 0) || Instant::now() > deadline {
            break info;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    if info.processes < 1
        || !info.address.starts_with("10.88.")
        || info.memory_used_bytes == 0
        || info.memory_limit_bytes != 64 << 20
        || info.image_id.len() != 64
    {
        return Err(format!("Inspect saw {info:?}"));
    }
    eprintln!("host: inspect: {info:?}");
    let sig = control::SignalRequest {
        cell_id: id.into(),
        signal: 15,
    };
    let (m, code, msg) = s.call(control::SIGNAL, &sig.encode(), Duration::from_secs(60))?;
    let reached = m
        .first()
        .and_then(|b| control::SignalResponse::decode(b).ok())
        .map_or(0, |r| r.processes);
    if code != 0 || reached < 1 {
        return Err(format!(
            "Signal ({code}, {msg}) reached {reached} processes"
        ));
    }
    let (m, code, msg) = s.wait(sleeper, Duration::from_secs(60))?;
    let exit = m
        .iter()
        .filter_map(|e| RunEvent::decode(e).ok())
        .find_map(|e| match e {
            RunEvent::ExitStatus(st) => Some(st),
            RunEvent::Output(_) => None,
        });
    if code != 0 || exit != Some(15) {
        return Err(format!(
            "the signalled Run ended ({code}, {msg}) with {exit:?}"
        ));
    }
    eprintln!("host: SIGTERM ended the sleeper");
    let (_, code, msg) = s.call(control::DESTROY, &inspect, Duration::from_secs(60))?;
    if code != 0 {
        return Err(format!("Destroy failed ({code}): {msg}"));
    }
    let (_, code, _) = s.call(control::INSPECT, &inspect, Duration::from_secs(60))?;
    if code != grpc::status::NOT_FOUND {
        return Err(format!("Inspect after Destroy gave status {code}"));
    }
    eprintln!("host: cell {id} destroyed");
    Ok(())
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
    // Publishing is asked for, but there is no API token on the boot volume:
    // the API stays on loopback.
    let out = ichor_tests::boot_with(
        "control-local",
        "control=50051 control_publish=50051 control_exit_after=30",
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
        "ichor: control: starting (",
        "no API token)",
        "control: no API token (\\ichor\\apitoken): serving on loopback only, not published",
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
    let layer_port = serve(extra_layer());
    let client = std::thread::spawn(move || {
        let r = session(host_port, layer_port);
        if let Err(e) = &r {
            eprintln!("host: FAILED: {e}");
        }
        r
    });
    // Exposure is explicit: published on the uplink.
    let cmdline = "control=50051 control_publish=50051 control_exit";
    let out = ichor_tests::boot_with("control", cmdline, 2, |c| {
        c.net_user_opts = format!("hostfwd=tcp:127.0.0.1:{host_port}-:50051");
        c.timeout = Some(Duration::from_secs(900));
        c.api_token = Some(API_TOKEN.into());
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
        ", not its pinned sha256:0000000000000000000000000000000000000000000000000000000000000000; refused",
        "control: pulling docker.io/library/alpine@sha256:1e42bbe2",
        "control: layer http://10.0.2.2:",
        "verified (",
        "control: cell 2 at 10.88.",
        "control: cell 2 runs [\"sleep\", \"600\"]",
        "control: cell 2 signal 15 to 1 processes",
        "control: cell 2 destroyed (",
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
    assert_eq!(
        text,
        "3.20.3\n42 from Linux\n/bin/busybox\nhello from an extra layer\n\
         127.0.0.1\tlocalhost\nichor\n"
    );
    assert_eq!(exit, 3 << 8);
}
