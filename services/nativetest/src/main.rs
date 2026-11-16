//! The native ABI v2 self-test (ADR-0012 §2), run by the kernel in the
//! system cell at every boot (`nativetest.rs`). It checks each call it can
//! from a real native process: the clock, the CSPRNG, the heap, TCP and
//! UDP over the cell's loopback, and the container path end to end:
//! Docker's `hello-world` layer (recorded from Docker Hub) converted into
//! an Ichor image here, verified by the kernel, made into a cell, and run,
//! with its output read back. Handles without the right are refused.
//!
//! Arguments: the system cell's handle and the switch's handle (hex).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use rt::{Error, Handle, WaitItem};

rt::main!(main);

/// The recorded `hello-world` layer blob (an HTTP response; its body is
/// the gzip'd tar).
const LAYER: &[u8] = include_bytes!("../../oci/testdata/hello-world/07.http");

fn fail(what: &str) -> i32 {
    rt::log!("native: FAILED: {what}");
    1
}

fn handle(arg: Option<&&str>) -> Option<Handle> {
    u64::from_str_radix(arg?, 16).ok().map(Handle::from_raw)
}

/// Waits up to 10 s for `events` on `h`.
fn wait_for(h: &Handle, events: u32) -> bool {
    let mut items = [WaitItem {
        handle: h.raw(),
        events,
        revents: 0,
    }];
    let deadline = rt::monotonic() + 10_000_000_000;
    while rt::monotonic() < deadline {
        if rt::wait(&mut items, 1_000_000_000) == Ok(1) {
            return true;
        }
    }
    false
}

fn main(args: &[&str]) -> i32 {
    let (Some(cell), Some(switch)) = (handle(args.get(1)), handle(args.get(2))) else {
        return fail("no cell and switch handles");
    };
    match run(&cell, &switch) {
        Ok(()) => {
            rt::log("native: v2 self-test passed");
            0
        }
        Err(what) => fail(what),
    }
}

fn run(cell: &Handle, switch: &Handle) -> Result<(), &'static str> {
    // Time and entropy.
    let t0 = rt::monotonic();
    let wall = rt::realtime() / 1_000_000_000;
    if !(1_700_000_000..4_000_000_000).contains(&wall) {
        return Err("CLOCK_REALTIME is not a plausible date");
    }
    let mut r = [0u8; 64];
    rt::random(&mut r);
    if r.iter().all(|&b| b == 0) {
        return Err("RANDOM gave zeros");
    }

    // The heap: many small blocks and a few large ones, freed and reused.
    let mut small: Vec<Vec<u8>> = (0..2000)
        .map(|i| alloc::vec![i as u8; i % 300 + 1])
        .collect();
    let big: Vec<u8> = alloc::vec![7; 3 << 20];
    if big.iter().map(|&b| u64::from(b)).sum::<u64>() != 7 * (3 << 20) {
        return Err("a large block lost its contents");
    }
    drop(big);
    small.retain(|v| v.len() % 2 == 0);
    if small.iter().any(|v| v.iter().any(|&b| b != v[0])) {
        return Err("a small block was overwritten");
    }
    drop(small);

    tcp()?;
    udp()?;
    container(cell, switch)?;
    rt::log!(
        "native: clock, random, heap, TCP, UDP and a container in {} ms",
        (rt::monotonic() - t0) / 1_000_000
    );
    Ok(())
}

fn tcp() -> Result<(), &'static str> {
    const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
    let listener = rt::tcp_listen(7070, 4).map_err(|_| "TCP_LISTEN")?;
    if rt::tcp_accept(&listener).err() != Some(Error::WouldBlock) {
        return Err("TCP_ACCEPT with nothing pending did not say WouldBlock");
    }
    let c = rt::tcp_connect(LOOPBACK, 7070).map_err(|_| "TCP_CONNECT")?;
    if !wait_for(&c, rt::WRITABLE) {
        return Err("the connection never became writable");
    }
    rt::sock_error(&c).map_err(|_| "SOCK_ERROR after connecting")?;
    if !wait_for(&listener, rt::READABLE) {
        return Err("the listener never became readable");
    }
    let s = rt::tcp_accept(&listener).map_err(|_| "TCP_ACCEPT")?;
    let msg = b"ping over the cell's loopback";
    if rt::send(&c, msg) != Ok(msg.len()) {
        return Err("SOCK_SEND");
    }
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while got.len() < msg.len() {
        if !wait_for(&s, rt::READABLE) {
            return Err("the accepted socket never became readable");
        }
        match rt::recv(&s, &mut buf) {
            Ok(0) => return Err("early end of stream"),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(Error::WouldBlock) => {}
            Err(_) => return Err("SOCK_RECV"),
        }
    }
    if got != msg {
        return Err("TCP data differs");
    }
    drop(c);
    // The peer's close is the end of the stream.
    loop {
        if !wait_for(&s, rt::READABLE) {
            return Err("the close never arrived");
        }
        match rt::recv(&s, &mut buf) {
            Ok(0) => break,
            Err(Error::WouldBlock) => {}
            _ => return Err("data after the close"),
        }
    }
    Ok(())
}

fn udp() -> Result<(), &'static str> {
    let a = rt::udp_bind(7071).map_err(|_| "UDP_BIND")?;
    let b = rt::udp_bind(0).map_err(|_| "UDP_BIND ephemeral")?;
    if rt::udp_send(&b, b"datagram", [127, 0, 0, 1], 7071) != Ok(8) {
        return Err("UDP_SEND");
    }
    if !wait_for(&a, rt::READABLE) {
        return Err("the datagram never arrived");
    }
    let mut buf = [0u8; 32];
    let (n, from, port) = rt::udp_recv(&a, &mut buf).map_err(|_| "UDP_RECV")?;
    if &buf[..n] != b"datagram" || from != [127, 0, 0, 1] || port == 0 {
        return Err("the datagram or its source is wrong");
    }
    Ok(())
}

fn container(cell: &Handle, switch: &Handle) -> Result<(), &'static str> {
    let body = LAYER
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &LAYER[i + 4..])
        .ok_or("the recorded layer has no body")?;
    let tar = layer::gunzip(body).map_err(|_| "gunzip")?;
    let mut tree = layer::Tree::new();
    tree.add_tar(&tar).map_err(|_| "the layer's tar")?;
    let image_bytes = tree.image();

    // A corrupted image is refused.
    let mut bad = image_bytes.clone();
    if let Some(b) = bad.get_mut(100) {
        *b ^= 1;
    }
    if rt::image_create(&bad).is_ok() {
        return Err("IMAGE_CREATE took a corrupted image");
    }
    let image = rt::image_create(&image_bytes).map_err(|_| "IMAGE_CREATE")?;

    // Capabilities: the image is not a cell, and a cell handle without
    // CREATE_CELL cannot make one.
    if rt::cell_create(&image, &image, 4096).err() != Some(Error::BadHandle) {
        return Err("CELL_CREATE took an image as the parent");
    }
    let weak = cell.dup(1 << 2).map_err(|_| "HANDLE_DUP")?; // INSPECT only
    if rt::cell_create(&weak, &image, 4096).is_ok() {
        return Err("CELL_CREATE without CREATE_CELL");
    }
    if rt::port_publish(&image, 8080, cell, 80).is_ok() {
        return Err("PORT_PUBLISH without the switch");
    }
    let _ = switch;

    let c = rt::cell_create(cell, &image, 4096).map_err(|_| "CELL_CREATE")?;
    let addr = rt::cell_addr(&c).map_err(|_| "CELL_ADDR")?;
    if addr[0] != 10 {
        return Err("the new cell has no switch address");
    }
    if rt::cell_spawn(&c, &["no-such-program"], &[]).err() != Some(Error::NotFound) {
        return Err("CELL_SPAWN of a missing program");
    }
    let p = rt::cell_spawn(&c, &["/hello"], &["PATH=/bin"]).map_err(|_| "CELL_SPAWN")?;
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        if !wait_for(&p, rt::READABLE) {
            return Err("the process's output never came");
        }
        match rt::process_read(&p, &mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(Error::WouldBlock) => {}
            Err(_) => return Err("PROCESS_READ"),
        }
    }
    let status = rt::process_wait(&p).map_err(|_| "PROCESS_WAIT")?;
    let text = String::from_utf8_lossy(&out);
    if status != 0 || !text.contains("Hello from Docker!") {
        rt::log!("native: hello-world exited {status:#x}: {text}");
        return Err("hello-world did not greet");
    }
    rt::log!(
        "native: hello-world ran in cell {}.{}.{}.{} ({} bytes of output)",
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        out.len()
    );
    Ok(())
}
