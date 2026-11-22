//! The machine's configuration from its cloud's metadata service
//! (`net::metadata`), asked for once, over the kernel's own TCP, before the
//! uplink is the cells' (which cannot reach the service). `metadata=gcp`,
//! `aws`, `azure` or `auto` (each in turn) asks; nothing is asked by
//! default, so a machine that is in no cloud does not wait for one.
//!
//! What the boot volume says goes over what the cloud says.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use frame::println;
use frame::sync::SpinLock;
use net::Ipv4Addr;
use net::iface::Interface;
use net::link::Link;
use net::metadata::{self, Client, Cloud, Config, Outcome};
use net::tcp::{Segment, Tcp};
use net::wire;

/// How long one request may take, and how often a cloud that was named is
/// asked (its service may be a moment behind the machine).
const PATIENCE: Duration = Duration::from_secs(5);
const TRIES: u32 = 4;

struct Ask {
    /// The clouds to try.
    clouds: Vec<Cloud>,
    at: (Ipv4Addr, u16),
}

static ASK: SpinLock<Option<Ask>> = SpinLock::new(None);
static CONFIG: SpinLock<Option<Config>> = SpinLock::new(None);

/// Has the metadata service asked: `which` cloud's (`metadata=`), at
/// another address than the real one (`metadata_addr=IP:PORT`; tests).
pub(crate) fn set(which: &str, at: Option<&str>) {
    let clouds = match (which, Cloud::parse(which)) {
        ("auto", _) => Cloud::ALL.to_vec(),
        (_, Some(c)) => alloc::vec![c],
        _ => {
            println!("ichor: cloud: no cloud {which:?} (gcp, aws, azure, auto)");
            return;
        }
    };
    let at = at
        .and_then(|a| a.split_once(':'))
        .and_then(|(ip, port)| Some((ip.parse().ok()?, port.parse().ok()?)))
        .unwrap_or((metadata::ADDRESS, metadata::PORT));
    *ASK.lock() = Some(Ask { clouds, at });
}

/// The machine's configuration, if it was asked for and has one.
pub(crate) fn config() -> Option<Config> {
    CONFIG.lock().clone()
}

/// Bytes for the rest of time (the control plane's blobs).
pub(crate) fn keep(s: &str) -> &'static [u8] {
    Box::leak(s.as_bytes().to_vec().into_boxed_slice())
}

/// Asks for the configuration, if it is to be.
pub(crate) fn run(dev: &mut dyn Link, ifc: &mut Interface) {
    let Some(ask) = ASK.lock().take() else {
        return;
    };
    let tries = if ask.clouds.len() == 1 { TRIES } else { 1 };
    for attempt in 0..tries {
        for &cloud in &ask.clouds {
            let Some(answer) = one(dev, ifc, cloud, ask.at) else {
                continue;
            };
            let config = answer.as_deref().and_then(Config::parse);
            match &config {
                // (Not what it says: a word in it may be a secret.)
                Some(c) => println!(
                    "ichor: cloud: {}: options [{}], {}, {}",
                    cloud.name(),
                    known(&c.options).join(" "),
                    if c.api_token.is_empty() {
                        "no API token"
                    } else {
                        "an API token"
                    },
                    if c.api_tls.is_empty() {
                        "no API certificate"
                    } else {
                        "an API certificate"
                    },
                ),
                None => println!("ichor: cloud: {}: no configuration", cloud.name()),
            }
            *CONFIG.lock() = config;
            return;
        }
        if attempt + 1 < tries {
            frame::task::sleep_until(frame::time::now() + Duration::from_secs(1));
        }
    }
    println!("ichor: cloud: no metadata service answered");
}

/// The names of the options that mean something from a cloud.
fn known(options: &str) -> Vec<&str> {
    let c = cmdline::Cmdline::new(options);
    let names = [
        "control",
        "control_listen",
        "control_publish",
        "control_plaintext",
        "control_exit",
        "control_exit_after",
        "dns",
    ];
    let has = |n: &&str| c.iter().any(|o| o.key == *n);
    names.into_iter().filter(has).collect()
}

/// One cloud's answer: `None` if it is not there.
fn one(
    dev: &mut dyn Link,
    ifc: &mut Interface,
    cloud: Cloud,
    at: (Ipv4Addr, u16),
) -> Option<Option<Vec<u8>>> {
    let mut client = Client::new(cloud);
    let host: String = alloc::format!("{}", at.0);
    for _ in 0..4 {
        let answer = exchange(dev, ifc, at, &client.request(&host))?;
        match client.answer(&answer) {
            Outcome::Ask => {}
            Outcome::Config(c) => return Some(c),
            Outcome::NotThis => return None,
        }
    }
    None
}

/// Sends `request` to `remote` and returns what came back before it closed.
fn exchange(
    dev: &mut dyn Link,
    ifc: &mut Interface,
    remote: (Ipv4Addr, u16),
    request: &[u8],
) -> Option<Vec<u8>> {
    let mut r = [0u8; 8];
    crate::random::fill(&mut r);
    let iss = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
    // Below the NAT's ports, and not the one before.
    let port = 20_000 + u16::from_le_bytes([r[4], r[5]]) % 10_000;
    let local = (ifc.addr, port);
    let start = frame::time::now();
    let mut tcp = Tcp::connect(local, remote, iss, start);
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = alloc::vec![0u8; 4096];
    let mut closing = false;
    loop {
        let t = frame::time::now();
        if tcp.error().is_some() || t.saturating_sub(start) > PATIENCE {
            return None;
        }
        sent += tcp.send(&request[sent..], t);
        loop {
            let n = tcp.recv(&mut buf, t);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        if got.len() > metadata::MAX_ANSWER {
            return None;
        }
        let whole = tcp.peer_closed() || metadata::complete(&got);
        if whole && !closing {
            tcp.close(t);
            closing = true;
        }
        tcp.poll(t);
        while let Some(seg) = tcp.transmit() {
            ifc.send(t, remote.0, wire::PROTO_TCP, &seg);
        }
        for p in crate::nettest::pump(dev, ifc) {
            if p.protocol == wire::PROTO_TCP
                && p.src == remote.0
                && let Some(seg) = Segment::parse(&p.payload, p.src, p.dst)
                && (seg.dst_port, seg.src_port) == (port, remote.1)
            {
                tcp.on_segment(&seg, frame::time::now());
            }
        }
        while let Some(seg) = tcp.transmit() {
            ifc.send(t, remote.0, wire::PROTO_TCP, &seg);
        }
        // (The other end has its FIN; what it answers is nobody's.)
        if closing {
            crate::nettest::pump(dev, ifc);
            return Some(got);
        }
        frame::task::yield_now();
    }
}
