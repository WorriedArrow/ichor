//! Milestone 5, first network test: the virtio-net driver and the
//! `kernel/net` stack against a real peer, QEMU's user-mode network
//! (slirp: gateway 10.0.2.2, this host 10.0.2.15).
//!
//! The interface resolves the gateway (ARP) and pings it (slirp's answer
//! depends on the host's ICMP permissions, so a missing reply is reported,
//! not fatal). With `net_echo_port=N` on the command line it then opens a
//! TCP connection to 10.0.2.2:N, which slirp forwards to the test
//! harness's echo server on the host's loopback, sends [`ECHO_BYTES`]
//! bytes, checks every byte comes back, and closes.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use frame::println;
use net::iface::Interface;
use net::tcp::{Segment, State, Tcp};
use net::wire::{self, Echo};
use net::{Ipv4Addr, Mac};

use crate::runtest::fail;

const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const ECHO_BYTES: usize = 256 * 1024;
const PING_IDENT: u16 = 0x1c40;

/// The harness's TCP echo port (0: none).
static ECHO_PORT: AtomicU32 = AtomicU32::new(0);

/// Sets the TCP echo test's port (`net_echo_port=N`).
pub(crate) fn set_echo_port(port: u16) {
    ECHO_PORT.store(u32::from(port), Ordering::Relaxed);
}

fn now() -> Duration {
    frame::time::now()
}

/// Moves frames between the device and the interface; returns the IP
/// packets the interface hands up.
fn pump(dev: &mut virtio_net::VirtioNet, ifc: &mut Interface) -> Vec<net::iface::Packet> {
    ifc.poll(now());
    while let Some(f) = ifc.transmit() {
        dev.transmit(&f);
    }
    let mut up = Vec::new();
    while let Some(f) = dev.receive() {
        if let Some(p) = ifc.receive(now(), &f) {
            up.push(p);
        }
    }
    while let Some(f) = ifc.transmit() {
        dev.transmit(&f);
    }
    up
}

pub(crate) fn run() {
    let Some(dev) = virtio_net::probe_all().into_iter().next() else {
        println!("ichor: net: no virtio-net device");
        return;
    };
    let mut dev = dev.unwrap_or_else(|e| {
        println!("ichor: net: virtio-net init failed: {e:?}");
        fail("virtio-net init")
    });
    let m = dev.mac();
    println!(
        "ichor: net: virtio-net {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, {GUEST}/24 via {GATEWAY}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    );
    let mut ifc = Interface::new(Mac(m), GUEST, 24, Some(GATEWAY));

    // Resolve the gateway and ping it.
    let req = Echo {
        kind: wire::ICMP_ECHO_REQUEST,
        ident: PING_IDENT,
        seq: 1,
        data: b"ichor",
    }
    .emit();
    ifc.send(now(), GATEWAY, wire::PROTO_ICMP, &req);
    let deadline = now() + Duration::from_secs(2);
    let mut pinged = false;
    while now() < deadline && !pinged {
        for p in pump(&mut dev, &mut ifc) {
            pinged |= p.protocol == wire::PROTO_ICMP
                && Echo::parse(&p.payload)
                    .is_some_and(|e| e.kind == wire::ICMP_ECHO_REPLY && e.ident == PING_IDENT);
        }
        if ifc.neighbor(GATEWAY, now()).is_some() && pinged {
            break;
        }
        frame::task::yield_now();
    }
    let Some(gw) = ifc.neighbor(GATEWAY, now()) else {
        fail("net: the gateway did not answer ARP");
    };
    println!(
        "ichor: net: gateway {GATEWAY} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}; ping {}",
        gw.0[0],
        gw.0[1],
        gw.0[2],
        gw.0[3],
        gw.0[4],
        gw.0[5],
        if pinged {
            "answered"
        } else {
            "not answered (host ICMP permissions)"
        }
    );

    let port = ECHO_PORT.load(Ordering::Relaxed) as u16;
    if port != 0 {
        tcp_echo(&mut dev, &mut ifc, port);
    }
}

/// Sends `ECHO_BYTES` to the harness's echo server and checks they return.
fn tcp_echo(dev: &mut virtio_net::VirtioNet, ifc: &mut Interface, port: u16) {
    let data: Vec<u8> = (0..ECHO_BYTES)
        .map(|i| (i as u8).wrapping_mul(13) ^ (i >> 10) as u8)
        .collect();
    let mut iss = [0u8; 4];
    crate::random::fill(&mut iss);
    let local = (GUEST, 49152);
    let remote = (GATEWAY, port);
    let start = now();
    let mut tcp = Tcp::connect(local, remote, u32::from_le_bytes(iss), start);
    let mut sent = 0;
    let mut got = Vec::with_capacity(ECHO_BYTES);
    let mut buf = alloc::vec![0u8; 65536];
    let mut closed = false;
    let deadline = start + Duration::from_secs(30);
    loop {
        let t = now();
        if t > deadline {
            println!(
                "ichor: net: tcp echo stalled in {:?}: sent {sent}, got {} of {ECHO_BYTES}",
                tcp.state(),
                got.len()
            );
            fail("net: tcp echo timed out");
        }
        if let Some(e) = tcp.error() {
            println!("ichor: net: tcp echo failed: {e:?}");
            fail("net: tcp echo");
        }
        sent += tcp.send(&data[sent..], t);
        let n = tcp.recv(&mut buf, t);
        got.extend_from_slice(&buf[..n]);
        if got.len() == ECHO_BYTES && !closed {
            tcp.close(t);
            closed = true;
        }
        tcp.poll(t);
        while let Some(seg) = tcp.transmit() {
            ifc.send(t, GATEWAY, wire::PROTO_TCP, &seg);
        }
        for p in pump(dev, ifc) {
            if p.protocol != wire::PROTO_TCP || p.src != GATEWAY {
                continue;
            }
            if let Some(seg) = Segment::parse(&p.payload, p.src, p.dst)
                && seg.dst_port == local.1
                && seg.src_port == port
            {
                tcp.on_segment(&seg, now());
            }
        }
        while let Some(seg) = tcp.transmit() {
            ifc.send(now(), GATEWAY, wire::PROTO_TCP, &seg);
        }
        if closed && matches!(tcp.state(), State::TimeWait | State::Closed) {
            break;
        }
        frame::task::yield_now();
    }
    if got != data {
        fail("net: tcp echo returned different bytes");
    }
    let ms = now().saturating_sub(start).as_millis();
    println!(
        "ichor: net: tcp echo of {} KiB through slirp ok ({ms} ms), closed in {:?}",
        ECHO_BYTES / 1024,
        tcp.state()
    );
}
