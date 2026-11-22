//! The cell switch (ADR-0010 §3): every cell's stack is a port with an
//! address the switch assigns in 10.88.0.0/16; the switch forwards IP
//! packets between ports by that assignment (anti-spoofing and rate limits
//! in `net::switch`), and anything bound outside goes to the uplink, any
//! `net::link::Link` (a NIC driver, or a software link such as a VPN
//! wrapped around one), through source NAT and published ports
//! (`net::nat`).
//!
//! Between two cells a packet is handed from one stack to the other as an
//! owned buffer, inside the call that produced it: no device and no copy
//! (the cross-cell fast path). [`send`] runs a work queue outside every
//! stack lock, so a reply that a delivery provokes is routed in the same
//! call and two stacks never lock each other.
//!
//! Lock order: the uplink's lock may be held while taking the table's,
//! never the reverse; stack locks are never held while taking either.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::time::Duration;

use frame::println;
use frame::sync::SpinLock;
use net::Ipv4Addr;
use net::dhcp::{Client, Lease};
use net::iface::{Interface, Packet};
use net::link::Link;
use net::nat::{self, Nat};
use net::switch::{PortId, Switch, Verdict};
use net::tcp;
use net::wire::{PROTO_TCP, PROTO_UDP};

use crate::netstack::Stack;

/// The cells' subnet.
pub(crate) const SUBNET: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 0);
pub(crate) const PREFIX: u8 = 16;
/// Most packets one [`send`] call routes (a loop guard).
const MAX_ROUNDS: usize = 100_000;

struct Table {
    switch: Switch,
    stacks: BTreeMap<PortId, Weak<Stack>>,
}

struct Uplink {
    dev: Box<dyn Link>,
    ifc: Interface,
    nat: Nat,
    last_expire: Duration,
    /// The largest TCP segment the uplink's network carries: its MTU
    /// less 40 (every SYN crossing the uplink is clamped to it).
    mss: u16,
    /// The client whose lease the address is, if it came from DHCP.
    dhcp: Option<Client>,
    renewed: bool,
    /// The lease ran out unrenewed (the address is kept: see
    /// [`Uplink::lease_news`]).
    expired: bool,
}

/// What became of the uplink's lease, to log outside the lock.
enum LeaseNews {
    /// The first renewal (later ones that change nothing are quiet).
    Renewed(Lease),
    /// A renewal that moved the uplink, from this address.
    Moved(Ipv4Addr, Lease),
    /// Nobody renewed it in time.
    Expired,
}

impl Uplink {
    /// Sends what the DHCP client has to say; tells when the lease has run
    /// out. The address is then kept, and servers asked until one answers:
    /// giving it up (RFC 2131 §4.4.5) would cut off every cell because a
    /// DHCP server was away, and clouds keep a VM's address for its life.
    fn poll_dhcp(&mut self, t: Duration) -> Option<LeaseNews> {
        let c = self.dhcp.as_mut()?;
        if let Some(f) = c.poll(t) {
            self.dev.transmit(&f);
        }
        let out = c.lease().is_none();
        (out && !core::mem::replace(&mut self.expired, out)).then_some(LeaseNews::Expired)
    }

    /// Takes a frame the DHCP client may be waiting for; applies the lease
    /// if it was the answer.
    fn dhcp_frame(&mut self, t: Duration, frame: &[u8]) -> Option<LeaseNews> {
        let c = self.dhcp.as_mut().filter(|c| c.exchanging())?;
        let lease = c.receive(t, frame)?;
        self.expired = false;
        let was = self.ifc.addr;
        if (lease.addr, lease.prefix, lease.router) == (was, self.ifc.prefix, self.ifc.gateway) {
            let first = !core::mem::replace(&mut self.renewed, true);
            return first.then_some(LeaseNews::Renewed(lease));
        }
        self.ifc.readdress(lease.addr, lease.prefix, lease.router);
        if lease.addr != was {
            self.nat.set_outside(lease.addr);
        }
        Some(LeaseNews::Moved(was, lease))
    }
}

/// Logs what became of the uplink's lease, and takes its DNS servers.
fn lease_news(news: LeaseNews) {
    match news {
        LeaseNews::Renewed(l) => {
            println!(
                "ichor: net: DHCP lease renewed ({}/{} from {})",
                l.addr, l.prefix, l.server
            );
            set_uplink_dns(l.dns);
        }
        LeaseNews::Moved(was, l) => {
            println!(
                "ichor: net: DHCP moved the uplink from {was} to {}/{} (from {}); connections through it are cut",
                l.addr, l.prefix, l.server
            );
            set_uplink_dns(l.dns);
        }
        LeaseNews::Expired => println!(
            "ichor: net: the DHCP lease ran out and no server renewed it; keeping the address and asking on"
        ),
    }
}

static TABLE: SpinLock<Option<Table>> = SpinLock::new(None);
static UPLINK: SpinLock<Option<Uplink>> = SpinLock::new(None);
/// The DNS servers the uplink's network named (its DHCP lease), first
/// one first.
static UPLINK_DNS: SpinLock<Vec<Ipv4Addr>> = SpinLock::new(Vec::new());

/// Records the uplink network's DNS servers.
pub(crate) fn set_uplink_dns(dns: Vec<Ipv4Addr>) {
    *UPLINK_DNS.lock() = dns;
}

/// The uplink network's first DNS server, if it named one.
pub(crate) fn uplink_dns() -> Option<Ipv4Addr> {
    UPLINK_DNS.lock().first().copied()
}

/// What the uplink has done with inbound traffic, for diagnostics.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UplinkStats {
    /// Frames the device received.
    pub(crate) frames: u64,
    /// IP packets translated and handed to a cell.
    pub(crate) delivered: u64,
    /// Connection requests refused (nothing published on the port).
    pub(crate) refused: u64,
    /// Other packets no mapping claimed (dropped).
    pub(crate) unmapped: u64,
    /// Packets cells sent out through NAT.
    pub(crate) sent: u64,
}

static UPLINK_STATS: SpinLock<UplinkStats> = SpinLock::new(UplinkStats {
    frames: 0,
    delivered: 0,
    refused: 0,
    unmapped: 0,
    sent: 0,
});

/// The uplink's counters.
pub(crate) fn uplink_stats() -> UplinkStats {
    *UPLINK_STATS.lock()
}

fn now() -> Duration {
    frame::time::now()
}

fn with_table<R>(f: impl FnOnce(&mut Table) -> R) -> R {
    let mut t = TABLE.lock();
    let t = t.get_or_insert_with(|| Table {
        switch: Switch::new(SUBNET, PREFIX),
        stacks: BTreeMap::new(),
    });
    f(t)
}

/// Attaches `stack` as the port of `cell`; returns its assigned address
/// (the same one again if the cell is already attached).
pub(crate) fn attach(cell: u64, stack: Weak<Stack>) -> Option<Ipv4Addr> {
    with_table(|t| {
        let addr = match t.switch.addr(cell) {
            Some(a) => a,
            None => t.switch.attach(cell)?,
        };
        t.stacks.insert(cell, stack);
        Some(addr)
    })
}

/// Withdraws every uplink port published to `cell`, which is being
/// destroyed; its live connections go on.
pub(crate) fn unpublish_cell(cell: u64) {
    let mut u = UPLINK.lock();
    if let (Some(u), Some(addr)) = (u.as_mut(), addr_of(cell)) {
        u.nat.unpublish_all(addr);
    }
}

/// Detaches `cell`: its address is free for another cell, so the NAT
/// forgets it in the same step (under the uplink's lock, which every
/// packet through the NAT takes).
pub(crate) fn detach(cell: u64) {
    let mut u = UPLINK.lock();
    let addr = with_table(|t| {
        let addr = t.switch.addr(cell);
        t.switch.detach(cell);
        t.stacks.remove(&cell);
        addr
    });
    if let (Some(u), Some(addr)) = (u.as_mut(), addr) {
        u.nat.forget_addr(addr);
    }
}

/// The address assigned to `cell`.
pub(crate) fn addr_of(cell: u64) -> Option<Ipv4Addr> {
    with_table(|t| t.switch.addr(cell))
}

/// Sets `cell`'s rate limits (0: unlimited).
#[allow(dead_code)] // the control plane's, milestone 6
pub(crate) fn set_limits(cell: u64, pps: u64, bps: u64) -> bool {
    with_table(|t| t.switch.set_limits(cell, pps, bps, now()))
}

/// The switch's counters for `cell`: (sent, received, dropped).
pub(crate) fn stats(cell: u64) -> Option<(u64, u64, u64)> {
    with_table(|t| {
        t.switch
            .stats(cell)
            .map(|s| (s.sent, s.received, s.dropped))
    })
}

/// Makes `dev`/`ifc` the uplink, on a network whose MTU is `mtu` (GCP's
/// VPCs: 1460; most others 1500). `dhcp` is the client whose lease `ifc`
/// has, renewed from here on.
pub(crate) fn set_uplink(dev: Box<dyn Link>, ifc: Interface, mtu: u16, dhcp: Option<Client>) {
    let nat = Nat::new(ifc.addr);
    *UPLINK.lock() = Some(Uplink {
        dev,
        ifc,
        nat,
        last_expire: now(),
        mss: mtu.clamp(576, 1500) - 40,
        dhcp,
        renewed: false,
        expired: false,
    });
}

/// Whether there is an uplink.
pub(crate) fn has_uplink() -> bool {
    UPLINK.lock().is_some()
}

/// Publishes `port` (protocol `proto`) on the uplink to `cell`'s
/// `inside_port`. Fails without an uplink or an attached cell, or if the
/// port is taken.
pub(crate) fn publish(proto: u8, port: u16, cell: u64, inside_port: u16) -> bool {
    let Some(addr) = addr_of(cell) else {
        return false;
    };
    match UPLINK.lock().as_mut() {
        Some(u) => u.nat.publish(proto, port, (addr, inside_port)),
        None => false,
    }
}

/// Withdraws a published port.
pub(crate) fn unpublish(proto: u8, port: u16) {
    if let Some(u) = UPLINK.lock().as_mut() {
        u.nat.unpublish(proto, port);
    }
}

fn ports(proto: u8, data: &[u8]) -> Option<(u16, u16)> {
    match proto {
        PROTO_TCP | PROTO_UDP if data.len() >= 8 => Some((
            u16::from_be_bytes([data[0], data[1]]),
            u16::from_be_bytes([data[2], data[3]]),
        )),
        _ => None,
    }
}

fn flags(proto: u8, data: &[u8]) -> u8 {
    if proto == PROTO_TCP {
        nat::tcp_flags(data)
    } else {
        0
    }
}

/// Routes packets that `from`'s stack sent, and every packet their
/// delivery provokes, until none are left.
pub(crate) fn send(from: PortId, pkts: Vec<Packet>) {
    if pkts.is_empty() {
        return;
    }
    let mut queue: VecDeque<(PortId, Packet)> = pkts.into_iter().map(|p| (from, p)).collect();
    for _ in 0..MAX_ROUNDS {
        let Some((port, p)) = queue.pop_front() else {
            return;
        };
        let (verdict, target) = with_table(|t| {
            let v = t
                .switch
                .route(port, p.src, p.dst, p.payload.len() + 20, now());
            let target = match v {
                Verdict::Deliver(id) => t.stacks.get(&id).and_then(Weak::upgrade),
                _ => None,
            };
            (v, target)
        });
        match (verdict, target) {
            (Verdict::Deliver(id), Some(stack)) => {
                for out in stack.receive(p) {
                    queue.push_back((id, out));
                }
            }
            (Verdict::Uplink, _) => uplink_out(port, p),
            _ => {}
        }
    }
}

/// Sends a packet of `from`'s cell out of the uplink, translated.
fn uplink_out(from: PortId, mut p: Packet) {
    let mut u = UPLINK.lock();
    let Some(u) = u.as_mut() else {
        return;
    };
    // Detached since it was routed: a mapping made now would outlive it.
    if with_table(|t| t.switch.port_of(p.src)) != Some(from) {
        return;
    }
    let Some((sp, dp)) = ports(p.protocol, &p.payload) else {
        return; // ICMP and others are not translated yet
    };
    let t = now();
    let f = flags(p.protocol, &p.payload);
    let Some(src) = u.nat.outbound(p.protocol, (p.src, sp), (p.dst, dp), f, t) else {
        return;
    };
    if !nat::rewrite(p.protocol, &mut p.payload, src, (p.dst, dp)) {
        return;
    }
    if p.protocol == PROTO_TCP {
        nat::clamp_mss(src.0, p.dst, &mut p.payload, u.mss);
    }
    u.ifc.send(t, p.dst, p.protocol, &p.payload);
    while let Some(frame) = u.ifc.transmit() {
        u.dev.transmit(&frame);
    }
    UPLINK_STATS.lock().sent += 1;
}

/// Moves the uplink's traffic: transmits what is queued, receives frames,
/// translates them and delivers them to their cells. Returns whether any
/// frame arrived (the caller polls again soon while traffic flows).
pub(crate) fn poll_uplink() -> bool {
    let mut inbound: Vec<(PortId, Packet)> = Vec::new();
    let mut any = false;
    let mut st = UplinkStats::default();
    let mut news = None;
    {
        let mut u = UPLINK.lock();
        let Some(u) = u.as_mut() else {
            return false;
        };
        let t = now();
        u.ifc.poll(t);
        news = u.poll_dhcp(t).or(news);
        if t.saturating_sub(u.last_expire) > Duration::from_secs(10) {
            u.nat.expire(t);
            u.last_expire = t;
        }
        for _ in 0..256 {
            let Some(frame) = u.dev.receive() else {
                break;
            };
            any = true;
            st.frames += 1;
            if let Some(n) = u.dhcp_frame(t, &frame) {
                news = Some(n);
                continue;
            }
            let Some(mut p) = u.ifc.receive(t, &frame) else {
                continue;
            };
            let Some((sp, dp)) = ports(p.protocol, &p.payload) else {
                continue;
            };
            let f = flags(p.protocol, &p.payload);
            let Some(inside) = u.nat.inbound(p.protocol, (p.src, sp), dp, f, t) else {
                // A connection request for a port nothing is published
                // on: refuse it, as a closed port does.
                if p.protocol == PROTO_TCP
                    && f & (tcp::SYN | tcp::ACK | tcp::RST) == tcp::SYN
                    && let Some(seg) = tcp::Segment::parse(&p.payload, p.src, p.dst)
                {
                    let ack = seg.seq.wrapping_add(seg.len());
                    let rst = tcp::segment(
                        (p.dst, dp),
                        (p.src, sp),
                        0,
                        ack,
                        tcp::RST | tcp::ACK,
                        0,
                        None,
                        &[],
                    );
                    u.ifc.send(t, p.src, PROTO_TCP, &rst);
                    st.refused += 1;
                } else {
                    st.unmapped += 1;
                }
                continue;
            };
            if !nat::rewrite(p.protocol, &mut p.payload, (p.src, sp), inside) {
                continue;
            }
            // A SYN from outside asks for segments the uplink's network
            // may not carry: clamp it, so the cell answers with small ones.
            if p.protocol == PROTO_TCP {
                nat::clamp_mss(p.src, inside.0, &mut p.payload, u.mss);
            }
            p.dst = inside.0;
            let Some(id) = with_table(|tb| {
                let id = tb.switch.port_of(inside.0)?;
                tb.switch.received_from_uplink(id);
                Some(id)
            }) else {
                continue;
            };
            inbound.push((id, p));
        }
        while let Some(frame) = u.ifc.transmit() {
            u.dev.transmit(&frame);
        }
    }
    if let Some(n) = news {
        lease_news(n);
    }
    if any {
        st.delivered = inbound.len() as u64;
        let mut s = UPLINK_STATS.lock();
        s.frames += st.frames;
        s.delivered += st.delivered;
        s.refused += st.refused;
        s.unmapped += st.unmapped;
    }
    for (id, p) in inbound {
        let stack = with_table(|t| t.stacks.get(&id).and_then(Weak::upgrade));
        if let Some(stack) = stack {
            let out = stack.receive(p);
            send(id, out);
        }
    }
    any
}
