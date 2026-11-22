//! One IPv4 interface on Ethernet: address resolution (ARP), ICMP echo,
//! and IPv4 in and out. Sans-I/O: [`Interface::receive`] takes a frame,
//! [`Interface::send`] queues an IP packet, [`Interface::transmit`] yields
//! frames to put on the wire, and [`Interface::poll`] runs the timers.
//!
//! An outgoing packet whose next hop has no ARP entry waits while the
//! interface asks (once a second) and is dropped after [`RESOLVE_TIMEOUT`].
//! Entries are learned only from ARP traffic aimed at this interface and
//! expire after [`ARP_TTL`].

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::time::Duration;

use crate::wire::{self, Arp, Echo, Ethernet, Ipv4};
use crate::{Ipv4Addr, Mac};

/// How long a learned address stays valid.
pub const ARP_TTL: Duration = Duration::from_secs(60);
/// How often an unresolved next hop is asked again.
pub const ARP_RETRY: Duration = Duration::from_secs(1);
/// How long a packet waits for its next hop before it is dropped.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
/// Most packets held waiting for resolution (beyond, new ones are dropped).
const MAX_WAITING: usize = 64;
/// Most frames queued for transmission.
const MAX_OUT: usize = 1024;

/// An IP packet for this host, handed up to the transport layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub payload: Vec<u8>,
}

/// An IPv4 interface.
#[derive(Debug)]
pub struct Interface {
    pub mac: Mac,
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    arp: BTreeMap<Ipv4Addr, (Mac, Duration)>,
    /// Packets waiting for their next hop: (next hop, IP packet, queued at).
    waiting: Vec<(Ipv4Addr, Vec<u8>, Duration)>,
    /// When each unresolved next hop was last asked.
    asked: BTreeMap<Ipv4Addr, Duration>,
    out: VecDeque<Vec<u8>>,
    next_id: u16,
}

impl Interface {
    pub fn new(mac: Mac, addr: Ipv4Addr, prefix: u8, gateway: Option<Ipv4Addr>) -> Interface {
        Interface {
            mac,
            addr,
            prefix: prefix.min(32),
            gateway,
            arp: BTreeMap::new(),
            waiting: Vec::new(),
            asked: BTreeMap::new(),
            out: VecDeque::new(),
            next_id: 1,
        }
    }

    /// Moves to another address and network, forgetting the old one's
    /// neighbors and what waited for them.
    pub fn readdress(&mut self, addr: Ipv4Addr, prefix: u8, gateway: Option<Ipv4Addr>) {
        self.addr = addr;
        self.prefix = prefix.min(32);
        self.gateway = gateway;
        self.arp.clear();
        self.asked.clear();
        self.waiting.clear();
    }

    fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix))
        }
    }

    /// Whether `ip` is on this interface's subnet.
    pub fn on_link(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.addr) & self.mask()
    }

    fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !self.mask())
    }

    /// Whether a packet to `dst` is for this host.
    fn for_us(&self, dst: Ipv4Addr) -> bool {
        dst == self.addr || dst == Ipv4Addr::BROADCAST || dst == self.broadcast()
    }

    fn push_frame(&mut self, f: Vec<u8>) {
        if self.out.len() < MAX_OUT {
            self.out.push_back(f);
        }
    }

    fn arp_send(&mut self, op: u16, target_mac: Mac, target_ip: Ipv4Addr, dst: Mac) {
        let a = Arp {
            op,
            sender_mac: self.mac,
            sender_ip: self.addr,
            target_mac,
            target_ip,
        };
        let f = wire::ethernet(dst, self.mac, wire::ETHERTYPE_ARP, &a.emit());
        self.push_frame(f);
    }

    /// The next frame to put on the wire.
    pub fn transmit(&mut self) -> Option<Vec<u8>> {
        self.out.pop_front()
    }

    /// The MAC for `ip`, if known and fresh.
    pub fn neighbor(&self, ip: Ipv4Addr, now: Duration) -> Option<Mac> {
        self.arp
            .get(&ip)
            .filter(|&&(_, until)| now < until)
            .map(|&(m, _)| m)
    }

    fn learn(&mut self, ip: Ipv4Addr, m: Mac, now: Duration) {
        if ip.is_unspecified() || m == Mac::BROADCAST || m == Mac::ZERO {
            return;
        }
        self.arp.insert(ip, (m, now + ARP_TTL));
        self.asked.remove(&ip);
        // Release what was waiting for it.
        let (ready, rest): (Vec<_>, Vec<_>) = core::mem::take(&mut self.waiting)
            .into_iter()
            .partition(|w| w.0 == ip);
        self.waiting = rest;
        for (_, pkt, _) in ready {
            let f = wire::ethernet(m, self.mac, wire::ETHERTYPE_IPV4, &pkt);
            self.push_frame(f);
        }
    }

    /// Sends a `protocol` payload to `dst`. Returns false if it was dropped
    /// (no route, or too much already waiting for resolution).
    pub fn send(&mut self, now: Duration, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> bool {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let pkt = wire::ipv4(self.addr, dst, protocol, id, payload);
        if dst == Ipv4Addr::BROADCAST || dst == self.broadcast() {
            let f = wire::ethernet(Mac::BROADCAST, self.mac, wire::ETHERTYPE_IPV4, &pkt);
            self.push_frame(f);
            return true;
        }
        let hop = if self.on_link(dst) {
            dst
        } else {
            match self.gateway {
                Some(g) => g,
                None => return false,
            }
        };
        if let Some(m) = self.neighbor(hop, now) {
            let f = wire::ethernet(m, self.mac, wire::ETHERTYPE_IPV4, &pkt);
            self.push_frame(f);
            return true;
        }
        if self.waiting.len() >= MAX_WAITING {
            return false;
        }
        self.waiting.push((hop, pkt, now));
        if let alloc::collections::btree_map::Entry::Vacant(e) = self.asked.entry(hop) {
            e.insert(now);
            self.arp_send(wire::ARP_REQUEST, Mac::ZERO, hop, Mac::BROADCAST);
        }
        true
    }

    /// Takes a received frame. Handles ARP and ICMP echo itself; returns an
    /// IP packet for this host that the transport layer should see.
    pub fn receive(&mut self, now: Duration, frame: &[u8]) -> Option<Packet> {
        let e = Ethernet::parse(frame)?;
        if e.dst != self.mac && e.dst != Mac::BROADCAST {
            return None;
        }
        match e.ethertype {
            wire::ETHERTYPE_ARP => {
                let a = Arp::parse(e.payload)?;
                if a.target_ip != self.addr {
                    return None; // not about us: learn nothing from it
                }
                self.learn(a.sender_ip, a.sender_mac, now);
                if a.op == wire::ARP_REQUEST {
                    self.arp_send(wire::ARP_REPLY, a.sender_mac, a.sender_ip, a.sender_mac);
                }
                None
            }
            wire::ETHERTYPE_IPV4 => {
                let ip = Ipv4::parse(e.payload)?;
                if !self.for_us(ip.dst) || ip.fragment {
                    return None;
                }
                if ip.protocol == wire::PROTO_ICMP
                    && let Some(echo) = Echo::parse(ip.payload)
                    && echo.kind == wire::ICMP_ECHO_REQUEST
                    && ip.dst == self.addr
                {
                    let reply = Echo {
                        kind: wire::ICMP_ECHO_REPLY,
                        ..echo
                    }
                    .emit();
                    self.send(now, ip.src, wire::PROTO_ICMP, &reply);
                    return None;
                }
                Some(Packet {
                    src: ip.src,
                    dst: ip.dst,
                    protocol: ip.protocol,
                    payload: ip.payload.into(),
                })
            }
            _ => None,
        }
    }

    /// Runs the timers: re-asks unresolved next hops, drops packets that
    /// waited too long, forgets expired entries.
    pub fn poll(&mut self, now: Duration) {
        self.waiting
            .retain(|&(_, _, since)| now.saturating_sub(since) < RESOLVE_TIMEOUT);
        let still: Vec<Ipv4Addr> = self.waiting.iter().map(|w| w.0).collect();
        self.asked.retain(|ip, _| still.contains(ip));
        let due: Vec<Ipv4Addr> = self
            .asked
            .iter()
            .filter(|&(_, &t)| now.saturating_sub(t) >= ARP_RETRY)
            .map(|(&ip, _)| ip)
            .collect();
        for ip in due {
            self.asked.insert(ip, now);
            self.arp_send(wire::ARP_REQUEST, Mac::ZERO, ip, Mac::BROADCAST);
        }
        self.arp.retain(|_, &mut (_, until)| now < until);
    }

    /// When [`Interface::poll`] next has work (None: nothing pending).
    pub fn next_timer(&self) -> Option<Duration> {
        let retry = self.asked.values().map(|&t| t + ARP_RETRY).min();
        let drop = self
            .waiting
            .iter()
            .map(|&(_, _, t)| t + RESOLVE_TIMEOUT)
            .min();
        match (retry, drop) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
    const B_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 3);
    const A_MAC: Mac = Mac([2, 0, 0, 0, 0, 2]);
    const B_MAC: Mac = Mac([2, 0, 0, 0, 0, 3]);

    fn pair() -> (Interface, Interface) {
        (
            Interface::new(A_MAC, A_IP, 24, None),
            Interface::new(B_MAC, B_IP, 24, None),
        )
    }

    /// Moves every queued frame from `from` into `to`, collecting what `to`
    /// hands up.
    fn deliver(from: &mut Interface, to: &mut Interface, now: Duration) -> Vec<Packet> {
        let mut up = Vec::new();
        while let Some(f) = from.transmit() {
            if let Some(p) = to.receive(now, &f) {
                up.push(p);
            }
        }
        up
    }

    #[test]
    fn ping_resolves_then_replies() {
        let (mut a, mut b) = pair();
        let t = Duration::from_secs(1);
        let req = Echo {
            kind: wire::ICMP_ECHO_REQUEST,
            ident: 9,
            seq: 1,
            data: b"hi",
        }
        .emit();
        assert!(a.send(t, B_IP, wire::PROTO_ICMP, &req));
        // A asks for B (the echo request waits); B answers and learns A.
        assert!(deliver(&mut a, &mut b, t).is_empty());
        assert_eq!(b.neighbor(A_IP, t), Some(A_MAC));
        assert!(deliver(&mut b, &mut a, t).is_empty());
        assert_eq!(a.neighbor(B_IP, t), Some(B_MAC));
        // The released echo request reaches B, which replies directly.
        assert!(deliver(&mut a, &mut b, t).is_empty());
        let up = deliver(&mut b, &mut a, t);
        assert_eq!(up.len(), 1);
        let echo = Echo::parse(&up[0].payload).unwrap();
        assert_eq!(
            (echo.kind, echo.ident, echo.data),
            (wire::ICMP_ECHO_REPLY, 9, &b"hi"[..])
        );
    }

    #[test]
    fn unresolved_packets_are_retried_then_dropped() {
        let (mut a, _) = pair();
        let t0 = Duration::from_secs(10);
        assert!(a.send(t0, B_IP, wire::PROTO_UDP, b"x"));
        assert!(a.transmit().is_some()); // the first ARP request
        a.poll(t0 + Duration::from_millis(500));
        assert!(a.transmit().is_none());
        a.poll(t0 + ARP_RETRY);
        assert!(a.transmit().is_some()); // asked again
        a.poll(t0 + RESOLVE_TIMEOUT);
        assert!(a.next_timer().is_none()); // the packet was dropped
    }

    #[test]
    fn learns_only_from_arp_aimed_at_it_and_routes_via_the_gateway() {
        let mut a = Interface::new(A_MAC, A_IP, 24, Some(Ipv4Addr::new(10, 88, 0, 1)));
        let t = Duration::from_secs(1);
        // An ARP request between two other hosts teaches A nothing.
        let other = Arp {
            op: wire::ARP_REQUEST,
            sender_mac: B_MAC,
            sender_ip: B_IP,
            target_mac: Mac::ZERO,
            target_ip: Ipv4Addr::new(10, 88, 0, 9),
        };
        let f = wire::ethernet(Mac::BROADCAST, B_MAC, wire::ETHERTYPE_ARP, &other.emit());
        assert!(a.receive(t, &f).is_none());
        assert_eq!(a.neighbor(B_IP, t), None);
        assert!(a.transmit().is_none());
        // Off-link traffic resolves the gateway, not the destination.
        assert!(a.send(t, Ipv4Addr::new(8, 8, 8, 8), wire::PROTO_UDP, b"x"));
        let req = a.transmit().unwrap();
        let e = Ethernet::parse(&req).unwrap();
        assert_eq!(
            Arp::parse(e.payload).unwrap().target_ip,
            Ipv4Addr::new(10, 88, 0, 1)
        );
        // Without a gateway, off-link traffic is refused.
        let (mut lone, _) = pair();
        assert!(!lone.send(t, Ipv4Addr::new(8, 8, 8, 8), wire::PROTO_UDP, b"x"));
    }

    #[test]
    fn frames_for_others_and_fragments_are_ignored() {
        let (mut a, _) = pair();
        let t = Duration::from_secs(1);
        let pkt = wire::ipv4(
            B_IP,
            A_IP,
            wire::PROTO_UDP,
            1,
            &wire::udp(B_IP, 1, A_IP, 2, b"x"),
        );
        let to_other = wire::ethernet(Mac([2, 9, 9, 9, 9, 9]), B_MAC, wire::ETHERTYPE_IPV4, &pkt);
        assert!(a.receive(t, &to_other).is_none());
        let to_a = wire::ethernet(A_MAC, B_MAC, wire::ETHERTYPE_IPV4, &pkt);
        assert_eq!(a.receive(t, &to_a).unwrap().protocol, wire::PROTO_UDP);
        let mut frag = pkt.clone();
        frag[6] |= 0x20; // more fragments
        frag[10..12].copy_from_slice(&[0, 0]);
        let c = wire::checksum(&frag[..20]);
        frag[10..12].copy_from_slice(&c.to_be_bytes());
        let f = wire::ethernet(A_MAC, B_MAC, wire::ETHERTYPE_IPV4, &frag);
        assert!(a.receive(t, &f).is_none());
    }
}
