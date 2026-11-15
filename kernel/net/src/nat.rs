//! Source NAT and published ports at the cell switch's uplink
//! (ADR-0010 §3), sans-I/O.
//!
//! Cells sit in a private subnet behind the uplink's one address. A
//! connection a cell opens to the outside leaves with the uplink's address
//! and a port the table picks, and replies are mapped back (source NAT with
//! connection tracking). A published port (`uplink:8080 -> cell:80`) maps
//! connections the outside opens to a cell, as Docker's default bridge
//! does. Mappings are per protocol and per remote endpoint; an idle one
//! expires, and a TCP one shortly after both FINs or a RST.

use alloc::collections::BTreeMap;
use core::time::Duration;

use crate::Ipv4Addr;
use crate::wire::{PROTO_TCP, PROTO_UDP, fold, pseudo_header, sum};

/// An address and port.
pub type Endpoint = (Ipv4Addr, u16);

/// Ports the table hands out for outbound connections.
pub const PORTS: core::ops::RangeInclusive<u16> = 49152..=65535;
/// How long an idle mapping lives.
pub const IDLE: Duration = Duration::from_secs(600);
/// How long a TCP mapping lives after both FINs or a RST.
pub const CLOSING: Duration = Duration::from_secs(60);

const FIN: u8 = 0x01;
const RST: u8 = 0x04;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mapping {
    inside: Endpoint,
    remote: Endpoint,
    outside_port: u16,
    last: Duration,
    /// FIN seen from the inside / from the outside.
    fin_in: bool,
    fin_out: bool,
    reset: bool,
}

impl Mapping {
    fn expired(&self, now: Duration) -> bool {
        let life = if self.reset || (self.fin_in && self.fin_out) {
            CLOSING
        } else {
            IDLE
        };
        now.saturating_sub(self.last) > life
    }
}

/// Key of a mapping seen from the inside: (protocol, inside, remote).
type InKey = (u8, Endpoint, Endpoint);
/// Key of a mapping seen from the outside: (protocol, outside port, remote).
type OutKey = (u8, u16, Endpoint);

/// The uplink's translation table.
#[derive(Debug)]
pub struct Nat {
    outside: Ipv4Addr,
    /// (protocol, outside port) -> inside endpoint.
    published: BTreeMap<(u8, u16), Endpoint>,
    by_inside: BTreeMap<InKey, OutKey>,
    by_outside: BTreeMap<OutKey, Mapping>,
    next_port: u16,
}

impl Nat {
    /// A table translating to `outside`, the uplink's address.
    pub fn new(outside: Ipv4Addr) -> Nat {
        Nat {
            outside,
            published: BTreeMap::new(),
            by_inside: BTreeMap::new(),
            by_outside: BTreeMap::new(),
            next_port: *PORTS.start(),
        }
    }

    /// The uplink's address.
    pub fn outside(&self) -> Ipv4Addr {
        self.outside
    }

    /// Publishes `port` on the uplink to `inside`. Fails if the port is
    /// already published.
    pub fn publish(&mut self, proto: u8, port: u16, inside: Endpoint) -> bool {
        if self.published.contains_key(&(proto, port)) {
            return false;
        }
        self.published.insert((proto, port), inside);
        true
    }

    /// Withdraws a published port (live connections keep their mappings).
    pub fn unpublish(&mut self, proto: u8, port: u16) {
        self.published.remove(&(proto, port));
    }

    /// The published endpoint for `(proto, port)`.
    pub fn published(&self, proto: u8, port: u16) -> Option<Endpoint> {
        self.published.get(&(proto, port)).copied()
    }

    /// Live mappings.
    pub fn len(&self) -> usize {
        self.by_outside.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_outside.is_empty()
    }

    fn port_free(&self, proto: u8, port: u16, remote: Endpoint) -> bool {
        !self.published.contains_key(&(proto, port))
            && !self.by_outside.contains_key(&(proto, port, remote))
    }

    fn pick_port(&mut self, proto: u8, remote: Endpoint) -> Option<u16> {
        let span = u32::from(*PORTS.end() - *PORTS.start()) + 1;
        for _ in 0..span {
            let p = self.next_port;
            self.next_port = if p >= *PORTS.end() {
                *PORTS.start()
            } else {
                p + 1
            };
            if self.port_free(proto, p, remote) {
                return Some(p);
            }
        }
        None
    }

    fn insert(&mut self, proto: u8, m: Mapping) {
        let ok = (proto, m.outside_port, m.remote);
        self.by_inside.insert((proto, m.inside, m.remote), ok);
        self.by_outside.insert(ok, m);
    }

    /// A packet from a cell (`inside`) to `remote` outside: the source it
    /// leaves with, or `None` if no port is free. `flags` are the TCP
    /// flags (0 for other protocols).
    pub fn outbound(
        &mut self,
        proto: u8,
        inside: Endpoint,
        remote: Endpoint,
        flags: u8,
        now: Duration,
    ) -> Option<Endpoint> {
        let key = match self.by_inside.get(&(proto, inside, remote)).copied() {
            Some(k) if self.by_outside.get(&k).is_some_and(|m| !m.expired(now)) => k,
            stale => {
                if let Some(k) = stale {
                    self.forget(k);
                }
                // A reply from a published server leaves from its port.
                let published = self
                    .published
                    .iter()
                    .find(|&(&(p, _), &e)| p == proto && e == inside)
                    .map(|(&(_, port), _)| port)
                    .filter(|&port| !self.by_outside.contains_key(&(proto, port, remote)));
                let port = match published {
                    Some(p) => p,
                    None => self.pick_port(proto, remote)?,
                };
                let m = Mapping {
                    inside,
                    remote,
                    outside_port: port,
                    last: now,
                    fin_in: false,
                    fin_out: false,
                    reset: false,
                };
                self.insert(proto, m);
                (proto, port, remote)
            }
        };
        let m = self.by_outside.get_mut(&key)?;
        m.last = now;
        m.fin_in |= flags & FIN != 0;
        m.reset |= flags & RST != 0;
        Some((self.outside, m.outside_port))
    }

    /// A packet from `remote` outside to the uplink's `port`: the cell
    /// endpoint it goes to, or `None` (drop it).
    pub fn inbound(
        &mut self,
        proto: u8,
        remote: Endpoint,
        port: u16,
        flags: u8,
        now: Duration,
    ) -> Option<Endpoint> {
        let key = (proto, port, remote);
        if self.by_outside.get(&key).is_some_and(|m| m.expired(now)) {
            self.forget(key);
        }
        if !self.by_outside.contains_key(&key) {
            let inside = *self.published.get(&(proto, port))?;
            // Only a connection request opens a TCP mapping from outside.
            if proto == PROTO_TCP && (flags & 0x02 == 0 || flags & 0x10 != 0) {
                return None;
            }
            let m = Mapping {
                inside,
                remote,
                outside_port: port,
                last: now,
                fin_in: false,
                fin_out: false,
                reset: false,
            };
            self.insert(proto, m);
        }
        let m = self.by_outside.get_mut(&key)?;
        m.last = now;
        m.fin_out |= flags & FIN != 0;
        m.reset |= flags & RST != 0;
        Some(m.inside)
    }

    fn forget(&mut self, key: OutKey) {
        if let Some(m) = self.by_outside.remove(&key) {
            self.by_inside.remove(&(key.0, m.inside, m.remote));
        }
    }

    /// Drops expired mappings.
    pub fn expire(&mut self, now: Duration) {
        let dead: alloc::vec::Vec<OutKey> = self
            .by_outside
            .iter()
            .filter(|(_, m)| m.expired(now))
            .map(|(&k, _)| k)
            .collect();
        for k in dead {
            self.forget(k);
        }
    }
}

/// Rewrites a TCP or UDP header's ports for new endpoints and recomputes
/// its checksum over the new pseudo-header. Returns `false` for a packet
/// too short to hold the header.
pub fn rewrite(proto: u8, seg: &mut [u8], src: Endpoint, dst: Endpoint) -> bool {
    let at = match proto {
        PROTO_TCP if seg.len() >= 20 => 16,
        PROTO_UDP if seg.len() >= 8 => 6,
        _ => return false,
    };
    seg[0..2].copy_from_slice(&src.1.to_be_bytes());
    seg[2..4].copy_from_slice(&dst.1.to_be_bytes());
    seg[at..at + 2].copy_from_slice(&[0, 0]);
    let mut c = fold(sum(pseudo_header(src.0, dst.0, proto, seg.len()), seg));
    if proto == PROTO_UDP && c == 0 {
        c = 0xffff; // 0 means "no checksum" in UDP
    }
    seg[at..at + 2].copy_from_slice(&c.to_be_bytes());
    true
}

/// The TCP flags of a segment (0 if it is too short).
pub fn tcp_flags(seg: &[u8]) -> u8 {
    seg.get(13).copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{self, Segment};

    const UP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const CELL: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
    const CELL2: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 3);
    const FAR: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;

    fn t(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn outbound_connections_share_the_uplink_address() {
        let mut n = Nat::new(UP);
        let a = n.outbound(PROTO_TCP, (CELL, 40000), (FAR, 443), SYN, t(0));
        let b = n.outbound(PROTO_TCP, (CELL2, 40000), (FAR, 443), SYN, t(0));
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.0, UP);
        assert_eq!(b.0, UP);
        assert_ne!(a.1, b.1, "two cells, same remote: distinct ports");
        // The same flow keeps its mapping.
        assert_eq!(
            n.outbound(PROTO_TCP, (CELL, 40000), (FAR, 443), ACK, t(1)),
            Some(a)
        );
        // Replies map back to the right cell.
        assert_eq!(
            n.inbound(PROTO_TCP, (FAR, 443), a.1, ACK, t(1)),
            Some((CELL, 40000))
        );
        assert_eq!(
            n.inbound(PROTO_TCP, (FAR, 443), b.1, ACK, t(1)),
            Some((CELL2, 40000))
        );
        // A different remote endpoint on that port is not let in.
        assert_eq!(n.inbound(PROTO_TCP, (FAR, 444), a.1, ACK, t(1)), None);
        assert_eq!(n.len(), 2);
    }

    #[test]
    fn unsolicited_inbound_is_dropped() {
        let mut n = Nat::new(UP);
        assert_eq!(n.inbound(PROTO_TCP, (FAR, 1234), 80, SYN, t(0)), None);
        assert_eq!(n.inbound(PROTO_UDP, (FAR, 1234), 53, 0, t(0)), None);
        assert!(n.is_empty());
    }

    #[test]
    fn published_ports_forward_and_replies_leave_from_them() {
        let mut n = Nat::new(UP);
        assert!(n.publish(PROTO_TCP, 8080, (CELL, 80)));
        assert!(
            !n.publish(PROTO_TCP, 8080, (CELL2, 80)),
            "already published"
        );
        // Only a SYN opens a mapping.
        assert_eq!(n.inbound(PROTO_TCP, (FAR, 5555), 8080, ACK, t(0)), None);
        assert_eq!(
            n.inbound(PROTO_TCP, (FAR, 5555), 8080, SYN, t(0)),
            Some((CELL, 80))
        );
        assert_eq!(
            n.outbound(PROTO_TCP, (CELL, 80), (FAR, 5555), SYN | ACK, t(0)),
            Some((UP, 8080))
        );
        // A second client gets its own mapping on the same port.
        assert_eq!(
            n.inbound(PROTO_TCP, (FAR, 5556), 8080, SYN, t(0)),
            Some((CELL, 80))
        );
        assert_eq!(
            n.outbound(PROTO_TCP, (CELL, 80), (FAR, 5556), SYN | ACK, t(0)),
            Some((UP, 8080))
        );
        // Outbound connections never take a published port.
        for i in 0..100 {
            let o = n.outbound(PROTO_TCP, (CELL2, 30000 + i), (FAR, 80), SYN, t(0));
            assert_ne!(o.map(|e| e.1), Some(8080));
        }
        n.unpublish(PROTO_TCP, 8080);
        assert_eq!(n.inbound(PROTO_TCP, (FAR, 5557), 8080, SYN, t(0)), None);
        // Live connections survive the unpublish.
        assert_eq!(
            n.inbound(PROTO_TCP, (FAR, 5555), 8080, ACK, t(1)),
            Some((CELL, 80))
        );
    }

    #[test]
    fn mappings_expire_when_idle_or_closed() {
        let mut n = Nat::new(UP);
        let a = n
            .outbound(PROTO_TCP, (CELL, 1), (FAR, 80), SYN, t(0))
            .unwrap();
        let b = n
            .outbound(PROTO_TCP, (CELL, 2), (FAR, 80), SYN, t(0))
            .unwrap();
        // b closes both ways.
        n.outbound(PROTO_TCP, (CELL, 2), (FAR, 80), FIN | ACK, t(10));
        n.inbound(PROTO_TCP, (FAR, 80), b.1, FIN | ACK, t(10));
        n.expire(t(10) + CLOSING + t(1));
        assert_eq!(n.len(), 1, "the closed mapping went first");
        assert_eq!(n.inbound(PROTO_TCP, (FAR, 80), b.1, ACK, t(80)), None);
        n.expire(t(0) + IDLE + t(1));
        assert!(n.is_empty());
        assert_eq!(n.inbound(PROTO_TCP, (FAR, 80), a.1, ACK, IDLE + t(2)), None);
    }

    #[test]
    fn port_exhaustion_fails_cleanly() {
        let mut n = Nat::new(UP);
        let span = *PORTS.end() - *PORTS.start() + 1;
        for i in 0..span {
            assert!(
                n.outbound(PROTO_UDP, (CELL2, i + 1), (FAR, 53), 0, t(0))
                    .is_some()
            );
        }
        assert_eq!(n.outbound(PROTO_UDP, (CELL, 1), (FAR, 53), 0, t(0)), None);
        // Another remote endpoint still has every port.
        assert!(
            n.outbound(PROTO_UDP, (CELL, 1), (FAR, 54), 0, t(0))
                .is_some()
        );
    }

    #[test]
    fn rewrite_keeps_the_checksum_valid() {
        let seg = tcp::segment((CELL, 40000), (FAR, 443), 7, 0, tcp::SYN, 1000, None, b"hi");
        let mut s = seg.clone();
        assert!(rewrite(PROTO_TCP, &mut s, (UP, 50000), (FAR, 443)));
        let p = Segment::parse(&s, UP, FAR).expect("valid after rewrite");
        assert_eq!((p.src_port, p.dst_port), (50000, 443));
        assert_eq!(p.payload, b"hi");
        assert!(
            Segment::parse(&s, CELL, FAR).is_none(),
            "old pseudo-header fails"
        );
        assert_eq!(tcp_flags(&s), tcp::SYN);
        let mut u = crate::wire::udp(CELL, 5353, FAR, 53, b"q");
        assert!(rewrite(PROTO_UDP, &mut u, (UP, 50001), (FAR, 53)));
        assert!(crate::wire::Udp::parse(&u, UP, FAR).is_some());
        assert!(!rewrite(PROTO_TCP, &mut [0u8; 10], (UP, 1), (FAR, 2)));
    }
}
