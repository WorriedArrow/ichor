//! The cell switch's forwarding decisions (ADR-0010 §3), sans-I/O.
//!
//! Every port is assigned an IPv4 address in the cells' subnet by the
//! switch itself; nothing is learned from traffic. A packet from a port is
//! checked against that assignment (anti-spoofing) and the port's token
//! buckets (packets and bytes per second), then goes to the port that owns
//! the destination address, to the uplink for anything outside the subnet,
//! or nowhere. Ports carry IP packets, not Ethernet frames: both ends of a
//! port are Ichor stacks, so there is no ARP on them at all (ADR-0010
//! amendment), and a cell never sees a packet not addressed to it.

use alloc::collections::BTreeMap;
use core::time::Duration;

use crate::Ipv4Addr;

/// Whether `dst:port` is the machine's own, not its cells': what a cloud
/// tells and gives a machine at link-local addresses (its credentials among
/// it, to whoever asks from there) and, on Azure, at 168.63.129.16. Names
/// are asked for there too, on some clouds: those any cell may ask for.
pub fn is_machines(dst: Ipv4Addr, port: u16) -> bool {
    const AZURE: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);
    const DNS: u16 = 53;
    (dst.is_link_local() || dst == AZURE) && port != DNS
}

/// A port's identity (the kernel uses the cell id).
pub type PortId = u64;

/// Where a packet goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// To the port that owns the destination.
    Deliver(PortId),
    /// Out of the uplink (through NAT).
    Uplink,
    /// Dropped.
    Drop(Reason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The sender is not attached.
    NoPort,
    /// The source address is not the port's assigned one.
    Spoofed,
    /// Over the port's rate limit.
    RateLimited,
    /// An unassigned address in the cells' subnet, or the switch itself.
    NoRoute,
}

/// A token bucket: `rate` tokens a second, at most `burst` saved up.
/// A rate of 0 means unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    rate: u64,
    burst: u64,
    /// Tokens, in millionths.
    micro: u64,
    last: Duration,
}

impl TokenBucket {
    pub const UNLIMITED: TokenBucket = TokenBucket {
        rate: 0,
        burst: 0,
        micro: 0,
        last: Duration::ZERO,
    };

    /// A full bucket.
    pub fn new(rate: u64, burst: u64, now: Duration) -> TokenBucket {
        TokenBucket {
            rate,
            burst,
            micro: burst.saturating_mul(1_000_000),
            last: now,
        }
    }

    /// Takes `cost` tokens if there are enough.
    pub fn take(&mut self, now: Duration, cost: u64) -> bool {
        if self.rate == 0 {
            return true;
        }
        let dt = now.saturating_sub(self.last);
        self.last = self.last.max(now);
        let earned = (dt.as_micros() as u64).saturating_mul(self.rate);
        self.micro = self
            .micro
            .saturating_add(earned)
            .min(self.burst.saturating_mul(1_000_000));
        let need = cost.saturating_mul(1_000_000);
        if self.micro >= need {
            self.micro -= need;
            true
        } else {
            false
        }
    }
}

/// Per-port counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    pub dropped: u64,
}

#[derive(Clone, Copy, Debug)]
struct Port {
    addr: Ipv4Addr,
    packets: TokenBucket,
    bytes: TokenBucket,
    stats: Stats,
}

/// The switch's table.
#[derive(Debug)]
pub struct Switch {
    net: u32,
    prefix: u8,
    ports: BTreeMap<PortId, Port>,
    by_addr: BTreeMap<Ipv4Addr, PortId>,
    next_host: u32,
}

impl Switch {
    /// A switch for the subnet `net/prefix`. The first host address is the
    /// switch's own (the cells' gateway); ports get the ones after it.
    pub fn new(net: Ipv4Addr, prefix: u8) -> Switch {
        let prefix = prefix.clamp(8, 30);
        let mask = u32::MAX << (32 - prefix);
        Switch {
            net: u32::from(net) & mask,
            prefix,
            ports: BTreeMap::new(),
            by_addr: BTreeMap::new(),
            next_host: 2,
        }
    }

    /// The switch's own address: the gateway cells route through.
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.net | 1)
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is in the cells' subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::MAX << (32 - self.prefix);
        u32::from(ip) & mask == self.net
    }

    fn hosts(&self) -> u32 {
        (1u32 << (32 - self.prefix)) - 2 // without network and broadcast
    }

    /// Attaches a port and assigns it the next free address; `None` when
    /// the subnet is full or the port is already attached.
    pub fn attach(&mut self, id: PortId) -> Option<Ipv4Addr> {
        if self.ports.contains_key(&id) {
            return None;
        }
        let hosts = self.hosts();
        for _ in 0..hosts {
            let h = self.next_host;
            self.next_host = if h >= hosts { 2 } else { h + 1 };
            let addr = Ipv4Addr::from(self.net | h);
            if !self.by_addr.contains_key(&addr) {
                self.ports.insert(
                    id,
                    Port {
                        addr,
                        packets: TokenBucket::UNLIMITED,
                        bytes: TokenBucket::UNLIMITED,
                        stats: Stats::default(),
                    },
                );
                self.by_addr.insert(addr, id);
                return Some(addr);
            }
        }
        None
    }

    /// Detaches a port; its address becomes free.
    pub fn detach(&mut self, id: PortId) {
        if let Some(p) = self.ports.remove(&id) {
            self.by_addr.remove(&p.addr);
        }
    }

    /// The address assigned to a port.
    pub fn addr(&self, id: PortId) -> Option<Ipv4Addr> {
        self.ports.get(&id).map(|p| p.addr)
    }

    /// The port owning `addr`.
    pub fn port_of(&self, addr: Ipv4Addr) -> Option<PortId> {
        self.by_addr.get(&addr).copied()
    }

    /// Sets a port's limits (0: unlimited); the buckets start full.
    pub fn set_limits(&mut self, id: PortId, pps: u64, bps: u64, now: Duration) -> bool {
        let Some(p) = self.ports.get_mut(&id) else {
            return false;
        };
        // A second's worth of burst, at least one full-size packet.
        p.packets = TokenBucket::new(pps, pps.max(1), now);
        p.bytes = TokenBucket::new(bps, bps.max(65536), now);
        true
    }

    pub fn stats(&self, id: PortId) -> Option<Stats> {
        self.ports.get(&id).map(|p| p.stats)
    }

    /// Decides where a `len`-byte packet from port `from`, `src -> dst`,
    /// goes, and charges it to the sender's limits.
    pub fn route(
        &mut self,
        from: PortId,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        len: usize,
        now: Duration,
    ) -> Verdict {
        let contains = self.contains(dst);
        let gateway = self.gateway();
        let target = self.by_addr.get(&dst).copied();
        let Some(p) = self.ports.get_mut(&from) else {
            return Verdict::Drop(Reason::NoPort);
        };
        let verdict = if src != p.addr {
            Verdict::Drop(Reason::Spoofed)
        } else if !p.packets.take(now, 1) || !p.bytes.take(now, len as u64) {
            Verdict::Drop(Reason::RateLimited)
        } else if let Some(t) = target {
            Verdict::Deliver(t)
        } else if contains || dst == gateway || dst.is_broadcast() || dst.is_multicast() {
            Verdict::Drop(Reason::NoRoute)
        } else {
            Verdict::Uplink
        };
        match verdict {
            Verdict::Drop(_) => p.stats.dropped += 1,
            _ => p.stats.sent += 1,
        }
        if let Verdict::Deliver(t) = verdict
            && let Some(r) = self.ports.get_mut(&t)
        {
            r.stats.received += 1;
        }
        verdict
    }

    /// Counts a packet the uplink delivered to `id`.
    pub fn received_from_uplink(&mut self, id: PortId) {
        if let Some(p) = self.ports.get_mut(&id) {
            p.stats.received += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 0);
    const FAR: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

    fn t(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    #[test]
    fn ports_get_distinct_assigned_addresses() {
        let mut s = Switch::new(NET, 16);
        assert_eq!(s.gateway(), Ipv4Addr::new(10, 88, 0, 1));
        let a = s.attach(1).unwrap();
        let b = s.attach(2).unwrap();
        assert_eq!(a, Ipv4Addr::new(10, 88, 0, 2));
        assert_eq!(b, Ipv4Addr::new(10, 88, 0, 3));
        assert_eq!(s.attach(1), None, "already attached");
        assert_eq!(s.port_of(b), Some(2));
        s.detach(1);
        assert_eq!(s.port_of(a), None);
        assert_eq!(s.addr(1), None);
    }

    #[test]
    fn the_machines_own_addresses_are_not_its_cells() {
        let metadata = Ipv4Addr::new(169, 254, 169, 254);
        let azure = Ipv4Addr::new(168, 63, 129, 16);
        for (dst, port) in [(metadata, 80), (metadata, 443), (azure, 80), (azure, 32526)] {
            assert!(is_machines(dst, port), "{dst}:{port}");
        }
        // Names, and everyone else.
        assert!(!is_machines(metadata, 53) && !is_machines(azure, 53));
        assert!(!is_machines(Ipv4Addr::new(169, 253, 0, 1), 80));
        assert!(!is_machines(Ipv4Addr::new(168, 63, 129, 17), 80));
    }

    #[test]
    fn small_subnet_fills_and_reuses_freed_addresses() {
        let mut s = Switch::new(Ipv4Addr::new(192, 168, 7, 0), 29); // 6 hosts
        let got: alloc::vec::Vec<_> = (0..5).map(|i| s.attach(i)).collect();
        assert!(got.iter().all(Option::is_some));
        assert_eq!(s.attach(9), None, "full: 5 ports plus the gateway");
        let freed = s.addr(2).unwrap();
        s.detach(2);
        assert_eq!(s.attach(9), Some(freed));
    }

    #[test]
    fn forwarding_by_assignment() {
        let mut s = Switch::new(NET, 16);
        let a = s.attach(1).unwrap();
        let b = s.attach(2).unwrap();
        assert_eq!(s.route(1, a, b, 60, t(0)), Verdict::Deliver(2));
        assert_eq!(s.route(2, b, a, 60, t(0)), Verdict::Deliver(1));
        assert_eq!(s.route(1, a, FAR, 60, t(0)), Verdict::Uplink);
        // Unassigned subnet addresses, the switch itself, broadcast: nowhere.
        let unassigned = Ipv4Addr::new(10, 88, 3, 9);
        assert_eq!(
            s.route(1, a, unassigned, 60, t(0)),
            Verdict::Drop(Reason::NoRoute)
        );
        assert_eq!(
            s.route(1, a, s.gateway(), 60, t(0)),
            Verdict::Drop(Reason::NoRoute)
        );
        let bcast = Ipv4Addr::BROADCAST;
        assert_eq!(
            s.route(1, a, bcast, 60, t(0)),
            Verdict::Drop(Reason::NoRoute)
        );
        assert_eq!(s.route(7, a, b, 60, t(0)), Verdict::Drop(Reason::NoPort));
        let st = s.stats(2).unwrap();
        assert_eq!((st.sent, st.received), (1, 1));
    }

    #[test]
    fn spoofed_sources_are_dropped() {
        let mut s = Switch::new(NET, 16);
        let a = s.attach(1).unwrap();
        let b = s.attach(2).unwrap();
        // Port 1 claims port 2's address, or an outside one.
        assert_eq!(s.route(1, b, a, 60, t(0)), Verdict::Drop(Reason::Spoofed));
        assert_eq!(s.route(1, FAR, b, 60, t(0)), Verdict::Drop(Reason::Spoofed));
        assert_eq!(s.stats(1).unwrap().dropped, 2);
        assert_eq!(s.stats(2).unwrap().received, 0);
    }

    #[test]
    fn rate_limits_per_port() {
        let mut s = Switch::new(NET, 16);
        let a = s.attach(1).unwrap();
        let b = s.attach(2).unwrap();
        assert!(s.set_limits(1, 10, 0, t(0)));
        let passed = (0..20)
            .filter(|_| s.route(1, a, b, 60, t(0)) == Verdict::Deliver(2))
            .count();
        assert_eq!(passed, 10, "a second's burst");
        assert_eq!(
            s.route(1, a, b, 60, t(0)),
            Verdict::Drop(Reason::RateLimited)
        );
        // 100 ms later one more packet's worth has accrued.
        assert_eq!(s.route(1, a, b, 60, t(100)), Verdict::Deliver(2));
        assert_eq!(
            s.route(1, a, b, 60, t(100)),
            Verdict::Drop(Reason::RateLimited)
        );
        // Port 2 is unaffected.
        assert!((0..100).all(|_| s.route(2, b, a, 60, t(100)) == Verdict::Deliver(1)));
    }

    #[test]
    fn byte_limits() {
        let mut b = TokenBucket::new(1000, 1500, t(0));
        assert!(b.take(t(0), 1500));
        assert!(!b.take(t(0), 1));
        assert!(!b.take(t(999), 1000));
        assert!(b.take(t(1000), 1000));
        let mut u = TokenBucket::UNLIMITED;
        assert!((0..1000).all(|_| u.take(t(0), 1 << 30)));
    }
}
