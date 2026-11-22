//! A DHCP client (RFC 2131), sans-I/O: how the uplink gets its address,
//! netmask, router and DNS servers on a network that hands them out (a
//! cloud VPC, QEMU's user networking, most LANs).
//!
//! The client speaks in whole Ethernet frames, because until it is bound
//! the interface has no address: it broadcasts from 0.0.0.0:68 to
//! 255.255.255.255:67, asks for broadcast replies (the BROADCAST flag),
//! and takes replies addressed to its MAC or to everyone. [`Client::poll`]
//! gives the frame to send now, if any (DISCOVER, REQUEST, and their
//! retransmissions with exponential backoff, RFC 2131 §4.1);
//! [`Client::receive`] takes any frame and returns the lease once an ACK
//! binds it. A bound client asks again at half the lease time (from its
//! address, broadcast as a rebinding client does, so any of the network's
//! servers may answer); a NAK, or the lease running out, starts over.
//!
//! Every parser treats its input as hostile: a bad frame or message is
//! ignored, never a panic.

use alloc::vec::Vec;
use core::time::Duration;

use crate::wire::{self, ETHERTYPE_IPV4, PROTO_UDP};
use crate::{Ipv4Addr, Mac};

const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// Fixed part of a BOOTP/DHCP message, before the magic cookie.
const FIXED: usize = 236;
const BROADCAST_FLAG: u16 = 0x8000;

const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;

const OPT_PAD: u8 = 0;
const OPT_SUBNET: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_MTU: u8 = 26;
const OPT_REQUESTED: u8 = 50;
const OPT_LEASE: u8 = 51;
const OPT_TYPE: u8 = 53;
const OPT_SERVER: u8 = 54;
const OPT_PARAMS: u8 = 55;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

/// First retransmission delay; doubles up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(64);

/// What a DHCP server gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub server: Ipv4Addr,
    /// How long the address is ours (`None`: infinite).
    pub time: Option<Duration>,
    pub mtu: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    /// Looking for an offer.
    Selecting,
    /// Asking the server that offered `addr` for it.
    Requesting { addr: Ipv4Addr, server: Ipv4Addr },
    /// Bound since `at`.
    Bound { lease: Lease, at: Duration },
    /// Bound, asking again before the lease runs out.
    Renewing { lease: Lease, at: Duration },
}

/// A DHCP client for one interface.
#[derive(Debug)]
pub struct Client {
    mac: Mac,
    xid: u32,
    state: State,
    /// When the last message went out, and the wait before the next.
    sent: Option<(Duration, Duration)>,
    /// The longest a lease is taken to last ([`Client::cap_lease`]).
    cap: Option<Duration>,
}

impl Client {
    /// A client for the interface with `mac`; `xid` is a random
    /// transaction id.
    pub fn new(mac: Mac, xid: u32) -> Client {
        Client {
            mac,
            xid,
            state: State::Selecting,
            sent: None,
            cap: None,
        }
    }

    /// Takes leases to last at most `t`, whatever the server says (so it
    /// is renewed sooner; tests).
    pub fn cap_lease(&mut self, t: Duration) {
        self.cap = Some(t);
    }

    /// Whether an exchange with a server is under way (a reply would mean
    /// something): always, but for a bound client not yet due to renew.
    pub fn exchanging(&self) -> bool {
        !matches!(self.state, State::Bound { .. })
    }

    /// The current lease, if bound.
    pub fn lease(&self) -> Option<&Lease> {
        match &self.state {
            State::Bound { lease, .. } | State::Renewing { lease, .. } => Some(lease),
            _ => None,
        }
    }

    /// The frame to send now, if any: the next message of the exchange,
    /// or a retransmission once its wait has passed.
    pub fn poll(&mut self, now: Duration) -> Option<Vec<u8>> {
        if let State::Bound { lease, at } = &self.state {
            let half = lease.time?.checked_div(2)?;
            if now.saturating_sub(*at) < half {
                return None;
            }
            self.state = State::Renewing {
                lease: lease.clone(),
                at: *at,
            };
            self.sent = None;
        }
        if let State::Renewing { lease, at } = &self.state
            && lease.time.is_some_and(|t| now.saturating_sub(*at) >= t)
        {
            // The lease ran out unrenewed: start over.
            self.state = State::Selecting;
            self.sent = None;
        }
        let wait = match self.sent {
            None => FIRST_BACKOFF,
            Some((at, wait)) if now.saturating_sub(at) >= wait => (wait * 2).min(MAX_BACKOFF),
            Some(_) => return None,
        };
        self.sent = Some((now, wait));
        let from = self.lease().map_or(Ipv4Addr::UNSPECIFIED, |l| l.addr);
        let msg = match &self.state {
            State::Selecting => self.message(DISCOVER, None, None, None),
            State::Requesting { addr, server } => {
                self.message(REQUEST, Some(*addr), Some(*server), None)
            }
            State::Renewing { lease, .. } => self.message(REQUEST, None, None, Some(lease.addr)),
            State::Bound { .. } => return None,
        };
        Some(frame(self.mac, from, &msg))
    }

    /// Takes a received frame; returns the lease when an ACK binds (or
    /// renews) one. Anything that is not a reply to this client is ignored.
    pub fn receive(&mut self, now: Duration, frame: &[u8]) -> Option<Lease> {
        let reply = parse_reply(frame, self.mac, self.xid)?;
        match (&self.state, reply.kind) {
            (State::Selecting, OFFER) => {
                self.state = State::Requesting {
                    addr: reply.yiaddr,
                    server: reply.server?,
                };
                self.sent = None; // the REQUEST goes out on the next poll
                None
            }
            (State::Requesting { .. } | State::Renewing { .. }, ACK) => {
                let mut lease = reply.lease()?;
                if let Some(cap) = self.cap {
                    lease.time = Some(lease.time.map_or(cap, |t| t.min(cap)));
                }
                self.state = State::Bound {
                    lease: lease.clone(),
                    at: now,
                };
                self.sent = None;
                Some(lease)
            }
            (State::Requesting { .. } | State::Renewing { .. }, NAK) => {
                self.state = State::Selecting;
                self.sent = None;
                None
            }
            _ => None,
        }
    }

    /// A client message of `kind`: `requested`/`server` while requesting
    /// an offer, `ciaddr` while renewing.
    fn message(
        &self,
        kind: u8,
        requested: Option<Ipv4Addr>,
        server: Option<Ipv4Addr>,
        ciaddr: Option<Ipv4Addr>,
    ) -> Vec<u8> {
        let mut m = alloc::vec![0u8; FIXED];
        m[0] = 1; // BOOTREQUEST
        m[1] = 1; // Ethernet
        m[2] = 6;
        m[4..8].copy_from_slice(&self.xid.to_be_bytes());
        m[10..12].copy_from_slice(&BROADCAST_FLAG.to_be_bytes());
        if let Some(c) = ciaddr {
            m[12..16].copy_from_slice(&c.octets());
        }
        m[28..34].copy_from_slice(&self.mac.0);
        m.extend_from_slice(&MAGIC);
        m.extend_from_slice(&[OPT_TYPE, 1, kind]);
        m.extend_from_slice(&[OPT_CLIENT_ID, 7, 1]);
        m.extend_from_slice(&self.mac.0);
        if let Some(a) = requested {
            m.extend_from_slice(&[OPT_REQUESTED, 4]);
            m.extend_from_slice(&a.octets());
        }
        if let Some(s) = server {
            m.extend_from_slice(&[OPT_SERVER, 4]);
            m.extend_from_slice(&s.octets());
        }
        m.extend_from_slice(&[
            OPT_PARAMS, 5, OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_LEASE, OPT_MTU,
        ]);
        m.push(OPT_END);
        m
    }
}

/// A client message in a broadcast frame: from `mac` and `from`:68 (no
/// address until bound) to everyone's port 67.
fn frame(mac: Mac, from: Ipv4Addr, msg: &[u8]) -> Vec<u8> {
    let to = Ipv4Addr::BROADCAST;
    let udp = wire::udp(from, CLIENT_PORT, to, SERVER_PORT, msg);
    let ip = wire::ipv4(from, to, PROTO_UDP, 0, &udp);
    wire::ethernet(Mac::BROADCAST, mac, ETHERTYPE_IPV4, &ip)
}

/// A server's reply, as far as the client needs it.
#[derive(Debug)]
struct Reply {
    kind: u8,
    yiaddr: Ipv4Addr,
    server: Option<Ipv4Addr>,
    subnet: Option<Ipv4Addr>,
    router: Option<Ipv4Addr>,
    dns: Vec<Ipv4Addr>,
    lease: Option<u32>,
    mtu: Option<u16>,
}

impl Reply {
    fn lease(&self) -> Option<Lease> {
        if self.yiaddr.is_unspecified() {
            return None;
        }
        let prefix = match self.subnet {
            Some(m) => {
                let bits = u32::from_be_bytes(m.octets());
                // A netmask is ones then zeros.
                if bits.leading_ones() + bits.trailing_zeros() != 32 {
                    return None;
                }
                bits.leading_ones() as u8
            }
            None => 32,
        };
        Some(Lease {
            addr: self.yiaddr,
            prefix,
            router: self.router,
            dns: self.dns.clone(),
            server: self.server?,
            time: match self.lease {
                Some(u32::MAX) | None => None,
                Some(s) => Some(Duration::from_secs(u64::from(s))),
            },
            mtu: self.mtu,
        })
    }
}

fn ip_at(b: &[u8], at: usize) -> Option<Ipv4Addr> {
    let o = b.get(at..at + 4)?;
    Some(Ipv4Addr::new(o[0], o[1], o[2], o[3]))
}

/// A reply to `mac`'s transaction `xid` in `frame`, if it is one.
fn parse_reply(frame: &[u8], mac: Mac, xid: u32) -> Option<Reply> {
    let eth = wire::Ethernet::parse(frame)?;
    if eth.ethertype != ETHERTYPE_IPV4 || (eth.dst != mac && eth.dst != Mac::BROADCAST) {
        return None;
    }
    let ip = wire::Ipv4::parse(eth.payload)?;
    if ip.protocol != PROTO_UDP || ip.fragment {
        return None;
    }
    let udp = wire::Udp::parse(ip.payload, ip.src, ip.dst)?;
    if udp.src_port != SERVER_PORT || udp.dst_port != CLIENT_PORT {
        return None;
    }
    let m = udp.payload;
    if m.len() < FIXED + MAGIC.len()
        || m[0] != 2 // BOOTREPLY
        || m.get(4..8)? != xid.to_be_bytes()
        || m.get(28..34)? != mac.0
        || m.get(FIXED..FIXED + 4)? != MAGIC
    {
        return None;
    }
    let mut r = Reply {
        kind: 0,
        yiaddr: ip_at(m, 16)?,
        server: None,
        subnet: None,
        router: None,
        dns: Vec::new(),
        lease: None,
        mtu: None,
    };
    let mut opts = &m[FIXED + 4..];
    while let Some((&code, rest)) = opts.split_first() {
        match code {
            OPT_PAD => {
                opts = rest;
                continue;
            }
            OPT_END => break,
            _ => {}
        }
        let (&len, rest) = rest.split_first()?;
        let val = rest.get(..usize::from(len))?;
        opts = &rest[usize::from(len)..];
        match (code, val.len()) {
            (OPT_TYPE, 1) => r.kind = val[0],
            (OPT_SERVER, 4) => r.server = ip_at(val, 0),
            (OPT_SUBNET, 4) => r.subnet = ip_at(val, 0),
            (OPT_ROUTER, n) if n >= 4 => r.router = ip_at(val, 0),
            (OPT_DNS, n) if n >= 4 => {
                r.dns = val
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| Ipv4Addr::from(*c))
                    .collect();
            }
            (OPT_LEASE, 4) => r.lease = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]])),
            (OPT_MTU, 2) => r.mtu = Some(u16::from_be_bytes([val[0], val[1]])),
            _ => {}
        }
    }
    (r.kind != 0).then_some(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const MAC: Mac = Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const OFFERED: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

    fn t(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// The DHCP message in a frame from a client with no address.
    fn sent(frame: &[u8]) -> (u8, u32, Vec<u8>) {
        sent_from(frame, Ipv4Addr::UNSPECIFIED)
    }

    /// The DHCP message in a client frame from `from`.
    fn sent_from(frame: &[u8], from: Ipv4Addr) -> (u8, u32, Vec<u8>) {
        let eth = wire::Ethernet::parse(frame).unwrap();
        assert_eq!(eth.dst, Mac::BROADCAST);
        let ip = wire::Ipv4::parse(eth.payload).unwrap();
        assert_eq!((ip.src, ip.dst), (from, Ipv4Addr::BROADCAST));
        let udp = wire::Udp::parse(ip.payload, ip.src, ip.dst).unwrap();
        assert_eq!((udp.src_port, udp.dst_port), (68, 67));
        let m = udp.payload.to_vec();
        let xid = u32::from_be_bytes([m[4], m[5], m[6], m[7]]);
        let kind = m[FIXED + 6]; // option 53 comes first
        (kind, xid, m)
    }

    /// A server's reply of `kind` to transaction `xid`.
    fn reply(kind: u8, xid: u32, extra: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; FIXED];
        m[0] = 2;
        m[1] = 1;
        m[2] = 6;
        m[4..8].copy_from_slice(&xid.to_be_bytes());
        m[16..20].copy_from_slice(&OFFERED.octets());
        m[28..34].copy_from_slice(&MAC.0);
        m.extend_from_slice(&MAGIC);
        m.extend_from_slice(&[OPT_TYPE, 1, kind, OPT_SERVER, 4, 10, 0, 2, 2]);
        m.extend_from_slice(&[OPT_PAD, OPT_SUBNET, 4, 255, 255, 255, 0]);
        m.extend_from_slice(&[OPT_ROUTER, 4, 10, 0, 2, 2]);
        m.extend_from_slice(&[OPT_DNS, 8, 10, 0, 2, 3, 8, 8, 8, 8]);
        m.extend_from_slice(&[OPT_LEASE, 4, 0, 0, 0x0e, 0x10]); // 3600 s
        m.extend_from_slice(extra);
        m.push(OPT_END);
        let udp = wire::udp(SERVER, 67, Ipv4Addr::BROADCAST, 68, &m);
        let ip = wire::ipv4(SERVER, Ipv4Addr::BROADCAST, PROTO_UDP, 1, &udp);
        wire::ethernet(Mac::BROADCAST, Mac([2, 0, 0, 0, 0, 2]), ETHERTYPE_IPV4, &ip)
    }

    #[test]
    fn discover_offer_request_ack_binds_a_lease() {
        let mut c = Client::new(MAC, 0x1234_5678);
        let (kind, xid, m) = sent(&c.poll(t(0)).unwrap());
        assert_eq!((kind, xid), (DISCOVER, 0x1234_5678));
        assert_eq!(&m[28..34], &MAC.0);
        assert_eq!(u16::from_be_bytes([m[10], m[11]]), BROADCAST_FLAG);
        assert!(c.poll(t(1)).is_none(), "nothing until the backoff passes");
        assert_eq!(c.receive(t(1), &reply(OFFER, xid, &[])), None);
        let (kind, _, m) = sent(&c.poll(t(1)).unwrap());
        assert_eq!(kind, REQUEST);
        let opts = &m[FIXED + 4..];
        assert!(
            opts.windows(6)
                .any(|w| w == [OPT_REQUESTED, 4, 10, 0, 2, 15])
        );
        assert!(opts.windows(6).any(|w| w == [OPT_SERVER, 4, 10, 0, 2, 2]));
        let lease = c
            .receive(t(2), &reply(ACK, xid, &[OPT_MTU, 2, 0x05, 0xdc]))
            .unwrap();
        assert_eq!(
            lease,
            Lease {
                addr: OFFERED,
                prefix: 24,
                router: Some(SERVER),
                dns: vec![Ipv4Addr::new(10, 0, 2, 3), Ipv4Addr::new(8, 8, 8, 8)],
                server: SERVER,
                time: Some(t(3600)),
                mtu: Some(1500),
            }
        );
        assert_eq!(c.lease(), Some(&lease));
        assert!(
            c.poll(t(100)).is_none(),
            "bound: quiet until half the lease"
        );
    }

    #[test]
    fn retransmits_with_backoff_and_ignores_strangers() {
        let mut c = Client::new(MAC, 7);
        assert!(c.poll(t(0)).is_some());
        assert!(c.poll(t(1)).is_none());
        assert!(c.poll(t(2)).is_some(), "after 2 s");
        assert!(c.poll(t(5)).is_none());
        assert!(c.poll(t(6)).is_some(), "after 4 s more");
        // Another transaction, another MAC, a request, garbage: ignored.
        assert_eq!(c.receive(t(7), &reply(OFFER, 8, &[])), None);
        let mut other = reply(OFFER, 7, &[]);
        other[0] ^= 0xff; // the frame's destination MAC
        assert_eq!(c.receive(t(7), &other), None);
        assert!(c.lease().is_none());
        for n in 0..300 {
            let mut f = reply(ACK, 7, &[]);
            let i = n % f.len();
            f[i] = f[i].wrapping_add(n as u8 | 1);
            let _ = c.receive(t(8), &f);
            let _ = c.receive(t(8), &f[..n % f.len()]);
        }
    }

    #[test]
    fn a_nak_starts_over_and_leases_are_renewed() {
        let mut c = Client::new(MAC, 9);
        c.poll(t(0)).unwrap();
        c.receive(t(0), &reply(OFFER, 9, &[]));
        c.poll(t(0)).unwrap();
        assert_eq!(c.receive(t(1), &reply(NAK, 9, &[])), None);
        let (kind, ..) = sent(&c.poll(t(1)).unwrap());
        assert_eq!(kind, DISCOVER, "a NAK starts over");
        c.receive(t(1), &reply(OFFER, 9, &[]));
        c.poll(t(1)).unwrap();
        c.receive(t(2), &reply(ACK, 9, &[])).unwrap();
        // At half the 3600 s lease: a broadcast REQUEST from our address,
        // with ciaddr set.
        assert!(c.poll(t(1000)).is_none());
        assert!(!c.exchanging());
        let (kind, _, m) = sent_from(&c.poll(t(1802)).unwrap(), OFFERED);
        assert_eq!(kind, REQUEST);
        assert_eq!(&m[12..16], &OFFERED.octets());
        assert!(c.exchanging());
        assert!(c.lease().is_some(), "still bound while renewing");
        let renewed = c.receive(t(1803), &reply(ACK, 9, &[])).unwrap();
        assert_eq!(renewed.addr, OFFERED);
        assert!(!c.exchanging());
        // Unrenewed past the lease: back to discovering.
        c.poll(t(1803 + 1800)).unwrap();
        let f = c.poll(t(1803 + 3600 + 1)).unwrap();
        assert_eq!(sent(&f).0, DISCOVER);
        assert!(c.lease().is_none());
        assert!(c.exchanging());
    }

    #[test]
    fn a_capped_lease_is_renewed_sooner() {
        let mut c = Client::new(MAC, 11);
        c.cap_lease(t(4));
        c.poll(t(0)).unwrap();
        c.receive(t(0), &reply(OFFER, 11, &[]));
        c.poll(t(0)).unwrap();
        let lease = c.receive(t(0), &reply(ACK, 11, &[])).unwrap();
        assert_eq!(lease.time, Some(t(4)), "not the server's hour");
        assert!(c.poll(t(1)).is_none());
        assert_eq!(sent_from(&c.poll(t(2)).unwrap(), OFFERED).0, REQUEST);
    }
}
