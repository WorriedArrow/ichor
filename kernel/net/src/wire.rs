//! Wire formats: Ethernet II, ARP (Ethernet/IPv4), IPv4, ICMP echo, UDP,
//! and the Internet checksum (RFC 1071).
//!
//! Parsers borrow from the input and validate everything a later layer
//! relies on (lengths, header sizes, checksums); builders return owned
//! packets with checksums filled in.

use alloc::vec::Vec;

use crate::{Ipv4Addr, Mac};

/// EtherTypes.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// IP protocol numbers.
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn ip(b: &[u8], at: usize) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(be32(b, at)?))
}

fn mac(b: &[u8], at: usize) -> Option<Mac> {
    let s = b.get(at..at + 6)?;
    let mut m = [0u8; 6];
    m.copy_from_slice(s);
    Some(Mac(m))
}

/// Adds `data` to a running one's-complement sum (big-endian 16-bit
/// words, an odd last byte padded with zero).
pub fn sum(acc: u32, data: &[u8]) -> u32 {
    // Eight bytes at a time: 2^16 is 1 modulo 2^16 - 1, so 32-bit words add
    // up to the same as their halves.
    let (blocks, rest) = data.as_chunks::<8>();
    let mut wide = u64::from(acc);
    for b in blocks {
        let v = u64::from_be_bytes(*b);
        wide += (v >> 32) + (v & 0xffff_ffff);
    }
    let (words, rest) = rest.as_chunks::<2>();
    for w in words {
        wide += u64::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
        wide += u64::from(*last) << 8;
    }
    while wide > 0xffff {
        wide = (wide & 0xffff) + (wide >> 16);
    }
    wide as u32
}

/// Folds a running sum into the 16-bit one's-complement checksum.
pub fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// The Internet checksum of `data`.
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum(0, data))
}

/// The running sum of the IPv4 pseudo-header for a TCP or UDP checksum.
pub fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> u32 {
    let mut acc = sum(0, &src.octets());
    acc = sum(acc, &dst.octets());
    acc + u32::from(proto) + (len as u32 & 0xffff) + ((len as u32) >> 16)
}

// ---------------------------------------------------------------------------
// Ethernet II.
// ---------------------------------------------------------------------------

/// An Ethernet II frame (no 802.1Q tag; tagged frames are not accepted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ethernet<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub const ETHERNET_HEADER: usize = 14;

impl<'a> Ethernet<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Ethernet<'a>> {
        Some(Ethernet {
            dst: mac(b, 0)?,
            src: mac(b, 6)?,
            ethertype: be16(b, 12)?,
            payload: b.get(ETHERNET_HEADER..)?,
        })
    }
}

/// Builds an Ethernet II frame.
pub fn ethernet(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETHERNET_HEADER + payload.len());
    f.extend_from_slice(&dst.0);
    f.extend_from_slice(&src.0);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

// ---------------------------------------------------------------------------
// ARP (Ethernet, IPv4).
// ---------------------------------------------------------------------------

pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

/// An ARP packet for IPv4 over Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4Addr,
    pub target_mac: Mac,
    pub target_ip: Ipv4Addr,
}

impl Arp {
    pub fn parse(b: &[u8]) -> Option<Arp> {
        // htype 1 (Ethernet), ptype IPv4, hlen 6, plen 4.
        if be16(b, 0)? != 1 || be16(b, 2)? != ETHERTYPE_IPV4 || *b.get(4)? != 6 || *b.get(5)? != 4 {
            return None;
        }
        Some(Arp {
            op: be16(b, 6)?,
            sender_mac: mac(b, 8)?,
            sender_ip: ip(b, 14)?,
            target_mac: mac(b, 18)?,
            target_ip: ip(b, 24)?,
        })
    }

    pub fn emit(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        b.extend_from_slice(&[6, 4]);
        b.extend_from_slice(&self.op.to_be_bytes());
        b.extend_from_slice(&self.sender_mac.0);
        b.extend_from_slice(&self.sender_ip.octets());
        b.extend_from_slice(&self.target_mac.0);
        b.extend_from_slice(&self.target_ip.octets());
        b
    }
}

// ---------------------------------------------------------------------------
// IPv4.
// ---------------------------------------------------------------------------

/// A parsed IPv4 packet (header checksum verified). Fragments are
/// reported as such; reassembly is the caller's choice (the stack drops
/// them in milestone 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub id: u16,
    /// More-fragments set or a nonzero fragment offset.
    pub fragment: bool,
    pub payload: &'a [u8],
}

impl<'a> Ipv4<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Ipv4<'a>> {
        let vihl = *b.first()?;
        let ihl = usize::from(vihl & 0xf) * 4;
        if vihl >> 4 != 4 || ihl < 20 || b.len() < ihl {
            return None;
        }
        let total = usize::from(be16(b, 2)?);
        if total < ihl || total > b.len() {
            return None;
        }
        if checksum(&b[..ihl]) != 0 {
            return None;
        }
        let flags_frag = be16(b, 6)?;
        Some(Ipv4 {
            src: ip(b, 12)?,
            dst: ip(b, 16)?,
            protocol: *b.get(9)?,
            ttl: *b.get(8)?,
            id: be16(b, 4)?,
            fragment: flags_frag & 0x3fff != 0, // MF or an offset
            payload: &b[ihl..total],
        })
    }
}

/// Builds an IPv4 packet (20-byte header, DF set, TTL 64).
pub fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.push(0x45);
    p.push(0); // DSCP/ECN
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    p.push(64);
    p.push(protocol);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

// ---------------------------------------------------------------------------
// ICMP echo.
// ---------------------------------------------------------------------------

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// An ICMP echo request or reply (checksum verified).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo<'a> {
    pub kind: u8,
    pub ident: u16,
    pub seq: u16,
    pub data: &'a [u8],
}

impl<'a> Echo<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Echo<'a>> {
        let kind = *b.first()?;
        if (kind != ICMP_ECHO_REQUEST && kind != ICMP_ECHO_REPLY) || *b.get(1)? != 0 {
            return None;
        }
        if b.len() < 8 || checksum(b) != 0 {
            return None;
        }
        Some(Echo {
            kind,
            ident: be16(b, 4)?,
            seq: be16(b, 6)?,
            data: &b[8..],
        })
    }

    pub fn emit(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + self.data.len());
        b.extend_from_slice(&[self.kind, 0, 0, 0]);
        b.extend_from_slice(&self.ident.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(self.data);
        let c = checksum(&b);
        b[2..4].copy_from_slice(&c.to_be_bytes());
        b
    }
}

pub const ICMP_UNREACHABLE: u8 = 3;
/// The codes of [`ICMP_UNREACHABLE`] told apart: a host, and a port nobody
/// listens on.
pub const UNREACHABLE_HOST: u8 = 1;
pub const UNREACHABLE_PORT: u8 = 3;

/// An ICMP "destination unreachable" (checksum verified), and what it
/// quotes of the packet it is about: its addresses, its protocol and the
/// first eight bytes of its payload (a UDP header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unreachable {
    pub code: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub head: [u8; 8],
}

impl Unreachable {
    pub fn parse(b: &[u8]) -> Option<Unreachable> {
        if *b.first()? != ICMP_UNREACHABLE || checksum(b) != 0 {
            return None;
        }
        // The quoted packet is cut short: only its header is checked.
        let quoted = b.get(8..)?;
        let first = *quoted.first()?;
        let ihl = usize::from(first & 0xf) * 4;
        if first >> 4 != 4 || ihl < 20 {
            return None;
        }
        Some(Unreachable {
            code: *b.get(1)?,
            src: ip(quoted, 12)?,
            dst: ip(quoted, 16)?,
            protocol: *quoted.get(9)?,
            head: *quoted.get(ihl..)?.first_chunk::<8>()?,
        })
    }

    pub fn emit(&self) -> Vec<u8> {
        let mut b = alloc::vec![ICMP_UNREACHABLE, self.code, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(&ipv4(self.src, self.dst, self.protocol, 0, &self.head));
        let c = checksum(&b);
        b[2..4].copy_from_slice(&c.to_be_bytes());
        b
    }
}

// ---------------------------------------------------------------------------
// UDP.
// ---------------------------------------------------------------------------

/// A UDP datagram (checksum verified when present).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> Udp<'a> {
    /// Parses `b` (an IPv4 payload from `src` to `dst`).
    pub fn parse(b: &'a [u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<Udp<'a>> {
        let len = usize::from(be16(b, 4)?);
        if len < 8 || len > b.len() {
            return None;
        }
        let stored = be16(b, 6)?;
        if stored != 0 && fold(sum(pseudo_header(src, dst, PROTO_UDP, len), &b[..len])) != 0 {
            return None;
        }
        Some(Udp {
            src_port: be16(b, 0)?,
            dst_port: be16(b, 2)?,
            payload: &b[8..len],
        })
    }
}

/// Builds a UDP datagram from `src` to `dst` with its checksum.
pub fn udp(src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut b = Vec::with_capacity(len);
    b.extend_from_slice(&src_port.to_be_bytes());
    b.extend_from_slice(&dst_port.to_be_bytes());
    b.extend_from_slice(&(len as u16).to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(payload);
    let mut c = fold(sum(pseudo_header(src, dst, PROTO_UDP, len), &b));
    if c == 0 {
        c = 0xffff; // 0 means "no checksum"
    }
    b[6..8].copy_from_slice(&c.to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 2);
    const B: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 3);

    #[test]
    fn checksum_matches_rfc1071_example() {
        // RFC 1071 §3: the sum of these words is 0xddf2; the checksum is
        // its complement.
        let d = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&d), !0xddf2);
        // A buffer including its own checksum sums to zero.
        let mut with = d.to_vec();
        with.extend_from_slice(&checksum(&d).to_be_bytes());
        assert_eq!(checksum(&with), 0);
        // Against the sum of 16-bit words, at every length; two parts (the
        // first of even length) sum to the whole.
        for fill in [0xffu8, 0, 0x5a] {
            for n in 0..70usize {
                let d: Vec<u8> = (0..n)
                    .map(|i| {
                        if fill == 0x5a {
                            (i * 89 + n) as u8
                        } else {
                            fill
                        }
                    })
                    .collect();
                let mut plain = 0u32;
                for w in d.chunks(2) {
                    plain += u32::from(w[0]) << 8 | u32::from(*w.get(1).unwrap_or(&0));
                }
                assert_eq!(fold(sum(0, &d)), fold(plain), "{n} bytes of {fill}");
                let (a, b) = d.split_at(n / 4 * 2);
                assert_eq!(fold(sum(sum(0, a), b)), fold(plain));
            }
        }
    }

    #[test]
    fn unreachable_round_trips_and_rejects_damage() {
        let u = Unreachable {
            code: UNREACHABLE_PORT,
            src: A,
            dst: B,
            protocol: PROTO_UDP,
            head: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let b = u.emit();
        assert_eq!(Unreachable::parse(&b), Some(u));
        for i in 0..b.len() {
            let mut bad = b.clone();
            bad[i] ^= 0x40;
            assert_eq!(Unreachable::parse(&bad), None, "byte {i}");
            assert_eq!(Unreachable::parse(&b[..i]), None, "{i} bytes");
        }
        // An echo is not one, and a quoted header may have options.
        assert_eq!(Unreachable::parse(&[8, 0, 0xf7, 0xff, 0, 0, 0, 0]), None);
        let mut long = b[..28].to_vec();
        long[8] = 0x46;
        long.extend_from_slice(&[9; 4]);
        long.extend_from_slice(&u.head);
        long[2..4].copy_from_slice(&[0, 0]);
        let c = checksum(&long);
        long[2..4].copy_from_slice(&c.to_be_bytes());
        assert_eq!(Unreachable::parse(&long), Some(u));
    }

    #[test]
    fn ipv4_round_trips_and_rejects_damage() {
        let p = ipv4(A, B, PROTO_UDP, 7, b"payload");
        let h = Ipv4::parse(&p).unwrap();
        assert_eq!(
            (h.src, h.dst, h.protocol, h.ttl, h.id),
            (A, B, PROTO_UDP, 64, 7)
        );
        assert_eq!(h.payload, b"payload");
        assert!(!h.fragment);
        let mut bad = p.clone();
        bad[15] ^= 1; // source address: header checksum fails
        assert!(Ipv4::parse(&bad).is_none());
        // A total length past the buffer, or below the header, is refused.
        let mut long = p.clone();
        long[2..4].copy_from_slice(&1000u16.to_be_bytes());
        assert!(Ipv4::parse(&long).is_none());
        // Trailing bytes after the total length (Ethernet padding) are cut.
        let mut padded = p.clone();
        padded.extend_from_slice(&[0; 10]);
        assert_eq!(Ipv4::parse(&padded).unwrap().payload, b"payload");
    }

    #[test]
    fn udp_and_icmp_round_trip() {
        let d = udp(A, 5000, B, 53, b"query");
        let u = Udp::parse(&d, A, B).unwrap();
        assert_eq!(
            (u.src_port, u.dst_port, u.payload),
            (5000, 53, &b"query"[..])
        );
        // The pseudo-header binds the addresses: another one fails. (Swapped
        // ones would not: the one's-complement sum is commutative.)
        assert!(Udp::parse(&d, A, Ipv4Addr::new(10, 88, 0, 9)).is_none());
        let e = Echo {
            kind: ICMP_ECHO_REQUEST,
            ident: 1,
            seq: 2,
            data: b"ping",
        }
        .emit();
        assert_eq!(Echo::parse(&e).unwrap().data, b"ping");
        let mut bad = e.clone();
        bad[9] ^= 1;
        assert!(Echo::parse(&bad).is_none());
    }

    #[test]
    fn arp_and_ethernet_round_trip() {
        let a = Arp {
            op: ARP_REQUEST,
            sender_mac: Mac([2, 0, 0, 0, 0, 1]),
            sender_ip: A,
            target_mac: Mac::ZERO,
            target_ip: B,
        };
        let f = ethernet(Mac::BROADCAST, a.sender_mac, ETHERTYPE_ARP, &a.emit());
        let e = Ethernet::parse(&f).unwrap();
        assert_eq!(e.ethertype, ETHERTYPE_ARP);
        assert_eq!(Arp::parse(e.payload), Some(a));
        assert!(Arp::parse(&[0; 27]).is_none());
        assert!(Ethernet::parse(&[0; 13]).is_none());
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 1;
        for len in 0..300 {
            let g: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (x >> 16) as u8
                })
                .collect();
            let _ = Ethernet::parse(&g);
            let _ = Arp::parse(&g);
            let _ = Ipv4::parse(&g);
            let _ = Echo::parse(&g);
            let _ = Udp::parse(&g, A, B);
            // Make it look like IPv4 to get past the version check.
            let mut v = g.clone();
            if let Some(b) = v.first_mut() {
                *b = 0x45;
            }
            let _ = Ipv4::parse(&v);
        }
    }
}
