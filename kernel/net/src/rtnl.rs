//! The read side of Linux's `NETLINK_ROUTE`: what `getifaddrs`,
//! `if_nameindex`, Go's `net.Interfaces` and `ip addr` ask. A request is a
//! user buffer of netlink messages; the answer is the datagrams to queue on
//! the socket. Links, IPv4 addresses and the IPv4 routes can be read;
//! everything that would change the network is refused (EPERM: a cell has no
//! CAP_NET_ADMIN).

use alloc::string::String;
use alloc::vec::Vec;

use crate::Ipv4Addr;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
/// `NLM_F_ROOT | NLM_F_MATCH`: all of them.
const NLM_F_DUMP: u16 = 0x300;

const RTM_BASE: u16 = 16;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
/// `struct nlmsghdr`.
const HEADER: usize = 16;
/// Most bytes put in one datagram (readers use buffers of 4 or 8 KiB).
const DATAGRAM: usize = 4096;

const EPERM: i32 = 1;
const ENODEV: i32 = 19;
const EOPNOTSUPP: i32 = 95;

pub const IFF_UP: u32 = 1;
pub const IFF_BROADCAST: u32 = 2;
pub const IFF_LOOPBACK: u32 = 8;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_MULTICAST: u32 = 0x1000;
const IFF_LOWER_UP: u32 = 0x1_0000;

/// One network interface, as a cell sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iface {
    pub index: u32,
    pub name: String,
    pub mac: [u8; 6],
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u32,
    pub loopback: bool,
    /// The default route's next hop, if it goes through this interface.
    pub gateway: Option<Ipv4Addr>,
}

impl Iface {
    /// `IFF_*` flags (those `SIOCGIFFLAGS` reports: the low 16 bits).
    pub fn flags(&self) -> u32 {
        if self.loopback {
            IFF_UP | IFF_LOOPBACK | IFF_RUNNING
        } else {
            IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST
        }
    }

    /// The address's netmask.
    pub fn netmask(&self) -> Ipv4Addr {
        let bits = u32::from(self.prefix.min(32));
        Ipv4Addr::from(u32::MAX.checked_shl(32 - bits).unwrap_or(0))
    }

    /// The subnet's broadcast address.
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) | !u32::from(self.netmask()))
    }

    /// `ARPHRD_*`: loopback or Ethernet.
    pub fn hardware_type(&self) -> u16 {
        if self.loopback { 772 } else { 1 }
    }
}

/// A message being built: an `nlmsghdr`, a fixed part, attributes.
struct Msg(Vec<u8>);

impl Msg {
    fn new(ty: u16, flags: u16, seq: u32, port: u32, fixed: &[u8]) -> Msg {
        let mut b = Vec::with_capacity(128);
        b.extend_from_slice(&0u32.to_le_bytes()); // length, when done
        b.extend_from_slice(&ty.to_le_bytes());
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&seq.to_le_bytes());
        b.extend_from_slice(&port.to_le_bytes());
        b.extend_from_slice(fixed);
        b.resize(b.len().next_multiple_of(4), 0);
        Msg(b)
    }

    /// Adds a `struct rtattr`.
    fn attr(mut self, ty: u16, data: &[u8]) -> Msg {
        self.0
            .extend_from_slice(&(4 + data.len() as u16).to_le_bytes());
        self.0.extend_from_slice(&ty.to_le_bytes());
        self.0.extend_from_slice(data);
        self.0.resize(self.0.len().next_multiple_of(4), 0);
        self
    }

    fn done(mut self) -> Vec<u8> {
        let len = (self.0.len() as u32).to_le_bytes();
        self.0[..4].copy_from_slice(&len);
        self.0
    }
}

/// One parsed request header.
#[derive(Clone, Copy)]
struct Request<'a> {
    ty: u16,
    flags: u16,
    seq: u32,
    /// The whole message, header included.
    bytes: &'a [u8],
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// Answers the requests in `buf`, for the socket numbered `port`: the
/// datagrams it will read. A malformed buffer ends where it stops making
/// sense, as on Linux.
pub fn answer(mut buf: &[u8], port: u32, ifaces: &[Iface]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let (Some(len), Some(ty), Some(flags), Some(seq)) = (
        u32_at(buf, 0),
        u16_at(buf, 4),
        u16_at(buf, 6),
        u32_at(buf, 8),
    ) {
        let len = len as usize;
        if len < HEADER || len > buf.len() {
            break;
        }
        let r = Request {
            ty,
            flags,
            seq,
            bytes: &buf[..len],
        };
        one(r, port, ifaces, &mut out);
        buf = buf.get(len.next_multiple_of(4)..).unwrap_or(&[]);
    }
    out
}

/// An `NLMSG_ERROR` (0: an acknowledgement) for `r`.
fn error(r: Request<'_>, port: u32, errno: i32) -> Vec<u8> {
    let mut fixed = (-errno).to_le_bytes().to_vec();
    fixed.extend_from_slice(&r.bytes[..HEADER]);
    Msg::new(NLMSG_ERROR, 0, r.seq, port, &fixed).done()
}

fn one(r: Request<'_>, port: u32, ifaces: &[Iface], out: &mut Vec<Vec<u8>>) {
    // Control messages and whatever is not a request: ignored.
    if r.flags & NLM_F_REQUEST == 0 || r.ty < RTM_BASE {
        return;
    }
    let dump = r.flags & NLM_F_DUMP == NLM_F_DUMP;
    let flags = if dump { NLM_F_MULTI } else { 0 };
    let family = r.bytes.get(HEADER).copied().unwrap_or(AF_UNSPEC);
    let msgs: Vec<Vec<u8>> = match r.ty {
        RTM_GETLINK => {
            let wanted = u32_at(r.bytes, HEADER + 4).unwrap_or(0);
            ifaces
                .iter()
                .filter(|i| dump || i.index == wanted)
                .map(|i| link(i, flags, r.seq, port))
                .collect()
        }
        RTM_GETADDR if dump && matches!(family, AF_UNSPEC | AF_INET) => ifaces
            .iter()
            .map(|i| address(i, flags, r.seq, port))
            .collect(),
        RTM_GETROUTE if dump && matches!(family, AF_UNSPEC | AF_INET) => ifaces
            .iter()
            .flat_map(|i| routes(i, flags, r.seq, port))
            .collect(),
        // Another family's (IPv6): there are none.
        RTM_GETADDR | RTM_GETROUTE if dump => Vec::new(),
        // The other reads (types come in fours: new, delete, get, set).
        ty if ty % 4 == 2 => {
            out.push(error(r, port, EOPNOTSUPP));
            return;
        }
        _ => {
            out.push(error(r, port, EPERM));
            return;
        }
    };
    if !dump && msgs.is_empty() {
        out.push(error(r, port, ENODEV));
        return;
    }
    let mut datagram = Vec::new();
    for m in msgs {
        if !datagram.is_empty() && datagram.len() + m.len() > DATAGRAM {
            out.push(core::mem::take(&mut datagram));
        }
        datagram.extend_from_slice(&m);
    }
    if !datagram.is_empty() {
        out.push(datagram);
    }
    if dump {
        let status = 0i32.to_le_bytes();
        out.push(Msg::new(NLMSG_DONE, NLM_F_MULTI, r.seq, port, &status).done());
    } else if r.flags & NLM_F_ACK != 0 {
        out.push(error(r, port, 0));
    }
}

/// `RTM_NEWLINK`: an `ifinfomsg` and its attributes.
fn link(i: &Iface, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    const IFLA_ADDRESS: u16 = 1;
    const IFLA_BROADCAST: u16 = 2;
    const IFLA_IFNAME: u16 = 3;
    const IFLA_MTU: u16 = 4;
    const IFLA_TXQLEN: u16 = 13;
    const IFLA_OPERSTATE: u16 = 16;
    const IFLA_STATS: u16 = 7;
    const OPER_UNKNOWN: u8 = 0;
    const OPER_UP: u8 = 6;
    let mut fixed = [0u8; 16];
    fixed[2..4].copy_from_slice(&i.hardware_type().to_le_bytes());
    fixed[4..8].copy_from_slice(&i.index.to_le_bytes());
    fixed[8..12].copy_from_slice(&(i.flags() | IFF_LOWER_UP).to_le_bytes());
    let (mac, brd) = if i.loopback {
        ([0u8; 6], [0u8; 6])
    } else {
        (i.mac, [0xff; 6])
    };
    let mut name = i.name.as_bytes().to_vec();
    name.push(0);
    let oper = if i.loopback { OPER_UNKNOWN } else { OPER_UP };
    Msg::new(RTM_NEWLINK, flags, seq, port, &fixed)
        .attr(IFLA_IFNAME, &name)
        .attr(IFLA_TXQLEN, &1000u32.to_le_bytes())
        .attr(IFLA_OPERSTATE, &[oper])
        .attr(IFLA_MTU, &i.mtu.to_le_bytes())
        .attr(IFLA_ADDRESS, &mac)
        .attr(IFLA_BROADCAST, &brd)
        // struct rtnl_link_stats: nothing is counted per cell interface.
        .attr(IFLA_STATS, &[0; 96])
        .done()
}

/// `RTM_NEWADDR`: an `ifaddrmsg` and its attributes.
fn address(i: &Iface, flags: u16, seq: u32, port: u32) -> Vec<u8> {
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    const IFA_LABEL: u16 = 3;
    const IFA_BROADCAST: u16 = 4;
    const IFA_FLAGS: u16 = 8;
    const IFA_F_PERMANENT: u8 = 0x80;
    const SCOPE_UNIVERSE: u8 = 0;
    const SCOPE_HOST: u8 = 254;
    let scope = if i.loopback {
        SCOPE_HOST
    } else {
        SCOPE_UNIVERSE
    };
    let mut fixed = [AF_INET, i.prefix, IFA_F_PERMANENT, scope, 0, 0, 0, 0];
    fixed[4..8].copy_from_slice(&i.index.to_le_bytes());
    let mut label = i.name.as_bytes().to_vec();
    label.push(0);
    let mut m = Msg::new(RTM_NEWADDR, flags, seq, port, &fixed)
        .attr(IFA_ADDRESS, &i.addr.octets())
        .attr(IFA_LOCAL, &i.addr.octets());
    if !i.loopback {
        m = m.attr(IFA_BROADCAST, &i.broadcast().octets());
    }
    m.attr(IFA_LABEL, &label)
        .attr(IFA_FLAGS, &u32::from(IFA_F_PERMANENT).to_le_bytes())
        .done()
}

/// `RTM_NEWROUTE` for each route of `i` in the main table.
fn routes(i: &Iface, flags: u16, seq: u32, port: u32) -> Vec<Vec<u8>> {
    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;
    const RTA_GATEWAY: u16 = 5;
    const RTA_PREFSRC: u16 = 7;
    const RTA_TABLE: u16 = 15;
    const TABLE_MAIN: u8 = 254;
    const PROTO_KERNEL: u8 = 2;
    const PROTO_BOOT: u8 = 3;
    const SCOPE_UNIVERSE: u8 = 0;
    const SCOPE_LINK: u8 = 253;
    const UNICAST: u8 = 1;
    let mut out = Vec::new();
    if i.loopback {
        return out; // Linux keeps loopback's in the local table.
    }
    let msg = |len: u8, proto: u8, scope: u8| {
        let fixed = [
            AF_INET, len, 0, 0, TABLE_MAIN, proto, scope, UNICAST, 0, 0, 0, 0,
        ];
        Msg::new(RTM_NEWROUTE, flags, seq, port, &fixed)
            .attr(RTA_TABLE, &u32::from(TABLE_MAIN).to_le_bytes())
    };
    let oif = i.index.to_le_bytes();
    if let Some(g) = i.gateway {
        out.push(
            msg(0, PROTO_BOOT, SCOPE_UNIVERSE)
                .attr(RTA_GATEWAY, &g.octets())
                .attr(RTA_OIF, &oif)
                .done(),
        );
    }
    let net = Ipv4Addr::from(u32::from(i.addr) & u32::from(i.netmask()));
    out.push(
        msg(i.prefix, PROTO_KERNEL, SCOPE_LINK)
            .attr(RTA_DST, &net.octets())
            .attr(RTA_PREFSRC, &i.addr.octets())
            .attr(RTA_OIF, &oif)
            .done(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn ifaces() -> Vec<Iface> {
        vec![
            Iface {
                index: 1,
                name: "lo".into(),
                mac: [0; 6],
                addr: Ipv4Addr::LOCALHOST,
                prefix: 8,
                mtu: 65536,
                loopback: true,
                gateway: None,
            },
            Iface {
                index: 2,
                name: "eth0".into(),
                mac: [2, 0x42, 10, 88, 0, 5],
                addr: Ipv4Addr::new(10, 88, 0, 5),
                prefix: 16,
                mtu: 1500,
                loopback: false,
                gateway: Some(Ipv4Addr::new(10, 88, 0, 1)),
            },
        ]
    }

    /// A request: header and an rtgenmsg-sized (or longer) body.
    fn request(ty: u16, flags: u16, body: &[u8]) -> Vec<u8> {
        Msg::new(ty, flags, 7, 0, body).done()
    }

    /// The messages in `datagrams`: (type, flags, body).
    fn messages(datagrams: &[Vec<u8>]) -> Vec<(u16, u16, Vec<u8>)> {
        let mut out = Vec::new();
        for d in datagrams {
            let mut b = &d[..];
            while !b.is_empty() {
                let len = u32_at(b, 0).unwrap() as usize;
                assert_eq!(u32_at(b, 8), Some(7), "sequence number echoed");
                assert_eq!(u32_at(b, 12), Some(99), "addressed to the socket");
                out.push((
                    u16_at(b, 4).unwrap(),
                    u16_at(b, 6).unwrap(),
                    b[HEADER..len].to_vec(),
                ));
                b = &b[len.next_multiple_of(4)..];
            }
        }
        out
    }

    /// The attributes after `fixed` bytes of a body.
    fn attrs(body: &[u8], fixed: usize) -> Vec<(u16, Vec<u8>)> {
        let mut b = &body[fixed..];
        let mut out = Vec::new();
        while !b.is_empty() {
            let len = u16_at(b, 0).unwrap() as usize;
            out.push((u16_at(b, 2).unwrap(), b[4..len].to_vec()));
            b = &b[len.next_multiple_of(4).min(b.len())..];
        }
        out
    }

    #[test]
    fn links_are_dumped_and_found_by_index() {
        let d = answer(&request(RTM_GETLINK, 0x301, &[0]), 99, &ifaces());
        let m = messages(&d);
        assert_eq!(m.len(), 3);
        assert_eq!((m[0].0, m[1].0, m[2].0), (RTM_NEWLINK, RTM_NEWLINK, 3));
        assert!(m.iter().all(|m| m.1 & NLM_F_MULTI != 0));
        assert_eq!(u32_at(&m[1].2, 4), Some(2));
        let a = attrs(&m[1].2, 16);
        assert!(a.contains(&(3, b"eth0\0".to_vec())));
        assert!(a.contains(&(1, vec![2, 0x42, 10, 88, 0, 5])));

        let mut body = [0u8; 16];
        body[4] = 2;
        let m = messages(&answer(&request(RTM_GETLINK, 1, &body), 99, &ifaces()));
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].0, m[0].1), (RTM_NEWLINK, 0));
        body[4] = 9;
        let m = messages(&answer(&request(RTM_GETLINK, 1, &body), 99, &ifaces()));
        assert_eq!(m[0].0, NLMSG_ERROR);
        assert_eq!(u32_at(&m[0].2, 0), Some((-ENODEV) as u32));
    }

    #[test]
    fn addresses_and_routes_are_dumped_by_family() {
        let m = messages(&answer(
            &request(RTM_GETADDR, 0x301, &[AF_INET]),
            99,
            &ifaces(),
        ));
        assert_eq!(m.len(), 3);
        assert_eq!(m[1].2[..2], [AF_INET, 16]);
        let a = attrs(&m[1].2, 8);
        assert!(a.contains(&(2, vec![10, 88, 0, 5])));
        assert!(a.contains(&(4, vec![10, 88, 255, 255])));
        // No IPv6 addresses: an empty dump.
        let m = messages(&answer(&request(RTM_GETADDR, 0x301, &[10]), 99, &ifaces()));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0, NLMSG_DONE);

        let m = messages(&answer(&request(RTM_GETROUTE, 0x301, &[0]), 99, &ifaces()));
        assert_eq!(m.len(), 3, "default, subnet, done");
        assert!(attrs(&m[0].2, 12).contains(&(5, vec![10, 88, 0, 1])));
        assert!(attrs(&m[1].2, 12).contains(&(1, vec![10, 88, 0, 0])));
    }

    #[test]
    fn changes_are_refused_and_junk_is_ignored() {
        for ty in [RTM_NEWLINK, RTM_NEWADDR, RTM_NEWROUTE, 17, 19, 21, 25] {
            let m = messages(&answer(&request(ty, 5, &[0; 16]), 99, &ifaces()));
            assert_eq!(m.len(), 1, "type {ty}");
            assert_eq!(u32_at(&m[0].2, 0), Some((-EPERM) as u32));
        }
        // Neighbours: a read we do not answer.
        let m = messages(&answer(&request(30, 0x301, &[0]), 99, &ifaces()));
        assert_eq!(u32_at(&m[0].2, 0), Some((-EOPNOTSUPP) as u32));
        assert!(answer(&[], 99, &ifaces()).is_empty());
        assert!(answer(&[1, 2, 3], 99, &ifaces()).is_empty());
        let mut long = request(RTM_GETLINK, 0x301, &[0]);
        long[0] = 200;
        assert!(answer(&long, 99, &ifaces()).is_empty());
        // Two requests in one buffer are both answered.
        let mut two = request(RTM_GETLINK, 0x301, &[0]);
        two.extend(request(RTM_GETADDR, 0x301, &[0]));
        assert_eq!(messages(&answer(&two, 99, &ifaces())).len(), 6);
    }

    #[test]
    fn long_dumps_are_split() {
        let many: Vec<Iface> = (0..100)
            .map(|n| Iface {
                index: n,
                ..ifaces()[1].clone()
            })
            .collect();
        let d = answer(&request(RTM_GETLINK, 0x301, &[0]), 99, &many);
        assert!(d.len() > 2 && d.iter().all(|d| d.len() <= DATAGRAM));
        assert_eq!(messages(&d).len(), 101);
    }

    #[test]
    fn masks() {
        let i = &ifaces()[1];
        assert_eq!(i.netmask(), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(i.broadcast(), Ipv4Addr::new(10, 88, 255, 255));
        let all = Iface {
            prefix: 0,
            ..i.clone()
        };
        assert_eq!(all.netmask(), Ipv4Addr::UNSPECIFIED);
    }
}
