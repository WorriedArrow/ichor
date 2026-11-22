//! `AF_NETLINK` sockets of the `NETLINK_ROUTE` family, read side only: what
//! `getifaddrs`, `if_nameindex` and Go's `net.Interfaces` ask about the
//! cell's links, addresses and routes (`net::rtnl` has the messages), and
//! the `SIOCGIF*` ioctls that ask the same things. A request is answered
//! into the socket's queue as it is sent; nothing else ever arrives (no
//! multicast groups: a cell's interfaces do not change).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use frame::sync::SpinLock;
use net::rtnl::{self, Iface};

use super::socket::{Timeouts, block_on, sockaddr as sockaddr_in};
use super::{EFAULT, EINVAL, EMFILE, EPERM};
use crate::netstack::{self, Waiters};
use crate::poll::{Object, POLLIN, POLLOUT, Watchers};
use crate::process::{Fd, LinuxProcess, ObjectEnd};
use crate::switch;

pub(super) const AF_NETLINK: u64 = 16;
const NETLINK_ROUTE: u64 = 0;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2_000_000;

const SOL_SOCKET: u64 = 1;
const SOL_NETLINK: u64 = 270;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;

const ENXIO: i64 = 6;
const ENODEV: i64 = 19;
const ENOPROTOOPT: i64 = 92;
const ENOTSOCK: i64 = 88;
const EPROTONOSUPPORT: i64 = 93;
const ESOCKTNOSUPPORT: i64 = 94;
const EAFNOSUPPORT: i64 = 97;

/// Most answers a socket holds unread; more are dropped (a reader that
/// falls behind on Linux gets ENOBUFS).
const QUEUE: usize = 256;

/// A netlink socket.
#[derive(Debug)]
pub(crate) struct Netlink {
    /// Its address (`nl_pid`), assigned when made.
    port: AtomicU32,
    ty: u64,
    /// The cell's interfaces.
    ifaces: Vec<Iface>,
    answers: SpinLock<VecDeque<Vec<u8>>>,
    wait: Waiters,
    timeouts: Timeouts,
}

impl Netlink {
    /// Its `nl_pid`.
    pub(super) fn port(&self) -> u32 {
        self.port.load(Ordering::Relaxed)
    }

    /// Answers the requests in `data`.
    pub(super) fn request(&self, data: &[u8]) {
        let new = rtnl::answer(data, self.port(), &self.ifaces);
        {
            let mut q = self.answers.lock();
            let room = QUEUE.saturating_sub(q.len());
            q.extend(new.into_iter().take(room));
        }
        self.wait.wake();
    }

    /// Takes (or copies) the next answer.
    pub(super) fn recv(
        &self,
        nonblock: bool,
        peek: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        let timeout = self.timeouts.recv.load(Ordering::Relaxed);
        block_on(&self.wait, nonblock, timeout, interrupted, || {
            let mut q = self.answers.lock();
            if peek {
                q.front().cloned().map(Ok)
            } else {
                q.pop_front().map(Ok)
            }
        })
    }
}

impl Object for Netlink {
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        let mut d = self.recv(nonblock, false, interrupted)?;
        d.truncate(max);
        Ok(d)
    }

    fn write(&self, data: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        self.request(data);
        Ok(data.len())
    }

    fn poll(&self) -> u16 {
        if self.answers.lock().is_empty() {
            POLLOUT
        } else {
            POLLOUT | POLLIN
        }
    }

    fn changes(&self) -> u64 {
        self.wait.changes.load(Ordering::Acquire)
    }

    fn mode(&self) -> u32 {
        0o140_000 // S_IFSOCK
    }

    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.wait.watchers)
    }

    fn netlink(&self) -> Option<&Netlink> {
        Some(self)
    }
}

/// The calling cell's interfaces: loopback, and its port on the cell switch
/// (an IP link: the MAC is made up from the address, as a container
/// runtime's is).
fn ifaces(p: &LinuxProcess) -> Vec<Iface> {
    let mut v = alloc::vec![Iface {
        index: 1,
        name: String::from("lo"),
        mac: [0; 6],
        addr: net::Ipv4Addr::LOCALHOST,
        prefix: 8,
        mtu: 65536,
        loopback: true,
        gateway: None,
    }];
    if let Some(addr) = netstack::stack_for(&p.cell).addr() {
        let o = addr.octets();
        v.push(Iface {
            index: 2,
            name: String::from("eth0"),
            mac: [0x02, 0x42, o[0], o[1], o[2], o[3]],
            addr,
            prefix: switch::PREFIX,
            mtu: 1500,
            loopback: false,
            gateway: Some(net::Ipv4Addr::from(u32::from(switch::SUBNET) + 1)),
        });
    }
    v
}

/// The netlink socket behind `fd`, if it is one, and whether it is
/// non-blocking.
pub(super) fn of(p: &LinuxProcess, fd: u64) -> Option<(Arc<dyn Object>, bool)> {
    match p.fd(fd)? {
        Fd::Object(o) if o.obj.netlink().is_some() => Some((o.obj, o.nonblock)),
        _ => None,
    }
}

pub(super) fn sock(o: &Arc<dyn Object>) -> Result<&Netlink, i64> {
    o.netlink().ok_or(ENOTSOCK)
}

/// `socket(AF_NETLINK, ty, proto)`.
pub(super) fn socket(p: &mut LinuxProcess, ty: u64, proto: u64) -> Result<u64, i64> {
    if !matches!(ty & 0xf, SOCK_DGRAM | SOCK_RAW) {
        return Err(ESOCKTNOSUPPORT);
    }
    if proto != NETLINK_ROUTE {
        return Err(EPROTONOSUPPORT);
    }
    // The process's first socket is numbered as the process, the others
    // below zero, as on Linux; here every one gets its own number.
    static NEXT: AtomicU32 = AtomicU32::new(u32::MAX);
    let s = Netlink {
        port: AtomicU32::new(NEXT.fetch_sub(1, Ordering::Relaxed)),
        ty: ty & 0xf,
        ifaces: ifaces(p),
        answers: SpinLock::new(VecDeque::new()),
        wait: Waiters::default(),
        timeouts: Timeouts::default(),
    };
    p.install_flags(
        Fd::Object(ObjectEnd {
            obj: Arc::new(s),
            nonblock: ty & SOCK_NONBLOCK != 0,
        }),
        ty & SOCK_CLOEXEC != 0,
    )
    .ok_or(EMFILE)
}

/// A `struct sockaddr_nl`: family, pad, port, groups.
pub(super) fn sockaddr(port: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[..2].copy_from_slice(&(AF_NETLINK as u16).to_le_bytes());
    b[4..8].copy_from_slice(&port.to_le_bytes());
    b
}

/// Reads a `sockaddr_nl`: its port.
fn read_sockaddr(p: &mut LinuxProcess, addr: u64, len: u64) -> Result<u32, i64> {
    if len < 12 {
        return Err(EINVAL);
    }
    let mut b = [0u8; 12];
    if p.copy_from_user(addr, &mut b) != 12 {
        return Err(EFAULT);
    }
    if u64::from(u16::from_le_bytes([b[0], b[1]])) != AF_NETLINK {
        return Err(EAFNOSUPPORT);
    }
    Ok(u32::from_le_bytes([b[4], b[5], b[6], b[7]]))
}

/// `bind`: takes the port asked for. The groups are ignored: their news
/// (a link or an address that changes) never comes here.
pub(super) fn bind(p: &mut LinuxProcess, s: &Netlink, addr: u64, len: u64) -> Result<u64, i64> {
    let port = read_sockaddr(p, addr, len)?;
    if port != 0 {
        s.port.store(port, Ordering::Relaxed);
    }
    Ok(0)
}

/// `connect`: only the kernel (port 0) is there to talk to.
pub(super) fn connect(p: &mut LinuxProcess, _: &Netlink, addr: u64, len: u64) -> Result<u64, i64> {
    match read_sockaddr(p, addr, len)? {
        0 => Ok(0),
        _ => Err(EPERM),
    }
}

/// Options change nothing here: buffers and strictness are accepted.
pub(super) fn setsockopt(level: u64, name: u64) -> Result<u64, i64> {
    match (level, name) {
        // SO_SNDBUF, SO_RCVBUF and their FORCE forms.
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF | 32 | 33) => Ok(0),
        // ADD/DROP_MEMBERSHIP, PKTINFO, EXT_ACK, GET_STRICT_CHK.
        (SOL_NETLINK, 1 | 2 | 3 | 11 | 12) => Ok(0),
        _ => Err(ENOPROTOOPT),
    }
}

pub(super) fn getsockopt(s: &Netlink, level: u64, name: u64) -> Result<Vec<u8>, i64> {
    let v: i32 = match (level, name) {
        (SOL_SOCKET, SO_TYPE) => s.ty as i32,
        (SOL_SOCKET, SO_ERROR) => 0,
        (SOL_SOCKET, SO_DOMAIN) => AF_NETLINK as i32,
        (SOL_SOCKET, SO_PROTOCOL) => NETLINK_ROUTE as i32,
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => 212_992,
        _ => return Err(ENOPROTOOPT),
    };
    Ok(v.to_le_bytes().to_vec())
}

/// The `SIOCGIF*` requests, on any socket (`struct ifreq`: a 16-byte name
/// and 24 bytes of answer). `None` if `request` is not one.
pub(super) fn ioctl(p: &mut LinuxProcess, request: u64, arg: u64) -> Option<Result<u64, i64>> {
    const SIOCGIFNAME: u64 = 0x8910;
    const SIOCGIFCONF: u64 = 0x8912;
    const SIOCGIFFLAGS: u64 = 0x8913;
    const SIOCGIFADDR: u64 = 0x8915;
    const SIOCGIFBRDADDR: u64 = 0x8919;
    const SIOCGIFNETMASK: u64 = 0x891b;
    const SIOCGIFMTU: u64 = 0x8921;
    const SIOCGIFHWADDR: u64 = 0x8927;
    const SIOCGIFINDEX: u64 = 0x8933;
    const SIOCGIFTXQLEN: u64 = 0x8942;
    if !matches!(
        request,
        SIOCGIFNAME
            | SIOCGIFCONF
            | SIOCGIFFLAGS
            | SIOCGIFADDR
            | SIOCGIFBRDADDR
            | SIOCGIFNETMASK
            | SIOCGIFMTU
            | SIOCGIFHWADDR
            | SIOCGIFINDEX
            | SIOCGIFTXQLEN
    ) {
        return None;
    }
    let all = ifaces(p);
    if request == SIOCGIFCONF {
        return Some(ifconf(p, &all, arg));
    }
    Some((|| {
        let mut req = [0u8; 40];
        if p.copy_from_user(arg, &mut req) != 40 {
            return Err(EFAULT);
        }
        let i = if request == SIOCGIFNAME {
            let index = u32::from_le_bytes([req[16], req[17], req[18], req[19]]);
            all.iter().find(|i| i.index == index).ok_or(ENXIO)?
        } else {
            let end = req[..16].iter().position(|&b| b == 0).unwrap_or(16);
            all.iter()
                .find(|i| i.name.as_bytes() == &req[..end])
                .ok_or(ENODEV)?
        };
        match request {
            SIOCGIFNAME => {
                req[..16].fill(0);
                req[..i.name.len()].copy_from_slice(i.name.as_bytes());
            }
            SIOCGIFFLAGS => req[16..18].copy_from_slice(&(i.flags() as u16).to_le_bytes()),
            SIOCGIFADDR => req[16..32].copy_from_slice(&sockaddr_in((i.addr, 0))),
            SIOCGIFBRDADDR => req[16..32].copy_from_slice(&sockaddr_in((i.broadcast(), 0))),
            SIOCGIFNETMASK => req[16..32].copy_from_slice(&sockaddr_in((i.netmask(), 0))),
            SIOCGIFMTU => req[16..20].copy_from_slice(&i.mtu.to_le_bytes()),
            SIOCGIFHWADDR => {
                req[16..32].fill(0);
                req[16..18].copy_from_slice(&i.hardware_type().to_le_bytes());
                req[18..24].copy_from_slice(&i.mac);
            }
            SIOCGIFTXQLEN => req[16..20].copy_from_slice(&1000u32.to_le_bytes()),
            _ => req[16..20].copy_from_slice(&i.index.to_le_bytes()),
        }
        if p.copy_to_user(arg, &req) != 40 {
            return Err(EFAULT);
        }
        Ok(0)
    })())
}

/// `SIOCGIFCONF`: an `ifconf` (`int len; char *buf`) to fill with an `ifreq`
/// for each interface that has an address; with no buffer, only the length.
fn ifconf(p: &mut LinuxProcess, all: &[Iface], arg: u64) -> Result<u64, i64> {
    let mut b = [0u8; 16];
    if p.copy_from_user(arg, &mut b) != 16 {
        return Err(EFAULT);
    }
    let room = i32::from_le_bytes([b[0], b[1], b[2], b[3]]).max(0) as usize;
    let buf = super::le_u64(&b[8..16]);
    let mut out = Vec::new();
    for i in all {
        let mut req = [0u8; 40];
        req[..i.name.len()].copy_from_slice(i.name.as_bytes());
        req[16..32].copy_from_slice(&sockaddr_in((i.addr, 0)));
        out.extend_from_slice(&req);
    }
    if buf != 0 {
        out.truncate(room / 40 * 40);
        if p.copy_to_user(buf, &out) != out.len() {
            return Err(EFAULT);
        }
    }
    if p.copy_to_user(arg, &(out.len() as u32).to_le_bytes()) != 4 {
        return Err(EFAULT);
    }
    Ok(0)
}
