//! BSD sockets on the calling cell's network stack (`netstack.rs`,
//! ADR-0010 §4): `AF_INET` + `SOCK_STREAM` (TCP). A socket is a kernel
//! object behind a descriptor, so read/write/poll/epoll/sendfile and
//! `fstat` work on it like on the other objects.
//!
//! Partial: no `SOCK_DGRAM`, `AF_INET6` or `AF_UNIX` yet (EAFNOSUPPORT /
//! ESOCKTNOSUPPORT); `MSG_PEEK` and out-of-band data are unsupported;
//! socket options are recorded and reported back, and only `SO_ERROR`,
//! `SO_TYPE` and `SO_REUSEADDR` change behavior.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use frame::sync::SpinLock;

use super::EFAULT;
use crate::netstack::{self, Addr, Stack, Waiters};
use crate::poll::{Object, Watchers};
use crate::proc;
use crate::process::{Fd, LinuxProcess, ObjectEnd};
use crate::signal;

const EAGAIN: i64 = 11;
const EBADF: i64 = 9;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOTSOCK: i64 = 88;
const ENOPROTOOPT: i64 = 92;
const EPROTONOSUPPORT: i64 = 93;
const ESOCKTNOSUPPORT: i64 = 94;
const EAFNOSUPPORT: i64 = 97;

const AF_INET: u16 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2_000_000;
const IPPROTO_TCP: u64 = 6;

const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_LINGER: u64 = 13;
const SO_REUSEPORT: u64 = 15;
const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
const SO_ACCEPTCONN: u64 = 30;
const TCP_NODELAY: u64 = 1;
const TCP_KEEPIDLE: u64 = 4;
const TCP_KEEPINTVL: u64 = 5;
const TCP_KEEPCNT: u64 = 6;

const MSG_PEEK: u64 = 0x2;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;

/// Largest single read or write moved through the kernel at once.
const CHUNK: usize = 64 * 1024;

/// A TCP socket: one socket of its cell's stack.
#[derive(Debug)]
pub(crate) struct Socket {
    stack: Arc<Stack>,
    id: u64,
    wait: Arc<Waiters>,
    listening: AtomicBool,
    opts: SpinLock<Vec<SockOpt>>,
}

/// An option recorded for getsockopt: `((level, name), value bytes)`.
type SockOpt = ((u64, u64), Vec<u8>);

impl Socket {
    fn new(stack: Arc<Stack>, id: u64, wait: Arc<Waiters>) -> Socket {
        Socket {
            stack,
            id,
            wait,
            listening: AtomicBool::new(false),
            opts: SpinLock::new(Vec::new()),
        }
    }

    fn id(&self) -> u64 {
        self.id
    }

    /// The stack-wide socket number, for `/proc/<pid>/fd` links.
    pub(crate) fn inode(&self) -> u64 {
        (self.stack.cell << 32) | (self.id & 0xffff_ffff)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.stack.release(self.id);
    }
}

/// Blocks on `s` until `attempt` yields, honoring non-blocking mode and
/// signals.
fn block<T>(
    s: &Socket,
    nonblock: bool,
    interrupted: &dyn Fn() -> bool,
    mut attempt: impl FnMut() -> Option<Result<T, i64>>,
) -> Result<T, i64> {
    s.wait.queue.wait_until(|| match attempt() {
        Some(r) => Some(r),
        None if nonblock => Some(Err(EAGAIN)),
        None if interrupted() => Some(Err(signal::ERESTARTSYS)),
        None => None,
    })
}

impl Object for Socket {
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        let mut buf = alloc::vec![0u8; max.min(CHUNK)];
        let id = self.id();
        let n = block(self, nonblock, interrupted, || {
            self.stack.recv(id, &mut buf, false).transpose()
        })?;
        buf.truncate(n);
        Ok(buf)
    }

    fn write(
        &self,
        data: &[u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        if data.is_empty() {
            return Ok(0);
        }
        let id = self.id();
        block(self, nonblock, interrupted, || {
            match self.stack.send(id, &data[..data.len().min(CHUNK)]) {
                Ok(0) => None,
                r => Some(r),
            }
        })
    }

    fn poll(&self) -> u16 {
        self.stack.poll(self.id())
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

    fn socket(&self) -> Option<&Socket> {
        Some(self)
    }
}

fn read_addr(p: &mut LinuxProcess, addr: u64, len: u64) -> Result<Addr, i64> {
    if len < 16 {
        return Err(EINVAL);
    }
    let mut b = [0u8; 16];
    if p.copy_from_user(addr, &mut b) != 16 {
        return Err(EFAULT);
    }
    if u16::from_le_bytes([b[0], b[1]]) != AF_INET {
        return Err(EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes([b[2], b[3]]);
    let ip = net::Ipv4Addr::new(b[4], b[5], b[6], b[7]);
    Ok((ip, port))
}

/// Writes `a` to a user `sockaddr` whose buffer length is at `lenp`.
fn write_addr(p: &mut LinuxProcess, addr: u64, lenp: u64, a: Addr) -> Result<(), i64> {
    if addr == 0 || lenp == 0 {
        return Ok(());
    }
    let mut lb = [0u8; 4];
    if p.copy_from_user(lenp, &mut lb) != 4 {
        return Err(EFAULT);
    }
    let room = u32::from_le_bytes(lb) as usize;
    let mut b = [0u8; 16];
    b[..2].copy_from_slice(&AF_INET.to_le_bytes());
    b[2..4].copy_from_slice(&a.1.to_be_bytes());
    b[4..8].copy_from_slice(&a.0.octets());
    let n = room.min(16);
    if p.copy_to_user(addr, &b[..n]) != n || p.copy_to_user(lenp, &16u32.to_le_bytes()) != 4 {
        return Err(EFAULT);
    }
    Ok(())
}

/// The socket behind `fd` and whether it is non-blocking.
fn sock_of(p: &LinuxProcess, fd: u64) -> Result<(Arc<dyn Object>, bool), i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Object(o) if o.obj.socket().is_some() => Ok((o.obj, o.nonblock)),
        _ => Err(ENOTSOCK),
    }
}

fn install(p: &mut LinuxProcess, s: Socket, nonblock: bool, cloexec: bool) -> Result<u64, i64> {
    p.install_flags(
        Fd::Object(ObjectEnd {
            obj: Arc::new(s),
            nonblock,
        }),
        cloexec,
    )
    .ok_or(EMFILE)
}

/// `socket(domain, type, protocol)`.
pub(super) fn socket(p: &mut LinuxProcess, domain: u64, ty: u64, proto: u64) -> Result<u64, i64> {
    if domain != u64::from(AF_INET) {
        return Err(EAFNOSUPPORT);
    }
    if ty & 0xf != SOCK_STREAM {
        return Err(ESOCKTNOSUPPORT);
    }
    if proto != 0 && proto != IPPROTO_TCP {
        return Err(EPROTONOSUPPORT);
    }
    let stack = netstack::stack_for(p.cell.id());
    let (id, wait) = stack.socket();
    let s = Socket::new(stack, id, wait);
    install(p, s, ty & SOCK_NONBLOCK != 0, ty & SOCK_CLOEXEC != 0)
}

pub(super) fn bind(p: &mut LinuxProcess, fd: u64, addr: u64, len: u64) -> Result<u64, i64> {
    let (o, _) = sock_of(p, fd)?;
    let a = read_addr(p, addr, len)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    s.stack.bind(s.id(), a).map(|()| 0)
}

pub(super) fn listen(p: &mut LinuxProcess, fd: u64, backlog: u64) -> Result<u64, i64> {
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let backlog = (backlog as i32).clamp(1, 4096) as usize;
    s.stack.listen(s.id(), backlog)?;
    s.listening.store(true, Ordering::Release);
    Ok(0)
}

/// `accept4(fd, addr, addrlen, flags)` (and `accept`, flags 0).
pub(super) fn accept4(
    p: &mut LinuxProcess,
    fd: u64,
    addr: u64,
    lenp: u64,
    flags: u64,
) -> Result<u64, i64> {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let (o, nonblock) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let entry = p.entry.clone();
    let id = s.id();
    let (cid, wait, peer) = block(s, nonblock, &|| proc::interrupted(&entry), || {
        s.stack.accept(id).transpose()
    })?;
    let new = Socket::new(s.stack.clone(), cid, wait);
    write_addr(p, addr, lenp, peer)?;
    install(
        p,
        new,
        flags & SOCK_NONBLOCK != 0,
        flags & SOCK_CLOEXEC != 0,
    )
}

pub(super) fn connect(p: &mut LinuxProcess, fd: u64, addr: u64, len: u64) -> Result<u64, i64> {
    let (o, nonblock) = sock_of(p, fd)?;
    let a = read_addr(p, addr, len)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let id = s.id();
    match s.stack.connect(id, a) {
        Ok(()) => {}
        // A second connect on a socket already connecting or connected.
        Err(netstack::EISCONN) => {
            return match s.stack.connect_result(id) {
                None => Err(netstack::EALREADY),
                Some(Ok(())) => Err(netstack::EISCONN),
                Some(Err(e)) => Err(e),
            };
        }
        Err(e) => return Err(e),
    }
    if nonblock {
        return match s.stack.connect_result(id) {
            Some(r) => r.map(|()| 0),
            None => Err(netstack::EINPROGRESS),
        };
    }
    let entry = p.entry.clone();
    block(s, false, &|| proc::interrupted(&entry), || {
        s.stack.connect_result(id)
    })
    .map(|()| 0)
}

pub(super) fn getsockname(p: &mut LinuxProcess, fd: u64, addr: u64, lenp: u64) -> Result<u64, i64> {
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let a = s.stack.local_addr(s.id())?;
    write_addr(p, addr, lenp, a).map(|()| 0)
}

pub(super) fn getpeername(p: &mut LinuxProcess, fd: u64, addr: u64, lenp: u64) -> Result<u64, i64> {
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let a = s.stack.peer_addr(s.id())?;
    write_addr(p, addr, lenp, a).map(|()| 0)
}

fn known_option(level: u64, name: u64) -> bool {
    match level {
        SOL_SOCKET => matches!(
            name,
            SO_REUSEADDR
                | SO_TYPE
                | SO_ERROR
                | SO_SNDBUF
                | SO_RCVBUF
                | SO_KEEPALIVE
                | SO_LINGER
                | SO_REUSEPORT
                | SO_RCVTIMEO
                | SO_SNDTIMEO
                | SO_ACCEPTCONN
        ),
        IPPROTO_TCP => matches!(
            name,
            TCP_NODELAY | TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT
        ),
        _ => false,
    }
}

pub(super) fn setsockopt(
    p: &mut LinuxProcess,
    fd: u64,
    level: u64,
    name: u64,
    val: u64,
    len: u64,
) -> Result<u64, i64> {
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    if !known_option(level, name)
        || matches!(
            (level, name),
            (SOL_SOCKET, SO_TYPE | SO_ERROR | SO_ACCEPTCONN)
        )
    {
        return Err(ENOPROTOOPT);
    }
    let len = usize::try_from(len).map_err(|_| EINVAL)?.min(64);
    let mut v = alloc::vec![0u8; len];
    if p.copy_from_user(val, &mut v) != len {
        return Err(EFAULT);
    }
    if (level, name) == (SOL_SOCKET, SO_REUSEADDR) {
        let on = v.iter().any(|&b| b != 0);
        s.stack.set_reuse_addr(s.id(), on)?;
    }
    let mut opts = s.opts.lock();
    opts.retain(|(k, _)| *k != (level, name));
    opts.push(((level, name), v));
    Ok(0)
}

pub(super) fn getsockopt(
    p: &mut LinuxProcess,
    fd: u64,
    level: u64,
    name: u64,
    val: u64,
    lenp: u64,
) -> Result<u64, i64> {
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    if !known_option(level, name) {
        return Err(ENOPROTOOPT);
    }
    let int = |v: i32| v.to_le_bytes().to_vec();
    let value = match (level, name) {
        (SOL_SOCKET, SO_TYPE) => int(SOCK_STREAM as i32),
        (SOL_SOCKET, SO_ERROR) => int(s.stack.take_error(s.id()) as i32),
        (SOL_SOCKET, SO_REUSEADDR) => int(i32::from(s.stack.reuse_addr(s.id()))),
        (SOL_SOCKET, SO_ACCEPTCONN) => int(i32::from(s.listening.load(Ordering::Acquire))),
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => s
            .opts
            .lock()
            .iter()
            .find(|(k, _)| *k == (level, name))
            .map_or_else(|| int(net::tcp::BUFFER as i32), |(_, v)| v.clone()),
        _ => s
            .opts
            .lock()
            .iter()
            .find(|(k, _)| *k == (level, name))
            .map_or_else(|| int(0), |(_, v)| v.clone()),
    };
    let mut lb = [0u8; 4];
    if p.copy_from_user(lenp, &mut lb) != 4 {
        return Err(EFAULT);
    }
    let n = (u32::from_le_bytes(lb) as usize).min(value.len());
    if p.copy_to_user(val, &value[..n]) != n || p.copy_to_user(lenp, &(n as u32).to_le_bytes()) != 4
    {
        return Err(EFAULT);
    }
    Ok(0)
}

/// Sends `data` on `fd` with `flags`; EPIPE raises SIGPIPE unless
/// `MSG_NOSIGNAL`.
fn send_bytes(p: &mut LinuxProcess, fd: u64, data: &[u8], flags: u64) -> Result<u64, i64> {
    let (o, nonblock) = sock_of(p, fd)?;
    let entry = p.entry.clone();
    let r = o.write(data, nonblock || flags & MSG_DONTWAIT != 0, &|| {
        proc::interrupted(&entry)
    });
    if r == Err(netstack::EPIPE) && flags & MSG_NOSIGNAL == 0 {
        proc::post(&p.entry, signal::SIGPIPE);
    }
    r.map(|n| n as u64)
}

fn recv_bytes(p: &mut LinuxProcess, fd: u64, max: usize, flags: u64) -> Result<Vec<u8>, i64> {
    if flags & MSG_PEEK != 0 {
        return Err(netstack::EOPNOTSUPP);
    }
    let (o, nonblock) = sock_of(p, fd)?;
    let entry = p.entry.clone();
    o.read(max, nonblock || flags & MSG_DONTWAIT != 0, &|| {
        proc::interrupted(&entry)
    })
}

/// `sendto(fd, buf, len, flags, addr, addrlen)`: the address is ignored on
/// a connected stream socket, as on Linux.
pub(super) fn sendto(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let len = usize::try_from(a[2]).map_err(|_| EINVAL)?.min(CHUNK);
    let mut data = alloc::vec![0u8; len];
    if p.copy_from_user(a[1], &mut data) != len {
        return Err(EFAULT);
    }
    send_bytes(p, a[0], &data, a[3])
}

/// `recvfrom(fd, buf, len, flags, addr, addrlen)`.
pub(super) fn recvfrom(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let max = usize::try_from(a[2]).map_err(|_| EINVAL)?;
    let data = recv_bytes(p, a[0], max, a[3])?;
    if p.copy_to_user(a[1], &data) != data.len() {
        return Err(EFAULT);
    }
    if a[4] != 0 {
        let (o, _) = sock_of(p, a[0])?;
        if let Some(s) = o.socket()
            && let Ok(peer) = s.stack.peer_addr(s.id())
        {
            write_addr(p, a[4], a[5], peer)?;
        }
    }
    Ok(data.len() as u64)
}

/// The iovecs of a user `msghdr`: (base, len) pairs.
fn msg_iov(p: &mut LinuxProcess, msg: u64) -> Result<Vec<(u64, usize)>, i64> {
    let mut h = [0u8; 56];
    if p.copy_from_user(msg, &mut h) != 56 {
        return Err(EFAULT);
    }
    let u = |at: usize| u64::from_le_bytes(h[at..at + 8].try_into().unwrap_or([0; 8]));
    let (iov, n) = (u(16), u(24));
    if n > 1024 {
        return Err(EINVAL);
    }
    let mut v = Vec::new();
    for i in 0..n {
        let mut e = [0u8; 16];
        if p.copy_from_user(iov + i * 16, &mut e) != 16 {
            return Err(EFAULT);
        }
        let base = u64::from_le_bytes(e[..8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(e[8..].try_into().unwrap_or([0; 8]));
        v.push((base, usize::try_from(len).map_err(|_| EINVAL)?));
    }
    Ok(v)
}

pub(super) fn sendmsg(p: &mut LinuxProcess, fd: u64, msg: u64, flags: u64) -> Result<u64, i64> {
    let iov = msg_iov(p, msg)?;
    let mut data = Vec::new();
    for (base, len) in iov {
        let take = len.min(CHUNK - data.len());
        let at = data.len();
        data.resize(at + take, 0);
        if p.copy_from_user(base, &mut data[at..]) != take {
            return Err(EFAULT);
        }
        if data.len() == CHUNK {
            break;
        }
    }
    send_bytes(p, fd, &data, flags)
}

pub(super) fn recvmsg(p: &mut LinuxProcess, fd: u64, msg: u64, flags: u64) -> Result<u64, i64> {
    let iov = msg_iov(p, msg)?;
    let total: usize = iov.iter().map(|&(_, l)| l).sum();
    let data = recv_bytes(p, fd, total, flags)?;
    let mut at = 0;
    for (base, len) in iov {
        if at >= data.len() {
            break;
        }
        let n = len.min(data.len() - at);
        if p.copy_to_user(base, &data[at..at + n]) != n {
            return Err(EFAULT);
        }
        at += n;
    }
    // No address, no control messages, no flags.
    let zero = [0u8; 8];
    if p.copy_to_user(msg + 8, &zero[..4]) != 4
        || p.copy_to_user(msg + 40, &zero) != 8
        || p.copy_to_user(msg + 48, &zero[..4]) != 4
    {
        return Err(EFAULT);
    }
    Ok(data.len() as u64)
}

pub(super) fn shutdown(p: &mut LinuxProcess, fd: u64, how: u64) -> Result<u64, i64> {
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let (rd, wr) = match how {
        0 => (true, false),
        1 => (false, true),
        2 => (true, true),
        _ => return Err(EINVAL),
    };
    s.stack.shutdown(s.id(), rd, wr).map(|()| 0)
}
