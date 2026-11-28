//! BSD sockets on the calling cell's network stack (`netstack.rs`,
//! ADR-0010 §4): `AF_INET` + `SOCK_STREAM` (TCP) and `SOCK_DGRAM` (UDP).
//! A socket is a kernel object behind a descriptor, so read/write/poll/
//! epoll/sendfile and `fstat` work on it like on the other objects. On a
//! datagram socket every read takes one datagram (the rest of a longer one
//! is discarded, `MSG_TRUNC` in `recvmsg`) and every write sends one.
//!
//! Partial: no `AF_INET6` (EAFNOSUPPORT); out-of-band data is unsupported;
//! socket options are recorded and reported back, and only `SO_REUSEADDR`,
//! `SO_RCVTIMEO`, `SO_SNDTIMEO` and `SO_LINGER` without a time (close
//! resets) change behavior.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use frame::sync::SpinLock;

use super::{EFAULT, fs, netlink, unix};
use crate::netstack::{self, Addr, Stack, Waiters};
use crate::poll::{Object, Watchers};
use crate::proc;
use crate::process::{Fd, LinuxProcess, ObjectEnd};
use crate::signal;

const EINTR: i64 = 4;
const EAGAIN: i64 = 11;
const EACCES: i64 = 13;
const EBADF: i64 = 9;
const EDOM: i64 = 33;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOTSOCK: i64 = 88;
const ENOPROTOOPT: i64 = 92;
const EPROTONOSUPPORT: i64 = 93;
const ESOCKTNOSUPPORT: i64 = 94;
const EAFNOSUPPORT: i64 = 97;

const AF_UNSPEC: u16 = 0;
const AF_INET: u16 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2_000_000;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;
const MSG_TRUNC: u64 = 0x20;

const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_DONTROUTE: u64 = 5;
const SO_BROADCAST: u64 = 6;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_OOBINLINE: u64 = 10;
const SO_PRIORITY: u64 = 12;
const SO_LINGER: u64 = 13;
const SO_REUSEPORT: u64 = 15;
pub(super) const SO_RCVTIMEO: u64 = 20;
pub(super) const SO_SNDTIMEO: u64 = 21;
const SO_ACCEPTCONN: u64 = 30;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const IPPROTO_IP: u64 = 0;
const IP_TOS: u64 = 1;
const IP_TTL: u64 = 2;
const IP_MTU_DISCOVER: u64 = 10;
/// Errors to the socket's error queue too. (It is always empty: the one
/// error there is, ECONNREFUSED, is the socket's. But glibc's resolver
/// gives up if it may not set this.)
const IP_RECVERR: u64 = 11;
const IP_FREEBIND: u64 = 15;
const IP_BIND_ADDRESS_NO_PORT: u64 = 24;
const IP_MULTICAST_IF: u64 = 32;
const IP_MULTICAST_TTL: u64 = 33;
const IP_MULTICAST_LOOP: u64 = 34;
const TCP_NODELAY: u64 = 1;
const TCP_MAXSEG: u64 = 2;
const TCP_SYNCNT: u64 = 7;
const TCP_LINGER2: u64 = 8;
const TCP_WINDOW_CLAMP: u64 = 10;
const TCP_INFO: u64 = 11;
const TCP_NOTSENT_LOWAT: u64 = 25;
/// nginx corks around `sendfile` (`TCP_NOPUSH`); our TCP sends what it
/// has at once, so corking is recorded and changes nothing.
const TCP_CORK: u64 = 3;
const TCP_KEEPIDLE: u64 = 4;
const TCP_KEEPINTVL: u64 = 5;
const TCP_KEEPCNT: u64 = 6;
const TCP_DEFER_ACCEPT: u64 = 9;
const TCP_QUICKACK: u64 = 12;
const TCP_USER_TIMEOUT: u64 = 18;
const TCP_FASTOPEN: u64 = 23;

const MSG_PEEK: u64 = 0x2;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_ERRQUEUE: u64 = 0x2000;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_WAITFORONE: u64 = 0x10000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;

/// Largest single read or write moved through the kernel at once.
const CHUNK: usize = 64 * 1024;

/// A TCP or UDP socket: one socket of its cell's stack.
#[derive(Debug)]
pub(crate) struct Socket {
    stack: Arc<Stack>,
    id: u64,
    wait: Arc<Waiters>,
    /// UDP (`SOCK_DGRAM`).
    dgram: bool,
    listening: AtomicBool,
    /// A `connect` started and has not reported its outcome yet.
    connecting: AtomicBool,
    /// `SO_LINGER` with no time: closing resets the connection.
    reset_on_close: AtomicBool,
    timeouts: Timeouts,
    opts: SpinLock<Vec<SockOpt>>,
}

/// An option recorded for getsockopt: `((level, name), value bytes)`.
type SockOpt = ((u64, u64), Vec<u8>);

impl Socket {
    /// Whether its data has no bounds.
    pub(super) fn is_stream(&self) -> bool {
        !self.dgram
    }

    fn new(stack: Arc<Stack>, id: u64, wait: Arc<Waiters>, dgram: bool) -> Socket {
        Socket {
            stack,
            id,
            wait,
            dgram,
            listening: AtomicBool::new(false),
            connecting: AtomicBool::new(false),
            reset_on_close: AtomicBool::new(false),
            timeouts: Timeouts::default(),
            opts: SpinLock::new(Vec::new()),
        }
    }

    /// Receives one datagram (blocking as asked): its source and bytes.
    fn recv_datagram(
        &self,
        nonblock: bool,
        peek: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<(Addr, Vec<u8>), i64> {
        block_recv(self, nonblock, interrupted, || {
            self.stack.recv_from(self.id, peek).transpose()
        })
    }

    /// Receives some of a stream (blocking as asked): up to `max` bytes,
    /// left in place if `peek`.
    fn recv_stream(
        &self,
        max: usize,
        nonblock: bool,
        peek: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        let mut buf = alloc::vec![0u8; max.min(CHUNK)];
        let n = block_recv(self, nonblock, interrupted, || {
            self.stack.recv(self.id, &mut buf, peek).transpose()
        })?;
        buf.truncate(n);
        Ok(buf)
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
        self.stack
            .release(self.id, self.reset_on_close.load(Ordering::Relaxed));
    }
}

/// `SO_RCVTIMEO` and `SO_SNDTIMEO`, in nanoseconds (0: wait forever).
#[derive(Debug, Default)]
pub(super) struct Timeouts {
    pub(super) recv: AtomicU64,
    pub(super) send: AtomicU64,
}

impl Timeouts {
    fn of(&self, name: u64) -> &AtomicU64 {
        if name == SO_RCVTIMEO {
            &self.recv
        } else {
            &self.send
        }
    }

    /// Sets one from a `struct timeval`.
    pub(super) fn set(&self, name: u64, v: &[u8]) -> Result<(), i64> {
        let word = |at: usize| v.get(at..at + 8).map(super::le_u64).ok_or(EINVAL);
        let (sec, usec) = (word(0)? as i64, word(8)? as i64);
        if !(0..1_000_000).contains(&usec) {
            return Err(EDOM);
        }
        let ns = u64::try_from(sec)
            .unwrap_or(0)
            .saturating_mul(1_000_000_000)
            .saturating_add(usec as u64 * 1000);
        self.of(name).store(ns, Ordering::Relaxed);
        Ok(())
    }

    /// One as a `struct timeval`.
    pub(super) fn get(&self, name: u64) -> Vec<u8> {
        let ns = self.of(name).load(Ordering::Relaxed);
        let mut v = (ns / 1_000_000_000).to_le_bytes().to_vec();
        v.extend_from_slice(&(ns % 1_000_000_000 / 1000).to_le_bytes());
        v
    }
}

/// Blocks on `w` until `attempt` yields, honoring non-blocking mode,
/// `timeout` (nanoseconds, 0 for none; EAGAIN when it passes) and signals
/// (which a call with a timeout does not restart after, as on Linux).
pub(super) fn block_on<T>(
    w: &Waiters,
    nonblock: bool,
    timeout: u64,
    interrupted: &dyn Fn() -> bool,
    mut attempt: impl FnMut() -> Option<Result<T, i64>>,
) -> Result<T, i64> {
    let cond = || match attempt() {
        Some(r) => Some(r),
        None if nonblock => Some(Err(EAGAIN)),
        None if interrupted() => Some(Err(if timeout == 0 {
            signal::ERESTARTSYS
        } else {
            EINTR
        })),
        None => None,
    };
    if timeout == 0 {
        return w.queue.wait_until(cond);
    }
    let deadline = frame::time::now().saturating_add(Duration::from_nanos(timeout));
    w.queue
        .wait_until_deadline(deadline, cond)
        .unwrap_or(Err(EAGAIN))
}

/// [`block_on`] a socket to receive (or accept).
fn block_recv<T>(
    s: &Socket,
    nonblock: bool,
    interrupted: &dyn Fn() -> bool,
    attempt: impl FnMut() -> Option<Result<T, i64>>,
) -> Result<T, i64> {
    let t = s.timeouts.recv.load(Ordering::Relaxed);
    block_on(&s.wait, nonblock, t, interrupted, attempt)
}

/// [`block_on`] a socket to send (or connect).
fn block_send<T>(
    s: &Socket,
    nonblock: bool,
    interrupted: &dyn Fn() -> bool,
    attempt: impl FnMut() -> Option<Result<T, i64>>,
) -> Result<T, i64> {
    let t = s.timeouts.send.load(Ordering::Relaxed);
    block_on(&s.wait, nonblock, t, interrupted, attempt)
}

impl Object for Socket {
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        if self.dgram {
            let (_, mut d) = self.recv_datagram(nonblock, false, interrupted)?;
            d.truncate(max);
            return Ok(d);
        }
        self.recv_stream(max, nonblock, false, interrupted)
    }

    fn write(
        &self,
        data: &[u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        if self.dgram {
            // A datagram is sent whole or not at all; nothing blocks.
            return self.stack.send_to(self.id, None, data);
        }
        // Everything, however long that takes (what fits, if it may not
        // wait); an error after some went reports what went.
        let id = self.id();
        let mut done = 0;
        while done < data.len() {
            let next = &data[done..data.len().min(done + CHUNK)];
            match block_send(self, nonblock, interrupted, || {
                match self.stack.send(id, next) {
                    Ok(0) => None,
                    r => Some(r),
                }
            }) {
                Ok(n) => done += n,
                Err(e) if done == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(done)
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

    fn readable(&self) -> Option<usize> {
        Some(self.stack.readable(self.id))
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

/// `a` as a `struct sockaddr_in`.
pub(super) fn sockaddr(a: Addr) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..2].copy_from_slice(&AF_INET.to_le_bytes());
    b[2..4].copy_from_slice(&a.1.to_be_bytes());
    b[4..8].copy_from_slice(&a.0.octets());
    b
}

/// Writes the `sockaddr` `b` to user memory at `addr`, whose buffer length
/// is at `lenp` (in: the room; out: the address's length).
pub(super) fn write_sockaddr(
    p: &mut LinuxProcess,
    addr: u64,
    lenp: u64,
    b: &[u8],
) -> Result<(), i64> {
    if addr == 0 || lenp == 0 {
        return Ok(());
    }
    let mut lb = [0u8; 4];
    if p.copy_from_user(lenp, &mut lb) != 4 {
        return Err(EFAULT);
    }
    let n = (u32::from_le_bytes(lb) as usize).min(b.len());
    if p.copy_to_user(addr, &b[..n]) != n
        || p.copy_to_user(lenp, &(b.len() as u32).to_le_bytes()) != 4
    {
        return Err(EFAULT);
    }
    Ok(())
}

/// Writes `a` to a user `sockaddr` whose buffer length is at `lenp`.
fn write_addr(p: &mut LinuxProcess, addr: u64, lenp: u64, a: Addr) -> Result<(), i64> {
    write_sockaddr(p, addr, lenp, &sockaddr(a))
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
    if domain == unix::AF_UNIX {
        return unix::socket(p, ty, proto);
    }
    if domain == netlink::AF_NETLINK {
        return netlink::socket(p, ty, proto);
    }
    if domain != u64::from(AF_INET) {
        return Err(EAFNOSUPPORT);
    }
    let dgram = match ty & 0xf {
        SOCK_STREAM => false,
        SOCK_DGRAM => true,
        // CAP_NET_RAW is outside the cell bounding set (ADR-0009 §3).
        SOCK_RAW => return Err(super::EPERM),
        _ => return Err(ESOCKTNOSUPPORT),
    };
    let want = if dgram { IPPROTO_UDP } else { IPPROTO_TCP };
    if proto != 0 && proto != want {
        return Err(EPROTONOSUPPORT);
    }
    let stack = netstack::stack_for(&p.cell);
    let (id, wait) = stack.socket(dgram);
    let s = Socket::new(stack, id, wait, dgram);
    install(p, s, ty & SOCK_NONBLOCK != 0, ty & SOCK_CLOEXEC != 0)
}

/// `socketpair(domain, ty, proto, sv)`: `AF_UNIX` only, as on Linux.
pub(super) fn socketpair(
    p: &mut LinuxProcess,
    domain: u64,
    ty: u64,
    proto: u64,
    sv: u64,
) -> Result<u64, i64> {
    match domain {
        unix::AF_UNIX => unix::socketpair(p, ty, proto, sv),
        d if d == u64::from(AF_INET) => Err(netstack::EOPNOTSUPP),
        _ => Err(EAFNOSUPPORT),
    }
}

pub(super) fn bind(p: &mut LinuxProcess, fd: u64, addr: u64, len: u64) -> Result<u64, i64> {
    if let Some((o, _)) = unix::of(p, fd) {
        return unix::bind(p, unix::sock(&o)?, addr, len);
    }
    if let Some((o, _)) = netlink::of(p, fd) {
        return netlink::bind(p, netlink::sock(&o)?, addr, len);
    }
    let (o, _) = sock_of(p, fd)?;
    let a = read_addr(p, addr, len)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    if s.stack.needs_bind_service(a.1) && !p.group.creds().has(crate::cred::cap::NET_BIND_SERVICE) {
        return Err(EACCES);
    }
    s.stack.bind(s.id(), a).map(|()| 0)
}

pub(super) fn listen(p: &mut LinuxProcess, fd: u64, backlog: u64) -> Result<u64, i64> {
    if let Some((o, _)) = unix::of(p, fd) {
        return unix::listen(p, unix::sock(&o)?, backlog);
    }
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
    if let Some((o, nonblock)) = unix::of(p, fd) {
        return unix::accept(p, unix::sock(&o)?, nonblock, addr, lenp, flags);
    }
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let (o, nonblock) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let entry = p.entry.clone();
    let id = s.id();
    let (cid, wait, peer) = block_recv(s, nonblock, &|| proc::interrupted(&entry), || {
        s.stack.accept(id).transpose()
    })?;
    let new = Socket::new(s.stack.clone(), cid, wait, false);
    write_addr(p, addr, lenp, peer)?;
    install(
        p,
        new,
        flags & SOCK_NONBLOCK != 0,
        flags & SOCK_CLOEXEC != 0,
    )
}

pub(super) fn connect(p: &mut LinuxProcess, fd: u64, addr: u64, len: u64) -> Result<u64, i64> {
    if let Some((o, nonblock)) = unix::of(p, fd) {
        return unix::connect(p, unix::sock(&o)?, nonblock, addr, len);
    }
    if let Some((o, _)) = netlink::of(p, fd) {
        return netlink::connect(p, netlink::sock(&o)?, addr, len);
    }
    let (o, nonblock) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let id = s.id();
    if s.dgram {
        // AF_UNSPEC dissolves the association; an address sets the peer.
        let mut fam = [0u8; 2];
        if len >= 2 && p.copy_from_user(addr, &mut fam) == 2 && u16::from_le_bytes(fam) == AF_UNSPEC
        {
            return s.stack.disconnect(id).map(|()| 0);
        }
        let a = read_addr(p, addr, len)?;
        return s.stack.connect(id, a).map(|()| 0);
    }
    let a = read_addr(p, addr, len)?;
    match s.stack.connect(id, a) {
        Ok(()) => s.connecting.store(true, Ordering::Relaxed),
        // Connecting already: a non-blocking caller learns the outcome once
        // it is known, a blocking one (restarted after a signal) waits on.
        Err(netstack::EISCONN) if s.connecting.load(Ordering::Relaxed) => {
            if nonblock {
                let r = s.stack.connect_result(id).ok_or(netstack::EALREADY)?;
                s.connecting.store(false, Ordering::Relaxed);
                return r.map(|()| 0);
            }
        }
        Err(e) => return Err(e),
    }
    if nonblock {
        // A non-blocking TCP connect is EINPROGRESS even when it is done
        // already (this stack's loopback completes synchronously): Linux
        // answers so, and callers wait for writability, then read
        // SO_ERROR (0 here). An immediate failure is reported as it is.
        return match s.stack.connect_result(id) {
            Some(Err(e)) => {
                s.connecting.store(false, Ordering::Relaxed);
                Err(e)
            }
            Some(Ok(())) | None => Err(netstack::EINPROGRESS),
        };
    }
    let entry = p.entry.clone();
    let r = block_send(s, false, &|| proc::interrupted(&entry), || {
        s.stack.connect_result(id)
    });
    match r {
        // SO_SNDTIMEO passed, or a signal came: the connection goes on.
        Err(EAGAIN) => return Err(netstack::EINPROGRESS),
        Err(EINTR | signal::ERESTARTSYS) => {}
        _ => s.connecting.store(false, Ordering::Relaxed),
    }
    r.map(|()| 0)
}

pub(super) fn getsockname(p: &mut LinuxProcess, fd: u64, addr: u64, lenp: u64) -> Result<u64, i64> {
    if let Some((o, _)) = unix::of(p, fd) {
        return unix::getsockname(p, unix::sock(&o)?, addr, lenp);
    }
    if let Some((o, _)) = netlink::of(p, fd) {
        let me = netlink::sock(&o)?.port();
        return write_sockaddr(p, addr, lenp, &netlink::sockaddr(me)).map(|()| 0);
    }
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let a = s.stack.local_addr(s.id())?;
    write_addr(p, addr, lenp, a).map(|()| 0)
}

pub(super) fn getpeername(p: &mut LinuxProcess, fd: u64, addr: u64, lenp: u64) -> Result<u64, i64> {
    if let Some((o, _)) = unix::of(p, fd) {
        return unix::getpeername(p, unix::sock(&o)?, addr, lenp);
    }
    if netlink::of(p, fd).is_some() {
        return write_sockaddr(p, addr, lenp, &netlink::sockaddr(0)).map(|()| 0);
    }
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    let a = s.stack.peer_addr(s.id())?;
    write_addr(p, addr, lenp, a).map(|()| 0)
}

/// Options of a kind this socket has: those that act (see [`setsockopt`]
/// and [`getsockopt`]), and those that are recorded only.
fn known_option(s: &Socket, level: u64, name: u64) -> bool {
    match level {
        SOL_SOCKET => matches!(
            name,
            SO_REUSEADDR
                | SO_TYPE
                | SO_ERROR
                | SO_DONTROUTE
                | SO_BROADCAST
                | SO_SNDBUF
                | SO_RCVBUF
                | SO_KEEPALIVE
                | SO_OOBINLINE
                | SO_PRIORITY
                | SO_LINGER
                | SO_REUSEPORT
                | SO_RCVTIMEO
                | SO_SNDTIMEO
                | SO_ACCEPTCONN
                | SO_PROTOCOL
                | SO_DOMAIN
        ),
        IPPROTO_IP => matches!(
            name,
            IP_TOS
                | IP_TTL
                | IP_MTU_DISCOVER
                | IP_RECVERR
                | IP_FREEBIND
                | IP_BIND_ADDRESS_NO_PORT
                | IP_MULTICAST_IF
                | IP_MULTICAST_TTL
                | IP_MULTICAST_LOOP
        ),
        IPPROTO_TCP if !s.dgram => matches!(
            name,
            TCP_NODELAY
                | TCP_MAXSEG
                | TCP_CORK
                | TCP_KEEPIDLE
                | TCP_KEEPINTVL
                | TCP_KEEPCNT
                | TCP_SYNCNT
                | TCP_LINGER2
                | TCP_DEFER_ACCEPT
                | TCP_WINDOW_CLAMP
                | TCP_QUICKACK
                | TCP_USER_TIMEOUT
                | TCP_FASTOPEN
                | TCP_NOTSENT_LOWAT
                | TCP_INFO
        ),
        _ => false,
    }
}

/// What an option that was never set reads as (Linux's defaults).
fn option_default(s: &Socket, level: u64, name: u64) -> i32 {
    match (level, name) {
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) if s.dgram => netstack::UDP_BUFFER as i32,
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => net::tcp::BUFFER as i32,
        (IPPROTO_IP, IP_TTL) => 64,
        (IPPROTO_IP, IP_MULTICAST_TTL | IP_MULTICAST_LOOP | IP_MTU_DISCOVER) => 1,
        (IPPROTO_TCP, TCP_MAXSEG) => 536,
        (IPPROTO_TCP, TCP_KEEPIDLE) => 7200,
        (IPPROTO_TCP, TCP_KEEPINTVL) => 75,
        (IPPROTO_TCP, TCP_KEEPCNT) => 9,
        (IPPROTO_TCP, TCP_SYNCNT) => 6,
        (IPPROTO_TCP, TCP_LINGER2) => 60,
        (IPPROTO_TCP, TCP_QUICKACK) => 1,
        _ => 0,
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
    if let Some((o, _)) = unix::of(p, fd) {
        return unix::setsockopt(p, unix::sock(&o)?, level, name, val, len);
    }
    if netlink::of(p, fd).is_some() {
        return netlink::setsockopt(level, name);
    }
    let (o, _) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    if !known_option(s, level, name)
        || matches!(
            (level, name),
            (
                SOL_SOCKET,
                SO_TYPE | SO_ERROR | SO_ACCEPTCONN | SO_PROTOCOL | SO_DOMAIN
            ) | (IPPROTO_TCP, TCP_INFO)
        )
    {
        return Err(ENOPROTOOPT);
    }
    let len = usize::try_from(len).map_err(|_| EINVAL)?.min(64);
    let mut v = alloc::vec![0u8; len];
    if p.copy_from_user(val, &mut v) != len {
        return Err(EFAULT);
    }
    let int = |at: usize| {
        v.get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(i32::from_le_bytes)
            .ok_or(EINVAL)
    };
    match (level, name) {
        (SOL_SOCKET, SO_RCVTIMEO | SO_SNDTIMEO) => {
            s.timeouts.set(name, &v)?;
            return Ok(0);
        }
        (SOL_SOCKET, SO_REUSEADDR) => s.stack.set_reuse_addr(s.id(), int(0)? != 0)?,
        (SOL_SOCKET, SO_REUSEPORT) => {
            s.stack.set_reuse_port(s.id(), int(0)? != 0)?;
            v = int(0)?.to_le_bytes().to_vec();
        }
        // struct linger { int l_onoff, l_linger; }: no time means reset.
        (SOL_SOCKET, SO_LINGER) => {
            let reset = int(0)? != 0 && int(4)? == 0;
            s.reset_on_close.store(reset, Ordering::Relaxed);
        }
        // Linux doubles what is asked, for its own overhead, and reports
        // that. (Buffers here grow with use; this does not size them.)
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => {
            const MAX: i32 = 212_992;
            let twice = int(0)?.clamp(1152, MAX) * 2;
            v = twice.to_le_bytes().to_vec();
        }
        // An address to send multicast from: an `in_addr`, or an `ip_mreq`
        // or `ip_mreqn`, which have it second.
        (IPPROTO_IP, IP_MULTICAST_IF) => {
            let at = if v.len() >= 8 { 4 } else { 0 };
            let b: [u8; 4] = v
                .get(at..at + 4)
                .and_then(|b| b.try_into().ok())
                .ok_or(EINVAL)?;
            let ip = net::Ipv4Addr::from(b);
            if !ip.is_unspecified() && !ip.is_loopback() && s.stack.addr() != Some(ip) {
                return Err(netstack::EADDRNOTAVAIL);
            }
            v = b.to_vec();
        }
        // IP options may be a byte; everything here else is an int.
        (IPPROTO_IP, _) if v.len() == 1 => v = i32::from(v[0]).to_le_bytes().to_vec(),
        _ => v = int(0)?.to_le_bytes().to_vec(),
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
    if let Some((o, _)) = unix::of(p, fd) {
        return unix::getsockopt(p, unix::sock(&o)?, level, name, val, lenp);
    }
    let value = if let Some((o, _)) = netlink::of(p, fd) {
        netlink::getsockopt(netlink::sock(&o)?, level, name)?
    } else {
        let (o, _) = sock_of(p, fd)?;
        option_value(o.socket().ok_or(ENOTSOCK)?, level, name)?
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

/// The value of an option of an inet socket.
fn option_value(s: &Socket, level: u64, name: u64) -> Result<Vec<u8>, i64> {
    if !known_option(s, level, name) {
        return Err(ENOPROTOOPT);
    }
    let int = |v: i32| v.to_le_bytes().to_vec();
    Ok(match (level, name) {
        (SOL_SOCKET, SO_TYPE) => int(if s.dgram { SOCK_DGRAM } else { SOCK_STREAM } as i32),
        (SOL_SOCKET, SO_ERROR) => int(s.stack.take_error(s.id()) as i32),
        (SOL_SOCKET, SO_REUSEADDR) => int(i32::from(s.stack.reuse_addr(s.id()))),
        (SOL_SOCKET, SO_ACCEPTCONN) => int(i32::from(s.listening.load(Ordering::Acquire))),
        (SOL_SOCKET, SO_DOMAIN) => int(i32::from(AF_INET)),
        (SOL_SOCKET, SO_PROTOCOL) => int(if s.dgram { IPPROTO_UDP } else { IPPROTO_TCP } as i32),
        (SOL_SOCKET, SO_RCVTIMEO | SO_SNDTIMEO) => s.timeouts.get(name),
        // A socket that is no connection is listening (10) or closed (7).
        (IPPROTO_TCP, TCP_INFO) => {
            let info = s.stack.tcp_info(s.id()).unwrap_or(net::tcp::Info {
                state: if s.listening.load(Ordering::Acquire) {
                    10
                } else {
                    7
                },
                ..Default::default()
            });
            info.bytes().to_vec()
        }
        _ => {
            let opts = s.opts.lock();
            match opts.iter().find(|(k, _)| *k == (level, name)) {
                Some((_, v)) => v.clone(),
                None if (level, name) == (SOL_SOCKET, SO_LINGER) => alloc::vec![0u8; 8],
                None => int(option_default(s, level, name)),
            }
        }
    })
}

/// Copies `total` bytes of `iov` in from user memory.
fn gather(p: &mut LinuxProcess, iov: &[(u64, usize)], total: usize) -> Result<Vec<u8>, i64> {
    let mut data = alloc::vec![0u8; total];
    let mut at = 0;
    for &(base, len) in iov {
        if p.copy_from_user(base, &mut data[at..at + len]) != len {
            return Err(EFAULT);
        }
        at += len;
    }
    Ok(data)
}

/// Copies `data` out over `iov`.
fn scatter(p: &mut LinuxProcess, iov: &[(u64, usize)], data: &[u8]) -> Result<(), i64> {
    let mut at = 0;
    for &(base, len) in iov {
        let n = len.min(data.len() - at);
        if p.copy_to_user(base, &data[at..at + n]) != n {
            return Err(EFAULT);
        }
        at += n;
    }
    Ok(())
}

/// Sends user memory on `fd` with `flags`: on a datagram socket as one
/// datagram, to the address `name` points at if given (a connected stream
/// socket ignores it, as on Linux); on a stream, all of it (what fits,
/// without blocking). EPIPE raises SIGPIPE unless `MSG_NOSIGNAL`.
fn send_iov(
    p: &mut LinuxProcess,
    fd: u64,
    iov: &[(u64, usize)],
    flags: u64,
    name: (u64, u64),
) -> Result<u64, i64> {
    let total: usize = iov.iter().map(|&(_, n)| n).sum();
    if let Some((o, _)) = netlink::of(p, fd) {
        if total > CHUNK {
            return Err(netstack::EMSGSIZE);
        }
        let data = gather(p, iov, total)?;
        netlink::sock(&o)?.request(&data);
        return Ok(total as u64);
    }
    let (o, nonblock) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    if !s.dgram {
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        let f = Fd::Object(ObjectEnd {
            obj: o.clone(),
            nonblock,
        });
        let sigpipe = flags & MSG_NOSIGNAL == 0;
        return fs::stream_gather(p, &f, iov, nonblock, sigpipe).map(|n| n as u64);
    }
    if total > netstack::UDP_MAX {
        return Err(netstack::EMSGSIZE);
    }
    let data = gather(p, iov, total)?;
    let to = match name {
        (0, _) => None,
        (addr, len) => Some(read_addr(p, addr, len)?),
    };
    s.stack.send_to(s.id(), to, &data).map(|n| n as u64)
}

/// What one receive took.
struct Received {
    data: Vec<u8>,
    /// A datagram's source, as a `sockaddr`.
    from: Option<Vec<u8>>,
    /// A datagram's full length (more than `data` when truncated).
    full: usize,
}

fn recv_bytes(p: &mut LinuxProcess, fd: u64, max: usize, flags: u64) -> Result<Received, i64> {
    let peek = flags & MSG_PEEK != 0;
    let entry = p.entry.clone();
    let interrupted = || proc::interrupted(&entry);
    if let Some((o, nonblock)) = netlink::of(p, fd) {
        let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
        let mut data = netlink::sock(&o)?.recv(nonblock, peek, &interrupted)?;
        let full = data.len();
        data.truncate(max);
        return Ok(Received {
            data,
            from: Some(netlink::sockaddr(0).to_vec()),
            full,
        });
    }
    let (o, nonblock) = sock_of(p, fd)?;
    let s = o.socket().ok_or(ENOTSOCK)?;
    // The error queue, which is never waited for (see `IP_RECVERR`).
    if flags & MSG_ERRQUEUE != 0 {
        return Err(EAGAIN);
    }
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    if s.dgram {
        let (from, mut data) = s.recv_datagram(nonblock, peek, &interrupted)?;
        let full = data.len();
        data.truncate(max);
        return Ok(Received {
            data,
            from: Some(sockaddr(from).to_vec()),
            full,
        });
    }
    let mut data = s.recv_stream(max, nonblock, peek, &interrupted)?;
    // MSG_WAITALL: until that much came, or the stream ends.
    while flags & MSG_WAITALL != 0 && !peek && !data.is_empty() && data.len() < max {
        match s.recv_stream(max - data.len(), nonblock, false, &interrupted) {
            Ok(more) if !more.is_empty() => data.extend_from_slice(&more),
            _ => break,
        }
    }
    Ok(Received {
        full: data.len(),
        data,
        from: None,
    })
}

/// `sendto(fd, buf, len, flags, addr, addrlen)`.
pub(super) fn sendto(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    if let Some((o, nonblock)) = unix::of(p, a[0]) {
        return unix::sendto(p, unix::sock(&o)?, nonblock, a);
    }
    let len = usize::try_from(a[2]).map_err(|_| EINVAL)?;
    send_iov(p, a[0], &[(a[1], len)], a[3], (a[4], a[5]))
}

/// `recvfrom(fd, buf, len, flags, addr, addrlen)`. `MSG_TRUNC` returns a
/// datagram's full length, as on Linux.
pub(super) fn recvfrom(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    if let Some((o, nonblock)) = unix::of(p, a[0]) {
        return unix::recvfrom(p, unix::sock(&o)?, nonblock, a);
    }
    let max = usize::try_from(a[2]).map_err(|_| EINVAL)?;
    let r = recv_bytes(p, a[0], max, a[3])?;
    if p.copy_to_user(a[1], &r.data) != r.data.len() {
        return Err(EFAULT);
    }
    if a[4] != 0 {
        let from = match r.from {
            Some(f) => Some(f),
            None => {
                let (o, _) = sock_of(p, a[0])?;
                o.socket()
                    .and_then(|s| s.stack.peer_addr(s.id()).ok())
                    .map(|a| sockaddr(a).to_vec())
            }
        };
        if let Some(f) = from {
            write_sockaddr(p, a[4], a[5], &f)?;
        }
    }
    let n = if a[3] & MSG_TRUNC != 0 {
        r.full
    } else {
        r.data.len()
    };
    Ok(n as u64)
}

/// A user `msghdr`: its name pointer and length, its iovecs as (base,
/// len) pairs, and its control buffer.
pub(super) struct MsgHdr {
    pub(super) name: u64,
    pub(super) namelen: u64,
    pub(super) iov: Vec<(u64, usize)>,
    pub(super) control: u64,
    pub(super) controllen: u64,
}

pub(super) fn msg_hdr(p: &mut LinuxProcess, msg: u64) -> Result<MsgHdr, i64> {
    let mut h = [0u8; 56];
    if p.copy_from_user(msg, &mut h) != 56 {
        return Err(EFAULT);
    }
    let u = |at: usize| super::le_u64(&h[at..at + 8]);
    let n = usize::try_from(u(24)).map_err(|_| netstack::EMSGSIZE)?;
    Ok(MsgHdr {
        name: u(0),
        namelen: u(8) & 0xffff_ffff,
        // (io_uring may have chosen the buffer.)
        iov: match p.uring.iov.clone() {
            Some(v) => v,
            None => fs::read_iov(p, u(16), n)?,
        },
        control: u(32),
        controllen: u(40),
    })
}

pub(super) fn sendmsg(p: &mut LinuxProcess, fd: u64, msg: u64, flags: u64) -> Result<u64, i64> {
    if let Some((o, nonblock)) = unix::of(p, fd) {
        return unix::sendmsg(p, unix::sock(&o)?, nonblock, msg, flags);
    }
    let h = msg_hdr(p, msg)?;
    send_iov(p, fd, &h.iov, flags, (h.name, h.namelen))
}

pub(super) fn recvmsg(p: &mut LinuxProcess, fd: u64, msg: u64, flags: u64) -> Result<u64, i64> {
    if let Some((o, nonblock)) = unix::of(p, fd) {
        return unix::recvmsg(p, unix::sock(&o)?, nonblock, msg, flags);
    }
    let h = msg_hdr(p, msg)?;
    let total: usize = h.iov.iter().map(|&(_, l)| l).sum();
    let r = recv_bytes(p, fd, total, flags)?;
    scatter(p, &h.iov, &r.data)?;
    // A datagram's source goes to msg_name (msg_namelen is in-out); no
    // control messages; MSG_TRUNC if the datagram was cut.
    match &r.from {
        Some(f) if h.name != 0 => write_sockaddr(p, h.name, msg + 8, f)?,
        _ => {
            if p.copy_to_user(msg + 8, &[0u8; 4]) != 4 {
                return Err(EFAULT);
            }
        }
    }
    let mut mflags = flags & MSG_CMSG_CLOEXEC;
    if r.full > r.data.len() {
        mflags |= MSG_TRUNC;
    }
    if p.copy_to_user(msg + 40, &[0u8; 8]) != 8
        || p.copy_to_user(msg + 48, &(mflags as u32).to_le_bytes()) != 4
    {
        return Err(EFAULT);
    }
    let n = if flags & MSG_TRUNC != 0 {
        r.full
    } else {
        r.data.len()
    };
    Ok(n as u64)
}

/// `struct mmsghdr`: a `msghdr`, then what its message moved.
const MMSGHDR: u64 = 64;
/// Most messages one `sendmmsg` or `recvmmsg` moves (Linux's `UIO_MAXIOV`).
const MMSG_MAX: u64 = 1024;

/// Runs `one` over `vlen` `mmsghdr`s at `vec`, storing each length; stops
/// at the first error, which is reported only if nothing went before it.
fn each_message(
    p: &mut LinuxProcess,
    vec: u64,
    vlen: u64,
    mut one: impl FnMut(&mut LinuxProcess, u64, u64) -> Option<Result<u64, i64>>,
) -> Result<u64, i64> {
    let mut done = 0;
    while done < vlen.min(MMSG_MAX) {
        let msg = vec + done * MMSGHDR;
        match one(p, msg, done) {
            None => break,
            Some(Err(e)) if done == 0 => return Err(e),
            Some(Err(_)) => break,
            Some(Ok(n)) => {
                if p.copy_to_user(msg + 56, &(n as u32).to_le_bytes()) != 4 {
                    return Err(EFAULT);
                }
                done += 1;
            }
        }
    }
    Ok(done)
}

/// `sendmmsg(fd, vec, vlen, flags)`.
pub(super) fn sendmmsg(
    p: &mut LinuxProcess,
    fd: u64,
    vec: u64,
    vlen: u64,
    flags: u64,
) -> Result<u64, i64> {
    each_message(p, vec, vlen, |p, msg, _| Some(sendmsg(p, fd, msg, flags)))
}

/// `recvmmsg(fd, vec, vlen, flags, timeout)`. As on Linux, the timeout is
/// looked at only after each message.
pub(super) fn recvmmsg(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let (fd, flags) = (a[0], a[3] & 0xffff_ffff);
    let until = if a[4] == 0 {
        None
    } else {
        let mut b = [0u8; 16];
        if p.copy_from_user(a[4], &mut b) != 16 {
            return Err(EFAULT);
        }
        let (s, ns) = (super::le_u64(&b[..8]), super::le_u64(&b[8..]));
        if ns >= 1_000_000_000 || s > i64::MAX as u64 {
            return Err(EINVAL);
        }
        let t = Duration::from_secs(s).saturating_add(Duration::from_nanos(ns));
        Some(frame::time::now().saturating_add(t))
    };
    each_message(p, a[1], a[2] & 0xffff_ffff, |p, msg, done| {
        let mut f = flags & !MSG_WAITFORONE;
        if done > 0 {
            if until.is_some_and(|t| frame::time::now() >= t) {
                return None;
            }
            if flags & MSG_WAITFORONE != 0 {
                f |= MSG_DONTWAIT;
            }
        }
        Some(recvmsg(p, fd, msg, f))
    })
}

/// Sockets for the native personality (`native.rs`): the same objects on
/// the same per-cell stack, driven without a Linux process and never
/// blocking.
pub(crate) mod native {
    use super::*;

    fn new(cell: &crate::kcell::Cell, dgram: bool) -> Socket {
        let stack = netstack::stack_for(cell);
        let (id, wait) = stack.socket(dgram);
        Socket::new(stack, id, wait, dgram)
    }

    /// Starts a TCP connection to `to`.
    pub(crate) fn tcp_connect(cell: &crate::kcell::Cell, to: Addr) -> Result<Arc<dyn Object>, i64> {
        let s = new(cell, false);
        s.stack.connect(s.id(), to)?;
        Ok(Arc::new(s))
    }

    /// A TCP listener on `port` of every address the cell has.
    pub(crate) fn tcp_listen(
        cell: &crate::kcell::Cell,
        addr: net::Ipv4Addr,
        port: u16,
        backlog: usize,
    ) -> Result<Arc<dyn Object>, i64> {
        let s = new(cell, false);
        s.stack.set_reuse_addr(s.id(), true)?;
        s.stack.bind(s.id(), (addr, port))?;
        s.stack.listen(s.id(), backlog)?;
        s.listening.store(true, Ordering::Release);
        Ok(Arc::new(s))
    }

    /// A pending connection of a listener, if any.
    pub(crate) fn accept(l: &Arc<dyn Object>) -> Result<Option<Arc<dyn Object>>, i64> {
        let s = l.socket().ok_or(ENOTSOCK)?;
        Ok(s.stack.accept(s.id())?.map(|(cid, wait, _)| {
            Arc::new(Socket::new(s.stack.clone(), cid, wait, false)) as Arc<dyn Object>
        }))
    }

    /// A UDP socket on `port` (0: ephemeral).
    pub(crate) fn udp_bind(cell: &crate::kcell::Cell, port: u16) -> Result<Arc<dyn Object>, i64> {
        let s = new(cell, true);
        s.stack.bind(s.id(), (net::Ipv4Addr::UNSPECIFIED, port))?;
        Ok(Arc::new(s))
    }

    pub(crate) fn udp_send(o: &Arc<dyn Object>, data: &[u8], to: Addr) -> Result<usize, i64> {
        let s = o.socket().ok_or(ENOTSOCK)?;
        s.stack.send_to(s.id(), Some(to), data)
    }

    pub(crate) fn udp_recv(o: &Arc<dyn Object>) -> Result<Option<(Addr, Vec<u8>)>, i64> {
        let s = o.socket().ok_or(ENOTSOCK)?;
        s.stack.recv_from(s.id(), false)
    }

    /// A connecting socket's outcome, once known.
    pub(crate) fn connect_result(o: &Arc<dyn Object>) -> Result<Option<Result<(), i64>>, i64> {
        let s = o.socket().ok_or(ENOTSOCK)?;
        Ok(s.stack.connect_result(s.id()))
    }
}

pub(super) fn shutdown(p: &mut LinuxProcess, fd: u64, how: u64) -> Result<u64, i64> {
    if let Some((o, _)) = unix::of(p, fd) {
        return unix::shutdown(unix::sock(&o)?, how);
    }
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
