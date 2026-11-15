//! Per-cell network stacks (ADR-0010 §2) and the TCP sockets on them.
//!
//! Each cell gets its own [`Stack`] on first use: its own sockets, port
//! numbers and connections, so nothing in one cell's stack can name
//! anything in another's. A stack's state sits behind one spinlock (the
//! blocking waits check their conditions with interrupts off, so they can
//! only take spinlocks), and the protocol work is `net::tcp`'s.
//!
//! Segments between the stack's own addresses (loopback, 127.0.0.0/8) are
//! delivered synchronously, inside the operation that produced them, until
//! none are left. A listener turns a SYN into a connection that waits in
//! its backlog once established; a segment for nothing gets a RST.
//! Sockets have their own wait queues and poll watchers, and only the
//! sockets an operation touched are woken. One kernel task, the net task,
//! runs every stack's timers (retransmission, TIME_WAIT), sleeping until
//! the earliest one or until an operation kicks it.
//!
//! Partial (milestone 5 so far): TCP over loopback only (the cell switch
//! and its ports come next), no UDP, no IPv6.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use frame::sync::SpinLock;
use frame::task::{TaskOptions, WaitQueue};
use net::Ipv4Addr;
use net::tcp::{self, Segment, State, Tcp};

use crate::poll::Watchers;

pub(crate) const EADDRINUSE: i64 = 98;
pub(crate) const EADDRNOTAVAIL: i64 = 99;
pub(crate) const ENETUNREACH: i64 = 101;
pub(crate) const ECONNRESET: i64 = 104;
pub(crate) const EISCONN: i64 = 106;
pub(crate) const ENOTCONN: i64 = 107;
pub(crate) const ETIMEDOUT: i64 = 110;
pub(crate) const ECONNREFUSED: i64 = 111;
pub(crate) const EALREADY: i64 = 114;
pub(crate) const EINPROGRESS: i64 = 115;
pub(crate) const EINVAL: i64 = 22;
pub(crate) const EPIPE: i64 = 32;
pub(crate) const EOPNOTSUPP: i64 = 95;

/// An IPv4 socket address.
pub(crate) type Addr = (Ipv4Addr, u16);

/// Ephemeral ports (Linux's default range).
const EPHEMERAL: core::ops::RangeInclusive<u16> = 32768..=60999;
/// Most segments delivered locally in one go (a loop guard).
const MAX_LOCAL_ROUNDS: usize = 100_000;

fn now() -> Duration {
    frame::time::now()
}

/// What a socket's readers and pollers wait on.
#[derive(Debug, Default)]
pub(crate) struct Waiters {
    pub(crate) queue: WaitQueue,
    pub(crate) watchers: Watchers,
    pub(crate) changes: AtomicU64,
}

impl Waiters {
    fn wake(&self) {
        self.changes.fetch_add(1, Ordering::AcqRel);
        self.queue.wake_all();
        self.watchers.notify();
    }
}

#[derive(Debug)]
enum Kind {
    /// Created, possibly bound.
    Fresh,
    Listening {
        /// Established connections not yet accepted.
        backlog: VecDeque<u64>,
        max: usize,
    },
    Conn {
        tcp: Box<Tcp>,
        /// The listener this came from, until it is accepted.
        parent: Option<u64>,
        /// Already put in the parent's backlog.
        queued: bool,
    },
}

#[derive(Debug)]
struct Sock {
    kind: Kind,
    local: Option<Addr>,
    wait: Arc<Waiters>,
    reuse_addr: bool,
    /// The application closed it: reap once the connection is done.
    orphan: bool,
    /// `shutdown(SHUT_RD)`: reads see EOF.
    shut_rd: bool,
    /// The socket's pending error, for `SO_ERROR` (taken on read).
    error: Option<i64>,
}

#[derive(Debug, Default)]
struct Inner {
    socks: BTreeMap<u64, Sock>,
    next_id: u64,
    next_port: u16,
    /// Segments between local addresses, to deliver: (src, dst, segment).
    local: VecDeque<(Ipv4Addr, Ipv4Addr, Vec<u8>)>,
    /// Sockets to wake when the lock is released.
    touched: BTreeSet<u64>,
}

/// One cell's network stack.
#[derive(Debug)]
pub(crate) struct Stack {
    pub(crate) cell: u64,
    inner: SpinLock<Inner>,
}

/// Every stack, by cell.
static STACKS: SpinLock<BTreeMap<u64, Arc<Stack>>> = SpinLock::new(BTreeMap::new());
/// Kicked when an operation may have armed an earlier timer.
static NET_KICK: WaitQueue = WaitQueue::new();
static KICKED: AtomicBool = AtomicBool::new(false);
static NET_TASK: AtomicBool = AtomicBool::new(false);

/// The stack of `cell`, made on first use.
pub(crate) fn stack_for(cell: u64) -> Arc<Stack> {
    let s = {
        let mut stacks = STACKS.lock();
        stacks
            .entry(cell)
            .or_insert_with(|| {
                Arc::new(Stack {
                    cell,
                    inner: SpinLock::new(Inner {
                        next_port: *EPHEMERAL.start(),
                        ..Inner::default()
                    }),
                })
            })
            .clone()
    };
    start_net_task();
    s
}

fn kick() {
    KICKED.store(true, Ordering::Release);
    NET_KICK.wake_all();
}

fn start_net_task() {
    if NET_TASK.swap(true, Ordering::AcqRel) {
        return;
    }
    let spawned = TaskOptions::new(net_task).spawn();
    if spawned.is_none() {
        NET_TASK.store(false, Ordering::Release);
    }
}

/// Runs every stack's timers, then sleeps until the next one or a kick.
fn net_task() {
    loop {
        let stacks: Vec<Weak<Stack>> = STACKS.lock().values().map(Arc::downgrade).collect();
        let t = now();
        let mut next: Option<Duration> = None;
        for s in stacks.iter().filter_map(Weak::upgrade) {
            if let Some(n) = s.run_timers(t) {
                next = Some(next.map_or(n, |m: Duration| m.min(n)));
            }
        }
        let cond = || KICKED.swap(false, Ordering::AcqRel).then_some(());
        match next {
            Some(d) if d > now() => {
                let _ = NET_KICK.wait_until_deadline(d, cond);
            }
            Some(_) => frame::task::yield_now(),
            None => {
                // Nothing scheduled: wake at least once a second anyway.
                let _ = NET_KICK.wait_until_deadline(now() + Duration::from_secs(1), cond);
            }
        }
    }
}

fn is_local(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
}

fn random_iss() -> u32 {
    let mut b = [0u8; 4];
    crate::random::fill(&mut b);
    u32::from_le_bytes(b)
}

impl Inner {
    fn sock(&mut self, id: u64) -> Result<&mut Sock, i64> {
        self.socks.get_mut(&id).ok_or(EINVAL)
    }

    /// Whether `port` on `ip` is taken for a new bind by `by`.
    fn port_taken(&self, ip: Ipv4Addr, port: u16, by: u64, reuse: bool) -> bool {
        self.socks.iter().any(|(&id, s)| {
            let Some((sip, sport)) = s.local else {
                return false;
            };
            if id == by || sport != port {
                return false;
            }
            let overlap = sip == ip || sip.is_unspecified() || ip.is_unspecified();
            if !overlap {
                return false;
            }
            match &s.kind {
                // A connection only blocks the port while it is live, and
                // not at all for SO_REUSEADDR binds.
                Kind::Conn { tcp, parent, .. } => {
                    parent.is_none()
                        && !reuse
                        && !matches!(tcp.state(), State::TimeWait | State::Closed)
                }
                _ => true,
            }
        })
    }

    fn ephemeral(&mut self, ip: Ipv4Addr, by: u64) -> Result<u16, i64> {
        let span = u32::from(*EPHEMERAL.end() - *EPHEMERAL.start()) + 1;
        for _ in 0..span {
            let p = self.next_port;
            self.next_port = if p >= *EPHEMERAL.end() {
                *EPHEMERAL.start()
            } else {
                p + 1
            };
            if !self.port_taken(ip, p, by, false) {
                return Ok(p);
            }
        }
        Err(EADDRINUSE)
    }

    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Takes every connection's queued segments and routes them.
    fn flush(&mut self) -> Result<(), i64> {
        let mut out = Vec::new();
        for (&id, s) in &mut self.socks {
            if let Kind::Conn { tcp, .. } = &mut s.kind {
                let mut any = false;
                while let Some(seg) = tcp.transmit() {
                    out.push((tcp.local.0, tcp.remote.0, seg));
                    any = true;
                }
                if any {
                    self.touched.insert(id);
                }
            }
        }
        for (src, dst, seg) in out {
            if is_local(dst) {
                self.local.push_back((src, dst, seg));
            }
            // Non-local destinations need the cell switch (next step):
            // dropped, so the connection times out.
        }
        Ok(())
    }

    /// Delivers local segments until none are left.
    fn run_local(&mut self) {
        let _ = self.flush();
        for _ in 0..MAX_LOCAL_ROUNDS {
            let Some((src, dst, bytes)) = self.local.pop_front() else {
                break;
            };
            self.input(src, dst, &bytes);
            let _ = self.flush();
        }
        self.promote_and_reap();
    }

    /// One segment arriving at this stack.
    fn input(&mut self, src: Ipv4Addr, dst: Ipv4Addr, bytes: &[u8]) {
        let Some(seg) = Segment::parse(bytes, src, dst) else {
            return;
        };
        let t = now();
        let local = (dst, seg.dst_port);
        let remote = (src, seg.src_port);
        // An existing connection.
        let conn = self
            .socks
            .iter_mut()
            .find_map(|(&id, s)| match &mut s.kind {
                Kind::Conn { tcp, .. } if tcp.local == local && tcp.remote == remote => {
                    Some((id, tcp))
                }
                _ => None,
            });
        if let Some((id, tcp)) = conn {
            tcp.on_segment(&seg, t);
            self.touched.insert(id);
            return;
        }
        // A new connection for a listener.
        if seg.flags & tcp::SYN != 0 && seg.flags & (tcp::ACK | tcp::RST) == 0 {
            let listener = self
                .socks
                .iter()
                .find_map(|(&id, s)| match (&s.kind, s.local) {
                    (Kind::Listening { .. }, Some((ip, port)))
                        if port == local.1 && (ip.is_unspecified() || ip == local.0) =>
                    {
                        Some(id)
                    }
                    _ => None,
                });
            if let Some(lid) = listener {
                let room = {
                    let pending = self
                        .socks
                        .values()
                        .filter(
                            |s| matches!(s.kind, Kind::Conn { parent: Some(p), .. } if p == lid),
                        )
                        .count();
                    let max = match self.socks.get(&lid).map(|l| &l.kind) {
                        Some(Kind::Listening { max, .. }) => *max,
                        _ => 0,
                    };
                    pending < max
                };
                if room {
                    let tcp = Box::new(Tcp::accept(local, remote, &seg, random_iss(), t));
                    let id = self.new_id();
                    self.socks.insert(
                        id,
                        Sock {
                            kind: Kind::Conn {
                                tcp,
                                parent: Some(lid),
                                queued: false,
                            },
                            local: Some(local),
                            wait: Arc::new(Waiters::default()),
                            reuse_addr: false,
                            orphan: false,
                            shut_rd: false,
                            error: None,
                        },
                    );
                    self.touched.insert(id);
                }
                return; // a full backlog drops the SYN (the peer retries)
            }
        }
        // Nothing here: answer with RST (never to a RST).
        if seg.flags & tcp::RST == 0 {
            let rst = if seg.flags & tcp::ACK != 0 {
                tcp::segment(local, remote, seg.ack, 0, tcp::RST, 0, None, &[])
            } else {
                let ack = seg.seq.wrapping_add(seg.len());
                tcp::segment(local, remote, 0, ack, tcp::RST | tcp::ACK, 0, None, &[])
            };
            if is_local(src) {
                self.local.push_back((dst, src, rst));
            }
        }
    }

    /// Queues newly established connections for their listeners, records
    /// errors, and forgets finished orphans.
    fn promote_and_reap(&mut self) {
        let mut ready: Vec<(u64, u64)> = Vec::new();
        let mut gone: Vec<u64> = Vec::new();
        for (&id, s) in &mut self.socks {
            if let Kind::Conn {
                tcp,
                parent,
                queued,
            } = &mut s.kind
            {
                if let Some(e) = tcp.error() {
                    s.error.get_or_insert(match e {
                        tcp::Error::Refused => ECONNREFUSED,
                        tcp::Error::Reset => ECONNRESET,
                        tcp::Error::TimedOut => ETIMEDOUT,
                    });
                }
                if let Some(p) = *parent
                    && !*queued
                    && tcp.state() != State::SynReceived
                {
                    *queued = true;
                    ready.push((p, id));
                }
                if tcp.is_closed() && (s.orphan || parent.is_some() && tcp.error().is_some()) {
                    gone.push(id);
                }
            }
        }
        for (lid, id) in ready {
            match self.socks.get_mut(&lid) {
                Some(Sock {
                    kind: Kind::Listening { backlog, .. },
                    ..
                }) => {
                    backlog.push_back(id);
                    self.touched.insert(lid);
                }
                // The listener went away: the connection is reset.
                _ => {
                    if let Some(Sock {
                        kind: Kind::Conn { tcp, .. },
                        ..
                    }) = self.socks.get_mut(&id)
                    {
                        tcp.abort();
                    }
                    gone.push(id);
                }
            }
        }
        for id in gone {
            // A pending connection that died leaves its listener's backlog.
            for s in self.socks.values_mut() {
                if let Kind::Listening { backlog, .. } = &mut s.kind {
                    backlog.retain(|&b| b != id);
                }
            }
            self.socks.remove(&id);
        }
    }

    fn take_touched(&mut self) -> Vec<Arc<Waiters>> {
        let ids = core::mem::take(&mut self.touched);
        ids.iter()
            .filter_map(|id| self.socks.get(id).map(|s| s.wait.clone()))
            .collect()
    }
}

/// Wakes what an operation touched, after the stack lock is dropped.
fn wake_all(ws: Vec<Arc<Waiters>>) {
    for w in ws {
        w.wake();
    }
}

impl Stack {
    /// Runs `f` on the state, delivers local traffic, and wakes what it
    /// touched.
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let (r, woken) = {
            let mut i = self.inner.lock();
            let r = f(&mut i);
            i.run_local();
            let w = i.take_touched();
            (r, w)
        };
        wake_all(woken);
        kick();
        r
    }

    /// A new, unbound socket.
    pub(crate) fn socket(&self) -> (u64, Arc<Waiters>) {
        let mut i = self.inner.lock();
        let id = i.new_id();
        let wait = Arc::new(Waiters::default());
        i.socks.insert(
            id,
            Sock {
                kind: Kind::Fresh,
                local: None,
                wait: wait.clone(),
                reuse_addr: false,
                orphan: false,
                shut_rd: false,
                error: None,
            },
        );
        (id, wait)
    }

    pub(crate) fn set_reuse_addr(&self, id: u64, on: bool) -> Result<(), i64> {
        self.inner.lock().sock(id)?.reuse_addr = on;
        Ok(())
    }

    pub(crate) fn reuse_addr(&self, id: u64) -> bool {
        self.inner
            .lock()
            .socks
            .get(&id)
            .is_some_and(|s| s.reuse_addr)
    }

    pub(crate) fn bind(&self, id: u64, mut addr: Addr) -> Result<(), i64> {
        let mut i = self.inner.lock();
        let reuse = i.sock(id)?.reuse_addr;
        if i.sock(id)?.local.is_some() {
            return Err(EINVAL);
        }
        if !addr.0.is_unspecified() && !is_local(addr.0) {
            return Err(EADDRNOTAVAIL);
        }
        if addr.1 == 0 {
            addr.1 = i.ephemeral(addr.0, id)?;
        } else if i.port_taken(addr.0, addr.1, id, reuse) {
            return Err(EADDRINUSE);
        }
        i.sock(id)?.local = Some(addr);
        Ok(())
    }

    pub(crate) fn listen(&self, id: u64, backlog: usize) -> Result<(), i64> {
        let mut i = self.inner.lock();
        if i.sock(id)?.local.is_none() {
            let p = i.ephemeral(Ipv4Addr::UNSPECIFIED, id)?;
            i.sock(id)?.local = Some((Ipv4Addr::UNSPECIFIED, p));
        }
        let s = i.sock(id)?;
        match &mut s.kind {
            Kind::Fresh => {
                s.kind = Kind::Listening {
                    backlog: VecDeque::new(),
                    max: backlog.clamp(1, 4096),
                };
                Ok(())
            }
            Kind::Listening { max, .. } => {
                *max = backlog.clamp(1, 4096);
                Ok(())
            }
            Kind::Conn { .. } => Err(EINVAL),
        }
    }

    /// Starts connecting to `remote`.
    pub(crate) fn connect(&self, id: u64, remote: Addr) -> Result<(), i64> {
        self.with(|i| {
            match i.sock(id)?.kind {
                Kind::Fresh => {}
                Kind::Conn { .. } => return Err(EISCONN),
                Kind::Listening { .. } => return Err(EINVAL),
            }
            if !is_local(remote.0) {
                return Err(ENETUNREACH);
            }
            let local_ip = match i.sock(id)?.local {
                Some((ip, _)) if !ip.is_unspecified() => ip,
                _ => Ipv4Addr::LOCALHOST,
            };
            let port = match i.sock(id)?.local {
                Some((_, p)) => p,
                None => i.ephemeral(local_ip, id)?,
            };
            let local = (local_ip, port);
            let tcp = Box::new(Tcp::connect(local, remote, random_iss(), now()));
            let s = i.sock(id)?;
            s.local = Some(local);
            s.kind = Kind::Conn {
                tcp,
                parent: None,
                queued: false,
            };
            i.touched.insert(id);
            Ok(())
        })
    }

    /// For a connecting socket: `Some(Ok)` once established, `Some(Err)`
    /// if it failed, `None` while the handshake is in progress.
    pub(crate) fn connect_result(&self, id: u64) -> Option<Result<(), i64>> {
        let mut i = self.inner.lock();
        let s = i.socks.get_mut(&id)?;
        match &s.kind {
            Kind::Conn { tcp, .. } => match tcp.state() {
                State::SynSent | State::SynReceived => None,
                State::Closed => Some(Err(s.error.take().unwrap_or(ECONNREFUSED))),
                _ => Some(Ok(())),
            },
            _ => Some(Err(ENOTCONN)),
        }
    }

    /// Takes an established connection from a listener's backlog:
    /// `(id, its waiters, peer address)`.
    pub(crate) fn accept(&self, id: u64) -> Result<Option<(u64, Arc<Waiters>, Addr)>, i64> {
        self.with(|i| {
            let s = i.sock(id)?;
            let Kind::Listening { backlog, .. } = &mut s.kind else {
                return Err(EINVAL);
            };
            let Some(cid) = backlog.pop_front() else {
                return Ok(None);
            };
            let c = i.sock(cid)?;
            let (wait, peer) = match &mut c.kind {
                Kind::Conn { tcp, parent, .. } => {
                    *parent = None;
                    (c.wait.clone(), tcp.remote)
                }
                _ => return Err(EINVAL),
            };
            Ok(Some((cid, wait, peer)))
        })
    }

    /// Sends what fits; `Ok(0)` means "no room yet" (callers wait).
    pub(crate) fn send(&self, id: u64, data: &[u8]) -> Result<usize, i64> {
        self.with(|i| {
            let s = i.sock(id)?;
            if let Some(e) = s.error.take() {
                return Err(e);
            }
            let Kind::Conn { tcp, .. } = &mut s.kind else {
                return Err(ENOTCONN);
            };
            match tcp.state() {
                State::SynSent | State::SynReceived => return Ok(0),
                State::Established | State::CloseWait => {}
                _ => return Err(EPIPE),
            }
            let n = tcp.send(data, now());
            i.touched.insert(id);
            Ok(n)
        })
    }

    /// Reads into `out`: `Ok(Some(n))` (n = 0 at end of stream), `Ok(None)`
    /// when nothing is ready yet.
    pub(crate) fn recv(&self, id: u64, out: &mut [u8], peek: bool) -> Result<Option<usize>, i64> {
        self.with(|i| {
            let s = i.sock(id)?;
            if s.shut_rd {
                return Ok(Some(0));
            }
            let Kind::Conn { tcp, .. } = &mut s.kind else {
                return Err(ENOTCONN);
            };
            if tcp.readable() > 0 {
                if peek {
                    return Err(EOPNOTSUPP);
                }
                let n = tcp.recv(out, now());
                i.touched.insert(id);
                return Ok(Some(n));
            }
            if let Some(e) = s.error.take() {
                return Err(e);
            }
            if tcp.peer_closed() || tcp.is_closed() {
                return Ok(Some(0));
            }
            if matches!(tcp.state(), State::SynSent | State::SynReceived) {
                return Ok(None);
            }
            Ok(None)
        })
    }

    /// `shutdown`: `rd` stops reads, `wr` sends FIN.
    pub(crate) fn shutdown(&self, id: u64, rd: bool, wr: bool) -> Result<(), i64> {
        self.with(|i| {
            let s = i.sock(id)?;
            let Kind::Conn { tcp, .. } = &mut s.kind else {
                return Err(ENOTCONN);
            };
            if wr {
                tcp.close(now());
            }
            if rd {
                s.shut_rd = true;
            }
            i.touched.insert(id);
            Ok(())
        })
    }

    /// The descriptor went away: close gracefully (a listener resets its
    /// queued connections) and forget the socket once done.
    pub(crate) fn release(&self, id: u64) {
        self.with(|i| {
            let mut doomed = Vec::new();
            if let Some(s) = i.socks.get_mut(&id) {
                match &mut s.kind {
                    Kind::Fresh => {
                        i.socks.remove(&id);
                    }
                    Kind::Listening { backlog, .. } => {
                        doomed.extend(backlog.drain(..));
                        i.socks.remove(&id);
                        doomed.extend(i.socks.iter().filter_map(|(&cid, c)| {
                            matches!(c.kind, Kind::Conn { parent: Some(p), .. } if p == id)
                                .then_some(cid)
                        }));
                    }
                    Kind::Conn { tcp, .. } => {
                        tcp.close(now());
                        s.orphan = true;
                    }
                }
            }
            for cid in doomed {
                if let Some(Sock {
                    kind: Kind::Conn { tcp, .. },
                    ..
                }) = i.socks.get_mut(&cid)
                {
                    tcp.abort();
                }
                if let Some(c) = i.socks.get_mut(&cid) {
                    c.orphan = true;
                }
            }
        });
    }

    /// Readiness of socket `id` (`POLL*` bits).
    pub(crate) fn poll(&self, id: u64) -> u16 {
        use crate::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT};
        let i = self.inner.lock();
        let Some(s) = i.socks.get(&id) else {
            return POLLHUP;
        };
        let mut r = if s.error.is_some() { POLLERR } else { 0 };
        match &s.kind {
            Kind::Fresh => r |= POLLOUT | POLLHUP,
            Kind::Listening { backlog, .. } => {
                if !backlog.is_empty() {
                    r |= POLLIN;
                }
            }
            Kind::Conn { tcp, .. } => {
                if tcp.readable() > 0 || tcp.peer_closed() || s.shut_rd {
                    r |= POLLIN;
                }
                if tcp.writable() > 0
                    && matches!(tcp.state(), State::Established | State::CloseWait)
                {
                    r |= POLLOUT;
                }
                if tcp.is_closed() {
                    r |= POLLHUP | POLLIN;
                }
            }
        }
        r
    }

    /// `getsockname`.
    pub(crate) fn local_addr(&self, id: u64) -> Result<Addr, i64> {
        let i = self.inner.lock();
        let s = i.socks.get(&id).ok_or(EINVAL)?;
        Ok(s.local.unwrap_or((Ipv4Addr::UNSPECIFIED, 0)))
    }

    /// `getpeername`.
    pub(crate) fn peer_addr(&self, id: u64) -> Result<Addr, i64> {
        let i = self.inner.lock();
        match &i.socks.get(&id).ok_or(EINVAL)?.kind {
            Kind::Conn { tcp, .. } if !tcp.is_closed() => Ok(tcp.remote),
            _ => Err(ENOTCONN),
        }
    }

    /// `SO_ERROR`: the pending error, cleared.
    pub(crate) fn take_error(&self, id: u64) -> i64 {
        let mut i = self.inner.lock();
        i.socks
            .get_mut(&id)
            .and_then(|s| s.error.take())
            .unwrap_or(0)
    }

    /// Runs this stack's timers; returns when they next need to run.
    fn run_timers(&self, t: Duration) -> Option<Duration> {
        let (next, woken) = {
            let mut i = self.inner.lock();
            let mut touched = Vec::new();
            for (&id, s) in &mut i.socks {
                if let Kind::Conn { tcp, .. } = &mut s.kind
                    && tcp.next_timer().is_some_and(|d| d <= t)
                {
                    tcp.poll(t);
                    touched.push(id);
                }
            }
            i.touched.extend(touched);
            i.run_local();
            let next = i
                .socks
                .values()
                .filter_map(|s| match &s.kind {
                    Kind::Conn { tcp, .. } => tcp.next_timer(),
                    _ => None,
                })
                .min();
            (next, i.take_touched())
        };
        wake_all(woken);
        next
    }
}
