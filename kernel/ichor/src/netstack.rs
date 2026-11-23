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
//! Each stack is also a port on the cell switch (`switch.rs`), which
//! assigns it an address in 10.88.0.0/16: segments for any other address
//! leave through the switch after the stack lock is dropped, and the
//! switch hands segments for this stack's address to [`Stack::receive`].
//!
//! UDP sockets share the stack: datagrams go through the same local
//! delivery and switch paths, with their own port space; a socket queues
//! up to [`UDP_BUFFER`] bytes and drops what does not fit, as a full Linux
//! socket does.
//!
//! A datagram for a port nobody has is answered with ICMP, which a
//! connected socket reports as ECONNREFUSED, within the cell and between
//! cells.
//!
//! Partial: no IPv6; ICMP errors from beyond the uplink do not pass the NAT.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use frame::sync::SpinLock;
use frame::task::{TaskOptions, WaitQueue};
use net::Ipv4Addr;
use net::iface::Packet;
use net::tcp::{self, Segment, State, Tcp};
use net::wire::{
    PROTO_ICMP, PROTO_TCP, PROTO_UDP, UNREACHABLE_HOST, UNREACHABLE_PORT, Udp, Unreachable,
};

use crate::poll::Watchers;

pub(crate) const EADDRINUSE: i64 = 98;
pub(crate) const EADDRNOTAVAIL: i64 = 99;
pub(crate) const ENETUNREACH: i64 = 101;
pub(crate) const ECONNRESET: i64 = 104;
pub(crate) const EISCONN: i64 = 106;
pub(crate) const ENOTCONN: i64 = 107;
pub(crate) const ETIMEDOUT: i64 = 110;
pub(crate) const ECONNREFUSED: i64 = 111;
const EHOSTUNREACH: i64 = 113;
pub(crate) const EALREADY: i64 = 114;
pub(crate) const EINPROGRESS: i64 = 115;
pub(crate) const EINVAL: i64 = 22;
pub(crate) const EPIPE: i64 = 32;
pub(crate) const EDESTADDRREQ: i64 = 89;
pub(crate) const EMSGSIZE: i64 = 90;
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

/// Sending to 0.0.0.0 means this host, as on Linux.
fn to_this_host(a: Addr) -> Addr {
    if a.0.is_unspecified() {
        (Ipv4Addr::LOCALHOST, a.1)
    } else {
        a
    }
}

/// What a socket's readers and pollers wait on.
#[derive(Debug, Default)]
pub(crate) struct Waiters {
    pub(crate) queue: WaitQueue,
    pub(crate) watchers: Watchers,
    pub(crate) changes: AtomicU64,
}

impl Waiters {
    pub(crate) fn wake(&self) {
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
    /// A UDP socket: received datagrams with their sources, and the
    /// peer `connect` fixed, if any.
    Udp {
        rx: VecDeque<(Addr, Vec<u8>)>,
        bytes: usize,
        peer: Option<Addr>,
    },
}

impl Kind {
    fn is_udp(&self) -> bool {
        matches!(self, Kind::Udp { .. })
    }

    /// Bytes this socket holds in buffers.
    fn buffered(&self) -> usize {
        match self {
            Kind::Conn { tcp, .. } => tcp.buffered(),
            Kind::Udp { bytes, .. } => *bytes,
            Kind::Fresh | Kind::Listening { .. } => 0,
        }
    }
}

/// Pages of headroom a stack leaves its cell before it stops growing
/// buffers; growth resumes at twice this.
const RESERVE: u64 = 16;
const PAGE: usize = 4096;

/// Most bytes a UDP socket queues before it drops datagrams.
pub(crate) const UDP_BUFFER: usize = 256 * 1024;
/// And datagrams, however small.
const UDP_DATAGRAMS: usize = 4096;
/// Largest UDP payload over IPv4.
pub(crate) const UDP_MAX: usize = 65507;

#[derive(Debug)]
struct Sock {
    kind: Kind,
    local: Option<Addr>,
    /// `connect` picked `local`: nobody bound it.
    picked: bool,
    wait: Arc<Waiters>,
    reuse_addr: bool,
    reuse_port: bool,
    /// The application closed it: reap once the connection is done.
    orphan: bool,
    /// `shutdown(SHUT_RD)`: reads see EOF.
    shut_rd: bool,
    /// The socket's pending error, for `SO_ERROR` (taken on read).
    error: Option<i64>,
    /// Buffered bytes as last counted toward the stack's charge.
    held: usize,
}

#[derive(Debug, Default)]
struct Inner {
    /// The cell's account: socket buffers are charged to it, by the page.
    account: Option<Arc<cell::Account>>,
    /// Bytes every socket holds, and the pages charged for them.
    held: usize,
    charged: u64,
    /// The account ran short: connections' buffers are capped where they
    /// stand and datagrams are dropped until there is headroom again.
    starved: bool,
    /// The address the switch assigned (none if the switch was full).
    addr: Option<Ipv4Addr>,
    socks: BTreeMap<u64, Sock>,
    next_id: u64,
    next_port: u16,
    /// Packets between local addresses, to deliver.
    local: VecDeque<Packet>,
    /// Segments for the switch, sent once the lock is released.
    out: Vec<Packet>,
    /// Sockets to wake when the lock is released.
    touched: BTreeSet<u64>,
}

/// One cell's network stack.
#[derive(Debug)]
pub(crate) struct Stack {
    pub(crate) cell: u64,
    addr: Option<Ipv4Addr>,
    inner: SpinLock<Inner>,
}

/// Every stack, by cell.
static STACKS: SpinLock<BTreeMap<u64, Arc<Stack>>> = SpinLock::new(BTreeMap::new());
/// Kicked when an operation may have armed an earlier timer.
static NET_KICK: WaitQueue = WaitQueue::new();
static KICKED: AtomicBool = AtomicBool::new(false);
static NET_TASK: AtomicBool = AtomicBool::new(false);

/// The stack of `cell`, made on first use; its socket buffers are charged
/// to the cell's account.
pub(crate) fn stack_for(c: &crate::kcell::Cell) -> Arc<Stack> {
    let cell = c.id();
    let s = {
        let mut stacks = STACKS.lock();
        stacks
            .entry(cell)
            .or_insert_with(|| {
                Arc::new_cyclic(|me| {
                    let addr = crate::switch::attach(cell, me.clone());
                    Stack {
                        cell,
                        addr,
                        inner: SpinLock::new(Inner {
                            addr,
                            next_port: *EPHEMERAL.start(),
                            account: Some(c.account().clone()),
                            ..Inner::default()
                        }),
                    }
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

/// Self-test: socket buffers are the cell's memory. In a cell of 48 pages
/// (far less than one connection's two 256 KiB buffers) a loopback sender
/// is stopped once the account runs short, the transfer still completes
/// as the reader drains, the charge never passes the limit, and closing
/// both ends gives every page back.
pub(crate) fn accounting_selftest() {
    const PAGES: u64 = 48;
    const LEN: usize = 1 << 20;
    let fail = |m: &str| -> ! { crate::runtest::fail(m) };
    let sys = crate::kcell::System::new(1 << 16).unwrap_or_else(|| fail("net: no system cell"));
    let cell = crate::kcell::Cell::new(&sys.root_account, PAGES)
        .unwrap_or_else(|| fail("net: no test cell"));
    let st = stack_for(&cell);
    let lo = Ipv4Addr::LOCALHOST;
    let (l, _) = st.socket(false);
    let (c, _) = st.socket(false);
    let ok = st.bind(l, (lo, 0)).is_ok() && st.listen(l, 4).is_ok();
    let port = st.local_addr(l).map_or(0, |a| a.1);
    if !ok || st.connect(c, (lo, port)).is_err() {
        fail("net: accounting: no loopback connection");
    }
    let Ok(Some((a, _, _))) = st.accept(l) else {
        fail("net: accounting: nothing to accept");
    };
    let data = alloc::vec![0x5au8; LEN];
    let mut buf = alloc::vec![0u8; 65536];
    let (mut sent, mut got, mut peak, mut stopped) = (0, 0, 0, false);
    let deadline = now() + Duration::from_secs(120);
    while got < LEN {
        if now() > deadline {
            crate::println!("ichor: net: accounting: sent {sent}, got {got}");
            fail("net: accounting: the capped transfer stalled");
        }
        // Write as far as it goes before reading anything.
        while sent < LEN {
            match st.send(c, &data[sent..(sent + 65536).min(LEN)]) {
                Ok(0) => break,
                Ok(n) => sent += n,
                Err(_) => fail("net: accounting: send failed"),
            }
        }
        peak = peak.max(cell.account().used());
        stopped |= sent < LEN && got == 0;
        match st.recv(a, &mut buf, false) {
            Ok(Some(n)) => got += n,
            Ok(None) => frame::task::yield_now(),
            Err(_) => fail("net: accounting: recv failed"),
        }
    }
    if !stopped || peak > PAGES {
        crate::println!("ichor: net: accounting: peak {peak} pages, stopped {stopped}");
        fail("net: accounting: the sender was not held to the cell's memory");
    }
    for id in [a, c, l] {
        st.release(id, false);
    }
    let deadline = now() + Duration::from_secs(30);
    while cell.account().used() != 0 {
        if now() > deadline {
            crate::println!(
                "ichor: net: accounting: {} pages still charged",
                cell.account().used()
            );
            fail("net: accounting: closed sockets kept their pages");
        }
        frame::task::yield_now();
    }
    crate::println!(
        "ichor: net: socket buffers are charged to the cell: a 1 MiB loopback transfer peaked at {peak} of {PAGES} pages and gave them back"
    );
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

/// Starts the net task if no stack has yet (the uplink needs polling).
pub(crate) fn start() {
    start_net_task();
}

/// Runs every stack's timers and polls the uplink, then sleeps until the
/// next timer, a kick, or the next uplink poll: 1 ms after recent
/// traffic, 10 ms when idle (the driver is polled, ADR-0010 §5).
fn net_task() {
    let mut last_traffic = Duration::ZERO;
    loop {
        if crate::switch::poll_uplink() {
            last_traffic = now();
        }
        let stacks: Vec<Weak<Stack>> = STACKS.lock().values().map(Arc::downgrade).collect();
        let t = now();
        let mut next: Option<Duration> = None;
        for s in stacks.iter().filter_map(Weak::upgrade) {
            if let Some(n) = s.run_timers(t) {
                next = Some(next.map_or(n, |m: Duration| m.min(n)));
            }
        }
        let t = now();
        if t.saturating_sub(last_traffic) < Duration::from_micros(200) {
            frame::task::yield_now(); // traffic is flowing: poll again now
            continue;
        }
        let mut wake = next.unwrap_or(t + Duration::from_secs(1));
        if crate::switch::has_uplink() {
            let poll = if t.saturating_sub(last_traffic) < Duration::from_secs(1) {
                Duration::from_millis(1)
            } else {
                Duration::from_millis(10)
            };
            wake = wake.min(t + poll);
        }
        let cond = || KICKED.swap(false, Ordering::AcqRel).then_some(());
        if wake > t {
            let _ = NET_KICK.wait_until_deadline(wake, cond);
        } else {
            frame::task::yield_now();
        }
    }
}

fn random_iss() -> u32 {
    let mut b = [0u8; 4];
    crate::random::fill(&mut b);
    u32::from_le_bytes(b)
}

impl Inner {
    /// Whether `ip` is one of this stack's own addresses.
    fn is_local(&self, ip: Ipv4Addr) -> bool {
        ip.is_loopback() || Some(ip) == self.addr
    }

    /// Queues a TCP segment for `dst`: delivered here if local, else sent
    /// through the switch.
    fn route(&mut self, src: Ipv4Addr, dst: Ipv4Addr, seg: Vec<u8>) {
        self.route_proto(PROTO_TCP, src, dst, seg);
    }

    fn route_proto(&mut self, protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: Vec<u8>) {
        let p = Packet {
            src,
            dst,
            protocol,
            payload,
        };
        if self.is_local(dst) {
            self.local.push_back(p);
        } else {
            self.out.push(p);
        }
    }

    fn sock(&mut self, id: u64) -> Result<&mut Sock, i64> {
        self.socks.get_mut(&id).ok_or(EINVAL)
    }

    /// Whether `port` on `ip` is taken for a new bind by `by` (TCP and
    /// UDP have separate port spaces). Sockets that all ask for it share a
    /// port: with SO_REUSEPORT whatever they are, with SO_REUSEADDR for
    /// datagrams, or for TCP while none of them listens.
    fn port_taken(&self, ip: Ipv4Addr, port: u16, by: u64, reuse: bool) -> bool {
        let (udp, reuse_port) = self
            .socks
            .get(&by)
            .map_or((false, false), |s| (s.kind.is_udp(), s.reuse_port));
        self.socks.iter().any(|(&id, s)| {
            let Some((sip, sport)) = s.local else {
                return false;
            };
            if id == by || sport != port || s.kind.is_udp() != udp {
                return false;
            }
            let overlap = sip == ip || sip.is_unspecified() || ip.is_unspecified();
            if !overlap || (reuse_port && s.reuse_port) {
                return false;
            }
            match &s.kind {
                Kind::Udp { .. } | Kind::Fresh if reuse && s.reuse_addr => false,
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

    /// The local endpoint socket `id` sends to `dst` from: its bound
    /// address if specific, else loopback or the switch's assignment, and
    /// its bound port or a new ephemeral one.
    fn source_for(&mut self, id: u64, dst: Ipv4Addr) -> Result<Addr, i64> {
        let loopback = dst.is_loopback();
        if dst.is_broadcast() || dst.is_multicast() {
            return Err(ENETUNREACH);
        }
        let bound = self.sock(id)?.local;
        let ip = match (bound, self.addr) {
            (Some((ip, _)), _) if !ip.is_unspecified() => ip,
            _ if loopback => Ipv4Addr::LOCALHOST,
            (_, Some(a)) => a,
            (_, None) => return Err(ENETUNREACH),
        };
        if ip.is_loopback() != loopback {
            return Err(EINVAL); // bound to loopback, sending out (or the reverse)
        }
        let port = match bound {
            Some((_, p)) => p,
            None => self.ephemeral(ip, id)?,
        };
        Ok((ip, port))
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
            self.route(src, dst, seg);
        }
        Ok(())
    }

    /// Delivers local segments until none are left.
    fn run_local(&mut self) {
        let _ = self.flush();
        for _ in 0..MAX_LOCAL_ROUNDS {
            let Some(p) = self.local.pop_front() else {
                break;
            };
            self.input_packet(&p);
            let _ = self.flush();
        }
        self.promote_and_reap();
    }

    /// One packet for this stack, by protocol.
    fn input_packet(&mut self, p: &Packet) {
        match p.protocol {
            PROTO_TCP => self.input(p.src, p.dst, &p.payload),
            PROTO_UDP => self.input_udp(p.src, p.dst, &p.payload),
            PROTO_ICMP => self.input_icmp(p),
            _ => {}
        }
    }

    /// A datagram nobody took goes back to its sender as "port
    /// unreachable" (never one sent to several hosts, or from no single
    /// one).
    fn unreachable(&mut self, src: Ipv4Addr, dst: Ipv4Addr, bytes: &[u8]) {
        let single =
            |ip: Ipv4Addr| !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast();
        if let Some(head) = bytes.first_chunk::<8>()
            && single(src)
            && self.is_local(dst)
        {
            let u = Unreachable {
                code: UNREACHABLE_PORT,
                src,
                dst,
                protocol: PROTO_UDP,
                head: *head,
            };
            self.route_proto(PROTO_ICMP, dst, src, u.emit());
        }
    }

    /// What ICMP says of a datagram we sent: the error of the socket that
    /// sent it, if it is connected to where that went.
    fn input_icmp(&mut self, p: &Packet) {
        let Some(u) = Unreachable::parse(&p.payload) else {
            return;
        };
        let port = |at: usize| u16::from_be_bytes([u.head[at], u.head[at + 1]]);
        let error = match u.code {
            // Only the host itself knows its ports.
            UNREACHABLE_PORT if p.src == u.dst => ECONNREFUSED,
            UNREACHABLE_HOST => EHOSTUNREACH,
            _ => return,
        };
        if u.protocol != PROTO_UDP || p.dst != u.src {
            return;
        }
        for (&id, s) in &mut self.socks {
            let ours = s
                .local
                .is_some_and(|(ip, n)| n == port(0) && (ip.is_unspecified() || ip == u.src));
            if let Kind::Udp { peer, .. } = &s.kind
                && ours
                && *peer == Some((u.dst, port(2)))
            {
                s.error = Some(error);
                self.touched.insert(id);
            }
        }
    }

    /// A UDP datagram: queued on the socket bound to its port (and
    /// connected to its source, if connected); dropped if none or full.
    fn input_udp(&mut self, src: Ipv4Addr, dst: Ipv4Addr, bytes: &[u8]) {
        let Some(d) = Udp::parse(bytes, src, dst) else {
            return;
        };
        let from = (src, d.src_port);
        let starved = self.starved;
        // The socket connected to the source first, then one bound to the
        // address, then one bound to all.
        let found: Vec<(u32, u64)> = self
            .socks
            .iter()
            .filter_map(|(&id, s)| {
                let (ip, port) = s.local?;
                match &s.kind {
                    Kind::Udp { peer, .. }
                        if port == d.dst_port
                            && (ip.is_unspecified() || ip == dst)
                            && peer.is_none_or(|p| p == from) =>
                    {
                        let fit = 2 * u32::from(peer.is_some()) + u32::from(ip == dst);
                        Some((fit, id))
                    }
                    _ => None,
                }
            })
            .collect();
        let Some(id) = self.choose(&found, from) else {
            return self.unreachable(src, dst, bytes);
        };
        // A full queue, or a cell short of memory, drops the datagram.
        if let Some(s) = self.socks.get_mut(&id)
            && let Kind::Udp { rx, bytes, .. } = &mut s.kind
            && *bytes + d.payload.len() <= UDP_BUFFER
            && rx.len() < UDP_DATAGRAMS
            && !starved
        {
            *bytes += d.payload.len();
            rx.push_back((from, d.payload.to_vec()));
            self.touched.insert(id);
        }
    }

    /// Which of `found` (how well each fits, and its id) takes what comes
    /// from `from`: of the best, one by the sender if they share the port
    /// for that (SO_REUSEPORT), else the last bound.
    fn choose(&self, found: &[(u32, u64)], from: Addr) -> Option<u64> {
        let best = found.iter().map(|f| f.0).max()?;
        let best: Vec<u64> = found.iter().filter(|f| f.0 == best).map(|f| f.1).collect();
        let shared = best
            .iter()
            .all(|id| self.socks.get(id).is_some_and(|s| s.reuse_port));
        if !shared {
            return best.last().copied();
        }
        let h = (u32::from(from.0) ^ u32::from(from.1)).wrapping_mul(0x9E37_79B1) >> 16;
        best.get(h as usize % best.len()).copied()
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
            let listeners: Vec<(u32, u64)> = self
                .socks
                .iter()
                .filter_map(|(&id, s)| match (&s.kind, s.local) {
                    (Kind::Listening { .. }, Some((ip, port)))
                        if port == local.1 && (ip.is_unspecified() || ip == local.0) =>
                    {
                        Some((u32::from(ip == local.0), id))
                    }
                    _ => None,
                })
                .collect();
            if let Some(lid) = self.choose(&listeners, remote) {
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
                            picked: false,
                            wait: Arc::new(Waiters::default()),
                            reuse_addr: false,
                            reuse_port: false,
                            orphan: false,
                            shut_rd: false,
                            error: None,
                            held: 0,
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
            self.route(dst, src, rst);
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
            self.remove_sock(id);
        }
    }

    /// Forgets socket `id`, and what it held.
    fn remove_sock(&mut self, id: u64) {
        if let Some(s) = self.socks.remove(&id) {
            self.held = self.held.saturating_sub(s.held);
        }
    }

    /// Recounts what the sockets in `ids` hold and settles the stack's
    /// charge with the cell's account. When the account runs short (a
    /// charge fails, or less than [`RESERVE`] pages are left) every
    /// connection's buffers are capped where they stand: windows close and
    /// writers wait, so peers back off instead of losing data. Growth
    /// resumes once there is twice the reserve again. What a single
    /// operation added before the cap took effect may stay uncharged until
    /// the next settle succeeds.
    fn settle(&mut self, ids: &BTreeSet<u64>) {
        for id in ids {
            if let Some(s) = self.socks.get_mut(id) {
                let b = s.kind.buffered();
                self.held = (self.held + b).saturating_sub(s.held);
                s.held = b;
            }
        }
        let Some(acct) = self.account.clone() else {
            return;
        };
        let want = self.held.div_ceil(PAGE) as u64;
        if want < self.charged {
            acct.release(self.charged - want);
            self.charged = want;
        }
        let mut short = false;
        if want > self.charged {
            match acct.charge(want - self.charged) {
                Ok(()) => self.charged = want,
                Err(_) => short = true,
            }
        }
        let t = now();
        if short || acct.available() < RESERVE {
            let newly = !self.starved;
            self.starved = true;
            for (id, s) in &mut self.socks {
                if let Kind::Conn { tcp, .. } = &mut s.kind
                    && (newly || ids.contains(id))
                {
                    tcp.set_cap(0, t);
                }
            }
        } else if self.starved && acct.available() >= 2 * RESERVE {
            self.starved = false;
            for s in self.socks.values_mut() {
                if let Kind::Conn { tcp, .. } = &mut s.kind {
                    tcp.set_cap(tcp::BUFFER, t);
                }
            }
            // Reopened windows are announced now.
            self.run_local();
        }
    }

    fn take_touched(&mut self) -> Vec<Arc<Waiters>> {
        let ids = core::mem::take(&mut self.touched);
        self.settle(&ids);
        // Thawing may have touched more (announcing windows).
        let mut ids = ids;
        ids.extend(core::mem::take(&mut self.touched));
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
        let (r, woken, out) = {
            let mut i = self.inner.lock();
            let r = f(&mut i);
            i.run_local();
            let w = i.take_touched();
            (r, w, core::mem::take(&mut i.out))
        };
        wake_all(woken);
        crate::switch::send(self.cell, out);
        kick();
        r
    }

    /// The address the switch assigned to this stack.
    pub(crate) fn addr(&self) -> Option<Ipv4Addr> {
        self.addr
    }

    /// A packet the switch delivers to this stack; returns the packets
    /// the stack sends in response (the switch routes them).
    pub(crate) fn receive(&self, p: Packet) -> Vec<Packet> {
        let (woken, out) = {
            let mut i = self.inner.lock();
            if Some(p.dst) == i.addr {
                i.input_packet(&p);
            }
            i.run_local();
            (i.take_touched(), core::mem::take(&mut i.out))
        };
        wake_all(woken);
        kick();
        out
    }

    /// A new, unbound socket: TCP, or UDP if `udp`.
    pub(crate) fn socket(&self, udp: bool) -> (u64, Arc<Waiters>) {
        let mut i = self.inner.lock();
        let id = i.new_id();
        let wait = Arc::new(Waiters::default());
        i.socks.insert(
            id,
            Sock {
                kind: if udp {
                    Kind::Udp {
                        rx: VecDeque::new(),
                        bytes: 0,
                        peer: None,
                    }
                } else {
                    Kind::Fresh
                },
                local: None,
                picked: false,
                wait: wait.clone(),
                reuse_addr: false,
                reuse_port: false,
                orphan: false,
                shut_rd: false,
                error: None,
                held: 0,
            },
        );
        (id, wait)
    }

    pub(crate) fn set_reuse_addr(&self, id: u64, on: bool) -> Result<(), i64> {
        self.inner.lock().sock(id)?.reuse_addr = on;
        Ok(())
    }

    pub(crate) fn set_reuse_port(&self, id: u64, on: bool) -> Result<(), i64> {
        self.inner.lock().sock(id)?.reuse_port = on;
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
        if !addr.0.is_unspecified() && !i.is_local(addr.0) {
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
        // SO_REUSEADDR let several bind the port; one of them listens.
        let me = i.sock(id)?;
        let (local, shares) = (me.local, me.reuse_port);
        let other = i.socks.iter().any(|(&n, s)| {
            let (Kind::Listening { .. }, Some((ip, port)), Some((mine, my_port))) =
                (&s.kind, s.local, local)
            else {
                return false;
            };
            let overlap = ip == mine || ip.is_unspecified() || mine.is_unspecified();
            n != id && port == my_port && overlap && !(shares && s.reuse_port)
        });
        if other {
            return Err(EADDRINUSE);
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
            Kind::Udp { .. } => Err(EOPNOTSUPP),
        }
    }

    /// Starts connecting to `remote` (for UDP: fixes the peer).
    pub(crate) fn connect(&self, id: u64, remote: Addr) -> Result<(), i64> {
        let remote = to_this_host(remote);
        self.with(|i| {
            let udp = match i.sock(id)?.kind {
                Kind::Fresh => false,
                Kind::Udp { .. } => true,
                Kind::Conn { .. } => return Err(EISCONN),
                Kind::Listening { .. } => return Err(EINVAL),
            };
            let picked = i.sock(id)?.local.is_none();
            let local = i.source_for(id, remote.0)?;
            if udp {
                let s = i.sock(id)?;
                s.local.get_or_insert(local);
                if let Kind::Udp { peer, .. } = &mut s.kind {
                    *peer = Some(remote);
                }
                return Ok(());
            }
            let tcp = Box::new(Tcp::connect(local, remote, random_iss(), now()));
            let s = i.sock(id)?;
            s.local = Some(local);
            s.picked = picked;
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
                State::Closed => {
                    // It may try again, from where it is bound (if it is).
                    s.kind = Kind::Fresh;
                    if s.picked {
                        s.local = None;
                    }
                    Some(Err(s.error.take().unwrap_or(ECONNREFUSED)))
                }
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
                    return Ok(Some(tcp.peek(out)));
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
            match &mut s.kind {
                Kind::Conn { tcp, .. } => {
                    if wr {
                        tcp.close(now());
                    }
                }
                // A connected datagram socket: only reads change.
                Kind::Udp { peer: Some(_), .. } => {}
                _ => return Err(ENOTCONN),
            }
            if rd {
                s.shut_rd = true;
            }
            i.touched.insert(id);
            Ok(())
        })
    }

    /// The descriptor went away: close gracefully (a listener resets its
    /// queued connections; a connection resets if told to `reset`) and
    /// forget the socket once done.
    pub(crate) fn release(&self, id: u64, reset: bool) {
        self.with(|i| {
            let mut doomed = Vec::new();
            if let Some(s) = i.socks.get_mut(&id) {
                match &mut s.kind {
                    Kind::Fresh | Kind::Udp { .. } => {
                        i.remove_sock(id);
                    }
                    Kind::Listening { backlog, .. } => {
                        doomed.extend(backlog.drain(..));
                        i.remove_sock(id);
                        doomed.extend(i.socks.iter().filter_map(|(&cid, c)| {
                            matches!(c.kind, Kind::Conn { parent: Some(p), .. } if p == id)
                                .then_some(cid)
                        }));
                    }
                    Kind::Conn { tcp, .. } => {
                        // What the application never read goes, and its
                        // memory with it.
                        let unread = tcp.readable() > 0;
                        tcp.discard_received();
                        // Closing on unread data resets too, as on Linux:
                        // the peer learns that not all of it was read.
                        if reset || unread {
                            tcp.abort();
                        } else {
                            tcp.close(now());
                        }
                        s.orphan = true;
                        i.touched.insert(id);
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
            // A datagram socket can always send (a full receiver drops).
            Kind::Udp { rx, .. } => {
                r |= POLLOUT;
                if !rx.is_empty() || s.shut_rd {
                    r |= POLLIN;
                }
            }
        }
        r
    }

    /// Bytes the next read would give: a stream's, or one datagram's.
    pub(crate) fn readable(&self, id: u64) -> usize {
        match self.inner.lock().socks.get(&id).map(|s| &s.kind) {
            Some(Kind::Conn { tcp, .. }) => tcp.readable(),
            Some(Kind::Udp { rx, .. }) => rx.front().map_or(0, |(_, d)| d.len()),
            _ => 0,
        }
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
            Kind::Udp { peer: Some(p), .. } => Ok(*p),
            _ => Err(ENOTCONN),
        }
    }

    /// `connect(AF_UNSPEC)` on a UDP socket: forgets the peer.
    pub(crate) fn disconnect(&self, id: u64) -> Result<(), i64> {
        let mut i = self.inner.lock();
        match &mut i.sock(id)?.kind {
            Kind::Udp { peer, .. } => {
                *peer = None;
                Ok(())
            }
            _ => Err(EOPNOTSUPP),
        }
    }

    /// Sends one UDP datagram to `to`, or to the connected peer. An
    /// unbound socket is bound to an ephemeral port first, as on Linux.
    pub(crate) fn send_to(&self, id: u64, to: Option<Addr>, data: &[u8]) -> Result<usize, i64> {
        if data.len() > UDP_MAX {
            return Err(EMSGSIZE);
        }
        self.with(|i| {
            let s = i.sock(id)?;
            if let Some(e) = s.error.take() {
                return Err(e);
            }
            let Kind::Udp { peer, .. } = &s.kind else {
                return Err(EOPNOTSUPP);
            };
            let dst = match (to, *peer) {
                (Some(t), _) => to_this_host(t),
                (None, Some(p)) => p,
                (None, None) => return Err(EDESTADDRREQ),
            };
            if dst.1 == 0 {
                return Err(EINVAL);
            }
            if i.sock(id)?.local.is_none() {
                let port = i.ephemeral(Ipv4Addr::UNSPECIFIED, id)?;
                i.sock(id)?.local = Some((Ipv4Addr::UNSPECIFIED, port));
            }
            let (sip, sport) = i.source_for(id, dst.0)?;
            let d = net::wire::udp(sip, sport, dst.0, dst.1, data);
            i.route_proto(PROTO_UDP, sip, dst.0, d);
            Ok(data.len())
        })
    }

    /// Takes the next received datagram and its source (a copy, if `peek`):
    /// `Ok(None)` when none is queued.
    pub(crate) fn recv_from(&self, id: u64, peek: bool) -> Result<Option<(Addr, Vec<u8>)>, i64> {
        let mut i = self.inner.lock();
        let s = i.sock(id)?;
        if let Some(e) = s.error.take() {
            return Err(e);
        }
        let shut = s.shut_rd;
        let Kind::Udp { rx, bytes, .. } = &mut s.kind else {
            return Err(EOPNOTSUPP);
        };
        if peek && let Some(d) = rx.front() {
            return Ok(Some(d.clone()));
        }
        match rx.pop_front() {
            Some((from, d)) => {
                *bytes -= d.len();
                // What the queue held goes back to the cell.
                i.touched.insert(id);
                let _ = i.take_touched();
                Ok(Some((from, d)))
            }
            // After shutdown(SHUT_RD) reads return 0 at once.
            None if shut => Ok(Some(((Ipv4Addr::UNSPECIFIED, 0), Vec::new()))),
            None => Ok(None),
        }
    }

    /// `TCP_INFO`: the connection's numbers, if it is one.
    pub(crate) fn tcp_info(&self, id: u64) -> Option<net::tcp::Info> {
        let i = self.inner.lock();
        match &i.socks.get(&id)?.kind {
            Kind::Conn { tcp, .. } => Some(tcp.info()),
            _ => None,
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
        let (next, woken, out) = {
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
            (next, i.take_touched(), core::mem::take(&mut i.out))
        };
        wake_all(woken);
        crate::switch::send(self.cell, out);
        next
    }
}
