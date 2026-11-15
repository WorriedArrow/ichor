//! `AF_UNIX` sockets (ADR-0010 §4): stream, datagram and seqpacket
//! sockets, `socketpair`, names in the cell's root (a socket node that
//! `bind` creates and `connect` resolves, permission-checked like a file)
//! or in the cell's abstract namespace, `SCM_RIGHTS` descriptor passing,
//! `SCM_CREDENTIALS`/`SO_PASSCRED` and `SO_PEERCRED`. They are a per-cell
//! object outside the IP stack: abstract names are keyed by cell, and a
//! path can only be reached through a root that holds it.
//!
//! A descriptor's [`UnixSocket`] owns an [`Endpoint`]; peers, listeners'
//! backlogs and the name tables point at endpoints. Closing the descriptor
//! shuts the endpoint down (its peer sees end of file, pending connections
//! are refused, queued messages and the descriptors they carry are
//! dropped), so the endpoint left behind is an empty shell that is cheap to
//! drop anywhere, wait conditions included.
//!
//! Partial: no `MSG_PEEK`, `MSG_OOB` or `MSG_WAITALL`; a socket whose own
//! descriptor is queued inside it (an `SCM_RIGHTS` cycle) is never freed
//! (Linux has a collector for those); `O_ASYNC` posts `SIGIO` to the
//! `F_SETOWN` process on arrival but carries no `F_SETSIG` siginfo.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use cell::Account;
use frame::sync::SpinLock;

use super::EFAULT;
use crate::netstack::Waiters;
use crate::poll::{Object, POLLHUP, POLLIN, POLLOUT, Watchers};
use crate::process::{Description, Fd, LinuxProcess, ObjectEnd};
use crate::vfs::{Ino, Kind, Vfs};
use crate::{proc, signal};

const EPERM: i64 = 1;
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const EPIPE: i64 = 32;
const ENOTSOCK: i64 = 88;
const EMSGSIZE: i64 = 90;
const EPROTOTYPE: i64 = 91;
const ENOPROTOOPT: i64 = 92;
const EPROTONOSUPPORT: i64 = 93;
const ESOCKTNOSUPPORT: i64 = 94;
const EOPNOTSUPP: i64 = 95;
const EADDRINUSE: i64 = 98;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const ECONNREFUSED: i64 = 111;
const ENOBUFS: i64 = 105;
const PAGE: usize = 4096;

pub(super) const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_SEQPACKET: u64 = 5;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2_000_000;

const SOL_SOCKET: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_LINGER: u64 = 13;
const SO_PASSCRED: u64 = 16;
const SO_PEERCRED: u64 = 17;
const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
const SO_ACCEPTCONN: u64 = 30;
const SO_SNDBUFFORCE: u64 = 32;
const SO_RCVBUFFORCE: u64 = 33;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;

const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

const MSG_PEEK: u64 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;

/// Bytes a socket's receive queue holds (stream bytes, or datagrams).
const BUFFER: usize = 256 * 1024;
/// Most descriptors one `SCM_RIGHTS` message carries (Linux's limit).
const SCM_MAX_FD: usize = 253;
/// `sizeof(sun_path)`.
const SUN_PATH: usize = 108;

/// Sockets bound to paths in one root, by socket node.
pub(crate) type Bound = SpinLock<BTreeMap<Ino, Weak<Endpoint>>>;

/// Abstract names, by (cell, name).
type AbstractNames = SpinLock<BTreeMap<(u64, Vec<u8>), Weak<Endpoint>>>;
static ABSTRACT: AbstractNames = SpinLock::new(BTreeMap::new());

/// Options recorded for getsockopt: `((level, name), value bytes)`.
type SockOpts = Vec<((u64, u64), Vec<u8>)>;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_AUTOBIND: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Type {
    Stream,
    Dgram,
    Seqpacket,
}

impl Type {
    fn code(self) -> i32 {
        match self {
            Type::Stream => SOCK_STREAM as i32,
            Type::Dgram => SOCK_DGRAM as i32,
            Type::Seqpacket => SOCK_SEQPACKET as i32,
        }
    }

    fn connected(self) -> bool {
        self != Type::Dgram
    }
}

/// A bound name: a path (as given to `bind`, and its node) or an
/// abstract name.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Name {
    Path(String, Ino),
    Abstract(Vec<u8>),
}

/// `struct ucred`.
#[derive(Clone, Copy, Debug)]
struct Ucred {
    pid: u32,
    uid: u32,
    gid: u32,
}

impl Ucred {
    fn of(p: &LinuxProcess) -> Ucred {
        let c = p.group.creds();
        Ucred {
            pid: p.group.tgid as u32,
            uid: c.euid,
            gid: c.egid,
        }
    }

    fn bytes(self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&self.pid.to_le_bytes());
        b[4..8].copy_from_slice(&self.uid.to_le_bytes());
        b[8..].copy_from_slice(&self.gid.to_le_bytes());
        b
    }
}

/// One queued message (a stream keeps writes as messages so descriptors
/// stay attached to the bytes they were sent with).
struct Msg {
    data: Vec<u8>,
    fds: Vec<Arc<Description>>,
    from: Option<Name>,
    cred: Ucred,
}

enum Conn {
    Idle,
    Listening {
        backlog: VecDeque<Arc<Endpoint>>,
        max: usize,
    },
    Connected(Weak<Endpoint>),
}

struct State {
    name: Option<Name>,
    conn: Conn,
    rx: VecDeque<Msg>,
    rx_bytes: usize,
    shut_rd: bool,
    shut_wr: bool,
    /// The peer sends no more (it shut down writing, or closed).
    eof: bool,
    /// The connected peer closed: writes fail with EPIPE.
    peer_closed: bool,
    /// This endpoint's descriptor is gone.
    closed: bool,
    peer_cred: Option<Ucred>,
    /// What `listen` recorded, for the clients that connect.
    listen_cred: Option<Ucred>,
    passcred: bool,
    /// `O_ASYNC` and the `F_SETOWN` process.
    async_io: bool,
    owner: Option<u64>,
    /// Pages charged to the cell for the receive queue.
    charged: u64,
}

impl State {
    /// Settles the queue's charge for `bytes` with `acct`; false if the
    /// account cannot cover them.
    fn charge_to(&mut self, acct: &Arc<Account>, bytes: usize) -> bool {
        let want = bytes.div_ceil(PAGE) as u64;
        if want > self.charged && acct.charge(want - self.charged).is_err() {
            return false;
        }
        if want < self.charged {
            acct.release(self.charged - want);
        }
        self.charged = want;
        true
    }
}

/// One end of `AF_UNIX` communication.
pub(crate) struct Endpoint {
    ty: Type,
    cell: u64,
    /// The cell's account, charged for what this end's queue holds.
    account: Arc<Account>,
    id: u64,
    state: SpinLock<State>,
    wait: Waiters,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("ty", &self.ty)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    fn new(ty: Type, cell: &crate::kcell::Cell) -> Arc<Endpoint> {
        Arc::new(Endpoint {
            ty,
            cell: cell.id(),
            account: cell.account().clone(),
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            state: SpinLock::new(State {
                name: None,
                conn: Conn::Idle,
                rx: VecDeque::new(),
                rx_bytes: 0,
                shut_rd: false,
                shut_wr: false,
                eof: false,
                peer_closed: false,
                closed: false,
                peer_cred: None,
                listen_cred: None,
                passcred: false,
                async_io: false,
                owner: None,
                charged: 0,
            }),
            wait: Waiters::default(),
        })
    }

    /// The connected peer, if it still exists.
    fn peer(&self) -> Option<Arc<Endpoint>> {
        match &self.state.lock().conn {
            Conn::Connected(w) => w.upgrade(),
            _ => None,
        }
    }

    /// Shuts this endpoint down; returns what it held, to drop outside
    /// every lock.
    fn shut_down(&self) -> (Vec<Msg>, Vec<Arc<Endpoint>>, Option<Name>) {
        let (conn, msgs, name) = {
            let mut st = self.state.lock();
            st.closed = true;
            st.rx_bytes = 0;
            st.charge_to(&self.account, 0);
            let conn = core::mem::replace(&mut st.conn, Conn::Idle);
            (conn, core::mem::take(&mut st.rx), st.name.clone())
        };
        let mut msgs: Vec<Msg> = msgs.into_iter().collect();
        let mut pending = Vec::new();
        match conn {
            Conn::Connected(w) if self.ty.connected() => {
                if let Some(peer) = w.upgrade() {
                    {
                        let mut ps = peer.state.lock();
                        ps.eof = true;
                        ps.peer_closed = true;
                    }
                    peer.wait.wake();
                    pending.push(peer);
                }
            }
            Conn::Listening { backlog, .. } => {
                // Connections never accepted are refused: their clients see
                // the end.
                for e in backlog {
                    let (m, p, _) = e.shut_down();
                    msgs.extend(m);
                    pending.extend(p);
                    pending.push(e);
                }
            }
            _ => {}
        }
        self.wait.wake();
        (msgs, pending, name)
    }
}

/// An `AF_UNIX` socket behind a descriptor.
pub(crate) struct UnixSocket {
    ep: Arc<Endpoint>,
    /// The root its paths resolve in (the creating process's).
    vfs: Arc<Vfs>,
    /// Who created it: the credentials `write` sends with.
    cred: Ucred,
    opts: SpinLock<SockOpts>,
}

impl fmt::Debug for UnixSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixSocket")
            .field("ep", &self.ep)
            .finish_non_exhaustive()
    }
}

impl UnixSocket {
    fn new(ep: Arc<Endpoint>, vfs: Arc<Vfs>, cred: Ucred) -> UnixSocket {
        UnixSocket {
            ep,
            vfs,
            cred,
            opts: SpinLock::new(Vec::new()),
        }
    }

    /// The number `/proc/<pid>/fd` shows (`socket:[N]`).
    pub(crate) fn inode(&self) -> u64 {
        (1 << 40) | self.ep.id
    }

    /// `O_ASYNC` on or off, and the process `SIGIO` goes to.
    pub(crate) fn set_async(&self, on: Option<bool>, owner: Option<u64>) {
        let mut st = self.ep.state.lock();
        if let Some(on) = on {
            st.async_io = on;
        }
        if let Some(o) = owner {
            st.owner = Some(o);
        }
    }

    /// `F_GETOWN`.
    pub(crate) fn owner(&self) -> u64 {
        self.ep.state.lock().owner.unwrap_or(0)
    }

    /// Whether `O_ASYNC` is on (for `F_GETFL`).
    pub(crate) fn is_async(&self) -> bool {
        self.ep.state.lock().async_io
    }
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        let (msgs, peers, name) = self.ep.shut_down();
        match name {
            Some(Name::Path(_, ino)) => {
                let mut b = self.vfs.unix.lock();
                if b.get(&ino)
                    .is_some_and(|w| w.as_ptr() == Arc::as_ptr(&self.ep))
                {
                    b.remove(&ino);
                }
            }
            Some(Name::Abstract(n)) => {
                let mut a = ABSTRACT.lock();
                let key = (self.ep.cell, n);
                if a.get(&key)
                    .is_some_and(|w| w.as_ptr() == Arc::as_ptr(&self.ep))
                {
                    a.remove(&key);
                }
            }
            None => {}
        }
        drop(msgs);
        drop(peers);
    }
}

/// Blocks on `w` until `attempt` yields, honoring non-blocking mode and
/// signals.
fn block<T>(
    w: &Waiters,
    nonblock: bool,
    interrupted: &dyn Fn() -> bool,
    mut attempt: impl FnMut() -> Option<Result<T, i64>>,
) -> Result<T, i64> {
    w.queue.wait_until(|| match attempt() {
        Some(r) => Some(r),
        None if nonblock => Some(Err(EAGAIN)),
        None if interrupted() => Some(Err(signal::ERESTARTSYS)),
        None => None,
    })
}

/// What one receive took.
pub(super) struct Received {
    data: Vec<u8>,
    fds: Vec<Arc<Description>>,
    from: Option<Name>,
    cred: Option<Ucred>,
    /// A datagram's or packet's full length (more than `data` when cut).
    full: usize,
}

/// Wakes `to`'s readers and posts `SIGIO` if it asked for it.
fn arrived(to: &Endpoint) {
    let owner = {
        let st = to.state.lock();
        st.owner.filter(|_| st.async_io)
    };
    to.wait.wake();
    if let Some(pid) = owner {
        let _ = proc::send(to.cell, pid, signal::SIGIO);
    }
}

impl Endpoint {
    /// One attempt to queue `data` (and `fds`, with its first bytes) on
    /// `peer`, the connected end: `None` while there is no room.
    fn try_send_conn(
        &self,
        peer: &Endpoint,
        data: &[u8],
        fds: &mut Vec<Arc<Description>>,
        cred: Ucred,
    ) -> Option<Result<usize, i64>> {
        if self.state.lock().shut_wr {
            return Some(Err(EPIPE));
        }
        let mut ps = peer.state.lock();
        if ps.closed || ps.shut_rd {
            return Some(Err(EPIPE));
        }
        let room = BUFFER.saturating_sub(ps.rx_bytes);
        let n = match self.ty {
            Type::Stream => {
                if data.is_empty() && fds.is_empty() {
                    return Some(Ok(0));
                }
                if room == 0 {
                    return None;
                }
                data.len().min(room)
            }
            _ => {
                if data.len() > room && ps.rx_bytes > 0 {
                    return None;
                }
                data.len()
            }
        };
        // The queue is the receiving cell's memory: with nothing queued to
        // wait for, a cell out of memory fails the write.
        let after = ps.rx_bytes + n;
        if !ps.charge_to(&peer.account, after) {
            return if ps.rx.is_empty() {
                Some(Err(ENOBUFS))
            } else {
                None
            };
        }
        ps.rx_bytes += n;
        ps.rx.push_back(Msg {
            data: data[..n].to_vec(),
            fds: core::mem::take(fds),
            from: None,
            cred,
        });
        Some(Ok(n))
    }

    /// One attempt to queue a datagram on `to`.
    fn try_send_dgram(
        &self,
        to: &Endpoint,
        data: &[u8],
        fds: &mut Vec<Arc<Description>>,
        from: &Option<Name>,
        cred: Ucred,
    ) -> Option<Result<usize, i64>> {
        let mut ts = to.state.lock();
        if ts.closed {
            return Some(Err(ECONNREFUSED));
        }
        // A socket connected elsewhere takes datagrams from its peer only.
        if let Conn::Connected(w) = &ts.conn
            && w.as_ptr() != core::ptr::from_ref(self)
        {
            return Some(Err(EPERM));
        }
        if ts.rx_bytes + data.len() > BUFFER && ts.rx_bytes > 0 {
            return None;
        }
        let after = ts.rx_bytes + data.len();
        if !ts.charge_to(&to.account, after) {
            return if ts.rx.is_empty() {
                Some(Err(ENOBUFS))
            } else {
                None
            };
        }
        ts.rx_bytes += data.len();
        ts.rx.push_back(Msg {
            data: data.to_vec(),
            fds: core::mem::take(fds),
            from: from.clone(),
            cred,
        });
        Some(Ok(data.len()))
    }

    /// One attempt to receive up to `max` bytes: `None` while nothing is
    /// queued and more may come.
    fn try_recv(&self, max: usize) -> Option<Result<Received, i64>> {
        let mut st = self.state.lock();
        let empty = Received {
            data: Vec::new(),
            fds: Vec::new(),
            from: None,
            cred: None,
            full: 0,
        };
        if st.rx.is_empty() {
            if st.shut_rd || (self.ty.connected() && (st.eof || st.peer_closed)) {
                return Some(Ok(empty));
            }
            if self.ty.connected() && !matches!(st.conn, Conn::Connected(_)) {
                return Some(Err(if matches!(st.conn, Conn::Listening { .. }) {
                    EINVAL
                } else {
                    ENOTCONN
                }));
            }
            return None;
        }
        if self.ty != Type::Stream {
            let m = st.rx.pop_front()?;
            st.rx_bytes -= m.data.len();
            let left = st.rx_bytes;
            st.charge_to(&self.account, left);
            let full = m.data.len();
            let mut data = m.data;
            data.truncate(max);
            return Some(Ok(Received {
                data,
                fds: m.fds,
                from: m.from,
                cred: Some(m.cred),
                full,
            }));
        }
        // A stream read takes bytes across writes, but descriptors start a
        // read of their own and end it.
        let mut out = Vec::new();
        let mut fds = Vec::new();
        let mut cred = None;
        let State { rx, rx_bytes, .. } = &mut *st;
        while out.len() < max {
            let Some(m) = rx.front_mut() else {
                break;
            };
            if !m.fds.is_empty() && !out.is_empty() {
                break;
            }
            fds = core::mem::take(&mut m.fds);
            cred.get_or_insert(m.cred);
            let take = (max - out.len()).min(m.data.len());
            out.extend(m.data.drain(..take));
            *rx_bytes -= take;
            if m.data.is_empty() {
                rx.pop_front();
            }
            if !fds.is_empty() {
                break;
            }
        }
        let left = st.rx_bytes;
        st.charge_to(&self.account, left);
        let full = out.len();
        Some(Ok(Received {
            data: out,
            fds,
            from: None,
            cred,
            full,
        }))
    }
}

impl UnixSocket {
    /// Sends `data` with `fds` to `to` (datagrams) or the peer.
    fn send(
        &self,
        data: &[u8],
        mut fds: Vec<Arc<Description>>,
        to: Option<Arc<Endpoint>>,
        cred: Ucred,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        let ep = &self.ep;
        if ep.ty == Type::Dgram {
            if data.len() > BUFFER {
                return Err(EMSGSIZE);
            }
            let target = match to {
                Some(t) => t,
                None => match &ep.state.lock().conn {
                    Conn::Connected(w) => w.upgrade().ok_or(ECONNREFUSED)?,
                    _ => return Err(ENOTCONN),
                },
            };
            if target.ty != Type::Dgram {
                return Err(EPROTOTYPE);
            }
            let from = ep.state.lock().name.clone();
            let n = block(&target.wait, nonblock, interrupted, || {
                ep.try_send_dgram(&target, data, &mut fds, &from, cred)
            })?;
            arrived(&target);
            return Ok(n);
        }
        if ep.ty == Type::Seqpacket && data.len() > BUFFER {
            return Err(EMSGSIZE);
        }
        let peer = {
            let st = ep.state.lock();
            if st.shut_wr || st.peer_closed {
                return Err(EPIPE);
            }
            match &st.conn {
                Conn::Connected(w) => w.upgrade().ok_or(EPIPE)?,
                _ => return Err(ENOTCONN),
            }
        };
        let n = block(&peer.wait, nonblock, interrupted, || {
            ep.try_send_conn(&peer, data, &mut fds, cred)
        })?;
        arrived(&peer);
        Ok(n)
    }

    /// Receives up to `max` bytes.
    fn recv(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Received, i64> {
        let r = block(&self.ep.wait, nonblock, interrupted, || {
            self.ep.try_recv(max)
        })?;
        // Room opened: wake writers waiting on us, and our peer's pollers.
        self.ep.wait.wake();
        if let Some(peer) = self.ep.peer() {
            peer.wait.wake();
        }
        Ok(r)
    }
}

impl Object for UnixSocket {
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        // Descriptors sent with these bytes are dropped (closed), as a
        // plain read on Linux does.
        self.recv(max, nonblock, interrupted).map(|r| r.data)
    }

    fn write(
        &self,
        data: &[u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        self.send(data, Vec::new(), None, self.cred, nonblock, interrupted)
    }

    fn poll(&self) -> u16 {
        let ep = &self.ep;
        let (mut r, peer) = {
            let st = ep.state.lock();
            if let Conn::Listening { backlog, .. } = &st.conn {
                return if backlog.is_empty() { 0 } else { POLLIN };
            }
            let mut r = 0;
            if !st.rx.is_empty() || st.shut_rd || (ep.ty.connected() && st.eof) {
                r |= POLLIN;
            }
            if ep.ty.connected() && (st.peer_closed || (st.eof && st.shut_wr)) {
                r |= POLLHUP;
            }
            let peer = match &st.conn {
                Conn::Connected(w) => Some(w.clone()),
                _ => None,
            };
            if st.shut_wr {
                return r;
            }
            (r, peer)
        };
        match peer.as_ref().map(Weak::upgrade) {
            Some(Some(pe)) => {
                let ps = pe.state.lock();
                if !ps.closed && ps.rx_bytes < BUFFER {
                    r |= POLLOUT;
                }
            }
            Some(None) => {}
            // An unconnected datagram socket can always try.
            None if ep.ty == Type::Dgram => r |= POLLOUT,
            None => {}
        }
        r
    }

    fn changes(&self) -> u64 {
        self.ep.wait.changes.load(Ordering::Acquire)
    }

    fn mode(&self) -> u32 {
        0o140_000 // S_IFSOCK
    }

    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.ep.wait.watchers)
    }

    fn unix(&self) -> Option<&UnixSocket> {
        Some(self)
    }
}

// ---------------------------------------------------------------------------
// Addresses.
// ---------------------------------------------------------------------------

/// A `sockaddr_un` as given.
enum Target {
    /// Only the family (`bind`: autobind).
    Unnamed,
    Path(String),
    Abstract(Vec<u8>),
}

fn read_sun(p: &mut LinuxProcess, addr: u64, len: u64) -> Result<Target, i64> {
    let len = usize::try_from(len).map_err(|_| EINVAL)?;
    if !(2..=2 + SUN_PATH).contains(&len) {
        return Err(EINVAL);
    }
    let mut b = alloc::vec![0u8; len];
    if p.copy_from_user(addr, &mut b) != len {
        return Err(EFAULT);
    }
    if u64::from(u16::from_le_bytes([b[0], b[1]])) != AF_UNIX {
        return Err(EINVAL);
    }
    let path = &b[2..];
    match path.first() {
        None => Ok(Target::Unnamed),
        Some(0) => Ok(Target::Abstract(path[1..].to_vec())),
        Some(_) => {
            let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
            String::from_utf8(path[..end].to_vec())
                .map(Target::Path)
                .map_err(|_| crate::vfs::errno::ENOENT)
        }
    }
}

/// Writes `name` as a `sockaddr_un` to `addr`, whose buffer length is at
/// `lenp` (set to the full length).
fn write_sun(p: &mut LinuxProcess, addr: u64, lenp: u64, name: Option<&Name>) -> Result<(), i64> {
    if lenp == 0 {
        return Ok(());
    }
    let mut b = (AF_UNIX as u16).to_le_bytes().to_vec();
    match name {
        Some(Name::Path(s, _)) => {
            b.extend_from_slice(s.as_bytes());
            b.push(0);
        }
        Some(Name::Abstract(n)) => {
            b.push(0);
            b.extend_from_slice(n);
        }
        None => {}
    }
    let mut lb = [0u8; 4];
    if p.copy_from_user(lenp, &mut lb) != 4 {
        return Err(EFAULT);
    }
    let n = (u32::from_le_bytes(lb) as usize).min(b.len());
    if (addr != 0 && p.copy_to_user(addr, &b[..n]) != n)
        || p.copy_to_user(lenp, &(b.len() as u32).to_le_bytes()) != 4
    {
        return Err(EFAULT);
    }
    Ok(())
}

/// The endpoint a name reaches from `p`.
fn lookup(p: &mut LinuxProcess, u: &UnixSocket, t: &Target) -> Result<Arc<Endpoint>, i64> {
    let ep = match t {
        Target::Unnamed => return Err(EINVAL),
        Target::Abstract(n) => ABSTRACT
            .lock()
            .get(&(u.ep.cell, n.clone()))
            .and_then(Weak::upgrade),
        Target::Path(path) => {
            let cwd = p.cwd();
            let ino = {
                let mut fs = p.fs();
                let ino = fs.resolve(cwd, path, true)?;
                if fs.stat(ino)?.kind != Kind::Socket {
                    return Err(ECONNREFUSED);
                }
                fs.permission(ino, overlay::MAY_WRITE)?;
                ino
            };
            u.vfs.unix.lock().get(&ino).and_then(Weak::upgrade)
        }
    };
    let ep = ep.ok_or(ECONNREFUSED)?;
    if ep.state.lock().closed {
        return Err(ECONNREFUSED);
    }
    Ok(ep)
}

// ---------------------------------------------------------------------------
// Syscalls (the socket layer dispatches here for AF_UNIX objects).
// ---------------------------------------------------------------------------

fn type_of(ty: u64, proto: u64) -> Result<Type, i64> {
    if proto != 0 {
        return Err(EPROTONOSUPPORT);
    }
    match ty & 0xf {
        SOCK_STREAM => Ok(Type::Stream),
        SOCK_DGRAM => Ok(Type::Dgram),
        SOCK_SEQPACKET => Ok(Type::Seqpacket),
        _ => Err(ESOCKTNOSUPPORT),
    }
}

fn install(p: &mut LinuxProcess, u: UnixSocket, ty: u64) -> Result<u64, i64> {
    p.install_flags(
        Fd::Object(ObjectEnd {
            obj: Arc::new(u),
            nonblock: ty & SOCK_NONBLOCK != 0,
        }),
        ty & SOCK_CLOEXEC != 0,
    )
    .ok_or(EMFILE)
}

/// `socket(AF_UNIX, ty, proto)`.
pub(super) fn socket(p: &mut LinuxProcess, ty: u64, proto: u64) -> Result<u64, i64> {
    let t = type_of(ty, proto)?;
    let u = UnixSocket::new(Endpoint::new(t, &p.cell), p.vfs.clone(), Ucred::of(p));
    install(p, u, ty)
}

/// `socketpair(AF_UNIX, ty, proto, sv)`.
pub(super) fn socketpair(p: &mut LinuxProcess, ty: u64, proto: u64, sv: u64) -> Result<u64, i64> {
    let t = type_of(ty, proto)?;
    let cred = Ucred::of(p);
    let (a, b) = (Endpoint::new(t, &p.cell), Endpoint::new(t, &p.cell));
    for (x, y) in [(&a, &b), (&b, &a)] {
        let mut st = x.state.lock();
        st.conn = Conn::Connected(Arc::downgrade(y));
        st.peer_cred = Some(cred);
    }
    let fa = install(p, UnixSocket::new(a, p.vfs.clone(), cred), ty)?;
    let fb = match install(p, UnixSocket::new(b, p.vfs.clone(), cred), ty) {
        Ok(f) => f,
        Err(e) => {
            p.close(fa);
            return Err(e);
        }
    };
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(fa as u32).to_le_bytes());
    out[4..].copy_from_slice(&(fb as u32).to_le_bytes());
    if p.copy_to_user(sv, &out) != 8 {
        p.close(fa);
        p.close(fb);
        return Err(EFAULT);
    }
    Ok(0)
}

pub(super) fn bind(p: &mut LinuxProcess, u: &UnixSocket, addr: u64, len: u64) -> Result<u64, i64> {
    let t = read_sun(p, addr, len)?;
    if u.ep.state.lock().name.is_some() {
        return Err(EINVAL);
    }
    let name = match t {
        Target::Path(path) => {
            let cwd = p.cwd();
            let umask = p.umask();
            let ino = {
                let mut fs = p.fs();
                let (dir, leaf) = fs.resolve_parent(cwd, &path)?;
                fs.mksocket(dir, &leaf, 0o777 & !umask)
                    .map_err(|e| if e == EEXIST { EADDRINUSE } else { e })?
            };
            u.vfs.unix.lock().insert(ino, Arc::downgrade(&u.ep));
            Name::Path(path, ino)
        }
        Target::Abstract(n) => {
            let mut a = ABSTRACT.lock();
            let key = (u.ep.cell, n.clone());
            if a.get(&key).and_then(Weak::upgrade).is_some() {
                return Err(EADDRINUSE);
            }
            a.insert(key, Arc::downgrade(&u.ep));
            Name::Abstract(n)
        }
        // Autobind: a fresh abstract name of five hex digits.
        Target::Unnamed => {
            let mut a = ABSTRACT.lock();
            let n = loop {
                let k = NEXT_AUTOBIND.fetch_add(1, Ordering::Relaxed) & 0xf_ffff;
                let n = alloc::format!("{k:05x}").into_bytes();
                if a.get(&(u.ep.cell, n.clone()))
                    .and_then(Weak::upgrade)
                    .is_none()
                {
                    break n;
                }
            };
            a.insert((u.ep.cell, n.clone()), Arc::downgrade(&u.ep));
            Name::Abstract(n)
        }
    };
    u.ep.state.lock().name = Some(name);
    Ok(0)
}

pub(super) fn listen(p: &LinuxProcess, u: &UnixSocket, backlog: u64) -> Result<u64, i64> {
    if u.ep.ty == Type::Dgram {
        return Err(EOPNOTSUPP);
    }
    let max = (backlog as i32).clamp(1, 4096) as usize;
    let mut st = u.ep.state.lock();
    if st.name.is_none() {
        return Err(EINVAL);
    }
    match &mut st.conn {
        Conn::Listening { max: m, .. } => *m = max,
        Conn::Connected(_) => return Err(EINVAL),
        Conn::Idle => {
            st.conn = Conn::Listening {
                backlog: VecDeque::new(),
                max,
            };
        }
    }
    st.listen_cred = Some(Ucred::of(p));
    Ok(0)
}

pub(super) fn connect(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    nonblock: bool,
    addr: u64,
    len: u64,
) -> Result<u64, i64> {
    let mut fam = [0u8; 2];
    if len >= 2 && p.copy_from_user(addr, &mut fam) == 2 && u16::from_le_bytes(fam) == 0 {
        // AF_UNSPEC: a datagram socket forgets its peer.
        if u.ep.ty == Type::Dgram {
            u.ep.state.lock().conn = Conn::Idle;
            return Ok(0);
        }
        return Err(EINVAL);
    }
    let t = read_sun(p, addr, len)?;
    let target = lookup(p, u, &t)?;
    if target.ty != u.ep.ty {
        return Err(EPROTOTYPE);
    }
    let ep = &u.ep;
    if ep.ty == Type::Dgram {
        ep.state.lock().conn = Conn::Connected(Arc::downgrade(&target));
        return Ok(0);
    }
    match ep.state.lock().conn {
        Conn::Idle => {}
        Conn::Connected(_) => return Err(EISCONN),
        Conn::Listening { .. } => return Err(EINVAL),
    }
    // The server's end: it is connected to us and named like its listener.
    let srv = Endpoint::new(ep.ty, &p.cell);
    {
        let mut ss = srv.state.lock();
        ss.conn = Conn::Connected(Arc::downgrade(ep));
        ss.peer_cred = Some(Ucred::of(p));
        ss.name = target.state.lock().name.clone();
    }
    let entry = p.entry.clone();
    let listen_cred = block(
        &target.wait,
        nonblock,
        &|| proc::interrupted(&entry),
        || {
            let mut ts = target.state.lock();
            if ts.closed {
                return Some(Err(ECONNREFUSED));
            }
            let cred = ts.listen_cred;
            match &mut ts.conn {
                Conn::Listening { backlog, max } if backlog.len() < *max => {
                    backlog.push_back(srv.clone());
                    Some(Ok(cred))
                }
                Conn::Listening { .. } => None,
                _ => Some(Err(ECONNREFUSED)),
            }
        },
    )?;
    {
        let mut st = ep.state.lock();
        st.conn = Conn::Connected(Arc::downgrade(&srv));
        st.peer_cred = listen_cred;
    }
    arrived(&target);
    Ok(0)
}

pub(super) fn accept(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    nonblock: bool,
    addr: u64,
    lenp: u64,
    flags: u64,
) -> Result<u64, i64> {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    if u.ep.ty == Type::Dgram {
        return Err(EOPNOTSUPP);
    }
    let entry = p.entry.clone();
    let srv = block(
        &u.ep.wait,
        nonblock,
        &|| proc::interrupted(&entry),
        || match &mut u.ep.state.lock().conn {
            Conn::Listening { backlog, .. } => backlog.pop_front().map(Ok),
            _ => Some(Err(EINVAL)),
        },
    )?;
    let peer_name = srv.peer().and_then(|c| c.state.lock().name.clone());
    let fd = install(p, UnixSocket::new(srv, u.vfs.clone(), u.cred), flags)?;
    if addr != 0 {
        write_sun(p, addr, lenp, peer_name.as_ref())?;
    }
    Ok(fd)
}

pub(super) fn getsockname(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    addr: u64,
    lenp: u64,
) -> Result<u64, i64> {
    let name = u.ep.state.lock().name.clone();
    write_sun(p, addr, lenp, name.as_ref()).map(|()| 0)
}

pub(super) fn getpeername(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    addr: u64,
    lenp: u64,
) -> Result<u64, i64> {
    let peer = u.ep.peer().ok_or(ENOTCONN)?;
    let name = peer.state.lock().name.clone();
    write_sun(p, addr, lenp, name.as_ref()).map(|()| 0)
}

pub(super) fn shutdown(u: &UnixSocket, how: u64) -> Result<u64, i64> {
    let (rd, wr) = match how {
        0 => (true, false),
        1 => (false, true),
        2 => (true, true),
        _ => return Err(EINVAL),
    };
    let peer = {
        let mut st = u.ep.state.lock();
        if !matches!(st.conn, Conn::Connected(_)) {
            return Err(ENOTCONN);
        }
        st.shut_rd |= rd;
        st.shut_wr |= wr;
        match &st.conn {
            Conn::Connected(w) => w.upgrade(),
            _ => None,
        }
    };
    if let Some(peer) = peer
        && u.ep.ty.connected()
    {
        // Our end stops writing: theirs reads to the end. (Our end stops
        // reading: their writes see our shut_rd and fail.)
        peer.state.lock().eof |= wr;
        peer.wait.wake();
    }
    u.ep.wait.wake();
    Ok(0)
}

fn int(v: i32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn recorded(name: u64) -> bool {
    matches!(
        name,
        SO_REUSEADDR
            | SO_SNDBUF
            | SO_RCVBUF
            | SO_KEEPALIVE
            | SO_LINGER
            | SO_RCVTIMEO
            | SO_SNDTIMEO
            | SO_SNDBUFFORCE
            | SO_RCVBUFFORCE
    )
}

pub(super) fn setsockopt(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    level: u64,
    name: u64,
    val: u64,
    len: u64,
) -> Result<u64, i64> {
    if level != SOL_SOCKET || !(recorded(name) || name == SO_PASSCRED) {
        return Err(ENOPROTOOPT);
    }
    let len = usize::try_from(len).map_err(|_| EINVAL)?.min(64);
    let mut v = alloc::vec![0u8; len];
    if p.copy_from_user(val, &mut v) != len {
        return Err(EFAULT);
    }
    if name == SO_PASSCRED {
        u.ep.state.lock().passcred = v.iter().any(|&b| b != 0);
        return Ok(0);
    }
    let mut opts = u.opts.lock();
    opts.retain(|(k, _)| *k != (level, name));
    opts.push(((level, name), v));
    Ok(0)
}

pub(super) fn getsockopt(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    level: u64,
    name: u64,
    val: u64,
    lenp: u64,
) -> Result<u64, i64> {
    if level != SOL_SOCKET {
        return Err(ENOPROTOOPT);
    }
    let value = {
        let st = u.ep.state.lock();
        match name {
            SO_TYPE => int(u.ep.ty.code()),
            SO_ERROR => int(0),
            SO_DOMAIN => int(AF_UNIX as i32),
            SO_PROTOCOL => int(0),
            SO_ACCEPTCONN => int(i32::from(matches!(st.conn, Conn::Listening { .. }))),
            SO_PASSCRED => int(i32::from(st.passcred)),
            // No peer: pid 0 and the overflow ids, as Linux reports.
            SO_PEERCRED => st
                .peer_cred
                .unwrap_or(Ucred {
                    pid: 0,
                    uid: u32::MAX,
                    gid: u32::MAX,
                })
                .bytes()
                .to_vec(),
            n if recorded(n) => {
                let default = if matches!(n, SO_SNDBUF | SO_RCVBUF) {
                    int(BUFFER as i32)
                } else {
                    int(0)
                };
                u.opts
                    .lock()
                    .iter()
                    .find(|(k, _)| *k == (level, n))
                    .map_or(default, |(_, v)| v.clone())
            }
            _ => return Err(ENOPROTOOPT),
        }
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

/// The descriptors an `SCM_RIGHTS` control buffer names.
fn rights(p: &mut LinuxProcess, ctl: u64, len: u64) -> Result<Vec<Arc<Description>>, i64> {
    if ctl == 0 || len == 0 {
        return Ok(Vec::new());
    }
    let len = usize::try_from(len).map_err(|_| EINVAL)?.min(64 * 1024);
    let mut b = alloc::vec![0u8; len];
    if p.copy_from_user(ctl, &mut b) != len {
        return Err(EFAULT);
    }
    let mut fds = Vec::new();
    let mut at = 0;
    while at + 16 <= len {
        let clen = u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8])) as usize;
        let level = i32::from_le_bytes(b[at + 8..at + 12].try_into().unwrap_or([0; 4]));
        let ty = i32::from_le_bytes(b[at + 12..at + 16].try_into().unwrap_or([0; 4]));
        if clen < 16 || at + clen > len {
            return Err(EINVAL);
        }
        match (level as u64, ty) {
            (SOL_SOCKET, SCM_RIGHTS) => {
                for c in b[at + 16..at + clen].as_chunks::<4>().0 {
                    let fd = u32::from_le_bytes(*c);
                    fds.push(p.desc(u64::from(fd)).ok_or(EBADF)?);
                }
                if fds.len() > SCM_MAX_FD {
                    return Err(EINVAL);
                }
            }
            // The kernel stamps the sender's real credentials.
            (SOL_SOCKET, SCM_CREDENTIALS) => {}
            _ => return Err(EINVAL),
        }
        at += clen.next_multiple_of(8);
    }
    Ok(fds)
}

/// Gathers `iov` from user memory, up to `max` bytes (`EMSGSIZE` past it
/// for a message type).
fn gather(p: &mut LinuxProcess, u: &UnixSocket, iov: &[(u64, usize)]) -> Result<Vec<u8>, i64> {
    let total: usize = iov.iter().map(|&(_, l)| l).sum();
    let want = if u.ep.ty == Type::Stream {
        total.min(BUFFER)
    } else if total > BUFFER {
        return Err(EMSGSIZE);
    } else {
        total
    };
    let mut data = Vec::with_capacity(want);
    for &(base, len) in iov {
        let take = len.min(want - data.len());
        let at = data.len();
        data.resize(at + take, 0);
        if p.copy_from_user(base, &mut data[at..]) != take {
            return Err(EFAULT);
        }
        if data.len() == want {
            break;
        }
    }
    Ok(data)
}

/// Sends on `u` for `sendto`/`sendmsg`; EPIPE raises SIGPIPE unless
/// `MSG_NOSIGNAL`.
fn send_from(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    nonblock: bool,
    data: &[u8],
    fds: Vec<Arc<Description>>,
    to: Option<Target>,
    flags: u64,
) -> Result<u64, i64> {
    let to = match to {
        Some(t) if u.ep.ty == Type::Dgram => Some(lookup(p, u, &t)?),
        Some(_) if u.ep.state.lock().peer_cred.is_some() => return Err(EISCONN),
        Some(_) => return Err(EOPNOTSUPP),
        None => None,
    };
    let entry = p.entry.clone();
    let cred = Ucred::of(p);
    let r = u.send(
        data,
        fds,
        to,
        cred,
        nonblock || flags & MSG_DONTWAIT != 0,
        &|| proc::interrupted(&entry),
    );
    if r == Err(EPIPE) && flags & MSG_NOSIGNAL == 0 {
        proc::post(&p.entry, signal::SIGPIPE);
    }
    r.map(|n| n as u64)
}

pub(super) fn sendto(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    nonblock: bool,
    a: &[u64; 6],
) -> Result<u64, i64> {
    let len = usize::try_from(a[2]).map_err(|_| EINVAL)?;
    let data = gather(p, u, &[(a[1], len)])?;
    let to = if a[4] == 0 {
        None
    } else {
        Some(read_sun(p, a[4], a[5])?)
    };
    send_from(p, u, nonblock, &data, Vec::new(), to, a[3])
}

pub(super) fn sendmsg(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    nonblock: bool,
    msg: u64,
    flags: u64,
) -> Result<u64, i64> {
    let h = super::socket::msg_hdr(p, msg)?;
    let data = gather(p, u, &h.iov)?;
    let fds = rights(p, h.control, h.controllen)?;
    let to = if h.name == 0 || h.namelen == 0 {
        None
    } else {
        Some(read_sun(p, h.name, h.namelen)?)
    };
    send_from(p, u, nonblock, &data, fds, to, flags)
}

fn recv_from(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    nonblock: bool,
    max: usize,
    flags: u64,
) -> Result<Received, i64> {
    if flags & MSG_PEEK != 0 {
        return Err(EOPNOTSUPP);
    }
    let entry = p.entry.clone();
    u.recv(max, nonblock || flags & MSG_DONTWAIT != 0, &|| {
        proc::interrupted(&entry)
    })
}

pub(super) fn recvfrom(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    nonblock: bool,
    a: &[u64; 6],
) -> Result<u64, i64> {
    let max = usize::try_from(a[2]).map_err(|_| EINVAL)?;
    let r = recv_from(p, u, nonblock, max, a[3])?;
    if p.copy_to_user(a[1], &r.data) != r.data.len() {
        return Err(EFAULT);
    }
    if a[4] != 0 {
        write_sun(p, a[4], a[5], r.from.as_ref())?;
    }
    let n = if a[3] & MSG_TRUNC != 0 {
        r.full
    } else {
        r.data.len()
    };
    Ok(n as u64)
}

/// A control message: header and data, padded to 8 bytes.
fn cmsg(out: &mut Vec<u8>, ty: i32, data: &[u8]) {
    out.extend_from_slice(&(16 + data.len() as u64).to_le_bytes());
    out.extend_from_slice(&(SOL_SOCKET as i32).to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(8), 0);
}

pub(super) fn recvmsg(
    p: &mut LinuxProcess,
    u: &UnixSocket,
    nonblock: bool,
    msg: u64,
    flags: u64,
) -> Result<u64, i64> {
    let h = super::socket::msg_hdr(p, msg)?;
    let total: usize = h.iov.iter().map(|&(_, l)| l).sum();
    let r = recv_from(p, u, nonblock, total, flags)?;
    let mut at = 0;
    for &(base, len) in &h.iov {
        if at >= r.data.len() {
            break;
        }
        let n = len.min(r.data.len() - at);
        if p.copy_to_user(base, &r.data[at..at + n]) != n {
            return Err(EFAULT);
        }
        at += n;
    }
    if h.name != 0 {
        write_sun(p, h.name, msg + 8, r.from.as_ref())?;
    } else if p.copy_to_user(msg + 8, &[0u8; 4]) != 4 {
        return Err(EFAULT);
    }
    // Control messages: credentials if asked for, then the descriptors
    // that fit (the rest are closed, and MSG_CTRUNC says so).
    let room = usize::try_from(h.controllen).unwrap_or(usize::MAX);
    let mut ctl = Vec::new();
    let mut mflags = if r.full > r.data.len() {
        MSG_TRUNC as u32
    } else {
        0
    };
    if u.ep.state.lock().passcred
        && let Some(c) = r.cred
    {
        if room >= 32 {
            cmsg(&mut ctl, SCM_CREDENTIALS, &c.bytes());
        } else {
            mflags |= MSG_CTRUNC;
        }
    }
    if !r.fds.is_empty() {
        let fit = room.saturating_sub(ctl.len() + 16) / 4;
        let n = r.fds.len().min(fit);
        if n < r.fds.len() {
            mflags |= MSG_CTRUNC;
        }
        let mut nums = Vec::new();
        for d in r.fds.into_iter().take(n) {
            match p.install_desc(d, flags & MSG_CMSG_CLOEXEC != 0) {
                Some(fd) => nums.extend_from_slice(&(fd as u32).to_le_bytes()),
                None => mflags |= MSG_CTRUNC,
            }
        }
        if !nums.is_empty() {
            cmsg(&mut ctl, SCM_RIGHTS, &nums);
        }
    }
    let ctl_len = ctl.len().min(room);
    if (ctl_len > 0 && p.copy_to_user(h.control, &ctl[..ctl_len]) != ctl_len)
        || p.copy_to_user(msg + 40, &(ctl_len as u64).to_le_bytes()) != 8
        || p.copy_to_user(msg + 48, &mflags.to_le_bytes()) != 4
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

/// Self-test: an `AF_UNIX` queue is the receiving cell's memory. In a
/// cell of 24 pages a stream queue stops at 24 pages (the writer would
/// wait), well short of its 256 KiB buffer, and reading gives every page
/// back.
pub(crate) fn accounting_selftest() {
    const PAGES: u64 = 24;
    let fail = |m: &str| -> ! { crate::runtest::fail(m) };
    let sys = crate::kcell::System::new(1 << 16).unwrap_or_else(|| fail("unix: no system cell"));
    let cell = crate::kcell::Cell::new(&sys.root_account, PAGES)
        .unwrap_or_else(|| fail("unix: no test cell"));
    let (a, b) = (
        Endpoint::new(Type::Stream, &cell),
        Endpoint::new(Type::Stream, &cell),
    );
    for (x, y) in [(&a, &b), (&b, &a)] {
        x.state.lock().conn = Conn::Connected(Arc::downgrade(y));
    }
    let cred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let chunk = [7u8; PAGE];
    let mut sent = 0;
    loop {
        match a.try_send_conn(&b, &chunk, &mut Vec::new(), cred) {
            Some(Ok(n)) => sent += n,
            None => break,
            Some(Err(_)) => fail("unix: a write failed instead of waiting"),
        }
        if sent > BUFFER {
            fail("unix: the queue grew past its cell's memory");
        }
    }
    let used = cell.account().used();
    if sent != PAGES as usize * PAGE || used != PAGES {
        crate::println!("ichor: unix: queued {sent} bytes, {used} pages charged");
        fail("unix: the queue did not stop at the cell's limit");
    }
    let mut got = 0;
    while let Some(Ok(r)) = b.try_recv(BUFFER) {
        if r.data.is_empty() {
            break;
        }
        got += r.data.len();
    }
    if got != sent || cell.account().used() != 0 {
        fail("unix: reading the queue did not give its pages back");
    }
    let _ = a.shut_down();
    let _ = b.shut_down();
    crate::println!(
        "ichor: unix: a stream queue stopped at its cell's {PAGES} pages and gave them back when read"
    );
}

/// The `AF_UNIX` socket behind `fd`, if it is one.
pub(super) fn of(p: &LinuxProcess, fd: u64) -> Option<(Arc<dyn Object>, bool)> {
    match p.fd(fd)? {
        Fd::Object(o) if o.obj.unix().is_some() => Some((o.obj, o.nonblock)),
        _ => None,
    }
}

/// `ENOTSOCK` unless the object is an `AF_UNIX` socket.
pub(super) fn sock(o: &Arc<dyn Object>) -> Result<&UnixSocket, i64> {
    o.unix().ok_or(ENOTSOCK)
}
