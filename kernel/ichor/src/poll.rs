//! Readiness: `poll`, `ppoll`, `select`, `pselect6`, `epoll`, and the
//! kernel objects behind descriptors that are not files or pipes
//! (`eventfd`, the epoll instances themselves).
//!
//! Readiness is computed from the objects descriptors name: a pipe is
//! readable with data (or no writers), writable with room (or no readers);
//! files, devices and the console are always ready. A waiter registers with
//! the [`Watchers`] of each object it polls and sleeps on its own queue, so
//! a state change wakes only the tasks polling that object; a deadline ends
//! it for timeouts, a signal with `EINTR`. The condition is checked while
//! the task is marked blocked, so it only takes spinlocks: the descriptors
//! are looked up once, before waiting.
//!
//! `EPOLLET` entries report an object once per change: pipes and eventfds
//! count their state changes ([`Object::changes`]), and an edge-triggered
//! entry stays quiet until the count moves past the one it last reported.
//! `ppoll`, `pselect6` and `epoll_pwait` install their signal mask for the
//! wait. Partial: the epoll interest list is fixed at the start of an
//! `epoll_wait`, and a nested epoll instance never polls ready.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Debug;
use core::time::Duration;

use frame::sync::{Mutex, SpinLock};
use frame::task::WaitQueue;

use crate::proc;
use crate::process::{Description, Fd, LinuxProcess};

const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const EBADF: i64 = 9;
const EINTR: i64 = 4;
const ENOENT: i64 = 2;
const EMFILE: i64 = 24;
const EPERM: i64 = 1;

pub(crate) const POLLIN: u16 = 0x001;
pub(crate) const POLLPRI: u16 = 0x002;
pub(crate) const POLLOUT: u16 = 0x004;
pub(crate) const POLLERR: u16 = 0x008;
pub(crate) const POLLHUP: u16 = 0x010;
pub(crate) const POLLNVAL: u16 = 0x020;

/// A directory entry: name and `d_type`.
pub(crate) type DirEntry = (alloc::string::String, u8);

/// A kernel object behind a descriptor (eventfd, epoll, later sockets).
pub(crate) trait Object: Send + Sync + Debug {
    /// Reads up to `max` bytes.
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64>;
    /// Writes `data`; returns how much was taken.
    fn write(
        &self,
        data: &[u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64>;
    /// Current readiness (`POLL*` bits).
    fn poll(&self) -> u16;
    /// A count of state changes, for edge-triggered epoll.
    fn changes(&self) -> u64 {
        0
    }
    /// `st_mode` file-type bits for `fstat`.
    fn mode(&self) -> u32 {
        0 // anonymous inode
    }
    /// This object as an epoll instance.
    fn as_epoll(&self) -> Option<&Epoll> {
        None
    }
    /// This object as a pseudo-terminal end.
    fn tty(&self) -> Option<&crate::pty::End> {
        None
    }
    /// The pollers to wake when its readiness changes (`None`: it never
    /// changes, or is not worth waiting on).
    fn watchers(&self) -> Option<&Watchers> {
        None
    }
    /// A directory's entries `(name, d_type)` and read cursor (`/proc`).
    fn dir(&self) -> Option<(&[DirEntry], &SpinLock<u64>)> {
        None
    }
    /// This object as a socket.
    fn socket(&self) -> Option<&crate::linuxabi::socket::Socket> {
        None
    }
    /// This object as an `AF_UNIX` socket.
    fn unix(&self) -> Option<&crate::linuxabi::unix::UnixSocket> {
        None
    }
}

/// One task sleeping in `poll`/`select`/`epoll_wait`, registered with each
/// object it watches.
#[derive(Debug)]
struct Poller {
    queue: WaitQueue,
}

/// The pollers watching one object. An object whose readiness can change
/// (pipe, eventfd, pty) owns one and calls [`Watchers::notify`] on every
/// change, which wakes only the tasks polling that object.
#[derive(Debug)]
pub(crate) struct Watchers(SpinLock<Vec<Weak<Poller>>>);

impl Watchers {
    pub(crate) const fn new() -> Watchers {
        Watchers(SpinLock::new(Vec::new()))
    }

    /// Wakes every task polling this object, so it re-checks.
    pub(crate) fn notify(&self) {
        let live: Vec<Arc<Poller>> = {
            let mut v = self.0.lock();
            v.retain(|w| w.strong_count() > 0);
            v.iter().filter_map(Weak::upgrade).collect()
        };
        for p in live {
            p.queue.wake_all();
        }
    }

    fn watch(&self, p: &Arc<Poller>) {
        self.0.lock().push(Arc::downgrade(p));
    }

    fn unwatch(&self, p: &Arc<Poller>) {
        self.0
            .lock()
            .retain(|w| w.strong_count() > 0 && !core::ptr::eq(w.as_ptr(), Arc::as_ptr(p)));
    }
}

impl Default for Watchers {
    fn default() -> Watchers {
        Watchers::new()
    }
}

/// The watcher list of what `fd` names, if its readiness can change.
fn watchers(fd: &Fd) -> Option<&Watchers> {
    match fd {
        Fd::Console | Fd::File(_) | Fd::Dev(_) => None,
        Fd::Pipe(e) => Some(e.pipe.watchers()),
        Fd::Object(o) => o.obj.watchers(),
    }
}

/// The readiness of what `fd` names (spinlocks only).
pub(crate) fn readiness(fd: &Fd) -> u16 {
    match fd {
        Fd::Console | Fd::File(_) | Fd::Dev(_) => POLLIN | POLLOUT,
        Fd::Pipe(e) => e.pipe.poll(e.write),
        Fd::Object(o) => o.obj.poll(),
    }
}

/// How many times what `fd` names has changed state (for `EPOLLET`).
fn changes(fd: &Fd) -> u64 {
    match fd {
        Fd::Console | Fd::File(_) | Fd::Dev(_) => 0,
        Fd::Pipe(e) => e.pipe.changes(),
        Fd::Object(o) => o.obj.changes(),
    }
}

/// Sleeps until `check` returns `Some`, the deadline passes (`Ok(None)`),
/// or a signal arrives (`EINTR`; posting a signal wakes the task directly).
/// The task is woken only by changes to the objects behind `fds`.
fn wait_ready<'f, T>(
    p: &LinuxProcess,
    fds: impl Iterator<Item = &'f Fd>,
    deadline: Option<Duration>,
    mut check: impl FnMut() -> Option<T>,
) -> Result<Option<T>, i64> {
    let entry = p.entry.clone();
    let mut cond = || {
        if let Some(v) = check() {
            return Some(Ok(v));
        }
        proc::interrupted(&entry).then_some(Err(EINTR))
    };
    // Registered before the first check, so a change after it wakes us.
    let poller = Arc::new(Poller {
        queue: WaitQueue::new(),
    });
    let watched: Vec<&Watchers> = fds.filter_map(watchers).collect();
    for w in &watched {
        w.watch(&poller);
    }
    let r = match deadline {
        Some(d) => poller.queue.wait_until_deadline(d, &mut cond),
        None => Some(poller.queue.wait_until(&mut cond)),
    };
    for w in &watched {
        w.unwatch(&poller);
    }
    match r {
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

fn read_timespec(p: &mut LinuxProcess, addr: u64) -> Result<Duration, i64> {
    let mut b = [0u8; 16];
    if p.copy_from_user(addr, &mut b) != 16 {
        return Err(EFAULT);
    }
    let sec = u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
    let nsec = u64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
    if nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    Ok(Duration::from_secs(sec).saturating_add(Duration::from_nanos(nsec)))
}

/// A deadline from a timeout in milliseconds (negative: none).
fn deadline_ms(ms: i64) -> Option<Duration> {
    (ms >= 0).then(|| frame::time::now().saturating_add(Duration::from_millis(ms as u64)))
}

// ---------------------------------------------------------------------------
// poll, ppoll.
// ---------------------------------------------------------------------------

fn do_poll(
    p: &mut LinuxProcess,
    fds_addr: u64,
    nfds: u64,
    deadline: Option<Duration>,
) -> Result<u64, i64> {
    if nfds > 4096 {
        return Err(EINVAL);
    }
    let n = nfds as usize;
    let mut raw = alloc::vec![0u8; n * 8];
    if p.copy_from_user(fds_addr, &mut raw) != raw.len() {
        return Err(EFAULT);
    }
    // struct pollfd { int fd; short events; short revents; }
    let entries: Vec<(i32, u16, Option<Fd>)> = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| {
            let fd = i32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            let events = u16::from_le_bytes([c[4], c[5]]);
            let obj = if fd >= 0 { p.fd(fd as u64) } else { None };
            (fd, events, obj)
        })
        .collect();
    let scan = |out: &mut Vec<u16>| -> u64 {
        out.clear();
        let mut ready = 0;
        for (fd, events, obj) in &entries {
            let rev = match (fd, obj) {
                (f, _) if *f < 0 => 0,
                (_, None) => POLLNVAL,
                (_, Some(o)) => readiness(o) & (*events | POLLERR | POLLHUP | POLLNVAL),
            };
            if rev != 0 {
                ready += 1;
            }
            out.push(rev);
        }
        ready
    };
    let mut revents = Vec::with_capacity(n);
    let fds = entries.iter().filter_map(|(_, _, o)| o.as_ref());
    let ready = match wait_ready(p, fds, deadline, || {
        let r = scan(&mut revents);
        (r > 0).then_some(r)
    })? {
        Some(r) => r,
        None => {
            scan(&mut revents);
            0
        }
    };
    for (i, rev) in revents.iter().enumerate() {
        raw[i * 8 + 6..i * 8 + 8].copy_from_slice(&rev.to_le_bytes());
    }
    if p.copy_to_user(fds_addr, &raw) != raw.len() {
        return Err(EFAULT);
    }
    Ok(ready)
}

/// `poll(fds, nfds, timeout_ms)`.
pub(crate) fn poll(p: &mut LinuxProcess, fds: u64, nfds: u64, timeout: i64) -> Result<u64, i64> {
    do_poll(p, fds, nfds, deadline_ms(timeout))
}

/// `ppoll(fds, nfds, timeout_ts, sigmask, size)`.
pub(crate) fn ppoll(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let deadline = if a[2] == 0 {
        None
    } else {
        Some(frame::time::now().saturating_add(read_timespec(p, a[2])?))
    };
    crate::signal::begin_wait_mask(p, a[3], a[4])?;
    let r = do_poll(p, a[0], a[1], deadline);
    crate::signal::end_wait_mask(p, &r);
    r
}

// ---------------------------------------------------------------------------
// select, pselect6.
// ---------------------------------------------------------------------------

fn read_set(p: &mut LinuxProcess, addr: u64, bytes: usize) -> Result<Vec<u8>, i64> {
    let mut v = alloc::vec![0u8; bytes];
    if addr != 0 && p.copy_from_user(addr, &mut v) != bytes {
        return Err(EFAULT);
    }
    Ok(v)
}

fn do_select(
    p: &mut LinuxProcess,
    nfds: u64,
    sets: [u64; 3],
    deadline: Option<Duration>,
) -> Result<u64, i64> {
    if nfds > 1024 {
        return Err(EINVAL);
    }
    let n = nfds as usize;
    let bytes = n.div_ceil(64) * 8;
    let ins: Vec<Vec<u8>> = sets
        .iter()
        .map(|&a| read_set(p, a, bytes))
        .collect::<Result<_, _>>()?;
    let is_set = |s: &[u8], i: usize| s[i / 8] & (1 << (i % 8)) != 0;
    let mut watch: Vec<(usize, u8, Fd)> = Vec::new(); // (fd, which sets, object)
    for i in 0..n {
        let which = (0..3).fold(0u8, |m, k| if is_set(&ins[k], i) { m | 1 << k } else { m });
        if which != 0 {
            watch.push((i, which, p.fd(i as u64).ok_or(EBADF)?));
        }
    }
    let scan = |outs: &mut [Vec<u8>; 3]| -> u64 {
        let mut count = 0;
        for o in outs.iter_mut() {
            o.iter_mut().for_each(|b| *b = 0);
        }
        for (i, which, obj) in &watch {
            let r = readiness(obj);
            let hits = [
                r & (POLLIN | POLLHUP | POLLERR) != 0,
                r & (POLLOUT | POLLERR) != 0,
                r & POLLPRI != 0,
            ];
            for k in 0..3 {
                if which & (1 << k) != 0 && hits[k] {
                    outs[k][i / 8] |= 1 << (i % 8);
                    count += 1;
                }
            }
        }
        count
    };
    let mut outs = [
        alloc::vec![0u8; bytes],
        alloc::vec![0u8; bytes],
        alloc::vec![0u8; bytes],
    ];
    let fds = watch.iter().map(|(_, _, o)| o);
    let ready = match wait_ready(p, fds, deadline, || {
        let c = scan(&mut outs);
        (c > 0).then_some(c)
    })? {
        Some(c) => c,
        None => scan(&mut outs),
    };
    for (k, &a) in sets.iter().enumerate() {
        if a != 0 && p.copy_to_user(a, &outs[k]) != bytes {
            return Err(EFAULT);
        }
    }
    Ok(ready)
}

/// `select(nfds, readfds, writefds, exceptfds, timeval)`.
pub(crate) fn select(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let deadline = if a[4] == 0 {
        None
    } else {
        let mut b = [0u8; 16];
        if p.copy_from_user(a[4], &mut b) != 16 {
            return Err(EFAULT);
        }
        let sec = u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
        let usec = u64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
        Some(
            frame::time::now()
                .saturating_add(Duration::from_secs(sec))
                .saturating_add(Duration::from_micros(usec)),
        )
    };
    do_select(p, a[0], [a[1], a[2], a[3]], deadline)
}

/// `pselect6(nfds, readfds, writefds, exceptfds, timespec, sig)`, where
/// `sig` points at `{ const sigset_t *ss; size_t ss_len; }`.
pub(crate) fn pselect6(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let deadline = if a[4] == 0 {
        None
    } else {
        Some(frame::time::now().saturating_add(read_timespec(p, a[4])?))
    };
    let (ss, len) = if a[5] == 0 {
        (0, 0)
    } else {
        let mut b = [0u8; 16];
        if p.copy_from_user(a[5], &mut b) != 16 {
            return Err(EFAULT);
        }
        (
            u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8])),
            u64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8])),
        )
    };
    crate::signal::begin_wait_mask(p, ss, len)?;
    let r = do_select(p, a[0], [a[1], a[2], a[3]], deadline);
    crate::signal::end_wait_mask(p, &r);
    r
}

// ---------------------------------------------------------------------------
// eventfd.
// ---------------------------------------------------------------------------

/// An `eventfd` counter.
#[derive(Debug)]
pub(crate) struct EventFd {
    count: SpinLock<u64>,
    changes: core::sync::atomic::AtomicU64,
    semaphore: bool,
    queue: WaitQueue,
    watchers: Watchers,
}

impl Object for EventFd {
    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.watchers)
    }

    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        if max < 8 {
            return Err(EINVAL);
        }
        let v = self.queue.wait_until(|| {
            let mut c = self.count.lock();
            if *c > 0 {
                let v = if self.semaphore { 1 } else { *c };
                *c -= v;
                Some(Ok(v))
            } else if nonblock {
                Some(Err(EAGAIN))
            } else if interrupted() {
                Some(Err(crate::signal::ERESTARTSYS))
            } else {
                None
            }
        })?;
        self.changed();
        Ok(v.to_le_bytes().to_vec())
    }

    fn write(
        &self,
        data: &[u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        let add = u64::from_le_bytes(
            data.get(..8)
                .ok_or(EINVAL)?
                .try_into()
                .map_err(|_| EINVAL)?,
        );
        if add == u64::MAX {
            return Err(EINVAL);
        }
        self.queue.wait_until(|| {
            let mut c = self.count.lock();
            if u64::MAX - 1 - *c >= add {
                *c += add;
                Some(Ok(()))
            } else if nonblock {
                Some(Err(EAGAIN))
            } else if interrupted() {
                Some(Err(crate::signal::ERESTARTSYS))
            } else {
                None
            }
        })?;
        self.changed();
        Ok(8)
    }

    fn changes(&self) -> u64 {
        self.changes.load(core::sync::atomic::Ordering::Acquire)
    }

    fn poll(&self) -> u16 {
        let c = *self.count.lock();
        let mut r = 0;
        if c > 0 {
            r |= POLLIN;
        }
        if c < u64::MAX - 1 {
            r |= POLLOUT;
        }
        r
    }
}

impl EventFd {
    fn changed(&self) {
        self.changes
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        self.queue.wake_all();
        self.watchers.notify();
    }
}

/// `eventfd2(initval, flags)`.
pub(crate) fn eventfd(p: &mut LinuxProcess, init: u64, flags: u64) -> Result<u64, i64> {
    const EFD_SEMAPHORE: u64 = 1;
    const EFD_NONBLOCK: u64 = 0o4000;
    const EFD_CLOEXEC: u64 = 0o2_000_000;
    if flags & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let obj = Arc::new(EventFd {
        count: SpinLock::new(init & 0xffff_ffff),
        changes: core::sync::atomic::AtomicU64::new(0),
        semaphore: flags & EFD_SEMAPHORE != 0,
        queue: WaitQueue::new(),
        watchers: Watchers::new(),
    });
    install(p, obj, flags & EFD_NONBLOCK != 0, flags & EFD_CLOEXEC != 0)
}

fn install(
    p: &mut LinuxProcess,
    obj: Arc<dyn Object>,
    nonblock: bool,
    cloexec: bool,
) -> Result<u64, i64> {
    p.install_flags(
        Fd::Object(crate::process::ObjectEnd { obj, nonblock }),
        cloexec,
    )
    .ok_or(EMFILE)
}

// ---------------------------------------------------------------------------
// epoll.
// ---------------------------------------------------------------------------

const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;

/// One descriptor an epoll instance watches.
///
/// It names the open file description weakly: as on Linux, the entry
/// goes away once every descriptor for that description is closed (nginx
/// closes connections without `EPOLL_CTL_DEL`), and it never keeps a
/// closed socket alive. Partial: entries are keyed by descriptor number
/// alone, so adding a new file at a reused number drops the entry of an
/// older file still open through a `dup` elsewhere (Linux keeps both).
#[derive(Debug, Clone)]
struct Interest {
    events: u32,
    data: u64,
    /// The description at `EPOLL_CTL_ADD`.
    desc: Weak<Description>,
    /// `EPOLLET`: the change count last reported.
    seen: Option<u64>,
}

impl Interest {
    fn names(&self, d: &Arc<Description>) -> bool {
        core::ptr::eq(self.desc.as_ptr(), Arc::as_ptr(d))
    }
}

/// An epoll instance: fd -> what it watches there.
#[derive(Debug)]
pub(crate) struct Epoll {
    interest: Mutex<BTreeMap<u64, Interest>>,
}

impl Object for Epoll {
    fn read(&self, _: usize, _: bool, _: &dyn Fn() -> bool) -> Result<Vec<u8>, i64> {
        Err(EINVAL)
    }
    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(EINVAL)
    }
    fn poll(&self) -> u16 {
        // Nested epoll readiness needs the interest list (a sleeping lock);
        // report nothing rather than block (partial).
        0
    }
    fn as_epoll(&self) -> Option<&Epoll> {
        Some(self)
    }
}

/// `epoll_create1(flags)` (and `epoll_create(size)` with flags 0).
pub(crate) fn epoll_create(p: &mut LinuxProcess, flags: u64) -> Result<u64, i64> {
    const EPOLL_CLOEXEC: u64 = 0o2_000_000;
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(EINVAL);
    }
    let obj = Arc::new(Epoll {
        interest: Mutex::new(BTreeMap::new()),
    });
    install(p, obj, false, flags & EPOLL_CLOEXEC != 0)
}

fn epoll_of(p: &LinuxProcess, epfd: u64) -> Result<Arc<dyn Object>, i64> {
    match p.fd(epfd).ok_or(EBADF)? {
        Fd::Object(o) if o.obj.as_epoll().is_some() => Ok(o.obj),
        _ => Err(EINVAL),
    }
}

/// `epoll_ctl(epfd, op, fd, event)`.
pub(crate) fn epoll_ctl(
    p: &mut LinuxProcess,
    epfd: u64,
    op: u64,
    fd: u64,
    ev: u64,
) -> Result<u64, i64> {
    const ADD: u64 = 1;
    const DEL: u64 = 2;
    const MOD: u64 = 3;
    let ep = epoll_of(p, epfd)?;
    let desc = p.desc(fd).ok_or(EBADF)?;
    let target = desc.state().clone();
    if fd == epfd {
        return Err(EINVAL);
    }
    if matches!(target, Fd::File(_)) {
        return Err(EPERM); // regular files cannot be polled with epoll
    }
    let (events, data) = if op == DEL {
        (0, 0)
    } else {
        // struct epoll_event { u32 events; u64 data; } (packed on x86-64)
        let mut b = [0u8; 12];
        if p.copy_from_user(ev, &mut b) != 12 {
            return Err(EFAULT);
        }
        (
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u64::from_le_bytes(b[4..12].try_into().unwrap_or([0; 8])),
        )
    };
    let Some(epoll) = ep.as_epoll() else {
        return Err(EINVAL);
    };
    let mut set = epoll.interest.lock();
    // An entry at this number for a description that has been closed (or
    // another one, the number having been reused) is gone.
    if set.get(&fd).is_some_and(|i| !i.names(&desc)) {
        set.remove(&fd);
    }
    match op {
        ADD if set.contains_key(&fd) => Err(EEXIST),
        ADD | MOD if op == ADD || set.contains_key(&fd) => {
            set.insert(
                fd,
                Interest {
                    events,
                    data,
                    desc: Arc::downgrade(&desc),
                    seen: None,
                },
            );
            Ok(0)
        }
        MOD => Err(ENOENT),
        DEL => set.remove(&fd).map(|_| 0).ok_or(ENOENT),
        _ => Err(EINVAL),
    }
}

/// `epoll_pwait(epfd, events, maxevents, timeout_ms, sigmask, size)`.
pub(crate) fn epoll_pwait(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    crate::signal::begin_wait_mask(p, a[4], a[5])?;
    let r = epoll_wait(p, a[0], a[1], a[2], a[3] as i32 as i64);
    crate::signal::end_wait_mask(p, &r);
    r
}

/// `epoll_wait(epfd, events, maxevents, timeout_ms)`.
pub(crate) fn epoll_wait(
    p: &mut LinuxProcess,
    epfd: u64,
    out: u64,
    max: u64,
    timeout: i64,
) -> Result<u64, i64> {
    // Linux's EP_MAX_EVENTS: servers size the array to their client limit
    // (redis asks for 10,128). Hits are bounded by the interest list.
    const EP_MAX_EVENTS: u64 = i32::MAX as u64 / 12;
    if max == 0 || max > EP_MAX_EVENTS {
        return Err(EINVAL);
    }
    let ep = epoll_of(p, epfd)?;
    let Some(epoll) = ep.as_epoll() else {
        return Err(EINVAL);
    };
    // (fd, entry, what it names, the description held for the wait).
    // Entries whose description has been closed are forgotten.
    let watch: Vec<(u64, Interest, Fd, Arc<Description>)> = {
        let mut set = epoll.interest.lock();
        set.retain(|_, i| i.desc.strong_count() > 0);
        set.iter()
            .filter_map(|(&fd, i)| {
                let d = i.desc.upgrade()?;
                let f = d.state().clone();
                Some((fd, i.clone(), f, d))
            })
            .collect()
    };
    // (fd, events, data, change count)
    let scan = || -> Vec<(u64, u32, u64, u64)> {
        let mut hits = Vec::new();
        for (fd, i, f, _) in &watch {
            if i.events & !EPOLLET == 0 {
                continue; // a disarmed EPOLLONESHOT entry
            }
            // Read the count first: a change after it is reported next time.
            let n = changes(f);
            if i.events & EPOLLET != 0 && i.seen == Some(n) {
                continue;
            }
            let r = u32::from(readiness(f)) & (i.events | u32::from(POLLERR | POLLHUP));
            if r != 0 {
                hits.push((*fd, r, i.data, n));
                if hits.len() as u64 == max {
                    break;
                }
            }
        }
        hits
    };
    let fds = watch.iter().map(|(_, _, f, _)| f);
    let hits = wait_ready(p, fds, deadline_ms(timeout), || {
        let h = scan();
        (!h.is_empty()).then_some(h)
    })?
    .unwrap_or_default();
    // Disarm one-shot entries that fired; remember what edge-triggered
    // entries reported.
    {
        let mut set = epoll.interest.lock();
        for (fd, _, _, n) in &hits {
            if let Some(e) = set.get_mut(fd) {
                if e.events & EPOLLONESHOT != 0 {
                    e.events = 0;
                }
                if e.events & EPOLLET != 0 {
                    e.seen = Some(*n);
                }
            }
        }
    }
    let mut buf = Vec::with_capacity(hits.len() * 12);
    for (_, r, data, _) in &hits {
        buf.extend_from_slice(&r.to_le_bytes());
        buf.extend_from_slice(&data.to_le_bytes());
    }
    if p.copy_to_user(out, &buf) != buf.len() {
        return Err(EFAULT);
    }
    Ok(hits.len() as u64)
}
