//! io_uring for the Linux personality (ADR-0013 §1).
//!
//! A ring is a descriptor naming kernel pages that the process maps
//! (`mmap` at Linux's offsets): the SQ and CQ rings in one mapping
//! (`IORING_FEAT_SINGLE_MMAP`), the SQE array in another. The kernel reads
//! and writes them through `UFrame` readers and writers, so frame is not
//! involved. `kernel/uring` holds the ABI and the ordering rules (links,
//! hard links, drains).
//!
//! An SQE runs on the thread that submits it, through the same code as the
//! synchronous syscall (`linuxabi::dispatch`). One on a pipe or socket that
//! is not ready is armed instead and runs once it is: by a thread waiting
//! in `io_uring_enter`, or by the ring's worker, a helper thread of the
//! process (`LinuxProcess::helper`) started the first time an SQE is
//! armed, so completions arrive while the program waits on the ring
//! descriptor with epoll or on a registered eventfd, as on Linux. An armed
//! SQE is claimed before it runs, so it runs once. POLL_ADD and TIMEOUT
//! wait the same way.
//! SQPOLL and IOPOLL rings, registered files and buffers, and LINK_TIMEOUT
//! are refused (`-EINVAL`), so libraries fall back.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use ::uring::{Cqe, Layout, Order, Sqe, abi};
use frame::mm::{PAGE_SIZE, UFrame};
use frame::sync::SpinLock;
use frame::user::UserContext;

use crate::poll::{self, Object, POLLERR, POLLHUP, POLLIN, POLLOUT, Watchers};
use crate::process::{Fd, LinuxProcess, ObjectEnd};

const ENOENT: i64 = 2;
const EINTR: i64 = 4;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ETIME: i64 = 62;
const EOPNOTSUPP: i64 = 95;
const ECANCELED: i64 = 125;

/// The opcodes this kernel runs (the probe reports exactly these).
const SUPPORTED: &[u8] = &[
    abi::OP_NOP,
    abi::OP_READV,
    abi::OP_WRITEV,
    abi::OP_FSYNC,
    abi::OP_POLL_ADD,
    abi::OP_POLL_REMOVE,
    abi::OP_SENDMSG,
    abi::OP_RECVMSG,
    abi::OP_TIMEOUT,
    abi::OP_TIMEOUT_REMOVE,
    abi::OP_ACCEPT,
    abi::OP_ASYNC_CANCEL,
    abi::OP_CONNECT,
    abi::OP_OPENAT,
    abi::OP_CLOSE,
    abi::OP_STATX,
    abi::OP_READ,
    abi::OP_WRITE,
    abi::OP_SEND,
    abi::OP_RECV,
    abi::OP_SHUTDOWN,
    abi::OP_RENAMEAT,
    abi::OP_UNLINKAT,
    abi::OP_MKDIRAT,
];

/// `IORING_TIMEOUT_ABS`.
const TIMEOUT_ABS: u32 = 1;
/// `IORING_FSYNC_DATASYNC`.
const FSYNC_DATASYNC: u32 = 1;

/// Pages shared with the process.
struct Mem(Vec<UFrame>);

impl Mem {
    fn alloc(bytes: u64) -> Option<Mem> {
        let n = bytes.div_ceil(PAGE_SIZE);
        (0..n)
            .map(|_| UFrame::alloc_zeroed())
            .collect::<Option<Vec<_>>>()
            .map(Mem)
    }

    fn read(&self, off: usize, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            let at = off + done;
            let (page, o) = (at / PAGE_SIZE as usize, at % PAGE_SIZE as usize);
            let n = (PAGE_SIZE as usize - o).min(out.len() - done);
            if let Some(f) = self.0.get(page) {
                let mut r = f.reader();
                r.skip(o);
                r.read(&mut out[done..done + n]);
            }
            done += n;
        }
    }

    fn write(&self, off: usize, data: &[u8]) {
        let mut done = 0;
        while done < data.len() {
            let at = off + done;
            let (page, o) = (at / PAGE_SIZE as usize, at % PAGE_SIZE as usize);
            let n = (PAGE_SIZE as usize - o).min(data.len() - done);
            if let Some(f) = self.0.get(page) {
                let mut w = f.writer();
                w.skip(o);
                w.write(&data[done..done + n]);
            }
            done += n;
        }
    }

    fn get(&self, off: u32) -> u32 {
        let mut b = [0u8; 4];
        self.read(off as usize, &mut b);
        u32::from_le_bytes(b)
    }

    fn set(&self, off: u32, v: u32) {
        self.write(off as usize, &v.to_le_bytes());
    }
}

/// A submitted SQE not yet complete.
#[derive(Debug)]
struct Op {
    sqe: Sqe,
    /// Waiting for readiness (or a deadline) before it runs.
    armed: bool,
    /// TIMEOUT: when it fires, and after how many completions it ends
    /// early (0: only the deadline).
    deadline: Option<Duration>,
    until: Option<u64>,
    /// A thread is running it (a submitter or the ring's worker): no other
    /// may run or cancel it.
    running: bool,
}

#[derive(Debug, Default)]
struct State {
    order: Order,
    ops: BTreeMap<u64, Op>,
    /// CQEs the CQ had no room for (`IORING_FEAT_NODROP`).
    overflow: VecDeque<Cqe>,
}

/// An io_uring instance.
pub(crate) struct Ring {
    layout: Layout,
    rings: Mem,
    sqes: Mem,
    state: SpinLock<State>,
    watchers: Watchers,
    eventfd: SpinLock<Option<Arc<dyn Object>>>,
    /// CQEs posted so far (TIMEOUT counts).
    completed: AtomicU64,
    /// Bumped whenever an SQE is armed or completes (the worker re-reads
    /// what to wait on).
    epoch: AtomicU64,
    /// Whether the worker runs (started the first time an SQE is armed).
    worker: core::sync::atomic::AtomicBool,
    /// This ring, for the worker (which must not keep it alive).
    me: alloc::sync::Weak<Ring>,
}

impl core::fmt::Debug for Ring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ring")
            .field("sq_entries", &self.layout.sq_entries)
            .field("cq_entries", &self.layout.cq_entries)
            .finish()
    }
}

impl Object for Ring {
    fn read(&self, _: usize, _: bool, _: &dyn Fn() -> bool) -> Result<Vec<u8>, i64> {
        Err(EINVAL)
    }

    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(EINVAL)
    }

    /// Readable while the CQ holds entries; writable while the SQ has room.
    fn poll(&self) -> u16 {
        let mut r = 0;
        if self.cq_ready() > 0 {
            r |= POLLIN;
        }
        let l = &self.layout;
        let queued = ::uring::pending(
            self.rings.get(l.sq.head),
            self.rings.get(l.sq.tail),
            l.sq_entries,
        );
        if queued < l.sq_entries {
            r |= POLLOUT;
        }
        r
    }

    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.watchers)
    }

    fn uring(&self) -> Option<&Ring> {
        Some(self)
    }
}

impl Ring {
    /// CQEs the application has not consumed.
    fn cq_ready(&self) -> u32 {
        let l = &self.layout;
        self.rings
            .get(l.cq.tail)
            .wrapping_sub(self.rings.get(l.cq.head))
            .min(l.cq_entries)
    }

    /// Writes a CQE, or keeps it until there is room.
    fn post(&self, c: Cqe) {
        {
            let mut st = self.state.lock();
            st.overflow.push_back(c);
            self.flush_overflow(&mut st);
        }
        self.completed.fetch_add(1, Ordering::AcqRel);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.watchers.notify();
        if let Some(e) = self.eventfd.lock().clone() {
            let _ = e.write(&1u64.to_le_bytes(), true, &|| false);
        }
    }

    fn flush_overflow(&self, st: &mut State) {
        let l = &self.layout;
        let head = self.rings.get(l.cq.head);
        let mut tail = self.rings.get(l.cq.tail);
        while ::uring::cq_space(head, tail, l.cq_entries) > 0 {
            let Some(c) = st.overflow.pop_front() else {
                break;
            };
            let slot = (tail & (l.cq_entries - 1)) as usize;
            self.rings
                .write(l.cq.cqes as usize + slot * 16, &c.encode());
            tail = tail.wrapping_add(1);
        }
        // The entries are in place before the tail says so.
        core::sync::atomic::fence(Ordering::Release);
        self.rings.set(l.cq.tail, tail);
        let flags = self.rings.get(l.sq.flags);
        let flags = if st.overflow.is_empty() {
            flags & !abi::SQ_CQ_OVERFLOW
        } else {
            flags | abi::SQ_CQ_OVERFLOW
        };
        self.rings.set(l.sq.flags, flags);
    }

    /// Takes up to `n` SQEs from the SQ.
    fn submit(&self, n: u32) -> u32 {
        let l = &self.layout;
        let head = self.rings.get(l.sq.head);
        let tail = self.rings.get(l.sq.tail);
        core::sync::atomic::fence(Ordering::Acquire);
        let n = ::uring::pending(head, tail, l.sq_entries).min(n);
        let mut st = self.state.lock();
        for i in 0..n {
            let at = l.sq.array + (head.wrapping_add(i) & (l.sq_entries - 1)) * 4;
            let idx = self.rings.get(at);
            if idx >= l.sq_entries {
                let d = self.rings.get(l.sq.dropped);
                self.rings.set(l.sq.dropped, d.wrapping_add(1));
                continue;
            }
            let mut b = [0u8; 64];
            self.sqes.read(idx as usize * 64, &mut b);
            let sqe = Sqe::parse(&b);
            let id = st.order.submit(sqe.flags);
            st.ops.insert(
                id,
                Op {
                    sqe,
                    armed: false,
                    deadline: None,
                    until: None,
                    running: false,
                },
            );
        }
        st.order.end_batch();
        self.rings.set(l.sq.head, head.wrapping_add(n));
        n
    }

    /// Completes `id` with `res`, and the SQEs a broken link cancels.
    fn complete(&self, id: u64, res: i64, ok: bool) {
        let (sqe, cancelled) = {
            let mut st = self.state.lock();
            let Some(op) = st.ops.remove(&id) else {
                return;
            };
            let gone = st.order.complete(id, ok);
            let cancelled: Vec<u64> = gone
                .iter()
                .filter_map(|c| st.ops.remove(c).map(|o| o.sqe.user_data))
                .collect();
            (op.sqe, cancelled)
        };
        let skip = sqe.flags & abi::SQE_CQE_SKIP_SUCCESS != 0 && res >= 0;
        if !skip {
            self.post(Cqe {
                user_data: sqe.user_data,
                res: res.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                flags: 0,
            });
        }
        for user_data in cancelled {
            self.post(Cqe {
                user_data,
                res: -(ECANCELED as i32),
                flags: 0,
            });
        }
    }

    /// Runs what can run now: newly ready SQEs, then armed ones whose
    /// object is ready or whose deadline passed.
    fn run(&self, p: &mut LinuxProcess) {
        loop {
            let ready: Vec<(u64, Sqe)> = {
                let mut st = self.state.lock();
                let ids = st.order.ready();
                ids.into_iter()
                    .filter_map(|id| st.ops.get(&id).map(|o| (id, o.sqe)))
                    .collect()
            };
            let mut progress = !ready.is_empty();
            for (id, sqe) in ready {
                self.start(p, id, sqe);
            }
            // Armed SQEs nobody else is running, claimed.
            let armed: Vec<(u64, Sqe)> = {
                let mut st = self.state.lock();
                st.ops
                    .iter_mut()
                    .filter(|(_, o)| o.armed && !o.running)
                    .map(|(&id, o)| {
                        o.running = true;
                        (id, o.sqe)
                    })
                    .collect()
            };
            for (id, sqe) in armed {
                let done = self.retry(p, id, sqe);
                if !done && let Some(o) = self.state.lock().ops.get_mut(&id) {
                    o.running = false;
                }
                progress |= done;
            }
            if !progress {
                break;
            }
        }
        self.start_worker(p);
    }

    fn arm(&self, id: u64, deadline: Option<Duration>, until: Option<u64>) {
        if let Some(o) = self.state.lock().ops.get_mut(&id) {
            o.armed = true;
            o.deadline = deadline;
            o.until = until;
        }
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.watchers.notify();
    }

    /// Starts the ring's worker the first time something is armed: a
    /// helper thread of the process that runs armed SQEs as they become
    /// ready, so they complete even while no thread is in
    /// `io_uring_enter` (a program may wait on the ring descriptor with
    /// epoll, or on a registered eventfd).
    fn start_worker(&self, p: &LinuxProcess) {
        let armed = self.state.lock().ops.values().any(|o| o.armed);
        if !armed || self.worker.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self.me.clone();
        if !crate::proc::start_helper(p.helper(), move |p| worker(&me, p)) {
            self.worker.store(false, Ordering::Release);
        }
    }

    /// Finds an armed SQE by `user_data` that no thread is running, claims
    /// it, and cancels it.
    fn cancel(&self, user_data: u64, only: Option<u8>) -> bool {
        let found = {
            let mut st = self.state.lock();
            st.ops
                .iter_mut()
                .find(|(_, o)| {
                    o.armed
                        && !o.running
                        && o.sqe.user_data == user_data
                        && only.is_none_or(|op| o.sqe.opcode == op)
                })
                .map(|(&id, o)| {
                    o.running = true;
                    id
                })
        };
        match found {
            Some(id) => {
                self.complete(id, -ECANCELED, false);
                true
            }
            None => false,
        }
    }

    /// The first run of an SQE.
    fn start(&self, p: &mut LinuxProcess, id: u64, sqe: Sqe) {
        if sqe.flags & (abi::SQE_FIXED_FILE | abi::SQE_BUFFER_SELECT) != 0
            || !SUPPORTED.contains(&sqe.opcode)
        {
            return self.complete(id, -EINVAL, false);
        }
        match sqe.opcode {
            abi::OP_NOP => self.complete(id, 0, true),
            abi::OP_TIMEOUT => {
                if sqe.len != 1 {
                    return self.complete(id, -EINVAL, false);
                }
                let t = match poll::read_timespec(p, sqe.addr) {
                    Ok(t) => t,
                    Err(e) => return self.complete(id, -e, false),
                };
                let deadline = if sqe.op_flags & TIMEOUT_ABS != 0 {
                    t
                } else {
                    frame::time::now().saturating_add(t)
                };
                let until =
                    (sqe.off != 0).then(|| self.completed.load(Ordering::Acquire) + sqe.off);
                self.arm(id, Some(deadline), until);
            }
            abi::OP_TIMEOUT_REMOVE => {
                let r = if self.cancel(sqe.addr, Some(abi::OP_TIMEOUT)) {
                    0
                } else {
                    -ENOENT
                };
                self.complete(id, r, r == 0);
            }
            abi::OP_POLL_REMOVE => {
                let r = if self.cancel(sqe.addr, Some(abi::OP_POLL_ADD)) {
                    0
                } else {
                    -ENOENT
                };
                self.complete(id, r, r == 0);
            }
            abi::OP_ASYNC_CANCEL => {
                let r = if self.cancel(sqe.addr, None) {
                    0
                } else {
                    -ENOENT
                };
                self.complete(id, r, r == 0);
            }
            abi::OP_POLL_ADD => self.arm(id, None, None),
            _ => {
                if !self.retry(p, id, sqe) {
                    self.arm(id, None, None);
                }
            }
        }
    }

    /// Runs an armed SQE if it can run now. Returns whether it completed.
    fn retry(&self, p: &mut LinuxProcess, id: u64, sqe: Sqe) -> bool {
        match sqe.opcode {
            abi::OP_TIMEOUT => {
                let (deadline, until) = {
                    let st = self.state.lock();
                    let Some(o) = st.ops.get(&id) else {
                        return false;
                    };
                    (o.deadline, o.until)
                };
                if until.is_some_and(|u| self.completed.load(Ordering::Acquire) >= u) {
                    self.complete(id, 0, true);
                    return true;
                }
                if deadline.is_some_and(|d| frame::time::now() >= d) {
                    self.complete(id, -ETIME, true);
                    return true;
                }
                false
            }
            abi::OP_POLL_ADD => {
                let Some(fd) = p.fd(sqe.fd as u32 as u64) else {
                    self.complete(id, -EBADF, false);
                    return true;
                };
                let want = (sqe.op_flags as u16) | POLLERR | POLLHUP;
                let got = poll::readiness(&fd) & want;
                if got == 0 {
                    return false;
                }
                self.complete(id, i64::from(got), true);
                true
            }
            _ => {
                if let Some(fd) = p.fd(sqe.fd as u32 as u64)
                    && would_block(&sqe, &fd)
                {
                    return false;
                }
                let (res, ok) = execute(p, &sqe);
                self.complete(id, res, ok);
                true
            }
        }
    }

    /// The objects armed SQEs wait on with the events each needs, and the
    /// nearest deadline.
    fn waits(&self, p: &LinuxProcess) -> (Vec<(Fd, u16)>, Option<Duration>) {
        let sqes: Vec<(Sqe, Option<Duration>)> = {
            let st = self.state.lock();
            st.ops
                .values()
                .filter(|o| o.armed)
                .map(|o| (o.sqe, o.deadline))
                .collect()
        };
        let mut fds = Vec::new();
        let mut deadline: Option<Duration> = None;
        for (sqe, d) in sqes {
            if let Some(d) = d {
                deadline = Some(deadline.map_or(d, |x| x.min(d)));
            }
            if let Some(need) = need(&sqe)
                && let Some(fd) = p.fd(sqe.fd as u32 as u64)
            {
                fds.push((fd, need));
            }
        }
        (fds, deadline)
    }
}

/// How often the worker re-checks that it should still run: the process
/// exiting or exec'ing, or the ring closing, does not wake it.
const WORKER_RECHECK: Duration = Duration::from_millis(100);

/// The ring's worker: runs armed SQEs as their objects become ready (and
/// fires timeouts), sleeping on those objects and on the ring itself (new
/// armed SQEs, completions) in between. It ends when the ring closes, the
/// process has no threads left, or it is killed.
fn worker(me: &alloc::sync::Weak<Ring>, p: &mut LinuxProcess) {
    loop {
        if p.group.threads().is_empty() || crate::proc::interrupted(&p.entry) {
            return;
        }
        let Some(ring) = me.upgrade() else {
            return;
        };
        let epoch = ring.epoch.load(Ordering::Acquire);
        ring.run(p);
        let (fds, deadline) = ring.waits(p);
        let mut until = frame::time::now() + WORKER_RECHECK;
        if let Some(d) = deadline {
            until = until.min(d);
        }
        let watched: Vec<&Watchers> = fds
            .iter()
            .filter_map(|(f, _)| poll::watchers(f))
            .chain(core::iter::once(&ring.watchers))
            .collect();
        poll::wait_watchers(&watched, Some(until), || {
            let changed = ring.epoch.load(Ordering::Acquire) != epoch;
            let ready = fds.iter().any(|(f, need)| poll::readiness(f) & need != 0);
            (changed || ready).then_some(())
        });
    }
}

/// The readiness an SQE waits for, if it waits on its descriptor.
fn need(sqe: &Sqe) -> Option<u16> {
    let ev = match sqe.opcode {
        abi::OP_READ | abi::OP_READV | abi::OP_RECV | abi::OP_RECVMSG | abi::OP_ACCEPT => POLLIN,
        abi::OP_WRITE | abi::OP_WRITEV | abi::OP_SEND | abi::OP_SENDMSG => POLLOUT,
        abi::OP_POLL_ADD => sqe.op_flags as u16,
        _ => return None,
    };
    Some(ev | POLLERR | POLLHUP)
}

/// Whether `sqe` on `fd` would block now (a pipe or socket not ready).
fn would_block(sqe: &Sqe, fd: &Fd) -> bool {
    if matches!(fd, Fd::Console | Fd::File(_) | Fd::Dev(_)) {
        return false;
    }
    need(sqe).is_some_and(|n| poll::readiness(fd) & n == 0)
}

/// Runs `nr` with `args` as the syscall would: `(result, ok)`.
fn syscall(p: &mut LinuxProcess, nr: u64, args: [u64; 6]) -> i64 {
    let mut ctx = UserContext::new(0, 0);
    ctx.rax = nr;
    ctx.rdi = args[0];
    ctx.rsi = args[1];
    ctx.rdx = args[2];
    ctx.r10 = args[3];
    ctx.r8 = args[4];
    ctx.r9 = args[5];
    let _ = super::dispatch(p, &mut ctx);
    let r = ctx.rax as i64;
    if crate::signal::Restart::of(nr, r).is_some() {
        p.resume_until = None;
        -EINTR
    } else {
        r
    }
}

/// A file offset of `-1`, or a stream (no offset): the current position.
fn positional(sqe: &Sqe, fd: Option<&Fd>) -> bool {
    sqe.off != u64::MAX && matches!(fd, Some(Fd::File(_)))
}

/// READV/WRITEV at an offset: each iovec in turn, as `preadv` would.
fn vectored_at(p: &mut LinuxProcess, sqe: &Sqe, write: bool) -> i64 {
    let n = sqe.len as usize;
    if n > 1024 {
        return -EINVAL;
    }
    let mut raw = alloc::vec![0u8; n * 16];
    if p.copy_from_user(sqe.addr, &mut raw) != raw.len() {
        return -EFAULT;
    }
    let mut done: i64 = 0;
    for iov in raw.as_chunks::<16>().0 {
        let base = u64::from_le_bytes(iov[..8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(iov[8..].try_into().unwrap_or([0; 8]));
        let nr = if write {
            super::nr::PWRITE64
        } else {
            super::nr::PREAD64
        };
        let off = sqe.off.wrapping_add(done as u64);
        let r = syscall(p, nr, [sqe.fd as u32 as u64, base, len, off, 0, 0]);
        if r < 0 {
            return if done > 0 { done } else { r };
        }
        done += r;
        if (r as u64) < len {
            break;
        }
    }
    done
}

/// Runs an I/O SQE through the matching syscall: `(result, ok)`, where a
/// short read or write is not ok (it breaks an `IO_LINK` chain).
fn execute(p: &mut LinuxProcess, s: &Sqe) -> (i64, bool) {
    use super::nr;
    let fd = s.fd as u32 as u64;
    let desc = p.fd(fd);
    let at = positional(s, desc.as_ref());
    let full = |r: i64| (r, r >= 0 && r as u64 == u64::from(s.len));
    let ok = |r: i64| (r, r >= 0);
    let len = u64::from(s.len);
    match s.opcode {
        abi::OP_READ if at => full(syscall(p, nr::PREAD64, [fd, s.addr, len, s.off, 0, 0])),
        abi::OP_READ => full(syscall(p, nr::READ, [fd, s.addr, len, 0, 0, 0])),
        abi::OP_WRITE if at => full(syscall(p, nr::PWRITE64, [fd, s.addr, len, s.off, 0, 0])),
        abi::OP_WRITE => full(syscall(p, nr::WRITE, [fd, s.addr, len, 0, 0, 0])),
        abi::OP_READV if at => ok(vectored_at(p, s, false)),
        abi::OP_READV => ok(syscall(p, nr::READV, [fd, s.addr, len, 0, 0, 0])),
        abi::OP_WRITEV if at => ok(vectored_at(p, s, true)),
        abi::OP_WRITEV => ok(syscall(p, nr::WRITEV, [fd, s.addr, len, 0, 0, 0])),
        abi::OP_FSYNC => {
            let n = if s.op_flags & FSYNC_DATASYNC != 0 {
                nr::FDATASYNC
            } else {
                nr::FSYNC
            };
            ok(syscall(p, n, [fd, 0, 0, 0, 0, 0]))
        }
        abi::OP_SEND => full(syscall(
            p,
            nr::SENDTO,
            [fd, s.addr, len, u64::from(s.op_flags), 0, 0],
        )),
        abi::OP_RECV => ok(syscall(
            p,
            nr::RECVFROM,
            [fd, s.addr, len, u64::from(s.op_flags), 0, 0],
        )),
        abi::OP_SENDMSG => ok(syscall(
            p,
            nr::SENDMSG,
            [fd, s.addr, u64::from(s.op_flags), 0, 0, 0],
        )),
        abi::OP_RECVMSG => ok(syscall(
            p,
            nr::RECVMSG,
            [fd, s.addr, u64::from(s.op_flags), 0, 0, 0],
        )),
        abi::OP_ACCEPT => ok(syscall(
            p,
            nr::ACCEPT4,
            [fd, s.addr, s.off, u64::from(s.op_flags), 0, 0],
        )),
        abi::OP_CONNECT => ok(syscall(p, nr::CONNECT, [fd, s.addr, s.off, 0, 0, 0])),
        abi::OP_SHUTDOWN => ok(syscall(p, nr::SHUTDOWN, [fd, len, 0, 0, 0, 0])),
        abi::OP_CLOSE => ok(syscall(p, nr::CLOSE, [fd, 0, 0, 0, 0, 0])),
        abi::OP_OPENAT => ok(syscall(
            p,
            nr::OPENAT,
            [s.fd as i64 as u64, s.addr, u64::from(s.op_flags), len, 0, 0],
        )),
        abi::OP_STATX => ok(syscall(
            p,
            nr::STATX,
            [
                s.fd as i64 as u64,
                s.addr,
                u64::from(s.op_flags),
                len,
                s.off,
                0,
            ],
        )),
        abi::OP_RENAMEAT => ok(syscall(
            p,
            nr::RENAMEAT2,
            [
                s.fd as i64 as u64,
                s.addr,
                len,
                s.off,
                u64::from(s.op_flags),
                0,
            ],
        )),
        abi::OP_UNLINKAT => ok(syscall(
            p,
            nr::UNLINKAT,
            [s.fd as i64 as u64, s.addr, u64::from(s.op_flags), 0, 0, 0],
        )),
        abi::OP_MKDIRAT => ok(syscall(
            p,
            nr::MKDIRAT,
            [s.fd as i64 as u64, s.addr, len, 0, 0, 0],
        )),
        _ => (-EINVAL, false),
    }
}

fn ring_of(p: &LinuxProcess, fd: u64) -> Result<Arc<dyn Object>, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Object(o) if o.obj.uring().is_some() => Ok(o.obj),
        _ => Err(EOPNOTSUPP),
    }
}

/// `io_uring_setup(entries, params)`.
pub(super) fn setup(p: &mut LinuxProcess, entries: u64, params: u64) -> Result<u64, i64> {
    let mut b = [0u8; 120];
    if p.copy_from_user(params, &mut b) != b.len() {
        return Err(EFAULT);
    }
    let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let entries = u32::try_from(entries).map_err(|_| EINVAL)?;
    let layout = ::uring::setup(entries, word(8), word(4))?;
    let rings = Mem::alloc(layout.ring_bytes).ok_or(ENOMEM)?;
    let sqes = Mem::alloc(layout.sqes_bytes).ok_or(ENOMEM)?;
    for (off, v) in layout.constants() {
        rings.set(off, v);
    }
    let ring = Arc::new_cyclic(|me| Ring {
        layout,
        rings,
        sqes,
        state: SpinLock::new(State::default()),
        watchers: Watchers::new(),
        eventfd: SpinLock::new(None),
        completed: AtomicU64::new(0),
        epoch: AtomicU64::new(0),
        worker: core::sync::atomic::AtomicBool::new(false),
        me: me.clone(),
    });
    let fd = p
        .install_flags(
            Fd::Object(ObjectEnd {
                obj: ring,
                nonblock: false,
            }),
            true,
        )
        .ok_or(EMFILE)?;
    if p.copy_to_user(params, &layout.params()) != 120 {
        p.close(fd);
        return Err(EFAULT);
    }
    Ok(fd)
}

/// `mmap` of a ring descriptor: the rings or the SQE array.
pub(super) fn mmap(p: &mut LinuxProcess, ring: &Ring, a: &[u64; 6]) -> Result<u64, i64> {
    let (addr, len, prot, flags, offset) = (a[0], a[1], a[2], a[3], a[5]);
    let mem = match offset {
        abi::OFF_SQ_RING | abi::OFF_CQ_RING => &ring.rings,
        abi::OFF_SQES => &ring.sqes,
        _ => return Err(EINVAL),
    };
    let pages = len.div_ceil(PAGE_SIZE) as usize;
    if len == 0 || pages > mem.0.len() {
        return Err(EINVAL);
    }
    p.mm().map_frames(addr, &mem.0[..pages], prot, flags)
}

/// `io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz)`.
pub(super) fn enter(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let (to_submit, min_complete, flags) = (a[1] as u32, a[2] as u32, a[3] as u32);
    let accepted =
        abi::ENTER_GETEVENTS | abi::ENTER_SQ_WAKEUP | abi::ENTER_SQ_WAIT | abi::ENTER_EXT_ARG;
    if flags & !accepted != 0 {
        return Err(EINVAL);
    }
    let obj = ring_of(p, a[0])?;
    let ring = obj.uring().ok_or(EOPNOTSUPP)?;
    // EXT_ARG: `struct io_uring_getevents_arg { sigmask, sigmask_sz, pad,
    // ts }`; its timeout bounds the wait (the signal mask is not applied).
    let mut deadline = None;
    if flags & abi::ENTER_EXT_ARG != 0 && a[4] != 0 {
        let mut arg = [0u8; 24];
        if p.copy_from_user(a[4], &mut arg) != arg.len() {
            return Err(EFAULT);
        }
        let ts = u64::from_le_bytes(arg[16..24].try_into().unwrap_or([0; 8]));
        if ts != 0 {
            deadline = Some(frame::time::now().saturating_add(poll::read_timespec(p, ts)?));
        }
    }
    {
        let mut st = ring.state.lock();
        ring.flush_overflow(&mut st);
    }
    let submitted = ring.submit(to_submit);
    ring.run(p);
    if flags & abi::ENTER_GETEVENTS == 0 {
        return Ok(u64::from(submitted));
    }
    loop {
        {
            let mut st = ring.state.lock();
            ring.flush_overflow(&mut st);
        }
        if ring.cq_ready() >= min_complete {
            return Ok(u64::from(submitted));
        }
        let (fds, next) = ring.waits(p);
        let until = match (deadline, next) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let mut watched: Vec<Fd> = fds.iter().map(|(f, _)| f.clone()).collect();
        watched.push(Fd::Object(ObjectEnd {
            obj: obj.clone(),
            nonblock: false,
        }));
        let r = poll::wait_ready(p, watched.iter(), until, || {
            let ready = fds.iter().any(|(f, need)| poll::readiness(f) & need != 0);
            (ready || ring.cq_ready() >= min_complete).then_some(())
        });
        if r.is_err() {
            p.resume_until = None;
            return if submitted == 0 {
                Err(EINTR)
            } else {
                Ok(u64::from(submitted))
            };
        }
        ring.run(p);
        if deadline.is_some_and(|d| frame::time::now() >= d) && ring.cq_ready() < min_complete {
            return if submitted > 0 {
                Ok(u64::from(submitted))
            } else {
                Err(ETIME)
            };
        }
    }
}

/// `io_uring_register(fd, opcode, arg, nr_args)`.
pub(super) fn register(
    p: &mut LinuxProcess,
    fd: u64,
    opcode: u64,
    arg: u64,
    n: u64,
) -> Result<u64, i64> {
    let obj = ring_of(p, fd)?;
    let ring = obj.uring().ok_or(EOPNOTSUPP)?;
    match opcode as u32 {
        abi::REGISTER_PROBE => {
            // `struct io_uring_probe { last_op, ops_len, resv, resv2[3],
            // ops[] }`, each op `{ op, resv, flags, resv2 }`.
            let n = (n as usize).min(256);
            let last = SUPPORTED.iter().copied().max().unwrap_or(0);
            let shown = n.min(usize::from(last) + 1);
            let mut b = alloc::vec![0u8; 16 + n * 8];
            b[0] = last;
            b[1] = shown as u8;
            for op in 0..shown {
                let e = &mut b[16 + op * 8..24 + op * 8];
                e[0] = op as u8;
                if SUPPORTED.contains(&(op as u8)) {
                    e[2..4].copy_from_slice(&abi::OP_SUPPORTED.to_le_bytes());
                }
            }
            if p.copy_to_user(arg, &b) != b.len() {
                return Err(EFAULT);
            }
            Ok(0)
        }
        abi::REGISTER_EVENTFD => {
            let mut b = [0u8; 4];
            if n != 1 || p.copy_from_user(arg, &mut b) != 4 {
                return Err(EINVAL);
            }
            let efd = u64::from(u32::from_le_bytes(b));
            let Some(Fd::Object(o)) = p.fd(efd) else {
                return Err(EBADF);
            };
            *ring.eventfd.lock() = Some(o.obj);
            Ok(0)
        }
        abi::UNREGISTER_EVENTFD => {
            *ring.eventfd.lock() = None;
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}
