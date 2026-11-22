//! io_uring for the Linux personality (ADR-0013 §1).
//!
//! A ring is a descriptor naming kernel pages that the process maps
//! (`mmap` at Linux's offsets): the SQ and CQ rings in one mapping
//! (`IORING_FEAT_SINGLE_MMAP`), the SQE array in another. The kernel reads
//! and writes them through `UFrame` readers and writers, so frame is not
//! involved. `kernel/uring` holds the ABI and the ordering rules (links,
//! hard links, link timeouts, drains); `ops` runs the operations, `tables`
//! holds what is registered with a ring.
//!
//! An SQE runs on the thread that submits it, through the same code as the
//! synchronous syscall, on the open file description it named when it
//! started (lent to the thread: [`Thread`]) and without blocking. One that
//! cannot go on is armed, and tried again when its object changes: by a
//! thread waiting in `io_uring_enter`, or by the ring's worker, a helper
//! thread of the process (`LinuxProcess::helper`) started the first time an
//! SQE is armed, so completions arrive while the program waits on the ring
//! descriptor with epoll or on a registered eventfd, as on Linux. The ring
//! is registered once with every object its SQEs wait for (its
//! [`poll::Hub`]). An armed SQE is claimed before it is tried, so it runs
//! once, and only by threads of the process that submitted it.
//!
//! `IORING_SETUP_SQPOLL` rings have a poller that is always asleep: the
//! ring says `IORING_SQ_NEED_WAKEUP`, so programs call `io_uring_enter` to
//! wake it, and that submits. Nothing spins. No file here can be polled for
//! completions, so reads and writes of an IOPOLL ring are refused, as on a
//! Linux file system that cannot do it.
//!
//! The cell pays for the ring's pages, for what is in flight, and for what
//! is registered.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use ::uring::{Cqe, Layout, Order, Sqe, abi};
use cell::Account;
use frame::mm::{PAGE_SIZE, UFrame, VmSpace};
use frame::sync::{Mutex, SpinLock};

use crate::page::{Page, Reserved, charged};
use crate::poll::{self, Hub, Object, POLLIN, POLLOUT, Waiter, Watch, Watchers};
use crate::process::{Description, Fd, LinuxProcess, ObjectEnd};

mod ops;
mod tables;

use ops::Step;
pub(super) use tables::register;

const ENOENT: i64 = 2;
const EINTR: i64 = 4;
const ENXIO: i64 = 6;
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ETIME: i64 = 62;
const EBADFD: i64 = 77;
const EOPNOTSUPP: i64 = 95;
const EALREADY: i64 = 114;
const ECANCELED: i64 = 125;

/// What a thread keeps for io_uring.
#[derive(Debug, Default)]
pub(crate) struct Thread {
    /// The files of the operation it is running, as descriptors [`LENT`]
    /// and below.
    lent: Vec<Arc<Description>>,
    /// Its registered rings (`IORING_REGISTER_RING_FDS`).
    rings: Vec<Option<Arc<dyn Object>>>,
    /// Where the message it receives goes, instead of where its `msghdr`
    /// says (a provided buffer, or the rest of one).
    pub(super) iov: Option<Vec<(u64, usize)>>,
    /// What the operation's arguments said when it was submitted.
    kept: Option<Arc<Kept>>,
    /// Where what it writes stays here, and that.
    written: Option<(u64, Vec<u8>)>,
}

/// Memory of the program's that an operation reads when it runs, as it was
/// when it was submitted (`IORING_FEAT_SUBMIT_STABLE`): by address.
#[derive(Debug, Default)]
struct Kept(Vec<(u64, Vec<u8>)>);

impl Kept {
    /// `b` in place of what is at `at`.
    fn of(at: u64, b: &[u8]) -> Kept {
        Kept(alloc::vec![(at, b.to_vec())])
    }

    /// Keeps `len` bytes at `at` (nothing, if they cannot be read: the
    /// operation will find that out).
    fn keep(&mut self, p: &mut LinuxProcess, at: u64, len: usize) -> Option<&[u8]> {
        let mut b = alloc::vec![0u8; len];
        if at == 0 || len == 0 || p.copy_from_user(at, &mut b) != len {
            return None;
        }
        self.0.push((at, b));
        self.0.last().map(|(_, b)| b.as_slice())
    }

    fn bytes(&self) -> usize {
        self.0.iter().map(|(_, b)| b.len() + 32).sum()
    }
}

/// The number an operation's file has while a thread runs it. No program
/// has a descriptor like it (`MAX_FDS`).
const LENT: u64 = i32::MAX as u64;

impl Thread {
    /// The file lent as descriptor `fd`.
    pub(crate) fn lent(&self, fd: u64) -> Option<&Arc<Description>> {
        self.lent.get(usize::try_from(LENT.checked_sub(fd)?).ok()?)
    }

    /// The `len` bytes at `at` as they were at submission, if kept.
    pub(crate) fn kept(&self, at: u64, len: usize) -> Option<&[u8]> {
        self.kept.as_ref()?.0.iter().find_map(|(from, b)| {
            let off = usize::try_from(at.checked_sub(*from)?).ok()?;
            b.get(off..off.checked_add(len)?)
        })
    }

    /// Where `len` bytes written at `at` go, if they stay here.
    pub(crate) fn written(&mut self, at: u64, len: usize) -> Option<&mut [u8]> {
        let (from, b) = self.written.as_mut()?;
        let off = usize::try_from(at.checked_sub(*from)?).ok()?;
        b.get_mut(off..off.checked_add(len)?)
    }
}

/// Pages shared with the process.
struct Mem(Vec<Page>);

impl Mem {
    fn alloc(account: &Arc<Account>, bytes: u64) -> Option<Mem> {
        let n = bytes.div_ceil(PAGE_SIZE);
        (0..n)
            .map(|_| charged(account, UFrame::alloc_zeroed()?))
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

/// Who submitted an SQE: a process, with the program it ran then.
#[derive(Clone, Debug)]
struct Owner {
    tgid: u64,
    space: Weak<VmSpace>,
    /// `Group::ring_due`.
    due: Arc<AtomicBool>,
}

impl Owner {
    fn of(p: &LinuxProcess) -> Owner {
        Owner {
            tgid: p.group.tgid,
            space: Arc::downgrade(&p.group.space()),
            due: p.group.ring_due.clone(),
        }
    }

    /// Whether `other` is the same process running the same program.
    fn is(&self, other: &Owner) -> bool {
        self.tgid == other.tgid && self.space.ptr_eq(&other.space)
    }
}

/// The file an SQE is on.
#[derive(Clone, Debug)]
enum File {
    Held(Arc<Description>),
    /// A ring: held weakly, so rings that wait for each other (or for
    /// themselves) close.
    Ring(Weak<Description>),
}

impl File {
    fn of(d: Arc<Description>) -> File {
        let ring = matches!(&*d.state(), Fd::Object(o) if o.obj.uring().is_some());
        if ring {
            File::Ring(Arc::downgrade(&d))
        } else {
            File::Held(d)
        }
    }

    fn get(&self) -> Option<Arc<Description>> {
        match self {
            File::Held(d) => Some(d.clone()),
            File::Ring(w) => w.upgrade(),
        }
    }

    fn is(&self, d: &Arc<Description>) -> bool {
        match self {
            File::Held(x) => Arc::ptr_eq(x, d),
            File::Ring(w) => core::ptr::eq(w.as_ptr(), Arc::as_ptr(d)),
        }
    }
}

/// Where a submitted SQE is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Its turn has not come, or a thread is at its first try.
    Queued,
    /// Waiting for its object, or for a deadline.
    Armed,
    /// A thread has it (no other may run or cancel it).
    Claimed,
    /// So has one that cancels it.
    Cancelled,
}

/// What was taken to be cancelled, and what the one who asked is told.
struct Cancelling {
    ids: Vec<u64>,
    result: Result<u64, i64>,
}

impl From<Result<u64, i64>> for Cancelling {
    fn from(result: Result<u64, i64>) -> Cancelling {
        Cancelling {
            ids: Vec::new(),
            result,
        }
    }
}

/// A submitted SQE not yet complete.
#[derive(Debug)]
struct Op {
    sqe: Sqe,
    owner: Owner,
    /// It was refused: what it completes with when its turn comes.
    refused: Option<i64>,
    phase: Phase,
    /// A thread of its process has begun it.
    begun: bool,
    /// It waited.
    waited: bool,
    /// Its object changed while a thread was trying it.
    again: bool,
    /// It is to be tried whether its object is ready or not.
    force: bool,
    /// When it began, if it uses what is registered.
    generation: Option<u64>,
    file: Option<File>,
    /// Its registration with its object, once armed.
    watch: Option<Watch>,
    kept: Option<Arc<Kept>>,
    /// Bytes moved so far (`MSG_WAITALL`), or a connection under way.
    done: u64,
    /// The object's changes counted before the last try, and when to try
    /// again though it has not changed.
    seen: Option<u64>,
    retry: Duration,
    /// TIMEOUT: its deadline, and the count of completions that ends it.
    deadline: Option<Duration>,
    until: Option<u64>,
}

/// An armed SQE, as looked at to tell whether to try it.
struct Look {
    sqe: Sqe,
    owner: Owner,
    begun: bool,
    force: bool,
    file: Option<File>,
    watch: Option<Watch>,
    seen: Option<u64>,
    retry: Duration,
}

impl Look {
    fn at(o: &Op) -> Look {
        Look {
            sqe: o.sqe,
            owner: o.owner.clone(),
            begun: o.begun,
            force: o.force,
            watch: o.watch.clone(),
            file: o.file.clone(),
            seen: o.seen,
            retry: o.retry,
        }
    }

    fn fd(&self) -> Option<Fd> {
        Some(self.file.as_ref()?.get()?.state().clone())
    }

    /// Is told of its file's next change too.
    fn watch_again(&self, fd: Option<&Fd>) {
        if let (Some(w), Some(fd)) = (&self.watch, fd) {
            w.again(fd);
        }
    }

    /// Whether its file (a ring) is closed.
    fn closed(&self, fd: Option<&Fd>) -> bool {
        self.file.is_some() && fd.is_none()
    }

    /// Whether it is worth a try.
    fn due(&self, fd: Option<&Fd>) -> bool {
        let again = frame::time::now() >= self.retry;
        let (Some(need), Some(fd)) = (ops::need(&self.sqe), fd) else {
            return again;
        };
        if self.force {
            return true;
        }
        if ops::ready(fd) & need == 0 {
            return false;
        }
        let changed = self.seen != Some(poll::changes(fd));
        match self.sqe.opcode {
            abi::OP_POLL_ADD => changed || self.sqe.len & abi::POLL_ADD_MULTI == 0,
            _ => changed || again,
        }
    }
}

/// A completion.
#[derive(Clone, Copy, Debug)]
struct Done {
    res: i64,
    /// As the operation asked (a failure breaks an `IO_LINK` chain).
    ok: bool,
    flags: u32,
}

impl Done {
    fn new(res: i64, ok: bool) -> Done {
        Done { res, ok, flags: 0 }
    }

    /// A result as a syscall gives it.
    fn of(r: Result<u64, i64>) -> Done {
        match r {
            Ok(v) => Done::new(v as i64, true),
            Err(e) => Done::err(e),
        }
    }

    fn err(e: i64) -> Done {
        Done::new(-e, false)
    }
}

/// SQEs and unread CQEs a page of the cell's memory pays for.
const PER_PAGE: usize = 8;
/// Most SQEs in flight in a ring.
const MAX_IN_FLIGHT: usize = 1 << 17;
/// Most tags that wait for operations to end.
const MAX_TAGS: usize = 1 << 16;

#[derive(Debug)]
struct State {
    order: Order,
    ops: BTreeMap<u64, Op>,
    /// CQEs the CQ had no room for (`IORING_FEAT_NODROP`), by number.
    overflow: BTreeMap<u64, Cqe>,
    next_overflow: u64,
    /// SQEs are being submitted.
    assembling: bool,
    /// Deadlines of armed timeouts, and the counts of completions others
    /// end at.
    timers: BTreeSet<(Duration, u64)>,
    counts: BTreeSet<(u64, u64)>,
    /// When to look again at SQEs that could not go on though their objects
    /// are ready.
    rechecks: BTreeSet<(Duration, u64)>,
    /// `IORING_SETUP_DEFER_TASKRUN`: something can go on, and whoever
    /// listens was told.
    pending: bool,
    /// The processes whose workers run.
    workers: Vec<u64>,
    /// Bytes of arguments kept.
    kept: usize,
    /// How often something registered has been taken out, how many SQEs
    /// began at each count and use what is registered, and the tags of what
    /// was taken out then (told of once none of those is left).
    generation: u64,
    uses: BTreeMap<u64, u32>,
    tags: BTreeMap<(u64, u64), u64>,
    paid: Reserved,
}

impl State {
    /// Pays for what is in flight and `more` bytes; false if the cell
    /// cannot.
    fn settle(&mut self, more: usize) -> bool {
        let n = self.ops.len() + self.overflow.len() + self.tags.len();
        let pages = n / PER_PAGE + 1 + (self.kept + more).div_ceil(PAGE_SIZE as usize);
        self.paid.resize(pages as u64)
    }

    /// Pays for one more SQE, with `bytes` of arguments.
    fn make_room(&mut self, bytes: usize) -> bool {
        self.ops.len() + self.overflow.len() < MAX_IN_FLIGHT && self.settle(bytes)
    }

    /// Takes a complete SQE out.
    fn take(&mut self, id: u64) -> Option<Op> {
        let op = self.ops.remove(&id)?;
        if let Some(d) = op.deadline {
            self.timers.remove(&(d, id));
        }
        if let Some(n) = op.until {
            self.counts.remove(&(n, id));
        }
        if let Some(k) = &op.kept {
            self.kept -= k.bytes();
        }
        self.rechecks.remove(&(op.retry, id));
        if let Some(g) = op.generation
            && let Some(n) = self.uses.get_mut(&g)
        {
            *n -= 1;
            if *n == 0 {
                self.uses.remove(&g);
            }
        }
        // (Paying for less always succeeds.)
        self.settle(0);
        Some(op)
    }

    /// Takes out the tag of something registered that no operation uses any
    /// more.
    fn unused(&mut self) -> Option<u64> {
        let (&(g, n), _) = self.tags.first_key_value()?;
        let oldest = self.uses.keys().next();
        if oldest.is_some_and(|&o| o <= g) {
            return None;
        }
        self.tags.remove(&(g, n))
    }

    /// Marks an armed SQE as taken by a thread.
    fn claim(&mut self, id: u64) -> bool {
        match self.ops.get_mut(&id) {
            Some(o) if o.phase == Phase::Armed => {
                o.phase = Phase::Claimed;
                true
            }
            _ => false,
        }
    }

    /// Adds a submitted SQE (`refused`: with what). Returns whether the
    /// rest of the submission is left for another call.
    fn add(
        &mut self,
        sqe: Sqe,
        mut refused: Option<i64>,
        owner: Owner,
        kept: Option<Arc<Kept>>,
    ) -> bool {
        let chain = self.order.chain();
        let timeout = match sqe.opcode {
            abi::OP_LINK_TIMEOUT if refused.is_none() => {
                let id = self.order.submit_timeout(sqe.flags);
                if id.is_none() {
                    refused = Some(EINVAL);
                }
                id
            }
            _ => None,
        };
        let id = timeout.unwrap_or_else(|| self.order.submit(sqe.flags));
        if refused.is_some()
            && let Some(first) = chain.and_then(|c| self.ops.get_mut(&c))
        {
            // A chain with a member that cannot be is not begun.
            first.refused.get_or_insert(ECANCELED);
        }
        self.ops.insert(
            id,
            Op {
                sqe,
                owner,
                refused,
                phase: Phase::Queued,
                begun: false,
                waited: false,
                again: false,
                force: false,
                generation: None,
                file: None,
                watch: None,
                kept,
                done: 0,
                seen: None,
                retry: Duration::ZERO,
                deadline: None,
                until: None,
            },
        );
        refused.is_some() && sqe.flags & (abi::SQE_IO_LINK | abi::SQE_IO_HARDLINK) == 0
    }
}

/// `IORING_REGISTER_EVENTFD`.
#[derive(Clone, Debug)]
struct Notify {
    eventfd: Arc<dyn Object>,
    /// Only of completions that waited (`_ASYNC`).
    waited: bool,
}

/// An io_uring instance.
pub(crate) struct Ring {
    layout: Layout,
    rings: Mem,
    sqes: Mem,
    account: Arc<Account>,
    /// Held while SQEs are submitted.
    submitting: Mutex<()>,
    /// Held while an operation may take a provided buffer.
    picking: Mutex<()>,
    state: SpinLock<State>,
    tables: SpinLock<tables::Tables>,
    /// Who polls the ring.
    watchers: Watchers,
    /// Where threads wait for what the ring's SQEs wait for, and for
    /// completions.
    hub: Arc<Hub>,
    notify: SpinLock<Option<Notify>>,
    /// CQEs posted so far, and those of them that count for TIMEOUT.
    posted: AtomicU64,
    counted: AtomicU64,
    /// Not `IORING_SETUP_R_DISABLED` (any more).
    enabled: AtomicBool,
    /// The thread that may submit (`IORING_SETUP_SINGLE_ISSUER`; 0: any).
    issuer: AtomicU64,
    limits: SpinLock<Option<tables::Restrictions>>,
    /// `IORING_REGISTER_IOWQ_MAX_WORKERS`: what the program asked for (no
    /// operation waits in a worker here, so nothing uses that many).
    max_workers: SpinLock<[u32; 2]>,
    /// This ring, for the worker (which must not keep it alive).
    me: Weak<Ring>,
}

impl core::fmt::Debug for Ring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ring")
            .field("sq_entries", &self.layout.sq_entries)
            .field("cq_entries", &self.layout.cq_entries)
            .finish()
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        // The worker sees that it is gone, and so do operations on it.
        self.hub.tell();
        self.watchers.notify();
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
        if self.cq_ready() > 0 || self.state.lock().pending {
            r |= POLLIN;
        }
        if self.queued() < self.layout.sq_entries {
            r |= POLLOUT;
        }
        r
    }

    fn changes(&self) -> u64 {
        self.posted.load(Ordering::Acquire)
    }

    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.watchers)
    }

    fn woken_by_ring(&self) -> bool {
        true
    }

    fn uring(&self) -> Option<&Ring> {
        Some(self)
    }
}

impl Ring {
    /// Has whoever waits here look again.
    pub(crate) fn wake(&self) {
        self.hub.tell();
    }

    /// How many CQEs were timeouts'.
    fn timeouts(&self) -> u64 {
        let counted = self.counted.load(Ordering::Acquire);
        self.posted.load(Ordering::Acquire).wrapping_sub(counted)
    }

    /// SQEs the application has queued.
    fn queued(&self) -> u32 {
        let l = &self.layout;
        ::uring::pending(
            self.rings.get(l.sq.head),
            self.rings.get(l.sq.tail),
            l.sq_entries,
        )
    }

    /// CQEs the application has not consumed.
    fn cq_ready(&self) -> u32 {
        let l = &self.layout;
        self.rings
            .get(l.cq.tail)
            .wrapping_sub(self.rings.get(l.cq.head))
            .min(l.cq_entries)
    }

    /// Writes a CQE, or keeps it until there is room (`waited`: its SQE
    /// did, or it has none; `counts`: for TIMEOUT).
    fn post(&self, c: Cqe, waited: bool, counts: bool) {
        {
            let mut st = self.state.lock();
            let n = st.next_overflow;
            st.next_overflow += 1;
            st.overflow.insert(n, c);
            self.flush_overflow(&mut st);
        }
        self.told(waited, counts);
    }

    /// Posts a CQE that no SQE of this ring paid for (MSG_RING); false if
    /// the cell cannot, or too many wait to be read.
    fn post_message(&self, c: Cqe) -> bool {
        if !self.state.lock().make_room(0) {
            return false;
        }
        self.post(c, true, true);
        true
    }

    /// Posts one of an SQE's several completions; false (and nothing
    /// happens) if the CQ has no room for it, which ends the SQE.
    fn post_more(&self, id: u64, done: Done) -> bool {
        let (waited, counts) = {
            let mut st = self.state.lock();
            let Some(op) = st.ops.get(&id) else {
                return true;
            };
            let l = &self.layout;
            let (head, tail) = (self.rings.get(l.cq.head), self.rings.get(l.cq.tail));
            if !st.overflow.is_empty() || ::uring::cq_space(head, tail, l.cq_entries) == 0 {
                return false;
            }
            let c = Cqe {
                user_data: op.sqe.user_data,
                res: done.res as i32,
                flags: done.flags | abi::CQE_F_MORE,
            };
            let r = (op.waited, op.sqe.opcode != abi::OP_TIMEOUT);
            let n = st.next_overflow;
            st.next_overflow += 1;
            st.overflow.insert(n, c);
            self.flush_overflow(&mut st);
            r
        };
        self.told(waited, counts);
        true
    }

    /// Tells whoever waits for completions of one.
    fn told(&self, waited: bool, counts: bool) {
        self.posted.fetch_add(1, Ordering::AcqRel);
        if counts {
            self.counted.fetch_add(1, Ordering::AcqRel);
        }
        self.hub.tell();
        self.watchers.notify();
        self.signal(waited);
    }

    /// Adds to the registered eventfd.
    fn signal(&self, waited: bool) {
        let notify = self.notify.lock().clone();
        if let Some(n) = notify
            && (waited || !n.waited)
            && self.rings.get(self.layout.cq.flags) & abi::CQ_EVENTFD_DISABLED == 0
            && let Some(e) = n.eventfd.eventfd()
        {
            e.signal();
        }
    }

    fn flush_overflow(&self, st: &mut State) {
        let l = &self.layout;
        let head = self.rings.get(l.cq.head);
        let mut tail = self.rings.get(l.cq.tail);
        while ::uring::cq_space(head, tail, l.cq_entries) > 0 {
            let Some((_, c)) = st.overflow.pop_first() else {
                break;
            };
            let slot = tail & (l.cq_entries - 1);
            // (The second half of a 32-byte CQE is zero: no operation
            // here has more to say.)
            self.rings
                .write((l.cq.cqes + slot * l.cqe_bytes) as usize, &c.encode());
            tail = tail.wrapping_add(1);
        }
        // The entries are in place before the tail says so.
        core::sync::atomic::fence(Ordering::Release);
        self.rings.set(l.cq.tail, tail);
        self.set_flags(st);
    }

    /// The flags of the SQ ring.
    fn set_flags(&self, st: &State) {
        let l = &self.layout;
        let mut flags = 0;
        if l.has(abi::SETUP_SQPOLL) {
            flags |= abi::SQ_NEED_WAKEUP;
        }
        if !st.overflow.is_empty() {
            flags |= abi::SQ_CQ_OVERFLOW;
        }
        if st.pending && l.has(abi::SETUP_TASKRUN_FLAG) {
            flags |= abi::SQ_TASKRUN;
        }
        self.rings.set(l.sq.flags, flags);
    }

    /// Takes up to `n` SQEs from the SQ.
    fn submit(&self, p: &mut LinuxProcess, n: u32) -> Result<u32, i64> {
        // One thread at a time; nothing begins before a batch is whole
        // (its chains are).
        let _one = self.submitting.lock();
        self.state.lock().assembling = true;
        let r = self.assemble(p, n);
        let mut st = self.state.lock();
        st.order.end_batch();
        st.assembling = false;
        r
    }

    fn assemble(&self, p: &mut LinuxProcess, n: u32) -> Result<u32, i64> {
        let l = &self.layout;
        let owner = Owner::of(p);
        let limits = self.limits.lock().clone();
        let mut head = self.rings.get(l.sq.head);
        let n = self.queued().min(n);
        core::sync::atomic::fence(Ordering::Acquire);
        let mut taken = 0;
        let mut paid = true;
        while taken < n {
            let slot = head & (l.sq_entries - 1);
            let idx = if l.has(abi::SETUP_NO_SQARRAY) {
                slot
            } else {
                self.rings.get(l.sq.array + slot * 4)
            };
            head = head.wrapping_add(1);
            if idx >= l.sq_entries {
                let d = self.rings.get(l.sq.dropped);
                self.rings.set(l.sq.dropped, d.wrapping_add(1));
                break;
            }
            let mut b = [0u8; 64];
            self.sqes.read((idx * l.sqe_bytes) as usize, &mut b);
            let sqe = Sqe::parse(&b);
            let refused = match &limits {
                Some(r) => r.sqe(&sqe),
                None => Ok(()),
            }
            .and_then(|()| ops::check(&sqe, l))
            .err();
            let kept = match refused {
                None => ops::keep(p, &sqe),
                Some(_) => Kept::default(),
            };
            let bytes = kept.bytes();
            let kept = (bytes != 0).then(|| Arc::new(kept));
            let mut st = self.state.lock();
            paid = st.make_room(bytes);
            if !paid {
                head = head.wrapping_sub(1);
                break;
            }
            st.kept += bytes;
            taken += 1;
            if st.add(sqe, refused, owner.clone(), kept) && !l.has(abi::SETUP_SUBMIT_ALL) {
                break;
            }
        }
        self.rings.set(l.sq.head, head);
        if taken == 0 && !paid {
            return Err(EAGAIN);
        }
        Ok(taken)
    }

    /// Completes `id`, and what a broken link cancels with it.
    fn complete(&self, id: u64, done: Done) {
        let (op, chain, timeout) = {
            let mut st = self.state.lock();
            let Some(op) = st.take(id) else {
                return;
            };
            let gone = if op.refused.is_some() {
                st.order.refuse(id)
            } else {
                st.order.complete(id, done.ok)
            };
            (op, gone.chain, gone.timeout.and_then(|t| st.take(t)))
        };
        let quiet = |o: &Op| o.sqe.flags & abi::SQE_CQE_SKIP_SUCCESS != 0;
        if !(done.ok && quiet(&op)) {
            self.post(
                Cqe {
                    user_data: op.sqe.user_data,
                    res: done.res.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                    flags: done.flags,
                },
                op.waited,
                op.sqe.opcode != abi::OP_TIMEOUT,
            );
        }
        let cancelled = |o: &Op| Cqe {
            user_data: o.sqe.user_data,
            res: -(o.refused.unwrap_or(ECANCELED) as i32),
            flags: 0,
        };
        // A chain is told of its end once: by what failed, if that was to
        // be silent about success; by each member, if not.
        for c in chain {
            let o = self.state.lock().take(c);
            if let Some(o) = &o
                && !quiet(&op)
            {
                self.post(cancelled(o), true, true);
            }
        }
        if let Some(t) = &timeout
            && !quiet(t)
        {
            self.post(cancelled(t), true, true);
        }
        if op.generation.is_some() {
            self.tell_tags();
        }
    }

    /// Something registered, with tag `tag` (0: none), has been taken out:
    /// the program is told once no operation uses it.
    fn left(&self, tag: u64) {
        if tag == 0 {
            return;
        }
        {
            let mut st = self.state.lock();
            let g = st.generation;
            st.generation += 1;
            let n = st.next_overflow;
            st.next_overflow += 1;
            st.tags.insert((g, n), tag);
        }
        self.tell_tags();
    }

    /// Refuses to take out more with a tag while so much waits to be told.
    fn may_leave(&self) -> Result<(), i64> {
        if self.state.lock().tags.len() < MAX_TAGS {
            Ok(())
        } else {
            Err(ENOMEM)
        }
    }

    fn tell_tags(&self) {
        loop {
            let tag = self.state.lock().unused();
            let Some(user_data) = tag else {
                return;
            };
            self.post(
                Cqe {
                    user_data,
                    res: 0,
                    flags: 0,
                },
                true,
                true,
            );
        }
    }

    /// Runs what can run now: SQEs whose turn it is and, with `waited`,
    /// timeouts that are over and armed SQEs whose objects have changed.
    fn run(&self, p: &mut LinuxProcess, waited: bool) {
        let me = Owner::of(p);
        loop {
            let ready = {
                let mut st = self.state.lock();
                if waited && st.pending {
                    st.pending = false;
                    self.set_flags(&st);
                }
                if st.assembling {
                    Vec::new()
                } else {
                    st.order.ready()
                }
            };
            let mut progress = !ready.is_empty();
            for id in ready {
                let mine = self
                    .state
                    .lock()
                    .ops
                    .get(&id)
                    .is_some_and(|o| o.owner.is(&me));
                if mine {
                    self.start(p, id);
                } else {
                    // Another process's: its worker starts it.
                    self.hand_over(id);
                }
            }
            if waited {
                progress |= self.fire(p);
                progress |= self.retry(p, &me);
            }
            if !progress {
                break;
            }
        }
        self.start_worker(p);
    }

    /// The first try of an SQE.
    fn start(&self, p: &mut LinuxProcess, id: u64) {
        let Some((sqe, refused)) = self.state.lock().ops.get(&id).map(|o| (o.sqe, o.refused))
        else {
            return;
        };
        if let Some(e) = refused {
            return self.complete(id, Done::err(e));
        }
        p.uring.kept = {
            let mut st = self.state.lock();
            let g = st.generation;
            let registered = ops::uses_registered(&sqe);
            if registered {
                *st.uses.entry(g).or_default() += 1;
            }
            match st.ops.get_mut(&id) {
                Some(o) => {
                    o.begun = true;
                    o.generation = registered.then_some(g);
                    o.kept.clone()
                }
                None => None,
            }
        };
        self.begin(p, id, &sqe);
        p.uring.kept = None;
    }

    fn begin(&self, p: &mut LinuxProcess, id: u64, sqe: &Sqe) {
        match sqe.opcode {
            abi::OP_NOP => self.complete(id, Done::new(0, true)),
            abi::OP_TIMEOUT | abi::OP_LINK_TIMEOUT => {
                match read_timeout(p, sqe.addr, sqe.op_flags) {
                    Ok(t) => {
                        let counts = sqe.opcode == abi::OP_TIMEOUT
                            && sqe.op_flags & abi::TIMEOUT_MULTISHOT == 0
                            && sqe.off != 0;
                        let until = counts
                            .then(|| self.counted.load(Ordering::Acquire).saturating_add(sqe.off));
                        self.set_timer(id, Some(t), until);
                        self.arm(id, None);
                    }
                    Err(e) => self.complete(id, Done::err(e)),
                }
            }
            abi::OP_TIMEOUT_REMOVE => {
                let c = self.remove_timeout(p, sqe);
                self.complete(id, Done::of(c.result));
                self.end(c.ids);
            }
            abi::OP_POLL_REMOVE => {
                let c = self.remove_poll(sqe);
                self.complete(id, Done::of(c.result));
                self.end(c.ids);
            }
            abi::OP_ASYNC_CANCEL => {
                let c = self.cancel_request(p, sqe);
                self.complete(id, Done::of(c.result));
                self.end(c.ids);
            }
            _ => {
                let mut file = None;
                if ops::on_file(sqe.opcode) {
                    let Some(d) = self.file(p, sqe) else {
                        return self.complete(id, Done::err(EBADF));
                    };
                    let f = File::of(d);
                    if let Some(o) = self.state.lock().ops.get_mut(&id) {
                        o.file = Some(f.clone());
                    }
                    file = Some(f);
                }
                if ops::waits_first(sqe) || !self.attempt(p, id) {
                    self.arm(id, file.as_ref());
                }
            }
        }
    }

    /// The description `sqe` is on.
    fn file(&self, p: &LinuxProcess, sqe: &Sqe) -> Option<Arc<Description>> {
        if sqe.flags & abi::SQE_FIXED_FILE != 0 {
            self.tables.lock().files.get(sqe.fd as u32)
        } else {
            p.desc(u64::from(sqe.fd as u32))
        }
    }

    /// Tries an SQE. Returns whether it is complete.
    fn attempt(&self, p: &mut LinuxProcess, id: u64) -> bool {
        // (A multishot operation gives way to others now and then.)
        for _ in 0..64 {
            let Some((sqe, file, mut done, seen, kept)) = ({
                let st = self.state.lock();
                st.ops
                    .get(&id)
                    .map(|o| (o.sqe, o.file.clone(), o.done, o.seen, o.kept.clone()))
            }) else {
                return true;
            };
            let desc = match &file {
                Some(f) => match f.get() {
                    Some(d) => Some(d),
                    None => {
                        self.complete(id, Done::err(ECANCELED));
                        return true;
                    }
                },
                None => None,
            };
            let fd = desc.as_ref().map(|d| d.state().clone());
            let before = fd.as_ref().map(poll::changes);
            p.uring.lent = desc.iter().cloned().collect();
            p.uring.kept = kept;
            let step = {
                // One picks a buffer at a time: what it gives back, if it
                // needed none, nobody missed meanwhile.
                let select = sqe.flags & abi::SQE_BUFFER_SELECT != 0;
                let _one = select.then(|| self.picking.lock());
                ops::issue(self, p, &sqe, fd.as_ref(), &mut done, seen)
            };
            p.uring.lent = Vec::new();
            p.uring.kept = None;
            p.uring.iov = None;
            match step {
                Step::Done(d) => {
                    self.complete(id, d);
                    return true;
                }
                Step::More(d) => {
                    if let Some(o) = self.state.lock().ops.get_mut(&id) {
                        o.seen = before;
                    }
                    if !self.post_more(id, d) {
                        self.complete(id, d);
                        return true;
                    }
                    if sqe.opcode == abi::OP_POLL_ADD {
                        return false;
                    }
                }
                Step::Again => {
                    // Tried again when its object changes; soon anyway, if
                    // that is ready as it is.
                    let soon = match (ops::need(&sqe), &fd) {
                        _ if sqe.opcode == abi::OP_POLL_ADD => false,
                        (Some(need), Some(fd)) => ops::ready(fd) & need != 0,
                        _ => true,
                    };
                    let mut st = self.state.lock();
                    let Some(o) = st.ops.get_mut(&id) else {
                        return true;
                    };
                    o.done = done;
                    o.seen = before;
                    o.force = false;
                    let was = o.retry;
                    let retry = frame::time::now() + RETRY;
                    o.retry = retry;
                    st.rechecks.remove(&(was, id));
                    if soon {
                        st.rechecks.insert((retry, id));
                    }
                    return false;
                }
            }
        }
        // Its buffers may be what ends it, so it is tried without data too.
        if let Some(o) = self.state.lock().ops.get_mut(&id) {
            o.force = true;
            o.again = true;
        }
        false
    }

    /// Leaves an SQE whose turn it is to a thread of its own process.
    fn hand_over(&self, id: u64) {
        let tgid = match self.state.lock().ops.get_mut(&id) {
            Some(o) => {
                o.phase = Phase::Armed;
                o.owner.tgid
            }
            None => return,
        };
        self.hub.due(Waiter { tgid, id });
    }

    /// Leaves an SQE to wait for `file`.
    fn arm(&self, id: u64, file: Option<&File>) {
        let (tgid, flag) = match self.state.lock().ops.get(&id) {
            Some(o) => (o.owner.tgid, o.owner.due.clone()),
            None => return,
        };
        let w = Waiter { tgid, id };
        let watch = file
            .and_then(File::get)
            .and_then(|d| self.hub.watch(&d.state(), w, &flag));
        if let Some(o) = self.state.lock().ops.get_mut(&id) {
            o.phase = Phase::Armed;
            o.waited = true;
            o.watch = watch;
        }
        // It may have changed before it was watched.
        self.hub.due(w);
    }

    fn set_timer(&self, id: u64, deadline: Option<Duration>, until: Option<u64>) {
        let mut st = self.state.lock();
        let Some(o) = st.ops.get_mut(&id) else {
            return;
        };
        let (was, was_until) = (o.deadline, o.until);
        (o.deadline, o.until) = (deadline, until);
        if let Some(d) = was {
            st.timers.remove(&(d, id));
        }
        if let Some(n) = was_until {
            st.counts.remove(&(n, id));
        }
        if let Some(d) = deadline {
            st.timers.insert((d, id));
        }
        if let Some(n) = until {
            st.counts.insert((n, id));
        }
    }

    /// Fires the timeouts that are over; whether there were any.
    fn fire(&self, p: &mut LinuxProcess) -> bool {
        let mut any = false;
        loop {
            let now = frame::time::now();
            let counted = self.counted.load(Ordering::Acquire);
            loop {
                let w = {
                    let mut st = self.state.lock();
                    let Some(&(t, id)) = st.rechecks.first().filter(|r| r.0 <= now) else {
                        break;
                    };
                    st.rechecks.remove(&(t, id));
                    st.ops.get(&id).map(|o| Waiter {
                        tgid: o.owner.tgid,
                        id,
                    })
                };
                if let Some(w) = w {
                    self.hub.due(w);
                }
            }
            let due = {
                let mut st = self.state.lock();
                let by_count = st.counts.first().filter(|c| c.0 <= counted).map(|c| c.1);
                let by_time = st.timers.first().filter(|t| t.0 <= now).map(|t| t.1);
                let id = by_count.or(by_time);
                // (One that is being removed is off the list in a moment.)
                id.filter(|&id| st.claim(id))
                    .and_then(|id| st.ops.get(&id).map(|o| (id, o.sqe, by_count.is_some())))
            };
            let Some((id, sqe, by_count)) = due else {
                return any;
            };
            any = true;
            if sqe.opcode == abi::OP_LINK_TIMEOUT {
                self.limit_reached(id);
            } else if by_count {
                self.complete(id, Done::new(0, true));
            } else {
                let ok = sqe.op_flags & abi::TIMEOUT_ETIME_SUCCESS != 0;
                let last = Done::new(-ETIME, ok);
                if sqe.op_flags & abi::TIMEOUT_MULTISHOT == 0 {
                    self.complete(id, last);
                } else {
                    self.fire_again(p, id, &sqe, last);
                }
            }
        }
    }

    /// A multishot timeout that is over, and begins again.
    fn fire_again(&self, p: &mut LinuxProcess, id: u64, sqe: &Sqe, done: Done) {
        let shot = {
            let mut st = self.state.lock();
            let Some(o) = st.ops.get_mut(&id) else {
                return;
            };
            o.done += 1;
            o.done
        };
        // `off`: how many times (0: without end).
        let last = sqe.off != 0 && shot >= sqe.off;
        p.uring.kept = match self.state.lock().ops.get(&id) {
            Some(o) => o.kept.clone(),
            None => None,
        };
        let next = read_timeout(p, sqe.addr, sqe.op_flags);
        p.uring.kept = None;
        match next {
            Ok(t) if !last && self.post_more(id, done) => {
                self.set_timer(id, Some(t), None);
                self.unclaim(id);
            }
            _ => self.complete(id, done),
        }
    }

    /// A LINK_TIMEOUT is over: what it limits is cancelled.
    fn limit_reached(&self, id: u64) {
        let (target, claimed) = {
            let mut st = self.state.lock();
            let target = st.order.limited_by(id);
            (target, target.is_some_and(|t| st.claim(t)))
        };
        let res = if target.is_some() && !claimed {
            -EALREADY
        } else {
            -ETIME
        };
        // First, so that the end of what it limits does not cancel it.
        self.complete(id, Done::new(res, res == -ETIME));
        if let Some(t) = target.filter(|_| claimed) {
            self.complete(t, Done::err(ECANCELED));
        }
    }

    /// Gives a claimed SQE back to wait.
    fn unclaim(&self, id: u64) {
        let again = match self.state.lock().ops.get_mut(&id) {
            Some(o) => {
                o.phase = Phase::Armed;
                core::mem::take(&mut o.again).then_some(o.owner.tgid)
            }
            None => None,
        };
        if let Some(tgid) = again {
            self.hub.due(Waiter { tgid, id });
        }
    }

    /// Tries the process's armed SQEs whose objects have changed; whether
    /// one is complete.
    fn retry(&self, p: &mut LinuxProcess, me: &Owner) -> bool {
        let mut progress = false;
        for id in self.hub.take(me.tgid) {
            let look = match self.state.lock().ops.get_mut(&id) {
                Some(o) if o.phase == Phase::Armed => {
                    (!(o.begun && ops::is_timeout(o.sqe.opcode))).then(|| Look::at(o))
                }
                // Who tries it now tries it again.
                Some(o) => {
                    o.again = true;
                    None
                }
                None => None,
            };
            let Some(w) = look else {
                continue;
            };
            let fd = w.fd();
            // A program that is gone (`execve`) gets nothing.
            let over = !w.owner.is(me) || w.closed(fd.as_ref());
            if !over && w.begun && !w.due(fd.as_ref()) {
                w.watch_again(fd.as_ref());
                if !w.due(fd.as_ref()) {
                    continue;
                }
            }
            if !self.state.lock().claim(id) {
                continue;
            }
            if over {
                self.complete(id, Done::err(ECANCELED));
                progress = true;
            } else if !w.begun {
                self.start(p, id);
                progress = true;
            } else if self.attempt(p, id) {
                progress = true;
            } else {
                w.watch_again(fd.as_ref());
                let now = self.state.lock().ops.get(&id).map(Look::at);
                if now.is_some_and(|n| n.due(fd.as_ref()))
                    && let Some(o) = self.state.lock().ops.get_mut(&id)
                {
                    o.again = true;
                }
                self.unclaim(id);
            }
        }
        progress
    }

    /// `IORING_SETUP_DEFER_TASKRUN`: the program runs what can go on when
    /// it asks for completions; this tells it that something can.
    fn nudge(&self, me: &Owner) {
        let now = frame::time::now();
        let counted = self.counted.load(Ordering::Acquire);
        let mut can = {
            let st = self.state.lock();
            if st.pending {
                return;
            }
            st.timers.first().is_some_and(|t| t.0 <= now)
                || st.counts.first().is_some_and(|c| c.0 <= counted)
        };
        // (Not by its own eventfd, for what that made ready.)
        let mut aloud = can;
        if !can {
            for id in self.hub.peek(me.tgid) {
                let look = match self.state.lock().ops.get(&id) {
                    Some(o) if o.phase == Phase::Armed => {
                        (!(o.begun && ops::is_timeout(o.sqe.opcode))).then(|| Look::at(o))
                    }
                    _ => None,
                };
                let Some(w) = look else {
                    continue;
                };
                let fd = w.fd();
                if !w.begun || w.closed(fd.as_ref()) || w.due(fd.as_ref()) {
                    can = true;
                    if !matches!(&fd, Some(Fd::Object(o)) if o.obj.woken_by_ring()) {
                        aloud = true;
                        break;
                    }
                }
            }
        }
        if can {
            {
                let mut st = self.state.lock();
                st.pending = true;
                self.set_flags(&st);
            }
            self.hub.tell();
            self.watchers.notify();
            if aloud {
                self.signal(true);
            }
        }
    }

    /// Takes the armed SQEs `matches` picks, the first or all of them, to
    /// be cancelled (`end`); or says why there are none.
    fn cancel(&self, all: bool, matches: impl Fn(&Op) -> bool) -> Cancelling {
        let mut ids = Vec::new();
        let mut busy = false;
        for _ in 0..1000 {
            busy = false;
            for (&id, o) in &mut self.state.lock().ops {
                if !matches(o) {
                    continue;
                }
                match o.phase {
                    Phase::Armed => {
                        o.phase = Phase::Cancelled;
                        ids.push(id);
                        if !all {
                            break;
                        }
                    }
                    Phase::Claimed => busy |= o.waited,
                    Phase::Queued | Phase::Cancelled => {}
                }
            }
            // Another thread is trying it, which does not take long.
            if !busy || (!all && !ids.is_empty()) {
                break;
            }
            frame::task::yield_now();
        }
        let result = match ids.len() as u64 {
            0 if busy => Err(EALREADY),
            0 => Err(ENOENT),
            n if all => Ok(n),
            _ => Ok(0),
        };
        Cancelling { ids, result }
    }

    /// Completes what was taken to be cancelled.
    fn end(&self, ids: Vec<u64>) {
        for id in ids {
            self.complete(id, Done::err(ECANCELED));
        }
    }

    /// Cancels what `user_data`, `fd` and `flags` (of ASYNC_CANCEL) name.
    fn cancel_matching(&self, p: &LinuxProcess, user_data: u64, fd: i32, flags: u32) -> Cancelling {
        let any = flags & abi::ASYNC_CANCEL_ANY != 0;
        let all = any || flags & abi::ASYNC_CANCEL_ALL != 0;
        let mut file = None;
        if flags & abi::ASYNC_CANCEL_FD != 0 {
            file = if flags & abi::ASYNC_CANCEL_FD_FIXED != 0 {
                self.tables.lock().files.get(fd as u32)
            } else {
                p.desc(u64::from(fd as u32))
            };
            if file.is_none() {
                return Cancelling::from(Err(EBADF));
            }
        }
        self.cancel(all, |o| match &file {
            _ if any => true,
            Some(d) => o.file.as_ref().is_some_and(|f| f.is(d)),
            None => o.sqe.user_data == user_data,
        })
    }

    fn cancel_request(&self, p: &LinuxProcess, s: &Sqe) -> Cancelling {
        let fixed = s.flags & abi::SQE_FIXED_FILE != 0;
        let flags = s.op_flags | if fixed { abi::ASYNC_CANCEL_FD_FIXED } else { 0 };
        let mut c = self.cancel_matching(p, s.addr, s.fd, flags);
        if c.result == Err(ENOENT)
            && s.op_flags & (abi::ASYNC_CANCEL_ALL | abi::ASYNC_CANCEL_ANY) != 0
        {
            c.result = Ok(0);
        }
        c
    }

    /// TIMEOUT_REMOVE, which may change one instead.
    fn remove_timeout(&self, p: &mut LinuxProcess, s: &Sqe) -> Cancelling {
        if s.op_flags & abi::TIMEOUT_UPDATE == 0 {
            return self.cancel(false, |o| {
                o.sqe.opcode == abi::OP_TIMEOUT && o.sqe.user_data == s.addr
            });
        }
        Cancelling::from(self.update_timeout(p, s))
    }

    fn update_timeout(&self, p: &mut LinuxProcess, s: &Sqe) -> Result<u64, i64> {
        let deadline = read_timeout(p, s.off, s.op_flags)?;
        let opcode = if s.op_flags & abi::LINK_TIMEOUT_UPDATE != 0 {
            abi::OP_LINK_TIMEOUT
        } else {
            abi::OP_TIMEOUT
        };
        let found = {
            let st = self.state.lock();
            st.ops
                .iter()
                .find(|(_, o)| {
                    o.sqe.opcode == opcode && o.sqe.user_data == s.addr && o.phase == Phase::Armed
                })
                .map(|(&id, _)| id)
        };
        self.set_timer(found.ok_or(ENOENT)?, Some(deadline), None);
        self.hub.tell();
        Ok(0)
    }

    /// POLL_REMOVE, which may change one instead.
    fn remove_poll(&self, s: &Sqe) -> Cancelling {
        if s.len & (abi::POLL_UPDATE_EVENTS | abi::POLL_UPDATE_USER_DATA) == 0 {
            return self.cancel(false, |o| {
                o.sqe.opcode == abi::OP_POLL_ADD && o.sqe.user_data == s.addr
            });
        }
        Cancelling::from(self.update_poll(s))
    }

    fn update_poll(&self, s: &Sqe) -> Result<u64, i64> {
        {
            let mut st = self.state.lock();
            let op = st
                .ops
                .values_mut()
                .find(|o| {
                    o.sqe.opcode == abi::OP_POLL_ADD
                        && o.sqe.user_data == s.addr
                        && o.phase == Phase::Armed
                })
                .ok_or(ENOENT)?;
            if s.len & abi::POLL_UPDATE_EVENTS != 0 {
                op.sqe.op_flags = s.op_flags;
                op.sqe.len = s.len & abi::POLL_ADD_MULTI;
            }
            if s.len & abi::POLL_UPDATE_USER_DATA != 0 {
                op.sqe.user_data = s.off;
            }
            op.seen = None;
        }
        self.hub.tell();
        Ok(0)
    }

    /// When something happens by itself.
    fn next(&self) -> Option<Duration> {
        let st = self.state.lock();
        let timer = st.timers.first().map(|t| t.0);
        let recheck = st.rechecks.first().map(|t| t.0);
        match (timer, recheck) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Starts the process's worker the first time an SQE of it is armed: a
    /// helper thread of the process that runs armed SQEs as they become
    /// ready, so they complete even while no thread is in
    /// `io_uring_enter` (a program may wait on the ring descriptor with
    /// epoll, or on a registered eventfd).
    fn start_worker(&self, p: &LinuxProcess) {
        let tgid = p.group.tgid;
        {
            let mut st = self.state.lock();
            if st.workers.contains(&tgid) {
                return;
            }
            let armed = st
                .ops
                .values()
                .any(|o| o.phase != Phase::Queued && o.owner.tgid == tgid);
            if !armed {
                return;
            }
            st.workers.push(tgid);
        }
        {
            let mut rings = p.group.rings.lock();
            rings.retain(|r| r.strong_count() > 0 && !r.ptr_eq(&self.me));
            rings.push(self.me.clone());
        }
        let me = self.me.clone();
        let hub = self.hub.clone();
        let started = p
            .helper()
            .is_some_and(|h| crate::proc::start_helper(h, move |p| worker(&me, &hub, p)));
        if !started {
            self.state.lock().workers.retain(|&w| w != tgid);
        }
    }
}

/// How long an SQE that could not go on, though its object is ready, waits
/// for that to change before it is tried again anyway.
const RETRY: Duration = Duration::from_millis(5);

/// How often the worker re-checks that it should still run (it is woken
/// for that too: `Group::wake_rings`).
const WORKER_RECHECK: Duration = Duration::from_millis(100);

/// A process's worker for a ring: runs its armed SQEs as their objects
/// change, and timeouts (or tells the program to, which asked for that). It
/// ends when the ring closes, the process has no threads left (what it had
/// in flight is cancelled, but for timeouts), or it is killed.
fn worker(me: &Weak<Ring>, hub: &Hub, p: &mut LinuxProcess) {
    let tgid = p.group.tgid;
    let mut owner = Owner::of(p);
    loop {
        let told = hub.told();
        let Some(ring) = me.upgrade() else {
            return;
        };
        if p.group.threads().is_empty() || crate::proc::interrupted(&p.entry) {
            let now = Owner::of(p);
            let c = ring.cancel(true, |o| {
                o.owner.tgid == tgid && !(ops::is_timeout(o.sqe.opcode) && o.owner.is(&now))
            });
            ring.end(c.ids);
            ring.state.lock().workers.retain(|&w| w != tgid);
            return;
        }
        let now = Owner::of(p);
        if !now.is(&owner) {
            // Another program (`execve`): the last one's are over.
            let c = ring.cancel(true, |o| o.owner.tgid == tgid && !o.owner.is(&now));
            ring.end(c.ids);
            owner = now;
        }
        let recheck = frame::time::now() + WORKER_RECHECK;
        let mut until = recheck;
        if ring.layout.has(abi::SETUP_DEFER_TASKRUN) {
            ring.nudge(&owner);
            if !ring.state.lock().pending
                && let Some(n) = ring.next()
            {
                until = n.min(recheck);
            }
        } else {
            ring.run(p, true);
            if let Some(n) = ring.next() {
                until = n.min(recheck);
            }
        }
        // Asleep, it does not keep the ring.
        drop(ring);
        hub.wait(&p.entry, told, Some(until));
    }
}

/// Runs what can go on in the process's rings, if an object has changed:
/// between a system call and the program, so that it finds what its own
/// call made ready.
pub(crate) fn task_work(p: &mut LinuxProcess) {
    if !p.group.ring_due.load(Ordering::Acquire) {
        return;
    }
    p.group.ring_due.store(false, Ordering::Release);
    let rings: Vec<Arc<Ring>> = {
        let rings = p.group.rings.lock();
        rings.iter().filter_map(Weak::upgrade).collect()
    };
    for r in rings {
        if r.layout.has(abi::SETUP_DEFER_TASKRUN) {
            r.nudge(&Owner::of(p));
        } else {
            r.run(p, true);
        }
    }
}

/// A timeout's deadline.
fn read_timeout(p: &mut LinuxProcess, at: u64, flags: u32) -> Result<Duration, i64> {
    let t = poll::read_timespec(p, at)?;
    let now = frame::time::now();
    Ok(if flags & abi::TIMEOUT_ABS == 0 {
        now.saturating_add(t)
    } else if flags & abi::TIMEOUT_REALTIME != 0 {
        now.saturating_add(t.saturating_sub(crate::vfs::wall_clock()))
    } else {
        t
    })
}

fn ring_of(p: &LinuxProcess, fd: u64) -> Result<Arc<dyn Object>, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Object(o) if o.obj.uring().is_some() => Ok(o.obj),
        _ => Err(EOPNOTSUPP),
    }
}

/// A ring by its place among the thread's registered ones.
fn registered_ring(p: &LinuxProcess, n: u64) -> Result<Arc<dyn Object>, i64> {
    let n = usize::try_from(n).map_err(|_| EINVAL)?;
    if n >= tables::RING_FDS {
        return Err(EINVAL);
    }
    p.uring.rings.get(n).cloned().flatten().ok_or(EBADF)
}

/// `io_uring_setup(entries, params)`.
pub(super) fn setup(p: &mut LinuxProcess, entries: u64, params: u64) -> Result<u64, i64> {
    let mut b = [0u8; 120];
    if p.copy_from_user(params, &mut b) != b.len() {
        return Err(EFAULT);
    }
    let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    if (28..40).any(|at| b[at] != 0) {
        return Err(EINVAL); // resv
    }
    let entries = u32::try_from(entries).map_err(|_| EINVAL)?;
    let layout = ::uring::setup(entries, word(8), word(4))?;
    // A ring to share workers or a poller with: here each has its own, and
    // the poller never runs.
    if layout.has(abi::SETUP_ATTACH_WQ) {
        match p.fd(u64::from(word(24))) {
            None => return Err(ENXIO),
            Some(Fd::Object(o)) if o.obj.uring().is_some() => {}
            Some(_) => return Err(EINVAL),
        }
    }
    if layout.has(abi::SETUP_SQ_AFF) && word(12) as usize >= frame::cpu::online_count() {
        return Err(EINVAL);
    }
    let account = p.cell.account().clone();
    let rings = Mem::alloc(&account, layout.ring_bytes).ok_or(ENOMEM)?;
    let sqes = Mem::alloc(&account, layout.sqes_bytes).ok_or(ENOMEM)?;
    for (off, v) in layout.constants() {
        rings.set(off, v);
    }
    if layout.has(abi::SETUP_SQPOLL) {
        rings.set(layout.sq.flags, abi::SQ_NEED_WAKEUP);
    }
    let paid = Reserved::new(&account, 1).ok_or(ENOMEM)?;
    let tables = tables::Tables::new(&account).ok_or(ENOMEM)?;
    let enabled = !layout.has(abi::SETUP_R_DISABLED);
    let single = layout.has(abi::SETUP_SINGLE_ISSUER) && enabled;
    let issuer = if single { p.entry.pid } else { 0 };
    let params_back = layout.params();
    let ring = Arc::new_cyclic(|me| Ring {
        layout,
        rings,
        sqes,
        account,
        submitting: Mutex::new(()),
        picking: Mutex::new(()),
        state: SpinLock::new(State {
            order: Order::default(),
            ops: BTreeMap::new(),
            overflow: BTreeMap::new(),
            next_overflow: 0,
            assembling: false,
            timers: BTreeSet::new(),
            counts: BTreeSet::new(),
            rechecks: BTreeSet::new(),
            pending: false,
            workers: Vec::new(),
            kept: 0,
            generation: 0,
            uses: BTreeMap::new(),
            tags: BTreeMap::new(),
            paid,
        }),
        tables: SpinLock::new(tables),
        watchers: Watchers::new(),
        hub: Arc::new(Hub::new()),
        notify: SpinLock::new(None),
        posted: AtomicU64::new(0),
        counted: AtomicU64::new(0),
        enabled: AtomicBool::new(enabled),
        issuer: AtomicU64::new(issuer),
        limits: SpinLock::new(None),
        max_workers: SpinLock::new([4 * frame::cpu::online_count() as u32, 1024]),
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
    if p.copy_to_user(params, &params_back) != 120 {
        p.close(fd);
        return Err(EFAULT);
    }
    Ok(fd)
}

/// `mmap` of a ring descriptor: the rings, the SQE array, or a group of
/// provided buffers.
pub(super) fn mmap(p: &mut LinuxProcess, ring: &Ring, a: &[u64; 6]) -> Result<u64, i64> {
    let (addr, len, prot, flags, offset) = (a[0], a[1], a[2], a[3], a[5]);
    let pages: Vec<Page> = match offset & abi::OFF_MMAP_MASK {
        abi::OFF_SQ_RING | abi::OFF_CQ_RING => ring.rings.0.clone(),
        abi::OFF_SQES => ring.sqes.0.clone(),
        abi::OFF_PBUF_RING => {
            let group = (offset & !abi::OFF_MMAP_MASK) >> abi::OFF_PBUF_SHIFT;
            ring.tables
                .lock()
                .buffer_pages(group as u16)
                .ok_or(EINVAL)?
        }
        _ => return Err(EINVAL),
    };
    let n = len.div_ceil(PAGE_SIZE) as usize;
    if len == 0 || n > pages.len() {
        return Err(EINVAL);
    }
    p.mm().map_pages(addr, &pages[..n], prot, flags)
}

/// `io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz)`.
pub(super) fn enter(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let (to_submit, min_complete, flags) = (a[1] as u32, a[2] as u32, a[3] as u32);
    let accepted = abi::ENTER_GETEVENTS
        | abi::ENTER_SQ_WAKEUP
        | abi::ENTER_SQ_WAIT
        | abi::ENTER_EXT_ARG
        | abi::ENTER_REGISTERED_RING;
    if flags & !accepted != 0 {
        return Err(EINVAL);
    }
    let obj = if flags & abi::ENTER_REGISTERED_RING != 0 {
        registered_ring(p, a[0])?
    } else {
        ring_of(p, a[0])?
    };
    let ring = obj.uring().ok_or(EOPNOTSUPP)?;
    if !ring.enabled.load(Ordering::Acquire) {
        return Err(EBADFD);
    }
    let issuer = ring.issuer.load(Ordering::Acquire);
    let other = issuer != 0 && issuer != p.entry.pid;
    let l = &ring.layout;
    let mut submitted = 0;
    if l.has(abi::SETUP_SQPOLL) {
        // The poller that sleeps until it is woken: it takes everything.
        if flags & abi::ENTER_SQ_WAKEUP != 0 || to_submit != 0 {
            while ring.queued() != 0 && ring.submit(p, u32::MAX)? != 0 {}
        }
        submitted = u64::from(to_submit);
    } else if to_submit != 0 {
        if other {
            return Err(EEXIST);
        }
        submitted = u64::from(ring.submit(p, to_submit)?);
    }
    let mut st = ring.state.lock();
    ring.flush_overflow(&mut st);
    drop(st);
    let defer = l.has(abi::SETUP_DEFER_TASKRUN);
    ring.run(p, !defer);
    if flags & abi::ENTER_GETEVENTS == 0 || submitted != u64::from(to_submit) {
        return Ok(submitted);
    }
    if other && defer {
        return Err(EEXIST);
    }
    let r = wait(p, ring, min_complete.min(l.cq_entries), flags, a[4], a[5]);
    match r {
        Ok(()) => Ok(submitted),
        Err(_) if submitted > 0 => Ok(submitted),
        Err(e) => Err(e),
    }
}

/// Waits until the CQ holds `min` entries.
fn wait(
    p: &mut LinuxProcess,
    ring: &Ring,
    min: u32,
    flags: u32,
    arg: u64,
    size: u64,
) -> Result<(), i64> {
    // EXT_ARG: `struct io_uring_getevents_arg { sigmask, sigmask_sz, pad,
    // ts }`; else `arg` is the signal mask.
    let (mut mask, mut mask_size, mut deadline) = (arg, size, None);
    if flags & abi::ENTER_EXT_ARG != 0 {
        let mut b = [0u8; 24];
        if size != 24 {
            return Err(EINVAL);
        }
        if p.copy_from_user(arg, &mut b) != b.len() {
            return Err(EFAULT);
        }
        let u = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
        mask = u(0);
        mask_size = u(8) & 0xffff_ffff;
        if u(8) >> 32 != 0 {
            return Err(EINVAL);
        }
        if u(16) != 0 {
            let t = poll::read_timespec(p, u(16))?;
            deadline = Some(frame::time::now().saturating_add(t));
        }
    }
    crate::signal::begin_wait_mask(p, mask, mask_size)?;
    let entry = p.entry.clone();
    let timeouts = ring.timeouts();
    let r = loop {
        let told = ring.hub.told();
        ring.run(p, true);
        {
            let mut st = ring.state.lock();
            ring.flush_overflow(&mut st);
        }
        // (A timeout's end ends any wait.)
        if ring.cq_ready() >= min || ring.timeouts() != timeouts {
            break Ok(0);
        }
        if deadline.is_some_and(|d| frame::time::now() >= d) {
            break Err(ETIME);
        }
        let until = match (deadline, ring.next()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if !ring.hub.wait(&entry, told, until) {
            break Err(EINTR);
        }
    };
    crate::signal::end_wait_mask(p, &r);
    r.map(|_| ())
}
