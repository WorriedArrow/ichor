//! Linux processes as kernel tasks: the process table (pids, parents, exit
//! statuses), `wait4`, and the loop that runs a process in ring 3.
//!
//! Every process runs on its own kernel task, which `fork` spawns. A
//! process that exits stays in the table as a zombie holding its wait
//! status until its parent reaps it. When a parent exits, its children are
//! orphaned (parent 0) and reaped by the kernel as they exit. A per-cell
//! init and pid namespaces arrive with multi-cell scheduling (milestone 4);
//! pids are global for now.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use frame::println;
use frame::sync::SpinLock;
use frame::task::{Task, TaskOptions, WaitQueue};
use frame::user::{UserContext, UserEvent, UserMode};

use crate::linuxabi::{self, Outcome};
use crate::page::Reserved;
use crate::process::{Group, LinuxProcess};
use crate::sched::SchedInfo;
use crate::signal::{self, Info};

const ECHILD: i64 = 10;
const EAGAIN: i64 = 11;

/// Signals raised by CPU exceptions.
const SIGILL: u32 = 4;
const SIGTRAP: u32 = 5;
const SIGFPE: u32 = 8;
/// A page fault's error code: a protection key denied the access.
const PF_PK: u64 = 1 << 5;
const ESRCH: i64 = 3;
const EINTR: i64 = 4;

/// `siginfo_t` codes for `SIGCHLD`.
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;

/// Signals posted but not yet taken, and what each carries. Standard
/// signals are pending once; real-time ones queue.
#[derive(Debug)]
struct Pending {
    /// Which are pending (a summary of `queue`, readable without its lock).
    set: AtomicU64,
    queue: SpinLock<VecDeque<(u32, Info)>>,
}

impl Default for Pending {
    fn default() -> Pending {
        Pending {
            set: AtomicU64::new(0),
            queue: SpinLock::new(VecDeque::new()),
        }
    }
}

/// Most signals queued at once (Linux's `RLIMIT_SIGPENDING` plays this
/// part); past it a real-time signal is refused.
const QUEUE_MAX: usize = 4096;

impl Pending {
    fn set(&self) -> u64 {
        self.set.load(Ordering::SeqCst)
    }

    /// Queues `sig`; false if there are too many.
    fn add(&self, sig: u32, info: Info) -> bool {
        const FIRST_REALTIME: u32 = 32;
        let mut q = self.queue.lock();
        if sig < FIRST_REALTIME && self.set() & signal::bit(sig) != 0 {
            return true;
        }
        if q.len() >= QUEUE_MAX && sig >= FIRST_REALTIME {
            return false;
        }
        q.push_back((sig, info));
        self.set.fetch_or(signal::bit(sig), Ordering::SeqCst);
        true
    }

    /// Takes the lowest-numbered signal of `wanted` (the first of its kind).
    fn take(&self, wanted: u64) -> Option<(u32, Info)> {
        if self.set() & wanted == 0 {
            return None;
        }
        let mut q = self.queue.lock();
        let sig = (self.set() & wanted).trailing_zeros() + 1;
        let at = q.iter().position(|&(s, _)| s == sig)?;
        let (_, info) = q.remove(at)?;
        if !q.iter().any(|&(s, _)| s == sig) {
            self.set.fetch_and(!signal::bit(sig), Ordering::SeqCst);
        }
        Some((sig, info))
    }

    /// Discards every pending signal of `which`.
    fn clear(&self, which: u64) {
        if self.set() & which == 0 {
            return;
        }
        let mut q = self.queue.lock();
        q.retain(|&(s, _)| signal::bit(s) & which == 0);
        self.set.fetch_and(!which, Ordering::SeqCst);
    }
}

/// Job control: whether a process is stopped, and what its parent has not
/// been told of yet.
#[derive(Debug, Default)]
struct Stop {
    /// The signal that stopped it, until it goes on.
    by: Option<u32>,
    /// Counts `SIGCONT`s, so that one sent between taking a stop signal and
    /// stopping is not lost.
    continues: u64,
    /// Threads that have stopped.
    parked: usize,
    /// All of them have, and the parent was told.
    complete: bool,
    /// What `wait4(WUNTRACED)` and `waitid(WSTOPPED)` have to report.
    stopped: Option<u32>,
    /// What `wait4(WCONTINUED)` has to report.
    continued: bool,
}

/// What a process's threads share of its signals.
#[derive(Debug)]
pub(crate) struct Shared {
    /// Signals sent to the process: the first thread that does not block
    /// one takes it.
    pending: Pending,
    stop: SpinLock<Stop>,
    /// `stop.by` is set (readable without the lock).
    stopping: AtomicBool,
    /// `SA_NOCLDSTOP` and `SA_NOCLDWAIT` (or an ignored `SIGCHLD`), as this
    /// process's children need to know.
    pub(crate) nocldstop: AtomicBool,
    pub(crate) nocldwait: AtomicBool,
    /// Polled through pidfds: changes when the process exits.
    pub(crate) exit: crate::poll::Watchers,
    /// Polled through signal descriptors: changes as signals are posted to
    /// the process or its threads, which `posted` counts.
    pub(crate) arrivals: crate::poll::Watchers,
    pub(crate) posted: AtomicU64,
    /// The process's CPU time (ns) at which one of its CPU-time timers may
    /// be due (`itimer`).
    pub(crate) cpu_due: AtomicU64,
}

impl Default for Shared {
    fn default() -> Shared {
        Shared {
            pending: Pending::default(),
            stop: SpinLock::new(Stop::default()),
            stopping: AtomicBool::new(false),
            nocldstop: AtomicBool::new(false),
            nocldwait: AtomicBool::new(false),
            exit: crate::poll::Watchers::new(),
            arrivals: crate::poll::Watchers::new(),
            posted: AtomicU64::new(0),
            cpu_due: AtomicU64::new(u64::MAX),
        }
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        crate::itimer::set_due(&self.cpu_due, u64::MAX);
    }
}

/// A process's entry in the table.
#[derive(Debug)]
pub(crate) struct ProcEntry {
    /// The thread id (for a process's first thread, also its pid).
    pub(crate) pid: u64,
    /// The thread group (process) this thread belongs to.
    pub(crate) tgid: u64,
    /// The cell the process runs in: signals and process-group operations
    /// never cross it.
    pub(crate) cell: u64,
    ppid: AtomicU64,
    /// Process group and session (meaningful on a process's first entry).
    pgid: AtomicU64,
    sid: AtomicU64,
    /// The process's real and saved uids (`ruid | suid << 32`), which
    /// `kill` checks senders against (ADR-0009 §4).
    uids: AtomicU64,
    /// `PR_SET_PDEATHSIG`: posted to this process when its parent exits.
    pub(crate) pdeathsig: core::sync::atomic::AtomicU32,
    /// When the thread was created, in clock ticks (`USER_HZ`, 100/s) since
    /// boot (`/proc/<pid>/stat` starttime).
    pub(crate) started: u64,
    /// The wait status once the process has exited.
    status: SpinLock<Option<u32>>,
    /// Woken whenever one of this process's children exits.
    children: WaitQueue,
    /// Signals sent to this thread and not yet taken.
    pending: Pending,
    /// What it shares with its process's other threads.
    pub(crate) shared: Arc<Shared>,
    /// The thread must end (its process is exiting, or another thread is
    /// in `execve`), without ending the process.
    ending: AtomicBool,
    /// The thread's signal mask and its process's ignored set, mirrored
    /// from its `Signals` so other tasks can decide whether a signal wakes
    /// it.
    blocked: AtomicU64,
    ignored: AtomicU64,
    /// The signals `rt_sigtimedwait` is waiting for.
    awaited: AtomicU64,
    /// The task running the process, to wake it for a signal.
    task: SpinLock<Option<Arc<Task>>>,
    /// Woken when a signal is posted (`pause`, `rt_sigsuspend`).
    signals: WaitQueue,
    /// The process, for a first entry (`/proc/<pid>`).
    process: SpinLock<Weak<Group>>,
    /// Its task's CPU time when the task began running the thread (ns).
    cpu_base: AtomicU64,
    /// The thread's CPU time once it no longer runs (ns).
    cpu_done: AtomicU64,
    /// What the entry costs the cell, until it is reaped.
    _kept: Reserved,
}

impl ProcEntry {
    /// The thread's CPU time in nanoseconds, user and system time together:
    /// its task's time on a CPU since it began running the thread
    /// (ADR-0021).
    pub(crate) fn cpu_ns(&self) -> u64 {
        match &*self.task.lock() {
            Some(t) => {
                let ns = u64::try_from(t.cpu_time().as_nanos()).unwrap_or(u64::MAX);
                ns.saturating_sub(self.cpu_base.load(Ordering::Relaxed))
            }
            None => self.cpu_done.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn ppid(&self) -> u64 {
        self.ppid.load(Ordering::Acquire)
    }

    /// The real and saved uids (see `uids`).
    pub(crate) fn uids(&self) -> (u32, u32) {
        let v = self.uids.load(Ordering::Acquire);
        (v as u32, (v >> 32) as u32)
    }

    /// The process it is the first entry of, while that has threads.
    pub(crate) fn process(&self) -> Option<Arc<Group>> {
        self.process.lock().upgrade()
    }

    pub(crate) fn set_group(&self, g: &Arc<Group>) {
        *self.process.lock() = Arc::downgrade(g);
    }

    /// Whether its thread is running or about to, or else waiting.
    pub(crate) fn runnable(&self) -> bool {
        let task = self.task.lock().clone();
        task.is_some_and(|t| t.state() == frame::task::TaskState::Runnable)
    }

    pub(crate) fn set_uids(&self, ruid: u32, suid: u32) {
        self.uids
            .store(u64::from(ruid) | (u64::from(suid) << 32), Ordering::Release);
    }

    /// The process group and session.
    pub(crate) fn group(&self) -> (u64, u64) {
        (
            self.pgid.load(Ordering::Acquire),
            self.sid.load(Ordering::Acquire),
        )
    }
}

/// `cell`'s live threads and processes, and the last pid handed out (for
/// `/proc/loadavg` and `/proc/stat`).
pub(crate) fn census(cell: u64) -> (usize, usize, u64) {
    let t = TABLE.lock();
    let live = t
        .values()
        .filter(|e| e.cell == cell && e.status.lock().is_none());
    let (mut threads, mut procs) = (0, 0);
    for e in live {
        threads += 1;
        if e.pid == e.tgid {
            procs += 1;
        }
    }
    (threads, procs, NEXT_PID.load(Ordering::Relaxed) - 1)
}

/// The pids of `cell`'s processes, zombies included, ascending.
pub(crate) fn pids(cell: u64) -> alloc::vec::Vec<u64> {
    TABLE
        .lock()
        .values()
        .filter(|e| e.cell == cell && e.pid == e.tgid)
        .map(|e| e.pid)
        .collect()
}

/// A process's first entry (which carries its group, session and status),
/// if `pid` is a live process in `cell`.
fn process(cell: u64, pid: u64) -> Option<Arc<ProcEntry>> {
    let t = TABLE.lock();
    let e = t.get(&pid)?;
    (e.cell == cell && e.pid == e.tgid).then(|| e.clone())
}

/// `getpgid` / `getsid` for `pid` (0: `me`).
pub(crate) fn group_of(me: &ProcEntry, pid: u64) -> Result<(u64, u64), i64> {
    if pid == 0 {
        return Ok(me.group());
    }
    process(me.cell, pid).map(|e| e.group()).ok_or(ESRCH)
}

/// `setpgid(pid, pgid)` by process `me` (its first entry), with POSIX's
/// rules: the target is `me` or a child of `me` in `me`'s session, not a
/// session leader, and `pgid` is the target's own pid or an existing group
/// of that session.
pub(crate) fn setpgid(me: &ProcEntry, pid: u64, pgid: u64) -> Result<(), i64> {
    const EPERM: i64 = 1;
    let pid = if pid == 0 { me.pid } else { pid };
    let pgid = if pgid == 0 { pid } else { pgid };
    let target = process(me.cell, pid).ok_or(ESRCH)?;
    if target.pid != me.pid && target.ppid() != me.pid {
        return Err(ESRCH);
    }
    let (_, sid) = target.group();
    if sid != me.group().1 {
        return Err(EPERM);
    }
    if sid == target.pid {
        return Err(EPERM); // a session leader cannot move
    }
    if pgid != target.pid {
        let t = TABLE.lock();
        let exists = t
            .values()
            .any(|e| e.cell == me.cell && e.pid == e.tgid && e.group() == (pgid, sid));
        if !exists {
            return Err(EPERM);
        }
    }
    target.pgid.store(pgid, Ordering::Release);
    Ok(())
}

/// `setsid` by process `me`: a new session and group led by it, unless it
/// already leads a group.
pub(crate) fn setsid(me: &ProcEntry) -> Result<u64, i64> {
    if me.group().0 == me.pid {
        return Err(1); // EPERM
    }
    me.sid.store(me.pid, Ordering::Release);
    me.pgid.store(me.pid, Ordering::Release);
    Ok(me.pid)
}

/// `kill(0)`, `kill(-pgid)`, `kill(-1)`: posts `sig` to every process of
/// the group (or, for `pgid` `None`, every process in the cell except
/// `me`). ESRCH if there was none.
pub(crate) fn send_group(
    me: &ProcEntry,
    pgid: Option<u64>,
    sig: u32,
    info: Info,
    allowed: &dyn Fn((u32, u32)) -> bool,
) -> Result<(), i64> {
    const EPERM: i64 = 1;
    let targets: alloc::vec::Vec<(u64, (u32, u32))> = {
        let t = TABLE.lock();
        t.values()
            .filter(|e| e.cell == me.cell && e.pid == e.tgid && e.status.lock().is_none())
            .filter(|e| match pgid {
                Some(g) => e.group().0 == g,
                None => e.tgid != me.tgid,
            })
            .map(|e| (e.pid, e.uids()))
            .collect()
    };
    if targets.is_empty() {
        return Err(ESRCH);
    }
    let mut any = false;
    for (pid, uids) in targets {
        if allowed(uids) {
            any = true;
            let _ = send_info(me.cell, pid, sig, info);
        }
    }
    if any { Ok(()) } else { Err(EPERM) }
}

/// Posts `sig` to every live process of `cell` (the control plane's
/// `Signal` and `Destroy`); returns how many.
pub(crate) fn signal_cell(cell: u64, sig: u32) -> u64 {
    let pids: alloc::vec::Vec<u64> = TABLE
        .lock()
        .values()
        .filter(|e| e.cell == cell && e.pid == e.tgid && e.status.lock().is_none())
        .map(|e| e.pid)
        .collect();
    let n = pids.len() as u64;
    for pid in pids {
        let _ = send(cell, pid, sig);
    }
    n
}

/// Posts `sig` to every live process of group `pgid` in `cell`: what a
/// terminal sends (INTR, hangup, window change), with no sender to check.
pub(crate) fn signal_pgrp(cell: u64, pgid: u64, sig: u32) {
    let pids: alloc::vec::Vec<u64> = TABLE
        .lock()
        .values()
        .filter(|e| e.cell == cell && e.pid == e.tgid && e.status.lock().is_none())
        .filter(|e| e.group().0 == pgid)
        .map(|e| e.pid)
        .collect();
    for pid in pids {
        let _ = send(cell, pid, sig);
    }
}

/// Whether a live process of `cell` is in group `pgid` of session `sid`.
pub(crate) fn pgrp_in_session(cell: u64, pgid: u64, sid: u64) -> bool {
    TABLE.lock().values().any(|e| {
        e.cell == cell && e.pid == e.tgid && e.status.lock().is_none() && e.group() == (pgid, sid)
    })
}

/// The real and saved uids of process `pid` in `cell`, if it is live.
pub(crate) fn uids_of(cell: u64, pid: u64) -> Result<(u32, u32), i64> {
    let t = TABLE.lock();
    let e = t.get(&pid).filter(|e| e.cell == cell).ok_or(ESRCH)?;
    let leader = t.get(&e.tgid).unwrap_or(e);
    Ok(leader.uids())
}

static TABLE: SpinLock<BTreeMap<u64, Arc<ProcEntry>>> = SpinLock::new(BTreeMap::new());
static NEXT_PID: AtomicU64 = AtomicU64::new(1);

/// Adds a thread of cell `cell` with parent process `ppid` (0: none) to
/// the table, as a new process (`tgid` `None`) or a thread of process
/// `tgid`, which shares the process's signals if it is given them (a kernel
/// helper is not). A new process starts in `group` = (pgid, sid), or in a
/// group and session of its own. `kept` is what the entry costs the cell.
pub(crate) fn register(
    cell: u64,
    ppid: u64,
    tgid: Option<u64>,
    group: Option<(u64, u64)>,
    shared: Option<Arc<Shared>>,
    kept: Reserved,
) -> Arc<ProcEntry> {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let (pgid, sid) = group.unwrap_or((pid, pid));
    let e = Arc::new(ProcEntry {
        pid,
        tgid: tgid.unwrap_or(pid),
        cell,
        ppid: AtomicU64::new(ppid),
        pgid: AtomicU64::new(pgid),
        sid: AtomicU64::new(sid),
        uids: AtomicU64::new(0),
        pdeathsig: core::sync::atomic::AtomicU32::new(0),
        started: (frame::time::now().as_millis() / 10) as u64,
        status: SpinLock::new(None),
        children: WaitQueue::new(),
        pending: Pending::default(),
        shared: shared.unwrap_or_default(),
        ending: AtomicBool::new(false),
        blocked: AtomicU64::new(0),
        ignored: AtomicU64::new(signal::bit(signal::SIGCHLD)),
        awaited: AtomicU64::new(0),
        task: SpinLock::new(None),
        signals: WaitQueue::new(),
        process: SpinLock::new(Weak::new()),
        cpu_base: AtomicU64::new(0),
        cpu_done: AtomicU64::new(0),
        _kept: kept,
    });
    TABLE.lock().insert(pid, e.clone());
    e
}

/// Publishes a process's signal mask and ignored set (see `signal::sync`).
pub(crate) fn set_masks(e: &ProcEntry, blocked: u64, ignored: u64) {
    e.blocked.store(blocked, Ordering::SeqCst);
    e.ignored.store(ignored, Ordering::SeqCst);
}

/// `e`'s signal mask as last published.
pub(crate) fn blocked(e: &ProcEntry) -> u64 {
    e.blocked.load(Ordering::SeqCst)
}

/// Signals pending for thread `e` or its process.
pub(crate) fn pending(e: &ProcEntry) -> u64 {
    e.pending.set() | e.shared.pending.set()
}

/// Takes a pending signal of `wanted`: the thread's own first, then its
/// process's.
pub(crate) fn take_signal(e: &ProcEntry, wanted: u64) -> Option<(u32, Info)> {
    e.pending
        .take(wanted)
        .or_else(|| e.shared.pending.take(wanted))
}

/// Discards pending signals of `set`, the thread's and its process's.
pub(crate) fn clear_pending(e: &ProcEntry, set: u64) {
    e.pending.clear(set);
    e.shared.pending.clear(set);
}

/// Whether thread `e` was told to end ([`end_thread`]).
pub(crate) fn ending(e: &ProcEntry) -> bool {
    e.ending.load(Ordering::SeqCst)
}

/// Marks thread `e` as to end, without ending its process: the process is
/// exiting already, or another of its threads is in `execve`. Wake it
/// ([`wake`]) unless it is the caller's.
pub(crate) fn end_thread(e: &ProcEntry) {
    e.ending.store(true, Ordering::SeqCst);
}

/// Whether `e` must stop what it is doing and end.
pub(crate) fn dying(e: &ProcEntry) -> bool {
    ending(e) || pending(e) & signal::bit(signal::SIGKILL) != 0
}

/// Whether a signal is pending that `e` would act on (not blocked, not
/// ignored), or it must stop or end: blocking syscalls give up with
/// `ERESTARTSYS` when so.
pub(crate) fn interrupted(e: &ProcEntry) -> bool {
    let awaited = e.awaited.load(Ordering::SeqCst);
    let open = !e.blocked.load(Ordering::SeqCst) | awaited;
    let heeded = !e.ignored.load(Ordering::SeqCst) | awaited | signal::bit(signal::SIGKILL);
    pending(e) & open & heeded != 0 || ending(e) || stopping(e)
}

/// Wakes thread `e`, whatever it is blocked on, or takes it out of user
/// code.
pub(crate) fn wake(e: &ProcEntry) {
    let task = e.task.lock().clone();
    if let Some(t) = task
        && !t.wake()
    {
        t.interrupt();
    }
    e.signals.wake_all();
}

/// Whether `sig`, arriving at thread `e`, is discarded at once (as on
/// Linux: ignored, and neither blocked nor waited for).
fn discarded(e: &ProcEntry, sig: u32) -> bool {
    let b = signal::bit(sig);
    let held = e.blocked.load(Ordering::SeqCst) | e.awaited.load(Ordering::SeqCst);
    sig != signal::SIGKILL && held & b == 0 && e.ignored.load(Ordering::SeqCst) & b != 0
}

/// The threads of `e`'s process.
fn threads_of(t: &BTreeMap<u64, Arc<ProcEntry>>, e: &ProcEntry) -> alloc::vec::Vec<Arc<ProcEntry>> {
    t.values()
        .filter(|c| Arc::ptr_eq(&c.shared, &e.shared))
        .cloned()
        .collect()
}

/// What sending `sig` to a process does before it is taken by anyone: a
/// stop signal and `SIGCONT` cancel each other's pending instances, and
/// `SIGCONT` makes a stopped process go on, even if it is ignored or
/// blocked.
fn job_control(t: &BTreeMap<u64, Arc<ProcEntry>>, e: &ProcEntry, sig: u32) {
    let cancels = match sig {
        signal::SIGCONT => signal::STOPS,
        s if signal::bit(s) & signal::STOPS != 0 => signal::bit(signal::SIGCONT),
        _ => return,
    };
    let threads = threads_of(t, e);
    e.shared.pending.clear(cancels);
    for c in &threads {
        c.pending.clear(cancels);
    }
    if sig != signal::SIGCONT {
        return;
    }
    let told = {
        let mut s = e.shared.stop.lock();
        s.continues += 1;
        if s.by.take().is_none() {
            return;
        }
        e.shared.stopping.store(false, Ordering::SeqCst);
        let complete = core::mem::take(&mut s.complete);
        if complete {
            s.stopped = None;
            s.continued = true;
        }
        complete
    };
    for c in &threads {
        wake(c);
    }
    if told && let Some(leader) = t.get(&e.tgid) {
        tell_parent(t, leader, CLD_CONTINUED, signal::SIGCONT);
    }
}

/// Tells the parent of process `leader` that it stopped or went on, unless
/// it does not want to know.
fn tell_parent(t: &BTreeMap<u64, Arc<ProcEntry>>, leader: &ProcEntry, code: i32, status: u32) {
    let Some(parent) = t.get(&leader.ppid()) else {
        return;
    };
    if !parent.shared.nocldstop.load(Ordering::Relaxed) {
        post_process(
            t,
            parent,
            signal::SIGCHLD,
            Info::child(leader, code, status),
        );
    }
    parent.children.wake_all();
}

/// Tells those who poll signal descriptors, and who read one, that a signal
/// was posted (nobody may have it unblocked, so nobody is woken for it).
fn arrived(e: &ProcEntry) {
    e.shared.posted.fetch_add(1, Ordering::AcqRel);
    e.shared.arrivals.notify();
    e.signals.wake_all();
}

/// Posts `sig` to the process of thread `e` (under the table's lock), and
/// wakes a thread that will take it. False if too many are queued.
fn post_process(
    t: &BTreeMap<u64, Arc<ProcEntry>>,
    e: &Arc<ProcEntry>,
    sig: u32,
    info: Info,
) -> bool {
    job_control(t, e, sig);
    if discarded(e, sig) {
        return true;
    }
    if !e.shared.pending.add(sig, info) {
        return false;
    }
    arrived(e);
    let b = signal::bit(sig);
    let takes = |c: &ProcEntry| {
        let open = !c.blocked.load(Ordering::SeqCst) | c.awaited.load(Ordering::SeqCst);
        open & b != 0 && c.task.lock().is_some()
    };
    if sig == signal::SIGKILL {
        for c in threads_of(t, e) {
            wake(&c);
        }
    } else if takes(e) {
        wake(e);
    } else if let Some(c) = t
        .values()
        .find(|c| Arc::ptr_eq(&c.shared, &e.shared) && takes(c))
    {
        wake(c);
    }
    true
}

/// Posts `sig` to thread `e` itself and wakes it if it is waiting. False if
/// too many are queued.
pub(crate) fn post_info(e: &Arc<ProcEntry>, sig: u32, info: Info) -> bool {
    {
        let t = TABLE.lock();
        job_control(&t, e, sig);
    }
    if discarded(e, sig) {
        return true;
    }
    if !e.pending.add(sig, info) {
        return false;
    }
    arrived(e);
    if sig == signal::SIGKILL {
        // Whoever it is sent to, it ends the process.
        let threads = threads_of(&TABLE.lock(), e);
        for c in threads {
            wake(&c);
        }
    }
    wake(e);
    true
}

/// Posts `sig` to thread `e`, from the kernel on its own behalf (SIGPIPE).
pub(crate) fn post(e: &Arc<ProcEntry>, sig: u32) {
    let (uid, _) = e.uids();
    post_info(e, sig, Info::sent(signal::SI_USER, e.tgid, uid));
}

/// `kill`: posts `sig` to the process of thread `pid` (0 only checks that
/// it exists); any of its threads may take it.
pub(crate) fn send_info(cell: u64, pid: u64, sig: u32, info: Info) -> Result<(), i64> {
    let t = TABLE.lock();
    let e = t.get(&pid).filter(|e| e.cell == cell).ok_or(ESRCH)?;
    if sig == 0 || e.status.lock().is_some() {
        return Ok(()); // a zombie takes nothing
    }
    if post_process(&t, e, sig, info) {
        Ok(())
    } else {
        Err(EAGAIN)
    }
}

/// [`send_info`] from the kernel.
pub(crate) fn send(cell: u64, pid: u64, sig: u32) -> Result<(), i64> {
    send_info(cell, pid, sig, Info::kernel())
}

/// `tgkill`/`tkill`: posts `sig` to thread `tid` (of process `tgid`, if
/// given).
pub(crate) fn send_thread(
    cell: u64,
    tgid: Option<u64>,
    tid: u64,
    sig: u32,
    info: Info,
) -> Result<(), i64> {
    let e = TABLE
        .lock()
        .get(&tid)
        .filter(|e| e.cell == cell)
        .cloned()
        .ok_or(ESRCH)?;
    if tgid.is_some_and(|g| g != e.tgid) || e.status.lock().is_some() {
        return Err(ESRCH);
    }
    if sig == 0 || post_info(&e, sig, info) {
        Ok(())
    } else {
        Err(EAGAIN)
    }
}

/// The entry of live process or thread `pid` in `cell` (a zombie counts).
pub(crate) fn find(cell: u64, pid: u64) -> Option<Arc<ProcEntry>> {
    TABLE.lock().get(&pid).filter(|e| e.cell == cell).cloned()
}

/// How many `SIGCONT`s the process of `e` was sent: see [`begin_stop`].
pub(crate) fn continues(e: &ProcEntry) -> u64 {
    e.shared.stop.lock().continues
}

/// Stops the process of `e`, for `sig`: its threads park as they see it.
/// Not if a `SIGCONT` came since `seen` ([`continues`]), nor, for a signal
/// from a terminal, if nobody could continue it (an orphaned group).
pub(crate) fn begin_stop(e: &ProcEntry, sig: u32, seen: u64) {
    let t = TABLE.lock();
    let Some(leader) = t.get(&e.tgid) else {
        return;
    };
    if sig != signal::SIGSTOP && orphaned_group(&t, e.cell, leader.group()) {
        return;
    }
    {
        let mut s = e.shared.stop.lock();
        if s.continues != seen || s.by.is_some() {
            return;
        }
        s.by = Some(sig);
        e.shared.stopping.store(true, Ordering::SeqCst);
        s.complete = false;
        s.continued = false;
    }
    for c in threads_of(&t, e) {
        if c.pid != e.pid {
            wake(&c);
        }
    }
}

/// Whether process group `pgid` of session `sid` is orphaned: no member's
/// parent is in another group of the session (a shell that could continue
/// it).
fn orphaned_group(t: &BTreeMap<u64, Arc<ProcEntry>>, cell: u64, (pgid, sid): (u64, u64)) -> bool {
    !t.values().any(|e| {
        e.cell == cell
            && e.pid == e.tgid
            && e.group() == (pgid, sid)
            && e.status.lock().is_none()
            && t.get(&e.ppid()).is_some_and(|p| {
                let (pg, ps) = p.group();
                ps == sid && pg != pgid
            })
    })
}

/// Whether the caller's process group is orphaned (see [`orphaned_group`]).
pub(crate) fn in_orphaned_group(leader: &ProcEntry) -> bool {
    orphaned_group(&TABLE.lock(), leader.cell, leader.group())
}

/// Whether the process of `e` is stopped (or stopping).
pub(crate) fn stopping(e: &ProcEntry) -> bool {
    e.shared.stopping.load(Ordering::SeqCst)
}

/// Parks thread `e` of a stopped process, one of `live` threads, until the
/// process goes on or the thread must end.
pub(crate) fn park(e: &ProcEntry, live: usize) {
    e.shared.stop.lock().parked += 1;
    stop_progress(e, live);
    e.signals
        .wait_until(|| (!stopping(e) || dying(e)).then_some(()));
    e.shared.stop.lock().parked -= 1;
}

/// Tells the parent once every one of a stopped process's `live` threads
/// has parked (also looked at when one of them exits).
pub(crate) fn stop_progress(e: &ProcEntry, live: usize) {
    let t = TABLE.lock();
    let sig = {
        let mut s = e.shared.stop.lock();
        let Some(sig) = s.by.filter(|_| !s.complete && s.parked >= live) else {
            return;
        };
        s.complete = true;
        s.stopped = Some(sig);
        sig
    };
    if let Some(leader) = t.get(&e.tgid) {
        tell_parent(&t, leader, CLD_STOPPED, sig);
    }
}

/// `rt_sigtimedwait`: takes a pending signal of `set`, waiting for one
/// until `deadline`. `Ok(None)` when that passes; EINTR if another signal
/// is to be acted on first.
pub(crate) fn await_signal(
    e: &ProcEntry,
    set: u64,
    deadline: Option<core::time::Duration>,
) -> Result<Option<(u32, Info)>, i64> {
    e.awaited.store(set, Ordering::SeqCst);
    let cond = || match take_signal(e, set) {
        Some(s) => Some(Ok(s)),
        None => interrupted(e).then_some(Err(EINTR)),
    };
    let r = match deadline {
        None => Some(e.signals.wait_until(cond)),
        Some(d) => e.signals.wait_until_deadline(d, cond),
    };
    e.awaited.store(0, Ordering::SeqCst);
    r.transpose()
}

/// Takes a pending signal of `set`, waiting for one until `interrupted`
/// (a signal descriptor's read).
pub(crate) fn wait_signal(
    e: &ProcEntry,
    set: u64,
    interrupted: &dyn Fn() -> bool,
) -> Result<(u32, Info), i64> {
    e.signals.wait_until(|| match take_signal(e, set) {
        Some(s) => Some(Ok(s)),
        None => interrupted().then_some(Err(signal::ERESTARTSYS)),
    })
}

/// Puts `e`'s entry in the place of its process's first thread's, for a
/// thread whose `execve` leaves it the only one: it has the process's id
/// from here on. Returns that entry.
pub(crate) fn take_over_leader(e: &Arc<ProcEntry>, leader: &Arc<ProcEntry>) -> Arc<ProcEntry> {
    if e.pid == leader.pid {
        return e.clone();
    }
    let mut t = TABLE.lock();
    leader.ending.store(false, Ordering::SeqCst);
    leader
        .blocked
        .store(e.blocked.load(Ordering::SeqCst), Ordering::SeqCst);
    leader
        .ignored
        .store(e.ignored.load(Ordering::SeqCst), Ordering::SeqCst);
    leader.pending.clear(u64::MAX);
    while let Some((sig, info)) = e.pending.take(u64::MAX) {
        leader.pending.add(sig, info);
    }
    // The task comes with its CPU time (ADR-0021).
    leader
        .cpu_base
        .store(e.cpu_base.load(Ordering::Relaxed), Ordering::Relaxed);
    *leader.task.lock() = e.task.lock().take();
    t.remove(&e.pid);
    leader.clone()
}

/// Sleeps until `deadline` (time since boot) or until `e` has a signal it
/// would act on; returns true if a signal ended the sleep.
pub(crate) fn sleep_until(e: &ProcEntry, deadline: core::time::Duration) -> bool {
    e.signals
        .wait_until_deadline(deadline, || interrupted(e).then_some(()))
        .is_some()
}

/// The wait status of the process `e` leads, once all its threads are gone.
pub(crate) fn exit_status(e: &ProcEntry) -> Option<u32> {
    *e.status.lock()
}

/// Waits on `e`'s signal queue until `done` holds or the thread must end.
pub(crate) fn wait_killable(e: &ProcEntry, done: impl Fn() -> bool) {
    e.signals.wait_until(|| (done() || dying(e)).then_some(()));
}

/// Sleeps until `e` has a signal it would act on.
pub(crate) fn wait_for_signal(e: &ProcEntry) {
    e.signals.wait_until(|| interrupted(e).then_some(()));
}

/// Records that `e` exited with wait status `status`, orphans its children,
/// and wakes its parent (posting `SIGCHLD`).
fn exited(e: &Arc<ProcEntry>, status: u32) {
    *e.task.lock() = None;
    let mut t = TABLE.lock();
    *e.status.lock() = Some(status);
    let orphans: alloc::vec::Vec<_> = t.values().filter(|c| c.ppid() == e.pid).cloned().collect();
    for c in orphans {
        c.ppid.store(0, Ordering::Release);
        let sig = c.pdeathsig.load(Ordering::Acquire);
        if sig != 0 && c.status.lock().is_none() {
            let (uid, _) = e.uids();
            post_process(&t, &c, sig, Info::sent(signal::SI_USER, e.pid, uid));
        }
    }
    if let Some(parent) = t.get(&e.ppid()) {
        let (code, st) = if status & 0x7f == 0 {
            (CLD_EXITED, (status >> 8) & 0xff)
        } else if status & 0x80 != 0 {
            (CLD_DUMPED, status & 0x7f)
        } else {
            (CLD_KILLED, status & 0x7f)
        };
        post_process(&t, parent, signal::SIGCHLD, Info::child(e, code, st));
        let parent = parent.clone();
        if parent.shared.nocldwait.load(Ordering::Relaxed) {
            e.ppid.store(0, Ordering::Release); // not to be waited for
        }
        parent.children.wake_all();
    }
    // Orphans that already exited (and this process, if it has no parent)
    // are reaped now; nobody will wait for them.
    t.retain(|_, c| c.ppid() != 0 || c.status.lock().is_none());
    drop(t);
    e.shared.exit.notify();
}

/// What a `wait4` or `waitid` looks for.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Wanted {
    /// Children that exited, that stopped, that went on.
    pub(crate) exited: bool,
    pub(crate) stopped: bool,
    pub(crate) continued: bool,
    /// Do not wait for one.
    pub(crate) nohang: bool,
    /// Leave what is found to be found again (`WNOWAIT`).
    pub(crate) keep: bool,
}

/// The wait status of a child that went on.
pub(crate) const CONTINUED: u32 = 0xffff;

/// What there is to report of child `c`, as a wait status.
fn report(c: &ProcEntry, want: Wanted) -> Option<u32> {
    if let Some(st) = *c.status.lock() {
        return want.exited.then_some(st);
    }
    let mut s = c.shared.stop.lock();
    if want.stopped
        && let Some(sig) = s.stopped
    {
        if !want.keep {
            s.stopped = None;
        }
        return Some(sig << 8 | 0x7f);
    }
    if want.continued && s.continued {
        s.continued = want.keep;
        return Some(CONTINUED);
    }
    None
}

/// `wait4` by thread `caller` of the process led by `leader`: reaps an
/// exited child process matching `pid` (-1 or less: any child), or reports
/// one that stopped or went on, and returns its pid, wait status and real
/// uid; `Ok(None)` if there is none yet and `want.nohang`, or `ECHILD` if
/// there is no such child.
pub(crate) fn wait(
    leader: &ProcEntry,
    caller: &ProcEntry,
    pid: i64,
    want: Wanted,
) -> Result<Option<(u64, u32, u32)>, i64> {
    leader.children.wait_until(|| {
        let mut t = TABLE.lock();
        let mut any = false;
        let mut found = None;
        for (&cpid, c) in t.iter() {
            let leader_of_child = c.pid == c.tgid;
            let wanted = match pid {
                p if p > 0 => p as u64 == cpid,
                0 => c.group().0 == leader.group().0,
                -1 => true,
                p => c.group().0 == p.unsigned_abs(),
            };
            if !leader_of_child || c.ppid() != leader.pid || !wanted {
                continue;
            }
            any = true;
            if let Some(st) = report(c, want) {
                let gone = c.status.lock().is_some();
                found = Some(((cpid, st, c.uids().0), gone));
                break;
            }
        }
        if let Some((r, gone)) = found {
            if gone && !want.keep {
                t.remove(&r.0);
            }
            return Some(Ok(Some(r)));
        }
        if !any {
            return Some(Err(ECHILD));
        }
        if want.nohang {
            return Some(Ok(None));
        }
        drop(t);
        interrupted(caller).then_some(Err(signal::ERESTARTSYS))
    })
}

/// A tile instruction's first #NM (ADR-0023): the thread's state gets room
/// for tile data, charged to its cell, and the instruction runs again. False
/// (a signal, as Linux sends: SIGILL without permission, SIGSEGV when the
/// cell cannot pay) otherwise.
fn first_tile_use(p: &mut LinuxProcess, ctx: &mut UserContext) -> bool {
    if !p.group.prctl.lock().xtile || ctx.fpu_tiles() {
        return false;
    }
    let pages = (frame::cpu::xstate_tile_size() as u64).div_ceil(4096);
    let Some(charge) = Reserved::new(p.cell.account(), pages) else {
        return false;
    };
    p.tile_charge = Some(charge);
    ctx.enable_tiles();
    true
}

/// Runs `p` in ring 3 from `ctx` until it exits, then frees it and records
/// its exit. Returns the wait status and how many syscalls it made.
pub(crate) fn run(mut p: LinuxProcess, mut ctx: UserContext) -> (u32, u32) {
    p.mm().space().bind_to_current_task();
    // Separates this cell's user code from other cells' on each CPU
    // (ADR-0004 §2).
    frame::task::set_current_domain(p.cell.id());
    let me = frame::task::current();
    // CPU time counts from here (ADR-0021): the system call path reads no
    // clock.
    let base = u64::try_from(me.cpu_time().as_nanos()).unwrap_or(u64::MAX);
    p.entry.cpu_base.store(base, Ordering::Relaxed);
    *p.entry.task.lock() = Some(me);
    signal::sync(&p);
    let mut syscalls = 0u32;
    let status = loop {
        let mut restart = None;
        // Not into user code with a signal to act on: one posted from here
        // on interrupts it (`wake`).
        let event = UserMode::new(&mut ctx).execute_unless(|| interrupted(&p.entry));
        crate::itimer::check_cpu(&p);
        match event {
            UserEvent::Syscall => {
                syscalls = syscalls.wrapping_add(1);
                let nr = ctx.rax;
                if let Outcome::Exit(code) = linuxabi::dispatch(&mut p, &mut ctx) {
                    break (code as u32 & 0xff) << 8;
                }
                restart = signal::Restart::of(nr, ctx.rax as i64);
                if restart.is_none() {
                    p.resume_until = None;
                }
                linuxabi::uring::task_work(&mut p);
            }
            UserEvent::Preempted => frame::task::yield_now(),
            // Not a protection-key violation (error bit 5): no mapping
            // change serves that.
            UserEvent::Exception {
                vector: 14,
                error,
                cr2,
            } if error & PF_PK == 0 && p.mm().fault(cr2, error & 2 != 0, error & 16 != 0) => {}
            // A tile instruction's first use (XFD's #NM): room, then again.
            UserEvent::Exception {
                vector: 7, error, ..
            } if error & frame::cpu::XSTATE_TILE_DATA != 0 && first_tile_use(&mut p, &mut ctx) => {}
            UserEvent::Exception { vector, error, cr2 } => {
                // The signal, its code and its address, as Linux reports.
                let trap = signal::Trap {
                    vector: u64::from(vector),
                    error,
                    cr2,
                };
                let rip = ctx.rip;
                let (sig, code, addr) = match vector {
                    0 => (SIGFPE, signal::FPE_INTDIV, rip),
                    16 | 19 => (SIGFPE, signal::FPE_FLTINV, rip),
                    1 => (SIGTRAP, signal::TRAP_TRACE, rip),
                    3 => (SIGTRAP, signal::SI_KERNEL, 0),
                    6 => (SIGILL, signal::ILL_ILLOPN, rip),
                    // Tiles without permission; with it, the cell was full.
                    7 if !p.group.prctl.lock().xtile => (SIGILL, signal::ILL_ILLOPC, rip),
                    14 if error & PF_PK != 0 => (signal::SIGSEGV, signal::SEGV_PKUERR, cr2),
                    14 if p.mm().mapped(cr2) => (signal::SIGSEGV, signal::SEGV_ACCERR, cr2),
                    14 => (signal::SIGSEGV, signal::SEGV_MAPERR, cr2),
                    _ => (signal::SIGSEGV, signal::SI_KERNEL, 0),
                };
                if let Some(status) = signal::fault(&mut p, &mut ctx, sig, code, addr, trap) {
                    // The cell's memory with it: a fault the kernel could
                    // not serve is often a full account.
                    let acct = p.cell.account();
                    println!(
                        "ichor: linux: pid {} killed: exception {vector} at rip {:#x} (cr2 {cr2:#x}); cell {} uses {} of {} pages",
                        p.entry.pid,
                        ctx.rip,
                        p.cell.id(),
                        acct.used(),
                        acct.limit()
                    );
                    p.group.begin_exit(status, &p.entry);
                    break status;
                }
            }
        }
        match signal::deliver(&mut p, &mut ctx, restart) {
            signal::Fate::Goes => {}
            // A fatal signal ends the whole process.
            signal::Fate::ProcessEnds(status) => {
                p.group.begin_exit(status, &p.entry);
                break status;
            }
            signal::Fate::ThreadEnds => break signal::SIGKILL,
        }
    };
    // Robust futexes the thread still holds are marked owner-dead first.
    crate::futex::exit_robust_list(&mut p);
    // `CLONE_CHILD_CLEARTID`: zero the word and wake one waiter (this is
    // how `pthread_join` learns the thread is gone).
    if p.clear_tid != 0 {
        let addr = p.clear_tid;
        let _ = p.copy_to_user(addr, &0u32.to_le_bytes());
        crate::futex::wake(&p, addr, 1, u32::MAX);
    }
    frame::mm::activate_kernel_space();
    let entry = p.entry.clone();
    let group = p.group.clone();
    let cpu = entry.cpu_ns();
    entry.cpu_done.store(cpu, Ordering::Relaxed);
    *entry.task.lock() = None;
    let last = group.thread_exited(&entry, status);
    if last.is_none() {
        stop_progress(&entry, group.threads().len());
        // A signal this thread was woken to take may be left: it is the
        // others' now.
        for t in group.threads() {
            if interrupted(&t) {
                wake(&t);
            }
        }
    }
    drop(p);
    if entry.pid != entry.tgid {
        TABLE.lock().remove(&entry.pid);
    }
    let gone = group.gone.clone();
    if let Some(group_status) = last {
        let leader = group.leader.clone();
        // Threads that left just before us may still hold a reference for
        // a moment; the memory and files must be gone before the status is
        // visible. Each wakes `gone` after dropping its reference; the
        // timed re-check covers a reference dropped some other way.
        while Arc::strong_count(&group) > 1 {
            let deadline = frame::time::now() + core::time::Duration::from_millis(10);
            gone.wait_until_deadline(deadline, || (Arc::strong_count(&group) == 1).then_some(()));
        }
        // A vfork parent goes on once the status is visible.
        let vfork = group.take_vfork();
        // The last thread frees the memory and files; its space is no
        // longer active on any CPU.
        drop(group);
        exited(&leader, group_status);
        if let Some(v) = vfork {
            v.release();
        }
    } else {
        // Let the last thread out see our reference gone.
        drop(group);
        gone.wake_all();
    }
    (status, syscalls)
}

/// `fork`: starts a copy of `p` on a new task, resuming at `ctx` with a
/// return value of 0 and, if `stack` is nonzero, that stack pointer.
/// Returns the child's pid.
pub(crate) fn fork(
    p: &mut LinuxProcess,
    ctx: &UserContext,
    stack: u64,
) -> Result<(LinuxProcess, UserContext), i64> {
    let child = p.fork().ok_or(EAGAIN)?;
    let mut cctx = ctx.clone();
    cctx.set_return(0);
    if stack != 0 {
        cctx.rsp = stack;
    }
    Ok((child, cctx))
}

/// Runs `work` on a new kernel task as the helper thread `p` (from
/// [`LinuxProcess::helper`]), then takes it out of the table and lets the
/// process's last thread see its reference gone. Returns false if no task
/// could be started.
///
/// The task stays on the kernel address space: a helper never runs user
/// code, and its copies to and from the process's memory go through the
/// linear map (ADR-0011). Binding it to the process's space would leave it
/// bound to a freed space once `execve` replaced that space, since
/// `execve` does not wait for helpers.
pub(crate) fn start_helper(
    p: LinuxProcess,
    work: impl FnOnce(&mut LinuxProcess) + Send + 'static,
) -> bool {
    let pid = p.entry.pid;
    let sched = SchedInfo::of_cell(p.cell.id());
    let task = TaskOptions::new(move || {
        let mut p = p;
        *p.entry.task.lock() = Some(frame::task::current());
        work(&mut p);
        *p.entry.task.lock() = None;
        let gone = p.group.gone.clone();
        drop(p);
        TABLE.lock().remove(&pid);
        gone.wake_all();
    })
    .data(sched)
    .spawn();
    if task.is_none() {
        TABLE.lock().remove(&pid);
        return false;
    }
    true
}

/// Drops a process that never ran (its program failed to load), taking it
/// out of the table.
pub(crate) fn discard(p: LinuxProcess) {
    let pid = p.entry.pid;
    p.group.never_ran(pid);
    drop(p);
    forget(pid);
}

/// Takes a process that never ran, and that nobody waits for, out of the
/// table.
pub(crate) fn forget(pid: u64) {
    TABLE.lock().remove(&pid);
}

/// Spawns the task that runs a forked child.
pub(crate) fn start(child: LinuxProcess, ctx: UserContext) -> Result<u64, i64> {
    let pid = child.entry.pid;
    let group = Arc::downgrade(&child.group);
    let sched = SchedInfo::of_cell(child.cell.id());
    let task = TaskOptions::new(move || {
        run(child, ctx);
    })
    .data(sched)
    .spawn();
    if task.is_none() {
        // The closure (and with it the child) was dropped unrun; nobody
        // learned its pid, so it leaves the table at once.
        forget(pid);
        if let Some(g) = group.upgrade() {
            g.never_ran(pid);
        }
        return Err(EAGAIN);
    }
    Ok(pid)
}
