//! Linux processes as kernel tasks: the process table (pids, parents, exit
//! statuses), `wait4`, and the loop that runs a process in ring 3.
//!
//! Every process runs on its own kernel task, which `fork` spawns. A
//! process that exits stays in the table as a zombie holding its wait
//! status until its parent reaps it. When a parent exits, its children are
//! orphaned (parent 0) and reaped by the kernel as they exit. A per-cell
//! init and pid namespaces arrive with multi-cell scheduling (milestone 4);
//! pids are global for now.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use frame::println;
use frame::sync::SpinLock;
use frame::task::{Task, TaskOptions, WaitQueue};
use frame::user::{UserContext, UserEvent, UserMode};

use crate::linuxabi::{self, Outcome};
use crate::process::LinuxProcess;
use crate::signal;

const ECHILD: i64 = 10;
const EAGAIN: i64 = 11;

/// Signals raised by CPU exceptions.
const SIGILL: u32 = 4;
const SIGTRAP: u32 = 5;
const SIGFPE: u32 = 8;
const ESRCH: i64 = 3;

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
    /// Signals posted but not yet delivered.
    pending: AtomicU64,
    /// The process's signal mask and ignored set, mirrored from its
    /// `Signals` so other tasks can decide whether a signal wakes it.
    blocked: AtomicU64,
    ignored: AtomicU64,
    /// The task running the process, to wake it for a signal.
    task: SpinLock<Option<Arc<Task>>>,
    /// Woken when a signal is posted (`pause`, `rt_sigsuspend`).
    signals: WaitQueue,
}

impl ProcEntry {
    pub(crate) fn ppid(&self) -> u64 {
        self.ppid.load(Ordering::Acquire)
    }

    /// The real and saved uids (see `uids`).
    pub(crate) fn uids(&self) -> (u32, u32) {
        let v = self.uids.load(Ordering::Acquire);
        (v as u32, (v >> 32) as u32)
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
            let _ = send(me.cell, pid, sig);
        }
    }
    if any { Ok(()) } else { Err(EPERM) }
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
/// `tgid`. A new process starts in `group` = (pgid, sid), or in a group and
/// session of its own.
pub(crate) fn register(
    cell: u64,
    ppid: u64,
    tgid: Option<u64>,
    group: Option<(u64, u64)>,
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
        pending: AtomicU64::new(0),
        blocked: AtomicU64::new(0),
        ignored: AtomicU64::new(signal::bit(signal::SIGCHLD)),
        task: SpinLock::new(None),
        signals: WaitQueue::new(),
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

/// Signals pending for `e`.
pub(crate) fn pending(e: &ProcEntry) -> u64 {
    e.pending.load(Ordering::SeqCst)
}

pub(crate) fn clear_pending(e: &ProcEntry, set: u64) {
    e.pending.fetch_and(!set, Ordering::SeqCst);
}

/// Whether a signal is pending that `e` would act on (not blocked, not
/// ignored): blocking syscalls give up with `ERESTARTSYS` when it is.
pub(crate) fn interrupted(e: &ProcEntry) -> bool {
    let p = e.pending.load(Ordering::SeqCst);
    let unblocked = !e.blocked.load(Ordering::SeqCst);
    let kill = signal::bit(signal::SIGKILL);
    p & unblocked & (!e.ignored.load(Ordering::SeqCst) | kill) != 0
}

/// Posts `sig` to `e` and wakes it if it is waiting.
pub(crate) fn post(e: &ProcEntry, sig: u32) {
    let b = signal::bit(sig);
    let blocked = e.blocked.load(Ordering::SeqCst) & b != 0;
    if sig != signal::SIGKILL && !blocked && e.ignored.load(Ordering::SeqCst) & b != 0 {
        return; // discarded on arrival, as Linux does
    }
    e.pending.fetch_or(b, Ordering::SeqCst);
    let task = e.task.lock().clone();
    if let Some(t) = task {
        t.wake();
    }
    e.signals.wake_all();
}

/// `kill`: posts `sig` to process `pid` (0 only checks that it exists).
/// It goes to the thread `pid` if that is still running, else to another
/// running thread of the process.
pub(crate) fn send(cell: u64, pid: u64, sig: u32) -> Result<(), i64> {
    let target = {
        let t = TABLE.lock();
        let e = t
            .get(&pid)
            .filter(|e| e.cell == cell)
            .cloned()
            .ok_or(ESRCH)?;
        if e.status.lock().is_some() {
            return Ok(()); // a zombie
        }
        if e.task.lock().is_some() {
            e
        } else {
            // The thread has exited while others run (or has not started
            // yet: then the signal waits for it in its pending set).
            t.values()
                .find(|c| c.tgid == e.tgid && c.task.lock().is_some())
                .cloned()
                .unwrap_or(e)
        }
    };
    if sig != 0 {
        post(&target, sig);
    }
    Ok(())
}

/// `tgkill`/`tkill`: posts `sig` to thread `tid` (of process `tgid`, if
/// given).
pub(crate) fn send_thread(cell: u64, tgid: Option<u64>, tid: u64, sig: u32) -> Result<(), i64> {
    let e = TABLE
        .lock()
        .get(&tid)
        .filter(|e| e.cell == cell)
        .cloned()
        .ok_or(ESRCH)?;
    if tgid.is_some_and(|g| g != e.tgid) || e.task.lock().is_none() {
        return Err(ESRCH);
    }
    if sig != 0 {
        post(&e, sig);
    }
    Ok(())
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

/// Sleeps until `e` has a signal it would act on.
/// Wakes `e` from a wait on its signal queue so it re-checks.
pub(crate) fn wake(e: &ProcEntry) {
    e.signals.wake_all();
}

/// Waits on `e`'s signal queue until `done` holds or `SIGKILL` is pending.
pub(crate) fn wait_killable(e: &ProcEntry, done: impl Fn() -> bool) {
    let kill = signal::bit(signal::SIGKILL);
    e.signals
        .wait_until(|| (done() || pending(e) & kill != 0).then_some(()));
}

pub(crate) fn wait_for_signal(e: &ProcEntry) {
    e.signals.wait_until(|| interrupted(e).then_some(()));
}

/// Records that `e` exited with wait status `status`, orphans its children,
/// and wakes its parent (posting `SIGCHLD`).
fn exited(e: &ProcEntry, status: u32) {
    *e.task.lock() = None;
    *e.status.lock() = Some(status);
    let parent = {
        let mut t = TABLE.lock();
        for c in t.values() {
            if c.ppid() == e.pid {
                c.ppid.store(0, Ordering::Release);
                let sig = c.pdeathsig.load(Ordering::Acquire);
                if sig != 0 && c.status.lock().is_none() {
                    post(c, sig);
                }
            }
        }
        // Orphans that already exited (and this process, if it has no
        // parent) are reaped now; nobody will wait for them.
        t.retain(|_, c| c.ppid() != 0 || c.status.lock().is_none());
        t.get(&e.ppid()).cloned()
    };
    if let Some(p) = parent {
        post(&p, signal::SIGCHLD);
        p.children.wake_all();
    }
}

/// `wait4` by thread `caller` of the process led by `leader`: reaps an
/// exited child process matching `pid` (-1 or less: any child) and returns
/// its pid and wait status, `Ok(None)` if `nohang` and none has exited yet,
/// or `ECHILD` if there is no such child.
pub(crate) fn wait(
    leader: &ProcEntry,
    caller: &ProcEntry,
    pid: i64,
    nohang: bool,
) -> Result<Option<(u64, u32)>, i64> {
    leader.children.wait_until(|| {
        if interrupted(caller) {
            return Some(Err(signal::ERESTARTSYS));
        }
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
            if let Some(st) = *c.status.lock() {
                found = Some((cpid, st));
                break;
            }
        }
        if let Some((cpid, st)) = found {
            t.remove(&cpid);
            return Some(Ok(Some((cpid, st))));
        }
        if !any {
            return Some(Err(ECHILD));
        }
        nohang.then_some(Ok(None))
    })
}

/// Runs `p` in ring 3 from `ctx` until it exits, then frees it and records
/// its exit. Returns the wait status and how many syscalls it made.
pub(crate) fn run(mut p: LinuxProcess, mut ctx: UserContext) -> (u32, u32) {
    p.mm().space().bind_to_current_task();
    *p.entry.task.lock() = Some(frame::task::current());
    signal::sync(&p);
    let mut syscalls = 0u32;
    let status = loop {
        let mut restart = None;
        match UserMode::new(&mut ctx).execute() {
            UserEvent::Syscall => {
                syscalls = syscalls.wrapping_add(1);
                let nr = ctx.rax;
                if let Outcome::Exit(code) = linuxabi::dispatch(&mut p, &mut ctx) {
                    break (code as u32 & 0xff) << 8;
                }
                if ctx.rax as i64 == -signal::ERESTARTSYS {
                    restart = Some(nr);
                }
            }
            UserEvent::Preempted => frame::task::yield_now(),
            UserEvent::Exception {
                vector: 14,
                error,
                cr2,
            } if p.mm().fault(cr2, error & 2 != 0, error & 16 != 0) => {}
            UserEvent::Exception { vector, cr2, .. } => {
                let sig = match vector {
                    0 | 16 | 19 => SIGFPE,
                    3 => SIGTRAP,
                    6 => SIGILL,
                    _ => signal::SIGSEGV,
                };
                if let Some(status) = signal::fault(&mut p, &mut ctx, sig, cr2) {
                    println!(
                        "ichor: linux: pid {} killed: exception {vector} at rip {:#x} (cr2 {cr2:#x})",
                        p.entry.pid, ctx.rip
                    );
                    p.group.begin_exit(status, &p.entry);
                    break status;
                }
            }
        }
        if let Some(status) = signal::deliver(&mut p, &mut ctx, restart) {
            // A fatal signal ends the whole process.
            p.group.begin_exit(status, &p.entry);
            break status;
        }
    };
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
    *entry.task.lock() = None;
    let last = group.thread_exited(&entry, status);
    drop(p);
    if entry.pid != entry.tgid {
        TABLE.lock().remove(&entry.pid);
    }
    if let Some(group_status) = last {
        let leader = group.leader.clone();
        // Threads that left just before us may still hold a reference for
        // a moment; the memory and files must be gone before the status is
        // visible.
        while Arc::strong_count(&group) > 1 {
            frame::task::yield_now();
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

/// Spawns the task that runs a forked child.
pub(crate) fn start(child: LinuxProcess, ctx: UserContext) -> Result<u64, i64> {
    let pid = child.entry.pid;
    let entry = child.entry.clone();
    let task = TaskOptions::new(move || {
        run(child, ctx);
    })
    .spawn();
    if task.is_none() {
        // The closure (and with it the child) was dropped unrun; nobody
        // learned its pid, so it leaves the table at once.
        TABLE.lock().remove(&entry.pid);
        return Err(EAGAIN);
    }
    Ok(pid)
}
