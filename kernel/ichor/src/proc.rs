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
    ppid: AtomicU64,
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
}

static TABLE: SpinLock<BTreeMap<u64, Arc<ProcEntry>>> = SpinLock::new(BTreeMap::new());
static NEXT_PID: AtomicU64 = AtomicU64::new(1);

/// Adds a thread with parent process `ppid` (0: none) to the table, as a
/// new process (`tgid` `None`) or a thread of process `tgid`.
pub(crate) fn register(ppid: u64, tgid: Option<u64>) -> Arc<ProcEntry> {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let e = Arc::new(ProcEntry {
        pid,
        tgid: tgid.unwrap_or(pid),
        ppid: AtomicU64::new(ppid),
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
pub(crate) fn send(pid: u64, sig: u32) -> Result<(), i64> {
    let target = {
        let t = TABLE.lock();
        let e = t.get(&pid).cloned().ok_or(ESRCH)?;
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
pub(crate) fn send_thread(tgid: Option<u64>, tid: u64, sig: u32) -> Result<(), i64> {
    let e = TABLE.lock().get(&tid).cloned().ok_or(ESRCH)?;
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
            if !leader_of_child || c.ppid() != leader.pid || (pid > 0 && pid as u64 != cpid) {
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
        // The last thread frees the memory and files; its space is no
        // longer active on any CPU.
        drop(group);
        exited(&leader, group_status);
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
    let mut cctx = *ctx;
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
