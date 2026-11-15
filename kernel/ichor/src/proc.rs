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
use frame::task::{TaskOptions, WaitQueue};
use frame::user::{UserContext, UserEvent, UserMode};

use crate::linuxabi::{self, Outcome};
use crate::process::LinuxProcess;

const ECHILD: i64 = 10;
const EAGAIN: i64 = 11;

/// Signal numbers used in wait statuses for processes killed by faults.
const SIGILL: u32 = 4;
const SIGFPE: u32 = 8;
const SIGSEGV: u32 = 11;

/// A process's entry in the table.
#[derive(Debug)]
pub(crate) struct ProcEntry {
    pub(crate) pid: u64,
    ppid: AtomicU64,
    /// The wait status once the process has exited.
    status: SpinLock<Option<u32>>,
    /// Woken whenever one of this process's children exits.
    children: WaitQueue,
}

impl ProcEntry {
    pub(crate) fn ppid(&self) -> u64 {
        self.ppid.load(Ordering::Acquire)
    }
}

static TABLE: SpinLock<BTreeMap<u64, Arc<ProcEntry>>> = SpinLock::new(BTreeMap::new());
static NEXT_PID: AtomicU64 = AtomicU64::new(1);

/// Adds a running process with parent `ppid` (0: none) to the table.
pub(crate) fn register(ppid: u64) -> Arc<ProcEntry> {
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);
    let e = Arc::new(ProcEntry {
        pid,
        ppid: AtomicU64::new(ppid),
        status: SpinLock::new(None),
        children: WaitQueue::new(),
    });
    TABLE.lock().insert(pid, e.clone());
    e
}

/// Records that `e` exited with wait status `status`, orphans its children,
/// and wakes its parent.
fn exited(e: &ProcEntry, status: u32) {
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
        p.children.wake_all();
    }
}

/// `wait4` for `me`: reaps an exited child matching `pid` (-1 or less: any
/// child) and returns its pid and wait status, `Ok(None)` if `nohang` and
/// none has exited yet, or `ECHILD` if there is no such child.
pub(crate) fn wait(me: &ProcEntry, pid: i64, nohang: bool) -> Result<Option<(u64, u32)>, i64> {
    me.children.wait_until(|| {
        let mut t = TABLE.lock();
        let mut any = false;
        let mut found = None;
        for (&cpid, c) in t.iter() {
            if c.ppid() != me.pid || (pid > 0 && pid as u64 != cpid) {
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
    p.mm.space().bind_to_current_task();
    let mut syscalls = 0u32;
    let status = loop {
        match UserMode::new(&mut ctx).execute() {
            UserEvent::Syscall => {
                syscalls = syscalls.wrapping_add(1);
                if let Outcome::Exit(code) = linuxabi::dispatch(&mut p, &mut ctx) {
                    break (code as u32 & 0xff) << 8;
                }
            }
            UserEvent::Exception {
                vector: 14,
                error,
                cr2,
            } if p.mm.fault(cr2, error & 2 != 0, error & 16 != 0) => {}
            UserEvent::Exception { vector, cr2, .. } => {
                println!(
                    "ichor: linux: pid {} killed: exception {vector} at rip {:#x} (cr2 {cr2:#x})",
                    p.entry.pid, ctx.rip
                );
                break match vector {
                    0 => SIGFPE,
                    6 => SIGILL,
                    _ => SIGSEGV,
                };
            }
        }
    };
    frame::mm::activate_kernel_space();
    let entry = p.entry.clone();
    drop(p); // Frees its memory and files (its space is no longer active).
    exited(&entry, status);
    (status, syscalls)
}

/// `fork`: starts a copy of `p` on a new task, resuming at `ctx` with a
/// return value of 0 and, if `stack` is nonzero, that stack pointer.
/// Returns the child's pid.
pub(crate) fn fork(
    p: &LinuxProcess,
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
