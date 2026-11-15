//! Tasks: kernel threads of execution, and the hooks a scheduler plugs into.
//!
//! Frame owns the mechanism: task stacks, the context switch, the per-CPU
//! idle task, preemption on timer ticks, and blocking/waking. The *policy*
//! (which task runs next, where, and for how long) is a [`Scheduler`] the
//! kernel injects once at boot.
//!
//! # Invariants
//!
//! * **A task is handed to the scheduler only while it is fully switched
//!   out.** A task that yields or is preempted is re-enqueued by the *next*
//!   task's `finish_switch`, after the outgoing task's registers are saved
//!   and its `running_on` claim is released. A waker enqueues a task only if
//!   it is already off-CPU. Otherwise the task's own CPU requeues it when it
//!   switches out. The two sides use the store/load (Dekker) pattern with
//!   SeqCst, so exactly one of them sees the other and no wake-up is lost.
//! * **A task runs on at most one CPU.** Before running a task a CPU claims
//!   its `running_on` field with a compare-exchange. Because of the first
//!   invariant the claim succeeds immediately for every task frame queued. A
//!   scheduler that hands out a running task (a policy bug) has that
//!   duplicate dropped, never run. Soundness does not depend on the policy.
//! * An exited task never runs again: it is checked after the claim.
//! * Sleeping (blocking, yielding) in atomic mode, while an `IrqGuard` or a
//!   spinlock guard is live, panics.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

use crate::arch::{self, switch};
use crate::cpu::{self, CpuId, IrqGuard};
use crate::mm::kspace;
use crate::sync::SpinLock;

const NOT_RUNNING: u32 = u32::MAX;

/// Lifecycle of a task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    /// Runnable or running.
    Runnable = 0,
    /// Waiting to be woken.
    Blocked = 1,
    /// Finished; will never run again.
    Exited = 2,
}

/// A kernel thread of execution.
pub struct Task {
    id: u64,
    /// Stack pointer saved by the context switch while not running.
    saved_rsp: AtomicU64,
    /// Top of the task's own stack, or 0 for a task that adopted a CPU's
    /// boot stack.
    stack_top: u64,
    /// CPU currently executing this task, or `NOT_RUNNING`.
    running_on: AtomicU32,
    state: AtomicU8,
    /// Whether the task is in the scheduler's hands (enqueued, not yet
    /// picked). Frame enqueues a task at most once at a time.
    queued: AtomicBool,
    is_idle: bool,
    entry: SpinLock<Option<Box<dyn FnOnce() + Send>>>,
    data: Box<dyn Any + Send + Sync>,
    /// Page table root to run with (0: the kernel's).
    vm_root: AtomicU64,
}

impl Task {
    /// Unique, never reused task ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The data the task was spawned with (see [`TaskOptions::data`]).
    pub fn data(&self) -> &(dyn Any + Send + Sync) {
        &*self.data
    }

    pub fn state(&self) -> TaskState {
        match self.state.load(Ordering::SeqCst) {
            0 => TaskState::Runnable,
            1 => TaskState::Blocked,
            _ => TaskState::Exited,
        }
    }

    pub(crate) fn vm_root(&self) -> u64 {
        self.vm_root.load(Ordering::Relaxed)
    }

    /// Sets the page table root this task runs with and activates it if
    /// this is the current task.
    #[allow(dead_code)] // First user: `VmSpace::activate` (milestone 2, user mode).
    pub(crate) fn set_vm_root(self: &Arc<Self>, root: u64) {
        self.vm_root.store(root, Ordering::Relaxed);
        let g = IrqGuard::new();
        let is_current = SCHED
            .get(&g)
            .current
            .lock()
            .as_ref()
            .is_some_and(|c| Arc::ptr_eq(c, self));
        if is_current {
            arch::activate_root(root);
        }
    }

    /// Makes a blocked task runnable again. Returns false if it was not
    /// blocked.
    pub fn wake(self: &Arc<Self>) -> bool {
        if self
            .state
            .compare_exchange(
                TaskState::Blocked as u8,
                TaskState::Runnable as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            return false;
        }
        // Still on its CPU (on the way to switching out): that CPU's
        // `finish_switch` sees `Runnable` and requeues it.
        if self.running_on.load(Ordering::SeqCst) == NOT_RUNNING {
            enqueue(self.clone(), Enqueue::Woken);
        }
        true
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task")
            .field("id", &self.id)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if self.stack_top != 0 {
            STACK_POOL.lock().push(self.stack_top);
        }
    }
}

/// Free kernel stacks, reused by new tasks.
static STACK_POOL: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Why a task is being handed to the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueue {
    Spawned,
    Woken,
    Yielded,
    Preempted,
}

/// Scheduling policy. Implemented in safe code and injected once with
/// [`inject_scheduler`].
pub trait Scheduler: Sync {
    /// Makes `task` runnable. The scheduler may pick any CPU for it and
    /// should call [`kick`] on that CPU if it might be idle.
    fn enqueue(&self, task: Arc<Task>, why: Enqueue);
    /// The next task for `cpu` to run, if any.
    fn pick_next(&self, cpu: CpuId) -> Option<Arc<Task>>;
    /// Called on every scheduler tick on `cpu` while `current` runs; return
    /// true to preempt it.
    fn tick(&self, cpu: CpuId, current: &Arc<Task>) -> bool;
    /// How long a task runs before the next tick.
    fn timeslice(&self) -> Duration;
}

static SCHEDULER: SpinLock<Option<&'static dyn Scheduler>> = SpinLock::new(None);

/// Installs the scheduling policy. Only the first call has an effect.
pub fn inject_scheduler(s: &'static dyn Scheduler) {
    let mut slot = SCHEDULER.lock();
    if slot.is_none() {
        *slot = Some(s);
    }
}

fn scheduler() -> Option<&'static dyn Scheduler> {
    *SCHEDULER.lock()
}

/// Hands a switched-out `task` to the scheduler unless it already holds it.
fn enqueue(task: Arc<Task>, why: Enqueue) {
    let Some(s) = scheduler() else { return };
    if task.is_idle || task.state() == TaskState::Exited {
        return;
    }
    if !task.queued.swap(true, Ordering::SeqCst) {
        s.enqueue(task, why);
    }
}

/// Per-CPU scheduling state, touched only by its own CPU.
struct CpuSched {
    current: SpinLock<Option<Arc<Task>>>,
    /// The task switched away from, and whether to requeue it, for the
    /// next task's `finish_switch`.
    prev: SpinLock<Option<(Arc<Task>, Option<Enqueue>)>>,
    idle: SpinLock<Option<Arc<Task>>>,
    need_resched: AtomicBool,
}

crate::cpu_local! {
    static SCHED: CpuSched = CpuSched {
        current: SpinLock::new(None),
        prev: SpinLock::new(None),
        idle: SpinLock::new(None),
        need_resched: AtomicBool::new(false),
    };
    static APIC_IDS: AtomicU32 = AtomicU32::new(u32::MAX);
    static TICKS: AtomicU64 = AtomicU64::new(0);
    static PREEMPTIONS: AtomicU64 = AtomicU64::new(0);
}

/// Records the calling CPU's interrupt-controller ID for [`kick`].
pub(crate) fn register_cpu() {
    let g = IrqGuard::new();
    APIC_IDS
        .get(&g)
        .store(arch::apic::apic_id(), Ordering::Relaxed);
}

/// Wakes `cpu` if it is idle so it re-checks its run queue.
pub fn kick(cpu: CpuId) {
    let id = APIC_IDS.get_on(cpu).load(Ordering::Relaxed);
    if id != u32::MAX && cpu != cpu::current() {
        arch::apic::send_ipi(id, arch::apic::IPI_VECTOR);
    }
}

/// Options for a new task.
pub struct TaskOptions {
    entry: Box<dyn FnOnce() + Send>,
    data: Box<dyn Any + Send + Sync>,
}

impl fmt::Debug for TaskOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskOptions").finish_non_exhaustive()
    }
}

impl TaskOptions {
    /// A task that will run `entry`.
    pub fn new(entry: impl FnOnce() + Send + 'static) -> Self {
        Self {
            entry: Box::new(entry),
            data: Box::new(()),
        }
    }

    /// Attaches data the kernel can retrieve with [`Task::data`].
    pub fn data(mut self, data: impl Any + Send + Sync) -> Self {
        self.data = Box::new(data);
        self
    }

    /// Creates the task without starting it.
    pub fn build(self) -> Option<Arc<Task>> {
        self.build_inner(false)
    }

    fn build_inner(self, is_idle: bool) -> Option<Arc<Task>> {
        let reused = STACK_POOL.lock().pop();
        let top = match reused {
            Some(t) => t,
            None => kspace::alloc_stack()?,
        };
        // SAFETY: `top` is the top of a mapped kernel stack owned by this new
        // task alone (fresh, or returned to the pool by a dropped task).
        let sp = unsafe { switch::prepare_stack(top, task_entry) };
        Some(Arc::new(Task {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            saved_rsp: AtomicU64::new(sp),
            stack_top: top,
            running_on: AtomicU32::new(NOT_RUNNING),
            state: AtomicU8::new(TaskState::Runnable as u8),
            queued: AtomicBool::new(false),
            is_idle,
            entry: SpinLock::new(Some(self.entry)),
            data: self.data,
            vm_root: AtomicU64::new(0),
        }))
    }

    /// Creates the task and hands it to the scheduler.
    pub fn spawn(self) -> Option<Arc<Task>> {
        let t = self.build()?;
        enqueue(t.clone(), Enqueue::Spawned);
        Some(t)
    }
}

/// First code a new task runs (via `prepare_stack`).
extern "sysv64" fn task_entry() -> ! {
    finish_switch();
    arch::restore_interrupts(true);
    let me = current();
    let entry = me.entry.lock().take();
    drop(me);
    if let Some(f) = entry {
        f();
    }
    exit()
}

/// Adopts the currently executing context as a task (no stack of its own).
fn adopt(is_idle: bool) -> Arc<Task> {
    Arc::new(Task {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        saved_rsp: AtomicU64::new(0),
        stack_top: 0,
        running_on: AtomicU32::new(cpu::current().index() as u32),
        state: AtomicU8::new(TaskState::Runnable as u8),
        queued: AtomicBool::new(false),
        is_idle,
        entry: SpinLock::new(None),
        data: Box::new(()),
        vm_root: AtomicU64::new(0),
    })
}

/// The task running on this CPU. The first call on a CPU adopts whatever is
/// running (e.g. the kernel's main function) as a task.
pub fn current() -> Arc<Task> {
    let g = IrqGuard::new();
    let mut cur = SCHED.get(&g).current.lock();
    cur.get_or_insert_with(|| adopt(false)).clone()
}

fn idle_task(g: &IrqGuard) -> Option<Arc<Task>> {
    let mut idle = SCHED.get(g).idle.lock();
    if idle.is_none() {
        *idle = Some(TaskOptions::new(|| idle_loop()).build_inner(true)?);
    }
    idle.clone()
}

/// Runs this CPU's idle loop in the current context forever, making it the
/// CPU's idle task. For APs once they are ready to take work.
pub fn become_idle() -> ! {
    {
        let g = IrqGuard::new();
        let me = adopt(true);
        *SCHED.get(&g).idle.lock() = Some(me.clone());
        let mut cur = SCHED.get(&g).current.lock();
        if cur.is_none() {
            *cur = Some(me);
        }
    }
    idle_loop()
}

fn idle_loop() -> ! {
    loop {
        // Returns with interrupts masked when there is nothing to run, so a
        // kick arriving now is held pending until the `sti; hlt` below and
        // cannot be lost.
        schedule_inner(Enqueue::Yielded, true);
        arch::enable_and_halt();
    }
}

/// Gives up the CPU to another runnable task, if any.
pub fn yield_now() {
    crate::irq::assert_not_atomic("yield");
    schedule(Enqueue::Yielded);
}

/// Ends the current task.
pub fn exit() -> ! {
    crate::irq::assert_not_atomic("exit a task");
    current()
        .state
        .store(TaskState::Exited as u8, Ordering::SeqCst);
    loop {
        // An exited task is never requeued or run again, so this does not
        // return; loop defensively in case nothing else could be found.
        schedule(Enqueue::Yielded);
    }
}

/// Blocks the current task until [`Task::wake`]. If `still_needed` returns
/// false after the task is marked blocked (the wake-up already happened),
/// returns immediately instead of sleeping.
fn block_current(still_needed: impl FnOnce() -> bool) {
    crate::irq::assert_not_atomic("block");
    let me = current();
    me.state.store(TaskState::Blocked as u8, Ordering::SeqCst);
    if !still_needed() {
        // Either we undo the block, or a waker already did (it saw us still
        // on this CPU, so it did not enqueue us). Both leave us runnable
        // and not queued, so we carry on.
        let _ = me.state.compare_exchange(
            TaskState::Blocked as u8,
            TaskState::Runnable as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        return;
    }
    drop(me);
    schedule(Enqueue::Yielded);
}

fn schedule(why: Enqueue) {
    schedule_inner(why, false);
}

/// Takes the next task from the scheduler and claims it for `cpu`. Exited
/// tasks and tasks running elsewhere (a policy bug) are dropped.
fn pick_and_claim(s: &dyn Scheduler, cpu: CpuId) -> Option<Arc<Task>> {
    loop {
        let t = s.pick_next(cpu)?;
        t.queued.store(false, Ordering::SeqCst);
        if t.state() == TaskState::Exited {
            continue;
        }
        if t.running_on
            .compare_exchange(
                NOT_RUNNING,
                cpu.index() as u32,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_err()
        {
            continue;
        }
        if t.state() == TaskState::Exited {
            t.running_on.store(NOT_RUNNING, Ordering::SeqCst);
            continue;
        }
        return Some(t);
    }
}

fn claim(t: &Task, cpu: CpuId) -> bool {
    t.running_on
        .compare_exchange(
            NOT_RUNNING,
            cpu.index() as u32,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok()
}

/// The core of the scheduler mechanism. With `from_idle`, returns with
/// interrupts still masked when there was nothing else to run.
fn schedule_inner(why: Enqueue, from_idle: bool) {
    let Some(sched) = scheduler() else { return };
    let irq = arch::save_and_disable_interrupts();
    let cpu = cpu::current();
    let (cur, idle) = {
        let g = IrqGuard::new();
        let s = SCHED.get(&g);
        s.need_resched.store(false, Ordering::Relaxed);
        let cur = s.current.lock().get_or_insert_with(|| adopt(false)).clone();
        (cur, idle_task(&g))
    };
    let runnable = cur.state() == TaskState::Runnable;
    let next = match pick_and_claim(sched, cpu) {
        Some(n) => n,
        None if runnable => {
            // Nothing else to run: the current task continues.
            if !cur.is_idle {
                crate::time::arm_slice(sched.timeslice());
            }
            if !from_idle {
                arch::restore_interrupts(irq);
            }
            return;
        }
        None => match idle.filter(|i| !Arc::ptr_eq(i, &cur) && claim(i, cpu)) {
            Some(i) => i,
            None => {
                // Cannot happen (an idle task always exists and is not
                // running while another task runs on its CPU).
                arch::restore_interrupts(irq);
                return;
            }
        },
    };
    let next_rsp = next.saved_rsp.load(Ordering::SeqCst);
    let next_root = next.vm_root();
    let next_is_idle = next.is_idle;
    let requeue = (runnable && !cur.is_idle).then_some(why);
    {
        let g = IrqGuard::new();
        let s = SCHED.get(&g);
        *s.prev.lock() = Some((cur.clone(), requeue));
        *s.current.lock() = Some(next);
    }
    arch::activate_root(next_root);
    if !next_is_idle {
        crate::time::arm_slice(sched.timeslice());
    }
    let save = cur.saved_rsp.as_ptr();
    drop(cur);
    // SAFETY: `save` points into the current task's `Task`, kept alive by
    // the reference now stored in this CPU's `prev` slot until
    // `finish_switch` runs on the next task. `next_rsp` was saved by an
    // earlier switch away from `next` (or by `prepare_stack`); `next` is
    // claimed for this CPU, fully switched out (it was queued, or is this
    // CPU's idle task), and its stack is mapped.
    unsafe { switch::switch_stacks(save, next_rsp) };
    // Back in the task that called `schedule`.
    finish_switch();
    if !from_idle {
        arch::restore_interrupts(irq);
    }
}

/// Runs on the incoming task right after a switch: releases the outgoing
/// task, then requeues it if it is still runnable (now that no CPU is
/// running it).
fn finish_switch() {
    let prev = {
        let g = IrqGuard::new();
        SCHED.get(&g).prev.lock().take()
    };
    let Some((p, requeue)) = prev else { return };
    p.running_on.store(NOT_RUNNING, Ordering::SeqCst);
    // Requeue if it yielded or was preempted, or if a waker made it
    // runnable while it was still switching out (the waker saw it running
    // and left the enqueue to us).
    let why = match requeue {
        Some(why) => Some(why),
        None if p.state() == TaskState::Runnable => Some(Enqueue::Woken),
        None => None,
    };
    if let Some(why) = why {
        enqueue(p, why);
    }
}

/// Scheduler tick from the timer interrupt (interrupts masked).
pub(crate) fn on_tick() {
    let Some(sched) = scheduler() else { return };
    let g = IrqGuard::new();
    TICKS.get(&g).fetch_add(1, Ordering::Relaxed);
    let s = SCHED.get(&g);
    let cur = s.current.lock().clone();
    if let Some(cur) = cur
        && !cur.is_idle
    {
        if sched.tick(g.cpu(), &cur) {
            s.need_resched.store(true, Ordering::Relaxed);
        }
        // Always keep the slice armed while a real task runs: if the
        // preemption this tick asks for ends up continuing the same task,
        // the next tick must still come.
        crate::time::arm_slice(sched.timeslice());
    }
}

/// Called at the end of an interrupt that arrived while interrupts were
/// enabled and no guard was live: preempts if a tick asked for it.
pub(crate) fn preempt_point() {
    let need = {
        let g = IrqGuard::new();
        SCHED.get(&g).need_resched.load(Ordering::Relaxed)
    };
    if need && cpu::atomic_depth() == 0 {
        {
            let g = IrqGuard::new();
            PREEMPTIONS.get(&g).fetch_add(1, Ordering::Relaxed);
        }
        schedule(Enqueue::Preempted);
    }
}

/// Diagnostic snapshot of one CPU's scheduling state.
#[derive(Clone, Copy, Debug)]
pub struct CpuSnapshot {
    pub current: Option<u64>,
    pub current_state: Option<TaskState>,
    pub current_is_idle: bool,
    pub need_resched: bool,
    pub ticks: u64,
    pub preemptions: u64,
}

/// Reads `cpu`'s scheduling state (racy; for diagnostics).
pub fn snapshot(cpu: CpuId) -> CpuSnapshot {
    let s = SCHED.get_on(cpu);
    let cur = s.current.lock().clone();
    CpuSnapshot {
        current: cur.as_ref().map(|t| t.id),
        current_state: cur.as_ref().map(|t| t.state()),
        current_is_idle: cur.as_ref().is_some_and(|t| t.is_idle),
        need_resched: s.need_resched.load(Ordering::Relaxed),
        ticks: TICKS.get_on(cpu).load(Ordering::Relaxed),
        preemptions: PREEMPTIONS.get_on(cpu).load(Ordering::Relaxed),
    }
}

/// A queue of tasks waiting for a condition.
pub struct WaitQueue {
    waiters: SpinLock<VecDeque<Arc<Task>>>,
}

impl fmt::Debug for WaitQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitQueue").finish_non_exhaustive()
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            waiters: SpinLock::new(VecDeque::new()),
        }
    }

    /// Sleeps until `cond` returns `Some`, re-checking after every wake-up.
    pub fn wait_until<T>(&self, mut cond: impl FnMut() -> Option<T>) -> T {
        loop {
            if let Some(v) = cond() {
                return v;
            }
            let me = current();
            self.waiters.lock().push_back(me.clone());
            drop(me);
            // Re-check after queueing so a wake between the check and the
            // queueing is not lost.
            let mut ready = None;
            block_current(|| {
                ready = cond();
                ready.is_none()
            });
            if let Some(v) = ready {
                return v;
            }
        }
    }

    /// Wakes one waiter.
    pub fn wake_one(&self) -> bool {
        loop {
            let Some(t) = self.waiters.lock().pop_front() else {
                return false;
            };
            if t.wake() {
                return true;
            }
        }
    }

    /// Wakes every waiter.
    pub fn wake_all(&self) -> usize {
        let all: Vec<_> = self.waiters.lock().drain(..).collect();
        all.iter().filter(|t| t.wake()).count()
    }
}
