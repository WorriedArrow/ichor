//! Plugs the `sched` policy into frame's scheduler hook.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use core::time::Duration;

use frame::cpu::{self, CpuId};
use frame::sync::SpinLock;
use frame::task::{self, Enqueue, Scheduler, Task};
use sched::{DEFAULT_WEIGHT, GroupId, RunQueue};

/// Scheduling identity of a task, attached as its task data. Tasks without
/// one belong to the kernel's group 0.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SchedInfo {
    pub(crate) group: GroupId,
    pub(crate) weight: u32,
}

impl SchedInfo {
    pub(crate) const KERNEL: SchedInfo = SchedInfo {
        group: GroupId(0),
        weight: DEFAULT_WEIGHT,
    };

    /// A task of cell `cell`'s: cells share each CPU fairly, however many
    /// tasks each has.
    pub(crate) fn of_cell(cell: u64) -> SchedInfo {
        SchedInfo {
            group: GroupId(cell + 1),
            weight: DEFAULT_WEIGHT,
        }
    }
}

fn info(t: &Task) -> SchedInfo {
    t.data()
        .downcast_ref::<SchedInfo>()
        .copied()
        .unwrap_or(SchedInfo::KERNEL)
}

const NO_GROUP: u64 = u64::MAX;

struct PerCpu {
    rq: SpinLock<RunQueue<Arc<Task>>>,
    /// When the task picked last started running (ns since boot).
    since: AtomicU64,
    /// Group of the task picked last, or `NO_GROUP` when idle.
    group: AtomicU64,
    /// Scheduler ticks taken on this CPU ([`tick_mark`]).
    ticks: AtomicU64,
}

frame::cpu_local! {
    static CPUS: PerCpu = PerCpu {
        rq: SpinLock::new(RunQueue::new()),
        since: AtomicU64::new(0),
        group: AtomicU64::new(NO_GROUP),
        ticks: AtomicU64::new(0),
    };
}

/// Weighted fair share between groups, round-robin within a group, per-CPU
/// queues with work stealing.
#[derive(Debug)]
pub(crate) struct FairScheduler;

const TIMESLICE: Duration = Duration::from_millis(4);

fn now_ns() -> u64 {
    u64::try_from(frame::time::now().as_nanos()).unwrap_or(u64::MAX)
}

/// Wakes an idle CPU other than `here`, if there is one, to come and take
/// work: an idle CPU halts with no tick, and only looks when told to.
fn call_idle(here: CpuId) {
    let idle = cpu::online().find(|&c| c != here && CPUS.get_on(c).group.load(Relaxed) == NO_GROUP);
    if let Some(c) = idle {
        task::kick(c);
    }
}

impl Scheduler for FairScheduler {
    fn enqueue(&self, task: Arc<Task>, why: Enqueue) {
        let here = cpu::current();
        let target = match why {
            Enqueue::Spawned => {
                let loads = cpu::online().map(|c| (c.index(), CPUS.get_on(c).rq.lock().len()));
                cpu::online()
                    .nth(sched::least_loaded(loads, here.index()))
                    .unwrap_or(here)
            }
            _ => here,
        };
        let SchedInfo { group, weight } = info(&task);
        let waiting = {
            let mut rq = CPUS.get_on(target).rq.lock();
            rq.enqueue(group, weight, task);
            rq.len()
        };
        if target != here {
            task::kick(target);
        } else if waiting > 1 {
            // More than the current task's leaving will serve at once.
            call_idle(here);
        }
    }

    fn pick_next(&self, cpu: CpuId) -> Option<Arc<Task>> {
        let pc = CPUS.get_on(cpu);
        let now = now_ns();
        let mut rq = pc.rq.lock();
        let prev = pc.group.swap(NO_GROUP, Relaxed);
        if prev != NO_GROUP {
            rq.charge(GroupId(prev), now.saturating_sub(pc.since.load(Relaxed)));
        }
        pc.since.store(now, Relaxed);
        if let Some((g, t)) = rq.pick() {
            pc.group.store(g.0, Relaxed);
            return Some(t);
        }
        rq.prune(); // cells come and go
        drop(rq);
        // Nothing local: steal from the first busy CPU after this one.
        let n = cpu::online_count();
        for k in 1..n {
            let Some(other) = cpu::online().nth((cpu.index() + k) % n) else {
                continue;
            };
            let stolen = CPUS.get_on(other).rq.try_lock().and_then(|mut q| q.steal());
            if let Some((g, w, t)) = stolen {
                let mut rq = pc.rq.lock();
                rq.enqueue(g, w, t);
                let (g, t) = rq.pick()?;
                pc.group.store(g.0, Relaxed);
                return Some(t);
            }
        }
        None
    }

    fn tick(&self, cpu: CpuId, _current: &Arc<Task>) -> bool {
        CPUS.get_on(cpu).ticks.fetch_add(1, Relaxed);
        // Preempt only if someone else is waiting on this CPU, or a
        // CPU-time timer has to be looked at.
        let waiting = !CPUS.get_on(cpu).rq.lock().is_empty();
        if waiting {
            // A task woken here waits for this CPU, which did not become
            // free soon: one with nothing to do may have it. (Not asked as
            // it is woken: its waker often stops at once, and it then runs
            // here sooner than another CPU could wake up for it.)
            call_idle(cpu);
        }
        crate::itimer::watching_cpu_time() || waiting
    }

    fn timeslice(&self) -> Duration {
        TIMESLICE
    }
}

pub(crate) static SCHEDULER: FairScheduler = FairScheduler;

/// This CPU and the ticks it has taken: when it changes across a system
/// call, a tick came during it (or the task moved CPU), and CPU-time timers
/// are looked at as the call returns, as Linux does at a tick in the kernel
/// (`proc::run`).
pub(crate) fn tick_mark() -> u64 {
    let g = frame::cpu::IrqGuard::new();
    let cpu = g.cpu();
    (u64::from(cpu.index() as u32) << 48) | (CPUS.get_on(cpu).ticks.load(Relaxed) & ((1 << 48) - 1))
}

/// Runnable tasks queued on `cpu` (diagnostics).
pub(crate) fn queue_len(cpu: CpuId) -> usize {
    CPUS.get_on(cpu).rq.lock().len()
}
