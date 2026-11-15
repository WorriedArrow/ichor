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
}

frame::cpu_local! {
    static CPUS: PerCpu = PerCpu {
        rq: SpinLock::new(RunQueue::new()),
        since: AtomicU64::new(0),
        group: AtomicU64::new(NO_GROUP),
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
        CPUS.get_on(target).rq.lock().enqueue(group, weight, task);
        if target != here {
            task::kick(target);
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
        // Preempt only if someone else is waiting on this CPU.
        !CPUS.get_on(cpu).rq.lock().is_empty()
    }

    fn timeslice(&self) -> Duration {
        TIMESLICE
    }
}

pub(crate) static SCHEDULER: FairScheduler = FairScheduler;

/// Runnable tasks queued on `cpu` (diagnostics).
pub(crate) fn queue_len(cpu: CpuId) -> usize {
    CPUS.get_on(cpu).rq.lock().len()
}
