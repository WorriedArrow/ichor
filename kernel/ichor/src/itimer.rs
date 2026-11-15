//! Interval timers: `setitimer`, `getitimer` and `alarm` (`ITIMER_REAL`,
//! which posts `SIGALRM`). Each process has at most one real timer; all of
//! them are kept in one table driven by one kernel task, which sleeps until
//! the earliest deadline or until a timer changes. A timer belongs to the
//! process (not a thread), survives `execve`, is not inherited by `fork`,
//! and is dropped when the process goes away.
//!
//! Partial: `ITIMER_VIRTUAL` and `ITIMER_PROF` (CPU-time timers) are
//! `EINVAL`; there are no POSIX `timer_create` timers yet.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use frame::sync::SpinLock;
use frame::task::{TaskOptions, WaitQueue};
use frame::time::now;

use crate::proc;
use crate::signal;

/// One armed timer: the next expiry (time since boot) and the reload.
#[derive(Clone, Copy, Debug)]
struct Timer {
    deadline: Duration,
    interval: Duration,
}

/// Armed timers by (cell, tgid).
static TIMERS: SpinLock<BTreeMap<(u64, u64), Timer>> = SpinLock::new(BTreeMap::new());
/// Bumped on every change, so the task re-reads the earliest deadline.
static GEN: AtomicU64 = AtomicU64::new(0);
static CHANGED: WaitQueue = WaitQueue::new();
static STARTED: AtomicBool = AtomicBool::new(false);

/// What `getitimer` reports: (time left, interval). Zero left means
/// disarmed.
pub(crate) fn get(cell: u64, tgid: u64) -> (Duration, Duration) {
    let t = now();
    TIMERS
        .lock()
        .get(&(cell, tgid))
        .map_or((Duration::ZERO, Duration::ZERO), |x| {
            // A due timer the task has not fired yet still counts as armed.
            let left = x.deadline.saturating_sub(t).max(Duration::from_micros(1));
            (left, x.interval)
        })
}

/// Arms (`value` > 0) or disarms the process's real timer; returns the
/// previous setting as [`get`] would. `None` if the timer task could not
/// be started.
pub(crate) fn set(
    cell: u64,
    tgid: u64,
    value: Duration,
    interval: Duration,
) -> Option<(Duration, Duration)> {
    if !value.is_zero() && !start() {
        return None;
    }
    let old = get(cell, tgid);
    {
        let mut timers = TIMERS.lock();
        if value.is_zero() {
            timers.remove(&(cell, tgid));
        } else {
            timers.insert(
                (cell, tgid),
                Timer {
                    deadline: now() + value,
                    interval,
                },
            );
        }
    }
    kick();
    Some(old)
}

/// The process is gone: forget its timer.
pub(crate) fn clear(cell: u64, tgid: u64) {
    if TIMERS.lock().remove(&(cell, tgid)).is_some() {
        kick();
    }
}

fn kick() {
    GEN.fetch_add(1, Ordering::AcqRel);
    CHANGED.wake_all();
}

/// Starts the timer task on first use.
fn start() -> bool {
    if STARTED.swap(true, Ordering::AcqRel) {
        return true;
    }
    if TaskOptions::new(run).spawn().is_none() {
        STARTED.store(false, Ordering::Release);
        return false;
    }
    true
}

fn run() {
    loop {
        let g = GEN.load(Ordering::Acquire);
        let t = now();
        let mut due = Vec::new();
        let next = {
            let mut timers = TIMERS.lock();
            timers.retain(|&k, x| {
                if x.deadline > t {
                    return true;
                }
                due.push(k);
                if x.interval.is_zero() {
                    return false;
                }
                // Reload; expiries missed while the machine was busy
                // collapse into one signal, as Linux's do.
                x.deadline += x.interval;
                if x.deadline <= t {
                    x.deadline = t + x.interval;
                }
                true
            });
            timers.values().map(|x| x.deadline).min()
        };
        for (cell, tgid) in due {
            if proc::send(cell, tgid, signal::SIGALRM).is_err() {
                TIMERS.lock().remove(&(cell, tgid));
            }
        }
        let changed = || (GEN.load(Ordering::Acquire) != g).then_some(());
        match next {
            Some(d) => {
                let _ = CHANGED.wait_until_deadline(d, changed);
            }
            None => CHANGED.wait_until(changed),
        }
    }
}
