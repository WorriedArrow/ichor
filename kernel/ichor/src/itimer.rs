//! Timers that send signals: `setitimer`, `getitimer` and `alarm`, and the
//! POSIX `timer_create` family. Those on wall-clock time are kept in one
//! table driven by one kernel task, which sleeps until the earliest deadline
//! or until a timer changes; those on CPU time (`ITIMER_VIRTUAL` and
//! `ITIMER_PROF`, the CPU-time clocks) are looked at as the process's
//! threads come back from user code, so they fire within a time slice. A
//! timer belongs to its process, is not inherited by `fork`, and is dropped
//! when the process goes away (POSIX ones at `execve` too).
//!
//! Partial: CPU time is user time only, so `ITIMER_PROF` counts as
//! `ITIMER_VIRTUAL` does.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use frame::sync::SpinLock;
use frame::task::{TaskOptions, WaitQueue};
use frame::time::now;

use crate::proc;
use crate::process::LinuxProcess;
use crate::signal::{self, Info};

const EINVAL: i64 = 22;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;

const SIGVTALRM: u32 = 26;
const SIGPROF: u32 = 27;

/// `setitimer`'s timers, as numbers no POSIX timer has.
pub(crate) const REAL: i32 = -1;
pub(crate) const VIRTUAL: i32 = -2;
pub(crate) const PROF: i32 = -3;

/// Most POSIX timers a process may have.
const MAX_TIMERS: usize = 1024;

/// What a timer measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Clock {
    /// Time since boot.
    Mono,
    /// Wall-clock time (kept as time since boot: the clock never steps).
    Real,
    /// The process's CPU time.
    Process,
    /// A thread's CPU time.
    Thread(u64),
}

impl Clock {
    fn is_cpu(self) -> bool {
        matches!(self, Clock::Process | Clock::Thread(_))
    }
}

/// Whom an expiry is sent to.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Notify {
    /// 0: nobody (`SIGEV_NONE`).
    pub(crate) sig: u32,
    /// A thread of the process, else the process.
    pub(crate) thread: Option<u64>,
    /// `si_value`.
    pub(crate) value: u64,
}

#[derive(Clone, Copy, Debug)]
struct Timer {
    clock: Clock,
    /// The next expiry, on its clock (time since boot, or CPU time).
    deadline: Option<Duration>,
    interval: Duration,
    notify: Notify,
    /// Expiries the last signal stands for besides its own.
    overrun: u32,
}

impl Timer {
    /// Moves past an expiry at `t`; returns what to send. Expiries missed
    /// while the machine was busy collapse into one signal, as Linux's do.
    fn expire(&mut self, t: Duration) -> Option<Notify> {
        let d = self.deadline.filter(|&d| d <= t)?;
        self.overrun = 0;
        self.deadline = None;
        if !self.interval.is_zero() {
            let missed = (t - d).as_nanos() / self.interval.as_nanos();
            self.overrun = u32::try_from(missed).unwrap_or(i32::MAX as u32);
            let periods = u32::try_from(missed + 1).unwrap_or(u32::MAX);
            self.deadline = Some(d.saturating_add(self.interval.saturating_mul(periods)));
        }
        Some(self.notify)
    }
}

/// A timer's process and number.
type Key = (u64, u64, i32);

/// Every timer, by (cell, tgid, number).
static TIMERS: SpinLock<BTreeMap<Key, Timer>> = SpinLock::new(BTreeMap::new());
/// Bumped on every change, so the task re-reads the earliest deadline.
static GEN: AtomicU64 = AtomicU64::new(0);
static CHANGED: WaitQueue = WaitQueue::new();
static STARTED: AtomicBool = AtomicBool::new(false);

/// The time now on `clock`, for a timer of `p`'s.
fn time_on(p: &LinuxProcess, clock: Clock) -> Duration {
    match clock {
        Clock::Mono | Clock::Real => now(),
        Clock::Process => Duration::from_nanos(p.group.cpu_ns()),
        Clock::Thread(tid) => Duration::from_nanos(
            proc::find(p.entry.cell, tid).map_or(0, |e| e.cpu_ns.load(Ordering::Relaxed)),
        ),
    }
}

/// (time left, interval) of a timer at `t`; zero left means disarmed. A due
/// timer that has not fired yet still counts as armed.
fn setting(x: &Timer, t: Duration) -> (Duration, Duration) {
    match x.deadline {
        Some(d) => (
            d.saturating_sub(t).max(Duration::from_micros(1)),
            x.interval,
        ),
        None => (Duration::ZERO, x.interval),
    }
}

/// The process's timer `id`, as (time left, interval).
pub(crate) fn get(p: &LinuxProcess, id: i32) -> Option<(Duration, Duration)> {
    let key = (p.entry.cell, p.group.tgid, id);
    let x = *TIMERS.lock().get(&key)?;
    Some(setting(&x, time_on(p, x.clock)))
}

/// Arms (`value` > 0) or disarms the process's timer `id`; returns the
/// previous setting as [`get`] would. `absolute`: `value` is a time on the
/// timer's clock.
pub(crate) fn set(
    p: &LinuxProcess,
    id: i32,
    value: Duration,
    interval: Duration,
    absolute: bool,
) -> Result<(Duration, Duration), i64> {
    let key = (p.entry.cell, p.group.tgid, id);
    let clock = TIMERS.lock().get(&key).map(|x| x.clock).ok_or(EINVAL)?;
    if !value.is_zero() && !clock.is_cpu() && !start() {
        return Err(ENOMEM);
    }
    let t = time_on(p, clock);
    let deadline = match (value.is_zero(), absolute, clock) {
        (true, ..) => None,
        (_, false, _) => Some(t.saturating_add(value)),
        (_, true, Clock::Real) => {
            Some(t.saturating_add(value.saturating_sub(crate::vfs::wall_clock())))
        }
        (_, true, _) => Some(value),
    };
    let old = {
        let mut timers = TIMERS.lock();
        let x = timers.get_mut(&key).ok_or(EINVAL)?;
        let old = setting(x, t);
        x.deadline = deadline;
        x.interval = interval;
        x.overrun = 0;
        old
    };
    if clock.is_cpu() {
        publish(p);
    } else {
        kick();
    }
    Ok(old)
}

/// `setitimer`'s timer `id`, made on first use.
pub(crate) fn set_itimer(
    p: &LinuxProcess,
    id: i32,
    value: Duration,
    interval: Duration,
) -> Result<(Duration, Duration), i64> {
    let (clock, sig) = match id {
        REAL => (Clock::Mono, signal::SIGALRM),
        VIRTUAL => (Clock::Process, SIGVTALRM),
        _ => (Clock::Process, SIGPROF),
    };
    TIMERS
        .lock()
        .entry((p.entry.cell, p.group.tgid, id))
        .or_insert(Timer {
            clock,
            deadline: None,
            interval: Duration::ZERO,
            notify: Notify {
                sig,
                thread: None,
                value: 0,
            },
            overrun: 0,
        });
    set(p, id, value, interval, false)
}

/// A new, disarmed POSIX timer; its number. `notify` gets that number, for
/// a default `si_value`.
pub(crate) fn create(
    p: &LinuxProcess,
    clock: Clock,
    notify: impl FnOnce(i32) -> Notify,
) -> Result<i32, i64> {
    let (cell, tgid) = (p.entry.cell, p.group.tgid);
    let mut timers = TIMERS.lock();
    let range = (cell, tgid, 0)..=(cell, tgid, i32::MAX);
    let mine: Vec<i32> = timers.range(range).map(|(k, _)| k.2).collect();
    if mine.len() >= MAX_TIMERS {
        return Err(EAGAIN);
    }
    let id = mine
        .iter()
        .enumerate()
        .find(|&(n, &id)| id != n as i32)
        .map_or(mine.len() as i32, |(n, _)| n as i32);
    timers.insert(
        (cell, tgid, id),
        Timer {
            clock,
            deadline: None,
            interval: Duration::ZERO,
            notify: notify(id),
            overrun: 0,
        },
    );
    Ok(id)
}

/// Whether the process has POSIX timer `id`; its overrun count.
pub(crate) fn overrun(p: &LinuxProcess, id: i32) -> Result<u32, i64> {
    let key = (p.entry.cell, p.group.tgid, id);
    TIMERS.lock().get(&key).map(|x| x.overrun).ok_or(EINVAL)
}

/// Deletes POSIX timer `id`.
pub(crate) fn delete(p: &LinuxProcess, id: i32) -> Result<(), i64> {
    let key = (p.entry.cell, p.group.tgid, id);
    TIMERS.lock().remove(&key).map(|_| ()).ok_or(EINVAL)?;
    publish(p);
    kick();
    Ok(())
}

/// `execve`: the process's POSIX timers go (its interval timers stay).
pub(crate) fn exec(p: &LinuxProcess) {
    let (cell, tgid) = (p.entry.cell, p.group.tgid);
    TIMERS
        .lock()
        .retain(|&(c, g, id), _| (c, g) != (cell, tgid) || id < 0);
    publish(p);
    kick();
}

/// The process is gone: forget its timers.
pub(crate) fn clear(cell: u64, tgid: u64) {
    let had = {
        let mut timers = TIMERS.lock();
        let n = timers.len();
        timers.retain(|&(c, g, _), _| (c, g) != (cell, tgid));
        timers.len() != n
    };
    if had {
        kick();
    }
}

/// Publishes when the process's CPU-time timers are next due, for its
/// threads to look at cheaply ([`check_cpu`]).
fn publish(p: &LinuxProcess) {
    let mut due = u64::MAX;
    {
        let timers = TIMERS.lock();
        let range = (p.entry.cell, p.group.tgid, i32::MIN)..=(p.entry.cell, p.group.tgid, i32::MAX);
        for x in timers.range(range).map(|(_, x)| x) {
            if let (true, Some(d)) = (x.clock.is_cpu(), x.deadline) {
                // A thread's clock runs no faster than its process's, so
                // its deadline is a safe time to look.
                due = due.min(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
            }
        }
    }
    set_due(&p.entry.shared.cpu_due, due);
}

/// Processes with a CPU-time timer armed.
static CPU_TIMED: AtomicU64 = AtomicU64::new(0);

/// Whether some process has a CPU-time timer armed: then every slice's end
/// takes user code into the kernel, even if nothing else wants the CPU, for
/// [`check_cpu`] to look.
pub(crate) fn watching_cpu_time() -> bool {
    CPU_TIMED.load(Ordering::Relaxed) > 0
}

/// Sets a process's `cpu_due` (`u64::MAX`: nothing armed).
pub(crate) fn set_due(cpu_due: &AtomicU64, due: u64) {
    let old = cpu_due.swap(due, Ordering::AcqRel);
    match (old == u64::MAX, due == u64::MAX) {
        (true, false) => {
            CPU_TIMED.fetch_add(1, Ordering::Relaxed);
        }
        (false, true) => {
            CPU_TIMED.fetch_sub(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

/// Fires the CPU-time timers of `p`'s process that are due. Called as a
/// thread comes back from user code.
pub(crate) fn check_cpu(p: &LinuxProcess) {
    let due = p.entry.shared.cpu_due.load(Ordering::Acquire);
    if due == u64::MAX {
        return;
    }
    let process = p.group.cpu_ns();
    if process < due {
        return;
    }
    let mut fired = Vec::new();
    {
        let threads = p.group.threads();
        let mut timers = TIMERS.lock();
        let range = (p.entry.cell, p.group.tgid, i32::MIN)..=(p.entry.cell, p.group.tgid, i32::MAX);
        for (&(_, _, id), x) in timers.range_mut(range) {
            let t = match x.clock {
                Clock::Process => process,
                Clock::Thread(tid) => threads
                    .iter()
                    .find(|e| e.pid == tid)
                    .map_or(0, |e| e.cpu_ns.load(Ordering::Relaxed)),
                _ => continue,
            };
            if let Some(n) = x.expire(Duration::from_nanos(t)) {
                fired.push((id, n, x.overrun));
            }
        }
    }
    publish(p);
    for (id, n, overrun) in fired {
        send(p.entry.cell, p.group.tgid, id, n, overrun);
    }
}

/// Sends what an expiry of timer `id` sends; false if the process is gone.
fn send(cell: u64, tgid: u64, id: i32, n: Notify, overrun: u32) -> bool {
    if n.sig == 0 {
        return true;
    }
    let info = if id < 0 {
        Info::kernel()
    } else {
        Info::timer(id, overrun, n.value)
    };
    match n.thread {
        // A thread that has ended takes its signals with it.
        Some(tid) => {
            let _ = proc::send_thread(cell, Some(tgid), tid, n.sig, info);
            true
        }
        None => proc::send_info(cell, tgid, n.sig, info).is_ok(),
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
            let mut next: Option<Duration> = None;
            for (&k, x) in timers.iter_mut().filter(|(_, x)| !x.clock.is_cpu()) {
                if let Some(n) = x.expire(t) {
                    due.push((k, n, x.overrun));
                }
                next = match (next, x.deadline) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
            next
        };
        for ((cell, tgid, id), n, overrun) in due {
            if !send(cell, tgid, id, n, overrun) {
                TIMERS.lock().remove(&(cell, tgid, id));
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
