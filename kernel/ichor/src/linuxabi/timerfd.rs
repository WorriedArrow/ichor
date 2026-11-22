//! Timers and signals as descriptors: `timerfd_create` and `signalfd`.
//!
//! A timer descriptor keeps its next expiry; how many have passed is worked
//! out when it is looked at, and the timer task ([`crate::itimer`]) wakes
//! whoever waits when the next one comes. A periodic timer asks to be woken
//! again once it has been read, as on Linux.
//!
//! Partial: `TFD_TIMER_CANCEL_ON_SET` is accepted (the clock never steps).
//! A signal descriptor takes the signals of the process that made it, also
//! from a child that inherited it.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use frame::sync::SpinLock;
use frame::time::now;

use super::fs::{O_CLOEXEC, O_NONBLOCK};
use super::socket::block_on;
use super::{EBADF, EFAULT, EINVAL, EMFILE, le_u64};
use crate::itimer::{self, Expires};
use crate::netstack::Waiters;
use crate::poll::{Object, POLLIN, Watchers, read_timespec};
use crate::proc::{self, ProcEntry};
use crate::process::{Fd, LinuxProcess, ObjectEnd};
use crate::signal;

#[derive(Debug, Default)]
struct Setting {
    /// The next expiry (time since boot) not read yet.
    due: Option<Duration>,
    interval: Duration,
}

impl Setting {
    /// Expiries up to `t` that were not read.
    fn expired(&self, t: Duration) -> u64 {
        match self.due {
            Some(d) if d <= t && self.interval.is_zero() => 1,
            Some(d) if d <= t => {
                let more = (t - d).as_nanos() / self.interval.as_nanos();
                u64::try_from(more).unwrap_or(u64::MAX - 1) + 1
            }
            _ => 0,
        }
    }

    /// Takes the expiries up to `t`.
    fn take(&mut self, t: Duration) -> u64 {
        let n = self.expired(t);
        if n > 0 {
            self.due = self.due.filter(|_| !self.interval.is_zero()).map(|d| {
                let n = u32::try_from(n).unwrap_or(u32::MAX);
                d.saturating_add(self.interval.saturating_mul(n))
            });
        }
        n
    }
}

/// A timer descriptor.
#[derive(Debug)]
pub(crate) struct TimerFd {
    me: Weak<TimerFd>,
    id: u64,
    /// Absolute times are wall-clock time.
    real: bool,
    setting: SpinLock<Setting>,
    wait: Waiters,
}

impl TimerFd {
    /// Asks to be woken at the next expiry, if there is one.
    fn arm(&self, due: Option<Duration>) {
        if let Some(d) = due {
            itimer::wake_at(d, self.id, self.me.clone());
        }
    }
}

impl Expires for TimerFd {
    fn expired(&self) {
        self.wait.wake();
    }
}

impl Object for TimerFd {
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        if max < 8 {
            return Err(EINVAL);
        }
        let n = block_on(&self.wait, nonblock, 0, interrupted, || {
            match self.setting.lock().take(now()) {
                0 => None,
                n => Some(Ok(n)),
            }
        })?;
        let due = self.setting.lock().due;
        self.arm(due);
        Ok(n.to_le_bytes().to_vec())
    }

    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(EINVAL)
    }

    fn poll(&self) -> u16 {
        if self.setting.lock().expired(now()) > 0 {
            POLLIN
        } else {
            0
        }
    }

    fn changes(&self) -> u64 {
        self.wait.changes.load(Ordering::Acquire)
    }

    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.wait.watchers)
    }

    fn timerfd(&self) -> Option<&TimerFd> {
        Some(self)
    }
}

fn install(p: &mut LinuxProcess, obj: Arc<dyn Object>, flags: u64) -> Result<u64, i64> {
    p.install_flags(
        Fd::Object(ObjectEnd {
            obj,
            nonblock: flags & O_NONBLOCK != 0,
        }),
        flags & O_CLOEXEC != 0,
    )
    .ok_or(EMFILE)
}

fn timer_of(p: &LinuxProcess, fd: u64) -> Result<Arc<dyn Object>, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Object(o) if o.obj.timerfd().is_some() => Ok(o.obj),
        _ => Err(EINVAL),
    }
}

/// `timerfd_create(clock, flags)`.
pub(super) fn create(p: &mut LinuxProcess, clock: u64, flags: u64) -> Result<u64, i64> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let real = match clock {
        0 | 8 => true, // REALTIME, REALTIME_ALARM
        1 | 7 | 9 => false,
        _ => return Err(EINVAL),
    };
    let t = Arc::new_cyclic(|me| TimerFd {
        me: me.clone(),
        id: NEXT.fetch_add(1, Ordering::Relaxed),
        real,
        setting: SpinLock::new(Setting::default()),
        wait: Waiters::default(),
    });
    install(p, t, flags)
}

/// (time left, interval), as `timerfd_gettime` reports.
fn setting(t: &TimerFd) -> (Duration, Duration) {
    let s = t.setting.lock();
    let at = now();
    // As Linux: the time to the next expiry after those that have passed
    // (which stay to be read).
    let n = s.expired(at);
    let next = match (s.due, n) {
        (Some(d), 0) => Some(d),
        (Some(d), n) if !s.interval.is_zero() => {
            let n = u32::try_from(n).unwrap_or(u32::MAX);
            Some(d.saturating_add(s.interval.saturating_mul(n)))
        }
        _ => None,
    };
    let left = next.map_or(Duration::ZERO, |d| {
        d.saturating_sub(at).max(Duration::from_nanos(1))
    });
    (left, s.interval)
}

/// `timerfd_settime(fd, flags, new, old)`.
pub(super) fn settime(
    p: &mut LinuxProcess,
    fd: u64,
    flags: u64,
    new: u64,
    old: u64,
) -> Result<u64, i64> {
    const ABSTIME: u64 = 1;
    const CANCEL_ON_SET: u64 = 2;
    if flags & !(ABSTIME | CANCEL_ON_SET) != 0 {
        return Err(EINVAL);
    }
    let obj = timer_of(p, fd)?;
    let t = obj.timerfd().ok_or(EINVAL)?;
    let interval = read_timespec(p, new)?;
    let value = read_timespec(p, new + 16)?;
    let at = now();
    let due = match (value.is_zero(), flags & ABSTIME != 0) {
        (true, _) => None,
        (_, false) => Some(at.saturating_add(value)),
        (_, true) if t.real => {
            Some(at.saturating_add(value.saturating_sub(crate::vfs::wall_clock())))
        }
        (_, true) => Some(value),
    };
    let was = setting(t);
    *t.setting.lock() = Setting { due, interval };
    if due.is_some() && !itimer::start() {
        return Err(12); // ENOMEM
    }
    t.arm(due);
    if old != 0 {
        super::put_itimerspec(p, old, was)?;
    }
    Ok(0)
}

/// `timerfd_gettime(fd, curr)`.
pub(super) fn gettime(p: &mut LinuxProcess, fd: u64, curr: u64) -> Result<u64, i64> {
    let obj = timer_of(p, fd)?;
    let was = setting(obj.timerfd().ok_or(EINVAL)?);
    super::put_itimerspec(p, curr, was)?;
    Ok(0)
}

/// A signal descriptor.
#[derive(Debug)]
pub(crate) struct SignalFd {
    entry: Arc<ProcEntry>,
    mask: AtomicU64,
}

impl Object for SignalFd {
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        const RECORD: usize = 128;
        const EAGAIN: i64 = 11;
        if max < RECORD {
            return Err(EINVAL);
        }
        let set = self.mask.load(Ordering::Acquire);
        let first = match proc::take_signal(&self.entry, set) {
            Some(s) => s,
            None if nonblock => return Err(EAGAIN),
            None => proc::wait_signal(&self.entry, set, interrupted)?,
        };
        let mut out = signal::signalfd_record(first.0, &first.1).to_vec();
        while out.len() + RECORD <= max {
            let Some((sig, info)) = proc::take_signal(&self.entry, set) else {
                break;
            };
            out.extend_from_slice(&signal::signalfd_record(sig, &info));
        }
        Ok(out)
    }

    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(EINVAL)
    }

    fn poll(&self) -> u16 {
        if proc::pending(&self.entry) & self.mask.load(Ordering::Acquire) != 0 {
            POLLIN
        } else {
            0
        }
    }

    fn changes(&self) -> u64 {
        self.entry.shared.posted.load(Ordering::Acquire)
    }

    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.entry.shared.arrivals)
    }

    fn signalfd(&self) -> Option<&SignalFd> {
        Some(self)
    }
}

/// `signalfd4(fd, mask, size, flags)`: a new one for fd -1, else another
/// mask for that one.
pub(super) fn signalfd(
    p: &mut LinuxProcess,
    fd: i64,
    mask: u64,
    size: u64,
    flags: u64,
) -> Result<u64, i64> {
    if size != 8 || flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let mut b = [0u8; 8];
    if p.copy_from_user(mask, &mut b) != 8 {
        return Err(EFAULT);
    }
    let mask = le_u64(&b) & !(signal::bit(signal::SIGKILL) | signal::bit(signal::SIGSTOP));
    if fd == -1 {
        let s = SignalFd {
            entry: p.entry.clone(),
            mask: AtomicU64::new(mask),
        };
        return install(p, Arc::new(s), flags);
    }
    match p.fd(fd as u64).ok_or(EBADF)? {
        Fd::Object(o) => {
            let s = o.obj.signalfd().ok_or(EINVAL)?;
            s.mask.store(mask, Ordering::Release);
            Ok(fd as u64)
        }
        _ => Err(EINVAL),
    }
}
