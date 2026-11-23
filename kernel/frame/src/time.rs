//! Time: a monotonic clock and per-CPU one-shot timers.
//!
//! The clock is the TSC, whose frequency frame determines at boot. Timers
//! are tickless: a CPU's timer interrupt fires only when armed, and the
//! handler (installed once, for every CPU) decides whether to re-arm. The
//! scheduler (milestone 2) becomes that handler.

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

use crate::arch::apic;

/// The firmware's clock as read at boot: Unix seconds, nanoseconds, and
/// the TSC at the moment of reading.
static WALL_SECS: AtomicU64 = AtomicU64::new(0);
static WALL_NANOS: AtomicU32 = AtomicU32::new(0);
static WALL_TSC: AtomicU64 = AtomicU64::new(0);
static WALL_VALID: AtomicBool = AtomicBool::new(false);

/// Records the firmware clock reading (boot, before ExitBootServices).
pub(crate) fn set_boot_wall_clock(secs: u64, nanos: u32, tsc: u64) {
    WALL_SECS.store(secs, Ordering::Relaxed);
    WALL_NANOS.store(nanos, Ordering::Relaxed);
    WALL_TSC.store(tsc, Ordering::Relaxed);
    WALL_VALID.store(true, Ordering::Release);
}

/// How the wall clock is steered (by an NTP client, [`steer_wall_clock`]):
/// at monotonic time `STEER_AT` (ns) it is `STEER_BY` ns ahead of the
/// firmware's reading plus the monotonic clock, and gains `STEER_PPB`
/// parts per billion from then on. A sequence counter guards the three.
static STEER_SEQ: AtomicU64 = AtomicU64::new(0);
static STEER_AT: AtomicU64 = AtomicU64::new(0);
static STEER_BY: AtomicI64 = AtomicI64::new(0);
static STEER_PPB: AtomicI64 = AtomicI64::new(0);

/// The steering at monotonic time `t` (ns), and its parts.
fn steering(t: u64) -> (i64, u64, i64, i64) {
    loop {
        let s = STEER_SEQ.load(Ordering::Acquire);
        let (at, by) = (
            STEER_AT.load(Ordering::Relaxed),
            STEER_BY.load(Ordering::Relaxed),
        );
        let ppb = STEER_PPB.load(Ordering::Relaxed);
        if s & 1 == 0 && STEER_SEQ.load(Ordering::Acquire) == s {
            let gained = i128::from(t.saturating_sub(at)) * i128::from(ppb) / 1_000_000_000;
            return (by.saturating_add(gained as i64), at, by, ppb);
        }
        core::hint::spin_loop();
    }
}

/// Steers the wall clock: steps it by `step_ns` now, and from now on has it
/// gain `ppb` parts per billion on the monotonic clock (which timers keep
/// using, unsteered). One caller at a time.
pub fn steer_wall_clock(step_ns: i64, ppb: i64) {
    // A reader interrupting the write on this CPU would wait for it forever.
    let _irq = crate::cpu::IrqGuard::new();
    let t = apic::now_ns();
    let (by, ..) = steering(t);
    STEER_SEQ.fetch_add(1, Ordering::AcqRel);
    STEER_AT.store(t, Ordering::Relaxed);
    STEER_BY.store(by.saturating_add(step_ns), Ordering::Relaxed);
    STEER_PPB.store(ppb, Ordering::Relaxed);
    STEER_SEQ.fetch_add(1, Ordering::Release);
}

/// The time of day as time since the Unix epoch (UTC): the firmware's
/// clock as read at boot plus the monotonic clock since (kvmclock's on
/// KVM, so a migration does not make it drift), as steered by an NTP
/// client if one runs. `None` if the firmware had no clock to read.
pub fn wall_clock() -> Option<Duration> {
    if !WALL_VALID.load(Ordering::Acquire) {
        return None;
    }
    // From the reading to boot, by the TSC; from boot on, the clock.
    let hz = u128::from(tsc_hz().max(1));
    let before = u128::from(apic::tsc_at_boot().saturating_sub(WALL_TSC.load(Ordering::Relaxed)));
    let before = before * 1_000_000_000 / hz;
    let t = apic::now_ns();
    let secs = u128::from(WALL_SECS.load(Ordering::Relaxed)) * 1_000_000_000;
    let ns = secs + u128::from(WALL_NANOS.load(Ordering::Relaxed)) + before + u128::from(t);
    let ns = (ns as i128)
        .saturating_add(i128::from(steering(t).0))
        .max(0);
    Some(Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX)))
}

/// Time since boot.
pub fn now() -> Duration {
    Duration::from_nanos(apic::now_ns())
}

/// TSC frequency in Hz.
pub fn tsc_hz() -> u64 {
    apic::tsc_hz()
}

/// Installs the function every CPU runs on its timer interrupt. It runs
/// with interrupts masked and must not block.
pub fn set_timer_handler(handler: fn()) {
    apic::set_timer_handler(handler);
}

/// Arms the current CPU's timer to fire once after `delay`, calling the
/// handler from [`set_timer_handler`]. Independent of the scheduler's
/// timeslice timer.
pub fn arm_timer(delay: Duration) {
    apic::arm(
        apic::TimerKind::Kernel,
        u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX),
    );
}

/// Arms the current CPU's scheduler timeslice.
pub(crate) fn arm_slice(delay: Duration) {
    apic::arm(
        apic::TimerKind::Slice,
        u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX),
    );
}

/// Busy-waits for `d`.
pub fn spin_for(d: Duration) {
    apic::delay_us(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
}

/// `cpu`'s armed timer deadlines (scheduler slice, kernel timer, timed
/// waits) in nanoseconds from now; for diagnostics.
pub fn deadlines(cpu: crate::cpu::CpuId) -> [Option<i64>; 3] {
    apic::deadlines_ns(cpu)
}
