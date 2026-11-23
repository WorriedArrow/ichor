//! Time: a monotonic clock and per-CPU one-shot timers.
//!
//! The clock is the TSC, whose frequency frame determines at boot. Timers
//! are tickless: a CPU's timer interrupt fires only when armed, and the
//! handler (installed once, for every CPU) decides whether to re-arm. The
//! scheduler (milestone 2) becomes that handler.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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

/// The time of day as time since the Unix epoch (UTC): the firmware's
/// clock as read at boot plus the monotonic clock since (kvmclock's on
/// KVM, so a migration does not make it drift). `None` if the firmware had
/// no clock to read. Nothing disciplines it yet (no NTP).
pub fn wall_clock() -> Option<Duration> {
    if !WALL_VALID.load(Ordering::Acquire) {
        return None;
    }
    // From the reading to boot, by the TSC; from boot on, the clock.
    let hz = u128::from(tsc_hz().max(1));
    let before = u128::from(apic::tsc_at_boot().saturating_sub(WALL_TSC.load(Ordering::Relaxed)));
    let before = Duration::from_nanos(u64::try_from(before * 1_000_000_000 / hz).unwrap_or(0));
    Some(
        Duration::new(
            WALL_SECS.load(Ordering::Relaxed),
            WALL_NANOS.load(Ordering::Relaxed),
        )
        .saturating_add(before)
        .saturating_add(now()),
    )
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
