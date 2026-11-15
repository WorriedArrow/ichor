//! Time: a monotonic clock and per-CPU one-shot timers.
//!
//! The clock is the TSC, whose frequency frame determines at boot. Timers
//! are tickless: a CPU's timer interrupt fires only when armed, and the
//! handler (installed once, for every CPU) decides whether to re-arm. The
//! scheduler (milestone 2) becomes that handler.

use core::time::Duration;

use crate::arch::apic;

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

/// Arms the current CPU's timer to fire once after `delay`.
pub fn arm_timer(delay: Duration) {
    apic::arm_timer_ns(u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX));
}

/// Busy-waits for `d`.
pub fn spin_for(d: Duration) {
    apic::delay_us(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
}
