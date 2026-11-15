//! Interrupt control for the current CPU.

use crate::arch;

/// Enables interrupts on this CPU. Frame installs the IDT and masks every
/// interrupt source it does not handle before the kernel runs.
///
/// Panics in atomic mode (while an `IrqGuard` or spinlock guard is live):
/// re-enabling interrupts there would allow preemption and migration while
/// per-CPU borrows are held.
pub fn enable_local() {
    assert_not_atomic("enable interrupts");
    arch::restore_interrupts(true);
}

/// Enables interrupts and sleeps until the next one arrives (atomically, so
/// a wake-up cannot be missed between the two). Panics in atomic mode.
pub fn enable_and_wait() {
    assert_not_atomic("wait for an interrupt");
    arch::enable_and_halt();
}

/// Panics if the CPU is in atomic mode.
#[allow(clippy::panic)] // Doing this is always a kernel bug.
pub(crate) fn assert_not_atomic(what: &str) {
    let depth = crate::cpu::atomic_depth();
    if depth != 0 {
        panic!("attempt to {what} in atomic mode ({depth} interrupt-masking guards live)");
    }
}

/// Interrupts received on vectors nothing handles (a sign of a
/// misconfigured device or a lost IPI).
pub fn unexpected_count() -> u64 {
    arch::apic::unexpected_irqs()
}
