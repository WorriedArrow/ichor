//! Interrupt control for the current CPU.

use crate::arch;

/// Enables interrupts on this CPU. Frame installs the IDT and masks every
/// interrupt source it does not handle before the kernel runs, so this is
/// always sound.
pub fn enable_local() {
    arch::restore_interrupts(true);
}

/// Enables interrupts and sleeps until the next one arrives (atomically, so
/// a wake-up cannot be missed between the two).
pub fn enable_and_wait() {
    arch::enable_and_halt();
}

/// Interrupts received on vectors nothing handles (a sign of a
/// misconfigured device or a lost IPI).
pub fn unexpected_count() -> u64 {
    arch::apic::unexpected_irqs()
}
