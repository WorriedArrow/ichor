//! x86_64 implementation of the architecture boundary.

pub(crate) mod early_console;
mod io;
pub(crate) mod qemu;

use core::arch::asm;

/// Masks maskable interrupts on the current CPU.
pub fn disable_local_interrupts() {
    // SAFETY: `cli` only clears RFLAGS.IF. Frame code never relies on
    // interrupts being enabled for memory safety, so masking them is always
    // sound (at worst it delays interrupt delivery).
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// Stops the current CPU forever with interrupts masked.
///
/// NMIs and SMIs can still wake the CPU from `hlt`, so this loops.
pub fn halt_forever() -> ! {
    disable_local_interrupts();
    loop {
        // SAFETY: `hlt` pauses the CPU until the next interrupt. It has no
        // memory effects; with IF clear only NMI/SMI/INIT resume it, after
        // which we halt again.
        unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}
