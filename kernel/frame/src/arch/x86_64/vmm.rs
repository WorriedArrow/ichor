//! Firecracker's boot timer, a port a guest writes once it has booted.

use super::io::outb;

/// Firecracker's boot-timer device (`--boot-timer`). Frame owns it; it is
/// written only when the command line asks (`boot_timer`).
const BOOT_TIMER_PORT: u16 = 0x3F0;
/// The byte that tells it the guest has booted.
const BOOT_COMPLETE: u8 = 123;

/// Tells Firecracker's boot timer that the guest is ready: it logs the time
/// since it started.
pub(crate) fn boot_complete() {
    // SAFETY: frame owns port 0x3F0. Under Firecracker it is the boot timer,
    // which only logs; elsewhere it is a floppy controller's status register
    // A, which is read-only, or nothing. The caller writes it only when the
    // operator asked on the command line.
    unsafe { outb(BOOT_TIMER_PORT, BOOT_COMPLETE) };
}
