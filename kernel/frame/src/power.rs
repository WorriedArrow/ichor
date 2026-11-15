//! Halting and shutting down the machine.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch;

/// Set during boot when the command line contains `qemu_debug_exit`.
static QEMU_DEBUG_EXIT: AtomicBool = AtomicBool::new(false);

pub(crate) fn enable_qemu_debug_exit() {
    QEMU_DEBUG_EXIT.store(true, Ordering::Relaxed);
}

/// Outcome reported when the kernel stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// The kernel finished what it was asked to do (for example, a test run).
    Success,
    /// The kernel stopped because something went wrong.
    Failure,
}

/// Stops the machine.
///
/// Under QEMU with `qemu_debug_exit` on the command line, this terminates the
/// VM with a status the test harness understands. Otherwise every CPU that
/// calls it halts. (ACPI power-off arrives with ACPI support in milestone 1.)
pub fn shutdown(status: ExitStatus) -> ! {
    if QEMU_DEBUG_EXIT.load(Ordering::Relaxed) {
        arch::qemu::exit(match status {
            ExitStatus::Success => arch::qemu::EXIT_SUCCESS,
            ExitStatus::Failure => arch::qemu::EXIT_FAILURE,
        });
    }
    arch::halt_forever()
}
