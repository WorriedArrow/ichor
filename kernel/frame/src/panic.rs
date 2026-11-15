//! The kernel panic handler. A panic always means a kernel bug.

use core::sync::atomic::{AtomicBool, Ordering};

static PANICKING: AtomicBool = AtomicBool::new(false);

/// Whether some CPU is panicking (other CPUs halt when they see this).
pub(crate) fn in_progress() -> bool {
    PANICKING.load(Ordering::Relaxed)
}

#[cfg(target_os = "uefi")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use crate::arch;
    use crate::console::print_unlocked;
    use crate::power::{ExitStatus, shutdown};

    arch::disable_local_interrupts();
    if PANICKING.swap(true, Ordering::SeqCst) {
        // A second panic, here or on another CPU: stop without touching
        // anything else.
        arch::halt_forever();
    }
    // Stop the other CPUs so the report is the last thing that happens.
    if crate::cpu::online_count() > 1 {
        arch::apic::send_nmi_all_but_self();
    }
    print_unlocked(format_args!(
        "
ichor: KERNEL PANIC: {info}
"
    ));
    shutdown(ExitStatus::Failure)
}
