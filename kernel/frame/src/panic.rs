//! The kernel panic handler. A panic always means a kernel bug.

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch;
use crate::console::print_unlocked;
use crate::power::{ExitStatus, shutdown};

static PANICKING: AtomicBool = AtomicBool::new(false);

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    arch::disable_local_interrupts();
    if PANICKING.swap(true, Ordering::SeqCst) {
        // A panic while reporting a panic: stop without touching anything else.
        arch::halt_forever();
    }
    print_unlocked(format_args!("\nichor: KERNEL PANIC: {info}\n"));
    shutdown(ExitStatus::Failure)
}
