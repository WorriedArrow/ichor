//! The kernel console: serial output for logs and panics.
//!
//! Output goes to the architecture's early console (COM1 on x86_64). Ichor is
//! headless, so this is the only local output device; structured logs and
//! metrics leave the machine over the network control API.

use core::fmt::{self, Write};

use crate::arch::early_console;
use crate::sync::SpinLock;

/// Serializes whole `print!` calls so lines from different CPUs don't
/// interleave. The lock guards no data: the UART itself is stateless from
/// software's point of view.
static CONSOLE: SpinLock<()> = SpinLock::new(());

struct Serial;

/// `bytes` with each `\n` preceded by `\r`, as a serial terminal expects.
fn crlf(bytes: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
    bytes.flat_map(|b| (b == b'\n').then_some(b'\r').into_iter().chain(Some(b)))
}

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        early_console::write_all(crlf(s.bytes()));
        Ok(())
    }
}

/// Writes formatted output to the console. Use [`print!`](crate::print) and
/// [`println!`](crate::println) rather than calling this directly.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let _guard = CONSOLE.lock();
    // Serial never reports an error; the only failure is a `Display` impl
    // returning `Err`, in which case the output is truncated.
    let _ = Serial.write_fmt(args);
}

/// Writes raw bytes to the console (no UTF-8 interpretation: user programs
/// write arbitrary bytes), under one lock for the whole buffer.
pub fn write_bytes(bytes: &[u8]) {
    let _guard = CONSOLE.lock();
    early_console::write_all(crlf(bytes.iter().copied()));
}

/// Writes to the console without taking the console lock. Used by the panic
/// handler, which may run while the lock is held. Output may interleave with
/// other CPUs.
pub(crate) fn print_unlocked(args: fmt::Arguments<'_>) {
    let _ = Serial.write_fmt(args);
}

/// Prints to the kernel console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!($($arg)*))
    };
}

/// Prints to the kernel console, followed by a newline.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}
