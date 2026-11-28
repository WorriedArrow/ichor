//! The kernel console: serial output for logs and panics.
//!
//! Output goes to the architecture's early console (COM1 on x86_64). Ichor is
//! headless, so this is the only local output device; structured logs and
//! metrics leave the machine over the network control API.
//!
//! Writes do not wait for the serial port (ADR-0019): each `print!` goes
//! whole into a 64 KiB ring, which hands the port what it takes at once.
//! The rest leaves as the port drains: on later writes, and from the
//! kernel's console task ([`drain`]). A clouds' serial port runs at 115,200
//! baud, about 87 us a byte, so a writer used to wait that long for every
//! byte it logged. Only a full ring makes a writer wait, and then only for
//! room, so nothing is lost and lines keep their order. [`flush`] writes out
//! everything (shutdown does), and a panic flushes before its report.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::early_console;
use crate::sync::SpinLock;

/// Bytes the ring holds: at 115,200 baud, about 5.7 s of output.
const RING: usize = 64 * 1024;

/// Output not yet handed to the serial port, oldest first. Its lock also
/// serializes whole `print!` calls, so lines from different CPUs don't
/// interleave.
struct Ring {
    buf: [u8; RING],
    start: usize,
    len: usize,
}

static OUT: SpinLock<Ring> = SpinLock::new(Ring {
    buf: [0; RING],
    start: 0,
    len: 0,
});

impl Ring {
    fn push(&mut self, b: u8) {
        if self.len == RING {
            self.send(early_console::wait_room());
        }
        self.buf[(self.start + self.len) % RING] = b;
        self.len += 1;
    }

    /// Hands the port up to `room` of the oldest bytes.
    fn send(&mut self, room: usize) {
        for _ in 0..room.min(self.len) {
            early_console::put(self.buf[self.start]);
            self.start = (self.start + 1) % RING;
            self.len -= 1;
        }
    }

    /// Hands the port what it takes without waiting.
    fn send_ready(&mut self) {
        while self.len > 0 {
            match early_console::room_now() {
                0 => break,
                room => self.send(room),
            }
        }
    }

    /// Hands the port everything, waiting for it.
    fn flush(&mut self) {
        while self.len > 0 {
            self.send(early_console::wait_room());
        }
    }
}

/// Formats into the ring.
struct Buffered<'a>(&'a mut Ring);

/// Formats straight to the port (the panic report).
struct Serial;

/// `bytes` with each `\n` preceded by `\r`, as a serial terminal expects.
fn crlf(bytes: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
    bytes.flat_map(|b| (b == b'\n').then_some(b'\r').into_iter().chain(Some(b)))
}

impl Write for Buffered<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in crlf(s.bytes()) {
            self.0.push(b);
        }
        Ok(())
    }
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
    let mut out = OUT.lock();
    // The ring never reports an error; the only failure is a `Display` impl
    // returning `Err`, in which case the output is truncated.
    let _ = Buffered(&mut out).write_fmt(args);
    if SYNC.load(Ordering::Relaxed) {
        out.send_ready();
    }
}

/// Writes raw bytes to the console (no UTF-8 interpretation: user programs
/// write arbitrary bytes), under one lock for the whole buffer.
pub fn write_bytes(bytes: &[u8]) {
    let mut out = OUT.lock();
    for b in crlf(bytes.iter().copied()) {
        out.push(b);
    }
    if SYNC.load(Ordering::Relaxed) {
        out.send_ready();
    }
}

/// Whether writers hand the port what it takes themselves (`console_sync`
/// on the command line). By default only the console task does (ADR-0019's
/// 2026-11-28 amendment): an emulated port takes every byte at once, one VM
/// exit each, which the writer paid (about 20 us a byte under Hyper-V).
static SYNC: AtomicBool = AtomicBool::new(false);

/// Makes writers hand the port what it takes (`console_sync`), so that a
/// hang before the console task runs still shows the last lines.
pub(crate) fn set_sync() {
    SYNC.store(true, Ordering::Relaxed);
}

/// Hands the serial port what it takes now; whether output is still
/// waiting. The kernel's console task calls it until nothing is. The ring's
/// lock is held only to take a FIFO-full at a time, not while the port is
/// written (one VM exit a byte on an emulated port), so writers do not wait
/// behind a long backlog.
pub fn drain() -> bool {
    let _port = PORT.lock();
    loop {
        let room = early_console::room_now().min(CHUNK);
        let mut chunk = [0u8; CHUNK];
        let (n, left) = {
            let mut out = OUT.lock();
            let n = room.min(out.len);
            for b in &mut chunk[..n] {
                *b = out.buf[out.start];
                out.start = (out.start + 1) % RING;
                out.len -= 1;
            }
            (n, out.len)
        };
        for &b in &chunk[..n] {
            early_console::put(b);
        }
        if n == 0 || left == 0 {
            return left > 0;
        }
    }
}

/// Most bytes [`drain`] takes from the ring at once: a 16550's FIFO.
const CHUNK: usize = 16;

/// Serializes [`drain`]'s writes to the port, so chunks leave in order.
static PORT: SpinLock<()> = SpinLock::new(());

/// Writes out everything the ring holds, waiting for the port (before the
/// machine stops).
pub fn flush() {
    // The port first, as `drain` takes them: a chunk it took goes out first.
    let _port = PORT.lock();
    OUT.lock().flush();
}

/// Writes to the console without waiting for the console lock. Used by the
/// panic handler, which may run while the lock is held (then what the ring
/// holds is not written). Output may interleave with other CPUs.
pub(crate) fn print_unlocked(args: fmt::Arguments<'_>) {
    if let Some(mut out) = OUT.try_lock() {
        out.flush();
    }
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
