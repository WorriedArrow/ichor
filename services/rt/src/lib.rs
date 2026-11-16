//! The runtime of Ichor's native-ABI services (ADR-0012 §1): the entry
//! point, the `syscall` instruction behind safe wrappers, a global
//! allocator over `MEM_MAP`, and the panic handler.
//!
//! This is the only `services/` crate allowed `unsafe`, under frame's
//! rules: one operation per block, each with a `// SAFETY:` comment. A
//! service is a `no_std` binary for `x86_64-unknown-none` that names its
//! entry with [`main!`]:
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//! #![forbid(unsafe_code)]
//! rt::main!(main);
//! fn main(args: &[&str]) -> i32 { rt::log("hello"); 0 }
//! ```
//!
//! A native process is single-threaded (the ABI has no threads), which
//! the allocator relies on.

#![no_std]

extern crate alloc;

mod heap;
pub mod sys;

pub use sys::*;

use alloc::vec::Vec;

/// Names the service's entry point: `fn(&[&str]) -> i32`, given the
/// program's arguments; its return value is the exit code.
#[macro_export]
macro_rules! main {
    ($main:path) => {
        #[doc(hidden)]
        #[unsafe(export_name = "__ichor_service_main")]
        extern "Rust" fn __ichor_service_main(args: &[&str]) -> i32 {
            let main: fn(&[&str]) -> i32 = $main;
            main(args)
        }
    };
}

unsafe extern "Rust" {
    /// Defined by [`main!`] in the service binary.
    fn __ichor_service_main(args: &[&str]) -> i32;
}

// The kernel's loader starts a process with `rsp` at `argc`, then the
// argument pointers, as Linux's System V layout (`loader.rs`).
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    "mov rdi, rsp",
    "and rsp, -16",
    "call {start}",
    "ud2",
    start = sym start,
);

/// Reads the arguments the loader put on the stack at `sp`, runs the
/// service and exits with its code.
extern "C" fn start(sp: *const u64) -> ! {
    let mut args: Vec<&'static str> = Vec::new();
    // SAFETY: `sp` is the initial stack pointer, which points at `argc`
    // (the loader writes it; `_start` passes `rsp` unchanged).
    let argc = unsafe { sp.read() };
    for i in 0..argc as usize {
        // SAFETY: argv[i] (i < argc) follows `argc` on the initial stack.
        let ptr = unsafe { sp.wrapping_add(1 + i).read() } as *const u8;
        let mut len = 0;
        // SAFETY: each argument is a NUL-terminated string the loader
        // copied onto the stack, which lives (unmodified) for the whole
        // process; reading up to its NUL stays inside it.
        while unsafe { ptr.wrapping_add(len).read() } != 0 {
            len += 1;
        }
        // SAFETY: as above: `len` bytes at `ptr` are the argument, alive
        // and never written again.
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
        args.push(core::str::from_utf8(bytes).unwrap_or(""));
    }
    // SAFETY: `__ichor_service_main` is only ever defined by `main!`, with
    // exactly this signature; defining it any other way takes an unsafe
    // attribute, which `forbid(unsafe_code)` service crates cannot use. A
    // missing or duplicate definition is a link error, not UB.
    let code = unsafe { __ichor_service_main(&args) };
    exit(code as u64)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut line = sys::Line::new();
    let _ = core::fmt::write(&mut line, format_args!("panic: {info}"));
    log(line.as_str());
    exit(101)
}
