//! The Ichor native ABI: the small, capability-based syscall interface used
//! by Ichor's own services (ADR-0002 §5). It is versioned and documented in
//! `docs/abi/`.
//!
//! Calls use the same `syscall` instruction as the Linux personality; the
//! kernel dispatches on the calling process's personality. The number is in
//! `rax`, arguments in `rdi, rsi, rdx, r10, r8, r9`, and the result in `rax`:
//! a non-negative value on success, or a negative [`Error`] code.

#![no_std]
#![forbid(unsafe_code)]

/// ABI version. Bumped on any incompatible change.
pub const VERSION: u64 = 1;

/// Native syscall numbers.
pub mod sys {
    /// Return the ABI version. No arguments.
    pub const VERSION: u64 = 0;
    /// Return the size in bytes of the memory object named by handle `arg0`.
    /// Requires the INSPECT right.
    pub const MEM_SIZE: u64 = 1;
    /// Duplicate handle `arg0` with rights `arg1`, returning a new handle.
    pub const HANDLE_DUP: u64 = 2;
    /// Close handle `arg0`. Returns 0.
    pub const HANDLE_CLOSE: u64 = 3;
    /// Stop the calling process with exit code `arg0`. Does not return.
    pub const EXIT: u64 = 4;
}

/// Error codes returned (as negative values) in `rax`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum Error {
    /// Unknown syscall number.
    NoSys = 1,
    /// The handle is invalid, foreign, revoked, or of the wrong type.
    BadHandle = 2,
    /// The capability lacks a required right.
    Denied = 3,
    /// An argument was invalid.
    Invalid = 4,
}

impl Error {
    /// The value the kernel writes to `rax` (negated, as a `u64`).
    pub fn to_rax(self) -> u64 {
        (-(self as i64)) as u64
    }
}

/// Encodes a successful result for `rax`.
pub fn ok(value: u64) -> u64 {
    value
}

/// Decodes a return value: `Ok(value)` or `Err(code)`.
pub fn decode(rax: u64) -> Result<u64, i64> {
    let signed = rax as i64;
    if signed < 0 { Err(-signed) } else { Ok(rax) }
}
