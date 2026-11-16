//! The Ichor native ABI: the small, capability-based syscall interface used
//! by Ichor's own services (ADR-0002 §5, ADR-0012 §2). It is versioned and
//! documented in `docs/abi/native.md`.
//!
//! Calls use the same `syscall` instruction as the Linux personality; the
//! kernel dispatches on the calling process's personality. The number is in
//! `rax`, arguments in `rdi, rsi, rdx, r10, r8, r9`, and the result in `rax`:
//! a non-negative value on success, or a negative [`Error`] code.

#![no_std]
#![forbid(unsafe_code)]

/// ABI version. Bumped on any incompatible change.
pub const VERSION: u64 = 2;

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

    // Version 2.
    /// Write `arg1` bytes at `arg0` to the console as one log line.
    pub const LOG: u64 = 5;
    /// The time in nanoseconds: `arg0` = [`super::CLOCK_MONOTONIC`] (since
    /// boot) or [`super::CLOCK_REALTIME`] (since the Unix epoch).
    pub const CLOCK: u64 = 6;
    /// Fill `arg1` bytes at `arg0` from the kernel's CSPRNG.
    pub const RANDOM: u64 = 7;
    /// Map `arg0` bytes (rounded up to pages) of zeroed, demand-paged,
    /// read-write memory charged to the caller's cell; returns its address.
    pub const MEM_MAP: u64 = 8;
    /// Wait for readiness: `arg0` points at `arg1` [`super::WaitItem`]s;
    /// `arg2` is a timeout in nanoseconds (`u64::MAX`: none). Returns how
    /// many items are ready and writes each one's `revents`.
    pub const OBJECT_WAIT: u64 = 9;
    /// Start a TCP connection on the caller's cell stack to IPv4 `arg0`
    /// (`a.b.c.d` as the big-endian `u32`) port `arg1`; returns a socket
    /// handle. Completion: writable, then [`SOCK_ERROR`].
    pub const TCP_CONNECT: u64 = 10;
    /// Listen on TCP port `arg0` (all of the cell's addresses), backlog
    /// `arg1`; returns a listener handle.
    pub const TCP_LISTEN: u64 = 11;
    /// Accept a connection from listener `arg0`; [`super::Error::WouldBlock`]
    /// if none is pending.
    pub const TCP_ACCEPT: u64 = 12;
    /// Send `arg2` bytes at `arg1` on socket `arg0`; returns the count.
    pub const SOCK_SEND: u64 = 13;
    /// Receive up to `arg2` bytes into `arg1` from socket `arg0`; 0 is the
    /// end of the stream.
    pub const SOCK_RECV: u64 = 14;
    /// Bind a UDP socket to port `arg0` (0: ephemeral).
    pub const UDP_BIND: u64 = 15;
    /// Send a datagram of `arg2` bytes at `arg1` on `arg0` to IPv4 `arg3`
    /// port `arg4`.
    pub const UDP_SEND: u64 = 16;
    /// Receive a datagram (up to `arg2` bytes into `arg1`) on `arg0`; its
    /// source (the four address octets, then the port, both in network
    /// byte order) goes to the 6 bytes at `arg3` unless it is 0.
    pub const UDP_RECV: u64 = 17;
    /// A connecting socket's outcome: 0 once connected, an error if it
    /// failed, [`super::Error::WouldBlock`] while still connecting.
    pub const SOCK_ERROR: u64 = 18;
    /// Publish TCP port `arg1` of the uplink to port `arg3` of cell `arg2`;
    /// needs the switch handle `arg0`.
    pub const PORT_PUBLISH: u64 = 19;
    /// Verify the Ichor image of `arg1` bytes at `arg0` and keep it;
    /// returns an image handle.
    pub const IMAGE_CREATE: u64 = 20;
    /// Create a cell under `arg0` (a cell handle with `CREATE_CELL`) whose
    /// root is image `arg1` with an in-memory upper layer, with `arg2`
    /// pages of memory; returns a cell handle.
    pub const CELL_CREATE: u64 = 21;
    /// Start a Linux process in cell `arg0`: `arg1`/`arg2` is a spec of
    /// NUL-terminated strings, the argv, an empty string, then the
    /// environment. Its stdout and stderr are captured; returns a process
    /// handle.
    pub const CELL_SPAWN: u64 = 22;
    /// Read up to `arg2` bytes of process `arg0`'s output into `arg1`; 0
    /// once it has exited and everything was read.
    pub const PROCESS_READ: u64 = 23;
    /// Process `arg0`'s wait status (`code << 8`, or the signal number),
    /// [`super::Error::WouldBlock`] while it runs.
    pub const PROCESS_WAIT: u64 = 24;
    /// The IPv4 address the switch assigned to cell `arg0`.
    pub const CELL_ADDR: u64 = 25;
    /// Unmap `arg1` bytes at `arg0` (pages from [`MEM_MAP`]).
    pub const MEM_UNMAP: u64 = 26;
}

/// [`sys::CLOCK`] clocks.
pub const CLOCK_MONOTONIC: u64 = 0;
pub const CLOCK_REALTIME: u64 = 1;

/// [`sys::OBJECT_WAIT`] events (the Linux `poll` bits).
pub const READABLE: u32 = 0x001;
pub const WRITABLE: u32 = 0x004;
pub const FAILED: u32 = 0x008;
pub const HANGUP: u32 = 0x010;

/// One [`sys::OBJECT_WAIT`] entry: 16 bytes, little-endian.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitItem {
    pub handle: u64,
    pub events: u32,
    pub revents: u32,
}

impl WaitItem {
    pub fn to_bytes(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.handle.to_le_bytes());
        b[8..12].copy_from_slice(&self.events.to_le_bytes());
        b[12..].copy_from_slice(&self.revents.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; 16]) -> WaitItem {
        let w = |r: core::ops::Range<usize>| {
            let mut a = [0u8; 4];
            a.copy_from_slice(&b[r]);
            u32::from_le_bytes(a)
        };
        let mut h = [0u8; 8];
        h.copy_from_slice(&b[..8]);
        WaitItem {
            handle: u64::from_le_bytes(h),
            events: w(8..12),
            revents: w(12..16),
        }
    }
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
    /// Nothing is ready yet (try again after [`sys::OBJECT_WAIT`]).
    WouldBlock = 5,
    /// The cell's memory (or a table) is full.
    NoMemory = 6,
    /// The peer refused the connection.
    Refused = 7,
    /// No such file, image or name.
    NotFound = 8,
    /// The operation failed (a reset connection, a bad image, ...).
    Failed = 9,
}

impl Error {
    /// The value the kernel writes to `rax` (negated, as a `u64`).
    pub fn to_rax(self) -> u64 {
        (-(self as i64)) as u64
    }

    /// The error for a negated code, if it is one.
    pub fn from_code(code: i64) -> Option<Error> {
        Some(match code {
            1 => Error::NoSys,
            2 => Error::BadHandle,
            3 => Error::Denied,
            4 => Error::Invalid,
            5 => Error::WouldBlock,
            6 => Error::NoMemory,
            7 => Error::Refused,
            8 => Error::NotFound,
            9 => Error::Failed,
            _ => return None,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_items_round_trip() {
        let w = WaitItem {
            handle: 0x1234_5678_9abc,
            events: READABLE | WRITABLE,
            revents: HANGUP,
        };
        assert_eq!(WaitItem::from_bytes(&w.to_bytes()), w);
    }

    #[test]
    fn errors_round_trip() {
        for e in [Error::NoSys, Error::WouldBlock, Error::Failed] {
            assert_eq!(decode(e.to_rax()).map_err(Error::from_code), Err(Some(e)));
        }
    }
}
