//! A first slice of the Linux x86-64 syscall personality (ADR-0002 §5,
//! milestone 3/4). Enough to run a static binary that writes to stdout and
//! exits. The number is in `rax`, arguments in `rdi, rsi, rdx, r10, r8, r9`,
//! and the (signed) result in `rax`; on error `rax` is `-errno`.
//!
//! This runs over frame's `VmSpace` (user memory is copied, never borrowed)
//! and a `Cell`. It will grow through milestones 3–4 into the coverage table
//! at `docs/linux-abi.md`.

use alloc::sync::Arc;

use frame::user::UserContext;

use crate::kcell::Cell;

/// Linux x86-64 syscall numbers used so far.
mod nr {
    pub(super) const WRITE: u64 = 1;
    pub(super) const WRITEV: u64 = 20;
    pub(super) const BRK: u64 = 12;
    pub(super) const ARCH_PRCTL: u64 = 158;
    pub(super) const SET_TID_ADDRESS: u64 = 218;
    pub(super) const EXIT: u64 = 60;
    pub(super) const EXIT_GROUP: u64 = 231;
}

const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const ENOSYS: i64 = 38;

/// What the kernel should do after a Linux syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Keep running the process.
    Continue,
    /// The process asked to exit with this status.
    Exit(i32),
}

/// Dispatches one Linux syscall against `cell`, writing the result into
/// `ctx.rax`.
pub(crate) fn dispatch(cell: &Arc<Cell>, ctx: &mut UserContext) -> Outcome {
    let (nr, args) = ctx.syscall_args();
    let result: Result<u64, i64> = match nr {
        nr::WRITE => write(cell, args[0], args[1], args[2] as usize),
        nr::WRITEV => writev(cell, args[0], args[1], args[2] as usize),
        nr::BRK => Ok(0), // No heap break yet; musl/glibc fall back to mmap.
        nr::ARCH_PRCTL => arch_prctl(ctx, args[0], args[1]),
        nr::SET_TID_ADDRESS => Ok(1), // Pretend TID 1.
        nr::EXIT | nr::EXIT_GROUP => return Outcome::Exit(args[0] as i32),
        _ => Err(ENOSYS),
    };
    ctx.set_return(encode(result));
    Outcome::Continue
}

/// Encodes a syscall result the Linux way: a value, or `-errno`.
fn encode(r: Result<u64, i64>) -> u64 {
    match r {
        Ok(v) => v,
        Err(e) => (-e) as u64,
    }
}

/// `write(fd, buf, count)`: fd 1 and 2 go to the kernel console.
fn write(cell: &Arc<Cell>, fd: u64, buf: u64, count: usize) -> Result<u64, i64> {
    if fd != 1 && fd != 2 {
        return Err(EBADF);
    }
    Ok(write_user_bytes(cell, buf, count) as u64)
}

/// `writev(fd, iov, iovcnt)`: fd 1 and 2 go to the kernel console.
fn writev(cell: &Arc<Cell>, fd: u64, iov: u64, iovcnt: usize) -> Result<u64, i64> {
    if fd != 1 && fd != 2 {
        return Err(EBADF);
    }
    let mut total = 0u64;
    for i in 0..iovcnt.min(1024) {
        // struct iovec { void *iov_base; size_t iov_len; } — 16 bytes.
        let entry = iov + (i as u64) * 16;
        let mut hdr = [0u8; 16];
        if cell.space().copy_from_user(entry, &mut hdr) != 16 {
            return Err(EFAULT);
        }
        let base = u64::from_le_bytes(hdr[0..8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(hdr[8..16].try_into().unwrap_or([0; 8])) as usize;
        total += write_user_bytes(cell, base, len) as u64;
    }
    Ok(total)
}

/// Copies up to `count` bytes from user memory and writes them to the
/// console in chunks. Returns the number written.
fn write_user_bytes(cell: &Arc<Cell>, buf: u64, count: usize) -> usize {
    let mut written = 0;
    let mut chunk = [0u8; 256];
    while written < count {
        let want = chunk.len().min(count - written);
        let got = cell
            .space()
            .copy_from_user(buf + written as u64, &mut chunk[..want]);
        if got == 0 {
            break;
        }
        if let Ok(s) = core::str::from_utf8(&chunk[..got]) {
            frame::print!("{s}");
        } else {
            // Print the valid prefix; stop at the first invalid byte.
            let valid = core::str::from_utf8(&chunk[..got])
                .err()
                .map_or(got, |e| e.valid_up_to());
            if let Ok(s) = core::str::from_utf8(&chunk[..valid]) {
                frame::print!("{s}");
            }
            written += valid;
            break;
        }
        written += got;
    }
    written
}

const ARCH_SET_FS: u64 = 0x1002;
const ARCH_SET_GS: u64 = 0x1001;

/// `arch_prctl`: lets a static binary set its FS base (TLS). GS is not
/// settable (the kernel keeps its per-CPU block there).
fn arch_prctl(ctx: &mut UserContext, code: u64, addr: u64) -> Result<u64, i64> {
    match code {
        ARCH_SET_FS => {
            ctx.fs_base = addr;
            Ok(0)
        }
        ARCH_SET_GS => Err(EFAULT),
        _ => Err(ENOSYS),
    }
}
