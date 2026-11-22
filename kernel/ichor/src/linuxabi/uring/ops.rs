//! io_uring's operations: what an SQE may say, and what it does, through
//! the code of the synchronous syscalls. An operation on a file finds it as
//! descriptor `LENT`, which does not block.

use alloc::sync::Arc;
use alloc::vec::Vec;

use ::uring::{Cqe, Layout, Sqe, abi};
use frame::user::UserContext;

use super::super::nr;
use super::super::splice::{Off, splice_at};
use super::tables::Buffer;
use super::{
    Done, EAGAIN, EALREADY, EBADF, EBADFD, EFAULT, EINTR, EINVAL, EOPNOTSUPP, Kept, LENT, Ring,
};
use crate::poll::{self, POLLERR, POLLHUP, POLLIN, POLLOUT};
use crate::process::{Fd, LinuxProcess};

const E2BIG: i64 = 7;
const EOVERFLOW: i64 = 75;
const ENOBUFS: i64 = 105;
const EINPROGRESS: i64 = 115;

/// The opcodes this kernel runs (the probe reports exactly these).
pub(super) const SUPPORTED: &[u8] = &[
    abi::OP_NOP,
    abi::OP_READV,
    abi::OP_WRITEV,
    abi::OP_FSYNC,
    abi::OP_READ_FIXED,
    abi::OP_WRITE_FIXED,
    abi::OP_POLL_ADD,
    abi::OP_POLL_REMOVE,
    abi::OP_SYNC_FILE_RANGE,
    abi::OP_SENDMSG,
    abi::OP_RECVMSG,
    abi::OP_TIMEOUT,
    abi::OP_TIMEOUT_REMOVE,
    abi::OP_ACCEPT,
    abi::OP_ASYNC_CANCEL,
    abi::OP_LINK_TIMEOUT,
    abi::OP_CONNECT,
    abi::OP_FALLOCATE,
    abi::OP_OPENAT,
    abi::OP_CLOSE,
    abi::OP_FILES_UPDATE,
    abi::OP_STATX,
    abi::OP_READ,
    abi::OP_WRITE,
    abi::OP_FADVISE,
    abi::OP_MADVISE,
    abi::OP_SEND,
    abi::OP_RECV,
    abi::OP_OPENAT2,
    abi::OP_EPOLL_CTL,
    abi::OP_SPLICE,
    abi::OP_PROVIDE_BUFFERS,
    abi::OP_REMOVE_BUFFERS,
    abi::OP_TEE,
    abi::OP_SHUTDOWN,
    abi::OP_RENAMEAT,
    abi::OP_UNLINKAT,
    abi::OP_MKDIRAT,
    abi::OP_SYMLINKAT,
    abi::OP_LINKAT,
    abi::OP_MSG_RING,
    abi::OP_SOCKET,
];

/// Every SQE flag there is.
const SQE_FLAGS: u8 = 0x7f;

const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CTRUNC: u64 = 0x8;

const RWF_DSYNC: u32 = 2;
const RWF_SYNC: u32 = 4;
const RWF_NOWAIT: u32 = 8;

const SOCK_CLOEXEC: u32 = 0o2_000_000;
const SOCK_NONBLOCK: u32 = 0o4000;
const O_CLOEXEC: u64 = 0o2_000_000;

/// What became of one try.
pub(super) enum Step {
    Done(Done),
    /// One completion of several.
    More(Done),
    /// Not now: its object is not ready.
    Again,
}

impl Step {
    fn err(e: i64) -> Step {
        Step::Done(Done::err(e))
    }
}

pub(super) fn is_timeout(op: u8) -> bool {
    matches!(op, abi::OP_TIMEOUT | abi::OP_LINK_TIMEOUT)
}

/// Whether `op` is on the file `fd` names.
pub(super) fn on_file(op: u8) -> bool {
    matches!(
        op,
        abi::OP_READV
            | abi::OP_WRITEV
            | abi::OP_FSYNC
            | abi::OP_READ_FIXED
            | abi::OP_WRITE_FIXED
            | abi::OP_POLL_ADD
            | abi::OP_SYNC_FILE_RANGE
            | abi::OP_SENDMSG
            | abi::OP_RECVMSG
            | abi::OP_ACCEPT
            | abi::OP_CONNECT
            | abi::OP_FALLOCATE
            | abi::OP_READ
            | abi::OP_WRITE
            | abi::OP_FADVISE
            | abi::OP_SEND
            | abi::OP_RECV
            | abi::OP_SPLICE
            | abi::OP_TEE
            | abi::OP_SHUTDOWN
            | abi::OP_MSG_RING
    )
}

/// Whether it takes a directory's descriptor, which is never a registered
/// file.
fn on_directory(op: u8) -> bool {
    matches!(
        op,
        abi::OP_OPENAT
            | abi::OP_OPENAT2
            | abi::OP_STATX
            | abi::OP_CLOSE
            | abi::OP_RENAMEAT
            | abi::OP_UNLINKAT
            | abi::OP_MKDIRAT
            | abi::OP_SYMLINKAT
            | abi::OP_LINKAT
    )
}

fn selects(op: u8) -> bool {
    matches!(
        op,
        abi::OP_READ | abi::OP_READV | abi::OP_RECV | abi::OP_RECVMSG
    )
}

/// Whether `s` is not tried before its object says it is ready.
pub(super) fn waits_first(s: &Sqe) -> bool {
    match s.opcode {
        abi::OP_SEND | abi::OP_RECV | abi::OP_SENDMSG | abi::OP_RECVMSG => {
            s.ioprio & abi::RECVSEND_POLL_FIRST != 0
        }
        // Its first event counts as one it waited for.
        abi::OP_POLL_ADD => s.len & abi::POLL_ADD_MULTI != 0,
        _ => false,
    }
}

/// Whether it uses a registered file or buffer.
pub(super) fn uses_registered(s: &Sqe) -> bool {
    s.flags & abi::SQE_FIXED_FILE != 0
        || matches!(s.opcode, abi::OP_READ_FIXED | abi::OP_WRITE_FIXED)
        || (matches!(s.opcode, abi::OP_SPLICE | abi::OP_TEE)
            && s.op_flags & abi::SPLICE_F_FD_IN_FIXED != 0)
}

/// The readiness an SQE waits for, if it waits for its file.
pub(super) fn need(s: &Sqe) -> Option<u16> {
    let ev = match s.opcode {
        abi::OP_READ
        | abi::OP_READV
        | abi::OP_READ_FIXED
        | abi::OP_RECV
        | abi::OP_RECVMSG
        | abi::OP_ACCEPT => POLLIN,
        abi::OP_WRITE
        | abi::OP_WRITEV
        | abi::OP_WRITE_FIXED
        | abi::OP_SEND
        | abi::OP_SENDMSG
        | abi::OP_CONNECT => POLLOUT,
        abi::OP_POLL_ADD => s.op_flags as u16,
        _ => return None,
    };
    Some(ev | POLLERR | POLLHUP)
}

/// What `fd` is ready for, `POLLRDNORM` and `POLLWRNORM` too.
pub(super) fn ready(fd: &Fd) -> u16 {
    const POLLRDNORM: u16 = 0x40;
    const POLLWRNORM: u16 = 0x100;
    let r = poll::readiness(fd);
    let also = |has: u16, then: u16| if r & has != 0 { then } else { 0 };
    r | also(POLLIN, POLLRDNORM) | also(POLLOUT, POLLWRNORM)
}

/// Refuses an SQE that says what its operation does not know.
pub(super) fn check(s: &Sqe, l: &Layout) -> Result<(), i64> {
    let zero = |fields: &[u64]| {
        if fields.iter().all(|&f| f == 0) {
            Ok(())
        } else {
            Err(EINVAL)
        }
    };
    let only = |flags: u32, known: u32| {
        if flags & !known == 0 {
            Ok(())
        } else {
            Err(EINVAL)
        }
    };
    if s.flags & !SQE_FLAGS != 0 || !SUPPORTED.contains(&s.opcode) || s.personality != 0 {
        return Err(EINVAL);
    }
    let select = s.flags & abi::SQE_BUFFER_SELECT != 0;
    if select && !selects(s.opcode) {
        return Err(EOPNOTSUPP);
    }
    let fixed = s.flags & abi::SQE_FIXED_FILE != 0;
    if fixed && on_directory(s.opcode) {
        return Err(EBADF);
    }
    let (buf, index) = (u64::from(s.buf_index), u64::from(s.file_index as u32));
    let (len, flags) = (u64::from(s.len), u64::from(s.op_flags));
    let rw = matches!(
        s.opcode,
        abi::OP_READ
            | abi::OP_READV
            | abi::OP_READ_FIXED
            | abi::OP_WRITE
            | abi::OP_WRITEV
            | abi::OP_WRITE_FIXED
    );
    let net = matches!(
        s.opcode,
        abi::OP_SEND | abi::OP_RECV | abi::OP_SENDMSG | abi::OP_RECVMSG | abi::OP_ACCEPT
    );
    if !rw && !net && s.ioprio != 0 {
        return Err(EINVAL);
    }
    if rw {
        priority(s.ioprio)?;
    }
    // Of these, only reads and writes wait for a device.
    let polls = rw
        || matches!(
            s.opcode,
            abi::OP_NOP
                | abi::OP_FILES_UPDATE
                | abi::OP_PROVIDE_BUFFERS
                | abi::OP_REMOVE_BUFFERS
                | abi::OP_MSG_RING
        );
    if l.has(abi::SETUP_IOPOLL) && !polls {
        return Err(EINVAL);
    }
    match s.opcode {
        abi::OP_FSYNC => {
            zero(&[s.addr, buf, index])?;
            only(s.op_flags, abi::FSYNC_DATASYNC)
        }
        abi::OP_SYNC_FILE_RANGE => zero(&[s.addr, buf, index]),
        abi::OP_POLL_ADD => {
            zero(&[buf, s.off, s.addr])?;
            only(s.len, abi::POLL_ADD_MULTI | abi::POLL_ADD_LEVEL)?;
            // Each of several completions is told of.
            zero(&[u64::from(
                s.len & abi::POLL_ADD_MULTI != 0 && s.flags & abi::SQE_CQE_SKIP_SUCCESS != 0,
            )])
        }
        abi::OP_POLL_REMOVE => {
            zero(&[buf, index])?;
            let update = abi::POLL_UPDATE_EVENTS | abi::POLL_UPDATE_USER_DATA;
            only(s.len, update | abi::POLL_ADD_MULTI)?;
            if s.len & update == 0 {
                zero(&[s.off, flags, len])
            } else if s.len & abi::POLL_UPDATE_USER_DATA == 0 {
                zero(&[s.off])
            } else {
                Ok(())
            }
        }
        abi::OP_TIMEOUT | abi::OP_LINK_TIMEOUT => {
            zero(&[buf, index])?;
            if s.len != 1 {
                return Err(EINVAL);
            }
            let clocks = abi::TIMEOUT_BOOTTIME | abi::TIMEOUT_REALTIME;
            let mut known = abi::TIMEOUT_ABS | abi::TIMEOUT_ETIME_SUCCESS | clocks;
            if s.opcode == abi::OP_TIMEOUT {
                known |= abi::TIMEOUT_MULTISHOT;
            } else {
                zero(&[s.off])?;
            }
            only(s.op_flags, known)?;
            let both = |a: u32| s.op_flags & a == a;
            if both(clocks) || both(abi::TIMEOUT_MULTISHOT | abi::TIMEOUT_ABS) {
                return Err(EINVAL);
            }
            Ok(())
        }
        abi::OP_TIMEOUT_REMOVE => {
            zero(&[buf, index, len])?;
            let clocks = abi::TIMEOUT_BOOTTIME | abi::TIMEOUT_REALTIME;
            if s.op_flags & (abi::TIMEOUT_UPDATE | abi::LINK_TIMEOUT_UPDATE) != 0 {
                only(
                    s.op_flags,
                    abi::TIMEOUT_UPDATE | abi::LINK_TIMEOUT_UPDATE | abi::TIMEOUT_ABS | clocks,
                )?;
                if s.op_flags & clocks == clocks {
                    return Err(EINVAL);
                }
                Ok(())
            } else {
                zero(&[flags])
            }
        }
        abi::OP_ASYNC_CANCEL => {
            zero(&[s.off, len, index])?;
            let (fd, any) = (abi::ASYNC_CANCEL_FD, abi::ASYNC_CANCEL_ANY);
            only(
                s.op_flags,
                abi::ASYNC_CANCEL_ALL | abi::ASYNC_CANCEL_FD_FIXED | fd | any,
            )?;
            zero(&[u64::from(s.op_flags & (fd | any) == fd | any)])
        }
        abi::OP_ACCEPT => {
            zero(&[len, buf])?;
            only(s.op_flags, SOCK_CLOEXEC | SOCK_NONBLOCK)?;
            only(u32::from(s.ioprio), u32::from(abi::ACCEPT_MULTISHOT))?;
            let direct = s.file_index != 0;
            let many = s.ioprio & abi::ACCEPT_MULTISHOT != 0;
            zero(&[
                u64::from(direct && s.op_flags & SOCK_CLOEXEC != 0),
                u64::from(direct && many && s.file_index as u32 != abi::FILE_INDEX_ALLOC),
            ])
        }
        abi::OP_CONNECT => zero(&[len, buf, flags, index]),
        abi::OP_SEND | abi::OP_SENDMSG => {
            only(u32::from(s.ioprio), u32::from(abi::RECVSEND_POLL_FIRST))
        }
        abi::OP_RECV | abi::OP_RECVMSG => {
            zero(&[s.off, index])?;
            let many = s.ioprio & abi::RECV_MULTISHOT != 0;
            only(
                u32::from(s.ioprio),
                u32::from(abi::RECVSEND_POLL_FIRST | abi::RECV_MULTISHOT),
            )?;
            zero(&[
                u64::from(many && !select),
                u64::from(many && flags & MSG_WAITALL != 0),
                u64::from(many && s.opcode == abi::OP_RECV && len != 0),
            ])
        }
        abi::OP_FALLOCATE => zero(&[buf, flags, index]),
        abi::OP_FADVISE => zero(&[buf, s.addr]),
        abi::OP_MADVISE => zero(&[buf, s.off, index]),
        abi::OP_OPENAT | abi::OP_OPENAT2 => {
            zero(&[buf])?;
            let cloexec = s.opcode == abi::OP_OPENAT && flags & O_CLOEXEC != 0;
            zero(&[u64::from(index != 0 && cloexec)])
        }
        abi::OP_CLOSE => {
            zero(&[s.off, s.addr, len, flags, buf])?;
            zero(&[u64::from(index != 0 && s.fd != 0)])
        }
        abi::OP_STATX | abi::OP_RENAMEAT | abi::OP_LINKAT => zero(&[buf, index]),
        abi::OP_UNLINKAT => zero(&[s.off, len, buf, index]),
        abi::OP_MKDIRAT => zero(&[s.off, flags, buf, index]),
        abi::OP_SYMLINKAT => zero(&[len, flags, buf, index]),
        abi::OP_SHUTDOWN => zero(&[s.off, s.addr, flags, buf, index]),
        abi::OP_EPOLL_CTL => zero(&[buf, index]),
        abi::OP_FILES_UPDATE => {
            zero(&[flags, index, u64::from(fixed)])?;
            if len == 0 { Err(EINVAL) } else { Ok(()) }
        }
        abi::OP_PROVIDE_BUFFERS => {
            zero(&[flags, index])?;
            provided(s)
        }
        abi::OP_REMOVE_BUFFERS => {
            zero(&[flags, s.addr, len, s.off, index])?;
            if (1..=65536).contains(&s.fd) {
                Ok(())
            } else {
                Err(EINVAL)
            }
        }
        abi::OP_MSG_RING => {
            zero(&[buf])?;
            only(
                s.op_flags,
                abi::MSG_RING_CQE_SKIP | abi::MSG_RING_FLAGS_PASS,
            )
        }
        abi::OP_SOCKET => zero(&[s.addr, flags, buf]),
        abi::OP_TEE => zero(&[s.addr, s.off]),
        _ => Ok(()),
    }
}

/// Whether `ioprio` is a priority a read or write may have (there is one
/// queue here, so it changes nothing).
fn priority(ioprio: u16) -> Result<(), i64> {
    const EPERM: i64 = 1;
    match (ioprio >> 13, ioprio & 0x1fff) {
        (0, 0) | (2 | 3, _) => Ok(()),
        // Real time is for those with CAP_SYS_NICE.
        (1, _) => Err(EPERM),
        _ => Err(EINVAL),
    }
}

/// Reads what `s` points to that must be as it was at submission, whenever
/// it runs: vectors, message headers, addresses, times.
pub(super) fn keep(p: &mut LinuxProcess, s: &Sqe) -> Kept {
    const TIMESPEC: usize = 16;
    const IOVEC: usize = 16;
    let mut k = Kept::default();
    match s.opcode {
        abi::OP_READV | abi::OP_WRITEV if s.len <= 1024 => {
            k.keep(p, s.addr, s.len as usize * IOVEC);
        }
        abi::OP_SENDMSG | abi::OP_RECVMSG => {
            let header = k.keep(p, s.addr, MSGHDR).map(|b| {
                let u = |at: usize| super::super::le_u64(&b[at..at + 8]);
                (u(0), u(8) & 0xffff_ffff, u(16), u(24))
            });
            if let Some((name, name_len, iov, n)) = header {
                if n <= 1024 {
                    k.keep(p, iov, n as usize * IOVEC);
                }
                if s.opcode == abi::OP_SENDMSG && name_len <= 128 {
                    k.keep(p, name, name_len as usize);
                }
            }
        }
        abi::OP_CONNECT if s.off <= 128 => {
            k.keep(p, s.addr, s.off as usize);
        }
        abi::OP_TIMEOUT | abi::OP_LINK_TIMEOUT => {
            k.keep(p, s.addr, TIMESPEC);
        }
        abi::OP_TIMEOUT_REMOVE if s.op_flags & abi::TIMEOUT_UPDATE != 0 => {
            k.keep(p, s.off, TIMESPEC);
        }
        _ => {}
    }
    k
}

/// Bytes of a `struct msghdr`.
const MSGHDR: usize = 56;

/// `PROVIDE_BUFFERS`: `fd` of them, `len` bytes each, from id `off`.
fn provided(s: &Sqe) -> Result<(), i64> {
    if !(1..=65536).contains(&s.fd) {
        return Err(E2BIG);
    }
    if s.len == 0 {
        return Err(EINVAL);
    }
    let n = s.fd as u64;
    if s.off > 0xffff {
        return Err(E2BIG);
    }
    if s.off + n > 65536 {
        return Err(EINVAL);
    }
    let end = s.addr.checked_add(n * u64::from(s.len)).ok_or(EOVERFLOW)?;
    if end > super::tables::USER_END {
        return Err(EFAULT);
    }
    Ok(())
}

/// Runs syscall `nr` with `args`.
fn call(p: &mut LinuxProcess, nr: u64, args: [u64; 6]) -> Result<u64, i64> {
    let mut ctx = UserContext::new(0, 0);
    ctx.rax = nr;
    ctx.rdi = args[0];
    ctx.rsi = args[1];
    ctx.rdx = args[2];
    ctx.r10 = args[3];
    ctx.r8 = args[4];
    ctx.r9 = args[5];
    let _ = super::super::dispatch(p, &mut ctx);
    let r = ctx.rax as i64;
    if crate::signal::Restart::of(nr, r).is_some() {
        p.resume_until = None;
        return Err(EINTR);
    }
    if r < 0 { Err(-r) } else { Ok(r as u64) }
}

/// Tries `s`, whose file is `fd`, once. `done` is kept between tries, and
/// `seen` is how often the file had changed at the last one.
pub(super) fn issue(
    ring: &Ring,
    p: &mut LinuxProcess,
    s: &Sqe,
    fd: Option<&Fd>,
    done: &mut u64,
    seen: Option<u64>,
) -> Step {
    match (s.opcode, fd) {
        (abi::OP_POLL_ADD, Some(fd)) => poll_add(s, fd, seen),
        (abi::OP_READ | abi::OP_READV | abi::OP_READ_FIXED, Some(fd)) => rw(ring, p, s, fd, false),
        (abi::OP_WRITE | abi::OP_WRITEV | abi::OP_WRITE_FIXED, Some(fd)) => {
            rw(ring, p, s, fd, true)
        }
        (abi::OP_RECV | abi::OP_RECVMSG, Some(fd)) => recv(ring, p, s, fd, done),
        (abi::OP_SEND | abi::OP_SENDMSG, Some(fd)) => send(p, s, fd, done),
        (abi::OP_ACCEPT, _) => accept(ring, p, s),
        (abi::OP_CONNECT, _) => {
            match call(p, nr::CONNECT, [LENT, s.addr, s.off, 0, 0, 0]) {
                // It goes on by itself; asked again, the socket says how it
                // ended.
                Err(EINPROGRESS) if *done == 0 => {
                    *done = 1;
                    Step::Again
                }
                Err(EAGAIN | EINPROGRESS | EALREADY) => Step::Again,
                r => Step::Done(Done::of(r)),
            }
        }
        (abi::OP_SPLICE | abi::OP_TEE, _) => match splice(ring, p, s) {
            Err(EAGAIN) => Step::Again,
            Ok(n) => Step::Done(Done::new(n as i64, n == u64::from(s.len))),
            Err(e) => Step::err(e),
        },
        (abi::OP_MSG_RING, Some(fd)) => Step::Done(Done::of(msg_ring(ring, s, fd))),
        _ => Step::Done(Done::of(other(ring, p, s))),
    }
}

fn poll_add(s: &Sqe, fd: &Fd, seen: Option<u64>) -> Step {
    let want = (s.op_flags as u16) | POLLERR | POLLHUP;
    let got = ready(fd) & want;
    let many = s.len & abi::POLL_ADD_MULTI != 0;
    if got == 0 || (many && seen == Some(poll::changes(fd))) {
        return Step::Again;
    }
    let d = Done::new(i64::from(got), true);
    let own = matches!(fd, Fd::Object(o) if o.obj.woken_by_ring());
    if many && !own {
        Step::More(d)
    } else {
        Step::Done(d)
    }
}

/// The total length of `n` iovecs at `at`.
fn iov_total(p: &mut LinuxProcess, at: u64, n: u32) -> Result<u64, i64> {
    let iov = super::super::fs::read_iov(p, at, n as usize)?;
    Ok(iov.iter().map(|&(_, l)| l as u64).sum())
}

fn rw(ring: &Ring, p: &mut LinuxProcess, s: &Sqe, fd: &Fd, write: bool) -> Step {
    // No file here can be polled for completions.
    if s.op_flags & !(RWF_DSYNC | RWF_SYNC | RWF_NOWAIT) != 0 || ring.layout.has(abi::SETUP_IOPOLL)
    {
        return Step::err(EOPNOTSUPP);
    }
    let vector = matches!(s.opcode, abi::OP_READV | abi::OP_WRITEV);
    let (mut addr, mut len) = (s.addr, u64::from(s.len));
    if matches!(s.opcode, abi::OP_READ_FIXED | abi::OP_WRITE_FIXED)
        && !ring.tables.lock().buffers.holds(s.buf_index, addr, len)
    {
        return Step::err(EFAULT);
    }
    let mut picked = None;
    let mut one = !vector;
    if s.flags & abi::SQE_BUFFER_SELECT != 0 {
        if vector {
            if s.len != 1 {
                return Step::err(EINVAL);
            }
            match iov_total(p, s.addr, 1) {
                Ok(n) => len = n,
                Err(e) => return Step::err(e),
            }
            one = true;
        }
        let Some(b) = ring.pick(p, s.buf_index) else {
            return Step::err(ENOBUFS);
        };
        addr = b.addr;
        len = if len == 0 { b.len } else { len.min(b.len) };
        picked = Some(b);
    }
    let want = if one {
        Ok(len)
    } else {
        iov_total(p, s.addr, s.len)
    };
    let at = s.off != u64::MAX && matches!(fd, Fd::File(_));
    let r = want.and_then(|want| {
        let n = match (one, at) {
            (true, true) => {
                let nr = if write { nr::PWRITE64 } else { nr::PREAD64 };
                call(p, nr, [LENT, addr, len, s.off, 0, 0])
            }
            (true, false) => {
                let nr = if write { nr::WRITE } else { nr::READ };
                call(p, nr, [LENT, addr, len, 0, 0, 0])
            }
            (false, true) => {
                let nr = if write { nr::PWRITEV } else { nr::PREADV };
                call(p, nr, [LENT, addr, u64::from(s.len), s.off, 0, 0])
            }
            (false, false) => {
                let nr = if write { nr::WRITEV } else { nr::READV };
                call(p, nr, [LENT, addr, u64::from(s.len), 0, 0, 0])
            }
        }?;
        Ok((n, n == want))
    });
    match r {
        Err(EAGAIN) if s.op_flags & RWF_NOWAIT == 0 => {
            ring.unpick(s.buf_index, picked);
            Step::Again
        }
        Err(e) => {
            ring.unpick(s.buf_index, picked);
            Step::err(e)
        }
        Ok((n, ok)) => Step::Done(Done {
            res: n as i64,
            ok,
            flags: picked.map_or(0, |b| b.flags()),
        }),
    }
}

/// Whether the socket is one whose data has no bounds.
fn streams(fd: &Fd) -> bool {
    match fd {
        Fd::Object(o) => match (o.obj.socket(), o.obj.unix()) {
            (Some(s), _) => s.is_stream(),
            (_, Some(u)) => u.is_stream(),
            _ => false,
        },
        _ => false,
    }
}

fn recv(ring: &Ring, p: &mut LinuxProcess, s: &Sqe, fd: &Fd, done: &mut u64) -> Step {
    let flags = u64::from(s.op_flags);
    let many = s.ioprio & abi::RECV_MULTISHOT != 0;
    let msg = s.opcode == abi::OP_RECVMSG;
    let (mut addr, mut len) = (s.addr, u64::from(s.len));
    let mut iov = Vec::new();
    if msg && (s.flags & abi::SQE_BUFFER_SELECT == 0 || many) {
        match super::super::socket::msg_hdr(p, s.addr) {
            Ok(h) => iov = h.iov,
            Err(e) => return Step::err(e),
        }
        len = iov.iter().map(|&(_, l)| l as u64).sum();
    }
    let mut picked = None;
    if s.flags & abi::SQE_BUFFER_SELECT != 0 {
        let Some(b) = ring.pick(p, s.buf_index) else {
            return Step::err(ENOBUFS);
        };
        if msg && many {
            return recvmsg_shot(ring, p, s, b);
        }
        if msg {
            len = b.len;
            iov = alloc::vec![(b.addr, b.len as usize)];
        } else {
            addr = b.addr;
            len = if len == 0 { b.len } else { len.min(b.len) };
        }
        picked = Some(b);
    }
    // A stream read to the last byte, over as many tries as it takes.
    let all = flags & MSG_WAITALL != 0 && streams(fd);
    let r = loop {
        let r = if msg {
            let skip = if all { *done } else { 0 };
            p.uring.iov = Some(after(&iov, skip));
            let f = if all { flags & !MSG_WAITALL } else { flags };
            call(p, nr::RECVMSG, [LENT, addr, f, 0, 0, 0])
        } else if all {
            let f = flags & !MSG_WAITALL;
            call(p, nr::RECVFROM, [LENT, addr + *done, len - *done, f, 0, 0])
        } else {
            call(p, nr::RECVFROM, [LENT, addr, len, flags, 0, 0])
        };
        match r {
            Ok(n) if all => {
                *done += n;
                if n == 0 || *done >= len {
                    break Ok(*done);
                }
            }
            r => break r,
        }
    };
    p.uring.iov = None;
    match r {
        Err(EAGAIN) if flags & MSG_DONTWAIT == 0 => {
            ring.unpick(s.buf_index, picked);
            Step::Again
        }
        Err(_) if *done > 0 => Step::Done(Done::new(*done as i64, false)),
        Err(e) => {
            ring.unpick(s.buf_index, picked);
            Step::err(e)
        }
        Ok(0) if picked.is_some() && !datagrams(fd) => {
            ring.unpick(s.buf_index, picked);
            Step::Done(Done::new(0, true))
        }
        Ok(n) => {
            let mut f = picked.map_or(0, |b| b.flags());
            if let Fd::Object(o) = fd
                && o.obj.readable().is_some_and(|n| n > 0)
            {
                f |= abi::CQE_F_SOCK_NONEMPTY;
            }
            let cut = flags & MSG_WAITALL != 0 && flags & (MSG_TRUNC | MSG_CTRUNC) != 0;
            let d = Done {
                res: n as i64,
                ok: !cut && (!all || n == len),
                flags: f,
            };
            if many { Step::More(d) } else { Step::Done(d) }
        }
    }
}

/// What is left of a vector after its first `skip` bytes.
fn after(iov: &[(u64, usize)], mut skip: u64) -> Vec<(u64, usize)> {
    let mut left = Vec::with_capacity(iov.len());
    for &(base, len) in iov {
        let gone = skip.min(len as u64);
        skip -= gone;
        if len as u64 > gone {
            left.push((base + gone, len - gone as usize));
        }
    }
    left
}

/// One message of a multishot RECVMSG, into the provided buffer `b`: a
/// header (`struct io_uring_recvmsg_out`), room for the name and control
/// data the program's `msghdr` has room for, and the data.
fn recvmsg_shot(ring: &Ring, p: &mut LinuxProcess, s: &Sqe, b: Buffer) -> Step {
    const OUT: u64 = 16;
    let group = s.buf_index;
    let give_up = |e: i64| {
        ring.unpick(group, Some(b));
        Step::err(e)
    };
    let mut h = [0u8; MSGHDR];
    if p.copy_from_user(s.addr, &mut h) != MSGHDR {
        return give_up(EFAULT);
    }
    let u = |at: usize| super::super::le_u64(&h[at..at + 8]);
    let (name_len, control_len) = (u(8) & 0xffff_ffff, u(40));
    let Some(data) = OUT
        .checked_add(name_len)
        .and_then(|n| n.checked_add(control_len))
        .filter(|&n| n <= b.len)
    else {
        return give_up(EFAULT);
    };
    // A header of our own: its name and control data go to the buffer, and
    // what is written to it stays here.
    h[..8].copy_from_slice(&(b.addr + OUT).to_le_bytes());
    h[32..40].copy_from_slice(&(b.addr + OUT + name_len).to_le_bytes());
    if name_len == 0 {
        h[..8].fill(0);
    }
    p.uring.kept = Some(Arc::new(Kept::of(s.addr, &h)));
    p.uring.written = Some((s.addr, h.to_vec()));
    p.uring.iov = Some(alloc::vec![(b.addr + data, (b.len - data) as usize)]);
    let r = call(
        p,
        nr::RECVMSG,
        [LENT, s.addr, u64::from(s.op_flags), 0, 0, 0],
    );
    p.uring.iov = None;
    let written = p.uring.written.take();
    let n = match r {
        Err(EAGAIN) if u64::from(s.op_flags) & MSG_DONTWAIT == 0 => {
            ring.unpick(group, Some(b));
            return Step::Again;
        }
        Err(e) => return give_up(e),
        Ok(0) if p.fd(LENT).is_some_and(|f| streams(&f)) => {
            ring.unpick(group, Some(b));
            return Step::Done(Done::new(0, true));
        }
        Ok(n) => n,
    };
    let Some((_, h)) = written else {
        return give_up(EFAULT);
    };
    let mut out = [0u8; OUT as usize];
    out[..4].copy_from_slice(&h[8..12]);
    out[4..8].copy_from_slice(&h[40..44]);
    out[8..12].copy_from_slice(&(n as u32).to_le_bytes());
    out[12..].copy_from_slice(&h[48..52]);
    if p.copy_to_user(b.addr, &out) != out.len() {
        return give_up(EFAULT);
    }
    Step::More(Done {
        res: (data + n.min(b.len - data)) as i64,
        ok: true,
        flags: b.flags(),
    })
}

/// Whether reading nothing from `fd` can be a message, not its end.
fn datagrams(fd: &Fd) -> bool {
    !streams(fd)
}

fn send(p: &mut LinuxProcess, s: &Sqe, fd: &Fd, done: &mut u64) -> Step {
    let asked = u64::from(s.op_flags);
    let flags = asked | MSG_NOSIGNAL;
    let len = u64::from(s.len);
    let all = asked & MSG_WAITALL != 0 && s.opcode == abi::OP_SEND && streams(fd);
    let r = loop {
        let r = if s.opcode == abi::OP_SENDMSG {
            call(p, nr::SENDMSG, [LENT, s.addr, flags, 0, 0, 0])
        } else {
            let name_len = u64::from(s.file_index as u32 & 0xffff);
            call(
                p,
                nr::SENDTO,
                [LENT, s.addr + *done, len - *done, flags, s.off, name_len],
            )
        };
        match r {
            Ok(n) if all => {
                *done += n;
                if n == 0 || *done >= len {
                    break Ok(*done);
                }
            }
            r => break r,
        }
    };
    match r {
        Err(EAGAIN) if asked & MSG_DONTWAIT == 0 => Step::Again,
        Err(_) if *done > 0 => Step::Done(Done::new(*done as i64, false)),
        r => {
            let mut d = Done::of(r);
            d.ok &= !all || d.res as u64 == len;
            Step::Done(d)
        }
    }
}

fn accept(ring: &Ring, p: &mut LinuxProcess, s: &Sqe) -> Step {
    let r = call(
        p,
        nr::ACCEPT4,
        [LENT, s.addr, s.off, u64::from(s.op_flags), 0, 0],
    );
    let fd = match r {
        Err(EAGAIN) => return Step::Again,
        Err(e) => return Step::err(e),
        Ok(fd) => fd,
    };
    let d = Done::of(direct(ring, p, s, fd));
    if d.ok && s.ioprio & abi::ACCEPT_MULTISHOT != 0 {
        Step::More(d)
    } else {
        Step::Done(d)
    }
}

/// What an operation that made descriptor `fd` gives: it, or the registered
/// file it becomes.
fn direct(ring: &Ring, p: &mut LinuxProcess, s: &Sqe, fd: u64) -> Result<u64, i64> {
    if s.file_index == 0 {
        return Ok(fd);
    }
    let d = p.take_desc(fd).ok_or(EBADF)?;
    ring.put_file(s.file_index as u32, d)
}

/// SPLICE and TEE: from `splice_fd_in` (`file_index`) to the SQE's file.
fn splice(ring: &Ring, p: &mut LinuxProcess, s: &Sqe) -> Result<u64, i64> {
    let from = if s.op_flags & abi::SPLICE_F_FD_IN_FIXED != 0 {
        let files = ring.tables.lock().files.get(s.file_index as u32);
        files.ok_or(EBADF)?
    } else {
        p.desc(u64::from(s.file_index as u32)).ok_or(EBADF)?
    };
    if s.len == 0 {
        return Ok(0);
    }
    p.uring.lent.push(from);
    let flags = u64::from(s.op_flags & !abi::SPLICE_F_FD_IN_FIXED);
    let len = u64::from(s.len);
    if s.opcode == abi::OP_TEE {
        super::super::splice::tee(p, LENT - 1, LENT, len, flags)
    } else {
        splice_at(
            p,
            (LENT - 1, Off::Value(s.addr)),
            (LENT, Off::Value(s.off)),
            len,
            flags,
        )
    }
    .map_err(|e| match e {
        crate::signal::ERESTARTSYS | crate::signal::ERESTARTNOHAND => EINTR,
        e => e,
    })
}

/// MSG_RING: a completion, or a registered file, for another ring.
fn msg_ring(ring: &Ring, s: &Sqe, fd: &Fd) -> Result<u64, i64> {
    let Fd::Object(o) = fd else {
        return Err(EBADFD);
    };
    let to = o.obj.uring().ok_or(EBADFD)?;
    if !to.enabled.load(core::sync::atomic::Ordering::Acquire) {
        return Err(EBADFD);
    }
    let mut cqe = Cqe {
        user_data: s.off,
        res: s.len as i32,
        flags: 0,
    };
    match s.addr {
        abi::MSG_DATA => {
            if s.op_flags & abi::MSG_RING_FLAGS_PASS != 0 {
                cqe.flags = s.file_index as u32;
            } else if s.file_index != 0 {
                return Err(EINVAL);
            }
            if s.op_flags & abi::MSG_RING_CQE_SKIP != 0 {
                return Err(EINVAL);
            }
            if to.post_message(cqe) {
                Ok(0)
            } else {
                Err(EOVERFLOW)
            }
        }
        abi::MSG_SEND_FD => {
            if s.len != 0 || core::ptr::eq(to, ring) {
                return Err(EINVAL);
            }
            let d = ring.tables.lock().files.get(s.addr3 as u32).ok_or(EBADF)?;
            let r = to.put_file(s.file_index as u32, d)?;
            if s.op_flags & abi::MSG_RING_CQE_SKIP == 0 {
                cqe.res = r as i32;
                if !to.post_message(cqe) {
                    return Err(EOVERFLOW);
                }
            }
            Ok(r)
        }
        _ => Err(EINVAL),
    }
}

/// `struct open_how`: flags and mode, if it asks for nothing else.
fn open_how(p: &mut LinuxProcess, at: u64, size: u64) -> Result<(u64, u64), i64> {
    if size < 24 {
        return Err(EINVAL);
    }
    let mut b = [0u8; 24];
    if p.copy_from_user(at, &mut b) != b.len() {
        return Err(EFAULT);
    }
    // What this kernel does not know must be zero.
    let mut more = alloc::vec![0u8; size.min(4096) as usize - 24];
    if p.copy_from_user(at + 24, &mut more) != more.len() {
        return Err(EFAULT);
    }
    if size > 4096 || more.iter().any(|&x| x != 0) {
        return Err(E2BIG);
    }
    let u = |at: usize| super::super::le_u64(&b[at..at + 8]);
    if u(16) != 0 {
        return Err(EOPNOTSUPP); // resolve
    }
    Ok((u(0), u(8)))
}

/// The operations that are one syscall, done at once.
fn other(ring: &Ring, p: &mut LinuxProcess, s: &Sqe) -> Result<u64, i64> {
    let dir = s.fd as i64 as u64;
    let (len, flags) = (u64::from(s.len), u64::from(s.op_flags));
    match s.opcode {
        abi::OP_FSYNC => {
            let data = s.op_flags & abi::FSYNC_DATASYNC != 0;
            let n = if data { nr::FDATASYNC } else { nr::FSYNC };
            call(p, n, [LENT, 0, 0, 0, 0, 0])
        }
        abi::OP_SYNC_FILE_RANGE => call(p, nr::SYNC_FILE_RANGE, [LENT, s.off, len, flags, 0, 0]),
        abi::OP_FALLOCATE => call(p, nr::FALLOCATE, [LENT, len, s.off, s.addr, 0, 0]),
        abi::OP_FADVISE => call(p, nr::FADVISE64, [LENT, s.off, len, flags, 0, 0]),
        abi::OP_MADVISE => call(p, nr::MADVISE, [s.addr, len, flags, 0, 0, 0]),
        abi::OP_SHUTDOWN => call(p, nr::SHUTDOWN, [LENT, len, 0, 0, 0, 0]),
        abi::OP_OPENAT => {
            let fd = call(p, nr::OPENAT, [dir, s.addr, flags, len, 0, 0])?;
            direct(ring, p, s, fd)
        }
        abi::OP_OPENAT2 => {
            let (f, mode) = open_how(p, s.off, len)?;
            if s.file_index != 0 && f & O_CLOEXEC != 0 {
                return Err(EINVAL);
            }
            let fd = call(p, nr::OPENAT, [dir, s.addr, f, mode, 0, 0])?;
            direct(ring, p, s, fd)
        }
        abi::OP_SOCKET => {
            let ty = s.off;
            if s.file_index != 0 && ty & u64::from(SOCK_CLOEXEC) != 0 {
                return Err(EINVAL);
            }
            let fd = call(p, nr::SOCKET, [s.fd as u32 as u64, ty, len, 0, 0, 0])?;
            direct(ring, p, s, fd)
        }
        abi::OP_CLOSE if s.file_index != 0 => ring.drop_file(s.file_index as u32 - 1),
        abi::OP_CLOSE => {
            let fd = u64::from(s.fd as u32);
            let is_ring = matches!(p.fd(fd), Some(Fd::Object(o)) if o.obj.uring().is_some());
            if is_ring {
                return Err(EBADF);
            }
            call(p, nr::CLOSE, [fd, 0, 0, 0, 0, 0])
        }
        abi::OP_STATX => call(p, nr::STATX, [dir, s.addr, flags, len, s.off, 0]),
        abi::OP_RENAMEAT => call(p, nr::RENAMEAT2, [dir, s.addr, len, s.off, flags, 0]),
        abi::OP_UNLINKAT => call(p, nr::UNLINKAT, [dir, s.addr, flags, 0, 0, 0]),
        abi::OP_MKDIRAT => call(p, nr::MKDIRAT, [dir, s.addr, len, 0, 0, 0]),
        abi::OP_SYMLINKAT => call(p, nr::SYMLINKAT, [s.addr, dir, s.off, 0, 0, 0]),
        abi::OP_LINKAT => call(p, nr::LINKAT, [dir, s.addr, len, s.off, flags, 0]),
        abi::OP_EPOLL_CTL => {
            let epfd = u64::from(s.fd as u32);
            call(p, nr::EPOLL_CTL, [epfd, len, s.off, s.addr, 0, 0])
        }
        abi::OP_FILES_UPDATE => ring.update_files(p, s.off as u32, s.addr, 0, s.len, true),
        abi::OP_PROVIDE_BUFFERS => ring.provide(s),
        abi::OP_REMOVE_BUFFERS => ring.take_back(s.buf_index, s.fd as usize),
        _ => Err(EINVAL),
    }
}

/// Keeps a file that a ring may wait for out of its own tables.
pub(super) fn may_register(d: &Arc<crate::process::Description>) -> bool {
    !matches!(&*d.state(), Fd::Object(o) if o.obj.uring().is_some())
}
