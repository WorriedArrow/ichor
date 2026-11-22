//! Process descriptors: `pidfd_open`, `CLONE_PIDFD`, `pidfd_send_signal`
//! and `waitid(P_PIDFD)`. One names a process for as long as it is open
//! (a reaped process's pid is never reused here, but the descriptor is
//! what programs hold), and polls readable once the process has exited.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{EBADF, EFAULT, EINVAL, EMFILE};
use crate::poll::{Object, POLLIN, Watchers};
use crate::proc::{self, ProcEntry};
use crate::process::{Fd, LinuxProcess, ObjectEnd};
use crate::signal;

const ESRCH: i64 = 3;
const O_NONBLOCK: u64 = 0o4000;

/// A descriptor of a process.
#[derive(Debug)]
pub(crate) struct PidFd {
    entry: Arc<ProcEntry>,
}

impl Object for PidFd {
    fn read(&self, _: usize, _: bool, _: &dyn Fn() -> bool) -> Result<Vec<u8>, i64> {
        Err(EINVAL)
    }

    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(EINVAL)
    }

    fn poll(&self) -> u16 {
        if proc::exit_status(&self.entry).is_some() {
            POLLIN
        } else {
            0
        }
    }

    fn changes(&self) -> u64 {
        u64::from(proc::exit_status(&self.entry).is_some())
    }

    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.entry.shared.exit)
    }

    fn pidfd(&self) -> Option<&PidFd> {
        Some(self)
    }
}

/// The process `fd` names.
fn entry(p: &LinuxProcess, fd: u64) -> Result<Arc<ProcEntry>, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Object(o) => o.obj.pidfd().map(|f| f.entry.clone()).ok_or(EBADF),
        _ => Err(EBADF),
    }
}

/// The pid of the process `fd` names, for `waitid`.
pub(super) fn pid_of(p: &LinuxProcess, fd: u64) -> Result<u64, i64> {
    entry(p, fd).map(|e| e.pid)
}

/// Whether `fd` was opened with `PIDFD_NONBLOCK`.
pub(super) fn nonblocking(p: &LinuxProcess, fd: u64) -> bool {
    matches!(p.fd(fd), Some(Fd::Object(o)) if o.nonblock)
}

/// A close-on-exec descriptor of process `entry`; its number is stored at
/// `at` too, if given (`CLONE_PIDFD`).
pub(super) fn install(
    p: &mut LinuxProcess,
    entry: Arc<ProcEntry>,
    nonblock: bool,
    at: Option<u64>,
) -> Result<u64, i64> {
    let fd = p
        .install_flags(
            Fd::Object(ObjectEnd {
                obj: Arc::new(PidFd { entry }),
                nonblock,
            }),
            true,
        )
        .ok_or(EMFILE)?;
    if let Some(at) = at
        && p.copy_to_user(at, &(fd as u32).to_le_bytes()) != 4
    {
        p.close(fd);
        return Err(EFAULT);
    }
    Ok(fd)
}

/// `pidfd_open(pid, flags)`.
pub(super) fn open(p: &mut LinuxProcess, pid: i64, flags: u64) -> Result<u64, i64> {
    if pid <= 0 || flags & !O_NONBLOCK != 0 {
        return Err(EINVAL);
    }
    let e = proc::find(p.entry.cell, pid.unsigned_abs()).ok_or(ESRCH)?;
    if e.pid != e.tgid {
        return Err(EINVAL); // a thread
    }
    install(p, e, flags & O_NONBLOCK != 0, None)
}

/// `pidfd_send_signal(fd, sig, info, flags)`.
pub(super) fn send_signal(
    p: &mut LinuxProcess,
    fd: u64,
    sig: u64,
    info: u64,
    flags: u64,
) -> Result<u64, i64> {
    if flags != 0 {
        return Err(EINVAL);
    }
    let e = entry(p, fd)?;
    if e.cell != p.entry.cell || proc::exit_status(&e).is_some() {
        return Err(ESRCH);
    }
    if info == 0 {
        signal::kill(p, e.pid.cast_signed(), sig)
    } else {
        signal::sigqueueinfo(p, e.pid, sig, info)
    }
}
