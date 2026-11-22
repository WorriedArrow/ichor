//! Small syscalls that belong nowhere else: what a program asks about the
//! machine, its memory or its privileges, mostly to adapt.

use super::{EBADF, EFAULT, EINVAL, EPERM};
use crate::process::{Fd, LinuxProcess};

const ENOMEM: i64 = 12;
const ESRCH: i64 = 3;
const PAGE_SIZE: u64 = 4096;

fn put(p: &mut LinuxProcess, at: u64, b: &[u8]) -> Result<u64, i64> {
    if at != 0 && p.copy_to_user(at, b) != b.len() {
        return Err(EFAULT);
    }
    Ok(0)
}

/// `getcpu(cpu, node)`: node 0, the only one.
pub(super) fn getcpu(p: &mut LinuxProcess, cpu: u64, node: u64) -> Result<u64, i64> {
    let here = frame::cpu::current().index() as u32;
    put(p, cpu, &here.to_le_bytes())?;
    put(p, node, &0u32.to_le_bytes())
}

/// `personality(persona)`: Linux's, with or without `ADDR_NO_RANDOMIZE`
/// (which programs under a debugger set); addresses here are not random.
pub(super) fn personality(p: &mut LinuxProcess, persona: u64) -> Result<u64, i64> {
    const QUERY: u32 = u32::MAX;
    const ADDR_NO_RANDOMIZE: u32 = 0x0004_0000;
    let new = persona as u32;
    if new != QUERY && new & !ADDR_NO_RANDOMIZE != 0 {
        return Err(EINVAL);
    }
    let mut c = p.group.prctl.lock();
    let old = c.personality;
    if new != QUERY {
        c.personality = new;
    }
    Ok(u64::from(old))
}

/// `syncfs(fd)` and `readahead(fd, ...)`: the descriptor must be a file;
/// there is nothing to write back, and reading ahead is only advice.
pub(super) fn on_file(p: &LinuxProcess, fd: u64) -> Result<u64, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::File(_) => Ok(0),
        _ => Err(EINVAL),
    }
}

/// A page-aligned range of mapped memory.
fn mapped(p: &LinuxProcess, addr: u64, len: u64) -> Result<(u64, u64), i64> {
    let start = addr & !(PAGE_SIZE - 1);
    let end = addr
        .checked_add(len)
        .and_then(|e| e.checked_next_multiple_of(PAGE_SIZE))
        .ok_or(ENOMEM)?;
    if start < end && !p.mm().all_mapped(start, end) {
        return Err(ENOMEM);
    }
    Ok((start, end))
}

/// `mincore(addr, len, vec)`.
pub(super) fn mincore(p: &mut LinuxProcess, addr: u64, len: u64, vec: u64) -> Result<u64, i64> {
    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(EINVAL);
    }
    let (mut va, end) = mapped(p, addr, len)?;
    let mut out = vec;
    while va < end {
        let mut b = [0u8; 256];
        let n = ((end - va) / PAGE_SIZE).min(b.len() as u64) as usize;
        {
            let mm = p.mm();
            for (i, r) in b[..n].iter_mut().enumerate() {
                *r = u8::from(mm.space().translate(va + i as u64 * PAGE_SIZE).is_some());
            }
        }
        if p.copy_to_user(out, &b[..n]) != n {
            return Err(EFAULT);
        }
        va += n as u64 * PAGE_SIZE;
        out += n as u64;
    }
    Ok(0)
}

/// `mlock`, `mlock2`: nothing is ever paged out, so resident is locked.
/// (`MLOCK_ONFAULT` pages stay wherever they come in.)
pub(super) fn mlock(p: &mut LinuxProcess, addr: u64, len: u64, flags: u64) -> Result<u64, i64> {
    const MLOCK_ONFAULT: u64 = 1;
    if flags & !MLOCK_ONFAULT != 0 {
        return Err(EINVAL);
    }
    let (start, end) = mapped(p, addr, len)?;
    if flags & MLOCK_ONFAULT == 0 {
        p.mm().populate(start, (end - start) as usize, false);
    }
    Ok(0)
}

/// `munlock`.
pub(super) fn munlock(p: &mut LinuxProcess, addr: u64, len: u64) -> Result<u64, i64> {
    mapped(p, addr, len).map(|_| 0)
}

/// `mlockall(flags)`.
pub(super) fn mlockall(flags: u64) -> Result<u64, i64> {
    if flags == 0 || flags & !7 != 0 {
        Err(EINVAL)
    } else {
        Ok(0)
    }
}

/// Whether `pid` (0: the caller's) is a process the caller may ask about.
fn known(p: &LinuxProcess, pid: u64) -> Result<(), i64> {
    if pid == 0 || crate::proc::find(p.entry.cell, pid).is_some() {
        Ok(())
    } else {
        Err(ESRCH)
    }
}

/// `sched_getscheduler(pid)`: every process is SCHED_OTHER.
pub(super) fn getscheduler(p: &LinuxProcess, pid: u64) -> Result<u64, i64> {
    known(p, pid).map(|()| 0)
}

/// `sched_setscheduler(pid, policy, param)`: SCHED_OTHER stays; real time
/// needs CAP_SYS_NICE, and BATCH and IDLE are not there.
pub(super) fn setscheduler(
    p: &mut LinuxProcess,
    pid: u64,
    policy: u64,
    param: u64,
) -> Result<u64, i64> {
    const RESET_ON_FORK: u64 = 0x4000_0000;
    known(p, pid)?;
    setparam(p, pid, param)?;
    match policy & !RESET_ON_FORK {
        0 => Ok(0),
        1 | 2 | 3 | 5 | 6 => Err(EPERM),
        _ => Err(EINVAL),
    }
}

/// `sched_getparam(pid, param)`: priority 0.
pub(super) fn getparam(p: &mut LinuxProcess, pid: u64, param: u64) -> Result<u64, i64> {
    known(p, pid)?;
    if param == 0 {
        return Err(EINVAL);
    }
    put(p, param, &0u32.to_le_bytes())
}

/// `sched_setparam(pid, param)`: priority 0 is the only one.
pub(super) fn setparam(p: &mut LinuxProcess, pid: u64, param: u64) -> Result<u64, i64> {
    known(p, pid)?;
    let mut b = [0u8; 4];
    if param == 0 || p.copy_from_user(param, &mut b) != 4 {
        return Err(EFAULT);
    }
    if b == [0; 4] { Ok(0) } else { Err(EINVAL) }
}

const CAPS_V1: u32 = 0x1998_0330;
const CAPS_V2: u32 = 0x2007_1026;
const CAPS_V3: u32 = 0x2008_0522;

/// The header of `capget` and `capset`: how many 32-bit words each set has,
/// and whose they are. An unknown version is answered with ours.
fn cap_header(p: &mut LinuxProcess, hdr: u64, data: u64) -> Result<Option<(usize, u64)>, i64> {
    let mut b = [0u8; 8];
    if p.copy_from_user(hdr, &mut b) != 8 {
        return Err(EFAULT);
    }
    let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let words = match word(0) {
        CAPS_V1 => 1,
        CAPS_V2 | CAPS_V3 => 2,
        _ => {
            put(p, hdr, &CAPS_V3.to_le_bytes())?;
            return if data == 0 { Ok(None) } else { Err(EINVAL) };
        }
    };
    Ok(Some((words, u64::from(word(4)))))
}

/// `capget(hdr, data)`.
pub(super) fn capget(p: &mut LinuxProcess, hdr: u64, data: u64) -> Result<u64, i64> {
    let Some((words, pid)) = cap_header(p, hdr, data)? else {
        return Ok(0);
    };
    known(p, pid)?;
    if data == 0 {
        return Ok(0);
    }
    let c = p.group.creds();
    for i in 0..words {
        // struct: effective, permitted, inheritable.
        let mut b = [0u8; 12];
        let half = |v: u64| ((v >> (32 * i)) as u32).to_le_bytes();
        b[0..4].copy_from_slice(&half(c.effective));
        b[4..8].copy_from_slice(&half(c.permitted));
        put(p, data + i as u64 * 12, &b)?;
    }
    Ok(0)
}

/// `capset(hdr, data)`: drops capabilities, or raises effective ones that
/// are permitted. Nothing is inheritable (partial).
pub(super) fn capset(p: &mut LinuxProcess, hdr: u64, data: u64) -> Result<u64, i64> {
    let Some((words, pid)) = cap_header(p, hdr, data)? else {
        return Err(EINVAL);
    };
    if pid != 0 && pid != p.entry.pid && pid != p.group.tgid {
        return Err(EPERM);
    }
    let mut sets = [0u64; 3];
    for i in 0..words {
        let mut b = [0u8; 12];
        if p.copy_from_user(data + i as u64 * 12, &mut b) != 12 {
            return Err(EFAULT);
        }
        for (s, w) in sets.iter_mut().zip(b.as_chunks::<4>().0) {
            *s |= u64::from(u32::from_le_bytes(*w)) << (32 * i);
        }
    }
    let [effective, permitted, inheritable] = sets;
    p.group
        .update_creds(|c| {
            if permitted & !c.permitted != 0
                || effective & !permitted != 0
                || inheritable & !c.permitted != 0
            {
                return Err(EPERM);
            }
            c.permitted = permitted;
            c.effective = effective;
            Ok(())
        })
        .map(|()| 0)
}

/// `unshare(flags)`: namespaces need CAP_SYS_ADMIN; what one thread shares
/// with its process here it cannot stop sharing.
pub(super) fn unshare(flags: u64) -> Result<u64, i64> {
    const CLONE_NEW: u64 = 0x7e02_0080;
    match flags {
        0 => Ok(0),
        f if f & CLONE_NEW != 0 => Err(EPERM),
        _ => Err(EINVAL),
    }
}
