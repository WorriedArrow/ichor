//! System V shared memory: `shmget`, `shmat`, `shmdt`, `shmctl`. Segments
//! belong to a cell (its IPC namespace) and are its memory: every page is
//! made, and charged, when the segment is. A segment goes with its last
//! attachment once it was removed, and counts attachments exactly
//! (PostgreSQL finds a dead postmaster's leftovers by `shm_nattch`), over
//! `fork`, `execve` and whatever way a process ends.
//!
//! Partial: no `SHM_HUGETLB`, `SHM_REMAP`, `SHM_LOCK`; a partly unmapped
//! attachment still counts. Semaphores and message queues are not here.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use frame::mm::UFrame;
use frame::sync::SpinLock;

use super::{EACCES, EFAULT, EINVAL, EPERM};
use crate::cred::Creds;
use crate::page::{Page, charged};
use crate::process::LinuxProcess;

const ENOENT: i64 = 2;
const ENOMEM: i64 = 12;
const EEXIST: i64 = 17;
const ENOSPC: i64 = 28;
const EIDRM: i64 = 43;

const PAGE_SIZE: u64 = 4096;
const IPC_PRIVATE: u32 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
/// `shm_perm.mode`: removed, going with the last attachment.
const SHM_DEST: u32 = 0o1000;
/// Most segments of a cell (Linux's `SHMMNI`).
const SHMMNI: usize = 4096;

/// What `IPC_SET` may change, and the times.
#[derive(Debug)]
struct Status {
    key: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    atime: u64,
    dtime: u64,
    ctime: u64,
    last_pid: u64,
    removed: bool,
}

#[derive(Debug)]
struct Segment {
    cell: u64,
    id: i32,
    size: u64,
    creator: (u32, u32),
    creator_pid: u64,
    pages: Vec<Page>,
    attached: AtomicU64,
    status: SpinLock<Status>,
}

static SEGMENTS: SpinLock<BTreeMap<(u64, i32), Arc<Segment>>> = SpinLock::new(BTreeMap::new());

/// An address space's attachment of a segment. Cloned by `fork`.
#[derive(Debug)]
pub(crate) struct Attached {
    segment: Arc<Segment>,
    pid: u64,
}

impl Clone for Attached {
    fn clone(&self) -> Attached {
        self.segment.attached.fetch_add(1, Ordering::AcqRel);
        Attached {
            segment: self.segment.clone(),
            pid: self.pid,
        }
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        let last = self.segment.attached.fetch_sub(1, Ordering::AcqRel) == 1;
        let removed = {
            let mut s = self.segment.status.lock();
            s.dtime = seconds();
            s.last_pid = self.pid;
            s.removed
        };
        if last && removed {
            let gone = SEGMENTS
                .lock()
                .remove(&(self.segment.cell, self.segment.id));
            drop(gone);
        }
    }
}

fn seconds() -> u64 {
    crate::vfs::wall_clock().as_secs()
}

impl Segment {
    /// Whether `c` may access it as `want` (`MAY_READ`/`MAY_WRITE` bits).
    fn permits(&self, c: &Creds, want: u32) -> bool {
        let s = self.status.lock();
        if c.euid == 0 {
            return true;
        }
        let in_group = |g: u32| c.egid == g || c.groups.contains(&g);
        let bits = if c.euid == s.uid || c.euid == self.creator.0 {
            s.mode >> 6
        } else if in_group(s.gid) || in_group(self.creator.1) {
            s.mode >> 3
        } else {
            s.mode
        };
        bits & want == want
    }

    /// Whether `c` may change or remove it.
    fn owned_by(&self, c: &Creds) -> bool {
        c.euid == 0 || c.euid == self.creator.0 || c.euid == self.status.lock().uid
    }
}

fn segment(p: &LinuxProcess, id: u64) -> Result<Arc<Segment>, i64> {
    let id = i32::try_from(id & 0xffff_ffff).map_err(|_| EINVAL)?;
    SEGMENTS
        .lock()
        .get(&(p.entry.cell, id))
        .cloned()
        .ok_or(EINVAL)
}

/// `shmget(key, size, flags)`.
pub(super) fn get(p: &mut LinuxProcess, key: u64, size: u64, flags: u64) -> Result<u64, i64> {
    let key = key as u32;
    let cell = p.entry.cell;
    let creds = p.group.creds();
    if key != IPC_PRIVATE {
        let found = SEGMENTS
            .lock()
            .values()
            .find(|s| s.cell == cell && s.status.lock().key == key)
            .cloned();
        if let Some(s) = found {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return Err(EEXIST);
            }
            if size > s.size {
                return Err(EINVAL);
            }
            let want = ((flags >> 6 | flags >> 3 | flags) & 0o6) as u32;
            if !s.permits(&creds, want) {
                return Err(EACCES);
            }
            return Ok(s.id as u64);
        }
        if flags & IPC_CREAT == 0 {
            return Err(ENOENT);
        }
    }
    if size == 0 || size > 1 << 40 {
        return Err(EINVAL);
    }
    let mut pages = Vec::new();
    for _ in 0..size.div_ceil(PAGE_SIZE) {
        let frame = UFrame::alloc_zeroed().ok_or(ENOMEM)?;
        pages.push(charged(p.cell.account(), frame).ok_or(ENOMEM)?);
    }
    let (uid, gid) = (creds.euid, creds.egid);
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut all = SEGMENTS.lock();
    if all.range((cell, 0)..=(cell, i32::MAX)).count() >= SHMMNI {
        return Err(ENOSPC);
    }
    let same = |s: &Arc<Segment>| s.cell == cell && s.status.lock().key == key;
    if key != IPC_PRIVATE && all.values().any(same) {
        return Err(EEXIST); // made meanwhile
    }
    let id = (NEXT.fetch_add(1, Ordering::Relaxed) & 0x7fff_ffff) as i32;
    all.insert(
        (cell, id),
        Arc::new(Segment {
            cell,
            id,
            size,
            creator: (uid, gid),
            creator_pid: p.group.tgid,
            pages,
            attached: AtomicU64::new(0),
            status: SpinLock::new(Status {
                key,
                uid,
                gid,
                mode: (flags & 0o777) as u32,
                atime: 0,
                dtime: 0,
                ctime: seconds(),
                last_pid: 0,
                removed: false,
            }),
        }),
    );
    Ok(id as u64)
}

/// `shmat(id, addr, flags)`.
pub(super) fn attach(p: &mut LinuxProcess, id: u64, addr: u64, flags: u64) -> Result<u64, i64> {
    const SHM_RDONLY: u64 = 0o10000;
    const SHM_RND: u64 = 0o20000;
    const SHM_EXEC: u64 = 0o100_000;
    const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
    const PROT_READ: u64 = 1;
    const PROT_WRITE: u64 = 2;
    const PROT_EXEC: u64 = 4;
    if flags & !(SHM_RDONLY | SHM_RND | SHM_EXEC) != 0 {
        return Err(EINVAL);
    }
    let addr = if flags & SHM_RND != 0 {
        addr & !(PAGE_SIZE - 1)
    } else {
        addr
    };
    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(EINVAL);
    }
    let s = segment(p, id)?;
    let write = flags & SHM_RDONLY == 0;
    if !s.permits(&p.group.creds(), if write { 0o6 } else { 0o4 }) {
        return Err(EACCES);
    }
    let mut prot = PROT_READ;
    if write {
        prot |= PROT_WRITE;
    }
    if flags & SHM_EXEC != 0 {
        prot |= PROT_EXEC;
    }
    let place = if addr == 0 { 0 } else { MAP_FIXED_NOREPLACE };
    let pid = p.group.tgid;
    // Counted before it is mapped, so a removal meanwhile leaves the pages.
    s.attached.fetch_add(1, Ordering::AcqRel);
    let hold = Attached {
        segment: s.clone(),
        pid,
    };
    let at = p.mm().attach(addr, &s.pages, prot, place, hold)?;
    let mut st = s.status.lock();
    st.atime = seconds();
    st.last_pid = pid;
    Ok(at)
}

/// `shmdt(addr)`.
pub(super) fn detach(p: &mut LinuxProcess, addr: u64) -> Result<u64, i64> {
    p.mm().detach(addr)
}

/// `shmctl(id, cmd, buf)`.
pub(super) fn control(p: &mut LinuxProcess, id: u64, cmd: u64, buf: u64) -> Result<u64, i64> {
    const IPC_RMID: u64 = 0;
    const IPC_SET: u64 = 1;
    const IPC_STAT: u64 = 2;
    const IPC_INFO: u64 = 3;
    const IPC_64: u64 = 0x100;
    let cmd = cmd & 0xffff_ffff & !IPC_64;
    if cmd == IPC_INFO {
        // struct shminfo64: shmmax, shmmin, shmmni, shmseg, shmall.
        let mut b = [0u8; 72];
        for (i, v) in [1u64 << 40, 1, SHMMNI as u64, SHMMNI as u64, 1 << 28]
            .iter()
            .enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        return if p.copy_to_user(buf, &b) == b.len() {
            Ok(0)
        } else {
            Err(EFAULT)
        };
    }
    let s = segment(p, id)?;
    let creds = p.group.creds();
    match cmd {
        IPC_STAT => {
            if !s.permits(&creds, 0o4) {
                return Err(EACCES);
            }
            let b = stat(&s);
            if p.copy_to_user(buf, &b) != b.len() {
                return Err(EFAULT);
            }
            Ok(0)
        }
        IPC_SET => {
            let mut b = [0u8; 112];
            if p.copy_from_user(buf, &mut b) != b.len() {
                return Err(EFAULT);
            }
            if !s.owned_by(&creds) {
                return Err(EPERM);
            }
            let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
            let mut st = s.status.lock();
            (st.uid, st.gid) = (word(4), word(8));
            st.mode = word(20) & 0o777;
            st.ctime = seconds();
            Ok(0)
        }
        IPC_RMID => {
            if !s.owned_by(&creds) {
                return Err(EPERM);
            }
            {
                let mut st = s.status.lock();
                if st.removed {
                    return Err(EIDRM);
                }
                st.removed = true;
                st.key = IPC_PRIVATE; // a new one may take the key
            }
            if s.attached.load(Ordering::Acquire) == 0 {
                let gone = SEGMENTS.lock().remove(&(s.cell, s.id));
                drop(gone);
            }
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

/// `struct shmid64_ds`.
fn stat(s: &Segment) -> [u8; 112] {
    let st = s.status.lock();
    let mode = st.mode | if st.removed { SHM_DEST } else { 0 };
    let mut b = [0u8; 112];
    for (i, v) in [st.key, st.uid, st.gid, s.creator.0, s.creator.1, mode]
        .iter()
        .enumerate()
    {
        b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    for (i, v) in [s.size, st.atime, st.dtime, st.ctime].iter().enumerate() {
        b[48 + i * 8..56 + i * 8].copy_from_slice(&v.to_le_bytes());
    }
    b[80..84].copy_from_slice(&(s.creator_pid as u32).to_le_bytes());
    b[84..88].copy_from_slice(&(st.last_pid as u32).to_le_bytes());
    let n = s.attached.load(Ordering::Acquire);
    b[88..96].copy_from_slice(&n.to_le_bytes());
    b
}
