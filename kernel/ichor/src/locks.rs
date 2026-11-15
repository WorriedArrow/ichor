//! Advisory file locks: `flock` and `fcntl` record locks.
//!
//! One table, keyed by (root, inode). Two independent families, as on
//! Linux:
//!
//! - `flock` locks cover the whole file and belong to an open file
//!   description (they go away when its last descriptor closes).
//! - Record locks cover byte ranges. Classic POSIX locks (`F_SETLK`) belong
//!   to a process, and closing *any* descriptor of the file drops them, as
//!   POSIX requires; OFD locks (`F_OFD_SETLK`) belong to a description.
//!   POSIX and OFD locks conflict with each other.
//!
//! Blocking requests (`F_SETLKW`, `flock` without `LOCK_NB`) wait on one
//! queue woken by every unlock, and give up with `ERESTARTSYS` when a
//! signal arrives. There is no deadlock detection (`EDEADLK`) yet.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use frame::sync::SpinLock;
use frame::task::WaitQueue;

use crate::signal::ERESTARTSYS;

const EAGAIN: i64 = 11;
const EWOULDBLOCK: i64 = EAGAIN;

/// (root identity, inode).
pub(crate) type Key = (usize, overlay::Ino);

/// Who holds a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    /// An open file description (flock, OFD locks).
    Desc(usize),
    /// A process (POSIX record locks), by tgid.
    Proc(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Flock,
    Record,
}

#[derive(Clone, Copy, Debug)]
struct Lock {
    owner: Owner,
    family: Family,
    write: bool,
    start: u64,
    /// Exclusive; `u64::MAX` means "to end of file, however long".
    end: u64,
    /// Reported by `F_GETLK` (-1 for OFD locks).
    pid: i64,
}

static LOCKS: SpinLock<BTreeMap<Key, Vec<Lock>>> = SpinLock::new(BTreeMap::new());
static UNLOCKED: WaitQueue = WaitQueue::new();

fn conflict(
    locks: &[Lock],
    owner: Owner,
    family: Family,
    write: bool,
    start: u64,
    end: u64,
) -> Option<&Lock> {
    locks.iter().find(|l| {
        l.family == family
            && l.owner != owner
            && l.start < end
            && start < l.end
            && (l.write || write)
    })
}

/// Removes `owner`'s `family` coverage of `[start, end)`, splitting locks
/// that straddle the edges.
fn carve(locks: &mut Vec<Lock>, owner: Owner, family: Family, start: u64, end: u64) {
    let mut out = Vec::with_capacity(locks.len() + 1);
    for l in locks.drain(..) {
        if l.owner != owner || l.family != family || l.end <= start || end <= l.start {
            out.push(l);
            continue;
        }
        if l.start < start {
            out.push(Lock { end: start, ..l });
        }
        if end < l.end {
            out.push(Lock { start: end, ..l });
        }
    }
    *locks = out;
}

/// What a record-lock request asks for.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Range {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

/// One lock request.
struct Request {
    owner: Owner,
    family: Family,
    /// `None` unlocks.
    write: Option<bool>,
    range: Range,
    pid: i64,
    wait: bool,
}

fn set(key: Key, req: Request, interrupted: &dyn Fn() -> bool) -> Result<(), i64> {
    let Request {
        owner,
        family,
        write,
        range: r,
        pid,
        wait,
    } = req;
    let Some(write) = write else {
        let mut t = LOCKS.lock();
        if let Some(v) = t.get_mut(&key) {
            carve(v, owner, family, r.start, r.end);
            if v.is_empty() {
                t.remove(&key);
            }
        }
        drop(t);
        UNLOCKED.wake_all();
        return Ok(());
    };
    UNLOCKED.wait_until(|| {
        let mut t = LOCKS.lock();
        let v = t.entry(key).or_default();
        if conflict(v, owner, family, write, r.start, r.end).is_some() {
            if !wait {
                return Some(Err(if family == Family::Flock {
                    EWOULDBLOCK
                } else {
                    EAGAIN
                }));
            }
            if interrupted() {
                return Some(Err(ERESTARTSYS));
            }
            return None;
        }
        carve(v, owner, family, r.start, r.end);
        v.push(Lock {
            owner,
            family,
            write,
            start: r.start,
            end: r.end,
            pid,
        });
        Some(Ok(()))
    })?;
    // Downgrades (exclusive to shared) can let others in.
    UNLOCKED.wake_all();
    Ok(())
}

/// `flock(op)`: `LOCK_SH`, `LOCK_EX`, `LOCK_UN`, optionally `LOCK_NB`.
pub(crate) fn flock(
    key: Key,
    desc: usize,
    op: u64,
    interrupted: &dyn Fn() -> bool,
) -> Result<(), i64> {
    const LOCK_SH: u64 = 1;
    const LOCK_EX: u64 = 2;
    const LOCK_NB: u64 = 4;
    const LOCK_UN: u64 = 8;
    let write = match op & !LOCK_NB {
        LOCK_SH => Some(false),
        LOCK_EX => Some(true),
        LOCK_UN => None,
        _ => return Err(22), // EINVAL
    };
    let req = Request {
        owner: Owner::Desc(desc),
        family: Family::Flock,
        write,
        range: Range {
            start: 0,
            end: u64::MAX,
        },
        pid: -1,
        wait: op & LOCK_NB == 0,
    };
    set(key, req, interrupted)
}

/// A record lock (`F_SETLK`/`F_SETLKW`, `F_OFD_SETLK`/`F_OFD_SETLKW`);
/// `write` `None` unlocks.
pub(crate) fn set_record(
    key: Key,
    owner: Owner,
    write: Option<bool>,
    r: Range,
    wait: bool,
    interrupted: &dyn Fn() -> bool,
) -> Result<(), i64> {
    let pid = match owner {
        Owner::Proc(p) => p as i64,
        Owner::Desc(_) => -1,
    };
    let req = Request {
        owner,
        family: Family::Record,
        write,
        range: r,
        pid,
        wait,
    };
    set(key, req, interrupted)
}

/// `F_GETLK`: the first lock that would block `write` over `r` for
/// `owner`, as (write, start, end, pid).
pub(crate) fn get_record(
    key: Key,
    owner: Owner,
    write: bool,
    r: Range,
) -> Option<(bool, u64, u64, i64)> {
    let t = LOCKS.lock();
    let v = t.get(&key)?;
    conflict(v, owner, Family::Record, write, r.start, r.end)
        .map(|l| (l.write, l.start, l.end, l.pid))
}

/// Drops every lock `owner` holds (a description's last close, a
/// process's exit).
pub(crate) fn release_owner(owner: Owner) {
    let mut any = false;
    {
        let mut t = LOCKS.lock();
        t.retain(|_, v| {
            let before = v.len();
            v.retain(|l| l.owner != owner);
            any |= v.len() != before;
            !v.is_empty()
        });
    }
    if any {
        UNLOCKED.wake_all();
    }
}

/// POSIX: closing any descriptor of a file drops the process's record
/// locks on it.
pub(crate) fn release_process_file(tgid: u64, key: Key) {
    let mut any = false;
    {
        let mut t = LOCKS.lock();
        if let Some(v) = t.get_mut(&key) {
            let before = v.len();
            v.retain(|l| l.owner != Owner::Proc(tgid));
            any = v.len() != before;
            if v.is_empty() {
                t.remove(&key);
            }
        }
    }
    if any {
        UNLOCKED.wake_all();
    }
}
