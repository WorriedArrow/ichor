//! Futexes: user-space locks' kernel half.
//!
//! Waiters are kept per (process, address), except in shared anonymous
//! memory, where they are kept per physical address so that processes
//! sharing the page meet on the same futex (with or without
//! `FUTEX_PRIVATE_FLAG`: a wake that Linux would confine to one process
//! may reach another, which futex users must tolerate as a spurious
//! wakeup). There are no shared file mappings yet.
//!
//! Waiters live in [`BUCKETS`] hashed buckets, each with its own lock, so
//! unrelated futexes (other processes, other addresses) do not contend.
//! A key's bucket lock is held while the user word is read atomically and
//! the waiter queued, and wakers take the same lock, so a wake between
//! "check the value" and "go to sleep" cannot be lost. Operations on two
//! keys (requeue, wake-op) lock both buckets in index order.
//!
//! Supported: WAIT, WAKE, REQUEUE, CMP_REQUEUE, WAKE_OP, WAIT_BITSET,
//! WAKE_BITSET. PI futexes and `FUTEX_FD` are not.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use frame::sync::{Mutex, SpinLock};
use frame::task::WaitQueue;

use crate::proc;
use crate::process::LinuxProcess;

const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOSYS: i64 = 38;
const ETIMEDOUT: i64 = 110;

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_WAKE_OP: u64 = 5;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const FUTEX_CLOCK_REALTIME: u64 = 256;

/// (shared, process identity or cell, user or physical address).
type Key = (bool, usize, u64);

#[derive(Debug)]
struct Waiter {
    bitset: u32,
    woken: AtomicBool,
    /// Where the waiter is queued now (a requeue moves it).
    key: SpinLock<Key>,
    queue: WaitQueue,
}

/// The waiters of the keys that hash to one bucket.
type Table = BTreeMap<Key, VecDeque<Arc<Waiter>>>;

/// Number of buckets (a power of two).
const BUCKETS: usize = 64;

static FUTEXES: [Mutex<Table>; BUCKETS] = [const { Mutex::new(BTreeMap::new()) }; BUCKETS];

fn key(p: &LinuxProcess, addr: u64) -> Key {
    match p.mm().shared_phys(addr) {
        Some(pa) => (true, p.cell.id() as usize, pa),
        None => (false, Arc::as_ptr(&p.group) as usize, addr),
    }
}

/// The bucket `k` lives in: a multiplicative hash of the whole key.
fn bucket(k: &Key) -> usize {
    let mixed = (k.2 >> 2) ^ (k.1 as u64).rotate_left(29) ^ u64::from(k.0);
    (mixed.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - BUCKETS.trailing_zeros())) as usize
}

/// Runs `f` with the tables of `a`'s and `b`'s buckets locked (lower index
/// first); the second table is `None` when both keys share a bucket.
fn with_two<R>(a: &Key, b: &Key, f: impl FnOnce(&mut Table, Option<&mut Table>) -> R) -> R {
    let (i, j) = (bucket(a), bucket(b));
    if i == j {
        return f(&mut FUTEXES[i].lock(), None);
    }
    let (lo, hi) = (i.min(j), i.max(j));
    let mut first = FUTEXES[lo].lock();
    let mut second = FUTEXES[hi].lock();
    if i < j {
        f(&mut first, Some(&mut second))
    } else {
        f(&mut second, Some(&mut first))
    }
}

/// The robust list's head: `{ next, futex_offset, list_op_pending }`.
pub(crate) const ROBUST_HEAD_LEN: u64 = 24;

/// A dying thread's robust futexes (Linux's `exit_robust_list`): every
/// lock on its list (and the one it was taking or dropping, per
/// `list_op_pending`) whose word still names it is marked
/// FUTEX_OWNER_DIED, and one waiter is woken, so the next locker gets
/// EOWNERDEAD instead of hanging. A list that cannot be read, or longer
/// than Linux's 2048 entries, is followed only as far as it goes.
pub(crate) fn exit_robust_list(p: &mut LinuxProcess) {
    const LIMIT: usize = 2048;
    let head = core::mem::take(&mut p.robust_list);
    if head == 0 {
        return;
    }
    let read = |p: &mut LinuxProcess, a: u64| -> Option<u64> {
        let mut b = [0u8; 8];
        (p.copy_from_user(a, &mut b) == 8).then(|| u64::from_le_bytes(b))
    };
    let (Some(mut entry), Some(offset), Some(pending)) =
        (read(p, head), read(p, head + 8), read(p, head + 16))
    else {
        return;
    };
    let tid = p.entry.pid as u32;
    // Bit 0 of an entry marks a PI futex; the address is the rest.
    let pending = pending & !1;
    for _ in 0..LIMIT {
        if entry == head || entry == 0 {
            break;
        }
        let next = read(p, entry);
        if entry & !1 != pending {
            owner_died(p, (entry & !1).wrapping_add(offset), tid);
        }
        match next {
            Some(n) => entry = n,
            None => break,
        }
    }
    if pending != 0 {
        owner_died(p, pending.wrapping_add(offset), tid);
    }
}

/// Marks the futex word at `addr` FUTEX_OWNER_DIED if thread `tid` holds it,
/// waking one waiter if there were any.
fn owner_died(p: &LinuxProcess, addr: u64, tid: u32) {
    const FUTEX_WAITERS: u32 = 0x8000_0000;
    const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
    const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
    let waiters = loop {
        let mm = p.mm();
        let space = mm.space();
        let Some(cur) = space.load_u32_atomic(addr) else {
            return;
        };
        if cur & FUTEX_TID_MASK != tid {
            return;
        }
        let new = (cur & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        match space.compare_exchange_u32(addr, cur, new) {
            None => return,
            Some(Ok(_)) => break cur & FUTEX_WAITERS != 0,
            Some(Err(_)) => continue,
        }
    };
    if waiters {
        wake(p, addr, 1, u32::MAX);
    }
}

/// Wakes up to `n` waiters on `addr` whose bitset meets `bitset`; returns
/// how many.
pub(crate) fn wake(p: &LinuxProcess, addr: u64, n: u32, bitset: u32) -> u64 {
    let k = key(p, addr);
    wake_key(&mut FUTEXES[bucket(&k)].lock(), k, n, bitset)
}

fn wake_key(t: &mut Table, k: Key, n: u32, bitset: u32) -> u64 {
    let mut woken = 0u64;
    if let Some(q) = t.get_mut(&k) {
        let mut keep = VecDeque::new();
        while let Some(w) = q.pop_front() {
            if woken < u64::from(n) && w.bitset & bitset != 0 {
                w.woken.store(true, Ordering::SeqCst);
                w.queue.wake_all();
                woken += 1;
            } else {
                keep.push_back(w);
            }
        }
        *q = keep;
        if q.is_empty() {
            t.remove(&k);
        }
    }
    woken
}

fn read_timespec(p: &mut LinuxProcess, addr: u64) -> Result<Duration, i64> {
    let mut b = [0u8; 16];
    if p.copy_from_user(addr, &mut b) != 16 {
        return Err(EFAULT);
    }
    let sec = u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
    let nsec = u64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
    if nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    Ok(Duration::from_secs(sec).saturating_add(Duration::from_nanos(nsec)))
}

fn wait(
    p: &mut LinuxProcess,
    addr: u64,
    val: u32,
    deadline: Option<Duration>,
    bitset: u32,
) -> Result<u64, i64> {
    if bitset == 0 {
        return Err(EINVAL);
    }
    let deadline = deadline.map(|d| p.resume_until.take().unwrap_or(d));
    p.mm().populate(addr, 4, false);
    let k = key(p, addr);
    let w = Arc::new(Waiter {
        bitset,
        woken: AtomicBool::new(false),
        key: SpinLock::new(k),
        queue: WaitQueue::new(),
    });
    {
        let mut t = FUTEXES[bucket(&k)].lock();
        let cur = p.mm().space().load_u32_atomic(addr).ok_or(EFAULT)?;
        if cur != val {
            return Err(EAGAIN);
        }
        t.entry(k).or_default().push_back(w.clone());
    }
    let entry = p.entry.clone();
    let cond = || (w.woken.load(Ordering::SeqCst) || proc::interrupted(&entry)).then_some(());
    let timed_out = match deadline {
        Some(d) => w.queue.wait_until_deadline(d, cond).is_none(),
        None => {
            w.queue.wait_until(cond);
            false
        }
    };
    if w.woken.load(Ordering::SeqCst) {
        return Ok(0);
    }
    // Leave the queue we are on. A requeue may move us, and changes our key
    // only while holding our current bucket, so the key read under that
    // bucket's lock is where we are.
    loop {
        let k = *w.key.lock();
        let mut t = FUTEXES[bucket(&k)].lock();
        if *w.key.lock() != k {
            continue; // moved meanwhile: try the new bucket
        }
        if let Some(q) = t.get_mut(&k) {
            q.retain(|x| !Arc::ptr_eq(x, &w));
            if q.is_empty() {
                t.remove(&k);
            }
        }
        break;
    }
    if w.woken.load(Ordering::SeqCst) {
        return Ok(0); // woken while we were leaving
    }
    match deadline {
        Some(_) if timed_out => Err(ETIMEDOUT),
        // A timed wait goes on to its deadline if no handler runs (else
        // EINTR), an untimed one restarts as any blocking call does.
        Some(_) => {
            p.resume_until = deadline;
            Err(crate::signal::ERESTARTNOHAND)
        }
        None => Err(crate::signal::ERESTARTSYS),
    }
}

fn requeue(
    p: &mut LinuxProcess,
    addr: u64,
    n_wake: u32,
    n_move: u32,
    addr2: u64,
    expect: Option<u32>,
) -> Result<u64, i64> {
    let (k1, k2) = (key(p, addr), key(p, addr2));
    if expect.is_some() {
        p.mm().populate(addr, 4, false);
    }
    with_two(&k1, &k2, |t1, t2| {
        if let Some(v) = expect {
            let cur = p.mm().space().load_u32_atomic(addr).ok_or(EFAULT)?;
            if cur != v {
                return Err(EAGAIN);
            }
        }
        let woken = wake_key(t1, k1, n_wake, u32::MAX);
        let mut moved = 0u64;
        let mut take = VecDeque::new();
        if let Some(q) = t1.get_mut(&k1) {
            while moved < u64::from(n_move) {
                let Some(w) = q.pop_front() else { break };
                // Both buckets are held, so a leaving waiter sees either
                // key consistently.
                *w.key.lock() = k2;
                take.push_back(w);
                moved += 1;
            }
            if q.is_empty() {
                t1.remove(&k1);
            }
        }
        if !take.is_empty() {
            t2.unwrap_or(t1).entry(k2).or_default().extend(take);
        }
        Ok(woken + moved)
    })
}

/// `FUTEX_WAKE_OP`: atomically applies `op` to `*addr2`, wakes `n1` on
/// `addr`, and `n2` on `addr2` if the old value passes the comparison.
fn wake_op(
    p: &mut LinuxProcess,
    addr: u64,
    n1: u32,
    addr2: u64,
    n2: u32,
    op: u32,
) -> Result<u64, i64> {
    let kind = (op >> 28) & 7;
    let shift = op & (8 << 28) != 0;
    let cmp = (op >> 24) & 15;
    let mut oparg = (op >> 12) & 0xfff;
    let cmparg = op & 0xfff;
    if shift {
        oparg = 1u32.checked_shl(oparg).unwrap_or(0);
    }
    p.mm().populate(addr2, 4, true);
    let (k1, k2) = (key(p, addr), key(p, addr2));
    with_two(&k1, &k2, |t1, t2| {
        wake_op_locked(
            p,
            addr2,
            kind,
            cmp,
            oparg,
            cmparg,
            n1,
            n2,
            (k1, t1),
            (k2, t2),
        )
    })
}

#[allow(clippy::too_many_arguments)] // the decoded fields of one futex op
fn wake_op_locked(
    p: &LinuxProcess,
    addr2: u64,
    kind: u32,
    cmp: u32,
    oparg: u32,
    cmparg: u32,
    n1: u32,
    n2: u32,
    (k1, t1): (Key, &mut Table),
    (k2, t2): (Key, Option<&mut Table>),
) -> Result<u64, i64> {
    let old = loop {
        let mm = p.mm();
        let space = mm.space();
        let cur = space.load_u32_atomic(addr2).ok_or(EFAULT)?;
        let new = match kind {
            0 => oparg,                   // SET
            1 => cur.wrapping_add(oparg), // ADD
            2 => cur | oparg,             // OR
            3 => cur & !oparg,            // ANDN
            4 => cur ^ oparg,             // XOR
            _ => return Err(ENOSYS),
        };
        match space.compare_exchange_u32(addr2, cur, new).ok_or(EFAULT)? {
            Ok(_) => break cur,
            Err(_) => continue,
        }
    };
    let ok = match cmp {
        0 => old == cmparg,
        1 => old != cmparg,
        2 => (old as i32) < (cmparg as i32),
        3 => (old as i32) <= (cmparg as i32),
        4 => (old as i32) > (cmparg as i32),
        5 => (old as i32) >= (cmparg as i32),
        _ => return Err(ENOSYS),
    };
    let mut n = wake_key(t1, k1, n1, u32::MAX);
    if ok {
        n += wake_key(t2.unwrap_or(t1), k2, n2, u32::MAX);
    }
    Ok(n)
}

/// `futex(uaddr, op, val, timeout_or_val2, uaddr2, val3)`.
pub(crate) fn futex(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let (addr, op, val, arg4, addr2, val3) = (a[0], a[1], a[2] as u32, a[3], a[4], a[5] as u32);
    if !addr.is_multiple_of(4) {
        return Err(EINVAL);
    }
    match op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME) {
        FUTEX_WAIT => {
            // Relative timeout.
            let deadline = if arg4 == 0 {
                None
            } else {
                Some(frame::time::now().saturating_add(read_timespec(p, arg4)?))
            };
            wait(p, addr, val, deadline, u32::MAX)
        }
        FUTEX_WAIT_BITSET => {
            // Absolute timeout (every clock counts from boot here).
            let deadline = if arg4 == 0 {
                None
            } else {
                Some(read_timespec(p, arg4)?)
            };
            wait(p, addr, val, deadline, val3)
        }
        FUTEX_WAKE => Ok(wake(p, addr, val, u32::MAX)),
        FUTEX_WAKE_BITSET => {
            if val3 == 0 {
                return Err(EINVAL);
            }
            Ok(wake(p, addr, val, val3))
        }
        FUTEX_REQUEUE => requeue(p, addr, val, arg4 as u32, addr2, None),
        FUTEX_CMP_REQUEUE => requeue(p, addr, val, arg4 as u32, addr2, Some(val3)),
        FUTEX_WAKE_OP => wake_op(p, addr, val, addr2, arg4 as u32, val3),
        _ => Err(ENOSYS),
    }
}
