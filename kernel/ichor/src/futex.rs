//! Futexes: user-space locks' kernel half.
//!
//! Waiters are kept per (process, address), so semantics are those of
//! `FUTEX_PRIVATE_FLAG` for every futex: a shared futex in memory mapped
//! into two processes is not supported (shared file mappings do not exist
//! yet either). The table lock is held while the user word is read
//! atomically and the waiter queued, and wakers take the same lock, so a
//! wake between "check the value" and "go to sleep" cannot be lost.
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
const EINTR: i64 = 4;

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_WAKE_OP: u64 = 5;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const FUTEX_CLOCK_REALTIME: u64 = 256;

/// (process identity, user address).
type Key = (usize, u64);

#[derive(Debug)]
struct Waiter {
    bitset: u32,
    woken: AtomicBool,
    /// Where the waiter is queued now (a requeue moves it).
    key: SpinLock<Key>,
    queue: WaitQueue,
}

static FUTEXES: Mutex<BTreeMap<Key, VecDeque<Arc<Waiter>>>> = Mutex::new(BTreeMap::new());

fn key(p: &LinuxProcess, addr: u64) -> Key {
    (Arc::as_ptr(&p.group) as usize, addr)
}

/// Wakes up to `n` waiters on `addr` whose bitset meets `bitset`; returns
/// how many.
pub(crate) fn wake(p: &LinuxProcess, addr: u64, n: u32, bitset: u32) -> u64 {
    wake_key(&mut FUTEXES.lock(), key(p, addr), n, bitset)
}

fn wake_key(t: &mut BTreeMap<Key, VecDeque<Arc<Waiter>>>, k: Key, n: u32, bitset: u32) -> u64 {
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
    p.mm().populate(addr, 4, false);
    let k = key(p, addr);
    let w = Arc::new(Waiter {
        bitset,
        woken: AtomicBool::new(false),
        key: SpinLock::new(k),
        queue: WaitQueue::new(),
    });
    {
        let mut t = FUTEXES.lock();
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
    // Leave the queue we are on (a requeue may have moved us).
    {
        let mut t = FUTEXES.lock();
        let k = *w.key.lock();
        if let Some(q) = t.get_mut(&k) {
            q.retain(|x| !Arc::ptr_eq(x, &w));
            if q.is_empty() {
                t.remove(&k);
            }
        }
    }
    if w.woken.load(Ordering::SeqCst) {
        return Ok(0); // woken while we were leaving
    }
    Err(if timed_out { ETIMEDOUT } else { EINTR })
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
    let mut t = FUTEXES.lock();
    if let Some(v) = expect {
        let cur = p.mm().space().load_u32_atomic(addr).ok_or(EFAULT)?;
        if cur != v {
            return Err(EAGAIN);
        }
    }
    let woken = wake_key(&mut t, k1, n_wake, u32::MAX);
    let mut moved = 0u64;
    let mut take = VecDeque::new();
    if let Some(q) = t.get_mut(&k1) {
        while moved < u64::from(n_move) {
            let Some(w) = q.pop_front() else { break };
            *w.key.lock() = k2;
            take.push_back(w);
            moved += 1;
        }
        if q.is_empty() {
            t.remove(&k1);
        }
    }
    if !take.is_empty() {
        t.entry(k2).or_default().extend(take);
    }
    Ok(woken + moved)
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
    let mut t = FUTEXES.lock();
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
    let mut n = wake_key(&mut t, key(p, addr), n1, u32::MAX);
    if ok {
        n += wake_key(&mut t, key(p, addr2), n2, u32::MAX);
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
