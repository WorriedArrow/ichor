//! KVM's paravirtual clock, kvmclock (ADR-0018). The host writes, into a
//! page the guest names, how its TSC turns into nanoseconds (a TSC stamp,
//! the host's time then, a multiplier and a shift), and writes it again
//! when that changes: a live migration to a host whose TSC runs at another
//! rate. On GCP's E2 machines the rate changed by about 96 ppm, and a clock
//! that kept the rate it calibrated at boot lost 8 s a day after one
//! migration. On KVM, frame's clock is this one.
//!
//! The page is the boot CPU's; every CPU reads its numbers, which a
//! sequence counter guards, refreshed from the page at most every 10 ms by
//! whichever CPU finds them due.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

use crate::arch::regs::{cpuid, rdtsc, wrmsr};
use crate::dma::DmaBuf;
use crate::sync::SpinLock;

const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;
const CLOCKSOURCE2: u32 = 1 << 3;

static PAGE: SpinLock<Option<DmaBuf>> = SpinLock::new(None);
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// The host's numbers: sequence (odd while written), TSC stamp, host
/// nanoseconds then, multiplier, shift (as `u64`, sign-extended).
static SEQ: AtomicU64 = AtomicU64::new(0);
static STAMP: AtomicU64 = AtomicU64::new(0);
static HOST_NS: AtomicU64 = AtomicU64::new(0);
static MUL: AtomicU64 = AtomicU64::new(0);
static SHIFT: AtomicU64 = AtomicU64::new(0);
/// The host's nanoseconds at boot, and when the numbers were last read.
static BOOT_NS: AtomicU64 = AtomicU64::new(0);
static READ_AT: AtomicU64 = AtomicU64::new(0);
static REFRESHING: AtomicBool = AtomicBool::new(false);
/// The TSC frequency the numbers mean.
static HZ: AtomicU64 = AtomicU64::new(0);

/// `delta` TSC ticks in nanoseconds, by the host's multiplier and shift.
fn scale(delta: u64, mul: u64, shift: i64) -> u64 {
    let d = if shift >= 0 {
        delta << shift
    } else {
        delta >> -shift
    };
    ((u128::from(d) * u128::from(mul)) >> 32) as u64
}

/// The TSC frequency the multiplier and shift mean.
fn hz(mul: u64, shift: i64) -> u64 {
    let per_tick = u128::from(mul.max(1)) << shift.max(0);
    ((1_000_000_000u128 << 32 << (-shift).max(0)) / per_tick) as u64
}

/// Reads the page into the numbers (one CPU at a time; the others go on
/// with what is there).
fn refresh() {
    if REFRESHING.swap(true, Ordering::Acquire) {
        return;
    }
    if let Some(p) = &*PAGE.lock() {
        for _ in 0..1000 {
            let v = p.read_u32(0);
            fence(Ordering::Acquire);
            let (stamp, ns, mul) = (p.read_u64(8), p.read_u64(16), p.read_u32(24));
            let shift = i64::from((p.read_u32(28) & 0xff) as u8 as i8);
            fence(Ordering::Acquire);
            if v & 1 == 0 && p.read_u32(0) == v {
                SEQ.fetch_add(1, Ordering::AcqRel);
                STAMP.store(stamp, Ordering::Relaxed);
                HOST_NS.store(ns, Ordering::Relaxed);
                MUL.store(u64::from(mul), Ordering::Relaxed);
                SHIFT.store(shift as u64, Ordering::Relaxed);
                SEQ.fetch_add(1, Ordering::Release);
                HZ.store(hz(u64::from(mul), shift), Ordering::Relaxed);
                break;
            }
        }
    }
    READ_AT.store(rdtsc(), Ordering::Relaxed);
    REFRESHING.store(false, Ordering::Release);
}

/// The host's nanoseconds now.
fn host_ns() -> u64 {
    loop {
        let s = SEQ.load(Ordering::Acquire);
        let (stamp, ns) = (
            STAMP.load(Ordering::Relaxed),
            HOST_NS.load(Ordering::Relaxed),
        );
        let (mul, shift) = (
            MUL.load(Ordering::Relaxed),
            SHIFT.load(Ordering::Relaxed) as i64,
        );
        fence(Ordering::Acquire);
        if s & 1 == 0 && SEQ.load(Ordering::Relaxed) == s {
            return ns.wrapping_add(scale(rdtsc().saturating_sub(stamp), mul, shift));
        }
        core::hint::spin_loop();
    }
}

/// Starts kvmclock if this is KVM and it offers it; the TSC frequency it
/// means. Clock time starts now.
pub(crate) fn init() -> Option<u64> {
    let [_, b, c, d] = cpuid(0x4000_0000, 0);
    let kvm =
        crate::arch::cpu::features().hypervisor && [b, c, d] == [0x4b4d_564b, 0x564b_4d56, 0x4d];
    if !kvm || cpuid(0x4000_0001, 0)[0] & CLOCKSOURCE2 == 0 {
        return None;
    }
    let page = DmaBuf::alloc(4096)?;
    let at = page.dma_addr(0)?.as_u64();
    *PAGE.lock() = Some(page);
    // SAFETY: CPUID says this KVM guest has the MSR; the page it names is
    // frame's for good (kept in `PAGE`), and the host writes only its first
    // 32 bytes.
    unsafe { wrmsr(MSR_KVM_SYSTEM_TIME_NEW, at | 1) };
    refresh();
    let hz = HZ.load(Ordering::Relaxed);
    if MUL.load(Ordering::Relaxed) == 0 || hz == 0 {
        return None;
    }
    BOOT_NS.store(host_ns(), Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Release);
    Some(hz)
}

/// Nanoseconds since boot by kvmclock, if it runs.
pub(crate) fn now_ns() -> Option<u64> {
    if !ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let due = HZ.load(Ordering::Relaxed) / 100;
    if rdtsc().wrapping_sub(READ_AT.load(Ordering::Relaxed)) > due {
        refresh();
    }
    Some(host_ns().saturating_sub(BOOT_NS.load(Ordering::Relaxed)))
}

/// The TSC frequency kvmclock now means (it changes with a migration), if
/// it runs.
pub(crate) fn tsc_hz() -> Option<u64> {
    ACTIVE
        .load(Ordering::Acquire)
        .then(|| HZ.load(Ordering::Relaxed))
}
