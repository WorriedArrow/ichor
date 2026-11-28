//! Time: a monotonic clock and per-CPU one-shot timers.
//!
//! The clock is the TSC, whose frequency frame determines at boot. Timers
//! are tickless: a CPU's timer interrupt fires only when armed, and the
//! handler (installed once, for every CPU) decides whether to re-arm. The
//! scheduler (milestone 2) becomes that handler.

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

use crate::arch::apic;

/// The firmware's clock as read at boot: Unix seconds, nanoseconds, and
/// the TSC at the moment of reading.
static WALL_SECS: AtomicU64 = AtomicU64::new(0);
static WALL_NANOS: AtomicU32 = AtomicU32::new(0);
static WALL_TSC: AtomicU64 = AtomicU64::new(0);
static WALL_VALID: AtomicBool = AtomicBool::new(false);

/// The TSC when the firmware (or a PVH loader) entered frame.
static ENTRY_TSC: AtomicU64 = AtomicU64::new(0);

/// Records the TSC at frame's entry point: the first thing it does.
pub(crate) fn record_entry() {
    ENTRY_TSC.store(crate::arch::regs::rdtsc(), Ordering::Relaxed);
}

/// Records the TSC a PVH entry read before it had a stack for Rust.
pub(crate) fn set_entry(tsc: u64) {
    ENTRY_TSC.store(tsc, Ordering::Relaxed);
}

/// Time since the firmware (or a PVH loader) entered frame, by the TSC.
pub fn since_entry() -> Duration {
    let ticks = crate::arch::regs::rdtsc().wrapping_sub(ENTRY_TSC.load(Ordering::Relaxed));
    ticks_to_duration(ticks)
}

/// The TSC's count at frame's entry, as time. A vCPU's TSC starts at 0
/// when the hypervisor makes it (KVM's and Hyper-V's do), so in a VM this
/// is about how long the VMM and the firmware took before the kernel.
pub fn tsc_at_entry() -> Duration {
    ticks_to_duration(ENTRY_TSC.load(Ordering::Relaxed))
}

/// Frame's boot steps, timed for the boot log (`ichor: frame: boot steps`).
#[derive(Clone, Copy)]
pub(crate) enum BootStep {
    /// The firmware's files read (or the PVH loader's modules).
    Files,
    /// Boot services exited.
    Exited,
    /// The higher half reached.
    HigherHalf,
    /// The page allocator and heap ready.
    Memory,
    /// The TSC's frequency known.
    Tsc,
    /// PCI enumerated.
    Pci,
    /// Mitigations enabled: the kernel is about to start.
    Done,
}

const STEPS: usize = 7;
static STEP_TSC: [AtomicU64; STEPS] = [const { AtomicU64::new(0) }; STEPS];

/// Records the TSC as boot reaches `step`.
pub(crate) fn record_step(step: BootStep) {
    STEP_TSC[step as usize].store(crate::arch::regs::rdtsc(), Ordering::Relaxed);
}

/// Time from frame's entry to `step` (zero if it was not recorded).
pub(crate) fn step_time(step: BootStep) -> Duration {
    let entry = ENTRY_TSC.load(Ordering::Relaxed);
    let at = STEP_TSC[step as usize].load(Ordering::Relaxed);
    ticks_to_duration(at.saturating_sub(entry))
}

fn ticks_to_duration(ticks: u64) -> Duration {
    let hz = u128::from(tsc_hz().max(1));
    Duration::from_nanos(u64::try_from(u128::from(ticks) * 1_000_000_000 / hz).unwrap_or(u64::MAX))
}

/// Where the wall clock came from (`UEFI` unless set).
static WALL_SOURCE: crate::sync::SpinLock<&'static str> = crate::sync::SpinLock::new("UEFI");

/// Whether boot has read a wall clock yet.
pub(crate) fn has_wall_clock() -> bool {
    WALL_VALID.load(Ordering::Acquire)
}

/// Records where the wall clock came from, when not from UEFI.
pub(crate) fn set_wall_clock_source(source: &'static str) {
    *WALL_SOURCE.lock() = source;
}

/// Where the wall clock came from: `UEFI` (`GetTime` at boot) or
/// `kvmclock` (KVM's wall clock, under a PVH loader).
pub fn wall_clock_source() -> &'static str {
    *WALL_SOURCE.lock()
}

/// Records the firmware clock reading (boot, before ExitBootServices).
pub(crate) fn set_boot_wall_clock(secs: u64, nanos: u32, tsc: u64) {
    WALL_SECS.store(secs, Ordering::Relaxed);
    WALL_NANOS.store(nanos, Ordering::Relaxed);
    WALL_TSC.store(tsc, Ordering::Relaxed);
    WALL_VALID.store(true, Ordering::Release);
}

/// How the wall clock is steered (by an NTP client, [`steer_wall_clock`]):
/// at monotonic time `STEER_AT` (ns) it is `STEER_BY` ns ahead of the
/// firmware's reading plus the monotonic clock, and gains `STEER_PPB`
/// parts per billion from then on. A sequence counter guards the three.
static STEER_SEQ: AtomicU64 = AtomicU64::new(0);
static STEER_AT: AtomicU64 = AtomicU64::new(0);
static STEER_BY: AtomicI64 = AtomicI64::new(0);
static STEER_PPB: AtomicI64 = AtomicI64::new(0);

/// The steering at monotonic time `t` (ns), and its parts.
fn steering(t: u64) -> (i64, u64, i64, i64) {
    loop {
        let s = STEER_SEQ.load(Ordering::Acquire);
        let (at, by) = (
            STEER_AT.load(Ordering::Relaxed),
            STEER_BY.load(Ordering::Relaxed),
        );
        let ppb = STEER_PPB.load(Ordering::Relaxed);
        if s & 1 == 0 && STEER_SEQ.load(Ordering::Acquire) == s {
            let gained = i128::from(t.saturating_sub(at)) * i128::from(ppb) / 1_000_000_000;
            return (by.saturating_add(gained as i64), at, by, ppb);
        }
        core::hint::spin_loop();
    }
}

/// Steers the wall clock: steps it by `step_ns` now, and from now on has it
/// gain `ppb` parts per billion on the monotonic clock (which timers keep
/// using, unsteered). One caller at a time.
pub fn steer_wall_clock(step_ns: i64, ppb: i64) {
    // A reader interrupting the write on this CPU would wait for it forever.
    let _irq = crate::cpu::IrqGuard::new();
    let t = apic::now_ns();
    let (by, ..) = steering(t);
    STEER_SEQ.fetch_add(1, Ordering::AcqRel);
    STEER_AT.store(t, Ordering::Relaxed);
    STEER_BY.store(by.saturating_add(step_ns), Ordering::Relaxed);
    STEER_PPB.store(ppb, Ordering::Relaxed);
    STEER_SEQ.fetch_add(1, Ordering::Release);
}

/// The time of day as time since the Unix epoch (UTC): the firmware's
/// clock as read at boot plus the monotonic clock since (kvmclock's on
/// KVM, so a migration does not make it drift), as steered by an NTP
/// client if one runs. `None` if the firmware had no clock to read.
pub fn wall_clock() -> Option<Duration> {
    if !WALL_VALID.load(Ordering::Acquire) {
        return None;
    }
    // From the reading to boot, by the TSC; from boot on, the clock.
    // (Negative when the reading came after boot: kvmclock's, ADR-0025.)
    let hz = i128::from(tsc_hz().max(1));
    let before = i128::from(apic::tsc_at_boot()) - i128::from(WALL_TSC.load(Ordering::Relaxed));
    let before = before * 1_000_000_000 / hz;
    let t = apic::now_ns();
    let secs = i128::from(WALL_SECS.load(Ordering::Relaxed)) * 1_000_000_000;
    let ns = secs + i128::from(WALL_NANOS.load(Ordering::Relaxed)) + before + i128::from(t);
    let ns = ns.saturating_add(i128::from(steering(t).0)).max(0);
    Some(Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX)))
}

/// Time since boot.
pub fn now() -> Duration {
    Duration::from_nanos(apic::now_ns())
}

/// TSC frequency in Hz.
pub fn tsc_hz() -> u64 {
    apic::tsc_hz()
}

/// Installs the function every CPU runs on its timer interrupt. It runs
/// with interrupts masked and must not block.
pub fn set_timer_handler(handler: fn()) {
    apic::set_timer_handler(handler);
}

/// Arms the current CPU's timer to fire once after `delay`, calling the
/// handler from [`set_timer_handler`]. Independent of the scheduler's
/// timeslice timer.
pub fn arm_timer(delay: Duration) {
    apic::arm(
        apic::TimerKind::Kernel,
        u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX),
    );
}

/// Arms the current CPU's scheduler timeslice.
pub(crate) fn arm_slice(delay: Duration) {
    apic::arm(
        apic::TimerKind::Slice,
        u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX),
    );
}

/// Busy-waits for `d`.
pub fn spin_for(d: Duration) {
    apic::delay_us(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
}

/// `cpu`'s armed timer deadlines (scheduler slice, kernel timer, timed
/// waits) in nanoseconds from now; for diagnostics.
pub fn deadlines(cpu: crate::cpu::CpuId) -> [Option<i64>; 3] {
    apic::deadlines_ns(cpu)
}
