//! Local x2APIC, the per-CPU timer, IPIs and TSC calibration.
//!
//! Ichor requires x2APIC (every cloud VM and server CPU of the last decade
//! has it), so the local APIC is programmed entirely through MSRs and needs
//! no MMIO mapping. The 8259 PICs are masked and never used. The timer runs
//! in TSC-deadline mode when available, else in one-shot mode calibrated
//! against the TSC; either way it only fires when armed (tickless).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use super::io::{inb, inl, outb};
use super::regs::{self, cpuid, rdmsr, rdtsc, wrmsr};
use super::trap::TrapFrame;
use crate::sync::SpinLock;

const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2APIC: u64 = 1 << 10;

const MSR_ID: u32 = 0x802;
const MSR_TPR: u32 = 0x808;
const MSR_EOI: u32 = 0x80B;
const MSR_SVR: u32 = 0x80F;
const MSR_ICR: u32 = 0x830;
const MSR_LVT_TIMER: u32 = 0x832;
const MSR_LVT_LINT0: u32 = 0x835;
const MSR_LVT_LINT1: u32 = 0x836;
const MSR_LVT_ERROR: u32 = 0x837;
const MSR_TIMER_INIT: u32 = 0x838;
const MSR_TIMER_CURRENT: u32 = 0x839;
const MSR_TIMER_DIVIDE: u32 = 0x83E;

const LVT_MASKED: u64 = 1 << 16;
const LVT_NMI: u64 = 0b100 << 8;
const LVT_TSC_DEADLINE: u64 = 0b10 << 17;

pub(crate) const TIMER_VECTOR: u8 = 0x20;
pub(crate) const IPI_VECTOR: u8 = 0xF0;
const ERROR_VECTOR: u8 = 0xFE;
const SPURIOUS_VECTOR: u8 = 0xFF;

static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_AT_BOOT: AtomicU64 = AtomicU64::new(0);
/// LAPIC timer ticks per millisecond (one-shot mode only).
static LAPIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);
static DEADLINE_MODE: AtomicBool = AtomicBool::new(false);

static TIMER_HANDLER: SpinLock<Option<fn()>> = SpinLock::new(None);
static IPI_HANDLER: SpinLock<Option<fn()>> = SpinLock::new(None);
static UNEXPECTED_IRQS: AtomicU64 = AtomicU64::new(0);

fn write(msr: u32, v: u64) {
    // SAFETY: `msr` is one of the x2APIC registers above, which exist once
    // x2APIC mode is enabled (`init_local` runs first on every CPU). They
    // only affect interrupt delivery to and from this CPU.
    unsafe { wrmsr(msr, v) };
}

fn read(msr: u32) -> u64 {
    // SAFETY: as in `write`; reads of these registers have no side effects.
    unsafe { rdmsr(msr) }
}

/// Puts this CPU's local APIC in x2APIC mode with all local interrupts
/// masked except NMI on LINT1 and the error interrupt.
pub(crate) fn init_local() -> Result<(), &'static str> {
    let f = super::cpu::features();
    if !f.x2apic {
        return Err("CPU lacks x2APIC");
    }
    // SAFETY: IA32_APIC_BASE exists on every x2APIC-capable CPU. Enabling
    // the APIC and then x2APIC mode is the architectural sequence (xAPIC ->
    // x2APIC); it changes only how this CPU's APIC is accessed.
    let base = unsafe { rdmsr(regs::MSR_APIC_BASE) };
    // SAFETY: as above (global enable first).
    unsafe { wrmsr(regs::MSR_APIC_BASE, base | APIC_BASE_ENABLE) };
    // SAFETY: as above (then x2APIC mode).
    unsafe {
        wrmsr(
            regs::MSR_APIC_BASE,
            base | APIC_BASE_ENABLE | APIC_BASE_X2APIC,
        )
    };
    write(MSR_TPR, 0);
    write(MSR_LVT_LINT0, LVT_MASKED);
    write(MSR_LVT_LINT1, LVT_NMI);
    write(MSR_LVT_ERROR, u64::from(ERROR_VECTOR));
    write(MSR_LVT_TIMER, LVT_MASKED);
    write(MSR_SVR, 0x100 | u64::from(SPURIOUS_VECTOR));
    Ok(())
}

/// Masks both 8259 PICs. Frame owns ports 0x20/0x21/0xA0/0xA1.
pub(crate) fn mask_legacy_pic() {
    // SAFETY: frame owns the PIC ports; masking all lines has no effect
    // beyond stopping legacy interrupts.
    unsafe { outb(0x21, 0xff) };
    // SAFETY: as above.
    unsafe { outb(0xa1, 0xff) };
}

/// This CPU's x2APIC ID.
pub(crate) fn apic_id() -> u32 {
    read(MSR_ID) as u32
}

pub(crate) fn eoi() {
    write(MSR_EOI, 0);
}

/// Sends a fixed-delivery IPI to the CPU with x2APIC ID `dest`.
pub(crate) fn send_ipi(dest: u32, vector: u8) {
    write(MSR_ICR, (u64::from(dest) << 32) | u64::from(vector));
}

/// Sends an NMI to every CPU except this one.
pub(crate) fn send_nmi_all_but_self() {
    write(MSR_ICR, (0b11 << 18) | LVT_NMI | (1 << 14));
}

/// Sends INIT, then two STARTUP IPIs for the trampoline at physical page
/// `page`, to the CPU with x2APIC ID `dest`.
pub(crate) fn start_ap(dest: u32, page: u8) {
    let d = u64::from(dest) << 32;
    write(MSR_ICR, d | (0b101 << 8) | (1 << 14)); // INIT, assert
    delay_us(10_000);
    for _ in 0..2 {
        write(MSR_ICR, d | (0b110 << 8) | u64::from(page)); // STARTUP
        delay_us(200);
    }
}

// ---------------------------------------------------------------------------
// Time.
// ---------------------------------------------------------------------------

/// Determines the TSC frequency: CPUID leaf 0x15, then the hypervisor
/// timing leaf, then calibration against the ACPI PM timer, then against
/// the PIT (absent on some cloud VMs). Returns the frequency and where it
/// came from; `None` if every source failed.
pub(crate) fn init_tsc() -> Option<(u64, &'static str)> {
    TSC_AT_BOOT.store(rdtsc(), Relaxed);
    let max = cpuid(0, 0)[0];
    let mut found = None;
    if max >= 0x15 {
        let [den, num, crystal, _] = cpuid(0x15, 0);
        if den != 0 && num != 0 && crystal != 0 {
            found = Some((
                u64::from(crystal) * u64::from(num) / u64::from(den),
                "cpuid 0x15",
            ));
        }
    }
    if found.is_none()
        && super::cpu::features().hypervisor
        && cpuid(0x4000_0000, 0)[0] >= 0x4000_0010
    {
        let khz = u64::from(cpuid(0x4000_0010, 0)[0]);
        found = (khz != 0).then_some((khz * 1000, "hypervisor leaf"));
    }
    if found.is_none() {
        found = crate::acpi::find_table(b"FACP")
            .and_then(|f| acpi::fadt_pm_timer(&f))
            .and_then(calibrate_with_pm_timer)
            .map(|hz| (hz, "ACPI PM timer"));
    }
    if found.is_none() {
        found = calibrate_with_pit().map(|hz| (hz, "PIT"));
    }
    let (hz, _) = found?;
    TSC_HZ.store(hz, Relaxed);
    found
}

/// The TSC against the ACPI PM timer: the median of three windows, since a
/// vCPU descheduled at either end of one measures it wrong.
fn calibrate_with_pm_timer(t: acpi::PmTimer) -> Option<u64> {
    let mut hz = [pm_window(t)?, pm_window(t)?, pm_window(t)?];
    hz.sort_unstable();
    Some(hz[1])
}

/// Measures the TSC over 10 ms of the ACPI PM timer (3.579545 MHz). `None`
/// if the counter does not advance (no timer at that port).
fn pm_window(t: acpi::PmTimer) -> Option<u64> {
    let mask: u32 = if t.bits32 { u32::MAX } else { 0x00ff_ffff };
    // SAFETY: the FADT names this port as the PM timer, a read-only
    // free-running counter: reading it has no side effects on any device.
    let read = || unsafe { inl(t.port) } & mask;
    let target = (acpi::PM_TIMER_HZ / 100) as u32; // 10 ms
    let start = read();
    let tsc_start = rdtsc();
    let mut spins = 0u64;
    let elapsed = loop {
        let e = read().wrapping_sub(start) & mask;
        if e >= target {
            break e;
        }
        spins += 1;
        if spins > 100_000_000 {
            return None;
        }
    };
    let ticks = rdtsc().wrapping_sub(tsc_start);
    Some(ticks * acpi::PM_TIMER_HZ / u64::from(elapsed))
}

/// Measures the TSC over 10 ms of PIT channel 2. Frame owns ports 0x42,
/// 0x43 and 0x61. `None` if the PIT never signals (absent).
fn calibrate_with_pit() -> Option<u64> {
    const PIT_HZ: u64 = 1_193_182;
    const COUNT: u64 = PIT_HZ / 100; // 10 ms
    // SAFETY: frame owns the PIT and the port-0x61 gate. Channel 2 drives
    // only the PC speaker, which stays disconnected (bit 1 clear).
    let gate = unsafe { inb(0x61) };
    // SAFETY: as above: enable channel 2's gate, speaker off.
    unsafe { outb(0x61, (gate & !0x02) | 0x01) };
    // SAFETY: as above: channel 2, lobyte/hibyte, mode 0, binary.
    unsafe { outb(0x43, 0b1011_0000) };
    // SAFETY: as above: count low byte.
    unsafe { outb(0x42, (COUNT & 0xff) as u8) };
    // SAFETY: as above: count high byte; counting starts.
    unsafe { outb(0x42, (COUNT >> 8) as u8) };
    let start = rdtsc();
    let mut spins = 0u64;
    // SAFETY: as above: OUT2 is reported in bit 5 of port 0x61.
    while unsafe { inb(0x61) } & 0x20 == 0 && spins < 100_000_000 {
        spins += 1;
    }
    let elapsed = rdtsc().wrapping_sub(start);
    // SAFETY: as above: restore the original gate state.
    unsafe { outb(0x61, gate) };
    (spins < 100_000_000).then_some(elapsed * PIT_HZ / COUNT)
}

pub(crate) fn tsc_hz() -> u64 {
    TSC_HZ.load(Relaxed)
}

/// Nanoseconds since boot.
pub(crate) fn now_ns() -> u64 {
    let hz = tsc_hz().max(1);
    let ticks = rdtsc().wrapping_sub(TSC_AT_BOOT.load(Relaxed));
    ((u128::from(ticks) * 1_000_000_000) / u128::from(hz)) as u64
}

/// Busy-waits for `us` microseconds.
pub(crate) fn delay_us(us: u64) {
    let target = rdtsc() + tsc_hz() / 1_000_000 * us;
    while rdtsc() < target {
        core::hint::spin_loop();
    }
}

/// Configures this CPU's timer (after [`init_local`] and [`init_tsc`]).
pub(crate) fn init_timer() {
    if super::cpu::features().tsc_deadline {
        DEADLINE_MODE.store(true, Relaxed);
        write(MSR_LVT_TIMER, LVT_TSC_DEADLINE | u64::from(TIMER_VECTOR));
        return;
    }
    // One-shot mode: measure LAPIC ticks per millisecond against the TSC.
    write(MSR_TIMER_DIVIDE, 0b0011); // divide by 16
    write(MSR_LVT_TIMER, LVT_MASKED | u64::from(TIMER_VECTOR));
    // The lowest of three: a vCPU descheduled between the reads of the two
    // clocks measures too high (every timer would be late) or too low
    // (timers fire early and are armed again, which costs little).
    let mut per_ms = u64::MAX;
    for _ in 0..3 {
        write(MSR_TIMER_INIT, u64::from(u32::MAX));
        let start = rdtsc();
        delay_us(3_000);
        let ticks = u64::from(u32::MAX) - read(MSR_TIMER_CURRENT);
        let elapsed = rdtsc().wrapping_sub(start).max(1);
        per_ms = per_ms.min(ticks * (tsc_hz() / 1000) / elapsed);
    }
    write(MSR_TIMER_INIT, 0);
    LAPIC_TICKS_PER_MS.store(per_ms.max(1), Relaxed);
    write(MSR_LVT_TIMER, u64::from(TIMER_VECTOR));
}

/// Which of a CPU's multiplexed timer deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimerKind {
    /// The scheduler's timeslice.
    Slice = 0,
    /// The kernel's own timer (`time::arm_timer`).
    Kernel = 1,
    /// The earliest timed wait (`task::sleep_until`, `wait_until_deadline`).
    Sleep = 2,
}

const KINDS: usize = 3;

crate::cpu_local! {
    /// Absolute TSC deadlines per kind; 0 means unarmed.
    static DEADLINES: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];
    /// What the hardware is programmed for (an absolute TSC; 0: nothing).
    static HARDWARE: AtomicU64 = AtomicU64::new(0);
}

fn ns_to_tsc(ns: u64) -> u64 {
    (u128::from(ns) * u128::from(tsc_hz()) / 1_000_000_000) as u64
}

/// Programs the hardware for the earliest armed deadline. If it is already
/// programmed for an earlier time, that interrupt will program the rest: a
/// context switch pushes the slice later every time, and each write is a VM
/// exit. (One long overdue is not waited for.)
fn program(g: &crate::cpu::IrqGuard, d: &[AtomicU64; KINDS]) {
    let next = d.iter().map(|x| x.load(Relaxed)).filter(|&x| x != 0).min();
    let Some(at) = next else { return };
    let hardware = HARDWARE.get(g);
    let set = hardware.load(Relaxed);
    if set != 0 && set <= at && rdtsc() < set.wrapping_add(tsc_hz() / 100) {
        return;
    }
    hardware.store(at, Relaxed);
    if DEADLINE_MODE.load(Relaxed) {
        // SAFETY: IA32_TSC_DEADLINE exists when CPUID reports TSC-deadline
        // support (checked in `init_timer`); writing it only arms this
        // CPU's timer interrupt.
        unsafe { wrmsr(regs::MSR_TSC_DEADLINE, at.max(1)) };
    } else {
        let left_ns =
            (u128::from(at.saturating_sub(rdtsc())) * 1_000_000_000) / u128::from(tsc_hz().max(1));
        let per_ms = u128::from(LAPIC_TICKS_PER_MS.load(Relaxed));
        let ticks = (left_ns * per_ms / 1_000_000).clamp(1, u128::from(u32::MAX));
        write(MSR_TIMER_INIT, ticks as u64);
    }
}

/// `cpu`'s armed deadlines as nanoseconds from now (negative: overdue),
/// for diagnostics.
pub(crate) fn deadlines_ns(cpu: crate::cpu::CpuId) -> [Option<i64>; KINDS] {
    let now = rdtsc();
    let hz = tsc_hz().max(1);
    DEADLINES.get_on(cpu).each_ref().map(|d| {
        let at = d.load(Relaxed);
        (at != 0)
            .then(|| ((i128::from(at) - i128::from(now)) * 1_000_000_000 / i128::from(hz)) as i64)
    })
}

/// Arms deadline `kind` on this CPU, `ns` nanoseconds from now.
pub(crate) fn arm(kind: TimerKind, ns: u64) {
    let g = crate::cpu::IrqGuard::new();
    let d = DEADLINES.get(&g);
    d[kind as usize].store(rdtsc().wrapping_add(ns_to_tsc(ns).max(1)), Relaxed);
    program(&g, d);
}

/// Handles this CPU's timer interrupt: fires expired deadlines, re-arms.
fn on_timer_interrupt() {
    let (slice, kernel, sleep) = {
        let g = crate::cpu::IrqGuard::new();
        let d = DEADLINES.get(&g);
        let now = rdtsc();
        let fired = |k: TimerKind| {
            let at = d[k as usize].load(Relaxed);
            let f = at != 0 && at <= now;
            if f {
                d[k as usize].store(0, Relaxed);
            }
            f
        };
        let r = (
            fired(TimerKind::Slice),
            fired(TimerKind::Kernel),
            fired(TimerKind::Sleep),
        );
        HARDWARE.get(&g).store(0, Relaxed);
        program(&g, d);
        r
    };
    if kernel {
        let handler = *TIMER_HANDLER.lock();
        if let Some(h) = handler {
            h();
        }
    }
    if sleep {
        crate::task::on_sleep_timer();
    }
    if slice {
        crate::task::on_tick();
    }
}

pub(crate) fn set_timer_handler(f: fn()) {
    *TIMER_HANDLER.lock() = Some(f);
}

#[allow(dead_code)] // The scheduler's wake-up path (milestone 2).
pub(crate) fn set_ipi_handler(f: fn()) {
    *IPI_HANDLER.lock() = Some(f);
}

/// Interrupts that arrived on vectors nobody handles.
pub(crate) fn unexpected_irqs() -> u64 {
    UNEXPECTED_IRQS.load(Relaxed)
}

pub(crate) fn handle_irq(vector: u8, _frame: &mut TrapFrame) {
    match vector {
        SPURIOUS_VECTOR => return, // no EOI for spurious interrupts
        TIMER_VECTOR => {
            eoi();
            on_timer_interrupt();
            return;
        }
        crate::mm::tlb::VECTOR => {
            eoi();
            crate::mm::tlb::on_ipi();
            return;
        }
        IPI_VECTOR => {
            eoi();
            let handler = *IPI_HANDLER.lock();
            if let Some(h) = handler {
                h();
            }
            return;
        }
        _ => {
            UNEXPECTED_IRQS.fetch_add(1, Relaxed);
        }
    }
    eoi();
}

pub(crate) fn handle_nmi() {
    if crate::panic::in_progress() {
        // Another CPU panicked and is stopping the machine.
        super::halt_forever();
    }
}
