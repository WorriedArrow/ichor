//! Control registers, MSRs and CPUID.

use core::arch::asm;

pub(crate) const CR0_MP: u64 = 1 << 1;
pub(crate) const CR0_EM: u64 = 1 << 2;
pub(crate) const CR0_TS: u64 = 1 << 3;
pub(crate) const CR0_WP: u64 = 1 << 16;
pub(crate) const CR4_PGE: u64 = 1 << 7;
pub(crate) const CR4_OSFXSR: u64 = 1 << 9;
pub(crate) const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub(crate) const CR4_UMIP: u64 = 1 << 11;
pub(crate) const CR4_LA57: u64 = 1 << 12;
pub(crate) const CR4_PCIDE: u64 = 1 << 17;
pub(crate) const CR4_SMEP: u64 = 1 << 20;
pub(crate) const CR4_SMAP: u64 = 1 << 21;
pub(crate) const CR4_PKE: u64 = 1 << 22;
pub(crate) const CR4_OSXSAVE: u64 = 1 << 18;

pub(crate) const MSR_EFER: u32 = 0xC000_0080;
pub(crate) const EFER_NXE: u64 = 1 << 11;
pub(crate) const MSR_FS_BASE: u32 = 0xC000_0100;
pub(crate) const MSR_GS_BASE: u32 = 0xC000_0101;
pub(crate) const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub(crate) const MSR_APIC_BASE: u32 = 0x1B;
pub(crate) const MSR_TSC_DEADLINE: u32 = 0x6E0;

pub(crate) fn read_cr0() -> u64 {
    let v;
    // SAFETY: reading CR0 has no side effects.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// # Safety
///
/// The new value must keep paging and protected mode enabled and must not
/// break invariants frame relies on (e.g. clearing WP while code depends on
/// read-only kernel mappings).
pub(crate) unsafe fn write_cr0(v: u64) {
    // SAFETY: caller contract.
    unsafe { asm!("mov cr0, {}", in(reg) v, options(nostack, preserves_flags)) };
}

pub(crate) fn read_cr2() -> u64 {
    let v;
    // SAFETY: reading CR2 has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub(crate) fn read_cr3() -> u64 {
    let v;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// # Safety
///
/// `v` must point at a valid PML4 that maps the currently executing code,
/// the current stack, and everything the caller touches afterwards.
pub(crate) unsafe fn write_cr3(v: u64) {
    // SAFETY: caller contract. Not `nomem`: changing the address space is
    // a memory barrier for the compiler.
    unsafe { asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags)) };
}

pub(crate) fn read_cr4() -> u64 {
    let v;
    // SAFETY: reading CR4 has no side effects.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// # Safety
///
/// Only bits whose effect the caller has accounted for may change (e.g.
/// SMAP must not be enabled while kernel code still accesses user pages).
pub(crate) unsafe fn write_cr4(v: u64) {
    // SAFETY: caller contract.
    unsafe { asm!("mov cr4, {}", in(reg) v, options(nostack, preserves_flags)) };
}

/// # Safety
///
/// `msr` must exist on this CPU (else #GP) and reading it must have no
/// side effects the caller has not accounted for.
pub(crate) unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: caller contract.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// # Safety
///
/// `msr` must exist and the write must not break any invariant frame relies
/// on (MSRs control paging, syscall entry, interrupt delivery, ...).
pub(crate) unsafe fn wrmsr(msr: u32, v: u64) {
    // SAFETY: caller contract.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nostack, preserves_flags))
    };
}

/// Executes CPUID.
pub(crate) fn cpuid(leaf: u32, subleaf: u32) -> [u32; 4] {
    let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    [r.eax, r.ebx, r.ecx, r.edx]
}

/// One RDRAND: a 64-bit value from the CPU's DRBG, or `None` if it had none
/// ready (carry clear).
///
/// # Safety
///
/// The CPU must support RDRAND (CPUID.1:ECX bit 30), else it faults (#UD).
pub(crate) unsafe fn rdrand() -> Option<u64> {
    let v: u64;
    let ok: u8;
    // SAFETY: caller contract; RDRAND only writes the output register and
    // the flags.
    unsafe {
        asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack))
    };
    (ok != 0).then_some(v)
}

/// One RDSEED: a 64-bit value from the CPU's conditioned entropy source,
/// or `None` if it had none ready (carry clear).
///
/// # Safety
///
/// The CPU must support RDSEED (CPUID.7.0:EBX bit 18), else it faults (#UD).
pub(crate) unsafe fn rdseed() -> Option<u64> {
    let v: u64;
    let ok: u8;
    // SAFETY: caller contract; RDSEED only writes the output register and
    // the flags.
    unsafe {
        asm!("rdseed {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack))
    };
    (ok != 0).then_some(v)
}

/// Reads the time-stamp counter.
pub(crate) fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: RDTSC is unprivileged-safe and side-effect free (CR4.TSD only
    // affects ring 3).
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    (u64::from(hi) << 32) | u64::from(lo)
}
