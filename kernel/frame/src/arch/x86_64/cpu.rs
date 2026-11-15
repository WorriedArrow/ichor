//! CPU feature detection and the control-register policy frame enforces.

use super::regs::{self, cpuid};

/// CPU features frame cares about.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    pub nx: bool,
    pub huge_1g: bool,
    pub pge: bool,
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
    pub pcid: bool,
    pub fsgsbase: bool,
    pub x2apic: bool,
    pub tsc_deadline: bool,
    pub invariant_tsc: bool,
    pub rdpid: bool,
    pub hypervisor: bool,
}

/// Detects features with CPUID. Cheap enough to call repeatedly.
pub fn features() -> Features {
    let max_leaf = cpuid(0, 0)[0];
    let max_ext = cpuid(0x8000_0000, 0)[0];
    let [_, _, ecx1, edx1] = cpuid(1, 0);
    let [_, ebx7, ecx7, _] = if max_leaf >= 7 { cpuid(7, 0) } else { [0; 4] };
    let [_, _, _, edx_e1] = if max_ext >= 0x8000_0001 {
        cpuid(0x8000_0001, 0)
    } else {
        [0; 4]
    };
    let [_, _, _, edx_e7] = if max_ext >= 0x8000_0007 {
        cpuid(0x8000_0007, 0)
    } else {
        [0; 4]
    };
    let bit = |r: u32, b: u32| r & (1 << b) != 0;
    Features {
        nx: bit(edx_e1, 20),
        huge_1g: bit(edx_e1, 26),
        pge: bit(edx1, 13),
        smep: bit(ebx7, 7),
        smap: bit(ebx7, 20),
        umip: bit(ecx7, 2),
        pcid: bit(ecx1, 17),
        fsgsbase: bit(ebx7, 0),
        x2apic: bit(ecx1, 21),
        tsc_deadline: bit(ecx1, 24),
        invariant_tsc: bit(edx_e7, 8),
        rdpid: bit(ecx7, 22),
        hypervisor: bit(ecx1, 31),
    }
}

/// Enables no-execute page support. Must run before any page table with NX
/// bits is loaded.
pub(crate) fn enable_nx() -> bool {
    if !features().nx {
        return false;
    }
    // SAFETY: EFER exists on every x86_64 CPU; setting NXE only makes bit 63
    // of page table entries meaningful, which frame wants.
    let efer = unsafe { regs::rdmsr(regs::MSR_EFER) };
    // SAFETY: as above; no other EFER bit changes.
    unsafe { regs::wrmsr(regs::MSR_EFER, efer | regs::EFER_NXE) };
    true
}

/// Turns on the protections frame relies on once it runs on its own page
/// tables: WP (read-only kernel pages are read-only to the kernel too),
/// global pages, SMEP, SMAP and UMIP where supported. Returns what is on.
pub(crate) fn enable_protections() -> Features {
    let f = features();
    // SAFETY: setting WP makes supervisor writes honour read-only mappings.
    // Frame never writes through a read-only kernel mapping.
    unsafe { regs::write_cr0(regs::read_cr0() | regs::CR0_WP) };
    let mut cr4 = regs::read_cr4();
    if f.pge {
        cr4 |= regs::CR4_PGE;
    }
    // SMEP/SMAP: the kernel never executes user pages and, until frame's
    // user-copy routines exist (milestone 2, which toggle AC around each
    // copy), never touches them either.
    if f.smep {
        cr4 |= regs::CR4_SMEP;
    }
    if f.smap {
        cr4 |= regs::CR4_SMAP;
    }
    if f.umip {
        cr4 |= regs::CR4_UMIP;
    }
    // SAFETY: the bits set above are accounted for as described; no other bit
    // changes.
    unsafe { regs::write_cr4(cr4) };
    f
}
