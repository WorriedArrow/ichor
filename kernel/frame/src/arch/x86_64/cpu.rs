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
    pub rdrand: bool,
    pub rdseed: bool,
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
        rdrand: bit(ecx1, 30),
        rdseed: bit(ebx7, 18),
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
/// global pages, SMEP, SMAP and UMIP where supported. Also enables SSE for
/// user code (every x86-64 CPU has it; the kernel itself is built
/// soft-float and never touches the FPU, so user FPU state only needs
/// saving at the ring-3 boundary). Runs on every CPU. Returns what is on.
pub(crate) fn enable_protections() -> Features {
    let f = features();
    // SAFETY: setting WP makes supervisor writes honour read-only mappings.
    // Frame never writes through a read-only kernel mapping.
    unsafe { regs::write_cr0(regs::read_cr0() | regs::CR0_WP) };
    // SAFETY: MP set and EM/TS clear make x87/SSE instructions execute
    // instead of trapping (#NM/#UD); kernel code contains none.
    unsafe {
        regs::write_cr0((regs::read_cr0() | regs::CR0_MP) & !(regs::CR0_EM | regs::CR0_TS));
    };
    let mut cr4 = regs::read_cr4() | regs::CR4_OSFXSR | regs::CR4_OSXMMEXCPT;
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

const MSR_ARCH_CAPABILITIES: u32 = 0x10A;

/// Which speculative-execution issues apply to this CPU (ADR-0004 §1).
/// `true` means affected.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vulnerabilities {
    pub intel: bool,
    /// Rogue data cache load: the kernel needs page-table isolation to
    /// host untrusted cells.
    pub meltdown: bool,
    /// Microarchitectural data sampling: VERW on return to user.
    pub mds: bool,
    /// TSX asynchronous abort.
    pub taa: bool,
    /// Enhanced IBRS available (Spectre v2 mitigated in hardware).
    pub eibrs: bool,
    /// Branch history injection.
    pub bhi: bool,
    /// Gather data sampling (Downfall).
    pub gds: bool,
    /// The CPU supports IBRS/IBPB.
    pub ibpb: bool,
    /// VERW clears CPU buffers (MD_CLEAR microcode).
    pub md_clear: bool,
}

/// Detects this CPU's vulnerabilities from CPUID and, where enumerated,
/// `IA32_ARCH_CAPABILITIES`.
pub fn vulnerabilities() -> Vulnerabilities {
    let [_, b, c, d] = cpuid(0, 0);
    let intel = [b, d, c] == [0x756e_6547, 0x4965_6e69, 0x6c65_746e]; // "GenuineIntel"
    let max_leaf = cpuid(0, 0)[0];
    let edx7 = if max_leaf >= 7 { cpuid(7, 0)[3] } else { 0 };
    let bit = |r: u64, n: u32| r & (1 << n) != 0;
    let caps = if edx7 & (1 << 29) != 0 {
        // SAFETY: CPUID.(EAX=7):EDX[29] enumerates IA32_ARCH_CAPABILITIES,
        // a read-only MSR with no side effects.
        unsafe { regs::rdmsr(MSR_ARCH_CAPABILITIES) }
    } else {
        0
    };
    let ibpb = edx7 & (1 << 26) != 0;
    let md_clear = edx7 & (1 << 10) != 0;
    if !intel {
        // AMD and others are not affected by Meltdown, MDS or TAA; their
        // own issues (Retbleed, SRSO) are handled per ADR-0004 §2.
        return Vulnerabilities {
            intel,
            eibrs: bit(caps, 1),
            ibpb,
            md_clear,
            ..Vulnerabilities::default()
        };
    }
    Vulnerabilities {
        intel,
        meltdown: !bit(caps, 0),
        mds: !bit(caps, 5),
        taa: !bit(caps, 8),
        eibrs: bit(caps, 1),
        bhi: !bit(caps, 20),
        gds: !bit(caps, 26),
        ibpb,
        md_clear,
    }
}
