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

/// Detects features with CPUID, each call anew. Not for hot paths: in a
/// virtual machine every CPUID traps to the hypervisor (microseconds).
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
/// user code and, where the CPU has XSAVE, the extended state ADR-0008
/// allows (AVX, AVX-512): the kernel itself is built soft-float and never
/// touches the FPU, so user state only needs saving at the ring-3
/// boundary. Runs on every CPU. Returns what is on.
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
    // SMEP/SMAP: the kernel never executes user pages and never touches
    // them through user addresses either: frame's user copies go through
    // the linear map, checking the PTE under the space lock (ADR-0011), so
    // AC is never set.
    if f.smep {
        cr4 |= regs::CR4_SMEP;
    }
    if f.smap {
        cr4 |= regs::CR4_SMAP;
    }
    if f.umip {
        cr4 |= regs::CR4_UMIP;
    }
    let xcr0 = super::xstate::decide();
    if xcr0 != 0 {
        cr4 |= regs::CR4_OSXSAVE;
    }
    // Protection keys exactly when PKRU is saved with the rest (ADR-0022).
    // The kernel never reaches user pages through user addresses (above),
    // so the user's PKRU, loaded while the kernel runs, never limits it.
    if xcr0 & super::xstate::PKRU != 0 {
        cr4 |= regs::CR4_PKE;
    }
    // SAFETY: the bits set above are accounted for as described (OSXSAVE
    // only makes XSAVE/XSETBV usable, which `decide` checked CPUID for; PKE
    // only lets keys in user PTEs limit user-page accesses); no other bit
    // changes.
    unsafe { regs::write_cr4(cr4) };
    super::xstate::enable(xcr0);
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
    /// The CPU supports IBRS (and so `IA32_SPEC_CTRL`): Intel's
    /// CPUID.7:EDX[26], or AMD's CPUID 8000_0008h EBX[14].
    pub ibrs: bool,
    /// `IA32_SPEC_CTRL.BHI_DIS_S` exists (CPUID.(7,2):EDX[4]).
    pub bhi_ctrl: bool,
    /// VERW clears CPU buffers (MD_CLEAR microcode).
    pub md_clear: bool,
    /// AMD's automatic IBRS (CPUID 8000_0021h EAX[8]).
    pub auto_ibrs: bool,
    /// AMD's Retbleed (families 15h to 17h, Hygon 18h).
    pub retbleed: bool,
    /// AMD's speculative return stack overflow (families 17h and 19h,
    /// without SRSO_NO or SRSO_USER_KERNEL_NO).
    pub srso: bool,
    /// IBPB also flushes return predictions (IBPB_BRTYPE microcode, which
    /// SRSO's mitigation needs on family 19h).
    pub ibpb_brtype: bool,
    /// `IA32_PRED_CMD` (IBPB) exists: Intel's CPUID.7:EDX[26], or AMD's
    /// CPUID 8000_0008h EBX[12].
    pub pred_cmd: bool,
    /// The safe-RET sequence that mitigates Retbleed or SRSO here (Zen 1/2
    /// and Hygon 18h, or Zen 3/4); `None` where it does not apply.
    pub(crate) safe_ret: Option<super::rethunk::SafeRet>,
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
    let bhi_ctrl = max_leaf >= 7 && cpuid(7, 0)[0] >= 2 && cpuid(7, 2)[3] & (1 << 4) != 0;
    if !intel {
        // AMD and others are not affected by Meltdown, MDS or TAA; their
        // own issues are Retbleed and SRSO (ADR-0004 §2).
        let amd = [b, d, c] == [0x6874_7541, 0x6974_6e65, 0x444d_4163]; // "AuthenticAMD"
        let hygon = [b, d, c] == [0x6f67_7948, 0x6e65_476e, 0x656e_6975]; // "HygonGenuine"
        let eax1 = cpuid(1, 0)[0];
        let base = (eax1 >> 8) & 0xf;
        let family = if base == 0xf {
            base + ((eax1 >> 20) & 0xff)
        } else {
            base
        };
        let max_ext = cpuid(0x8000_0000, 0)[0];
        let ext21 = if max_ext >= 0x8000_0021 {
            u64::from(cpuid(0x8000_0021, 0)[0])
        } else {
            0
        };
        // AMD enumerates IBPB (bit 12) and IBRS (bit 14) here, not in leaf 7.
        let ext8 = if max_ext >= 0x8000_0008 {
            u64::from(cpuid(0x8000_0008, 0)[1])
        } else {
            0
        };
        let retbleed = (amd && (0x15..=0x17).contains(&family)) || (hygon && family == 0x18);
        let srso = ((amd && matches!(family, 0x17 | 0x19)) || (hygon && family == 0x18))
            && !bit(ext21, 29)
            && !bit(ext21, 30);
        use super::rethunk::SafeRet;
        return Vulnerabilities {
            intel,
            eibrs: bit(caps, 1),
            ibrs: ibpb || bit(ext8, 14),
            bhi_ctrl,
            md_clear,
            auto_ibrs: (amd || hygon) && bit(ext21, 8),
            retbleed,
            srso,
            safe_ret: match family {
                0x17 | 0x18 if retbleed || srso => Some(SafeRet::Zen12),
                0x19 if srso => Some(SafeRet::Alias),
                _ => None,
            },
            // Zen 1 and 2's IBPB flushes return predictions without saying.
            ibpb_brtype: bit(ext21, 28) || family == 0x17,
            pred_cmd: ibpb || bit(ext8, 12),
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
        ibrs: ibpb,
        bhi_ctrl,
        md_clear,
        pred_cmd: ibpb,
        ..Vulnerabilities::default()
    }
}
