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
    /// Intel's indirect target selection: indirect branches and returns in
    /// the lower half of a cache line may be predicted from user training
    /// despite enhanced IBRS.
    pub its: bool,
    /// AMD's transient scheduler attacks (Zen 3 and 4): VERW on return to
    /// user, where `md_clear` says it clears.
    pub tsa: bool,
    /// Intel's processor MMIO stale data.
    pub mmio: bool,
    /// Speculative store bypass (Spectre v4).
    pub ssb: bool,
    /// How a thread's speculative store bypass is disabled here, if it can
    /// be.
    pub(crate) ssbd: Option<Ssbd>,
    /// `IA32_SPEC_CTRL.STIBP` exists, and AMD prefers it always on.
    pub stibp: bool,
    pub stibp_always_on: bool,
    /// The CPU's cores run more than one thread.
    pub smt: bool,
}

/// Where a thread's speculative store bypass disable bit lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ssbd {
    /// `IA32_SPEC_CTRL` bit 2 (Intel's CPUID.7:EDX[31], AMD's 8000_0008h
    /// EBX[24]).
    SpecCtrl,
    /// AMD's `VIRT_SPEC_CTRL` (0xC001_011F) bit 2, offered by hypervisors
    /// (8000_0008h EBX[25]).
    Virt,
}

/// Intel family 6 models, by Linux's names, for the lists below.
mod model {
    pub(super) const HASWELL_X: u32 = 0x3f;
    pub(super) const BROADWELL_D: u32 = 0x56;
    pub(super) const BROADWELL_X: u32 = 0x4f;
    pub(super) const SKYLAKE_X: u32 = 0x55;
    pub(super) const SKYLAKE_L: u32 = 0x4e;
    pub(super) const SKYLAKE: u32 = 0x5e;
    pub(super) const KABYLAKE_L: u32 = 0x8e;
    pub(super) const KABYLAKE: u32 = 0x9e;
    pub(super) const ICELAKE_L: u32 = 0x7e;
    pub(super) const ICELAKE_D: u32 = 0x6c;
    pub(super) const ICELAKE_X: u32 = 0x6a;
    pub(super) const COMETLAKE: u32 = 0xa5;
    pub(super) const COMETLAKE_L: u32 = 0xa6;
    pub(super) const TIGERLAKE_L: u32 = 0x8c;
    pub(super) const TIGERLAKE: u32 = 0x8d;
    pub(super) const LAKEFIELD: u32 = 0x8a;
    pub(super) const ROCKETLAKE: u32 = 0xa7;
    pub(super) const ATOM_TREMONT: u32 = 0x96;
    pub(super) const ATOM_TREMONT_D: u32 = 0x86;
    pub(super) const ATOM_TREMONT_L: u32 = 0x9c;
}

/// Processor MMIO stale data, where `IA32_ARCH_CAPABILITIES` does not
/// rule it out (Linux's list).
const MMIO_MODELS: &[u32] = {
    use model::*;
    &[
        HASWELL_X,
        BROADWELL_D,
        BROADWELL_X,
        SKYLAKE_X,
        SKYLAKE_L,
        SKYLAKE,
        KABYLAKE_L,
        KABYLAKE,
        ICELAKE_L,
        ICELAKE_D,
        ICELAKE_X,
        COMETLAKE,
        COMETLAKE_L,
        LAKEFIELD,
        ROCKETLAKE,
        ATOM_TREMONT,
        ATOM_TREMONT_D,
        ATOM_TREMONT_L,
    ]
};

/// Gather data sampling, where `GDS_NO` is clear (Linux's list).
const GDS_MODELS: &[u32] = {
    use model::*;
    &[
        SKYLAKE_X,
        SKYLAKE_L,
        SKYLAKE,
        KABYLAKE_L,
        KABYLAKE,
        ICELAKE_L,
        ICELAKE_D,
        ICELAKE_X,
        COMETLAKE,
        COMETLAKE_L,
        TIGERLAKE_L,
        TIGERLAKE,
        ROCKETLAKE,
    ]
};

/// Indirect target selection on bare metal: each model from a stepping on
/// (Linux's list).
const ITS_MODELS: &[(u32, u32)] = {
    use model::*;
    &[
        (SKYLAKE_X, 6),
        (KABYLAKE_L, 0xc),
        (KABYLAKE, 0xd),
        (ICELAKE_L, 0),
        (ICELAKE_D, 0),
        (ICELAKE_X, 0),
        (COMETLAKE, 0),
        (COMETLAKE_L, 0),
        (TIGERLAKE_L, 0),
        (TIGERLAKE, 0),
        (ROCKETLAKE, 0),
    ]
};

/// Detects this CPU's vulnerabilities from CPUID and, where enumerated,
/// `IA32_ARCH_CAPABILITIES`.
pub fn vulnerabilities() -> Vulnerabilities {
    let [_, b, c, d] = cpuid(0, 0);
    let intel = [b, d, c] == [0x756e_6547, 0x4965_6e69, 0x6c65_746e]; // "GenuineIntel"
    let max_leaf = cpuid(0, 0)[0];
    let [_, ebx7, _, edx7] = if max_leaf >= 7 { cpuid(7, 0) } else { [0; 4] };
    let bit = |r: u64, n: u32| r & (1 << n) != 0;
    let [eax1, _, ecx1, _] = cpuid(1, 0);
    let hypervisor = bit(u64::from(ecx1), 31);
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
    let edx7 = u64::from(edx7);
    let base = (eax1 >> 8) & 0xf;
    let family = if base == 0xf {
        base + ((eax1 >> 20) & 0xff)
    } else {
        base
    };
    let max_ext = cpuid(0x8000_0000, 0)[0];
    if !intel {
        // AMD and others are not affected by Meltdown, MDS, TAA or ITS;
        // their own issues are Retbleed, SRSO and TSA (ADR-0004 §2).
        let amd = [b, d, c] == [0x6874_7541, 0x6974_6e65, 0x444d_4163]; // "AuthenticAMD"
        let hygon = [b, d, c] == [0x6f67_7948, 0x6e65_476e, 0x656e_6975]; // "HygonGenuine"
        let [eax21, _, ecx21, _] = if max_ext >= 0x8000_0021 {
            cpuid(0x8000_0021, 0)
        } else {
            [0; 4]
        };
        let (ext21, ecx21) = (u64::from(eax21), u64::from(ecx21));
        // AMD enumerates IBPB (bit 12), IBRS (14), STIBP (15, and 17: keep it
        // on), SSBD (24, or 25 through VIRT_SPEC_CTRL) and SSB_NO (26) here,
        // not in leaf 7.
        let ext8 = if max_ext >= 0x8000_0008 {
            u64::from(cpuid(0x8000_0008, 0)[1])
        } else {
            0
        };
        let retbleed = (amd && (0x15..=0x17).contains(&family)) || (hygon && family == 0x18);
        let srso = ((amd && matches!(family, 0x17 | 0x19)) || (hygon && family == 0x18))
            && !bit(ext21, 29)
            && !bit(ext21, 30);
        // TSA: Zen 3 and 4 (family 19h), unless both TSA_SQ_NO and
        // TSA_L1_NO say otherwise. VERW clears what it leaks only where
        // VERW_CLEAR (8000_0021h EAX[5]) says so.
        let tsa = amd && family == 0x19 && !(bit(ecx21, 1) && bit(ecx21, 2));
        // Threads per core: 8000_001Eh EBX[15:8] plus one, with topology
        // extensions (8000_0001h ECX[22]).
        let topoext = max_ext >= 0x8000_0001 && cpuid(0x8000_0001, 0)[2] & (1 << 22) != 0;
        let smt = topoext && max_ext >= 0x8000_001e && (cpuid(0x8000_001e, 0)[1] >> 8) & 0xff > 0;
        use super::rethunk::SafeRet;
        return Vulnerabilities {
            intel,
            eibrs: bit(caps, 1),
            ibrs: ibpb || bit(ext8, 14),
            bhi_ctrl,
            md_clear: bit(ext21, 5),
            tsa,
            ssb: (amd || hygon) && !bit(ext8, 26),
            ssbd: if bit(ext8, 24) {
                Some(Ssbd::SpecCtrl)
            } else if bit(ext8, 25) {
                Some(Ssbd::Virt)
            } else {
                None
            },
            stibp: bit(ext8, 15),
            stibp_always_on: bit(ext8, 17),
            smt,
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
    let model = if family == 6 {
        ((eax1 >> 4) & 0xf) | ((eax1 >> 12) & 0xf0)
    } else {
        0
    };
    let stepping = eax1 & 0xf;
    // Threads per core: the SMT level of leaf 0Bh (its type, ECX[15:8], is
    // 1), EBX[15:0] logical processors.
    let smt = max_leaf >= 0xb && {
        let [_, ebx, ecx, _] = cpuid(0xb, 0);
        (ecx >> 8) & 0xff == 1 && ebx & 0xffff > 1
    };
    Vulnerabilities {
        intel,
        meltdown: !bit(caps, 0),
        mds: !bit(caps, 5),
        // TAA needs TSX: RTM (CPUID.7:EBX[11]), or TSX_CTRL (caps bit 7)
        // where firmware or microcode turned it off. Clouds that hide TSX
        // and leave TAA_NO clear (AWS) are not affected.
        taa: !bit(caps, 8) && (ebx7 & (1 << 11) != 0 || bit(caps, 7)),
        eibrs: bit(caps, 1),
        bhi: !bit(caps, 20),
        // GDS: the listed models with AVX (CPUID.1:ECX[28]), unless GDS_NO.
        gds: !bit(caps, 26) && GDS_MODELS.contains(&model) && ecx1 & (1 << 28) != 0,
        // ITS (Linux's test): not with ITS_NO (caps bit 62), nor where
        // BHI_DIS_S exists (no affected CPU has it); a guest that is not
        // told ITS_NO may run on, or move to, an affected host.
        its: !bit(caps, 62)
            && !bhi_ctrl
            && (hypervisor || ITS_MODELS.iter().any(|&(m, s)| m == model && stepping >= s)),
        // MMIO stale data: the listed models, unless SBDR_SSDP_NO,
        // FBSDP_NO and PSDP_NO (caps bits 13 to 15) all rule it out.
        mmio: !(bit(caps, 13) && bit(caps, 14) && bit(caps, 15)) && MMIO_MODELS.contains(&model),
        ssb: !bit(caps, 4),
        ssbd: bit(edx7, 31).then_some(Ssbd::SpecCtrl),
        stibp: bit(edx7, 27),
        smt,
        ibrs: ibpb,
        bhi_ctrl,
        md_clear,
        pred_cmd: ibpb,
        ..Vulnerabilities::default()
    }
}
