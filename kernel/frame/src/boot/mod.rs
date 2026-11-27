//! Boot: from firmware hand-off to the kernel's `main`.
//!
//! Ichor is itself a UEFI application (ADR-0001, "Boot"). Firmware calls
//! frame's `efi_main`, which, in order:
//!
//! 1. initializes the serial console,
//! 2. records firmware identity and the ACPI RSDP from the UEFI configuration
//!    tables,
//! 3. reads the kernel command line from `\ichor\cmdline` on the volume the
//!    kernel was loaded from,
//! 4. fetches the final memory map and exits boot services,
//! 5. builds the kernel page tables and jumps to the higher half on a guarded
//!    boot stack (`mm::kspace`),
//! 6. drops the identity map, enables SMEP/SMAP/UMIP/WP, initializes the
//!    page allocator and the heap, and
//! 7. calls the kernel's main function (declared with
//!    [`frame::main!`](crate::main)) with a [`BootInfo`].
//!
//! After step 4 no firmware code runs again: Ichor never calls UEFI runtime
//! services.

mod uefi;

use core::cell::UnsafeCell;
use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::cpu::CpuId;
use crate::mm::early::EarlyAlloc;
use crate::mm::{self, PhysAddr};
use crate::power::{self, ExitStatus};
use crate::sync::SpinLock;
use crate::{arch, println};

pub(crate) const MAX_REGIONS: usize = 1638;
pub(crate) const CMDLINE_MAX: usize = 4096;
/// Room for `\ichor\roots.pem` (Mozilla's bundle is about 200 KiB).
pub(crate) const ROOTS_MAX: usize = 512 * 1024;
/// Room for `\ichor\suffixes.dat` (the list's ICANN rules are about 75 KiB).
pub(crate) const SUFFIXES_MAX: usize = 256 * 1024;
/// Room for `\ichor\apitoken` (the control plane's API credential).
pub(crate) const TOKEN_MAX: usize = 256;
/// Room for `\ichor\apitls.pem` (the API's TLS certificates and key).
pub(crate) const TLS_MAX: usize = 16 * 1024;
pub(crate) const VENDOR_MAX: usize = 64;

/// What boot learns from firmware, kept in `.bss` and handed from the
/// firmware phase to the higher-half phase.
pub(crate) struct BootState {
    pub(crate) regions: [MemoryRegion; MAX_REGIONS],
    pub(crate) region_count: usize,
    pub(crate) cmdline: [u8; CMDLINE_MAX],
    /// Length of the valid UTF-8 prefix of `cmdline`.
    pub(crate) cmdline_len: usize,
    /// `\ichor\roots.pem`, the control plane's CA bundle (ADR-0012 §4).
    pub(crate) roots: [u8; ROOTS_MAX],
    pub(crate) roots_len: usize,
    /// `\ichor\suffixes.dat`, the Public Suffix List's ICANN rules.
    pub(crate) suffixes: [u8; SUFFIXES_MAX],
    pub(crate) suffixes_len: usize,
    /// `\ichor\apitoken`, the control plane's API credential.
    pub(crate) token: [u8; TOKEN_MAX],
    pub(crate) token_len: usize,
    /// `\ichor\apitls.pem`, the API's TLS certificates and key.
    pub(crate) tls: [u8; TLS_MAX],
    pub(crate) tls_len: usize,
    pub(crate) vendor: [u8; VENDOR_MAX],
    pub(crate) vendor_len: usize,
    pub(crate) acpi_rsdp: Option<PhysAddr>,
    pub(crate) firmware_revision: u32,
    pub(crate) uefi_revision: u32,
    pub(crate) kernel_image: MemoryRegion,
    pub(crate) early: EarlyAlloc,
}

impl BootState {
    pub(crate) fn cmdline(&self) -> &str {
        core::str::from_utf8(&self.cmdline[..self.cmdline_len]).unwrap_or("")
    }

    pub(crate) fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.region_count]
    }
}

const EMPTY_REGION: MemoryRegion = MemoryRegion {
    base: PhysAddr::new(0),
    len: 0,
    kind: MemoryKind::Usable,
};

struct BootStateCell(UnsafeCell<BootState>);

// SAFETY: the contents are only reached through `take_boot_state`, which
// hands out one `&mut` per boot phase; see there.
unsafe impl Sync for BootStateCell {}

static BOOT_STATE: BootStateCell = BootStateCell(UnsafeCell::new(BootState {
    regions: [EMPTY_REGION; MAX_REGIONS],
    region_count: 0,
    cmdline: [0; CMDLINE_MAX],
    cmdline_len: 0,
    roots: [0; ROOTS_MAX],
    roots_len: 0,
    suffixes: [0; SUFFIXES_MAX],
    suffixes_len: 0,
    token: [0; TOKEN_MAX],
    token_len: 0,
    tls: [0; TLS_MAX],
    tls_len: 0,
    vendor: [0; VENDOR_MAX],
    vendor_len: 0,
    acpi_rsdp: None,
    firmware_revision: 0,
    uefi_revision: 0,
    kernel_image: EMPTY_REGION,
    early: EarlyAlloc::EMPTY,
}));

/// Which boot phase may take the boot state next.
static PHASE: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Phase {
    /// `efi_main`, on firmware's identity map.
    Firmware = 0,
    /// `kernel_space_entry`, in the higher half.
    HigherHalf = 1,
}

/// Hands out the boot state once per phase, in order.
///
/// The firmware-phase reference is moved into [`start`], which diverges
/// into the higher half and abandons the firmware stack, so it is dead by
/// the time the higher-half phase takes a new one. At no point are two
/// usable references live.
pub(crate) fn take_boot_state(phase: Phase) -> Option<&'static mut BootState> {
    let p = phase as u8;
    PHASE
        .compare_exchange(p, p + 1, Ordering::AcqRel, Ordering::Acquire)
        .ok()?;
    // SAFETY: the compare-exchange admits each phase once, in order; the
    // previous phase's reference is dead (see above).
    Some(unsafe { &mut *BOOT_STATE.0.get() })
}

static MEMORY_MAP: SpinLock<&'static [MemoryRegion]> = SpinLock::new(&[]);
static ACPI_RSDP: SpinLock<Option<PhysAddr>> = SpinLock::new(None);

/// The firmware memory map (empty before the higher-half phase).
pub(crate) fn memory_map() -> &'static [MemoryRegion] {
    *MEMORY_MAP.lock()
}

/// The ACPI RSDP, if firmware provided one.
pub(crate) fn acpi_rsdp() -> Option<PhysAddr> {
    *ACPI_RSDP.lock()
}

/// Per-CPU initialization shared by the boot CPU and APs: protections,
/// per-CPU block, GDT/TSS/IDT, x2APIC and timer. Marks the CPU online.
pub(crate) fn init_cpu(id: CpuId) {
    arch::cpu::enable_nx();
    arch::cpu::enable_protections();
    if arch::trap::init_cpu().is_none() {
        fatal("out of memory for CPU tables");
    }
    if let Err(e) = arch::apic::init_local() {
        fatal(e);
    }
    arch::apic::init_timer();
    // Syscall entry, and the mitigations the boot CPU chose (none yet when
    // this is the boot CPU: `kernel_space_entry` turns them on after).
    arch::usermode::init_cpu();
    arch::usermode::enable_cpu_mitigations();
    crate::task::register_cpu();
    let _ = id;
    crate::cpu::mark_online();
}

/// Stops the machine during boot with a message.
pub(crate) fn fatal(what: &str) -> ! {
    println!("ichor: frame: fatal: {what}");
    power::shutdown(ExitStatus::Failure)
}

/// Firmware phase, after boot services are gone: build the kernel address
/// space and switch to it.
fn start(state: &'static mut BootState) -> ! {
    if !arch::cpu::enable_nx() {
        fatal("CPU lacks no-execute support");
    }
    let Some(mut early) = EarlyAlloc::new(state.regions()) else {
        fatal("no usable memory above 1 MiB");
    };
    let plan = match mm::kspace::build(state.regions(), state.kernel_image, &mut early) {
        Ok(plan) => plan,
        Err(e) => fatal(e),
    };
    state.early = early;
    mm::kspace::switch(plan)
}

/// Higher-half phase: first code to run on the kernel's own page tables and
/// boot stack.
pub(crate) extern "sysv64" fn kernel_space_entry() -> ! {
    let Some(state) = take_boot_state(Phase::HigherHalf) else {
        fatal("higher-half entry reached twice");
    };
    mm::kspace::finish_switch();
    crate::cpu::init_boot_cpu_block();
    let mut early = core::mem::replace(&mut state.early, EarlyAlloc::EMPTY);
    if let Err(e) = mm::init(state.regions(), &mut early) {
        fatal(e);
    }
    let state: &'static BootState = state;
    *MEMORY_MAP.lock() = state.regions();
    *ACPI_RSDP.lock() = state.acpi_rsdp;
    println!("ichor: frame: running in the higher half");

    if arch::trap::init_idt().is_none() {
        fatal("cannot map the entry area");
    }
    arch::apic::mask_legacy_pic();
    let Some((hz, source)) = arch::apic::init_tsc() else {
        fatal("cannot determine the TSC frequency (no CPUID leaf, PM timer or PIT)");
    };
    init_cpu(CpuId::BOOT);
    println!(
        "ichor: frame: cpu0 ready ({} id {}, TSC {} MHz from {source}, {} timer)",
        if arch::cpu::features().x2apic {
            "x2APIC"
        } else {
            "xAPIC"
        },
        arch::apic::apic_id(),
        hz / 1_000_000,
        if arch::cpu::features().tsc_deadline {
            "TSC-deadline"
        } else {
            "one-shot"
        }
    );
    println!("ichor: frame: pci: {} functions", crate::bus::pci::init());
    let acpi_power = match power::init_acpi() {
        Some(true) => "power button and S5 from the FADT and DSDT",
        Some(false) => "power button, but no S5 in the DSDT or an SSDT (cannot turn off)",
        None => "no fixed-hardware power button",
    };
    println!("ichor: frame: acpi: {acpi_power}");
    let v = arch::cpu::vulnerabilities();
    let yn = |b: bool| if b { "affected" } else { "no" };
    println!(
        "ichor: frame: cpu0 speculation (ADR-0004): meltdown {}, mds {}, taa {}, bhi {}, gds {}, retbleed {}, srso {}, its {}, tsa {}, mmio {}, ssb {}; eibrs {}, ibrs {}, ibpb {}, md_clear {}, stibp {}, ssbd {}, smt {}",
        yn(v.meltdown),
        yn(v.mds),
        yn(v.taa),
        yn(v.bhi),
        yn(v.gds),
        yn(v.retbleed),
        yn(v.srso),
        yn(v.its),
        yn(v.tsa),
        yn(v.mmio),
        yn(v.ssb),
        v.eibrs,
        v.ibrs,
        v.pred_cmd,
        v.md_clear,
        v.stibp,
        v.ssbd.is_some(),
        v.smt,
    );
    let cmdline = cmdline::Cmdline::new(state.cmdline());
    let force_verw = cmdline.flag("force_verw");
    let forced = arch::usermode::Forced {
        verw: force_verw,
        pti: cmdline.flag("force_pti"),
        bhb: cmdline.flag("force_bhb"),
        ibpb_entry: cmdline.flag("force_ibpb_entry"),
        safe_ret: cmdline.flag("force_safe_ret"),
        ibpb_not_safe_ret: cmdline.get("srso") == Some("ibpb"),
        retpoline: cmdline.flag("force_retpoline"),
        stibp: cmdline.flag("force_stibp"),
    };
    let m = match arch::usermode::enable_mitigations(&v, forced) {
        Ok(m) => m,
        Err(e) => fatal(e),
    };
    let on = |b: bool| if b { "on" } else { "off (not needed)" };
    let pcid = if m.pcid { "PCID" } else { "no PCID" };
    println!(
        "ichor: frame: mitigations (ADR-0004): VERW on return to ring 3 {}, IBPB between cells {}, page-table isolation {}, Spectre v2 in the kernel {}, branch history {}, IBPB on entry {}, return thunks {}, RSB filled on context switch, Spectre v1 masked indices, indirect target selection {}, STIBP {}, speculative store bypass {}",
        // Forced, VERW runs whatever the CPU; it clears the buffers only
        // with MD_CLEAR (or AMD's VERW_CLEAR) microcode.
        match (m.verw, m.verw_missing, force_verw) {
            (true, true, _) => "on (forced; clears nothing without MD_CLEAR microcode)",
            (false, true, _) => "MISSING (no MD_CLEAR or VERW_CLEAR microcode)",
            (true, false, true) if !(v.mds || v.taa || v.tsa) => "on (forced)",
            (true, false, _) if v.tsa => "on (TSA)",
            (verw, _, _) => on(verw),
        },
        if m.ibpb {
            "on"
        } else {
            "off (IBPB not enumerated)"
        },
        if !m.pti {
            "off (not needed)".into()
        } else if v.meltdown {
            alloc::format!("on ({pcid})")
        } else {
            alloc::format!("on (forced, {pcid})")
        },
        match (m.eibrs, m.auto_ibrs, m.retpoline, m.retpoline_failed) {
            (true, _, true, _) => "eIBRS, retpolines (forced)".into(),
            (true, ..) => "eIBRS".into(),
            (_, true, ..) => "AutoIBRS".into(),
            (_, _, true, _) => "retpolines".into(),
            (_, _, _, Some(why)) if v.ibrs => alloc::format!("IBRS on entry (retpolines: {why})"),
            (_, _, _, Some(why)) => alloc::format!("NOT MITIGATED (retpolines: {why})"),
            _ if v.ibrs => "IBRS on entry".into(),
            _ => alloc::string::String::from("NOT MITIGATED (no IBRS)"),
        },
        match (m.bhi_dis_s, m.bhb_clear) {
            (true, _) => "BHI_DIS_S",
            (false, true) if v.bhi => "cleared on entry",
            (false, true) => "cleared on entry (forced)",
            (false, false) => "not affected",
        },
        match (m.ibpb_entry, m.ibpb_entry_missing, m.srso_incomplete) {
            (_, true, _) => "NOT MITIGATED (no IBPB)",
            (true, _, true) => "on (SRSO NOT MITIGATED: no IBPB_BRTYPE microcode)",
            (true, _, _) if v.retbleed || v.srso => "on (Retbleed, SRSO)",
            (true, _, _) => "on (forced)",
            (false, _, _) if forced.ibpb_entry => "off (forced, but no IBPB)",
            (false, _, _) if m.safe_ret.is_some() => "not needed (safe RET)",
            (false, _, _) => "not needed",
        },
        match (m.safe_ret, m.safe_ret_failed) {
            (_, Some(why)) => alloc::format!("NOT INSTALLED ({why})"),
            (Some(k), _) => alloc::format!(
                "safe RET ({}{})",
                match k {
                    arch::rethunk::SafeRet::Zen12 => "Zen 1/2",
                    arch::rethunk::SafeRet::Alias if v.srso => "Zen 3/4",
                    arch::rethunk::SafeRet::Alias => "Zen 3/4, forced",
                },
                if m.srso_incomplete {
                    "; SRSO between cells NOT MITIGATED: no IBPB_BRTYPE microcode"
                } else {
                    ""
                }
            ),
            (None, _) => "not needed".into(),
        },
        match (v.its, m.its_failed) {
            (true, Some(why)) => alloc::format!("aligned thunks (stack probe NOT ALIGNED: {why})"),
            (true, None) => "aligned thunks".into(),
            (false, _) => "not affected (thunks aligned)".into(),
        },
        match (m.stibp, m.stibp_missing) {
            (_, true) => "NOT MITIGATED (SMT, no STIBP)",
            (true, _) if forced.stibp && !v.smt => "on (forced)",
            (true, _) => "on (SMT)",
            (false, _) if v.smt => "not needed (eIBRS or AutoIBRS)",
            (false, _) => "not needed (no SMT)",
        },
        match (v.ssb, m.ssbd) {
            (false, _) => "not affected",
            (true, Some(arch::cpu::Ssbd::SpecCtrl)) => "SSBD by prctl",
            (true, Some(arch::cpu::Ssbd::Virt)) => "SSBD by prctl (VIRT_SPEC_CTRL)",
            (true, None) => "vulnerable (no SSBD)",
        },
    );
    if v.mmio {
        println!(
            "ichor: frame: MMIO stale data applies; no cell is given MMIO, so it calls for no VERW (ADR-0004)"
        );
    }
    enter_kernel(BootInfo {
        cmdline: state.cmdline(),
        roots: &state.roots[..state.roots_len],
        suffixes: &state.suffixes[..state.suffixes_len],
        api_token: Secret(&state.token[..state.token_len]),
        api_tls: Secret(&state.tls[..state.tls_len]),
        memory_map: state.regions(),
        acpi_rsdp: state.acpi_rsdp,
        firmware_vendor: core::str::from_utf8(&state.vendor[..state.vendor_len]).unwrap_or(""),
        firmware_revision: state.firmware_revision,
        uefi_revision: state.uefi_revision,
        kernel_image: state.kernel_image,
    })
}

/// Declares the kernel's entry point.
///
/// Expands to the one symbol frame's boot path calls once boot services have
/// been exited. Use it exactly once, in the kernel binary crate:
///
/// ```ignore
/// frame::main!(kmain);
///
/// fn kmain(info: frame::boot::BootInfo) -> ! {
///     frame::println!("hello");
///     frame::power::shutdown(frame::power::ExitStatus::Success)
/// }
/// ```
///
/// The expansion contains frame's only cross-crate `unsafe` attribute
/// (`export_name`); because it comes from this crate's macro, the kernel crate
/// can keep `#![forbid(unsafe_code)]`. The function-pointer coercion makes the
/// signature check happen at compile time in the caller's crate.
#[macro_export]
macro_rules! main {
    ($main:path) => {
        #[doc(hidden)]
        #[unsafe(export_name = "__ichor_kernel_main")]
        extern "Rust" fn __ichor_kernel_main(info: $crate::boot::BootInfo) -> ! {
            let main: fn($crate::boot::BootInfo) -> ! = $main;
            main(info)
        }
    };
}

unsafe extern "Rust" {
    /// Defined by [`main!`] in the kernel binary.
    fn __ichor_kernel_main(info: BootInfo) -> !;
}

fn enter_kernel(info: BootInfo) -> ! {
    // SAFETY: `__ichor_kernel_main` is only ever defined by the `main!` macro,
    // which gives it exactly this signature; defining it any other way
    // requires `unsafe` attributes, which only frame may use. A missing or
    // duplicate definition is a link error, not UB.
    unsafe { __ichor_kernel_main(info) }
}

/// Everything the kernel learns from firmware before boot services exit.
#[derive(Debug)]
pub struct BootInfo {
    cmdline: &'static str,
    roots: &'static [u8],
    suffixes: &'static [u8],
    api_token: Secret,
    api_tls: Secret,
    memory_map: &'static [MemoryRegion],
    acpi_rsdp: Option<PhysAddr>,
    firmware_vendor: &'static str,
    firmware_revision: u32,
    uefi_revision: u32,
    kernel_image: MemoryRegion,
}

impl BootInfo {
    /// The kernel command line (contents of `\ichor\cmdline`, or empty).
    pub fn cmdline(&self) -> &'static str {
        self.cmdline
    }

    /// The contents of `\ichor\roots.pem` on the boot volume (empty if
    /// there is none): the control plane's CA bundle.
    pub fn roots(&self) -> &'static [u8] {
        self.roots
    }

    /// The contents of `\ichor\suffixes.dat` on the boot volume (empty if
    /// there is none): the Public Suffix List rules the control plane
    /// checks wildcard certificates against.
    pub fn suffixes(&self) -> &'static [u8] {
        self.suffixes
    }

    /// The contents of `\ichor\apitoken` on the boot volume (empty if
    /// there is none): the control plane's API credential.
    pub fn api_token(&self) -> &'static [u8] {
        self.api_token.0
    }

    /// The contents of `\ichor\apitls.pem` on the boot volume (empty if
    /// there is none): the control plane's TLS certificates and key.
    pub fn api_tls(&self) -> &'static [u8] {
        self.api_tls.0
    }
}

/// Bytes that `Debug` does not print.
struct Secret(&'static [u8]);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes, redacted>", self.0.len())
    }
}

impl BootInfo {
    /// The firmware memory map, captured at the moment boot services exited.
    pub fn memory_map(&self) -> &'static [MemoryRegion] {
        self.memory_map
    }

    /// Physical address of the ACPI RSDP, preferring the ACPI 2.0+ table.
    pub fn acpi_rsdp(&self) -> Option<PhysAddr> {
        self.acpi_rsdp
    }

    /// Firmware vendor string (non-ASCII characters replaced with `?`).
    pub fn firmware_vendor(&self) -> &'static str {
        self.firmware_vendor
    }

    /// Vendor-defined firmware revision.
    pub fn firmware_revision(&self) -> u32 {
        self.firmware_revision
    }

    /// UEFI specification revision as `(major, minor)`; minor is encoded the
    /// way the spec does, e.g. 2.70 is `(2, 70)`.
    pub fn uefi_revision(&self) -> (u16, u16) {
        ((self.uefi_revision >> 16) as u16, self.uefi_revision as u16)
    }

    /// Where firmware loaded the kernel image.
    pub fn kernel_image(&self) -> MemoryRegion {
        self.kernel_image
    }
}

/// A physically contiguous range of memory and what it may be used for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    /// First byte of the region.
    pub base: PhysAddr,
    /// Length in bytes; always a multiple of the page size.
    pub len: u64,
    /// What the region holds.
    pub kind: MemoryKind,
}

impl MemoryRegion {
    /// One past the last byte of the region.
    pub fn end(&self) -> PhysAddr {
        PhysAddr::new(self.base.as_u64().saturating_add(self.len))
    }
}

impl fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#014x}..{:#014x}) {:?}",
            self.base.as_u64(),
            self.end().as_u64(),
            self.kind
        )
    }
}

/// Classification of a [`MemoryRegion`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MemoryKind {
    /// Free RAM.
    Usable,
    /// RAM used by firmware boot services. Free once frame has moved off the
    /// firmware-provided stack (milestone 1); until then it is in use.
    BootServices,
    /// The kernel image and data frame placed in it during boot.
    Kernel,
    /// ACPI tables; reclaimable once parsed.
    AcpiReclaimable,
    /// ACPI non-volatile storage; never usable.
    AcpiNvs,
    /// Firmware runtime services. Ichor never calls them, but the memory
    /// must stay untouched in case firmware SMM code depends on it.
    RuntimeServices,
    /// Memory-mapped I/O reported by firmware.
    Mmio,
    /// Byte-addressable persistent memory.
    Persistent,
    /// Memory that must be accepted before use (TDX/SEV-SNP guests).
    Unaccepted,
    /// RAM with detected errors.
    Unusable,
    /// Anything else, including types firmware invented.
    Reserved,
}
