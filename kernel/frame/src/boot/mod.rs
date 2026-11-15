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
//! 5. masks interrupts and calls the kernel's main function (declared with
//!    [`frame::main!`](crate::main)) with a [`BootInfo`].
//!
//! After step 4 no firmware code runs again: Ichor never calls UEFI runtime
//! services.

mod uefi;

use core::fmt;

use crate::mm::PhysAddr;

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
