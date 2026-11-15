//! Memory management: physical memory, the kernel address space, the page
//! allocator and the kernel heap.
//!
//! Kernel virtual address layout (x86_64, 4-level paging):
//!
//! | Range | Contents |
//! |---|---|
//! | `0x0000_0000_0000_0000..0x0000_8000_0000_0000` | user (empty until milestone 2) |
//! | `0xffff_8000_0000_0000..+64 TiB` | linear map of all RAM, RW, NX |
//! | `0xffff_e000_0000_0000..` | kernel stacks, each below an unmapped guard page |
//! | `0xffff_ffff_8000_0000..` | the kernel image, per-section permissions |
//!
//! All 256 upper-half PML4 slots get their PDPT at boot, so every future
//! address space can share the kernel half by copying PML4 entries.

pub(crate) mod early;
mod frame;
mod heap;
pub(crate) mod kspace;
pub(crate) mod meta;
pub(crate) mod page_alloc;
pub(crate) mod tlb;
mod vmspace;

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use self::early::EarlyAlloc;
use crate::boot::MemoryRegion;

pub use self::frame::{UFrame, VmReader, VmWriter};
pub use self::page_alloc::{MemStats, stats};
pub use self::vmspace::VmSpace;

/// Unbinds any user address space from the current task and switches back to
/// the kernel address space. Call before dropping a `VmSpace` the current
/// task was bound to.
pub fn activate_kernel_space() {
    crate::task::set_current_vm_root(0);
}
pub use crate::arch::paging::{MapError, UserProt};

/// Size of a base page on every architecture Ichor supports.
pub const PAGE_SIZE: u64 = 4096;

/// Base of the linear map of physical memory.
pub(crate) const LINEAR_BASE: u64 = 0xffff_8000_0000_0000;
/// Size of the linear map window (the most physical memory supported).
pub(crate) const LINEAR_LIMIT: u64 = 1 << 46;
/// Base of the kernel stack region.
pub(crate) const STACKS_BASE: u64 = 0xffff_e000_0000_0000;
/// Where the kernel image is mapped.
pub(crate) const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;

/// Offset from a physical address to the virtual address it is accessible
/// at: 0 while running on firmware's identity map, `LINEAR_BASE` afterwards.
static PHYS_OFFSET: AtomicU64 = AtomicU64::new(0);

/// The virtual address at which frame currently reaches physical `pa`.
pub(crate) fn phys_to_virt(pa: PhysAddr) -> u64 {
    pa.0.wrapping_add(PHYS_OFFSET.load(Ordering::Relaxed))
}

/// Called once the kernel page tables (with the linear map) are live.
pub(crate) fn linear_map_active() {
    PHYS_OFFSET.store(LINEAR_BASE, Ordering::Relaxed);
}

/// A physical address. Holding one grants nothing: it cannot be dereferenced
/// or mapped without going through frame's allocator and page-table APIs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Wraps a raw physical address.
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// The raw address.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// The page frame number containing this address.
    pub const fn pfn(self) -> u64 {
        self.0 / PAGE_SIZE
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Reserves and installs the page metadata array, then hands free memory to
/// the page allocator (which makes the heap usable). Runs once, in the
/// higher half, before any other CPU starts.
pub(crate) fn init(regions: &[MemoryRegion], early: &mut EarlyAlloc) -> Result<(), &'static str> {
    let max_pfn = page_alloc::max_ram_pfn(regions);
    if max_pfn > u64::from(u32::MAX - 1) {
        return Err("more physical memory than page links can address");
    }
    let bytes = max_pfn * core::mem::size_of::<meta::PageMeta>() as u64;
    let pages = bytes.div_ceil(PAGE_SIZE);
    let pa = early
        .alloc(pages)
        .ok_or("out of memory for page metadata")?;
    let va = phys_to_virt(pa);
    let ptr = core::ptr::with_exposed_provenance_mut::<u8>(va as usize);
    // SAFETY: the early allocator just carved these pages out of usable RAM
    // and will never hand them out again; they are mapped RW through the
    // linear map, and nothing else refers to them.
    unsafe { core::ptr::write_bytes(ptr, 0, (pages * PAGE_SIZE) as usize) };
    // SAFETY: `va` is the linear-map address of `max_pfn` zeroed,
    // page-aligned, permanently reserved metadata slots; this runs once,
    // before other CPUs exist.
    unsafe { meta::install(va, max_pfn as usize) };
    page_alloc::init(regions, early.used());
    Ok(())
}

pub(crate) const fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

pub(crate) const fn align_down(v: u64, a: u64) -> u64 {
    v / a * a
}
