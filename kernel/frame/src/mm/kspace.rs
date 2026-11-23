//! Building and entering the kernel address space (ADR-0001 §3, "Higher
//! half").
//!
//! Firmware runs the image identity-mapped at wherever it loaded it. Frame
//! builds its own page tables with the linear map, the image at
//! `KERNEL_BASE` and a guarded boot stack, temporarily borrowing firmware's
//! lower-half (identity) entries. It loads them, rebases the image's absolute
//! pointers with its PE base relocations, and jumps to the high alias on the
//! new stack. Then it drops the identity map.
//!
//! While relocations are being applied, both the low and the high alias of
//! the image are mapped onto the same physical pages, so any mix of
//! patched (high) and unpatched (low) pointers is valid. That is what makes
//! it safe to run ordinary Rust code, including the panic handler, during the
//! switch.

use core::sync::atomic::{AtomicU64, Ordering};

use super::early::EarlyAlloc;
use super::page_alloc::{self, is_ram};
use super::{
    KERNEL_BASE, LINEAR_BASE, LINEAR_LIMIT, PAGE_SIZE, PhysAddr, STACKS_BASE, align_down, align_up,
};
use crate::arch::paging::{self, Mapper, Props};
use crate::arch::{self, regs};
use crate::boot::MemoryRegion;
use crate::mm::meta::kind;
use crate::sync::SpinLock;

/// Pages in a kernel stack (64 KiB). Each stack sits above an unmapped guard
/// page.
pub(crate) const STACK_PAGES: u64 = 16;
const STACK_SLOT: u64 = (STACK_PAGES + 1) * PAGE_SIZE;

const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Physical address of the kernel PML4.
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);
/// Serializes changes to kernel mappings after boot.
static KSPACE_LOCK: SpinLock<u64> = SpinLock::new(1); // next free stack slot

/// Everything [`switch`] needs.
#[derive(Debug)]
pub(crate) struct Plan {
    root: PhysAddr,
    stack_top: u64,
    image_base: u64,
    size_of_image: u64,
    relocs: Option<(u64, u64)>,
}

/// The image's PE headers, read from its first page.
fn image_headers(image: &MemoryRegion) -> Result<pe::Headers, &'static str> {
    let len = image.len.min(PAGE_SIZE) as usize;
    let ptr = core::ptr::with_exposed_provenance::<u8>(image.base.as_u64() as usize);
    // SAFETY: the first page of the loaded image holds the PE headers.
    // Firmware loaded them, they are identity-mapped while this runs, they
    // are not part of any Rust object, and nothing writes them.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    pe::parse_headers(bytes).map_err(|_| "kernel image has malformed PE headers")
}

/// Builds the kernel page tables. Runs on firmware's identity map.
pub(crate) fn build(
    regions: &[MemoryRegion],
    image: MemoryRegion,
    early: &mut EarlyAlloc,
) -> Result<Plan, &'static str> {
    if regs::read_cr4() & regs::CR4_LA57 != 0 {
        return Err("firmware enabled 5-level paging; not supported yet");
    }
    let headers = image_headers(&image)?;
    if headers.section_alignment as u64 != PAGE_SIZE || u64::from(headers.size_of_image) > image.len
    {
        return Err("kernel image layout is not page-aligned");
    }
    let huge_1g = arch::cpu::features().huge_1g;
    let root = early
        .alloc_zeroed_page()
        .ok_or("out of memory for page tables")?;
    let stack = early
        .alloc(STACK_PAGES)
        .ok_or("out of memory for the boot stack")?;
    let mut alloc = || early.alloc_zeroed_page();
    // SAFETY: `root` and every page `alloc` returns are fresh, zeroed pages
    // owned by the new page table and reachable at `phys_to_virt` (identity).
    let mut m = unsafe { Mapper::new(root, huge_1g, &mut alloc) };
    let oom = |_| "out of memory or overlap while building kernel page tables";

    // Every upper-half slot gets a PDPT so address spaces can share them.
    for slot in 256..512u64 {
        m.ensure_pdpt(0xffff_0000_0000_0000 | (slot << 39))
            .map_err(oom)?;
    }

    // Linear map of RAM, coalescing adjacent regions for larger pages.
    let mut span: Option<(u64, u64)> = None;
    let map_span = |m: &mut Mapper<'_>, (s, e): (u64, u64)| -> Result<(), &'static str> {
        let (s, e) = (align_down(s, PAGE_SIZE), align_up(e, PAGE_SIZE));
        if e > LINEAR_LIMIT {
            return Err("physical memory beyond the 64 TiB linear map");
        }
        // SAFETY: the linear map window is otherwise unused; it maps RAM
        // non-executable. Nothing creates references through it except frame
        // code that owns the memory in question.
        unsafe { m.map(LINEAR_BASE + s, s, e - s, Props::RW_DATA) }.map_err(oom)
    };
    for r in regions.iter().filter(|r| is_ram(r.kind)) {
        let (b, e) = (r.base.as_u64(), r.end().as_u64());
        span = match span {
            Some((s, se)) if se == b => Some((s, e)),
            Some(prev) => {
                map_span(&mut m, prev)?;
                Some((b, e))
            }
            None => Some((b, e)),
        };
    }
    if let Some(s) = span {
        map_span(&mut m, s)?;
    }

    // The image: headers read-only, sections with their own permissions.
    let base = image.base.as_u64();
    // SAFETY: `KERNEL_BASE` and up is otherwise unused; the pages are the
    // image's own.
    unsafe { m.map(KERNEL_BASE, base, PAGE_SIZE, Props::RO_DATA) }.map_err(oom)?;
    for s in headers.sections() {
        if s.virtual_size == 0 {
            continue;
        }
        let start = align_down(u64::from(s.virtual_address), PAGE_SIZE);
        let end = align_up(
            u64::from(s.virtual_address) + u64::from(s.virtual_size),
            PAGE_SIZE,
        );
        let props = match (s.is_exec(), s.is_write()) {
            (true, false) => Props::CODE,
            (false, true) => Props::RW_DATA,
            (false, false) => Props::RO_DATA,
            (true, true) => return Err("kernel image has a writable, executable section"),
        };
        // SAFETY: as above; sections are page-aligned and disjoint.
        unsafe { m.map(KERNEL_BASE + start, base + start, end - start, props) }.map_err(oom)?;
    }

    // The boot stack, in stack slot 0 (guard page below it).
    let stack_bottom = STACKS_BASE + PAGE_SIZE;
    // SAFETY: the stack region is otherwise unused; `stack` is fresh memory.
    unsafe {
        m.map(
            stack_bottom,
            stack.as_u64(),
            STACK_PAGES * PAGE_SIZE,
            Props::RW_DATA,
        )
    }
    .map_err(oom)?;

    // Borrow firmware's identity map for the lower half until we are high.
    let firmware_root = PhysAddr::new(regs::read_cr3() & ADDR_MASK);
    // SAFETY: CR3 points at firmware's live, identity-mapped PML4, which is
    // only read; `root` is our fresh PML4.
    unsafe { paging::copy_lower_half(firmware_root, root) };

    Ok(Plan {
        root,
        stack_top: stack_bottom + STACK_PAGES * PAGE_SIZE,
        image_base: base,
        size_of_image: u64::from(headers.size_of_image),
        relocs: headers
            .base_relocs
            .map(|d| (base + u64::from(d.rva), u64::from(d.size))),
    })
}

/// Loads the kernel page tables, rebases the image and continues at
/// `crate::boot::kernel_space_entry` on the boot stack, in the higher half.
pub(crate) fn switch(plan: Plan) -> ! {
    // SAFETY: `plan.root` maps the lower half exactly as firmware's tables do
    // (copied entries), so the code, stack and data in use stay mapped; it
    // adds the linear map, the high image alias and the boot stack.
    unsafe { regs::write_cr3(plan.root.as_u64()) };
    super::linear_map_active();
    KERNEL_ROOT.store(plan.root.as_u64(), Ordering::Relaxed);

    let delta = KERNEL_BASE.wrapping_sub(plan.image_base);
    if let Some((table, len)) = plan.relocs {
        let ptr = core::ptr::with_exposed_provenance::<u8>(table as usize);
        // SAFETY: the base relocation table lies inside the loaded image
        // (`.reloc`), is identity-mapped until we leave the lower half, is
        // not part of any Rust object, and is never written.
        let table = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
        for rva in pe::dir64_relocations(table) {
            let Ok(rva) = rva else {
                crate::boot::fatal("kernel image has an unsupported base relocation");
            };
            let rva = u64::from(rva);
            if rva + 8 > plan.size_of_image {
                crate::boot::fatal("kernel image relocation outside the image");
            }
            // Patch through the (writable) linear map alias: the image's own
            // mapping may be read-only for `.rdata`.
            let slot = core::ptr::with_exposed_provenance_mut::<u64>(
                (LINEAR_BASE + plan.image_base + rva) as usize,
            );
            // SAFETY: `slot` is an 8-byte field inside the image that the
            // linker recorded as an absolute address; it is mapped RW in the
            // linear map. This is the loader's job, done once on one CPU.
            let old = unsafe { slot.read_unaligned() };
            // SAFETY: as above. The new value is what the linker would have
            // written for base `KERNEL_BASE`; until we jump, both the old and
            // the new target are mapped onto the same memory.
            unsafe { slot.write_unaligned(old.wrapping_add(delta)) };
        }
    }

    // SAFETY: the stack is mapped and unused; the image is mapped at
    // `KERNEL_BASE` and fully rebased; `kernel_space_entry` never returns.
    unsafe { arch::jump_to_high_half(plan.stack_top, delta) }
}

/// Runs first thing in the higher half: removes the identity map and turns
/// on the protections that would have broken firmware's tables.
pub(crate) fn finish_switch() {
    let root = PhysAddr::new(KERNEL_ROOT.load(Ordering::Relaxed));
    // SAFETY: we execute from the high image alias on the high boot stack;
    // nothing refers to the lower half any more. The TLB is flushed below.
    unsafe { paging::clear_lower_half(root) };
    arch::flush_tlb_all();
    arch::cpu::enable_protections();
}

/// Physical address of the kernel PML4.
pub(crate) fn kernel_root() -> u64 {
    KERNEL_ROOT.load(Ordering::Relaxed)
}

/// Allocates and maps a new kernel stack below a guard page; returns its top.
pub(crate) fn alloc_stack() -> Option<u64> {
    let pages = page_alloc::alloc(STACK_PAGES.trailing_zeros() as u8, kind::ALLOCATED)?;
    let mut next_slot = KSPACE_LOCK.lock();
    let bottom = STACKS_BASE + *next_slot * STACK_SLOT + PAGE_SIZE;
    let root = PhysAddr::new(KERNEL_ROOT.load(Ordering::Relaxed));
    let mut alloc = || {
        let pa = page_alloc::alloc(0, kind::ALLOCATED)?;
        // SAFETY: a fresh page from the allocator, reachable via the linear
        // map, about to become a page table.
        unsafe { paging::zero_page(pa) };
        Some(pa)
    };
    // SAFETY: `root` is the live kernel PML4 and `alloc` yields zeroed,
    // owned pages, all reachable through the linear map.
    let mut m = unsafe { Mapper::new(root, false, &mut alloc) };
    // SAFETY: stack slots are handed out once each (under the lock), so the
    // range is unused; the pages are freshly allocated.
    if unsafe {
        m.map(
            bottom,
            pages.as_u64(),
            STACK_PAGES * PAGE_SIZE,
            Props::RW_DATA,
        )
    }
    .is_err()
    {
        drop(next_slot);
        page_alloc::free(pages, STACK_PAGES.trailing_zeros() as u8, kind::ALLOCATED);
        return None;
    }
    *next_slot += 1;
    Some(bottom + STACK_PAGES * PAGE_SIZE)
}

/// Maps `[pa, pa + len)` at `va` in the entry area (ADR-0004 §2: the one
/// kernel slot user roots share under page-table isolation). Each caller
/// owns a fixed, disjoint part of the area, so nothing is mapped twice.
pub(crate) fn map_entry(va: u64, pa: u64, len: u64, props: Props) -> Option<()> {
    if paging::slot_of(va) != paging::slot_of(super::ENTRY_BASE) {
        return None;
    }
    let _serial = KSPACE_LOCK.lock();
    let root = PhysAddr::new(KERNEL_ROOT.load(Ordering::Relaxed));
    let mut alloc = || {
        let pa = page_alloc::alloc(0, kind::ALLOCATED)?;
        // SAFETY: a fresh page from the allocator, reachable via the linear
        // map, about to become a page table.
        unsafe { paging::zero_page(pa) };
        Some(pa)
    };
    // SAFETY: `root` is the live kernel PML4 and `alloc` yields zeroed,
    // owned pages, all reachable through the linear map.
    let mut m = unsafe { Mapper::new(root, false, &mut alloc) };
    // SAFETY: the range lies in the entry area, otherwise unused, and each
    // part is mapped once (above). The pages are frame's own (image text,
    // its per-CPU tables, stacks and blocks), already reachable through
    // their usual mapping; an alias of them creates no new Rust reference.
    unsafe { m.map(va, pa, len, props) }.ok()
}

/// The physical address of kernel virtual address `va`.
pub(crate) fn kernel_phys(va: u64) -> Option<u64> {
    // SAFETY: the kernel root and all its tables are frame-built page
    // tables, reachable through the linear map; the walk only reads.
    unsafe { paging::translate(PhysAddr::new(kernel_root()), va) }
}

/// Base of the kernel MMIO window (ADR-0005).
const MMIO_BASE: u64 = 0xffff_d000_0000_0000;
/// Size of the MMIO window (1 TiB).
const MMIO_SIZE: u64 = 1 << 40;
/// Next free offset in the MMIO window.
static MMIO_NEXT: SpinLock<u64> = SpinLock::new(0);

/// Maps physical `[pa, pa + len)` uncached into the MMIO window and returns
/// the virtual address of `pa`. The caller (`IoMem::map`) has checked the
/// range is device memory, not RAM.
pub(crate) fn map_mmio(pa: u64, len: u64) -> Option<u64> {
    let props = Props {
        write: true,
        exec: false,
        global: true,
        uncached: true,
    };
    map_window(pa, len, props)
}

/// Maps the page of code at `pa` (a hypervisor's) into the same window.
pub(crate) fn map_code(pa: u64) -> Option<u64> {
    map_window(pa, PAGE_SIZE, Props::CODE)
}

fn map_window(pa: u64, len: u64, props: Props) -> Option<u64> {
    let start = super::align_down(pa, PAGE_SIZE);
    let end = super::align_up(pa.checked_add(len)?, PAGE_SIZE);
    let size = end - start;
    let mut next = MMIO_NEXT.lock();
    if next.checked_add(size)? > MMIO_SIZE {
        return None;
    }
    let va = MMIO_BASE + *next;
    let root = PhysAddr::new(KERNEL_ROOT.load(Ordering::Relaxed));
    let mut alloc = || {
        let pa = page_alloc::alloc(0, kind::ALLOCATED)?;
        // SAFETY: a fresh page from the allocator, reachable via the linear
        // map, about to become a page table.
        unsafe { paging::zero_page(pa) };
        Some(pa)
    };
    // SAFETY: `root` is the live kernel PML4 and `alloc` yields zeroed,
    // owned pages, all reachable through the linear map.
    let mut m = unsafe { Mapper::new(root, false, &mut alloc) };
    // SAFETY: the window range is handed out once (bump allocator under the
    // lock), so it is unused. The physical range is device MMIO, not RAM, or
    // a page given up to the hypervisor: no Rust object lives there and the
    // mapping cannot alias one.
    unsafe { m.map(va, start, size, props) }.ok()?;
    *next += size;
    Some(va + (pa - start))
}
