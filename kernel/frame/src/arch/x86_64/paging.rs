//! x86_64 4-level page tables.
//!
//! Table pages are viewed as `[AtomicU64; 512]`: hardware sets accessed/dirty
//! bits concurrently with software, and other CPUs may walk the same tables,
//! so every entry access is atomic.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::mm::{PAGE_SIZE, PhysAddr, phys_to_virt};

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const WRITE_THROUGH: u64 = 1 << 3;
const NO_CACHE: u64 = 1 << 4;
const HUGE: u64 = 1 << 7;
const GLOBAL: u64 = 1 << 8;
const NO_EXECUTE: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

const SIZE_2M: u64 = 2 << 20;
const SIZE_1G: u64 = 1 << 30;

pub(crate) type Table = [AtomicU64; 512];

/// Access properties of a kernel mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Props {
    pub(crate) write: bool,
    pub(crate) exec: bool,
    pub(crate) global: bool,
    pub(crate) uncached: bool,
}

impl Props {
    pub(crate) const RW_DATA: Props = Props {
        write: true,
        exec: false,
        global: true,
        uncached: false,
    };
    pub(crate) const RO_DATA: Props = Props {
        write: false,
        ..Self::RW_DATA
    };
    pub(crate) const CODE: Props = Props {
        write: false,
        exec: true,
        ..Self::RW_DATA
    };

    fn bits(self, huge: bool) -> u64 {
        let mut e = PRESENT;
        if self.write {
            e |= WRITABLE;
        }
        if !self.exec {
            e |= NO_EXECUTE;
        }
        if self.global {
            e |= GLOBAL;
        }
        if self.uncached {
            e |= NO_CACHE | WRITE_THROUGH;
        }
        if huge {
            e |= HUGE;
        }
        e
    }
}

/// Views the page table page at `pa`.
///
/// # Safety
///
/// `pa` must be a page that belongs to a page table (or is about to become
/// one) for at least `'a`, and must be mapped at `phys_to_virt(pa)` for `'a`.
pub(crate) unsafe fn table<'a>(pa: PhysAddr) -> &'a Table {
    let va = phys_to_virt(pa) as usize;
    // SAFETY: caller contract: the page is page-table memory, mapped, 4 KiB
    // aligned (PFN-derived), and only ever accessed atomically.
    unsafe { &*core::ptr::with_exposed_provenance::<Table>(va) }
}

/// Why a mapping could not be installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MapError {
    OutOfMemory,
    AlreadyMapped,
    Misaligned,
}

/// Installs mappings into a page table. Intermediate tables come from
/// `alloc`, which must return zeroed, exclusively owned pages.
pub(crate) struct Mapper<'a> {
    root: PhysAddr,
    huge_1g: bool,
    alloc: &'a mut dyn FnMut() -> Option<PhysAddr>,
}

impl<'a> Mapper<'a> {
    /// # Safety
    ///
    /// `root` must be a PML4 page satisfying [`table`]'s contract for `'a`,
    /// and every page `alloc` returns must too.
    pub(crate) unsafe fn new(
        root: PhysAddr,
        huge_1g: bool,
        alloc: &'a mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Self {
        Self {
            root,
            huge_1g,
            alloc,
        }
    }

    fn root(&self) -> &'a Table {
        // SAFETY: `new`'s contract.
        unsafe { table(self.root) }
    }

    fn child(&mut self, t: &Table, index: usize) -> Result<&'a Table, MapError> {
        let e = t[index].load(Relaxed);
        let pa = if e & PRESENT == 0 {
            let pa = (self.alloc)().ok_or(MapError::OutOfMemory)?;
            t[index].store(pa.as_u64() | PRESENT | WRITABLE, Relaxed);
            pa
        } else if e & HUGE != 0 {
            return Err(MapError::AlreadyMapped);
        } else {
            PhysAddr::new(e & ADDR_MASK)
        };
        // SAFETY: `pa` is either a fresh page from `alloc` or a table this
        // root already references; both satisfy `table` per `new`'s contract.
        Ok(unsafe { table(pa) })
    }

    /// Ensures the PDPT for the PML4 slot covering `va` exists.
    pub(crate) fn ensure_pdpt(&mut self, va: u64) -> Result<(), MapError> {
        let root = self.root();
        self.child(root, pml4_index(va)).map(|_| ())
    }

    /// Maps `[va, va + len)` to `[pa, pa + len)` using the largest pages that
    /// fit the alignment of both addresses.
    ///
    /// # Safety
    ///
    /// The range must be unused kernel virtual address space in this table,
    /// and mapping `pa` there must not let safe code create references that
    /// alias memory Rust already has references to in an incompatible way.
    pub(crate) unsafe fn map(
        &mut self,
        mut va: u64,
        mut pa: u64,
        len: u64,
        props: Props,
    ) -> Result<(), MapError> {
        if !va.is_multiple_of(PAGE_SIZE)
            || !pa.is_multiple_of(PAGE_SIZE)
            || !len.is_multiple_of(PAGE_SIZE)
        {
            return Err(MapError::Misaligned);
        }
        let end = va.checked_add(len).ok_or(MapError::Misaligned)?;
        while va < end {
            let left = end - va;
            let fits =
                |size: u64| va.is_multiple_of(size) && pa.is_multiple_of(size) && left >= size;
            let pdpt = self.child(self.root(), pml4_index(va))?;
            let size = if self.huge_1g && fits(SIZE_1G) {
                set_leaf(&pdpt[pdpt_index(va)], pa, props.bits(true))?;
                SIZE_1G
            } else {
                let pd = self.child(pdpt, pdpt_index(va))?;
                if fits(SIZE_2M) {
                    set_leaf(&pd[pd_index(va)], pa, props.bits(true))?;
                    SIZE_2M
                } else {
                    let pt = self.child(pd, pd_index(va))?;
                    set_leaf(&pt[pt_index(va)], pa, props.bits(false))?;
                    PAGE_SIZE
                }
            };
            va += size;
            pa += size;
        }
        Ok(())
    }
}

fn set_leaf(e: &AtomicU64, pa: u64, bits: u64) -> Result<(), MapError> {
    if e.load(Relaxed) & PRESENT != 0 {
        return Err(MapError::AlreadyMapped);
    }
    e.store((pa & ADDR_MASK) | bits, Relaxed);
    Ok(())
}

fn pml4_index(va: u64) -> usize {
    ((va >> 39) & 511) as usize
}
fn pdpt_index(va: u64) -> usize {
    ((va >> 30) & 511) as usize
}
fn pd_index(va: u64) -> usize {
    ((va >> 21) & 511) as usize
}
fn pt_index(va: u64) -> usize {
    ((va >> 12) & 511) as usize
}

/// Zeroes a page through its page-table view.
///
/// # Safety
///
/// Same as [`table`], and nothing else may be using the page.
pub(crate) unsafe fn zero_page(pa: PhysAddr) {
    // SAFETY: caller contract.
    let t = unsafe { table(pa) };
    for e in t {
        e.store(0, Relaxed);
    }
}

/// Copies the lower-half (user) PML4 entries from `from` into `to`.
///
/// # Safety
///
/// Both must satisfy [`table`]'s contract.
pub(crate) unsafe fn copy_lower_half(from: PhysAddr, to: PhysAddr) {
    // SAFETY: caller contract.
    let (from, to) = (unsafe { table(from) }, unsafe { table(to) });
    for (f, t) in from.iter().zip(to.iter()).take(256) {
        t.store(f.load(Relaxed), Relaxed);
    }
}

/// Clears the lower-half PML4 entries of `root`.
///
/// # Safety
///
/// Same as [`table`]; the caller must not be executing from or using the
/// lower half, and must flush the TLB afterwards.
pub(crate) unsafe fn clear_lower_half(root: PhysAddr) {
    // SAFETY: caller contract.
    let t = unsafe { table(root) };
    for e in t.iter().take(256) {
        e.store(0, Relaxed);
    }
}

/// Copies the upper-half (kernel) PML4 entries from `from` into `to`.
///
/// # Safety
///
/// Both must satisfy [`table`]'s contract.
pub(crate) unsafe fn copy_upper_half(from: PhysAddr, to: PhysAddr) {
    // SAFETY: caller contract.
    let (from, to) = (unsafe { table(from) }, unsafe { table(to) });
    for (f, t) in from.iter().zip(to.iter()).skip(256) {
        t.store(f.load(Relaxed), Relaxed);
    }
}

/// Writes one raw entry of the table at `pa`.
///
/// # Safety
///
/// [`table`]'s contract, and `value` must be a valid entry for that level
/// that the caller has accounted for.
pub(crate) unsafe fn set_entry(pa: PhysAddr, index: usize, value: u64) {
    // SAFETY: caller contract.
    let t = unsafe { table(pa) };
    if let Some(e) = t.get(index) {
        e.store(value, Relaxed);
    }
}
