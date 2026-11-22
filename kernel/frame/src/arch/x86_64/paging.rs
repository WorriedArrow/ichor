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
pub enum MapError {
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

/// Copies PML4 entry `index` from `from` into `to`, so both roots share
/// that slot's tables (page-table isolation: the entry area, and each
/// user slot of a shadow root).
///
/// # Safety
///
/// Both must satisfy [`table`]'s contract.
pub(crate) unsafe fn copy_entry(from: PhysAddr, to: PhysAddr, index: usize) {
    // SAFETY: caller contract.
    let (from, to) = (unsafe { table(from) }, unsafe { table(to) });
    if let (Some(f), Some(t)) = (from.get(index), to.get(index)) {
        t.store(f.load(Relaxed), Relaxed);
    }
}

/// The PML4 slot of `va`.
pub(crate) fn slot_of(va: u64) -> usize {
    pml4_index(va)
}

/// The physical address `va` translates to in the tables under `root`,
/// following huge pages; `None` if unmapped.
///
/// # Safety
///
/// `root` and every table reachable from it must satisfy [`table`]'s
/// contract (frame-built page tables do).
pub(crate) unsafe fn translate(root: PhysAddr, va: u64) -> Option<u64> {
    // SAFETY: caller contract.
    let mut t = unsafe { table(root) };
    let mut shift = 39u32;
    loop {
        let e = t[((va >> shift) & 511) as usize].load(Relaxed);
        if e & PRESENT == 0 {
            return None;
        }
        if shift == 12 || (shift < 39 && e & HUGE != 0) {
            let size = 1u64 << shift;
            return Some((e & ADDR_MASK & !(size - 1)) + (va & (size - 1)));
        }
        // SAFETY: a present non-leaf entry points at a table of the same
        // page table (caller contract).
        t = unsafe { table(PhysAddr::new(e & ADDR_MASK)) };
        shift -= 9;
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

// ---------------------------------------------------------------------------
// User address spaces (lower half, 4 KiB pages only).
// ---------------------------------------------------------------------------

const USER: u64 = 1 << 2;

/// One past the highest user virtual address.
pub(crate) const USER_END: u64 = 0x0000_7fff_ffff_f000;

/// Permissions of a user page. User pages are always readable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserProt {
    pub write: bool,
    pub exec: bool,
}

impl UserProt {
    fn bits(self) -> u64 {
        let mut e = PRESENT | USER;
        if self.write {
            e |= WRITABLE;
        }
        if !self.exec {
            e |= NO_EXECUTE;
        }
        e
    }

    fn from_bits(e: u64) -> Self {
        Self {
            write: e & WRITABLE != 0,
            exec: e & NO_EXECUTE == 0,
        }
    }
}

/// Finds the last-level entry for `va`, creating intermediate tables with
/// `alloc` when given.
///
/// # Safety
///
/// `root` and every table reachable from its lower half must satisfy
/// [`table`]'s contract for `'a`; `alloc` must return zeroed pages that do.
unsafe fn user_leaf<'a>(
    root: PhysAddr,
    va: u64,
    mut alloc: Option<&mut dyn FnMut() -> Option<PhysAddr>>,
) -> Result<Option<&'a AtomicU64>, MapError> {
    if va >= USER_END || !va.is_multiple_of(PAGE_SIZE) {
        return Err(MapError::Misaligned);
    }
    // SAFETY: caller contract.
    let mut t: &'a Table = unsafe { table(root) };
    for index in [pml4_index(va), pdpt_index(va), pd_index(va)] {
        let e = t[index].load(Relaxed);
        let next = if e & PRESENT != 0 {
            if e & HUGE != 0 {
                return Err(MapError::AlreadyMapped);
            }
            PhysAddr::new(e & ADDR_MASK)
        } else if let Some(a) = alloc.as_mut() {
            let pa = a().ok_or(MapError::OutOfMemory)?;
            t[index].store(pa.as_u64() | PRESENT | WRITABLE | USER, Relaxed);
            pa
        } else {
            return Ok(None);
        };
        // SAFETY: `next` is a table of this address space (caller contract)
        // or a fresh one from `alloc`.
        t = unsafe { table(next) };
    }
    Ok(Some(&t[pt_index(va)]))
}

/// Maps the page at `pa` at user address `va`.
///
/// # Safety
///
/// [`user_leaf`]'s contract. The caller transfers one reference to the
/// untyped page `pa` into the mapping.
pub(crate) unsafe fn user_map(
    root: PhysAddr,
    va: u64,
    pa: PhysAddr,
    prot: UserProt,
    alloc: &mut dyn FnMut() -> Option<PhysAddr>,
) -> Result<(), MapError> {
    // SAFETY: caller contract.
    let leaf = unsafe { user_leaf(root, va, Some(alloc)) }?.ok_or(MapError::OutOfMemory)?;
    set_leaf(leaf, pa.as_u64(), prot.bits())
}

/// Removes the mapping at `va`, returning the page it mapped. The caller
/// must flush the TLB.
///
/// # Safety
///
/// [`user_leaf`]'s contract.
pub(crate) unsafe fn user_unmap(root: PhysAddr, va: u64) -> Option<PhysAddr> {
    // SAFETY: caller contract.
    let leaf = unsafe { user_leaf(root, va, None) }.ok()??;
    let e = leaf.swap(0, Relaxed);
    (e & PRESENT != 0).then(|| PhysAddr::new(e & ADDR_MASK))
}

/// Changes the permissions of the mapping at `va`. The caller must flush
/// the TLB.
///
/// # Safety
///
/// [`user_leaf`]'s contract.
pub(crate) unsafe fn user_protect(root: PhysAddr, va: u64, prot: UserProt) -> bool {
    // SAFETY: caller contract.
    let Some(leaf) = unsafe { user_leaf(root, va, None) }.ok().flatten() else {
        return false;
    };
    let e = leaf.load(Relaxed);
    if e & PRESENT == 0 {
        return false;
    }
    leaf.store((e & ADDR_MASK) | prot.bits(), Relaxed);
    true
}

/// The page and permissions mapped at page-aligned `va`.
///
/// # Safety
///
/// [`user_leaf`]'s contract.
pub(crate) unsafe fn user_translate(root: PhysAddr, va: u64) -> Option<(PhysAddr, UserProt)> {
    // SAFETY: caller contract.
    let leaf = unsafe { user_leaf(root, va, None) }.ok()??;
    let e = leaf.load(Relaxed);
    (e & PRESENT != 0).then(|| (PhysAddr::new(e & ADDR_MASK), UserProt::from_bits(e)))
}

/// Clears the whole lower half of `root`, calling `leaf` for every mapped
/// page and `table` for every page-table page below the PML4.
///
/// # Safety
///
/// [`user_leaf`]'s contract; the address space must not be active on any
/// CPU.
pub(crate) unsafe fn user_teardown(
    root: PhysAddr,
    leaf: &mut dyn FnMut(PhysAddr),
    table_page: &mut dyn FnMut(PhysAddr),
) {
    fn walk(
        t: &Table,
        level: u8,
        leaf: &mut dyn FnMut(PhysAddr),
        table_page: &mut dyn FnMut(PhysAddr),
    ) {
        for e in t {
            let v = e.swap(0, Relaxed);
            if v & PRESENT == 0 {
                continue;
            }
            let pa = PhysAddr::new(v & ADDR_MASK);
            if level == 1 {
                leaf(pa);
            } else {
                // SAFETY: a present non-leaf entry of a user address space
                // points at one of its tables (`user_teardown`'s contract).
                walk(unsafe { table(pa) }, level - 1, leaf, table_page);
                table_page(pa);
            }
        }
    }
    // SAFETY: caller contract.
    let root_t = unsafe { table(root) };
    for e in root_t.iter().take(256) {
        let v = e.swap(0, Relaxed);
        if v & PRESENT == 0 {
            continue;
        }
        let pa = PhysAddr::new(v & ADDR_MASK);
        // SAFETY: as in `walk`.
        walk(unsafe { table(pa) }, 3, leaf, table_page);
        table_page(pa);
    }
}

/// Flushes the TLB entry for `va` on this CPU.
pub(crate) fn flush_page(va: u64) {
    // SAFETY: `invlpg` only drops a TLB entry.
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
}
