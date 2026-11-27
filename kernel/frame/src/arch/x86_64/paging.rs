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
// User address spaces (lower half): 4 KiB pages, and 2 MiB pages of 512
// pages each (ADR-0020), split back into 4 KiB pages when part of one
// changes.
// ---------------------------------------------------------------------------

const USER: u64 = 1 << 2;
/// A user leaf's protection key (bits 59-62), which PKRU's two bits for it
/// govern when CR4.PKE is set; ignored otherwise.
const KEY_SHIFT: u32 = 59;
const KEY: u64 = 0xf << KEY_SHIFT;
/// The bits of a user leaf that say what it allows.
const USER_BITS: u64 = PRESENT | WRITABLE | USER | NO_EXECUTE | KEY;
/// A 2 MiB leaf's page address (bit 12 is its PAT bit).
const HUGE_ADDR: u64 = ADDR_MASK & !(SIZE_2M - 1);
/// Bytes of a 2 MiB user page.
pub(crate) const USER_HUGE: u64 = SIZE_2M;

/// One past the highest user virtual address.
pub(crate) const USER_END: u64 = 0x0000_7fff_ffff_f000;

/// Permissions of a user page. User pages are always readable. `key` is
/// the page's protection key (0-15; only its low four bits count).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserProt {
    pub write: bool,
    pub exec: bool,
    pub key: u8,
}

impl UserProt {
    fn bits(self) -> u64 {
        let mut e = PRESENT | USER | ((u64::from(self.key) << KEY_SHIFT) & KEY);
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
            key: ((e & KEY) >> KEY_SHIFT) as u8,
        }
    }
}

/// A page-table page from `alloc`: zeroed, exclusively owned, and meeting
/// [`table`]'s contract.
type Alloc<'b> = &'b mut dyn FnMut() -> Option<PhysAddr>;

/// What [`user_leaf`] does on its way down.
enum Walk<'b> {
    /// Creates absent tables; stops at a 2 MiB page (`AlreadyMapped`).
    Create(Alloc<'b>),
    /// Splits a 2 MiB page into a table of 4 KiB pages; stops at an absent
    /// table.
    Split(Alloc<'b>),
}

/// Replaces the 2 MiB leaf `entry` (holding `e`) with a table of 512 4 KiB
/// leaves for the same pages, with the same permissions: every translation
/// stays what it was, so the TLB needs no flush for it. False if `alloc` has
/// no page.
fn split(entry: &AtomicU64, e: u64, alloc: Alloc<'_>) -> bool {
    let Some(pa) = alloc() else {
        return false;
    };
    // SAFETY: a fresh page-table page from `alloc` (its contract).
    let t = unsafe { table(pa) };
    let base = e & HUGE_ADDR;
    for (i, leaf) in (0u64..).zip(t.iter()) {
        leaf.store((base + i * PAGE_SIZE) | (e & USER_BITS), Relaxed);
    }
    entry.store(pa.as_u64() | PRESENT | WRITABLE | USER, Relaxed);
    true
}

/// Finds the last-level entry for `va` as `walk` says.
///
/// # Safety
///
/// `root` and every table reachable from its lower half must satisfy
/// [`table`]'s contract for `'a`, and each of its 2 MiB leaves must map one
/// aligned block of 512 untyped pages, each holding the one reference that
/// leaf was given per page (so a split's 4 KiB leaves take them over).
unsafe fn user_leaf<'a>(
    root: PhysAddr,
    va: u64,
    mut walk: Walk<'_>,
) -> Result<Option<&'a AtomicU64>, MapError> {
    if va >= USER_END || !va.is_multiple_of(PAGE_SIZE) {
        return Err(MapError::Misaligned);
    }
    // SAFETY: caller contract.
    let mut t: &'a Table = unsafe { table(root) };
    for (level, index) in [(3, pml4_index(va)), (2, pdpt_index(va)), (1, pd_index(va))] {
        let mut e = t[index].load(Relaxed);
        if e & PRESENT != 0 && e & HUGE != 0 {
            // Only page directories hold user pages this large.
            let (1, Walk::Split(a)) = (level, &mut walk) else {
                return Err(MapError::AlreadyMapped);
            };
            if !split(&t[index], e, &mut **a) {
                return Err(MapError::OutOfMemory);
            }
            e = t[index].load(Relaxed);
        }
        let next = if e & PRESENT != 0 {
            PhysAddr::new(e & ADDR_MASK)
        } else if let Walk::Create(a) = &mut walk {
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
    alloc: Alloc<'_>,
) -> Result<(), MapError> {
    // SAFETY: caller contract.
    let leaf = unsafe { user_leaf(root, va, Walk::Create(alloc)) }?.ok_or(MapError::OutOfMemory)?;
    set_leaf(leaf, pa.as_u64(), prot.bits())
}

/// Maps the aligned block of 512 pages at `pa` at 2 MiB-aligned user address
/// `va` as one 2 MiB page. A table there with nothing in it is replaced and
/// returned: the caller frees it once no CPU can still walk it (after a TLB
/// shootdown).
///
/// # Safety
///
/// [`user_leaf`]'s contract. The caller transfers one reference to each of
/// the 512 untyped pages into the mapping.
pub(crate) unsafe fn user_map_huge(
    root: PhysAddr,
    va: u64,
    pa: PhysAddr,
    prot: UserProt,
    alloc: Alloc<'_>,
) -> Result<Option<PhysAddr>, MapError> {
    let aligned = va.is_multiple_of(SIZE_2M) && pa.as_u64().is_multiple_of(SIZE_2M);
    if !aligned || va.checked_add(SIZE_2M).is_none_or(|e| e > USER_END) {
        return Err(MapError::Misaligned);
    }
    // SAFETY: caller contract.
    let mut t: &Table = unsafe { table(root) };
    for index in [pml4_index(va), pdpt_index(va)] {
        let e = t[index].load(Relaxed);
        let next = if e & PRESENT != 0 {
            PhysAddr::new(e & ADDR_MASK)
        } else {
            let pa = alloc().ok_or(MapError::OutOfMemory)?;
            t[index].store(pa.as_u64() | PRESENT | WRITABLE | USER, Relaxed);
            pa
        };
        // SAFETY: as in `user_leaf`.
        t = unsafe { table(next) };
    }
    let entry = &t[pd_index(va)];
    let e = entry.load(Relaxed);
    let old = if e & PRESENT == 0 {
        None
    } else if e & HUGE != 0 {
        return Err(MapError::AlreadyMapped);
    } else {
        let pt = PhysAddr::new(e & ADDR_MASK);
        // SAFETY: a present non-leaf entry is one of this space's tables.
        if unsafe { table(pt) }
            .iter()
            .any(|l| l.load(Relaxed) & PRESENT != 0)
        {
            return Err(MapError::AlreadyMapped);
        }
        Some(pt)
    };
    entry.store(pa.as_u64() | prot.bits() | HUGE, Relaxed);
    Ok(old)
}

/// Removes the mappings in `[start, end)`, at most `max` pages of them,
/// adding each page's address and page to `out`; returns where to go on from
/// if it stopped at `max`. Tables that are absent are skipped whole. A 2 MiB
/// page partly in the range is split first (a table from `alloc`); if there
/// is no page for one, all of it goes. The caller must flush the TLB.
///
/// # Safety
///
/// [`user_leaf`]'s contract.
pub(crate) unsafe fn user_unmap_range(
    root: PhysAddr,
    start: u64,
    end: u64,
    max: usize,
    out: &mut alloc::vec::Vec<(u64, PhysAddr)>,
    alloc: Alloc<'_>,
) -> Option<u64> {
    let end = end.min(USER_END);
    let mut va = start;
    'next: while va < end {
        // SAFETY: caller contract.
        let mut t: &Table = unsafe { table(root) };
        for (shift, index) in [
            (39, pml4_index(va)),
            (30, pdpt_index(va)),
            (21, pd_index(va)),
        ] {
            let mut e = t[index].load(Relaxed);
            if e & PRESENT != 0 && e & HUGE != 0 && shift == 21 {
                let base = va & !(SIZE_2M - 1);
                let whole = va == base && end - base >= SIZE_2M;
                if whole || !split(&t[index], e, &mut *alloc) {
                    if !out.is_empty() && out.len() + 512 > max {
                        return Some(va);
                    }
                    let pa = t[index].swap(0, Relaxed) & HUGE_ADDR;
                    for i in 0..512 {
                        let at = i * PAGE_SIZE;
                        out.push((base + at, PhysAddr::new(pa + at)));
                    }
                    va = base + SIZE_2M;
                    continue 'next;
                }
                e = t[index].load(Relaxed);
            }
            if e & PRESENT == 0 || e & HUGE != 0 {
                va = (va >> shift << shift) + (1 << shift);
                continue 'next;
            }
            // SAFETY: a present non-leaf entry of this space's lower half is
            // one of its tables (caller contract).
            t = unsafe { table(PhysAddr::new(e & ADDR_MASK)) };
        }
        for e in &t[pt_index(va)..] {
            if va >= end {
                break;
            }
            if out.len() >= max {
                return Some(va);
            }
            // An exchange only where present (the CPU may set its accessed
            // and dirty bits meanwhile; an absent entry it never writes).
            if e.load(Relaxed) & PRESENT != 0 {
                let v = e.swap(0, Relaxed);
                out.push((va, PhysAddr::new(v & ADDR_MASK)));
            }
            va += PAGE_SIZE;
        }
    }
    None
}

/// Changes the permissions of the mapping at `va`: `Ok(false)` if there is
/// none. A 2 MiB page there is split first (a table from `alloc`);
/// `Err(OutOfMemory)` if there is no page for one, and nothing changed. The
/// caller must flush the TLB.
///
/// # Safety
///
/// [`user_leaf`]'s contract.
pub(crate) unsafe fn user_protect(
    root: PhysAddr,
    va: u64,
    prot: UserProt,
    alloc: Alloc<'_>,
) -> Result<bool, MapError> {
    // SAFETY: caller contract.
    let leaf = match unsafe { user_leaf(root, va, Walk::Split(alloc)) } {
        Ok(Some(leaf)) => leaf,
        Err(MapError::OutOfMemory) => return Err(MapError::OutOfMemory),
        _ => return Ok(false),
    };
    let e = leaf.load(Relaxed);
    if e & PRESENT == 0 {
        return Ok(false);
    }
    leaf.store((e & ADDR_MASK) | prot.bits(), Relaxed);
    Ok(true)
}

/// The page and permissions mapped at page-aligned `va` (one of the 512
/// pages of a 2 MiB page, in one).
///
/// # Safety
///
/// [`user_leaf`]'s contract.
pub(crate) unsafe fn user_translate(root: PhysAddr, va: u64) -> Option<(PhysAddr, UserProt)> {
    if va >= USER_END || !va.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    // SAFETY: caller contract.
    let mut t: &Table = unsafe { table(root) };
    for (shift, index) in [
        (39, pml4_index(va)),
        (30, pdpt_index(va)),
        (21, pd_index(va)),
    ] {
        let e = t[index].load(Relaxed);
        if e & PRESENT == 0 || (e & HUGE != 0 && shift != 21) {
            return None;
        }
        if e & HUGE != 0 {
            let pa = (e & HUGE_ADDR) + (va & (SIZE_2M - 1));
            return Some((PhysAddr::new(pa), UserProt::from_bits(e)));
        }
        // SAFETY: as in `user_leaf`.
        t = unsafe { table(PhysAddr::new(e & ADDR_MASK)) };
    }
    let e = t[pt_index(va)].load(Relaxed);
    (e & PRESENT != 0).then(|| (PhysAddr::new(e & ADDR_MASK), UserProt::from_bits(e)))
}

/// Clears the whole lower half of `root`, calling `leaf` for every mapped
/// page and `table` for every page-table page below the PML4.
///
/// # Safety
///
/// [`user_leaf`]'s contract; the address space must not be active on any
/// CPU. A 2 MiB page is a call for each of its 512 pages.
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
        // Read, and cleared only where present: the space is active on no
        // CPU, so a plain load and store do (an exchange on each of a
        // table's 512 entries cost microseconds per address space).
        for e in t {
            let v = e.load(Relaxed);
            if v & PRESENT == 0 {
                continue;
            }
            e.store(0, Relaxed);
            let pa = PhysAddr::new(v & ADDR_MASK);
            if level == 1 {
                leaf(pa);
            } else if level == 2 && v & HUGE != 0 {
                // A 2 MiB page: one reference to each of its pages.
                for i in 0..512 {
                    leaf(PhysAddr::new((v & HUGE_ADDR) + i * PAGE_SIZE));
                }
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
        let v = e.load(Relaxed);
        if v & PRESENT == 0 {
            continue;
        }
        e.store(0, Relaxed);
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
