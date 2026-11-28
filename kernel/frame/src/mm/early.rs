//! The boot-time bump allocator.
//!
//! Before the page allocator exists, frame needs memory for page tables, the
//! boot stack and the page metadata array. It carves them, top-down, from the
//! largest usable region above 1 MiB. Everything it hands out stays reserved
//! forever; the page allocator is told to skip `[next, hi)`.

use crate::arch::paging;
use crate::boot::{MemoryKind, MemoryRegion};
use crate::mm::{PAGE_SIZE, PhysAddr, align_down, align_up};

const ONE_MIB: u64 = 1 << 20;

#[derive(Debug)]
pub(crate) struct EarlyAlloc {
    lo: u64,
    next: u64,
    hi: u64,
}

impl EarlyAlloc {
    pub(crate) const EMPTY: Self = Self {
        lo: 0,
        next: 0,
        hi: 0,
    };

    /// Takes the largest usable region between 1 MiB and `limit` (the end
    /// of what the current page tables identity-map).
    pub(crate) fn new(regions: &[MemoryRegion], limit: u64) -> Option<Self> {
        let r = regions
            .iter()
            .filter(|r| r.kind == MemoryKind::Usable)
            .map(|r| {
                let lo = align_up(r.base.as_u64().max(ONE_MIB), PAGE_SIZE);
                let hi = align_down(r.end().as_u64().min(limit), PAGE_SIZE);
                (lo, hi.max(lo))
            })
            .max_by_key(|&(lo, hi)| hi - lo)?;
        Some(Self {
            lo: r.0,
            next: r.1,
            hi: r.1,
        })
    }

    /// Allocates `pages` contiguous pages (not zeroed).
    pub(crate) fn alloc(&mut self, pages: u64) -> Option<PhysAddr> {
        let size = pages.checked_mul(PAGE_SIZE)?;
        if self.next - self.lo < size {
            return None;
        }
        self.next -= size;
        Some(PhysAddr::new(self.next))
    }

    /// Allocates one zeroed page.
    pub(crate) fn alloc_zeroed_page(&mut self) -> Option<PhysAddr> {
        let pa = self.alloc(1)?;
        // SAFETY: the page was just carved out of usable RAM that nothing
        // else owns, and it is reachable at `phys_to_virt` (identity before
        // the switch, linear map after).
        unsafe { paging::zero_page(pa) };
        Some(pa)
    }

    /// The physical range handed out so far.
    pub(crate) fn used(&self) -> (u64, u64) {
        (self.next, self.hi)
    }
}
