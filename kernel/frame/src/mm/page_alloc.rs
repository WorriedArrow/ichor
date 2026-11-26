//! The physical page allocator: buddy policy (safe, `kernel/buddy`) over the
//! page metadata array, with frame validating every block it hands out.

use core::sync::atomic::Ordering::Relaxed;

use buddy::{Buddy, PageLinks};

use super::meta::{self, NO_PAGE, PageMeta, kind};
use super::{PAGE_SIZE, PhysAddr, align_down, align_up};
use crate::boot::{MemoryKind, MemoryRegion};
use crate::sync::SpinLock;

const ONE_MIB: u64 = 1 << 20;

static BUDDY: SpinLock<Buddy> = SpinLock::new(Buddy::new(0));
/// The largest order any contiguous request has asked for, served or not
/// (page allocator, large heap allocations, DMA buffers).
static LARGEST_REQUEST: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Records a contiguous request of `2^order` pages (see [`MemStats`]).
pub(crate) fn note_request(order: u32) {
    LARGEST_REQUEST.fetch_max(order, Relaxed);
}

struct Links(&'static [PageMeta]);

impl Links {
    fn link(v: u32) -> Option<usize> {
        (v != NO_PAGE).then_some(v as usize)
    }
    fn unlink(v: Option<usize>) -> u32 {
        v.and_then(|v| u32::try_from(v).ok()).unwrap_or(NO_PAGE)
    }
}

impl PageLinks for Links {
    fn next(&self, pfn: usize) -> Option<usize> {
        self.0
            .get(pfn)
            .and_then(|m| Self::link(m.next.load(Relaxed)))
    }
    fn prev(&self, pfn: usize) -> Option<usize> {
        self.0
            .get(pfn)
            .and_then(|m| Self::link(m.prev.load(Relaxed)))
    }
    fn set_next(&mut self, pfn: usize, next: Option<usize>) {
        if let Some(m) = self.0.get(pfn) {
            m.next.store(Self::unlink(next), Relaxed);
        }
    }
    fn set_prev(&mut self, pfn: usize, prev: Option<usize>) {
        if let Some(m) = self.0.get(pfn) {
            m.prev.store(Self::unlink(prev), Relaxed);
        }
    }
    fn free_order(&self, pfn: usize) -> Option<u8> {
        let m = self.0.get(pfn)?;
        (m.kind.load(Relaxed) == kind::FREE).then(|| m.order.load(Relaxed))
    }
    fn set_free_order(&mut self, pfn: usize, order: Option<u8>) {
        if let Some(m) = self.0.get(pfn) {
            match order {
                Some(o) => {
                    m.order.store(o, Relaxed);
                    m.kind.store(kind::FREE, Relaxed);
                }
                None => m.kind.store(kind::AVAILABLE, Relaxed),
            }
        }
    }
}

/// Whether a region holds RAM (as opposed to MMIO or holes).
pub(crate) fn is_ram(k: MemoryKind) -> bool {
    matches!(
        k,
        MemoryKind::Usable
            | MemoryKind::BootServices
            | MemoryKind::Kernel
            | MemoryKind::AcpiReclaimable
            | MemoryKind::AcpiNvs
            | MemoryKind::RuntimeServices
    )
}

/// One past the highest RAM page frame.
pub(crate) fn max_ram_pfn(regions: &[MemoryRegion]) -> u64 {
    regions
        .iter()
        .filter(|r| is_ram(r.kind))
        .map(|r| r.end().as_u64() / PAGE_SIZE)
        .max()
        .unwrap_or(0)
}

/// Hands free memory to the allocator: usable and boot-services RAM above
/// 1 MiB, minus `reserved` (the early allocator's range).
pub(crate) fn init(regions: &[MemoryRegion], reserved: (u64, u64)) {
    let metas = meta::all();
    let mut links = Links(metas);
    let mut b = BUDDY.lock();
    *b = Buddy::new(metas.len());
    for r in regions {
        if !matches!(r.kind, MemoryKind::Usable | MemoryKind::BootServices) {
            continue;
        }
        let lo = align_up(r.base.as_u64().max(ONE_MIB), PAGE_SIZE);
        let hi = align_down(r.end().as_u64(), PAGE_SIZE);
        // Split around the reserved range.
        let pieces = [(lo, hi.min(reserved.0)), (lo.max(reserved.1), hi)];
        for (s, e) in pieces {
            if s >= e {
                continue;
            }
            let (s, e) = (s / PAGE_SIZE, e / PAGE_SIZE);
            for m in metas.iter().take(e as usize).skip(s as usize) {
                m.kind.store(kind::AVAILABLE, Relaxed);
            }
            b.add_range(&mut links, s as usize, e as usize);
        }
    }
}

/// Allocates `2^order` contiguous pages, marking them with `tag`
/// (`kind::ALLOCATED` or `kind::SLAB`).
pub(crate) fn alloc(order: u8, tag: u8) -> Option<PhysAddr> {
    note_request(u32::from(order));
    let metas = meta::all();
    let pfn = BUDDY.lock().alloc(&mut Links(metas), order)?;
    let block = metas.get(pfn..pfn + (1 << order))?;
    // Validate the policy's answer before anything can use the memory.
    for m in block {
        let k = m.kind.load(Relaxed);
        if k != kind::AVAILABLE {
            #[allow(clippy::panic)]
            {
                panic!(
                    "page allocator returned pfn {pfn:#x} order {order} containing a page of kind {k}"
                );
            }
        }
    }
    for m in &block[1..] {
        m.kind.store(kind::TAIL, Relaxed);
    }
    block[0].order.store(order, Relaxed);
    block[0].kind.store(tag, Relaxed);
    Some(PhysAddr::new(pfn as u64 * PAGE_SIZE))
}

/// Allocates `2^order` contiguous pages as that many blocks of one page,
/// each marked with `tag` and freed on its own.
pub(crate) fn alloc_pages(order: u8, tag: u8) -> Option<PhysAddr> {
    let pa = alloc(order, tag)?;
    let pfn = pa.pfn() as usize;
    for m in meta::all().get(pfn..pfn + (1 << order))? {
        m.order.store(0, Relaxed);
        m.kind.store(tag, Relaxed);
    }
    Some(pa)
}

/// Frees a block from [`alloc`]. Panics (a kernel bug) if the block is not
/// currently allocated with this order and tag.
pub(crate) fn free(pa: PhysAddr, order: u8, tag: u8) {
    let metas = meta::all();
    let pfn = pa.pfn() as usize;
    let Some(block) = metas.get(pfn..pfn + (1 << order)) else {
        #[allow(clippy::panic)]
        {
            panic!("free of out-of-range page {pa}");
        }
    };
    let head_ok = block[0].kind.load(Relaxed) == tag && block[0].order.load(Relaxed) == order;
    if !head_ok || !pa.as_u64().is_multiple_of(PAGE_SIZE) {
        #[allow(clippy::panic)]
        {
            panic!("invalid free of {pa} order {order}: not an allocated block");
        }
    }
    for m in block {
        m.kind.store(kind::AVAILABLE, Relaxed);
    }
    if let Err(e) = BUDDY.lock().free(&mut Links(metas), pfn, order) {
        #[allow(clippy::panic)]
        {
            panic!("buddy rejected free of {pa} order {order}: {e:?}");
        }
    }
}

/// Physical memory statistics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemStats {
    /// Pages managed by the page allocator.
    pub total_pages: usize,
    /// Pages currently free.
    pub free_pages: usize,
    /// The largest order (`2^order` pages) any contiguous request has asked
    /// for since boot, including ones refused for exceeding `MAX_ORDER`.
    pub largest_request_order: u32,
}

/// Current physical memory statistics.
pub fn stats() -> MemStats {
    let b = BUDDY.lock();
    MemStats {
        total_pages: b.total_pages(),
        free_pages: b.free_pages(),
        largest_request_order: LARGEST_REQUEST.load(Relaxed),
    }
}
