//! The kernel heap (`GlobalAlloc`).
//!
//! Small allocations (up to 2 KiB) come from slab pages: one size class per
//! page, with the slot-in-use bitmap kept in the page's metadata rather than
//! in the freed memory itself. No allocator state ever lives in memory handed
//! to callers, so a use-after-free in a caller cannot corrupt the allocator,
//! and double or mismatched frees are detected. Larger allocations take
//! whole buddy blocks. All heap memory is reached through the linear map.
//!
//! Per-CPU slab caches arrive with the scheduler; one lock per size class
//! is enough for boot.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::Ordering::Relaxed;

use super::meta::{self, NO_PAGE, kind};
use super::page_alloc;
use super::{LINEAR_BASE, PAGE_SIZE, PhysAddr, phys_to_virt};
use crate::sync::SpinLock;

const CLASSES: [u64; 7] = [32, 64, 128, 256, 512, 1024, 2048];

/// Head of the list of partially used slab pages of each class.
static PARTIAL: [SpinLock<u32>; CLASSES.len()] = [const { SpinLock::new(NO_PAGE) }; CLASSES.len()];

fn slots(class: usize) -> u32 {
    (PAGE_SIZE / CLASSES[class]) as u32
}

fn class_for(layout: Layout) -> Option<usize> {
    let size = layout.size().max(layout.align()) as u64;
    CLASSES.iter().position(|&c| c >= size)
}

fn large_order(layout: Layout) -> Option<u8> {
    let size = (layout.size().max(layout.align()) as u64).div_ceil(PAGE_SIZE);
    let order = size.next_power_of_two().trailing_zeros();
    (order <= u32::from(buddy::MAX_ORDER)).then_some(order as u8)
}

fn used_count(m: &meta::PageMeta) -> u32 {
    m.bitmap[0].load(Relaxed).count_ones() + m.bitmap[1].load(Relaxed).count_ones()
}

fn list_push(head: &mut u32, pfn: u32) {
    let metas = meta::all();
    let Some(m) = metas.get(pfn as usize) else {
        return;
    };
    m.prev.store(NO_PAGE, Relaxed);
    m.next.store(*head, Relaxed);
    if let Some(h) = metas.get(*head as usize) {
        h.prev.store(pfn, Relaxed);
    }
    *head = pfn;
}

fn list_remove(head: &mut u32, pfn: u32) {
    let metas = meta::all();
    let Some(m) = metas.get(pfn as usize) else {
        return;
    };
    let (prev, next) = (m.prev.load(Relaxed), m.next.load(Relaxed));
    match metas.get(prev as usize) {
        Some(p) => p.next.store(next, Relaxed),
        None => *head = next,
    }
    if let Some(n) = metas.get(next as usize) {
        n.prev.store(prev, Relaxed);
    }
    m.next.store(NO_PAGE, Relaxed);
    m.prev.store(NO_PAGE, Relaxed);
}

/// Claims a free slot in slab page `m`; returns its index.
fn claim_slot(m: &meta::PageMeta, class: usize) -> Option<u32> {
    let n = slots(class);
    for (w, word) in m.bitmap.iter().enumerate() {
        let base = w as u32 * 64;
        if base >= n {
            break;
        }
        let valid = if n - base >= 64 {
            u64::MAX
        } else {
            (1u64 << (n - base)) - 1
        };
        let free = !word.load(Relaxed) & valid;
        if free != 0 {
            let bit = free.trailing_zeros();
            word.fetch_or(1 << bit, Relaxed);
            return Some(base + bit);
        }
    }
    None
}

fn alloc_small(class: usize) -> Option<u64> {
    let mut head = PARTIAL[class].lock();
    let metas = meta::all();
    let (pfn, slot) = match metas.get(*head as usize) {
        Some(m) => {
            let pfn = *head;
            let slot = claim_slot(m, class)?;
            if used_count(m) == slots(class) {
                list_remove(&mut head, pfn);
            }
            (pfn, slot)
        }
        None => {
            let pa = page_alloc::alloc(0, kind::SLAB)?;
            let pfn = u32::try_from(pa.pfn()).ok()?;
            let m = metas.get(pfn as usize)?;
            m.class.store(class as u8, Relaxed);
            m.bitmap[0].store(1, Relaxed);
            m.bitmap[1].store(0, Relaxed);
            list_push(&mut head, pfn);
            (pfn, 0)
        }
    };
    Some(phys_to_virt(PhysAddr::new(u64::from(pfn) * PAGE_SIZE)) + u64::from(slot) * CLASSES[class])
}

#[allow(clippy::panic)] // Invalid frees are kernel bugs.
fn free_small(addr: u64, class: usize) {
    let pa = addr.wrapping_sub(LINEAR_BASE);
    let pfn = pa / PAGE_SIZE;
    let mut head = PARTIAL[class].lock();
    let Some(m) = meta::get(pfn) else {
        panic!("heap: free of {addr:#x}, not heap memory");
    };
    if m.kind.load(Relaxed) != kind::SLAB || usize::from(m.class.load(Relaxed)) != class {
        panic!("heap: free of {addr:#x} with wrong layout or not a heap object");
    }
    let offset = pa % PAGE_SIZE;
    if !offset.is_multiple_of(CLASSES[class]) {
        panic!("heap: free of {addr:#x}, not an object start");
    }
    let slot = (offset / CLASSES[class]) as usize;
    let word = &m.bitmap[slot / 64];
    let bit = 1u64 << (slot % 64);
    if word.load(Relaxed) & bit == 0 {
        panic!("heap: double free of {addr:#x}");
    }
    let was_full = used_count(m) == slots(class);
    word.fetch_and(!bit, Relaxed);
    let pfn = pfn as u32;
    if used_count(m) == 0 {
        if !was_full {
            list_remove(&mut head, pfn);
        }
        drop(head);
        page_alloc::free(PhysAddr::new(pa - offset), 0, kind::SLAB);
    } else if was_full {
        list_push(&mut head, pfn);
    }
}

fn alloc_inner(layout: Layout) -> Option<u64> {
    if meta::all().is_empty() {
        return None; // Heap not initialized yet.
    }
    match class_for(layout) {
        Some(class) => alloc_small(class),
        None => {
            let pa = page_alloc::alloc(large_order(layout)?, kind::ALLOCATED)?;
            Some(phys_to_virt(pa))
        }
    }
}

#[allow(clippy::panic)] // Invalid frees are kernel bugs.
fn dealloc_inner(addr: u64, layout: Layout) {
    match class_for(layout) {
        Some(class) => free_small(addr, class),
        None => {
            let Some(order) = large_order(layout) else {
                panic!("heap: free of {addr:#x} with impossible layout");
            };
            page_alloc::free(
                PhysAddr::new(addr.wrapping_sub(LINEAR_BASE)),
                order,
                kind::ALLOCATED,
            );
        }
    }
}

struct Heap;

// SAFETY: `alloc` returns either null or the linear-map address of memory
// that is exclusively owned by the allocation: a slab slot whose bit was
// claimed under the class lock, or a whole buddy block validated against the
// page metadata. Slots are aligned to their (power-of-two) class size and
// buddy blocks to their size, so `layout.align()` is honoured because the
// class or block size is at least `max(size, align)`. Nothing in that memory
// is ever read or written by the allocator. `dealloc` checks the metadata
// and panics on invalid input instead of corrupting state.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match alloc_inner(layout) {
            Some(addr) => core::ptr::with_exposed_provenance_mut(addr as usize),
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        dealloc_inner(ptr.expose_provenance() as u64, layout);
    }
}

#[cfg(target_os = "uefi")]
#[global_allocator]
static HEAP: Heap = Heap;
