//! Binary buddy allocator for physical pages.
//!
//! This is allocation *policy* only, written in safe code. It never touches
//! the memory it manages. Free-list links are kept in caller-provided storage
//! (in the kernel, frame's per-page metadata array) through the [`PageLinks`]
//! trait, identified by page frame number (PFN).
//!
//! Frame does not trust this crate for soundness (ADR-0001 §4.3). It checks
//! the page metadata of every block handed out, so a bug here causes a panic,
//! not aliasing.

#![no_std]
#![forbid(unsafe_code)]

/// Largest block is `2^MAX_ORDER` pages (4 MiB with 4 KiB pages). Nothing
/// in the kernel needs more contiguous memory: images are read on demand
/// through the page cache, executables and file mappings map cached pages,
/// and upper-layer files are paged. Kept at least 9, for 2 MiB pages.
pub const MAX_ORDER: u8 = 10;

/// Per-page storage the allocator threads its free lists through.
pub trait PageLinks {
    /// Next block on the same free list.
    fn next(&self, pfn: usize) -> Option<usize>;
    /// Previous block on the same free list.
    fn prev(&self, pfn: usize) -> Option<usize>;
    fn set_next(&mut self, pfn: usize, next: Option<usize>);
    fn set_prev(&mut self, pfn: usize, prev: Option<usize>);
    /// `Some(order)` exactly when `pfn` heads a free block of that order.
    fn free_order(&self, pfn: usize) -> Option<u8>;
    fn set_free_order(&mut self, pfn: usize, order: Option<u8>);
}

/// Why a free was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreeError {
    /// The block is already free.
    DoubleFree,
    /// `pfn` is not aligned to `2^order` pages.
    Misaligned,
    /// The block extends past the managed PFN limit.
    OutOfRange,
    /// `order > MAX_ORDER`.
    BadOrder,
}

/// Allocator state: one free list per order.
#[derive(Debug)]
pub struct Buddy {
    heads: [Option<usize>; MAX_ORDER as usize + 1],
    limit_pfn: usize,
    free_pages: usize,
    total_pages: usize,
}

impl Buddy {
    /// An allocator for PFNs below `limit_pfn`, initially empty.
    pub const fn new(limit_pfn: usize) -> Self {
        Self {
            heads: [None; MAX_ORDER as usize + 1],
            limit_pfn,
            free_pages: 0,
            total_pages: 0,
        }
    }

    /// Pages currently free.
    pub fn free_pages(&self) -> usize {
        self.free_pages
    }

    /// Pages ever added with [`Buddy::add_range`].
    pub fn total_pages(&self) -> usize {
        self.total_pages
    }

    /// Adds the pages `[start, end)` as free memory. Pages beyond the limit
    /// are ignored.
    pub fn add_range<L: PageLinks>(&mut self, links: &mut L, start: usize, end: usize) {
        let end = end.min(self.limit_pfn);
        let mut pfn = start;
        while pfn < end {
            let mut order = MAX_ORDER;
            while order > 0 && (!pfn.is_multiple_of(1 << order) || pfn + (1 << order) > end) {
                order -= 1;
            }
            self.total_pages += 1 << order;
            // A fresh range cannot already be on a list unless the caller
            // added it twice; skip rather than corrupt the lists.
            if self.free(links, pfn, order).is_err() {
                self.total_pages -= 1 << order;
            }
            pfn += 1 << order;
        }
    }

    /// Allocates a naturally aligned block of `2^order` pages; returns its
    /// first PFN.
    pub fn alloc<L: PageLinks>(&mut self, links: &mut L, order: u8) -> Option<usize> {
        if order > MAX_ORDER {
            return None;
        }
        let mut k = order;
        let pfn = loop {
            if let Some(pfn) = self.heads[k as usize] {
                break pfn;
            }
            if k == MAX_ORDER {
                return None;
            }
            k += 1;
        };
        self.remove(links, pfn, k);
        while k > order {
            k -= 1;
            self.push(links, pfn + (1 << k), k);
        }
        self.free_pages -= 1 << order;
        Some(pfn)
    }

    /// Returns a block to the allocator, merging with free buddies.
    pub fn free<L: PageLinks>(
        &mut self,
        links: &mut L,
        pfn: usize,
        order: u8,
    ) -> Result<(), FreeError> {
        if order > MAX_ORDER {
            return Err(FreeError::BadOrder);
        }
        if !pfn.is_multiple_of(1 << order) {
            return Err(FreeError::Misaligned);
        }
        if pfn
            .checked_add(1 << order)
            .is_none_or(|end| end > self.limit_pfn)
        {
            return Err(FreeError::OutOfRange);
        }
        if links.free_order(pfn).is_some() {
            return Err(FreeError::DoubleFree);
        }
        self.free_pages += 1 << order;
        let (mut pfn, mut order) = (pfn, order);
        while order < MAX_ORDER {
            let buddy = pfn ^ (1 << order);
            if buddy >= self.limit_pfn || links.free_order(buddy) != Some(order) {
                break;
            }
            self.remove(links, buddy, order);
            pfn = pfn.min(buddy);
            order += 1;
        }
        self.push(links, pfn, order);
        Ok(())
    }

    fn push<L: PageLinks>(&mut self, links: &mut L, pfn: usize, order: u8) {
        let head = self.heads[order as usize];
        links.set_next(pfn, head);
        links.set_prev(pfn, None);
        if let Some(h) = head {
            links.set_prev(h, Some(pfn));
        }
        links.set_free_order(pfn, Some(order));
        self.heads[order as usize] = Some(pfn);
    }

    fn remove<L: PageLinks>(&mut self, links: &mut L, pfn: usize, order: u8) {
        let (prev, next) = (links.prev(pfn), links.next(pfn));
        match prev {
            Some(p) => links.set_next(p, next),
            None => self.heads[order as usize] = next,
        }
        if let Some(n) = next {
            links.set_prev(n, prev);
        }
        links.set_next(pfn, None);
        links.set_prev(pfn, None);
        links.set_free_order(pfn, None);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    #[derive(Clone, Default)]
    struct Slot {
        next: Option<usize>,
        prev: Option<usize>,
        order: Option<u8>,
    }

    struct VecLinks(Vec<Slot>);

    impl PageLinks for VecLinks {
        fn next(&self, pfn: usize) -> Option<usize> {
            self.0[pfn].next
        }
        fn prev(&self, pfn: usize) -> Option<usize> {
            self.0[pfn].prev
        }
        fn set_next(&mut self, pfn: usize, v: Option<usize>) {
            self.0[pfn].next = v;
        }
        fn set_prev(&mut self, pfn: usize, v: Option<usize>) {
            self.0[pfn].prev = v;
        }
        fn free_order(&self, pfn: usize) -> Option<u8> {
            self.0[pfn].order
        }
        fn set_free_order(&mut self, pfn: usize, o: Option<u8>) {
            self.0[pfn].order = o;
        }
    }

    fn setup(pages: usize, ranges: &[(usize, usize)]) -> (Buddy, VecLinks) {
        let mut links = VecLinks(std::vec![Slot::default(); pages]);
        let mut b = Buddy::new(pages);
        for &(s, e) in ranges {
            b.add_range(&mut links, s, e);
        }
        (b, links)
    }

    #[test]
    fn add_range_builds_maximal_blocks() {
        let max = 1usize << MAX_ORDER;
        let (b, links) = setup(4 * max, &[(0, 2 * max)]);
        assert_eq!(b.free_pages(), 2 * max);
        assert_eq!(links.free_order(0), Some(MAX_ORDER));
        assert_eq!(links.free_order(max), Some(MAX_ORDER));
        let (b, _) = setup(64, &[(3, 17)]);
        assert_eq!(b.free_pages(), 14);
    }

    #[test]
    fn alloc_splits_and_free_merges() {
        let max = 1usize << MAX_ORDER;
        let (mut b, mut l) = setup(max, &[(0, max)]);
        let a = b.alloc(&mut l, 0).unwrap();
        assert_eq!(b.free_pages(), max - 1);
        let c = b.alloc(&mut l, 3).unwrap();
        assert_eq!(c % 8, 0);
        b.free(&mut l, a, 0).unwrap();
        b.free(&mut l, c, 3).unwrap();
        assert_eq!(b.free_pages(), max);
        assert_eq!(l.free_order(0), Some(MAX_ORDER), "everything merged back");
    }

    #[test]
    fn rejects_bad_frees() {
        let (mut b, mut l) = setup(64, &[(0, 64)]);
        let p = b.alloc(&mut l, 2).unwrap();
        assert_eq!(b.free(&mut l, p + 1, 2), Err(FreeError::Misaligned));
        assert_eq!(b.free(&mut l, 60, 3), Err(FreeError::Misaligned));
        assert_eq!(b.free(&mut l, 64, 0), Err(FreeError::OutOfRange));
        assert_eq!(b.free(&mut l, 0, MAX_ORDER + 1), Err(FreeError::BadOrder));
        b.free(&mut l, p, 2).unwrap();
        assert_eq!(b.free(&mut l, 0, 6), Err(FreeError::DoubleFree));
        assert_eq!(b.free_pages(), 64);
    }

    #[test]
    fn exhaustion_returns_none() {
        let (mut b, mut l) = setup(16, &[(0, 16)]);
        for _ in 0..16 {
            b.alloc(&mut l, 0).unwrap();
        }
        assert_eq!(b.alloc(&mut l, 0), None);
        assert_eq!(b.alloc(&mut l, MAX_ORDER + 1), None);
    }

    #[test]
    fn holes_never_merge() {
        // Pages 4..8 are a hole; 0..4 and 8..16 must not merge across it.
        let (mut b, mut l) = setup(16, &[(0, 4), (8, 16)]);
        assert_eq!(b.free_pages(), 12);
        assert_eq!(b.alloc(&mut l, 4), None);
        let p = b.alloc(&mut l, 3).unwrap();
        assert_eq!(p, 8);
    }

    /// Randomized alloc/free against a model: allocations never overlap, stay
    /// within added ranges, and freeing everything restores the free count.
    #[test]
    fn randomized_model_check() {
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rand = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..20 {
            let pages = 1 << (8 + round % 5);
            let ranges = [(1, pages / 3), (pages / 3 + 5, pages - 2)];
            let (mut b, mut l) = setup(pages, &ranges);
            let initial = b.free_pages();
            let mut live: BTreeMap<usize, u8> = BTreeMap::new();
            let mut owner = std::vec![false; pages];
            for _ in 0..4000 {
                if rand() % 3 != 0 || live.is_empty() {
                    let order = (rand() % 6) as u8;
                    if let Some(p) = b.alloc(&mut l, order) {
                        assert_eq!(p % (1 << order), 0);
                        for (q, o) in owner.iter_mut().enumerate().skip(p).take(1 << order) {
                            assert!(!*o, "page {q} handed out twice");
                            assert!(
                                ranges.iter().any(|&(s, e)| s <= q && q < e),
                                "page {q} not managed"
                            );
                            *o = true;
                        }
                        live.insert(p, order);
                    }
                } else {
                    let idx = (rand() as usize) % live.len();
                    let (&p, &order) = live.iter().nth(idx).unwrap();
                    live.remove(&p);
                    owner
                        .iter_mut()
                        .skip(p)
                        .take(1 << order)
                        .for_each(|o| *o = false);
                    b.free(&mut l, p, order).unwrap();
                }
                let used: usize = live.values().map(|&o| 1usize << o).sum();
                assert_eq!(b.free_pages() + used, initial);
            }
            for (p, o) in std::mem::take(&mut live) {
                b.free(&mut l, p, o).unwrap();
            }
            assert_eq!(b.free_pages(), initial);
        }
    }
}
