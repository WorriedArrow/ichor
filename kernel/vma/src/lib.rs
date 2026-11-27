//! Region bookkeeping for a user address space: which page ranges are
//! reserved, with what protection, and what is behind them. This is the
//! policy half of `mmap`, `munmap`, `mprotect` and `brk`; the kernel applies
//! it to a `VmSpace` and fills pages on demand from page faults.
//!
//! Regions are page-aligned, non-overlapping half-open ranges. Removing or
//! re-protecting part of a region splits it, and neighbors that are alike
//! (same protection, equal backing) are one region. A map holds at most
//! [`MAX_REGIONS`]: a process that splits a mapping into ever more pieces
//! is refused, where the kernel would run out of memory for the pieces.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod pagemap;
pub use pagemap::{PageMap, PageSet};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Page size the map works in.
pub const PAGE: u64 = 4096;

/// Most regions one address space has: Linux's default `vm.max_map_count`.
pub const MAX_REGIONS: usize = 65_530;

/// Access a region allows, and its protection key (`pkey_mprotect`; 0
/// unless one was given).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Prot {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub key: u8,
}

impl Prot {
    pub const NONE: Prot = Prot {
        read: false,
        write: false,
        exec: false,
        key: 0,
    };
    pub const RW: Prot = Prot {
        read: true,
        write: true,
        exec: false,
        key: 0,
    };

    /// From Linux `PROT_*` bits (`READ = 1, WRITE = 2, EXEC = 4`), with key
    /// 0. Unknown bits are rejected.
    pub fn from_linux(bits: u64) -> Option<Prot> {
        if bits & !7 != 0 {
            return None;
        }
        Some(Prot {
            read: bits & 1 != 0,
            write: bits & 2 != 0,
            exec: bits & 4 != 0,
            key: 0,
        })
    }

    /// Whether any access is allowed (x86 cannot map write- or exec-only
    /// pages without read, so any bit makes the page present).
    pub fn accessible(self) -> bool {
        self.read || self.write || self.exec
    }

    /// Whether this protection permits an access of the given kind.
    pub fn permits(self, write: bool, exec: bool) -> bool {
        self.accessible() && (!write || self.write) && (!exec || self.exec)
    }
}

/// A reserved range, and what is behind it. A backing says the same thing
/// wherever its region is split (a file mapping's: which file, and how far
/// its offsets are from the addresses).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region<B> {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
    pub backing: B,
}

/// Rounds `len` up to whole pages; `None` on overflow or zero.
pub fn page_len(len: u64) -> Option<u64> {
    if len == 0 {
        return None;
    }
    len.checked_add(PAGE - 1).map(|l| l & !(PAGE - 1))
}

/// What a region has besides where it starts.
#[derive(Clone, Debug)]
struct Body<B> {
    end: u64,
    prot: Prot,
    backing: B,
}

/// The regions of one address space.
#[derive(Clone, Debug)]
pub struct RegionMap<B> {
    /// By start address.
    map: BTreeMap<u64, Body<B>>,
    /// Window `[lo, hi)` used for placing mappings without an address.
    lo: u64,
    hi: u64,
}

impl<B: Clone + PartialEq> RegionMap<B> {
    /// An empty map that places unaddressed mappings top-down in `[lo, hi)`.
    pub fn new(lo: u64, hi: u64) -> RegionMap<B> {
        RegionMap {
            map: BTreeMap::new(),
            lo,
            hi,
        }
    }

    /// How many regions there are.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// All regions in address order.
    pub fn regions(&self) -> impl Iterator<Item = Region<B>> + '_ {
        self.map.iter().map(|(&s, b)| region(s, b))
    }

    /// The region containing `va`.
    pub fn find(&self, va: u64) -> Option<Region<B>> {
        let (&start, body) = self.map.range(..=va).next_back()?;
        (va < body.end).then(|| region(start, body))
    }

    /// The regions overlapping `[start, end)`, in address order.
    pub fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = Region<B>> + '_ {
        // Only the last region starting at or before `start` can reach into
        // the range from below.
        let first = match self.map.range(..=start).next_back() {
            Some((&s, b)) if b.end > start => s,
            _ => start,
        };
        self.map
            .range(first..end.max(first))
            .map(|(&s, b)| region(s, b))
    }

    /// Whether `[start, end)` overlaps no region.
    pub fn is_free(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        // The last region starting before `end` is the only candidate.
        match self.map.range(..end).next_back() {
            Some((_, b)) => b.end <= start,
            None => true,
        }
    }

    /// The highest free, page-aligned `len`-byte range inside the window.
    pub fn find_free(&self, len: u64) -> Option<u64> {
        self.find_free_aligned(len, PAGE)
    }

    /// The highest free `len`-byte range inside the window that starts on a
    /// multiple of `align` (a power of two, at least a page).
    pub fn find_free_aligned(&self, len: u64, align: u64) -> Option<u64> {
        let len = page_len(len)?;
        if !align.is_power_of_two() || align < PAGE {
            return None;
        }
        let floor = self.lo.checked_add(len)?;
        // The aligned start of a `len`-byte range ending at or below `top`,
        // if it lies at or above `bottom`.
        let fit = |bottom: u64, top: u64| {
            let at = (top - len) & !(align - 1);
            (at >= bottom).then_some(at)
        };
        let mut top = self.hi;
        // Walk regions from the top of the window down, checking the gap
        // between each region's end and the current top.
        for (&start, &Body { end, .. }) in self.map.range(..self.hi).rev() {
            if top < floor {
                return None;
            }
            if end <= top
                && let Some(at) = fit(end.max(self.lo), top)
            {
                return Some(at);
            }
            top = top.min(start);
        }
        if top < floor {
            return None;
        }
        fit(self.lo, top)
    }

    /// Reserves `[start, end)`, which must be page-aligned and free; false
    /// also if the map is full.
    pub fn insert(&mut self, start: u64, end: u64, prot: Prot, backing: B) -> bool {
        if !aligned(start) || !aligned(end) || !self.is_free(start, end) {
            return false;
        }
        if self.map.len() >= MAX_REGIONS && !self.joins(start, end, prot, &backing) {
            return false;
        }
        self.map.insert(start, Body { end, prot, backing });
        self.join(start);
        self.join(end);
        true
    }

    /// Removes `[start, end)` from every region it overlaps, splitting
    /// partial overlaps. Returns the ranges that were removed, or `None`
    /// (changing nothing) if a split would be one region too many.
    pub fn remove(&mut self, start: u64, end: u64) -> Option<Vec<(u64, u64)>> {
        let mut removed = Vec::new();
        if start >= end {
            return Some(removed);
        }
        if self.map.len() >= MAX_REGIONS
            && self
                .find(start)
                .is_some_and(|r| r.start < start && r.end > end)
        {
            return None;
        }
        let mut at = start;
        while let Some(r) = self.next_overlap(at, end) {
            self.cut(&r, start, end);
            removed.push((r.start.max(start), r.end.min(end)));
            at = r.end;
        }
        Some(removed)
    }

    /// Sets the protection of `[start, end)`, which must be entirely
    /// covered by regions (Linux returns `ENOMEM` otherwise). Splits
    /// regions at the boundaries; false (changing nothing) if that would be
    /// too many regions.
    pub fn protect(&mut self, start: u64, end: u64, prot: Prot) -> bool {
        self.protect_with(start, end, |_| prot)
    }

    /// [`Self::protect`] with each region's new protection made from its
    /// old one by `f` (`mprotect` keeps each region's key).
    pub fn protect_with(&mut self, start: u64, end: u64, f: impl Fn(Prot) -> Prot) -> bool {
        if start >= end || !self.covered(start, end) {
            return false;
        }
        let splits = |at: u64| {
            self.find(at)
                .is_some_and(|r| r.start < at && r.prot != f(r.prot))
        };
        let more = usize::from(splits(start)) + usize::from(splits(end));
        if self.map.len() + more > MAX_REGIONS {
            return false;
        }
        let mut at = start;
        while let Some(r) = self.next_overlap(at, end) {
            at = r.end;
            let from = r.start.max(start);
            let prot = f(r.prot);
            if r.prot != prot {
                self.cut(&r, start, end);
                self.map.insert(
                    from,
                    Body {
                        end: r.end.min(end),
                        prot,
                        backing: r.backing,
                    },
                );
            }
            self.join(from);
        }
        self.join(end);
        true
    }

    /// Whether every byte of `[start, end)` lies in some region.
    pub fn covered(&self, start: u64, end: u64) -> bool {
        let mut at = start;
        while at < end {
            match self.map.range(..=at).next_back() {
                Some((_, b)) if at < b.end => at = b.end,
                _ => return false,
            }
        }
        true
    }

    /// The first region overlapping `[at, end)`.
    fn next_overlap(&self, at: u64, end: u64) -> Option<Region<B>> {
        self.overlapping(at, end).next().filter(|_| at < end)
    }

    /// Takes `[start, end)` out of `r`, which the map has.
    fn cut(&mut self, r: &Region<B>, start: u64, end: u64) {
        self.map.remove(&r.start);
        let mut keep = |from: u64, to: u64| {
            let body = Body {
                end: to,
                prot: r.prot,
                backing: r.backing.clone(),
            };
            self.map.insert(from, body);
        };
        if r.start < start {
            keep(r.start, start);
        }
        if r.end > end {
            keep(end, r.end);
        }
    }

    /// Whether a region `[start, end)` would join one of its neighbors.
    fn joins(&self, start: u64, end: u64, prot: Prot, backing: &B) -> bool {
        let like = |b: &Body<B>| b.prot == prot && b.backing == *backing;
        let below = self.map.range(..start).next_back();
        below.is_some_and(|(_, b)| b.end == start && like(b))
            || self.map.get(&end).is_some_and(like)
    }

    /// Joins the region starting at `at`, if there is one, to the one that
    /// ends there if they are alike.
    fn join(&mut self, at: u64) {
        let Some(upper) = self.map.get(&at) else {
            return;
        };
        let end = upper.end;
        let Some((&start, lower)) = self.map.range(..at).next_back() else {
            return;
        };
        if lower.end != at || lower.prot != upper.prot || lower.backing != upper.backing {
            return;
        }
        self.map.remove(&at);
        if let Some(b) = self.map.get_mut(&start) {
            b.end = end;
        }
    }
}

fn region<B: Clone>(start: u64, b: &Body<B>) -> Region<B> {
    Region {
        start,
        end: b.end,
        prot: b.prot,
        backing: b.backing.clone(),
    }
}

fn aligned(v: u64) -> bool {
    v.is_multiple_of(PAGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LO: u64 = 0x1000_0000;
    const HI: u64 = 0x2000_0000;
    const R: Prot = Prot {
        read: true,
        write: false,
        exec: false,
        key: 0,
    };

    fn map() -> RegionMap<u8> {
        RegionMap::new(LO, HI)
    }

    #[test]
    fn protect_with_keeps_each_regions_key() {
        let mut m = map();
        assert!(m.insert(LO, LO + 4 * PAGE, Prot::RW, 0));
        // A key on the middle two pages splits the region.
        let keyed = |p: Prot| Prot { key: 3, ..p };
        assert!(m.protect_with(LO + PAGE, LO + 3 * PAGE, keyed));
        assert_eq!(m.len(), 3);
        // mprotect of all four to read-only keeps the keys apart.
        assert!(m.protect_with(LO, LO + 4 * PAGE, |p| Prot { key: p.key, ..R }));
        assert_eq!(
            snapshot(&m),
            [
                (LO, LO + PAGE, R),
                (LO + PAGE, LO + 3 * PAGE, Prot { key: 3, ..R }),
                (LO + 3 * PAGE, LO + 4 * PAGE, R),
            ]
        );
        // Back to key 0, the three join again.
        assert!(m.protect_with(LO, LO + 4 * PAGE, |p| Prot { key: 0, ..p }));
        assert_eq!(snapshot(&m), [(LO, LO + 4 * PAGE, R)]);
    }

    fn snapshot(m: &RegionMap<u8>) -> Vec<(u64, u64, Prot)> {
        m.regions().map(|r| (r.start, r.end, r.prot)).collect()
    }

    #[test]
    fn places_top_down_and_skips_used_ranges() {
        let mut m = map();
        let a = m.find_free(3 * PAGE).unwrap();
        assert_eq!(a, HI - 3 * PAGE);
        assert!(m.insert(a, a + 3 * PAGE, Prot::RW, 0));
        let b = m.find_free(1).unwrap();
        assert_eq!(b, a - PAGE);
        assert!(m.insert(b, b + PAGE, Prot::RW, 0));
        // Free a hole above `b` and fill it exactly.
        m.remove(a, a + PAGE).unwrap();
        assert_eq!(m.find_free(PAGE), Some(a));
        // Too big for the hole: goes below `b`.
        assert_eq!(m.find_free(2 * PAGE), Some(b - 2 * PAGE));
    }

    #[test]
    fn places_aligned_ranges_below_the_gaps_they_fit() {
        const BIG: u64 = 2 << 20;
        let mut m = map();
        // A page at the top leaves the gap below it unaligned.
        assert!(m.insert(HI - PAGE, HI, R, 0));
        let a = m.find_free_aligned(BIG, BIG).unwrap();
        assert_eq!(a, HI - 2 * BIG);
        assert!(a.is_multiple_of(BIG) && m.is_free(a, a + BIG));
        assert!(m.insert(a, a + BIG, R, 0));
        // A gap big enough but never aligned is passed over.
        assert!(m.insert(a - PAGE, a, R, 0));
        assert!(m.insert(LO, a - BIG - PAGE, R, 0));
        assert!(m.find_free_aligned(BIG, BIG).is_none());
        assert_eq!(m.find_free(BIG), Some(a - BIG - PAGE));
        assert!(m.find_free_aligned(PAGE, 3 * PAGE).is_none());
    }

    #[test]
    fn window_exhaustion() {
        let mut m: RegionMap<u8> = RegionMap::new(LO, LO + 4 * PAGE);
        assert!(m.find_free(5 * PAGE).is_none());
        let a = m.find_free(4 * PAGE).unwrap();
        assert_eq!(a, LO);
        assert!(m.insert(a, a + 4 * PAGE, R, 0));
        assert!(m.find_free(PAGE).is_none());
        assert!(m.find_free(0).is_none());
    }

    #[test]
    fn insert_rejects_overlap_and_misalignment() {
        let mut m = map();
        assert!(m.insert(LO, LO + 2 * PAGE, R, 0));
        assert!(!m.insert(LO + PAGE, LO + 3 * PAGE, R, 0));
        assert!(!m.insert(LO - PAGE, LO + PAGE, R, 0));
        assert!(!m.insert(LO + 2 * PAGE + 1, LO + 4 * PAGE, R, 0));
        assert!(m.insert(LO + 2 * PAGE, LO + 3 * PAGE, R, 0));
        assert!(m.is_free(LO + 3 * PAGE, LO + 4 * PAGE));
        assert!(!m.is_free(LO, LO));
    }

    #[test]
    fn remove_splits() {
        let mut m = map();
        assert!(m.insert(LO, LO + 4 * PAGE, R, 0));
        let removed = m.remove(LO + PAGE, LO + 2 * PAGE).unwrap();
        assert_eq!(removed, [(LO + PAGE, LO + 2 * PAGE)]);
        assert_eq!(
            snapshot(&m),
            [(LO, LO + PAGE, R), (LO + 2 * PAGE, LO + 4 * PAGE, R)]
        );
        // A range spanning a hole and both pieces.
        let removed = m.remove(LO, LO + 3 * PAGE).unwrap();
        assert_eq!(removed, [(LO, LO + PAGE), (LO + 2 * PAGE, LO + 3 * PAGE)]);
        assert_eq!(snapshot(&m), [(LO + 3 * PAGE, LO + 4 * PAGE, R)]);
        assert!(m.remove(HI, HI + PAGE).unwrap().is_empty());
        assert!(m.remove(LO + PAGE, LO + PAGE).unwrap().is_empty());
    }

    #[test]
    fn protect_splits_and_requires_coverage() {
        let mut m = map();
        assert!(m.insert(LO, LO + 4 * PAGE, Prot::NONE, 0));
        assert!(m.protect(LO + PAGE, LO + 3 * PAGE, Prot::RW));
        assert_eq!(
            snapshot(&m),
            [
                (LO, LO + PAGE, Prot::NONE),
                (LO + PAGE, LO + 3 * PAGE, Prot::RW),
                (LO + 3 * PAGE, LO + 4 * PAGE, Prot::NONE),
            ]
        );
        assert_eq!(m.find(LO + 2 * PAGE + 5).unwrap().prot, Prot::RW);
        // Not covered: no change.
        assert!(!m.protect(LO + 3 * PAGE, LO + 5 * PAGE, R));
        assert_eq!(m.find(LO + 3 * PAGE).unwrap().prot, Prot::NONE);
        // Across several regions, which are one again.
        assert!(m.protect(LO, LO + 4 * PAGE, R));
        assert_eq!(snapshot(&m), [(LO, LO + 4 * PAGE, R)]);
    }

    #[test]
    fn alike_neighbors_are_one_region() {
        let mut m = map();
        assert!(m.insert(LO, LO + PAGE, R, 1));
        assert!(m.insert(LO + 2 * PAGE, LO + 3 * PAGE, R, 1));
        // Fills the hole: joins both.
        assert!(m.insert(LO + PAGE, LO + 2 * PAGE, R, 1));
        assert_eq!(snapshot(&m), [(LO, LO + 3 * PAGE, R)]);
        // Another backing, or another protection, stays apart.
        assert!(m.insert(LO + 3 * PAGE, LO + 4 * PAGE, R, 2));
        assert!(m.insert(LO + 4 * PAGE, LO + 5 * PAGE, Prot::RW, 2));
        assert_eq!(m.regions().count(), 3);
        assert_eq!(m.find(LO + 3 * PAGE).unwrap().backing, 2);
        // Protecting the last one alike joins it to its like only.
        assert!(m.protect(LO + 4 * PAGE, LO + 5 * PAGE, R));
        assert_eq!(
            snapshot(&m),
            [(LO, LO + 3 * PAGE, R), (LO + 3 * PAGE, LO + 5 * PAGE, R)]
        );
        // The split and the join at once: a boundary that moves.
        assert!(m.protect(LO, LO + PAGE, Prot::RW));
        assert!(m.protect(LO + PAGE, LO + 2 * PAGE, Prot::RW));
        assert_eq!(m.find(LO).unwrap().end, LO + 2 * PAGE);
        assert_eq!(m.find(LO + 2 * PAGE).unwrap().end, LO + 3 * PAGE);
    }

    #[test]
    fn finds_what_overlaps_a_range() {
        let mut m = map();
        assert!(m.insert(LO, LO + 4 * PAGE, R, 0));
        assert!(m.insert(LO + 6 * PAGE, LO + 7 * PAGE, R, 0));
        let starts = |from, to| {
            m.overlapping(from, to)
                .map(|r| r.start)
                .collect::<Vec<u64>>()
        };
        assert_eq!(starts(LO + PAGE, LO + 2 * PAGE), [LO]);
        assert_eq!(starts(LO + 3 * PAGE, LO + 7 * PAGE), [LO, LO + 6 * PAGE]);
        assert!(starts(LO + 4 * PAGE, LO + 6 * PAGE).is_empty());
        assert!(starts(LO + 7 * PAGE, HI).is_empty());
        assert!(starts(LO + 8 * PAGE, LO).is_empty());
    }

    #[test]
    fn a_full_map_refuses_more_pieces() {
        let mut m = RegionMap::<u8>::new(0, HI * 8);
        let at = |i: usize| LO + i as u64 * PAGE;
        assert!(m.insert(LO, at(2 * MAX_REGIONS + 10), R, 0));
        // Every other page re-protected: two more pieces each time.
        let mut i = 1;
        while m.protect(at(i), at(i + 1), Prot::RW) {
            i += 2;
        }
        let n = m.regions().count();
        assert!(n <= MAX_REGIONS && n + 2 > MAX_REGIONS, "{n}");
        // At most one more fits, then none: nothing changes when refused.
        let _ = m.insert(HI * 2, HI * 2 + PAGE, R, 0);
        let before = m.regions().count();
        assert_eq!(before, MAX_REGIONS);
        assert!(!m.insert(HI * 4, HI * 4 + PAGE, R, 0));
        assert!(m.remove(at(i + 5), at(i + 6)).is_none());
        assert!(!m.protect(at(i + 5), at(i + 6), Prot::RW));
        assert_eq!(m.regions().count(), before);
        assert!(m.covered(LO, at(2 * MAX_REGIONS + 10)));
        // What adds no region is allowed: joining, shrinking, removing.
        assert!(m.insert(HI * 2 + PAGE, HI * 2 + 2 * PAGE, R, 0));
        assert!(m.protect(at(1), at(2), R));
        assert!(m.remove(LO, at(4)).is_some());
        assert!(m.insert(HI * 4, HI * 4 + PAGE, R, 0));
    }

    /// The map against a page-by-page model, over random operations.
    #[test]
    fn agrees_with_a_page_by_page_model() {
        const PAGES: usize = 40;
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let mut m = map();
        let mut model: [Option<(Prot, u8)>; PAGES] = [None; PAGES];
        let va = |p: usize| LO + p as u64 * PAGE;
        let prots = [Prot::NONE, R, Prot::RW];
        for _ in 0..20_000 {
            let a = next(PAGES);
            let b = a + 1 + next((PAGES - a).min(8));
            let (prot, tag) = (prots[next(3)], next(2) as u8);
            match next(3) {
                0 => {
                    let free = model[a..b].iter().all(Option::is_none);
                    assert_eq!(m.insert(va(a), va(b), prot, tag), free);
                    if free {
                        model[a..b].fill(Some((prot, tag)));
                    }
                }
                1 => {
                    let gone: u64 = m
                        .remove(va(a), va(b))
                        .unwrap()
                        .iter()
                        .map(|(s, e)| e - s)
                        .sum();
                    let had = model[a..b].iter().flatten().count();
                    assert_eq!(gone, had as u64 * PAGE);
                    model[a..b].fill(None);
                }
                _ => {
                    let all = model[a..b].iter().all(Option::is_some);
                    assert_eq!(m.protect(va(a), va(b), prot), all);
                    if all {
                        for p in model[a..b].iter_mut().flatten() {
                            p.0 = prot;
                        }
                    }
                }
            }
            let mut want = 0;
            for (p, page) in model.iter().enumerate() {
                let got = m.find(va(p)).map(|r| (r.prot, r.backing));
                assert_eq!(got, *page, "page {p}");
                if page.is_some() && (p == 0 || model[p - 1] != *page) {
                    want += 1;
                }
            }
            assert_eq!(m.regions().count(), want);
        }
    }

    #[test]
    fn prot_bits() {
        assert_eq!(Prot::from_linux(3), Some(Prot::RW));
        assert_eq!(Prot::from_linux(8), None);
        assert!(!Prot::NONE.accessible());
        assert!(Prot::RW.permits(true, false));
        assert!(!Prot::RW.permits(false, true));
        assert!(!R.permits(true, false));
        assert_eq!(page_len(1), Some(PAGE));
        assert_eq!(page_len(0), None);
        assert_eq!(page_len(u64::MAX), None);
    }
}
