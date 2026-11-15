//! Region bookkeeping for a user address space: which page ranges are
//! reserved and with what protection. This is the policy half of `mmap`,
//! `munmap`, `mprotect` and `brk`; the kernel applies it to a `VmSpace`
//! and fills pages on demand from page faults.
//!
//! Regions are page-aligned, non-overlapping half-open ranges. Removing or
//! re-protecting part of a region splits it. Adjacent regions are not
//! merged (nothing depends on it, and it keeps the map simple).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Page size the map works in.
pub const PAGE: u64 = 4096;

/// Access a region allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Prot {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Prot {
    pub const NONE: Prot = Prot {
        read: false,
        write: false,
        exec: false,
    };
    pub const RW: Prot = Prot {
        read: true,
        write: true,
        exec: false,
    };

    /// From Linux `PROT_*` bits (`READ = 1, WRITE = 2, EXEC = 4`). Unknown
    /// bits are rejected.
    pub fn from_linux(bits: u64) -> Option<Prot> {
        if bits & !7 != 0 {
            return None;
        }
        Some(Prot {
            read: bits & 1 != 0,
            write: bits & 2 != 0,
            exec: bits & 4 != 0,
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

/// A reserved range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
}

/// Rounds `len` up to whole pages; `None` on overflow or zero.
pub fn page_len(len: u64) -> Option<u64> {
    if len == 0 {
        return None;
    }
    len.checked_add(PAGE - 1).map(|l| l & !(PAGE - 1))
}

/// The regions of one address space.
#[derive(Clone, Debug)]
pub struct RegionMap {
    /// start -> (end, prot)
    map: BTreeMap<u64, (u64, Prot)>,
    /// Window `[lo, hi)` used for placing mappings without an address.
    lo: u64,
    hi: u64,
}

impl RegionMap {
    /// An empty map that places unaddressed mappings top-down in `[lo, hi)`.
    pub fn new(lo: u64, hi: u64) -> RegionMap {
        RegionMap {
            map: BTreeMap::new(),
            lo,
            hi,
        }
    }

    /// All regions in address order.
    pub fn regions(&self) -> impl Iterator<Item = Region> + '_ {
        self.map
            .iter()
            .map(|(&start, &(end, prot))| Region { start, end, prot })
    }

    /// The region containing `va`.
    pub fn find(&self, va: u64) -> Option<Region> {
        let (&start, &(end, prot)) = self.map.range(..=va).next_back()?;
        (va < end).then_some(Region { start, end, prot })
    }

    /// Whether `[start, end)` overlaps no region.
    pub fn is_free(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        // The last region starting before `end` is the only candidate.
        match self.map.range(..end).next_back() {
            Some((_, &(e, _))) => e <= start,
            None => true,
        }
    }

    /// The highest free, page-aligned `len`-byte range inside the window.
    pub fn find_free(&self, len: u64) -> Option<u64> {
        let len = page_len(len)?;
        let floor = self.lo.checked_add(len)?;
        let mut top = self.hi;
        // Walk regions from the top of the window down, checking the gap
        // between each region's end and the current top.
        for (&start, &(end, _)) in self.map.range(..self.hi).rev() {
            if top < floor {
                return None;
            }
            if end <= top && top - end >= len {
                return Some(top - len);
            }
            top = top.min(start);
        }
        (top >= floor).then(|| top - len)
    }

    /// Reserves `[start, end)`, which must be page-aligned and free.
    pub fn insert(&mut self, start: u64, end: u64, prot: Prot) -> bool {
        if !aligned(start) || !aligned(end) || !self.is_free(start, end) {
            return false;
        }
        self.map.insert(start, (end, prot));
        true
    }

    fn overlapping(&self, start: u64, end: u64) -> Vec<(u64, u64, Prot)> {
        self.map
            .range(..end)
            .filter(|&(_, &(e, _))| e > start)
            .map(|(&s, &(e, p))| (s, e, p))
            .collect()
    }

    /// Removes `[start, end)` from every region it overlaps, splitting
    /// partial overlaps. Returns the ranges that were removed.
    pub fn remove(&mut self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut removed = Vec::new();
        if start >= end {
            return removed;
        }
        for (s, e, p) in self.overlapping(start, end) {
            self.map.remove(&s);
            if s < start {
                self.map.insert(s, (start, p));
            }
            if e > end {
                self.map.insert(end, (e, p));
            }
            removed.push((s.max(start), e.min(end)));
        }
        removed
    }

    /// Sets the protection of `[start, end)`, which must be entirely
    /// covered by regions (Linux returns `ENOMEM` otherwise). Splits
    /// regions at the boundaries.
    pub fn protect(&mut self, start: u64, end: u64, prot: Prot) -> bool {
        if start >= end || !self.covered(start, end) {
            return false;
        }
        for (s, e, p) in self.overlapping(start, end) {
            self.map.remove(&s);
            if s < start {
                self.map.insert(s, (start, p));
            }
            self.map.insert(s.max(start), (e.min(end), prot));
            if e > end {
                self.map.insert(end, (e, p));
            }
        }
        true
    }

    /// Whether every byte of `[start, end)` lies in some region.
    pub fn covered(&self, start: u64, end: u64) -> bool {
        let mut at = start;
        while at < end {
            match self.find(at) {
                Some(r) => at = r.end,
                None => return false,
            }
        }
        true
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
    };

    fn snapshot(m: &RegionMap) -> Vec<(u64, u64, Prot)> {
        m.regions().map(|r| (r.start, r.end, r.prot)).collect()
    }

    #[test]
    fn places_top_down_and_skips_used_ranges() {
        let mut m = RegionMap::new(LO, HI);
        let a = m.find_free(3 * PAGE).unwrap();
        assert_eq!(a, HI - 3 * PAGE);
        assert!(m.insert(a, a + 3 * PAGE, Prot::RW));
        let b = m.find_free(1).unwrap();
        assert_eq!(b, a - PAGE);
        assert!(m.insert(b, b + PAGE, Prot::RW));
        // Free a hole above `b` and fill it exactly.
        m.remove(a, a + PAGE);
        assert_eq!(m.find_free(PAGE), Some(a));
        // Too big for the hole: goes below `b`.
        assert_eq!(m.find_free(2 * PAGE), Some(b - 2 * PAGE));
    }

    #[test]
    fn window_exhaustion() {
        let mut m = RegionMap::new(LO, LO + 4 * PAGE);
        assert!(m.find_free(5 * PAGE).is_none());
        let a = m.find_free(4 * PAGE).unwrap();
        assert_eq!(a, LO);
        assert!(m.insert(a, a + 4 * PAGE, R));
        assert!(m.find_free(PAGE).is_none());
        assert!(m.find_free(0).is_none());
    }

    #[test]
    fn insert_rejects_overlap_and_misalignment() {
        let mut m = RegionMap::new(LO, HI);
        assert!(m.insert(LO, LO + 2 * PAGE, R));
        assert!(!m.insert(LO + PAGE, LO + 3 * PAGE, R));
        assert!(!m.insert(LO - PAGE, LO + PAGE, R));
        assert!(!m.insert(LO + 2 * PAGE + 1, LO + 4 * PAGE, R));
        assert!(m.insert(LO + 2 * PAGE, LO + 3 * PAGE, R));
        assert!(m.is_free(LO + 3 * PAGE, LO + 4 * PAGE));
        assert!(!m.is_free(LO, LO));
    }

    #[test]
    fn remove_splits() {
        let mut m = RegionMap::new(LO, HI);
        assert!(m.insert(LO, LO + 4 * PAGE, R));
        let removed = m.remove(LO + PAGE, LO + 2 * PAGE);
        assert_eq!(removed, [(LO + PAGE, LO + 2 * PAGE)]);
        assert_eq!(
            snapshot(&m),
            [(LO, LO + PAGE, R), (LO + 2 * PAGE, LO + 4 * PAGE, R)]
        );
        // A range spanning a hole and both pieces.
        let removed = m.remove(LO, LO + 3 * PAGE);
        assert_eq!(removed, [(LO, LO + PAGE), (LO + 2 * PAGE, LO + 3 * PAGE)]);
        assert_eq!(snapshot(&m), [(LO + 3 * PAGE, LO + 4 * PAGE, R)]);
        assert!(m.remove(HI, HI + PAGE).is_empty());
    }

    #[test]
    fn protect_splits_and_requires_coverage() {
        let mut m = RegionMap::new(LO, HI);
        assert!(m.insert(LO, LO + 4 * PAGE, Prot::NONE));
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
        // Across several regions.
        assert!(m.protect(LO, LO + 4 * PAGE, R));
        assert!(m.regions().all(|r| r.prot == R));
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
