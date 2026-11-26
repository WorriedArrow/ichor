//! A map from page address to one value per page, kept in chunks of
//! [`SPAN`] consecutive pages: a sequential insert is an array store, where
//! a tree of single pages took a node walk and splits for each (the kernel's
//! resident pages, about 160 ns a page). A chunk is [`SPAN`] slots, so a
//! sparse map pays at most that many per value.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::ops::Range;

use crate::PAGE;

/// Pages a chunk covers.
pub const SPAN: usize = 64;
const CHUNK: u64 = SPAN as u64 * PAGE;

struct Chunk<V> {
    slots: [Option<V>; SPAN],
    used: usize,
}

/// Values by page-aligned address.
pub struct PageMap<V> {
    chunks: BTreeMap<u64, Box<Chunk<V>>>,
    len: usize,
}

impl<V> Default for PageMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> core::fmt::Debug for PageMap<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageMap").field("len", &self.len).finish()
    }
}

/// The chunk base and slot of page address `va`.
fn split(va: u64) -> (u64, usize) {
    (va - va % CHUNK, (va % CHUNK / PAGE) as usize)
}

impl<V> PageMap<V> {
    pub const fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            len: 0,
        }
    }

    /// Values held.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn get(&self, va: &u64) -> Option<&V> {
        let (base, slot) = split(*va);
        self.chunks.get(&base)?.slots[slot].as_ref()
    }

    pub fn contains_key(&self, va: &u64) -> bool {
        self.get(va).is_some()
    }

    /// Puts `v` at `va`, returning what was there.
    pub fn insert(&mut self, va: u64, v: V) -> Option<V> {
        let (base, slot) = split(va);
        let c = self.chunks.entry(base).or_insert_with(|| {
            Box::new(Chunk {
                slots: [const { None }; SPAN],
                used: 0,
            })
        });
        let old = c.slots[slot].replace(v);
        if old.is_none() {
            c.used += 1;
            self.len += 1;
        }
        old
    }

    pub fn remove(&mut self, va: &u64) -> Option<V> {
        let (base, slot) = split(*va);
        let c = self.chunks.get_mut(&base)?;
        let old = c.slots[slot].take()?;
        c.used -= 1;
        self.len -= 1;
        if c.used == 0 {
            self.chunks.remove(&base);
        }
        Some(old)
    }

    /// The values in `range`, by address.
    pub fn range(&self, range: Range<u64>) -> impl Iterator<Item = (u64, &V)> + '_ {
        let Range { start, end } = range;
        let first = split(start).0;
        self.chunks
            .range(first..end.max(first))
            .flat_map(|(&base, c)| {
                c.slots
                    .iter()
                    .enumerate()
                    .filter_map(move |(i, v)| Some((base + i as u64 * PAGE, v.as_ref()?)))
            })
            .filter(move |&(va, _)| start <= va && va < end)
    }

    /// Every value, by address.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &V)> + '_ {
        self.range(0..u64::MAX)
    }
}

/// A set of page addresses, as a [`PageMap`] of nothing.
#[derive(Debug, Default)]
pub struct PageSet(PageMap<()>);

impl PageSet {
    pub const fn new() -> Self {
        Self(PageMap::new())
    }

    pub fn contains(&self, va: &u64) -> bool {
        self.0.contains_key(va)
    }

    /// Whether `va` was not there yet.
    pub fn insert(&mut self, va: u64) -> bool {
        self.0.insert(va, ()).is_none()
    }

    /// Whether `va` was there.
    pub fn remove(&mut self, va: &u64) -> bool {
        self.0.remove(va).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn behaves_as_a_map_of_pages() {
        let mut m = PageMap::new();
        let mut model = BTreeMap::new();
        // Sequential, sparse and chunk-straddling addresses, with overwrites
        // and removals.
        let mut x = 12345u64;
        for step in 0..5000u64 {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let va = match step % 3 {
                0 => step * PAGE,
                1 => (x >> 20) % 4096 * PAGE,
                _ => (x >> 30) % 64 * CHUNK + PAGE * 63,
            };
            if x.is_multiple_of(4) {
                assert_eq!(m.remove(&va), model.remove(&va));
            } else {
                assert_eq!(m.insert(va, step), model.insert(va, step));
            }
            assert_eq!(m.len(), model.len());
        }
        for va in (0..8192).map(|p| p * PAGE) {
            assert_eq!(m.get(&va), model.get(&va));
            assert_eq!(m.contains_key(&va), model.contains_key(&va));
        }
        let all: Vec<_> = m.iter().map(|(k, &v)| (k, v)).collect();
        let want: Vec<_> = model.iter().map(|(&k, &v)| (k, v)).collect();
        assert_eq!(all, want);
        for (s, e) in [
            (0, PAGE),
            (PAGE * 5, PAGE * 200),
            (CHUNK - PAGE, CHUNK + PAGE),
            (7, 5),
        ] {
            let got: Vec<_> = m.range(s..e).map(|(k, _)| k).collect();
            let want: Vec<_> = model.range(s..e.max(s)).map(|(&k, _)| k).collect();
            assert_eq!(got, want, "{s:#x}..{e:#x}");
        }
        // Emptied chunks go.
        let keys: Vec<u64> = model.keys().copied().collect();
        for k in keys {
            m.remove(&k);
        }
        assert!(m.is_empty() && m.chunks.is_empty());
        let mut s = PageSet::new();
        assert!(s.insert(PAGE) && !s.insert(PAGE) && s.contains(&PAGE));
        assert!(s.remove(&PAGE) && !s.remove(&PAGE) && !s.contains(&PAGE));
    }
}
