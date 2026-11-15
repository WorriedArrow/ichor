//! A Linux process's memory: the region map (`vma`), the pages the process
//! owns, and the program break. This is what `mmap`, `munmap`, `mprotect`
//! and `brk` operate on.
//!
//! Anonymous memory is demand-paged: a mapping only reserves a region, and
//! the first access faults into [`Mm::fault`], which allocates a zeroed
//! page (charged to the cell's account) and maps it. Syscalls that copy to
//! or from user memory call [`Mm::populate`] first, so they see the same
//! memory a user access would. A page made `PROT_NONE` is unmapped but kept,
//! so its contents survive a later `mprotect` back.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use frame::mm::{PAGE_SIZE, UFrame, UserProt};
use vma::{Prot, RegionMap};

use crate::kcell::Cell;

const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;
const EEXIST: i64 = 17;
const ENODEV: i64 = 19;

/// Where `mmap` places mappings that do not ask for an address.
pub(crate) const MMAP_LO: u64 = 0x1000_0000_0000;
pub(crate) const MMAP_HI: u64 = 0x7fff_0000_0000;
/// Largest program break, relative to its start.
const BRK_MAX: u64 = 1 << 30;

/// Linux `mmap` flags.
pub(crate) mod flags {
    pub(crate) const MAP_SHARED: u64 = 0x01;
    pub(crate) const MAP_PRIVATE: u64 = 0x02;
    pub(crate) const MAP_FIXED: u64 = 0x10;
    pub(crate) const MAP_ANONYMOUS: u64 = 0x20;
    pub(crate) const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
}

/// A file mapping's source: the file and the offset of the first page.
pub(crate) struct FileSource<'a> {
    pub(crate) node: &'a image::Node<'static>,
    pub(crate) offset: u64,
}

fn user_prot(p: Prot) -> UserProt {
    UserProt {
        write: p.write,
        exec: p.exec,
    }
}

fn page_down(v: u64) -> u64 {
    v & !(PAGE_SIZE - 1)
}

fn page_up(v: u64) -> Option<u64> {
    Some(v.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1))
}

/// A process's address-space bookkeeping.
pub(crate) struct Mm {
    regions: RegionMap,
    /// Every page the process owns, mapped or not (`PROT_NONE`).
    pages: BTreeMap<u64, UFrame>,
    brk_start: u64,
    brk: u64,
}

impl Mm {
    pub(crate) fn new() -> Mm {
        Mm {
            regions: RegionMap::new(MMAP_LO, MMAP_HI),
            pages: BTreeMap::new(),
            brk_start: 0,
            brk: 0,
        }
    }

    /// Sets where the program break starts (the page after the image).
    pub(crate) fn set_brk_start(&mut self, va: u64) {
        self.brk_start = va;
        self.brk = va;
    }

    /// Reserves `[start, end)` with `prot` without allocating pages.
    pub(crate) fn reserve(&mut self, start: u64, end: u64, prot: Prot) -> bool {
        self.regions.insert(start, end, prot)
    }

    /// The page the process owns at `va`, allocating (and charging) a zeroed
    /// one if there is none. Does not map it.
    pub(crate) fn frame(&mut self, cell: &Cell, va: u64) -> Option<UFrame> {
        if let Some(f) = self.pages.get(&va) {
            return Some(f.clone());
        }
        cell.account().charge(1).ok()?;
        let Some(f) = UFrame::alloc_zeroed() else {
            cell.account().release(1);
            return None;
        };
        self.pages.insert(va, f.clone());
        Some(f)
    }

    /// Handles a user page fault at `addr`. Returns false if the access is
    /// not allowed (the process should get `SIGSEGV`).
    pub(crate) fn fault(&mut self, cell: &Cell, addr: u64, write: bool, exec: bool) -> bool {
        let va = page_down(addr);
        let Some(region) = self.regions.find(va) else {
            return false;
        };
        if !region.prot.permits(write, exec) {
            return false;
        }
        if cell.space().translate(va).is_some() {
            // Present yet faulting: a protection violation the region map
            // does not explain. Never loop on it.
            return false;
        }
        let Some(f) = self.frame(cell, va) else {
            return false;
        };
        cell.space().map(va, &f, user_prot(region.prot)).is_ok()
    }

    /// Faults in `[va, va+len)` ahead of a kernel copy, stopping at the
    /// first page the process may not access that way.
    pub(crate) fn populate(&mut self, cell: &Cell, va: u64, len: usize, write: bool) {
        let Some(end) = va.checked_add(len as u64) else {
            return;
        };
        let mut page = page_down(va);
        while page < end {
            if cell.space().translate(page).is_none() && !self.fault(cell, page, write, false) {
                return;
            }
            page += PAGE_SIZE;
        }
    }

    /// Frees every page in `[start, end)`.
    fn free_range(&mut self, cell: &Cell, start: u64, end: u64) {
        let vas: Vec<u64> = self.pages.range(start..end).map(|(&v, _)| v).collect();
        for va in vas {
            cell.space().unmap(va);
            self.pages.remove(&va);
            cell.account().release(1);
        }
    }

    /// Frees everything (process exit).
    pub(crate) fn clear(&mut self, cell: &Cell) {
        self.free_range(cell, 0, u64::MAX);
        self.regions = RegionMap::new(MMAP_LO, MMAP_HI);
    }

    /// `mmap`. `file` is `None` for anonymous mappings.
    pub(crate) fn mmap(
        &mut self,
        cell: &Cell,
        addr: u64,
        len: u64,
        prot: u64,
        map_flags: u64,
        file: Option<FileSource<'_>>,
    ) -> Result<u64, i64> {
        use flags::*;
        let prot = Prot::from_linux(prot).ok_or(EINVAL)?;
        let len = vma::page_len(len).ok_or(EINVAL)?;
        if map_flags & (MAP_SHARED | MAP_PRIVATE) == 0 {
            return Err(EINVAL);
        }
        if (map_flags & MAP_ANONYMOUS != 0) != file.is_none() {
            return Err(ENODEV);
        }
        if let Some(f) = &file
            && !f.offset.is_multiple_of(PAGE_SIZE)
        {
            return Err(EINVAL);
        }
        let fixed = map_flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
        let start = if fixed {
            let end = addr.checked_add(len).ok_or(ENOMEM)?;
            if !addr.is_multiple_of(PAGE_SIZE) || addr == 0 || end > USER_TOP {
                return Err(EINVAL);
            }
            if !self.regions.is_free(addr, end) {
                if map_flags & MAP_FIXED_NOREPLACE != 0 {
                    return Err(EEXIST);
                }
                self.munmap(cell, addr, len)?;
            }
            addr
        } else {
            // A free, aligned hint is honored; anything else is placed.
            let hinted = addr != 0
                && addr.is_multiple_of(PAGE_SIZE)
                && addr.checked_add(len).is_some_and(|e| e <= USER_TOP)
                && self.regions.is_free(addr, addr + len);
            if hinted {
                addr
            } else {
                self.regions.find_free(len).ok_or(ENOMEM)?
            }
        };
        if !self.regions.insert(start, start + len, prot) {
            return Err(ENOMEM);
        }
        if let Some(f) = file {
            // Private file mappings are copied in now (the root is read-only,
            // so a shared mapping can never observe a write either).
            let mut buf = alloc::vec![0u8; PAGE_SIZE as usize];
            let mut va = start;
            while va < start + len {
                let off = f.offset + (va - start);
                let n = f.node.read_at(off, &mut buf);
                if n > 0 {
                    let Some(frame) = self.frame(cell, va) else {
                        self.munmap(cell, start, len)?;
                        return Err(ENOMEM);
                    };
                    frame.writer().write(&buf[..n]);
                    if prot.accessible() && cell.space().map(va, &frame, user_prot(prot)).is_err() {
                        self.munmap(cell, start, len)?;
                        return Err(ENOMEM);
                    }
                }
                va += PAGE_SIZE;
            }
        }
        Ok(start)
    }

    /// `munmap`.
    pub(crate) fn munmap(&mut self, cell: &Cell, addr: u64, len: u64) -> Result<u64, i64> {
        let len = vma::page_len(len).ok_or(EINVAL)?;
        if !addr.is_multiple_of(PAGE_SIZE) {
            return Err(EINVAL);
        }
        let end = addr.checked_add(len).ok_or(EINVAL)?;
        for (s, e) in self.regions.remove(addr, end) {
            self.free_range(cell, s, e);
        }
        Ok(0)
    }

    /// `mprotect`.
    pub(crate) fn mprotect(
        &mut self,
        cell: &Cell,
        addr: u64,
        len: u64,
        prot: u64,
    ) -> Result<u64, i64> {
        let prot = Prot::from_linux(prot).ok_or(EINVAL)?;
        if !addr.is_multiple_of(PAGE_SIZE) {
            return Err(EINVAL);
        }
        if len == 0 {
            return Ok(0);
        }
        let len = vma::page_len(len).ok_or(ENOMEM)?;
        let end = addr.checked_add(len).ok_or(ENOMEM)?;
        if !self.regions.protect(addr, end, prot) {
            return Err(ENOMEM);
        }
        let vas: Vec<u64> = self.pages.range(addr..end).map(|(&v, _)| v).collect();
        for va in vas {
            if cell.space().translate(va).is_none() {
                continue; // Faulted in with the new protection on next use.
            }
            if prot.accessible() {
                cell.space().protect(va, user_prot(prot));
            } else {
                cell.space().unmap(va); // `pages` keeps the frame.
            }
        }
        Ok(0)
    }

    /// `brk`: returns the new break, or the old one if `addr` is refused.
    pub(crate) fn brk(&mut self, cell: &Cell, addr: u64) -> u64 {
        if self.brk_start == 0 || addr < self.brk_start || addr > self.brk_start + BRK_MAX {
            return self.brk;
        }
        let (Some(old_end), Some(new_end)) = (page_up(self.brk), page_up(addr)) else {
            return self.brk;
        };
        if new_end > old_end {
            if !self.regions.insert(old_end, new_end, Prot::RW) {
                return self.brk;
            }
        } else if new_end < old_end {
            for (s, e) in self.regions.remove(new_end, old_end) {
                self.free_range(cell, s, e);
            }
        }
        self.brk = addr;
        addr
    }
}

/// One past the highest user address.
pub(crate) const USER_TOP: u64 = 0x0000_7fff_ffff_f000;
