//! A Linux process's memory: its own address space, the region map
//! (`vma`), the pages the process owns, and the program break. This is what `mmap`, `munmap`, `mprotect`
//! and `brk` operate on.
//!
//! Anonymous memory is demand-paged: a mapping only reserves a region, and
//! the first access faults into [`Mm::fault`], which allocates a zeroed
//! page (charged to the cell's account) and maps it. Syscalls that copy to
//! or from user memory call [`Mm::populate`] first, so they see the same
//! memory a user access would. A page made `PROT_NONE` is unmapped but kept,
//! so its contents survive a later `mprotect` back.
//!
//! Private file mappings are filled on first touch from the file's bytes,
//! which the mapping keeps (charged to the account) so that a page dropped
//! by `MADV_DONTNEED` comes back with the file's contents, as on Linux. The
//! loader's own segments are not file mappings: dropping one of their pages
//! zero-fills it (partial).
//!
//! Shared anonymous mappings (`MAP_SHARED | MAP_ANONYMOUS`) stay shared
//! across `fork`: before the copy, every page of them is made resident,
//! and parent and child then map the same frames writable, never
//! copy-on-write. Their contents survive `MADV_DONTNEED`, as shmem's do.
//! (Making a large shared mapping resident at fork is eager; a page cache
//! will let it stay lazy.)
//!
//! `fork` is copy-on-write: parent and child map the same pages read-only
//! and mark them shared; the first write on either side (a fault, or a
//! kernel copy into user memory) gives that side its own copy. The child
//! is charged for every page up front, so breaking a share never fails on
//! the account.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use cell::Account;
use frame::mm::{PAGE_SIZE, UFrame, UserProt, VmSpace};
use vma::{Prot, RegionMap};

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

/// A file mapping's source: the file's bytes from `offset` on (already
/// read, at most the mapping's length; the rest of the mapping is zero).
pub(crate) struct FileSource {
    pub(crate) bytes: Vec<u8>,
    pub(crate) offset: u64,
}

/// The bytes behind a file mapping, charged to `account` (by the page)
/// while any mapping still uses them.
struct Backing {
    bytes: Vec<u8>,
    account: Arc<Account>,
    pages: u64,
}

impl Drop for Backing {
    fn drop(&mut self) {
        self.account.release(self.pages);
    }
}

/// `[start, end)` of the address space shows `backing` from `base` on.
#[derive(Clone)]
struct FileRange {
    start: u64,
    end: u64,
    base: u64,
    backing: Arc<Backing>,
}

/// Linux `madvise` advice values.
mod advice {
    pub(super) const NORMAL: u64 = 0;
    pub(super) const WILLNEED: u64 = 3;
    pub(super) const DONTNEED: u64 = 4;
    pub(super) const FREE: u64 = 8;
    pub(super) const MERGEABLE: u64 = 12;
    pub(super) const DODUMP: u64 = 17;
    pub(super) const KEEPONFORK: u64 = 19;
    pub(super) const PAGEOUT: u64 = 21;
    pub(super) const POPULATE_READ: u64 = 22;
    pub(super) const POPULATE_WRITE: u64 = 23;
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

/// A process's address space and its bookkeeping. Pages are charged to
/// `account` (the cell's) and released when unmapped or when the `Mm` is
/// dropped. Drop it only while its space is not active (switch to the
/// kernel space first).
pub(crate) struct Mm {
    space: VmSpace,
    account: Arc<Account>,
    regions: RegionMap,
    /// Every page the process owns, mapped or not (`PROT_NONE`).
    pages: BTreeMap<u64, UFrame>,
    /// Pages possibly shared with another process after `fork`: mapped
    /// read-only, copied on the first write.
    cow: BTreeSet<u64>,
    /// File mappings, for filling their pages.
    files: Vec<FileRange>,
    /// Shared anonymous mappings: `[start, end)`.
    shared: Vec<(u64, u64)>,
    brk_start: u64,
    brk: u64,
}

impl Mm {
    /// An empty address space charging `account`.
    pub(crate) fn new(account: &Arc<Account>) -> Option<Mm> {
        Some(Mm {
            space: VmSpace::new()?,
            account: account.clone(),
            regions: RegionMap::new(MMAP_LO, MMAP_HI),
            pages: BTreeMap::new(),
            cow: BTreeSet::new(),
            files: Vec::new(),
            shared: Vec::new(),
            brk_start: 0,
            brk: 0,
        })
    }

    /// The address space.
    pub(crate) fn space(&self) -> &VmSpace {
        &self.space
    }

    /// A copy-on-write copy of this address space for `fork`: same
    /// regions and break; every page is shared read-only and marked
    /// copy-on-write on both sides. `None` if memory or the account runs out.
    pub(crate) fn fork(&mut self) -> Option<Mm> {
        // Shared memory must exist before the copy, so both sides hold it.
        for (s, e) in self.shared.clone() {
            let mut va = s;
            while va < e {
                self.frame(va)?;
                va += PAGE_SIZE;
            }
        }
        let mut child = Mm::new(&self.account)?;
        child.regions = self.regions.clone();
        child.files = self.files.clone();
        child.shared = self.shared.clone();
        child.brk_start = self.brk_start;
        child.brk = self.brk;
        self.account.charge(self.pages.len() as u64).ok()?;
        for (&va, f) in &self.pages {
            child.pages.insert(va, f.clone());
            if self.is_shared(va) {
                let prot = self.regions.find(va).map(|r| r.prot);
                if let Some(prot) = prot.filter(|p| p.accessible())
                    && child.space.map(va, f, user_prot(prot)).is_err()
                {
                    return None;
                }
                continue;
            }
            child.cow.insert(va);
            self.cow.insert(va);
            if let Some((_, prot)) = self.space.translate(va) {
                let ro = UserProt {
                    write: false,
                    exec: prot.exec,
                };
                if prot.write {
                    // This space is the active one (we are its task), so
                    // the local TLB flush `protect` does is enough.
                    self.space.protect(va, ro);
                }
                if child.space.map(va, f, ro).is_err() {
                    return None; // `child` drops and releases its charge
                }
            }
        }
        Some(child)
    }

    /// Whether `va` lies in a shared anonymous mapping.
    fn is_shared(&self, va: u64) -> bool {
        self.shared.iter().any(|&(s, e)| s <= va && va < e)
    }

    /// The physical address behind `addr` if it lies in shared memory (so a
    /// futex there is the same futex in every process that maps it), making
    /// the page resident first.
    pub(crate) fn shared_phys(&mut self, addr: u64) -> Option<u64> {
        let va = page_down(addr);
        if !self.is_shared(va) {
            return None;
        }
        self.populate(va, 4, false);
        self.space
            .translate(va)
            .map(|(pa, _)| pa.as_u64() + (addr - va))
    }

    /// Gives this process its own copy of a copy-on-write page at `va` and
    /// maps it with the region's protection.
    fn break_cow(&mut self, va: u64, prot: Prot) -> bool {
        let Some(shared) = self.pages.get(&va).cloned() else {
            return false;
        };
        let Some(copy) = UFrame::alloc_zeroed() else {
            return false;
        };
        let mut buf = alloc::vec![0u8; PAGE_SIZE as usize];
        shared.reader().read(&mut buf);
        copy.writer().write(&buf);
        self.space.unmap(va);
        if self.space.map(va, &copy, user_prot(prot)).is_err() {
            return false;
        }
        self.pages.insert(va, copy);
        self.cow.remove(&va);
        true
    }

    /// How `va` is mapped given its region protection: shared pages stay
    /// read-only until written.
    fn mapped_prot(&self, va: u64, prot: Prot) -> UserProt {
        let mut p = user_prot(prot);
        if self.cow.contains(&va) {
            p.write = false;
        }
        p
    }

    /// Sets where the program break starts (the page after the image).
    pub(crate) fn set_brk_start(&mut self, va: u64) {
        self.brk_start = va;
        self.brk = va;
    }

    /// Pages the process currently owns.
    pub(crate) fn resident_pages(&self) -> usize {
        self.pages.len()
    }

    /// `/proc/<pid>/maps`: one line per region.
    pub(crate) fn maps(&self) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        let brk_end = page_up(self.brk).unwrap_or(self.brk);
        for r in self.regions.regions() {
            let share = if self.is_shared(r.start) { 's' } else { 'p' };
            let label = if r.start >= self.brk_start && r.end <= brk_end && self.brk_start != 0 {
                "[heap]"
            } else if r.end == 0x7fff_f000_0000 {
                "[stack]"
            } else {
                ""
            };
            let _ = writeln!(
                s,
                "{:08x}-{:08x} {}{}{}{share} 00000000 00:00 0 {label}",
                r.start,
                r.end,
                if r.prot.read { 'r' } else { '-' },
                if r.prot.write { 'w' } else { '-' },
                if r.prot.exec { 'x' } else { '-' },
            );
        }
        s
    }

    /// A free, page-aligned range of `len` bytes in the mmap area.
    pub(crate) fn find_free(&self, len: u64) -> Option<u64> {
        self.regions.find_free(len)
    }

    /// Reserves `[start, end)` with `prot` without allocating pages.
    pub(crate) fn reserve(&mut self, start: u64, end: u64, prot: Prot) -> bool {
        self.regions.insert(start, end, prot)
    }

    /// The page the process owns at `va`, allocating (and charging) one if
    /// there is none: zeroed, or filled from the file mapped there. Does not
    /// map it.
    pub(crate) fn frame(&mut self, va: u64) -> Option<UFrame> {
        if let Some(f) = self.pages.get(&va) {
            return Some(f.clone());
        }
        self.account.charge(1).ok()?;
        let Some(f) = UFrame::alloc_zeroed() else {
            self.account.release(1);
            return None;
        };
        if let Some(r) = self.files.iter().find(|r| r.start <= va && va < r.end) {
            let at = (va - r.base) as usize;
            let bytes = &r.backing.bytes;
            if let Some(chunk) = bytes.get(at..bytes.len().min(at + PAGE_SIZE as usize)) {
                f.writer().write(chunk);
            }
        }
        self.pages.insert(va, f.clone());
        Some(f)
    }

    /// Forgets the shared anonymous ranges over `[start, end)`.
    fn trim_shared(&mut self, start: u64, end: u64) {
        let mut kept = Vec::with_capacity(self.shared.len());
        for &(s, e) in &self.shared {
            if e <= start || s >= end {
                kept.push((s, e));
                continue;
            }
            if s < start {
                kept.push((s, start));
            }
            if e > end {
                kept.push((end, e));
            }
        }
        self.shared = kept;
    }

    /// Drops the private pages of `[start, end)` (`MADV_DONTNEED`);
    /// shared memory keeps its contents.
    fn drop_private(&mut self, start: u64, end: u64) {
        let shared: Vec<(u64, u64)> = self
            .shared
            .iter()
            .filter(|&&(s, e)| s < end && start < e)
            .map(|&(s, e)| (s.max(start), e.min(end)))
            .collect();
        let mut at = start;
        for (s, e) in shared {
            self.free_range(at, s.max(at));
            at = at.max(e);
        }
        self.free_range(at, end);
    }

    /// Forgets the file mappings over `[start, end)`.
    fn trim_files(&mut self, start: u64, end: u64) {
        let mut kept = Vec::with_capacity(self.files.len());
        for r in self.files.drain(..) {
            if r.end <= start || r.start >= end {
                kept.push(r);
                continue;
            }
            if r.start < start {
                kept.push(FileRange {
                    end: start,
                    ..r.clone()
                });
            }
            if r.end > end {
                kept.push(FileRange { start: end, ..r });
            }
        }
        self.files = kept;
    }

    /// Handles a user page fault at `addr`. Returns false if the access is
    /// not allowed (the process should get `SIGSEGV`).
    pub(crate) fn fault(&mut self, addr: u64, write: bool, exec: bool) -> bool {
        let va = page_down(addr);
        let Some(region) = self.regions.find(va) else {
            return false;
        };
        if !region.prot.permits(write, exec) {
            return false;
        }
        if write && self.cow.contains(&va) {
            return self.break_cow(va, region.prot);
        }
        if self.space.translate(va).is_some() {
            // Present yet faulting: a protection violation the region map
            // does not explain. Never loop on it.
            return false;
        }
        let Some(f) = self.frame(va) else {
            return false;
        };
        let prot = self.mapped_prot(va, region.prot);
        self.space.map(va, &f, prot).is_ok()
    }

    /// Faults in `[va, va+len)` ahead of a kernel copy, stopping at the
    /// first page the process may not access that way.
    pub(crate) fn populate(&mut self, va: u64, len: usize, write: bool) {
        let Some(end) = va.checked_add(len as u64) else {
            return;
        };
        let mut page = page_down(va);
        while page < end {
            let needs = self.space.translate(page).is_none() || (write && self.cow.contains(&page));
            if needs && !self.fault(page, write, false) {
                return;
            }
            page += PAGE_SIZE;
        }
    }

    /// Frees every page in `[start, end)`.
    fn free_range(&mut self, start: u64, end: u64) {
        let vas: Vec<u64> = self.pages.range(start..end).map(|(&v, _)| v).collect();
        for va in vas {
            self.space.unmap(va);
            self.pages.remove(&va);
            self.cow.remove(&va);
            self.account.release(1);
        }
    }

    /// `mmap`. `file` is `None` for anonymous mappings.
    pub(crate) fn mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        map_flags: u64,
        file: Option<FileSource>,
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
                self.munmap(addr, len)?;
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
        // A file mapping keeps the file's bytes and fills pages as they are
        // touched. A shared mapping is only allowed read-only, so it cannot
        // miss a write to the file it would have made; it can miss later
        // writes by others (partial).
        let backing = match file {
            Some(f) => {
                let pages = page_up(f.bytes.len() as u64).ok_or(ENOMEM)? / PAGE_SIZE;
                self.account.charge(pages).map_err(|_| ENOMEM)?;
                Some(Arc::new(Backing {
                    bytes: f.bytes,
                    account: self.account.clone(),
                    pages,
                }))
            }
            None => None,
        };
        if !self.regions.insert(start, start + len, prot) {
            return Err(ENOMEM); // `backing` drops and returns its charge
        }
        if backing.is_none() && map_flags & MAP_SHARED != 0 {
            self.shared.push((start, start + len));
        }
        if let Some(backing) = backing {
            self.files.push(FileRange {
                start,
                end: start + len,
                base: start,
                backing,
            });
        }
        Ok(start)
    }

    /// `munmap`.
    pub(crate) fn munmap(&mut self, addr: u64, len: u64) -> Result<u64, i64> {
        let len = vma::page_len(len).ok_or(EINVAL)?;
        if !addr.is_multiple_of(PAGE_SIZE) {
            return Err(EINVAL);
        }
        let end = addr.checked_add(len).ok_or(EINVAL)?;
        for (s, e) in self.regions.remove(addr, end) {
            self.free_range(s, e);
        }
        self.trim_files(addr, end);
        self.trim_shared(addr, end);
        Ok(0)
    }

    /// `madvise`. `MADV_DONTNEED` and `MADV_FREE` drop the pages (the next
    /// touch sees zeros, or the file's contents for a file mapping);
    /// `MADV_POPULATE_*` faults them in; the pure hints are accepted and
    /// change nothing. Advice that would change semantics we do not have
    /// (`DONTFORK`, `WIPEONFORK`, `REMOVE`, `HWPOISON`, ...) is EINVAL.
    pub(crate) fn madvise(&mut self, addr: u64, len: u64, advice: u64) -> Result<u64, i64> {
        use advice::*;
        if !addr.is_multiple_of(PAGE_SIZE) {
            return Err(EINVAL);
        }
        let len = vma::page_len(len).ok_or(EINVAL)?;
        let end = addr.checked_add(len).ok_or(EINVAL)?;
        let file = self.files.iter().any(|r| r.start < end && addr < r.end)
            || self.shared.iter().any(|&(s, e)| s < end && addr < e);
        match advice {
            NORMAL..=WILLNEED | MERGEABLE..=DODUMP | KEEPONFORK..=PAGEOUT => {}
            DONTNEED => self.drop_private(addr, end),
            FREE if !file => self.free_range(addr, end),
            POPULATE_READ | POPULATE_WRITE => {
                self.populate(addr, len as usize, advice == POPULATE_WRITE)
            }
            _ => return Err(EINVAL),
        }
        if self.regions.covered(addr, end) {
            Ok(0)
        } else {
            Err(ENOMEM)
        }
    }

    /// `mprotect`.
    pub(crate) fn mprotect(&mut self, addr: u64, len: u64, prot: u64) -> Result<u64, i64> {
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
            if self.space.translate(va).is_none() {
                continue; // Faulted in with the new protection on next use.
            }
            if prot.accessible() {
                let mapped = self.mapped_prot(va, prot);
                self.space.protect(va, mapped);
            } else {
                self.space.unmap(va); // `pages` keeps the frame.
            }
        }
        Ok(0)
    }

    /// `brk`: returns the new break, or the old one if `addr` is refused.
    pub(crate) fn brk(&mut self, addr: u64) -> u64 {
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
                self.free_range(s, e);
            }
        }
        self.brk = addr;
        addr
    }
}

/// One past the highest user address.
pub(crate) const USER_TOP: u64 = 0x0000_7fff_ffff_f000;

impl Drop for Mm {
    fn drop(&mut self) {
        // The pages themselves are freed with `pages` and `space`.
        self.account.release(self.pages.len() as u64);
    }
}
