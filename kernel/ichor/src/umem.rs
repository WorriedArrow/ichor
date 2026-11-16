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
//! File mappings are filled on first touch from the file they hold: a page
//! the page cache has (an unmodified lower-layer file) is mapped
//! copy-on-write, so processes mapping the same library share it;
//! anything else is read into a fresh page. A page dropped by
//! `MADV_DONTNEED` comes back with the file's contents, as on Linux. The
//! loader maps whole executable pages the same way; dropping one of its
//! pages zero-fills it (partial).
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

use crate::file::File;
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

/// A file mapping's source: the file, and the offset the mapping starts
/// at (page-aligned).
pub(crate) struct FileSource {
    pub(crate) file: Arc<dyn File>,
    pub(crate) offset: u64,
}

/// `[start, end)` of the address space shows `file` from `offset` (at
/// `base`) on.
#[derive(Clone)]
struct FileRange {
    start: u64,
    end: u64,
    base: u64,
    offset: u64,
    file: Arc<dyn File>,
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

    /// Maps `frame` (a page cache page) at `va`, copy-on-write: read-only
    /// until written. Charged as one page.
    pub(crate) fn map_cow(&mut self, va: u64, frame: UFrame, prot: Prot) -> bool {
        if self.pages.contains_key(&va) || self.account.charge(1).is_err() {
            return false;
        }
        self.pages.insert(va, frame.clone());
        self.cow.insert(va);
        let p = self.mapped_prot(va, prot);
        !prot.accessible() || self.space.map(va, &frame, p).is_ok()
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

    /// Bytes of address space mapped (`/proc` VmSize, vsize).
    pub(crate) fn virtual_size(&self) -> u64 {
        self.regions.regions().map(|r| r.end - r.start).sum()
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

    /// Reserves `[start, end)` (page-aligned) as a private mapping of
    /// `file` from `offset`: pages are filled on first touch (the page
    /// cache's copy, copy-on-write), as `mmap(MAP_PRIVATE)` of a file does.
    pub(crate) fn map_file_lazily(
        &mut self,
        start: u64,
        end: u64,
        prot: Prot,
        offset: u64,
        file: Arc<dyn File>,
    ) -> bool {
        if !self.regions.insert(start, end, prot) {
            return false;
        }
        self.files.push(FileRange {
            start,
            end,
            base: start,
            offset,
            file,
        });
        true
    }

    /// The page the process owns at `va`, allocating (and charging) one if
    /// there is none: zeroed, or filled from the file mapped there. Does not
    /// map it.
    pub(crate) fn frame(&mut self, va: u64) -> Option<UFrame> {
        if let Some(f) = self.pages.get(&va) {
            return Some(f.clone());
        }
        self.account.charge(1).ok()?;
        let file = self.files.iter().find(|r| r.start <= va && va < r.end);
        let at = file.map(|r| r.offset + (va - r.base));
        // A cache page needs no fresh frame (or zeroing one to throw away).
        if let (Some(r), Some(at)) = (file, at)
            && let Some(cached) = r.file.cached_page(at / PAGE_SIZE)
        {
            // Shared with the cache: read-only until written.
            self.pages.insert(va, cached.clone());
            self.cow.insert(va);
            return Some(cached);
        }
        let Some(f) = UFrame::alloc_zeroed() else {
            self.account.release(1);
            return None;
        };
        if let (Some(r), Some(at)) = (self.files.iter().find(|r| r.start <= va && va < r.end), at) {
            let mut page = alloc::vec![0u8; PAGE_SIZE as usize];
            let n = r.file.read_at(at, &mut page);
            f.writer().write(&page[..n]);
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
        if let Some((_, p)) = self.space.translate(va) {
            // Present: another thread (or a kernel copy for one) took this
            // fault first, between the access and this lock. Retry the
            // access if the mapping now allows it (the CPU drops the
            // faulting translation, so the retry sees the new PTE). Any
            // other present page is a protection violation the region map
            // does not explain: never loop on it.
            return (!write || p.write) && (!exec || p.exec);
        }
        let Some(f) = self.frame(va) else {
            return false;
        };
        if write && self.cow.contains(&va) {
            return self.break_cow(va, region.prot); // a cached file page
        }
        let prot = self.mapped_prot(va, region.prot);
        self.space.map(va, &f, prot).is_ok()
    }

    /// Copies `data` to user memory at `va` as user stores would: frame
    /// copies up to the first page not mapped writable, that page is
    /// faulted as a user write would fault it (demand paging, or breaking
    /// copy-on-write), and the copy goes on. Stops at the first page the
    /// process may not write. Returns the bytes copied.
    pub(crate) fn copy_to_user(&mut self, va: u64, data: &[u8]) -> usize {
        self.copy_user(va, data.len(), true, |space, at, done| {
            space.copy_to_user(at, &data[done..])
        })
    }

    /// Copies user memory at `va` into `out` as user loads would (unmapped
    /// pages are faulted in). Stops at the first page the process may not
    /// read. Returns the bytes copied.
    pub(crate) fn copy_from_user(&mut self, va: u64, out: &mut [u8]) -> usize {
        self.copy_user(va, out.len(), false, |space, at, done| {
            space.copy_from_user(at, &mut out[done..])
        })
    }

    /// The fault-and-retry loop behind both copies. `copy(space, at, done)`
    /// copies from byte `done` (user address `at`) on and returns how far
    /// it got. A page is faulted at most once in a row, so a fault that
    /// does not make it accessible can never loop.
    fn copy_user(
        &mut self,
        va: u64,
        len: usize,
        write: bool,
        mut copy: impl FnMut(&VmSpace, u64, usize) -> usize,
    ) -> usize {
        let mut done = 0usize;
        let mut faulted = None;
        loop {
            let Some(at) = va.checked_add(done as u64) else {
                return done;
            };
            done += copy(&self.space, at, done);
            if done >= len {
                return done;
            }
            let Some(at) = va.checked_add(done as u64) else {
                return done;
            };
            if faulted == Some(at) || !self.fault(at, write, false) {
                return done;
            }
            faulted = Some(at);
        }
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

    /// Frees every page in `[start, end)` (one TLB shootdown for all).
    fn free_range(&mut self, start: u64, end: u64) {
        let vas: Vec<u64> = self.pages.range(start..end).map(|(&v, _)| v).collect();
        if vas.is_empty() {
            return;
        }
        self.space.unmap_range(start, end);
        for va in vas {
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
        if !self.regions.insert(start, start + len, prot) {
            return Err(ENOMEM);
        }
        // A file mapping fills pages from the file as they are touched. A
        // shared mapping is only allowed read-only, so it cannot miss a
        // write to the file it would have made; it can miss later writes by
        // others (partial).
        match file {
            Some(f) => self.files.push(FileRange {
                start,
                end: start + len,
                base: start,
                offset: f.offset,
                file: f.file,
            }),
            None if map_flags & MAP_SHARED != 0 => self.shared.push((start, start + len)),
            None => {}
        }
        Ok(start)
    }

    /// Maps kernel pages shared with the kernel (an io_uring ring): placed
    /// as `mmap(MAP_SHARED | MAP_ANONYMOUS)` with `map_flags`' placement
    /// bits would place them, the pages being `frames` instead of fresh
    /// ones. They stay shared across `fork`. Charged as one page each while
    /// mapped.
    pub(crate) fn map_frames(
        &mut self,
        addr: u64,
        frames: &[UFrame],
        prot: u64,
        map_flags: u64,
    ) -> Result<u64, i64> {
        use flags::*;
        let len = frames.len() as u64 * PAGE_SIZE;
        let place = map_flags & (MAP_FIXED | MAP_FIXED_NOREPLACE);
        let start = self.mmap(addr, len, prot, MAP_SHARED | MAP_ANONYMOUS | place, None)?;
        let user = Prot::from_linux(prot).ok_or(EINVAL)?;
        for (i, f) in frames.iter().enumerate() {
            let va = start + i as u64 * PAGE_SIZE;
            let mapped = self.account.charge(1).is_ok() && {
                self.pages.insert(va, f.clone());
                !user.accessible() || self.space.map(va, f, user_prot(user)).is_ok()
            };
            if !mapped {
                let _ = self.munmap(start, len);
                return Err(ENOMEM);
            }
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

    /// `mremap(old, old_len, new_len, flags, new_addr)`: shrinks in place,
    /// grows in place when the pages after are free, or (with
    /// `MREMAP_MAYMOVE`) moves the mapping, pages and all, without copying.
    /// The old range must lie in one region. Partial: no `MREMAP_DONTUNMAP`,
    /// and `old_len` 0 (duplicating a shared mapping) is EINVAL.
    pub(crate) fn mremap(
        &mut self,
        old: u64,
        old_len: u64,
        new_len: u64,
        flags: u64,
        new_addr: u64,
    ) -> Result<u64, i64> {
        const MAYMOVE: u64 = 1;
        const FIXED: u64 = 2;
        const EFAULT: i64 = 14;
        if !old.is_multiple_of(PAGE_SIZE)
            || flags & !(MAYMOVE | FIXED) != 0
            || (flags & FIXED != 0 && flags & MAYMOVE == 0)
        {
            return Err(EINVAL);
        }
        let old_len = vma::page_len(old_len).filter(|&l| l > 0).ok_or(EINVAL)?;
        let new_len = vma::page_len(new_len).filter(|&l| l > 0).ok_or(EINVAL)?;
        let old_end = old.checked_add(old_len).ok_or(EINVAL)?;
        // The range may span adjacent regions (an earlier in-place grow adds
        // one), as long as they have one protection: Linux merges those.
        let region = self.regions.find(old).ok_or(EFAULT)?;
        let prot = region.prot;
        let mut at = region.end;
        while at < old_end {
            match self.regions.find(at) {
                Some(r) if r.prot == prot => at = r.end,
                _ => return Err(EFAULT),
            }
        }
        if flags & FIXED == 0 && new_len <= old_len {
            if new_len < old_len {
                self.munmap(old + new_len, old_len - new_len)?;
            }
            return Ok(old);
        }
        let new_end_here = old.checked_add(new_len).ok_or(ENOMEM)?;
        if flags & FIXED == 0
            && new_end_here <= USER_TOP
            && self.regions.is_free(old_end, new_end_here)
        {
            if !self.regions.insert(old_end, new_end_here, prot) {
                return Err(ENOMEM);
            }
            self.extend_ranges(old_end, new_end_here);
            return Ok(old);
        }
        if flags & MAYMOVE == 0 {
            return Err(ENOMEM);
        }
        let dst = if flags & FIXED != 0 {
            let end = new_addr.checked_add(new_len).ok_or(EINVAL)?;
            if !new_addr.is_multiple_of(PAGE_SIZE)
                || end > USER_TOP
                || (new_addr < old_end && old < end)
            {
                return Err(EINVAL);
            }
            self.munmap(new_addr, new_len)?;
            new_addr
        } else {
            self.regions.find_free(new_len).ok_or(ENOMEM)?
        };
        if !self.regions.insert(dst, dst + new_len, prot) {
            return Err(ENOMEM);
        }
        let moved = old_len.min(new_len);
        // Pages move with their frames and copy-on-write state.
        let vas: Vec<u64> = self
            .pages
            .range(old..old + moved)
            .map(|(&v, _)| v)
            .collect();
        for va in vas {
            let Some(f) = self.pages.remove(&va) else {
                continue;
            };
            let to = dst + (va - old);
            let cow = self.cow.remove(&va);
            let mapped = self.space.translate(va).map(|(_, p)| p);
            if cow {
                self.cow.insert(to);
            }
            if let Some(p) = mapped
                && self.space.map(to, &f, p).is_err()
            {
                return Err(ENOMEM);
            }
            self.pages.insert(to, f);
        }
        self.space.unmap_range(old, old + moved);
        // File and shared ranges follow; a grown tail continues them.
        let shift = |v: u64| v.wrapping_sub(old).wrapping_add(dst);
        let mut moved_files = Vec::new();
        for r in &self.files {
            if r.start < old_end && old < r.end {
                let end = if r.end >= old_end {
                    dst + new_len
                } else {
                    shift(r.end.min(old + moved))
                };
                moved_files.push(FileRange {
                    start: shift(r.start.max(old)),
                    end,
                    base: shift(r.base),
                    ..r.clone()
                });
            }
        }
        let mut moved_shared = Vec::new();
        for &(s, e) in &self.shared {
            if s < old_end && old < e {
                let end = if e >= old_end {
                    dst + new_len
                } else {
                    shift(e.min(old + moved))
                };
                moved_shared.push((shift(s.max(old)), end));
            }
        }
        // What is left of the old range (if shrinking) is freed here.
        self.munmap(old, old_len)?;
        self.files.extend(moved_files);
        self.shared.extend(moved_shared);
        Ok(dst)
    }

    /// File and shared ranges ending at `at` extend to `to` (`mremap`
    /// growing in place).
    fn extend_ranges(&mut self, at: u64, to: u64) {
        for r in &mut self.files {
            if r.end == at {
                r.end = to;
            }
        }
        for r in &mut self.shared {
            if r.1 == at {
                r.1 = to;
            }
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
