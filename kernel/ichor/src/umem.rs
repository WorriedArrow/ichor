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
//! (Making a large shared mapping resident at fork is eager.)
//!
//! Shared file mappings map the file's own pages, the ones `read` and
//! `write` copy from and to ([`crate::page`]), so everyone mapping,
//! reading or writing the file sees one copy. A file of the image nobody
//! has written yet is mapped from the page cache, read-only; the first
//! write through a mapping copies the file up. Partial: a mapping that has
//! touched such a page, or a page since truncated away, does not see what
//! others write to the file afterwards until it touches the page anew.
//!
//! `fork` is copy-on-write: parent and child map the same pages read-only
//! and mark them shared; the first write on either side (a fault, or a
//! kernel copy into user memory) gives that side its own copy. A page is
//! charged to the cell once, however many address spaces hold it (it is
//! a shared `Charged` handle), and the copy a write makes is charged when
//! it is made: so a forked child costs what it copies, as on Linux, and a
//! write that breaks a share can fail on a full account (the fault then
//! kills the writer, as Linux's OOM handling would).

use alloc::sync::Arc;
use alloc::vec::Vec;

use cell::Account;

use crate::file::File;
use crate::linuxabi::shm::Attached;
use crate::page::{Page, charged, charged_all};
use frame::mm::{PAGE_SIZE, UFrame, UserProt, VmSpace};
use vma::{PageMap, PageSet, Prot, Region, RegionMap};

const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EEXIST: i64 = 17;
const ENODEV: i64 = 19;

/// Where `mmap` places mappings that do not ask for an address.
pub(crate) const MMAP_LO: u64 = 0x1000_0000_0000;
pub(crate) const MMAP_HI: u64 = 0x7fff_0000_0000;
/// Pages handled per step when a range is walked (free, protect, move):
/// a list of every page of a big region would be an allocation larger than
/// the largest contiguous block (MAX_ORDER), and the kernel panics on that.
const PAGE_BATCH: usize = 4096;

/// Pages an anonymous fault that follows the last one maps ahead of itself
/// (`Mm::fault_around`): 64 KiB at a time with the faulting page.
pub(crate) const FAULT_AROUND: u64 = 15;
/// A 2 MiB page (`Mm::fault_huge`, ADR-0020).
const HUGE: u64 = frame::mm::HUGE_PAGE_SIZE;
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
    /// The descriptor it was mapped through allows writing.
    pub(crate) writable: bool,
}

/// A mapping of a file.
#[derive(Clone)]
struct FileMap {
    file: Arc<dyn File>,
    /// What to add to an address for its place in the file (wrapping).
    shift: u64,
    /// `MAP_SHARED`: the mapping shows the file's own pages.
    shared: bool,
    /// A shared mapping may be (made) writable.
    writable: bool,
}

impl FileMap {
    /// The offset in the file of address `va`.
    fn at(&self, va: u64) -> u64 {
        va.wrapping_add(self.shift)
    }
}

impl PartialEq for FileMap {
    fn eq(&self, other: &FileMap) -> bool {
        Arc::ptr_eq(&self.file, &other.file)
            && self.shift == other.shift
            && self.shared == other.shared
            && self.writable == other.writable
    }
}

/// What is behind a region.
#[derive(Clone, PartialEq)]
enum Backing {
    /// The process's own pages.
    Private,
    /// The same, named in `/proc/<pid>/maps`.
    Named(&'static str),
    /// Pages shared across `fork`: shared anonymous memory, System V
    /// segments, kernel pages.
    Shared,
    File(FileMap),
}

impl Backing {
    fn shared(&self) -> bool {
        match self {
            Backing::Shared => true,
            Backing::File(f) => f.shared,
            Backing::Private | Backing::Named(_) => false,
        }
    }

    /// Whether dropping its pages leaves zeros, and nothing else.
    fn anonymous(&self) -> bool {
        matches!(self, Backing::Private | Backing::Named(_))
    }

    /// The backing of the same memory moved from `old` to `new`.
    fn moved(self, old: u64, new: u64) -> Backing {
        match self {
            Backing::File(f) => Backing::File(FileMap {
                shift: f.shift.wrapping_add(old).wrapping_sub(new),
                ..f
            }),
            other => other,
        }
    }
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
/// `account` (the cell's) once each (`Charged`), and released when no
/// address space holds them any more. Drop it only while its space is not
/// active (switch to the kernel space first).
///
/// The space is shared so a copy can run without the `Mm` lock
/// ([`copy_user`], ADR-0011 as amended): such a copy holds its own
/// reference for its duration, so the space outlives an `execve` that
/// replaces this `Mm` mid-copy. That last reference is dropped by the
/// copying task, which is never bound to the space: `execve` and the last
/// thread out wait for every other thread of the process to leave first,
/// and helper threads (the only ones not waited for) run on the kernel
/// space (`proc::start_helper`).
pub(crate) struct Mm {
    space: Arc<VmSpace>,
    account: Arc<Account>,
    regions: RegionMap<Backing>,
    /// Every page the process holds, mapped or not (`PROT_NONE`).
    pages: PageMap<Page>,
    /// Pages possibly shared with another process after `fork`: mapped
    /// read-only, copied on the first write.
    cow: PageSet,
    /// System V segments attached: `[start, end)` each.
    attached: Vec<(u64, u64, Attached)>,
    brk_start: u64,
    brk: u64,
    /// The page after the last anonymous fault's (`fault_around`).
    next_anon: u64,
}

impl Mm {
    /// An empty address space charging `account`.
    pub(crate) fn new(account: &Arc<Account>) -> Option<Mm> {
        Some(Mm {
            space: Arc::new(VmSpace::new()?),
            account: account.clone(),
            regions: RegionMap::new(MMAP_LO, MMAP_HI),
            pages: PageMap::new(),
            cow: PageSet::new(),
            attached: Vec::new(),
            brk_start: 0,
            brk: 0,
            next_anon: 0,
        })
    }

    /// The address space.
    pub(crate) fn space(&self) -> &VmSpace {
        &self.space
    }

    /// A reference to the address space for a copy that runs without the
    /// `Mm` lock ([`copy_user`]).
    pub(crate) fn shared_space(&self) -> Arc<VmSpace> {
        self.space.clone()
    }

    /// Whether `space` is this `Mm`'s address space (not one an `execve`
    /// has since replaced).
    pub(crate) fn owns(&self, space: &Arc<VmSpace>) -> bool {
        Arc::ptr_eq(&self.space, space)
    }

    /// A copy-on-write copy of this address space for `fork`: same
    /// regions and break; every page is shared read-only and marked
    /// copy-on-write on both sides. `None` if memory or the account runs out.
    pub(crate) fn fork(&mut self) -> Option<Mm> {
        // Shared memory must exist before the copy, so both sides hold it.
        let mut from = 0;
        while let Some((s, e)) = self.next_shared(from, u64::MAX) {
            let mut va = s;
            while va < e {
                self.frame(va)?;
                va += PAGE_SIZE;
            }
            from = e;
        }
        let mut child = Mm::new(&self.account)?;
        child.regions = self.regions.clone();
        child.attached = self.attached.clone();
        child.brk_start = self.brk_start;
        child.brk = self.brk;
        // The child shares every page (no new charge): what either side
        // copies on write is charged then.
        let mut region: Option<Region<Backing>> = None;
        // This side's writable pages turn read-only a batch at a time, one
        // TLB flush each (all before `fork` returns).
        let mut protect: Vec<u64> = Vec::new();
        for (va, f) in self.pages.iter() {
            child.pages.insert(va, f.clone());
            if !region.as_ref().is_some_and(|r| r.start <= va && va < r.end) {
                region = self.regions.find(va);
            }
            if let Some(r) = region.as_ref().filter(|r| r.backing.shared()) {
                // An image page in a shared mapping stays read-only until
                // a write copies the file up.
                if self.cow.contains(&va) {
                    child.cow.insert(va);
                }
                if r.prot.accessible()
                    && child
                        .space
                        .map(va, f, self.mapped_prot(va, r.prot))
                        .is_err()
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
                    protect.push(va);
                    if protect.len() == PAGE_BATCH {
                        self.space.write_protect(&protect);
                        protect.clear();
                    }
                }
                if child.space.map(va, f, ro).is_err() {
                    self.space.write_protect(&protect);
                    return None; // `child` drops and releases its charge
                }
            }
        }
        self.space.write_protect(&protect);
        Some(child)
    }

    /// Whether `va` lies in a shared mapping.
    fn is_shared(&self, va: u64) -> bool {
        self.regions.find(va).is_some_and(|r| r.backing.shared())
    }

    /// The next stretch of shared anonymous memory in `[from, to)`.
    fn next_shared(&self, from: u64, to: u64) -> Option<(u64, u64)> {
        self.regions
            .overlapping(from, to)
            .find(|r| r.backing == Backing::Shared)
            .map(|r| (r.start.max(from), r.end.min(to)))
    }

    /// The file mapped at `va`.
    fn file_at(&self, va: u64) -> Option<FileMap> {
        match self.regions.find(va)?.backing {
            Backing::File(f) => Some(f),
            _ => None,
        }
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
        if self.pages.contains_key(&va) {
            return false;
        }
        let Some(page) = charged(&self.account, frame.clone()) else {
            return false;
        };
        self.pages.insert(va, page);
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
        // The copy is charged; the shared page's charge goes with its last
        // holder (this one, if the other side already copied or left).
        let Some(copy) = UFrame::alloc_zeroed().and_then(|f| charged(&self.account, f)) else {
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

    /// How many regions there are.
    pub(crate) fn mappings(&self) -> usize {
        self.regions.len()
    }

    /// `/proc/<pid>/maps`: one line per region from `from` on, some of them
    /// at a time, and where the next ones start (`None`: that was all).
    pub(crate) fn maps(&self, from: u64) -> (alloc::string::String, Option<u64>) {
        use core::fmt::Write;
        const SOME: usize = 16 << 10;
        let mut s = alloc::string::String::new();
        for r in self.regions.overlapping(from, u64::MAX) {
            if s.len() >= SOME {
                return (s, Some(r.start));
            }
            let share = if r.backing.shared() { 's' } else { 'p' };
            let (mut offset, mut dev, mut ino) = (0, 0, 0);
            let mut label = alloc::string::String::new();
            match &r.backing {
                Backing::File(f) => {
                    offset = f.at(r.start);
                    if let Some((n, path)) = f.file.identity() {
                        (dev, ino) = (1, n); // as `fstat` has it
                        label = path.unwrap_or_else(|| "(deleted)".into());
                    }
                }
                Backing::Named(name) => label.push_str(name),
                Backing::Private | Backing::Shared => {}
            }
            let line = s.len();
            let _ = write!(
                s,
                "{:08x}-{:08x} {}{}{}{share} {offset:08x} 00:{dev:02x} {ino} ",
                r.start,
                r.end,
                if r.prot.read { 'r' } else { '-' },
                if r.prot.write { 'w' } else { '-' },
                if r.prot.exec { 'x' } else { '-' },
            );
            if !label.is_empty() {
                // Names line up, as on Linux.
                let pad = 73usize.saturating_sub(s.len() - line);
                let _ = write!(s, "{:pad$}{label}", "");
            }
            s.push('\n');
        }
        (s, None)
    }

    /// A free, page-aligned range of `len` bytes in the mmap area.
    pub(crate) fn find_free(&self, len: u64) -> Option<u64> {
        self.regions.find_free(len)
    }

    /// Reserves `[start, end)` with `prot` without allocating pages.
    pub(crate) fn reserve(&mut self, start: u64, end: u64, prot: Prot) -> bool {
        self.regions.insert(start, end, prot, Backing::Private)
    }

    /// Reserves `[start, end)` as the first thread's stack.
    pub(crate) fn reserve_stack(&mut self, start: u64, end: u64) -> bool {
        let stack = Backing::Named("[stack]");
        self.regions.insert(start, end, Prot::RW, stack)
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
        let map = FileMap {
            file,
            shift: offset.wrapping_sub(start),
            shared: false,
            writable: false,
        };
        self.regions.insert(start, end, prot, Backing::File(map))
    }

    /// The page the process owns at `va`, allocating (and charging) one if
    /// there is none: zeroed, or filled from the file mapped there. Does not
    /// map it.
    pub(crate) fn frame(&mut self, va: u64) -> Option<UFrame> {
        if let Some(f) = self.pages.get(&va) {
            return Some((***f).clone());
        }
        let map = self.file_at(va);
        // A cache page needs no fresh frame (or zeroing one to throw away).
        if let Some(m) = &map
            && let Some(cached) = m.file.cached_page(m.at(va) / PAGE_SIZE)
        {
            // Shared with the cache: read-only until written.
            self.pages
                .insert(va, charged(&self.account, cached.clone())?);
            self.cow.insert(va);
            return Some(cached);
        }
        let page = charged(&self.account, UFrame::alloc_zeroed()?)?;
        if let Some(m) = &map {
            let mut buf = alloc::vec![0u8; PAGE_SIZE as usize];
            let n = m.file.read_at(m.at(va), &mut buf);
            page.writer().write(&buf[..n]);
        }
        let f = (**page).clone();
        self.pages.insert(va, page);
        Some(f)
    }

    /// A fault in a shared file mapping: maps the file's own page. A hole
    /// is given one; past the end of the file there is none (the fault
    /// fails; Linux sends SIGBUS).
    fn fault_shared(
        &mut self,
        map: &FileMap,
        va: u64,
        prot: Prot,
        write: bool,
        exec: bool,
    ) -> bool {
        if let Some((_, p)) = self.space.translate(va)
            && (!write || p.write)
            && (!exec || p.exec)
        {
            return true; // another thread took this fault first
        }
        match map.file.shared_page(map.at(va) / PAGE_SIZE, write) {
            Ok(Some(page)) => {
                // Takes the place of the image's page, if that was mapped.
                self.space.unmap(va);
                self.cow.remove(&va);
                let mapped = self.space.map(va, &page, user_prot(prot)).is_ok();
                self.pages.insert(va, page);
                mapped
            }
            // Nobody has written this file: the image's page will do, until
            // somebody writes it through here.
            Ok(None) if !write => {
                let Some(f) = self.frame(va) else {
                    return false;
                };
                self.cow.insert(va);
                let p = self.mapped_prot(va, prot);
                self.space.map(va, &f, p).is_ok()
            }
            _ => false,
        }
    }

    /// Drops the private pages of `[start, end)` (`MADV_DONTNEED`);
    /// shared memory keeps its contents.
    fn drop_private(&mut self, start: u64, end: u64) {
        let mut at = start;
        while let Some((s, e)) = self.next_shared(at, end) {
            self.free_range(at, s);
            at = e;
        }
        self.free_range(at, end);
    }

    /// Whether all of `[start, end)` is mapped (with whatever permissions).
    pub(crate) fn all_mapped(&self, start: u64, end: u64) -> bool {
        self.regions.covered(start, end)
    }

    /// Whether anything is mapped at `addr` (with whatever permissions).
    pub(crate) fn mapped(&self, addr: u64) -> bool {
        self.regions.find(addr).is_some()
    }

    /// Whether a file's contents are mapped at `addr`, shared.
    pub(crate) fn maps_file(&self, addr: u64) -> bool {
        self.regions
            .find(addr)
            .is_some_and(|r| matches!(&r.backing, Backing::File(f) if f.shared))
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
        if let Backing::File(map) = &region.backing
            && map.shared
        {
            return self.fault_shared(map, va, region.prot, write, exec);
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
        let anonymous = region.backing.anonymous();
        if anonymous && va == self.next_anon && self.fault_huge(va, &region) {
            return true;
        }
        let Some(f) = self.frame(va) else {
            return false;
        };
        if write && self.cow.contains(&va) {
            return self.break_cow(va, region.prot); // a cached file page
        }
        let prot = self.mapped_prot(va, region.prot);
        let ok = self.space.map(va, &f, prot).is_ok();
        if ok && anonymous {
            self.fault_around(va, &region);
        }
        ok
    }

    /// A sequential anonymous fault at `va` (one that follows the last one's
    /// pages) whose aligned 2 MiB block lies in `region` with no page in it
    /// yet: maps the block as one 2 MiB page, zeroed and charged (512
    /// pages), as Linux's transparent huge pages do (ADR-0020). Only a
    /// sequential touch takes one, so a sparse one is not charged 2 MiB a
    /// page. False, and nothing changed, if the block is not such, or memory
    /// or the account has no 2 MiB for it (4 KiB pages do then).
    fn fault_huge(&mut self, va: u64, region: &Region<Backing>) -> bool {
        let block = va & !(HUGE - 1);
        let Some(end) = block.checked_add(HUGE) else {
            return false;
        };
        let room = self.account.available() >= HUGE / PAGE_SIZE;
        if !room || block < region.start || end > region.end {
            return false;
        }
        if self.pages.range(block..end).next().is_some() {
            return false;
        }
        let Some(frames) = UFrame::alloc_zeroed_huge() else {
            return false;
        };
        let mapped = self.space.map_huge(block, &frames, user_prot(region.prot));
        let Some(pages) = mapped
            .ok()
            .and_then(|()| charged_all(&self.account, frames))
        else {
            self.space.unmap_range(block, end);
            return false;
        };
        for (va, page) in (block..end).step_by(PAGE_SIZE as usize).zip(pages) {
            self.pages.insert(va, page);
        }
        self.next_anon = end;
        true
    }

    /// After an anonymous fault at `va`: if it follows the last one's pages
    /// (a sequential touch), maps up to `FAULT_AROUND` more pages of the
    /// same region ahead of it now, zeroed and charged, as Linux's
    /// multi-size THP does for anonymous memory with 64 KiB folios. Each
    /// stops at a page already there, the region's end, the account's, or
    /// the next 2 MiB boundary (where the touch, if it goes on, may take a
    /// 2 MiB page: `fault_huge`).
    fn fault_around(&mut self, va: u64, region: &Region<Backing>) {
        let sequential = va == self.next_anon;
        self.next_anon = va + PAGE_SIZE;
        if !sequential {
            return;
        }
        let prot = user_prot(region.prot);
        let boundary = (va & !(HUGE - 1)).saturating_add(HUGE);
        let end = region
            .end
            .min(va + (FAULT_AROUND + 1) * PAGE_SIZE)
            .min(boundary);
        let mut at = va + PAGE_SIZE;
        while at < end {
            if self.pages.contains_key(&at) || self.space.translate(at).is_some() {
                break;
            }
            let Some(page) = UFrame::alloc_zeroed().and_then(|f| charged(&self.account, f)) else {
                break;
            };
            if self.space.map(at, &page, prot).is_err() {
                break;
            }
            self.pages.insert(at, page);
            at += PAGE_SIZE;
        }
        self.next_anon = at;
    }

    /// Copies `data` to user memory at `va` as user stores would (see
    /// [`copy_user`]), holding this `Mm` throughout: for spaces no other
    /// thread can reach (the loader's new image, a native process).
    /// Returns the bytes copied.
    pub(crate) fn copy_to_user(&mut self, va: u64, data: &[u8]) -> usize {
        let space = self.space.clone();
        copy_user(&space, va, UserBuf::To(data), |at, write| {
            self.fault(at, write, false).then_some(())
        })
    }

    /// Copies user memory at `va` into `out` as user loads would (see
    /// [`copy_user`]), holding this `Mm` throughout. Returns the bytes
    /// copied.
    pub(crate) fn copy_from_user(&mut self, va: u64, out: &mut [u8]) -> usize {
        let space = self.space.clone();
        copy_user(&space, va, UserBuf::From(out), |at, write| {
            self.fault(at, write, false).then_some(())
        })
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
        if self.pages.range(start..end).next().is_none() {
            return;
        }
        self.space.unmap_range(start, end);
        // Forget the pages a batch at a time: a list of every resident
        // page of a large process would itself be a large allocation.
        loop {
            let vas: Vec<u64> = self
                .pages
                .range(start..end)
                .map(|(v, _)| v)
                .take(PAGE_BATCH)
                .collect();
            if vas.is_empty() {
                return;
            }
            for va in vas {
                // The charge goes with the page's last holder.
                self.pages.remove(&va);
                self.cow.remove(&va);
            }
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
            // Private anonymous memory a whole number of 2 MiB long starts on
            // a 2 MiB boundary, so it can take 2 MiB pages, as on Linux.
            let huge = file.is_none() && map_flags & MAP_SHARED == 0 && len.is_multiple_of(HUGE);
            if hinted {
                addr
            } else if let Some(at) = huge
                .then(|| self.regions.find_free_aligned(len, HUGE))
                .flatten()
            {
                at
            } else {
                self.regions.find_free(len).ok_or(ENOMEM)?
            }
        };
        // A file mapping takes its pages from the file as they are touched.
        let shared = map_flags & MAP_SHARED != 0;
        let backing = match file {
            Some(f) => Backing::File(FileMap {
                file: f.file,
                shift: f.offset.wrapping_sub(start),
                shared,
                writable: f.writable,
            }),
            None if shared => Backing::Shared,
            None => Backing::Private,
        };
        if !self.regions.insert(start, start + len, prot, backing) {
            return Err(ENOMEM);
        }
        Ok(start)
    }

    /// Maps kernel pages shared with the kernel (an io_uring ring): placed
    /// as `mmap(MAP_SHARED | MAP_ANONYMOUS)` with `map_flags`' placement
    /// bits would place them, the pages being these (charged already)
    /// instead of fresh ones. They stay shared across `fork`.
    pub(crate) fn map_pages(
        &mut self,
        addr: u64,
        pages: &[Page],
        prot: u64,
        map_flags: u64,
    ) -> Result<u64, i64> {
        use flags::*;
        let len = pages.len() as u64 * PAGE_SIZE;
        let place = map_flags & (MAP_FIXED | MAP_FIXED_NOREPLACE);
        let start = self.mmap(addr, len, prot, MAP_SHARED | MAP_ANONYMOUS | place, None)?;
        let user = Prot::from_linux(prot).ok_or(EINVAL)?;
        for (i, page) in pages.iter().enumerate() {
            let va = start + i as u64 * PAGE_SIZE;
            self.pages.insert(va, page.clone());
            if user.accessible() && self.space.map(va, page, user_prot(user)).is_err() {
                let _ = self.munmap(start, len);
                return Err(ENOMEM);
            }
        }
        Ok(start)
    }

    /// `shmat`: maps a System V segment's `pages`, and holds `hold` until
    /// they are detached.
    pub(crate) fn attach(
        &mut self,
        addr: u64,
        pages: &[Page],
        prot: u64,
        place: u64,
        hold: Attached,
    ) -> Result<u64, i64> {
        if self.attached.len() >= vma::MAX_REGIONS {
            return Err(ENOMEM);
        }
        let at = self.map_pages(addr, pages, prot, place)?;
        let end = at + pages.len() as u64 * PAGE_SIZE;
        self.attached.push((at, end, hold));
        Ok(at)
    }

    /// `shmdt`: unmaps the segment attached at `addr`.
    pub(crate) fn detach(&mut self, addr: u64) -> Result<u64, i64> {
        let (start, end) = self
            .attached
            .iter()
            .find(|a| a.0 == addr)
            .map(|a| (a.0, a.1))
            .ok_or(EINVAL)?;
        self.munmap(start, end - start)
    }

    /// `munmap`.
    pub(crate) fn munmap(&mut self, addr: u64, len: u64) -> Result<u64, i64> {
        let len = vma::page_len(len).ok_or(EINVAL)?;
        if !addr.is_multiple_of(PAGE_SIZE) {
            return Err(EINVAL);
        }
        let end = addr.checked_add(len).ok_or(EINVAL)?;
        for (s, e) in self.regions.remove(addr, end).ok_or(ENOMEM)? {
            self.free_range(s, e);
        }
        self.attached.retain(|a| a.0 < addr || a.1 > end);
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
        let anonymous = |m: &Mm| {
            let mut regions = m.regions.overlapping(addr, end);
            regions.all(|r| r.backing.anonymous())
        };
        match advice {
            NORMAL..=WILLNEED | MERGEABLE..=DODUMP | KEEPONFORK..=PAGEOUT => {}
            DONTNEED => self.drop_private(addr, end),
            FREE if anonymous(self) => self.free_range(addr, end),
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
        let region = self.regions.find(old).ok_or(EFAULT)?;
        if region.end < old_end {
            return Err(EFAULT);
        }
        let prot = region.prot;
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
            // Joins the region it continues.
            if !self
                .regions
                .insert(old_end, new_end_here, prot, region.backing)
            {
                return Err(ENOMEM);
            }
            return Ok(old);
        }
        // The move adds a region, and may split those it takes from and
        // goes over.
        if flags & MAYMOVE == 0 || self.regions.len() + 3 > vma::MAX_REGIONS {
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
        let backing = region.backing.moved(old, dst);
        if !self.regions.insert(dst, dst + new_len, prot, backing) {
            return Err(ENOMEM);
        }
        let moved = old_len.min(new_len);
        // Pages move with their frames and copy-on-write state, a batch at
        // a time (the destination never overlaps the source).
        let mut from = old;
        loop {
            let vas: Vec<u64> = self
                .pages
                .range(from..old + moved)
                .map(|(v, _)| v)
                .take(PAGE_BATCH)
                .collect();
            let Some(&last) = vas.last() else {
                break;
            };
            from = last + PAGE_SIZE;
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
        }
        self.space.unmap_range(old, old + moved);
        // What is left of the old range (if shrinking) is freed here.
        self.munmap(old, old_len)?;
        Ok(dst)
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
        // A shared mapping of a file opened for reading stays that.
        let denied = |r: Region<Backing>| match r.backing {
            Backing::File(f) => f.shared && !f.writable,
            _ => false,
        };
        if prot.write && self.regions.overlapping(addr, end).any(denied) {
            return Err(EACCES);
        }
        if !self.regions.protect(addr, end, prot) {
            return Err(ENOMEM);
        }
        // A batch at a time: a list of every page of a large region would
        // itself be a large allocation.
        let mut from = addr;
        loop {
            let vas: Vec<u64> = self
                .pages
                .range(from..end)
                .map(|(v, _)| v)
                .take(PAGE_BATCH)
                .collect();
            let Some(&last) = vas.last() else {
                return Ok(0);
            };
            from = last + PAGE_SIZE;
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
        }
    }

    /// `msync`: what a shared mapping writes is in the file already, and
    /// nothing is behind the file to write it back to.
    pub(crate) fn msync(&self, addr: u64, len: u64, flags: u64) -> Result<u64, i64> {
        const ASYNC: u64 = 1;
        const INVALIDATE: u64 = 2;
        const SYNC: u64 = 4;
        if !addr.is_multiple_of(PAGE_SIZE)
            || flags & !(ASYNC | INVALIDATE | SYNC) != 0
            || flags & (ASYNC | SYNC) == (ASYNC | SYNC)
        {
            return Err(EINVAL);
        }
        let len = vma::page_len(len).unwrap_or(0);
        let end = addr.checked_add(len).ok_or(ENOMEM)?;
        if len == 0 || self.regions.covered(addr, end) {
            Ok(0)
        } else {
            Err(ENOMEM)
        }
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
            let heap = Backing::Named("[heap]");
            if !self.regions.insert(old_end, new_end, Prot::RW, heap) {
                return self.brk;
            }
        } else if new_end < old_end && self.munmap(new_end, old_end - new_end).is_err() {
            return self.brk;
        }
        self.brk = addr;
        addr
    }
}

/// The kernel side of a copy between kernel and user memory.
pub(crate) enum UserBuf<'a> {
    /// Bytes to store into user memory (`copy_to_user`).
    To(&'a [u8]),
    /// Where to load user memory into (`copy_from_user`).
    From(&'a mut [u8]),
}

impl UserBuf<'_> {
    fn len(&self) -> usize {
        match self {
            UserBuf::To(d) => d.len(),
            UserBuf::From(o) => o.len(),
        }
    }

    /// Whether the user side is written.
    fn write(&self) -> bool {
        matches!(self, UserBuf::To(_))
    }

    /// Frame's copy of bytes `from..to` at user address `at`, as far as
    /// the pages are mapped with the access needed.
    fn copy(&mut self, space: &VmSpace, at: u64, from: usize, to: usize) -> usize {
        match self {
            UserBuf::To(d) => space.copy_to_user(at, &d[from..to]),
            UserBuf::From(o) => space.copy_from_user(at, &mut o[from..to]),
        }
    }
}

/// Copies between `buf` and user memory at `va` in `space` with the
/// access a user load or store has. Frame copies as far as the pages are
/// mapped that way (ADR-0011); where it stops, `fault(at, write)` handles
/// the fault a user access would take there and, if the access is now
/// allowed, returns a guard (the `Mm` lock) held while that one page is
/// copied, so nothing can unmap or protect it between the fault and the
/// copy. Then the guard is dropped and the copy goes on without it.
///
/// So the `Mm` lock is held only for faults, never across a copy of
/// resident pages, and another thread's `mmap`, `munmap`, `mprotect` or
/// page fault waits for at most one fault and one page copy. A page that
/// is faulted and still cannot be copied ends the copy, so it never loops;
/// a page unmapped by another thread before the fault ends it too (the
/// fault fails). Returns the bytes copied.
pub(crate) fn copy_user<G>(
    space: &VmSpace,
    va: u64,
    mut buf: UserBuf<'_>,
    mut fault: impl FnMut(u64, bool) -> Option<G>,
) -> usize {
    let len = buf.len();
    let write = buf.write();
    let mut done = 0usize;
    loop {
        let Some(at) = va.checked_add(done as u64) else {
            return done;
        };
        done += buf.copy(space, at, done, len);
        if done >= len {
            return done;
        }
        let Some(at) = va.checked_add(done as u64) else {
            return done;
        };
        let Some(guard) = fault(at, write) else {
            return done;
        };
        let page_end = (PAGE_SIZE - (at & (PAGE_SIZE - 1))) as usize;
        let n = buf.copy(space, at, done, done.saturating_add(page_end).min(len));
        drop(guard);
        if n == 0 {
            return done;
        }
        done += n;
    }
}

/// One past the highest user address.
pub(crate) const USER_TOP: u64 = 0x0000_7fff_ffff_f000;

// Dropping an `Mm` drops `pages` (each page's charge goes with its last
// holder) and `space` (which clears the mappings).
