//! User address spaces.
//!
//! A [`VmSpace`] owns the lower (user) half of a page table. Its upper half
//! shares the kernel's pre-allocated PML4 entries (ADR-0001 §4.3), so the
//! kernel stays mapped in every address space and a switch is just a CR3
//! load. Mappings take [`UFrame`]s only, so a typed (kernel-owned) page can
//! never reach user space by construction.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::frame::{self, UFrame};
use super::meta::kind;
use super::page_alloc;
use super::{PhysAddr, align_down, phys_to_virt};
use crate::arch;
use crate::arch::paging::{self, MapError, UserProt};
use crate::sync::SpinLock;

/// A user address space.
#[derive(Debug)]
pub struct VmSpace {
    inner: SpinLock<Inner>,
    root: PhysAddr,
}

#[derive(Debug)]
struct Inner {
    /// Pages mapped into this space, kept alive until unmapped or teardown.
    frames: Vec<(u64, UFrame)>,
}

fn alloc_table_page() -> Option<PhysAddr> {
    let pa = page_alloc::alloc(0, kind::PAGE_TABLE)?;
    // SAFETY: a fresh page from the allocator, reachable via the linear map,
    // becoming a user page table.
    unsafe { paging::zero_page(pa) };
    Some(pa)
}

impl VmSpace {
    /// Creates an empty user address space sharing the kernel half.
    pub fn new() -> Option<VmSpace> {
        let root = alloc_table_page()?;
        // SAFETY: both are page-table pages reachable via the linear map;
        // `root` is fresh, the kernel root is live and only read.
        unsafe { paging::copy_upper_half(PhysAddr::new(crate::mm::kspace::kernel_root()), root) };
        Some(VmSpace {
            inner: SpinLock::new(Inner { frames: Vec::new() }),
            root,
        })
    }

    /// Maps `frame` at user address `va` with `prot`. Replacing an existing
    /// mapping is rejected.
    pub fn map(&self, va: u64, frame: &UFrame, prot: UserProt) -> Result<(), MapError> {
        let mut inner = self.inner.lock();
        let mut alloc = alloc_table_page;
        let pa = frame.incref_for_mapping();
        // SAFETY: `root` is this space's PML4; its lower half and every table
        // below it are this space's own pages (`alloc_table_page`), reachable
        // via the linear map. `pa` is the untyped page `frame` owns, whose
        // refcount we just bumped for this mapping.
        let r = unsafe { paging::user_map(self.root, va, pa, prot, &mut alloc) };
        match r {
            Ok(()) => {
                inner.frames.push((va, frame.clone()));
                Ok(())
            }
            Err(e) => {
                // Roll back the mapping refcount.
                frame::drop_untyped(pa);
                Err(e)
            }
        }
    }

    /// Removes the mapping at `va`, if any. The page is released only
    /// after every CPU running this space has forgotten the translation.
    /// Must not be called in atomic mode.
    pub fn unmap(&self, va: u64) {
        let (unmapped, frames) = {
            let mut inner = self.inner.lock();
            // SAFETY: as in `map`; unmapping only clears a leaf of this space.
            let unmapped = unsafe { paging::user_unmap(self.root, va) };
            let mut kept = Vec::new();
            if unmapped.is_some() {
                // Keep the `UFrame`s alive until the shootdown is done.
                let (gone, rest): (Vec<_>, Vec<_>) = core::mem::take(&mut inner.frames)
                    .into_iter()
                    .partition(|(v, _)| *v == va);
                inner.frames = rest;
                kept = gone;
            }
            (unmapped, kept)
        };
        if let Some(pa) = unmapped {
            super::tlb::shootdown(self.root.as_u64(), Some(va));
            frame::drop_untyped(pa);
        }
        drop(frames);
    }

    /// Changes the permissions of the mapping at `va`; on return no CPU
    /// running this space can still use the old permissions. Must not be
    /// called in atomic mode.
    pub fn protect(&self, va: u64, prot: UserProt) -> bool {
        let ok = {
            let _inner = self.inner.lock();
            // SAFETY: as in `map`.
            unsafe { paging::user_protect(self.root, va, prot) }
        };
        if ok {
            super::tlb::shootdown(self.root.as_u64(), Some(va));
        }
        ok
    }

    /// The aligned user `u32` at `va` as an atomic, under the space lock
    /// (so the page cannot be unmapped meanwhile), for futexes. `None` if
    /// `va` is unaligned, unmapped, or (with `write`) not writable.
    fn with_user_atomic<R>(
        &self,
        va: u64,
        write: bool,
        f: impl FnOnce(&AtomicU32) -> R,
    ) -> Option<R> {
        if !va.is_multiple_of(4) {
            return None;
        }
        let _inner = self.inner.lock();
        // SAFETY: as in `translate`; a read-only walk of this space.
        let (pa, prot) =
            unsafe { paging::user_translate(self.root, align_down(va, super::PAGE_SIZE)) }?;
        if write && !prot.write {
            return None;
        }
        let addr = phys_to_virt(pa) + (va & (super::PAGE_SIZE - 1));
        let ptr = core::ptr::with_exposed_provenance::<AtomicU32>(addr as usize);
        // SAFETY: `addr` is 4-byte aligned, inside a page mapped in this
        // space (it stays mapped while `_inner` is held, and the mapping
        // holds a page reference), and reachable through the linear map.
        // User code may access the word concurrently, which is why it is
        // only ever touched through atomic operations here.
        let a = unsafe { &*ptr };
        Some(f(a))
    }

    /// Atomically loads the user `u32` at `va` (4-byte aligned).
    pub fn load_u32_atomic(&self, va: u64) -> Option<u32> {
        self.with_user_atomic(va, false, |a| a.load(Ordering::SeqCst))
    }

    /// Atomically compares the user `u32` at `va` with `current` and, if
    /// equal, stores `new`. `Ok(previous)` on success, `Err(actual)` if it
    /// differed; `None` if `va` is not a writable, aligned, mapped word.
    pub fn compare_exchange_u32(
        &self,
        va: u64,
        current: u32,
        new: u32,
    ) -> Option<Result<u32, u32>> {
        self.with_user_atomic(va, true, |a| {
            a.compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst)
        })
    }

    /// The page and permissions mapped at page-aligned `va`.
    pub fn translate(&self, va: u64) -> Option<(PhysAddr, UserProt)> {
        let _inner = self.inner.lock();
        // SAFETY: as in `map`; a read-only walk.
        unsafe { paging::user_translate(self.root, align_down(va, super::PAGE_SIZE)) }
    }

    /// Copies up to `out.len()` bytes from user virtual address `va` into
    /// `out`, stopping at the first unmapped page. Returns the number copied.
    /// The bytes may change concurrently (another thread in this space), so
    /// this is a snapshot copy, never a borrow.
    pub fn copy_from_user(&self, va: u64, out: &mut [u8]) -> usize {
        self.walk_user(va, out.len(), |off, pa, poff, len| {
            let src = core::ptr::with_exposed_provenance::<u8>((phys_to_virt(pa) + poff) as usize);
            // SAFETY: `pa` is a page mapped in this space (from `translate`),
            // reachable via the linear map; `len` stays within it; `out` is a
            // Rust slice that cannot alias user memory.
            unsafe { arch::copy_untyped(out[off..].as_mut_ptr(), src, len) };
            true
        })
    }

    /// Copies `data` into user virtual address `va`, stopping at the first
    /// page that is not mapped writable. Returns the number copied.
    pub fn copy_to_user(&self, va: u64, data: &[u8]) -> usize {
        self.walk_user(va, data.len(), |off, pa, poff, len| {
            let dst =
                core::ptr::with_exposed_provenance_mut::<u8>((phys_to_virt(pa) + poff) as usize);
            // SAFETY: as in `copy_from_user`; the page is writable (checked in
            // `walk_user`).
            unsafe { arch::copy_untyped(dst, data[off..].as_ptr(), len) };
            true
        })
    }

    /// Walks the user range `[va, va+len)` page by page, calling `f(offset,
    /// page_phys, page_offset, chunk_len)` for each mapped page. For a write
    /// (`f` needs the page writable) the caller's closure is only reached for
    /// writable pages via `translate`'s prot. Stops at the first gap.
    fn walk_user(
        &self,
        va: u64,
        len: usize,
        mut f: impl FnMut(usize, PhysAddr, u64, usize) -> bool,
    ) -> usize {
        let mut done = 0usize;
        while done < len {
            let cur = va + done as u64;
            let page = align_down(cur, super::PAGE_SIZE);
            let Some((pa, _prot)) = self.translate(page) else {
                break;
            };
            let poff = cur - page;
            let chunk = ((super::PAGE_SIZE - poff) as usize).min(len - done);
            if !f(done, pa, poff, chunk) {
                break;
            }
            done += chunk;
        }
        done
    }

    /// Makes this address space active and binds it to the current task, so
    /// it is re-activated whenever the task is rescheduled (even on another
    /// CPU). The caller must keep the `VmSpace` alive for as long as the
    /// task runs in it, and call [`crate::mm::activate_kernel_space`] before
    /// dropping it.
    pub fn bind_to_current_task(&self) {
        crate::task::set_current_vm_root(self.root.as_u64());
    }
}

impl Drop for VmSpace {
    fn drop(&mut self) {
        let mut frames = core::mem::take(&mut self.inner.lock().frames);
        // Clear the page tables, dropping a mapping reference for every page
        // and freeing the intermediate tables. The `frames` vector holds the
        // matching `UFrame`s, dropped below.
        let mut leaf = |pa: PhysAddr| frame::drop_untyped(pa);
        let mut table_page = |pa: PhysAddr| page_alloc::free(pa, 0, kind::PAGE_TABLE);
        // SAFETY: a `VmSpace` is dropped only when no task uses it, so it is
        // active on no CPU; `root` and its lower-half tables are this space's
        // own pages.
        unsafe { paging::user_teardown(self.root, &mut leaf, &mut table_page) };
        frames.clear();
        page_alloc::free(self.root, 0, kind::PAGE_TABLE);
    }
}
