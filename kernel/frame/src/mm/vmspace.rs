//! User address spaces.
//!
//! A [`VmSpace`] owns the lower (user) half of a page table. Its upper half
//! shares the kernel's pre-allocated PML4 entries (ADR-0001 §4.3), so the
//! kernel stays mapped in every address space and a switch is just a CR3
//! load. Mappings take [`UFrame`]s only, so a typed (kernel-owned) page can
//! never reach user space by construction.

use alloc::vec::Vec;

use super::frame::{self, UFrame};
use super::meta::kind;
use super::page_alloc;
use super::{PhysAddr, align_down};
use crate::arch::paging::{self, MapError, UserProt};
use crate::arch::regs;
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

    /// Removes the mapping at `va`, if any.
    pub fn unmap(&self, va: u64) {
        let mut inner = self.inner.lock();
        // SAFETY: as in `map`; unmapping only clears a leaf of this space.
        let unmapped = unsafe { paging::user_unmap(self.root, va) };
        if let Some(pa) = unmapped {
            self.flush(va);
            frame::drop_untyped(pa);
            inner.frames.retain(|(v, _)| *v != va);
        }
    }

    /// Changes the permissions of the mapping at `va`.
    pub fn protect(&self, va: u64, prot: UserProt) -> bool {
        let _inner = self.inner.lock();
        // SAFETY: as in `map`.
        let ok = unsafe { paging::user_protect(self.root, va, prot) };
        if ok {
            self.flush(va);
        }
        ok
    }

    /// The page and permissions mapped at page-aligned `va`.
    pub fn translate(&self, va: u64) -> Option<(PhysAddr, UserProt)> {
        let _inner = self.inner.lock();
        // SAFETY: as in `map`; a read-only walk.
        unsafe { paging::user_translate(self.root, align_down(va, super::PAGE_SIZE)) }
    }

    fn flush(&self, va: u64) {
        // A full picture of which CPUs have this space active needs the TLB
        // shootdown IPI (added with multi-threaded processes). For now a
        // space is only modified while not running on another CPU, so a
        // local flush suffices.
        if regs::read_cr3() & 0x000f_ffff_ffff_f000 == self.root.as_u64() {
            paging::flush_page(va);
        }
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
