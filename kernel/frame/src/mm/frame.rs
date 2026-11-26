//! Typed and untyped physical frames.
//!
//! Physical pages the kernel hands out are *untyped*: their bytes may change
//! under the kernel at any time, because user threads (and later devices)
//! can write them through their own mappings. So the kernel never forms a
//! Rust `&`/`&mut` into an untyped page. The only access is by copying, with
//! [`VmReader`] and [`VmWriter`], which use `rep movsb` outside the Rust
//! memory model (ADR-0001 §4.3).
//!
//! A [`UFrame`] is a reference-counted handle to one untyped page. Cloning it
//! bumps the page's metadata refcount; dropping the last handle (and last
//! mapping) frees the page. A `VmSpace` mapping also holds a count, so a page
//! stays allocated as long as any cell maps it.

use alloc::vec::Vec;
use core::sync::atomic::Ordering::{AcqRel, Release};

use super::meta::{self, kind};
use super::page_alloc;
use super::{PAGE_SIZE, PhysAddr, phys_to_virt};
use crate::arch;

/// A reference-counted handle to one untyped physical page.
#[derive(Debug)]
pub struct UFrame {
    pa: PhysAddr,
}

impl UFrame {
    /// Allocates a zeroed untyped page.
    pub fn alloc_zeroed() -> Option<UFrame> {
        let pa = page_alloc::alloc(0, kind::UNTYPED)?;
        let m = meta::get(pa.pfn())?;
        m.refcount.store(1, Release);
        let f = UFrame { pa };
        f.writer().fill(0);
        Some(f)
    }

    /// Allocates 512 zeroed untyped pages that make one aligned 2 MiB block,
    /// in address order, for [`super::VmSpace::map_huge`]. Each is a page of
    /// its own, freed when its last handle and mapping go. `None` if memory
    /// has no such block free.
    pub fn alloc_zeroed_huge() -> Option<Vec<UFrame>> {
        const PAGES: usize = 512;
        let mut frames = Vec::new();
        frames.try_reserve_exact(PAGES).ok()?;
        let pa = page_alloc::alloc_pages(9, kind::UNTYPED)?;
        for i in 0..PAGES as u64 {
            let page = PhysAddr::new(pa.as_u64() + i * PAGE_SIZE);
            if let Some(m) = meta::get(page.pfn()) {
                m.refcount.store(1, Release);
            }
            frames.push(UFrame { pa: page });
        }
        let dst = core::ptr::with_exposed_provenance_mut::<u8>(phys_to_virt(pa) as usize);
        // SAFETY: the linear-map alias of the 2 MiB block just allocated, which
        // nothing else holds yet and no Rust reference points into.
        unsafe { arch::fill_untyped(dst, 0, PAGES * PAGE_SIZE as usize) };
        Some(frames)
    }

    /// The page's physical address.
    pub fn phys(&self) -> PhysAddr {
        self.pa
    }

    /// A reader over the page's bytes.
    pub fn reader(&self) -> VmReader<'_> {
        VmReader {
            base: phys_to_virt(self.pa),
            len: PAGE_SIZE as usize,
            pos: 0,
            _marker: core::marker::PhantomData,
        }
    }

    /// A writer over the page's bytes.
    pub fn writer(&self) -> VmWriter<'_> {
        VmWriter {
            base: phys_to_virt(self.pa),
            len: PAGE_SIZE as usize,
            pos: 0,
            _marker: core::marker::PhantomData,
        }
    }

    /// Adds one to the page's reference count for a new mapping, and returns
    /// the raw address to store in the page table.
    pub(crate) fn incref_for_mapping(&self) -> PhysAddr {
        if let Some(m) = meta::get(self.pa.pfn()) {
            m.refcount.fetch_add(1, AcqRel);
        }
        self.pa
    }
}

impl Clone for UFrame {
    fn clone(&self) -> UFrame {
        if let Some(m) = meta::get(self.pa.pfn()) {
            m.refcount.fetch_add(1, AcqRel);
        }
        UFrame { pa: self.pa }
    }
}

impl Drop for UFrame {
    fn drop(&mut self) {
        drop_untyped(self.pa);
    }
}

/// Drops one reference to an untyped page, freeing it at zero.
pub(crate) fn drop_untyped(pa: PhysAddr) {
    if let Some(m) = meta::get(pa.pfn())
        && m.refcount.fetch_sub(1, AcqRel) == 1
    {
        page_alloc::free(pa, 0, kind::UNTYPED);
    }
}

/// Copies bytes *out of* untyped memory. The source may change during the
/// read; callers get some valid byte for each position, never UB.
#[derive(Debug)]
pub struct VmReader<'a> {
    base: u64,
    len: usize,
    pos: usize,
    _marker: core::marker::PhantomData<&'a ()>,
}

impl VmReader<'_> {
    /// Bytes remaining.
    pub fn remaining(&self) -> usize {
        self.len - self.pos
    }

    /// Reads into `out`, returning how many bytes were copied.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.remaining());
        let src = core::ptr::with_exposed_provenance::<u8>((self.base + self.pos as u64) as usize);
        // SAFETY: `[base, base+len)` is the linear-map alias of one untyped
        // page, mapped readable; `n <= remaining`, so the read stays inside
        // it. `out` is an ordinary Rust slice that cannot alias untyped
        // memory. Concurrent writes to the page yield unspecified bytes.
        unsafe { arch::copy_untyped(out.as_mut_ptr(), src, n) };
        self.pos += n;
        n
    }

    /// Advances without reading.
    pub fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.len);
    }
}

/// Copies bytes *into* untyped memory.
#[derive(Debug)]
pub struct VmWriter<'a> {
    base: u64,
    len: usize,
    pos: usize,
    _marker: core::marker::PhantomData<&'a ()>,
}

impl VmWriter<'_> {
    /// Bytes that can still be written.
    pub fn remaining(&self) -> usize {
        self.len - self.pos
    }

    /// Writes `data`, returning how many bytes were copied.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.remaining());
        let dst =
            core::ptr::with_exposed_provenance_mut::<u8>((self.base + self.pos as u64) as usize);
        // SAFETY: `[base, base+len)` is the linear-map alias of one untyped
        // page, mapped writable; `n <= remaining`, so the write stays inside
        // it, and no Rust reference exists into untyped memory.
        unsafe { arch::copy_untyped(dst, data.as_ptr(), n) };
        self.pos += n;
        n
    }

    /// Advances the write position without writing.
    pub fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.len);
    }

    /// Fills the rest of the range with `byte`.
    pub fn fill(&mut self, byte: u8) {
        let n = self.remaining();
        let dst =
            core::ptr::with_exposed_provenance_mut::<u8>((self.base + self.pos as u64) as usize);
        // SAFETY: as in `write`.
        unsafe { arch::fill_untyped(dst, byte, n) };
        self.pos += n;
    }
}
