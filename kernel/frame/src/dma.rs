//! DMA buffers (ADR-0005).
//!
//! A [`DmaBuf`] is a reference-counted run of physically contiguous untyped
//! pages a device may read or write. Like a `UFrame`, the CPU only ever
//! copies in and out (the device can change the bytes at any time). Its bus
//! address is an opaque [`DmaAddr`] that can only come from a live buffer,
//! so safe code cannot invent one. Virtio drivers never see a `DmaAddr`:
//! frame's `VirtQueue` writes descriptors itself.

use alloc::sync::Arc;

use crate::arch;
use crate::mm::meta::kind;
use crate::mm::{PAGE_SIZE, PhysAddr, page_alloc, phys_to_virt};

#[derive(Debug)]
struct Inner {
    pa: PhysAddr,
    order: u8,
    len: usize,
}

impl Drop for Inner {
    fn drop(&mut self) {
        page_alloc::free(self.pa, self.order, kind::DMA);
    }
}

/// A device-visible memory buffer. Cloning shares it.
#[derive(Clone, Debug)]
pub struct DmaBuf {
    inner: Arc<Inner>,
}

/// A bus address inside a live [`DmaBuf`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaAddr(u64);

impl DmaAddr {
    /// The raw bus address, for device-owned ring formats frame does not
    /// manage (NVMe). Every use of this marks a driver as DMA-trusted
    /// (ADR-0005); virtio drivers never need it.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl DmaBuf {
    /// Allocates a zeroed buffer of at least `len` bytes (rounded up to a
    /// power-of-two number of pages, at most 4 MiB).
    pub fn alloc(len: usize) -> Option<DmaBuf> {
        let pages = (len as u64).div_ceil(PAGE_SIZE).max(1);
        let order = pages.next_power_of_two().trailing_zeros();
        if order > u32::from(buddy::MAX_ORDER) {
            return None;
        }
        let order = order as u8;
        let pa = page_alloc::alloc(order, kind::DMA)?;
        let bytes = (PAGE_SIZE << order) as usize;
        let dst = core::ptr::with_exposed_provenance_mut::<u8>(phys_to_virt(pa) as usize);
        // SAFETY: a fresh, exclusively owned block of `bytes` bytes, mapped
        // RW through the linear map; no Rust reference points into it.
        unsafe { arch::fill_untyped(dst, 0, bytes) };
        Some(DmaBuf {
            inner: Arc::new(Inner {
                pa,
                order,
                len: bytes,
            }),
        })
    }

    /// Size of the buffer in bytes.
    pub fn len(&self) -> usize {
        self.inner.len
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len == 0
    }

    /// The bus address of byte `offset`, if in range.
    pub fn dma_addr(&self, offset: usize) -> Option<DmaAddr> {
        (offset < self.inner.len).then(|| DmaAddr(self.inner.pa.as_u64() + offset as u64))
    }

    fn va(&self, offset: usize) -> u64 {
        phys_to_virt(self.inner.pa) + offset as u64
    }

    /// Copies bytes out from `offset`; returns how many were copied.
    pub fn read(&self, offset: usize, out: &mut [u8]) -> usize {
        let n = out.len().min(self.inner.len.saturating_sub(offset));
        let src = core::ptr::with_exposed_provenance::<u8>(self.va(offset) as usize);
        // SAFETY: `[offset, offset+n)` is inside this block (clamped above),
        // mapped through the linear map; `out` is a Rust slice that cannot
        // alias device memory. Concurrent device writes yield unspecified
        // bytes, not UB (the copy is `rep movsb`).
        unsafe { arch::copy_untyped(out.as_mut_ptr(), src, n) };
        n
    }

    /// Copies `data` in at `offset`; returns how many bytes were copied.
    pub fn write(&self, offset: usize, data: &[u8]) -> usize {
        let n = data.len().min(self.inner.len.saturating_sub(offset));
        let dst = core::ptr::with_exposed_provenance_mut::<u8>(self.va(offset) as usize);
        // SAFETY: as in `read`.
        unsafe { arch::copy_untyped(dst, data.as_ptr(), n) };
        n
    }

    /// Reads a little-endian `u16` at `offset` (0 if out of range).
    pub fn read_u16(&self, offset: usize) -> u16 {
        let mut b = [0u8; 2];
        self.read(offset, &mut b);
        u16::from_le_bytes(b)
    }

    /// Reads a little-endian `u32` at `offset` (0 if out of range).
    pub fn read_u32(&self, offset: usize) -> u32 {
        let mut b = [0u8; 4];
        self.read(offset, &mut b);
        u32::from_le_bytes(b)
    }

    /// Writes a little-endian `u16` at `offset`.
    pub fn write_u16(&self, offset: usize, v: u16) {
        self.write(offset, &v.to_le_bytes());
    }

    /// Writes a little-endian `u32` at `offset`.
    pub fn write_u32(&self, offset: usize, v: u32) {
        self.write(offset, &v.to_le_bytes());
    }

    /// Writes a little-endian `u64` at `offset`.
    pub fn write_u64(&self, offset: usize, v: u64) {
        self.write(offset, &v.to_le_bytes());
    }
}
