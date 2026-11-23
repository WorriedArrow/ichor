//! Virtio split virtqueues, owned by frame (ADR-0005).
//!
//! The descriptor table, available ring and used ring live in one DMA
//! buffer that frame alone writes. A driver submits chains of
//! [`Segment`]s, which name a [`DmaBuf`] and a byte range, and frame turns
//! them into descriptors with addresses it derives itself. A driver never
//! handles a bus address, so it cannot point the device at memory it does
//! not own. A submitted chain keeps clones of its buffers until the device
//! returns it, so dropping a buffer early cannot lead to DMA after free.
//!
//! Ring memory and in-flight buffers are deliberately leaked if the queue
//! is dropped: the device may keep using them until it is reset.

use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use core::sync::atomic::{Ordering, fence};

use crate::dma::{DmaAddr, DmaBuf};

const DESC_LEN: usize = 16;
const F_NEXT: u16 = 1;
const F_WRITE: u16 = 2;

/// One buffer in a descriptor chain.
#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    pub buf: &'a DmaBuf,
    pub offset: usize,
    pub len: usize,
    /// The device writes this segment (otherwise it reads it).
    pub device_writes: bool,
}

/// Why a submission was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// Not enough free descriptors.
    Full,
    /// A segment is empty or outside its buffer, or the chain is empty.
    BadSegment,
}

#[derive(Debug)]
struct InFlight {
    descs: Vec<u16>,
    _bufs: Vec<DmaBuf>,
}

/// A split virtqueue.
#[derive(Debug)]
pub struct VirtQueue {
    mem: ManuallyDrop<DmaBuf>,
    size: u16,
    avail_off: usize,
    used_off: usize,
    free: Vec<u16>,
    avail_idx: u16,
    last_used: u16,
    in_flight: ManuallyDrop<Vec<Option<InFlight>>>,
}

impl VirtQueue {
    /// A queue of `size` entries (a power of two), whose used ring is
    /// aligned to `align` bytes (likewise, at least 4; a legacy device has
    /// 4096, and takes the queue as one piece at the first address).
    pub fn new(size: u16, align: usize) -> Option<VirtQueue> {
        if !size.is_power_of_two() || !align.is_power_of_two() {
            return None;
        }
        let n = usize::from(size);
        let avail_off = n * DESC_LEN;
        let used_off = (avail_off + 6 + 2 * n).checked_next_multiple_of(align.max(4))?;
        let total = used_off + 6 + 8 * n;
        let mem = DmaBuf::alloc(total)?;
        Some(VirtQueue {
            mem: ManuallyDrop::new(mem),
            size,
            avail_off,
            used_off,
            free: (0..size).rev().collect(),
            avail_idx: 0,
            last_used: 0,
            in_flight: ManuallyDrop::new((0..n).map(|_| None).collect()),
        })
    }

    /// Number of entries.
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Bus addresses of the descriptor table, available ring and used ring,
    /// to program into the device.
    pub fn addresses(&self) -> (DmaAddr, DmaAddr, DmaAddr) {
        let at = |o| self.mem.dma_addr(o);
        // In range by construction (`new` sized the buffer to fit all three).
        match (at(0), at(self.avail_off), at(self.used_off)) {
            (Some(d), Some(a), Some(u)) => (d, a, u),
            _ => unreachable_layout(),
        }
    }

    /// Submits a descriptor chain; returns its token (the head index).
    pub fn submit(&mut self, segs: &[Segment<'_>]) -> Result<u16, SubmitError> {
        if segs.is_empty() {
            return Err(SubmitError::BadSegment);
        }
        if segs.len() > self.free.len() {
            return Err(SubmitError::Full);
        }
        let mut addrs = Vec::with_capacity(segs.len());
        for s in segs {
            let end = s.offset.checked_add(s.len).ok_or(SubmitError::BadSegment)?;
            if s.len == 0 || end > s.buf.len() || u32::try_from(s.len).is_err() {
                return Err(SubmitError::BadSegment);
            }
            addrs.push(s.buf.dma_addr(s.offset).ok_or(SubmitError::BadSegment)?);
        }
        let mut descs = Vec::with_capacity(segs.len());
        for _ in segs {
            descs.push(self.free.pop().ok_or(SubmitError::Full)?);
        }
        for (i, (s, addr)) in segs.iter().zip(&addrs).enumerate() {
            let d = usize::from(descs[i]) * DESC_LEN;
            let next = descs.get(i + 1).copied();
            let mut flags = if s.device_writes { F_WRITE } else { 0 };
            if next.is_some() {
                flags |= F_NEXT;
            }
            self.mem.write_u64(d, addr.as_u64());
            self.mem.write_u32(d + 8, s.len as u32);
            self.mem.write_u16(d + 12, flags);
            self.mem.write_u16(d + 14, next.unwrap_or(0));
        }
        let head = descs[0];
        let slot = self.avail_off + 4 + 2 * usize::from(self.avail_idx % self.size);
        self.mem.write_u16(slot, head);
        // The ring entry must be visible before the index that publishes it.
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.mem.write_u16(self.avail_off + 2, self.avail_idx);
        fence(Ordering::SeqCst);
        if let Some(slot) = self.in_flight.get_mut(usize::from(head)) {
            *slot = Some(InFlight {
                descs,
                _bufs: segs.iter().map(|s| s.buf.clone()).collect(),
            });
        }
        Ok(head)
    }

    /// Takes the next completed chain from the used ring: `(token, bytes
    /// the device wrote)`. Frees its descriptors and releases its buffers.
    pub fn poll(&mut self) -> Option<(u16, u32)> {
        let used_idx = self.mem.read_u16(self.used_off + 2);
        if used_idx == self.last_used {
            return None;
        }
        fence(Ordering::SeqCst);
        let e = self.used_off + 4 + 8 * usize::from(self.last_used % self.size);
        let id = self.mem.read_u32(e);
        let len = self.mem.read_u32(e + 4);
        self.last_used = self.last_used.wrapping_add(1);
        // A device returning an id it was not given is ignored: we only free
        // what we recorded, never what the ring says.
        let head = u16::try_from(id).ok()?;
        let done = self.in_flight.get_mut(usize::from(head))?.take()?;
        self.free.extend(done.descs);
        Some((head, len))
    }
}

#[allow(clippy::panic)] // Unreachable: the buffer is sized for the layout.
fn unreachable_layout() -> ! {
    panic!("virtqueue layout outside its buffer")
}
