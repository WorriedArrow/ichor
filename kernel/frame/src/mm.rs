//! Memory management types.
//!
//! Milestone 0 only needs to *describe* physical memory. Paging, the frame
//! allocator, the kernel heap, and the typed/untyped frame split described in
//! ADR-0001 arrive with milestone 1.

use core::fmt;

/// Size of a base page on every architecture Ichor supports.
pub const PAGE_SIZE: u64 = 4096;

/// A physical address. Holding one grants nothing: it cannot be dereferenced
/// or mapped without going through frame's allocator and page-table APIs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Wraps a raw physical address.
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// The raw address.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
