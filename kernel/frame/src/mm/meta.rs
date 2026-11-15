//! Per-page metadata: one [`PageMeta`] per physical page frame, in an array
//! reserved at boot and reached through the linear map.
//!
//! The metadata is the source of truth about what a page is used for. The
//! page allocator and the heap check it on every allocation and free, so a
//! policy bug (in the buddy allocator, or a double free) is caught instead of
//! producing aliased memory.

use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// What a page is used for.
pub(crate) mod kind {
    // 0: not managed by the page allocator (firmware, kernel image, holes).
    /// Head of a free block; `order` is the block order.
    pub(crate) const FREE: u8 = 1;
    /// Managed by the page allocator, inside a free block (not its head).
    pub(crate) const AVAILABLE: u8 = 2;
    /// Head of an allocated block; `order` is the block order.
    pub(crate) const ALLOCATED: u8 = 3;
    /// Non-head page of an allocated block.
    pub(crate) const TAIL: u8 = 4;
    /// A heap slab page; `class` is the size class.
    pub(crate) const SLAB: u8 = 5;
}

/// Sentinel for "no page" in the `next`/`prev` links.
pub(crate) const NO_PAGE: u32 = u32::MAX;

#[repr(C, align(32))]
#[derive(Debug)]
pub(crate) struct PageMeta {
    pub(crate) kind: AtomicU8,
    pub(crate) order: AtomicU8,
    pub(crate) class: AtomicU8,
    _reserved: AtomicU8,
    pub(crate) refcount: AtomicU32,
    pub(crate) next: AtomicU32,
    pub(crate) prev: AtomicU32,
    /// Slab pages: which slots are in use.
    pub(crate) bitmap: [AtomicU64; 2],
}

static META_PTR: AtomicPtr<PageMeta> = AtomicPtr::new(core::ptr::null_mut());
static META_LEN: AtomicUsize = AtomicUsize::new(0);

/// Installs the metadata array.
///
/// # Safety
///
/// `va` must be the linear-map address of `len * size_of::<PageMeta>()`
/// zeroed bytes reserved for this purpose forever. Call at most once,
/// before any other CPU runs.
pub(crate) unsafe fn install(va: u64, len: usize) {
    META_PTR.store(
        core::ptr::with_exposed_provenance_mut(va as usize),
        Ordering::Release,
    );
    META_LEN.store(len, Ordering::Release);
}

/// The metadata array (empty before [`install`]).
pub(crate) fn all() -> &'static [PageMeta] {
    let ptr = META_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return &[];
    }
    let len = META_LEN.load(Ordering::Acquire);
    // SAFETY: `install`'s contract: the memory is reserved forever, zeroed
    // (a valid `PageMeta` is all-zero atomics) and suitably aligned (page
    // aligned). It is only accessed through atomics, so shared references are
    // sound across CPUs.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// Metadata for page frame `pfn`, if it exists.
pub(crate) fn get(pfn: u64) -> Option<&'static PageMeta> {
    all().get(usize::try_from(pfn).ok()?)
}
