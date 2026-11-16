//! The global allocator: power-of-two size classes up to 2 KiB carved from
//! 64 KiB `MEM_MAP` chunks, with a free list per class; larger blocks are
//! mapped and unmapped whole. Single-threaded, as native processes are.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;

use crate::sys;

const PAGE: usize = 4096;
const CHUNK: usize = 64 * 1024;
/// Classes 16, 32, ..., 2048 bytes.
const CLASSES: usize = 8;
const MAX_SMALL: usize = 16 << (CLASSES - 1);

struct State {
    /// Free blocks per class, linked through their first word.
    free: [*mut u8; CLASSES],
    /// The unused tail of the current chunk.
    next: *mut u8,
    end: *mut u8,
}

struct Heap(UnsafeCell<State>);

// SAFETY: a native process has one thread (the ABI has no way to make
// another) and the kernel never runs its code re-entrantly, so the state
// is never touched by two threads at once.
unsafe impl Sync for Heap {}

#[global_allocator]
static HEAP: Heap = Heap(UnsafeCell::new(State {
    free: [null_mut(); CLASSES],
    next: null_mut(),
    end: null_mut(),
}));

/// The class for a small layout, or `None` for a large one.
fn class(layout: Layout) -> Option<usize> {
    let size = layout
        .size()
        .max(layout.align())
        .max(16)
        .next_power_of_two();
    (size <= MAX_SMALL).then(|| (size.trailing_zeros() - 4) as usize)
}

fn large_len(layout: Layout) -> usize {
    layout.size().next_multiple_of(PAGE)
}

impl State {
    fn alloc_small(&mut self, c: usize) -> *mut u8 {
        let head = self.free[c];
        if !head.is_null() {
            // SAFETY: a free block holds the next free block's address in
            // its first word (written by `dealloc`); blocks are at least
            // 16 bytes and 16-aligned.
            self.free[c] = unsafe { head.cast::<*mut u8>().read() };
            return head;
        }
        let size = 16usize << c;
        // Blocks are aligned to their size: chunks are page-aligned and
        // carved in order of size within a chunk only after aligning.
        let at = (self.next as usize).next_multiple_of(size);
        if self.next.is_null() || at + size > self.end as usize {
            let Ok(chunk) = sys::mem_map(CHUNK) else {
                return null_mut();
            };
            self.next = chunk;
            self.end = chunk.wrapping_add(CHUNK);
            return self.alloc_small(c);
        }
        let p = self.next.wrapping_add(at - self.next as usize);
        self.next = p.wrapping_add(size);
        p
    }
}

// SAFETY: `alloc` returns blocks of at least the layout's size, aligned
// to its alignment (class blocks are size-aligned and the size covers the
// alignment; large blocks are page-aligned, and larger alignments are
// refused), never handed out twice until freed.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: single-threaded (see `Sync` above), and no reference to
        // the state outlives this call.
        let st = unsafe { &mut *self.0.get() };
        match class(layout) {
            Some(c) => st.alloc_small(c),
            None if layout.align() <= PAGE => sys::mem_map(large_len(layout)).unwrap_or(null_mut()),
            None => null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as in `alloc`.
        let st = unsafe { &mut *self.0.get() };
        match class(layout) {
            Some(c) => {
                // SAFETY: `ptr` is a block of this class (the caller gives
                // back the layout it allocated with), at least 16 bytes and
                // 16-aligned, no longer in use: it holds the list link now.
                unsafe { ptr.cast::<*mut u8>().write(st.free[c]) };
                st.free[c] = ptr;
            }
            None => sys::mem_unmap(ptr, large_len(layout)),
        }
    }
}
