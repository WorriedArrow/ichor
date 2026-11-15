//! The program loader: maps an ELF image into a cell's address space.
//!
//! It walks the `elf` crate's bounds-checked load plan, allocates an untyped
//! page per virtual page of each loadable segment, copies the segment's file
//! bytes in (the rest stays zero, which is `.bss`), charges the pages to the
//! cell's account, and maps them with the segment's permissions. Milestone 3
//! handles static executables; the dynamic path (`PT_INTERP`, a separate
//! mapping of the interpreter) comes with dynamic linking in milestone 4.

use alloc::vec::Vec;

use cap::Rights;
use elf::{LoadPlan, Machine};
use frame::mm::{PAGE_SIZE, UFrame, UserProt};

use crate::kcell::{Cell, rights};

/// A loaded program ready to run.
pub(crate) struct Loaded {
    /// Entry point (virtual address).
    pub entry: u64,
    /// Initial stack pointer (top of the mapped user stack, 16-byte aligned).
    pub stack_pointer: u64,
    /// Pages kept alive for the life of the process (also reachable via the
    /// cell's mappings; held here so a load failure frees cleanly).
    _frames: Vec<UFrame>,
}

/// Why a load failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LoadError {
    /// The ELF image is malformed or unsupported.
    Elf(elf::Error),
    /// The image is not for this machine.
    WrongArch,
    /// Dynamic binaries are not supported yet (milestone 4).
    Dynamic,
    /// Out of memory, or the cell's account limit was hit.
    OutOfMemory,
    /// A segment could not be mapped (overlap or bad address).
    Map,
}

/// Where the user stack is placed and how big it is.
const STACK_TOP: u64 = 0x7fff_f000_0000;
const STACK_PAGES: u64 = 32; // 128 KiB

/// Loads `image` into `cell`'s address space.
pub(crate) fn load(cell: &Cell, image: &[u8]) -> Result<Loaded, LoadError> {
    let plan: LoadPlan = elf::parse(image).map_err(LoadError::Elf)?;
    if plan.machine != Machine::X86_64 {
        return Err(LoadError::WrongArch);
    }
    if plan.interp.is_some() || plan.pie {
        // A PIE needs a load bias and relocation; an interpreter needs a
        // second mapping. Both are milestone 4.
        return Err(LoadError::Dynamic);
    }

    let mut frames = Vec::new();
    for seg in plan.segments() {
        let prot = UserProt {
            write: seg.flags.write,
            exec: seg.flags.exec,
        };
        let (start, end) = seg.page_range(PAGE_SIZE);
        let mut va = start;
        while va < end {
            // Charge, allocate, and fill this page.
            if cell.account().charge(1).is_err() {
                return Err(LoadError::OutOfMemory);
            }
            let Some(frame) = UFrame::alloc_zeroed() else {
                cell.account().release(1);
                return Err(LoadError::OutOfMemory);
            };
            copy_segment_page(image, seg, va, &frame);
            if cell.space().map(va, &frame, prot).is_err() {
                cell.account().release(1);
                return Err(LoadError::Map);
            }
            frames.push(frame);
            va += PAGE_SIZE;
        }
    }

    // A zero-filled stack with a null auxv/argv/envp frame: argc=0, then a
    // null argv terminator, a null envp terminator, and an AT_NULL auxv.
    let mut stack_frames = map_stack(cell, &mut frames)?;
    frames.append(&mut stack_frames.0);
    Ok(Loaded {
        entry: plan.entry,
        stack_pointer: stack_frames.1,
        _frames: frames,
    })
}

/// Copies the file bytes of `seg` that fall within the page at `va` into
/// `frame` at the right offset.
fn copy_segment_page(image: &[u8], seg: &elf::Segment, va: u64, frame: &UFrame) {
    // Byte range of this page in the segment's virtual space.
    let page_start = va;
    let page_end = va + PAGE_SIZE;
    // The segment's file-backed virtual range is [vaddr, vaddr+file_size).
    let file_vstart = seg.vaddr;
    let file_vend = seg.vaddr + seg.file_size;
    let copy_start = page_start.max(file_vstart);
    let copy_end = page_end.min(file_vend);
    if copy_start >= copy_end {
        return; // All .bss on this page.
    }
    let in_page = (copy_start - page_start) as usize;
    let in_file = (seg.file_offset + (copy_start - file_vstart)) as usize;
    let len = (copy_end - copy_start) as usize;
    if let Some(bytes) = image.get(in_file..in_file + len) {
        let mut w = frame.writer();
        w.skip(in_page);
        w.write(bytes);
    }
}

/// Maps a zeroed user stack and builds a minimal System V entry frame
/// (argc=0, null argv, null envp, AT_NULL). Returns the stack pages and the
/// initial rsp.
fn map_stack(cell: &Cell, _frames: &mut [UFrame]) -> Result<(Vec<UFrame>, u64), LoadError> {
    let mut pages = Vec::new();
    let base = STACK_TOP - STACK_PAGES * PAGE_SIZE;
    for i in 0..STACK_PAGES {
        if cell.account().charge(1).is_err() {
            return Err(LoadError::OutOfMemory);
        }
        let Some(frame) = UFrame::alloc_zeroed() else {
            cell.account().release(1);
            return Err(LoadError::OutOfMemory);
        };
        let va = base + i * PAGE_SIZE;
        if cell
            .space()
            .map(
                va,
                &frame,
                UserProt {
                    write: true,
                    exec: false,
                },
            )
            .is_err()
        {
            cell.account().release(1);
            return Err(LoadError::Map);
        }
        pages.push(frame);
    }
    // Entry frame at the very top: six zeroed u64 (argc=0, argv NULL, envp
    // NULL, auxv AT_NULL = 0,0). The top page is `pages[STACK_PAGES-1]`.
    let frame_words = 6u64;
    let sp = STACK_TOP - frame_words * 8;
    // The top page's bytes are already zero (fresh frame), so argc=0 etc. are
    // in place. Keep the stack 16-byte aligned at entry.
    let sp = sp & !0xf;
    let _ = (&pages, cell);
    Ok((pages, sp))
}

/// Rights granted to a process over its own image pages.
#[allow(dead_code)]
pub(crate) fn image_rights() -> Rights {
    Rights::INSPECT | rights::READ | rights::WRITE | rights::MAP
}
