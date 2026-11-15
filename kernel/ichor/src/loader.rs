//! The program loader: maps an ELF image into a process's address space and
//! builds its initial stack.
//!
//! It walks the `elf` crate's bounds-checked load plan, takes a page from
//! the process's [`Mm`] for every virtual page a loadable segment touches
//! (two segments may share a page; the page gets the union of their
//! permissions), copies the file bytes in (the rest stays zero, which is
//! `.bss`), and maps it. The stack is a demand-paged region; the loader
//! writes the System V entry frame (argc, argv, envp, auxv) at its top.
//! Milestone 3 handles static executables; the dynamic path (`PT_INTERP`,
//! a separate mapping of the interpreter) comes with milestone 4.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use elf::{LoadPlan, Machine};
use frame::mm::{PAGE_SIZE, UFrame, UserProt};
use vma::Prot;

use crate::umem::Mm;

/// A loaded program ready to run.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Loaded {
    /// Entry point (virtual address).
    pub entry: u64,
    /// Initial stack pointer (points at argc, 16-byte aligned).
    pub stack_pointer: u64,
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
    /// A segment could not be mapped (bad address, or the image overlaps
    /// the stack or the mmap area).
    Map,
    /// argv, envp and the auxiliary vector do not fit the stack.
    ArgsTooLong,
}

/// Where the user stack is placed and how big it may grow.
const STACK_TOP: u64 = 0x7fff_f000_0000;
/// The most stack an image leaves room for (`RLIMIT_STACK` is clamped to
/// it), and the least a process gets.
const MAX_STACK: u64 = 1 << 30;
const MIN_STACK: u64 = 128 << 10;
/// Most bytes of argv/envp strings plus pointers.
const MAX_ARGS: usize = 128 * 1024;

// Auxiliary vector keys.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_MINSIGSTKSZ: u64 = 51;
const AT_EXECFN: u64 = 31;

/// Where a position-independent executable is placed.
const PIE_BASE: u64 = 0x5555_5555_4000;

/// The interpreter (`PT_INTERP`) `image` asks for, if any: the path the
/// caller must read and pass to [`load`].
pub(crate) fn interp_path(image: &[u8]) -> Result<Option<String>, LoadError> {
    let plan = elf::parse(image).map_err(LoadError::Elf)?;
    let Some((off, len)) = plan.interp else {
        return Ok(None);
    };
    let bytes = image
        .get(off as usize..(off + len) as usize)
        .ok_or(LoadError::Elf(elf::Error::BadSegment))?;
    let path = core::str::from_utf8(bytes).map_err(|_| LoadError::Dynamic)?;
    Ok(Some(String::from(path)))
}

/// Maps `plan`'s segments at `bias` into `mm`; returns the end of the
/// highest page.
fn map_image(mm: &mut Mm, plan: &LoadPlan, image: &[u8], bias: u64) -> Result<u64, LoadError> {
    // Every page the image touches, with the union of its segments' access.
    let mut pages: BTreeMap<u64, Prot> = BTreeMap::new();
    let mut image_end = 0;
    let segs: Vec<elf::Segment> = plan
        .segments()
        .iter()
        .map(|s| {
            let mut s = *s;
            s.vaddr = s.vaddr.wrapping_add(bias);
            s
        })
        .collect();
    for seg in &segs {
        let (start, end) = seg.page_range(PAGE_SIZE);
        if end > STACK_TOP - MAX_STACK || end < start {
            return Err(LoadError::Map);
        }
        image_end = image_end.max(end);
        let mut va = start;
        while va < end {
            let p = pages.entry(va).or_insert(Prot::NONE);
            p.read |= seg.flags.read;
            p.write |= seg.flags.write;
            p.exec |= seg.flags.exec;
            va += PAGE_SIZE;
        }
    }
    let mut frames: BTreeMap<u64, UFrame> = BTreeMap::new();
    for (&va, &prot) in &pages {
        if !mm.reserve(va, va + PAGE_SIZE, prot) {
            return Err(LoadError::Map);
        }
        let frame = mm.frame(va).ok_or(LoadError::OutOfMemory)?;
        frames.insert(va, frame);
    }
    for seg in &segs {
        let (start, end) = seg.page_range(PAGE_SIZE);
        let mut va = start;
        while va < end {
            if let Some(f) = frames.get(&va) {
                copy_segment_page(image, seg, va, f);
            }
            va += PAGE_SIZE;
        }
    }
    // Map only after the bytes are in place.
    for (&va, f) in &frames {
        let prot = pages.get(&va).copied().unwrap_or(Prot::NONE);
        let user = UserProt {
            write: prot.write,
            exec: prot.exec,
        };
        if prot.accessible() && mm.space().map(va, f, user).is_err() {
            return Err(LoadError::Map);
        }
    }
    Ok(image_end)
}

fn parse(image: &[u8]) -> Result<LoadPlan, LoadError> {
    let plan: LoadPlan = elf::parse(image).map_err(LoadError::Elf)?;
    if plan.machine != Machine::X86_64 {
        return Err(LoadError::WrongArch);
    }
    Ok(plan)
}

/// What the entry frame's auxiliary vector reports about the program.
struct Aux {
    phdr: Option<u64>,
    phent: u16,
    phnum: u16,
    entry: u64,
    /// Where the interpreter was loaded (0 without one).
    base: u64,
}

/// Loads `image` into the fresh address space `mm`, with `argv` and `envp`
/// on the stack. A position-independent executable is placed at a fixed
/// bias. If the image names an interpreter ([`interp_path`]), `interp` must
/// be that file: it is loaded too, and the process starts there, finding
/// the program through the auxiliary vector (`AT_PHDR`, `AT_ENTRY`,
/// `AT_BASE`), as on Linux.
pub(crate) fn load(
    mm: &mut Mm,
    image: &[u8],
    interp: Option<&[u8]>,
    argv: &[&str],
    envp: &[&str],
    stack_limit: u64,
) -> Result<Loaded, LoadError> {
    let stack_size = stack_limit.clamp(MIN_STACK, MAX_STACK) & !(PAGE_SIZE - 1);
    let plan = parse(image)?;
    let bias = if plan.pie { PIE_BASE } else { 0 };
    let image_end = map_image(mm, &plan, image, bias)?;
    mm.set_brk_start(image_end);

    let mut aux = Aux {
        phdr: plan.phdr_vaddr.map(|p| p + bias),
        phent: plan.phentsize,
        phnum: plan.phnum,
        entry: plan.entry.wrapping_add(bias),
        base: 0,
    };
    let mut start = aux.entry;
    match (plan.interp.is_some(), interp) {
        (false, _) => {}
        (true, None) => return Err(LoadError::Dynamic),
        (true, Some(ld)) => {
            let ip = parse(ld)?;
            if ip.interp.is_some() || !ip.pie {
                return Err(LoadError::Dynamic); // must be a self-contained ET_DYN
            }
            let (lo, hi) = ip.address_span(PAGE_SIZE).ok_or(LoadError::Map)?;
            let base = mm.find_free(hi - lo).ok_or(LoadError::OutOfMemory)? - lo;
            map_image(mm, &ip, ld, base)?;
            aux.base = base;
            start = ip.entry.wrapping_add(base);
        }
    }

    if !mm.reserve(STACK_TOP - stack_size, STACK_TOP, Prot::RW) {
        return Err(LoadError::Map);
    }
    let stack_pointer = build_stack(mm, &aux, argv, envp, stack_size)?;
    Ok(Loaded {
        entry: start,
        stack_pointer,
    })
}

/// Copies the file bytes of `seg` that fall within the page at `va` into
/// `frame` at the right offset.
fn copy_segment_page(image: &[u8], seg: &elf::Segment, va: u64, frame: &UFrame) {
    let page_end = va + PAGE_SIZE;
    // The segment's file-backed virtual range is [vaddr, vaddr+file_size).
    let file_vend = seg.vaddr + seg.file_size;
    let copy_start = va.max(seg.vaddr);
    let copy_end = page_end.min(file_vend);
    if copy_start >= copy_end {
        return; // All .bss on this page.
    }
    let in_page = (copy_start - va) as usize;
    let in_file = (seg.file_offset + (copy_start - seg.vaddr)) as usize;
    let len = (copy_end - copy_start) as usize;
    if let Some(bytes) = image.get(in_file..in_file + len) {
        let mut w = frame.writer();
        w.skip(in_page);
        w.write(bytes);
    }
}

/// 16 bytes for `AT_RANDOM` (the libc's stack-protector canary and pointer
/// guard), from the kernel generator.
fn random_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    crate::random::fill(&mut out);
    out
}

/// Writes the System V x86-64 entry frame at the top of the stack and
/// returns the initial rsp:
///
/// ```text
/// rsp -> argc, argv[0..argc], NULL, envp[..], NULL, auxv pairs, AT_NULL
///        ... padding, random bytes, strings ... STACK_TOP
/// ```
fn build_stack(
    mm: &mut Mm,
    plan: &Aux,
    argv: &[&str],
    envp: &[&str],
    stack_size: u64,
) -> Result<u64, LoadError> {
    // Strings and blobs go at the top, laid out downwards in `blob`, which
    // is the memory [blob_base, STACK_TOP).
    let mut strings: Vec<u8> = Vec::new();
    let mut place = |bytes: &[u8], nul: bool| -> usize {
        let at = strings.len();
        strings.extend_from_slice(bytes);
        if nul {
            strings.push(0);
        }
        at
    };
    let random_at = place(&random_bytes(), false);
    let platform_at = place(b"x86_64", true);
    let execfn_at = place(argv.first().copied().unwrap_or("").as_bytes(), true);
    let argv_at: Vec<usize> = argv.iter().map(|a| place(a.as_bytes(), true)).collect();
    let envp_at: Vec<usize> = envp.iter().map(|e| place(e.as_bytes(), true)).collect();
    if strings.len() > MAX_ARGS {
        return Err(LoadError::ArgsTooLong);
    }
    let blob_base = (STACK_TOP - strings.len() as u64) & !0xf;
    let addr = |off: usize| blob_base + off as u64;

    let mut auxv: Vec<(u64, u64)> = Vec::new();
    if let Some(phdr) = plan.phdr {
        auxv.push((AT_PHDR, phdr));
    }
    if plan.base != 0 {
        auxv.push((AT_BASE, plan.base));
    }
    auxv.extend_from_slice(&[
        (AT_PHENT, u64::from(plan.phent)),
        (AT_PHNUM, u64::from(plan.phnum)),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_ENTRY, plan.entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_PLATFORM, addr(platform_at)),
        (AT_HWCAP, 0),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_RANDOM, addr(random_at)),
        (AT_MINSIGSTKSZ, crate::signal::frame_stack_size()),
        (AT_EXECFN, addr(execfn_at)),
        (AT_NULL, 0),
    ]);

    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64);
    words.extend(argv_at.iter().map(|&o| addr(o)));
    words.push(0);
    words.extend(envp_at.iter().map(|&o| addr(o)));
    words.push(0);
    for (k, v) in auxv {
        words.push(k);
        words.push(v);
    }
    let sp = (blob_base - words.len() as u64 * 8) & !0xf;

    let mut frame_bytes: Vec<u8> = Vec::with_capacity((STACK_TOP - sp) as usize);
    for w in &words {
        frame_bytes.extend_from_slice(&w.to_le_bytes());
    }
    frame_bytes.resize((blob_base - sp) as usize, 0);
    frame_bytes.extend_from_slice(&strings);
    if frame_bytes.len() > (stack_size / 2) as usize {
        return Err(LoadError::ArgsTooLong);
    }
    mm.populate(sp, frame_bytes.len(), true);
    if mm.space().copy_to_user(sp, &frame_bytes) != frame_bytes.len() {
        return Err(LoadError::OutOfMemory);
    }
    Ok(sp)
}
