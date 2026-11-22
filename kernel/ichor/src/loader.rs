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

use crate::file::File;
use crate::umem::Mm;

/// A loaded program ready to run.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Loaded {
    /// Entry point (virtual address).
    pub entry: u64,
    /// Initial stack pointer (points at argc, 16-byte aligned).
    pub stack_pointer: u64,
    /// Where its argument strings are.
    pub args: Args,
}

/// Where a program's argv strings are (one after another, each with its
/// NUL), and where the envp strings that follow them end.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Args {
    pub start: u64,
    pub end: u64,
    pub env_end: u64,
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
/// Most bytes of argv/envp strings plus pointers (Linux's limit, for the
/// default stack).
pub(crate) const MAX_ARGS: usize = 2 << 20;

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
pub(crate) fn interp_path(image: &dyn File) -> Result<Option<String>, LoadError> {
    let plan = parse(image)?;
    let Some((off, len)) = plan.interp else {
        return Ok(None);
    };
    let len = usize::try_from(len)
        .map_err(|_| LoadError::Dynamic)?
        .min(4096);
    let mut bytes = alloc::vec![0u8; len];
    if image.read_at(off, &mut bytes) != len {
        return Err(LoadError::Elf(elf::Error::BadSegment));
    }
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    let path = core::str::from_utf8(&bytes).map_err(|_| LoadError::Dynamic)?;
    Ok(Some(String::from(path)))
}

/// Bytes of an image read to parse its headers.
const HEAD: usize = 64 << 10;

/// The image's first bytes (its ELF and program headers).
fn head(image: &dyn File) -> alloc::vec::Vec<u8> {
    let n = usize::try_from(image.size()).unwrap_or(HEAD).min(HEAD);
    let mut v = alloc::vec![0u8; n];
    let got = image.read_at(0, &mut v);
    v.truncate(got);
    v
}

/// Maps `plan`'s segments at `bias` into `mm`; returns the end of the
/// highest page. A page that lies wholly within one segment's file bytes
/// at a page-aligned file offset maps the page cache's copy of the file
/// page copy-on-write when there is one; every other page is a fresh page
/// the segment bytes are copied into.
fn map_image(mm: &mut Mm, plan: &LoadPlan, image: &dyn File, bias: u64) -> Result<u64, LoadError> {
    // Every page the image touches, with the union of its segments' access.
    let mut pages: BTreeMap<u64, Prot> = BTreeMap::new();
    // How many segments touch each page (a shared page is always copied).
    let mut users: BTreeMap<u64, u32> = BTreeMap::new();
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
            *users.entry(va).or_insert(0) += 1;
            let p = pages.entry(va).or_insert(Prot::NONE);
            p.read |= seg.flags.read;
            p.write |= seg.flags.write;
            p.exec |= seg.flags.exec;
            va += PAGE_SIZE;
        }
    }
    // Whole file pages that belong to one segment alone are mapped lazily,
    // like `mmap(MAP_PRIVATE)` of the file: they fault in from the page
    // cache on first touch, so exec costs what the program touches, not
    // its size. Edge pages (partial, shared by two segments, or bss) are
    // built below as before.
    let mut lazy: Vec<(u64, u64, u64, Prot)> = Vec::new(); // start, end, file offset, prot
    let source = image.mappable();
    if source.is_some() {
        for seg in &segs {
            let Some(file_end) = seg.vaddr.checked_add(seg.file_size) else {
                continue;
            };
            let mut s = seg.vaddr.next_multiple_of(PAGE_SIZE);
            let mut e = file_end & !(PAGE_SIZE - 1);
            while s < e && users.get(&s) != Some(&1) {
                s += PAGE_SIZE;
            }
            while e > s && users.get(&(e - PAGE_SIZE)) != Some(&1) {
                e -= PAGE_SIZE;
            }
            let offset = seg.file_offset + (s - seg.vaddr);
            let exclusive = (s..e)
                .step_by(PAGE_SIZE as usize)
                .all(|va| users.get(&va) == Some(&1));
            if s < e && exclusive && offset.is_multiple_of(PAGE_SIZE) {
                let prot = pages.get(&s).copied().unwrap_or(Prot::NONE);
                lazy.push((s, e, offset, prot));
            }
        }
    }
    let is_lazy = |va: u64| lazy.iter().any(|&(s, e, _, _)| s <= va && va < e);
    let mut frames: BTreeMap<u64, UFrame> = BTreeMap::new();
    for (&va, &prot) in &pages {
        if is_lazy(va) {
            continue;
        }
        if !mm.reserve(va, va + PAGE_SIZE, prot) {
            return Err(LoadError::Map);
        }
        // A whole file page: share the cache's copy.
        let whole = segs.iter().find_map(|seg| {
            let off = seg.file_offset + va.checked_sub(seg.vaddr)?;
            let inside = va >= seg.vaddr && va + PAGE_SIZE <= seg.vaddr + seg.file_size;
            (inside && off.is_multiple_of(PAGE_SIZE)).then_some(off / PAGE_SIZE)
        });
        if users.get(&va) == Some(&1)
            && let Some(f) = whole.and_then(|i| image.cached_page(i))
        {
            if !mm.map_cow(va, f, prot) {
                return Err(LoadError::OutOfMemory);
            }
            continue;
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
    if let Some(file) = source {
        for (s, e, offset, prot) in lazy {
            if !mm.map_file_lazily(s, e, prot, offset, file.clone()) {
                return Err(LoadError::Map);
            }
        }
    }
    Ok(image_end)
}

fn parse(image: &dyn File) -> Result<LoadPlan, LoadError> {
    let plan: LoadPlan = elf::parse_head(&head(image), image.size()).map_err(LoadError::Elf)?;
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
    ids: Ids,
}

/// The uid, effective uid, gid and effective gid a program runs with.
pub(crate) type Ids = [u32; 4];

/// Loads `image` into the fresh address space `mm`, with `argv` and `envp`
/// on the stack. A position-independent executable is placed at a fixed
/// bias. If the image names an interpreter ([`interp_path`]), `interp` must
/// be that file: it is loaded too, and the process starts there, finding
/// the program through the auxiliary vector (`AT_PHDR`, `AT_ENTRY`,
/// `AT_BASE`), as on Linux.
///
/// argv and envp strings are bytes, as on Linux: nothing requires them to
/// be UTF-8.
pub(crate) fn load<S: AsRef<[u8]>>(
    mm: &mut Mm,
    image: &dyn File,
    interp: Option<&dyn File>,
    argv: &[S],
    envp: &[S],
    stack_limit: u64,
    ids: Ids,
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
        ids,
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

    if !mm.reserve_stack(STACK_TOP - stack_size, STACK_TOP) {
        return Err(LoadError::Map);
    }
    let (stack_pointer, args) = build_stack(mm, &aux, argv, envp, stack_size)?;
    Ok(Loaded {
        entry: start,
        stack_pointer,
        args,
    })
}

/// Copies the file bytes of `seg` that fall within the page at `va` into
/// `frame` at the right offset.
fn copy_segment_page(image: &dyn File, seg: &elf::Segment, va: u64, frame: &UFrame) {
    let page_end = va + PAGE_SIZE;
    // The segment's file-backed virtual range is [vaddr, vaddr+file_size).
    let file_vend = seg.vaddr + seg.file_size;
    let copy_start = va.max(seg.vaddr);
    let copy_end = page_end.min(file_vend);
    if copy_start >= copy_end {
        return; // All .bss on this page.
    }
    let in_page = (copy_start - va) as usize;
    let in_file = seg.file_offset + (copy_start - seg.vaddr);
    let len = (copy_end - copy_start) as usize;
    let mut bytes = alloc::vec![0u8; len];
    let n = image.read_at(in_file, &mut bytes);
    let mut w = frame.writer();
    w.skip(in_page);
    w.write(&bytes[..n]);
}

/// 16 bytes for `AT_RANDOM` (the libc's stack-protector canary and pointer
/// guard), from the kernel generator.
fn random_bytes() -> [u8; 16] {
    let mut out = [0u8; 16];
    crate::random::fill(&mut out);
    out
}

/// Writes the System V x86-64 entry frame at the top of the stack and
/// returns the initial rsp, and where the strings are:
///
/// ```text
/// rsp -> argc, argv[0..argc], NULL, envp[..], NULL, auxv pairs, AT_NULL
///        ... padding, random bytes, strings ... STACK_TOP
/// ```
fn build_stack<S: AsRef<[u8]>>(
    mm: &mut Mm,
    plan: &Aux,
    argv: &[S],
    envp: &[S],
    stack_size: u64,
) -> Result<(u64, Args), LoadError> {
    // Strings and blobs go at the top, in `[blob_base, STACK_TOP)`: what is
    // fixed first, then argv's strings and envp's.
    let random = random_bytes();
    let platform = b"x86_64\0";
    let execfn = argv.first().map_or(&[][..], AsRef::as_ref);
    let long = |s: &[S]| s.iter().map(|s| s.as_ref().len() + 1).sum::<usize>();
    let fixed = random.len() + platform.len() + execfn.len() + 1;
    let blob = fixed + long(argv) + long(envp);
    let pointers = (argv.len() + envp.len()) * 8;
    // (What is fixed is not the caller's.)
    let given = blob - fixed + pointers;
    let most = (stack_size / 4).clamp(MIN_STACK, MAX_ARGS as u64);
    if given as u64 > most || (blob + pointers) as u64 > stack_size * 3 / 4 {
        return Err(LoadError::ArgsTooLong);
    }
    let blob_base = (STACK_TOP - blob as u64) & !0xf;
    let random_at = blob_base;
    let platform_at = random_at + random.len() as u64;
    let execfn_at = platform_at + platform.len() as u64;
    let args = Args {
        start: blob_base + fixed as u64,
        end: blob_base + (fixed + long(argv)) as u64,
        env_end: blob_base + blob as u64,
    };

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
        (AT_UID, u64::from(plan.ids[0])),
        (AT_EUID, u64::from(plan.ids[1])),
        (AT_GID, u64::from(plan.ids[2])),
        (AT_EGID, u64::from(plan.ids[3])),
        (AT_PLATFORM, platform_at),
        (AT_HWCAP, 0),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_RANDOM, random_at),
        (AT_MINSIGSTKSZ, crate::signal::frame_stack_size()),
        (AT_EXECFN, execfn_at),
        (AT_NULL, 0),
    ]);
    // argc, and the NULLs after argv and envp.
    let words = 3 + argv.len() + envp.len() + 2 * auxv.len();
    let sp = (blob_base - words as u64 * 8) & !0xf;

    let mut out = Writer {
        mm,
        at: sp,
        buf: Vec::new(),
    };
    let mut string_at = args.start;
    out.word(argv.len() as u64)?;
    for list in [argv, envp] {
        for s in list {
            out.word(string_at)?;
            string_at += s.as_ref().len() as u64 + 1;
        }
        out.word(0)?;
    }
    for (k, v) in auxv {
        out.word(k)?;
        out.word(v)?;
    }
    while out.position() < blob_base {
        out.word(0)?;
    }
    out.bytes(&random)?;
    out.bytes(platform)?;
    for s in core::iter::once(execfn).chain(argv.iter().chain(envp).map(AsRef::as_ref)) {
        out.bytes(s)?;
        out.bytes(&[0])?;
    }
    out.flush()?;
    Ok((sp, args))
}

/// Writes to fresh user memory, one thing after another, through a small
/// buffer.
struct Writer<'a> {
    mm: &'a mut Mm,
    at: u64,
    buf: Vec<u8>,
}

impl Writer<'_> {
    fn position(&self) -> u64 {
        self.at + self.buf.len() as u64
    }

    fn bytes(&mut self, data: &[u8]) -> Result<(), LoadError> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= PAGE_SIZE as usize {
            self.flush()?;
        }
        Ok(())
    }

    fn word(&mut self, w: u64) -> Result<(), LoadError> {
        self.bytes(&w.to_le_bytes())
    }

    fn flush(&mut self) -> Result<(), LoadError> {
        if self.mm.copy_to_user(self.at, &self.buf) != self.buf.len() {
            return Err(LoadError::OutOfMemory);
        }
        self.at += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }
}
