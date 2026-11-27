//! The program loader: maps an ELF image into a process's address space and
//! builds its initial stack.
//!
//! It walks the `elf` crate's bounds-checked load plan and reserves what
//! each loadable segment covers (two segments may share a page; the page
//! gets the union of their permissions): whole file pages map the file
//! lazily, `.bss` is demand-zero, and only a segment's partial edge pages
//! are built at exec ([`map_image`]). The stack is a demand-paged region; the loader
//! writes the System V entry frame (argc, argv, envp, auxv) at its top.
//! Milestone 3 handles static executables; the dynamic path (`PT_INTERP`,
//! a separate mapping of the interpreter) comes with milestone 4.

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

/// Most bytes of an image read to parse its headers.
const HEAD: usize = 64 << 10;

/// Bytes read first: the ELF header, and the program headers too in every
/// image a linker writes.
const FIRST: usize = 4096;

/// The image's first bytes (its ELF and program headers).
fn head(image: &dyn File) -> Vec<u8> {
    let size = usize::try_from(image.size()).unwrap_or(HEAD).min(HEAD);
    let mut v = alloc::vec![0u8; size.min(FIRST)];
    let got = image.read_at(0, &mut v);
    v.truncate(got);
    // Program headers further in: read up to their end (at most `HEAD`).
    let field = |at: usize, len: usize| {
        v.get(at..at + len).map(|b| {
            b.iter()
                .rev()
                .fold(0usize, |n, &x| n.wrapping_shl(8) | usize::from(x))
        })
    };
    if let (Some(phoff), Some(size_of), Some(count)) = (field(32, 8), field(54, 2), field(56, 2)) {
        let need = phoff
            .saturating_add(size_of.saturating_mul(count))
            .min(size);
        if need > v.len() && got == FIRST {
            v.resize(need, 0);
            let more = image.read_at(FIRST as u64, &mut v[FIRST..]);
            v.truncate(FIRST + more);
        }
    }
    v
}

/// One piece of an image's address space: pages `[start, end)` that the
/// same segments cover.
struct Piece<'a> {
    start: u64,
    end: u64,
    /// The union of the covering segments' access.
    prot: Prot,
    /// The covering segments.
    segs: Vec<&'a elf::Segment>,
}

/// Whether `seg` has file bytes on the page at `va`.
fn has_file_bytes(seg: &elf::Segment, va: u64) -> bool {
    va < seg.vaddr.saturating_add(seg.file_size) && va + PAGE_SIZE > seg.vaddr && seg.file_size > 0
}

/// Maps `plan`'s segments at `bias` into `mm`; returns the end of the
/// highest page.
///
/// The work is per piece of address space between segment boundaries, not
/// per page, so it costs the same for a large program as for a small one.
/// Whole file pages that belong to one segment alone, at page-aligned file
/// offsets, are mapped lazily, like `mmap(MAP_PRIVATE)` of the file: they
/// fault in from the page cache on first touch. Pages with no file bytes
/// (`.bss`) are demand-zero. Only the pages left, a segment's partial first
/// and last pages and pages two segments share, are built here: the page
/// cache's copy, copy-on-write, for a whole file page one segment owns,
/// else a fresh page with each segment's bytes copied in.
fn map_image(mm: &mut Mm, plan: &LoadPlan, image: &dyn File, bias: u64) -> Result<u64, LoadError> {
    let segs: Vec<elf::Segment> = plan
        .segments()
        .iter()
        .map(|s| {
            let mut s = *s;
            s.vaddr = s.vaddr.wrapping_add(bias);
            s
        })
        .collect();
    let mut image_end = 0;
    let mut cuts: Vec<u64> = Vec::with_capacity(segs.len() * 2);
    for seg in &segs {
        let (start, end) = seg.page_range(PAGE_SIZE);
        if end > STACK_TOP - MAX_STACK || end < start {
            return Err(LoadError::Map);
        }
        image_end = image_end.max(end);
        cuts.extend([start, end]);
    }
    cuts.sort_unstable();
    cuts.dedup();
    // Between two cuts, the same segments cover every page.
    let mut pieces = Vec::new();
    for w in cuts.windows(2) {
        let (start, end) = (w[0], w[1]);
        let covering: Vec<&elf::Segment> = segs
            .iter()
            .filter(|s| {
                let (a, b) = s.page_range(PAGE_SIZE);
                a <= start && end <= b
            })
            .collect();
        let mut prot = Prot::NONE;
        for s in &covering {
            prot.read |= s.flags.read;
            prot.write |= s.flags.write;
            prot.exec |= s.flags.exec;
        }
        if !covering.is_empty() {
            pieces.push(Piece {
                start,
                end,
                prot,
                segs: covering,
            });
        }
    }
    let source = image.mappable();
    for piece in &pieces {
        // The lazily mapped part, if any: whole file pages of one segment.
        let mut lazy = (piece.start, piece.start, 0);
        if let ([seg], Some(_)) = (piece.segs.as_slice(), &source)
            && let Some(file_end) = seg.vaddr.checked_add(seg.file_size)
        {
            let s = seg.vaddr.next_multiple_of(PAGE_SIZE).max(piece.start);
            let e = (file_end & !(PAGE_SIZE - 1)).min(piece.end);
            if s < e {
                let offset = seg.file_offset + (s - seg.vaddr);
                if offset.is_multiple_of(PAGE_SIZE) {
                    lazy = (s, e, offset);
                }
            }
        }
        let (ls, le, offset) = lazy;
        for (s, e) in [(piece.start, ls), (le, piece.end)] {
            if s < e && !mm.reserve(s, e, piece.prot) {
                return Err(LoadError::Map);
            }
        }
        if ls < le
            && let Some(file) = &source
            && !mm.map_file_lazily(ls, le, piece.prot, offset, file.clone())
        {
            return Err(LoadError::Map);
        }
        // The pages with file bytes outside the lazy part.
        let first = piece
            .segs
            .iter()
            .map(|s| s.vaddr & !(PAGE_SIZE - 1))
            .min()
            .unwrap_or(piece.end)
            .max(piece.start);
        let last = piece
            .segs
            .iter()
            .map(|s| {
                s.vaddr
                    .saturating_add(s.file_size)
                    .next_multiple_of(PAGE_SIZE)
            })
            .max()
            .unwrap_or(piece.start)
            .min(piece.end);
        let mut va = first;
        while va < last {
            if va == ls && ls < le {
                va = le;
                continue;
            }
            if piece.segs.iter().any(|s| has_file_bytes(s, va)) {
                build_page(mm, image, piece, va)?;
            }
            va += PAGE_SIZE;
        }
    }
    Ok(image_end)
}

/// Builds the page at `va` of `piece` and maps it: the page cache's copy,
/// copy-on-write, if it is a whole file page of one segment, else a fresh
/// page with each covering segment's bytes copied in.
fn build_page(mm: &mut Mm, image: &dyn File, piece: &Piece<'_>, va: u64) -> Result<(), LoadError> {
    if let [seg] = piece.segs.as_slice() {
        let off = seg.file_offset + va.saturating_sub(seg.vaddr);
        let whole = va >= seg.vaddr && va + PAGE_SIZE <= seg.vaddr + seg.file_size;
        if whole
            && off.is_multiple_of(PAGE_SIZE)
            && let Some(f) = image.cached_page(off / PAGE_SIZE)
        {
            return if mm.map_cow(va, f, piece.prot) {
                Ok(())
            } else {
                Err(LoadError::OutOfMemory)
            };
        }
    }
    let frame = mm.frame(va).ok_or(LoadError::OutOfMemory)?;
    for seg in &piece.segs {
        copy_segment_page(image, seg, va, &frame);
    }
    // Mapped only once the bytes are in place.
    let user = UserProt {
        write: piece.prot.write,
        exec: piece.prot.exec,
        key: 0,
    };
    if piece.prot.accessible() && mm.space().map(va, &frame, user).is_err() {
        return Err(LoadError::Map);
    }
    Ok(())
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
