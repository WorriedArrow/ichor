//! Kernel copies into user memory obey the page's protection and never
//! outlive the mapping they write through (docs/reports/user-copy-fix.md).
//!
//! [`frame_race`] tests frame's `VmSpace` copy API directly, as any safe
//! caller may use it: a read-only page refuses a kernel write, and while a
//! kernel thread copies into a page in a loop, no byte lands in the page
//! after `unmap` has returned.
//!
//! [`run`] tests the Linux ABI on a root whose file pages come from the
//! shared page cache: `read` and `stat` into read-only pages return
//! `EFAULT` and leave them alone; `read` into a writable private file
//! mapping gets its own copy; a second cell and the cache page itself still
//! see the original bytes. [`mm_unlocked`] shows a copy runs without the
//! process's `Mm` lock and takes it only to fault. A stress program then
//! races large `read`s in one thread against `munmap`/`mmap`/`mprotect` of
//! the buffer in another.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use frame::mm::{PAGE_SIZE, UFrame, UserProt, VmSpace};
use frame::println;
use frame::task::{TaskOptions, WaitQueue};

use crate::kcell::{Cell, System};
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::Vfs;
use testprog::{Asm, BLOB_VADDR, Label, Reg, static_elf};

mod sys {
    pub(super) const READ: u64 = 0;
    pub(super) const OPEN: u64 = 2;
    pub(super) const STAT: u64 = 4;
    pub(super) const MMAP: u64 = 9;
    pub(super) const MPROTECT: u64 = 10;
    pub(super) const MUNMAP: u64 = 11;
    pub(super) const PREAD64: u64 = 17;
    pub(super) const CLONE: u64 = 56;
    pub(super) const EXIT: u64 = 60;
    pub(super) const FUTEX: u64 = 202;
    pub(super) const EXIT_GROUP: u64 = 231;
}

const EFAULT: i32 = -14;
const PROT_READ: u64 = 1;
const PROT_RW: u64 = 3;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANON: u64 = 0x20;
/// The file whose cache pages the tests map: 300 KiB of known bytes.
const PATTERN: &str = "/usr/share/pattern";
/// Pages of it the stress program maps.
const STRESS_PAGES: u64 = 16;
/// munmap/mmap/mprotect rounds in the stress program (each is three TLB
/// shootdowns, slow under TCG; every boot of the test suite runs them).
const STRESS_ROUNDS: u64 = 600;
/// The stress program goes on remapping until the reader made this many
/// reads, so the two always overlap.
const STRESS_MIN_READS: i32 = 300;

/// Must match xtask's `pattern_byte` (and blktest's).
fn pattern_byte(i: usize) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 9)) as u8
}

fn page_bytes(f: &UFrame) -> Vec<u8> {
    let mut b = alloc::vec![0u8; PAGE_SIZE as usize];
    f.reader().read(&mut b);
    b
}

/// Frame's copy API on its own, with no kernel `Mm` lock around it.
pub(crate) fn frame_race() {
    const VA: u64 = 0x10_0000_0000;
    const ROUNDS: usize = 32;
    static STOP: AtomicBool = AtomicBool::new(false);
    static DONE: AtomicBool = AtomicBool::new(false);
    static EXITED: WaitQueue = WaitQueue::new();

    let start = frame::time::now();
    let space = Arc::new(VmSpace::new().unwrap_or_else(|| fail("usercopy: no space")));
    let rw = UserProt {
        write: true,
        exec: false,
    };
    let ro = UserProt {
        write: false,
        exec: false,
    };

    // A read-only page refuses a kernel write and still reads.
    let page = UFrame::alloc_zeroed().unwrap_or_else(|| fail("usercopy: no page"));
    if space.map(VA, &page, ro).is_err() {
        fail("usercopy: map");
    }
    let copied = space.copy_to_user(VA, &[0xaa; 64]);
    if copied != 0 || page_bytes(&page).iter().any(|&b| b != 0) {
        println!("ichor: usercopy: copy_to_user wrote {copied} bytes through a read-only PTE");
        fail("usercopy: a kernel write went through a read-only mapping");
    }
    let mut back = [0xffu8; 64];
    if space.copy_from_user(VA, &mut back) != 64 || back[..] != page_bytes(&page)[..64] {
        fail("usercopy: a read-only page did not read back");
    }
    space.unmap(VA);

    // A writer copies into VA in a loop; this thread maps a fresh page
    // there, lets the writer at it, unmaps it, and checks that nothing
    // reaches the page once `unmap` has returned.
    let writer = space.clone();
    let spawned = TaskOptions::new(move || {
        // A different byte each pass, so a copy finishing late shows.
        let mut data = alloc::vec![0u8; PAGE_SIZE as usize];
        let mut v = 0u8;
        while !STOP.load(Ordering::Acquire) {
            v = v.wrapping_add(1).max(1);
            data.fill(v);
            core::hint::black_box(writer.copy_to_user(VA, &data));
        }
        drop(writer);
        DONE.store(true, Ordering::Release);
        EXITED.wake_all();
    })
    .spawn();
    if spawned.is_none() {
        fail("usercopy: could not spawn the writer");
    }
    // A yield runs the writer if it is queued on this CPU (it then runs
    // until preempted, often mid-copy: the window being tested); with
    // other CPUs, a short spin lets a writer running elsewhere overlap.
    let smp = frame::cpu::online_count() > 1;
    let pause = || {
        frame::task::yield_now();
        if smp {
            frame::time::spin_for(core::time::Duration::from_micros(200));
        }
    };
    let mut late = 0usize;
    let mut hit = 0usize;
    // On a loaded host the writer's CPU may not run in any of the rounds:
    // more of them then, until it has (or plainly never will).
    let patience = frame::time::now() + core::time::Duration::from_secs(20);
    let mut rounds = 0;
    while rounds < ROUNDS || (hit == 0 && frame::time::now() < patience) {
        rounds += 1;
        let f = UFrame::alloc_zeroed().unwrap_or_else(|| fail("usercopy: no page"));
        if space.map(VA, &f, rw).is_err() {
            fail("usercopy: map");
        }
        pause();
        space.unmap(VA);
        let before = page_bytes(&f);
        if before.iter().any(|&b| b != 0) {
            hit += 1;
        }
        // Give a copy that started before the unmap time to land.
        pause();
        if page_bytes(&f) != before {
            late += 1;
        }
    }
    STOP.store(true, Ordering::Release);
    EXITED.wait_until(|| DONE.load(Ordering::Acquire).then_some(()));
    if hit == 0 {
        fail("usercopy: the writer never reached a mapped page (the race test proves nothing)");
    }
    if late != 0 {
        println!("ichor: usercopy: {late} of {rounds} pages were written after unmap returned");
        fail("usercopy: a kernel copy wrote into a page after it was unmapped");
    }
    if Arc::strong_count(&space) != 1 {
        fail("usercopy: the space is still referenced");
    }
    println!(
        "ichor: usercopy: frame refuses kernel writes through read-only PTEs; no copy landed after unmap ({rounds} rounds, {hit} written while mapped, {} ms)",
        frame::time::now().saturating_sub(start).as_millis()
    );
}

/// A Linux process's copies run without its `Mm` lock (ADR-0011 as
/// amended): while this task holds the lock, as another thread's `mmap`,
/// `munmap`, `mprotect` or page fault would, a kernel task copies four
/// resident pages into the process and finishes; its next copy, into four
/// pages not yet faulted in, waits for the lock and finishes once it is
/// released.
fn mm_unlocked(p: LinuxProcess) {
    const LEN: usize = 4 * PAGE_SIZE as usize;
    const RESIDENT: u32 = 1;
    const FAULTED: u32 = 2;
    const SHORT: u32 = u32::MAX;
    let va = p
        .mm()
        .mmap(0, 2 * LEN as u64, PROT_RW, MAP_PRIVATE | MAP_ANON, None)
        .unwrap_or_else(|_| fail("usercopy: mmap"));
    p.mm().populate(va, LEN, true);
    let step = Arc::new((AtomicU32::new(0), WaitQueue::new()));
    let mut copier = p.helper().unwrap_or_else(|| fail("usercopy: helper"));
    let shared = step.clone();
    let mm = p.mm();
    let spawned = TaskOptions::new(move || {
        let (at, woken) = &*shared;
        let data = alloc::vec![0x5au8; LEN];
        for (k, next) in [RESIDENT, FAULTED].into_iter().enumerate() {
            let n = copier.copy_to_user(va + (k * LEN) as u64, &data);
            at.store(if n == LEN { next } else { SHORT }, Ordering::Release);
            woken.wake_all();
        }
        crate::proc::discard(copier);
    })
    .spawn();
    if spawned.is_none() {
        fail("usercopy: could not spawn the copier");
    }
    let (at, woken) = &*step;
    let reached = |want: u32, ms: u64| {
        let deadline = frame::time::now() + core::time::Duration::from_millis(ms);
        woken.wait_until_deadline(deadline, || {
            let s = at.load(Ordering::Acquire);
            (s == want || s == SHORT).then_some(())
        });
        at.load(Ordering::Acquire)
    };
    if reached(RESIDENT, 10_000) != RESIDENT {
        fail("usercopy: a copy into resident pages waited for the Mm lock");
    }
    // The next copy needs four faults, so it must wait for the lock.
    if reached(FAULTED, 20) != RESIDENT {
        fail("usercopy: a copy faulted pages in without the Mm lock");
    }
    drop(mm);
    if reached(FAULTED, 10_000) != FAULTED {
        fail("usercopy: a copy waiting for the Mm lock did not finish");
    }
    let mut back = alloc::vec![0u8; 2 * LEN];
    let mut p = p;
    if p.copy_from_user(va, &mut back) != back.len() || back.iter().any(|&b| b != 0x5a) {
        fail("usercopy: the copies did not land");
    }
    crate::proc::discard(p);
}

/// `mov r15, n; cmp x, imm; jne bad`.
fn expect_imm(a: &mut Asm, n: u64, x: Reg, imm: i32, bad: Label) {
    a.mov_imm(Reg::R15, n);
    a.cmp_imm(x, imm);
    a.jne(bad);
}

/// `mov r15, n; cmp x, y; jne bad`.
fn expect_eq(a: &mut Asm, n: u64, x: Reg, y: Reg, bad: Label) {
    a.mov_imm(Reg::R15, n);
    a.cmp(x, y);
    a.jne(bad);
}

/// `rax = mmap(addr or 0, len, prot, flags, fd or -1, 0)`.
fn mmap(a: &mut Asm, addr: Option<Reg>, len: u64, prot: u64, flags: u64, fd: Option<Reg>) {
    match addr {
        Some(r) => a.mov(Reg::Rdi, r),
        None => a.mov_imm(Reg::Rdi, 0),
    }
    a.mov_imm(Reg::Rsi, len);
    a.mov_imm(Reg::Rdx, prot);
    a.mov_imm(Reg::R10, flags);
    match fd {
        Some(r) => a.mov(Reg::R8, r),
        None => a.mov_imm(Reg::R8, u64::MAX),
    }
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
}

/// `rax = pread64(fd, buf, len, 0)`.
fn pread(a: &mut Asm, fd: Reg, buf: Reg, len: u64) {
    a.mov(Reg::Rdi, fd);
    a.mov(Reg::Rsi, buf);
    a.mov_imm(Reg::Rdx, len);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::PREAD64);
}

fn open(a: &mut Asm, path: testprog::Data, dst: Reg) {
    a.mov_data(Reg::Rdi, path);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    a.mov(dst, Reg::Rax);
}

fn finish(mut a: Asm, bad: Label) -> Vec<u8> {
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Kernel writes into read-only and copy-on-write pages. Exits 0 if every
/// check held, else the number of the first that failed.
fn copy_program() -> Vec<u8> {
    let hello = u64::from_le_bytes(*b"hello fr"); // the root disk's motd
    let mut a = Asm::new();
    let motd = a.data(b"/usr/share/motd\0");
    let pattern = a.data(b"/usr/share/pattern\0");
    let bad = a.label();
    open(&mut a, motd, Reg::R12);
    open(&mut a, pattern, Reg::R13);
    // r14 = a read-only private mapping of the pattern file; touching it
    // maps the shared cache page. rbx = its first word.
    mmap(&mut a, None, 4096, PROT_READ, MAP_PRIVATE, Some(Reg::R13));
    a.mov(Reg::R14, Reg::Rax);
    a.load(Reg::Rbx, Reg::R14, 0);
    // 1, 2: read() into it is EFAULT and leaves it alone.
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::R14);
    a.mov_imm(Reg::Rdx, 16);
    a.sys(sys::READ);
    expect_imm(&mut a, 1, Reg::Rax, EFAULT, bad);
    a.load(Reg::Rax, Reg::R14, 0);
    expect_eq(&mut a, 2, Reg::Rax, Reg::Rbx, bad);
    // 3, 4: so is stat() into it.
    a.mov_data(Reg::Rdi, motd);
    a.mov(Reg::Rsi, Reg::R14);
    a.sys(sys::STAT);
    expect_imm(&mut a, 3, Reg::Rax, EFAULT, bad);
    a.load(Reg::Rax, Reg::R14, 0);
    expect_eq(&mut a, 4, Reg::Rax, Reg::Rbx, bad);
    // 5-8: a writable private mapping of the same page starts with the same
    // bytes; pread() into it succeeds and shows the new data, and the
    // read-only mapping (still the cache page) does not change.
    mmap(&mut a, None, 4096, PROT_RW, MAP_PRIVATE, Some(Reg::R13));
    a.mov(Reg::Rbp, Reg::Rax);
    a.load(Reg::Rax, Reg::Rbp, 0);
    expect_eq(&mut a, 5, Reg::Rax, Reg::Rbx, bad);
    pread(&mut a, Reg::R12, Reg::Rbp, 16);
    expect_imm(&mut a, 6, Reg::Rax, 16, bad);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R8, hello);
    expect_eq(&mut a, 7, Reg::Rax, Reg::R8, bad);
    a.load(Reg::Rax, Reg::R14, 0);
    expect_eq(&mut a, 8, Reg::Rax, Reg::Rbx, bad);
    // 9, 10: a read-only anonymous page, already mapped (zero), refuses too.
    mmap(&mut a, None, 4096, PROT_READ, MAP_PRIVATE | MAP_ANON, None);
    a.mov(Reg::Rbp, Reg::Rax);
    a.load(Reg::Rax, Reg::Rbp, 0);
    pread(&mut a, Reg::R12, Reg::Rbp, 16);
    expect_imm(&mut a, 9, Reg::Rax, EFAULT, bad);
    a.load(Reg::Rax, Reg::Rbp, 0);
    expect_imm(&mut a, 10, Reg::Rax, 0, bad);
    // 11-14: a buffer running from a writable page into a read-only one is
    // filled up to the boundary (a short read), not past it.
    mmap(&mut a, None, 8192, PROT_RW, MAP_PRIVATE | MAP_ANON, None);
    a.mov(Reg::Rbp, Reg::Rax);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 4096);
    a.mov_imm(Reg::Rsi, 4096);
    a.mov_imm(Reg::Rdx, PROT_READ);
    a.sys(sys::MPROTECT);
    expect_imm(&mut a, 11, Reg::Rax, 0, bad);
    a.load(Reg::Rax, Reg::Rbp, 4096);
    a.add_imm(Reg::Rbp, 4088);
    pread(&mut a, Reg::R12, Reg::Rbp, 16);
    expect_imm(&mut a, 12, Reg::Rax, 8, bad);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R8, hello);
    expect_eq(&mut a, 13, Reg::Rax, Reg::R8, bad);
    a.load(Reg::Rax, Reg::Rbp, 8);
    expect_imm(&mut a, 14, Reg::Rax, 0, bad);
    finish(a, bad)
}

/// Another cell maps the pattern file read-only and checks its first two
/// words are `w0` and `w1`.
fn reader_program(w0: u64, w1: u64) -> Vec<u8> {
    let mut a = Asm::new();
    let pattern = a.data(b"/usr/share/pattern\0");
    let bad = a.label();
    open(&mut a, pattern, Reg::R13);
    mmap(&mut a, None, 4096, PROT_READ, MAP_PRIVATE, Some(Reg::R13));
    a.mov(Reg::R14, Reg::Rax);
    a.load(Reg::Rax, Reg::R14, 0);
    a.mov_imm(Reg::R8, w0);
    expect_eq(&mut a, 1, Reg::Rax, Reg::R8, bad);
    a.load(Reg::Rax, Reg::R14, 8);
    a.mov_imm(Reg::R8, w1);
    expect_eq(&mut a, 2, Reg::Rax, Reg::R8, bad);
    finish(a, bad)
}

/// A thread `pread`s 64 KiB of the pattern file into a buffer over and
/// over while the main thread cycles the buffer through unmapped, fresh
/// anonymous memory, a read-only private mapping of the same file (the
/// cache's pages) and that mapping made writable. Every read must return
/// the full length, a short count, or `EFAULT`. Exits 0, or 1 for a bad
/// mapping call, 2 for a bad read result, 3 if no read ran.
fn stress_program() -> Vec<u8> {
    const FLAGS: u64 = 0x35_0f00; // VM FS FILES SIGHAND THREAD SYSVSEM PARENT_SETTID CHILD_CLEARTID
    const FUTEX_WAIT_PRIVATE: u64 = 128;
    const LEN: u64 = STRESS_PAGES * 4096;
    const STACK: u64 = 0x1_0000;
    let mut a = Asm::new();
    let pattern = a.data(b"/usr/share/pattern\0");
    let bad = a.label();
    let thread = a.label();
    let round = a.label();
    let next = a.label();
    let enough = a.label();
    let join = a.label();
    let join_wait = a.label();
    let joined = a.label();
    let t_loop = a.label();
    let t_ok = a.label();
    let t_bad = a.label();
    let t_done = a.label();
    // rbp -> shared words below the stack: [0] stop, [8] tid, [16] the
    // first bad read result, [24] reads done.
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rax, 0);
    for off in [0, 8, 16, 24] {
        a.store(Reg::Rbp, off, Reg::Rax);
    }
    open(&mut a, pattern, Reg::R13);
    // r12 = the buffer, r14 = the thread's stack.
    mmap(&mut a, None, LEN, PROT_RW, MAP_PRIVATE | MAP_ANON, None);
    a.mov(Reg::R12, Reg::Rax);
    mmap(&mut a, None, STACK, PROT_RW, MAP_PRIVATE | MAP_ANON, None);
    a.mov(Reg::R14, Reg::Rax);
    a.mov_imm(Reg::Rdi, FLAGS);
    a.mov(Reg::Rsi, Reg::R14);
    a.add_imm(Reg::Rsi, STACK as i32);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, 8);
    a.mov(Reg::R10, Reg::Rdx);
    a.mov_imm(Reg::R8, 0);
    a.sys(sys::CLONE);
    a.cmp_imm(Reg::Rax, 0);
    a.je(thread);

    // Main: rbx rounds of remapping, then more until the reader caught up.
    a.mov_imm(Reg::Rbx, STRESS_ROUNDS);
    a.bind(round);
    let remap = |a: &mut Asm, prot: u64, flags: u64, fd: Option<Reg>| {
        a.mov(Reg::Rdi, Reg::R12);
        a.mov_imm(Reg::Rsi, LEN);
        a.sys(sys::MUNMAP);
        expect_imm(a, 1, Reg::Rax, 0, bad);
        mmap(a, Some(Reg::R12), LEN, prot, flags | MAP_FIXED, fd);
        expect_eq(a, 1, Reg::Rax, Reg::R12, bad);
    };
    // Fresh anonymous memory, one page of it touched.
    remap(&mut a, PROT_RW, MAP_PRIVATE | MAP_ANON, None);
    a.store(Reg::R12, 0, Reg::Rax);
    // The file, read-only, with its first pages mapped from the cache.
    remap(&mut a, PROT_READ, MAP_PRIVATE, Some(Reg::R13));
    a.load(Reg::Rax, Reg::R12, 0);
    a.load(Reg::Rax, Reg::R12, 4096);
    // ... then made writable: still copy-on-write.
    a.mov(Reg::Rdi, Reg::R12);
    a.mov_imm(Reg::Rsi, LEN);
    a.mov_imm(Reg::Rdx, PROT_RW);
    a.sys(sys::MPROTECT);
    expect_imm(&mut a, 1, Reg::Rax, 0, bad);
    a.cmp_imm(Reg::Rbx, 0);
    a.je(next);
    a.sub_imm(Reg::Rbx, 1);
    a.jmp(round);
    a.bind(next);
    a.load(Reg::Rax, Reg::Rbp, 24);
    a.cmp_imm(Reg::Rax, STRESS_MIN_READS);
    a.ja(enough);
    a.jmp(round);
    a.bind(enough);
    // Stop the reader and join it.
    a.mov_imm(Reg::Rax, 1);
    a.store(Reg::Rbp, 0, Reg::Rax);
    a.bind(join);
    a.load(Reg::Rax, Reg::Rbp, 8);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(join_wait);
    a.jmp(joined);
    a.bind(join_wait);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 8);
    a.mov_imm(Reg::Rsi, FUTEX_WAIT_PRIVATE);
    a.mov(Reg::Rdx, Reg::Rax);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::FUTEX);
    a.jmp(join);
    a.bind(joined);
    a.load(Reg::Rax, Reg::Rbp, 16);
    expect_imm(&mut a, 2, Reg::Rax, 0, bad);
    a.load(Reg::Rax, Reg::Rbp, 24);
    a.mov_imm(Reg::R15, 3);
    a.cmp_imm(Reg::Rax, 0);
    a.je(bad);
    a.mov_imm(Reg::R15, 0);
    a.jmp(bad);

    // The reader: r15 counts reads.
    a.bind(thread);
    a.mov_imm(Reg::R15, 0);
    a.bind(t_loop);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(t_done);
    pread(&mut a, Reg::R13, Reg::R12, LEN);
    a.cmp_imm(Reg::Rax, EFAULT);
    a.je(t_ok);
    // Anything else must be 0..=LEN (unsigned, so errors are above it).
    a.mov_imm(Reg::R8, LEN);
    a.cmp(Reg::Rax, Reg::R8);
    a.ja(t_bad);
    a.bind(t_ok);
    a.add_imm(Reg::R15, 1);
    a.store(Reg::Rbp, 24, Reg::R15);
    a.jmp(t_loop);
    a.bind(t_bad);
    a.store(Reg::Rbp, 16, Reg::Rax);
    a.mov_imm(Reg::R15, u64::MAX >> 1); // lets the main thread stop
    a.store(Reg::Rbp, 24, Reg::R15);
    a.bind(t_done);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT);
    finish(a, bad)
}

/// Whether `pages` (pages 0.. of the pattern file in the cache) still hold
/// the file's bytes, and the cache still hands out those same pages.
fn cache_intact(vfs: &Vfs, ino: crate::vfs::Ino, pages: &[UFrame]) -> bool {
    pages.iter().enumerate().all(|(k, f)| {
        let base = k * PAGE_SIZE as usize;
        let same = vfs
            .cached_page(ino, k as u64)
            .is_some_and(|c| c.phys() == f.phys());
        same && page_bytes(f)
            .iter()
            .enumerate()
            .all(|(i, &b)| b == pattern_byte(base + i))
    })
}

/// The Linux-level tests, on `vfs`, a root that shares the page cache.
pub(crate) fn run(vfs: &Arc<Vfs>) {
    let ino = vfs
        .lock()
        .resolve(crate::vfs::ROOT, PATTERN, true)
        .unwrap_or_else(|_| fail("usercopy: no pattern file"));
    let pages: Vec<UFrame> = (0..STRESS_PAGES)
        .map(|k| {
            vfs.cached_page(ino, k)
                .unwrap_or_else(|| fail("usercopy: no cache page"))
        })
        .collect();
    if !cache_intact(vfs, ino, &pages) {
        fail("usercopy: the pattern file's cache pages are wrong before the test");
    }
    let word = |at: usize| u64::from_le_bytes(core::array::from_fn(|i| pattern_byte(at + i)));
    let system = System::new(4096).unwrap_or_else(|| fail("usercopy: no system cell"));
    let process = || {
        let cell = Cell::new(&system.root_account, 256).unwrap_or_else(|| fail("no process cell"));
        LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"))
    };

    let (copy, _) = run_linux(process(), &copy_program(), None, &["copytest"]);
    let (other, _) = run_linux(
        process(),
        &reader_program(word(0), word(8)),
        None,
        &["copyreader"],
    );
    let intact = cache_intact(vfs, ino, &pages);
    if copy != 0 || other != 0 || !intact {
        println!(
            "ichor: usercopy: copytest exit {copy} (failed check), other cell exit {other}, page cache intact: {intact}"
        );
        fail("usercopy: a kernel write reached a read-only or shared page");
    }
    println!(
        "ichor: usercopy: read and stat into read-only pages return EFAULT; read into a private file mapping broke copy-on-write; another cell and the page cache kept the original bytes"
    );

    mm_unlocked(process());
    println!(
        "ichor: usercopy: a copy into resident pages ran while the Mm lock was held; one that needed faults waited for it"
    );

    let start = frame::time::now();
    let (stress, syscalls) = run_linux(process(), &stress_program(), None, &["copystress"]);
    let ms = frame::time::now().saturating_sub(start).as_millis();
    if stress != 0 {
        println!("ichor: usercopy: copystress failed check {stress}");
        fail("usercopy: stress");
    }
    if !cache_intact(vfs, ino, &pages) {
        fail("usercopy: the stress test changed the page cache");
    }
    println!(
        "ichor: usercopy: reads raced {STRESS_ROUNDS}+ munmap/mmap/mprotect rounds; each completed or returned EFAULT; page cache intact ({syscalls} syscalls, {ms} ms, memory returned)"
    );
}
