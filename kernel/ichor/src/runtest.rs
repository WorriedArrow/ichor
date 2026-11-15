//! Milestone 3 self-tests: real static Linux x86-64 ELF binaries run,
//! unmodified, in cells through the Linux syscall personality, reading files
//! from a mounted Ichor image.

use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::power::{ExitStatus, shutdown};
use frame::println;
use frame::user::{UserContext, UserEvent, UserMode};

use crate::kcell::{Cell, System};
use crate::linuxabi::{self, Outcome};
use crate::loader;
use crate::process::LinuxProcess;
use crate::testprog::{Asm, BLOB_VADDR, Reg, static_elf};
use crate::vfs::Vfs;

pub(crate) fn fail(what: &str) -> ! {
    println!("ichor: runtest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

/// Linux syscall numbers the test programs use.
mod sys {
    pub(super) const READ: u64 = 0;
    pub(super) const WRITE: u64 = 1;
    pub(super) const OPEN: u64 = 2;
    pub(super) const CLOSE: u64 = 3;
    pub(super) const FSTAT: u64 = 5;
    pub(super) const STAT: u64 = 4;
    pub(super) const MMAP: u64 = 9;
    pub(super) const MPROTECT: u64 = 10;
    pub(super) const MUNMAP: u64 = 11;
    pub(super) const BRK: u64 = 12;
    pub(super) const UNAME: u64 = 63;
    pub(super) const GETCWD: u64 = 79;
    pub(super) const CHDIR: u64 = 80;
    pub(super) const RENAME: u64 = 82;
    pub(super) const MKDIR: u64 = 83;
    pub(super) const RMDIR: u64 = 84;
    pub(super) const UNLINK: u64 = 87;
    pub(super) const GETDENTS64: u64 = 217;
    pub(super) const EXIT_GROUP: u64 = 231;
}

const MOTD: &[u8] = b"hello from /etc/motd inside an Ichor image\n";
const HELLO: &[u8] = b"hello from a real Linux ELF running on Ichor\n";

/// The environment every test program gets.
const ENVP: &[&str] = &["PATH=/bin:/usr/bin", "HOME=/", "TERM=dumb"];

/// Loads `elf` into `p`'s cell with `argv`, runs it to exit, and frees its
/// memory; returns the exit status and the number of syscalls it made.
pub(crate) fn run_linux(p: &mut LinuxProcess, elf: &[u8], argv: &[&str]) -> (i32, u32) {
    let loaded = match loader::load(&p.cell, &mut p.mm, elf, argv, ENVP) {
        Ok(l) => l,
        Err(e) => {
            println!("ichor: runtest: load error {e:?}");
            fail("could not load the ELF");
        }
    };
    p.cell.space().bind_to_current_task();
    let mut ctx = UserContext::new(loaded.entry, loaded.stack_pointer);
    let mut syscalls = 0u32;
    let mut faults = 0u32;
    let status = loop {
        match UserMode::new(&mut ctx).execute() {
            UserEvent::Syscall => {
                syscalls += 1;
                if let Outcome::Exit(code) = linuxabi::dispatch(p, &mut ctx) {
                    break code;
                }
            }
            UserEvent::Exception {
                vector: 14,
                error,
                cr2,
            } if p.mm.fault(&p.cell, cr2, error & 2 != 0, error & 16 != 0) => {
                faults += 1;
            }
            UserEvent::Exception { vector, cr2, .. } => {
                frame::mm::activate_kernel_space();
                println!(
                    "ichor: runtest: fault vector {vector} cr2 {cr2:#x} rip {:#x}",
                    ctx.rip
                );
                fail("the Linux binary faulted");
            }
        }
        if syscalls > 100_000 || faults > 100_000 {
            fail("the Linux binary made too many syscalls or faults");
        }
    };
    frame::mm::activate_kernel_space();
    p.mm.clear(&p.cell);
    if p.cell.account().used() != 0 {
        println!(
            "ichor: runtest: {} pages still charged",
            p.cell.account().used()
        );
        fail("process memory was not returned");
    }
    (status, syscalls)
}

/// `write(1, msg); exit_group(7)`.
fn hello_program() -> Vec<u8> {
    let mut a = Asm::new();
    let msg = a.data(HELLO);
    a.mov_imm(Reg::Rdi, 1);
    a.mov_data(Reg::Rsi, msg);
    a.mov_imm(Reg::Rdx, HELLO.len() as u64);
    a.sys(sys::WRITE);
    a.mov_imm(Reg::Rdi, 7);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// A tiny `cat /etc/motd` with checks; exits 0 only if every check held.
pub(crate) fn cat_program() -> Vec<u8> {
    let mut a = Asm::new();
    let nope = a.data(b"/nope\0");
    let motd = a.data(b"/etc/motd\0");
    let bad = a.label();
    let done = a.label();
    // r13 = open("/nope", O_RDONLY)   (expect -ENOENT)
    a.mov_data(Reg::Rdi, nope);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    a.mov(Reg::R13, Reg::Rax);
    // r12 = open("/etc/motd", O_RDONLY)   (a symlink to /usr/share/motd)
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    a.mov(Reg::R12, Reg::Rax);
    // r14 = read(r12, rbx = rsp - 4096, 1024); write(1, rbx, r14)
    a.mov(Reg::Rbx, Reg::Rsp);
    a.sub_imm(Reg::Rbx, 4096);
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::Rbx);
    a.mov_imm(Reg::Rdx, 1024);
    a.sys(sys::READ);
    a.mov(Reg::R14, Reg::Rax);
    a.mov_imm(Reg::Rdi, 1);
    a.mov(Reg::Rsi, Reg::Rbx);
    a.mov(Reg::Rdx, Reg::R14);
    a.sys(sys::WRITE);
    // fstat(r12, rbp = rsp - 8192); r15 = st_size
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 8192);
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::FSTAT);
    a.load(Reg::R15, Reg::Rbp, 48);
    // close(r12)
    a.mov(Reg::Rdi, Reg::R12);
    a.sys(sys::CLOSE);
    // Checks: ENOENT for /nope, fd 3 for the first open, size == bytes read.
    a.cmp_imm(Reg::R13, -2);
    a.jne(bad);
    a.cmp_imm(Reg::R12, 3);
    a.jne(bad);
    a.cmp(Reg::R15, Reg::R14);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 0);
    a.jmp(done);
    a.bind(bad);
    a.mov_imm(Reg::Rdi, 1);
    a.bind(done);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Exercises argc, `brk`, anonymous and file `mmap` (demand paging),
/// `mprotect` round trips, `munmap`, `uname` and `getdents64`. Exits 0 if
/// every check held, else the number of the first failed check.
fn mem_program() -> Vec<u8> {
    const PATTERN: u64 = 0x1234_5678_9abc_def0;
    let mut a = Asm::new();
    let etc = a.data(b"/etc\0");
    let motd = a.data(b"/etc/motd\0");
    let ok = a.data(b"memtest ok\n");
    let bad = a.label();
    let check = |a: &mut Asm, n: u64, x: Reg, y: Reg| {
        a.mov_imm(Reg::R15, n);
        a.cmp(x, y);
        a.jne(bad);
    };
    let zero = |a: &mut Asm, n: u64, x: Reg| {
        a.mov_imm(Reg::R14, 0);
        a.mov_imm(Reg::R15, n);
        a.cmp(x, Reg::R14);
        a.jne(bad);
    };
    // 1: argc == 3.
    a.load(Reg::Rax, Reg::Rsp, 0);
    a.mov_imm(Reg::R14, 3);
    check(&mut a, 1, Reg::Rax, Reg::R14);
    // 2: r12 = brk(0); brk(r12 + 3 pages) == r12 + 3 pages.
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::BRK);
    a.mov(Reg::R12, Reg::Rax);
    a.mov(Reg::Rdi, Reg::R12);
    a.add_imm(Reg::Rdi, 0x3000);
    a.sys(sys::BRK);
    check(&mut a, 2, Reg::Rax, Reg::Rdi);
    // 3: the new heap is demand-paged and holds what is stored.
    a.mov_imm(Reg::Rbx, PATTERN);
    a.store(Reg::R12, 0, Reg::Rbx);
    a.load(Reg::Rax, Reg::R12, 0);
    check(&mut a, 3, Reg::Rax, Reg::Rbx);
    a.store(Reg::R12, 0x2ff8, Reg::Rbx);
    a.load(Reg::Rax, Reg::R12, 0x2ff8);
    check(&mut a, 3, Reg::Rax, Reg::Rbx);
    // 4: shrinking the break back works.
    a.mov(Reg::Rdi, Reg::R12);
    a.sys(sys::BRK);
    check(&mut a, 4, Reg::Rax, Reg::R12);
    // 5: r13 = mmap(NULL, 4 pages, RW, PRIVATE|ANONYMOUS); fresh memory is
    // zero and keeps a store.
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 0x4000);
    a.mov_imm(Reg::Rdx, 3);
    a.mov_imm(Reg::R10, 0x22);
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::R13, Reg::Rax);
    a.load(Reg::Rax, Reg::R13, 0);
    zero(&mut a, 5, Reg::Rax);
    a.store(Reg::R13, 0x3ff8, Reg::Rbx);
    a.load(Reg::Rax, Reg::R13, 0x3ff8);
    check(&mut a, 5, Reg::Rax, Reg::Rbx);
    // 6: mprotect(last page, NONE) then back to RW keeps its contents.
    a.mov(Reg::Rdi, Reg::R13);
    a.add_imm(Reg::Rdi, 0x3000);
    a.mov_imm(Reg::Rsi, 0x1000);
    a.mov_imm(Reg::Rdx, 0);
    a.sys(sys::MPROTECT);
    zero(&mut a, 6, Reg::Rax);
    a.mov_imm(Reg::Rdx, 3);
    a.sys(sys::MPROTECT);
    zero(&mut a, 6, Reg::Rax);
    a.load(Reg::Rax, Reg::R13, 0x3ff8);
    check(&mut a, 6, Reg::Rax, Reg::Rbx);
    // 7: munmap the whole mapping.
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 0x4000);
    a.sys(sys::MUNMAP);
    zero(&mut a, 7, Reg::Rax);
    // 8: uname(rbp = rsp - 8192) reports "Linux" (the kernel faults the
    // untouched stack page in for its copy).
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 8192);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.sys(sys::UNAME);
    zero(&mut a, 8, Reg::Rax);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R14, u64::from_le_bytes(*b"Linux\0\0\0"));
    check(&mut a, 8, Reg::Rax, Reg::R14);
    // 9: getdents64 on /etc returns ".", ".." and "motd": 3 x 24 bytes.
    a.mov_data(Reg::Rdi, etc);
    a.mov_imm(Reg::Rsi, 0o200_000); // O_DIRECTORY
    a.sys(sys::OPEN);
    a.mov(Reg::Rdi, Reg::Rax);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 4096);
    a.sys(sys::GETDENTS64);
    a.mov_imm(Reg::R14, 72);
    check(&mut a, 9, Reg::Rax, Reg::R14);
    // 10: a private file mapping of /etc/motd starts with its bytes.
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    a.mov(Reg::R8, Reg::Rax);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 4096);
    a.mov_imm(Reg::Rdx, 1);
    a.mov_imm(Reg::R10, 2);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.load(Reg::Rax, Reg::Rax, 0);
    a.mov_imm(Reg::R14, u64::from_le_bytes(*b"hello fr"));
    check(&mut a, 10, Reg::Rax, Reg::R14);
    // All good: print and exit 0.
    a.mov_imm(Reg::Rdi, 1);
    a.mov_data(Reg::Rsi, ok);
    a.mov_imm(Reg::Rdx, 11);
    a.sys(sys::WRITE);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Exercises the copy-on-write root through the Linux ABI: mkdir, create,
/// write and read back, copy-up of an image file, rename, chdir/getcwd and a
/// relative open, unlink, rmdir, and EEXIST. Exits 0 if every check held,
/// else the number of the first failed check.
fn fs_program() -> Vec<u8> {
    let mut a = Asm::new();
    let tmp = a.data(b"/tmp\0");
    let f = a.data(b"/tmp/f\0");
    let g_abs = a.data(b"/tmp/g\0");
    let g = a.data(b"g\0");
    let motd = a.data(b"/etc/motd\0");
    let text = a.data(b"hello upper\n");
    let shout = a.data(b"HELLO");
    let ok = a.data(b"fstest ok\n");
    let bad = a.label();
    // Fails with code `n` unless rax == imm.
    let expect = |a: &mut Asm, n: u64, imm: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, imm);
        a.jne(bad);
    };
    // rbp = scratch buffer below the stack pointer.
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // 1: mkdir("/tmp", 0777) == 0.
    a.mov_data(Reg::Rdi, tmp);
    a.mov_imm(Reg::Rsi, 0o777);
    a.sys(sys::MKDIR);
    expect(&mut a, 1, 0);
    // 2: open("/tmp/f", O_CREAT|O_WRONLY|O_TRUNC, 0644) == 3; write 12 bytes.
    a.mov_data(Reg::Rdi, f);
    a.mov_imm(Reg::Rsi, 0o1101);
    a.mov_imm(Reg::Rdx, 0o644);
    a.sys(sys::OPEN);
    expect(&mut a, 2, 3);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_data(Reg::Rsi, text);
    a.mov_imm(Reg::Rdx, 12);
    a.sys(sys::WRITE);
    expect(&mut a, 2, 12);
    a.mov_imm(Reg::Rdi, 3);
    a.sys(sys::CLOSE);
    // 3: reopen read-only and read the bytes back.
    a.mov_data(Reg::Rdi, f);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    expect(&mut a, 3, 3);
    a.mov_imm(Reg::Rdi, 3);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 64);
    a.sys(sys::READ);
    expect(&mut a, 3, 12);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R14, u64::from_le_bytes(*b"hello up"));
    a.mov_imm(Reg::R15, 3);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 3);
    a.sys(sys::CLOSE);
    // 4: an image file copies up on write: "HELLO" over /etc/motd.
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 1); // O_WRONLY
    a.sys(sys::OPEN);
    expect(&mut a, 4, 3);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_data(Reg::Rsi, shout);
    a.mov_imm(Reg::Rdx, 5);
    a.sys(sys::WRITE);
    expect(&mut a, 4, 5);
    a.mov_imm(Reg::Rdi, 3);
    a.sys(sys::CLOSE);
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    a.mov_imm(Reg::Rdi, 3);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 8);
    a.sys(sys::READ);
    expect(&mut a, 4, 8);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R14, u64::from_le_bytes(*b"HELLO fr"));
    a.mov_imm(Reg::R15, 4);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 3);
    a.sys(sys::CLOSE);
    // 5: rename("/tmp/f", "/tmp/g") == 0; stat("/tmp/f") == -ENOENT.
    a.mov_data(Reg::Rdi, f);
    a.mov_data(Reg::Rsi, g_abs);
    a.sys(sys::RENAME);
    expect(&mut a, 5, 0);
    a.mov_data(Reg::Rdi, f);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::STAT);
    expect(&mut a, 5, -2);
    // 6: chdir("/tmp"); getcwd == 5 ("/tmp\0"); open("g") relative == 3.
    a.mov_data(Reg::Rdi, tmp);
    a.sys(sys::CHDIR);
    expect(&mut a, 6, 0);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, 64);
    a.sys(sys::GETCWD);
    expect(&mut a, 6, 5);
    a.mov_data(Reg::Rdi, g);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    expect(&mut a, 6, 3);
    a.mov_imm(Reg::Rdi, 3);
    a.sys(sys::CLOSE);
    // 7: unlink("g"); rmdir("/tmp") (now empty) == 0.
    a.mov_data(Reg::Rdi, g);
    a.sys(sys::UNLINK);
    expect(&mut a, 7, 0);
    a.mov_data(Reg::Rdi, tmp);
    a.sys(sys::RMDIR);
    expect(&mut a, 7, 0);
    // 8: mkdir over an existing file is EEXIST.
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 0o755);
    a.sys(sys::MKDIR);
    expect(&mut a, 8, -17);
    // All good.
    a.mov_imm(Reg::Rdi, 1);
    a.mov_data(Reg::Rsi, ok);
    a.mov_imm(Reg::Rdx, 10);
    a.sys(sys::WRITE);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// The root image: `/usr/share/motd`, `/etc/motd -> /usr/share/motd`.
fn root_image() -> &'static [u8] {
    let mut b = image::builder::Builder::new();
    let motd = b.file("motd", MOTD, 0o644);
    let share = b.dir("share", &[motd], 0o755);
    let usr = b.dir("usr", &[share], 0o755);
    let link = b.symlink("motd", "/usr/share/motd");
    let etc = b.dir("etc", &[link], 0o755);
    let root = b.dir("/", &[etc, usr], 0o755);
    b.finish(root).leak()
}

pub(crate) fn run() {
    let system = System::new(4096).unwrap_or_else(|| fail("no system cell"));
    let vfs = Arc::new(
        Vfs::mount(root_image()).unwrap_or_else(|_| fail("could not mount the root image")),
    );
    let new_process = || {
        let cell = Cell::new(&system.root_account, 128).unwrap_or_else(|| fail("no process cell"));
        LinuxProcess::new(cell, vfs.clone())
    };

    let (status, syscalls) = run_linux(&mut new_process(), &hello_program(), &["hello"]);
    if status != 7 {
        fail("hello did not exit with status 7");
    }
    println!(
        "ichor: linux: static ELF ran via the Linux ABI, exited {status} after {syscalls} syscalls"
    );

    let (status, syscalls) = run_linux(&mut new_process(), &cat_program(), &["cat", "/etc/motd"]);
    if status != 0 {
        fail("cat: ENOENT, fd number, read or fstat check failed");
    }
    println!(
        "ichor: linux: cat read /etc/motd through a symlink in the image ({syscalls} syscalls, checks passed)"
    );

    let (status, syscalls) = run_linux(&mut new_process(), &mem_program(), &["memtest", "a", "b"]);
    if status != 0 {
        println!("ichor: linux: memtest failed check {status}");
        fail("memtest");
    }
    println!(
        "ichor: linux: brk, mmap, mprotect, munmap, uname, getdents64 ok ({syscalls} syscalls, memory returned)"
    );

    let (status, syscalls) = run_linux(&mut new_process(), &fs_program(), &["fstest"]);
    if status != 0 {
        println!("ichor: linux: fstest failed check {status}");
        fail("fstest");
    }
    println!(
        "ichor: linux: copy-on-write root: create, write, copy-up, rename, chdir, unlink, rmdir ok ({syscalls} syscalls)"
    );
}
