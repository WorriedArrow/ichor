//! Milestone 3 self-tests: real static Linux x86-64 ELF binaries run,
//! unmodified, in cells through the Linux syscall personality, reading files
//! from a mounted Ichor image.

use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::power::{ExitStatus, shutdown};
use frame::println;
use frame::user::UserContext;

use crate::kcell::{Cell, System};
use crate::loader;
use crate::proc;
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
    pub(super) const POLL: u64 = 7;
    pub(super) const MMAP: u64 = 9;
    pub(super) const MPROTECT: u64 = 10;
    pub(super) const MUNMAP: u64 = 11;
    pub(super) const BRK: u64 = 12;
    pub(super) const SCHED_YIELD: u64 = 24;
    pub(super) const NANOSLEEP: u64 = 35;
    pub(super) const GETPID: u64 = 39;
    pub(super) const EXECVE: u64 = 59;
    pub(super) const FCNTL: u64 = 72;
    pub(super) const CLONE: u64 = 56;
    pub(super) const FORK: u64 = 57;
    pub(super) const EXIT: u64 = 60;
    pub(super) const FUTEX: u64 = 202;
    pub(super) const WAIT4: u64 = 61;
    pub(super) const UNAME: u64 = 63;
    pub(super) const GETCWD: u64 = 79;
    pub(super) const CHDIR: u64 = 80;
    pub(super) const RENAME: u64 = 82;
    pub(super) const MKDIR: u64 = 83;
    pub(super) const RMDIR: u64 = 84;
    pub(super) const UNLINK: u64 = 87;
    pub(super) const GETDENTS64: u64 = 217;
    pub(super) const EPOLL_WAIT: u64 = 232;
    pub(super) const EPOLL_CTL: u64 = 233;
    pub(super) const EVENTFD2: u64 = 290;
    pub(super) const EPOLL_CREATE1: u64 = 291;
    pub(super) const PIPE2: u64 = 293;
    pub(super) const EXIT_GROUP: u64 = 231;
    pub(super) const RT_SIGACTION: u64 = 13;
    pub(super) const RT_SIGRETURN: u64 = 15;
    pub(super) const DUP2: u64 = 33;
    pub(super) const KILL: u64 = 62;
    pub(super) const SIGALTSTACK: u64 = 131;
    pub(super) const PRLIMIT64: u64 = 302;
    pub(super) const MADVISE: u64 = 28;
    pub(super) const RT_SIGPROCMASK: u64 = 14;
    pub(super) const VFORK: u64 = 58;
    pub(super) const PPOLL: u64 = 271;
    pub(super) const EPOLL_PWAIT: u64 = 281;
}

const MOTD: &[u8] = b"hello from /etc/motd inside an Ichor image\n";
const HELLO: &[u8] = b"hello from a real Linux ELF running on Ichor\n";

/// The environment every test program gets.
const ENVP: &[&str] = &[
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root",
    "TERM=dumb",
];

/// Loads `elf` into `p` with `argv`, runs it to exit (on this task; any
/// children it forks run on their own), and checks that all of the cell's
/// memory came back. Returns the exit code (or minus the signal that killed
/// it) and the number of syscalls it made.
pub(crate) fn run_linux(
    p: LinuxProcess,
    elf: &[u8],
    interp: Option<&[u8]>,
    argv: &[&str],
) -> (i32, u32) {
    let loaded = match loader::load(&mut p.mm(), elf, interp, argv, ENVP, 8 << 20) {
        Ok(l) => l,
        Err(e) => {
            println!("ichor: runtest: load error {e:?}");
            fail("could not load the ELF");
        }
    };
    p.group.set_exec(argv.first().copied().unwrap_or(""), argv);
    let cell = p.cell.clone();
    let leader = p.group.leader.clone();
    let ctx = UserContext::new(loaded.entry, loaded.stack_pointer);
    let (_, syscalls) = proc::run(p, ctx);
    // Other threads may still be on their way out; the process's status is
    // known once the last one is.
    let status = loop {
        if let Some(s) = proc::exit_status(&leader) {
            break s;
        }
        frame::task::yield_now();
    };
    if cell.account().used() != 0 {
        println!(
            "ichor: runtest: {} pages still charged",
            cell.account().used()
        );
        fail("process memory was not returned");
    }
    let code = if status & 0x7f == 0 {
        (status >> 8) as i32
    } else {
        -((status & 0x7f) as i32)
    };
    (code, syscalls)
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

/// Copy-on-write fork: the parent stores a value and forks; the child
/// overwrites the same word, checks it reads its own value, and exits 42;
/// the parent checks `wait4` saw 42 and that its own copy is unchanged.
/// Exits 0 if every check held, else the number of the failed check.
fn fork_program() -> Vec<u8> {
    const PARENT: u64 = 0x1111_2222_3333_4444;
    const CHILD: u64 = 0x5555_6666_7777_8888;
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rbx, PARENT);
    a.store(Reg::Rbp, 0, Reg::Rbx);
    a.sys(sys::FORK);
    a.mov(Reg::R12, Reg::Rax);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    // Child: write its own value over the shared word and read it back.
    a.mov_imm(Reg::Rbx, CHILD);
    a.store(Reg::Rbp, 0, Reg::Rbx);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::Rdi, 1);
    a.cmp(Reg::Rax, Reg::Rbx);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 42);
    a.sys(sys::EXIT_GROUP);
    // Parent: wait4(-1, rbp + 16, 0, NULL) == child pid; status == 42 << 8.
    a.bind(parent);
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 16);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.mov_imm(Reg::Rdi, 2);
    a.cmp(Reg::Rax, Reg::R12);
    a.jne(bad);
    a.load(Reg::Rax, Reg::Rbp, 16);
    a.mov_imm(Reg::R14, 42 << 8);
    a.mov_imm(Reg::Rdi, 3);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    // The child's write must not show through.
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R14, PARENT);
    a.mov_imm(Reg::Rdi, 4);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 0);
    a.bind(bad);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Threads and futexes: the main thread maps a stack and clones a thread
/// (pthread-style flags, with PARENT_SETTID and CHILD_CLEARTID); the thread
/// stores 42 into a shared word, futex-wakes, and exits alone (`exit`, not
/// `exit_group`). The main thread futex-waits for the 42, then joins by
/// futex-waiting until the kernel clears the tid word, and checks its pid
/// is unchanged. Exits 0 if every check held, else the failed check.
fn thread_program() -> Vec<u8> {
    const FLAGS: u64 = 0x35_0f00; // VM FS FILES SIGHAND THREAD SYSVSEM PARENT_SETTID CHILD_CLEARTID
    const FUTEX_WAIT_PRIVATE: u64 = 128;
    const FUTEX_WAKE_PRIVATE: u64 = 129;
    let mut a = Asm::new();
    let bad = a.label();
    let main = a.label();
    let wait_value = a.label();
    let got_value = a.label();
    let join = a.label();
    let join_wait = a.label();
    let joined = a.label();
    // rbp -> two shared words below the main stack: [rbp] value, [rbp+8] tid.
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 0, Reg::Rax);
    a.store(Reg::Rbp, 8, Reg::Rax);
    a.sys(sys::GETPID);
    a.mov(Reg::R12, Reg::Rax);
    // r13 = mmap(NULL, 64 KiB, RW, PRIVATE | ANONYMOUS): the thread's stack.
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 0x1_0000);
    a.mov_imm(Reg::Rdx, 3);
    a.mov_imm(Reg::R10, 0x22);
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::R13, Reg::Rax);
    // clone(FLAGS, r13 + 64 KiB, &tid, &tid, 0)
    a.mov_imm(Reg::Rdi, FLAGS);
    a.mov(Reg::Rsi, Reg::R13);
    a.add_imm(Reg::Rsi, 0x1_0000);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, 8);
    a.mov(Reg::R10, Reg::Rdx);
    a.mov_imm(Reg::R8, 0);
    a.sys(sys::CLONE);
    a.mov_imm(Reg::R15, 1);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(main);
    // The thread: store 42, wake one waiter on [rbp], exit alone.
    a.mov_imm(Reg::Rax, 42);
    a.store(Reg::Rbp, 0, Reg::Rax);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, FUTEX_WAKE_PRIVATE);
    a.mov_imm(Reg::Rdx, 1);
    a.sys(sys::FUTEX);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT);
    // Main: wait until [rbp] != 0, then check it is 42.
    a.bind(main);
    a.bind(wait_value);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(got_value);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, FUTEX_WAIT_PRIVATE);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::FUTEX);
    a.jmp(wait_value);
    a.bind(got_value);
    a.mov_imm(Reg::R15, 2);
    a.cmp_imm(Reg::Rax, 42);
    a.jne(bad);
    // Join: wait until the kernel has cleared the tid word.
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
    // Still the same process after the thread left.
    a.sys(sys::GETPID);
    a.mov_imm(Reg::R15, 3);
    a.cmp(Reg::Rax, Reg::R12);
    a.jne(bad);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// TLB shootdown: a thread spins reading a page (so its CPU caches the
/// translation) while the main thread unmaps it and sleeps. The spinning
/// thread must fault, and its SIGSEGV kills the process; if a stale
/// translation survived, the main thread wakes and exits 0 instead.
fn shootdown_program() -> Vec<u8> {
    const FLAGS: u64 = 0x5_0f00; // VM FS FILES SIGHAND THREAD SYSVSEM
    let mut a = Asm::new();
    let main = a.label();
    let spin = a.label();
    let wait_ready = a.label();
    let ready = a.label();
    let sleep_ts = a.data(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // 2 s
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 0, Reg::Rax);
    // r14 = the page to unmap; r13 = the thread's stack.
    for dst in [Reg::R14, Reg::R13] {
        a.mov_imm(Reg::Rdi, 0);
        a.mov_imm(Reg::Rsi, 0x1_0000);
        a.mov_imm(Reg::Rdx, 3);
        a.mov_imm(Reg::R10, 0x22);
        a.mov_imm(Reg::R8, u64::MAX);
        a.mov_imm(Reg::R9, 0);
        a.sys(sys::MMAP);
        a.mov(dst, Reg::Rax);
    }
    a.store(Reg::R14, 0, Reg::Rax); // touch it so it is mapped
    a.mov_imm(Reg::Rdi, FLAGS);
    a.mov(Reg::Rsi, Reg::R13);
    a.add_imm(Reg::Rsi, 0x1_0000);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.mov_imm(Reg::R8, 0);
    a.sys(sys::CLONE);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(main);
    // The thread: say it is running, then read the page forever.
    a.mov_imm(Reg::Rax, 1);
    a.store(Reg::Rbp, 0, Reg::Rax);
    a.bind(spin);
    a.load(Reg::Rax, Reg::R14, 0);
    a.jmp(spin);
    // Main: wait for the thread, unmap the page, sleep, then exit 0 (which
    // only happens if the thread never faulted).
    a.bind(main);
    a.bind(wait_ready);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(ready);
    a.sys(sys::SCHED_YIELD);
    a.jmp(wait_ready);
    a.bind(ready);
    a.mov(Reg::Rdi, Reg::R14);
    a.mov_imm(Reg::Rsi, 0x1_0000);
    a.sys(sys::MUNMAP);
    a.mov_data(Reg::Rdi, sleep_ts);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::NANOSLEEP);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Readiness: poll on an empty pipe times out at once; a blocking poll
/// wakes when a forked child writes 50 ms later; epoll reports the pipe
/// with its registered data; an eventfd counts. Exits 0 if every check
/// held, else the number of the failed check.
fn poll_program() -> Vec<u8> {
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    let x = a.data(b"x");
    let ts = a.data(&[0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0xf0, 0xfa, 0x02, 0, 0, 0, 0]); // 50 ms
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // 1: pipe2 -> fds 3 (read) and 4 (write).
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PIPE2);
    expect(&mut a, 1, 0);
    // 2: poll({fd 3, POLLIN}, 1, 0) == 0 (nothing to read yet).
    a.mov_imm(Reg::Rax, 3 | (1 << 32));
    a.store(Reg::Rbp, 16, Reg::Rax);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 16);
    a.mov_imm(Reg::Rsi, 1);
    a.mov_imm(Reg::Rdx, 0);
    a.sys(sys::POLL);
    expect(&mut a, 2, 0);
    // 3: fork; the child sleeps 50 ms, writes one byte, exits.
    a.sys(sys::FORK);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    a.mov_data(Reg::Rdi, ts);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::NANOSLEEP);
    a.mov_imm(Reg::Rdi, 4);
    a.mov_data(Reg::Rsi, x);
    a.mov_imm(Reg::Rdx, 1);
    a.sys(sys::WRITE);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    // Parent: a blocking poll wakes with POLLIN.
    a.bind(parent);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 16);
    a.mov_imm(Reg::Rsi, 1);
    a.mov_imm(Reg::Rdx, u64::MAX); // -1: no timeout
    a.sys(sys::POLL);
    expect(&mut a, 3, 1);
    a.load(Reg::Rax, Reg::Rbp, 16);
    a.mov_imm(Reg::R14, 3 | (1 << 32) | (1 << 48)); // revents = POLLIN
    a.mov_imm(Reg::R15, 4);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    // 5: epoll_create1 -> 5; add fd 3 with data 0x1234; wait sees it.
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EPOLL_CREATE1);
    expect(&mut a, 5, 5);
    a.mov_imm(Reg::Rax, 1 | (0x1234 << 32));
    a.store(Reg::Rbp, 32, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 40, Reg::Rax);
    a.mov_imm(Reg::Rdi, 5);
    a.mov_imm(Reg::Rsi, 1); // EPOLL_CTL_ADD
    a.mov_imm(Reg::Rdx, 3);
    a.mov(Reg::R10, Reg::Rbp);
    a.add_imm(Reg::R10, 32);
    a.sys(sys::EPOLL_CTL);
    expect(&mut a, 5, 0);
    a.mov_imm(Reg::Rdi, 5);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 64);
    a.mov_imm(Reg::Rdx, 4);
    a.mov_imm(Reg::R10, 100);
    a.sys(sys::EPOLL_WAIT);
    expect(&mut a, 6, 1);
    a.load(Reg::Rax, Reg::Rbp, 64);
    a.mov_imm(Reg::R14, 1 | (0x1234 << 32));
    a.mov_imm(Reg::R15, 6);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    // 7: eventfd2(0, 0) -> 6; write 3; read gives 3.
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::EVENTFD2);
    expect(&mut a, 7, 6);
    a.mov_imm(Reg::Rax, 3);
    a.store(Reg::Rbp, 96, Reg::Rax);
    a.mov_imm(Reg::Rdi, 6);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 96);
    a.mov_imm(Reg::Rdx, 8);
    a.sys(sys::WRITE);
    expect(&mut a, 7, 8);
    a.mov_imm(Reg::Rdi, 6);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 104);
    a.mov_imm(Reg::Rdx, 8);
    a.sys(sys::READ);
    expect(&mut a, 8, 8);
    a.load(Reg::Rax, Reg::Rbp, 104);
    expect(&mut a, 8, 3);
    // Reap the child.
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Close-on-exec: opens a file with and without `O_CLOEXEC` and a pipe with
/// `O_CLOEXEC`, then execs `/bin/sh`, which checks through `/proc/self/fd`
/// that only the plain descriptor survived. Needs a root with busybox.
pub(crate) fn cloexec_program() -> Vec<u8> {
    const O_CLOEXEC: u64 = 0o2_000_000;
    let mut a = Asm::new();
    let motd = a.data(b"/etc/motd\0");
    let sh = a.data(b"/bin/sh\0");
    let arg0 = a.data(b"sh\0");
    let arg1 = a.data(b"-c\0");
    let arg2 = a.data(
        b"[ -L /proc/self/fd/4 ] && [ ! -L /proc/self/fd/3 ] && [ ! -L /proc/self/fd/5 ] \
          && [ ! -L /proc/self/fd/6 ] && echo sh: CLOEXEC descriptors did not survive exec\0",
    );
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // fd 3: O_CLOEXEC; fd 4: plain; fds 5, 6: pipe2(O_CLOEXEC).
    for flags in [O_CLOEXEC, 0] {
        a.mov_data(Reg::Rdi, motd);
        a.mov_imm(Reg::Rsi, flags);
        a.sys(sys::OPEN);
    }
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 64);
    a.mov_imm(Reg::Rsi, O_CLOEXEC);
    a.sys(sys::PIPE2);
    // argv = { "sh", "-c", script, NULL } at rbp.
    for (i, d) in [arg0, arg1, arg2].into_iter().enumerate() {
        a.mov_data(Reg::Rax, d);
        a.store(Reg::Rbp, (i * 8) as i32, Reg::Rax);
    }
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 24, Reg::Rax);
    a.mov_data(Reg::Rdi, sh);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 0);
    a.sys(sys::EXECVE);
    // Only reached if execve failed.
    a.mov_imm(Reg::Rdi, 99);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Resource limits and the alternate signal stack. `RLIMIT_NOFILE` (5, 5)
/// lets fds 3 and 4 open, then `open` fails with EMFILE and `dup2` to 7
/// with EBADF; a hard limit over the table size is EPERM. A SIGUSR1 handler
/// installed with `SA_ONSTACK` runs on the `sigaltstack` stack, finds the
/// stack in its `uc_stack` (flags 0: the interrupted code was not on it),
/// and cannot replace the stack it runs on (EPERM). Exits 0, or the number of the failed check.
fn limits_program() -> Vec<u8> {
    const NOFILE: u64 = 7;
    const SIGUSR1: u64 = 10;
    const SA_ONSTACK_RESTORER: u64 = 0x0C00_0000;
    const ALT_SIZE: i32 = 65536;
    let mut a = Asm::new();
    let bad = a.label();
    let handler = a.label();
    let restorer = a.label();
    let motd = a.data(b"/etc/motd\0");
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    let prlimit = |a: &mut Asm, new: i32, old: i32| {
        a.mov_imm(Reg::Rdi, 0);
        a.mov_imm(Reg::Rsi, NOFILE);
        for (r, off) in [(Reg::Rdx, new), (Reg::R10, old)] {
            if off < 0 {
                a.mov_imm(r, 0);
            } else {
                a.mov(r, Reg::Rbp);
                a.add_imm(r, off);
            }
        }
        a.sys(sys::PRLIMIT64);
    };
    let pair = |a: &mut Asm, soft: u64, hard: u64| {
        a.mov_imm(Reg::Rax, soft);
        a.store(Reg::Rbp, 0, Reg::Rax);
        a.mov_imm(Reg::Rax, hard);
        a.store(Reg::Rbp, 8, Reg::Rax);
    };
    let altstack = |a: &mut Asm| {
        a.mov(Reg::Rdi, Reg::Rbp);
        a.add_imm(Reg::Rdi, 64);
        a.mov_imm(Reg::Rsi, 0);
        a.sys(sys::SIGALTSTACK);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // 1-2: NOFILE (5, 5) set and read back.
    pair(&mut a, 5, 5);
    prlimit(&mut a, 0, -1);
    expect(&mut a, 1, 0);
    pair(&mut a, 0, 0);
    prlimit(&mut a, -1, 0);
    expect(&mut a, 2, 0);
    a.load(Reg::Rax, Reg::Rbp, 0);
    expect(&mut a, 2, 5);
    // 3-6: fds 3 and 4 open; the next is EMFILE; dup2 past the limit EBADF.
    for (n, want) in [(3, 3), (4, 4), (5, -24)] {
        a.mov_data(Reg::Rdi, motd);
        a.mov_imm(Reg::Rsi, 0);
        a.sys(sys::OPEN);
        expect(&mut a, n, want);
    }
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 7);
    a.sys(sys::DUP2);
    expect(&mut a, 6, -9);
    // 7: a hard limit past the table: EPERM.
    pair(&mut a, 5, 4096);
    prlimit(&mut a, 0, -1);
    expect(&mut a, 7, -1);
    // 8-9: stack_t at rbp+64: too small is ENOMEM, then 64 KiB 1 MiB down.
    a.mov(Reg::R13, Reg::Rsp);
    a.sub_imm(Reg::R13, 1 << 20);
    a.store(Reg::Rbp, 64, Reg::R13);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 72, Reg::Rax);
    a.mov_imm(Reg::Rax, 1000);
    a.store(Reg::Rbp, 80, Reg::Rax);
    altstack(&mut a);
    expect(&mut a, 8, -12);
    a.mov_imm(Reg::Rax, ALT_SIZE as u64);
    a.store(Reg::Rbp, 80, Reg::Rax);
    altstack(&mut a);
    expect(&mut a, 9, 0);
    // 10: sigaction(SIGUSR1, { handler, SA_ONSTACK | SA_RESTORER, restorer, 0 }).
    a.mov_label(Reg::Rax, handler);
    a.store(Reg::Rbp, 128, Reg::Rax);
    a.mov_imm(Reg::Rax, SA_ONSTACK_RESTORER);
    a.store(Reg::Rbp, 136, Reg::Rax);
    a.mov_label(Reg::Rax, restorer);
    a.store(Reg::Rbp, 144, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 152, Reg::Rax);
    a.store(Reg::Rbp, 200, Reg::Rax);
    a.mov_imm(Reg::Rdi, SIGUSR1);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 128);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 8);
    a.sys(sys::RT_SIGACTION);
    expect(&mut a, 10, 0);
    a.sys(sys::GETPID);
    a.mov(Reg::Rdi, Reg::Rax);
    a.mov_imm(Reg::Rsi, SIGUSR1);
    a.sys(sys::KILL);
    // 11: uc_stack named the alternate stack, with flags 0.
    a.load(Reg::Rax, Reg::Rbp, 216);
    a.mov_imm(Reg::R15, 11);
    a.cmp(Reg::Rax, Reg::R13);
    a.jne(bad);
    a.load(Reg::Rax, Reg::Rbp, 224);
    expect(&mut a, 11, 0);
    // 12: the handler ran on the alternate stack.
    a.load(Reg::Rax, Reg::Rbp, 200);
    a.mov_imm(Reg::R15, 12);
    a.cmp(Reg::Rax, Reg::R13);
    a.jbe(bad);
    a.add_imm(Reg::R13, ALT_SIZE);
    a.cmp(Reg::Rax, Reg::R13);
    a.ja(bad);
    // 13: replacing its stack was EPERM.
    a.load(Reg::Rax, Reg::Rbp, 208);
    expect(&mut a, 13, -1);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    // The handler: rbp is the interrupted code's; rdx is the ucontext.
    a.bind(handler);
    a.store(Reg::Rbp, 200, Reg::Rsp);
    a.load(Reg::Rax, Reg::Rdx, 16);
    a.store(Reg::Rbp, 216, Reg::Rax);
    a.load(Reg::Rax, Reg::Rdx, 24);
    a.store(Reg::Rbp, 224, Reg::Rax);
    altstack(&mut a);
    a.store(Reg::Rbp, 208, Reg::Rax);
    a.ret();
    a.bind(restorer);
    a.sys(sys::RT_SIGRETURN);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// `madvise`: `MADV_DONTNEED` on an anonymous page brings it back zeroed
/// and leaves its neighbour alone; on a written private file mapping it
/// brings back the file's bytes. A hint is 0, unknown advice EINVAL, an
/// unaligned address EINVAL, an unmapped range ENOMEM. Exits 0, or the
/// number of the failed check.
fn madvise_program() -> Vec<u8> {
    const PROT_RW: u64 = 3;
    const PRIVATE_ANON: u64 = 0x22;
    const PRIVATE: u64 = 0x02;
    const DONTNEED: u64 = 4;
    let mut a = Asm::new();
    let bad = a.label();
    let motd = a.data(b"/etc/motd\0");
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    let madvise = |a: &mut Asm, addr: Reg, off: i32, len: u64, advice: u64| {
        a.mov(Reg::Rdi, addr);
        a.add_imm(Reg::Rdi, off);
        a.mov_imm(Reg::Rsi, len);
        a.mov_imm(Reg::Rdx, advice);
        a.sys(sys::MADVISE);
    };
    // 1: r12 = two anonymous pages, both written.
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 8192);
    a.mov_imm(Reg::Rdx, PROT_RW);
    a.mov_imm(Reg::R10, PRIVATE_ANON);
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::R12, Reg::Rax);
    a.mov_imm(Reg::R13, 0x4141_4141_4141_4141);
    a.store(Reg::R12, 0, Reg::R13);
    a.store(Reg::R12, 4096, Reg::R13);
    // 2-3: DONTNEED the first: it reads 0, the second is untouched.
    madvise(&mut a, Reg::R12, 0, 4096, DONTNEED);
    expect(&mut a, 2, 0);
    a.load(Reg::Rax, Reg::R12, 0);
    expect(&mut a, 3, 0);
    a.load(Reg::Rax, Reg::R12, 4096);
    a.mov_imm(Reg::R15, 3);
    a.cmp(Reg::Rax, Reg::R13);
    a.jne(bad);
    // 4-6: a hint, bad advice, an unaligned address.
    madvise(&mut a, Reg::R12, 0, 8192, 1);
    expect(&mut a, 4, 0);
    madvise(&mut a, Reg::R12, 0, 8192, 999);
    expect(&mut a, 5, -22);
    madvise(&mut a, Reg::R12, 1, 4096, DONTNEED);
    expect(&mut a, 6, -22);
    // 7: past the end of the mapping (unmapped): ENOMEM.
    a.mov(Reg::Rdi, Reg::R12);
    a.mov_imm(Reg::Rsi, 4096);
    a.sys(sys::MUNMAP);
    madvise(&mut a, Reg::R12, 0, 8192, DONTNEED);
    expect(&mut a, 7, -12);
    // 8: r14 = a private writable mapping of /etc/motd; r13 = its first 8 bytes.
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    expect(&mut a, 8, 3);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 4096);
    a.mov_imm(Reg::Rdx, PROT_RW);
    a.mov_imm(Reg::R10, PRIVATE);
    a.mov_imm(Reg::R8, 3);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::R14, Reg::Rax);
    a.load(Reg::R13, Reg::R14, 0);
    // 9-10: overwrite it, DONTNEED it: the file's bytes are back.
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::R14, 0, Reg::Rax);
    madvise(&mut a, Reg::R14, 0, 4096, DONTNEED);
    expect(&mut a, 9, 0);
    a.load(Reg::Rax, Reg::R14, 0);
    a.mov_imm(Reg::R15, 10);
    a.cmp(Reg::Rax, Reg::R13);
    a.jne(bad);
    // 11: and they are the file's, not zeros.
    a.mov(Reg::Rax, Reg::R13);
    a.mov_imm(Reg::R15, 11);
    a.cmp_imm(Reg::Rax, 0);
    a.je(bad);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// `MAP_SHARED | MAP_ANONYMOUS` across fork: the child writes a value and
/// a flag into the shared page and wakes a (non-private) futex on the
/// flag; the parent, waiting on that futex, sees both, and still sees the
/// value after `MADV_DONTNEED`. A private page written by the child stays
/// the parent's. Exits 0, or the number of the failed check.
fn shared_program() -> Vec<u8> {
    const PROT_RW: u64 = 3;
    const SHARED_ANON: u64 = 0x21;
    const PRIVATE_ANON: u64 = 0x22;
    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    let again = a.label();
    let done = a.label();
    let ts = a.data(&[0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0xf0, 0xfa, 0x02, 0, 0, 0, 0]); // 50 ms
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    let map = |a: &mut Asm, flags: u64| {
        a.mov_imm(Reg::Rdi, 0);
        a.mov_imm(Reg::Rsi, 4096);
        a.mov_imm(Reg::Rdx, PROT_RW);
        a.mov_imm(Reg::R10, flags);
        a.mov_imm(Reg::R8, u64::MAX);
        a.mov_imm(Reg::R9, 0);
        a.sys(sys::MMAP);
    };
    let futex = |a: &mut Asm, op: u64, val: u64| {
        a.mov(Reg::Rdi, Reg::R12);
        a.add_imm(Reg::Rdi, 8);
        a.mov_imm(Reg::Rsi, op);
        a.mov_imm(Reg::Rdx, val);
        a.mov_imm(Reg::R10, 0);
        a.sys(sys::FUTEX);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // r12 = shared page (value at 0, flag at 8), r13 = private page.
    map(&mut a, SHARED_ANON);
    a.mov(Reg::R12, Reg::Rax);
    map(&mut a, PRIVATE_ANON);
    a.mov(Reg::R13, Reg::Rax);
    a.mov_imm(Reg::Rax, 1);
    a.store(Reg::R13, 0, Reg::Rax);
    a.sys(sys::FORK);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    // Child: after 50 ms (the parent is asleep on the futex by then),
    // private := 7, value := 42, flag := 1, wake the parent.
    a.mov_data(Reg::Rdi, ts);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::NANOSLEEP);
    a.mov_imm(Reg::Rax, 7);
    a.store(Reg::R13, 0, Reg::Rax);
    a.mov_imm(Reg::Rax, 42);
    a.store(Reg::R12, 0, Reg::Rax);
    a.mov_imm(Reg::Rax, 1);
    a.store(Reg::R12, 8, Reg::Rax);
    futex(&mut a, FUTEX_WAKE, 1);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    // Parent: wait on the flag until it is set.
    a.bind(parent);
    a.bind(again);
    a.load(Reg::Rax, Reg::R12, 8);
    a.cmp_imm(Reg::Rax, 1);
    a.je(done);
    futex(&mut a, FUTEX_WAIT, 0);
    a.jmp(again);
    a.bind(done);
    // 1: the child's value is in the shared page.
    a.load(Reg::Rax, Reg::R12, 0);
    expect(&mut a, 1, 42);
    // 2: the private page is still ours.
    a.load(Reg::Rax, Reg::R13, 0);
    expect(&mut a, 2, 1);
    // 3: MADV_DONTNEED keeps shared contents.
    a.mov(Reg::Rdi, Reg::R12);
    a.mov_imm(Reg::Rsi, 4096);
    a.mov_imm(Reg::Rdx, 4);
    a.sys(sys::MADVISE);
    expect(&mut a, 3, 0);
    a.load(Reg::Rax, Reg::R12, 0);
    expect(&mut a, 3, 42);
    // 4: reap the child; it exited 0.
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R14, 0xffff_ffff);
    a.mov_imm(Reg::R15, 4);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(bad);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Waits done right. An `EPOLLET` pipe entry reports a write once, stays
/// quiet while the data sits unread, and reports the next write. With
/// SIGUSR1 blocked and pending, `ppoll` and `epoll_pwait` given an empty
/// mask are interrupted by it (its handler runs; EINTR), and the blocked
/// mask is back afterwards, also after a `ppoll` that just times out.
/// `vfork` returns only once the child (which sleeps 50 ms first) has
/// exited, so `WNOHANG` reaps it at once. Exits 0, or the failed check.
fn waits_program() -> Vec<u8> {
    const EPOLL_CTL_ADD: u64 = 1;
    const SIGUSR1: u64 = 10;
    const USR1_BIT: i32 = 1 << 9;
    const SA_RESTORER: u64 = 0x0400_0000;
    let mut a = Asm::new();
    let bad = a.label();
    let handler = a.label();
    let restorer = a.label();
    let parent = a.label();
    let ms50 = a.data(&[0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0xf0, 0xfa, 0x02, 0, 0, 0, 0]);
    let sec2 = a.data(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let zero = a.data(&[0; 16]);
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    let epoll_wait = |a: &mut Asm| {
        a.mov_imm(Reg::Rdi, 5);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.add_imm(Reg::Rsi, 64);
        a.mov_imm(Reg::Rdx, 4);
        a.mov_imm(Reg::R10, 0);
        a.sys(sys::EPOLL_WAIT);
    };
    let write1 = |a: &mut Asm| {
        a.mov_imm(Reg::Rdi, 4);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.mov_imm(Reg::Rdx, 1);
        a.sys(sys::WRITE);
    };
    // The mask now (SIG_BLOCK nothing, old into rbp+216) must be USR1 alone.
    let mask_is_usr1 = |a: &mut Asm, n: u64| {
        a.mov_imm(Reg::Rdi, 0);
        a.mov_imm(Reg::Rsi, 0);
        a.mov(Reg::Rdx, Reg::Rbp);
        a.add_imm(Reg::Rdx, 216);
        a.mov_imm(Reg::R10, 8);
        a.sys(sys::RT_SIGPROCMASK);
        a.load(Reg::Rax, Reg::Rbp, 216);
        expect(a, n, USR1_BIT);
    };
    let raise = |a: &mut Asm| {
        a.sys(sys::GETPID);
        a.mov(Reg::Rdi, Reg::Rax);
        a.mov_imm(Reg::Rsi, SIGUSR1);
        a.sys(sys::KILL);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 300, Reg::Rax);
    // 1: pipe (3, 4), epoll 5 watching 3 for EPOLLIN | EPOLLET, data 7.
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PIPE2);
    expect(&mut a, 1, 0);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EPOLL_CREATE1);
    expect(&mut a, 1, 5);
    a.mov_imm(Reg::Rax, 0x0000_0007_8000_0001);
    a.store(Reg::Rbp, 16, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 24, Reg::Rax);
    a.mov_imm(Reg::Rdi, 5);
    a.mov_imm(Reg::Rsi, EPOLL_CTL_ADD);
    a.mov_imm(Reg::Rdx, 3);
    a.mov(Reg::R10, Reg::Rbp);
    a.add_imm(Reg::R10, 16);
    a.sys(sys::EPOLL_CTL);
    expect(&mut a, 1, 0);
    // 2-4: a write is reported once; unread data is not reported again;
    // the next write is.
    write1(&mut a);
    epoll_wait(&mut a);
    expect(&mut a, 2, 1);
    epoll_wait(&mut a);
    expect(&mut a, 3, 0);
    write1(&mut a);
    epoll_wait(&mut a);
    expect(&mut a, 4, 1);
    // 5: SIGUSR1 handler (counts at rbp+300), then block it and raise it.
    a.mov_label(Reg::Rax, handler);
    a.store(Reg::Rbp, 128, Reg::Rax);
    a.mov_imm(Reg::Rax, SA_RESTORER);
    a.store(Reg::Rbp, 136, Reg::Rax);
    a.mov_label(Reg::Rax, restorer);
    a.store(Reg::Rbp, 144, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 152, Reg::Rax);
    a.mov_imm(Reg::Rdi, SIGUSR1);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 128);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 8);
    a.sys(sys::RT_SIGACTION);
    expect(&mut a, 5, 0);
    a.mov_imm(Reg::Rax, USR1_BIT as u64);
    a.store(Reg::Rbp, 208, Reg::Rax);
    a.mov_imm(Reg::Rdi, 0); // SIG_BLOCK
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 208);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 8);
    a.sys(sys::RT_SIGPROCMASK);
    expect(&mut a, 5, 0);
    raise(&mut a);
    // 6-7: ppoll(nothing, 2 s, empty mask): the handler runs, EINTR, and
    // the mask is USR1 again.
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_data(Reg::Rdx, sec2);
    a.mov_data(Reg::R10, zero);
    a.mov_imm(Reg::R8, 8);
    a.sys(sys::PPOLL);
    expect(&mut a, 6, -4);
    a.load(Reg::Rax, Reg::Rbp, 300);
    expect(&mut a, 6, 1);
    mask_is_usr1(&mut a, 7);
    // 8-9: the same through epoll_pwait (the pipe's data is not news, so
    // only the signal can end it).
    raise(&mut a);
    a.mov_imm(Reg::Rdi, 5);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 64);
    a.mov_imm(Reg::Rdx, 4);
    a.mov_imm(Reg::R10, 2000);
    a.mov_data(Reg::R8, zero);
    a.mov_imm(Reg::R9, 8);
    a.sys(sys::EPOLL_PWAIT);
    expect(&mut a, 8, -4);
    a.load(Reg::Rax, Reg::Rbp, 300);
    expect(&mut a, 8, 2);
    mask_is_usr1(&mut a, 9);
    // 10: a ppoll that times out restores the mask too.
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_data(Reg::Rdx, zero);
    a.mov_data(Reg::R10, zero);
    a.mov_imm(Reg::R8, 8);
    a.sys(sys::PPOLL);
    expect(&mut a, 10, 0);
    mask_is_usr1(&mut a, 10);
    // 11: vfork; the child sleeps 50 ms and exits 5.
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 400, Reg::Rax);
    a.sys(sys::VFORK);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    a.mov_data(Reg::Rdi, ms50);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::NANOSLEEP);
    a.mov_imm(Reg::Rdi, 5);
    a.sys(sys::EXIT_GROUP);
    // 11-12: by the time vfork returns, the child is a zombie with status 5.
    a.bind(parent);
    a.mov(Reg::R12, Reg::Rax);
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 400);
    a.mov_imm(Reg::Rdx, 1); // WNOHANG
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.mov_imm(Reg::R15, 11);
    a.cmp(Reg::Rax, Reg::R12);
    a.jne(bad);
    a.load(Reg::Rax, Reg::Rbp, 400);
    expect(&mut a, 12, 0x500);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    a.bind(handler);
    a.load(Reg::Rax, Reg::Rbp, 300);
    a.add_imm(Reg::Rax, 1);
    a.store(Reg::Rbp, 300, Reg::Rax);
    a.ret();
    a.bind(restorer);
    a.sys(sys::RT_SIGRETURN);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// AVX state is per thread and survives signals (ADR-0008). YMM0 is set to
/// all ones; a forked child zeroes its own YMM0 and yields while the parent
/// yields too, and the parent's upper 128 bits must still be ones. A
/// SIGUSR1 handler checks that its frame's `fpstate` carries the XSAVE
/// software bytes (`magic`) and YMM0's upper half (at offset 576, the AVX
/// component), then zeroes YMM0; after `rt_sigreturn` the ones are back.
/// Exits 0, or the number of the failed check.
fn avx_program(magic: u64) -> Vec<u8> {
    const SIGUSR1: u64 = 10;
    const SA_RESTORER: u64 = 0x0400_0000;
    const YMM0_ONES: [u8; 4] = [0xc5, 0xfd, 0x76, 0xc0]; // vpcmpeqd ymm0, ymm0, ymm0
    const YMM0_ZERO: [u8; 4] = [0xc5, 0xfd, 0xef, 0xc0]; // vpxor ymm0, ymm0, ymm0
    let store_ymm0 = |a: &mut Asm, disp: i32| {
        a.raw(&[0xc5, 0xfe, 0x7f, 0x85]); // vmovdqu [rbp + disp32], ymm0
        a.raw(&disp.to_le_bytes());
    };
    let mut a = Asm::new();
    let bad = a.label();
    let handler = a.label();
    let restorer = a.label();
    let parent = a.label();
    let child_loop = a.label();
    let parent_loop = a.label();
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    // The upper 128 bits of the YMM0 stored at rbp+disp are all ones.
    let upper_ones = |a: &mut Asm, n: u64, disp: i32| {
        store_ymm0(a, disp);
        a.load(Reg::Rax, Reg::Rbp, disp + 16);
        expect(a, n, -1);
        a.load(Reg::Rax, Reg::Rbp, disp + 24);
        expect(a, n, -1);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.raw(&YMM0_ONES);
    // 1: across a fork whose child zeroes its own YMM0.
    a.sys(sys::FORK);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    a.raw(&YMM0_ZERO);
    a.mov_imm(Reg::R12, 20);
    a.bind(child_loop);
    a.sys(sys::SCHED_YIELD);
    a.add_imm(Reg::R12, -1);
    a.cmp_imm(Reg::R12, 0);
    a.jne(child_loop);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    a.bind(parent);
    a.mov_imm(Reg::R12, 20);
    a.bind(parent_loop);
    a.sys(sys::SCHED_YIELD);
    a.add_imm(Reg::R12, -1);
    a.cmp_imm(Reg::R12, 0);
    a.jne(parent_loop);
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 400);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    upper_ones(&mut a, 1, 0);
    // 2: sigaction(SIGUSR1, handler); the handler leaves 1 at rbp+300 if
    // its frame was right.
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 300, Reg::Rax);
    a.mov_label(Reg::Rax, handler);
    a.store(Reg::Rbp, 128, Reg::Rax);
    a.mov_imm(Reg::Rax, SA_RESTORER);
    a.store(Reg::Rbp, 136, Reg::Rax);
    a.mov_label(Reg::Rax, restorer);
    a.store(Reg::Rbp, 144, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 152, Reg::Rax);
    a.mov_imm(Reg::Rdi, SIGUSR1);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 128);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 8);
    a.sys(sys::RT_SIGACTION);
    expect(&mut a, 2, 0);
    a.sys(sys::GETPID);
    a.mov(Reg::Rdi, Reg::Rax);
    a.mov_imm(Reg::Rsi, SIGUSR1);
    a.sys(sys::KILL);
    // 3: the handler saw the XSAVE frame; 4: YMM0 is whole again.
    a.load(Reg::Rax, Reg::Rbp, 300);
    expect(&mut a, 3, 1);
    upper_ones(&mut a, 4, 32);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    // The handler: rdx = ucontext; fpstate = uc_mcontext (40) + 192.
    let h_bad = a.label();
    a.bind(handler);
    a.load(Reg::Rax, Reg::Rdx, 40 + 192);
    a.load(Reg::R14, Reg::Rax, 464);
    a.mov_imm(Reg::R13, magic);
    a.cmp(Reg::R14, Reg::R13);
    a.jne(h_bad);
    a.load(Reg::R14, Reg::Rax, 576);
    a.cmp_imm(Reg::R14, -1);
    a.jne(h_bad);
    a.mov_imm(Reg::R14, 1);
    a.store(Reg::Rbp, 300, Reg::R14);
    a.bind(h_bad);
    a.raw(&YMM0_ZERO);
    a.ret();
    a.bind(restorer);
    a.sys(sys::RT_SIGRETURN);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// POSIX record locks across fork: the parent write-locks bytes 0..10; the
/// child's overlapping F_SETLK fails with EAGAIN, F_GETLK names the parent,
/// a disjoint range locks fine, and F_SETLKW blocks until the parent
/// unlocks 50 ms later. Exits 0 if every check held.
fn lock_program() -> Vec<u8> {
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETLKW: u64 = 7;
    const WR: u64 = 1;
    const UN: u64 = 2;
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    let path = a.data(b"/lockfile\0");
    let ts = a.data(&[0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0xf0, 0xfa, 0x02, 0, 0, 0, 0]); // 50 ms
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    // struct flock at rbp: l_type | l_whence << 16, l_start, l_len, l_pid.
    let flock = |a: &mut Asm, ty: u64, start: u64, len: u64| {
        a.mov_imm(Reg::Rax, ty);
        a.store(Reg::Rbp, 0, Reg::Rax);
        a.mov_imm(Reg::Rax, start);
        a.store(Reg::Rbp, 8, Reg::Rax);
        a.mov_imm(Reg::Rax, len);
        a.store(Reg::Rbp, 16, Reg::Rax);
        a.mov_imm(Reg::Rax, 0);
        a.store(Reg::Rbp, 24, Reg::Rax);
    };
    let fcntl = |a: &mut Asm, cmd: u64| {
        a.mov_imm(Reg::Rdi, 3);
        a.mov_imm(Reg::Rsi, cmd);
        a.mov(Reg::Rdx, Reg::Rbp);
        a.sys(sys::FCNTL);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.sys(sys::GETPID);
    a.mov(Reg::R12, Reg::Rax);
    // fd 3 = open("/lockfile", O_CREAT | O_RDWR, 0644)
    a.mov_data(Reg::Rdi, path);
    a.mov_imm(Reg::Rsi, 0o102);
    a.mov_imm(Reg::Rdx, 0o644);
    a.sys(sys::OPEN);
    expect(&mut a, 1, 3);
    flock(&mut a, WR, 0, 10);
    fcntl(&mut a, F_SETLK);
    expect(&mut a, 1, 0);
    a.sys(sys::FORK);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    // Child.
    flock(&mut a, WR, 5, 1);
    fcntl(&mut a, F_SETLK);
    expect(&mut a, 2, -11); // EAGAIN
    flock(&mut a, WR, 5, 1);
    fcntl(&mut a, F_GETLK);
    expect(&mut a, 3, 0);
    a.load(Reg::Rax, Reg::Rbp, 24); // l_pid (and padding, zero)
    a.mov_imm(Reg::R15, 3);
    a.cmp(Reg::Rax, Reg::R12);
    a.jne(bad);
    flock(&mut a, WR, 20, 10);
    fcntl(&mut a, F_SETLK);
    expect(&mut a, 4, 0);
    flock(&mut a, WR, 0, 1);
    fcntl(&mut a, F_SETLKW); // blocks until the parent unlocks
    expect(&mut a, 5, 0);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    // Parent: give the child time to block, unlock, reap it.
    a.bind(parent);
    a.mov_data(Reg::Rdi, ts);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::NANOSLEEP);
    flock(&mut a, UN, 0, 10);
    fcntl(&mut a, F_SETLK);
    expect(&mut a, 6, 0);
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 64);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.load(Reg::Rax, Reg::Rbp, 64);
    a.mov_imm(Reg::R14, 0xffff_ffff);
    a.mov_imm(Reg::R15, 7);
    // The child's exit code is in bits 8..16 of the status: it must be 0.
    a.mov(Reg::Rdx, Reg::Rax);
    a.cmp_imm(Reg::Rdx, 0);
    a.jne(bad);
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
        LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"))
    };

    let (status, syscalls) = run_linux(new_process(), &hello_program(), None, &["hello"]);
    if status != 7 {
        fail("hello did not exit with status 7");
    }
    println!(
        "ichor: linux: static ELF ran via the Linux ABI, exited {status} after {syscalls} syscalls"
    );

    let (status, syscalls) = run_linux(new_process(), &cat_program(), None, &["cat", "/etc/motd"]);
    if status != 0 {
        fail("cat: ENOENT, fd number, read or fstat check failed");
    }
    println!(
        "ichor: linux: cat read /etc/motd through a symlink in the image ({syscalls} syscalls, checks passed)"
    );

    let (status, syscalls) = run_linux(new_process(), &mem_program(), None, &["memtest", "a", "b"]);
    if status != 0 {
        println!("ichor: linux: memtest failed check {status}");
        fail("memtest");
    }
    println!(
        "ichor: linux: brk, mmap, mprotect, munmap, uname, getdents64 ok ({syscalls} syscalls, memory returned)"
    );

    let (status, syscalls) = run_linux(new_process(), &fs_program(), None, &["fstest"]);
    if status != 0 {
        println!("ichor: linux: fstest failed check {status}");
        fail("fstest");
    }
    println!(
        "ichor: linux: copy-on-write root: create, write, copy-up, rename, chdir, unlink, rmdir ok ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(new_process(), &fork_program(), None, &["forktest"]);
    if status != 0 {
        println!("ichor: linux: forktest failed check {status}");
        fail("forktest");
    }
    println!("ichor: linux: copy-on-write fork isolated parent and child ({syscalls} syscalls)");

    let (status, syscalls) = run_linux(new_process(), &thread_program(), None, &["threadtest"]);
    if status != 0 {
        println!("ichor: linux: threadtest failed check {status}");
        fail("threadtest");
    }
    println!(
        "ichor: linux: thread clone, futex wait/wake and join via CHILD_CLEARTID ok ({syscalls} syscalls)"
    );

    let (status, _) = run_linux(new_process(), &shootdown_program(), None, &["shootdown"]);
    if status != -(crate::signal::SIGSEGV as i32) {
        println!("ichor: linux: shootdown test exited {status}, expected SIGSEGV");
        fail("tlb shootdown");
    }
    println!("ichor: linux: munmap shot down a page another thread was reading (it faulted)");

    let (status, syscalls) = run_linux(new_process(), &poll_program(), None, &["polltest"]);
    if status != 0 {
        println!("ichor: linux: polltest failed check {status}");
        fail("polltest");
    }
    println!("ichor: linux: poll timeout and wakeup, epoll, eventfd ok ({syscalls} syscalls)");

    let (status, syscalls) = run_linux(new_process(), &lock_program(), None, &["locktest"]);
    if status != 0 {
        println!("ichor: linux: locktest failed check {status}");
        fail("locktest");
    }
    println!(
        "ichor: linux: fcntl record locks: conflict, F_GETLK, F_SETLKW wakeup ok ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(new_process(), &limits_program(), None, &["limitstest"]);
    if status != 0 {
        println!("ichor: linux: limitstest failed check {status}");
        fail("limitstest");
    }
    println!(
        "ichor: linux: RLIMIT_NOFILE enforced, SA_ONSTACK handler ran on the sigaltstack ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(new_process(), &madvise_program(), None, &["madvisetest"]);
    if status != 0 {
        println!("ichor: linux: madvisetest failed check {status}");
        fail("madvisetest");
    }
    println!(
        "ichor: linux: madvise DONTNEED zero-fills anonymous pages, refills file pages ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(new_process(), &shared_program(), None, &["sharedtest"]);
    if status != 0 {
        println!("ichor: linux: sharedtest failed check {status}");
        fail("sharedtest");
    }
    println!(
        "ichor: linux: MAP_SHARED anonymous memory and its futex are shared across fork ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(new_process(), &waits_program(), None, &["waitstest"]);
    if status != 0 {
        println!("ichor: linux: waitstest failed check {status}");
        fail("waitstest");
    }
    println!(
        "ichor: linux: EPOLLET edges, ppoll/epoll_pwait signal masks, vfork waits for the child ({syscalls} syscalls)"
    );

    // AVX needs XSAVE with the AVX component; CPUs without it skip this.
    const AVX: u64 = 1 << 2;
    if frame::cpu::xstate_features() & AVX != 0 {
        let size = frame::cpu::xstate_size() as u64;
        let magic = 0x4650_5853 | ((size + 4) << 32);
        let (status, syscalls) = run_linux(new_process(), &avx_program(magic), None, &["avxtest"]);
        if status != 0 {
            println!("ichor: linux: avxtest failed check {status}");
            fail("avxtest");
        }
        println!(
            "ichor: linux: AVX state is per thread and survives signals (XSAVE frame, {syscalls} syscalls)"
        );
    } else {
        println!("ichor: linux: no AVX: AVX state test skipped");
    }
}
