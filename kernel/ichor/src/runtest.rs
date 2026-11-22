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
use crate::vfs::Vfs;
use testprog::{Asm, BLOB_VADDR, Reg, static_elf};

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
    pub(super) const GETPRIORITY: u64 = 140;
    pub(super) const SETPRIORITY: u64 = 141;
    pub(super) const FADVISE64: u64 = 221;
    pub(super) const CLOSE_RANGE: u64 = 436;
    pub(super) const MEMFD_CREATE: u64 = 319;
    pub(super) const CLOCK_GETTIME: u64 = 228;
    pub(super) const MKNOD: u64 = 133;
    pub(super) const SYMLINK: u64 = 88;
    pub(super) const SENDFILE: u64 = 40;
    pub(super) const FTRUNCATE: u64 = 77;
    pub(super) const LSEEK: u64 = 8;
    pub(super) const CLOCK_GETRES: u64 = 229;
    pub(super) const FALLOCATE: u64 = 285;
    pub(super) const SYNC_FILE_RANGE: u64 = 277;
    pub(super) const MEMBARRIER: u64 = 324;
    pub(super) const SETXATTR: u64 = 188;
    pub(super) const WAITID: u64 = 247;
    pub(super) const PREADV: u64 = 295;
    pub(super) const RT_SIGPENDING: u64 = 127;
    pub(super) const SCHED_GET_PRIORITY_MAX: u64 = 146;
    pub(super) const SCHED_SETAFFINITY: u64 = 203;
    pub(super) const SCHED_GETAFFINITY: u64 = 204;
    pub(super) const CLOCK_SETTIME: u64 = 227;
    pub(super) const GETXATTR: u64 = 191;
    pub(super) const LISTXATTR: u64 = 194;
    pub(super) const GETTID: u64 = 186;
    pub(super) const SET_ROBUST_LIST: u64 = 273;
    pub(super) const READLINK: u64 = 89;
    pub(super) const CLOCK_NANOSLEEP: u64 = 230;
    pub(super) const PREAD64: u64 = 17;
    pub(super) const PWRITE64: u64 = 18;
    pub(super) const MSYNC: u64 = 26;
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
    pub(super) const MREMAP: u64 = 25;
    pub(super) const PRCTL: u64 = 157;
    pub(super) const SENDMSG: u64 = 46;
    pub(super) const RECVMSG: u64 = 47;
    pub(super) const SOCKETPAIR: u64 = 53;
    pub(super) const GETSOCKOPT: u64 = 55;
    pub(super) const IO_URING_SETUP: u64 = 425;
    pub(super) const IO_URING_ENTER: u64 = 426;
    pub(super) const IO_URING_REGISTER: u64 = 427;
}

/// io_uring completions without `io_uring_enter` (the ring's worker): a
/// READ armed on an empty pipe completes, after a forked child writes, while
/// the program blocks reading an eventfd registered with the ring; then
/// again while it waits on the ring descriptor with `epoll_wait`. Exiting
/// with the worker alive must not hang. The exit code is the failing check.
fn uring_worker_program() -> Vec<u8> {
    use ::uring::abi;
    let Ok(l) = ::uring::setup(8, 0, 0) else {
        fail("uring layout");
    };
    let mut a = Asm::new();
    let bad = a.label();
    let x = a.data(b"x");
    let ms50 = a.data(&[0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0xf0, 0xfa, 0x02, 0, 0, 0, 0]);
    let expect = |a: &mut Asm, n: u64, v: u64| {
        a.mov_imm(Reg::R15, n);
        a.mov_imm(Reg::R14, v);
        a.cmp(Reg::Rax, Reg::R14);
        a.jne(bad);
    };
    // A READ of one byte from fd 3 into rbp+512+slot, in SQE `slot`.
    let read_sqe = |a: &mut Asm, slot: i32, ud: u64| {
        let words = [u64::from(abi::OP_READ) | (3 << 32), 0, 0, 1, ud, 0, 0, 0];
        for (k, w) in words.iter().enumerate() {
            a.mov_imm(Reg::Rax, *w);
            a.store(Reg::R13, slot * 64 + 8 * k as i32, Reg::Rax);
        }
        a.mov(Reg::Rax, Reg::Rbp);
        a.add_imm(Reg::Rax, 512 + slot);
        a.store(Reg::R13, slot * 64 + 16, Reg::Rax);
        a.mov_imm(Reg::Rax, slot as u64);
        a.store32(Reg::R12, l.sq.array as i32 + 4 * slot, Reg::Rax);
        a.mov_imm(Reg::Rax, slot as u64 + 1);
        a.store32(Reg::R12, l.sq.tail as i32, Reg::Rax);
        // Submit only: no GETEVENTS, nobody waits in the ring.
        a.mov_imm(Reg::Rdi, 5);
        a.mov_imm(Reg::Rsi, 1);
        a.mov_imm(Reg::Rdx, 0);
        a.mov_imm(Reg::R10, 0);
        a.mov_imm(Reg::R8, 0);
        a.mov_imm(Reg::R9, 0);
        a.sys(sys::IO_URING_ENTER);
    };
    // A child that writes one byte to the pipe after 50 ms.
    let child_writes = |a: &mut Asm| {
        let parent = a.label();
        a.sys(sys::FORK);
        a.cmp_imm(Reg::Rax, 0);
        a.jne(parent);
        a.mov_data(Reg::Rdi, ms50);
        a.mov_imm(Reg::Rsi, 0);
        a.sys(sys::NANOSLEEP);
        a.mov_imm(Reg::Rdi, 4);
        a.mov_data(Reg::Rsi, x);
        a.mov_imm(Reg::Rdx, 1);
        a.sys(sys::WRITE);
        a.mov_imm(Reg::Rdi, 0);
        a.sys(sys::EXIT_GROUP);
        a.bind(parent);
    };
    let reap = |a: &mut Asm| {
        a.mov_imm(Reg::Rdi, u64::MAX);
        a.mov_imm(Reg::Rsi, 0);
        a.mov_imm(Reg::Rdx, 0);
        a.mov_imm(Reg::R10, 0);
        a.sys(sys::WAIT4);
    };
    let cqe = |a: &mut Asm, n: u64, i: i32, ud: u64, res: u64| {
        a.load32(Reg::Rax, Reg::R12, l.cq.tail as i32);
        expect(a, n, i as u64 + 1);
        a.load(Reg::Rax, Reg::R12, l.cq.cqes as i32 + 16 * i);
        expect(a, n, ud);
        a.load32(Reg::Rax, Reg::R12, l.cq.cqes as i32 + 16 * i + 8);
        expect(a, n, res);
        a.mov_imm(Reg::Rax, i as u64 + 1);
        a.store32(Reg::R12, l.cq.head as i32, Reg::Rax);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 8192);
    // 1: the pipe (3, 4), the ring (5), an eventfd (6).
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 256);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PIPE2);
    expect(&mut a, 1, 0);
    a.mov_imm(Reg::Rax, 0);
    for k in 0..15 {
        a.store(Reg::Rbp, 8 * k, Reg::Rax);
    }
    a.mov_imm(Reg::Rdi, 8);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::IO_URING_SETUP);
    expect(&mut a, 1, 5);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::EVENTFD2);
    expect(&mut a, 1, 6);
    for (reg, len, off) in [
        (Reg::R12, l.ring_bytes, abi::OFF_SQ_RING),
        (Reg::R13, l.sqes_bytes, abi::OFF_SQES),
    ] {
        a.mov_imm(Reg::Rdi, 0);
        a.mov_imm(Reg::Rsi, len);
        a.mov_imm(Reg::Rdx, 3);
        a.mov_imm(Reg::R10, 1);
        a.mov_imm(Reg::R8, 5);
        a.mov_imm(Reg::R9, off);
        a.sys(sys::MMAP);
        a.mov_imm(Reg::R15, 2);
        a.mov_imm(Reg::R14, (-4096i64) as u64);
        a.cmp(Reg::Rax, Reg::R14);
        a.ja(bad);
        a.mov(reg, Reg::Rax);
    }
    // 3: register the eventfd.
    a.mov_imm(Reg::Rax, 6);
    a.store(Reg::Rbp, 128, Reg::Rax);
    a.mov_imm(Reg::Rdi, 5);
    a.mov_imm(Reg::Rsi, u64::from(abi::REGISTER_EVENTFD));
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, 128);
    a.mov_imm(Reg::R10, 1);
    a.sys(sys::IO_URING_REGISTER);
    expect(&mut a, 3, 0);
    // 4: a READ armed on the empty pipe; nothing completes yet.
    read_sqe(&mut a, 0, 1);
    expect(&mut a, 4, 1);
    a.load32(Reg::Rax, Reg::R12, l.cq.tail as i32);
    expect(&mut a, 4, 0);
    // 5: the child writes; the parent blocks on the eventfd, not the ring.
    child_writes(&mut a);
    a.mov_imm(Reg::Rdi, 6);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 160);
    a.mov_imm(Reg::Rdx, 8);
    a.sys(sys::READ);
    expect(&mut a, 5, 8);
    cqe(&mut a, 6, 0, 1, 1);
    reap(&mut a);
    // 7: again, waiting on the ring descriptor with epoll (fd 7).
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EPOLL_CREATE1);
    expect(&mut a, 7, 7);
    a.mov_imm(Reg::Rax, 1 | (0x5a << 32)); // EPOLLIN, data 0x5a
    a.store(Reg::Rbp, 32, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 40, Reg::Rax);
    a.mov_imm(Reg::Rdi, 7);
    a.mov_imm(Reg::Rsi, 1); // EPOLL_CTL_ADD
    a.mov_imm(Reg::Rdx, 5);
    a.mov(Reg::R10, Reg::Rbp);
    a.add_imm(Reg::R10, 32);
    a.sys(sys::EPOLL_CTL);
    expect(&mut a, 7, 0);
    read_sqe(&mut a, 1, 2);
    expect(&mut a, 8, 1);
    child_writes(&mut a);
    a.mov_imm(Reg::Rdi, 7);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 64);
    a.mov_imm(Reg::Rdx, 4);
    a.mov_imm(Reg::R10, 10_000); // ms; a hang shows as a timeout
    a.sys(sys::EPOLL_WAIT);
    expect(&mut a, 9, 1);
    a.load(Reg::Rax, Reg::Rbp, 64);
    expect(&mut a, 9, 1 | (0x5a << 32));
    cqe(&mut a, 10, 1, 2, 1);
    reap(&mut a);
    // 11: exit with the worker still running (it must not hold us up).
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// io_uring (ADR-0013 §1) from ring 3: a ring set up and mapped; a write
/// linked to a read through a pipe, beside a NOP, all completed by one
/// `io_uring_enter`; a read of an empty pipe armed, then completed by a
/// forked child's write while the parent waits; a timeout; an unknown
/// opcode refused; the probe. The exit code is the failing check.
fn uring_program() -> Vec<u8> {
    use ::uring::abi;
    let Ok(l) = ::uring::setup(8, 0, 0) else {
        fail("uring layout");
    };
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    let text = a.data(b"uring!");
    let x = a.data(b"x");
    let ms50 = a.data(&[0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0xf0, 0xfa, 0x02, 0, 0, 0, 0]);
    let ms20 = a.data(&[0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x2d, 0x31, 0x01, 0, 0, 0, 0]);
    let expect = |a: &mut Asm, n: u64, v: u64| {
        a.mov_imm(Reg::R15, n);
        a.mov_imm(Reg::R14, v);
        a.cmp(Reg::Rax, Reg::R14);
        a.jne(bad);
    };
    // SQE `slot`: (opcode, flags, fd), off, addr, len, user_data.
    let sqe = |a: &mut Asm,
               slot: i32,
               op: u8,
               flags: u8,
               fd: i32,
               off: u64,
               addr: Option<(Reg, i32)>,
               len: u32,
               ud: u64| {
        let w0 = u64::from(op) | (u64::from(flags) << 8) | (u64::from(fd as u32) << 32);
        let words = [w0, off, 0, u64::from(len), ud, 0, 0, 0];
        for (k, w) in words.iter().enumerate() {
            a.mov_imm(Reg::Rax, *w);
            a.store(Reg::R13, slot * 64 + 8 * k as i32, Reg::Rax);
        }
        if let Some((base, disp)) = addr {
            a.mov(Reg::Rax, base);
            a.add_imm(Reg::Rax, disp);
            a.store(Reg::R13, slot * 64 + 16, Reg::Rax);
        }
        // The SQ array names the slot, then the tail moves past it.
        a.mov_imm(Reg::Rax, slot as u64);
        a.store32(Reg::R12, l.sq.array as i32 + 4 * slot, Reg::Rax);
        a.mov_imm(Reg::Rax, slot as u64 + 1);
        a.store32(Reg::R12, l.sq.tail as i32, Reg::Rax);
    };
    let enter = |a: &mut Asm, submit: u64, min: u64, flags: u64| {
        a.mov_imm(Reg::Rdi, 5);
        a.mov_imm(Reg::Rsi, submit);
        a.mov_imm(Reg::Rdx, min);
        a.mov_imm(Reg::R10, flags);
        a.mov_imm(Reg::R8, 0);
        a.mov_imm(Reg::R9, 0);
        a.sys(sys::IO_URING_ENTER);
    };
    let cqe = |a: &mut Asm, n: u64, i: i32, ud: u64, res: i32| {
        a.load(Reg::Rax, Reg::R12, l.cq.cqes as i32 + 16 * i);
        expect(a, n, ud);
        a.load32(Reg::Rax, Reg::R12, l.cq.cqes as i32 + 16 * i + 8);
        expect(a, n, u64::from(res as u32));
    };
    let cq_tail = |a: &mut Asm, n: u64, v: u64| {
        a.load32(Reg::Rax, Reg::R12, l.cq.tail as i32);
        expect(a, n, v);
    };
    let set_cq_head = |a: &mut Asm, v: u64| {
        a.mov_imm(Reg::Rax, v);
        a.store32(Reg::R12, l.cq.head as i32, Reg::Rax);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 8192);
    // 1: a pipe (fds 3 and 4).
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 256);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PIPE2);
    expect(&mut a, 1, 0);
    // 2: io_uring_setup(8, zeroed params) is fd 5; the params say 8
    // entries and our features.
    a.mov_imm(Reg::Rax, 0);
    for k in 0..15 {
        a.store(Reg::Rbp, 8 * k, Reg::Rax);
    }
    a.mov_imm(Reg::Rdi, 8);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::IO_URING_SETUP);
    expect(&mut a, 2, 5);
    a.load32(Reg::Rax, Reg::Rbp, 0);
    expect(&mut a, 2, 8);
    a.load32(Reg::Rax, Reg::Rbp, 20);
    expect(&mut a, 2, u64::from(::uring::FEATURES));
    // 3: map the rings and the SQEs.
    for (reg, len, off) in [
        (Reg::R12, l.ring_bytes, abi::OFF_SQ_RING),
        (Reg::R13, l.sqes_bytes, abi::OFF_SQES),
    ] {
        a.mov_imm(Reg::Rdi, 0);
        a.mov_imm(Reg::Rsi, len);
        a.mov_imm(Reg::Rdx, 3); // PROT_READ | PROT_WRITE
        a.mov_imm(Reg::R10, 1); // MAP_SHARED
        a.mov_imm(Reg::R8, 5);
        a.mov_imm(Reg::R9, off);
        a.sys(sys::MMAP);
        a.mov_imm(Reg::R15, 3);
        a.mov_imm(Reg::R14, (-4096i64) as u64);
        a.cmp(Reg::Rax, Reg::R14);
        a.ja(bad);
        a.mov(reg, Reg::Rax);
    }
    a.load32(Reg::Rax, Reg::R12, l.sq.ring_entries as i32);
    expect(&mut a, 3, 8);
    // 4: WRITE "uring!" to the pipe, linked to a READ of it; a NOP beside.
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 512, Reg::Rax);
    a.mov_data(Reg::Rbx, text);
    sqe(
        &mut a,
        0,
        abi::OP_WRITE,
        abi::SQE_IO_LINK,
        4,
        0,
        Some((Reg::Rbx, 0)),
        6,
        1,
    );
    sqe(
        &mut a,
        1,
        abi::OP_READ,
        0,
        3,
        0,
        Some((Reg::Rbp, 512)),
        6,
        2,
    );
    sqe(&mut a, 2, abi::OP_NOP, 0, -1, 0, None, 0, 3);
    enter(&mut a, 3, 3, u64::from(abi::ENTER_GETEVENTS));
    expect(&mut a, 4, 3);
    // 5: three CQEs: the write, the NOP, then the read it unblocked.
    cq_tail(&mut a, 5, 3);
    cqe(&mut a, 5, 0, 1, 6);
    cqe(&mut a, 6, 1, 3, 0);
    cqe(&mut a, 7, 2, 2, 6);
    a.load(Reg::Rax, Reg::Rbp, 512);
    expect(&mut a, 8, u64::from_le_bytes(*b"uring!\0\0"));
    set_cq_head(&mut a, 3);
    // 9: a READ of the empty pipe is armed, not completed.
    sqe(
        &mut a,
        3,
        abi::OP_READ,
        0,
        3,
        0,
        Some((Reg::Rbp, 600)),
        1,
        4,
    );
    enter(&mut a, 1, 0, 0);
    expect(&mut a, 9, 1);
    cq_tail(&mut a, 9, 3);
    // 10: a child writes after 50 ms; the parent's wait completes it.
    a.sys(sys::FORK);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    a.mov_data(Reg::Rdi, ms50);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::NANOSLEEP);
    a.mov_imm(Reg::Rdi, 4);
    a.mov_data(Reg::Rsi, x);
    a.mov_imm(Reg::Rdx, 1);
    a.sys(sys::WRITE);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    a.bind(parent);
    enter(&mut a, 0, 1, u64::from(abi::ENTER_GETEVENTS));
    expect(&mut a, 10, 0);
    cq_tail(&mut a, 10, 4);
    cqe(&mut a, 11, 3, 4, 1);
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    set_cq_head(&mut a, 4);
    // 12: a 20 ms TIMEOUT ends with -ETIME.
    a.mov_data(Reg::Rbx, ms20);
    sqe(
        &mut a,
        4,
        abi::OP_TIMEOUT,
        0,
        -1,
        0,
        Some((Reg::Rbx, 0)),
        1,
        5,
    );
    enter(&mut a, 1, 1, u64::from(abi::ENTER_GETEVENTS));
    expect(&mut a, 12, 1);
    cqe(&mut a, 12, 4, 5, -62);
    // 13: an unknown opcode is -EINVAL.
    sqe(&mut a, 5, 200, 0, -1, 0, None, 0, 6);
    enter(&mut a, 1, 1, u64::from(abi::ENTER_GETEVENTS));
    expect(&mut a, 13, 1);
    cqe(&mut a, 13, 5, 6, -22);
    // 14: the probe: last op MKDIRAT (37), 38 ops listed.
    a.mov_imm(Reg::Rdi, 5);
    a.mov_imm(Reg::Rsi, u64::from(abi::REGISTER_PROBE));
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, 1024);
    a.mov_imm(Reg::R10, 64);
    a.sys(sys::IO_URING_REGISTER);
    expect(&mut a, 14, 0);
    a.load(Reg::Rax, Reg::Rbp, 1024);
    expect(&mut a, 14, 37 | (38 << 8));
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
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
    let interp = interp.map(crate::file::Bytes);
    let loaded = match loader::load(
        &mut p.mm(),
        &crate::file::Bytes(elf),
        interp.as_ref().map(|f| f as &dyn crate::file::File),
        argv,
        ENVP,
        8 << 20,
    ) {
        Ok(l) => l,
        Err(e) => {
            println!("ichor: runtest: load error {e:?}");
            fail("could not load the ELF");
        }
    };
    let path = argv.first().copied().unwrap_or("");
    let name = path.rsplit('/').next().unwrap_or("");
    p.group.set_exec(path, name, argv);
    let cell = p.cell.clone();
    // A root that opted out of page sharing charges its private cache pages
    // to the cell too; those are the root's, not the process's.
    let cache_ns = p.vfs.private_ns();
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
    // Orphans the program left (killed, or exiting on their own) may still
    // be on their way out: give the cell's other processes time to go.
    let deadline = frame::time::now() + core::time::Duration::from_secs(30);
    let cached = loop {
        let cached = cache_ns.map_or(0, |ns| crate::pagecache::private_pages(ns) as u64);
        if cell.account().used() == cached || frame::time::now() > deadline {
            break cached;
        }
        frame::task::yield_now();
    };
    if cell.account().used() != cached {
        let (threads, procs, _) = proc::census(cell.id());
        println!("ichor: runtest: {procs} processes ({threads} threads) still live in the cell");
        println!(
            "ichor: runtest: {} pages still charged ({cached} private cache pages)",
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

/// The direction flag belongs to user code: a backward `rep movsq` (what
/// memmove does for overlapping copies) into 16 untouched pages faults on
/// each page mid-copy, and must resume backward each time; then DF must
/// survive a syscall. Exits 0, or 1 if the copy came out wrong, 2 if DF
/// was lost across the syscall. (Clearing DF dropped it at every return
/// to ring 3, and memmoves interrupted that way corrupted heaps.)
fn direction_program() -> Vec<u8> {
    const QWORDS: i32 = 0x1_0000 / 8;
    const STD: u8 = 0xfd;
    const CLD: u8 = 0xfc;
    let mut a = Asm::new();
    let fill = a.label();
    let check = a.label();
    let bad_copy = a.label();
    let bad_flag = a.label();
    // r12 = source, rbx = destination: 64 KiB each, untouched.
    for dst in [Reg::R12, Reg::Rbx] {
        a.mov_imm(Reg::Rdi, 0);
        a.mov_imm(Reg::Rsi, 0x1_0000);
        a.mov_imm(Reg::Rdx, 3);
        a.mov_imm(Reg::R10, 0x22);
        a.mov_imm(Reg::R8, u64::MAX);
        a.mov_imm(Reg::R9, 0);
        a.sys(sys::MMAP);
        a.mov(dst, Reg::Rax);
    }
    // Source qword i holds i + 1.
    a.mov_imm(Reg::Rax, 1);
    a.mov(Reg::Rdx, Reg::R12);
    a.bind(fill);
    a.store(Reg::Rdx, 0, Reg::Rax);
    a.add_imm(Reg::Rdx, 8);
    a.add_imm(Reg::Rax, 1);
    a.cmp_imm(Reg::Rax, QWORDS + 1);
    a.jne(fill);
    // Copy from the last qword down.
    a.mov(Reg::Rsi, Reg::R12);
    a.add_imm(Reg::Rsi, 0x1_0000 - 8);
    a.mov(Reg::Rdi, Reg::Rbx);
    a.add_imm(Reg::Rdi, 0x1_0000 - 8);
    a.mov_imm(Reg::Rcx, QWORDS as u64);
    a.raw(&[STD, 0xf3, 0x48, 0xa5, CLD]); // std; rep movsq; cld
    a.mov_imm(Reg::Rax, 1);
    a.mov(Reg::Rdx, Reg::Rbx);
    a.bind(check);
    a.load(Reg::Rcx, Reg::Rdx, 0);
    a.cmp(Reg::Rcx, Reg::Rax);
    a.jne(bad_copy);
    a.add_imm(Reg::Rdx, 8);
    a.add_imm(Reg::Rax, 1);
    a.cmp_imm(Reg::Rax, QWORDS + 1);
    a.jne(check);
    // DF across a syscall.
    a.raw(&[STD]);
    a.sys(sys::GETPID);
    a.raw(&[0x9c, 0x58, CLD]); // pushfq; pop rax; cld
    a.raw(&[0xa9, 0x00, 0x04, 0x00, 0x00]); // test eax, 0x400
    a.je(bad_flag);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    a.bind(bad_copy);
    a.mov_imm(Reg::Rdi, 1);
    a.sys(sys::EXIT_GROUP);
    a.bind(bad_flag);
    a.mov_imm(Reg::Rdi, 2);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// What CPython's subprocess and os modules call: `close_range` closes a
/// pipe's two ends (fds 3 and 4) and nothing below them; `fadvise64` checks
/// its descriptor; the nice value reads 0 (raw 20), rises to 5 (raw 15),
/// and cannot be lowered again; `memfd_create` gives a close-on-exec file
/// that keeps what is written. Exits 0, or the number of the failed check.
fn misc_program() -> Vec<u8> {
    const F_GETFD: u64 = 1;
    let neg = |e: i64| (-e) as u64;
    let mut a = Asm::new();
    let bad = a.label();
    let check = |a: &mut Asm, n: u64, want: u64| {
        a.mov_imm(Reg::R14, want);
        a.mov_imm(Reg::Rdi, n);
        a.cmp(Reg::Rax, Reg::R14);
        a.jne(bad);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PIPE2);
    check(&mut a, 1, 0);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_imm(Reg::Rsi, u64::from(u32::MAX));
    a.mov_imm(Reg::Rdx, 0);
    a.sys(sys::CLOSE_RANGE);
    check(&mut a, 2, 0);
    for (n, fd, want) in [(3, 3, neg(9)), (4, 4, neg(9)), (5, 2, 0)] {
        a.mov_imm(Reg::Rdi, fd);
        a.mov_imm(Reg::Rsi, F_GETFD);
        a.sys(sys::FCNTL);
        check(&mut a, n, want);
    }
    a.mov_imm(Reg::Rdi, 3); // closed
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::FADVISE64);
    check(&mut a, 6, neg(9));
    for (n, call, value, want) in [
        (7, sys::GETPRIORITY, 0, 20),
        (8, sys::SETPRIORITY, 5, 0),
        (9, sys::GETPRIORITY, 0, 15),
        (10, sys::SETPRIORITY, 0, neg(13)),
    ] {
        a.mov_imm(Reg::Rdi, 0); // PRIO_PROCESS
        a.mov_imm(Reg::Rsi, 0); // the caller
        a.mov_imm(Reg::Rdx, value);
        a.sys(call);
        check(&mut a, n, want);
    }
    // memfd_create("m", MFD_CLOEXEC) is the lowest free fd (3), close-on-
    // exec, and holds what is written; MFD_HUGETLB is EINVAL.
    let name = a.data(b"m\0");
    let text = a.data(b"memfd");
    a.mov_data(Reg::Rdi, name);
    a.mov_imm(Reg::Rsi, 1);
    a.sys(sys::MEMFD_CREATE);
    check(&mut a, 11, 3);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_imm(Reg::Rsi, F_GETFD);
    a.sys(sys::FCNTL);
    check(&mut a, 12, 1);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_data(Reg::Rsi, text);
    a.mov_imm(Reg::Rdx, 5);
    a.sys(sys::WRITE);
    check(&mut a, 13, 5);
    a.mov_imm(Reg::Rdi, 3);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 8);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::PREAD64);
    check(&mut a, 14, 5);
    a.load(Reg::Rax, Reg::Rbp, 0);
    check(
        &mut a,
        15,
        u64::from_le_bytes(*b"memfd\0\0\0") & 0xff_ffff_ffff,
    );
    a.mov_data(Reg::Rdi, name);
    a.mov_imm(Reg::Rsi, 4);
    a.sys(sys::MEMFD_CREATE);
    check(&mut a, 16, neg(22));
    // clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME) until the next whole
    // second, and the clock is past it afterwards; CPU clocks are ENOTSUP.
    a.mov_imm(Reg::Rdi, 1);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 16);
    a.sys(sys::CLOCK_GETTIME);
    a.load(Reg::Rax, Reg::Rbp, 16);
    a.add_imm(Reg::Rax, 1);
    a.store(Reg::Rbp, 16, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 24, Reg::Rax);
    a.mov_imm(Reg::Rdi, 1);
    a.mov_imm(Reg::Rsi, 1);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, 16);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::CLOCK_NANOSLEEP);
    check(&mut a, 17, 0);
    a.mov_imm(Reg::Rdi, 1);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 32);
    a.sys(sys::CLOCK_GETTIME);
    a.load(Reg::Rax, Reg::Rbp, 16);
    a.load(Reg::Rcx, Reg::Rbp, 32);
    a.mov_imm(Reg::Rdi, 18);
    a.cmp(Reg::Rax, Reg::Rcx);
    a.ja(bad); // woke before the deadline's second
    a.mov_imm(Reg::Rdi, 2);
    a.mov_imm(Reg::Rsi, 0);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, 16);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::CLOCK_NANOSLEEP);
    check(&mut a, 19, neg(95));
    // Names are bytes: a directory named "x\xff" is made, entered, and
    // getcwd gives the same bytes back; a symlink's non-UTF-8 target reads
    // back unchanged.
    let dir = a.data(b"/x\xff\0");
    let target = a.data(b"t\xfe\0");
    let link = a.data(b"/l\0");
    a.mov_data(Reg::Rdi, dir);
    a.mov_imm(Reg::Rsi, 0o755);
    a.sys(sys::MKDIR);
    check(&mut a, 20, 0);
    a.mov_data(Reg::Rdi, dir);
    a.sys(sys::CHDIR);
    check(&mut a, 21, 0);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, 64);
    a.sys(sys::GETCWD);
    check(&mut a, 22, 4);
    a.load32(Reg::Rax, Reg::Rbp, 0);
    check(&mut a, 23, u64::from(u32::from_le_bytes(*b"/x\xff\0")));
    a.mov_data(Reg::Rdi, target);
    a.mov_data(Reg::Rsi, link);
    a.sys(sys::SYMLINK);
    check(&mut a, 24, 0);
    a.mov_data(Reg::Rdi, link);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 64);
    a.sys(sys::READLINK);
    check(&mut a, 25, 2);
    a.load32(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::Rcx, 0xffff);
    a.raw(&[0x48, 0x21, 0xc8]); // and rax, rcx
    check(&mut a, 26, u64::from(u16::from_le_bytes(*b"t\xfe")));
    // clock_getres(CLOCK_MONOTONIC) is 1 ns; fallocate grows the memfd
    // (fd 3) to 8 KiB; sync_file_range and membarrier's query succeed;
    // /dev/shm exists.
    a.mov_imm(Reg::Rdi, 1);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::CLOCK_GETRES);
    check(&mut a, 27, 0);
    a.load(Reg::Rax, Reg::Rbp, 8);
    check(&mut a, 28, 1);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 8192);
    a.sys(sys::FALLOCATE);
    check(&mut a, 29, 0);
    a.mov_imm(Reg::Rdi, 3);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::FSTAT);
    a.load(Reg::Rax, Reg::Rbp, 48); // st_size
    check(&mut a, 30, 8192);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::SYNC_FILE_RANGE);
    check(&mut a, 31, 0);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::MEMBARRIER);
    check(&mut a, 32, 0);
    let shm = a.data(b"/dev/shm\0");
    a.mov_data(Reg::Rdi, shm);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::STAT);
    check(&mut a, 33, 0);
    // No extended attributes: an empty list, ENODATA, ENOTSUP; a missing
    // file is ENOENT.
    let attr = a.data(b"user.x\0");
    let nope = a.data(b"/nope\0");
    for (n, call, path, want) in [
        (34, sys::LISTXATTR, shm, 0),
        (35, sys::GETXATTR, shm, neg(61)),
        (36, sys::SETXATTR, shm, neg(95)),
        (37, sys::LISTXATTR, nope, neg(2)),
    ] {
        a.mov_data(Reg::Rdi, path);
        if call == sys::LISTXATTR {
            a.mov_imm(Reg::Rsi, 0);
            a.mov_imm(Reg::Rdx, 0);
        } else {
            a.mov_data(Reg::Rsi, attr);
            a.mov(Reg::Rdx, Reg::Rbp);
            a.mov_imm(Reg::R10, 1);
            a.mov_imm(Reg::R8, 0);
        }
        a.sys(call);
        check(&mut a, n, want);
    }
    a.mov_imm(Reg::Rdi, 0);
    a.bind(bad);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// sendfile reports what it wrote: from a 1 MiB file into a non-blocking
/// AF_UNIX stream socket nobody reads, the first call sends part of the
/// file (more than 0, less than all; never EAGAIN after progress) and
/// leaves the file offset there; the next call, with no room, is EAGAIN.
/// Exits 0, or the failed check.
fn sendfile_program() -> Vec<u8> {
    const SOCK_STREAM_NONBLOCK: u64 = 1 | 0o4000;
    const LEN: u64 = 1 << 20;
    let mut a = Asm::new();
    let bad = a.label();
    let path = a.data(b"/sendfile\0");
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rdi, 1); // AF_UNIX
    a.mov_imm(Reg::Rsi, SOCK_STREAM_NONBLOCK);
    a.mov_imm(Reg::Rdx, 0);
    a.mov(Reg::R10, Reg::Rbp);
    a.sys(sys::SOCKETPAIR);
    a.mov_imm(Reg::Rdi, 1);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(bad);
    a.load32(Reg::R12, Reg::Rbp, 0); // the end to send on
    a.mov_data(Reg::Rdi, path);
    a.mov_imm(Reg::Rsi, 0o102); // O_RDWR | O_CREAT
    a.mov_imm(Reg::Rdx, 0o644);
    a.sys(sys::OPEN);
    a.mov(Reg::R13, Reg::Rax);
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, LEN);
    a.sys(sys::FTRUNCATE);
    a.mov_imm(Reg::Rdi, 2);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(bad);
    // sendfile(sock, file, NULL, LEN): 0 < n < LEN.
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::R13);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, LEN);
    a.sys(sys::SENDFILE);
    a.mov(Reg::R14, Reg::Rax);
    a.mov_imm(Reg::Rdi, 3);
    a.cmp_imm(Reg::Rax, 0);
    a.jbe(bad); // 0, or an error (as unsigned: huge, caught below)
    a.mov_imm(Reg::Rcx, LEN);
    a.mov_imm(Reg::Rdi, 4);
    a.cmp(Reg::Rcx, Reg::Rax);
    a.jbe(bad); // LEN <= n: all of it, or an error's huge unsigned value
    // The file offset is where the sending stopped.
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 1); // SEEK_CUR
    a.sys(sys::LSEEK);
    a.mov_imm(Reg::Rdi, 5);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    // Nothing more fits: EAGAIN.
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::R13);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, LEN);
    a.sys(sys::SENDFILE);
    a.mov_imm(Reg::Rcx, (-11i64) as u64);
    a.mov_imm(Reg::Rdi, 6);
    a.cmp(Reg::Rax, Reg::Rcx);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 0);
    a.bind(bad);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// A fork costs what it copies: in a 128-page cell, a process with 80
/// touched pages forks (charging the child for all of them again would
/// need 160 pages and fail), and the child copies one page by writing it.
/// Exits 0; 1 if fork failed; 2 if the child did not exit 0.
fn fork_charge_program() -> Vec<u8> {
    const PAGES: u64 = 80;
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    let fill = a.label();
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, PAGES * 4096);
    a.mov_imm(Reg::Rdx, 3);
    a.mov_imm(Reg::R10, 0x22);
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::R12, Reg::Rax);
    a.mov_imm(Reg::Rcx, 0);
    a.mov(Reg::Rdx, Reg::R12);
    a.bind(fill);
    a.store(Reg::Rdx, 0, Reg::Rcx);
    a.add_imm(Reg::Rdx, 4096);
    a.add_imm(Reg::Rcx, 1);
    a.cmp_imm(Reg::Rcx, PAGES as i32);
    a.jne(fill);
    a.sys(sys::FORK);
    a.mov_imm(Reg::Rdi, 1);
    a.mov_imm(Reg::R14, (-4096i64) as u64);
    a.cmp(Reg::Rax, Reg::R14);
    a.ja(bad); // -errno
    a.mov(Reg::R13, Reg::Rax);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    // Child: write one page (its copy), check it, exit 0.
    a.mov_imm(Reg::Rax, 0x77);
    a.store(Reg::R12, 0, Reg::Rax);
    a.load(Reg::Rcx, Reg::R12, 0);
    a.mov_imm(Reg::Rdi, 9);
    a.cmp(Reg::Rcx, Reg::Rax);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    a.bind(parent);
    a.mov(Reg::Rdi, Reg::R13);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.load32(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::Rdi, 2);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(bad);
    // The parent's page 0 still holds 0: the child's write was its own.
    a.load(Reg::Rax, Reg::R12, 0);
    a.mov_imm(Reg::Rdi, 3);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 0);
    a.bind(bad);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Ranges bigger than one batch of page bookkeeping (4096 pages): 4200
/// touched pages, each holding its index, move with mremap and are all
/// found at the new address, are made read-only, then unmapped. (Lists of
/// every page used to be one allocation, which a 2 GiB process could not
/// get.) Exits 0, or the failed check.
fn big_range_program() -> Vec<u8> {
    const PAGES: u64 = 4200;
    const LEN: u64 = PAGES * 4096;
    let mut a = Asm::new();
    let bad = a.label();
    let fill = a.label();
    let check = a.label();
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, LEN);
    a.mov_imm(Reg::Rdx, 3);
    a.mov_imm(Reg::R10, 0x22);
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::R12, Reg::Rax);
    // Page i holds i.
    a.mov_imm(Reg::Rcx, 0);
    a.mov(Reg::Rdx, Reg::R12);
    a.bind(fill);
    a.store(Reg::Rdx, 0, Reg::Rcx);
    a.add_imm(Reg::Rdx, 4096);
    a.add_imm(Reg::Rcx, 1);
    a.cmp_imm(Reg::Rcx, PAGES as i32);
    a.jne(fill);
    // mremap(old, LEN, 2 * LEN, MREMAP_MAYMOVE): a bigger region elsewhere.
    a.mov(Reg::Rdi, Reg::R12);
    a.mov_imm(Reg::Rsi, LEN);
    a.mov_imm(Reg::Rdx, 2 * LEN);
    a.mov_imm(Reg::R10, 1);
    a.sys(sys::MREMAP);
    a.mov(Reg::R13, Reg::Rax);
    a.mov_imm(Reg::Rcx, 0);
    a.mov(Reg::Rdx, Reg::R13);
    a.bind(check);
    a.load(Reg::Rax, Reg::Rdx, 0);
    a.mov_imm(Reg::Rdi, 1);
    a.cmp(Reg::Rax, Reg::Rcx);
    a.jne(bad);
    a.add_imm(Reg::Rdx, 4096);
    a.add_imm(Reg::Rcx, 1);
    a.cmp_imm(Reg::Rcx, PAGES as i32);
    a.jne(check);
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 2 * LEN);
    a.mov_imm(Reg::Rdx, 1); // PROT_READ
    a.sys(sys::MPROTECT);
    a.mov_imm(Reg::Rdi, 2);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(bad);
    a.load(Reg::Rax, Reg::R13, (4096 * (PAGES - 1)) as i32);
    a.mov_imm(Reg::R14, PAGES - 1);
    a.mov_imm(Reg::Rdi, 3);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 2 * LEN);
    a.sys(sys::MUNMAP);
    a.mov_imm(Reg::Rdi, 4);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 0);
    a.bind(bad);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// More of what CPython's suite calls: waitid reports a child's exit as a
/// siginfo (CLD_EXITED, status 5); preadv reads at an offset; nothing is
/// pending for rt_sigpending; SCHED_FIFO's priorities top out at 99; an
/// affinity mask set is the one read back; a pipe's capacity reads 64 KiB
/// and can be set to one page; clock_settime is EPERM. Exits 0, or the
/// failed check.
fn misc2_program() -> Vec<u8> {
    const WEXITED: u64 = 4;
    let neg = |e: i64| (-e) as u64;
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    let check = |a: &mut Asm, n: u64, want: u64| {
        a.mov_imm(Reg::R14, want);
        a.mov_imm(Reg::Rdi, n);
        a.cmp(Reg::Rax, Reg::R14);
        a.jne(bad);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.sys(sys::FORK);
    a.mov(Reg::R12, Reg::Rax);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    a.mov_imm(Reg::Rdi, 5);
    a.sys(sys::EXIT_GROUP);
    a.bind(parent);
    a.mov_imm(Reg::Rdi, 1); // P_PID
    a.mov(Reg::Rsi, Reg::R12);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.mov_imm(Reg::R10, WEXITED);
    a.mov_imm(Reg::R8, 0);
    a.sys(sys::WAITID);
    check(&mut a, 1, 0);
    a.load32(Reg::Rax, Reg::Rbp, 8); // si_code
    check(&mut a, 2, 1);
    a.load32(Reg::Rax, Reg::Rbp, 24); // si_status
    check(&mut a, 3, 5);
    // A pipe: write "abcdef", preadv is ESPIPE on it; its capacity.
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 256);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PIPE2);
    check(&mut a, 4, 0);
    a.load32(Reg::R13, Reg::Rbp, 256); // read end
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 1032); // F_GETPIPE_SZ
    a.sys(sys::FCNTL);
    check(&mut a, 5, 64 * 1024);
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 1031); // F_SETPIPE_SZ
    a.mov_imm(Reg::Rdx, 100);
    a.sys(sys::FCNTL);
    check(&mut a, 6, 4096);
    // preadv on a file at offset 1: "/x" of a fresh file holding "hello".
    let name = a.data(b"/preadv\0");
    let text = a.data(b"hello");
    a.mov_data(Reg::Rdi, name);
    a.mov_imm(Reg::Rsi, 0o102); // O_RDWR | O_CREAT
    a.mov_imm(Reg::Rdx, 0o644);
    a.sys(sys::OPEN);
    a.mov(Reg::R15, Reg::Rax);
    a.mov(Reg::Rdi, Reg::R15);
    a.mov_data(Reg::Rsi, text);
    a.mov_imm(Reg::Rdx, 5);
    a.sys(sys::WRITE);
    check(&mut a, 7, 5);
    // iovec { rbp + 512, 3 } at rbp + 64.
    a.mov(Reg::Rax, Reg::Rbp);
    a.add_imm(Reg::Rax, 512);
    a.store(Reg::Rbp, 64, Reg::Rax);
    a.mov_imm(Reg::Rax, 3);
    a.store(Reg::Rbp, 72, Reg::Rax);
    a.mov(Reg::Rdi, Reg::R15);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 64);
    a.mov_imm(Reg::Rdx, 1);
    a.mov_imm(Reg::R10, 1);
    a.mov_imm(Reg::R8, 0);
    a.sys(sys::PREADV);
    check(&mut a, 8, 3);
    a.load32(Reg::Rax, Reg::Rbp, 512);
    a.mov_imm(Reg::Rcx, 0xff_ffff);
    a.raw(&[0x48, 0x21, 0xc8]); // and rax, rcx
    check(&mut a, 9, u64::from(u32::from_le_bytes(*b"ell\0")));
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, 8);
    a.sys(sys::RT_SIGPENDING);
    check(&mut a, 10, 0);
    a.load(Reg::Rax, Reg::Rbp, 0);
    check(&mut a, 11, 0);
    a.mov_imm(Reg::Rdi, 1); // SCHED_FIFO
    a.sys(sys::SCHED_GET_PRIORITY_MAX);
    check(&mut a, 12, 99);
    a.mov_imm(Reg::Rax, 1); // CPU 0 only
    a.store(Reg::Rbp, 0, Reg::Rax);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 8);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.sys(sys::SCHED_SETAFFINITY);
    check(&mut a, 13, 0);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 0, Reg::Rax);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 8);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.sys(sys::SCHED_GETAFFINITY);
    check(&mut a, 14, 8);
    a.load(Reg::Rax, Reg::Rbp, 0);
    check(&mut a, 15, 1);
    a.mov_imm(Reg::Rdi, 0);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::CLOCK_SETTIME);
    check(&mut a, 16, neg(1));
    a.mov_imm(Reg::Rdi, 0);
    a.bind(bad);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Robust futexes: a forked child registers a robust list (in MAP_SHARED
/// memory) holding one lock whose word is its tid, and exits holding it;
/// the parent then finds the word marked FUTEX_OWNER_DIED with the tid
/// gone. A head length other than 24 is EINVAL. Exits 0, or the failed
/// check.
fn robust_program() -> Vec<u8> {
    const OWNER_DIED: u64 = 0x4000_0000;
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 4096);
    a.mov_imm(Reg::Rdx, 3);
    a.mov_imm(Reg::R10, 0x21); // MAP_SHARED | MAP_ANONYMOUS
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::R13, Reg::Rax);
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 23);
    a.sys(sys::SET_ROBUST_LIST);
    a.mov_imm(Reg::R14, (-22i64) as u64);
    a.mov_imm(Reg::Rdi, 1);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.sys(sys::FORK);
    a.mov(Reg::R12, Reg::Rax);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    // Child: head at +0 { next = +32, futex_offset = 8, pending = 0 };
    // the lock's entry at +32 { next = head }, its word at +40 = tid.
    a.sys(sys::GETTID);
    a.store32(Reg::R13, 40, Reg::Rax);
    a.mov(Reg::Rax, Reg::R13);
    a.add_imm(Reg::Rax, 32);
    a.store(Reg::R13, 0, Reg::Rax);
    a.mov_imm(Reg::Rax, 8);
    a.store(Reg::R13, 8, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::R13, 16, Reg::Rax);
    a.store(Reg::R13, 32, Reg::R13);
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 24);
    a.sys(sys::SET_ROBUST_LIST);
    a.mov(Reg::Rdi, Reg::Rax); // exit status: set_robust_list's result
    a.sys(sys::EXIT);
    a.bind(parent);
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.mov_imm(Reg::Rdi, 2);
    a.cmp(Reg::Rax, Reg::R12);
    a.jne(bad);
    a.load32(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R14, 0);
    a.mov_imm(Reg::Rdi, 3); // the child's set_robust_list failed
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.load32(Reg::Rax, Reg::R13, 40);
    a.mov_imm(Reg::R14, OWNER_DIED);
    a.mov_imm(Reg::Rdi, 4);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.mov_imm(Reg::Rdi, 0);
    a.bind(bad);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// Named pipes: `mknod(S_IFIFO)` makes one that stats as a FIFO; a
/// non-blocking open for writing with no reader is ENXIO; with a reader
/// open, bytes pass and the last writer's close is EOF; a blocking reader
/// open waits for a forked child's blocking writer open (each waits for
/// the other); device nodes are EPERM. Exits 0, or the failed check.
fn fifo_program() -> Vec<u8> {
    const S_IFIFO: u64 = 0o010_000;
    const O_WRONLY: u64 = 1;
    const O_NONBLOCK: u64 = 0o4000;
    let neg = |e: i64| (-e) as u64;
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    let path = a.data(b"/fifo\0");
    let dev = a.data(b"/dev0\0");
    let text = a.data(b"abc");
    let check = |a: &mut Asm, n: u64, want: u64| {
        a.mov_imm(Reg::R14, want);
        a.mov_imm(Reg::Rdi, n);
        a.cmp(Reg::Rax, Reg::R14);
        a.jne(bad);
    };
    let open = |a: &mut Asm, flags: u64| {
        a.mov_data(Reg::Rdi, path);
        a.mov_imm(Reg::Rsi, flags);
        a.mov_imm(Reg::Rdx, 0);
        a.sys(sys::OPEN);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_data(Reg::Rdi, path);
    a.mov_imm(Reg::Rsi, S_IFIFO | 0o644);
    a.mov_imm(Reg::Rdx, 0);
    a.sys(sys::MKNOD);
    check(&mut a, 1, 0);
    a.mov_data(Reg::Rdi, path);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::STAT);
    check(&mut a, 2, 0);
    a.load32(Reg::Rax, Reg::Rbp, 24); // st_mode
    check(&mut a, 3, S_IFIFO | 0o644);
    open(&mut a, O_WRONLY | O_NONBLOCK);
    check(&mut a, 4, neg(6)); // ENXIO
    open(&mut a, O_NONBLOCK);
    check(&mut a, 5, 3);
    open(&mut a, O_WRONLY | O_NONBLOCK);
    check(&mut a, 6, 4);
    a.mov_imm(Reg::Rdi, 4);
    a.mov_data(Reg::Rsi, text);
    a.mov_imm(Reg::Rdx, 3);
    a.sys(sys::WRITE);
    check(&mut a, 7, 3);
    a.mov_imm(Reg::Rdi, 4);
    a.sys(sys::CLOSE);
    for (n, want) in [(8, 3), (9, 0)] {
        a.mov_imm(Reg::Rdi, 3);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.mov_imm(Reg::Rdx, 16);
        a.sys(sys::READ);
        check(&mut a, n, want); // the bytes, then EOF
    }
    a.mov_imm(Reg::Rdi, 3);
    a.sys(sys::CLOSE);
    // Blocking opens meet across fork.
    a.sys(sys::FORK);
    a.mov(Reg::R12, Reg::Rax);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    open(&mut a, O_WRONLY);
    a.mov(Reg::Rdi, Reg::Rax);
    a.mov_data(Reg::Rsi, text);
    a.mov_imm(Reg::Rdx, 1);
    a.sys(sys::WRITE);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    a.bind(parent);
    open(&mut a, 0);
    check(&mut a, 10, 3);
    a.mov_imm(Reg::Rdi, 3);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 16);
    a.sys(sys::READ);
    check(&mut a, 11, 1);
    a.mov(Reg::Rdi, Reg::R12);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 64);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.mov_imm(Reg::Rdi, 12);
    a.cmp(Reg::Rax, Reg::R12);
    a.jne(bad);
    a.mov_data(Reg::Rdi, dev);
    a.mov_imm(Reg::Rsi, 0o020_000 | 0o644); // S_IFCHR
    a.mov_imm(Reg::Rdx, 0x103);
    a.sys(sys::MKNOD);
    check(&mut a, 13, neg(1));
    a.mov_imm(Reg::Rdi, 0);
    a.bind(bad);
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

/// A thread asleep in `epoll_wait` on an empty instance sees what another
/// thread adds to it, and does not keep a pipe's write end open once it is
/// closed: the read end (added edge-triggered) reports the hang-up, and
/// reads end-of-file. Go's runtime parks a thread there all the time.
/// Exits 0, or the failed check.
fn epoll_threads_program() -> Vec<u8> {
    const FLAGS: u64 = 0x35_0f00; // as `thread_program`
    const FUTEX_WAIT_PRIVATE: u64 = 128;
    const FUTEX_WAKE_PRIVATE: u64 = 129;
    const IN_RDHUP_ET: u64 = 0x8000_2001;
    let mut a = Asm::new();
    let bad = a.label();
    let main = a.label();
    let wait = a.label();
    let woken = a.label();
    let ms50 = a.data(&[0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0xf0, 0xfa, 0x02, 0, 0, 0, 0]);
    let s5 = a.data(&[5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    let nap = |a: &mut Asm| {
        a.mov_data(Reg::Rdi, ms50);
        a.mov_imm(Reg::Rsi, 0);
        a.sys(sys::NANOSLEEP);
    };
    // [rbp] done, [rbp+8] epoll_wait's result, +16 the event added, +32 the
    // pipe's ends, +48 the thread's tid, +64 the events reported.
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 0, Reg::Rax);
    a.store(Reg::Rbp, 24, Reg::Rax);
    a.mov_imm(Reg::Rax, IN_RDHUP_ET | (0x77 << 32));
    a.store(Reg::Rbp, 16, Reg::Rax);
    // 1: epoll -> 3, a pipe -> 4 and 5, a stack for the thread.
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EPOLL_CREATE1);
    expect(&mut a, 1, 3);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 32);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PIPE2);
    expect(&mut a, 1, 0);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 0x1_0000);
    a.mov_imm(Reg::Rdx, 3);
    a.mov_imm(Reg::R10, 0x22);
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::Rsi, Reg::Rax);
    a.add_imm(Reg::Rsi, 0x1_0000);
    a.mov_imm(Reg::Rdi, FLAGS);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, 48);
    a.mov(Reg::R10, Reg::Rdx);
    a.mov_imm(Reg::R8, 0);
    a.sys(sys::CLONE);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(main);
    // The thread: wait for whatever comes.
    a.mov_imm(Reg::Rdi, 3);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 64);
    a.mov_imm(Reg::Rdx, 4);
    a.mov_imm(Reg::R10, u64::MAX); // -1: no timeout
    a.sys(sys::EPOLL_WAIT);
    a.store(Reg::Rbp, 8, Reg::Rax);
    a.mov_imm(Reg::Rax, 1);
    a.store(Reg::Rbp, 0, Reg::Rax);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, FUTEX_WAKE_PRIVATE);
    a.mov_imm(Reg::Rdx, 1);
    a.sys(sys::FUTEX);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT);
    // Main: once it sleeps, add the read end; a while later close the
    // write end.
    a.bind(main);
    nap(&mut a);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_imm(Reg::Rsi, 1); // EPOLL_CTL_ADD
    a.mov_imm(Reg::Rdx, 4);
    a.mov(Reg::R10, Reg::Rbp);
    a.add_imm(Reg::R10, 16);
    a.sys(sys::EPOLL_CTL);
    expect(&mut a, 2, 0);
    nap(&mut a);
    a.mov_imm(Reg::Rdi, 5);
    a.sys(sys::CLOSE);
    expect(&mut a, 2, 0);
    // 3: the thread is woken (within 5 s).
    a.bind(wait);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(woken);
    a.mov(Reg::Rdi, Reg::Rbp);
    a.mov_imm(Reg::Rsi, FUTEX_WAIT_PRIVATE);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_data(Reg::R10, s5);
    a.sys(sys::FUTEX);
    a.mov_imm(Reg::R15, 3);
    a.cmp_imm(Reg::Rax, -110); // ETIMEDOUT
    a.je(bad);
    a.jmp(wait);
    // 4: with one event, the pipe's; 5: which reads end-of-file.
    a.bind(woken);
    a.load(Reg::Rax, Reg::Rbp, 8);
    expect(&mut a, 4, 1);
    a.load(Reg::Rax, Reg::Rbp, 68);
    expect(&mut a, 4, 0x77);
    a.mov_imm(Reg::Rdi, 4);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov_imm(Reg::Rdx, 8);
    a.sys(sys::READ);
    expect(&mut a, 5, 0);
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

/// argv and envp are bytes: execs `/bin/sh` with a 5,000-byte argument
/// (longer than a path) and `X=\xff\xfe` (not UTF-8) in its environment;
/// the shell checks both arrived whole. Exits 99 if execve failed. Needs a
/// root with busybox.
pub(crate) fn exec_bytes_program() -> Vec<u8> {
    let mut a = Asm::new();
    let sh = a.data(b"/bin/sh\0");
    let arg0 = a.data(b"sh\0");
    let arg1 = a.data(b"-c\0");
    let arg2 = a.data(
        b"[ ${#1} -eq 5000 ] && [ \"$X\" = \"$(printf '\\377\\376')\" ] \
          && echo sh: exec passed a 5000-byte argument and a non-UTF-8 environment\0",
    );
    let arg3 = a.data(b"name\0");
    let mut long = alloc::vec![b'a'; 5000];
    long.push(0);
    let arg4 = a.data(&long);
    let env0 = a.data(b"X=\xff\xfe\0");
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // argv = { "sh", "-c", script, "name", long, NULL } at rbp;
    // envp = { "X=\xff\xfe", NULL } at rbp + 64.
    for (i, d) in [arg0, arg1, arg2, arg3, arg4].into_iter().enumerate() {
        a.mov_data(Reg::Rax, d);
        a.store(Reg::Rbp, (i * 8) as i32, Reg::Rax);
    }
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 40, Reg::Rax);
    a.mov_data(Reg::Rax, env0);
    a.store(Reg::Rbp, 64, Reg::Rax);
    a.mov_imm(Reg::Rax, 0);
    a.store(Reg::Rbp, 72, Reg::Rax);
    a.mov_data(Reg::Rdi, sh);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, 64);
    a.sys(sys::EXECVE);
    // Only reached if execve failed.
    a.mov_imm(Reg::Rdi, 99);
    a.sys(sys::EXIT_GROUP);
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_else(|| fail("assembler")))
}

/// `AF_UNIX` descriptor passing: a stream socketpair (fds 3, 4) carries
/// `/etc/motd`'s descriptor (5) with `SCM_RIGHTS`; after the sender closes
/// it, the receiver gets it back as fd 5 in a 24-byte control message and
/// reads the file through it. A seqpacket pair (6, 7) keeps two writes
/// apart, and `SO_PEERCRED` names this process. Exits 0, or the number of
/// the failed check.
fn scm_rights_program() -> Vec<u8> {
    const AF_UNIX: u64 = 1;
    const SOCK_STREAM: u64 = 1;
    const SOCK_SEQPACKET: u64 = 5;
    const SOL_SOCKET: u64 = 1;
    const SO_PEERCRED: u64 = 17;
    let mut a = Asm::new();
    let bad = a.label();
    let motd = a.data(b"/etc/motd\0");
    let abc = a.data(b"abcde");
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    // Stores `v` at rbp+off.
    let put = |a: &mut Asm, off: i32, v: u64| {
        a.mov_imm(Reg::Rax, v);
        a.store(Reg::Rbp, off, Reg::Rax);
    };
    // Stores rbp+target at rbp+off.
    let put_ptr = |a: &mut Asm, off: i32, target: i32| {
        a.mov(Reg::Rax, Reg::Rbp);
        a.add_imm(Reg::Rax, target);
        a.store(Reg::Rbp, off, Reg::Rax);
    };
    // msghdr at rbp+256: iov rbp+64 (1 byte at rbp+128), control rbp+192
    // (24 bytes).
    let msghdr = |a: &mut Asm| {
        put(a, 256, 0);
        put(a, 264, 0);
        put_ptr(a, 272, 64);
        put(a, 280, 1);
        put_ptr(a, 288, 192);
        put(a, 296, 24);
        put(a, 304, 0);
        put_ptr(a, 64, 128);
        put(a, 72, 1);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // 1: socketpair(AF_UNIX, SOCK_STREAM) -> fds 3 and 4.
    a.mov_imm(Reg::Rdi, AF_UNIX);
    a.mov_imm(Reg::Rsi, SOCK_STREAM);
    a.mov_imm(Reg::Rdx, 0);
    a.mov(Reg::R10, Reg::Rbp);
    a.sys(sys::SOCKETPAIR);
    expect(&mut a, 1, 0);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R14, 3 | (4 << 32));
    a.mov_imm(Reg::R15, 1);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    // 2: open(/etc/motd) -> 5.
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    expect(&mut a, 2, 5);
    // 3: sendmsg(3, "x" + SCM_RIGHTS [5]) -> 1.
    put(&mut a, 128, u64::from(b'x'));
    put(&mut a, 192, 20);
    put(&mut a, 200, SOL_SOCKET | (1 << 32));
    put(&mut a, 208, 5);
    msghdr(&mut a);
    a.mov_imm(Reg::Rdi, 3);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 256);
    a.mov_imm(Reg::Rdx, 0);
    a.sys(sys::SENDMSG);
    expect(&mut a, 3, 1);
    // 4: close(5): the message still holds the open file.
    a.mov_imm(Reg::Rdi, 5);
    a.sys(sys::CLOSE);
    expect(&mut a, 4, 0);
    // 5: recvmsg(4) -> 1 byte, "x".
    for off in [128, 192, 200, 208] {
        put(&mut a, off, 0);
    }
    msghdr(&mut a);
    a.mov_imm(Reg::Rdi, 4);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 256);
    a.mov_imm(Reg::Rdx, 0);
    a.sys(sys::RECVMSG);
    expect(&mut a, 5, 1);
    a.load(Reg::Rax, Reg::Rbp, 128);
    expect(&mut a, 5, i32::from(b'x'));
    // 6: one SCM_RIGHTS control message of 20 bytes naming fd 5; the
    // control length came back as 24.
    a.load(Reg::Rax, Reg::Rbp, 192);
    expect(&mut a, 6, 20);
    a.load(Reg::Rax, Reg::Rbp, 200);
    a.mov_imm(Reg::R14, SOL_SOCKET | (1 << 32));
    a.mov_imm(Reg::R15, 6);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.load(Reg::Rax, Reg::Rbp, 208);
    expect(&mut a, 6, 5);
    a.load(Reg::Rax, Reg::Rbp, 296);
    expect(&mut a, 6, 24);
    // 7: read(5) reads /etc/motd through the passed descriptor.
    a.mov_imm(Reg::Rdi, 5);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 128);
    a.mov_imm(Reg::Rdx, 5);
    a.sys(sys::READ);
    expect(&mut a, 7, 5);
    // The same five bytes as a fresh open reads (fstest rewrote the file
    // earlier in this root).
    put(&mut a, 144, 0);
    a.mov_data(Reg::Rdi, motd);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::OPEN);
    expect(&mut a, 7, 6);
    a.mov_imm(Reg::Rdi, 6);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 144);
    a.mov_imm(Reg::Rdx, 5);
    a.sys(sys::READ);
    expect(&mut a, 7, 5);
    a.mov_imm(Reg::Rdi, 6);
    a.sys(sys::CLOSE);
    a.load(Reg::Rax, Reg::Rbp, 128);
    a.load(Reg::R14, Reg::Rbp, 144);
    a.mov_imm(Reg::R15, 7);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    // 8: a seqpacket pair (6, 7): writes of 3 and 2 bytes read back as 3
    // and 2.
    a.mov_imm(Reg::Rdi, AF_UNIX);
    a.mov_imm(Reg::Rsi, SOCK_SEQPACKET);
    a.mov_imm(Reg::Rdx, 0);
    a.mov(Reg::R10, Reg::Rbp);
    a.sys(sys::SOCKETPAIR);
    expect(&mut a, 8, 0);
    for (data, len) in [(0u64, 3u64), (3, 2)] {
        a.mov_imm(Reg::Rdi, 6);
        a.mov_data(Reg::Rsi, abc);
        a.add_imm(Reg::Rsi, data as i32);
        a.mov_imm(Reg::Rdx, len);
        a.sys(sys::WRITE);
        expect(&mut a, 8, len as i32);
    }
    for len in [3, 2] {
        a.mov_imm(Reg::Rdi, 7);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.add_imm(Reg::Rsi, 128);
        a.mov_imm(Reg::Rdx, 100);
        a.sys(sys::READ);
        expect(&mut a, 8, len);
    }
    // 9: SO_PEERCRED on fd 3: this process, uid 0.
    put(&mut a, 336, 12);
    a.mov_imm(Reg::Rdi, 3);
    a.mov_imm(Reg::Rsi, SOL_SOCKET);
    a.mov_imm(Reg::Rdx, SO_PEERCRED);
    a.mov(Reg::R10, Reg::Rbp);
    a.add_imm(Reg::R10, 320);
    a.mov(Reg::R8, Reg::Rbp);
    a.add_imm(Reg::R8, 336);
    a.sys(sys::GETSOCKOPT);
    expect(&mut a, 9, 0);
    a.sys(sys::GETPID);
    a.load(Reg::R14, Reg::Rbp, 320);
    a.mov_imm(Reg::R15, 9);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
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
    // 7: a hard limit past the table (MAX_FDS, 65,536): EPERM.
    pair(&mut a, 5, 1 << 20);
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

/// Shared file mappings are the file: what is stored through one, `pread`,
/// another mapping and a forked child see, and the other way round; a
/// write through a mapping of an image file copies it up; a private mapping
/// keeps its stores; a descriptor opened for reading cannot be mapped (or
/// made) writable. Exits 0, or the failed check.
fn shared_file_program() -> Vec<u8> {
    const RW: u64 = 3;
    const SHARED: u64 = 1;
    const PRIVATE: u64 = 2;
    const EACCES: i32 = -13;
    let mut a = Asm::new();
    let bad = a.label();
    let parent = a.label();
    let path = a.data(b"/shfile\0");
    let motd = a.data(b"/usr/share/motd\0");
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    let open = |a: &mut Asm, path, flags: u64, n: u64, want: i32| {
        a.mov_data(Reg::Rdi, path);
        a.mov_imm(Reg::Rsi, flags);
        a.mov_imm(Reg::Rdx, 0o644);
        a.sys(sys::OPEN);
        expect(a, n, want);
    };
    let map = |a: &mut Asm, len: u64, prot: u64, flags: u64, fd: u64| {
        a.mov_imm(Reg::Rdi, 0);
        a.mov_imm(Reg::Rsi, len);
        a.mov_imm(Reg::Rdx, prot);
        a.mov_imm(Reg::R10, flags);
        a.mov_imm(Reg::R8, fd);
        a.mov_imm(Reg::R9, 0);
        a.sys(sys::MMAP);
    };
    // pread64/pwrite64(fd, rbp, 8, at), then the 8 bytes in rax.
    let io = |a: &mut Asm, nr: u64, fd: u64, at: u64, n: u64| {
        a.mov_imm(Reg::Rdi, fd);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.mov_imm(Reg::Rdx, 8);
        a.mov_imm(Reg::R10, at);
        a.sys(nr);
        expect(a, n, 8);
        a.load(Reg::Rax, Reg::Rbp, 0);
    };
    let put = |a: &mut Asm, base: Reg, at: i32, v: u64| {
        a.mov_imm(Reg::Rax, v);
        a.store(base, at, Reg::Rax);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    open(&mut a, path, 0o102, 1, 3); // O_RDWR | O_CREAT
    a.mov_imm(Reg::Rdi, 3);
    a.mov_imm(Reg::Rsi, 12288);
    a.sys(sys::FTRUNCATE);
    expect(&mut a, 1, 0);
    map(&mut a, 12288, RW, SHARED, 3);
    a.mov(Reg::R12, Reg::Rax);
    // 2: a store is in the file (a hole was given a page).
    put(&mut a, Reg::R12, 4104, 0x41);
    io(&mut a, sys::PREAD64, 3, 4104, 2);
    expect(&mut a, 2, 0x41);
    // 3: a write is in the mapping.
    put(&mut a, Reg::Rbp, 0, 0x42);
    io(&mut a, sys::PWRITE64, 3, 16, 3);
    a.load(Reg::Rax, Reg::R12, 16);
    expect(&mut a, 3, 0x42);
    // 4: a forked child's store (to a page nobody had touched) is ours.
    a.sys(sys::FORK);
    a.mov(Reg::Rbx, Reg::Rax);
    a.cmp_imm(Reg::Rax, 0);
    a.jne(parent);
    put(&mut a, Reg::R12, 8192, 0x43);
    put(&mut a, Reg::R12, 16, 0x46);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    a.bind(parent);
    a.mov(Reg::Rdi, Reg::Rbx);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::WAIT4);
    a.load(Reg::Rax, Reg::R12, 8192);
    expect(&mut a, 4, 0x43);
    a.load(Reg::Rax, Reg::R12, 16);
    expect(&mut a, 4, 0x46);
    // 5, 6: so it is in another mapping, both ways.
    map(&mut a, 12288, RW, SHARED, 3);
    a.mov(Reg::R13, Reg::Rax);
    a.load(Reg::Rax, Reg::R13, 8192);
    expect(&mut a, 5, 0x43);
    put(&mut a, Reg::R13, 0, 0x44);
    a.load(Reg::Rax, Reg::R12, 0);
    expect(&mut a, 6, 0x44);
    // 7: msync of it, and of what is not mapped (ENOMEM).
    a.mov(Reg::Rdi, Reg::R12);
    a.mov_imm(Reg::Rsi, 12288);
    a.mov_imm(Reg::Rdx, 4); // MS_SYNC
    a.sys(sys::MSYNC);
    expect(&mut a, 7, 0);
    a.mov_imm(Reg::Rdi, 4096);
    a.mov_imm(Reg::Rsi, 4096);
    a.mov_imm(Reg::Rdx, 4);
    a.sys(sys::MSYNC);
    expect(&mut a, 7, -12);
    // 8, 9: opened for reading, it cannot be written.
    open(&mut a, path, 0, 8, 4);
    map(&mut a, 4096, RW, SHARED, 4);
    expect(&mut a, 8, EACCES);
    map(&mut a, 4096, 1, SHARED, 4);
    a.mov(Reg::R14, Reg::Rax);
    a.mov(Reg::Rdi, Reg::R14);
    a.mov_imm(Reg::Rsi, 4096);
    a.mov_imm(Reg::Rdx, RW);
    a.sys(sys::MPROTECT);
    expect(&mut a, 9, EACCES);
    a.load(Reg::Rax, Reg::R14, 0);
    expect(&mut a, 9, 0x44);
    // 10: an image file: read first, then written, copied up under us.
    open(&mut a, motd, 2, 10, 5); // O_RDWR
    map(&mut a, 4096, RW, SHARED, 5);
    a.mov(Reg::R14, Reg::Rax);
    io(&mut a, sys::PREAD64, 5, 0, 10);
    a.mov(Reg::Rbx, Reg::Rax);
    a.load(Reg::Rax, Reg::R14, 0);
    a.mov_imm(Reg::R15, 10);
    a.cmp(Reg::Rax, Reg::Rbx);
    a.jne(bad);
    put(&mut a, Reg::R14, 0, 0x45);
    io(&mut a, sys::PREAD64, 5, 0, 10);
    expect(&mut a, 10, 0x45);
    // 11: a private mapping sees the file and keeps its stores.
    map(&mut a, 4096, RW, PRIVATE, 3);
    a.mov(Reg::R13, Reg::Rax);
    a.load(Reg::Rax, Reg::R13, 0);
    expect(&mut a, 11, 0x44);
    put(&mut a, Reg::R13, 0, 0x47);
    io(&mut a, sys::PREAD64, 3, 0, 11);
    expect(&mut a, 11, 0x44);
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

/// `mremap` and `prctl`. Two written anonymous pages move (with their
/// data) when grown to four with `MREMAP_MAYMOVE`, the new tail is
/// usable, and shrinking stays in place. `PR_SET_NAME` round-trips through
/// `PR_GET_NAME`, and `PR_CAPBSET_READ` reports CAP_CHOWN in the cell
/// bounding set and CAP_SYS_ADMIN outside it. Exits 0, or the failed check.
fn mremap_program() -> Vec<u8> {
    const PROT_RW: u64 = 3;
    const PRIVATE_ANON: u64 = 0x22;
    const MAYMOVE: u64 = 1;
    let mut a = Asm::new();
    let bad = a.label();
    let name = a.data(b"ichortest\0");
    let expect = |a: &mut Asm, n: u64, v: i32| {
        a.mov_imm(Reg::R15, n);
        a.cmp_imm(Reg::Rax, v);
        a.jne(bad);
    };
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // r12 = 2 pages; markers 0x11 at 0 and 0x22 at 4096.
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 8192);
    a.mov_imm(Reg::Rdx, PROT_RW);
    a.mov_imm(Reg::R10, PRIVATE_ANON);
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(sys::MMAP);
    a.mov(Reg::R12, Reg::Rax);
    a.mov_imm(Reg::Rax, 0x11);
    a.store(Reg::R12, 0, Reg::Rax);
    a.mov_imm(Reg::Rax, 0x22);
    a.store(Reg::R12, 4096, Reg::Rax);
    // 1-3: grow to 4 pages (may move): data follows; the tail works.
    a.mov(Reg::Rdi, Reg::R12);
    a.mov_imm(Reg::Rsi, 8192);
    a.mov_imm(Reg::Rdx, 16384);
    a.mov_imm(Reg::R10, MAYMOVE);
    a.sys(sys::MREMAP);
    a.mov(Reg::R13, Reg::Rax);
    a.load(Reg::Rax, Reg::R13, 0);
    expect(&mut a, 1, 0x11);
    a.load(Reg::Rax, Reg::R13, 4096);
    expect(&mut a, 2, 0x22);
    a.mov_imm(Reg::Rax, 0x33);
    a.store(Reg::R13, 3 * 4096, Reg::Rax);
    a.load(Reg::Rax, Reg::R13, 3 * 4096);
    expect(&mut a, 3, 0x33);
    // 4: shrinking to one page stays put.
    a.mov(Reg::Rdi, Reg::R13);
    a.mov_imm(Reg::Rsi, 16384);
    a.mov_imm(Reg::Rdx, 4096);
    a.mov_imm(Reg::R10, 0);
    a.sys(sys::MREMAP);
    a.mov_imm(Reg::R15, 4);
    a.cmp(Reg::Rax, Reg::R13);
    a.jne(bad);
    // 5: PR_SET_NAME then PR_GET_NAME into rbp: "ichortes" comes back.
    a.mov_imm(Reg::Rdi, 15);
    a.mov_data(Reg::Rsi, name);
    a.sys(sys::PRCTL);
    expect(&mut a, 5, 0);
    a.mov_imm(Reg::Rdi, 16);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.sys(sys::PRCTL);
    expect(&mut a, 5, 0);
    a.load(Reg::Rax, Reg::Rbp, 0);
    a.mov_imm(Reg::R14, u64::from_le_bytes(*b"ichortes"));
    a.mov_imm(Reg::R15, 5);
    a.cmp(Reg::Rax, Reg::R14);
    a.jne(bad);
    // 6-7: CAP_CHOWN is in the bounding set, CAP_SYS_ADMIN (21) is not.
    a.mov_imm(Reg::Rdi, 23);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PRCTL);
    expect(&mut a, 6, 1);
    a.mov_imm(Reg::Rdi, 23);
    a.mov_imm(Reg::Rsi, 21);
    a.sys(sys::PRCTL);
    expect(&mut a, 7, 0);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(sys::EXIT_GROUP);
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
    // fds 4, 5 = pipe: the child says when its conflict checks are done,
    // so the parent's unlock cannot overtake them however slow the child
    // is to run (a loaded host).
    a.mov(Reg::Rdi, Reg::Rbp);
    a.add_imm(Reg::Rdi, 128);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(sys::PIPE2);
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
    // Tell the parent the checks that need its lock held are done.
    a.mov_imm(Reg::Rdi, 5);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 160);
    a.mov_imm(Reg::Rdx, 1);
    a.sys(sys::WRITE);
    flock(&mut a, WR, 0, 1);
    fcntl(&mut a, F_SETLKW); // blocks until the parent unlocks
    expect(&mut a, 5, 0);
    a.mov_imm(Reg::Rdi, 0);
    a.sys(sys::EXIT_GROUP);
    // Parent: wait for the child's checks, give it time to block in
    // F_SETLKW, unlock, reap it.
    a.bind(parent);
    a.mov_imm(Reg::Rdi, 4);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, 160);
    a.mov_imm(Reg::Rdx, 1);
    a.sys(sys::READ);
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
pub(crate) fn root_image() -> &'static [u8] {
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
        Vfs::mount_slice(root_image()).unwrap_or_else(|_| fail("could not mount the root image")),
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

    let (status, _) = run_linux(new_process(), &direction_program(), None, &["dirtest"]);
    if status != 0 {
        println!("ichor: linux: direction flag test failed check {status}");
        fail("direction flag");
    }
    println!(
        "ichor: linux: a backward rep movsq resumed backward across 16 page faults; DF kept across a syscall"
    );

    let (status, _) = run_linux(new_process(), &sendfile_program(), None, &["sendfiletest"]);
    if status != 0 {
        println!("ichor: linux: sendfiletest failed check {status}");
        fail("sendfile progress");
    }
    println!(
        "ichor: linux: sendfile into a full non-blocking socket reports what it sent, then EAGAIN"
    );

    let (status, _) = run_linux(new_process(), &fork_charge_program(), None, &["forkcharge"]);
    if status != 0 {
        println!("ichor: linux: forkcharge failed check {status}");
        fail("fork accounting");
    }
    println!("ichor: linux: fork charges only what is copied (80 shared pages in a 128-page cell)");

    // Its own system and cell: the test needs more than one batch of
    // pages (4200 pages, 16 MiB), more than the usual test cells hold.
    let big = System::new(8192).unwrap_or_else(|| fail("no big system cell"));
    let big_cell = Cell::new(&big.root_account, 5000).unwrap_or_else(|| fail("no big cell"));
    let big_process =
        LinuxProcess::new(big_cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
    let (status, _) = run_linux(big_process, &big_range_program(), None, &["bigrange"]);
    if status != 0 {
        println!("ichor: linux: bigrange failed check {status}");
        fail("large ranges");
    }
    println!("ichor: linux: 4200 pages moved, protected and unmapped in batches");

    let (status, _) = run_linux(new_process(), &misc2_program(), None, &["misc2test"]);
    if status != 0 {
        println!("ichor: linux: misc2test failed check {status}");
        fail("waitid, preadv, sigpending, sched_*, pipe size");
    }
    println!(
        "ichor: linux: waitid, preadv, rt_sigpending, sched priorities and affinity, F_SETPIPE_SZ ok"
    );

    let (status, _) = run_linux(new_process(), &robust_program(), None, &["robusttest"]);
    if status != 0 {
        println!("ichor: linux: robusttest failed check {status}");
        fail("robust futexes");
    }
    println!("ichor: linux: a robust futex held by an exiting process is marked FUTEX_OWNER_DIED");

    crate::pipe::fifo_selftest();
    let (status, _) = run_linux(new_process(), &fifo_program(), None, &["fifotest"]);
    if status != 0 {
        println!("ichor: linux: fifotest failed check {status}");
        fail("named pipes");
    }
    println!(
        "ichor: linux: mknod FIFO: ENXIO without a reader, EOF after the writer, blocking opens meet"
    );

    let (status, _) = run_linux(new_process(), &misc_program(), None, &["misctest"]);
    if status != 0 {
        println!("ichor: linux: misctest failed check {status}");
        fail("close_range, fadvise64, priorities");
    }
    println!(
        "ichor: linux: close_range, fadvise64, get/setpriority, memfd_create, absolute clock_nanosleep, non-UTF-8 names ok"
    );

    let (status, syscalls) = run_linux(new_process(), &poll_program(), None, &["polltest"]);
    if status != 0 {
        println!("ichor: linux: polltest failed check {status}");
        fail("polltest");
    }
    println!("ichor: linux: poll timeout and wakeup, epoll, eventfd ok ({syscalls} syscalls)");

    let (status, _) = run_linux(new_process(), &epoll_threads_program(), None, &["epollthr"]);
    if status != 0 {
        println!("ichor: linux: epollthr failed check {status}");
        fail("epoll across threads");
    }
    println!("ichor: linux: a sleeping epoll_wait sees what another thread adds and closes");

    let (status, syscalls) = run_linux(new_process(), &uring_program(), None, &["uringtest"]);
    if status != 0 {
        println!("ichor: linux: uringtest failed check {status}");
        fail("uringtest");
    }
    println!(
        "ichor: linux: io_uring: linked write and read, armed read woken by a child, timeout, probe ok ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(
        new_process(),
        &uring_worker_program(),
        None,
        &["uringworker"],
    );
    if status != 0 {
        println!("ichor: linux: uringworker failed check {status}");
        fail("uringworker");
    }
    println!(
        "ichor: linux: io_uring: armed reads completed with nobody in io_uring_enter (registered eventfd, epoll on the ring) ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(new_process(), &lock_program(), None, &["locktest"]);
    if status != 0 {
        println!("ichor: linux: locktest failed check {status}");
        fail("locktest");
    }
    println!(
        "ichor: linux: fcntl record locks: conflict, F_GETLK, F_SETLKW wakeup ok ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(new_process(), &scm_rights_program(), None, &["unixtest"]);
    if status != 0 {
        println!("ichor: linux: unixtest failed check {status}");
        fail("unixtest");
    }
    println!(
        "ichor: linux: SCM_RIGHTS passed a descriptor over AF_UNIX, seqpacket kept boundaries, SO_PEERCRED named us ({syscalls} syscalls)"
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

    let (status, syscalls) = run_linux(new_process(), &shared_file_program(), None, &["shfile"]);
    if status != 0 {
        println!("ichor: linux: shfile failed check {status}");
        fail("shared file mappings");
    }
    println!(
        "ichor: linux: shared file mappings are the file, across fork, read, write and copy-up ({syscalls} syscalls)"
    );

    let (status, syscalls) = run_linux(new_process(), &mremap_program(), None, &["mremaptest"]);
    if status != 0 {
        println!("ichor: linux: mremaptest failed check {status}");
        fail("mremaptest");
    }
    println!(
        "ichor: linux: mremap moves and resizes mappings; prctl names and bounding set ok ({syscalls} syscalls)"
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
