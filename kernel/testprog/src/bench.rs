//! The Phase E benchmark programs. Each is a static ELF that times its own
//! loop with `clock_gettime(CLOCK_MONOTONIC)` and prints one line,
//!
//! ```text
//! ichor-bench: <name> n=<iterations> ns=<elapsed nanoseconds>
//! ```
//!
//! then exits 0 (1 if a setup syscall failed). The same bytes run on Ichor
//! (`bench.rs` in the kernel) and on Linux (xtask's reference boot), so the
//! two kernels are compared on identical work. Process start and exit are
//! outside the timed loop.

use alloc::format;
use alloc::vec::Vec;

use crate::{Asm, BLOB_VADDR, Reg, static_elf};

const READ: u64 = 0;
const WRITE: u64 = 1;
const MMAP: u64 = 9;
const GETPID: u64 = 39;
const FORK: u64 = 57;
const EXECVE: u64 = 59;
const WAIT4: u64 = 61;
const CLOCK_GETTIME: u64 = 228;
const EXIT_GROUP: u64 = 231;
const PIPE2: u64 = 293;
const CLOCK_MONOTONIC: u64 = 1;

/// Scratch at `rbp + TIMESPEC` (16 bytes) for `clock_gettime`.
const TIMESPEC: i32 = 64;
/// The decimal number is built backwards ending at `rbp + DIGITS_END`.
const DIGITS_END: i32 = 200;

/// The benchmarks: `(name, program builder, iteration count)`. The counts
/// keep each run around a second or less on a KVM guest.
pub type Program = fn(u64) -> Vec<u8>;

/// Every benchmark program with the iteration count to run it at.
pub const ALL: &[(&str, Program, u64)] = &[
    ("null-syscall", null_syscall, 1_000_000),
    ("pipe-round-trip", pipe_round_trip, 20_000),
    ("page-fault", page_fault, 16_384),
    ("fork-wait", fork_wait, 1000),
    ("fork-exec-wait", fork_exec_wait, 300),
];

/// `rbp = rsp - 4096`: scratch space below the stack.
fn prologue(a: &mut Asm) {
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
}

/// `dst = CLOCK_MONOTONIC now, in nanoseconds` (clobbers rax, rcx, rdx,
/// rdi, rsi, r11).
fn now_ns(a: &mut Asm, dst: Reg) {
    a.mov_imm(Reg::Rdi, CLOCK_MONOTONIC);
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, TIMESPEC);
    a.sys(CLOCK_GETTIME);
    a.load(Reg::Rax, Reg::Rbp, TIMESPEC);
    a.raw(&[0x48, 0x69, 0xC0, 0x00, 0xCA, 0x9A, 0x3B]); // imul rax, rax, 1e9
    a.load(Reg::Rdx, Reg::Rbp, TIMESPEC + 8);
    a.raw(&[0x48, 0x01, 0xD0]); // add rax, rdx
    a.mov(dst, Reg::Rax);
}

/// Writes `prefix` then r14 in decimal and a newline to stdout.
fn report(a: &mut Asm, prefix: &[u8]) {
    let msg = a.data(prefix);
    a.mov_imm(Reg::Rdi, 1);
    a.mov_data(Reg::Rsi, msg);
    a.mov_imm(Reg::Rdx, prefix.len() as u64);
    a.sys(WRITE);
    // rsi = rbp + DIGITS_END holds '\n'; digits go in front of it.
    a.mov(Reg::Rsi, Reg::Rbp);
    a.add_imm(Reg::Rsi, DIGITS_END);
    a.raw(&[0xC6, 0x06, b'\n']); // mov byte [rsi], '\n'
    a.mov(Reg::Rax, Reg::R14);
    a.mov_imm(Reg::Rcx, 10);
    let digit = a.label();
    a.bind(digit);
    a.sub_imm(Reg::Rsi, 1);
    a.raw(&[0x31, 0xD2]); // xor edx, edx
    a.raw(&[0x48, 0xF7, 0xF1]); // div rcx
    a.raw(&[0x80, 0xC2, b'0']); // add dl, '0'
    a.raw(&[0x88, 0x16]); // mov [rsi], dl
    a.cmp_imm(Reg::Rax, 0);
    a.jne(digit);
    // write(1, rsi, rbp + DIGITS_END + 1 - rsi)
    a.mov(Reg::Rdx, Reg::Rbp);
    a.add_imm(Reg::Rdx, DIGITS_END + 1);
    a.raw(&[0x48, 0x29, 0xF2]); // sub rdx, rsi
    a.mov_imm(Reg::Rdi, 1);
    a.sys(WRITE);
}

/// Times `body` run `n` times (counter in r12) and reports it as `name`.
fn timed(a: &mut Asm, name: &str, n: u64, body: impl FnOnce(&mut Asm)) {
    now_ns(a, Reg::R13);
    let top = a.label();
    a.mov_imm(Reg::R12, n);
    a.bind(top);
    body(a);
    a.sub_imm(Reg::R12, 1);
    a.cmp_imm(Reg::R12, 0);
    a.jne(top);
    now_ns(a, Reg::R14);
    a.raw(&[0x4D, 0x29, 0xEE]); // sub r14, r13
    report(a, format!("ichor-bench: {name} n={n} ns=").as_bytes());
}

fn exit(a: &mut Asm, code: u64) {
    a.mov_imm(Reg::Rdi, code);
    a.sys(EXIT_GROUP);
}

fn finish(a: Asm) -> Vec<u8> {
    // Every label above is bound before `finish`, so this cannot fail; an
    // empty program would fail loudly when run.
    static_elf(&a.finish(BLOB_VADDR).unwrap_or_default())
}

/// `n` times `getpid`.
pub fn null_syscall(n: u64) -> Vec<u8> {
    let mut a = Asm::new();
    prologue(&mut a);
    timed(&mut a, "null-syscall", n, |a| a.sys(GETPID));
    exit(&mut a, 0);
    finish(a)
}

/// `n` round trips of one byte: the parent writes fd 4 and reads fd 5;
/// the forked child reads fd 3 and writes fd 6 (fds 3/4 and 5/6 are the
/// two pipes, the lowest free descriptors).
pub fn pipe_round_trip(n: u64) -> Vec<u8> {
    let mut a = Asm::new();
    let child = a.label();
    let bad = a.label();
    prologue(&mut a);
    for off in [0, 8] {
        a.mov(Reg::Rdi, Reg::Rbp);
        a.add_imm(Reg::Rdi, off);
        a.mov_imm(Reg::Rsi, 0);
        a.sys(PIPE2);
        a.cmp_imm(Reg::Rax, 0);
        a.jne(bad);
    }
    a.sys(FORK);
    a.cmp_imm(Reg::Rax, 0);
    a.je(child);
    let io = |a: &mut Asm, nr: u64, fd: u64| {
        a.mov_imm(Reg::Rdi, fd);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.add_imm(Reg::Rsi, 32);
        a.mov_imm(Reg::Rdx, 1);
        a.sys(nr);
    };
    timed(&mut a, "pipe-round-trip", n, |a| {
        io(a, WRITE, 4);
        io(a, READ, 5);
    });
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(WAIT4);
    exit(&mut a, 0);
    a.bind(child);
    let top = a.label();
    a.mov_imm(Reg::R12, n);
    a.bind(top);
    io(&mut a, READ, 3);
    io(&mut a, WRITE, 6);
    a.sub_imm(Reg::R12, 1);
    a.cmp_imm(Reg::R12, 0);
    a.jne(top);
    exit(&mut a, 0);
    a.bind(bad);
    exit(&mut a, 1);
    finish(a)
}

/// Maps `n` fresh anonymous pages and writes one word to each (one
/// demand-zero fault per page).
pub fn page_fault(n: u64) -> Vec<u8> {
    let mut a = Asm::new();
    let bad = a.label();
    prologue(&mut a);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, n * 4096);
    a.mov_imm(Reg::Rdx, 3); // PROT_READ | PROT_WRITE
    a.mov_imm(Reg::R10, 0x22); // MAP_PRIVATE | MAP_ANONYMOUS
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(MMAP);
    a.mov(Reg::Rbx, Reg::Rax);
    // An error is -4095..-1: above every user address.
    a.mov_imm(Reg::Rcx, u64::MAX - 4095);
    a.cmp(Reg::Rbx, Reg::Rcx);
    a.ja(bad);
    timed(&mut a, "page-fault", n, |a| {
        a.store(Reg::Rbx, 0, Reg::R12);
        a.add_imm(Reg::Rbx, 4096);
    });
    exit(&mut a, 0);
    a.bind(bad);
    exit(&mut a, 1);
    finish(a)
}

/// `n` times: fork; the child exits (or execs `/bin/true` with argv
/// `{"true"}`); the parent reaps it.
fn fork_loop(name: &str, n: u64, exec: bool) -> Vec<u8> {
    let mut a = Asm::new();
    let path = a.data(b"/bin/true\0");
    let argv0 = a.data(b"true\0");
    let child = a.label();
    prologue(&mut a);
    // argv = { "true", NULL } at rbp, envp = { NULL } at rbp + 8.
    a.mov_data(Reg::Rbx, argv0);
    a.store(Reg::Rbp, 0, Reg::Rbx);
    a.mov_imm(Reg::Rbx, 0);
    a.store(Reg::Rbp, 8, Reg::Rbx);
    timed(&mut a, name, n, |a| {
        a.sys(FORK);
        a.cmp_imm(Reg::Rax, 0);
        a.je(child);
        a.mov_imm(Reg::Rdi, u64::MAX);
        a.mov_imm(Reg::Rsi, 0);
        a.mov_imm(Reg::Rdx, 0);
        a.mov_imm(Reg::R10, 0);
        a.sys(WAIT4);
    });
    exit(&mut a, 0);
    a.bind(child);
    if exec {
        a.mov_data(Reg::Rdi, path);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.mov(Reg::Rdx, Reg::Rbp);
        a.add_imm(Reg::Rdx, 8);
        a.sys(EXECVE);
        exit(&mut a, 1); // exec failed
    }
    exit(&mut a, 0);
    finish(a)
}

/// `n` times fork + exit + wait.
pub fn fork_wait(n: u64) -> Vec<u8> {
    fork_loop("fork-wait", n, false)
}

/// `n` times fork + exec `/bin/true` + wait.
pub fn fork_exec_wait(n: u64) -> Vec<u8> {
    fork_loop("fork-exec-wait", n, true)
}

/// Parses one program's output line: `(name, iterations, nanoseconds)`.
pub fn parse(line: &str) -> Option<(&str, u64, u64)> {
    let rest = line.trim().strip_prefix("ichor-bench: ")?;
    let mut it = rest.split(' ');
    let name = it.next()?;
    let n = it.next()?.strip_prefix("n=")?.parse().ok()?;
    let ns = it.next()?.strip_prefix("ns=")?.parse().ok()?;
    Some((name, n, ns))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report_lines() {
        assert_eq!(
            parse("ichor-bench: null-syscall n=1000 ns=123456\n"),
            Some(("null-syscall", 1000, 123456))
        );
        assert_eq!(parse("ichor: bench: done"), None);
        assert_eq!(parse("ichor-bench: x n=1 ns=nope"), None);
    }

    #[test]
    fn every_program_assembles() {
        for (name, prog, n) in ALL {
            let elf = prog(*n);
            assert!(elf.len() > 64 + 56 + 32, "{name} is empty");
        }
    }

    /// On a Linux host (CI), run the programs that need no files and check
    /// what they print.
    #[cfg(target_os = "linux")]
    #[test]
    fn programs_run_and_report_on_linux() {
        extern crate std;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ichor-testprog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, prog, _) in ALL.iter().filter(|(n, _, _)| *n != "fork-exec-wait") {
            let path = dir.join(name);
            std::fs::write(&path, prog(100)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            let out = std::process::Command::new(&path).output().unwrap();
            assert!(out.status.success(), "{name} exited {:?}", out.status);
            let text = std::string::String::from_utf8(out.stdout).unwrap();
            let (got, n, ns) = parse(&text).unwrap_or_else(|| panic!("{name} printed {text:?}"));
            assert_eq!((got, n), (*name, 100));
            assert!(ns > 0, "{name} took no time");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
