//! Benchmarks (Phase E): the costs the scalability work is measured by.
//!
//! `bench` on the kernel command line runs them on the root disk after its
//! self-tests (`cargo xtask bench`). Each microbenchmark is a tiny static
//! ELF run twice in a fresh cell, with a small and a large iteration
//! count; the cost per operation is the difference in wall time divided by
//! the difference in iterations, so process start and exit cancel out.
//!
//! - null syscall: `getpid` in a loop.
//! - pipe round trip: a byte to a forked child and back over two pipes
//!   (two wake-ups and, on one CPU, two context switches).
//! - page fault: first touch of fresh anonymous pages (demand-zero fault).
//! - fork + wait: `fork`, the child exits, the parent reaps it.
//! - fork + exec + wait: the same with the child exec'ing busybox `true`.
//! - container start: mount a fresh root from the disk's image (root hash
//!   checked), create a cell, run busybox `true` in it to exit.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use frame::println;

use crate::kcell::{Cell, System};
use crate::pagecache::Mounted;
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::Vfs;
use testprog::{Asm, BLOB_VADDR, Reg, static_elf};

const GETPID: u64 = 39;
const READ: u64 = 0;
const WRITE: u64 = 1;
const MMAP: u64 = 9;
const PIPE2: u64 = 293;
const FORK: u64 = 57;
const EXECVE: u64 = 59;
const WAIT4: u64 = 61;
const EXIT_GROUP: u64 = 231;

/// Pages a benchmark cell may use (64 MiB).
const CELL_PAGES: u64 = 16384;

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Asks for the benchmarks to run (`bench` on the command line).
pub(crate) fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

fn elf(a: Asm) -> Vec<u8> {
    static_elf(
        &a.finish(BLOB_VADDR)
            .unwrap_or_else(|| fail("bench: assembler")),
    )
}

/// `loop { body } n times` around `body`, counting in r12.
fn looped(a: &mut Asm, n: u64, body: impl FnOnce(&mut Asm)) {
    let top = a.label();
    a.mov_imm(Reg::R12, n);
    a.bind(top);
    body(a);
    a.sub_imm(Reg::R12, 1);
    a.cmp_imm(Reg::R12, 0);
    a.jne(top);
}

fn exit0(a: &mut Asm) {
    a.mov_imm(Reg::Rdi, 0);
    a.sys(EXIT_GROUP);
}

/// `n` times `getpid`.
fn null_syscall(n: u64) -> Vec<u8> {
    let mut a = Asm::new();
    looped(&mut a, n, |a| a.sys(GETPID));
    exit0(&mut a);
    elf(a)
}

/// `n` round trips of one byte: parent writes fd 4 and reads fd 5; the
/// child reads fd 3 and writes fd 6.
fn pipe_round_trip(n: u64) -> Vec<u8> {
    let mut a = Asm::new();
    let child = a.label();
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    for off in [0, 8] {
        a.mov(Reg::Rdi, Reg::Rbp);
        a.add_imm(Reg::Rdi, off);
        a.mov_imm(Reg::Rsi, 0);
        a.sys(PIPE2);
    }
    a.sys(FORK);
    a.cmp_imm(Reg::Rax, 0);
    a.je(child);
    let io = |a: &mut Asm, nr: u64, fd: u64| {
        a.mov_imm(Reg::Rdi, fd);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.add_imm(Reg::Rsi, 64);
        a.mov_imm(Reg::Rdx, 1);
        a.sys(nr);
    };
    looped(&mut a, n, |a| {
        io(a, WRITE, 4);
        io(a, READ, 5);
    });
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(WAIT4);
    exit0(&mut a);
    a.bind(child);
    looped(&mut a, n, |a| {
        io(a, READ, 3);
        io(a, WRITE, 6);
    });
    exit0(&mut a);
    elf(a)
}

/// Maps `n` anonymous pages and writes one word to each.
fn page_fault(n: u64) -> Vec<u8> {
    let mut a = Asm::new();
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, n * 4096);
    a.mov_imm(Reg::Rdx, 3); // PROT_READ | PROT_WRITE
    a.mov_imm(Reg::R10, 0x22); // MAP_PRIVATE | MAP_ANONYMOUS
    a.mov_imm(Reg::R8, u64::MAX);
    a.mov_imm(Reg::R9, 0);
    a.sys(MMAP);
    a.mov(Reg::Rbx, Reg::Rax);
    looped(&mut a, n, |a| {
        a.store(Reg::Rbx, 0, Reg::R12);
        a.add_imm(Reg::Rbx, 4096);
    });
    exit0(&mut a);
    elf(a)
}

/// `n` times: fork; the child exits (or execs busybox `true`); reap it.
fn fork_wait(n: u64, exec: bool) -> Vec<u8> {
    let mut a = Asm::new();
    let path = a.data(b"/bin/true\0");
    let name = a.data(b"true\0");
    let child = a.label();
    let top = a.label();
    a.mov(Reg::Rbp, Reg::Rsp);
    a.sub_imm(Reg::Rbp, 4096);
    // argv = { "true", NULL } and envp = { NULL } at rbp.
    a.mov_data(Reg::Rbx, name);
    a.store(Reg::Rbp, 0, Reg::Rbx);
    a.mov_imm(Reg::Rbx, 0);
    a.store(Reg::Rbp, 8, Reg::Rbx);
    a.mov_imm(Reg::R12, n);
    a.bind(top);
    a.sys(FORK);
    a.cmp_imm(Reg::Rax, 0);
    a.je(child);
    a.mov_imm(Reg::Rdi, u64::MAX);
    a.mov_imm(Reg::Rsi, 0);
    a.mov_imm(Reg::Rdx, 0);
    a.mov_imm(Reg::R10, 0);
    a.sys(WAIT4);
    a.sub_imm(Reg::R12, 1);
    a.cmp_imm(Reg::R12, 0);
    a.jne(top);
    exit0(&mut a);
    a.bind(child);
    if exec {
        a.mov_data(Reg::Rdi, path);
        a.mov(Reg::Rsi, Reg::Rbp);
        a.mov(Reg::Rdx, Reg::Rbp);
        a.add_imm(Reg::Rdx, 8);
        a.sys(EXECVE);
        a.mov_imm(Reg::Rdi, 1); // exec failed
        a.sys(EXIT_GROUP);
    }
    exit0(&mut a);
    elf(a)
}

fn time(f: impl FnOnce()) -> Duration {
    let start = frame::time::now();
    f();
    frame::time::now().saturating_sub(start)
}

/// Cost per iteration of `prog`, from runs of `small` and `large`.
fn per_op(
    name: &str,
    system: &System,
    vfs: &Arc<Vfs>,
    prog: impl Fn(u64) -> Vec<u8>,
    small: u64,
    large: u64,
) -> Duration {
    let run = |n: u64| {
        let elf = prog(n);
        let cell =
            Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("bench: no cell"));
        let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("bench: no process"));
        let mut status = 0;
        let t = time(|| status = run_linux(p, &elf, None, &[name]).0);
        if status != 0 {
            println!("ichor: bench: {name} exited {status}");
            fail("benchmark program failed");
        }
        t
    };
    let a = run(small);
    let b = run(large);
    b.saturating_sub(a) / u32::try_from(large - small).unwrap_or(u32::MAX)
}

fn report(name: &str, d: Duration) {
    let ns = d.as_nanos();
    if ns >= 10_000 {
        println!("ichor: bench: {name}: {} us", ns / 1000);
    } else {
        println!("ichor: bench: {name}: {ns} ns");
    }
}

/// A microbenchmark: name, program builder (iterations -> ELF), and the
/// small and large iteration counts.
type Row<'a> = (&'a str, &'a dyn Fn(u64) -> Vec<u8>, u64, u64);

/// Runs the benchmarks against the root disk `m` (mounted as `vfs`), whose
/// `/bin/busybox` they exec.
pub(crate) fn run(m: &Mounted, vfs: &Arc<Vfs>, busybox: &[u8]) {
    let cpus = frame::cpu::online_count();
    println!("ichor: bench: {cpus} CPUs; per operation, from a small and a large run");
    let system = System::new(CELL_PAGES * 2).unwrap_or_else(|| fail("bench: no system cell"));
    let rows: [Row<'_>; 5] = [
        ("null syscall", &null_syscall, 1000, 201_000),
        ("pipe round trip", &pipe_round_trip, 100, 10_100),
        ("page fault", &page_fault, 16, 4112),
        ("fork + wait", &|n| fork_wait(n, false), 4, 204),
        ("fork + exec + wait", &|n| fork_wait(n, true), 4, 104),
    ];
    for (name, prog, small, large) in rows {
        report(name, per_op(name, &system, vfs, prog, small, large));
    }
    // Container start: a fresh root and cell per run.
    const STARTS: u32 = 10;
    let total = time(|| {
        for _ in 0..STARTS {
            let root =
                Arc::new(Vfs::mount_disk(m).unwrap_or_else(|_| fail("bench: mounting a root")));
            let cell = Cell::new(&system.root_account, CELL_PAGES)
                .unwrap_or_else(|| fail("bench: no cell"));
            let p = LinuxProcess::new(cell, root).unwrap_or_else(|| fail("bench: no process"));
            if run_linux(p, busybox, None, &["true"]).0 != 0 {
                fail("bench: busybox true failed");
            }
        }
    });
    report("container start", total / STARTS);
    println!("ichor: bench: done");
}
