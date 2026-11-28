//! Benchmarks (Phase E): the costs the scalability work is measured by.
//!
//! `bench` on the kernel command line runs them on the root disk after its
//! self-tests. Each microbenchmark is a tiny static ELF from
//! `testprog::bench`, run twice in a fresh cell with a small and a large
//! iteration count; the cost per operation is the difference in wall time
//! divided by the difference in iterations, so process start and exit
//! cancel out. The programs also time their own loops and print an
//! `ichor-bench:` line: the measurement the Linux reference boot reports.
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
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::time::Duration;

use frame::println;

use crate::kcell::{Cell, System};
use crate::pagecache::Mounted;
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::Vfs;
use testprog::bench;

/// Pages a benchmark cell may use (96 MiB: the page-fault program's 64 MiB
/// and the rest of the process).
const CELL_PAGES: u64 = 24576;

static ENABLED: AtomicBool = AtomicBool::new(false);

/// How many times the microbenchmarks run (`bench_rounds=N`, default 1).
static ROUNDS: AtomicU32 = AtomicU32::new(1);

/// Asks for the benchmarks to run (`bench` on the command line), each
/// microbenchmark `rounds` times (at least once).
pub(crate) fn enable(rounds: Option<u32>) {
    ENABLED.store(true, Ordering::Relaxed);
    ROUNDS.store(rounds.unwrap_or(1).clamp(1, 20), Ordering::Relaxed);
}

pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
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
    // The programs also time their own loops and print `ichor-bench:`
    // lines, the measurement the Linux reference boot reports.
    let rows: [Row<'_>; 5] = [
        ("null syscall", &bench::null_syscall, 1000, 201_000),
        ("pipe round trip", &bench::pipe_round_trip, 100, 10_100),
        // 64 MiB, the size Linux runs (`testprog::bench`'s table): 32
        // aligned blocks. The program's own line times the touch alone,
        // this row the process's exit too.
        ("page fault", &bench::page_fault, 16, 16384),
        ("fork + wait", &bench::fork_wait, 4, 204),
        ("fork + exec + wait", &bench::fork_exec_wait, 4, 104),
    ];
    // Several rounds show how much the first one, on memory the machine
    // has not touched yet, pays for that.
    for _ in 0..ROUNDS.load(Ordering::Relaxed) {
        for &(name, prog, small, large) in &rows {
            report(name, per_op(name, &system, vfs, prog, small, large));
        }
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
    caller_start(m);
    println!("ichor: bench: done");
}

/// Container start as a caller sees it, the way Linux's is measured with
/// `unshare` or an OCI runtime: `services/nativetest` in a system cell,
/// holding that cell (with `CREATE_CELL`) and the root disk as an image,
/// asks for each container through the native ABI (`CELL_CREATE`,
/// `CELL_SPAWN` of `/bin/true`, `PROCESS_WAIT` until it is reaped, then
/// closing both handles, which ends the cell) and times the loop itself.
/// It logs `native: start-bench n=.. ns=.. per_ns=..`.
fn caller_start(m: &Mounted) {
    use cap::{Cap, Rights};

    use crate::kcell::{Object, rights};
    const RUNS: &str = "20";
    // An image object lives for the life of the system, as IMAGE_CREATE's.
    let image: &'static Mounted = alloc::boxed::Box::leak(alloc::boxed::Box::new(Mounted {
        image: m.image,
        disk: m.disk,
    }));
    let system = System::new(CELL_PAGES * 2).unwrap_or_else(|| fail("bench: no caller cell"));
    let cell = system.cell.clone();
    let me = cell
        .install(Cap::mint(Object::Cell(cell.clone()), Rights::ALL))
        .unwrap_or_else(|| fail("bench: no cell handle"));
    let img = cell
        .install(Cap::mint(
            Object::Image(image),
            Rights::DUPLICATE | Rights::INSPECT | rights::READ,
        ))
        .unwrap_or_else(|| fail("bench: no image handle"));
    let hex = |h: cap::Handle| alloc::format!("{:x}", h.raw());
    let pages = alloc::format!("{CELL_PAGES}");
    let argv = [
        "nativetest",
        "start-bench",
        &hex(me),
        &hex(img),
        &pages,
        RUNS,
    ];
    if crate::native::run(&cell, crate::nativetest::NATIVETEST, &argv) != Some(0) {
        fail("bench: the caller-side container start failed");
    }
    // The cell holds a handle to itself; closing it breaks the cycle.
    let _ = cell.close(me);
    let _ = cell.close(img);
}
