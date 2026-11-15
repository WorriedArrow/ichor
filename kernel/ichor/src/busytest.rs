//! Milestone 3 acceptance: a real, unmodified static busybox (the official
//! busybox.net musl build, put on the root disk by xtask) runs applets in a
//! cell through the Linux ABI, including a shell that forks, execs and
//! waits.

use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::println;

use crate::kcell::{Cell, System};
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::{ROOT, Vfs};

/// Pages the busybox cell may use (32 MiB).
const CELL_PAGES: u64 = 8192;

/// `(argv, expected exit code)`.
const RUNS: &[(&[&str], i32)] = &[
    (&["echo", "hello from busybox"], 0),
    (&["ls", "/etc", "/bin"], 0),
    (&["sh", "-c", "echo sh: pipes work | cat"], 0),
    (
        &[
            "sh",
            "-c",
            "ls /bin | grep -q wc && echo sh: ls piped into grep",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "[ \"$(echo a b c | wc -w)\" -eq 3 ] && echo sh: command substitution",
        ],
        0,
    ),
    (&["cat", "/etc/motd"], 0),
    (&["sh", "-c", "echo sh: 6x7=$((6*7)); exit 3"], 3),
    (
        &["sh", "-c", "/bin/true && echo sh: fork, exec and wait ok"],
        0,
    ),
];

pub(crate) fn run(vfs: &Arc<Vfs>) {
    let elf = read_busybox(vfs);
    println!(
        "ichor: busybox: {} KiB static ELF from the root disk",
        elf.len() / 1024
    );
    let system = System::new(CELL_PAGES * 2).unwrap_or_else(|| fail("no system cell"));
    for (argv, want) in RUNS {
        let cell =
            Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("no busybox cell"));
        let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
        let (code, syscalls) = run_linux(p, &elf, None, argv);
        if code != *want {
            println!("ichor: busybox: {argv:?} exited {code}, expected {want}");
            fail("busybox applet");
        }
        println!("ichor: busybox: {} ok ({syscalls} syscalls)", argv[0]);
    }
    println!("ichor: busybox: all applets passed");
}

fn read_busybox(vfs: &Arc<Vfs>) -> Vec<u8> {
    let mut fs = vfs.lock();
    let ino = fs
        .resolve(ROOT, "/bin/busybox", true)
        .unwrap_or_else(|_| fail("no /bin/busybox on the root disk"));
    let size = fs.stat(ino).map(|s| s.size).unwrap_or(0) as usize;
    let mut elf = alloc::vec![0u8; size];
    let n = fs.read(ino, 0, &mut elf).unwrap_or(0);
    if n != size || size == 0 {
        fail("could not read /bin/busybox");
    }
    elf
}
