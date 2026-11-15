//! Milestone 4, first step: Alpine Linux's own userland, unmodified, in a
//! cell. The cell's root is Alpine's minirootfs (read off its own disk,
//! with a copy-on-write upper layer). `/bin/busybox` there is a dynamically
//! linked PIE, so every run goes through `ld-musl` (`PT_INTERP`), and the
//! shell's children are exec'd the same way.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::println;

use crate::kcell::{Cell, System};
use crate::loader;
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::{ROOT, Vfs};

const CELL_PAGES: u64 = 8192;

/// `(argv, expected exit code)`. argv[0] selects the busybox applet.
const RUNS: &[(&[&str], i32)] = &[
    (&["cat", "/etc/alpine-release"], 0),
    (&["sh", "-c", "echo alpine sh: $((2+3))"], 0),
    (
        &[
            "sh",
            "-c",
            "[ \"$(readlink /proc/self/exe)\" = /usr/bin/readlink ] && head -1 /proc/meminfo | grep -q MemTotal && ls /proc/self | grep -q maps && echo alpine: /proc works",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "grep -h ^NAME /etc/os-release | cut -d= -f2 | tr -d '\"'",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "/bin/true && echo alpine: fork, exec via ld-musl, wait ok",
        ],
        0,
    ),
    (
        &["sh", "-c", "echo hi > /tmp/f && cat /tmp/f && rm /tmp/f"],
        0,
    ),
];

fn read(vfs: &Vfs, path: &str) -> Vec<u8> {
    let mut fs = vfs.lock();
    let ino = fs
        .resolve(ROOT, path, true)
        .unwrap_or_else(|_| fail("alpine: missing file"));
    let size = fs.stat(ino).map(|s| s.size).unwrap_or(0) as usize;
    let mut v = alloc::vec![0u8; size];
    let n = fs.read(ino, 0, &mut v).unwrap_or(0);
    v.truncate(n);
    v
}

pub(crate) fn run(vfs: &Arc<Vfs>) {
    let release = read(vfs, "/etc/alpine-release");
    println!(
        "ichor: alpine: root disk holds Alpine {}",
        String::from_utf8_lossy(&release).trim()
    );
    let busybox = read(vfs, "/bin/busybox");
    let interp_path = match loader::interp_path(&busybox) {
        Ok(Some(p)) => p,
        _ => fail("alpine: /bin/busybox is not dynamically linked"),
    };
    let interp = read(vfs, &interp_path);
    println!(
        "ichor: alpine: /bin/busybox is dynamic, interpreter {interp_path} ({} KiB)",
        interp.len() / 1024
    );
    let system = System::new(CELL_PAGES * 2).unwrap_or_else(|| fail("no system cell"));
    for (argv, want) in RUNS {
        let cell =
            Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("no alpine cell"));
        let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
        let (code, syscalls) = run_linux(p, &busybox, Some(&interp), argv);
        if code != *want {
            println!("ichor: alpine: {argv:?} exited {code}, expected {want}");
            fail("alpine applet");
        }
        println!("ichor: alpine: {} ok ({syscalls} syscalls)", argv[0]);
    }
    println!("ichor: alpine: all runs passed");
}
