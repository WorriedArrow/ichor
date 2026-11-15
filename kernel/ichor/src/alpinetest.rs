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
    (
        &[
            "sh",
            "-c",
            "apk add --no-network /mirror/tree-2.1.1-r0.apk /mirror/oniguruma-6.9.9-r0.apk \
             /mirror/jq-1.7.1-r0.apk && apk info -e tree jq oniguruma >/dev/null && \
             tree /etc/apk >/dev/null && [ \"$(echo '{\"a\":[1,2,3]}' | jq '.a|add')\" = 6 ] && \
             echo alpine: apk installed tree and jq from the local mirror",
        ],
        0,
    ),
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
    (
        &[
            "sh",
            "-c",
            "{ echo out1; echo err >&2; echo out2; } >/tmp/o 2>&1; \
             [ \"$(wc -l < /tmp/o)\" = 3 ] && [ \"$(sed -n 2p /tmp/o)\" = err ] && \
             echo 'alpine: 2>&1 shares one offset'",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "rm -f /tmp/ap; (for i in $(seq 200); do echo aaaaaaaa; done >>/tmp/ap) & \
             (for i in $(seq 200); do echo bbbbbbbb; done >>/tmp/ap) & wait; \
             [ \"$(wc -l < /tmp/ap)\" = 400 ] && [ \"$(grep -c a /tmp/ap)\" = 200 ] && \
             echo alpine: two appenders kept every line",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "touch /tmp/l; flock -x /tmp/l -c 'flock -n -x /tmp/l -c true'; [ $? = 1 ] && \
             flock -n /tmp/l -c true && echo alpine: flock excludes, then releases",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "rm -f /tmp/pg /tmp/ids; \
             setsid sh -c 'read l </proc/self/stat; echo $l | cut -d\" \" -f1,5,6 >/tmp/ids; \
             sleep 30 & sleep 30 & echo $$ >/tmp/pg; wait' & \
             while [ ! -s /tmp/pg ]; do sleep 0.05; done; \
             kill -s TERM -$(cat /tmp/pg); wait; \
             set -- $(cat /tmp/ids); [ \"$1\" = \"$2\" ] && [ \"$2\" = \"$3\" ] && \
             echo alpine: kill -pgid ended the whole group",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "ulimit -n 64 && [ \"$(ulimit -n)\" = 64 ] && ulimit -s 512 && \
             [ \"$(sh -c 'ulimit -s')\" = 512 ] && ! ulimit -n 4096 2>/dev/null && \
             echo alpine: ulimit survives fork and exec",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "[ \"$(awk '/^MemTotal/ {print $2}' /proc/meminfo)\" = 32768 ] && \
             read a b c d e </proc/loadavg && [ \"${d#*/}\" -ge 1 ] && [ \"$e\" -gt 1 ] && \
             [ \"$(awk '/^VmSize/ {print ($2 > 0)}' /proc/self/status)\" = 1 ] && \
             echo alpine: /proc shows cell memory and threads",
        ],
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
