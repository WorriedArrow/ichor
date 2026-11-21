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
    (
        &[
            "sh",
            "-c",
            "grep -q ^Tgid: /proc/self/status && ls /proc/self/fd | grep -q 2 && [ \"$(cat /proc/sys/kernel/ostype)\" = Linux ] && echo sh: /proc works",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "[ \"$(head -c 16 /dev/zero | wc -c)\" -eq 16 ] && echo x >/dev/null && head -c 8 /dev/urandom >/dev/null && echo sh: /dev works",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "trap 'echo sh: trap ran' USR1; kill -USR1 $$; echo sh: after the trap",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "sleep 30 & kill $!; wait $!; echo sh: sleep was killed, status $?",
        ],
        0,
    ),
    (
        &[
            "sh",
            "-c",
            "[ \"$(yes | head -n 3 | wc -l)\" -eq 3 ] && echo sh: yes died of SIGPIPE",
        ],
        0,
    ),
    (&["sh", "-c", "kill -9 $$; echo not reached"], -9),
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
    let cell = Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("no cell"));
    let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
    let (code, _) = run_linux(p, &crate::runtest::cloexec_program(), None, &["cloexec"]);
    if code != 0 {
        println!("ichor: busybox: cloexec test exited {code}");
        fail("close-on-exec");
    }
    let cell = Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("no cell"));
    let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
    let (code, _) = run_linux(
        p,
        &crate::runtest::exec_bytes_program(),
        None,
        &["execbytes"],
    );
    if code != 0 {
        println!("ichor: busybox: exec bytes test exited {code}");
        fail("exec argv/envp as bytes");
    }
}

pub(crate) fn read_busybox(vfs: &Arc<Vfs>) -> Vec<u8> {
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
