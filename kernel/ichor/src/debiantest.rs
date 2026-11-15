//! Milestone 4, Phase D: Debian 12 (bookworm-slim) userland, unmodified,
//! in a cell. Its programs are glibc-linked: every run goes through
//! glibc's `ld-linux-x86-64.so.2` (`PT_INTERP`).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::println;

use crate::kcell::{Cell, System};
use crate::loader;
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::{ROOT, Vfs};

const CELL_PAGES: u64 = 65536;

/// `(argv, expected exit code)`: argv[0] is a path under `/usr/bin`.
const RUNS: &[(&[&str], i32)] = &[
    (
        &[
            "dash",
            "-c",
            "echo debian: dash runs, release $(cat /etc/debian_version)",
        ],
        0,
    ),
    (
        &[
            "dash",
            "-c",
            "ls /usr/bin >/dev/null && [ \"$(id -u)\" = 0 ] && \
             printf 'b\\na\\n' | sort | head -1 | grep -q a && \
             echo debian: coreutils run",
        ],
        0,
    ),
    (
        &[
            "dash",
            "-c",
            "export DEBIAN_FRONTEND=noninteractive; apt-get update -q &&              apt-get install -y -q --no-install-recommends hello jq && hello &&              [ \"$(echo '{\"a\":[1,2,3]}' | jq '.a|add')\" = 6 ] && dpkg -s libonig5 >/dev/null &&              echo debian: apt-get installed hello and jq from the local repository",
        ],
        0,
    ),
];

fn read(vfs: &Vfs, path: &str) -> Vec<u8> {
    let mut fs = vfs.lock();
    let ino = fs
        .resolve(ROOT, path, true)
        .unwrap_or_else(|_| fail("debian: missing file"));
    let size = fs.stat(ino).map(|s| s.size).unwrap_or(0) as usize;
    let mut v = alloc::vec![0u8; size];
    let n = fs.read(ino, 0, &mut v).unwrap_or(0);
    v.truncate(n);
    v
}

pub(crate) fn run(vfs: &Arc<Vfs>) {
    let release = read(vfs, "/etc/debian_version");
    println!(
        "ichor: debian: root disk holds Debian {}",
        String::from_utf8_lossy(&release).trim()
    );
    let system = System::new(CELL_PAGES * 2).unwrap_or_else(|| fail("no system cell"));
    for (argv, want) in RUNS {
        let exe = read(vfs, &alloc::format!("/usr/bin/{}", argv[0]));
        let interp_path = match loader::interp_path(&crate::file::Bytes(&exe)) {
            Ok(Some(p)) => p,
            _ => fail("debian: program is not dynamically linked"),
        };
        let interp = read(vfs, &interp_path);
        let cell =
            Cell::new(&system.root_account, CELL_PAGES).unwrap_or_else(|| fail("no debian cell"));
        let p = LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process"));
        let (code, syscalls) = run_linux(p, &exe, Some(&interp), argv);
        if code != *want {
            println!("ichor: debian: {argv:?} exited {code}, expected {want}");
            fail("debian program");
        }
        println!("ichor: debian: {} ok ({syscalls} syscalls)", argv[0]);
    }
    println!("ichor: debian: all runs passed");
}
