//! Boot tests.
//!
//! Milestone 0: the kernel boots as a UEFI application, prints to serial,
//! exits boot services and halts cleanly.
//!
//! Milestone 1: frame builds its own page tables and runs in the higher
//! half, the page allocator and heap work, traps are handled (including a
//! stack overflow caught by a guard page), and every CPU comes online and
//! takes timer interrupts.
//!
//! Milestone 2 (scheduler): kernel threads run on every CPU, block and wake
//! through wait queues, and never-yielding threads are preempted.
//!
//! Milestone 2 (user mode): a ring-3 program runs in its own address space,
//! makes a syscall, faults, and is isolated from another address space.
//!
//! Milestone 2 (cells): capabilities isolate cells, rights are enforced,
//! memory is accounted hierarchically, revocation works, and a native-ABI
//! ring-3 process can act only on handles its cell holds.
//!
//! Milestone 3: real static Linux x86-64 ELFs run unmodified in cells
//! through the Linux syscall personality, on a copy-on-write root read off
//! virtio-blk and NVMe disks by safe drivers. The acceptance test is the
//! official static busybox: echo, ls, cat, and a shell that forks, execs
//! and waits.

use ichor_tests::{Exit, boot, boot_disk, boot_disk_with};

const BOOT_MARKERS: &[&str] = &[
    "ichor: frame: entered from UEFI",
    "ichor: frame: boot services exited",
    "ichor: frame: running in the higher half",
    "ichor: frame: cpu0 ready (x2APIC id ",
    "ichor: kernel ",
    "ichor: memory: ",
    "ichor: acpi: rsdp at 0x",
    "ichor: kernel entry at 0xffffffff8",
    "ichor: heap: selftest passed",
    "ichor: trap: breakpoint handled (1 so far)",
];

#[test]
fn m1_boots_on_four_cpus() {
    let out = boot("m1-smp4", "memmap", 4);
    out.assert_exit(Exit::Success);
    out.assert_in_order(BOOT_MARKERS);
    out.assert_in_order(&[
        "ichor: smp: 4 CPUs online, every CPU took 5 timer interrupts",
        "ichor: random: ChaCha20 seeded",
        "ichor: xstate: XCR0 ",
        "ichor: time: wall clock from UEFI",
        "ichor: sched: 32 threads finished",
        "ichor: sched: 9 spinners on 4 CPUs all ran (preemption works",
        "ichor: sleep: 4 timed waits woke after their deadlines",
        "ichor: user: ring-3 program ran, 1 syscall(s), page fault at 0 handled, isolation ok",
        "ichor: cell: 2 cells isolated, rights enforced, accounting ok",
        "ichor: proc: native process ran, MEM_SIZE ok (4096), forged handle denied (error 2)",
        "hello from a real Linux ELF running on Ichor",
        "ichor: linux: static ELF ran via the Linux ABI, exited 7 after 2 syscalls",
        "hello from /etc/motd inside an Ichor image",
        "ichor: linux: cat read /etc/motd through a symlink in the image",
        "memtest ok",
        "ichor: linux: brk, mmap, mprotect, munmap, uname, getdents64 ok",
        "fstest ok",
        "ichor: linux: copy-on-write root: create, write, copy-up, rename, chdir, unlink, rmdir ok",
        "ichor: linux: copy-on-write fork isolated parent and child",
        "ichor: linux: thread clone, futex wait/wake and join via CHILD_CLEARTID ok",
        "ichor: linux: munmap shot down a page another thread was reading",
        "ichor: linux: poll timeout and wakeup, epoll, eventfd ok",
        "ichor: linux: fcntl record locks: conflict, F_GETLK, F_SETLKW wakeup ok",
        "ichor: linux: RLIMIT_NOFILE enforced, SA_ONSTACK handler ran on the sigaltstack",
        "ichor: linux: madvise DONTNEED zero-fills anonymous pages, refills file pages",
        "ichor: linux: MAP_SHARED anonymous memory and its futex are shared across fork",
        "ichor: linux: mremap moves and resizes mappings; prctl names and bounding set ok",
        "ichor: linux: EPOLLET edges, ppoll/epoll_pwait signal masks, vfork waits for the child",
        "ichor: linux: AVX state is per thread and survives signals",
        "ichor: blk: virtio-blk disk, ",
        "ichor: pagecache: opted-out cells read private copies charged to their own account; sharing cells share",
        "ichor: blk: virtio-blk: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the virtio-blk disk",
        "hello from /etc/motd on the root disk",
        "ichor: blk: cat read /etc/motd from the virtio-blk disk",
        "hello from busybox",
        "ichor: busybox: echo ok",
        "ichor: busybox: ls ok",
        "sh: pipes work",
        "sh: ls piped into grep",
        "sh: command substitution",
        "ichor: busybox: cat ok",
        "sh: /proc works",
        "sh: /dev works",
        "sh: trap ran",
        "sh: after the trap",
        "sh: sleep was killed, status 143",
        "sh: yes died of SIGPIPE",
        "sh: 6x7=42",
        "sh: fork, exec and wait ok",
        "ichor: busybox: all applets passed",
        "sh: CLOEXEC descriptors did not survive exec",
        "ichor: alpine: root disk holds Alpine 3.20.3",
        "ichor: alpine: /bin/busybox is dynamic, interpreter /lib/ld-musl-x86_64.so.1",
        "alpine: apk installed tree and jq from the local mirror",
        "alpine sh: 5",
        "alpine: /proc works",
        "Alpine Linux",
        "alpine: fork, exec via ld-musl, wait ok",
        "alpine: 2>&1 shares one offset",
        "alpine: two appenders kept every line",
        "alpine: flock excludes, then releases",
        "alpine: kill -pgid ended the whole group",
        "alpine: ulimit survives fork and exec",
        "alpine: /proc shows cell memory and threads",
        "alpine: wall clock, file times and urandom are real",
        "alpine: hard links, directory link counts, sparse 100 MiB file",
        "alpine: the image carries owners and times",
        "alpine: users and permissions are enforced",
        "alpine: sysinfo shows the cell",
        "ichor: alpine: all runs passed",
        "ichor: debian: root disk holds Debian 12",
        "debian: dash runs, release 12",
        "debian: coreutils run",
        "debian: nproc, getconf and stat agree",
        "debian: pty: openpty, line editing, echo, stty, ^C and hangup work",
        "Hello, world!",
        "debian: apt-get installed hello and jq from the local repository",
        "ichor: debian: all runs passed",
        "ichor: blk: nvme block size 4096 bytes",
        "ichor: blk: nvme: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the nvme disk",
        "ichor: blk: cat read /etc/motd from the nvme disk",
        "ichor: blk: tampered metadata is refused at mount; a tampered chunk reads as EIO",
        "ichor: pagecache: ",
        "ichor: memory: largest contiguous request 2^",
        "ichor: boot complete; halting",
    ]);
    // Every page the heap self-test used came back.
    out.assert_in_order(&["(0 pages not returned)"]);
    // Between 300 MiB and 512 MiB of the 512 MiB guest is usable.
    let usable_mib: u64 = out
        .serial
        .lines()
        .find_map(|l| {
            l.split(" MiB usable")
                .next()?
                .rsplit(' ')
                .next()?
                .parse()
                .ok()
        })
        .expect("memory summary line");
    assert!(
        (300..=512).contains(&usable_mib),
        "usable memory {usable_mib} MiB"
    );
}

#[test]
fn m1_boots_on_one_cpu() {
    let out = boot("m1-smp1", "", 1);
    out.assert_exit(Exit::Success);
    out.assert_in_order(BOOT_MARKERS);
    out.assert_in_order(&[
        "ichor: smp: 1 CPUs online, every CPU took 5 timer interrupts",
        "ichor: random: ChaCha20 seeded",
        "ichor: xstate: XCR0 ",
        "ichor: time: wall clock from UEFI",
        "ichor: sched: 32 threads finished",
        "ichor: sched: 3 spinners on 1 CPUs all ran (preemption works",
        "ichor: sleep: 4 timed waits woke after their deadlines",
        "ichor: user: ring-3 program ran, 1 syscall(s), page fault at 0 handled, isolation ok",
        "ichor: cell: 2 cells isolated, rights enforced, accounting ok",
        "ichor: proc: native process ran, MEM_SIZE ok (4096), forged handle denied (error 2)",
        "hello from a real Linux ELF running on Ichor",
        "ichor: linux: static ELF ran via the Linux ABI, exited 7 after 2 syscalls",
        "hello from /etc/motd inside an Ichor image",
        "ichor: linux: cat read /etc/motd through a symlink in the image",
        "memtest ok",
        "ichor: linux: brk, mmap, mprotect, munmap, uname, getdents64 ok",
        "fstest ok",
        "ichor: linux: copy-on-write root: create, write, copy-up, rename, chdir, unlink, rmdir ok",
        "ichor: linux: copy-on-write fork isolated parent and child",
        "ichor: linux: thread clone, futex wait/wake and join via CHILD_CLEARTID ok",
        "ichor: linux: munmap shot down a page another thread was reading",
        "ichor: linux: poll timeout and wakeup, epoll, eventfd ok",
        "ichor: linux: fcntl record locks: conflict, F_GETLK, F_SETLKW wakeup ok",
        "ichor: linux: RLIMIT_NOFILE enforced, SA_ONSTACK handler ran on the sigaltstack",
        "ichor: linux: madvise DONTNEED zero-fills anonymous pages, refills file pages",
        "ichor: linux: MAP_SHARED anonymous memory and its futex are shared across fork",
        "ichor: linux: mremap moves and resizes mappings; prctl names and bounding set ok",
        "ichor: linux: EPOLLET edges, ppoll/epoll_pwait signal masks, vfork waits for the child",
        "ichor: linux: AVX state is per thread and survives signals",
        "ichor: blk: virtio-blk disk, ",
        "ichor: blk: virtio-blk: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the virtio-blk disk",
        "hello from /etc/motd on the root disk",
        "ichor: blk: cat read /etc/motd from the virtio-blk disk",
        "hello from busybox",
        "ichor: busybox: echo ok",
        "ichor: busybox: ls ok",
        "sh: pipes work",
        "sh: ls piped into grep",
        "sh: command substitution",
        "ichor: busybox: cat ok",
        "sh: /proc works",
        "sh: /dev works",
        "sh: trap ran",
        "sh: after the trap",
        "sh: sleep was killed, status 143",
        "sh: yes died of SIGPIPE",
        "sh: 6x7=42",
        "sh: fork, exec and wait ok",
        "ichor: busybox: all applets passed",
        "sh: CLOEXEC descriptors did not survive exec",
        "ichor: alpine: root disk holds Alpine 3.20.3",
        "ichor: alpine: /bin/busybox is dynamic, interpreter /lib/ld-musl-x86_64.so.1",
        "alpine: apk installed tree and jq from the local mirror",
        "alpine sh: 5",
        "alpine: /proc works",
        "Alpine Linux",
        "alpine: fork, exec via ld-musl, wait ok",
        "alpine: 2>&1 shares one offset",
        "alpine: two appenders kept every line",
        "alpine: flock excludes, then releases",
        "alpine: kill -pgid ended the whole group",
        "alpine: ulimit survives fork and exec",
        "alpine: /proc shows cell memory and threads",
        "alpine: wall clock, file times and urandom are real",
        "alpine: hard links, directory link counts, sparse 100 MiB file",
        "alpine: the image carries owners and times",
        "alpine: users and permissions are enforced",
        "alpine: sysinfo shows the cell",
        "ichor: alpine: all runs passed",
        "ichor: debian: root disk holds Debian 12",
        "debian: dash runs, release 12",
        "debian: coreutils run",
        "debian: nproc, getconf and stat agree",
        "debian: pty: openpty, line editing, echo, stty, ^C and hangup work",
        "Hello, world!",
        "debian: apt-get installed hello and jq from the local repository",
        "ichor: debian: all runs passed",
        "ichor: blk: nvme block size 4096 bytes",
        "ichor: blk: nvme: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the nvme disk",
        "ichor: blk: cat read /etc/motd from the nvme disk",
        "ichor: blk: tampered metadata is refused at mount; a tampered chunk reads as EIO",
        "ichor: pagecache: ",
        "ichor: memory: largest contiguous request 2^",
        "ichor: boot complete; halting",
    ]);
}

#[test]
fn m2_scheduler_on_eight_cpus() {
    let out = boot("m2-smp8", "", 8);
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: smp: 8 CPUs online, every CPU took 5 timer interrupts",
        "ichor: random: ChaCha20 seeded",
        "ichor: xstate: XCR0 ",
        "ichor: time: wall clock from UEFI",
        "ichor: sched: 32 threads finished",
        "ichor: sched: 17 spinners on 8 CPUs all ran (preemption works",
        "ichor: sleep: 4 timed waits woke after their deadlines",
        "ichor: user: ring-3 program ran, 1 syscall(s), page fault at 0 handled, isolation ok",
        "ichor: cell: 2 cells isolated, rights enforced, accounting ok",
        "ichor: proc: native process ran, MEM_SIZE ok (4096), forged handle denied (error 2)",
        "hello from a real Linux ELF running on Ichor",
        "ichor: linux: static ELF ran via the Linux ABI, exited 7 after 2 syscalls",
        "hello from /etc/motd inside an Ichor image",
        "ichor: linux: cat read /etc/motd through a symlink in the image",
        "memtest ok",
        "ichor: linux: brk, mmap, mprotect, munmap, uname, getdents64 ok",
        "fstest ok",
        "ichor: linux: copy-on-write root: create, write, copy-up, rename, chdir, unlink, rmdir ok",
        "ichor: linux: copy-on-write fork isolated parent and child",
        "ichor: linux: thread clone, futex wait/wake and join via CHILD_CLEARTID ok",
        "ichor: linux: munmap shot down a page another thread was reading",
        "ichor: linux: poll timeout and wakeup, epoll, eventfd ok",
        "ichor: linux: fcntl record locks: conflict, F_GETLK, F_SETLKW wakeup ok",
        "ichor: linux: RLIMIT_NOFILE enforced, SA_ONSTACK handler ran on the sigaltstack",
        "ichor: linux: madvise DONTNEED zero-fills anonymous pages, refills file pages",
        "ichor: linux: MAP_SHARED anonymous memory and its futex are shared across fork",
        "ichor: linux: mremap moves and resizes mappings; prctl names and bounding set ok",
        "ichor: linux: EPOLLET edges, ppoll/epoll_pwait signal masks, vfork waits for the child",
        "ichor: linux: AVX state is per thread and survives signals",
        "ichor: blk: virtio-blk disk, ",
        "ichor: blk: virtio-blk: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the virtio-blk disk",
        "hello from /etc/motd on the root disk",
        "ichor: blk: cat read /etc/motd from the virtio-blk disk",
        "hello from busybox",
        "ichor: busybox: echo ok",
        "ichor: busybox: ls ok",
        "sh: pipes work",
        "sh: ls piped into grep",
        "sh: command substitution",
        "ichor: busybox: cat ok",
        "sh: /proc works",
        "sh: /dev works",
        "sh: trap ran",
        "sh: after the trap",
        "sh: sleep was killed, status 143",
        "sh: yes died of SIGPIPE",
        "sh: 6x7=42",
        "sh: fork, exec and wait ok",
        "ichor: busybox: all applets passed",
        "sh: CLOEXEC descriptors did not survive exec",
        "ichor: alpine: root disk holds Alpine 3.20.3",
        "ichor: alpine: /bin/busybox is dynamic, interpreter /lib/ld-musl-x86_64.so.1",
        "alpine: apk installed tree and jq from the local mirror",
        "alpine sh: 5",
        "alpine: /proc works",
        "Alpine Linux",
        "alpine: fork, exec via ld-musl, wait ok",
        "alpine: 2>&1 shares one offset",
        "alpine: two appenders kept every line",
        "alpine: flock excludes, then releases",
        "alpine: kill -pgid ended the whole group",
        "alpine: ulimit survives fork and exec",
        "alpine: /proc shows cell memory and threads",
        "alpine: wall clock, file times and urandom are real",
        "alpine: hard links, directory link counts, sparse 100 MiB file",
        "alpine: the image carries owners and times",
        "alpine: users and permissions are enforced",
        "alpine: sysinfo shows the cell",
        "ichor: alpine: all runs passed",
        "ichor: debian: root disk holds Debian 12",
        "debian: dash runs, release 12",
        "debian: coreutils run",
        "debian: nproc, getconf and stat agree",
        "debian: pty: openpty, line editing, echo, stty, ^C and hangup work",
        "Hello, world!",
        "debian: apt-get installed hello and jq from the local repository",
        "ichor: debian: all runs passed",
        "ichor: blk: nvme block size 4096 bytes",
        "ichor: blk: nvme: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the nvme disk",
        "ichor: blk: cat read /etc/motd from the nvme disk",
        "ichor: blk: tampered metadata is refused at mount; a tampered chunk reads as EIO",
        "ichor: pagecache: ",
        "ichor: memory: largest contiguous request 2^",
        "ichor: boot complete; halting",
    ]);
}

#[test]
fn panic_reports_failure_and_stops_other_cpus() {
    let out = boot("panic", "test_panic", 2);
    out.assert_exit(Exit::Failure);
    out.assert_in_order(&[
        "ichor: smp: 2 CPUs online",
        "ichor: KERNEL PANIC: ",
        "test_panic requested",
    ]);
}

/// A cloud-style boot: one GPT disk on NVMe (no vvfat ESP, no other
/// disks), the firmware booting `\EFI\BOOT\BOOTX64.EFI` from its FAT32
/// ESP with the command line in `\ichor\cmdline`, and the kernel finding
/// its root in the Ichor root partition and running busybox from it.
#[test]
fn cloud_disk_boots_from_gpt_on_nvme() {
    let out = boot_disk("cloud-disk", "", 2);
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: cmdline: \"qemu_debug_exit \"",
        "ichor: blk: no virtio-blk device",
        "ichor: blk: nvme: GPT disk, Ichor root partition at sector ",
        "ichor: blk: nvme disk, ",
        "ichor: blk: nvme: verified 300 KiB read across multiple requests",
        "ichor: blk: cat read /etc/motd from the nvme disk",
        "hello from busybox",
        "ichor: busybox: all applets passed",
        "ichor: boot complete; halting",
    ]);
}

/// A less friendly cloud VM: a blank NVMe volume ahead of the boot disk in
/// PCI order (as instance storage can be), a boot controller that allows
/// only 8 KiB per transfer (MDTS 1), 4 GiB and 4 vCPUs. The blank volume
/// is skipped, reads are split to fit, and the boot completes.
#[test]
fn cloud_disk_tolerates_blank_volumes_and_small_transfers() {
    let blank = std::env::temp_dir().join(format!("ichor-blank-{}.img", std::process::id()));
    std::fs::write(&blank, vec![0u8; 16 << 20]).unwrap();
    let out = boot_disk_with("cloud-disk-awkward", "", 4, |cfg| {
        cfg.memory_mib = 4096;
        cfg.disk_nvme_props = "mdts=1".into();
        cfg.disk_devices_before = vec![
            "-drive".into(),
            format!(
                "if=none,id=blank,format=raw,readonly=on,file={}",
                blank.display()
            ),
            "-device".into(),
            "nvme,serial=ichor-blank,drive=blank".into(),
        ];
    });
    let _ = std::fs::remove_file(&blank);
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: smp: 4 CPUs online",
        "ichor: blk: nvme: 16384 KiB, no Ichor image; skipped",
        "ichor: blk: nvme: GPT disk, Ichor root partition at sector ",
        "ichor: blk: nvme: verified 300 KiB read across multiple requests",
        "ichor: busybox: all applets passed",
        "ichor: boot complete; halting",
    ]);
}

/// The Phase E benchmarks still build and run (their numbers are printed,
/// not checked: CI machines vary).
#[test]
fn benchmarks_run_and_report() {
    let out = boot("bench", "bench", 4);
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: bench: 4 CPUs",
        "ichor: bench: null syscall: ",
        "ichor: bench: pipe round trip: ",
        "ichor: bench: page fault: ",
        "ichor: bench: fork + wait: ",
        "ichor: bench: fork + exec + wait: ",
        "ichor: bench: container start: ",
        "ichor: bench: done",
    ]);
}

#[test]
fn stack_overflow_hits_the_guard_page() {
    let out = boot("stack-overflow", "test_stack_overflow", 1);
    out.assert_exit(Exit::Failure);
    out.assert_in_order(&[
        "ichor: overflowing the kernel stack",
        "ichor: KERNEL PANIC: ",
        "double fault (kernel stack overflow)",
    ]);
}
