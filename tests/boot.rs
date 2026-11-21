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
    // VERW on every return to ring 3, forced (ADR-0004): everything below
    // runs through that path too.
    let out = boot("m1-smp4", "memmap force_verw", 4);
    out.assert_exit(Exit::Success);
    out.assert_in_order(BOOT_MARKERS);
    out.assert_in_order(&[
        "ichor: frame: mitigations (ADR-0004): VERW on return to ring 3 on",
        "ichor: mitigations: ",
        "ichor: boot complete",
    ]);
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
        "ichor: usercopy: frame refuses kernel writes through read-only PTEs; no copy landed after unmap",
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
        "ichor: linux: a backward rep movsq resumed backward across 16 page faults",
        "ichor: linux: close_range, fadvise64, get/setpriority ok",
        "ichor: linux: poll timeout and wakeup, epoll, eventfd ok",
        "ichor: linux: io_uring: linked write and read, armed read woken by a child, timeout, probe ok",
        "ichor: linux: io_uring: armed reads completed with nobody in io_uring_enter (registered eventfd, epoll on the ring)",
        "ichor: linux: fcntl record locks: conflict, F_GETLK, F_SETLKW wakeup ok",
        "ichor: linux: SCM_RIGHTS passed a descriptor over AF_UNIX, seqpacket kept boundaries, SO_PEERCRED named us",
        "ichor: linux: RLIMIT_NOFILE enforced, SA_ONSTACK handler ran on the sigaltstack",
        "ichor: linux: madvise DONTNEED zero-fills anonymous pages, refills file pages",
        "ichor: linux: MAP_SHARED anonymous memory and its futex are shared across fork",
        "ichor: linux: mremap moves and resizes mappings; prctl names and bounding set ok",
        "ichor: linux: EPOLLET edges, ppoll/epoll_pwait signal masks, vfork waits for the child",
        "ichor: linux: AVX state is per thread and survives signals",
        "ichor: net: socket buffers are charged to the cell: a 1 MiB loopback transfer peaked at",
        "ichor: unix: a stream queue stopped at its cell's 24 pages and gave them back when read",
        "native: hello-world ran in cell 10.88.",
        "native: clock, random, heap, TCP, UDP and a container in",
        "ichor: native: v2 self-test passed",
        "ichor: blk: virtio-blk disk, ",
        "ichor: pagecache: opted-out cells read private copies charged to their own account; sharing cells share",
        "ichor: blk: virtio-blk: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the virtio-blk disk",
        "hello from /etc/motd on the root disk",
        "ichor: blk: cat read /etc/motd from the virtio-blk disk",
        "ichor: usercopy: read and stat into read-only pages return EFAULT; read into a private file mapping broke copy-on-write; another cell and the page cache kept the original bytes",
        "ichor: usercopy: reads raced 600+ munmap/mmap/mprotect rounds; each completed or returned EFAULT; page cache intact",
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
        "sh: exec passed a 5000-byte argument and a non-UTF-8 environment",
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
        "alpine: nginx and redis installed from the local mirror",
        "alpine: redis-benchmark: SET:",
        "alpine: redis-benchmark: GET:",
        "alpine: nginx served six pages and redis answered from cell 10.88.",
        "workers over AF_UNIX channels and stopped them",
        "alpine: nginx and redis stopped",
        "ichor: alpine: all runs passed",
        "ichor: debian: root disk holds Debian 12",
        "debian: dash runs, release 12",
        "debian: coreutils run",
        "debian: nproc, getconf and stat agree",
        "debian: pty: openpty, line editing, echo, stty, ^C and hangup work",
        "debian: sockets: refused, EADDRINUSE, 1 MiB each way, half-close, non-blocking connect and accept work",
        "debian: udp: datagrams keep boundaries and sources, truncate, connect filters, ports are per protocol",
        "debian: alarm and setitimer deliver SIGALRM, getitimer reads back",
        "debian: unix: socketpair, path servers, abstract datagrams, SO_PEERCRED and end of file work",
        "Hello, world!",
        "debian: apt-get installed hello and jq from the local repository",
        "through the switch; loopback is per cell",
        "debian: cells: a datagram crossed the switch and came back",
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
        "ichor: usercopy: frame refuses kernel writes through read-only PTEs; no copy landed after unmap",
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
        "ichor: linux: a backward rep movsq resumed backward across 16 page faults",
        "ichor: linux: close_range, fadvise64, get/setpriority ok",
        "ichor: linux: poll timeout and wakeup, epoll, eventfd ok",
        "ichor: linux: io_uring: linked write and read, armed read woken by a child, timeout, probe ok",
        "ichor: linux: io_uring: armed reads completed with nobody in io_uring_enter (registered eventfd, epoll on the ring)",
        "ichor: linux: fcntl record locks: conflict, F_GETLK, F_SETLKW wakeup ok",
        "ichor: linux: SCM_RIGHTS passed a descriptor over AF_UNIX, seqpacket kept boundaries, SO_PEERCRED named us",
        "ichor: linux: RLIMIT_NOFILE enforced, SA_ONSTACK handler ran on the sigaltstack",
        "ichor: linux: madvise DONTNEED zero-fills anonymous pages, refills file pages",
        "ichor: linux: MAP_SHARED anonymous memory and its futex are shared across fork",
        "ichor: linux: mremap moves and resizes mappings; prctl names and bounding set ok",
        "ichor: linux: EPOLLET edges, ppoll/epoll_pwait signal masks, vfork waits for the child",
        "ichor: linux: AVX state is per thread and survives signals",
        "ichor: net: socket buffers are charged to the cell: a 1 MiB loopback transfer peaked at",
        "ichor: unix: a stream queue stopped at its cell's 24 pages and gave them back when read",
        "native: hello-world ran in cell 10.88.",
        "native: clock, random, heap, TCP, UDP and a container in",
        "ichor: native: v2 self-test passed",
        "ichor: blk: virtio-blk disk, ",
        "ichor: blk: virtio-blk: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the virtio-blk disk",
        "hello from /etc/motd on the root disk",
        "ichor: blk: cat read /etc/motd from the virtio-blk disk",
        "ichor: usercopy: read and stat into read-only pages return EFAULT; read into a private file mapping broke copy-on-write; another cell and the page cache kept the original bytes",
        "ichor: usercopy: reads raced 600+ munmap/mmap/mprotect rounds; each completed or returned EFAULT; page cache intact",
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
        "sh: exec passed a 5000-byte argument and a non-UTF-8 environment",
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
        "alpine: nginx and redis installed from the local mirror",
        "alpine: redis-benchmark: SET:",
        "alpine: redis-benchmark: GET:",
        "alpine: nginx served six pages and redis answered from cell 10.88.",
        "workers over AF_UNIX channels and stopped them",
        "alpine: nginx and redis stopped",
        "ichor: alpine: all runs passed",
        "ichor: debian: root disk holds Debian 12",
        "debian: dash runs, release 12",
        "debian: coreutils run",
        "debian: nproc, getconf and stat agree",
        "debian: pty: openpty, line editing, echo, stty, ^C and hangup work",
        "debian: sockets: refused, EADDRINUSE, 1 MiB each way, half-close, non-blocking connect and accept work",
        "debian: udp: datagrams keep boundaries and sources, truncate, connect filters, ports are per protocol",
        "debian: alarm and setitimer deliver SIGALRM, getitimer reads back",
        "debian: unix: socketpair, path servers, abstract datagrams, SO_PEERCRED and end of file work",
        "Hello, world!",
        "debian: apt-get installed hello and jq from the local repository",
        "through the switch; loopback is per cell",
        "debian: cells: a datagram crossed the switch and came back",
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
        "ichor: usercopy: frame refuses kernel writes through read-only PTEs; no copy landed after unmap",
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
        "ichor: linux: a backward rep movsq resumed backward across 16 page faults",
        "ichor: linux: close_range, fadvise64, get/setpriority ok",
        "ichor: linux: poll timeout and wakeup, epoll, eventfd ok",
        "ichor: linux: io_uring: linked write and read, armed read woken by a child, timeout, probe ok",
        "ichor: linux: io_uring: armed reads completed with nobody in io_uring_enter (registered eventfd, epoll on the ring)",
        "ichor: linux: fcntl record locks: conflict, F_GETLK, F_SETLKW wakeup ok",
        "ichor: linux: SCM_RIGHTS passed a descriptor over AF_UNIX, seqpacket kept boundaries, SO_PEERCRED named us",
        "ichor: linux: RLIMIT_NOFILE enforced, SA_ONSTACK handler ran on the sigaltstack",
        "ichor: linux: madvise DONTNEED zero-fills anonymous pages, refills file pages",
        "ichor: linux: MAP_SHARED anonymous memory and its futex are shared across fork",
        "ichor: linux: mremap moves and resizes mappings; prctl names and bounding set ok",
        "ichor: linux: EPOLLET edges, ppoll/epoll_pwait signal masks, vfork waits for the child",
        "ichor: linux: AVX state is per thread and survives signals",
        "ichor: net: socket buffers are charged to the cell: a 1 MiB loopback transfer peaked at",
        "ichor: unix: a stream queue stopped at its cell's 24 pages and gave them back when read",
        "native: hello-world ran in cell 10.88.",
        "native: clock, random, heap, TCP, UDP and a container in",
        "ichor: native: v2 self-test passed",
        "ichor: blk: virtio-blk disk, ",
        "ichor: blk: virtio-blk: verified 300 KiB read across multiple requests",
        "ichor: blk: mounted the root image from the virtio-blk disk",
        "hello from /etc/motd on the root disk",
        "ichor: blk: cat read /etc/motd from the virtio-blk disk",
        "ichor: usercopy: read and stat into read-only pages return EFAULT; read into a private file mapping broke copy-on-write; another cell and the page cache kept the original bytes",
        "ichor: usercopy: reads raced 600+ munmap/mmap/mprotect rounds; each completed or returned EFAULT; page cache intact",
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
        "sh: exec passed a 5000-byte argument and a non-UTF-8 environment",
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
        "alpine: nginx and redis installed from the local mirror",
        "alpine: redis-benchmark: SET:",
        "alpine: redis-benchmark: GET:",
        "alpine: nginx served six pages and redis answered from cell 10.88.",
        "workers over AF_UNIX channels and stopped them",
        "alpine: nginx and redis stopped",
        "ichor: alpine: all runs passed",
        "ichor: debian: root disk holds Debian 12",
        "debian: dash runs, release 12",
        "debian: coreutils run",
        "debian: nproc, getconf and stat agree",
        "debian: pty: openpty, line editing, echo, stty, ^C and hangup work",
        "debian: sockets: refused, EADDRINUSE, 1 MiB each way, half-close, non-blocking connect and accept work",
        "debian: udp: datagrams keep boundaries and sources, truncate, connect filters, ports are per protocol",
        "debian: alarm and setitimer deliver SIGALRM, getitimer reads back",
        "debian: unix: socketpair, path servers, abstract datagrams, SO_PEERCRED and end of file work",
        "Hello, world!",
        "debian: apt-get installed hello and jq from the local repository",
        "through the switch; loopback is per cell",
        "debian: cells: a datagram crossed the switch and came back",
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

/// A cloud-shaped machine: no PIT and no HPET (the TSC must calibrate from
/// the ACPI PM timer), two sockets of three cores (sparse APIC ids, as
/// multi-socket hosts give), 2 GiB, booting the GPT disk from NVMe.
#[test]
fn cloud_disk_boots_without_legacy_timers_on_two_sockets() {
    let out = boot_disk_with("cloud-disk-sockets", "", 6, |cfg| {
        cfg.memory_mib = 2048;
        cfg.machine_props = "pit=off,hpet=off".into();
        cfg.smp_topology = "sockets=2,cores=3,threads=1".into();
    });
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "from ACPI PM timer",
        "ichor: smp: 6 CPUs online",
        "ichor: blk: nvme: GPT disk, Ichor root partition at sector ",
        "ichor: busybox: all applets passed",
        "ichor: boot complete; halting",
    ]);
}

/// Milestone 5, first network test: virtio-net and Ichor's own TCP/IP
/// against a real peer. The kernel resolves QEMU's user-mode gateway, then
/// opens a TCP connection through it to an echo server this test runs on
/// the host's loopback, sends 256 KiB, checks it all comes back, and
/// closes.
#[test]
fn tcp_through_virtio_net_to_a_host_echo_server() {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    // A TCP echo and a UDP echo on the same port number.
    let (listener, udp) = (0..50)
        .find_map(|_| {
            let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
            let u = std::net::UdpSocket::bind(l.local_addr().ok()?).ok()?;
            Some((l, u))
        })
        .expect("a port free for both TCP and UDP");
    let port = listener.local_addr().unwrap().port();
    let datagrams = Arc::new(AtomicUsize::new(0));
    let counted = datagrams.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = udp.recv_from(&mut buf) {
            if udp.send_to(&buf[..n], from).is_ok() {
                counted.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    // Two clients: the kernel's own TCP, then a Debian cell through the
    // cell switch's NAT.
    let totals: Arc<[AtomicUsize; 2]> = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let seen = totals.clone();
    std::thread::spawn(move || {
        for total in seen.iter() {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut buf = vec![0u8; 65536];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        total.fetch_add(n, Ordering::SeqCst);
                    }
                }
            }
        }
    });
    let out = boot("net-echo", &format!("net_echo_port={port}"), 2);
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: net: virtio-net ",
        "ichor: net: gateway 10.0.2.2 is at ",
        "ichor: net: tcp echo of 256 KiB through slirp ok",
        "ichor: net: uplink 10.0.2.15 is the cell switch's",
        "through the switch; loopback is per cell",
        &format!("debian: nat: a cell echoed 256 KiB with 10.0.2.2:{port} through the uplink"),
        "debian: nat: a datagram went through the uplink and came back",
    ]);
    assert!(
        datagrams.load(Ordering::SeqCst) >= 1,
        "the host echoed no datagram"
    );
    for (i, t) in totals.iter().enumerate() {
        assert_eq!(
            t.load(Ordering::SeqCst),
            256 * 1024,
            "client {i}: the host saw every byte"
        );
    }
}

/// The host reaches a server in a cell through a port published on the
/// cell switch's uplink (QEMU forwards a host port to the guest's 8080,
/// published to the cell's port 80).
#[test]
fn a_published_port_serves_the_host_from_a_cell() {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let host_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // The port is published twice in turn: to Debian's perl server, then
    // to nginx in an Alpine cell. Each answer is kept once.
    const BODIES: [&str; 2] = [
        "hello from an Ichor cell",
        "hello from nginx in an Ichor cell",
    ];
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let halt = stop.clone();
    let client = std::thread::spawn(move || {
        let mut got: [Option<String>; 2] = [None, None];
        // (attempts, connect failures, read errors, empty or other answers,
        // slowest attempt), reported if an answer is missing.
        let (mut tries, mut refused, mut errors, mut other) = (0, 0, 0, 0);
        let mut slowest = Duration::ZERO;
        let mut sample = String::new();
        let start = Instant::now();
        let deadline = start + Duration::from_secs(600);
        while Instant::now() < deadline
            && got.iter().any(Option::is_none)
            && !halt.load(std::sync::atomic::Ordering::Acquire)
        {
            // QEMU accepts as soon as it runs; until a cell listens the
            // forwarded connection fails and this tries again.
            tries += 1;
            let t0 = Instant::now();
            if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", host_port)) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
                let mut resp = String::new();
                if s.write_all(b"GET / HTTP/1.0\r\nHost: ichor\r\n\r\n")
                    .is_ok()
                    && s.read_to_string(&mut resp).is_ok()
                {
                    let mut known = false;
                    for (slot, body) in got.iter_mut().zip(BODIES) {
                        if resp.contains(body) {
                            *slot = Some(resp.clone());
                            known = true;
                        }
                    }
                    if !known {
                        other += 1;
                        if !resp.is_empty() && sample.is_empty() {
                            sample = resp.chars().take(200).collect();
                        }
                    }
                } else {
                    errors += 1;
                }
            } else {
                refused += 1;
            }
            slowest = slowest.max(t0.elapsed());
            std::thread::sleep(Duration::from_millis(250));
        }
        let log = format!(
            "{tries} attempts in {:?}: {refused} connect failures, {errors} read errors, \
             {other} other answers (first non-empty: {sample:?}), slowest {slowest:?}",
            start.elapsed()
        );
        (got, log)
    });
    let out = ichor_tests::boot_with("net-publish", "net_publish=8080", 2, |c| {
        c.net_user_opts = format!("hostfwd=tcp:127.0.0.1:{host_port}-:8080");
        c.timeout = Some(Duration::from_secs(420)); // two servers wait for the host
    });
    stop.store(true, std::sync::atomic::Ordering::Release);
    let (got, log) = client.join().unwrap();
    eprintln!("host client: {log}");
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: net: uplink 10.0.2.15 is the cell switch's",
        "debian: published: listening on port 80",
        "debian: published: served a request from 10.0.2.2",
    ]);
    out.assert_in_order(&["alpine: nginx served the host through the published port"]);
    for (resp, body) in got.iter().zip(BODIES) {
        let resp = resp
            .as_deref()
            .unwrap_or_else(|| panic!("no {body:?} response"));
        assert!(
            resp.starts_with("HTTP/1.0 200 OK\r\n") || resp.starts_with("HTTP/1.1 200 OK\r\n"),
            "response: {resp:?}"
        );
    }
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
