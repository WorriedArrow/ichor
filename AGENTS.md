# AGENTS.md

Working notes for anyone (human or agent) picking up Ichor. Keep this file
current: when a session changes build commands, conventions, or the active
milestone, update it in the same commit.

Ichor is a cloud-first server OS in Rust that runs OCI containers natively on
a framekernel. The founding brief is the source of truth until an ADR in
`docs/adr/` supersedes part of it. Read these first:

- `docs/adr/0001-kernel-architecture.md`: the framekernel shape, the trust
  model, frame's planned API surface, the unsafe policy, and the frame budget.
- `docs/adr/0002-cells-and-capabilities.md`: cells, capabilities, and how the
  Linux ABI's namespaces and cgroups map onto them.

## Status

**Active milestone: 5.** Network stack, virtio-net, inter-cell switching;
nginx and redis serve traffic from cells. The design is ADR-0010: our own
sans-I/O stack in `kernel/net` (host-tested), one stack per cell, an
in-kernel cell switch with assigned addresses, proxy ARP, anti-spoofing,
rate limits, a cross-cell fast path, and NAT plus published ports at the
uplink; virtio-net first (polled).

Milestones 0-4 are done (4's acceptance test: Debian's `apt-get install`
from a local mirror). Phase E (scalability) is done except the vDSO and
the Mm-lock item, both blocked, and the per-CPU page lists, held back on
`pcp-page-lists`.

- M4 so far: Alpine 3.20.3's own userland runs unmodified in a cell. xtask
  fetches the minirootfs (pinned SHA-256, `artifact.rs`), gunzips and reads
  the tar in memory (`inflate.rs`, `rootfs.rs`: no host extraction), and
  attaches it as a second virtio-blk disk; the kernel mounts every virtio
  disk and runs the Alpine checks on the one with `/etc/alpine-release`.
  The loader handles PIEs (fixed bias) and `PT_INTERP` (`ld-musl` loaded
  in the mmap area, `AT_BASE`), in `execve` too, so Alpine's dynamic
  busybox shell forks and execs dynamic children.
- M4 pipes: `pipe`/`pipe2` (`kernel/ichor/src/pipe.rs`: 64 KiB buffer,
  blocking on wait queues, EOF and `EPIPE` from per-end reference counts,
  atomic writes up to `PIPE_BUF`). Shell pipelines and command substitution
  work in both the static busybox and Alpine's dynamic shell.
- M4 signals (`signal.rs`, pending state in `proc::ProcEntry`):
  rt_sigaction/rt_sigprocmask/rt_sigreturn with a Linux-layout
  `rt_sigframe` (registers, FXSAVE state, mask, siginfo), default actions,
  kill/tkill/tgkill, SIGCHLD on child exit, SIGPIPE on EPIPE, faults
  delivered to handlers, and interruptible waits (pipes, wait4, pause,
  rt_sigsuspend, nanosleep) via an internal `ERESTARTSYS` that becomes a
  restart (`SA_RESTART`) or `EINTR`. Busybox `trap`, `kill` of a blocked
  `sleep`, `kill -9 $$` and `yes | head` pass. No job control or
  `sigaltstack` yet.
- M4 timed waits: frame's timer has a third deadline kind (`Sleep`) over a
  global sleeper list; `WaitQueue::wait_until_deadline` and
  `task::sleep_until` block until a condition or a deadline. `nanosleep`
  uses them (interruptible by signals). Self-tested on every boot.
- M4 copy-on-write fork (`umem`): parent and child share pages read-only;
  the first write (fault or kernel copy-in) copies. The child is charged
  up front. A test ELF checks isolation both ways. Each root gets a `/dev`
  (`dev.rs`, overlay `mknod`); busybox needed `/dev/null` for background
  jobs, which faster forks exposed.
- M4 threads and futexes: `process.rs` splits a process (`Group`: memory,
  files, cwd/umask, signal actions behind sleeping locks) from its threads
  (`LinuxProcess`: tid entry, mask, clear-tid). `clone` with `CLONE_THREAD`
  adds a thread (TLS, PARENT/CHILD_SETTID, CHILD_CLEARTID); `exit` ends a
  thread, `exit_group` or a fatal signal ends the process; `kill` is
  process-directed, `tgkill`/`tkill` thread-directed; `wait4` reaps whole
  processes. `futex.rs`: WAIT/WAKE/REQUEUE/CMP_REQUEUE/WAKE_OP/*_BITSET
  (private semantics) over frame's atomic user `u32` ops. Frame (ADR-0007):
  per-CPU loaded roots and a TLB-shootdown IPI on every `unmap`/`protect`;
  ring-3 code is now preempted (`UserEvent::Preempted`; `execute` holds a
  guard, so a user spinner used to keep its CPU). Tests: clone + futex +
  join, and a shootdown test where a spinning reader must fault after
  another thread's `munmap`, on 1-8 vCPUs.
- M4 readiness and /proc: `poll.rs` has poll/ppoll/select/pselect6, epoll
  (create/ctl/wait/pwait; level-triggered, EPOLLONESHOT) and eventfd, over
  one poll wait queue that pipes and eventfds notify; descriptors can hold
  any kernel `Object` (`Fd::Object`). `procfs.rs` answers absolute `/proc`
  paths (open, stat, readlink, access, getdents): self, the calling
  process's pid dir (cmdline, comm, cwd, exe, fd/, maps, mounts, stat,
  status), cpuinfo, meminfo, mounts, uptime, version, stat, loadavg,
  sys/kernel/*. Busybox and Alpine read it; a test ELF checks poll
  timeouts and wakeups, epoll data and eventfd counts.

- M0/M1: boots as a UEFI app into the higher half; buddy page allocator and
  heap; traps with IST stacks; x2APIC + tickless timer; SMP bring-up; per-CPU
  data.
- M2 (scheduler): frame owns tasks, the context switch, atomic-mode tracking
  and preemption; `kernel/sched` is the injected weighted-fair-share policy.
  Kernel threads run, block/wake on wait queues, and are preempted.
- M2 (user mode): typed/untyped frames (`UFrame`, `VmReader`/`VmWriter`),
  `VmSpace`, and `UserMode::execute` run ring-3 code. A ring-3 program makes
  a syscall, faults, and is isolated from other address spaces.
- M2 (cells): `kernel/cap` (rights, revocation, generation-tagged CSpace
  handles) and `kernel/cell` (hierarchical accounts). The kernel's `kcell`
  ties CSpace + Account + VmSpace into a `Cell`. `kernel/abi` + the kernel's
  `nativeabi` dispatcher give native-ABI processes capability syscalls
  (`docs/abi/native.md`). Self-tests prove isolation, rights, accounting,
  revocation, and that a ring-3 native process acts only on handles its cell
  holds.

- M3 (done): the acceptance test runs the official static busybox 1.35.0
  (busybox.net musl build; xtask fetches it, pins its SHA-256, caches it in
  `target/busybox/`, `ICHOR_BUSYBOX` overrides) from the root disk:
  echo, ls, cat (via sendfile), and `sh -c` with arithmetic, exit codes,
  and fork + execve + wait4 of `/bin/true`. Processes run on their own
  kernel tasks (`proc`: pids, zombies, wait4); `fork`/`vfork`/fork-like
  `clone` copy the address space eagerly; `execve` loads a static ELF from
  the root. Frame enables SSE on every CPU and saves each user context's
  FXSAVE state around ring 3 (the kernel is soft-float).
- M3 pieces: `kernel/elf` (load plans), `kernel/image` (read-only,
  content-addressed image format; `builder` feature is the writer), and in
  the kernel: `loader` (ELF into a cell's `VmSpace`), `vfs` (root mounted
  from an image; `.`/`..`, bounded symlink following), `process` (Linux
  process + fd table), `linuxabi` (console I/O, open/openat/read/close,
  stat family, lseek, arch_prctl, exit). Coverage is generated into
  `docs/linux-abi.md` (`cargo xtask linux-abi-table`; lint checks it).
  `testprog` is a tiny assembler for self-test binaries. Real static Linux
  ELFs run in cells and read files from a mounted image.
- M3 device I/O (ADR-0005): frame enumerates PCI and offers `IoMem`
  (bounds-checked MMIO from `PciDevice::map_bar` only), `DmaBuf`/`DmaAddr`
  and a frame-owned split `VirtQueue`. `kernel/block` is the block-device
  trait; `kernel/drivers/virtio-blk` is a safe, polled virtio-blk driver
  and `kernel/drivers/nvme` a safe, polled NVMe driver (one I/O queue pair;
  DMA-trusted per ADR-0005 because it writes PRPs). Every QEMU run attaches
  `target/qemu/<run>/root.img` (built by xtask with the image builder) as a
  virtio-blk disk and as a 4 KiB-block NVMe namespace; the kernel reads each,
  verifies a 300 KiB pattern file, mounts it, and runs `cat` against it.
- M3 memory: `kernel/vma` (region map, host-tested) and the kernel's
  `umem` give Linux processes `brk`, `mmap` (anonymous, and private copies
  of files), `mprotect` and `munmap`, with demand paging from user page
  faults; syscalls fault user buffers in before copying. The loader builds
  a real argv/envp/auxv stack (AT_PHDR, AT_RANDOM, ...) and tolerates
  segments sharing a page. `linuxabi` also has uname, getdents64, dup*,
  fcntl, ioctl(TIOCGWINSZ), clock_gettime, prlimit64, and signal/futex
  stubs. A process's memory is freed and its charge returned at exit.
- M3 root file system (ADR-0006): `kernel/overlay` (host-tested) is the
  image plus a copy-on-write upper layer in memory: lazy inodes, copy-up,
  whiteouts, rename of lower directories, open-after-unlink, byte budgets,
  and path resolution. The kernel's `vfs` locks it; `linuxabi/fs.rs` has
  the file syscalls (create/write/truncate, mkdir/rmdir/unlink/rename,
  symlink/readlink, chmod, chdir/getcwd, the `*at` forms, pread/pwrite).
  Processes have a working directory and a umask.

`tests/boot.rs` proves all of this on 1, 4 and 8 vCPUs.

- M4 apk: the Alpine disk carries a local `/mirror` of three official,
  signed Alpine 3.20 packages (`tree`, `jq`, `oniguruma`; pinned in
  `xtask/src/artifact.rs`). `apk add` installs them (signatures checked by
  apk against the minirootfs keys, dependency order resolved), runs the
  busybox trigger, and the binaries work. `execve` runs `#!` scripts. The
  overlay records uid/gid and atime/mtime/ctime; `chown` family and
  `utimensat`/`futimesat`/`utimes` set them (uid 0 semantics until the
  identity ADR). Linux console writes go out as raw bytes.
- M4 honest stubs and entropy (Phase A, done): sigaltstack/SA_ONSTACK,
  per-process rlimits (NOFILE, STACK enforced), madvise (file mappings
  fill on touch and refill after DONTNEED), MAP_SHARED anonymous memory
  across fork with physically keyed futexes, EPOLLET, ppoll/pselect6/
  epoll_pwait masks, vfork waits, process groups and sessions, real /proc
  numbers. `cargo xtask lint` fails if a `=> Ok(0)` dispatch arm is listed
  as implemented or a table entry has no arm. `random.rs`: ChaCha20
  seeded from RDSEED/RDRAND and virtio-rng (every QEMU run attaches one)
  behind getrandom, /dev/[u]random and AT_RANDOM; `frame::time::wall_clock`
  is UEFI GetTime at boot plus TSC time, behind CLOCK_REALTIME,
  gettimeofday and file times.
- M4 identity and apt (Phase D, ADR-0009): per-process credentials, the
  set*id family, DAC checks in the overlay (`Overlay::set_cred`, installed
  by `LinuxProcess::fs()` for syscall work only), kill permission, image
  format v3 with owners and mtimes. Debian's `apt-get install` from the
  local `/mirror` (hello, jq, libjq1, libonig5; pinned on
  snapshot.debian.org) passes in CI: milestone 4's acceptance test.
  prctl, statx, sched_getaffinity, /sys cpu lists, mremap, sysinfo are in.
  Open: the cross-cell isolation test (owner is writing it).
- Pseudo-terminals (`pty.rs`): `/dev/ptmx` and a devpts per root
  (`Vfs::ptys`; a slave opens only through the node made for it in the
  same root), an N_TTY-style line discipline (canonical editing, echo,
  ISIG to the foreground group, MIN/TIME, ONLCR), termios/winsize/job
  control/ptmx ioctls, controlling terminals and `/dev/tty`, hangup on
  master close. Debian's perl drives a session through dash, `tty` and
  `stty` on every boot. Partial: no SIGTTIN/SIGTTOU, flow control or
  packet mode; the console is still not a tty.
- Page-sharing opt-out (ADR-0004 §4): `Vfs::mount_disk_private` gives a
  cell's root a private page-cache namespace (`pagecache::View`), charged
  to the cell's account, evicting only its own pages, freed with the root.
  `blktest::opt_out` checks it on every boot.
- Scheduler wake-ups (frame `task.rs`): a task is marked blocked before it
  is visible on a wait queue, the re-check runs with interrupts off, and a
  task that does not sleep leaves the queue; the idle loop re-checks before
  `hlt` when `finish_switch` requeued a woken task locally. These fixed an
  intermittent SMP hang (pipe- and lock-heavy work under apt/dpkg).
- M4 Debian (Phase D): xtask fetches the official `debian:bookworm-slim`
  amd64 layer from Docker Hub (anonymous token; pinned by manifest digest,
  verified by the layer digest), builds it once into
  `target/debian/debian-<digest>-v<format>.img`, and attaches it as a third
  virtio disk. `debiantest.rs` runs Debian 12's glibc `dash` and coreutils
  through `ld-linux-x86-64.so.2`. Syscall `int` arguments are read as
  32-bit signed values (glibc zero-extends them).
- M4 page cache (Phase C, step 1): image format v2 hashes chunks with
  BLAKE3, aligns each chunk to a page, and carries a root hash over the
  metadata, checked at mount. `pagecache.rs` mounts a disk from its
  metadata alone; lower-file reads fetch one chunk (one aligned device
  read) at a time through a global, bounded (32 MiB, clock) cache keyed by
  the *verified* chunk hash, so identical chunks share a page across disks
  and a bad device byte is EIO. The whole-disk buffer is gone. `file.rs`:
  exec and file mmap work on open files; whole file pages of an unmodified
  lower file map the cache's page copy-on-write (one physical copy of
  busybox/ld-musl for every process). `MAX_ORDER` is back to 10 (4 MiB):
  frame records the largest contiguous request and the boot fails if it
  exceeds that. Not yet: shared cache pages charged to an image account.
- M4 upper layer (Phase C, step 2): upper files are paged and sparse (a
  page map, the byte budget counts pages; MAX_FILE 1 TiB of offsets), copy-up
  goes page by page, directories report 2 + subdirectories, and
  `Overlay::link` plus link/linkat give hard links (lower files link
  without copy-up).
- M4 extended state (Phase B, ADR-0008): every CPU loads one XCR0 (x87,
  SSE, AVX, AVX-512 if whole) and threads keep a boxed standard-format
  XSAVE area, restored eagerly before ring 3 and saved with XSAVEOPT
  after (FXSAVE on CPUs without XSAVE). `UserContext` is `Clone`, not
  `Copy`. Signal frames carry the area with Linux's `_fpx_sw_bytes` and
  `FP_XSTATE_MAGIC2`; sigreturn sanitizes it; the auxv has
  AT_MINSIGSTKSZ. A test checks YMM upper halves across fork and signals.
- M4 fd model: descriptors point at shared open file descriptions
  (`process::Description`: offset, status flags, the reference on what it
  names), so `dup`/`dup2`/`dup3`/`F_DUPFD` and `fork` share offset and
  flags; file I/O holds the description for the whole operation. Each slot
  has its own `FD_CLOEXEC` (`O_CLOEXEC`, `*_CLOEXEC`, `F_SETFD`), closed by
  `execve`. `F_SETFL` sets O_APPEND/O_NONBLOCK; O_APPEND writes are one
  atomic overlay append (up to 1 MiB per call). `locks.rs`: flock (per
  description), POSIX record locks (per process, dropped on any close of
  the file), OFD locks (per description), with blocking variants that a
  signal interrupts. Tests: `2>&1` ordering, two `>>` appenders, flock,
  close-on-exec through `/proc/self/fd`, record-lock conflict/F_GETLK/
  F_SETLKW across fork.

## Agreed plan (owner, 2026-11-15)

Commit at every green step; every commit must build and pass on its own;
report at the end of each phase. Do not rewrite `main`.

- **A. Harden what exists.** (1) apk green [done]. (2) CI asserts KVM [done].
  (3) [done] fd model: open file descriptions shared by dup/fork (offset, status
  flags), FD_CLOEXEC/O_CLOEXEC, F_SETFL O_NONBLOCK/O_APPEND, a lock table
  for flock and fcntl F_SETLK/F_SETLKW/F_OFD_*; tests for `2>&1`, `>>` from
  two processes, no fd leak across exec. (4) [done] Every fake-success stub made
  honest (audit table), ABI statuses checkable by lint. (5) [done] RDSEED/RDRAND +
  virtio-rng into a ChaCha20 CSPRNG for getrandom, /dev/urandom, AT_RANDOM;
  wall clock from UEFI GetTime (no CMOS fallback).
- **B. XSAVE before glibc.** [done: ADR-0008] Document today's FPU handling; enable
  XSAVE/XSAVEOPT, XCR0 per CPU support, per-thread extended state (lazy vs
  eager in an ADR with the security reasoning), XSAVE layout in signal
  frames.
- **C. Page cache and storage.** [done] The audit's plan, plus: BLAKE3 chunk
  hashes verified on fill and a root hash in the header (hash-keyed sharing
  only on verified BLAKE3); the upper layer as a real in-memory filesystem
  (paged data, mode, uid/gid, times, nlink, hard links); `VmSpace::frames`
  as a tree with range ops; `MAX_ORDER` back to 10 with a test that fails
  on any > 4 MiB contiguous allocation. Write the frame budget ADR before
  exceeding the budget.
- **D. Debian.** Identity-model ADR first (per-cell uid/gid mapping, what
  uid 0 means in a cell, enforcement); then setresuid & co., chown family,
  utimensat, link/linkat, statx, sched_getaffinity,
  /sys/devices/system/cpu/online, mremap, prctl, sysinfo/getrusage/times.
  Then pinned bookworm-slim by digest, dash, coreutils, `apt-get install`
  from a local `file:` repo in CI: milestone 4 is done only then.
- **E. Scalability before milestone 5.** Per-CPU page lists, hashed futex
  buckets (shared futexes keyed by physical page), per-object wait queues,
  no busy-wait loops, idle CPUs kicked for woken tasks, Mm lock not held
  across whole user copies, a VFS that does not serialize reads, batched
  console writes, a vDSO; first benchmarks (null syscall, context switch,
  page fault, fork+exec, container start) against Linux before and after.
  [in progress: `bench.rs` measures all six on Ichor (`bench` flag,
  `benchmarks_run_and_report`; CI prints a KVM run to the job summary);
  futexes are in 64 hashed buckets; lower-file reads run outside the
  root's tree lock (`Vfs::read`); console output fills the UART FIFO
  between status polls; `execve` and the last thread out sleep on
  `Group::gone` instead of yield loops (the polled block drivers and TLB
  shootdown acks still spin, by design until interrupt-driven I/O);
  poll/select/epoll waiters register with each watched object's
  `poll::Watchers`, so a change wakes only its own pollers; idle CPUs
  are already kicked when a task is enqueued on them (`sched.rs`).
  Per-CPU single-page lists are on the local branch `pcp-page-lists`,
  held back: one unexplained user page fault (dpkg's decompressor) in 20
  one-CPU boots, against 0 in 20 without it. Baseline in `docs/benchmarks.md`; Linux reference
  numbers come from `cargo xtask bench` (Alpine `linux-virt` booted with
  the same `testprog::bench` programs; CI job summary). Open: frame's
  `VmSpace` user copy ignores the page's
  write permission and copies after dropping its lock (owner deciding how
  to handle it; the Mm-lock item waits on it).]

Carried over from milestone 3: per-cell pid namespaces (paging the root
image in on demand, copy-on-write `fork`, `FD_CLOEXEC` and shared offsets
after `dup` are done).

Suggested order for milestone 4:

1. Done: signals, timed waits, threads and futexes (PCID and robust lists
   are still open).
2. Done: copy-on-write fork (kernel-side, no frame change) and a minimal
   `/dev` (null, zero, full, random, urandom, tty, console) plus `getrandom`.
3. `PT_INTERP` and PIE: done for musl (Alpine); glibc's `ld-linux` next with
   debian-slim (it needs more of `mmap` with file offsets and `/proc/self`).
4. Done: pipes, `poll`/`epoll`/eventfd, `/proc` (own process only), `/dev`.
   Next: Alpine `apk` and debian-slim `apt` against a local mirror (needs
   sockets or a file-backed mirror, more `/proc`, and glibc's `ld-linux`).

ADR-0004 records the side-channel posture; its per-CPU mitigations (VERW,
IBPB on cross-cell switch, page-table isolation for Meltdown-affected CPUs)
are owed as multi-cell scheduling lands in milestone 4. Boot logs which apply.

Frame budget: ADR-0005 sets the milestone 3 ceiling at 8,500 lines / 380
sites; ADR-0007 raises it to 9,500 / 420 for milestone 4 (TLB shootdown,
atomic user ops for futexes, PCID). `audit.toml` is at step 6 (5,800 / 250);
frame is at 5,527 / 242 (A5 added RDSEED/RDRAND and UEFI GetTime; B
added XSAVE; C the frames tree and request tracking).

The goal set for this effort is milestone 8, whose acceptance test needs
cloud accounts and bare-metal hardware from the owner.

Toward milestone 8 so far: `cargo xtask disk-image` writes a single
bootable GPT disk (FAT32 ESP with `\EFI\BOOT\BOOTX64.EFI` and
`\ichor\cmdline`, plus an Ichor root partition the kernel finds by type,
`partition.rs`). `cloud_disk_boots_from_gpt_on_nvme` boots it under OVMF
from NVMe alone (no vvfat, no other disks) and runs busybox from the root
partition. `cloud_disk_tolerates_blank_volumes_and_small_transfers`
adds a blank NVMe volume ahead of it and an 8 KiB MDTS. The TSC
calibrates from CPUID, the hypervisor leaf, the ACPI PM timer or the PIT
(the boot log names it); NVMe honors MQES and MDTS, probes every
controller, allows 30 s per command and logs failures. `--size-gib N` pads
the disk and `--gcp` writes GCP's import archive; `cargo xtask run --disk
FILE` boots any such image. Runbook for a first real-cloud boot:
`docs/cloud.md`. Not yet: a network driver (AWS ENA / GCP gVNIC /
virtio-net), Hyper-V VMBus for Azure, Secure Boot.

## Commands

```bash
cargo xtask build          # kernel -> target/kernel/x86_64-unknown-uefi/debug/ichor.efi
cargo xtask run            # boot in QEMU + OVMF, serial on stdio, exits on halt
cargo xtask run --cmdline "memmap"   # without qemu_debug_exit: halts; Ctrl-C to quit
cargo xtask test           # host unit tests, then QEMU integration tests (tests/)
cargo xtask lint           # fmt check, clippy (host + UEFI target), forbid check, frame budget
cargo xtask frame-audit    # frame line and unsafe-site counts against the budget
cargo xtask run --cmdline "qemu_debug_exit bench" --smp 4 --release   # benchmarks (use KVM for real numbers)
cargo xtask bench --accel kvm --smp 4   # Ichor vs Linux, same machine and programs (Markdown table)
cargo xtask disk-image     # target/ichor-disk.img: bootable GPT disk (ESP + Ichor root) for clouds/bare metal
cargo deny check           # licenses, advisories, sources
```

Useful options: `--release`, `--accel auto|kvm|whpx|hvf|tcg`, `--smp N`,
`--memory MiB`, `--timeout secs`, `--gdb` (waits on tcp::1234), and `-- <raw
qemu args>`.

Environment overrides: `ICHOR_QEMU`, `ICHOR_OVMF_CODE` + `ICHOR_OVMF_VARS`,
`ICHOR_ACCEL`, `ICHOR_TEST_VERBOSE=1` (echo guest serial during tests), and
`ICHOR_REQUIRE_KVM=1` (CI sets it: `cargo xtask test` fails unless KVM is
the accelerator).

Plain `cargo build` / `cargo test` at the root only touch host crates
(`default-members`). Crates that depend on frame (`ichor`, `ichor-frame`,
`ichor-virtio-pci`, `ichor-virtio-blk`, `ichor-virtio-rng`, `ichor-nvme`) are kernel-only: xtask's `KERNEL_ONLY` list keeps them
out of host clippy and tests and lints them for the UEFI target. The kernel and frame build for `x86_64-unknown-uefi`
through xtask, into `target/kernel` so they never contend for cargo's build
lock with the host build.

### Kernel command line

The kernel reads `\ichor\cmdline` from the boot volume, which xtask writes per
run. Options are whitespace-separated `key` or `key=value`; `#` starts a
comment.

| Option | Effect |
|---|---|
| `qemu_debug_exit` | `shutdown()` exits QEMU through `isa-debug-exit`: status 33 = success, 35 = failure |
| `memmap` | print the full memory map |
| `test_panic` | panic after boot (exercises the panic path) |
| `test_stack_overflow` | recurse until the kernel stack hits its guard page |
| `trace_errors` | log every failing Linux syscall (pid, number, first arguments, errno) |
| `trace_pid=N` | log every Linux syscall of pid N with its result |
| `bench` | run the Phase E benchmarks (`bench.rs`) after the root disk's self-tests and print them |

## Layout

```
kernel/frame     the unsafe TCB (only crate allowed `unsafe`); owns efi_main
  src/boot         UEFI entry, boot state, higher-half entry, per-CPU init
  src/mm           linear map/kspace switch, page metadata, page allocator, heap
  src/arch/x86_64  paging, GDT/TSS/IDT + trap stubs, x2APIC/timer, AP trampoline
  src/cpu.rs       CpuId, IrqGuard, CpuLocal<T>, cpu_local!
  src/bus, io.rs, dma.rs, virtio.rs   PCI, IoMem, DmaBuf, VirtQueue
kernel/cmdline   command line parser (no_std, host-tested)
kernel/pe        PE32+ headers + base relocations (no_std, host-tested)
kernel/buddy     buddy allocator policy over abstract links (no_std, host-tested)
kernel/acpi      RSDP/XSDT/MADT parsing from byte slices (no_std, host-tested)
kernel/pe,buddy  (above) PE + buddy allocator
kernel/sched     scheduling policy: group fair-share + work stealing (host-tested)
kernel/cap       capabilities, rights, revocation, CSpace (host-tested)
kernel/cell      hierarchical resource accounts (host-tested)
kernel/abi       native ABI definitions (docs/abi/native.md)
kernel/elf       ELF64 parsing into load plans (host-tested)
kernel/image     read-only content-addressed image format (host-tested)
kernel/block     block-device trait and helpers (host-tested)
kernel/vma       user address-space region map for mmap/brk (host-tested)
kernel/overlay   cell root: image + copy-on-write upper layer (host-tested)
kernel/csprng    ChaCha20 generator with fast key erasure (host-tested)
kernel/civil     calendar time to Unix time, for the firmware clock (host-tested)
kernel/blake3    BLAKE3, portable, checked against the official vectors (host-tested)
kernel/testprog  tiny x86-64 assembler + static-ELF writer for self-test and benchmark programs (host-tested; xtask uses it too)
kernel/gpt       GUID partition tables: CRC-checked reader (kernel), writer behind `builder` (xtask) (host-tested)
kernel/drivers/virtio-pci  modern virtio PCI transport shared by the virtio drivers
kernel/drivers/virtio-blk  safe virtio-blk driver over frame's IoMem/DMA
kernel/drivers/virtio-rng  safe virtio-rng (entropy) driver
kernel/drivers/nvme        safe NVMe driver (polled, DMA-trusted)
xtask/src/artifact.rs      pinned downloads (busybox, Alpine): SHA-256, cache, never committed
xtask/src/inflate.rs       gzip/DEFLATE decoder; rootfs.rs: tar -> Ichor image
xtask/src/disk.rs, fat.rs  bootable GPT disk image (FAT32 ESP + Ichor root partition)
xtask/src/linuxref.rs      Linux reference boot for `cargo xtask bench` (Alpine linux-virt + initramfs)
kernel/ichor     the kernel binary; frame::main!(kmain); kcell/nativeabi tie it together
xtask/           build/run/test/lint tooling (lib + bin, no dependencies)
tests/           QEMU integration tests (host crate using xtask's runner)
docs/adr/        architecture decision records
```

Planned crates (create as milestones need them): `kernel/{mm,sched,cap,cell,
vfs,block,net,linux-abi,native-abi}`, `kernel/drivers/*`, `abi/`, `services/`.

## Conventions

- **Unsafe lives only in `kernel/frame`.** Every other kernel crate (and later
  `services/`) starts with `#![forbid(unsafe_code)]`; `cargo xtask lint`
  checks this. In frame, each `unsafe` block holds one operation and has a
  `// SAFETY:` comment, and each `unsafe fn` has a `# Safety` section. Clippy
  denies violations.
- Frame's public API must be sound for *any* safe caller. Raw firmware and
  hardware types stay private.
- No `unwrap`/`expect`/`panic!` in kernel code (workspace clippy lints).
  Tests may use them (`clippy.toml`). A justified `#[allow]` with a comment is
  the only exception.
- Kernel dependencies: `no_std`, minimal, and audited before adding (cargo-deny
  now, cargo-vet from the first external kernel dependency). There are none
  today. Macro-exporting or proc-macro dependencies of kernel crates need an
  audit of their expansions, because a foreign macro's output bypasses
  `forbid(unsafe_code)` (ADR-0001 §5).
- Put logic that does not touch hardware into host-testable crates
  (`cargo test`, and later Miri, proptest, fuzzing).
- Every milestone ends with an automated test in CI. Add a QEMU test by
  calling `ichor_tests::boot(name, cmdline, smp)` and asserting on serial
  markers and the exit status.
- Write an ADR for decisions that would be expensive to reverse. Update
  `docs/adr/README.md`.
- Commit in small steps that build and pass `cargo xtask lint` and
  `cargo xtask test`. Commit messages say what changed and why. A tracked
  benchmark regression needs a justification in the message.
- Code is MIT OR Apache-2.0. Never copy Asterinas code (MPL-2.0) into
  differently licensed files. Re-implement from its documented invariants.

## Toolchain

Pinned stable `1.100.0` (`rust-toolchain.toml`) with target
`x86_64-unknown-uefi`.

### Unstable features

None. If one becomes necessary, pin a dated nightly and list it here with the
reason. Known candidates: CET/IBT codegen and retpolines (side-channel ADR).

## Environment notes

- CI (GitHub Actions, `ubuntu-24.04`) installs `qemu-system-x86` and `ovmf`,
  enables `/dev/kvm`, and runs lint, test, and cargo-deny.
- On Windows, QEMU's own `share/edk2-x86_64-code.fd` + `edk2-i386-vars.fd`
  are found automatically. There is no KVM there, so runs use TCG: about 2 s
  per boot. WHPX is untested.
- The ESP is a QEMU `vvfat` directory under `target/qemu/<run>/esp`, passed
  as a workspace-relative path, because a Windows drive-letter colon breaks
  `fat:` parsing.

## Needs the owner

Settled by the owner:

- License: MIT OR Apache-2.0 (confirmed 2026-11-14).

The brief cannot decide these, so ask the owner:

- Secure Boot signing keys and how they are custodied (before milestone 8).
- Cloud accounts and bare-metal hardware for milestones 8 and benchmarks.
