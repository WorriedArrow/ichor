# ADR-0013: Milestone 7: io_uring and real workloads' own test suites

- Status: Accepted
- Date: 2026-11-15
- Amended: 2026-11-22 (io_uring as built, at the end)
- Milestone: 7 ("io_uring; postgres, node, python, go, and JVM workloads
  pass their own test suites at a tracked pass rate")

## Context

Milestone 6 left a control plane that pulls an image from Docker Hub,
makes a cell of it and runs a process there, driven over gRPC
(`tests/control.rs`). The Linux personality has 160 calls implemented or
partial (`docs/linux-abi.md`). Debian's apt, Alpine's apk, nginx and redis
run.

Milestone 7 asks two things:

1. **io_uring**, the asynchronous submission interface modern runtimes
   use for file and network I/O (libuv since 1.45 for file operations,
   PostgreSQL 18's `io_method=io_uring`, Java's and Go's ecosystems
   through libraries).
2. **Five runtimes pass their own test suites at a tracked pass rate:**
   PostgreSQL, Node.js, CPython, Go and a JVM. "Tracked" means the rate is
   measured, recorded and may not silently fall; it does not mean 100%.

What the runtimes need beyond today's ABI, from their sources and
documentation (to be confirmed by tracing each one, as earlier milestones
did):

| Runtime | Needs we lack |
|---|---|
| PostgreSQL | System V shared memory (`shmget`/`shmat`/`shmctl`, a small interlock segment beside the anonymous shared mapping), `MAP_SHARED` file mappings that stay coherent, `fsync`/`fdatasync`/`sync_file_range` semantics, `setsid` children, `SIGUSR1` latches over pipes or `signalfd` |
| Node.js (libuv) | io_uring (with fallback), `eventfd`, `epoll`, `inotify` (`fs.watch` tests), `timerfd`, `clone3`, `getrandom`, `statx` |
| CPython | `os.*` breadth: `pipe2`, `posix_spawn` (`clone(CLONE_VM\|CLONE_VFORK)`), `memfd_create`, `sendfile`, `getrlimit`/`setrlimit`, `waitid`, `faccessat2`, `copy_file_range`, locale files, `/proc/self/fd` |
| Go | `SIGURG`-based preemption (`tgkill`), `sigaltstack` on every thread, `rt_sigreturn` precision, `madvise(MADV_FREE/DONTNEED)`, `sched_getaffinity`, large `PROT_NONE` reservations, `clone` with `CLONE_VM\|CLONE_FS\|CLONE_FILES\|CLONE_SIGHAND\|CLONE_SYSVSEM\|CLONE_THREAD` |
| JVM (OpenJDK) | SIGSEGV with an exact `ucontext` for implicit null checks and safepoint polls, `mprotect` of polling pages, `/proc/self/maps` and `/proc/meminfo` accuracy, cgroup files (`/sys/fs/cgroup`) for container sizing, `membarrier`, `rseq` (or a clean `ENOSYS`) |

## Decision

### 1. io_uring in the Linux personality

- `io_uring_setup`, `io_uring_enter` and `io_uring_register` on a ring
  object (`Fd::Object`). The SQ ring, CQ ring and SQE array are pages the
  kernel allocates and charges to the cell, mapped into the process by
  `mmap` of the ring descriptor at Linux's offsets
  (`IORING_OFF_SQ_RING`, `IORING_OFF_CQ_RING`, `IORING_OFF_SQES`; with
  `IORING_FEAT_SINGLE_MMAP` the two rings share one mapping). The kernel
  reads and writes them through `UFrame` readers and writers: no new
  `unsafe`, and frame does not change. Head and tail indices are read
  with acquire and written with release ordering through frame's atomic
  user-word operations (ADR-0007).
- **Execution:** `io_uring_enter` consumes SQEs in order. An operation
  that can complete without blocking (a ready socket, a cached file page)
  completes inline. One that would block is handed to the ring's worker
  tasks (up to `min(4, CPUs)` per ring, created on demand), which run the
  same code the synchronous syscall runs, with the ring's process
  credentials and file table. Poll-type operations register on the
  object's `poll::Watchers` instead of occupying a worker.
  `IOSQE_IO_LINK`/`IO_HARDLINK`, `IOSQE_IO_DRAIN` and `IOSQE_ASYNC` are
  honored; `IORING_SETUP_SQPOLL` and `IOPOLL` are refused (`EINVAL`):
  a kernel thread spinning on user memory is a cross-cell scheduling and
  side-channel cost ADR-0004 does not budget for.
- **Opcodes, in order of need:** `NOP`, `READ`/`WRITE`/`READV`/`WRITEV`
  (and `_FIXED` once registered buffers land), `FSYNC`, `POLL_ADD`/
  `POLL_REMOVE`, `TIMEOUT`/`TIMEOUT_REMOVE`/`LINK_TIMEOUT`, `ACCEPT`,
  `CONNECT`, `SEND`/`RECV`/`SENDMSG`/`RECVMSG`, `OPENAT`, `CLOSE`,
  `STATX`, `ASYNC_CANCEL`, `FALLOCATE`, `RENAMEAT`/`UNLINKAT`/`MKDIRAT`.
  Unknown opcodes complete with `-EINVAL`, as on Linux, so libraries probe
  and fall back. `IORING_REGISTER_PROBE` reports exactly what exists.
- **Accounting:** rings and in-flight buffers charge the cell; the CQ
  never overflows silently (`IORING_FEAT_NODROP`: submission waits, or
  `-EBUSY`, when the CQ is full).
- **Testing:** host tests for the ring logic (a sans-I/O core in a new
  `kernel/uring` crate: index arithmetic, linking, draining, cancellation)
  and a boot test that drives rings from a static test program
  (`testprog`) and from liburing's own test programs built against musl
  in Alpine, at a tracked pass rate like the workloads.

### 2. Workload suites, through the control plane

The suites run the way users will run them: images pulled through the
control plane's API, by digest, and commands run in cells.

- **Images:** official Docker Hub images pinned by index digest
  (`postgres`, `node`, `python`, `golang`, `eclipse-temurin`), each the
  Debian-based variant. Suites that the image does not carry (CPython's
  `Lib/test` is stripped from the official image; PostgreSQL's regression
  sources and Node's `test/` are not in theirs) come from the project's
  official source release, pinned by SHA-256 like other artifacts, and
  are converted by xtask into a second image layered into the cell.
  (This needs `CreateCell` to take several images: an image plus layers,
  ADR-0006's lower stack.)
- **Suites and how they are scored:**
  - PostgreSQL: `pg_regress` against a server started in the same cell
    (`initdb`, `pg_ctl start`, the `parallel_schedule`); score = passed
    tests / tests.
  - Node.js: `tools/test.py` over `test/parallel` and `test/sequential`
    with the image's `node`; score = passed / run.
  - CPython: `python -m test -j0 -w` from the matching source tree;
    score = passed / run, per test module.
  - Go: `go test -short std` with the image's toolchain; score = passed
    packages / packages.
  - JVM: the OpenJDK `tier1` jtreg subset for `java.base` from the
    matching JDK source; score = passed / run.
- **Where they run:** `cargo xtask workloads [--suite NAME]` boots Ichor
  with `control=`, drives the API from the host as `tests/control.rs`
  does, parses each suite's own summary output, and writes
  `docs/workloads.md`: suite, image digest, pass rate, run time, and the
  failing tests. A CI workflow runs it with KVM on a schedule and on
  demand (not on every push: the suites take hours), and fails if any
  rate falls below the floor recorded in `workloads.toml`. Raising a
  floor is part of the change that earns it.
- **Order:** CPython first (the widest ABI coverage for the least
  harness), then Go, PostgreSQL, Node.js (with io_uring), and the JVM.
  The ABI gaps each one exposes are fixed in the kernel as they appear,
  each with its own test, as milestones 3-5 did.

## Alternatives considered

- **io_uring by translating each SQE into a synchronous syscall in
  `io_uring_enter`:** simplest, but blocks the submitter on any slow
  operation, which defeats the interface and deadlocks programs that
  submit a read and the write that satisfies it in one batch. Rejected;
  inline completion stays for what is ready.
- **SQPOLL:** a kernel thread per ring polling user memory. Rejected for
  now (scheduling and side-channel cost across cells).
- **Running the suites from xtask-built images, bypassing the control
  plane:** less moving parts, but it would not exercise the path users
  take, and milestone 6 exists to provide it. Rejected; xtask still
  builds the source-tree layers.
- **Requiring 100% pass rates:** the suites include tests for Linux
  features cells deliberately lack (ptrace, kernel modules, raw sockets,
  real hardware); the brief asks for a tracked rate. Rejected; known
  exclusions are listed in `docs/workloads.md` with reasons.

## Consequences

- io_uring is a second path into every operation it supports; the
  shared implementation (workers call the synchronous code) keeps them
  consistent, and its tests run both ways.
- `CreateCell` grows layered images (several images, lowest first),
  which the overlay already models.
- The suites need the internet in CI (Docker Hub, source releases) and
  hours of KVM time; their numbers live in `docs/workloads.md`, not in
  every push's results.
- Many Linux ABI additions land through this milestone; each is listed
  in `docs/linux-abi.md` with its status as before.

## Amendment (2026-11-22): io_uring as built

- **Workers:** one per ring and process, not up to four per ring. It is
  a helper thread of the process that submitted (its memory, files and
  credentials), started when something first has to wait. Operations do
  not block: each is tried without blocking on the open file description
  it named when it started (held by the ring, lent to the thread), and
  tried again when that object changes. So closing a descriptor, or
  giving its number to another file, does not redirect an operation, and
  no operation occupies a worker. What a process submitted is run only by
  its own threads, and is cancelled when it exits or execs.
- **Waiting:** a ring registers once with every object its operations
  wait for, as an epoll instance does, and waiters sleep until it is told
  of a change.
- **SQPOLL** is accepted, without the polling: the ring always says
  `IORING_SQ_NEED_WAKEUP`, so the program calls `io_uring_enter` to wake
  the poller, and that submits. No kernel thread reads user memory on its
  own, which is what the decision above refused; programs that insist on
  SQPOLL run, without its latency. IOPOLL stays refused.
- **Charges:** the ring's pages, what is in flight (8 SQEs or unread CQEs
  a page; `EAGAIN` from `io_uring_enter` when the cell cannot pay, or at
  131,072), registered tables, and the kernel's side of provided-buffer
  rings. A finished SQE is forgotten at once, however long an earlier one
  waits.
- **Cycles:** rings do not hold rings. An operation on a ring holds it
  weakly, rings cannot be registered files, and cannot be passed in
  `SCM_RIGHTS` (Linux refuses both too).
- **Registered buffers** are address ranges, not pinned pages: an
  operation on one the program has unmapped fails with `EFAULT`, where
  Linux's succeeds on the pinned page.
- **liburing's tests** run as a sixth suite (`cargo xtask workloads
  uring`), built with glibc in `buildpack-deps` rather than with musl in
  Alpine: the suite machinery pulls images, and its tests expect glibc.
  Version 2.5, of Linux 6.6's time, which is the version cells see.
