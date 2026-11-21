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

**Active milestone: 7** (io_uring; postgres, node, python, go and JVM
workloads pass their own test suites at a tracked pass rate). The design
is ADR-0013: io_uring rings as cell-charged pages read through `UFrame`s
(no frame change), inline completion for what is ready and per-ring
worker tasks for the rest, no SQPOLL; the suites run through the control
plane on pinned official images (plus pinned source-tree layers), scored
by `cargo xtask workloads` into `docs/workloads.md`, with floors in
`workloads.toml`. Order: CPython, Go, PostgreSQL, Node.js (io_uring), JVM.

Owner's order of work for milestone 7 (2026-11-16), all before any
milestone 8 preparation: (1) fuzz every parser, score certificate
validation on x509-limbo, write up the gaps [done]; (2) an ADR for
`services/rt` as the second trusted crate [done: ADR-0014, and lint now
fails if frame or rt relaxes an unsafe-code lint]; (3) the control-plane
listener local unless configured, with a test [done:
`the_control_api_is_local_unless_configured`], then API authentication and
Signal/Inspect/Destroy before any cloud boot [done: bearer token from
`\ichor\apitoken`, ADR-0012 amendment; TLS for the API still owed before
anything internet-reachable]; (4) io_uring completions
without an enter (epoll on the ring fd, registered eventfd), with a test,
before the Node.js suite [done]; (5) extra layers in PullImage, each pinned and
verified by digest, with a refusal test [done: `LayerSource` (url, sha256
digest, `from`/`to` remap via `layer::Tree::add_tar_at`), fetched after
the image, checked with `oci::digest_of` before `oci::convert_with`;
tests/control.rs serves one from the host and refuses a wrong digest]; (6) ADR-0004's owed mitigations
(VERW, IBPB on cross-cell switches, page-table isolation), logged at
boot [VERW and IBPB done; page-table isolation not yet built, logged
MISSING on Meltdown-affected CPUs]. The cell access-control suite is written in another worktree: do
not write it; merge its branch when it lands.

- M7 parsers and certificates: `fuzz/` (host-only) mutation-fuzzes every
  parser of untrusted input (TLS server side, X.509/DER, PEM, HPACK,
  HTTP/2 both ends + gRPC, protobuf, HTTP/1.1, registry protocol + JSON,
  DNS, gzip, tar, Ichor images) from real seeds; a panic or a 5 s input
  fails and is saved to `target/fuzz/`. Every test run fuzzes 300 inputs
  per target, CI 20,000 (`conformance` job), `cargo xtask fuzz` longer.
  Not coverage-guided (that needs nightly). `cargo xtask x509-limbo` scores
  `verify_chain` on x509-limbo (pinned) into `docs/x509-limbo.md` with
  floors; `docs/tls-and-x509.md` says what is enforced and the deliberate
  gaps. Verification now builds paths with backtracking and enforces name
  constraints, leaf serverAuth EKU and not-a-CA, DNS SAN syntax, serial
  and RSA key rules (98.4% accept / 99.4% refuse agreement).
- M7 io_uring, first step: `kernel/uring` (host-tested) has the ABI, this
  kernel's ring layout (one mapping for both rings, fields grouped by
  writer) and the ordering rules (`Order`: links, hard links, drains,
  chains cut at each submission's end). `linuxabi/uring.rs`: setup,
  `mmap` of the ring descriptor (`Mm::map_frames`: kernel pages shared
  with the process, kept across fork), enter (with GETEVENTS waits on
  armed objects, EXT_ARG timeouts, overflow kept per NODROP) and register
  (probe, eventfd). SQEs run on the submitting thread through
  `linuxabi::dispatch` (the synchronous syscalls' code); one on a pipe or
  socket that is not ready is armed and completes during a later enter.
  Ops: NOP, READ/WRITE(V) (positional on files), FSYNC, POLL_ADD/REMOVE,
  SEND/RECV(MSG), ACCEPT, CONNECT, SHUTDOWN, CLOSE, OPENAT, STATX,
  RENAMEAT/UNLINKAT/MKDIRAT, TIMEOUT/TIMEOUT_REMOVE, ASYNC_CANCEL.
  `runtest::uring_program` checks it from ring 3 on every boot. The
  ring's worker (`uring::worker`, a `LinuxProcess::helper` thread: shares
  the process, blocks signals but SIGKILL, is not one of the group's
  threads, ends when the ring closes or the process has no threads)
  completes armed SQEs with nobody in `io_uring_enter`; armed SQEs are
  claimed (`running`) so they run once. `runtest::uring_worker_program`
  checks completion while blocked on a registered eventfd and on
  `epoll_wait` of the ring fd. Not yet: registered files/buffers,
  LINK_TIMEOUT, the EXT_ARG signal mask, liburing's tests.

**Milestone 6 is done** (2026-11-15): the control plane pulls a real OCI
image from a registry, verifies it, converts it, and runs it through the
gRPC API. `tests/control.rs` (needs the internet): the host, through
gRPC on a forwarded port, has the guest pull Docker Hub's `hello-world`
and Alpine 3.20.3 by digest (TLS 1.3 to the registry, TLS 1.2 to the
Cloudflare/CloudFront CDNs, roots from the boot volume), make a cell of
each and run `/hello` and `sh -c ...`, checking output and exit status.
The design is ADR-0012: `services/control`, a native-ABI service embedded
in the kernel image and run in the system cell (`control=PORT`,
`control_exit`, `dns=`); `services/rt` its only `unsafe` crate; native
ABI v2; our own host-tested crates for crypto, X.509, TLS 1.2 + 1.3,
HTTP/1.1 and HTTP/2, gRPC/protobuf, OCI, layer conversion and DNS;
Mozilla's CA bundle (`xtask::artifact::MOZILLA_ROOTS`, pinned) as
`\ichor\roots.pem` on the ESP, read by frame at boot and handed to the
service as a Blob capability. Open from it: `Signal`/`Inspect`/`Destroy`
calls and cell destruction, image deletion, API TLS and authentication
(before milestone 8 runs anywhere reachable), signature verification,
a working directory and user for `Run`, an offline (recorded) variant of
the acceptance test.

- M6 control plane: `services/control` is one `OBJECT_WAIT` loop over the
  API listener and connections (`grpc::Server` on `http::h2`), pulls
  (`oci::Puller` driving `fetch.rs`: DNS over UDP, TCP, TLS or plain
  HTTP, one request per connection) and runs (process output streamed
  as `RunEvent`s). `services/http` gained `hpack` (RFC 7541 incl.
  Huffman, the canonical code built from Appendix B's lengths; RFC C.2-C.4
  vectors) and `h2` (both ends, flow control, CONTINUATION, PING,
  RST/GOAWAY); `services/grpc` has protobuf, framing, server and client
  sides and the `ichor.v1.Control` messages (`docs/abi/control.proto`).
- M6 host crates (all `no_std`, our own code): `services/crypto`
  (SHA-2, HMAC/HKDF/TLS PRF, ChaCha20-Poly1305, X25519, RSA and ECDSA
  P-256/P-384 verification; RFC vectors and OpenSSL-made signatures),
  `services/x509` (DER, certificates, chain verification; Docker Hub's
  real chains), `services/tls` (TLS 1.3 + 1.2 client; live sessions with
  Docker Hub recorded with fixed randomness and replayed offline),
  `services/http` (HTTP/1.1 client messages), `services/layer` (gzip +
  tar layers with OCI whiteouts into images; xtask uses it through thin
  shims), `services/oci` (references, Bearer token flow, index to
  linux/amd64, digest-verified manifests and blobs, CDN redirects without
  the token, conversion, image config; a real `hello-world` pull recorded
  and replayed), `services/dns` (A records, CNAME chains). AES-GCM is left
  out: every Docker Hub endpoint accepts ChaCha20-Poly1305. Refresh a
  recording with `cargo test -p ichor-tls -- --ignored record_live` (or
  `-p ichor-oci`); it needs the internet and the Windows-exported roots in
  `services/x509/testdata/roots.pem`.
- M6 native ABI v2 (`docs/abi/native.md`): `kernel/ichor/src/native.rs`
  runs native processes (a demand-paged `Mm` charged to the cell, the ELF
  loader, faults) and the v2 calls: LOG, CLOCK, RANDOM, MEM_MAP/UNMAP,
  OBJECT_WAIT (over `poll::Watchers`), TCP/UDP sockets on the cell's own
  stack (`socket::native`), PORT_PUBLISH (switch handle), IMAGE_CREATE
  (pages behind the page cache as a RAM disk, root hash checked),
  CELL_CREATE, CELL_SPAWN (a Linux process through `exec::exec`, stdout
  and stderr on one pipe), PROCESS_READ/WAIT, CELL_ADDR. `services/rt`
  (the only unsafe services crate, budget in `services/rt/audit.toml`):
  `_start`, syscalls behind slice-taking wrappers, a size-class heap,
  the panic handler, `rt::main!`. Services build for
  `x86_64-unknown-none` (static, small code model; `.cargo/config.toml`)
  and the kernel embeds them (`ICHOR_SERVICES_DIR`, set by xtask). Boot
  runs `services/nativetest`: clock, CSPRNG, heap, loopback TCP and UDP,
  refused handles, and Docker's recorded `hello-world` layer converted in
  the service, made a cell and run.

Roadmap from the founding brief (the brief is not checked in; this is
its milestone list as an earlier session recorded it):

6. Control plane pulls a real OCI image from a registry, verifies it,
   converts it, and runs it through the gRPC API.
7. io_uring; postgres, node, python, go, and JVM workloads pass their own
   test suites at a tracked pass rate.
8. Cloud drivers and metadata: Ichor boots and runs containers on AWS,
   GCP, Azure, and one bare-metal machine (needs the owner's accounts and
   hardware).
9. CRI: a kubelet schedules onto Ichor.

**Milestone 5 is done** (2026-11-15): network stack, virtio-net,
inter-cell switching; nginx and redis serve traffic from cells, to each
other and to the host through a published port. The design is ADR-0010:
our own sans-I/O stack in `kernel/net` (host-tested), one stack per cell,
an in-kernel cell switch with assigned addresses, anti-spoofing, rate
limits, a cross-cell fast path, and NAT plus published ports at the
uplink; virtio-net (polled). Open from it: IPv6, ICMP errors for UDP,
`MSG_PEEK`, interrupt-driven virtio-net (milestone 8 with cloud NICs).

- M5 so far: `kernel/net` (wire formats, an IPv4 interface with ARP, a
  TCP state machine tested over a lossy, reordering simulated link),
  `virtio-net` (polled), and a TCP echo to the host through slirp
  (`nettest.rs`). `netstack.rs` is the per-cell `Stack` (sockets, ports,
  connections behind one spinlock; loopback delivered synchronously; the
  net task runs timers); `linuxabi/socket.rs` gives `AF_INET`
  `SOCK_STREAM` sockets as poll/epoll-able objects (socket, bind, listen,
  accept4, connect incl. non-blocking, send*/recv*, shutdown,
  get/setsockopt, getsockname/getpeername, SIGPIPE). Debian's perl runs a
  socket session on every boot. `switch.rs` + `net::switch`/`net::nat`:
  the cell switch (assigned 10.88.0.0/16 addresses, anti-spoofing, the
  cross-cell fast path), source NAT and published ports at the uplink; a
  SYN for an unpublished uplink port gets RST.
- M5 workloads (`alpinetest::servers`): Alpine's own nginx 1.26 and redis
  7.2 (pinned packages in the Alpine mirror) run in a server cell; a client
  cell checks them with wget, redis-cli and redis-benchmark through the
  switch, and with `net_publish` the host fetches from nginx through the
  published port (`a_published_port_serves_the_host_from_a_cell`). Needed
  on the way: TCP_CORK and friends (recorded), `setitimer`/`getitimer`/
  `alarm` (`itimer.rs`, ITIMER_REAL), a 65,536-entry descriptor ceiling
  (soft 1024; raising a hard limit is EPERM, CAP_SYS_RESOURCE being outside
  the cell bounding set), Linux's epoll maxevents bound, and
  `/proc/sys/net/core/somaxconn`. Load exposed three Linux behaviors we
  lacked: epoll entries now name their open file description weakly and
  vanish when it closes (nginx never DELs before `close`; a reused fd
  number was EEXIST and closed sockets stayed alive); TCP takes a bare FIN
  against a zero window, sends no window update after the peer's FIN, and
  ends TIME_WAIT quietly on a RST; the NAT lets a SYN reopen a finished
  mapping.
- M5 UDP: `SOCK_DGRAM` sockets on the same per-cell stack (own port
  space, 256 KiB receive queue that drops when full, autobind on first
  send, connect/AF_UNSPEC, MSG_TRUNC, msg_name in sendmsg/recvmsg).
  Tested on loopback (Debian perl), across the switch between cells, and
  through the uplink's NAT to a host UDP echo. No ICMP errors yet.
- M5 `AF_UNIX` (`linuxabi/unix.rs`): stream, datagram and seqpacket
  sockets, `socketpair`, path names (a socket node in the cell's root,
  `overlay::Kind::Socket`, checked for write permission; open is ENXIO)
  and per-cell abstract names (autobind too), `SCM_RIGHTS` (passes open
  file descriptions; `MSG_CTRUNC`), `SCM_CREDENTIALS`/`SO_PASSCRED`,
  `SO_PEERCRED`, and `O_ASYNC`/`F_SETOWN`/`FIOASYNC` posting SIGIO. A
  descriptor's `UnixSocket` owns an `Endpoint`; closing it shuts the
  endpoint down outside every lock, so endpoints are cheap to drop inside
  wait conditions. nginx now runs with its master process and workers.
  Tests: `scm_rights_program` (runtest) and Debian perl's `UNIX_SCRIPT`.
  Not yet: `MSG_PEEK`, a collector for `SCM_RIGHTS` cycles.
- M5 socket memory: each stack charges what its sockets buffer to the
  cell's account by the page (`Inner::settle` after every operation);
  short of memory, it caps every connection's buffers where they stand
  (`Tcp::set_cap`: the window closes, writers wait) and drops datagrams,
  resuming with twice `RESERVE` pages of headroom. `AF_UNIX` queues charge
  the receiving cell; a write it cannot cover waits (ENOBUFS with nothing
  queued). Closing a TCP socket drops what it never read and answers later
  data with RST, as Linux does. Self-tests: `netstack::accounting_selftest`
  and `unix::accounting_selftest`.

Milestones 0-4 are done (4's acceptance test: Debian's `apt-get install`
from a local mirror). Phase E (scalability) is done except the vDSO
(blocked) and the per-CPU page lists, held back on `pcp-page-lists`.

- User copies (ADR-0011): `VmSpace::copy_to_user`/`copy_from_user` copy
  through the linear map one page at a time under the space lock, after
  checking the PTE (writes need it writable), so they stop where a user
  access would fault. `umem::copy_user` faults that page (demand paging,
  copy-on-write break) and copies on. `LinuxProcess::copy_*` run without
  the `Mm` lock (amended ADR-0011): the space is an `Arc` shared by `Mm`
  and `Group::space`, and `Mm` is locked only for a fault plus that one
  page's copy. The loader and native processes use `Mm::copy_*`, which
  hold the `Mm` throughout. io_uring helpers stay on the kernel address
  space. `copytest.rs` checks it on every boot: the frame API under a
  concurrent unmap, `read`/`stat` into read-only and page-cache-backed
  pages, a second cell, a copy running while the `Mm` lock is held
  (`mm_unlocked`), and a read/munmap stress race.

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
  one-CPU boots, against 0 in 20 without it (worth retrying: the
  direction-flag bug fixed on 2026-11-21, `docs/reports/direction-flag-fix.md`,
  corrupted memory past interrupted backward copies, and decompressors
  memmove a lot). Baseline in `docs/benchmarks.md`; Linux reference
  numbers come from `cargo xtask bench` (Alpine `linux-virt` booted with
  the same `testprog::bench` programs; CI job summary). Mm lock not held
  across whole user copies: done. Frame's copies check the PTE and copy
  each page under the space lock (ADR-0011,
  `docs/reports/user-copy-fix.md`), and Linux copies take the `Mm` lock
  only to fault a page (ADR-0011's amendment, `copytest::mm_unlocked`).]

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
frame is at 5,630 / 244 (A5 added RDSEED/RDRAND and UEFI GetTime; B
added XSAVE; C the frames tree and request tracking; M6 reading
`\ichor\roots.pem`; ADR-0011 the checked user copy). `services/rt` has
its own budget (`services/rt/audit.toml`: 500 / 40; at 402 / 29).

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
cargo xtask frame-audit    # frame's and services/rt's line and unsafe-site counts against their budgets
cargo xtask run --cmdline "qemu_debug_exit bench" --smp 4 --release   # benchmarks (use KVM for real numbers)
cargo xtask bench --accel kvm --smp 4   # Ichor vs Linux, same machine and programs (Markdown table)
cargo xtask disk-image     # target/ichor-disk.img: bootable GPT disk (ESP + Ichor root) for clouds/bare metal
cargo xtask fuzz [TARGET] --iterations N   # mutation-fuzz the parsers (failing inputs: target/fuzz/)
cargo xtask x509-limbo     # certificate validation vs x509-limbo -> docs/x509-limbo.md (fails below floors)
cargo deny check           # licenses, advisories, sources
```

Useful options: `--release`, `--accel auto|kvm|whpx|hvf|tcg`, `--smp N`,
`--memory MiB`, `--timeout secs`, `--gdb` (waits on tcp::1234), and `-- <raw
qemu args>`.

Environment overrides: `ICHOR_QEMU`, `ICHOR_OVMF_CODE` + `ICHOR_OVMF_VARS`,
`ICHOR_ACCEL`, `ICHOR_TEST_VERBOSE=1` (echo guest serial during tests),
`ICHOR_TEST_CMDLINE` (extra kernel options for every test boot, e.g.
`trace_errors` while chasing a flaky test; load the host with busy loops
to reproduce timing bugs: 11 parallel QEMUs on TCG are slow), and
`ICHOR_REQUIRE_KVM=1` (CI sets it: `cargo xtask test` fails unless KVM is
the accelerator).

Plain `cargo build` / `cargo test` at the root only touch host crates
(`default-members`). Crates that depend on frame (`ichor`, `ichor-frame`,
`ichor-virtio-pci`, `ichor-virtio-blk`, `ichor-virtio-rng`, `ichor-virtio-net`, `ichor-nvme`) are kernel-only: xtask's `KERNEL_ONLY` list keeps them
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
| `net_echo_port=N` | the kernel's TCP, then a Debian cell through NAT, echo 256 KiB with the host's echo server at 10.0.2.2:N |
| `net_publish=N` | publish uplink port N to a Debian cell's port 80 and serve one HTTP request from the host (QEMU forwards a host port to N) |
| `control=PORT` | after the self-tests, run the control plane serving gRPC on PORT, on the system cell's loopback only (the API has no authentication yet) |
| `control_listen=ADDR` | the address the API listens on (`0.0.0.0`: all of the system cell's, reachable from other cells) |
| `control_publish=PORT` | publish the API on uplink port PORT (without `control_listen`, listens on all addresses); needs an API token in `\ichor\apitoken` (`RunConfig::api_token`, `disk-image --api-token-file`), else the API stays on loopback |
| `control_exit` | with `control`: stop when the first API client hangs up, then shut down (tests) |
| `control_exit_after=SECONDS` | with `control`: stop after that long once no client is connected (tests) |
| `dns=A.B.C.D` | the control plane's DNS resolver (default `10.0.2.3`, QEMU's) |

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
kernel/drivers/virtio-net  safe virtio-net driver (polled, MAC feature only)
kernel/net       network protocols, sans-I/O: Ethernet, ARP, IPv4, ICMP, UDP, TCP (host-tested; ADR-0010)
kernel/uring     io_uring's ABI, ring layout and submission ordering, sans-I/O (host-tested; ADR-0013)
kernel/drivers/nvme        safe NVMe driver (polled, DMA-trusted)
xtask/src/artifact.rs      pinned downloads (busybox, Alpine): SHA-256, cache, never committed
xtask/src/inflate.rs       gzip/DEFLATE decoder; rootfs.rs: tar -> Ichor image
xtask/src/disk.rs, fat.rs  bootable GPT disk image (FAT32 ESP + Ichor root partition)
xtask/src/linuxref.rs      Linux reference boot for `cargo xtask bench` (Alpine linux-virt + initramfs)
kernel/ichor     the kernel binary; frame::main!(kmain); kcell/nativeabi tie it together
services/crypto  SHA-2, HMAC/HKDF, ChaCha20-Poly1305, X25519, RSA/ECDSA verify (host-tested; ADR-0012)
services/x509    DER, X.509, PEM root stores, chain verification (host-tested)
services/tls     sans-I/O TLS 1.3 + 1.2 client (host-tested, recorded sessions)
services/http    sans-I/O HTTP/1.1 client messages (host-tested)
services/layer   gzip/DEFLATE + tar layers (OCI whiteouts) into images; xtask uses it (host-tested)
services/oci     image references, the registry pull protocol, conversion, image config (host-tested)
services/dns     stub resolver messages (host-tested)
services/rt      native services' runtime: entry, syscalls, heap, panic (the only unsafe services crate; x86_64-unknown-none)
services/nativetest  native ABI v2 boot self-test, embedded in the kernel image
services/control the control plane: gRPC API, registry pulls, cells and runs (native service, embedded)
services/grpc    protobuf, gRPC over HTTP/2, ichor.v1.Control messages (host-tested)
fuzz/            mutation fuzzing of every untrusted-input parser (host-only)
xtask/           build/run/test/lint tooling (lib + bin, no dependencies)
tests/           QEMU integration tests (host crate using xtask's runner)
docs/adr/        architecture decision records
docs/reports/    write-ups of fixes and investigations (user-copy-fix.md, direction-flag-fix.md)
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

Pinned stable `1.100.0` (`rust-toolchain.toml`) with targets
`x86_64-unknown-uefi` (the kernel) and `x86_64-unknown-none` (native
services, built into `target/services`; xtask's `SERVICE_ONLY` list keeps
them out of host builds and lints them for that target).

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
