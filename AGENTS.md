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
- `docs/architecture.md`: the map: layers, a container's path, storage,
  networking, and where Ichor is meant to be extended (diagrams in
  `docs/architecture/`, Excalidraw sources beside their SVGs).

## Status

**Milestone 8 is done** (owner, 2026-11-23): Ichor boots and runs
containers on AWS, GCP and Azure (details under "Milestone 8" below). The bare-metal machine is deferred, not dropped: the owner has no
dedicated hardware yet, and declined using the development PC. Next on the
roadmap is milestone 9 (CRI); nobody has started it.

**Milestone 7** (io_uring; postgres, node, python, go and JVM workloads
pass their own test suites at a tracked pass rate; the suites run weekly
in `workloads.yml`). The design
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
`\ichor\apitoken`, ADR-0012 amendment; then TLS 1.3 from
`\ichor\apitls.pem`, its 2026-11-21 amendment]; (4) io_uring completions
without an enter (epoll on the ring fd, registered eventfd), with a test,
before the Node.js suite [done]; (5) extra layers in PullImage, each pinned and
verified by digest, with a refusal test [done: `LayerSource` (url, sha256
digest, `from`/`to` remap via `layer::Tree::add_tar_at`), fetched after
the image, checked with `oci::digest_of` before `oci::convert_with`;
tests/control.rs serves one from the host and refuses a wrong digest]; (6) ADR-0004's owed mitigations
(VERW, IBPB on cross-cell switches, page-table isolation), logged at
boot [done: VERW, IBPB, and page-table isolation (ADR-0004's second
2026-11-16 amendment)].

- Cell access-control suite (merged 2026-11-23, WorriedArrow/ichor#4;
  `docs/reports/cell-access-tests.md`): `cell_access` runs
  `kernel/ichor/src/cellaccess.rs`, two cells with their own roots, a helper
  in B owning one object of each kind, and A's real syscalls on them with
  exact errnos and controls (`tests/cell_access.rs`, one test per rule).
  All nine sections are done and pass; they found that a destroyed
  cell's System V segments and network stack leaked (fixed: a `Cell` that
  drops calls `shm::free_cell` and `netstack::end_cell`, which withdraws
  its published ports, lets closed connections finish for up to 60 s, then
  frees the address and its NAT mappings together; anything new keyed by
  cell id needs the same). Section 3 (file systems) leaves what it made in
  A's root so that B can look for it; what has a name of B's it removes. A
  syscall that stops being ENOSYS or changes errno needs its check updated.

- M7 page-table isolation (`kernel/frame/src/arch/x86_64/entry.rs`): the
  entry area (`mm::ENTRY_BASE`, one PML4 slot) aliases the entry code, the
  IDT and per CPU its block (GS), GDT/TSS, entry stack (RSP0) and IST
  stacks; the CPU always enters through the aliases. On Meltdown-affected
  CPUs, or with `force_pti`, a `VmSpace` root is an 8 KiB pair (full root,
  then a shadow with only the entry slot plus the shared user slots), ring
  3 runs on the shadow, every entry loads the full root first, PGE is off,
  and PCID (0 kernel, 1 user; user flushes owed by root changes and
  shootdowns) avoids flushes. Every trap from ring 3 now returns through
  `UserMode::execute` and `ichor_enter_user` (the one way into ring 3).
  `m2_scheduler_on_eight_cpus` boots with `force_pti`;
  `frame::user::isolation_selftest` checks the shadow on isolated boots.

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
  and RSA key rules. Since 2026-11-23 it agrees with every applicable
  case (504 accept, 4,798 refuse; floors 100%): the RFC 5280 / CABF
  issuance profile (AKI, SKI, critical BC, root AKI, AIA, SAN
  criticality), ML-DSA (FIPS 204, `crypto::mldsa`, with SHAKE in
  `crypto::sha3`; Wycheproof's 631 verify vectors, malformed ones
  included, pass in `cargo xtask wycheproof`, run by CI and `cargo xtask
  test`), and the Public Suffix List's ICANN rules against
  wildcards (`x509::suffix`; pinned `artifact::PUBLIC_SUFFIX_LIST`, its own
  file on the boot volume, `\ichor\suffixes.dat`, written by
  `artifact::public_suffix_rules`, read by frame and handed to the control
  plane as a second Blob, `suffix-blob=`). Ten cases contradict another
  case and are listed, with reasons, in `limbo.rs`'s `CONFLICTS`; one,
  `root-missing-ski`, is contradicted by Mozilla's TWCA Global Root CA
  (no SKI) and listed in `DEPARTURES` (both checked each run). Trust
  anchors need no SKI; every Mozilla root must anchor, or xtask refuses to
  build a boot volume (`RootStore::unusable`).
- M7 io_uring (ADR-0013 and its 2026-11-22 amendment): `kernel/uring`
  (host-tested) has the ABI, this kernel's ring layout and the ordering
  rules (`Order`: links, hard links, link timeouts, drains; what is
  complete is forgotten at once). `linuxabi/uring.rs` is the ring,
  `uring/ops.rs` what an SQE may say and does (the synchronous syscalls'
  code, through `linuxabi::dispatch`), `uring/tables.rs` what is
  registered (files with tags, buffers, provided-buffer groups, rings,
  restrictions). An SQE is tried without blocking on the description it
  named when it began, lent to the thread as descriptor `LENT`; what it
  points to is read when it is submitted (`Kept`); one that cannot go on is
  armed with its own registration on its object (`poll::Hub::watch`), and
  tried again when that changes: by a thread in `io_uring_enter`, by any
  thread of its process after a system call (`uring::task_work`), or by the
  ring's worker for that process (`LinuxProcess::helper`). Claimed while
  tried, so it runs once. DEFER_TASKRUN rings only run when asked
  (`nudge` tells the program); SQPOLL rings always say NEED_WAKEUP.
  `runtest::uring_program` and `uring_worker_program` check it on every
  boot; `cargo xtask workloads uring` runs liburing 2.5's tests. Not yet:
  personalities, URING_CMD, zero-copy sends, NO_MMAP, xattr operations.
  While a thread is in `io_uring_enter` (`State::entering`), it alone
  starts what is ready, as Linux's submitter does: the ring's worker (or
  another thread's task work) used to take a just-submitted SQE now and
  then, so `enter` returned before an inline completion was posted
  (`uring_program`'s check 23 failed once under the gate's load,
  2026-11-22).
- M7 CPython (first suite): `cargo xtask workloads python` pulls
  `python:3.12-slim-bookworm` plus the 3.12.16 source tree's `Lib/test`
  as a pinned layer and runs `python -m test -j0` in a cell. Fixed on
  the way: the direction flag was cleared on every return to ring 3,
  corrupting memory past interrupted backward copies
  (`docs/reports/direction-flag-fix.md`); `execve` argv/envp are bytes;
  file names are bytes (`overlay::name`: a reversible escape for
  non-UTF-8 bytes at the syscall boundary); `close_range`, `fadvise64`,
  get/setpriority, `memfd_create`, absolute `clock_nanosleep`, named
  pipes (`mknod`/`mknodat` S_IFIFO, blocking opens), robust futex lists;
  open TCP NAT mappings live five days (Linux's established timeout), not
  ten minutes; futex deadlines of the wall clock (`FUTEX_CLOCK_REALTIME`
  was taken as time since boot, so `sem_timedwait` never timed out).
  Latest full run (2026-11-22): 454 of 457 modules (99.3%). The three:
  no compiler in the image (`test_ctypes`), `dnotify` (`test_fcntl`), and
  `multiprocessing_spawn.test_processes`, which takes 9 of its 10 minutes
  under TCG and passes with a longer limit. rseq is ENOSYS.
- M7 Go (second suite): `cargo xtask workloads go` runs `go test -short
  std` on the official `golang` image. Fixed on the way: `epoll_wait` held
  descriptors and a fixed interest list while asleep (an epoll instance is
  now an eventcount hub: `Poller`, `Watchers::notify`); TCP announces a
  window that grew (pulls crawled at 0.8 MB/s); pulls time out on silence,
  not on size; signals sent to a process go to a thread that does not block
  them, `siginfo` says who sent one, real-time ones queue
  (`proc::Shared`, `proc::Pending`), and one posted to a thread spinning in
  ring 3 on an otherwise idle CPU takes it out (`Task::interrupt`,
  `UserMode::execute_unless`; it used to wait for a trap); `execve` from a
  process with threads killed the process; stop signals stop
  (`proc::begin_stop`, parked in `signal::deliver`), `wait4`/`waitid`
  report it, ptys send SIGTTIN/SIGTTOU; calls a signal interrupts without a
  handler go on to their deadline (`ERESTARTNOHAND`, `resume_until`);
  `splice` and friends (`linuxabi/splice.rs`), streams move more than 4 KiB
  a call and gathered writes are one; `MSG_PEEK`, `SO_RCVTIMEO`,
  `SO_LINGER` resets, `recvmmsg`; `NETLINK_ROUTE` reads (`net::rtnl`,
  `linuxabi/netlink.rs`); CPU-time and POSIX timers (`itimer.rs`); pidfds
  and `clone3`. Debian's perl checks most of it on every boot
  (`SIGNAL_SCRIPT`, `MOVE_SCRIPT`). Explore with
  `--cmd "go version" --follow FILE` (append shell lines to FILE; with
  `--image REF --memory MiB` on a machine too small for the suite's own).
  Latest full run (2026-11-22): 260 of 262 packages. The two: `crypto/sha1`
  (under TCG: QEMU reads 32 bytes for a 16-byte AVX2 operand) and `syscall`
  (ptrace).
- M7 PostgreSQL (third suite): `cargo xtask workloads postgres` builds
  16.16 in `buildpack-deps` (the official image carries no `pg_regress`)
  and runs `make check`; first run 223 of 224 (the other was QEMU's FMA on
  Windows, which `Accel::cpu_model` now leaves out). Needed: System V
  shared memory (`linuxabi/shm.rs`), `signalfd` (`linuxabi/timerfd.rs`,
  with `timerfd`), and a scheduler that calls idle CPUs to steal (a woken
  task waits on its waker's CPU; `sched::call_idle` at the tick). Tasks are
  scheduled by cell now (`SchedInfo::of_cell`).
- M7 also: `inotify` (the overlay records changes while watched), nested
  epoll, O_TMPFILE, `/proc/<pid>` of every process of the cell,
  `/dev/fd`, `/dev/std*` and `/proc/self/fd/N` opened anew
  (`fs::reopen`), paths that lead into `/proc` any way
  (`Overlay::set_elsewhere`), `execve` of `/proc/self/exe`, and small calls
  in `linuxabi/misc.rs`, O_RDWR FIFOs, file names in `/proc/<pid>/maps`,
  `/proc/<pid>/cmdline` read from the process's memory (titles written over
  argv), 2 MiB of arguments.
- M7 Node.js (fourth suite): `cargo xtask workloads node` runs its
  `test/parallel` and `test/sequential`; 4398 of 4404 (2026-11-22, 98 min
  under TCG). The six: four CPU-profiler tests (V8 samples every 100 us,
  which TCG cannot keep up with), `net-boundsocket` (wants port 1 refused;
  any user may bind any port in a cell, as in Docker), and `watch-mode`.
- M7 JVM (fifth suite): `cargo xtask workloads jvm` (jtreg, OpenJDK 21's
  tier 1). On KVM (`workloads.yml`): 2283 of 2376 (2026-11-22, 34 min).
  Of the 93, by their names: about 50 need native test libraries, which are
  not built (`java/foreign`, JNI), about ten the Unicode data files (not in
  a layer), and many of the rest may have met a full cell (the kernel log
  has processes killed at its 5 GiB; four tests run at once). Not under TCG, where about one JVM in
  twenty dies, since QEMU fetches an instruction in pieces while the JVM
  patches it (an `hs_err` whose fault address decodes from the old first
  bytes and the new last ones; memory is right). A sample of
  other directories passed 247 of 274; of its failures, `ProcessHandle`,
  `PortUnreachable` and four more pass since. Left to work on: multicast,
  urgent data, extended attributes (`CheckPermissions`, `FileAttributes`),
  `CopyProcFile`, `TracePinnedThreads`.
  Leave NIO's large-file tests out of a 5 GiB cell.
- M7 liburing (sixth suite): `cargo xtask workloads uring` builds
  liburing 2.5 (of Linux 6.6's time) in `buildpack-deps` and runs its
  tests one by one: 150 of 156 (2026-11-22; `timeout` is fixed since, the
  other five want IPv6, `CAP_SYS_RESOURCE`, which containers lack,
  `IP_RECVORIGDSTADDR`, URING_CMD on sockets, and Linux's own worker
  threads). It found the `execve` race (`/proc/<pid>/cmdline` read
  the old arguments' address in the new memory) and that a TCP socket whose
  connect was refused could not connect again.
- A pull that does not fit in memory fails, and the control plane lives
  on: `rt::memory_available` (`MEM_AVAILABLE`) is asked before large work,
  through `layer::Room` (`gunzip_within`, `add_tar_within`, `into_image`).
  Asking matters because a native process's heap does not fail: touching a
  page the cell cannot pay for ends the process. Converting takes the image
  about twice; layers may have several gzip members. Images are never freed
  (`IMAGE_CREATE` leaks them).
- WHPX (Windows) does not work with QEMU 9.0: it cannot run firmware from
  pflash, and with `-bios` (the two images concatenated) the firmware itself
  fails. OpenVMM runs on the same hypervisor platform and works.
- M7 storage (ADR-0006's 2026-11-21 amendment): a cell's root writes are
  frames charged to its account (`page.rs`: one charged-page type for
  process memory and file pages; `overlay::Pages` is where the overlay
  gets them), so `MAP_SHARED` file mappings map the file's own pages
  (`umem::fault_shared`, `runtest::shared_file_program`,
  `blktest::root_charges`), and images with megabytes of metadata mount
  (format v4: 64 KiB segments, `Image::mount_segments`).
- M7 what a cell takes of the kernel (2026-11-22; Go's runtime tests split
  a mapping into 40,000 pieces and the kernel panicked on one 4.5 MiB list
  of them): no list a program can lengthen is one allocation without a
  bound (an allocation over 4 MiB, or one that fails, is a kernel panic:
  bound it, page it, or keep it in a tree), and what is held for long is
  charged to the cell. Mappings: one `vma::RegionMap` with each region's
  backing (alike neighbors joined), at most 65,530 (`max_map_count`);
  `/proc/<pid>/maps` is written as it is read. Charged: upper inodes,
  names and long symlinks (`overlay::Pages::keep`, 8 a page), a thread's
  kernel stack and table entry (`page::Reserved`: 17 pages; EAGAIN), pipe
  buffers (ENOMEM). Bounded: 524,288 inodes a root, 16,384 locks a file,
  4,096 queued datagrams or `AF_UNIX` messages a socket. Directories are
  listed by an entry's place (`Overlay::list`), not its index, so removing
  while reading skips nothing. Not charged yet: page tables, region maps,
  epoll interest, open file descriptions, sockets' own state, futex and
  timer entries; kernel stacks are pooled, never freed.
- Boot hangs under the full gate's load (2026-11-21), found by booting 30
  VMs at a time until one stuck (1 in 60) and by reading. Fixed: a
  blocking FIFO open missed a peer that opened, wrote and closed between
  its count and its wait (reproduced: both CPUs halted, nothing armed;
  `pipe::fifo_selftest`); the timer self-test could halt after its last
  tick; `finish_switch` and a waker could both queue a task, and the stale
  entry then ran it while marked blocked, to be lost at its next
  preemption (`pick_and_claim` now refuses it; suspected for the one hang
  seen in `copytest::frame_race`, not proven); and the LAPIC and PM timer
  calibrations took one sample, which a descheduled vCPU spoils. A test
  boot that times out now appends every vCPU's registers, LAPIC and stack
  to its log (`qemu::vcpu_state`): read that first. Both CPUs at the idle
  `hlt` with no timer armed means a lost wake-up, not a lost interrupt.
- Cells cannot reach what is the machine's alone: link-local addresses and
  Azure's 168.63.129.16, where clouds answer whoever asks with the machine's
  credentials (`net::switch::is_machines`: refused with a reset at the
  uplink, DNS excepted).
- NICs: `virtio-net`, and `intel-gbe` (82574L and the 82576/I350/I210
  family; tested on QEMU's `e1000e` and `igb`: `RunConfig::nic`). The first
  that comes up is the uplink (`nettest::find`).
- The uplink is any `net::link::Link` (`kernel/net/src/link.rs`:
  `mac`/`transmit`/`receive`): NIC drivers implement it (virtio-net), and
  a software link such as a VPN can wrap one. New NIC drivers (ENA,
  gVNIC, VMBus) implement it too.

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
service as a Blob capability (and, since 2026-11-23, the Public Suffix
List's rules as `\ichor\suffixes.dat`, a second Blob). Open from it: `Signal`/`Inspect`/`Destroy`
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
  and replayed), `services/dns` (A records, CNAME chains). The TLS client
  also speaks AES-128-GCM (bitsliced) and P-256 (constant-time) since
  2026-11-22: Amazon's, Microsoft's and Quay's registries want them. Refresh
  a recording with `cargo test -p ichor-tls -- --ignored record_live` (or
  `-p ichor-oci`), and the clocks beside `SESSIONS` (there and in `fuzz`);
  it needs the internet and the roots in
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
uplink; virtio-net (polled). Open from it: IPv6, ICMP errors through the
NAT, interrupt-driven virtio-net (milestone 8 with cloud NICs).

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
  through the uplink's NAT to a host UDP echo. A closed port is
  ECONNREFUSED to a connected socket, in its cell or another.
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
  The cross-cell isolation test is the cell access-control suite (merged
  2026-11-23).
- Pseudo-terminals (`pty.rs`): `/dev/ptmx` and a devpts per root
  (`Vfs::ptys`; a slave opens only through the node made for it in the
  same root), an N_TTY-style line discipline (canonical editing, echo,
  ISIG to the foreground group, MIN/TIME, ONLCR), termios/winsize/job
  control/ptmx ioctls, controlling terminals and `/dev/tty`, hangup on
  master close. Debian's perl drives a session through dash, `tty` and
  `stty` on every boot. Partial: no flow control or packet mode; the
  console is still not a tty, and `/dev/tty` without a controlling terminal
  is ENXIO.
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

ADR-0004 records the side-channel posture. Built: VERW, IBPB on cross-cell
switch, page-table isolation for Meltdown-affected CPUs, IBRS on every
entry from ring 3 for CPUs without enhanced IBRS (`ichor_spec_ctrl` in
`entry.rs`), and enhanced IBRS
with BHI_DIS_S where enumerated (first run on AWS's m7i-flex, Sapphire
Rapids, 2026-11-22). Since 2026-11-23 (ADR-0004's last amendment) also:
the branch history cleared on every entry from ring 3 where BHI applies
without BHI_DIS_S (`ichor_clear_bhb`), IBPB on every entry for AMD's
Retbleed and SRSO (`ichor_entry_barriers`), AutoIBRS on AMD, the RSB
filled on every context switch (`switch_stacks`), and Spectre v1 masked
indices (`frame::nospec::index`; syscall numbers, descriptors, signals,
capability slots, io_uring's registered tables). Nothing in §2 is owed
now. Seen working on real hardware on GCP (2026-11-23): the BHB sequence
on Ice Lake (n2), IBPB and IBRS on entry on EPYC Milan (n2d); that run
found AMD's IBRS bit (CPUID 8000_0008h EBX[14]) unread, now fixed
(`Vulnerabilities::ibrs`). CI's forced flags test the code paths. Boot
logs which apply. GCP benchmarks against Debian 12 on the same machine
types, Ice Lake, Milan and Rome: `docs/benchmarks.md` (second round, with
fault-around and safe RET: system calls 1.5-3x Linux, pipes and fork
cheaper, 4 KiB page faults cheaper on AMD and slower on Intel; Linux's
own figures are huge-page faults, THP being on; container start 0.3-0.5
ms against 1.3-2 ms for `unshare`, 5-7 ms crun, 15-22 ms runc, 250-600 ms
Docker).

Frame budget: ADR-0005 sets the milestone 3 ceiling at 8,500 lines / 380
sites; ADR-0007 raises it to 9,500 / 420 for milestone 4 (TLB shootdown,
atomic user ops for futexes, PCID). `audit.toml` is at step 14 (7,250 / 310,
ADR-0004's safe-RET amendment); frame is at 7,202 / 292 (A5 added
RDSEED/RDRAND and UEFI GetTime; B added XSAVE; C the frames tree and
request tracking; M6 reading `\ichor\roots.pem`, later
`\ichor\suffixes.dat` too; ADR-0011 the checked user
copy; ADR-0004 VERW/IBPB, page-table isolation, eIBRS and IBRS; `IoPorts`;
xAPIC; Hyper-V; placing BARs the firmware left at 0, ADR-0005's second
amendment; the ACPI power button and S5, ADR-0017; kvmclock, ADR-0018; the
wall clock's NTP steering; the rest of ADR-0004 §2; AMD's IBRS bit and the
safe-RET return thunks, `arch::rethunk`). Growth past the step
needs an ADR and a new audit step.
`services/rt` has its own budget (`services/rt/audit.toml`: 500 / 40; at
417 / 30).

Milestone 8 (done 2026-11-23, bare metal deferred until hardware): `cargo xtask disk-image` writes a single
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
`docs/cloud.md`. `kernel/drivers/virtio-scsi` reads the disks of GCP's
general-purpose machine types (`cloud_disk_boots_from_virtio_scsi`);
with their virtio-net NIC those can network: the uplink takes its
address, router and DNS server from DHCP (`net::dhcp`, host-tested;
QEMU's slirp hands out 10.0.2.15, so the tests see the same address),
and the control plane resolves through the lease's DNS server unless
`dns=` is given. The uplink renews the lease at half its time, and moves
address if the server says so (published ports stay, connections are
cut); unrenewed past its end, it keeps the address and asks on.
**Google Cloud is done** (2026-11-22, an E2 machine: boots, pulls and runs
containers through the API over the internet; `docs/cloud.md`). Its virtio
devices are legacy (I/O ports: `frame::io::IoPorts`, ADR-0005's amendment;
virtio-pci speaks both transports). **Hyper-V** (Azure's hypervisor):
ADR-0015 (xAPIC) and ADR-0016: `frame::hyperv` (hypercalls, SynIC),
`kernel/vmbus` (the protocol, sans-I/O, fuzzed), `kernel/drivers/hyperv`
(disks and network). Works on OpenVMM, Microsoft's VMM, which runs on this
kind of PC without administrator rights and with hardware virtualization
(`docs/cloud.md` has the command): the fastest local way to run Ichor.
**Azure is done** (2026-11-22, a Standard_D4s_v5: boots, pulls and runs
containers through the API).
**AWS is done** (2026-11-22, an m7i-flex.large: boots from EBS on NVMe,
networks over the ENA, takes its options from IMDSv2, pulls and runs
containers through the API; `docs/cloud.md` has the run and the runbook).
`kernel/ena` (host-tested) is the ENA protocol, `kernel/drivers/ena` the
polled driver: transmit through a low-latency queue in device memory when
offered (newer instance types require it), else host memory. Two things
AWS taught: its firmware leaves the ENA's BARs at 0 (frame places them in
the bridge's window, ADR-0005's second amendment), and the ENA creates no
completion queue unless the host information says Linux and driver
version 2 (`ena::host_info`; status 6 otherwise). Links say their MTU
(`Link::mtu`, 1500); AWS's DHCP says 9001 and is not believed. Only the
m7i-flex has been tried (t3 and older types: not yet).
The ACPI power button (ADR-0017): frame owns the PM1 and SMI_CMD ports
(ACPI mode on if the firmware left it off), enables the fixed button's
event without taking the SCI, and the kernel polls it every 250 ms
(`frame::power::power_button`, `watch_power_button` in `main.rs`); a press
writes `\_S5`'s sleep types (read from the DSDT, else an SSDT, by
`acpi::s5_sleep_types`, no AML run) and turns the machine off (`frame::power::power_off`). So a
cloud's stop should end the machine at once on GCP and AWS (tested in
QEMU only: `the_power_button_turns_the_machine_off`, `system_powerdown`
through `RunConfig::power_button_after`); Azure's hardware-reduced FADT has no
such button: its stop needs Hyper-V's shutdown integration service.
**gVNIC** (2026-11-23): `kernel/gve` (host-tested) and `kernel/drivers/gve`,
GQI-QPL, polled; works on GCP E2 (first boot, MTU 1460). It polls the
status register the management interrupt announces (100 ms) and resets the
device when asked (`ichor: gve:` lines). DQO-only devices (C3 and newer)
are refused. `kernel/ichor/src/watch.rs` (`metadata=gcp` or `watch_cloud`):
GCP's `maintenance-event` long-polled, the wall clock against the
metadata server's NTP (`net::ntp`), a stall ticker, and `disk_hammer`.
`tests/migration/` is the live-migration campaign (README there). It found
the TSC calibrated over 10 ms of the PM timer was 14 ppm off on GCP (now
100 ms: 0.25 ppm); that a live migration moves the guest to a host whose TSC
runs about 96 ppm differently, after which a boot-calibrated clock loses 8 s
a day (so on KVM frame's clock is kvmclock now, `frame::kvm`, ADR-0018:
refreshed within 10 ms of a migration; checked only on GCP and CI's KVM,
since TCG has none); that kvmclock itself runs 71 ppm slow against NTP on
GCP (its rate is the host's own TSC calibration), so the watch now
disciplines the wall clock (`net::ntp::Discipline`: a step at the first
quick sample, then a PI loop on the rate, tau 60 s, at most 500 ppm;
`frame::time::steer_wall_clock`; `now()` and timers stay unsteered;
ADR-0018's amendment); that GCP keeps `\_S5` in an SSDT, not its DSDT
(now searched too; not yet seen working on GCP); and
that GCE's simulated maintenance takes about 11 minutes a run (3.5 to 6.5
before the notice, 80 s of migration, 3.5 before the operation ends), and
fails now and then (`BACKEND_ERROR`, nothing migrated). Results so far (two
migrations under load; the owner stopped the campaign early): network, disk,
API and TCP connections came through untouched, no stall of 250 ms, no
gVNIC reset; the clock now stays within 0.62 ms of NTP through one
(`tests/migration/README.md`).
Not yet: Azure's newest sizes (PCI over VMBus: NVMe and MANA),
Secure Boot, Azure's shutdown service; Azure's CPU enumerates no MD_CLEAR or
SPEC_CTRL (VERW and IBRS off: look into; frame reads the right bits, and
on OpenVMM the guest OS ID changes nothing in CPUID leaf 7, so try it on
Azure itself next time). Deferred: one bare-metal machine (the owner has
none yet; the owner called milestone 8 done without it).

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
cargo xtask api HOST:50051 --name NAME --ca ca.pem --token-file F IMAGE -- CMD   # pull and run on a running machine (docs/cloud.md)
cargo xtask fuzz [TARGET] --iterations N   # mutation-fuzz the parsers (failing inputs: target/fuzz/)
cargo xtask x509-limbo     # certificate validation vs x509-limbo -> docs/x509-limbo.md (fails below floors)
cargo xtask wycheproof     # Wycheproof's ML-DSA verify vectors (malformed ones too); fails on any wrong verdict
cargo xtask workloads python   # CPython's own suite through the control plane -> docs/workloads.md (fails below workloads.toml's floor)
cargo xtask workloads python --tests "test_os test_json"   # a subset (printed, not recorded)
cargo xtask workloads python --cmdline trace_errors --cmd "python3 -c ..."   # explore; guest log in target/workloads-python.serial.log
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
`ichor-virtio-pci`, `ichor-virtio-blk`, `ichor-virtio-rng`, `ichor-virtio-net`, `ichor-intel-gbe`, `ichor-nvme`, `ichor-virtio-scsi`, `ichor-hyperv`, `ichor-ena-driver`) are kernel-only: xtask's `KERNEL_ONLY` list keeps them
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
| `force_verw` | VERW before every return to ring 3 on any CPU (ADR-0004; tests) |
| `force_pti` | page-table isolation on any CPU, Meltdown-affected or not (ADR-0004; tests) |
| `force_bhb` | the branch-history clearing sequence on every entry from ring 3, on any CPU (ADR-0004; tests) |
| `force_ibpb_entry` | IBPB on every entry from ring 3 where the CPU has IBPB (ADR-0004; tests) |
| `force_safe_ret` | the Zen 3/4 safe-RET return thunks on any CPU (ADR-0004's safe-RET amendment; tests) |
| `srso=ibpb` | on CPUs SRSO or Retbleed affects, IBPB on every entry instead of safe-RET return thunks |
| `trace_errors` | log every failing Linux syscall (pid, number, first arguments, errno) |
| `trace_pid=N` | log every Linux syscall of pid N with its result |
| `bench` | run the Phase E benchmarks (`bench.rs`) after the root disk's self-tests and print them |
| `cell_access` | run the cell access-control suite (`cellaccess.rs`) after the Debian checks |
| `cell_access_uplink` | with `cell_access`: check the uplink too; a host client must be connecting to a forward of port 7300 |
| `net_echo_port=N` | the kernel's TCP, then a Debian cell through NAT, echo 256 KiB with the host's echo server at 10.0.2.2:N |
| `net_publish=N` | publish uplink port N to a Debian cell's port 80 and serve one HTTP request from the host (QEMU forwards a host port to N) |
| `control=PORT` | after the self-tests, run the control plane serving gRPC on PORT, on the system cell's loopback only, over TLS if there is `\ichor\apitls.pem` |
| `control_listen=ADDR` | the address the API listens on (`0.0.0.0`: all of the system cell's, reachable from other cells); needs what `control_publish` needs |
| `control_publish=PORT` | publish the API on uplink port PORT (without `control_listen`, listens on all addresses); needs an API token in `\ichor\apitoken` (`RunConfig::api_token`, `disk-image --api-token-file`) and a certificate and Ed25519 key in `\ichor\apitls.pem` (`RunConfig::api_tls`, `disk-image --api-tls-file`), else the API stays on loopback |
| `control_plaintext` | let `control_listen`/`control_publish` do without a certificate (a network you trust) |
| `control_exit` | with `control`: stop when the first API client hangs up, then shut down (tests) |
| `control_exit_after=SECONDS` | with `control`: stop after that long once no client is connected (tests) |
| `uplink_mtu=N` | the uplink network's MTU, over the DHCP lease's (default: the lease's, else 1500); every TCP SYN crossing the uplink is clamped to MTU - 40 |
| `metadata=CLOUD` | ask the cloud (`gcp`, `aws`, `azure`, or `auto`: each in turn) for the machine's configuration: `control*` and `dns` options, the API's token and certificate (`cloud.rs`, `net::metadata`, `docs/cloud.md`) |
| `metadata_addr=IP:PORT` | ask there instead of at 169.254.169.254:80 (tests) |
| `dhcp_lease=SECONDS` | the longest the uplink's DHCP lease is taken to last (tests: renewed sooner) |
| `dns=A.B.C.D` | the control plane's DNS resolver (default: the uplink's DHCP lease's first DNS server, else `10.0.2.3`, QEMU's) |

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
kernel/drivers/intel-gbe   safe Intel gigabit Ethernet driver (polled, DMA-trusted)
kernel/net       network protocols, sans-I/O: Ethernet, ARP, IPv4, ICMP, UDP, TCP (host-tested; ADR-0010)
kernel/uring     io_uring's ABI, ring layout and submission ordering, sans-I/O (host-tested; ADR-0013)
kernel/drivers/nvme        safe NVMe driver (polled, DMA-trusted)
kernel/drivers/virtio-scsi safe virtio-scsi driver: every target's disk, read-only, polled (GCP's E2/N1/N2 disks)
kernel/vmbus     VMBus (Hyper-V), sans-I/O: the connection, rings, storage and network protocols (host-tested, fuzzed; ADR-0016)
kernel/drivers/hyperv      safe Hyper-V disk and network drivers over VMBus (polled, DMA-trusted)
kernel/ena       AWS's Elastic Network Adapter, sans-I/O: admin commands, descriptors, LLQ layout (host-tested)
kernel/drivers/ena         safe ENA driver (polled, DMA-trusted; LLQ when offered)
xtask/src/artifact.rs      pinned downloads (busybox, Alpine): SHA-256, cache, never committed
xtask/src/inflate.rs       gzip/DEFLATE decoder; rootfs.rs: tar -> Ichor image
xtask/src/disk.rs, fat.rs  bootable GPT disk image (FAT32 ESP + Ichor root partition)
xtask/src/linuxref.rs      Linux reference boot for `cargo xtask bench` (Alpine linux-virt + initramfs)
kernel/ichor     the kernel binary; frame::main!(kmain); kcell/nativeabi tie it together
services/crypto  SHA-2, HMAC/HKDF, ChaCha20-Poly1305, X25519, Ed25519, RSA/ECDSA verify (host-tested; ADR-0012)
services/x509    DER, X.509, PEM root stores, chain verification (host-tested)
services/tls     sans-I/O TLS 1.3 + 1.2 client, TLS 1.3 server (host-tested, recorded sessions; `testdata/api.pem` is a public test key)
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

The kernel build only (`xtask::build::kernel`), with `RUSTC_BOOTSTRAP=1` on
the pinned stable compiler (the owner's choice, 2026-11-23, over a dated
nightly; ADR-0004's safe-RET amendment): `-Zfunction-return=thunk-extern`
(return thunks for AMD's SRSO), `-Zbuild-std=core,alloc,compiler_builtins`
with `compiler-builtins-mem` (so the standard library's returns use them
too; its assembly stack probe frame patches at boot). The kernel build
also runs without a compiler wrapper (sccache hangs on its command line on
Windows), and the first build after a clean compiles the standard library.
Everything else builds on plain stable. Remaining candidate: CET/IBT
codegen.

## Environment notes

- CI (GitHub Actions, `ubuntu-24.04`) installs `qemu-system-x86` and `ovmf`,
  enables `/dev/kvm`, and runs lint, test, and cargo-deny.
  `.github/workflows/workloads.yml` runs the workload suites on KVM, weekly
  and on demand, and fails below their floors.
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
