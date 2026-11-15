# ADR-0002: Cell model and capabilities

- Status: Accepted
- Date: 2026-11-14
- Amended: 2026-11-15 (milestone 2 implementation notes, at the end)

## Context

Linux builds containers by attaching *views* (namespaces) and *limits*
(cgroups) to processes that still live in one global kernel. Each namespace
type is a separate filter over global tables (PIDs, mounts, network devices,
users, IPC keys, hostnames). Escapes keep happening because the global object
is always one missed check away. The brief inverts this: **there is no global
namespace to carve up.** The unit of isolation is a *cell*, and a cell can
reach only what it holds a capability to.

The model also has to serve two kinds of client:

- unmodified Linux binaries that call `getpid`, `open("/etc/passwd")`,
  `unshare`, `mount`, and read `/proc/self/cgroup`; and
- Ichor's own services, which use a small, capability-based native ABI.

Prior art studied: seL4 (capability spaces, untyped retyping, revocation via
the derivation tree), Fuchsia Zircon (handles with per-handle rights,
VMO/VMAR, jobs as policy and resource containers), Capsicum (capability mode
for POSIX file descriptors), and Linux namespaces/cgroups (the thing we
emulate, not imitate).

## Decision

### 1. Kernel objects and capabilities

- All kernel state a cell can affect is held in **kernel objects**: `Cell`,
  `Process`, `Thread`, `AddressSpace`, `MemoryObject` (anonymous memory, file
  pages, image pages, memfd), `Node` (a VFS directory or file within a mount
  view), `Volume`, `Image` (a read-only, content-addressed OCI layer set),
  `Port` (a virtual network interface on the cell switch), `Device`
  (passthrough), `Channel` (message IPC), `Event`/`Timer`, and `Account` (a
  resource budget).
- A **capability** is an unforgeable reference to one object together with a
  **rights** mask. Rights are generic (`DUPLICATE`, `TRANSFER`, `INSPECT`,
  `WAIT`) plus object-specific (`READ`, `WRITE`, `EXEC`, `MAP`, `CREATE_CELL`,
  `KILL`, `ATTACH_VOLUME`, ...).
- In the kernel a capability is `Cap<T> { obj: Arc<T>, rights: Rights,
  revoke: Option<Arc<RevokeToken>> }`. This is a plain safe Rust value in
  `kernel/cap`; frame is not involved.
- **Rights only shrink.** `duplicate(cap, rights)` requires
  `rights ⊆ cap.rights` and the `DUPLICATE` right. There is no operation that
  amplifies rights.
- **Revocation.** A capability may be minted with a revocation token shared by
  everything derived from it. Revoking flips the token, and every use checks it
  with one atomic load. This is how the control plane detaches a volume or
  network port from a running cell without hunting down every copy. It is
  cheaper than seL4's derivation tree, at the price of coarser granularity:
  revocation is per token, not per individual derivation. Objects without a
  token are revoked only by dropping the last reference (Zircon semantics).

### 2. Capability spaces

- **Each cell has its own capability table (CSpace).** Native-ABI handles are
  `u64` values: a 32-bit slot index plus a 32-bit generation, so a stale handle
  never aliases a new object (no ABA). Handles mean nothing outside the cell
  that issued them, so passing a handle value to another cell grants nothing.
- Capabilities move between cells only by **explicit transfer**, either over a
  `Channel` or by the control plane when it creates or modifies a cell. Both
  require the `TRANSFER` right.
- Linux processes never see handles. Their **file-descriptor table is a
  per-process view that maps fd numbers to capabilities** (files, sockets,
  pipes, epoll, eventfd, timerfd, signalfd, pidfd, memfd). `dup`, `fork`,
  `SCM_RIGHTS`, and `pidfd_getfd` are capability duplication and transfer
  underneath, so they follow the same rules.

### 3. Cells

A cell holds one container, or one pod (several containers that share
whatever the pod spec says they share). A cell owns:

| State | How the Linux ABI sees it |
|---|---|
| CSpace | fd tables of its processes; native handles |
| PID space | `getpid` and friends; the container's init is PID 1 |
| Root mount view (a `Node` capability tree) | `/`, `mount`, `chroot`, `pivot_root` |
| Network stack instance plus its `Port`s | `socket`, `ip link`, `/proc/net/*` |
| UID/GID map and credential state | `getuid`, `setuid`, user namespace maps |
| UTS state | `uname`, `sethostname` |
| SysV IPC and POSIX mqueue keyspace | `shmget`, `msgget`, `mq_open` |
| Clock offsets | time namespaces |
| `Account` (resource budget) | `/sys/fs/cgroup`, `/proc/self/cgroup` |

- **There is no "host" namespace above cells.** The kernel's own bookkeeping
  (the list of all cells, the global frame allocator) exists, but **no syscall
  takes a global name.** The only way to name an object is through a
  capability the caller holds, or through a cell-local name (a path in the
  caller's mount view, a PID in the caller's PID space) that resolves inside
  the caller's cell state.
- **Linux namespaces inside a cell are nested views over that cell's own
  state.** `unshare(CLONE_NEWPID)` creates a child PID view whose PIDs are
  also PIDs in the cell's space, as on Linux. `CLONE_NEWNS` copies the cell's
  mount view; `CLONE_NEWNET` creates another network stack instance charged to
  the cell; `CLONE_NEWUSER` composes UID maps. A nested view can only narrow
  the cell's state, never widen it, because it is built from objects the cell
  already holds. Tools that unshare namespaces inside containers (`unshare`,
  `bwrap`, rootless podman, buildkit) therefore work without becoming an
  escape vector.
- **cgroups are a view over `Account`s.** The cgroup2 filesystem in a cell is
  synthesized from the cell's account tree. Creating a cgroup directory
  creates a child account whose limits are clamped to the parent's. Writing
  `memory.max` sets a limit on that account; it cannot exceed the cell's own
  budget. `/proc/self/cgroup` reports the path within the cell, which is `/`
  for a process in the cell's root account.
- **UID 0 inside a cell is not a host superuser, because no host superuser
  exists.** Linux capabilities (`CAP_SYS_ADMIN` and so on) are emulated. They
  gate operations only against the cell's own objects, and are bounded by what
  the cell's CSpace contains. `mount` succeeds if the caller has
  `CAP_SYS_ADMIN` *in the cell* and the source is a `Volume` or `Image`
  capability the cell holds. A cell cannot mount what it was not given.

### 4. The cell tree, authority, and accounting

- At boot the kernel creates exactly one cell, the **system cell**. It runs
  Ichor's native-ABI services (the control plane) and initially holds every
  root capability: all memory accounts, all devices, the switch, and
  `CREATE_CELL`. The kernel interprets no other privilege.
- A cell is created by a holder of a `Cell` capability with `CREATE_CELL`.
  It is given:
  1. an `Account` carved from the creator's account,
  2. its root filesystem view (an `Image` plus a copy-on-write upper layer
     backed by a `Volume` or by memory),
  3. zero or more `Port` and `Volume` capabilities, and
  4. a policy (CPU pinning, sharing opt-out, Linux-capability bounding set,
     seccomp-equivalent syscall filter).
- **Authority comes from capabilities, not from position in the tree.** The
  creator keeps a `Cell` capability to the child, with rights such as `KILL`,
  `INSPECT`, and `ATTACH_VOLUME`. Without that capability, being an ancestor
  confers nothing.
- **Accounting is hierarchical.** Accounts form a tree that mirrors creation,
  for hierarchical fair share: between cells, then within a cell. They are
  enforced *at the point of use*:
  - Memory is charged when the frame allocator hands out a page for the cell,
    and a refused charge returns `ENOMEM` to the cell (or invokes the cell's OOM
    policy), never the global OOM path.
  - CPU is enforced by the scheduler (shares, quota/period, optional dedicated
    cores).
  - Block IO uses per-queue token buckets in the block layer.
  - Network uses per-`Port` rate limits in the switch.
- **Shared image pages are charged to the `Image`'s account** (owned by the
  system cell), not to whichever tenant touched the page first. Linux charges
  the first toucher, which creates cross-tenant accounting interference.
  A cell that opts out of sharing gets private copies, charged to itself. This
  is also the opt-out that tenants worried about cross-cell page-cache timing
  channels use.

### 5. Two syscall personalities

- A process has **exactly one personality, fixed at creation**: Linux or
  native. Linux processes are created by `execve` of an ELF in a Linux cell, or
  by the control plane starting a container's entrypoint. Native processes are
  started by the system cell's service loader.
- Both personalities arrive through the same `syscall` entry and frame's
  `UserMode::execute` (ADR-0001 §4.5). The kernel dispatches on the process's
  personality, so a Linux process cannot reach native calls by choosing
  syscall numbers.
- The native ABI is object-oriented: `handle_duplicate`, `handle_close`,
  `channel_*`, `object_wait`, `vm_map`, `cell_create`, and so on. Every call
  takes the handles it acts on, and no call takes a path or a global ID. It is
  versioned and specified in `docs/abi/` (milestone 2).
- The Linux ABI is implemented in `kernel/linux-abi` as safe code over the same
  objects. `docs/linux-abi.md` tracks syscall coverage once the personality
  exists (milestone 3).

### 6. Hardware isolation posture (summary)

Cells are hostile-tenant boundaries. The mechanisms, all in frame, are:

- per-address-space PCID;
- SMEP, SMAP, and UMIP;
- IBPB and RSB filling on cell switch, where the CPU needs them;
- L1D flush on switch to and from a cell flagged sensitive;
- optional **dedicated cores**: a cell pinned to physical cores whose SMT
  siblings are never scheduled for another cell;
- a page-sharing opt-out (section 4).

The threat model and which mitigations are on by default are decided in the
side-channel ADR, due before milestone 2 completes.

### 7. Lifecycle (maps onto OCI)

| OCI | Ichor |
|---|---|
| `create` | control plane calls `cell_create` (objects allocated, accounts charged, init process created but not started) |
| `start` | `cell_start` runs init |
| `kill` | `cell_signal` delivers a signal to init, or to all processes |
| `state` | `cell_inspect` (status, PIDs, exit code, usage) |
| `delete` | `cell_destroy` revokes every capability the cell holds, frees its accounts, and drops its objects |

After `cell_destroy`, nothing the cell created survives except what it handed
to others through capabilities, such as a volume written to. That is the state
the control plane manages.

## Alternatives considered

- **Emulate Linux's model: global objects plus namespace and cgroup filters.**
  Every new kernel feature would need namespace awareness to be secure by
  default, and a missed check is an escape. Rejected. This is the design the
  brief exists to avoid.
- **One VM per container** (Firecracker, Kata). Strong isolation, but a guest
  kernel per container costs memory and startup time, and container-to-container
  traffic crosses virtual NICs. That contradicts the brief's density and
  cold-start goals. Rejected.
- **seL4-style explicit untyped memory in every CSpace.** Precise, but the Linux
  ABI allocates kernel memory implicitly everywhere (a `socket()` call allocates
  a stack-sized object). Accounts charged at the point of use give the same
  bound with much less mechanism. Rejected for the Linux personality. The
  native ABI may expose finer-grained memory capabilities later.
- **Capsicum-style capability mode as an option on top of global state.** It
  helps applications sandbox themselves, but it still leaves global state
  underneath. Rejected as the foundation. Its idea of mapping fd tables onto
  capabilities is adopted (section 2).
- **Per-derivation revocation tree (seL4 CDT).** Exact, but adds memory and
  locking to every duplicate and transfer. Rejected in favour of shared
  revocation tokens, which cover the control plane's needs (detach a volume or
  port) with one atomic load per use.

## Consequences

- An escape needs either a memory-safety bug in frame or a logic bug that
  hands a cell a capability it was never given. Both are local, auditable
  properties; nothing depends on remembering to filter a global table.
- The Linux personality has to synthesize much of what Linux keeps globally
  (`/proc`, `/sys`, cgroupfs, namespace files) from per-cell state. This is real
  work, budgeted in milestones 3–4.
- Cross-cell features have to be designed as capability transfers: shared
  volumes, inter-pod networking, and the page sharing that the image format
  relies on. That is the intent.

## Amendment: milestone 2 implementation notes (2026-11-15)

The capability and cell model landed as designed, in safe crates plus a thin
kernel tie-in:

- **Capabilities** (`kernel/cap`): `Cap<T>` carries an object, a `Rights`
  mask, and an optional `Arc<RevocationToken>`. `derive` only ever drops
  rights and needs `DUPLICATE`. Revocation is one atomic flag checked on
  every use. `CSpace<T>` is a slot table; a `Handle` is a 32-bit index plus a
  32-bit generation, so a closed handle never resolves again (no ABA). All of
  this is `#![forbid(unsafe_code)]` and host-tested.
- **Accounts** (`kernel/cell`): a tree of atomic (limit, used) nodes. A
  charge reserves against the node and every ancestor and rolls back on
  failure; a child's limit is clamped to the parent's. A concurrency test
  confirms charges never exceed the limit. The per-account *children list*
  from §4 was dropped for now: it needed interior mutability (unsafe), is not
  required for correct accounting, and can be tracked by the kernel
  separately when a cgroup tree view needs it.
- **The kernel tie-in** (`kernel/ichor::kcell`): a `Cell` owns a
  `SpinLock<CSpace<Object>>`, an `Account`, and a `VmSpace`. `Object` is
  `Memory(UFrame)` or `Cell`. `alloc_memory` charges the account before
  installing a capability, so memory is accounted at the point of use.
- **Native ABI** (`kernel/abi`, dispatched by `kernel/ichor::nativeabi`):
  version 1 has `VERSION`, `MEM_SIZE`, `HANDLE_DUP`, `HANDLE_CLOSE`, `EXIT`
  (`docs/abi/native.md`). A process's syscalls act only on its cell's CSpace,
  so a forged or foreign handle returns `BadHandle`. The Linux personality
  (§5) and the richer object set (channels, events, cell lifecycle) come in
  milestones 3–6.

Not yet built from this ADR: the two syscall personalities sharing one entry
is in place (the dispatcher is chosen per process), but only the native one
exists; the Linux personality, `/proc`/`/sys`/cgroupfs synthesis, namespace
nesting, and the hardware isolation posture (§6, the side-channel ADR) are
milestone 3+ work.
