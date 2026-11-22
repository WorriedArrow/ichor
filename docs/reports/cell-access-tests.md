# Cell access-control tests

Date: 2026-11-22. Code: `kernel/ichor/src/cellaccess.rs` and
`cellaccess/*.pl` (kernel side), `tests/cell_access.rs` (host side). Plan
and working notes: `cell-access-tests-plan.md`.

The suite checks that the Linux ABI keeps a process to its own cell's
objects. Cells A and B each have their own root from the same Debian disk.
A helper in B owns one object of each kind. A makes the real syscall on
B's object and asserts one exact errno, then makes the same call on its
own (the control). `cell_access` on the command line runs it;
`cell_access_uplink` adds the uplink checks, which need the host client in
`tests/cell_access.rs`.

## Result

| Section (and test) | Checks | Result |
|---|---:|---|
| harness | 4 | pass |
| 1 `process_ids_and_signals_are_scoped_to_their_cell` | 146 | pass |
| 2 `proc_and_sys_show_only_their_cell` | 115 | pass |
| 3 file systems | 0 | **not written** (see below) |
| 4 `shared_cache_pages_never_carry_writes_between_cells` | 35 | pass |
| 5 `networks_are_scoped_to_their_cell` | 30 | pass |
| 6 `other_kernel_state_is_per_cell` | 28 | pass |
| 7 `uid_0_in_a_cell_has_no_authority_outside_it` | 51 | pass |
| 8 `resource_limits_are_per_cell` | 6 | pass |
| 9 `cells_clean_up_after_themselves` | B after each section, memory | pass |
| `a_destroyed_cell_leaves_no_shared_memory` | 3 | pass (bug 1, fixed) |

**Section 3 has no coverage.** A safety classifier stopped the session
while its script was being written, and it was not written again. So
nothing here checks `..` at the root, symlinks, links and renames across
roots, or that A cannot open B's ptys. Partial evidence elsewhere: B's file
is ENOENT to `stat`, `chown`, `chmod` and io_uring `OPENAT` from A, B's
socket path is ENOENT, and B's own file and ptys are unchanged after every
section. The owner decides how that section gets written.

## Bug 1 (fixed): a destroyed cell's System V segments were never freed

`linuxabi/shm.rs` keeps segments in a global table keyed by (cell id, id).
Only `IPC_RMID` removed one. Nothing did when a cell was destroyed, so its
pages stayed allocated and charged to the dead cell's account and every
account above it, up to the system's. ADR-0002 §7: after `cell_destroy`,
"nothing the cell created survives". A tenant that creates segments and is
destroyed, repeatedly, used up the node's memory budget for good.

The suite was committed with this check failing (d17ae02); the owner then
asked for the fix. `Cell` now frees its segments when its last reference
drops (`shm::free_cell`). Every process holds its cell, so nothing can make
another segment by then, and an attachment holds its segment, so pages
still mapped go when it does.

The check makes a 64-page segment in a cell, attaches it, lets the program
exit, drops the root and the last reference to the cell, and expects
nothing charged; the control removes its segment first. With the call to
`free_cell` disabled it finds 64 pages. B's own segment is intact after it.

## Bug 2 (open, found by reading): a destroyed cell's network stack stays

`netstack::STACKS` holds every cell's `Stack` and nothing removes one;
`net::switch`'s `detach` is never called by the kernel. So a destroyed
cell keeps its stack, its switch port and its 10.88.0.0/16 address (which
runs out), and ports published for it stay published. No check covers it
yet.

Two smaller observations, not failing checks:

- `fcntl(F_SETOWN)` accepts any pid; Linux answers ESRCH for one that does
  not exist. B's pid behaves exactly like a pid nobody has, and no SIGIO
  reaches B (`unix.rs` sends to the socket's own cell).
- At a full account, the first touch of a code page a program has not run
  yet is SIGSEGV, because file pages mapped into a process are charged to
  it. That is inside one cell, so not an access-control matter.

## Checks, errnos and code paths

Section 1, for each of B's four processes (helper, child, two futex
waiters). Controls use A's own child, which reports caught signals.

| Call on B's pid or tid | Errno | Code |
|---|---|---|
| `kill` 0/SIGUSR1/SIGTERM/SIGKILL | ESRCH | `proc::uids_of`, `proc::send_info` |
| `tkill`, `tgkill` | ESRCH | `proc::send_thread` |
| `kill(-pgid)`; `kill(0)`, `kill(-1)` reach only A | ESRCH | `proc::send_group` |
| `kill(p, 0)` for every pid handed out | only A's | `proc::uids_of` |
| `rt_sigqueueinfo`, `rt_tgsigqueueinfo` | ESRCH | `signal::may_signal` |
| `pidfd_open` | ESRCH | `proc::find` |
| `wait4`, `waitid` (P_PID, P_PGID) | ECHILD | `proc::wait` (not a child) |
| `getpgid`, `getsid` | ESRCH | `proc::process` |
| `setpgid` | ESRCH | `proc::process`, then "not me or my child" |
| `prlimit64` | ESRCH | `proc::find`, `signal::may_signal` |
| `sched_getaffinity`, `sched_setaffinity` | ESRCH | `proc::uids_of` |
| `sched_getscheduler`, `sched_getparam`, `capget` | ESRCH | `misc::known` |
| `getpriority`, `setpriority` | ESRCH | `linuxabi::priority` (caller only) |
| `get_robust_list` | EPERM | any thread but the caller, existing or not |

Section 2: `stat` of `/proc/<B pid>` and 14 files and directories in it,
its `task/` entries, `readlink` of `cwd` and `open` of `status` are ENOENT
(`procfs::process`, through `proc::find`); the control is another process
of A's. `/proc` lists only A's two processes (`proc::pids`). `/proc/self`'s
`cwd`, `fd/N` and `exe` name A's objects and A's maps do not show B's
mapping. `/proc/<pid>/root` and `mem` do not exist for anyone, so for those
two ENOENT proves nothing yet; nor does it for `/proc/self/cwd/x`, since
links are not followed partway through a path.

Section 4: page 1 of `/usr/bin/dash` is the same physical page in both
roots (checked). A's CPU store through `MAP_PRIVATE`, its `read()` into a
private mapping (ADR-0011) and its copy-up write leave B's mapping, B's
file and the cache page unchanged; so does A's CPU store through
`MAP_SHARED` of `/usr/bin/bash`. `read()` into `PROT_READ` is EFAULT.
`FUTEX_WAKE`, plain and private, at B's shared and private waiters wakes 0
(`futex::key`); the control wakes exactly A's own waiter on that page. B
confirms both waits end with the harness's signal (EINTR). An opted-out
root (`Vfs::mount_disk_private`) is charged for its pages and keeps the
same physical pages while A reads 79 MB and the shared cache evicts.

Section 5: `bind` to B's address is EADDRNOTAVAIL (`Stack::bind`). TCP from
A to B is allowed (ADR-0010) and B sees A's address. B's port on 127.0.0.1
is ECONNREFUSED. SOCK_RAW is EPERM, AF_PACKET EAFNOSUPPORT. rtnetlink shows
A's address, not B's. B's Unix path is ENOENT; its abstract names are
ECONNREFUSED to `connect`, `sendto` and an SCM_RIGHTS `sendmsg`
(`unix::lookup`). SO_PEERCRED names A's child. At the uplink B's listening
port refuses the host until published; published for A it never reaches B;
published for B the host gets B's answer.

Section 6: B's segment is ENOENT by key and EINVAL by id for `shmat` and
`shmctl` (`shm::get`, `shm::segment`); A's segment under the same key is
another, empty one. `sethostname`, `setdomainname` are EPERM. io_uring:
OPENAT of B's path is -ENOENT, READ of B's descriptor number -EBADF,
CONNECT to B's abstract name -ECONNREFUSED and path -ENOENT.

Section 7, as uid 0: `mount`, `umount2`, device `mknod`/`mknodat` (a FIFO
works), `clock_settime`, `settimeofday`, `unshare`, `setns` are EPERM.
`chown`, `lchown`, `chmod`, `fchownat` of B's paths are ENOENT. `kill` of
B's pids is ESRCH.

Section 8: a program fills A to 16384 of 16384 pages, where `fork` is
EAGAIN; another forks until EAGAIN (943 processes). B allocates 8 MiB and
forks at both points.

## Scoping removed, to check the checks

Each edit was made, booted, restored with `git checkout` and confirmed with
an empty `git diff`; none was committed.

| Removed | What failed |
|---|---|
| Cell filters in `proc::uids_of`, `send_info`, `send_thread`, `send_group` | Every `kill`, `tkill`, `rt_sigqueueinfo` and group check, `tgkill`, `rt_tgsigqueueinfo`, both `sched_*affinity`, and the pid sweep (found B's four); B was killed and the boot failed |
| Cell filters in `proc::find`, `process`, `pids` | `getpgid`, `getsid`, `pidfd_open`, `sched_getscheduler`, `sched_getparam`, `capget`; in section 2 the listing and every `/proc/<B pid>` check but `root` and `mem` |
| Cell id and process identity in `futex::key` | Both waiters were woken by A: 6 checks, in A, B and the harness |

The first run of the first experiment killed B before the later checks ran,
so SIGKILL now comes last. Not sensitive to a cell filter, because another
rule also refuses: `wait4`/`waitid` (not a child), `setpgid` (not a child),
`get`/`setpriority` (caller only), `get_robust_list` (caller only).
`prlimit64` has two filters, and either alone refuses it. Section 3's
experiment was not possible. Sections 5 to 8 were not asked for and not
done.

## ADR conflicts

- ADR-0002 §3 gives each cell a PID space whose init is PID 1. Pids are
  global numbers filtered by cell (`proc.rs` says so).
- ADR-0009 §3 puts MKNOD and SYS_CHROOT in the cell's bounding set. Device
  `mknod` is EPERM ("no CAP_MKNOD in cells") and `chroot` is ENOSYS. The
  task asks for `mknod` to fail, so EPERM is asserted.
- Bug 1 was, and bug 2 is, against ADR-0002 §7.
- ADR-0009 says `settimeofday`, `reboot` and module loading are "already
  EPERM or absent", so ENOSYS there agrees with it. Section 7's commit
  message says otherwise and is wrong.

## What global files and numbers show

- `/proc/loadavg`'s last field and `/proc/stat`'s `processes` are the
  global last pid, so a cell can count every cell's process creation.
  Its own pids show the same thing.
- System V segment ids come from one global counter: how many segments all
  cells made.
- `meminfo` is the cell's account. `cpuinfo`, the `/sys` cpu lists,
  `uptime`, `version` and `pid_max` are the machine's. `mounts` and
  `hostname` are fixed strings, the same in every cell.

## ENOSYS today, needing a real check later

`ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_getfd`,
`semget`, `msgget`, `mq_open`, `reboot`, `adjtimex`, `clock_adjtime`,
`chroot`, `init_module`, `iopl`, `ioperm`, `kexec_load`, `swapon`.

## Not tested

- Section 3 (above).
- The switch's anti-spoofing: no raw sockets, so no syscall can send
  another source address. `kernel/net` tests it.
- A denied cell-to-cell TCP policy: ADR-0010 has none.
- B's threads other than its processes' first: its helper is
  single-threaded, so its tids are its pids.
- `/proc/<pid>/root` and `mem`, which do not exist.
- A cell destroyed while its processes run (the control plane's Destroy).

## Running it

`cargo xtask test` runs it, with `--no-fail-fast` so a failing check does
not hide the test files after it. On a host short of memory QEMU may
not start all the boots at once; `cargo test -p ichor-tests --test boot --
--test-threads=2` with `ICHOR_KERNEL` set runs them two at a time.
