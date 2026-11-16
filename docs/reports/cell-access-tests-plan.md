# Cell access-control tests: plan

Working plan for the Linux-ABI cell access-control suite (the owner's
task of 2026-11-15). The finished write-up is `cell-access-tests.md`;
this file is the checklist. At the start of each session: read this and
`git log`, and resume at the first unticked item.

## Harness design

- **Where it runs.** `kernel/ichor/src/cellaccess.rs`, run from
  `blktest` on the Debian disk when the command line has `cell_access`
  (after `debiantest`, so a normal boot is unchanged). The host side is
  `tests/cell_access.rs`: one boot (shared through a `OnceLock`) and one
  `#[test]` per rule, named after it, each asserting its own markers. The
  uplink check needs a host client, so the boot forwards a host port.
- **Two cells, two roots.** Cells A and B (own accounts, carved from one
  system cell), each with its own root from `Vfs::mount_disk` of the same
  Debian disk: separate overlays and devpts, the same shared page cache
  pages. A third cell B' with `Vfs::mount_disk_private` for the private
  cache check (section 4).
- **Programs.** Debian's perl (as `debiantest` runs it, through
  `run_linux`, so each run ends with the "memory returned" check:
  the cell's account must drop back to 0). Checks use perl's
  `syscall()` for the raw call and compare `$!` numerically, so the errno
  is exact. A CPU store into a private file mapping needs an instruction
  perl cannot issue: that one is a `testprog` ELF.
- **B's helper.** One long-lived perl process in B (on its own kernel
  task). It sets up B's objects (a forked child, a file only in its root,
  a TCP listener on its address, a listener for the uplink port, a Unix
  path socket and an abstract name, two ptys, a futex waiter in a forked
  child at a file offset, signal handlers counting what arrives), then
  serves requests until told to exit.
- **Channel.** Files under `/run/ichor/` in each root, written and read by
  the harness through the root's overlay (kernel side) and by perl through
  ordinary syscalls. `out-NAME` is a report from perl, `in-NAME` a request
  from the harness; each is written to a temporary name and renamed, so a
  reader never sees half. B's helper polls for `in-*` and answers with
  `out-*`; A's scripts get B's identifiers only from the harness (argv,
  and `in-*` files for later phases). Nothing in A can name B's root.
- **Output.** A check prints `cellaccess: RULE: CHECK: ok (ERRNO)` and its
  control `... control ok`; a failure prints `cellaccess FAILED: RULE:
  CHECK: expected X, got Y`. The harness prints `ichor: cellaccess: RULE:
  N checks passed` per section, checks B after each section
  (`ichor: cellaccess: B alive after RULE`), and fails the boot at the end
  if any section failed. Sections that fail do not stop later ones.

## Sections

Status: [ ] to do, [x] done and committed.

- [x] **Harness**: cells, roots, B's helper and its report, the channel,
  one trivial check each way, the host test file. Commit.
- [x] **1. process_ids_and_signals_are_scoped_to_their_cell** (83 checks)
  - kill(B pid, 0/SIGUSR1/SIGKILL) ESRCH (`signal::kill` -> `proc::uids_of`
    filters `e.cell == cell`); tkill/tgkill(B tid) ESRCH
    (`proc::send_thread`); kill(-B pgid) ESRCH, kill(-1) and kill(0)
    reach only A (`proc::send_group`, filter `e.cell == me.cell`).
  - wait4(B pid) ECHILD (`proc::wait`: not a child).
  - getpgid/getsid(B pid) ESRCH, setpgid(B pid) ESRCH (`proc::process`).
  - prlimit64(B pid) ESRCH (own process only), sched_getaffinity(B pid)
    ESRCH (`proc::uids_of`).
  - ENOSYS today: rt_sigqueueinfo, rt_tgsigqueueinfo, pidfd_open, waitid,
    sched_setaffinity, getpriority, setpriority, ptrace,
    process_vm_readv, process_vm_writev, kcmp.
  - kill(p, 0) for every pid up to the highest allocated finds only A's.
  - B reports no signal arrived.
- [x] **2. proc_and_sys_show_only_their_cell**: /proc/B ENOENT
  (`procfs::lookup`: only `me`), listing, self links, global files
  recorded. (66 checks)
- [ ] **3. file_systems_are_scoped_to_their_root** (BLOCKED, see notes): `..` at the root,
  symlinks into B's paths ENOENT, created files invisible both ways, link
  and rename stay in A, B's ptys ENOENT in A (`Vfs::ptys` per root).
- [x] **4. shared_cache_pages_never_carry_writes_between_cells** (27 checks):
  MAP_PRIVATE store, copy-up, read() into a private mapping, EFAULT into
  PROT_READ, futex wake at B's offset wakes 0, private root not evicted
  and charged to its cell.
- [x] **5. networks_are_scoped_to_their_cell** (28 checks; the uplink
  part needs `cell_access_uplink` and the host client in
  tests/cell_access.rs): bind B's address
  EADDRNOTAVAIL, cross-cell TCP allowed (ADR-0010) with A's source
  address, loopback per cell ECONNREFUSED, uplink refuses an unpublished
  port, Unix path ENOENT, abstract ECONNREFUSED, SO_PEERCRED,
  SCM_RIGHTS stays in A.
- [x] **6. other_kernel_state_is_per_cell** (18 checks): SysV IPC (ENOSYS today),
  sethostname (ENOSYS today) and B's uname, io_uring ops on B's names.
- [ ] **7. uid_0_in_a_cell_has_no_authority_outside_it**: mount/umount2
  EPERM, mknod/reboot/clock_settime/settimeofday/adjtimex (ENOSYS today),
  chown/chmod of B's paths ENOENT, signals ESRCH.
- [ ] **8. resource_limits_are_per_cell**: A at its memory limit and
  unable to fork; B allocates and forks.
- [ ] **9. cells_clean_up_after_themselves**: B alive and correct after
  each section; memory returned for every run.
- [ ] **Scoping removal** (sections 1, 2, 3, futex in 4): each edit, the
  failure seen, the restore checked with `git diff` (never committed).
- [ ] **Review, report, AGENTS.md, push.**

## Notes as they come up

- 2026-11-15: section 3 is **blocked**. A safety classifier stopped the
  session while it was writing the section 3 script, so it was not written.
  Sections 1-2 and 4-9 go ahead without it, and section 3 waits for the
  owner to decide how to proceed.
- pids are global numbers filtered by cell (`proc.rs` header), not a
  per-cell pid space with init as 1 as ADR-0002 §3 says: an ADR conflict
  for the report.
- procfs gaps seen in section 2 (not cell scoping): no `/proc/<pid>/root`
  or `mem`; a link in the middle of a path (`/proc/self/cwd/x`) is not
  followed; fd links of files read `anon_inode:[file]`.
- Global files: `/proc/loadavg`'s last field and `/proc/stat`'s
  `processes` are the global last pid (`proc::census` returns
  `NEXT_PID - 1`), so A sees how many processes every cell has started.
  meminfo shows A's account (65536 kB = its 16384 pages). cpuinfo,
  `/sys` cpu lists, uptime and version are host-wide, the same for every
  cell. mounts and hostname are fixed strings.
- Section 4 copies up `/usr/bin/dash` in A's root, so later A scripts
  must not run `/bin/sh` (perl's `system`).
- Section 5: ADR-0010 has no cell-to-cell deny policy, so the denied case
  is loopback (127.0.0.1 is per cell: ECONNREFUSED). A has no raw or
  packet sockets (ESOCKTNOSUPPORT, EAFNOSUPPORT), so the switch's
  anti-spoofing cannot be reached from the Linux ABI. B's reported peer
  address shows the switch delivered A's real address. A may bind B's
  abstract names in its own namespace (they are per cell).
