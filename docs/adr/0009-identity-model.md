# ADR-0009: Identity inside a cell (uids, gids, uid 0, enforcement)

Status: Accepted (2026-11-15)

## Context

Debian's userland expects Unix identity to work:
- dpkg and apt drop privileges (`_apt` sandbox user, `setresuid`/`setgroups`);
- maintainer scripts `chown` files to system users and groups;
- `/etc/shadow` is `root:shadow 0640`;
- programs check `access`, `geteuid` and supplementary groups.

Until now every process was uid 0, ownership was recorded but never checked, and the image
format carried no owners at all.

ADR-0002 §3 settles the frame: a cell owns its UID/GID map and credential state, there is no
host superuser above cells, and Linux capabilities are emulated and gate only the cell's own
objects. This ADR makes that concrete. It decides:
- what a uid is;
- what uid 0 may do;
- which checks the kernel enforces, and where;
- how ownership reaches the root image and shared volumes.

## Decision

### 1. Identities are cell-local numbers

- A cell's uids and gids are plain 32-bit numbers, meaningful only inside that cell. There is
  no global uid: two cells' uid 1000 are unrelated, and no syscall can name another cell's
  processes or files, so they never meet. Nothing is mapped at the kernel boundary for a
  cell's root image or upper layer: the ids on those files are the cell's ids.
- Where storage is shared between cells (ext4 volumes, ADR-0006), the volume capability
  carries an **id map**, like an idmapped mount: a range `[inside, inside + n)` maps to
  `[outside, outside + n)` on disk.
  - Ids outside the map read as the overflow id 65534 and cannot be written.
  - The cell's view of the volume is mapped through it, so a volume shared read-write by two
    cells with different maps cannot be used by either to forge the other's ownership.
  - This lands with volumes (milestone 5). Roots are per cell and need no map.

### 2. Credentials

- Each process holds Linux's credential set:
  - real, effective, saved and filesystem uid;
  - the same four gids;
  - supplementary groups (up to `NGROUPS_MAX` = 65536);
  - effective, permitted and inheritable capability sets.
- Credentials are per process. Linux keeps them per thread, but glibc and musl make them
  per process (`setxid` broadcasts the change to every thread), so per-process storage gives
  the same results for every program that does not issue raw per-thread set*id syscalls.
  That case is recorded as partial.
- `fork` copies credentials. `execve` applies the usual transitions: saved ids become the
  effective ids, and capabilities are recomputed from the uid (§3). **No setuid or setgid
  executables:** the S_ISUID and S_ISGID bits are kept on files but ignored at exec, so
  privilege inside a cell only ever goes down.
- The set*id calls follow POSIX and Linux exactly: `setuid`, `setgid`, `setreuid`,
  `setregid`, `setresuid`, `setresgid`, `setfsuid`, `setfsgid`, `setgroups`, `getgroups`,
  and the `get*` family. Changing to an id you do not already hold needs `CAP_SETUID` /
  `CAP_SETGID` (in practice, being uid 0). Giving up uid 0 clears the capability sets as
  Linux does (no `SECBIT_KEEP_CAPS` yet).

### 3. What uid 0 means in a cell

- uid 0's capabilities are bounded by the **cell bounding set**, roughly Docker's default.
  These are the capabilities whose effect stays inside the cell's own objects:

  > `CHOWN`, `DAC_OVERRIDE`, `DAC_READ_SEARCH`, `FOWNER`, `FSETID`, `KILL`, `SETGID`,
  > `SETUID`, `SETPCAP`, `NET_BIND_SERVICE`, `SYS_CHROOT`, `MKNOD`, `AUDIT_WRITE`, `SETFCAP`.

- A process whose effective uid is 0 holds all of them; any other uid holds none.
- Everything outside the set is never held by anyone in a cell, uid 0 included:
  - `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_TIME`, `SYS_BOOT`, `NET_ADMIN`;
  - `SYS_PTRACE` across processes the caller could not otherwise signal;
  - `IPC_LOCK` beyond the account.
- The calls those capabilities would unlock fail with EPERM. `mount`, `settimeofday`,
  `reboot` and module loading are already EPERM or absent.
- Later, a cell spec may add a few of them (`NET_ADMIN` on the cell's own stack,
  `SYS_ADMIN` for `mount` of volumes it holds, as ADR-0002 §3 describes) when those objects
  exist. A bit outside the bounding set can never be acquired: it is not a check that can be
  bypassed, because nothing grants it.
- **uid 0 has no authority outside the cell.** Memory, devices, network and other cells are
  reached only through capabilities the cell holds (ADR-0002), and neither a uid nor a Linux
  capability ever names them. So uid 0 in a cell is contained by construction, not by a
  mapping to an unprivileged host uid.

### 4. Enforcement

The kernel checks discretionary access as Linux does, with the filesystem uid/gid and the
capability set:

- **Permission bits:**
  - owner, then group (primary or supplementary), then other;
  - `CAP_DAC_OVERRIDE` bypasses read/write, and execute when any execute bit is set;
  - `CAP_DAC_READ_SEARCH` bypasses read on files and search and read on directories.
- **Where it is checked:**
  - every path component needs search (x) on its directory;
  - `open` needs read and/or write as requested, and `O_TRUNC` needs write;
  - `execve` needs x on a regular file;
  - `access`/`faccessat` check with the real ids (`AT_EACCESS`: effective);
  - creating, unlinking or renaming in a directory needs w and x on it, and the sticky bit
    restricts unlink and rename to the file's or directory's owner (or `CAP_FOWNER`).
- **Metadata changes:**
  - `chmod` and `utimensat` with explicit times need ownership or `CAP_FOWNER`;
  - `chown` of the uid needs `CAP_CHOWN`; the owner may change the gid to a group they are
    in;
  - a write or `chown` by a process without `CAP_FSETID` clears S_ISUID and S_ISGID.
- **Signals:** `kill` needs the sender's real or effective uid to match the target's real or
  saved uid, or `CAP_KILL`, within the cell (signals never cross cells; ADR-0002).

### 5. Ownership in images

- Image format version 3 widens a node from 48 to 64 bytes, adding uid, gid and mtime.
- The control plane's converter (xtask's tar import today) takes them from the layer's tar
  headers.
- Lower files then report the owners and times the image was built with, and a cell's root
  starts with Debian's real ownership (`root:shadow` on `/etc/shadow`, `_apt` on
  `/var/cache/apt/archives/partial`).

## Alternatives considered

- **Every process uid 0, no checks (the status quo):** dpkg and apt run, but their privilege
  drops are fake. A service that drops to `nobody` would still be able to read
  `/etc/shadow`. Rejected: containers rely on in-container users for defense in depth.
- **Mapping a cell's uid 0 to an unprivileged host uid (Linux user namespaces):** solves a
  problem Ichor does not have, since nothing outside a cell is reachable by uid. Kept only
  for shared volumes (§1), where ids do leave the cell.
- **Per-thread credentials:** exact Linux semantics, but every check would have to read the
  current thread's credentials, and libc makes them per process anyway. Revisit if a real
  workload issues raw per-thread set*id syscalls.

## Consequences

- dpkg's and apt's privilege drops, and services running as non-root users, behave as on
  Linux, including the failures they expect (`EACCES`, `EPERM`).
- Tests run as several uids and check that DAC is denied and allowed.
- `getuid` & co. stop being partial. The partial entries become: per-process credentials,
  no setuid executables, no file capabilities, and no `SECBIT_*`.
- Image format v3 grows the metadata by a third (16 more bytes per node).
