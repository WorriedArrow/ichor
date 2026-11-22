//! The Linux x86-64 syscall personality (ADR-0002 §5): dispatch, and the
//! calls that have no module of their own (the root's files are in [`fs`],
//! sockets in [`socket`] and [`unix`], signals in [`crate::signal`], ...).
//! The number is in `rax`, arguments in `rdi, rsi, rdx, r10, r8, r9`, and
//! the result in `rax`; on error `rax` is `-errno`.
//!
//! User memory is only ever copied (`VmSpace::copy_{from,to}_user`), never
//! borrowed. Coverage is tracked in `docs/linux-abi.md`.

pub(crate) mod exec;
mod fs;
pub(crate) mod inotify;
mod misc;
pub(crate) mod netlink;
pub(crate) mod pidfd;
pub(crate) mod shm;
pub(crate) mod socket;
mod splice;
pub(crate) mod timerfd;
pub(crate) mod unix;
pub(crate) mod uring;

use core::time::Duration;

use crate::process::{Fd, LinuxProcess};
use crate::umem;
use crate::{proc, signal};
use fs::AT_FDCWD;

/// Linux x86-64 syscall numbers implemented so far. `cargo xtask
/// linux-abi-table` generates `docs/linux-abi.md` from this table: a
/// trailing `// partial: ...` or `// stub: ...` sets an entry's status.
/// `cargo xtask lint` checks that every entry has a dispatch arm and that
/// an arm answering with a constant success (`=> Ok(0)`) is not listed as
/// implemented.
mod nr {
    pub(super) const READ: u64 = 0; // partial: files and console (stdin is EOF)
    pub(super) const WRITE: u64 = 1;
    pub(super) const OPEN: u64 = 2;
    pub(super) const CLOSE: u64 = 3;
    pub(super) const STAT: u64 = 4;
    pub(super) const FSTAT: u64 = 5;
    pub(super) const LSTAT: u64 = 6;
    pub(super) const POLL: u64 = 7;
    pub(super) const LSEEK: u64 = 8;
    pub(super) const MMAP: u64 = 9; // partial: a shared file mapping does not see later writes to an image page it has touched, or to a page truncated away; touching past the end of the file is SIGSEGV, not SIGBUS
    pub(super) const MPROTECT: u64 = 10;
    pub(super) const MUNMAP: u64 = 11;
    pub(super) const BRK: u64 = 12;
    pub(super) const RT_SIGACTION: u64 = 13;
    pub(super) const RT_SIGPROCMASK: u64 = 14;
    pub(super) const RT_SIGRETURN: u64 = 15;
    pub(super) const IOCTL: u64 = 16; // partial: termios, window size, job control and ptmx ioctls on ptys (the console is not a tty); FIONBIO, FIOCLEX/FIONCLEX; FIOASYNC on AF_UNIX sockets
    pub(super) const PREAD64: u64 = 17;
    pub(super) const PWRITE64: u64 = 18;
    pub(super) const READV: u64 = 19;
    pub(super) const WRITEV: u64 = 20;
    pub(super) const ACCESS: u64 = 21;
    pub(super) const PIPE: u64 = 22;
    pub(super) const SELECT: u64 = 23;
    pub(super) const SCHED_YIELD: u64 = 24;
    pub(super) const MREMAP: u64 = 25; // partial: no MREMAP_DONTUNMAP; old_len 0 is EINVAL
    pub(super) const MSYNC: u64 = 26;
    pub(super) const MADVISE: u64 = 28; // partial: DONTNEED on the loaded image's own segments zero-fills
    pub(super) const PAUSE: u64 = 34;
    pub(super) const NANOSLEEP: u64 = 35;
    pub(super) const GETITIMER: u64 = 36; // partial: ITIMER_PROF counts user time only
    pub(super) const ALARM: u64 = 37;
    pub(super) const SETITIMER: u64 = 38; // partial: ITIMER_PROF counts user time only
    pub(super) const DUP: u64 = 32;
    pub(super) const DUP2: u64 = 33;
    pub(super) const GETPID: u64 = 39;
    pub(super) const SENDFILE: u64 = 40;
    pub(super) const SOCKET: u64 = 41; // partial: AF_INET (TCP, UDP) and AF_UNIX (stream, dgram, seqpacket); AF_NETLINK (NETLINK_ROUTE reads); no AF_INET6
    pub(super) const CONNECT: u64 = 42; // partial: a connected UDP socket sees no ICMP errors from beyond the uplink
    pub(super) const ACCEPT: u64 = 43;
    pub(super) const SENDTO: u64 = 44; // partial: no out-of-band data
    pub(super) const RECVFROM: u64 = 45; // partial: no out-of-band data
    pub(super) const SENDMSG: u64 = 46; // partial: control messages (SCM_RIGHTS, SCM_CREDENTIALS) on AF_UNIX only
    pub(super) const RECVMSG: u64 = 47; // partial: control messages on AF_UNIX only; MSG_WAITALL on TCP only
    pub(super) const SHUTDOWN: u64 = 48;
    pub(super) const BIND: u64 = 49; // partial: the cell's own IPv4 addresses (loopback, its switch address, INADDR_ANY)
    pub(super) const LISTEN: u64 = 50;
    pub(super) const GETSOCKNAME: u64 = 51;
    pub(super) const GETPEERNAME: u64 = 52;
    pub(super) const SOCKETPAIR: u64 = 53;
    pub(super) const SETSOCKOPT: u64 = 54; // partial: SO_REUSEADDR, SO_REUSEPORT, SO_PASSCRED, SO_RCVTIMEO, SO_SNDTIMEO and SO_LINGER with no time act; other known options are recorded only
    pub(super) const GETSOCKOPT: u64 = 55; // partial: SO_ERROR, SO_TYPE, SO_ACCEPTCONN, SO_REUSEADDR, SO_PEERCRED, SO_PASSCRED; others echo what was set
    pub(super) const CLONE: u64 = 56; // partial: fork, vfork-style and thread clones
    pub(super) const FORK: u64 = 57;
    pub(super) const VFORK: u64 = 58; // partial: the child gets a copy-on-write copy, not the parent's memory
    pub(super) const EXECVE: u64 = 59; // static and PIE ELF, PT_INTERP, #! scripts
    pub(super) const EXIT: u64 = 60;
    pub(super) const WAIT4: u64 = 61; // partial: rusage is all zero (no accounting yet)
    pub(super) const KILL: u64 = 62;
    pub(super) const UNAME: u64 = 63;
    pub(super) const FCNTL: u64 = 72; // partial: F_SETOWN/F_GETOWN and O_ASYNC on AF_UNIX sockets only; no F_*SIG/leases/seals
    pub(super) const FLOCK: u64 = 73;
    pub(super) const FSYNC: u64 = 74; // partial: the upper layer is memory
    pub(super) const FDATASYNC: u64 = 75; // partial: the upper layer is memory
    pub(super) const TRUNCATE: u64 = 76;
    pub(super) const FTRUNCATE: u64 = 77;
    pub(super) const GETCWD: u64 = 79;
    pub(super) const CHDIR: u64 = 80;
    pub(super) const FCHDIR: u64 = 81;
    pub(super) const RENAME: u64 = 82;
    pub(super) const MKDIR: u64 = 83;
    pub(super) const RMDIR: u64 = 84;
    pub(super) const CREAT: u64 = 85;
    pub(super) const LINK: u64 = 86;
    pub(super) const UNLINK: u64 = 87;
    pub(super) const SYMLINK: u64 = 88;
    pub(super) const READLINK: u64 = 89;
    pub(super) const CHMOD: u64 = 90;
    pub(super) const FCHMOD: u64 = 91;
    pub(super) const CHOWN: u64 = 92;
    pub(super) const FCHOWN: u64 = 93;
    pub(super) const LCHOWN: u64 = 94;
    pub(super) const UMASK: u64 = 95;
    pub(super) const GETRUSAGE: u64 = 98; // partial: user CPU time only (system time and children are zero); maxrss is the current rss
    pub(super) const SYSINFO: u64 = 99; // partial: the cell's memory; no load averages or swap
    pub(super) const TIMES: u64 = 100; // partial: user CPU time only (system and children's times are zero)
    pub(super) const GETTIMEOFDAY: u64 = 96; // firmware clock at boot plus monotonic time (no NTP)
    pub(super) const GETRLIMIT: u64 = 97;
    pub(super) const SETRLIMIT: u64 = 160; // partial: NOFILE and STACK enforced, others stored
    pub(super) const GETUID: u64 = 102;
    pub(super) const GETGID: u64 = 104;
    pub(super) const SETUID: u64 = 105; // partial: per-process credentials (libc's semantics)
    pub(super) const SETGID: u64 = 106; // partial: per-process credentials (libc's semantics)
    pub(super) const GETEUID: u64 = 107;
    pub(super) const GETEGID: u64 = 108;
    pub(super) const SETREUID: u64 = 113; // partial: per-process credentials (libc's semantics)
    pub(super) const SETREGID: u64 = 114; // partial: per-process credentials (libc's semantics)
    pub(super) const GETGROUPS: u64 = 115;
    pub(super) const SETGROUPS: u64 = 116; // partial: per-process credentials (libc's semantics)
    pub(super) const SETRESUID: u64 = 117; // partial: per-process credentials (libc's semantics)
    pub(super) const GETRESUID: u64 = 118;
    pub(super) const SETRESGID: u64 = 119; // partial: per-process credentials (libc's semantics)
    pub(super) const GETRESGID: u64 = 120;
    pub(super) const SETFSUID: u64 = 122;
    pub(super) const SETFSGID: u64 = 123;
    pub(super) const SETPGID: u64 = 109;
    pub(super) const GETPPID: u64 = 110;
    pub(super) const GETPGRP: u64 = 111;
    pub(super) const SETSID: u64 = 112; // partial: no controlling terminals
    pub(super) const GETPGID: u64 = 121;
    pub(super) const GETSID: u64 = 124;
    pub(super) const RT_SIGSUSPEND: u64 = 130;
    pub(super) const SIGALTSTACK: u64 = 131;
    pub(super) const MOUNT: u64 = 165; // partial: always EPERM (cells cannot mount)
    pub(super) const UMOUNT2: u64 = 166; // partial: always EPERM (cells cannot mount)
    pub(super) const STATFS: u64 = 137;
    pub(super) const FSTATFS: u64 = 138;
    pub(super) const PRCTL: u64 = 157; // partial: NAME (per process), CAPBSET_READ, PDEATHSIG, KEEPCAPS, DUMPABLE, NO_NEW_PRIVS
    pub(super) const ARCH_PRCTL: u64 = 158; // partial: ARCH_SET_FS only
    pub(super) const GETTID: u64 = 186;
    pub(super) const TIME: u64 = 201; // firmware clock at boot plus monotonic time (no NTP)
    pub(super) const TKILL: u64 = 200;
    pub(super) const SCHED_GETAFFINITY: u64 = 204; // partial: the mask sched_setaffinity recorded
    pub(super) const SCHED_SETAFFINITY: u64 = 203; // partial: the caller's process only; recorded, not applied by the scheduler
    pub(super) const SCHED_GET_PRIORITY_MAX: u64 = 146;
    pub(super) const SCHED_GET_PRIORITY_MIN: u64 = 147;
    pub(super) const SCHED_RR_GET_INTERVAL: u64 = 148; // partial: always Linux's 100 ms slice
    pub(super) const RT_SIGPENDING: u64 = 127;
    pub(super) const EXECVEAT: u64 = 322; // partial: an fd's file is found again by name (ENOENT once unlinked); AT_SYMLINK_NOFOLLOW not applied
    pub(super) const WAITID: u64 = 247; // partial: rusage is all zero (no accounting yet)
    pub(super) const PREADV: u64 = 295;
    pub(super) const PWRITEV: u64 = 296;
    pub(super) const PREADV2: u64 = 327; // partial: no RWF_* flags (EOPNOTSUPP)
    pub(super) const PWRITEV2: u64 = 328; // partial: no RWF_* flags (EOPNOTSUPP)
    pub(super) const CLOCK_SETTIME: u64 = 227; // partial: always EPERM (no CAP_SYS_TIME in cells)
    pub(super) const SETTIMEOFDAY: u64 = 164; // partial: always EPERM (no CAP_SYS_TIME in cells)
    pub(super) const FUTEX: u64 = 202; // partial: shared only within shared anonymous memory; no PI, no FUTEX_FD
    pub(super) const EPOLL_CREATE: u64 = 213;
    pub(super) const GETDENTS64: u64 = 217;
    pub(super) const SET_TID_ADDRESS: u64 = 218;
    pub(super) const SET_ROBUST_LIST: u64 = 273;
    pub(super) const GET_ROBUST_LIST: u64 = 274; // partial: the caller's own list only (others are EPERM)
    pub(super) const CLOCK_GETTIME: u64 = 228; // partial: CPU-time clocks count user time only; other processes' CPU clocks are EINVAL
    pub(super) const CLOCK_NANOSLEEP: u64 = 230; // partial: CPU-time clocks are ENOTSUP; an absolute realtime sleep does not follow clock steps
    pub(super) const UTIMES: u64 = 235;
    pub(super) const EXIT_GROUP: u64 = 231;
    pub(super) const EPOLL_WAIT: u64 = 232;
    pub(super) const EPOLL_CTL: u64 = 233;
    pub(super) const TGKILL: u64 = 234;
    pub(super) const OPENAT: u64 = 257;
    pub(super) const MKDIRAT: u64 = 258;
    pub(super) const MKNOD: u64 = 133; // partial: FIFOs, regular files, sockets; device nodes are EPERM (no CAP_MKNOD in cells)
    pub(super) const MKNODAT: u64 = 259; // partial: FIFOs, regular files, sockets; device nodes are EPERM (no CAP_MKNOD in cells)
    pub(super) const FCHOWNAT: u64 = 260;
    pub(super) const NEWFSTATAT: u64 = 262;
    pub(super) const UNLINKAT: u64 = 263;
    pub(super) const LINKAT: u64 = 265;
    pub(super) const FUTIMESAT: u64 = 261;
    pub(super) const RENAMEAT: u64 = 264;
    pub(super) const SYMLINKAT: u64 = 266;
    pub(super) const READLINKAT: u64 = 267;
    pub(super) const FCHMODAT: u64 = 268;
    pub(super) const PSELECT6: u64 = 270;
    pub(super) const PPOLL: u64 = 271;
    pub(super) const FACCESSAT: u64 = 269;
    pub(super) const FACCESSAT2: u64 = 439;
    pub(super) const UTIMENSAT: u64 = 280;
    pub(super) const ACCEPT4: u64 = 288;
    pub(super) const EPOLL_PWAIT: u64 = 281;
    pub(super) const EPOLL_PWAIT2: u64 = 441;
    pub(super) const EVENTFD: u64 = 284;
    pub(super) const EVENTFD2: u64 = 290;
    pub(super) const EPOLL_CREATE1: u64 = 291;
    pub(super) const DUP3: u64 = 292;
    pub(super) const PIPE2: u64 = 293;
    pub(super) const GETPRIORITY: u64 = 140; // partial: PRIO_PROCESS of the caller only; the nice value does not affect scheduling
    pub(super) const SETPRIORITY: u64 = 141; // partial: PRIO_PROCESS of the caller only; the nice value does not affect scheduling
    pub(super) const FADVISE64: u64 = 221; // partial: advice is checked and ignored
    pub(super) const CLOSE_RANGE: u64 = 436; // partial: CLOSE_RANGE_UNSHARE is EINVAL
    pub(super) const CLOCK_GETRES: u64 = 229;
    pub(super) const SETXATTR: u64 = 188; // partial: no extended attributes (ENOTSUP)
    pub(super) const LSETXATTR: u64 = 189; // partial: no extended attributes (ENOTSUP)
    pub(super) const FSETXATTR: u64 = 190; // partial: no extended attributes (ENOTSUP)
    pub(super) const GETXATTR: u64 = 191; // partial: no extended attributes (ENODATA)
    pub(super) const LGETXATTR: u64 = 192; // partial: no extended attributes (ENODATA)
    pub(super) const FGETXATTR: u64 = 193; // partial: no extended attributes (ENODATA)
    pub(super) const LISTXATTR: u64 = 194; // partial: no extended attributes (empty list)
    pub(super) const LLISTXATTR: u64 = 195; // partial: no extended attributes (empty list)
    pub(super) const FLISTXATTR: u64 = 196; // partial: no extended attributes (empty list)
    pub(super) const REMOVEXATTR: u64 = 197; // partial: no extended attributes (ENODATA)
    pub(super) const LREMOVEXATTR: u64 = 198; // partial: no extended attributes (ENODATA)
    pub(super) const FREMOVEXATTR: u64 = 199; // partial: no extended attributes (ENODATA)
    pub(super) const FALLOCATE: u64 = 285; // partial: mode 0 extends the size (nothing is reserved); KEEP_SIZE is a no-op; holes and ranges are EOPNOTSUPP
    pub(super) const SYNC_FILE_RANGE: u64 = 277; // partial: nothing to write back (the upper layer is memory)
    pub(super) const MEMBARRIER: u64 = 324; // partial: CMD_QUERY reports no commands
    pub(super) const MEMFD_CREATE: u64 = 319; // partial: no sealing (F_ADD_SEALS); /proc/self/fd shows anon_inode:[file], not /memfd:NAME
    pub(super) const STATX: u64 = 332;
    pub(super) const PRLIMIT64: u64 = 302; // partial: NOFILE, STACK and FSIZE enforced, others stored
    pub(super) const GETRANDOM: u64 = 318; // ChaCha20 seeded from RDSEED/RDRAND and virtio-rng
    pub(super) const RENAMEAT2: u64 = 316; // partial: RENAME_NOREPLACE only
    pub(super) const MINCORE: u64 = 27;
    pub(super) const CAPGET: u64 = 125; // partial: nothing is inheritable; other processes' are the caller's
    pub(super) const CAPSET: u64 = 126; // partial: nothing is inheritable
    pub(super) const PERSONALITY: u64 = 135; // partial: Linux's, with or without ADDR_NO_RANDOMIZE
    pub(super) const SCHED_SETPARAM: u64 = 142; // partial: priority 0 only
    pub(super) const SCHED_GETPARAM: u64 = 143;
    pub(super) const SCHED_SETSCHEDULER: u64 = 144; // partial: SCHED_OTHER only
    pub(super) const SCHED_GETSCHEDULER: u64 = 145;
    pub(super) const MLOCK: u64 = 149; // partial: makes the pages resident; nothing is ever paged out
    pub(super) const MUNLOCK: u64 = 150; // partial: checks the range; nothing is ever paged out
    pub(super) const MLOCKALL: u64 = 151; // partial: nothing is ever paged out; does not make pages resident
    pub(super) const MUNLOCKALL: u64 = 152; // partial: nothing is ever paged out
    pub(super) const SYNC: u64 = 162; // partial: the upper layer is memory
    pub(super) const SETHOSTNAME: u64 = 170; // partial: always EPERM (no CAP_SYS_ADMIN in cells)
    pub(super) const SETDOMAINNAME: u64 = 171; // partial: always EPERM (no CAP_SYS_ADMIN in cells)
    pub(super) const READAHEAD: u64 = 187; // partial: advice, checked and ignored
    pub(super) const UNSHARE: u64 = 272; // partial: namespaces are EPERM (no CAP_SYS_ADMIN in cells)
    pub(super) const SYNCFS: u64 = 306; // partial: the upper layer is memory
    pub(super) const SETNS: u64 = 308; // partial: always EPERM (no CAP_SYS_ADMIN in cells)
    pub(super) const GETCPU: u64 = 309;
    pub(super) const MLOCK2: u64 = 325; // partial: as mlock
    pub(super) const RSEQ: u64 = 334; // partial: always ENOSYS (libcs go without)
    pub(super) const FCHMODAT2: u64 = 452;
    pub(super) const TIMERFD_CREATE: u64 = 283;
    pub(super) const TIMERFD_SETTIME: u64 = 286;
    pub(super) const TIMERFD_GETTIME: u64 = 287;
    pub(super) const SIGNALFD: u64 = 282; // partial: takes the signals of the process that made it
    pub(super) const SIGNALFD4: u64 = 289; // partial: takes the signals of the process that made it
    pub(super) const INOTIFY_INIT: u64 = 253;
    pub(super) const INOTIFY_ADD_WATCH: u64 = 254; // partial: a file with several names reports to one of its directories
    pub(super) const INOTIFY_RM_WATCH: u64 = 255;
    pub(super) const INOTIFY_INIT1: u64 = 294;
    pub(super) const SHMGET: u64 = 29; // partial: no huge pages
    pub(super) const SHMAT: u64 = 30; // partial: no SHM_REMAP
    pub(super) const SHMCTL: u64 = 31; // partial: STAT, SET, RMID and INFO
    pub(super) const SHMDT: u64 = 67;
    pub(super) const TIMER_CREATE: u64 = 222; // partial: CPU-time clocks count user time only; no alarm clocks or other processes' clocks
    pub(super) const TIMER_SETTIME: u64 = 223;
    pub(super) const TIMER_GETTIME: u64 = 224;
    pub(super) const TIMER_GETOVERRUN: u64 = 225;
    pub(super) const TIMER_DELETE: u64 = 226;
    pub(super) const RT_SIGTIMEDWAIT: u64 = 128;
    pub(super) const RT_SIGQUEUEINFO: u64 = 129;
    pub(super) const RT_TGSIGQUEUEINFO: u64 = 297;
    pub(super) const PIDFD_SEND_SIGNAL: u64 = 424; // partial: no flags
    pub(super) const PIDFD_OPEN: u64 = 434; // partial: processes only (no PIDFD_THREAD)
    pub(super) const CLONE3: u64 = 435; // partial: as clone; no CLONE_CLEAR_SIGHAND, CLONE_INTO_CGROUP or set_tid
    pub(super) const SPLICE: u64 = 275;
    pub(super) const TEE: u64 = 276;
    pub(super) const VMSPLICE: u64 = 278; // partial: copies (SPLICE_F_GIFT is accepted and ignored)
    pub(super) const COPY_FILE_RANGE: u64 = 326;
    pub(super) const SENDMMSG: u64 = 307; // partial: as sendmsg
    pub(super) const RECVMMSG: u64 = 299; // partial: as recvmsg
    pub(super) const IO_URING_SETUP: u64 = 425; // partial: no SQPOLL/IOPOLL rings
    pub(super) const IO_URING_ENTER: u64 = 426; // partial: the EXT_ARG signal mask is not applied; the worker completes armed pipe and socket operations but CONNECT runs on the submitter (it may block it); a forked child's submissions run on the parent's worker
    pub(super) const IO_URING_REGISTER: u64 = 427; // partial: probe and eventfd only (no registered files or buffers)
}

const EPERM: i64 = 1;
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const ENODEV: i64 = 19;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOTTY: i64 = 25;
const ENOSYS: i64 = 38;

/// `trace_errors` on the command line: log every Linux syscall that fails.
pub(crate) static TRACE_ERRORS: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// `trace_pid=N`: log every Linux syscall of pid N, and its result.
pub(crate) static TRACE_PID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// What the kernel should do after a Linux syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Keep running the process.
    Continue,
    /// The process asked to exit with this status.
    Exit(i32),
}

/// Dispatches one Linux syscall, writing the result into `ctx.rax`.
pub(crate) fn dispatch(p: &mut LinuxProcess, ctx: &mut frame::user::UserContext) -> Outcome {
    let (nr, a) = ctx.syscall_args();
    // A C `int` argument: only the low 32 bits are defined (glibc passes
    // them zero-extended, musl sign-extended), so read them as Linux does.
    let i = |v: u64| i64::from(v as u32 as i32);
    let result: Result<u64, i64> = match nr {
        // Files and paths.
        nr::READ => fs::read(p, a[0], a[1], a[2] as usize),
        nr::WRITE => fs::write(p, a[0], a[1], a[2] as usize),
        nr::PREAD64 => fs::pread(p, a[0], a[1], a[2] as usize, a[3]),
        nr::PWRITE64 => fs::pwrite(p, a[0], a[1], a[2] as usize, a[3]),
        nr::READV => fs::vector(p, a[0], a[1], a[2] as usize, false),
        nr::WRITEV => fs::vector(p, a[0], a[1], a[2] as usize, true),
        nr::OPEN => fs::open(p, AT_FDCWD, a[0], a[1], a[2]),
        nr::OPENAT => fs::open(p, i(a[0]), a[1], a[2], a[3]),
        nr::CREAT => fs::open(p, AT_FDCWD, a[0], 0o1101, a[1]), // O_CREAT|O_TRUNC|O_WRONLY
        nr::CLOSE => {
            if p.close(a[0]) {
                Ok(0)
            } else {
                Err(EBADF)
            }
        }
        nr::STAT => fs::stat(p, a[0], a[1], true),
        nr::LSTAT => fs::stat(p, a[0], a[1], false),
        nr::NEWFSTATAT => fs::fstatat(p, i(a[0]), a[1], a[2], a[3]),
        nr::STATX => fs::statx(p, i(a[0]), a[1], a[2], a[4]),
        nr::FSTAT => fs::fstat(p, a[0], a[1]),
        nr::LSEEK => fs::lseek(p, a[0], a[1] as i64, a[2]), // off_t: 64 bits
        nr::ACCESS => fs::access(p, AT_FDCWD, a[0], a[1], 0),
        nr::FACCESSAT => fs::access(p, i(a[0]), a[1], a[2], 0),
        nr::FACCESSAT2 => fs::access(p, i(a[0]), a[1], a[2], a[3]),
        nr::TRUNCATE => fs::truncate(p, a[0], a[1]),
        nr::FTRUNCATE => fs::ftruncate(p, a[0], a[1]),
        nr::FSYNC | nr::FDATASYNC => fs::fsync(p, a[0]),
        nr::SENDFILE => fs::sendfile(p, a[0], a[1], a[2], a[3] as usize),
        nr::GETDENTS64 => fs::getdents64(p, a[0], a[1], a[2] as usize),
        nr::MKDIR => fs::mkdir(p, AT_FDCWD, a[0], a[1]),
        nr::MKDIRAT => fs::mkdir(p, i(a[0]), a[1], a[2]),
        nr::MKNOD => fs::mknod(p, AT_FDCWD, a[0], a[1], a[2]),
        nr::MKNODAT => fs::mknod(p, i(a[0]), a[1], a[2], a[3]),
        nr::RMDIR => fs::unlink(p, AT_FDCWD, a[0], 0x200),
        nr::UNLINK => fs::unlink(p, AT_FDCWD, a[0], 0),
        nr::LINK => fs::link(p, AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        nr::LINKAT => fs::link(p, i(a[0]), a[1], i(a[2]), a[3], a[4]),
        nr::UNLINKAT => fs::unlink(p, i(a[0]), a[1], a[2]),
        nr::RENAME => fs::rename(p, AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        nr::RENAMEAT => fs::rename(p, i(a[0]), a[1], i(a[2]), a[3], 0),
        nr::RENAMEAT2 => fs::rename(p, i(a[0]), a[1], i(a[2]), a[3], a[4]),
        nr::IO_URING_SETUP => uring::setup(p, a[0], a[1]),
        nr::IO_URING_ENTER => uring::enter(p, &a),
        nr::IO_URING_REGISTER => uring::register(p, a[0], a[1], a[2], a[3]),
        nr::SYMLINK => fs::symlink(p, a[0], AT_FDCWD, a[1]),
        nr::SYMLINKAT => fs::symlink(p, a[0], i(a[1]), a[2]),
        nr::READLINK => fs::readlink(p, AT_FDCWD, a[0], a[1], a[2]),
        nr::READLINKAT => fs::readlink(p, i(a[0]), a[1], a[2], a[3]),
        nr::CHMOD => fs::chmod(p, AT_FDCWD, a[0], a[1]),
        nr::FCHMODAT => fs::chmod(p, i(a[0]), a[1], a[2]),
        nr::FCHMOD => fs::fchmod(p, a[0], a[1]),
        nr::CHDIR => fs::chdir(p, a[0]),
        nr::FCHDIR => fs::fchdir(p, a[0]),
        nr::GETCWD => fs::getcwd(p, a[0], a[1]),
        nr::UMASK => fs::umask(p, a[0]),
        nr::CHOWN => fs::chown(p, AT_FDCWD, a[0], a[1], a[2], 0),
        nr::LCHOWN => fs::chown(p, AT_FDCWD, a[0], a[1], a[2], 0x100),
        nr::FCHOWN => fs::fchown(p, a[0], a[1], a[2]),
        nr::FCHOWNAT => fs::chown(p, i(a[0]), a[1], a[2], a[3], a[4]),
        nr::UTIMENSAT => fs::utimensat(p, i(a[0]), a[1], a[2], a[3]),
        nr::FUTIMESAT => fs::futimesat(p, i(a[0]), a[1], a[2]),
        nr::UTIMES => fs::futimesat(p, AT_FDCWD, a[0], a[1]),
        nr::MOUNT | nr::UMOUNT2 => Err(EPERM),
        // Sockets (TCP over the cell's stack).
        nr::SOCKET => socket::socket(
            p,
            a[0] & 0xffff_ffff,
            a[1] & 0xffff_ffff,
            a[2] & 0xffff_ffff,
        ),
        nr::BIND => socket::bind(p, a[0], a[1], a[2]),
        nr::LISTEN => socket::listen(p, a[0], a[1]),
        nr::ACCEPT => socket::accept4(p, a[0], a[1], a[2], 0),
        nr::ACCEPT4 => socket::accept4(p, a[0], a[1], a[2], a[3] & 0xffff_ffff),
        nr::CONNECT => socket::connect(p, a[0], a[1], a[2]),
        nr::GETSOCKNAME => socket::getsockname(p, a[0], a[1], a[2]),
        nr::GETPEERNAME => socket::getpeername(p, a[0], a[1], a[2]),
        nr::SOCKETPAIR => socket::socketpair(
            p,
            a[0] & 0xffff_ffff,
            a[1] & 0xffff_ffff,
            a[2] & 0xffff_ffff,
            a[3],
        ),
        nr::SETSOCKOPT => {
            socket::setsockopt(p, a[0], a[1] & 0xffff_ffff, a[2] & 0xffff_ffff, a[3], a[4])
        }
        nr::GETSOCKOPT => {
            socket::getsockopt(p, a[0], a[1] & 0xffff_ffff, a[2] & 0xffff_ffff, a[3], a[4])
        }
        nr::SENDTO => socket::sendto(p, &a),
        nr::RECVFROM => socket::recvfrom(p, &a),
        nr::SENDMSG => socket::sendmsg(p, a[0], a[1], a[2] & 0xffff_ffff),
        nr::RECVMSG => socket::recvmsg(p, a[0], a[1], a[2] & 0xffff_ffff),
        nr::SENDMMSG => socket::sendmmsg(p, a[0], a[1], a[2] & 0xffff_ffff, a[3] & 0xffff_ffff),
        nr::RECVMMSG => socket::recvmmsg(p, &a),
        nr::SPLICE => splice::splice(p, &a),
        nr::TEE => splice::tee(p, a[0], a[1], a[2], a[3] & 0xffff_ffff),
        nr::VMSPLICE => splice::vmsplice(p, a[0], a[1], a[2] as usize, a[3] & 0xffff_ffff),
        nr::COPY_FILE_RANGE => splice::copy_file_range(p, &a),
        nr::SHUTDOWN => socket::shutdown(p, a[0], a[1] & 0xffff_ffff),
        nr::FLOCK => fs::flock(p, a[0], a[1]),
        nr::STATFS => fs::statfs(p, a[0], a[1]),
        nr::FSTATFS => fs::fstatfs(p, a[0], a[1]),
        nr::GETRANDOM => getrandom(p, a[0], a[1] as usize, a[2]),
        // Readiness.
        nr::POLL => crate::poll::poll(p, a[0], a[1], i(a[2])),
        nr::PPOLL => crate::poll::ppoll(p, &a),
        nr::SELECT => crate::poll::select(p, &a),
        nr::PSELECT6 => crate::poll::pselect6(p, &a),
        nr::EPOLL_CREATE => crate::poll::epoll_create(p, 0),
        nr::EPOLL_CREATE1 => crate::poll::epoll_create(p, a[0]),
        nr::EPOLL_CTL => crate::poll::epoll_ctl(p, a[0], a[1], a[2], a[3]),
        nr::EPOLL_WAIT => crate::poll::epoll_wait(p, a[0], a[1], a[2], i(a[3])),
        nr::EPOLL_PWAIT => crate::poll::epoll_pwait(p, &a),
        nr::EPOLL_PWAIT2 => crate::poll::epoll_pwait2(p, &a),
        nr::EVENTFD => crate::poll::eventfd(p, a[0], 0),
        nr::EVENTFD2 => crate::poll::eventfd(p, a[0], a[1]),
        nr::PIPE => fs::pipe2(p, a[0], 0),
        nr::PIPE2 => fs::pipe2(p, a[0], a[1]),
        // Descriptors.
        nr::DUP => p.dup_from(a[0], 0, false).ok_or(EMFILE),
        nr::DUP2 => p.dup_to(a[0], a[1], false).ok_or(EBADF),
        nr::DUP3 => {
            if a[0] == a[1] {
                Err(EINVAL)
            } else {
                p.dup_to(a[0], a[1], a[2] & fs::O_CLOEXEC != 0).ok_or(EBADF)
            }
        }
        nr::FCNTL => fcntl(p, a[0], a[1], a[2]),
        nr::IOCTL => ioctl(p, a[0], a[1], a[2]),
        // Memory.
        nr::MMAP => mmap(p, &a),
        nr::MPROTECT => p.mm().mprotect(a[0], a[1], a[2]),
        nr::MUNMAP => p.mm().munmap(a[0], a[1]),
        nr::BRK => Ok(p.mm().brk(a[0])),
        nr::MSYNC => p.mm().msync(a[0], a[1], a[2]),
        nr::MADVISE => p.mm().madvise(a[0], a[1], a[2]),
        nr::GETCPU => misc::getcpu(p, a[0], a[1]),
        nr::PERSONALITY => misc::personality(p, a[0]),
        nr::SYNC => Ok(0),
        nr::SYNCFS | nr::READAHEAD => misc::on_file(p, a[0]),
        nr::MINCORE => misc::mincore(p, a[0], a[1], a[2]),
        nr::MLOCK => misc::mlock(p, a[0], a[1], 0),
        nr::MLOCK2 => misc::mlock(p, a[0], a[1], a[2] & 0xffff_ffff),
        nr::MUNLOCK => misc::munlock(p, a[0], a[1]),
        nr::MLOCKALL => misc::mlockall(a[0] & 0xffff_ffff),
        nr::MUNLOCKALL => Ok(0),
        nr::SCHED_GETSCHEDULER => misc::getscheduler(p, a[0]),
        nr::SCHED_SETSCHEDULER => misc::setscheduler(p, a[0], a[1] & 0xffff_ffff, a[2]),
        nr::SCHED_GETPARAM => misc::getparam(p, a[0], a[1]),
        nr::SCHED_SETPARAM => misc::setparam(p, a[0], a[1]),
        nr::CAPGET => misc::capget(p, a[0], a[1]),
        nr::CAPSET => misc::capset(p, a[0], a[1]),
        nr::UNSHARE => misc::unshare(a[0] & 0xffff_ffff),
        // CAP_SYS_ADMIN, outside the cell bounding set.
        nr::SETNS | nr::SETHOSTNAME | nr::SETDOMAINNAME => Err(EPERM),
        nr::FCHMODAT2 => fs::fchmodat2(p, i(a[0]), a[1], a[2], a[3] & 0xffff_ffff),
        // glibc asks every thread and goes without.
        nr::RSEQ => Err(ENOSYS),
        nr::TIMERFD_CREATE => timerfd::create(p, a[0], a[1] & 0xffff_ffff),
        nr::TIMERFD_SETTIME => timerfd::settime(p, a[0], a[1] & 0xffff_ffff, a[2], a[3]),
        nr::TIMERFD_GETTIME => timerfd::gettime(p, a[0], a[1]),
        nr::SIGNALFD => timerfd::signalfd(p, i(a[0]), a[1], a[2], 0),
        nr::SIGNALFD4 => timerfd::signalfd(p, i(a[0]), a[1], a[2], a[3] & 0xffff_ffff),
        nr::INOTIFY_INIT => inotify::init(p, 0),
        nr::INOTIFY_INIT1 => inotify::init(p, a[0] & 0xffff_ffff),
        nr::INOTIFY_ADD_WATCH => inotify::add(p, a[0], a[1], a[2]),
        nr::INOTIFY_RM_WATCH => inotify::remove(p, a[0], a[1]),
        nr::SHMGET => shm::get(p, a[0], a[1], a[2] & 0xffff_ffff),
        nr::SHMAT => shm::attach(p, a[0], a[1], a[2] & 0xffff_ffff),
        nr::SHMDT => shm::detach(p, a[0]),
        nr::SHMCTL => shm::control(p, a[0], a[1], a[2]),
        nr::MREMAP => p.mm().mremap(a[0], a[1], a[2], a[3], a[4]),
        // Identity, time, limits, signals, threads.
        nr::UNAME => uname(p, a[0]),
        nr::CLOCK_GETTIME => clock_gettime(p, a[0], a[1]),
        nr::CLOCK_GETRES => clock_getres(p, a[0], a[1]),
        nr::SETXATTR
        | nr::LSETXATTR
        | nr::FSETXATTR
        | nr::GETXATTR
        | nr::LGETXATTR
        | nr::FGETXATTR
        | nr::LISTXATTR
        | nr::LLISTXATTR
        | nr::FLISTXATTR
        | nr::REMOVEXATTR
        | nr::LREMOVEXATTR
        | nr::FREMOVEXATTR => {
            use fs::Xattr::*;
            // Numbered in threes from 188: path, lpath, fd forms of set,
            // get, list and remove.
            let op = [Set, Get, List, Remove][((nr - nr::SETXATTR) / 3) as usize];
            let form = (nr - nr::SETXATTR) % 3;
            fs::xattr(p, op, a[0], form == 2, form == 0)
        }
        nr::FALLOCATE => fs::fallocate(p, a[0], a[1], a[2], a[3]),
        nr::SYNC_FILE_RANGE => fs::sync_file_range(p, a[0], a[1], a[2], a[3]),
        nr::MEMBARRIER => {
            // MEMBARRIER_CMD_QUERY: no commands are offered (callers fall
            // back to their own fences); any other command is EINVAL.
            if a[0] == 0 { Ok(0) } else { Err(EINVAL) }
        }
        nr::GETTIMEOFDAY => gettimeofday(p, a[0]),
        nr::TIME => {
            let secs = crate::vfs::wall_clock().as_secs();
            if a[0] != 0 && p.copy_to_user(a[0], &secs.to_le_bytes()) != 8 {
                Err(EFAULT)
            } else {
                Ok(secs)
            }
        }
        nr::GETRLIMIT => prlimit(p, 0, a[0], 0, a[1]),
        nr::SETRLIMIT => prlimit(p, 0, a[0], a[1], 0),
        nr::PRLIMIT64 => prlimit(p, a[0], a[1], a[2], a[3]),
        nr::RT_SIGACTION => signal::sigaction(p, a[0], a[1], a[2], a[3]),
        nr::RT_SIGPROCMASK => signal::sigprocmask(p, a[0], a[1], a[2], a[3]),
        nr::RT_SIGRETURN => match signal::sigreturn(p, ctx) {
            // The interrupted context is back, return value included.
            Ok(()) => return Outcome::Continue,
            Err(_) => return Outcome::Exit(-(signal::SIGSEGV as i32)),
        },
        nr::RT_SIGSUSPEND => signal::sigsuspend(p, a[0], a[1]),
        nr::PAUSE => signal::pause(p),
        nr::NANOSLEEP => signal::nanosleep(p, a[0], a[1]),
        nr::GETITIMER => getitimer(p, a[0], a[1]),
        nr::ALARM => alarm(p, a[0]),
        nr::SETITIMER => setitimer(p, a[0], a[1], a[2]),
        nr::TIMER_CREATE => timer_create(p, a[0], a[1], a[2]),
        nr::TIMER_SETTIME => timer_settime(p, a[0], a[1], a[2], a[3]),
        nr::TIMER_GETTIME => timer_gettime(p, a[0], a[1]),
        nr::TIMER_GETOVERRUN => {
            timer_id(a[0]).and_then(|id| crate::itimer::overrun(p, id).map(u64::from))
        }
        nr::TIMER_DELETE => timer_id(a[0]).and_then(|id| crate::itimer::delete(p, id).map(|()| 0)),
        nr::CLOCK_NANOSLEEP => signal::clock_nanosleep(p, a[0], a[1], a[2], a[3]),
        nr::KILL => signal::kill(p, i(a[0]), a[1]),
        nr::TKILL => signal::tkill(p, None, a[0], a[1]),
        nr::TGKILL => signal::tkill(p, Some(a[0]), a[1], a[2]),
        nr::SETPGID => proc::setpgid(&p.group.leader, a[0], a[1]).map(|()| 0),
        nr::GETPGRP => Ok(p.group.leader.group().0),
        nr::GETPGID => proc::group_of(&p.group.leader, a[0]).map(|g| g.0),
        nr::GETSID => proc::group_of(&p.group.leader, a[0]).map(|g| g.1),
        nr::SETSID => proc::setsid(&p.group.leader),
        nr::SIGALTSTACK => signal::sigaltstack(p, ctx, a[0], a[1]),
        nr::FUTEX => crate::futex::futex(p, &a),
        nr::SCHED_YIELD => {
            frame::task::yield_now();
            Ok(0)
        }
        nr::GETPID => Ok(p.group.tgid),
        nr::PRCTL => prctl(p, a[0], a[1], a[2]),
        nr::GETPRIORITY => priority(p, i(a[0]), a[1], None),
        nr::SETPRIORITY => priority(p, i(a[0]), a[1], Some(i(a[2]))),
        nr::MEMFD_CREATE => fs::memfd_create(p, a[0], a[1]),
        nr::FADVISE64 => {
            // POSIX_FADV_NORMAL..=POSIX_FADV_NOREUSE on an open descriptor.
            if p.fd(a[0]).is_none() {
                Err(EBADF)
            } else if a[3] > 5 {
                Err(EINVAL)
            } else {
                Ok(0)
            }
        }
        nr::CLOSE_RANGE => {
            const CLOSE_RANGE_CLOEXEC: u64 = 4;
            let (first, last, flags) = (a[0] as u32, a[1] as u32, a[2]);
            if first > last || flags & !CLOSE_RANGE_CLOEXEC != 0 {
                Err(EINVAL)
            } else {
                p.close_range(
                    u64::from(first),
                    u64::from(last),
                    flags & CLOSE_RANGE_CLOEXEC != 0,
                );
                Ok(0)
            }
        }
        nr::SCHED_GETAFFINITY => sched_getaffinity(p, a[0], a[1], a[2]),
        nr::SCHED_SETAFFINITY => sched_setaffinity(p, a[0], a[1], a[2]),
        nr::SCHED_GET_PRIORITY_MAX => sched_priority_bound(a[0], true),
        nr::SCHED_GET_PRIORITY_MIN => sched_priority_bound(a[0], false),
        nr::SCHED_RR_GET_INTERVAL => sched_rr_get_interval(p, a[0], a[1]),
        nr::RT_SIGPENDING => signal::sigpending(p, a[0], a[1]),
        nr::WAITID => waitid(p, a[0], a[1], a[2], a[3], a[4]),
        nr::PREADV => fs::vector_at(p, a[0], a[1], a[2] as usize, a[3], 0, false),
        nr::PWRITEV => fs::vector_at(p, a[0], a[1], a[2] as usize, a[3], 0, true),
        nr::PREADV2 => fs::vector_at(p, a[0], a[1], a[2] as usize, a[3], a[5], false),
        nr::PWRITEV2 => fs::vector_at(p, a[0], a[1], a[2] as usize, a[3], a[5], true),
        // Setting a clock needs CAP_SYS_TIME, outside the cell bounding set.
        nr::CLOCK_SETTIME | nr::SETTIMEOFDAY => Err(EPERM),
        nr::SYSINFO => sysinfo(p, a[0]),
        nr::GETRUSAGE => getrusage(p, i(a[0]), a[1]),
        nr::TIMES => times(p, a[0]),
        nr::GETTID => Ok(p.entry.pid),
        nr::GETPPID => Ok(p.entry.ppid()),
        nr::GETUID => Ok(u64::from(p.group.creds().ruid)),
        nr::GETEUID => Ok(u64::from(p.group.creds().euid)),
        nr::GETGID => Ok(u64::from(p.group.creds().rgid)),
        nr::GETEGID => Ok(u64::from(p.group.creds().egid)),
        nr::GETRESUID | nr::GETRESGID => getres(p, nr == nr::GETRESUID, [a[0], a[1], a[2]]),
        nr::SETUID => p.group.update_creds(|c| c.setuid(a[0])).map(|()| 0),
        nr::SETGID => p.group.update_creds(|c| c.setgid(a[0])).map(|()| 0),
        nr::SETREUID => p.group.update_creds(|c| c.setreuid(a[0], a[1])).map(|()| 0),
        nr::SETREGID => p.group.update_creds(|c| c.setregid(a[0], a[1])).map(|()| 0),
        nr::SETRESUID => p
            .group
            .update_creds(|c| c.setresuid(a[0], a[1], a[2]))
            .map(|()| 0),
        nr::SETRESGID => p
            .group
            .update_creds(|c| c.setresgid(a[0], a[1], a[2]))
            .map(|()| 0),
        nr::SETFSUID => p.group.update_creds(|c| Ok(u64::from(c.setfsuid(a[0])))),
        nr::SETFSGID => p.group.update_creds(|c| Ok(u64::from(c.setfsgid(a[0])))),
        nr::GETGROUPS => getgroups(p, a[0], a[1]),
        nr::SETGROUPS => setgroups(p, a[0], a[1]),
        // Processes.
        nr::FORK => clone(p, ctx, 17, 0, 0, 0, 0, None), // SIGCHLD
        nr::VFORK => clone(p, ctx, 0x4000 | 0x100 | 17, 0, 0, 0, 0, None), // CLONE_VFORK | CLONE_VM
        nr::CLONE => clone(p, ctx, a[0], a[1], a[2], a[3], a[4], None),
        nr::CLONE3 => clone3(p, ctx, a[0], a[1]),
        nr::PIDFD_OPEN => pidfd::open(p, i(a[0]), a[1]),
        nr::PIDFD_SEND_SIGNAL => pidfd::send_signal(p, a[0], a[1], a[2], a[3]),
        nr::RT_SIGTIMEDWAIT => signal::sigtimedwait(p, a[0], a[1], a[2], a[3]),
        nr::RT_SIGQUEUEINFO => signal::sigqueueinfo(p, a[0], a[1], a[2]),
        nr::RT_TGSIGQUEUEINFO => signal::tgsigqueueinfo(p, a[0], a[1], a[2], a[3]),
        nr::WAIT4 => wait4(p, i(a[0]), a[1], a[2], a[3]),
        nr::EXECVE => match exec::execve(p, ctx, a[0], a[1], a[2]) {
            // The context now starts the new program: no return value.
            Ok(()) => return Outcome::Continue,
            Err(e) => Err(e),
        },
        nr::EXECVEAT => match exec::execveat(p, ctx, i(a[0]), a[1], a[2], a[3], a[4]) {
            Ok(()) => return Outcome::Continue,
            Err(e) => Err(e),
        },
        nr::ARCH_PRCTL => arch_prctl(ctx, a[0], a[1]),
        nr::SET_TID_ADDRESS => {
            p.clear_tid = a[0];
            Ok(p.entry.pid)
        }
        nr::SET_ROBUST_LIST => {
            if a[1] != crate::futex::ROBUST_HEAD_LEN {
                Err(EINVAL)
            } else {
                p.robust_list = a[0];
                Ok(0)
            }
        }
        nr::GET_ROBUST_LIST => {
            // Another thread's list would need ptrace rights; only the
            // caller's (pid 0 or its own tid) is answered.
            if a[0] != 0 && a[0] != p.entry.pid {
                Err(EPERM)
            } else {
                let head = p.robust_list.to_le_bytes();
                let len = crate::futex::ROBUST_HEAD_LEN.to_le_bytes();
                if p.copy_to_user(a[1], &head) != 8 || p.copy_to_user(a[2], &len) != 8 {
                    Err(EFAULT)
                } else {
                    Ok(0)
                }
            }
        }
        nr::EXIT => return Outcome::Exit(a[0] as i32),
        nr::EXIT_GROUP => {
            p.group.begin_exit((a[0] as u32 & 0xff) << 8, &p.entry);
            return Outcome::Exit(a[0] as i32);
        }
        _ => {
            frame::println!(
                "ichor: linux: pid {}: syscall {nr} is not implemented",
                p.entry.pid
            );
            Err(ENOSYS)
        }
    };
    // A path into what is not the root's, where nothing else serves it.
    let result = match result {
        Err(crate::vfs::errno::ELSEWHERE) => Err(2), // ENOENT
        r => r,
    };
    inotify::flush(&p.vfs);
    let traced = TRACE_PID.load(core::sync::atomic::Ordering::Relaxed) == p.entry.pid
        || (TRACE_ERRORS.load(core::sync::atomic::Ordering::Relaxed)
            && result.is_err_and(|e| e < signal::ERESTARTSYS));
    if traced {
        // Name the path argument of path syscalls, so traces are readable.
        let path_arg = match nr {
            nr::OPEN
            | nr::STAT
            | nr::LSTAT
            | nr::ACCESS
            | nr::READLINK
            | nr::EXECVE
            | nr::UNLINK
            | nr::MKDIR
            | nr::RMDIR
            | nr::CHDIR
            | nr::RENAME
            | nr::CHMOD => Some(a[0]),
            nr::OPENAT
            | nr::NEWFSTATAT
            | nr::FACCESSAT
            | nr::READLINKAT
            | nr::UNLINKAT
            | nr::MKDIRAT
            | nr::FACCESSAT2 => Some(a[1]),
            _ => None,
        };
        let path = path_arg
            .and_then(|addr| fs::user_path(p, addr).ok())
            .unwrap_or_default();
        frame::println!(
            "ichor: trace: pid {} syscall {nr}({:#x}, {:#x}, {:#x}) {path:?} = {result:?}",
            p.entry.pid,
            a[0],
            a[1],
            a[2]
        );
    }
    ctx.set_return(match result {
        Ok(v) => v,
        Err(e) => (-e) as u64,
    });
    Outcome::Continue
}

// ---------------------------------------------------------------------------
// Console.
// ---------------------------------------------------------------------------

/// Copies up to `count` bytes from user memory to the console.
fn console_write(p: &mut LinuxProcess, buf: u64, count: usize) -> usize {
    let mut written = 0;
    let mut chunk = [0u8; 256];
    while written < count {
        let want = chunk.len().min(count - written);
        let got = p.copy_from_user(buf + written as u64, &mut chunk[..want]);
        if got == 0 {
            break;
        }
        // The console is byte-oriented: bytes go out as they are.
        frame::console::write_bytes(&chunk[..got]);
        written += got;
    }
    written
}

/// `getrandom(buf, len, flags)`: fills `buf` from the kernel generator
/// (`/dev/urandom`). If boot found too little entropy the generator never
/// becomes seeded, so a caller that did not pass `GRND_INSECURE` gets
/// EAGAIN rather than a wait that could not end.
fn getrandom(p: &mut LinuxProcess, buf: u64, len: usize, flags: u64) -> Result<u64, i64> {
    const GRND_NONBLOCK: u64 = 1;
    const GRND_RANDOM: u64 = 2;
    const GRND_INSECURE: u64 = 4;
    if flags & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0
        || flags & (GRND_RANDOM | GRND_INSECURE) == GRND_RANDOM | GRND_INSECURE
    {
        return Err(EINVAL);
    }
    if !crate::random::seeded() && flags & GRND_INSECURE == 0 {
        return Err(EAGAIN);
    }
    let n = len.min(256 * 1024);
    let mut b = alloc::vec![0u8; n];
    crate::random::fill(&mut b);
    if p.copy_to_user(buf, &b) != n {
        return Err(EFAULT);
    }
    Ok(n as u64)
}

/// Prints kernel-held bytes to the console.
fn console_bytes(b: &[u8]) {
    frame::console::write_bytes(b);
}

pub(crate) fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

/// `ioctl`. The console is a serial byte sink, not a tty (no termios, no
/// window size), so every tty request is `ENOTTY`, as for a pipe. The
/// generic descriptor requests work on everything.
fn ioctl(p: &mut LinuxProcess, fd: u64, request: u64, arg: u64) -> Result<u64, i64> {
    const FIONCLEX: u64 = 0x5450;
    const FIOCLEX: u64 = 0x5451;
    const FIONBIO: u64 = 0x5421;
    const FIONREAD: u64 = 0x541b;
    const FIOASYNC: u64 = 0x5452;
    let desc = p.desc(fd).ok_or(EBADF)?;
    if request == FIOASYNC {
        // O_ASYNC: AF_UNIX sockets only (partial).
        let mut b = [0u8; 4];
        if p.copy_from_user(arg, &mut b) != 4 {
            return Err(EFAULT);
        }
        let st = desc.state();
        let Fd::Object(o) = &*st else {
            return Err(ENOTTY);
        };
        let u = o.obj.unix().ok_or(ENOTTY)?;
        u.set_async(Some(u32::from_le_bytes(b) != 0), None);
        return Ok(0);
    }
    if !matches!(request, FIOCLEX | FIONCLEX | FIONBIO) {
        let obj = match &*desc.state() {
            Fd::Object(o) => Some(o.obj.clone()),
            _ => None,
        };
        if let Some(end) = obj.as_deref().and_then(|o| o.tty()) {
            return crate::pty::ioctl(p, end, request, arg);
        }
    }
    if request == FIONREAD {
        let n = match &*desc.state() {
            Fd::Pipe(e) => e.pipe.buffered(),
            Fd::Object(o) => o.obj.readable().ok_or(ENOTTY)?,
            Fd::File(f) => {
                let s = p.vfs.lock().stat(f.ino)?;
                if s.kind != crate::vfs::Kind::File {
                    return Err(ENOTTY);
                }
                usize::try_from(s.size.saturating_sub(f.offset)).unwrap_or(usize::MAX)
            }
            Fd::Console | Fd::Dev(_) => return Err(ENOTTY),
        };
        let n = u32::try_from(n).unwrap_or(i32::MAX as u32);
        if p.copy_to_user(arg, &n.to_le_bytes()) != 4 {
            return Err(EFAULT);
        }
        return Ok(0);
    }
    let is_socket = matches!(&*desc.state(),
        Fd::Object(o) if o.obj.mode() & 0o170_000 == 0o140_000);
    if is_socket && let Some(r) = netlink::ioctl(p, request, arg) {
        return r;
    }
    match request {
        FIOCLEX | FIONCLEX => {
            p.set_cloexec(fd, request == FIOCLEX);
            Ok(0)
        }
        FIONBIO => {
            let mut b = [0u8; 4];
            if p.copy_from_user(arg, &mut b) != 4 {
                return Err(EFAULT);
            }
            let on = u32::from_le_bytes(b) != 0;
            match &mut *desc.state() {
                Fd::File(of) => {
                    of.flags = if on {
                        of.flags | fs::O_NONBLOCK
                    } else {
                        of.flags & !fs::O_NONBLOCK
                    };
                }
                Fd::Pipe(e) => e.nonblock = on,
                Fd::Object(o) => o.nonblock = on,
                Fd::Console | Fd::Dev(_) => {}
            }
            Ok(0)
        }
        _ => Err(ENOTTY),
    }
}

fn fcntl(p: &mut LinuxProcess, fd: u64, cmd: u64, arg: u64) -> Result<u64, i64> {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETLKW: u64 = 7;
    const F_OFD_GETLK: u64 = 36;
    const F_OFD_SETLK: u64 = 37;
    const F_OFD_SETLKW: u64 = 38;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_SETPIPE_SZ: u64 = 1031;
    const F_GETPIPE_SZ: u64 = 1032;
    const F_SETOWN: u64 = 8;
    const F_GETOWN: u64 = 9;
    const FD_CLOEXEC: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_APPEND: u64 = 0o2000;
    const O_ASYNC: u64 = 0o20000;
    let desc = p.desc(fd).ok_or(EBADF)?;
    match cmd {
        F_DUPFD => p.dup_from(fd, arg, false).ok_or(EMFILE),
        F_DUPFD_CLOEXEC => p.dup_from(fd, arg, true).ok_or(EMFILE),
        F_GETFD => Ok(if p.cloexec(fd).ok_or(EBADF)? {
            FD_CLOEXEC
        } else {
            0
        }),
        F_SETFD => {
            p.set_cloexec(fd, arg & FD_CLOEXEC != 0);
            Ok(0)
        }
        F_GETFL => Ok(match &*desc.state() {
            Fd::Console | Fd::Dev(_) => O_RDWR,
            Fd::File(of) => of.flags,
            Fd::Pipe(e) => {
                let acc = match (e.read, e.write) {
                    (true, true) => O_RDWR,
                    (_, write) => u64::from(write),
                };
                acc | if e.nonblock { fs::O_NONBLOCK } else { 0 }
            }
            Fd::Object(o) => {
                let asy = o.obj.unix().is_some_and(|u| u.is_async());
                O_RDWR | if o.nonblock { fs::O_NONBLOCK } else { 0 } | if asy { O_ASYNC } else { 0 }
            }
        }),
        F_SETFL => {
            // O_APPEND and O_NONBLOCK can change after open, and O_ASYNC on
            // AF_UNIX sockets (Linux also takes O_DIRECT/O_NOATIME, which
            // mean nothing here).
            let nb = arg & fs::O_NONBLOCK != 0;
            match &mut *desc.state() {
                Fd::File(of) => {
                    of.flags = (of.flags & !(O_APPEND | fs::O_NONBLOCK))
                        | (arg & (O_APPEND | fs::O_NONBLOCK));
                }
                Fd::Pipe(e) => e.nonblock = nb,
                Fd::Object(o) => {
                    o.nonblock = nb;
                    if let Some(u) = o.obj.unix() {
                        u.set_async(Some(arg & O_ASYNC != 0), None);
                    }
                }
                Fd::Console | Fd::Dev(_) => {}
            }
            Ok(0)
        }
        // SIGIO ownership: AF_UNIX sockets only (partial).
        F_SETOWN | F_GETOWN => {
            let st = desc.state();
            let Fd::Object(o) = &*st else {
                return Err(EINVAL);
            };
            let u = o.obj.unix().ok_or(EINVAL)?;
            if cmd == F_GETOWN {
                return Ok(u.owner());
            }
            // A process group (negative) is not kept.
            if (arg as i64) < 0 {
                return Err(EINVAL);
            }
            u.set_async(None, Some(arg));
            Ok(0)
        }
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            fs::record_lock(p, &desc, cmd, arg)
        }
        // Pipe capacity: Linux answers EBADF for anything but a pipe.
        F_SETPIPE_SZ | F_GETPIPE_SZ => match &*desc.state() {
            Fd::Pipe(e) if cmd == F_GETPIPE_SZ => Ok(e.pipe.capacity() as u64),
            Fd::Pipe(e) => e.pipe.set_capacity(arg).map(|n| n as u64),
            _ => Err(EBADF),
        },
        _ => Err(EINVAL),
    }
}

// ---------------------------------------------------------------------------
// Memory.
// ---------------------------------------------------------------------------

fn mmap(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let (addr, len, prot, map_flags, fd, offset) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    if map_flags & umem::flags::MAP_ANONYMOUS != 0 {
        return p.mm().mmap(addr, len, prot, map_flags, None);
    }
    match p.fd(fd).ok_or(EBADF)? {
        Fd::File(_) => {}
        Fd::Object(o) if o.obj.uring().is_some() => {
            let obj = o.obj.clone();
            return match obj.uring() {
                Some(ring) => uring::mmap(p, ring, a),
                None => Err(ENODEV),
            };
        }
        _ => return Err(ENODEV),
    }
    let (ino, mode) = match p.fd(fd).ok_or(EBADF)? {
        Fd::File(f) if f.flags & fs::O_PATH != 0 => return Err(EBADF),
        Fd::File(f) => (f.ino, f.flags & fs::O_ACCMODE),
        _ => return Err(ENODEV),
    };
    if p.vfs.lock().stat(ino)?.kind != crate::vfs::Kind::File {
        return Err(ENODEV);
    }
    // Reading through the mapping needs a descriptor that can read; writing
    // the file through it, one that can do both.
    let writable = mode == fs::O_RDWR;
    let shared = map_flags & umem::flags::MAP_SHARED != 0;
    if mode == fs::O_WRONLY || (shared && prot & 2 != 0 && !writable) {
        return Err(EACCES);
    }
    let file = crate::file::VfsFile::open(&p.vfs, ino)?;
    let src = umem::FileSource {
        file: alloc::sync::Arc::new(file),
        offset,
        writable,
    };
    p.mm().mmap(addr, len, prot, map_flags, Some(src))
}

// ---------------------------------------------------------------------------
// Processes.
// ---------------------------------------------------------------------------

/// `fork`, `vfork` and `clone`. Without `CLONE_THREAD` the child is a new
/// process (a copy-on-write copy; `CLONE_VM | CLONE_VFORK`, as `vfork` and
/// `posix_spawn` use, is served the same way, which is correct because the
/// child only execs or exits). With `CLONE_VFORK` the caller waits until
/// the child has exec'd or exited. With `CLONE_THREAD` it is a new thread in the
/// caller's process, on `stack`, with TLS `tls` if `CLONE_SETTLS`.
/// `clone3(args, size)`: `clone` with its arguments in a `clone_args`.
fn clone3(
    p: &mut LinuxProcess,
    ctx: &frame::user::UserContext,
    args: u64,
    size: u64,
) -> Result<u64, i64> {
    /// `CLONE_ARGS_SIZE_VER0` and the size with everything since.
    const MIN: u64 = 64;
    const FULL: usize = 88;
    const E2BIG: i64 = 7;
    /// CLONE_CLEAR_SIGHAND and CLONE_INTO_CGROUP.
    const EXTENDED: u64 = !0xffff_ffff;
    if size < MIN {
        return Err(EINVAL);
    }
    if size > 4096 {
        return Err(E2BIG);
    }
    let mut b = [0u8; 4096];
    let n = size as usize;
    if p.copy_from_user(args, &mut b[..n]) != n {
        return Err(EFAULT);
    }
    if b[FULL..].iter().any(|&x| x != 0) {
        return Err(E2BIG); // a newer caller's, asking for something
    }
    let word = |i: usize| le_u64(&b[i * 8..i * 8 + 8]);
    let [
        flags,
        pidfd,
        child_tid,
        parent_tid,
        exit_signal,
        stack,
        stack_size,
        tls,
        set_tid,
    ] = core::array::from_fn(word);
    if flags & (EXTENDED | 0xff) != 0 || exit_signal > 64 || (stack == 0) != (stack_size == 0) {
        return Err(EINVAL);
    }
    if set_tid != 0 {
        return Err(EPERM); // CAP_CHECKPOINT_RESTORE
    }
    let top = stack.checked_add(stack_size).ok_or(EINVAL)?;
    clone(
        p,
        ctx,
        flags | exit_signal,
        top,
        parent_tid,
        child_tid,
        tls,
        Some(pidfd),
    )
}

/// `clone`, and the rest of the family. `pidfd_at`: where `CLONE_PIDFD`
/// puts the descriptor, if not in `parent_tid`'s place.
#[allow(clippy::too_many_arguments)] // the syscall's own
fn clone(
    p: &mut LinuxProcess,
    ctx: &frame::user::UserContext,
    flags: u64,
    stack: u64,
    parent_tid: u64,
    child_tid: u64,
    tls: u64,
    pidfd_at: Option<u64>,
) -> Result<u64, i64> {
    const CSIGNAL: u64 = 0xff;
    const CLONE_VM: u64 = 0x100;
    const CLONE_FS: u64 = 0x200;
    const CLONE_FILES: u64 = 0x400;
    const CLONE_SIGHAND: u64 = 0x800;
    const CLONE_PIDFD: u64 = 0x1000;
    const CLONE_VFORK: u64 = 0x4000;
    const CLONE_PARENT: u64 = 0x8000;
    const CLONE_THREAD: u64 = 0x1_0000;
    const CLONE_SYSVSEM: u64 = 0x4_0000;
    const CLONE_SETTLS: u64 = 0x8_0000;
    const CLONE_PARENT_SETTID: u64 = 0x10_0000;
    const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
    const CLONE_DETACHED: u64 = 0x40_0000;
    const CLONE_CHILD_SETTID: u64 = 0x100_0000;
    /// NEWTIME, NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET.
    const CLONE_NEW: u64 = 0x7e02_0080;
    let thread = flags & CLONE_THREAD != 0;
    if flags & CLONE_NEW & !CSIGNAL != 0 {
        return Err(EPERM); // a cell makes no namespaces (CAP_SYS_ADMIN)
    }
    let allowed = CSIGNAL
        | CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_PIDFD
        | CLONE_VFORK
        | CLONE_THREAD
        | CLONE_SYSVSEM
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_DETACHED
        | CLONE_CHILD_SETTID;
    if flags & CLONE_PARENT != 0 || flags & !allowed != 0 {
        return Err(ENOSYS);
    }
    if flags & CLONE_PIDFD != 0 && thread {
        return Err(EINVAL);
    }
    if thread {
        // A thread shares memory and signal handlers (Linux requires both).
        let need = CLONE_VM | CLONE_SIGHAND;
        if flags & need != need || stack == 0 {
            return Err(EINVAL);
        }
    } else if flags & (CLONE_VM | CLONE_VFORK) == CLONE_VM
        || flags & (CLONE_SIGHAND | CLONE_FILES | CLONE_FS) != 0
    {
        // Sharing memory or files between processes is not supported.
        return Err(ENOSYS);
    }
    let (mut child, mut cctx) = if thread {
        let mut c = ctx.clone();
        c.set_return(0);
        c.rsp = stack;
        (p.new_thread().ok_or(EAGAIN)?, c)
    } else {
        proc::fork(p, ctx, stack)?
    };
    if flags & CLONE_SETTLS != 0 {
        cctx.fs_base = tls;
    }
    let tid = (child.entry.pid as u32).to_le_bytes();
    // An address that cannot be written is passed over, as on Linux.
    if flags & CLONE_PARENT_SETTID != 0 {
        let _ = p.copy_to_user(parent_tid, &tid);
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        let _ = child.copy_to_user(child_tid, &tid);
    }
    if flags & CLONE_CHILD_CLEARTID != 0 {
        child.clear_tid = child_tid;
    }
    if flags & CLONE_PIDFD != 0 {
        // `clone` puts it where the parent's tid would go.
        let at = pidfd_at.unwrap_or(parent_tid);
        let entry = child.entry.clone();
        if let Err(e) = pidfd::install(p, entry, false, Some(at)) {
            proc::discard(child);
            return Err(e);
        }
    }
    signal::sync(&child);
    let vfork = (flags & CLONE_VFORK != 0 && !thread).then(|| {
        let v = crate::process::Vfork::new(p.entry.clone());
        child.group.set_vfork(v.clone());
        v
    });
    let pid = proc::start(child, cctx)?;
    if let Some(v) = vfork {
        v.wait();
    }
    Ok(pid)
}

fn wait4(
    p: &mut LinuxProcess,
    pid: i64,
    wstatus: u64,
    options: u64,
    rusage: u64,
) -> Result<u64, i64> {
    const WNOHANG: u64 = 1;
    const WUNTRACED: u64 = 2;
    const WCONTINUED: u64 = 8;
    /// `__WNOTHREAD`, `__WALL`, `__WCLONE`: every child is waited for here.
    const KNOWN: u64 = WNOHANG | WUNTRACED | WCONTINUED | 0xe000_0000;
    /// `sizeof(struct rusage)` on x86-64.
    const RUSAGE_SIZE: usize = 144;
    let options = options & 0xffff_ffff;
    if options & !KNOWN != 0 {
        return Err(EINVAL);
    }
    let want = proc::Wanted {
        exited: true,
        stopped: options & WUNTRACED != 0,
        continued: options & WCONTINUED != 0,
        nohang: options & WNOHANG != 0,
        keep: false,
    };
    match proc::wait(&p.group.leader, &p.entry, pid, want)? {
        None => Ok(0),
        Some((cpid, status, _)) => {
            if wstatus != 0 && p.copy_to_user(wstatus, &status.to_le_bytes()) != 4 {
                return Err(EFAULT);
            }
            // No resource accounting yet: report zero usage rather than
            // leave the caller's buffer as it was.
            if rusage != 0 && p.copy_to_user(rusage, &[0u8; RUSAGE_SIZE]) != RUSAGE_SIZE {
                return Err(EFAULT);
            }
            Ok(cpid)
        }
    }
}

/// `waitid(idtype, id, infop, options, rusage)`: the child's state is a
/// `siginfo_t`.
fn waitid(
    p: &mut LinuxProcess,
    idtype: u64,
    id: u64,
    infop: u64,
    options: u64,
    rusage: u64,
) -> Result<u64, i64> {
    const WNOHANG: u64 = 1;
    const WSTOPPED: u64 = 2;
    const WEXITED: u64 = 4;
    const WCONTINUED: u64 = 8;
    const WNOWAIT: u64 = 0x0100_0000;
    const KNOWN: u64 = WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT | 0xe000_0000;
    const SIGCHLD: u32 = 17;
    const CLD_EXITED: u32 = 1;
    const CLD_KILLED: u32 = 2;
    const CLD_DUMPED: u32 = 3;
    const CLD_STOPPED: u32 = 5;
    const CLD_CONTINUED: u32 = 6;
    if options & !KNOWN != 0 || options & (WEXITED | WSTOPPED | WCONTINUED) == 0 {
        return Err(EINVAL);
    }
    let pid = match idtype {
        0 => -1,                                           // P_ALL
        1 if id > 0 && id <= i32::MAX as u64 => id as i64, // P_PID
        2 if id <= i32::MAX as u64 => -(id as i64),        // P_PGID (0: the caller's)
        3 => pidfd::pid_of(p, id)?.cast_signed(),          // P_PIDFD
        _ => return Err(EINVAL),
    };
    let want = proc::Wanted {
        exited: options & WEXITED != 0,
        stopped: options & WSTOPPED != 0,
        continued: options & WCONTINUED != 0,
        nohang: options & WNOHANG != 0 || (idtype == 3 && pidfd::nonblocking(p, id)),
        keep: options & WNOWAIT != 0,
    };
    let found = proc::wait(&p.group.leader, &p.entry, pid, want)?;
    if found.is_none() && options & WNOHANG == 0 {
        return Err(EAGAIN); // a non-blocking pidfd
    }
    // struct siginfo (128 bytes): signo, errno, code, then pid, uid, status.
    let mut si = [0u8; 128];
    if let Some((cpid, st, uid)) = found {
        let (code, status) = if st == proc::CONTINUED {
            (CLD_CONTINUED, signal::SIGCONT)
        } else if st & 0xff == 0x7f {
            (CLD_STOPPED, st >> 8)
        } else if st & 0x7f == 0 {
            (CLD_EXITED, (st >> 8) & 0xff)
        } else if st & 0x80 != 0 {
            (CLD_DUMPED, st & 0x7f)
        } else {
            (CLD_KILLED, st & 0x7f)
        };
        si[0..4].copy_from_slice(&SIGCHLD.to_le_bytes());
        si[8..12].copy_from_slice(&code.to_le_bytes());
        si[16..20].copy_from_slice(&(cpid as u32).to_le_bytes());
        si[20..24].copy_from_slice(&uid.to_le_bytes());
        si[24..28].copy_from_slice(&status.to_le_bytes());
    }
    if infop != 0 && p.copy_to_user(infop, &si) != si.len() {
        return Err(EFAULT);
    }
    if rusage != 0 && p.copy_to_user(rusage, &[0u8; 144]) != 144 {
        return Err(EFAULT);
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Identity, time, limits, signals and futexes.
// ---------------------------------------------------------------------------

fn uname(p: &mut LinuxProcess, buf: u64) -> Result<u64, i64> {
    // struct utsname: six 65-byte NUL-padded fields. The release is a
    // modern Linux version, since libcs refuse to run on old kernels.
    let fields: [&str; 6] = [
        "Linux",
        "ichor",
        "6.6.0-ichor",
        "#1 Ichor",
        "x86_64",
        "(none)",
    ];
    let mut u = [0u8; 65 * 6];
    for (i, f) in fields.iter().enumerate() {
        u[i * 65..i * 65 + f.len()].copy_from_slice(f.as_bytes());
    }
    if p.copy_to_user(buf, &u) == u.len() {
        Ok(0)
    } else {
        Err(EFAULT)
    }
}

fn put_pair(p: &mut LinuxProcess, addr: u64, a: u64, b: u64) -> Result<u64, i64> {
    let mut t = [0u8; 16];
    t[..8].copy_from_slice(&a.to_le_bytes());
    t[8..].copy_from_slice(&b.to_le_bytes());
    if p.copy_to_user(addr, &t) == t.len() {
        Ok(0)
    } else {
        Err(EFAULT)
    }
}

/// `clock_gettime`. The realtime clocks read the firmware clock taken at
/// boot plus monotonic time; the monotonic and boot-time clocks count from
/// boot. CPU time is not accounted yet, so the CPU-time clocks report the
/// time since the process started, an upper bound (partial).
fn clock_gettime(p: &mut LinuxProcess, clock: u64, tp: u64) -> Result<u64, i64> {
    const REALTIME: u64 = 0;
    const MONOTONIC: u64 = 1;
    const PROCESS_CPUTIME: u64 = 2;
    const THREAD_CPUTIME: u64 = 3;
    const MONOTONIC_RAW: u64 = 4;
    const REALTIME_COARSE: u64 = 5;
    const MONOTONIC_COARSE: u64 = 6;
    const BOOTTIME: u64 = 7;
    let t = match clock {
        REALTIME | REALTIME_COARSE => crate::vfs::wall_clock(),
        MONOTONIC | MONOTONIC_RAW | MONOTONIC_COARSE | BOOTTIME => frame::time::now(),
        PROCESS_CPUTIME => core::time::Duration::from_nanos(p.group.cpu_ns()),
        THREAD_CPUTIME => core::time::Duration::from_nanos(
            p.entry.cpu_ns.load(core::sync::atomic::Ordering::Relaxed),
        ),
        // A CPU-time clock id for a pid or tid (clock_getcpuclockid,
        // pthread_getcpuclockid): `~id << 3 | type`, bit 2 for a thread.
        // The caller's own process and threads are answered.
        c if (c as i32) < 0 => {
            let c = c as i32;
            let id = u64::from((!c >> 3) as u32);
            if c & 3 == 3 {
                return Err(EINVAL);
            }
            let ns = if c & 4 != 0 {
                p.group
                    .threads()
                    .iter()
                    .find(|e| e.pid == id || (id == 0 && e.pid == p.entry.pid))
                    .ok_or(EINVAL)?
                    .cpu_ns
                    .load(core::sync::atomic::Ordering::Relaxed)
            } else if id == 0 || id == p.group.tgid {
                p.group.cpu_ns()
            } else {
                return Err(EINVAL);
            };
            core::time::Duration::from_nanos(ns)
        }
        _ => return Err(EINVAL),
    };
    put_pair(p, tp, t.as_secs(), u64::from(t.subsec_nanos()))
}

/// `clock_getres`: every clock `clock_gettime` answers reads the TSC-based
/// time in nanoseconds (the coarse ones too), so the resolution is 1 ns.
fn clock_getres(p: &mut LinuxProcess, clock: u64, res: u64) -> Result<u64, i64> {
    if clock > 7 {
        return Err(EINVAL);
    }
    if res == 0 {
        return Ok(0);
    }
    put_pair(p, res, 0, 1)
}

fn gettimeofday(p: &mut LinuxProcess, tv: u64) -> Result<u64, i64> {
    if tv == 0 {
        return Ok(0);
    }
    let now = crate::vfs::wall_clock();
    put_pair(p, tv, now.as_secs(), u64::from(now.subsec_micros()))
}

/// `getpriority` (`value` None) and `setpriority`: the caller's nice value.
/// The raw syscall returns `20 - nice` so that it is never negative. Raising
/// the nice value is always allowed; lowering it needs CAP_SYS_NICE, which
/// is outside the cell bounding set, so it is EACCES as for an unprivileged
/// Linux process.
fn priority(p: &mut LinuxProcess, which: i64, who: u64, value: Option<i64>) -> Result<u64, i64> {
    const PRIO_USER: i64 = 2;
    const ESRCH: i64 = 3;
    const EACCES: i64 = 13;
    if !(0..=PRIO_USER).contains(&which) {
        return Err(EINVAL);
    }
    // PRIO_PROCESS names a pid; PRIO_PGRP and PRIO_USER only themselves (0).
    let me = who == 0 || (which == 0 && who == p.group.tgid);
    if !me {
        return Err(ESRCH);
    }
    let mut prctl = p.group.prctl.lock();
    match value {
        None => Ok((20 - prctl.nice) as u64),
        Some(v) => {
            let nice = v.clamp(-20, 19) as i32;
            if nice < prctl.nice {
                return Err(EACCES);
            }
            prctl.nice = nice;
            Ok(0)
        }
    }
}

/// `prctl(option, arg2, ...)`: the options libc, apt and service managers
/// use. Anything else is EINVAL, as Linux answers for unknown options.
fn prctl(p: &mut LinuxProcess, option: u64, arg2: u64, arg3: u64) -> Result<u64, i64> {
    const PR_SET_PDEATHSIG: u64 = 1;
    const PR_GET_PDEATHSIG: u64 = 2;
    const PR_GET_DUMPABLE: u64 = 3;
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_GET_KEEPCAPS: u64 = 7;
    const PR_SET_KEEPCAPS: u64 = 8;
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    const PR_CAPBSET_READ: u64 = 23;
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_GET_NO_NEW_PRIVS: u64 = 39;
    let _ = arg3;
    match option {
        PR_SET_PDEATHSIG => {
            let sig = u32::try_from(arg2)
                .ok()
                .filter(|&s| s <= signal::NSIG)
                .ok_or(EINVAL)?;
            p.group
                .leader
                .pdeathsig
                .store(sig, core::sync::atomic::Ordering::Release);
            Ok(0)
        }
        PR_GET_PDEATHSIG => {
            let sig = p
                .group
                .leader
                .pdeathsig
                .load(core::sync::atomic::Ordering::Acquire);
            if p.copy_to_user(arg2, &sig.to_le_bytes()) != 4 {
                return Err(EFAULT);
            }
            Ok(0)
        }
        PR_GET_DUMPABLE => Ok(u64::from(p.group.prctl.lock().dumpable)),
        PR_SET_DUMPABLE if arg2 <= 1 => {
            p.group.prctl.lock().dumpable = arg2 == 1;
            Ok(0)
        }
        PR_GET_KEEPCAPS => Ok(u64::from(p.group.creds().keepcaps)),
        PR_SET_KEEPCAPS if arg2 <= 1 => p.group.update_creds(|c| {
            c.keepcaps = arg2 == 1;
            Ok(0)
        }),
        PR_SET_NAME => {
            let mut b = [0u8; 16];
            let n = p.copy_from_user(arg2, &mut b);
            let len = b[..n].iter().position(|&c| c == 0).unwrap_or(n.min(15));
            let name = alloc::string::String::from_utf8_lossy(&b[..len.min(15)]).into_owned();
            p.group.prctl.lock().name = Some(name);
            Ok(0)
        }
        PR_GET_NAME => {
            let name = p.group.prctl.lock().name.clone().unwrap_or_else(|| {
                let exe = p.group.exe();
                exe.rsplit('/')
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(15)
                    .collect()
            });
            let mut b = [0u8; 16];
            let n = name.len().min(15);
            b[..n].copy_from_slice(&name.as_bytes()[..n]);
            if p.copy_to_user(arg2, &b) != 16 {
                return Err(EFAULT);
            }
            Ok(0)
        }
        PR_CAPBSET_READ => {
            if arg2 > 40 {
                return Err(EINVAL);
            }
            Ok(u64::from(crate::cred::BOUNDING & (1 << arg2) != 0))
        }
        PR_SET_NO_NEW_PRIVS if arg2 == 1 => {
            // Nothing in a cell ever gains privilege at exec (ADR-0009), so
            // the flag only has to be remembered and reported.
            p.group.prctl.lock().no_new_privs = true;
            Ok(0)
        }
        PR_GET_NO_NEW_PRIVS => Ok(u64::from(p.group.prctl.lock().no_new_privs)),
        _ => Err(EINVAL),
    }
}

/// `sched_getaffinity(pid, len, mask)`: every online CPU (threads may run
/// on any of them). Returns the bytes written, as the raw syscall does.
fn sched_getaffinity(p: &mut LinuxProcess, pid: u64, len: u64, mask: u64) -> Result<u64, i64> {
    const ESRCH: i64 = 3;
    let pid = u64::from(pid as u32);
    if pid != 0 && crate::proc::uids_of(p.entry.cell, pid).is_err() {
        return Err(ESRCH);
    }
    let n = frame::cpu::online_count();
    let bytes = n.div_ceil(64) * 8;
    if (len as usize) < bytes || !len.is_multiple_of(8) {
        return Err(EINVAL);
    }
    let set = p.group.prctl.lock().affinity;
    let mut v = alloc::vec![0u8; bytes];
    for cpu in 0..n {
        if set.is_none_or(|m| cpu < 64 && m & (1 << cpu) != 0) {
            v[cpu / 8] |= 1 << (cpu % 8);
        }
    }
    if p.copy_to_user(mask, &v) != v.len() {
        return Err(EFAULT);
    }
    Ok(bytes as u64)
}

/// `sched_setaffinity(pid, len, mask)`: the caller's process (pid 0 or
/// one of its own) records the mask, which must name an online CPU; the
/// scheduler does not apply it yet (partial). Another process: EPERM, as
/// for an unprivileged caller without CAP_SYS_NICE.
fn sched_setaffinity(p: &mut LinuxProcess, pid: u64, len: u64, mask: u64) -> Result<u64, i64> {
    const ESRCH: i64 = 3;
    let pid = u64::from(pid as u32);
    if pid != 0 && pid != p.group.tgid && pid != p.entry.pid {
        crate::proc::uids_of(p.entry.cell, pid).map_err(|_| ESRCH)?;
        return Err(EPERM);
    }
    let n = frame::cpu::online_count().min(64);
    let mut b = [0u8; 8];
    let take = (len as usize).min(8);
    if p.copy_from_user(mask, &mut b[..take]) != take {
        return Err(EFAULT);
    }
    let online = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    let m = u64::from_le_bytes(b) & online;
    if m == 0 {
        return Err(EINVAL);
    }
    p.group.prctl.lock().affinity = (m != online).then_some(m);
    Ok(0)
}

/// `sched_get_priority_max`/`min`: 1..=99 for the real-time policies
/// (FIFO, RR, DEADLINE has none), 0 for the others, as on Linux.
fn sched_priority_bound(policy: u64, max: bool) -> Result<u64, i64> {
    match policy {
        1 | 2 => Ok(if max { 99 } else { 1 }), // SCHED_FIFO, SCHED_RR
        0 | 3 | 5 | 6 => Ok(0),                // OTHER, BATCH, IDLE, DEADLINE
        _ => Err(EINVAL),
    }
}

/// `sched_rr_get_interval`: the round-robin time slice Linux reports
/// (100 ms); the caller's process only.
fn sched_rr_get_interval(p: &mut LinuxProcess, pid: u64, tp: u64) -> Result<u64, i64> {
    const ESRCH: i64 = 3;
    let pid = u64::from(pid as u32);
    if pid != 0 && crate::proc::uids_of(p.entry.cell, pid).is_err() {
        return Err(ESRCH);
    }
    put_pair(p, tp, 0, 100_000_000)
}

/// `sysinfo`: uptime, the cell's memory (its account, as `/proc/meminfo`
/// shows it), and its process count.
fn sysinfo(p: &mut LinuxProcess, buf: u64) -> Result<u64, i64> {
    let st = frame::mm::stats();
    let account = p.cell.account();
    let total = account.limit().min(st.total_pages as u64) * 4096;
    let free = account.available().min(st.free_pages as u64) * 4096;
    let (_, procs, _) = crate::proc::census(p.entry.cell);
    let mut b = [0u8; 112];
    b[0..8].copy_from_slice(&frame::time::now().as_secs().to_le_bytes());
    b[32..40].copy_from_slice(&total.to_le_bytes());
    b[40..48].copy_from_slice(&free.to_le_bytes());
    b[80..82].copy_from_slice(&(procs.min(u16::MAX as usize) as u16).to_le_bytes());
    b[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
    if p.copy_to_user(buf, &b) != b.len() {
        return Err(EFAULT);
    }
    Ok(0)
}

/// `getrusage(who, usage)`: no CPU-time accounting yet, so times are zero;
/// `ru_maxrss` is the current resident size (an under-estimate of the peak).
fn getrusage(p: &mut LinuxProcess, who: i64, buf: u64) -> Result<u64, i64> {
    const RUSAGE_SELF: i64 = 0;
    const RUSAGE_CHILDREN: i64 = -1;
    const RUSAGE_THREAD: i64 = 1;
    let mut b = [0u8; 144];
    match who {
        RUSAGE_SELF | RUSAGE_THREAD => {
            // ru_utime: user CPU time (a timeval); system time is not
            // accounted yet.
            let ns = if who == RUSAGE_SELF {
                p.group.cpu_ns()
            } else {
                p.entry.cpu_ns.load(core::sync::atomic::Ordering::Relaxed)
            };
            b[0..8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
            b[8..16].copy_from_slice(&((ns % 1_000_000_000) / 1000).to_le_bytes());
            let rss_kb = p.mm().resident_pages() as u64 * 4;
            b[32..40].copy_from_slice(&rss_kb.to_le_bytes());
        }
        RUSAGE_CHILDREN => {}
        _ => return Err(EINVAL),
    }
    if p.copy_to_user(buf, &b) != b.len() {
        return Err(EFAULT);
    }
    Ok(0)
}

/// `times(buf)`: the process's user CPU time in clock ticks (`USER_HZ`,
/// 100/s); system and children's times are not accounted yet (zero).
/// Returns clock ticks since boot.
fn times(p: &mut LinuxProcess, buf: u64) -> Result<u64, i64> {
    let mut t = [0u8; 32];
    t[0..8].copy_from_slice(&(p.group.cpu_ns() / 10_000_000).to_le_bytes());
    if buf != 0 && p.copy_to_user(buf, &t) != 32 {
        return Err(EFAULT);
    }
    Ok((frame::time::now().as_millis() / 10) as u64)
}

/// `getresuid` / `getresgid`: three `u32`s (each pointer may be null).
fn getres(p: &mut LinuxProcess, uids: bool, at: [u64; 3]) -> Result<u64, i64> {
    let c = p.group.creds();
    let v = if uids {
        [c.ruid, c.euid, c.suid]
    } else {
        [c.rgid, c.egid, c.sgid]
    };
    for (addr, id) in at.iter().zip(v) {
        if *addr != 0 && p.copy_to_user(*addr, &id.to_le_bytes()) != 4 {
            return Err(EFAULT);
        }
    }
    Ok(0)
}

/// `getgroups(size, list)`: the count with `size` 0, else EINVAL if the
/// list does not fit.
fn getgroups(p: &mut LinuxProcess, size: u64, list: u64) -> Result<u64, i64> {
    let g = p.group.creds().groups;
    if size == 0 {
        return Ok(g.len() as u64);
    }
    if (size as usize) < g.len() {
        return Err(EINVAL);
    }
    let bytes: alloc::vec::Vec<u8> = g.iter().flat_map(|x| x.to_le_bytes()).collect();
    if p.copy_to_user(list, &bytes) != bytes.len() {
        return Err(EFAULT);
    }
    Ok(g.len() as u64)
}

fn setgroups(p: &mut LinuxProcess, size: u64, list: u64) -> Result<u64, i64> {
    let n = usize::try_from(size).map_err(|_| EINVAL)?;
    if n > crate::cred::NGROUPS_MAX {
        return Err(EINVAL);
    }
    let mut bytes = alloc::vec![0u8; n * 4];
    if n > 0 && p.copy_from_user(list, &mut bytes) != bytes.len() {
        return Err(EFAULT);
    }
    let groups = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u32::from_le_bytes(*b))
        .collect();
    p.group.update_creds(|c| c.setgroups(groups)).map(|()| 0)
}

/// `prlimit64(pid, resource, new, old)`, `getrlimit`, `setrlimit`. Limits
/// are per process and survive fork and exec; `RLIMIT_NOFILE` caps
/// descriptor numbers and `RLIMIT_STACK` sizes the stack at exec. Only the
/// calling process can be named (partial).
fn prlimit(p: &mut LinuxProcess, pid: u64, resource: u64, new: u64, old: u64) -> Result<u64, i64> {
    use crate::process::{MAX_FDS, RLIM_NLIMITS, RLIMIT_NOFILE};
    const ESRCH: i64 = 3;
    let group = if pid == 0 || pid == p.group.tgid {
        p.group.clone()
    } else {
        let e = proc::find(p.entry.cell, pid).ok_or(ESRCH)?;
        signal::may_signal(p, pid, 0)?; // the same rights as to signal it
        let leader = proc::find(p.entry.cell, e.tgid).ok_or(ESRCH)?;
        leader.process().ok_or(ESRCH)?
    };
    let r = usize::try_from(resource)
        .ok()
        .filter(|&r| r < RLIM_NLIMITS)
        .ok_or(EINVAL)?;
    let (cur, max) = group.limits()[r];
    if new != 0 {
        let mut b = [0u8; 16];
        if p.copy_from_user(new, &mut b) != 16 {
            return Err(EFAULT);
        }
        let soft = u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
        let hard = u64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
        if soft > hard {
            return Err(EINVAL);
        }
        // Raising a hard limit needs CAP_SYS_RESOURCE, which is outside
        // the cell bounding set (ADR-0009 §3), as in Docker's default; and
        // the descriptor table holds MAX_FDS entries.
        if hard > max || (r == RLIMIT_NOFILE && hard > MAX_FDS as u64) {
            return Err(EPERM);
        }
        group.set_limit(r, soft, hard);
    }
    if old != 0 {
        put_pair(p, old, cur, max)?;
    }
    Ok(0)
}

/// A user `struct itimerval` (interval, then value; `timeval`s).
fn put_itimerval(
    p: &mut LinuxProcess,
    at: u64,
    (value, interval): (Duration, Duration),
) -> Result<(), i64> {
    let mut b = [0u8; 32];
    for (i, d) in [interval, value].into_iter().enumerate() {
        b[i * 16..i * 16 + 8].copy_from_slice(&d.as_secs().to_le_bytes());
        b[i * 16 + 8..i * 16 + 16].copy_from_slice(&u64::from(d.subsec_micros()).to_le_bytes());
    }
    if p.copy_to_user(at, &b) != 32 {
        return Err(EFAULT);
    }
    Ok(())
}

/// An interval timer's number in the timer table.
fn which_itimer(which: u64) -> Result<i32, i64> {
    use crate::itimer::{PROF, REAL, VIRTUAL};
    [REAL, VIRTUAL, PROF]
        .get(usize::try_from(which).unwrap_or(usize::MAX))
        .copied()
        .ok_or(EINVAL)
}

/// `getitimer(which, curr)`.
fn getitimer(p: &mut LinuxProcess, which: u64, curr: u64) -> Result<u64, i64> {
    let v = crate::itimer::get(p, which_itimer(which)?).unwrap_or_default();
    put_itimerval(p, curr, v).map(|()| 0)
}

/// `setitimer(which, new, old)`: arms `ITIMER_REAL` (`SIGALRM`),
/// `ITIMER_VIRTUAL` (`SIGVTALRM`) or `ITIMER_PROF` (`SIGPROF`).
fn setitimer(p: &mut LinuxProcess, which: u64, new: u64, old: u64) -> Result<u64, i64> {
    let id = which_itimer(which)?;
    let mut b = [0u8; 32];
    if new != 0 && p.copy_from_user(new, &mut b) != 32 {
        return Err(EFAULT);
    }
    let tv = |at: usize| -> Result<Duration, i64> {
        let s = i64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
        let us = i64::from_le_bytes(b[at + 8..at + 16].try_into().unwrap_or([0; 8]));
        if s < 0 || !(0..1_000_000).contains(&us) {
            return Err(EINVAL);
        }
        Ok(Duration::new(s as u64, us as u32 * 1000))
    };
    let (interval, value) = (tv(0)?, tv(16)?);
    let prev = if new == 0 {
        crate::itimer::get(p, id).unwrap_or_default()
    } else {
        crate::itimer::set_itimer(p, id, value, interval)?
    };
    if old != 0 {
        put_itimerval(p, old, prev)?;
    }
    Ok(0)
}

/// `timer_create(clock, sigevent, id)`.
fn timer_create(p: &mut LinuxProcess, clock: u64, event: u64, id: u64) -> Result<u64, i64> {
    use crate::itimer::{Clock, Notify};
    const SIGEV_SIGNAL: u32 = 0;
    const SIGEV_NONE: u32 = 1;
    const SIGEV_THREAD: u32 = 2; // libc's own; the kernel just signals
    const SIGEV_THREAD_ID: u32 = 4;
    let clock = match clock {
        0 => Clock::Real,
        1 | 7 => Clock::Mono,
        2 => Clock::Process,
        3 => Clock::Thread(p.entry.pid),
        _ => return Err(EINVAL),
    };
    let notify = if event == 0 {
        None
    } else {
        // struct sigevent: value, signo, notify, then the thread id.
        let mut b = [0u8; 64];
        if p.copy_from_user(event, &mut b) != 64 {
            return Err(EFAULT);
        }
        let word = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let (value, sig, how) = (le_u64(&b[..8]), word(8), word(12));
        if how != SIGEV_NONE && !(1..=signal::NSIG).contains(&sig) {
            return Err(EINVAL);
        }
        let thread = match how {
            SIGEV_SIGNAL | SIGEV_NONE | SIGEV_THREAD => None,
            SIGEV_THREAD_ID => {
                let tid = u64::from(word(16));
                let mine = p.group.threads().iter().any(|t| t.pid == tid);
                Some(mine.then_some(tid).ok_or(EINVAL)?)
            }
            _ => return Err(EINVAL),
        };
        Some(Notify {
            sig: if how == SIGEV_NONE { 0 } else { sig },
            thread,
            value,
        })
    };
    let n = crate::itimer::create(p, clock, |n| {
        notify.unwrap_or(Notify {
            sig: signal::SIGALRM,
            thread: None,
            value: n as u64,
        })
    })?;
    if p.copy_to_user(id, &n.to_le_bytes()) != 4 {
        let _ = crate::itimer::delete(p, n);
        return Err(EFAULT);
    }
    Ok(0)
}

/// A POSIX timer's number.
fn timer_id(id: u64) -> Result<i32, i64> {
    i32::try_from(id & 0xffff_ffff).map_err(|_| EINVAL)
}

/// Writes a `struct itimerspec`: interval, then value.
fn put_itimerspec(
    p: &mut LinuxProcess,
    at: u64,
    (left, interval): (Duration, Duration),
) -> Result<(), i64> {
    let mut b = [0u8; 32];
    for (i, d) in [interval, left].iter().enumerate() {
        b[i * 16..i * 16 + 8].copy_from_slice(&d.as_secs().to_le_bytes());
        let ns = u64::from(d.subsec_nanos());
        b[i * 16 + 8..i * 16 + 16].copy_from_slice(&ns.to_le_bytes());
    }
    if p.copy_to_user(at, &b) != 32 {
        return Err(EFAULT);
    }
    Ok(())
}

/// `timer_settime(id, flags, new, old)`.
fn timer_settime(
    p: &mut LinuxProcess,
    id: u64,
    flags: u64,
    new: u64,
    old: u64,
) -> Result<u64, i64> {
    const TIMER_ABSTIME: u64 = 1;
    let interval = crate::poll::read_timespec(p, new)?;
    let value = crate::poll::read_timespec(p, new + 16)?;
    let absolute = flags & TIMER_ABSTIME != 0;
    let prev = crate::itimer::set(p, timer_id(id)?, value, interval, absolute)?;
    if old != 0 {
        put_itimerspec(p, old, prev)?;
    }
    Ok(0)
}

/// `timer_gettime(id, curr)`.
fn timer_gettime(p: &mut LinuxProcess, id: u64, curr: u64) -> Result<u64, i64> {
    let v = crate::itimer::get(p, timer_id(id)?).ok_or(EINVAL)?;
    put_itimerspec(p, curr, v).map(|()| 0)
}

/// `alarm(seconds)`: a one-shot `ITIMER_REAL`; returns the seconds the
/// previous alarm had left, rounded as Linux does.
fn alarm(p: &mut LinuxProcess, secs: u64) -> Result<u64, i64> {
    let secs = secs & 0xffff_ffff;
    let (left, _) = crate::itimer::set_itimer(
        p,
        crate::itimer::REAL,
        Duration::from_secs(secs),
        Duration::ZERO,
    )?;
    if left.is_zero() {
        return Ok(0);
    }
    Ok((left.as_secs() + u64::from(left.subsec_micros() >= 500_000)).max(1))
}

/// One past the highest user address (the top of the lower canonical half).
const USER_ADDR_END: u64 = 0x0000_7fff_ffff_f000;
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;

/// `arch_prctl`: lets a static binary set its FS base (TLS). GS is not
/// settable (the kernel keeps its per-CPU block there; see ADR-0001).
fn arch_prctl(ctx: &mut frame::user::UserContext, code: u64, addr: u64) -> Result<u64, i64> {
    match code {
        ARCH_SET_FS => {
            // Like Linux: the base must be a user address (anything else
            // would fault when loaded into the MSR).
            if addr >= USER_ADDR_END {
                return Err(EPERM);
            }
            ctx.fs_base = addr;
            Ok(0)
        }
        ARCH_SET_GS => Err(EINVAL),
        _ => Err(EINVAL),
    }
}
