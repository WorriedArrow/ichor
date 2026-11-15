//! The Linux x86-64 syscall personality (ADR-0002 §5), milestone 3 slice:
//! console I/O, the root file system (an image with a copy-on-write upper
//! layer; file calls live in [`fs`]), memory (`mmap`, `brk`, demand paging),
//! TLS, process identity, and exit. Signals are accepted but never delivered
//! yet. The number is in `rax`, arguments in `rdi, rsi, rdx, r10, r8, r9`,
//! and the result in `rax`; on error `rax` is `-errno`.
//!
//! User memory is only ever copied (`VmSpace::copy_{from,to}_user`), never
//! borrowed. Coverage is tracked in `docs/linux-abi.md`.

mod exec;
mod fs;

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
    pub(super) const MMAP: u64 = 9; // partial: shared file mappings are read-only snapshots
    pub(super) const MPROTECT: u64 = 10;
    pub(super) const MUNMAP: u64 = 11;
    pub(super) const BRK: u64 = 12;
    pub(super) const RT_SIGACTION: u64 = 13;
    pub(super) const RT_SIGPROCMASK: u64 = 14;
    pub(super) const RT_SIGRETURN: u64 = 15;
    pub(super) const IOCTL: u64 = 16; // partial: no tty ioctls (the console is not a tty); FIONBIO, FIOCLEX/FIONCLEX
    pub(super) const PREAD64: u64 = 17;
    pub(super) const PWRITE64: u64 = 18;
    pub(super) const READV: u64 = 19;
    pub(super) const WRITEV: u64 = 20;
    pub(super) const ACCESS: u64 = 21; // partial: existence only (every process is root)
    pub(super) const PIPE: u64 = 22;
    pub(super) const SELECT: u64 = 23;
    pub(super) const SCHED_YIELD: u64 = 24;
    pub(super) const MADVISE: u64 = 28; // partial: DONTNEED on the loaded image's own segments zero-fills
    pub(super) const PAUSE: u64 = 34;
    pub(super) const NANOSLEEP: u64 = 35;
    pub(super) const DUP: u64 = 32;
    pub(super) const DUP2: u64 = 33;
    pub(super) const GETPID: u64 = 39;
    pub(super) const SENDFILE: u64 = 40;
    pub(super) const CLONE: u64 = 56; // partial: fork, vfork-style and thread clones
    pub(super) const FORK: u64 = 57;
    pub(super) const VFORK: u64 = 58; // partial: the child gets a copy-on-write copy, not the parent's memory
    pub(super) const EXECVE: u64 = 59; // static and PIE ELF, PT_INTERP, #! scripts
    pub(super) const EXIT: u64 = 60;
    pub(super) const WAIT4: u64 = 61; // partial: rusage is all zero (no accounting yet)
    pub(super) const KILL: u64 = 62;
    pub(super) const UNAME: u64 = 63;
    pub(super) const FCNTL: u64 = 72; // partial: no F_SETOWN/F_*SIG/leases/seals
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
    pub(super) const UNLINK: u64 = 87;
    pub(super) const SYMLINK: u64 = 88;
    pub(super) const READLINK: u64 = 89;
    pub(super) const CHMOD: u64 = 90;
    pub(super) const FCHMOD: u64 = 91;
    pub(super) const CHOWN: u64 = 92; // partial: recorded; every process is uid 0 (no checks yet)
    pub(super) const FCHOWN: u64 = 93; // partial: recorded; every process is uid 0 (no checks yet)
    pub(super) const LCHOWN: u64 = 94; // partial: recorded; every process is uid 0 (no checks yet)
    pub(super) const UMASK: u64 = 95;
    pub(super) const GETTIMEOFDAY: u64 = 96; // firmware clock at boot plus monotonic time (no NTP)
    pub(super) const GETRLIMIT: u64 = 97;
    pub(super) const SETRLIMIT: u64 = 160; // partial: NOFILE and STACK enforced, others stored
    pub(super) const GETUID: u64 = 102; // partial: always 0
    pub(super) const GETGID: u64 = 104; // partial: always 0
    pub(super) const GETEUID: u64 = 107; // partial: always 0
    pub(super) const GETEGID: u64 = 108; // partial: always 0
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
    pub(super) const ARCH_PRCTL: u64 = 158; // partial: ARCH_SET_FS only
    pub(super) const GETTID: u64 = 186;
    pub(super) const TKILL: u64 = 200;
    pub(super) const FUTEX: u64 = 202; // partial: shared only within shared anonymous memory; no PI, no FUTEX_FD
    pub(super) const EPOLL_CREATE: u64 = 213;
    pub(super) const GETDENTS64: u64 = 217;
    pub(super) const SET_TID_ADDRESS: u64 = 218;
    pub(super) const CLOCK_GETTIME: u64 = 228; // partial: CPU-time clocks report time since the process started
    pub(super) const CLOCK_NANOSLEEP: u64 = 230; // partial: relative sleeps only
    pub(super) const UTIMES: u64 = 235;
    pub(super) const EXIT_GROUP: u64 = 231;
    pub(super) const EPOLL_WAIT: u64 = 232; // partial: interest list fixed for the wait; nested epoll never ready
    pub(super) const EPOLL_CTL: u64 = 233;
    pub(super) const TGKILL: u64 = 234;
    pub(super) const OPENAT: u64 = 257;
    pub(super) const MKDIRAT: u64 = 258;
    pub(super) const FCHOWNAT: u64 = 260; // partial: recorded; every process is uid 0 (no checks yet)
    pub(super) const NEWFSTATAT: u64 = 262;
    pub(super) const UNLINKAT: u64 = 263;
    pub(super) const FUTIMESAT: u64 = 261;
    pub(super) const RENAMEAT: u64 = 264;
    pub(super) const SYMLINKAT: u64 = 266;
    pub(super) const READLINKAT: u64 = 267;
    pub(super) const FCHMODAT: u64 = 268;
    pub(super) const PSELECT6: u64 = 270;
    pub(super) const PPOLL: u64 = 271;
    pub(super) const FACCESSAT: u64 = 269; // partial: existence only (every process is root)
    pub(super) const UTIMENSAT: u64 = 280;
    pub(super) const EPOLL_PWAIT: u64 = 281; // partial: interest list fixed for the wait; nested epoll never ready
    pub(super) const EVENTFD: u64 = 284;
    pub(super) const EVENTFD2: u64 = 290;
    pub(super) const EPOLL_CREATE1: u64 = 291;
    pub(super) const DUP3: u64 = 292;
    pub(super) const PIPE2: u64 = 293;
    pub(super) const PRLIMIT64: u64 = 302; // partial: own process only; NOFILE and STACK enforced, others stored
    pub(super) const GETRANDOM: u64 = 318; // ChaCha20 seeded from RDSEED/RDRAND and virtio-rng
    pub(super) const RENAMEAT2: u64 = 316; // partial: RENAME_NOREPLACE only
}

const EPERM: i64 = 1;
const EBADF: i64 = 9;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const ENODEV: i64 = 19;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOTTY: i64 = 25;
const ENOSYS: i64 = 38;

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
    let i = |v: u64| v as i64;
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
        nr::FSTAT => fs::fstat(p, a[0], a[1]),
        nr::LSEEK => fs::lseek(p, a[0], i(a[1]), a[2]),
        nr::ACCESS => fs::access(p, AT_FDCWD, a[0], a[1]),
        nr::FACCESSAT => fs::access(p, i(a[0]), a[1], a[2]),
        nr::TRUNCATE => fs::truncate(p, a[0], a[1]),
        nr::FTRUNCATE => fs::ftruncate(p, a[0], a[1]),
        nr::FSYNC | nr::FDATASYNC => fs::fsync(p, a[0]),
        nr::SENDFILE => fs::sendfile(p, a[0], a[1], a[2], a[3] as usize),
        nr::GETDENTS64 => fs::getdents64(p, a[0], a[1], a[2] as usize),
        nr::MKDIR => fs::mkdir(p, AT_FDCWD, a[0], a[1]),
        nr::MKDIRAT => fs::mkdir(p, i(a[0]), a[1], a[2]),
        nr::RMDIR => fs::unlink(p, AT_FDCWD, a[0], 0x200),
        nr::UNLINK => fs::unlink(p, AT_FDCWD, a[0], 0),
        nr::UNLINKAT => fs::unlink(p, i(a[0]), a[1], a[2]),
        nr::RENAME => fs::rename(p, AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        nr::RENAMEAT => fs::rename(p, i(a[0]), a[1], i(a[2]), a[3], 0),
        nr::RENAMEAT2 => fs::rename(p, i(a[0]), a[1], i(a[2]), a[3], a[4]),
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
        nr::EPOLL_WAIT => crate::poll::epoll_wait(p, a[0], a[1], a[2], i(a[3]) as i32 as i64),
        nr::EPOLL_PWAIT => crate::poll::epoll_pwait(p, &a),
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
        nr::MADVISE => p.mm().madvise(a[0], a[1], a[2]),
        // Identity, time, limits, signals, threads.
        nr::UNAME => uname(p, a[0]),
        nr::CLOCK_GETTIME => clock_gettime(p, a[0], a[1]),
        nr::GETTIMEOFDAY => gettimeofday(p, a[0]),
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
        nr::CLOCK_NANOSLEEP if a[1] == 0 => signal::nanosleep(p, a[2], a[3]),
        nr::CLOCK_NANOSLEEP => Err(EINVAL), // TIMER_ABSTIME
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
        nr::GETTID => Ok(p.entry.pid),
        nr::GETPPID => Ok(p.entry.ppid()),
        nr::GETUID | nr::GETGID | nr::GETEUID | nr::GETEGID => Ok(0),
        // Processes.
        nr::FORK => clone(p, ctx, 17, 0, 0, 0, 0), // SIGCHLD
        nr::VFORK => clone(p, ctx, 0x4000 | 0x100 | 17, 0, 0, 0, 0), // CLONE_VFORK | CLONE_VM
        nr::CLONE => clone(p, ctx, a[0], a[1], a[2], a[3], a[4]),
        nr::WAIT4 => wait4(p, i(a[0]), a[1], a[2], a[3]),
        nr::EXECVE => match exec::execve(p, ctx, a[0], a[1], a[2]) {
            // The context now starts the new program: no return value.
            Ok(()) => return Outcome::Continue,
            Err(e) => Err(e),
        },
        nr::ARCH_PRCTL => arch_prctl(ctx, a[0], a[1]),
        nr::SET_TID_ADDRESS => {
            p.clear_tid = a[0];
            Ok(p.entry.pid)
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
    const EAGAIN: i64 = 11;
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

fn le_u64(b: &[u8]) -> u64 {
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
    let desc = p.desc(fd).ok_or(EBADF)?;
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
    const FD_CLOEXEC: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_APPEND: u64 = 0o2000;
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
            Fd::Pipe(e) => u64::from(e.write) | if e.nonblock { fs::O_NONBLOCK } else { 0 },
            Fd::Object(o) => O_RDWR | if o.nonblock { fs::O_NONBLOCK } else { 0 },
        }),
        F_SETFL => {
            // Only O_APPEND and O_NONBLOCK can change after open (Linux also
            // takes O_ASYNC/O_DIRECT/O_NOATIME, which mean nothing here).
            let nb = arg & fs::O_NONBLOCK != 0;
            match &mut *desc.state() {
                Fd::File(of) => {
                    of.flags = (of.flags & !(O_APPEND | fs::O_NONBLOCK))
                        | (arg & (O_APPEND | fs::O_NONBLOCK));
                }
                Fd::Pipe(e) => e.nonblock = nb,
                Fd::Object(o) => o.nonblock = nb,
                Fd::Console | Fd::Dev(_) => {}
            }
            Ok(0)
        }
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            fs::record_lock(p, &desc, cmd, arg)
        }
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
    if !matches!(p.fd(fd).ok_or(EBADF)?, Fd::File(_)) {
        return Err(ENODEV);
    }
    if map_flags & umem::flags::MAP_SHARED != 0 && prot & 2 != 0 {
        // A shared writable mapping would need writes to reach the file.
        return Err(EACCES);
    }
    let bytes = fs::file_bytes(p, fd, offset, len)?;
    let src = umem::FileSource { bytes, offset };
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
fn clone(
    p: &mut LinuxProcess,
    ctx: &frame::user::UserContext,
    flags: u64,
    stack: u64,
    parent_tid: u64,
    child_tid: u64,
    tls: u64,
) -> Result<u64, i64> {
    const CSIGNAL: u64 = 0xff;
    const CLONE_VM: u64 = 0x100;
    const CLONE_FS: u64 = 0x200;
    const CLONE_FILES: u64 = 0x400;
    const CLONE_SIGHAND: u64 = 0x800;
    const CLONE_VFORK: u64 = 0x4000;
    const CLONE_THREAD: u64 = 0x1_0000;
    const CLONE_SYSVSEM: u64 = 0x4_0000;
    const CLONE_SETTLS: u64 = 0x8_0000;
    const CLONE_PARENT_SETTID: u64 = 0x10_0000;
    const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
    const CLONE_DETACHED: u64 = 0x40_0000;
    const CLONE_CHILD_SETTID: u64 = 0x100_0000;
    let thread = flags & CLONE_THREAD != 0;
    let allowed = CSIGNAL
        | CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_VFORK
        | CLONE_THREAD
        | CLONE_SYSVSEM
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_DETACHED
        | CLONE_CHILD_SETTID;
    if flags & !allowed != 0 {
        return Err(ENOSYS);
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
        (p.new_thread(), c)
    } else {
        proc::fork(p, ctx, stack)?
    };
    if flags & CLONE_SETTLS != 0 {
        cctx.fs_base = tls;
    }
    let tid = (child.entry.pid as u32).to_le_bytes();
    if flags & CLONE_PARENT_SETTID != 0 && p.copy_to_user(parent_tid, &tid) != tid.len() {
        return Err(EFAULT);
    }
    if flags & CLONE_CHILD_SETTID != 0 && child.copy_to_user(child_tid, &tid) != tid.len() {
        return Err(EFAULT);
    }
    if flags & CLONE_CHILD_CLEARTID != 0 {
        child.clear_tid = child_tid;
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
    /// `sizeof(struct rusage)` on x86-64.
    const RUSAGE_SIZE: usize = 144;
    match proc::wait(&p.group.leader, &p.entry, pid, options & WNOHANG != 0)? {
        None => Ok(0),
        Some((cpid, status)) => {
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
        PROCESS_CPUTIME | THREAD_CPUTIME => {
            let started = core::time::Duration::from_millis(p.group.leader.started * 10);
            frame::time::now().saturating_sub(started)
        }
        _ => return Err(EINVAL),
    };
    put_pair(p, tp, t.as_secs(), u64::from(t.subsec_nanos()))
}

fn gettimeofday(p: &mut LinuxProcess, tv: u64) -> Result<u64, i64> {
    if tv == 0 {
        return Ok(0);
    }
    let now = crate::vfs::wall_clock();
    put_pair(p, tv, now.as_secs(), u64::from(now.subsec_micros()))
}

/// `prlimit64(pid, resource, new, old)`, `getrlimit`, `setrlimit`. Limits
/// are per process and survive fork and exec; `RLIMIT_NOFILE` caps
/// descriptor numbers and `RLIMIT_STACK` sizes the stack at exec. Only the
/// calling process can be named (partial).
fn prlimit(p: &mut LinuxProcess, pid: u64, resource: u64, new: u64, old: u64) -> Result<u64, i64> {
    use crate::process::{MAX_FDS, RLIM_NLIMITS, RLIMIT_NOFILE};
    const ESRCH: i64 = 3;
    if pid != 0 && pid != p.group.tgid {
        return Err(ESRCH);
    }
    let r = usize::try_from(resource)
        .ok()
        .filter(|&r| r < RLIM_NLIMITS)
        .ok_or(EINVAL)?;
    let (cur, max) = p.group.limits()[r];
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
        // The descriptor table holds MAX_FDS entries.
        if r == RLIMIT_NOFILE && hard > MAX_FDS as u64 {
            return Err(EPERM);
        }
        p.group.set_limit(r, soft, hard);
    }
    if old != 0 {
        put_pair(p, old, cur, max)?;
    }
    Ok(0)
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
