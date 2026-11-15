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

use crate::process::{Fd, LinuxProcess, MAX_FDS};
use crate::umem;
use crate::{proc, signal};
use fs::AT_FDCWD;

/// Linux x86-64 syscall numbers implemented so far. `cargo xtask
/// linux-abi-table` generates `docs/linux-abi.md` from this table: a
/// trailing `// partial: ...` or `// stub: ...` sets an entry's status.
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
    pub(super) const MMAP: u64 = 9; // partial: anonymous, and private copies of files
    pub(super) const MPROTECT: u64 = 10;
    pub(super) const MUNMAP: u64 = 11;
    pub(super) const BRK: u64 = 12;
    pub(super) const RT_SIGACTION: u64 = 13;
    pub(super) const RT_SIGPROCMASK: u64 = 14;
    pub(super) const RT_SIGRETURN: u64 = 15;
    pub(super) const IOCTL: u64 = 16; // partial: TIOCGWINSZ on the console
    pub(super) const PREAD64: u64 = 17;
    pub(super) const PWRITE64: u64 = 18;
    pub(super) const READV: u64 = 19;
    pub(super) const WRITEV: u64 = 20;
    pub(super) const ACCESS: u64 = 21; // partial: existence only (every process is root)
    pub(super) const PIPE: u64 = 22;
    pub(super) const SELECT: u64 = 23;
    pub(super) const SCHED_YIELD: u64 = 24;
    pub(super) const MADVISE: u64 = 28; // stub: advice is ignored
    pub(super) const PAUSE: u64 = 34;
    pub(super) const NANOSLEEP: u64 = 35;
    pub(super) const DUP: u64 = 32; // partial: the copy has its own offset
    pub(super) const DUP2: u64 = 33; // partial: the copy has its own offset
    pub(super) const GETPID: u64 = 39;
    pub(super) const SENDFILE: u64 = 40;
    pub(super) const CLONE: u64 = 56; // partial: fork, vfork-style and thread clones
    pub(super) const FORK: u64 = 57;
    pub(super) const VFORK: u64 = 58; // partial: a full copy, the parent does not wait
    pub(super) const EXECVE: u64 = 59; // partial: static ELF binaries
    pub(super) const EXIT: u64 = 60;
    pub(super) const WAIT4: u64 = 61; // partial: no rusage, no process groups
    pub(super) const KILL: u64 = 62; // partial: pid > 0 only (no process groups)
    pub(super) const UNAME: u64 = 63;
    pub(super) const FCNTL: u64 = 72; // partial: F_DUPFD, F_GETFD/SETFD, F_GETFL/SETFL
    pub(super) const FLOCK: u64 = 73; // partial: always granted (no lock table yet)
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
    pub(super) const GETTIMEOFDAY: u64 = 96; // partial: time since boot (no RTC yet)
    pub(super) const GETRLIMIT: u64 = 97;
    pub(super) const GETUID: u64 = 102; // partial: always 0
    pub(super) const GETGID: u64 = 104; // partial: always 0
    pub(super) const GETEUID: u64 = 107; // partial: always 0
    pub(super) const GETEGID: u64 = 108; // partial: always 0
    pub(super) const SETPGID: u64 = 109; // stub: no process groups yet
    pub(super) const GETPPID: u64 = 110;
    pub(super) const GETPGRP: u64 = 111; // stub: the pid
    pub(super) const SETSID: u64 = 112; // stub: the pid
    pub(super) const GETPGID: u64 = 121; // stub: the pid
    pub(super) const GETSID: u64 = 124; // stub: the pid
    pub(super) const RT_SIGSUSPEND: u64 = 130;
    pub(super) const SIGALTSTACK: u64 = 131; // stub: no alternate stacks yet
    pub(super) const MOUNT: u64 = 165; // partial: always EPERM (cells cannot mount)
    pub(super) const UMOUNT2: u64 = 166; // partial: always EPERM (cells cannot mount)
    pub(super) const STATFS: u64 = 137;
    pub(super) const FSTATFS: u64 = 138;
    pub(super) const ARCH_PRCTL: u64 = 158; // partial: ARCH_SET_FS only
    pub(super) const GETTID: u64 = 186;
    pub(super) const TKILL: u64 = 200;
    pub(super) const FUTEX: u64 = 202; // partial: private semantics only (no PI, no FUTEX_FD)
    pub(super) const EPOLL_CREATE: u64 = 213;
    pub(super) const GETDENTS64: u64 = 217;
    pub(super) const SET_TID_ADDRESS: u64 = 218;
    pub(super) const CLOCK_GETTIME: u64 = 228; // partial: every clock counts from boot
    pub(super) const CLOCK_NANOSLEEP: u64 = 230; // partial: relative sleeps only
    pub(super) const UTIMES: u64 = 235;
    pub(super) const EXIT_GROUP: u64 = 231;
    pub(super) const EPOLL_WAIT: u64 = 232;
    pub(super) const EPOLL_CTL: u64 = 233; // partial: EPOLLET is level-triggered
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
    pub(super) const PSELECT6: u64 = 270; // partial: the signal mask is ignored
    pub(super) const PPOLL: u64 = 271; // partial: the signal mask is ignored
    pub(super) const FACCESSAT: u64 = 269; // partial: existence only (every process is root)
    pub(super) const SET_ROBUST_LIST: u64 = 273; // stub: robust lists are not walked at exit
    pub(super) const UTIMENSAT: u64 = 280;
    pub(super) const EPOLL_PWAIT: u64 = 281; // partial: the signal mask is ignored
    pub(super) const EVENTFD: u64 = 284;
    pub(super) const EVENTFD2: u64 = 290;
    pub(super) const EPOLL_CREATE1: u64 = 291;
    pub(super) const DUP3: u64 = 292; // partial: the copy has its own offset
    pub(super) const PIPE2: u64 = 293; // partial: O_CLOEXEC is accepted and ignored
    pub(super) const PRLIMIT64: u64 = 302; // partial: reads limits, ignores new ones
    pub(super) const GETRANDOM: u64 = 318; // partial: not cryptographic until frame has an entropy source
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
        nr::GETRANDOM => getrandom(p, a[0], a[1] as usize),
        // Readiness.
        nr::POLL => crate::poll::poll(p, a[0], a[1], i(a[2])),
        nr::PPOLL => crate::poll::ppoll(p, a[0], a[1], a[2]),
        nr::SELECT => crate::poll::select(p, &a),
        nr::PSELECT6 => crate::poll::pselect6(p, &a),
        nr::EPOLL_CREATE => crate::poll::epoll_create(p, 0),
        nr::EPOLL_CREATE1 => crate::poll::epoll_create(p, a[0]),
        nr::EPOLL_CTL => crate::poll::epoll_ctl(p, a[0], a[1], a[2], a[3]),
        nr::EPOLL_WAIT | nr::EPOLL_PWAIT => {
            crate::poll::epoll_wait(p, a[0], a[1], a[2], i(a[3]) as i32 as i64)
        }
        nr::EVENTFD => crate::poll::eventfd(p, a[0], 0),
        nr::EVENTFD2 => crate::poll::eventfd(p, a[0], a[1]),
        nr::PIPE => fs::pipe2(p, a[0], 0),
        nr::PIPE2 => fs::pipe2(p, a[0], a[1]),
        // Descriptors.
        nr::DUP => p.dup_from(a[0], 0).ok_or(EBADF),
        nr::DUP2 => p.dup_to(a[0], a[1]).ok_or(EBADF),
        nr::DUP3 => {
            if a[0] == a[1] {
                Err(EINVAL)
            } else {
                p.dup_to(a[0], a[1]).ok_or(EBADF)
            }
        }
        nr::FCNTL => fcntl(p, a[0], a[1], a[2]),
        nr::IOCTL => ioctl(p, a[0], a[1], a[2]),
        // Memory.
        nr::MMAP => mmap(p, &a),
        nr::MPROTECT => p.mm().mprotect(a[0], a[1], a[2]),
        nr::MUNMAP => p.mm().munmap(a[0], a[1]),
        nr::BRK => Ok(p.mm().brk(a[0])),
        nr::MADVISE => Ok(0),
        // Identity, time, limits, signals, threads.
        nr::UNAME => uname(p, a[0]),
        nr::CLOCK_GETTIME => clock_gettime(p, a[1]),
        nr::GETTIMEOFDAY => gettimeofday(p, a[0]),
        nr::GETRLIMIT => prlimit(p, a[0], a[1]),
        nr::PRLIMIT64 => prlimit(p, a[1], a[3]),
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
        nr::TKILL => signal::tkill(None, a[0], a[1]),
        nr::TGKILL => signal::tkill(Some(a[0]), a[1], a[2]),
        nr::SETPGID => Ok(0),
        nr::GETPGRP | nr::SETSID | nr::GETPGID | nr::GETSID => Ok(p.group.tgid),
        nr::SIGALTSTACK => zero_out(p, a[1], 24),
        nr::FUTEX => crate::futex::futex(p, &a),
        nr::SCHED_YIELD => {
            frame::task::yield_now();
            Ok(0)
        }
        nr::SET_ROBUST_LIST => Ok(0),
        nr::GETPID => Ok(p.group.tgid),
        nr::GETTID => Ok(p.entry.pid),
        nr::GETPPID => Ok(p.entry.ppid()),
        nr::GETUID | nr::GETGID | nr::GETEUID | nr::GETEGID => Ok(0),
        // Processes.
        nr::FORK => clone(p, ctx, 17, 0, 0, 0, 0), // SIGCHLD
        nr::VFORK => clone(p, ctx, 0x4000 | 0x100 | 17, 0, 0, 0, 0), // CLONE_VFORK | CLONE_VM
        nr::CLONE => clone(p, ctx, a[0], a[1], a[2], a[3], a[4]),
        nr::WAIT4 => wait4(p, i(a[0]), a[1], a[2]),
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

/// `getrandom`: fills `buf` from the kernel generator (`/dev/urandom`).
fn getrandom(p: &mut LinuxProcess, buf: u64, len: usize) -> Result<u64, i64> {
    let n = len.min(256 * 1024);
    let mut b = alloc::vec![0u8; n];
    crate::dev::random_bytes(&mut b);
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

fn ioctl(p: &mut LinuxProcess, fd: u64, request: u64, arg: u64) -> Result<u64, i64> {
    const TIOCGWINSZ: u64 = 0x5413;
    match (p.fd(fd).ok_or(EBADF)?, request) {
        (Fd::Console, TIOCGWINSZ) => {
            // struct winsize { rows, cols, xpixel, ypixel: u16 }
            let mut b = [0u8; 8];
            b[0..2].copy_from_slice(&24u16.to_le_bytes());
            b[2..4].copy_from_slice(&80u16.to_le_bytes());
            if p.copy_to_user(arg, &b) == b.len() {
                Ok(0)
            } else {
                Err(EFAULT)
            }
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
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const O_RDWR: u64 = 2;
    let f = p.fd(fd).ok_or(EBADF)?;
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => p.dup_from(fd, arg).ok_or(EMFILE),
        F_GETFD | F_SETFD | F_SETFL => Ok(0),
        F_GETFL => Ok(match f {
            Fd::Console => O_RDWR,
            Fd::File(of) => of.flags,
            Fd::Pipe(e) => u64::from(e.write) | if e.nonblock { 0o4000 } else { 0 },
            Fd::Dev(_) => O_RDWR,
            Fd::Object(o) => O_RDWR | if o.nonblock { 0o4000 } else { 0 },
        }),
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
    let src = umem::FileSource {
        bytes: &bytes,
        offset,
    };
    p.mm().mmap(addr, len, prot, map_flags, Some(src))
}

// ---------------------------------------------------------------------------
// Processes.
// ---------------------------------------------------------------------------

/// `fork`, `vfork` and `clone`. Without `CLONE_THREAD` the child is a new
/// process (a copy-on-write copy; `CLONE_VM | CLONE_VFORK`, as
/// `posix_spawn` uses, is served the same way, which is correct because the
/// child only execs or exits). With `CLONE_THREAD` it is a new thread in the
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
        let mut c = *ctx;
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
    proc::start(child, cctx)
}

fn wait4(p: &mut LinuxProcess, pid: i64, wstatus: u64, options: u64) -> Result<u64, i64> {
    const WNOHANG: u64 = 1;
    match proc::wait(&p.group.leader, &p.entry, pid, options & WNOHANG != 0)? {
        None => Ok(0),
        Some((cpid, status)) => {
            if wstatus != 0 && p.copy_to_user(wstatus, &status.to_le_bytes()) != 4 {
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

fn clock_gettime(p: &mut LinuxProcess, tp: u64) -> Result<u64, i64> {
    let now = frame::time::now();
    put_pair(p, tp, now.as_secs(), u64::from(now.subsec_nanos()))
}

fn gettimeofday(p: &mut LinuxProcess, tv: u64) -> Result<u64, i64> {
    if tv == 0 {
        return Ok(0);
    }
    let now = frame::time::now();
    put_pair(p, tv, now.as_secs(), u64::from(now.subsec_micros()))
}

fn prlimit(p: &mut LinuxProcess, resource: u64, old: u64) -> Result<u64, i64> {
    const RLIMIT_STACK: u64 = 3;
    const RLIMIT_NOFILE: u64 = 7;
    const RLIM_INFINITY: u64 = u64::MAX;
    let (cur, max) = match resource {
        RLIMIT_STACK => (8 << 20, RLIM_INFINITY),
        RLIMIT_NOFILE => (MAX_FDS as u64, MAX_FDS as u64),
        r if r < 16 => (RLIM_INFINITY, RLIM_INFINITY),
        _ => return Err(EINVAL),
    };
    if old == 0 {
        return Ok(0);
    }
    put_pair(p, old, cur, max)
}

/// Zeroes `len` bytes at `addr` if it is non-null: the "old value" out
/// parameter of calls whose state is always empty.
fn zero_out(p: &mut LinuxProcess, addr: u64, len: usize) -> Result<u64, i64> {
    if addr == 0 {
        return Ok(0);
    }
    let z = alloc::vec![0u8; len];
    if p.copy_to_user(addr, &z) == len {
        Ok(0)
    } else {
        Err(EFAULT)
    }
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
