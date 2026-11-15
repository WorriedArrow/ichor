//! The Linux x86-64 syscall personality (ADR-0002 §5), milestone 3 slice:
//! console I/O, the read-only file system, memory (`mmap`, `brk`, demand
//! paging), TLS, process identity, and exit. Signals are accepted but never
//! delivered yet. The number is in
//! `rax`, arguments in `rdi, rsi, rdx, r10, r8, r9`, and the result in
//! `rax`; on error `rax` is `-errno`.
//!
//! User memory is only ever copied (`VmSpace::copy_{from,to}_user`), never
//! borrowed. Coverage is tracked in `docs/linux-abi.md`.

use image::Kind;

use crate::process::{Fd, LinuxProcess, MAX_FDS, OpenFile};
use crate::umem;
use crate::vfs::{self, errno::*};

/// Linux x86-64 syscall numbers implemented so far. `cargo xtask
/// linux-abi-table` generates `docs/linux-abi.md` from this table: a
/// trailing `// partial: ...` or `// stub: ...` sets an entry's status.
mod nr {
    pub(super) const READ: u64 = 0; // partial: files and console (stdin is EOF)
    pub(super) const WRITE: u64 = 1; // partial: console only (the root is read-only)
    pub(super) const OPEN: u64 = 2; // partial: O_RDONLY on the read-only root
    pub(super) const CLOSE: u64 = 3;
    pub(super) const STAT: u64 = 4;
    pub(super) const FSTAT: u64 = 5;
    pub(super) const LSTAT: u64 = 6;
    pub(super) const LSEEK: u64 = 8;
    pub(super) const MMAP: u64 = 9; // partial: anonymous, and private copies of files
    pub(super) const MPROTECT: u64 = 10;
    pub(super) const MUNMAP: u64 = 11;
    pub(super) const BRK: u64 = 12;
    pub(super) const RT_SIGACTION: u64 = 13; // stub: accepted, signals are never delivered
    pub(super) const RT_SIGPROCMASK: u64 = 14; // stub: accepted, the mask is always empty
    pub(super) const IOCTL: u64 = 16; // partial: TIOCGWINSZ on the console
    pub(super) const READV: u64 = 19;
    pub(super) const WRITEV: u64 = 20; // partial: console only
    pub(super) const ACCESS: u64 = 21;
    pub(super) const SCHED_YIELD: u64 = 24;
    pub(super) const MADVISE: u64 = 28; // stub: advice is ignored
    pub(super) const DUP: u64 = 32;
    pub(super) const DUP2: u64 = 33;
    pub(super) const GETPID: u64 = 39; // partial: always 1
    pub(super) const EXIT: u64 = 60; // partial: ends the whole process (single-threaded)
    pub(super) const UNAME: u64 = 63;
    pub(super) const FCNTL: u64 = 72; // partial: F_DUPFD, F_GETFD/SETFD, F_GETFL/SETFL
    pub(super) const GETCWD: u64 = 79; // partial: the working directory is always /
    pub(super) const GETTIMEOFDAY: u64 = 96; // partial: time since boot (no RTC yet)
    pub(super) const GETRLIMIT: u64 = 97;
    pub(super) const GETUID: u64 = 102; // partial: always 0
    pub(super) const GETGID: u64 = 104; // partial: always 0
    pub(super) const GETEUID: u64 = 107; // partial: always 0
    pub(super) const GETEGID: u64 = 108; // partial: always 0
    pub(super) const GETPPID: u64 = 110; // partial: always 0
    pub(super) const SIGALTSTACK: u64 = 131; // stub: accepted, signals are never delivered
    pub(super) const ARCH_PRCTL: u64 = 158; // partial: ARCH_SET_FS only
    pub(super) const GETTID: u64 = 186; // partial: always 1
    pub(super) const FUTEX: u64 = 202; // partial: WAIT/WAKE for one thread
    pub(super) const GETDENTS64: u64 = 217;
    pub(super) const SET_TID_ADDRESS: u64 = 218; // stub: returns TID 1
    pub(super) const CLOCK_GETTIME: u64 = 228; // partial: every clock counts from boot
    pub(super) const EXIT_GROUP: u64 = 231;
    pub(super) const OPENAT: u64 = 257; // partial: AT_FDCWD or absolute paths
    pub(super) const NEWFSTATAT: u64 = 262; // partial: AT_FDCWD or absolute paths
    pub(super) const FACCESSAT: u64 = 269; // partial: AT_FDCWD or absolute paths
    pub(super) const SET_ROBUST_LIST: u64 = 273; // stub: accepted (single-threaded)
    pub(super) const DUP3: u64 = 292;
    pub(super) const PRLIMIT64: u64 = 302; // partial: reads limits, ignores new ones
}

const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EISDIR: i64 = 21;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const EROFS: i64 = 30;
const ENOSYS: i64 = 38;

const O_ACCMODE: u64 = 0o3;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_DIRECTORY: u64 = 0o200_000;
const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

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
    let result: Result<u64, i64> = match nr {
        nr::READ => read(p, a[0], a[1], a[2] as usize),
        nr::WRITE => write(p, a[0], a[1], a[2] as usize),
        nr::WRITEV => writev(p, a[0], a[1], a[2] as usize),
        nr::OPEN => open(p, AT_FDCWD, a[0], a[1]),
        nr::OPENAT => open(p, a[0] as i64, a[1], a[2]),
        nr::CLOSE => {
            if p.close(a[0]) {
                Ok(0)
            } else {
                Err(EBADF)
            }
        }
        nr::STAT => stat_path(p, AT_FDCWD, a[0], a[1], true),
        nr::LSTAT => stat_path(p, AT_FDCWD, a[0], a[1], false),
        nr::NEWFSTATAT => stat_path(p, a[0] as i64, a[1], a[2], a[3] & AT_SYMLINK_NOFOLLOW == 0),
        nr::FSTAT => fstat(p, a[0], a[1]),
        nr::LSEEK => lseek(p, a[0], a[1] as i64, a[2]),
        nr::MMAP => mmap(p, &a),
        nr::MPROTECT => p.mm.mprotect(&p.cell, a[0], a[1], a[2]),
        nr::MUNMAP => p.mm.munmap(&p.cell, a[0], a[1]),
        nr::BRK => Ok(p.mm.brk(&p.cell, a[0])),
        nr::MADVISE => Ok(0),
        nr::READV => readv(p, a[0], a[1], a[2] as usize),
        nr::IOCTL => ioctl(p, a[0], a[1], a[2]),
        nr::ACCESS => access(p, AT_FDCWD, a[0], a[1]),
        nr::FACCESSAT => access(p, a[0] as i64, a[1], a[2]),
        nr::DUP => p.dup_from(a[0], 0).ok_or(EBADF),
        nr::DUP2 => dup2(p, a[0], a[1]),
        nr::DUP3 => {
            if a[0] == a[1] {
                Err(EINVAL)
            } else {
                dup2(p, a[0], a[1])
            }
        }
        nr::FCNTL => fcntl(p, a[0], a[1], a[2]),
        nr::GETDENTS64 => getdents64(p, a[0], a[1], a[2] as usize),
        nr::GETCWD => getcwd(p, a[0], a[1]),
        nr::UNAME => uname(p, a[0]),
        nr::CLOCK_GETTIME => clock_gettime(p, a[1]),
        nr::GETTIMEOFDAY => gettimeofday(p, a[0]),
        nr::GETRLIMIT => prlimit(p, a[0], a[1]),
        nr::PRLIMIT64 => prlimit(p, a[1], a[3]),
        nr::RT_SIGACTION => zero_out(p, a[2], 32),
        nr::RT_SIGPROCMASK => zero_out(p, a[2], (a[3] as usize).min(128)),
        nr::SIGALTSTACK => zero_out(p, a[1], 24),
        nr::FUTEX => futex(p, a[0], a[1]),
        nr::SCHED_YIELD | nr::SET_ROBUST_LIST => Ok(0),
        nr::GETPID | nr::GETTID => Ok(1),
        nr::GETPPID | nr::GETUID | nr::GETGID | nr::GETEUID | nr::GETEGID => Ok(0),
        nr::ARCH_PRCTL => arch_prctl(ctx, a[0], a[1]),
        nr::SET_TID_ADDRESS => Ok(1),
        nr::EXIT | nr::EXIT_GROUP => return Outcome::Exit(a[0] as i32),
        _ => Err(ENOSYS),
    };
    ctx.set_return(match result {
        Ok(v) => v,
        Err(e) => (-e) as u64,
    });
    Outcome::Continue
}

// ---------------------------------------------------------------------------
// Console and file I/O.
// ---------------------------------------------------------------------------

fn read(p: &mut LinuxProcess, fd: u64, buf: u64, count: usize) -> Result<u64, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Console => Ok(0), // No console input yet: EOF.
        Fd::File(f) => {
            if f.node.kind() == Kind::Directory {
                return Err(EISDIR);
            }
            let mut chunk = [0u8; 512];
            let mut done = 0usize;
            let mut offset = f.offset;
            while done < count {
                let want = chunk.len().min(count - done);
                let n = f.node.read_at(offset, &mut chunk[..want]);
                if n == 0 {
                    break;
                }
                let copied = p.copy_to_user(buf + done as u64, &chunk[..n]);
                done += copied;
                offset += copied as u64;
                if copied < n {
                    if done == 0 {
                        return Err(EFAULT);
                    }
                    break;
                }
            }
            if let Some(f) = p.file_mut(fd) {
                f.offset = offset;
            }
            Ok(done as u64)
        }
    }
}

fn write(p: &mut LinuxProcess, fd: u64, buf: u64, count: usize) -> Result<u64, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Console => Ok(console_write(p, buf, count) as u64),
        Fd::File(_) => Err(EBADF), // Opened read-only (the root is read-only).
    }
}

fn writev(p: &mut LinuxProcess, fd: u64, iov: u64, iovcnt: usize) -> Result<u64, i64> {
    if !matches!(p.fd(fd).ok_or(EBADF)?, Fd::Console) {
        return Err(EBADF);
    }
    if iovcnt > 1024 {
        return Err(EINVAL);
    }
    let mut total = 0u64;
    for i in 0..iovcnt {
        // struct iovec { void *iov_base; size_t iov_len; }
        let mut hdr = [0u8; 16];
        if p.copy_from_user(iov + i as u64 * 16, &mut hdr) != 16 {
            return Err(EFAULT);
        }
        let base = le_u64(&hdr[0..8]);
        let len = le_u64(&hdr[8..16]) as usize;
        total += console_write(p, base, len) as u64;
    }
    Ok(total)
}

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
        for &b in &chunk[..got] {
            // The console is byte-oriented; print each byte as a char so
            // invalid UTF-8 cannot stop the stream.
            frame::print!("{}", char::from(b));
        }
        written += got;
    }
    written
}

fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

// ---------------------------------------------------------------------------
// Paths.
// ---------------------------------------------------------------------------

/// Copies a NUL-terminated path out of user memory.
fn user_path(p: &mut LinuxProcess, addr: u64) -> Result<alloc::string::String, i64> {
    let mut out = alloc::vec::Vec::new();
    let mut chunk = [0u8; 256];
    while out.len() < vfs::PATH_MAX {
        let got = p.copy_from_user(addr + out.len() as u64, &mut chunk);
        if got == 0 {
            return Err(EFAULT);
        }
        if let Some(nul) = chunk[..got].iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul]);
            return alloc::string::String::from_utf8(out).map_err(|_| ENOENT);
        }
        out.extend_from_slice(&chunk[..got]);
    }
    Err(ENAMETOOLONG)
}

/// Checks a `dirfd`: only `AT_FDCWD` (or an absolute path) is supported, as
/// the working directory is always `/` for now.
fn check_dirfd(dirfd: i64, path: &str) -> Result<(), i64> {
    if dirfd == AT_FDCWD || path.starts_with('/') {
        Ok(())
    } else {
        Err(EBADF)
    }
}

fn open(p: &mut LinuxProcess, dirfd: i64, path: u64, flags: u64) -> Result<u64, i64> {
    let path = user_path(p, path)?;
    check_dirfd(dirfd, &path)?;
    if flags & O_ACCMODE != 0 || flags & (O_CREAT | O_TRUNC) != 0 {
        // Anything but O_RDONLY needs the copy-on-write upper layer.
        let exists = p.vfs.resolve(&path, true).is_ok();
        return Err(if exists || flags & O_CREAT != 0 {
            EROFS
        } else {
            ENOENT
        });
    }
    let node = p.vfs.resolve(&path, true)?;
    if flags & O_DIRECTORY != 0 && node.kind() != Kind::Directory {
        return Err(ENOTDIR);
    }
    p.install(Fd::File(OpenFile { node, offset: 0 }))
        .ok_or(EMFILE)
}

fn lseek(p: &mut LinuxProcess, fd: u64, offset: i64, whence: u64) -> Result<u64, i64> {
    const SEEK_SET: u64 = 0;
    const SEEK_CUR: u64 = 1;
    const SEEK_END: u64 = 2;
    let f = p.file_mut(fd).ok_or(EBADF)?;
    let base = match whence {
        SEEK_SET => 0i64,
        SEEK_CUR => f.offset as i64,
        SEEK_END => f.node.size() as i64,
        _ => return Err(EINVAL),
    };
    let new = base.checked_add(offset).filter(|&n| n >= 0).ok_or(EINVAL)?;
    f.offset = new as u64;
    Ok(new as u64)
}

// ---------------------------------------------------------------------------
// stat.
// ---------------------------------------------------------------------------

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFCHR: u32 = 0o020_000;

/// Builds an x86-64 `struct stat` (144 bytes).
fn stat_bytes(ino: u64, mode: u32, size: u64) -> [u8; 144] {
    let mut st = [0u8; 144];
    st[0..8].copy_from_slice(&1u64.to_le_bytes()); // st_dev
    st[8..16].copy_from_slice(&ino.to_le_bytes()); // st_ino
    st[16..24].copy_from_slice(&1u64.to_le_bytes()); // st_nlink
    st[24..28].copy_from_slice(&mode.to_le_bytes()); // st_mode
    st[48..56].copy_from_slice(&size.to_le_bytes()); // st_size
    st[56..64].copy_from_slice(&4096u64.to_le_bytes()); // st_blksize
    st[64..72].copy_from_slice(&size.div_ceil(512).to_le_bytes()); // st_blocks
    st
}

fn node_stat(node: &image::Node<'static>) -> [u8; 144] {
    let kind = match node.kind() {
        Kind::File => S_IFREG,
        Kind::Directory => S_IFDIR,
        Kind::Symlink => S_IFLNK,
    };
    stat_bytes(node.inode(), kind | (node.mode & 0o7777), node.size())
}

fn put_stat(p: &mut LinuxProcess, addr: u64, st: &[u8; 144]) -> Result<u64, i64> {
    if p.copy_to_user(addr, st) == st.len() {
        Ok(0)
    } else {
        Err(EFAULT)
    }
}

fn fstat(p: &mut LinuxProcess, fd: u64, addr: u64) -> Result<u64, i64> {
    let st = match p.fd(fd).ok_or(EBADF)? {
        Fd::Console => stat_bytes(0, S_IFCHR | 0o620, 0),
        Fd::File(f) => node_stat(&f.node),
    };
    put_stat(p, addr, &st)
}

fn stat_path(
    p: &mut LinuxProcess,
    dirfd: i64,
    path: u64,
    addr: u64,
    follow: bool,
) -> Result<u64, i64> {
    let path = user_path(p, path)?;
    check_dirfd(dirfd, &path)?;
    let node = p.vfs.resolve(&path, follow)?;
    put_stat(p, addr, &node_stat(&node))
}

// ---------------------------------------------------------------------------
// Misc.
// ---------------------------------------------------------------------------

const EPERM: i64 = 1;
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

// ---------------------------------------------------------------------------
// Memory.
// ---------------------------------------------------------------------------

fn mmap(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let (addr, len, prot, map_flags, fd, offset) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    if map_flags & umem::flags::MAP_ANONYMOUS != 0 {
        return p.mm.mmap(&p.cell, addr, len, prot, map_flags, None);
    }
    let node = match p.fd(fd).ok_or(EBADF)? {
        Fd::File(f) if f.node.kind() == Kind::File => f.node,
        Fd::File(_) | Fd::Console => return Err(ENODEV),
    };
    if map_flags & umem::flags::MAP_SHARED != 0 && prot & 2 != 0 {
        return Err(EACCES); // Shared and writable needs a writable file.
    }
    let src = umem::FileSource {
        node: &node,
        offset,
    };
    p.mm.mmap(&p.cell, addr, len, prot, map_flags, Some(src))
}

// ---------------------------------------------------------------------------
// More file and descriptor calls.
// ---------------------------------------------------------------------------

const EAGAIN: i64 = 11;
const EACCES: i64 = 13;
const ENODEV: i64 = 19;
const ENOTDIR: i64 = 20;
const ENOTTY: i64 = 25;
const ERANGE: i64 = 34;

fn readv(p: &mut LinuxProcess, fd: u64, iov: u64, iovcnt: usize) -> Result<u64, i64> {
    if iovcnt > 1024 {
        return Err(EINVAL);
    }
    p.fd(fd).ok_or(EBADF)?;
    let mut total = 0u64;
    for i in 0..iovcnt {
        let mut hdr = [0u8; 16];
        if p.copy_from_user(iov + i as u64 * 16, &mut hdr) != 16 {
            return Err(EFAULT);
        }
        let (base, len) = (le_u64(&hdr[0..8]), le_u64(&hdr[8..16]) as usize);
        let n = read(p, fd, base, len)?;
        total += n;
        if (n as usize) < len {
            break;
        }
    }
    Ok(total)
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

fn access(p: &mut LinuxProcess, dirfd: i64, path: u64, mode: u64) -> Result<u64, i64> {
    const W_OK: u64 = 2;
    let path = user_path(p, path)?;
    check_dirfd(dirfd, &path)?;
    p.vfs.resolve(&path, true)?;
    if mode & W_OK != 0 {
        return Err(EROFS);
    }
    Ok(0)
}

fn dup2(p: &mut LinuxProcess, old: u64, new: u64) -> Result<u64, i64> {
    p.dup_to(old, new).ok_or(EBADF)
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
            Fd::File(_) => 0,
        }),
        _ => Err(EINVAL),
    }
}

/// `getdents64`: directory entries as `struct linux_dirent64`, including
/// `.` and `..`. The file offset counts entries.
fn getdents64(p: &mut LinuxProcess, fd: u64, buf: u64, count: usize) -> Result<u64, i64> {
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    const DT_LNK: u8 = 10;
    const HEADER: usize = 19; // d_ino, d_off, d_reclen, d_type
    let f = match p.fd(fd).ok_or(EBADF)? {
        Fd::File(f) => f,
        Fd::Console => return Err(ENOTDIR),
    };
    if f.node.kind() != Kind::Directory {
        return Err(ENOTDIR);
    }
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut index = f.offset;
    loop {
        let entry = match index {
            0 => Some((f.node.inode(), DT_DIR, ".")),
            1 => Some((f.node.inode(), DT_DIR, "..")),
            i => f.node.entries().nth((i - 2) as usize).map(|e| {
                let t = match e.kind() {
                    Kind::Directory => DT_DIR,
                    Kind::File => DT_REG,
                    Kind::Symlink => DT_LNK,
                };
                (e.inode(), t, e.name())
            }),
        };
        let Some((ino, dtype, name)) = entry else {
            break;
        };
        let reclen = (HEADER + name.len() + 1).next_multiple_of(8);
        if out.len() + reclen > count {
            if out.is_empty() {
                return Err(EINVAL);
            }
            break;
        }
        let start = out.len();
        out.extend_from_slice(&ino.to_le_bytes());
        out.extend_from_slice(&(index + 1).to_le_bytes()); // d_off
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(dtype);
        out.extend_from_slice(name.as_bytes());
        out.resize(start + reclen, 0);
        index += 1;
    }
    if p.copy_to_user(buf, &out) != out.len() {
        return Err(EFAULT);
    }
    if let Some(f) = p.file_mut(fd) {
        f.offset = index;
    }
    Ok(out.len() as u64)
}

fn getcwd(p: &mut LinuxProcess, buf: u64, size: u64) -> Result<u64, i64> {
    if size < 2 {
        return Err(ERANGE);
    }
    if p.copy_to_user(buf, b"/\0") != 2 {
        return Err(EFAULT);
    }
    Ok(2)
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

fn futex(p: &mut LinuxProcess, uaddr: u64, op: u64) -> Result<u64, i64> {
    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    match op & 0x7f {
        // With one thread nobody could wake a waiter, so a wait would hang
        // forever; report the value as already changed.
        FUTEX_WAIT => {
            let mut b = [0u8; 4];
            if p.copy_from_user(uaddr, &mut b) != 4 {
                return Err(EFAULT);
            }
            Err(EAGAIN)
        }
        FUTEX_WAKE => Ok(0),
        _ => Err(ENOSYS),
    }
}
