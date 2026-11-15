//! The Linux x86-64 syscall personality (ADR-0002 §5), milestone 3 slice:
//! console I/O, the read-only file system, TLS, and exit. The number is in
//! `rax`, arguments in `rdi, rsi, rdx, r10, r8, r9`, and the result in
//! `rax`; on error `rax` is `-errno`.
//!
//! User memory is only ever copied (`VmSpace::copy_{from,to}_user`), never
//! borrowed. Coverage is tracked in `docs/linux-abi.md`.

use image::Kind;

use crate::process::{Fd, LinuxProcess, OpenFile};
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
    pub(super) const BRK: u64 = 12; // stub: always fails, so libcs fall back to mmap
    pub(super) const WRITEV: u64 = 20; // partial: console only
    pub(super) const EXIT: u64 = 60; // partial: ends the whole process (single-threaded)
    pub(super) const ARCH_PRCTL: u64 = 158; // partial: ARCH_SET_FS only
    pub(super) const SET_TID_ADDRESS: u64 = 218; // stub: returns TID 1
    pub(super) const EXIT_GROUP: u64 = 231;
    pub(super) const OPENAT: u64 = 257; // partial: AT_FDCWD or absolute paths
    pub(super) const NEWFSTATAT: u64 = 262; // partial: AT_FDCWD or absolute paths
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
        nr::BRK => Ok(0), // No heap break yet; libcs fall back to mmap.
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
                let copied = p.cell.space().copy_to_user(buf + done as u64, &chunk[..n]);
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
        if p.cell.space().copy_from_user(iov + i as u64 * 16, &mut hdr) != 16 {
            return Err(EFAULT);
        }
        let base = le_u64(&hdr[0..8]);
        let len = le_u64(&hdr[8..16]) as usize;
        total += console_write(p, base, len) as u64;
    }
    Ok(total)
}

/// Copies up to `count` bytes from user memory to the console.
fn console_write(p: &LinuxProcess, buf: u64, count: usize) -> usize {
    let mut written = 0;
    let mut chunk = [0u8; 256];
    while written < count {
        let want = chunk.len().min(count - written);
        let got = p
            .cell
            .space()
            .copy_from_user(buf + written as u64, &mut chunk[..want]);
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
fn user_path(p: &LinuxProcess, addr: u64) -> Result<alloc::string::String, i64> {
    let mut out = alloc::vec::Vec::new();
    let mut chunk = [0u8; 256];
    while out.len() < vfs::PATH_MAX {
        let got = p
            .cell
            .space()
            .copy_from_user(addr + out.len() as u64, &mut chunk);
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

fn put_stat(p: &LinuxProcess, addr: u64, st: &[u8; 144]) -> Result<u64, i64> {
    if p.cell.space().copy_to_user(addr, st) == st.len() {
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
