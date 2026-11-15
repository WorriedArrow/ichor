//! File and path syscalls over the root overlay: open/create, read/write,
//! the stat family, directories, links, renames, permissions and the working
//! directory. Paths are resolved from the process's working directory or a
//! directory descriptor (the `*at` calls).

use alloc::string::String;
use alloc::vec::Vec;

use super::{EBADF, EFAULT, EINVAL, EMFILE, console_bytes, console_write, le_u64};
use crate::pipe::Pipe;
use crate::process::{Fd, LinuxProcess, OpenFile, PipeEnd};
use crate::vfs::{self, Ino, Kind, Stat, errno::*};
use crate::{proc, procfs, signal};

pub(super) const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;

const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200_000;
const O_NOFOLLOW: u64 = 0o400_000;
pub(super) const O_NONBLOCK: u64 = 0o4000;
pub(super) const O_CLOEXEC: u64 = 0o2_000_000;

const ENAMETOOLONG: i64 = 36;
const ESPIPE: i64 = 29;
const EACCES: i64 = 13;
const EPIPE: i64 = 32;
const ERANGE: i64 = 34;

/// Copy chunk for file I/O.
const CHUNK: usize = 4096;

/// Copies a NUL-terminated path out of user memory.
pub(super) fn user_path(p: &mut LinuxProcess, addr: u64) -> Result<String, i64> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 256];
    while out.len() < vfs::PATH_MAX {
        let got = p.copy_from_user(addr + out.len() as u64, &mut chunk);
        if got == 0 {
            return Err(EFAULT);
        }
        if let Some(nul) = chunk[..got].iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul]);
            return String::from_utf8(out).map_err(|_| ENOENT);
        }
        out.extend_from_slice(&chunk[..got]);
    }
    Err(ENAMETOOLONG)
}

/// The directory a relative path in an `*at` call starts from.
fn base(p: &LinuxProcess, dirfd: i64, path: &str) -> Result<Ino, i64> {
    if dirfd == AT_FDCWD || path.starts_with('/') {
        return Ok(p.cwd());
    }
    match p.fd(dirfd as u64).ok_or(EBADF)? {
        Fd::File(f) => Ok(f.ino),
        Fd::Console | Fd::Pipe(_) | Fd::Dev(_) | Fd::Object(_) => Err(ENOTDIR),
    }
}

/// Reads the path argument and resolves its starting directory.
fn path_at(p: &mut LinuxProcess, dirfd: i64, addr: u64) -> Result<(Ino, String), i64> {
    let path = user_path(p, addr)?;
    Ok((base(p, dirfd, &path)?, path))
}

fn file(p: &LinuxProcess, fd: u64) -> Result<OpenFile, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::File(f) => Ok(f),
        Fd::Console | Fd::Dev(_) => Err(EINVAL),
        Fd::Pipe(_) | Fd::Object(_) => Err(ESPIPE),
    }
}

// ---------------------------------------------------------------------------
// open, read, write, seek.
// ---------------------------------------------------------------------------

pub(super) fn open(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    flags: u64,
    mode: u64,
) -> Result<u64, i64> {
    let (start, path) = path_at(p, dirfd, addr)?;
    open_path(p, start, &path, flags, mode, 0)
}

/// `open` on a path string (`/proc` links come back here when followed).
fn open_path(
    p: &mut LinuxProcess,
    start: Ino,
    path: &str,
    flags: u64,
    mode: u64,
    hops: u32,
) -> Result<u64, i64> {
    let acc = flags & O_ACCMODE;
    if acc == O_ACCMODE {
        return Err(EINVAL);
    }
    if let Some(node) = procfs::lookup(p, path, flags & O_NOFOLLOW == 0) {
        return open_proc(p, start, node?, flags, mode, hops);
    }
    let umask = p.umask();
    let ino = {
        let mut fs = p.fs();
        let mut created = false;
        let ino = if flags & O_CREAT != 0 {
            let (dir, name) = fs.resolve_parent(start, path)?;
            match fs.lookup(dir, &name) {
                Ok(_) if flags & O_EXCL != 0 => return Err(EEXIST),
                Ok(_) => fs.resolve(start, path, flags & O_NOFOLLOW == 0)?,
                Err(ENOENT) => {
                    created = true;
                    fs.create(dir, &name, mode as u32 & !umask)?
                }
                Err(e) => return Err(e),
            }
        } else {
            fs.resolve(start, path, flags & O_NOFOLLOW == 0)?
        };
        let st = fs.stat(ino)?;
        // The file's permission bits, unless this call just created it.
        if !created && st.kind != Kind::Symlink {
            let mut want = match acc {
                0 => overlay::MAY_READ,
                1 => overlay::MAY_WRITE,
                _ => overlay::MAY_READ | overlay::MAY_WRITE,
            };
            if flags & O_TRUNC != 0 {
                want |= overlay::MAY_WRITE;
            }
            fs.permission(ino, want)?;
        }
        match st.kind {
            Kind::Directory if acc != 0 => return Err(EISDIR),
            Kind::Symlink => return Err(ELOOP), // O_NOFOLLOW on a symlink
            Kind::File | Kind::CharDevice if flags & O_DIRECTORY != 0 => return Err(ENOTDIR),
            Kind::CharDevice => {
                drop(fs);
                let fd = crate::dev::open(p, st.rdev, ino, flags)?;
                return p.install_flags(fd, flags & O_CLOEXEC != 0).ok_or(EMFILE);
            }
            _ => {}
        }
        if flags & O_TRUNC != 0 && acc != 0 && st.kind == Kind::File {
            fs.truncate(ino, 0)?;
        }
        fs.open(ino)?;
        ino
    };
    let f = OpenFile {
        ino,
        offset: 0,
        flags: flags & (O_ACCMODE | O_APPEND | O_NONBLOCK),
    };
    p.install_flags(Fd::File(f), flags & O_CLOEXEC != 0)
        .ok_or(EMFILE)
}

/// Where a `/proc` link points, as a path to open or stat.
fn proc_target(target: &str) -> alloc::string::String {
    if target.starts_with('/') {
        alloc::string::String::from(target)
    } else {
        alloc::format!("/proc/{target}")
    }
}

/// Opens a `/proc` node: a snapshot file, a directory, or a followed link.
fn open_proc(
    p: &mut LinuxProcess,
    start: Ino,
    node: procfs::Node,
    flags: u64,
    mode: u64,
    hops: u32,
) -> Result<u64, i64> {
    let obj: alloc::sync::Arc<dyn crate::poll::Object> = match node {
        procfs::Node::Link(t) => {
            if hops >= 8 {
                return Err(ELOOP);
            }
            return open_path(p, start, &proc_target(&t), flags, mode, hops + 1);
        }
        procfs::Node::Dir(_) if flags & O_ACCMODE != 0 => return Err(EISDIR),
        procfs::Node::Dir(e) => alloc::sync::Arc::new(procfs::ProcDir::new(e)),
        procfs::Node::File(_) if flags & O_DIRECTORY != 0 => return Err(ENOTDIR),
        procfs::Node::File(_) if flags & O_ACCMODE != 0 => return Err(EACCES),
        procfs::Node::File(d) => alloc::sync::Arc::new(procfs::ProcFile::new(d)),
    };
    p.install_flags(
        Fd::Object(crate::process::ObjectEnd {
            obj,
            nonblock: false,
        }),
        flags & O_CLOEXEC != 0,
    )
    .ok_or(EMFILE)
}

/// `stat` of a `/proc` node (following links if `follow`).
fn stat_proc(p: &mut LinuxProcess, path: &str, follow: bool, hops: u32) -> Result<[u8; 144], i64> {
    let node = procfs::lookup(p, path, follow).ok_or(ENOENT)??;
    Ok(match node {
        procfs::Node::Link(t) if follow => {
            if hops >= 8 {
                return Err(ELOOP);
            }
            let target = proc_target(&t);
            if target.starts_with("/proc") {
                return stat_proc(p, &target, true, hops + 1);
            }
            let cwd = p.cwd();
            let mut fs = p.fs();
            let ino = fs.resolve(cwd, &target, true)?;
            to_stat(&fs.stat(ino)?)
        }
        procfs::Node::Link(t) => stat_bytes(0, S_IFLNK | 0o777, 1, t.len() as u64),
        procfs::Node::Dir(_) => stat_bytes(0, S_IFDIR | 0o555, 2, 0),
        procfs::Node::File(_) => stat_bytes(0, S_IFREG | 0o444, 1, 0),
    })
}

/// Reads from file `f` at `offset` into user memory; returns bytes read.
fn read_file(
    p: &mut LinuxProcess,
    f: OpenFile,
    offset: u64,
    buf: u64,
    count: usize,
) -> Result<u64, i64> {
    if f.flags & O_ACCMODE == O_WRONLY {
        return Err(EBADF);
    }
    let mut chunk = alloc::vec![0u8; CHUNK.min(count.max(1))];
    let mut done = 0usize;
    while done < count {
        let want = chunk.len().min(count - done);
        let n = p
            .vfs
            .read(f.ino, offset + done as u64, &mut chunk[..want])?;
        if n == 0 {
            break;
        }
        let copied = p.copy_to_user(buf + done as u64, &chunk[..n]);
        done += copied;
        if copied < n {
            if done == 0 {
                return Err(EFAULT);
            }
            break;
        }
    }
    Ok(done as u64)
}

/// Writes user memory to file `f` at `offset`; returns bytes written.
/// Writes user memory to file `f` at `offset` (or at its end, for
/// `O_APPEND`); returns the bytes written and the offset after them. An
/// append of up to `APPEND_ATOMIC` bytes is one atomic step, so concurrent
/// appenders (other descriptions too) never interleave within a write.
fn write_file(
    p: &mut LinuxProcess,
    f: OpenFile,
    offset: u64,
    buf: u64,
    count: usize,
) -> Result<(u64, u64), i64> {
    const APPEND_ATOMIC: usize = 1 << 20;
    if f.flags & O_ACCMODE == 0 {
        return Err(EBADF);
    }
    let append = f.flags & O_APPEND != 0;
    let step = if append && count <= APPEND_ATOMIC {
        count.max(1)
    } else {
        CHUNK.min(count.max(1))
    };
    let mut chunk = alloc::vec![0u8; step];
    let mut done = 0usize;
    let mut pos = offset;
    while done < count {
        let want = chunk.len().min(count - done);
        let got = p.copy_from_user(buf + done as u64, &mut chunk[..want]);
        if got == 0 {
            if done == 0 {
                return Err(EFAULT);
            }
            break;
        }
        let r = if append {
            p.fs().append(f.ino, &chunk[..got]).map(|end| {
                pos = end;
                got
            })
        } else {
            p.vfs
                .lock()
                .write(f.ino, pos, &chunk[..got])
                .inspect(|&n| pos += n as u64)
        };
        match r {
            Ok(n) => done += n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok((done as u64, pos))
}

pub(super) fn read(p: &mut LinuxProcess, fd: u64, buf: u64, count: usize) -> Result<u64, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Console => Ok(0), // No console input yet: EOF.
        Fd::Object(o) => {
            let entry = p.entry.clone();
            let bytes = o
                .obj
                .read(count, o.nonblock, &|| proc::interrupted(&entry))?;
            if p.copy_to_user(buf, &bytes) != bytes.len() {
                return Err(EFAULT);
            }
            Ok(bytes.len() as u64)
        }
        Fd::Dev(d) => {
            let mut chunk = alloc::vec![0u8; CHUNK.min(count)];
            let n = d.read(&mut chunk);
            if p.copy_to_user(buf, &chunk[..n]) != n {
                return Err(EFAULT);
            }
            Ok(n as u64)
        }
        Fd::Pipe(e) if e.write => Err(EBADF),
        Fd::Pipe(e) => {
            let mut chunk = alloc::vec![0u8; CHUNK.min(count)];
            let entry = p.entry.clone();
            let n = e
                .pipe
                .read(&mut chunk, e.nonblock, &|| proc::interrupted(&entry))?;
            if p.copy_to_user(buf, &chunk[..n]) != n {
                return Err(EFAULT);
            }
            Ok(n as u64)
        }
        Fd::File(_) => {
            // Hold the description across the read: its offset is shared.
            let desc = p.desc(fd).ok_or(EBADF)?;
            let mut st = desc.state();
            let Fd::File(of) = &mut *st else {
                return Err(EBADF);
            };
            let n = read_file(p, *of, of.offset, buf, count)?;
            of.offset += n;
            Ok(n)
        }
    }
}

pub(super) fn write(p: &mut LinuxProcess, fd: u64, buf: u64, count: usize) -> Result<u64, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Console => Ok(console_write(p, buf, count) as u64),
        Fd::Dev(d) => d.write(count).map(|n| n as u64),
        Fd::Object(o) => {
            let mut data = alloc::vec![0u8; count.min(CHUNK)];
            if p.copy_from_user(buf, &mut data) != data.len() {
                return Err(EFAULT);
            }
            let entry = p.entry.clone();
            let r = o
                .obj
                .write(&data, o.nonblock, &|| proc::interrupted(&entry));
            // A socket whose peer is gone (only sockets answer EPIPE here).
            if r == Err(EPIPE) {
                proc::post(&p.entry, signal::SIGPIPE);
            }
            r.map(|n| n as u64)
        }
        Fd::Pipe(e) if !e.write => Err(EBADF),
        Fd::Pipe(e) => pipe_write(p, &e, buf, count),
        Fd::File(_) => {
            let desc = p.desc(fd).ok_or(EBADF)?;
            let mut st = desc.state();
            let Fd::File(of) = &mut *st else {
                return Err(EBADF);
            };
            let (n, end) = write_file(p, *of, of.offset, buf, count)?;
            of.offset = end;
            Ok(n)
        }
    }
}

pub(super) fn pread(
    p: &mut LinuxProcess,
    fd: u64,
    buf: u64,
    count: usize,
    off: u64,
) -> Result<u64, i64> {
    let f = file(p, fd)?;
    read_file(p, f, off, buf, count)
}

pub(super) fn pwrite(
    p: &mut LinuxProcess,
    fd: u64,
    buf: u64,
    count: usize,
    off: u64,
) -> Result<u64, i64> {
    let f = file(p, fd)?;
    write_file(p, f, off, buf, count).map(|(n, _)| n)
}

/// `readv` (`write == false`) and `writev`.
pub(super) fn vector(
    p: &mut LinuxProcess,
    fd: u64,
    iov: u64,
    iovcnt: usize,
    is_write: bool,
) -> Result<u64, i64> {
    if iovcnt > 1024 {
        return Err(EINVAL);
    }
    p.fd(fd).ok_or(EBADF)?;
    let mut total = 0u64;
    for i in 0..iovcnt {
        // struct iovec { void *iov_base; size_t iov_len; }
        let mut hdr = [0u8; 16];
        if p.copy_from_user(iov + i as u64 * 16, &mut hdr) != 16 {
            return Err(EFAULT);
        }
        let (base, len) = (le_u64(&hdr[0..8]), le_u64(&hdr[8..16]) as usize);
        let n = if is_write {
            write(p, fd, base, len)?
        } else {
            read(p, fd, base, len)?
        };
        total += n;
        if (n as usize) < len {
            break;
        }
    }
    Ok(total)
}

pub(super) fn lseek(p: &mut LinuxProcess, fd: u64, offset: i64, whence: u64) -> Result<u64, i64> {
    const SEEK_SET: u64 = 0;
    const SEEK_CUR: u64 = 1;
    const SEEK_END: u64 = 2;
    let f = file(p, fd).map_err(|_| ESPIPE)?;
    let base = match whence {
        SEEK_SET => 0i64,
        SEEK_CUR => f.offset as i64,
        SEEK_END => p.fs().stat(f.ino)?.size as i64,
        _ => return Err(EINVAL),
    };
    let new = base.checked_add(offset).filter(|&n| n >= 0).ok_or(EINVAL)?;
    p.with_file(fd, |of| {
        of.offset = new as u64;
    });
    Ok(new as u64)
}

pub(super) fn ftruncate(p: &mut LinuxProcess, fd: u64, len: u64) -> Result<u64, i64> {
    let f = file(p, fd)?;
    if f.flags & O_ACCMODE == 0 {
        return Err(EINVAL);
    }
    p.fs().truncate(f.ino, len)?;
    Ok(0)
}

pub(super) fn truncate(p: &mut LinuxProcess, addr: u64, len: u64) -> Result<u64, i64> {
    let (start, path) = path_at(p, AT_FDCWD, addr)?;
    let mut fs = p.fs();
    let ino = fs.resolve(start, &path, true)?;
    if fs.stat(ino)?.kind == Kind::Directory {
        return Err(EISDIR);
    }
    fs.permission(ino, overlay::MAY_WRITE)?;
    fs.truncate(ino, len)?;
    Ok(0)
}

/// `fsync`/`fdatasync`: the upper layer is memory, so there is nothing to
/// flush yet.
pub(super) fn fsync(p: &mut LinuxProcess, fd: u64) -> Result<u64, i64> {
    p.fd(fd).ok_or(EBADF).map(|_| 0)
}

// ---------------------------------------------------------------------------
// stat.
// ---------------------------------------------------------------------------

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;

/// Builds an x86-64 `struct stat` (144 bytes).
fn stat_bytes(ino: u64, mode: u32, nlink: u32, size: u64) -> [u8; 144] {
    let mut st = [0u8; 144];
    st[0..8].copy_from_slice(&1u64.to_le_bytes()); // st_dev
    st[8..16].copy_from_slice(&ino.to_le_bytes()); // st_ino
    st[16..24].copy_from_slice(&u64::from(nlink).to_le_bytes()); // st_nlink
    st[24..28].copy_from_slice(&mode.to_le_bytes()); // st_mode
    st[48..56].copy_from_slice(&size.to_le_bytes()); // st_size
    st[56..64].copy_from_slice(&4096u64.to_le_bytes()); // st_blksize
    st[64..72].copy_from_slice(&size.div_ceil(512).to_le_bytes()); // st_blocks
    st
}

/// Fills `st_uid`/`st_gid` and the three timestamps of a `struct stat`.
fn put_owner_times(st: &mut [u8; 144], s: &Stat) {
    st[28..32].copy_from_slice(&s.uid.to_le_bytes());
    st[32..36].copy_from_slice(&s.gid.to_le_bytes());
    for (off, t) in [(72, s.atime), (88, s.mtime), (104, s.ctime)] {
        st[off..off + 8].copy_from_slice(&t.sec.to_le_bytes());
        st[off + 8..off + 16].copy_from_slice(&u64::from(t.nsec).to_le_bytes());
    }
}

fn to_stat(s: &Stat) -> [u8; 144] {
    let kind = match s.kind {
        Kind::File => S_IFREG,
        Kind::Directory => S_IFDIR,
        Kind::Symlink => S_IFLNK,
        Kind::CharDevice => S_IFCHR,
    };
    let mut st = stat_bytes(s.ino, kind | s.mode, s.nlink, s.size);
    st[40..48].copy_from_slice(&u64::from(s.rdev).to_le_bytes()); // st_rdev
    put_owner_times(&mut st, s);
    st
}

fn put_stat(p: &mut LinuxProcess, addr: u64, st: &[u8; 144]) -> Result<u64, i64> {
    if p.copy_to_user(addr, st) == st.len() {
        Ok(0)
    } else {
        Err(EFAULT)
    }
}

pub(super) fn fstat(p: &mut LinuxProcess, fd: u64, addr: u64) -> Result<u64, i64> {
    let st = fstat_raw(p, fd)?;
    put_stat(p, addr, &st)
}

fn fstat_raw(p: &mut LinuxProcess, fd: u64) -> Result<[u8; 144], i64> {
    Ok(match p.fd(fd).ok_or(EBADF)? {
        Fd::Console => stat_bytes(0, S_IFCHR | 0o620, 1, 0),
        Fd::Pipe(_) => stat_bytes(0, S_IFIFO | 0o600, 1, 0),
        Fd::Object(o) => match o.obj.tty() {
            // A terminal stats as the node it was opened through, which
            // `ttyname` checks.
            Some(t) => to_stat(&p.fs().stat(t.ino())?),
            None => stat_bytes(0, o.obj.mode() | 0o600, 1, 0),
        },
        Fd::Dev(d) => {
            let mut st = stat_bytes(0, S_IFCHR | 0o666, 1, 0);
            st[40..48].copy_from_slice(&u64::from(d.rdev()).to_le_bytes()); // st_rdev
            st
        }
        Fd::File(f) => to_stat(&p.fs().stat(f.ino)?),
    })
}

pub(super) fn fstatat(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    out: u64,
    flags: u64,
) -> Result<u64, i64> {
    let path = user_path(p, addr)?;
    if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
        if dirfd == AT_FDCWD {
            let cwd = p.cwd();
            let st = to_stat(&p.fs().stat(cwd)?);
            return put_stat(p, out, &st);
        }
        return fstat(p, dirfd as u64, out);
    }
    if (path.starts_with("/proc") || path.starts_with("/sys"))
        && procfs::lookup(p, &path, false).is_some()
    {
        let st = stat_proc(p, &path, flags & AT_SYMLINK_NOFOLLOW == 0, 0)?;
        return put_stat(p, out, &st);
    }
    let start = base(p, dirfd, &path)?;
    let st = {
        let mut fs = p.fs();
        let ino = fs.resolve(start, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
        to_stat(&fs.stat(ino)?)
    };
    put_stat(p, out, &st)
}

/// `statx(dirfd, path, flags, mask, buf)`: the `fstatat` result in
/// `struct statx` form, with `STATX_BASIC_STATS` (no birth time).
pub(super) fn statx(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    flags: u64,
    buf: u64,
) -> Result<u64, i64> {
    const AT_NO_AUTOMOUNT: u64 = 0x800;
    const AT_STATX_SYNC_TYPE: u64 = 0x6000;
    const STATX_BASIC_STATS: u32 = 0x7ff;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE) != 0
        || flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE
    {
        return Err(EINVAL);
    }
    // Build the `struct stat` in a scratch page of the caller's stack-free
    // kernel buffer: fstatat writes user memory, so run it on a kernel copy.
    let st = stat_raw(
        p,
        dirfd,
        addr,
        flags & (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH),
    )?;
    let u64_at = |o: usize| u64::from_le_bytes(st[o..o + 8].try_into().unwrap_or([0; 8]));
    let u32_at = |o: usize| u32::from_le_bytes(st[o..o + 4].try_into().unwrap_or([0; 4]));
    let mut x = [0u8; 256];
    x[0..4].copy_from_slice(&STATX_BASIC_STATS.to_le_bytes());
    x[4..8].copy_from_slice(&(u64_at(56) as u32).to_le_bytes()); // blksize
    x[16..20].copy_from_slice(&(u64_at(16) as u32).to_le_bytes()); // nlink
    x[20..24].copy_from_slice(&u32_at(28).to_le_bytes()); // uid
    x[24..28].copy_from_slice(&u32_at(32).to_le_bytes()); // gid
    x[28..30].copy_from_slice(&(u32_at(24) as u16).to_le_bytes()); // mode
    x[32..40].copy_from_slice(&u64_at(8).to_le_bytes()); // ino
    x[40..48].copy_from_slice(&u64_at(48).to_le_bytes()); // size
    x[48..56].copy_from_slice(&u64_at(64).to_le_bytes()); // blocks
    for (src, dst) in [(72, 64), (104, 96), (88, 112)] {
        // atime, ctime, mtime: tv_sec i64, tv_nsec u32
        x[dst..dst + 8].copy_from_slice(&u64_at(src).to_le_bytes());
        x[dst + 8..dst + 12].copy_from_slice(&(u64_at(src + 8) as u32).to_le_bytes());
    }
    let rdev = u64_at(40);
    x[128..132].copy_from_slice(&(((rdev >> 8) & 0xfff) as u32).to_le_bytes());
    x[132..136].copy_from_slice(&((rdev & 0xff) as u32).to_le_bytes());
    x[140..144].copy_from_slice(&1u32.to_le_bytes()); // dev minor 1
    if p.copy_to_user(buf, &x) != x.len() {
        return Err(EFAULT);
    }
    Ok(0)
}

/// `fstatat`'s `struct stat`, in kernel memory.
fn stat_raw(p: &mut LinuxProcess, dirfd: i64, addr: u64, flags: u64) -> Result<[u8; 144], i64> {
    let path = user_path(p, addr)?;
    if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
        if dirfd == AT_FDCWD {
            let cwd = p.cwd();
            return Ok(to_stat(&p.fs().stat(cwd)?));
        }
        return fstat_raw(p, dirfd as u64);
    }
    if (path.starts_with("/proc") || path.starts_with("/sys"))
        && procfs::lookup(p, &path, false).is_some()
    {
        return stat_proc(p, &path, flags & AT_SYMLINK_NOFOLLOW == 0, 0);
    }
    let start = base(p, dirfd, &path)?;
    let mut fs = p.fs();
    let ino = fs.resolve(start, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
    Ok(to_stat(&fs.stat(ino)?))
}

pub(super) fn stat(p: &mut LinuxProcess, addr: u64, out: u64, follow: bool) -> Result<u64, i64> {
    let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
    fstatat(p, AT_FDCWD, addr, out, flags)
}

pub(super) fn access(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    mode: u64,
    flags: u64,
) -> Result<u64, i64> {
    let (start, path) = path_at(p, dirfd, addr)?;
    if let Some(node) = procfs::lookup(p, &path, true) {
        return node.map(|_| 0);
    }
    // Checked with the real ids (AT_EACCESS: effective), as Linux does.
    const AT_EACCESS: u64 = 0x200;
    let c = p.group.creds();
    let cred = if flags & AT_EACCESS != 0 {
        c.fs()
    } else {
        c.real()
    };
    let mut fs = p.vfs.lock_as(cred);
    let ino = fs.resolve(start, &path, true)?;
    let mask = (mode & 7) as u32;
    if mask != 0 {
        fs.permission(ino, mask)?;
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Directories.
// ---------------------------------------------------------------------------

/// `getdents64`: directory entries as `struct linux_dirent64`, `.` and `..`
/// first, then entries in name order. The file offset counts entries.
pub(super) fn getdents64(
    p: &mut LinuxProcess,
    fd: u64,
    buf: u64,
    count: usize,
) -> Result<u64, i64> {
    const DT_CHR: u8 = 2;
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    const DT_LNK: u8 = 10;
    const HEADER: usize = 19; // d_ino, d_off, d_reclen, d_type
    if let Some(Fd::Object(o)) = p.fd(fd)
        && let Some((entries, pos)) = o.obj.dir()
    {
        let mut out: Vec<u8> = Vec::new();
        let mut index = *pos.lock();
        while let Some((name, dtype)) = entries.get(index as usize) {
            let reclen = (19 + name.len() + 1).next_multiple_of(8);
            if out.len() + reclen > count {
                if out.is_empty() {
                    return Err(EINVAL);
                }
                break;
            }
            let start = out.len();
            out.extend_from_slice(&(index + 1).to_le_bytes()); // d_ino
            out.extend_from_slice(&(index + 1).to_le_bytes()); // d_off
            out.extend_from_slice(&(reclen as u16).to_le_bytes());
            out.push(*dtype);
            out.extend_from_slice(name.as_bytes());
            out.resize(start + reclen, 0);
            index += 1;
        }
        if p.copy_to_user(buf, &out) != out.len() {
            return Err(EFAULT);
        }
        *pos.lock() = index;
        return Ok(out.len() as u64);
    }
    let f = file(p, fd).map_err(|_| ENOTDIR)?;
    let (me, parent, entries) = {
        let mut fs = p.fs();
        if fs.stat(f.ino)?.kind != Kind::Directory {
            return Err(ENOTDIR);
        }
        let parent = fs.lookup(f.ino, "..")?;
        let mut list = Vec::new();
        for (name, ino, kind) in fs.readdir(f.ino)? {
            list.push((name, fs.stat(ino)?.ino, kind));
        }
        (fs.stat(f.ino)?.ino, fs.stat(parent)?.ino, list)
    };
    let mut out: Vec<u8> = Vec::new();
    let mut index = f.offset;
    loop {
        let entry = match index {
            0 => Some((me, DT_DIR, ".")),
            1 => Some((parent, DT_DIR, "..")),
            i => entries.get((i - 2) as usize).map(|(n, ino, k)| {
                let t = match k {
                    Kind::Directory => DT_DIR,
                    Kind::File => DT_REG,
                    Kind::Symlink => DT_LNK,
                    Kind::CharDevice => DT_CHR,
                };
                (*ino, t, n.as_str())
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
    p.with_file(fd, |of| {
        of.offset = index;
    });
    Ok(out.len() as u64)
}

pub(super) fn mkdir(p: &mut LinuxProcess, dirfd: i64, addr: u64, mode: u64) -> Result<u64, i64> {
    let (start, path) = path_at(p, dirfd, addr)?;
    let umask = p.umask();
    let mut fs = p.fs();
    let (dir, name) = fs.resolve_parent(start, &path)?;
    fs.mkdir(dir, &name, mode as u32 & !umask)?;
    Ok(0)
}

pub(super) fn unlink(p: &mut LinuxProcess, dirfd: i64, addr: u64, flags: u64) -> Result<u64, i64> {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(EINVAL);
    }
    let (start, path) = path_at(p, dirfd, addr)?;
    let mut fs = p.fs();
    let (dir, name) = fs.resolve_parent(start, &path)?;
    if flags & AT_REMOVEDIR != 0 {
        fs.rmdir(dir, &name)?;
    } else {
        fs.unlink(dir, &name)?;
    }
    Ok(0)
}

pub(super) fn rename(
    p: &mut LinuxProcess,
    olddirfd: i64,
    oldaddr: u64,
    newdirfd: i64,
    newaddr: u64,
    flags: u64,
) -> Result<u64, i64> {
    const RENAME_NOREPLACE: u64 = 1;
    if flags & !RENAME_NOREPLACE != 0 {
        return Err(EINVAL);
    }
    let (ostart, opath) = path_at(p, olddirfd, oldaddr)?;
    let (nstart, npath) = path_at(p, newdirfd, newaddr)?;
    let mut fs = p.fs();
    let (odir, oname) = fs.resolve_parent(ostart, &opath)?;
    let (ndir, nname) = fs.resolve_parent(nstart, &npath)?;
    if flags & RENAME_NOREPLACE != 0 && fs.lookup(ndir, &nname).is_ok() {
        return Err(EEXIST);
    }
    fs.rename(odir, &oname, ndir, &nname)?;
    Ok(0)
}

pub(super) fn symlink(
    p: &mut LinuxProcess,
    target: u64,
    dirfd: i64,
    addr: u64,
) -> Result<u64, i64> {
    let target = user_path(p, target)?;
    let (start, path) = path_at(p, dirfd, addr)?;
    let mut fs = p.fs();
    let (dir, name) = fs.resolve_parent(start, &path)?;
    fs.symlink(dir, &name, &target)?;
    Ok(0)
}

/// `link` / `linkat(olddirfd, oldpath, newdirfd, newpath, flags)`: a hard
/// link. The old path's last symlink is not followed unless
/// `AT_SYMLINK_FOLLOW`; `AT_EMPTY_PATH` links the file `olddirfd` names.
pub(super) fn link(
    p: &mut LinuxProcess,
    odirfd: i64,
    oaddr: u64,
    ndirfd: i64,
    naddr: u64,
    flags: u64,
) -> Result<u64, i64> {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    // inode_at follows unless AT_SYMLINK_NOFOLLOW; link's default is not to.
    let follow = if flags & AT_SYMLINK_FOLLOW != 0 {
        0
    } else {
        AT_SYMLINK_NOFOLLOW
    };
    let ino = inode_at(p, odirfd, oaddr, (flags & AT_EMPTY_PATH) | follow)?;
    let (start, path) = path_at(p, ndirfd, naddr)?;
    let mut fs = p.fs();
    let (dir, name) = fs.resolve_parent(start, &path)?;
    fs.link(ino, dir, &name)?;
    Ok(0)
}

pub(super) fn readlink(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    buf: u64,
    size: u64,
) -> Result<u64, i64> {
    if size == 0 {
        return Err(EINVAL);
    }
    let (start, path) = path_at(p, dirfd, addr)?;
    if let Some(node) = procfs::lookup(p, &path, false) {
        let procfs::Node::Link(t) = node? else {
            return Err(EINVAL);
        };
        let n = t.len().min(size as usize);
        if p.copy_to_user(buf, &t.as_bytes()[..n]) != n {
            return Err(EFAULT);
        }
        return Ok(n as u64);
    }
    let target = {
        let mut fs = p.fs();
        let ino = fs.resolve(start, &path, false)?;
        fs.readlink(ino)?
    };
    // No NUL terminator, truncated to the buffer (like Linux).
    let n = target.len().min(size as usize);
    if p.copy_to_user(buf, &target.as_bytes()[..n]) != n {
        return Err(EFAULT);
    }
    Ok(n as u64)
}

pub(super) fn chmod(p: &mut LinuxProcess, dirfd: i64, addr: u64, mode: u64) -> Result<u64, i64> {
    let (start, path) = path_at(p, dirfd, addr)?;
    let mut fs = p.fs();
    let ino = fs.resolve(start, &path, true)?;
    fs.chmod(ino, mode as u32)?;
    Ok(0)
}

pub(super) fn fchmod(p: &mut LinuxProcess, fd: u64, mode: u64) -> Result<u64, i64> {
    let f = file(p, fd)?;
    p.fs().chmod(f.ino, mode as u32)?;
    Ok(0)
}

pub(super) fn chdir(p: &mut LinuxProcess, addr: u64) -> Result<u64, i64> {
    let (start, path) = path_at(p, AT_FDCWD, addr)?;
    let ino = {
        let mut fs = p.fs();
        let ino = fs.resolve(start, &path, true)?;
        if fs.stat(ino)?.kind != Kind::Directory {
            return Err(ENOTDIR);
        }
        fs.permission(ino, overlay::MAY_EXEC)?;
        ino
    };
    p.set_cwd(ino);
    Ok(0)
}

pub(super) fn fchdir(p: &mut LinuxProcess, fd: u64) -> Result<u64, i64> {
    let f = file(p, fd)?;
    if p.fs().stat(f.ino)?.kind != Kind::Directory {
        return Err(ENOTDIR);
    }
    p.set_cwd(f.ino);
    Ok(0)
}

pub(super) fn getcwd(p: &mut LinuxProcess, buf: u64, size: u64) -> Result<u64, i64> {
    let cwd = p.cwd();
    let mut path = p.fs().path(cwd)?;
    path.push('\0');
    if (size as usize) < path.len() {
        return Err(ERANGE);
    }
    if p.copy_to_user(buf, path.as_bytes()) != path.len() {
        return Err(EFAULT);
    }
    Ok(path.len() as u64)
}

pub(super) fn umask(p: &mut LinuxProcess, mask: u64) -> Result<u64, i64> {
    Ok(u64::from(p.set_umask(mask as u32 & 0o777)))
}

/// `sendfile`: copies from file `in_fd` (at `*offp`, or its offset) to
/// `out_fd` (the console or a file) inside the kernel.
pub(super) fn sendfile(
    p: &mut LinuxProcess,
    out_fd: u64,
    in_fd: u64,
    offp: u64,
    count: usize,
) -> Result<u64, i64> {
    let src = file(p, in_fd)?;
    let out = p.fd(out_fd).ok_or(EBADF)?;
    if let Fd::File(o) = out
        && o.flags & O_ACCMODE == 0
    {
        return Err(EBADF);
    }
    let mut offset = if offp != 0 {
        let mut b = [0u8; 8];
        if p.copy_from_user(offp, &mut b) != 8 {
            return Err(EFAULT);
        }
        u64::from_le_bytes(b)
    } else {
        src.offset
    };
    let mut buf = alloc::vec![0u8; CHUNK];
    let mut done = 0usize;
    while done < count {
        let want = CHUNK.min(count - done);
        let n = p.vfs.read(src.ino, offset, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        match p.fd(out_fd).ok_or(EBADF)? {
            Fd::Console => console_bytes(&buf[..n]),
            Fd::Dev(d) => {
                d.write(n)?;
            }
            Fd::Object(o) => {
                let entry = p.entry.clone();
                o.obj
                    .write(&buf[..n], o.nonblock, &|| proc::interrupted(&entry))?;
            }
            Fd::Pipe(e) if !e.write => return Err(EBADF),
            Fd::Pipe(e) => {
                let entry = p.entry.clone();
                e.pipe
                    .write(&buf[..n], e.nonblock, &|| proc::interrupted(&entry))?;
            }
            Fd::File(o) => {
                let at = if o.flags & O_APPEND != 0 {
                    p.fs().stat(o.ino)?.size
                } else {
                    o.offset
                };
                p.fs().write(o.ino, at, &buf[..n])?;
                p.with_file(out_fd, |of| {
                    of.offset = at + n as u64;
                });
            }
        }
        offset += n as u64;
        done += n;
    }
    if offp != 0 {
        if p.copy_to_user(offp, &offset.to_le_bytes()) != 8 {
            return Err(EFAULT);
        }
    } else {
        p.with_file(in_fd, |f| f.offset = offset);
    }
    Ok(done as u64)
}

/// Writes user memory to a pipe's write end, in chunks.
fn pipe_write(p: &mut LinuxProcess, e: &PipeEnd, buf: u64, count: usize) -> Result<u64, i64> {
    let mut chunk = alloc::vec![0u8; CHUNK.min(count.max(1))];
    let mut done = 0usize;
    while done < count {
        let want = chunk.len().min(count - done);
        let got = p.copy_from_user(buf + done as u64, &mut chunk[..want]);
        if got == 0 {
            return if done == 0 {
                Err(EFAULT)
            } else {
                Ok(done as u64)
            };
        }
        let entry = p.entry.clone();
        match e
            .pipe
            .write(&chunk[..got], e.nonblock, &|| proc::interrupted(&entry))
        {
            Ok(n) => done += n,
            Err(err) => {
                if err == EPIPE {
                    proc::post(&p.entry, signal::SIGPIPE);
                }
                if done == 0 {
                    return Err(err);
                }
                break;
            }
        }
    }
    Ok(done as u64)
}

/// `pipe2`: a new pipe; `[read fd, write fd]` go to `fds` as two `int`s.
pub(super) fn pipe2(p: &mut LinuxProcess, fds: u64, flags: u64) -> Result<u64, i64> {
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let pipe = Pipe::new();
    let nonblock = flags & O_NONBLOCK != 0;
    let end = |write| {
        Fd::Pipe(PipeEnd {
            pipe: pipe.clone(),
            write,
            nonblock,
        })
    };
    let cloexec = flags & O_CLOEXEC != 0;
    let r = p.install_flags(end(false), cloexec).ok_or(EMFILE)?;
    let w = match p.install_flags(end(true), cloexec) {
        Some(w) => w,
        None => {
            p.close(r);
            return Err(EMFILE);
        }
    };
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(r as u32).to_le_bytes());
    out[4..].copy_from_slice(&(w as u32).to_le_bytes());
    if p.copy_to_user(fds, &out) != out.len() {
        p.close(r);
        p.close(w);
        return Err(EFAULT);
    }
    Ok(0)
}

/// The `struct statfs` (120 bytes) for the root, or `/proc` if `proc`.
fn statfs_bytes(p: &LinuxProcess, proc: bool) -> [u8; 120] {
    const PROC_SUPER_MAGIC: u64 = 0x9fa0;
    const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;
    let (total, used) = p.vfs.space();
    let blocks = (total / 4096) as u64;
    let free = (total.saturating_sub(used) / 4096) as u64;
    let mut b = [0u8; 120];
    let mut put = |i: usize, v: u64| b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    if proc {
        put(0, PROC_SUPER_MAGIC);
        put(1, 4096);
    } else {
        put(0, OVERLAYFS_SUPER_MAGIC);
        put(1, 4096); // f_bsize
        put(2, blocks); // f_blocks
        put(3, free); // f_bfree
        put(4, free); // f_bavail
        put(5, 1 << 20); // f_files
        put(6, 1 << 20); // f_ffree
    }
    put(8, 255); // f_namelen
    put(9, 4096); // f_frsize
    b
}

/// `statfs(path, buf)`.
pub(super) fn statfs(p: &mut LinuxProcess, addr: u64, buf: u64) -> Result<u64, i64> {
    let (start, path) = path_at(p, AT_FDCWD, addr)?;
    let proc = match procfs::lookup(p, &path, true) {
        Some(n) => {
            n?;
            true
        }
        None => {
            p.fs().resolve(start, &path, true)?;
            false
        }
    };
    let b = statfs_bytes(p, proc);
    if p.copy_to_user(buf, &b) != b.len() {
        return Err(EFAULT);
    }
    Ok(0)
}

/// `fstatfs(fd, buf)`.
pub(super) fn fstatfs(p: &mut LinuxProcess, fd: u64, buf: u64) -> Result<u64, i64> {
    let f = p.fd(fd).ok_or(EBADF)?;
    let proc = matches!(&f, Fd::Object(o) if o.obj.dir().is_some() || o.obj.mode() == 0o100_000);
    let b = statfs_bytes(p, proc);
    if p.copy_to_user(buf, &b) != b.len() {
        return Err(EFAULT);
    }
    Ok(0)
}

/// `flock`: whole-file advisory locks owned by the open file description.
pub(super) fn flock(p: &mut LinuxProcess, fd: u64, op: u64) -> Result<u64, i64> {
    let desc = p.desc(fd).ok_or(EBADF)?;
    let key = desc.lock_key().ok_or(22i64)?; // EINVAL: not a file
    let entry = p.entry.clone();
    crate::locks::flock(key, desc.id(), op, &|| proc::interrupted(&entry))?;
    Ok(0)
}

/// The inode a `*at` call names: `path` from `dirfd`, or `dirfd` itself
/// for an empty path with `AT_EMPTY_PATH` (or a null path, as
/// `utimensat` allows).
fn inode_at(p: &mut LinuxProcess, dirfd: i64, addr: u64, flags: u64) -> Result<Ino, i64> {
    let path = if addr == 0 {
        alloc::string::String::new()
    } else {
        user_path(p, addr)?
    };
    if path.is_empty() {
        if addr != 0 && flags & AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        return match p.fd(dirfd as u64).ok_or(EBADF)? {
            Fd::File(f) => Ok(f.ino),
            _ => Err(EINVAL),
        };
    }
    let start = base(p, dirfd, &path)?;
    p.vfs
        .lock()
        .resolve(start, &path, flags & AT_SYMLINK_NOFOLLOW == 0)
}

/// `chown`, `fchown`, `lchown`, `fchownat`. Every process in a cell is uid
/// 0 for now (the identity-model ADR adds per-cell mapping and checks), and
/// Linux lets root change any owner, so this records the owner.
pub(super) fn chown(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    uid: u64,
    gid: u64,
    flags: u64,
) -> Result<u64, i64> {
    let ino = inode_at(p, dirfd, addr, flags)?;
    // -1 (as a 32-bit id) means "leave unchanged".
    let id = |v: u64| (v as u32 != u32::MAX).then_some(v as u32);
    p.fs().chown(ino, id(uid), id(gid))?;
    Ok(0)
}

/// `fchown(fd, uid, gid)`.
pub(super) fn fchown(p: &mut LinuxProcess, fd: u64, uid: u64, gid: u64) -> Result<u64, i64> {
    chown(p, fd as i64, 0, uid, gid, AT_EMPTY_PATH)
}

/// Reads `struct timespec[2]` for `utimensat` (null: both now), honouring
/// `UTIME_NOW` and `UTIME_OMIT`.
fn read_times(
    p: &mut LinuxProcess,
    addr: u64,
    micros: bool,
) -> Result<([Option<overlay::Time>; 2], bool), i64> {
    const UTIME_NOW: u64 = (1 << 30) - 1;
    const UTIME_OMIT: u64 = (1 << 30) - 2;
    let now = crate::vfs::realtime();
    if addr == 0 {
        return Ok(([Some(now), Some(now)], false));
    }
    let mut explicit = false;
    let mut b = [0u8; 32];
    if p.copy_from_user(addr, &mut b) != 32 {
        return Err(EFAULT);
    }
    let mut out = [None, None];
    for (i, slot) in out.iter_mut().enumerate() {
        let sec = u64::from_le_bytes(b[i * 16..i * 16 + 8].try_into().unwrap_or([0; 8]));
        let frac = u64::from_le_bytes(b[i * 16 + 8..i * 16 + 16].try_into().unwrap_or([0; 8]));
        if micros {
            if frac >= 1_000_000 {
                return Err(EINVAL);
            }
            *slot = Some(overlay::Time {
                sec,
                nsec: (frac * 1000) as u32,
            });
            explicit = true;
            continue;
        }
        *slot = match frac {
            UTIME_NOW => Some(now),
            UTIME_OMIT => None,
            n if n < 1_000_000_000 => {
                explicit = true;
                Some(overlay::Time {
                    sec,
                    nsec: n as u32,
                })
            }
            _ => return Err(EINVAL),
        };
    }
    Ok((out, explicit))
}

/// `utimensat(dirfd, path, times, flags)`.
pub(super) fn utimensat(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    times: u64,
    flags: u64,
) -> Result<u64, i64> {
    let ([a, m], explicit) = read_times(p, times, false)?;
    let ino = inode_at(p, dirfd, addr, flags | AT_EMPTY_PATH)?;
    let mut fs = p.fs();
    fs.may_set_times(ino, explicit)?;
    fs.set_times(ino, a, m)?;
    Ok(0)
}

/// `futimesat(dirfd, path, timeval[2])` and `utimes(path, timeval[2])`.
pub(super) fn futimesat(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    times: u64,
) -> Result<u64, i64> {
    let ([a, m], explicit) = read_times(p, times, true)?;
    let ino = inode_at(p, dirfd, addr, 0)?;
    let mut fs = p.fs();
    fs.may_set_times(ino, explicit)?;
    fs.set_times(ino, a, m)?;
    Ok(0)
}

/// `fcntl` record locks: `F_GETLK`/`F_SETLK`/`F_SETLKW` (owned by the
/// process) and `F_OFD_*` (owned by the open file description), over a
/// `struct flock { short l_type, l_whence; off_t l_start, l_len; pid_t l_pid; }`.
pub(super) fn record_lock(
    p: &mut LinuxProcess,
    desc: &alloc::sync::Arc<crate::process::Description>,
    cmd: u64,
    arg: u64,
) -> Result<u64, i64> {
    use crate::locks::{Owner, Range};
    const F_RDLCK: u16 = 0;
    const F_WRLCK: u16 = 1;
    const F_UNLCK: u16 = 2;
    let ofd = cmd >= 36;
    let get = cmd == 5 || cmd == 36;
    let wait = cmd == 7 || cmd == 38;
    let (key, offset, size) = {
        let st = desc.state();
        let Fd::File(of) = &*st else {
            return Err(EBADF);
        };
        let size = p.fs().stat(of.ino)?.size;
        (
            (alloc::sync::Arc::as_ptr(&p.vfs) as usize, of.ino),
            of.offset,
            size,
        )
    };
    let mut b = [0u8; 32];
    if p.copy_from_user(arg, &mut b) != 32 {
        return Err(EFAULT);
    }
    let ltype = u16::from_le_bytes([b[0], b[1]]);
    let whence = u16::from_le_bytes([b[2], b[3]]);
    let lstart = i64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
    let llen = i64::from_le_bytes(b[16..24].try_into().unwrap_or([0; 8]));
    let lpid = i32::from_le_bytes(b[24..28].try_into().unwrap_or([0; 4]));
    if ofd && lpid != 0 {
        return Err(EINVAL);
    }
    let base: i64 = match whence {
        0 => 0,
        1 => offset as i64,
        2 => size as i64,
        _ => return Err(EINVAL),
    };
    let start = base.checked_add(lstart).ok_or(EINVAL)?;
    let (start, end) = match llen {
        0 => (start, u64::MAX),
        l if l > 0 => (start, start.checked_add(l).ok_or(EINVAL)? as u64),
        l => (start.checked_add(l).ok_or(EINVAL)?, start as u64),
    };
    if start < 0 {
        return Err(EINVAL);
    }
    let r = Range {
        start: start as u64,
        end,
    };
    let owner = if ofd {
        Owner::Desc(desc.id())
    } else {
        Owner::Proc(p.group.tgid)
    };
    let write = match ltype {
        F_RDLCK => Some(false),
        F_WRLCK => Some(true),
        F_UNLCK => None,
        _ => return Err(EINVAL),
    };
    // A lock needs the matching access mode.
    let acc = match &*desc.state() {
        Fd::File(of) => of.flags & O_ACCMODE,
        _ => 0,
    };
    if (write == Some(true) && acc == 0) || (write == Some(false) && acc == O_WRONLY) {
        return Err(EBADF);
    }
    if get {
        let Some(want) = write else {
            return Err(EINVAL);
        };
        let mut out = b;
        match crate::locks::get_record(key, owner, want, r) {
            None => out[0..2].copy_from_slice(&F_UNLCK.to_le_bytes()),
            Some((w, s, e, pid)) => {
                out[0..2].copy_from_slice(&(if w { F_WRLCK } else { F_RDLCK }).to_le_bytes());
                out[2..4].copy_from_slice(&0u16.to_le_bytes());
                out[8..16].copy_from_slice(&(s as i64).to_le_bytes());
                let len = if e == u64::MAX { 0 } else { (e - s) as i64 };
                out[16..24].copy_from_slice(&len.to_le_bytes());
                out[24..28].copy_from_slice(&(pid as i32).to_le_bytes());
            }
        }
        if p.copy_to_user(arg, &out) != 32 {
            return Err(EFAULT);
        }
        return Ok(0);
    }
    let entry = p.entry.clone();
    crate::locks::set_record(key, owner, write, r, wait, &|| proc::interrupted(&entry))?;
    Ok(0)
}
