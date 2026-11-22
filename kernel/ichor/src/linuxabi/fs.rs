//! File and path syscalls over the root overlay: open/create, read/write,
//! the stat family, directories, links, renames, permissions and the working
//! directory. Paths are resolved from the process's working directory or a
//! directory descriptor (the `*at` calls).

use alloc::string::String;
use alloc::vec::Vec;

use super::{EBADF, EFAULT, EINVAL, EMFILE, console_bytes, console_write, le_u64};
use crate::pipe::Pipe;
use crate::process::{Fd, LinuxProcess, OpenFile, PipeEnd, RLIMIT_FSIZE};
use crate::vfs::{self, Ino, Kind, Stat, errno::*};
use crate::{proc, procfs, signal};

pub(super) const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;

pub(super) const O_ACCMODE: u64 = 0o3;
pub(super) const O_WRONLY: u64 = 0o1;
pub(super) const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
pub(super) const O_APPEND: u64 = 0o2000;
const O_DIRECTORY: u64 = 0o200_000;
const O_NOFOLLOW: u64 = 0o400_000;
/// With O_DIRECTORY, which it includes.
const O_TMPFILE: u64 = 0o20_200_000;
pub(super) const O_NONBLOCK: u64 = 0o4000;
pub(super) const O_CLOEXEC: u64 = 0o2_000_000;

const ENAMETOOLONG: i64 = 36;
const ESPIPE: i64 = 29;
const EACCES: i64 = 13;
const EPIPE: i64 = 32;
const ERANGE: i64 = 34;
const ENXIO: i64 = 6;

/// Copy chunk for file I/O.
const CHUNK: usize = 64 * 1024;

/// Most bytes one operation on a pipe, socket or device moves at a time
/// (more than any datagram).
const STREAM: usize = 256 * 1024;

/// Copies a NUL-terminated path out of user memory. Paths are bytes; one
/// that is not UTF-8 is carried escaped (`overlay::name`), and names going
/// back out ([`getdents64`], [`readlink`], [`getcwd`]) are unescaped.
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
            return Ok(overlay::name::encode(&out));
        }
        out.extend_from_slice(&chunk[..got]);
    }
    Err(ENAMETOOLONG)
}

/// The directory a relative path in an `*at` call starts from.
pub(super) fn base(p: &LinuxProcess, dirfd: i64, path: &str) -> Result<Ino, i64> {
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
    from_dir(p, dirfd, path)
}

/// Where `path` starts from; made absolute if that is a `/proc` directory.
fn from_dir(p: &LinuxProcess, dirfd: i64, path: String) -> Result<(Ino, String), i64> {
    if dirfd != AT_FDCWD
        && !path.starts_with('/')
        && let Some(Fd::Object(o)) = p.fd(dirfd as u64)
        && let Some(d) = o.obj.proc_dir()
    {
        return Ok((p.cwd(), alloc::format!("{d}/{path}")));
    }
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
    if hops > 8 {
        return Err(ELOOP);
    }
    if let Some(node) = procfs::lookup(p, path, flags & O_NOFOLLOW == 0) {
        if let Some(fd) = procfs::own_fd(p, path)
            && flags & O_NOFOLLOW == 0
        {
            return reopen(p, fd, flags);
        }
        return open_proc(p, start, path, node?, flags, mode, hops);
    }
    let umask = p.umask();
    let ino = {
        let mut fs = p.fs();
        let mut created = false;
        let follow = flags & O_NOFOLLOW == 0;
        let mut find = || {
            if flags & O_CREAT == 0 {
                return fs.resolve(start, path, follow);
            }
            let through = follow && flags & O_EXCL == 0;
            let (dir, name) = fs.resolve_create(start, path, through)?;
            match fs.lookup(dir, &name) {
                Ok(_) if flags & O_EXCL != 0 => Err(EEXIST),
                Ok(_) => fs.resolve(start, path, follow),
                Err(ENOENT) if path.ends_with('/') => Err(EISDIR),
                Err(ENOENT) => {
                    created = true;
                    fs.create(dir, &name, mode as u32 & !umask)
                }
                Err(e) => Err(e),
            }
        };
        let found = find();
        // It leads into `/proc`, or is it (by a relative path).
        let proc = match found {
            Err(ELSEWHERE) => Some(fs.take_crossing()),
            Ok(i) if fs.is_elsewhere(i) => Some(fs.path(i)?),
            _ => None,
        };
        if let Some(path) = proc {
            drop(fs);
            return open_path(p, start, &path, flags, mode, hops + 1);
        }
        let ino = found?;
        let st = fs.stat(ino)?;
        if flags & O_TMPFILE == O_TMPFILE {
            // A file with no name, in the file system of this directory.
            if st.kind != Kind::Directory {
                return Err(ENOTDIR);
            }
            if acc == 0 {
                return Err(EINVAL);
            }
            fs.permission(ino, overlay::MAY_WRITE | overlay::MAY_EXEC)?;
            let ino = fs.create_unnamed(mode as u32 & !umask)?;
            drop(fs);
            let f = OpenFile {
                ino,
                offset: 0,
                flags: flags & (O_ACCMODE | O_APPEND | O_NONBLOCK),
            };
            return p
                .install_flags(Fd::File(f), flags & O_CLOEXEC != 0)
                .ok_or(EMFILE);
        }
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
            Kind::File | Kind::CharDevice | Kind::Socket | Kind::Fifo
                if flags & O_DIRECTORY != 0 =>
            {
                return Err(ENOTDIR);
            }
            // A socket node is reached with connect, not open (Linux: ENXIO).
            Kind::Socket => return Err(ENXIO),
            Kind::Fifo => {
                let id = fs.fifo_id(ino).ok_or(ENXIO)?;
                drop(fs);
                return open_fifo(p, id, flags);
            }
            Kind::CharDevice => {
                drop(fs);
                let fd = crate::dev::open(p, st.rdev, ino, flags)?;
                return p.install_flags(fd, flags & O_CLOEXEC != 0).ok_or(EMFILE);
            }
            _ => {}
        }
        if flags & O_TRUNC != 0 && acc != 0 && !created && st.kind == Kind::File {
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
    super::inotify::note(&p.vfs, ino, super::inotify::IN_OPEN);
    p.install_flags(Fd::File(f), flags & O_CLOEXEC != 0)
        .ok_or(EMFILE)
}

/// Opens what descriptor `fd` names anew (`/proc/self/fd/N`, `/dev/stdout`):
/// a description of its own on the same file, pipe or terminal. Sockets and
/// other objects cannot be opened (ENXIO).
fn reopen(p: &mut LinuxProcess, fd: u64, flags: u64) -> Result<u64, i64> {
    let nonblock = flags & O_NONBLOCK != 0;
    let acc = flags & O_ACCMODE;
    let new = match p.fd(fd).ok_or(ENOENT)? {
        Fd::File(of) => {
            let mut fs = p.fs();
            let want = match acc {
                0 => overlay::MAY_READ,
                O_WRONLY => overlay::MAY_WRITE,
                _ => overlay::MAY_READ | overlay::MAY_WRITE,
            };
            fs.permission(of.ino, want)?;
            let kind = fs.stat(of.ino)?.kind;
            if kind == Kind::Directory && acc != 0 {
                return Err(EISDIR);
            }
            if kind != Kind::Directory && flags & O_DIRECTORY != 0 {
                return Err(ENOTDIR);
            }
            if flags & O_TRUNC != 0 && acc != 0 {
                fs.truncate(of.ino, 0)?;
            }
            fs.open(of.ino)?;
            Fd::File(OpenFile {
                ino: of.ino,
                offset: 0,
                flags: flags & (O_ACCMODE | O_APPEND | O_NONBLOCK),
            })
        }
        Fd::Pipe(e) => {
            // Both ends at once cannot be held in one: the end it is of.
            let write = match acc {
                0 => false,
                O_WRONLY => true,
                _ => e.write,
            };
            e.pipe.add_end(write);
            Fd::Pipe(PipeEnd {
                pipe: e.pipe,
                write,
                nonblock,
            })
        }
        Fd::Object(o) if o.obj.tty().is_some() => Fd::Object(crate::process::ObjectEnd {
            obj: o.obj,
            nonblock,
        }),
        Fd::Object(_) => return Err(ENXIO),
        f @ (Fd::Console | Fd::Dev(_)) => f,
    };
    p.install_flags(new, flags & O_CLOEXEC != 0).ok_or(EMFILE)
}

/// Opens a named pipe: one end of the FIFO's pipe, shared by every open of
/// it. As on Linux, opening one end blocks until the other is opened
/// (unless O_NONBLOCK); a non-blocking open for writing with no reader is
/// ENXIO. O_RDWR (both ends in one description) is not supported: EINVAL.
fn open_fifo(p: &mut LinuxProcess, id: u64, flags: u64) -> Result<u64, i64> {
    let write = match flags & O_ACCMODE {
        0 => false,
        O_WRONLY => true,
        _ => return Err(EINVAL),
    };
    let nonblock = flags & O_NONBLOCK != 0;
    let pipe = crate::pipe::fifo(id, p.cell.account());
    if write && nonblock && pipe.readers() == 0 {
        return Err(ENXIO);
    }
    let peer_opens = pipe.add_end(write);
    if !nonblock {
        let entry = p.entry.clone();
        if let Err(e) = pipe.wait_peer(write, peer_opens, &|| proc::interrupted(&entry)) {
            pipe.drop_end(write);
            return Err(e);
        }
    }
    let end = PipeEnd {
        pipe,
        write,
        nonblock,
    };
    // A full table drops the description, which drops the end again.
    p.install_flags(Fd::Pipe(end), flags & O_CLOEXEC != 0)
        .ok_or(EMFILE)
}

/// `memfd_create(name, flags)`: an anonymous read-write file. It is an
/// unnamed file of the cell's root (its pages count against the root's
/// byte budget, as tmpfs memory would count against the cell) and lives
/// until its last descriptor closes. Sealing is not supported: with
/// MFD_ALLOW_SEALING the file is made, but F_ADD_SEALS is not.
pub(super) fn memfd_create(p: &mut LinuxProcess, name: u64, flags: u64) -> Result<u64, i64> {
    const MFD_CLOEXEC: u64 = 1;
    const MFD_ALLOW_SEALING: u64 = 2;
    /// Linux's limit: "memfd:" plus the name fits NAME_MAX.
    const MFD_NAME_MAX: usize = 249;
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING) != 0 {
        return Err(EINVAL); // MFD_HUGETLB and friends
    }
    if user_path(p, name)?.len() > MFD_NAME_MAX {
        return Err(EINVAL);
    }
    let ino = p.fs().create_unnamed(0o600)?;
    let f = OpenFile {
        ino,
        offset: 0,
        flags: 0o2, // O_RDWR
    };
    // A full table drops the description, which closes (frees) the file.
    p.install_flags(Fd::File(f), flags & MFD_CLOEXEC != 0)
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
    path: &str,
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
        procfs::Node::Dir(e) => alloc::sync::Arc::new(procfs::ProcDir::new(path, e)),
        _ if flags & O_DIRECTORY != 0 => return Err(ENOTDIR),
        _ if flags & O_ACCMODE != 0 => return Err(EACCES),
        procfs::Node::File(d) => alloc::sync::Arc::new(procfs::ProcFile::new(d)),
        procfs::Node::Maps(g) => alloc::sync::Arc::new(procfs::ProcFile::maps(g)),
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

/// What a path names: an inode of the root, or something `procfs` serves.
enum Place {
    Tree(Ino),
    Proc(String),
}

/// Finds what `path` names, starting from `start`.
fn place(p: &LinuxProcess, start: Ino, path: &str, follow: bool) -> Result<Place, i64> {
    if procfs::serves(path) {
        return Ok(Place::Proc(String::from(path)));
    }
    let mut fs = p.fs();
    match fs.resolve(start, path, follow) {
        Err(ELSEWHERE) => Ok(Place::Proc(fs.take_crossing())),
        Ok(i) if fs.is_elsewhere(i) => Ok(Place::Proc(fs.path(i)?)),
        r => r.map(Place::Tree),
    }
}

/// What `execve` of a path runs: a file, or (from `/proc/self/exe`) the
/// file at another path.
pub(super) enum Exec {
    File(Ino),
    Path(String),
}

/// Finds the file `execve` runs for `path`: also `/proc/self/exe`, or an
/// open file's `/proc/self/fd/N`.
pub(super) fn executable(p: &LinuxProcess, start: Ino, path: &str) -> Result<Exec, i64> {
    match place(p, start, path, true)? {
        Place::Tree(ino) => Ok(Exec::File(ino)),
        Place::Proc(path) => {
            if let Some(fd) = procfs::own_fd(p, &path) {
                return match p.fd(fd).ok_or(ENOENT)? {
                    Fd::File(of) => Ok(Exec::File(of.ino)),
                    _ => Err(EACCES),
                };
            }
            match procfs::lookup(p, &path, false).ok_or(ENOENT)?? {
                procfs::Node::Link(t) => Ok(Exec::Path(proc_target(&t))),
                _ => Err(EACCES),
            }
        }
    }
}

/// `stat` of a `/proc` node (following links if `follow`).
fn stat_proc(p: &mut LinuxProcess, path: &str, follow: bool, hops: u32) -> Result<[u8; 144], i64> {
    if follow && let Some(fd) = procfs::own_fd(p, path) {
        return fstat_raw(p, fd);
    }
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
        procfs::Node::Link(t) => {
            let len = t.len() as u64;
            apart(DEV_PROC, path_ino(path), S_IFLNK | 0o777, 1, len)
        }
        procfs::Node::Dir(_) => apart(DEV_PROC, path_ino(path), S_IFDIR | 0o555, 2, 0),
        procfs::Node::File(_) | procfs::Node::Maps(_) => {
            apart(DEV_PROC, path_ino(path), S_IFREG | 0o444, 1, 0)
        }
    })
}

/// `st_dev` of what is not the root's (1): programs tell files apart by
/// device and inode together.
const DEV_PROC: u64 = 2;
const DEV_PIPE: u64 = 3;
const DEV_SOCKET: u64 = 4;
const DEV_ANON: u64 = 5;

/// An inode number for a `/proc` path: the same each time (FNV-1a).
fn path_ino(path: &str) -> u64 {
    path.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// A `struct stat` of something on device `dev`.
fn apart(dev: u64, ino: u64, mode: u32, nlink: u32, size: u64) -> [u8; 144] {
    let mut st = stat_bytes(ino, mode, nlink, size);
    st[0..8].copy_from_slice(&dev.to_le_bytes());
    st
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
        let n = match p.vfs.read(f.ino, offset + done as u64, &mut chunk[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        let copied = p.copy_to_user(buf + done as u64, &chunk[..n]);
        done += copied;
        if copied < n {
            if done == 0 {
                return Err(EFAULT);
            }
            break;
        }
    }
    if done > 0 {
        super::inotify::note(&p.vfs, f.ino, super::inotify::IN_ACCESS);
    }
    Ok(done as u64)
}

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
    let limit = p.group.limits()[RLIMIT_FSIZE].0;
    let count = if limit == u64::MAX || count == 0 {
        count
    } else {
        let at = if append {
            p.vfs.lock().stat(f.ino)?.size
        } else {
            offset
        };
        if at >= limit {
            return Err(too_large(p));
        }
        count.min(usize::try_from(limit - at).unwrap_or(usize::MAX))
    };
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
            p.fs().append(f.ino, &chunk[..got]).map(|(end, n)| {
                pos = end;
                n
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

/// A file may not grow past `RLIMIT_FSIZE`: SIGXFSZ, and EFBIG if that is
/// ignored or handled.
fn too_large(p: &LinuxProcess) -> i64 {
    const SIGXFSZ: u32 = 25;
    proc::post(&p.entry, SIGXFSZ);
    EFBIG
}

/// Whether the process may make a file `len` bytes long.
fn check_length(p: &LinuxProcess, len: u64) -> Result<(), i64> {
    if len > p.group.limits()[RLIMIT_FSIZE].0 {
        return Err(too_large(p));
    }
    Ok(())
}

/// Reads up to `max` bytes (at most [`STREAM`]) from what is not a file:
/// one read of a pipe, a socket or a device. `nonblock` adds to the
/// descriptor's own.
pub(super) fn stream_read(
    p: &LinuxProcess,
    f: &Fd,
    max: usize,
    nonblock: bool,
) -> Result<Vec<u8>, i64> {
    let max = max.min(STREAM);
    let entry = p.entry.clone();
    let interrupted = || proc::interrupted(&entry);
    match f {
        Fd::Console => Ok(Vec::new()), // No console input yet: EOF.
        Fd::Object(o) => {
            if let Some(end) = o.obj.tty() {
                crate::pty::foreground(p, end, signal::SIGTTIN)?;
            }
            o.obj.read(max, o.nonblock || nonblock, &interrupted)
        }
        Fd::Dev(d) => {
            let mut chunk = alloc::vec![0u8; max];
            let n = d.read(&mut chunk);
            chunk.truncate(n);
            Ok(chunk)
        }
        Fd::Pipe(e) if e.write => Err(EBADF),
        Fd::Pipe(e) => e.pipe.take(max, e.nonblock || nonblock, &interrupted),
        Fd::File(_) => Err(EINVAL),
    }
}

/// Writes `data` to what is not a file, in one write: a pipe, a socket (one
/// datagram) or a device. Returns how much was taken; a reader or peer that
/// is gone posts SIGPIPE.
pub(super) fn stream_write(
    p: &LinuxProcess,
    f: &Fd,
    data: &[u8],
    nonblock: bool,
) -> Result<usize, i64> {
    let r = stream_put(p, f, data, nonblock);
    if r == Err(EPIPE) {
        proc::post(&p.entry, signal::SIGPIPE);
    }
    r
}

/// [`stream_write`] without the signal.
fn stream_put(p: &LinuxProcess, f: &Fd, data: &[u8], nonblock: bool) -> Result<usize, i64> {
    let entry = p.entry.clone();
    let interrupted = || proc::interrupted(&entry);
    match f {
        Fd::Console => {
            console_bytes(data);
            Ok(data.len())
        }
        Fd::Dev(d) => d.write(data.len()).map(|_| data.len()),
        Fd::Object(o) => {
            if let Some(end) = o.obj.tty() {
                crate::pty::may_write(p, end)?;
            }
            o.obj.write(data, o.nonblock || nonblock, &interrupted)
        }
        Fd::Pipe(e) if !e.write => Err(EBADF),
        Fd::Pipe(_) if data.is_empty() => Ok(0),
        Fd::Pipe(e) => e.pipe.write(data, e.nonblock || nonblock, &interrupted),
        Fd::File(_) => Err(EINVAL),
    }
}

pub(super) fn read(p: &mut LinuxProcess, fd: u64, buf: u64, count: usize) -> Result<u64, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        f @ (Fd::Console | Fd::Object(_) | Fd::Dev(_) | Fd::Pipe(_)) => {
            let bytes = stream_read(p, &f, count, false)?;
            if p.copy_to_user(buf, &bytes) != bytes.len() {
                return Err(EFAULT);
            }
            Ok(bytes.len() as u64)
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
        f @ (Fd::Object(_) | Fd::Pipe(_)) => {
            stream_gather(p, &f, &[(buf, count)], false, true).map(|n| n as u64)
        }
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

/// Writes the user memory of `iov` (base, length; see [`read_iov`]), taken
/// together, to a pipe or an object: at most [`STREAM`] bytes a write, so
/// whatever fits there is one (a datagram, or a pipe write of `PIPE_BUF`).
/// Stops, with what went so far, at the first that is short or fails. EPIPE
/// raises SIGPIPE if `sigpipe`.
pub(super) fn stream_gather(
    p: &mut LinuxProcess,
    f: &Fd,
    iov: &[(u64, usize)],
    nonblock: bool,
    sigpipe: bool,
) -> Result<usize, i64> {
    let total: usize = iov.iter().map(|&(_, n)| n).sum();
    let mut data = alloc::vec![0u8; total.min(STREAM)];
    let (mut i, mut at) = (0, 0); // where in `iov` the next byte is
    let mut done = 0usize;
    loop {
        let want = data.len().min(total - done);
        let mut have = 0;
        while have < want {
            let (base, len) = iov[i];
            let n = (len - at).min(want - have);
            let got = p.copy_from_user(base + at as u64, &mut data[have..have + n]);
            have += got;
            at += got;
            if got < n {
                break; // unreadable from here on
            }
            if at == len {
                (i, at) = (i + 1, 0);
            }
        }
        if have < want && have == 0 {
            return if done == 0 { Err(EFAULT) } else { Ok(done) };
        }
        match stream_put(p, f, &data[..have], nonblock) {
            Ok(n) => {
                done += n;
                if n < have || have < want || done == total {
                    return Ok(done);
                }
            }
            Err(e) => {
                if e == EPIPE && sigpipe {
                    proc::post(&p.entry, signal::SIGPIPE);
                }
                return if done == 0 { Err(e) } else { Ok(done) };
            }
        }
    }
}

/// A `struct iovec` array: (base, length) of each.
pub(super) fn read_iov(
    p: &mut LinuxProcess,
    iov: u64,
    iovcnt: usize,
) -> Result<Vec<(u64, usize)>, i64> {
    const IOV_MAX: usize = 1024;
    if iovcnt > IOV_MAX {
        return Err(EINVAL);
    }
    let mut raw = alloc::vec![0u8; iovcnt * 16];
    if p.copy_from_user(iov, &mut raw) != raw.len() {
        return Err(EFAULT);
    }
    let mut total = 0usize;
    let mut v = Vec::with_capacity(iovcnt);
    for c in raw.as_chunks::<16>().0 {
        let len = usize::try_from(le_u64(&c[8..16])).map_err(|_| EINVAL)?;
        total = total
            .checked_add(len)
            .filter(|&t| t <= isize::MAX as usize)
            .ok_or(EINVAL)?;
        v.push((le_u64(&c[0..8]), len));
    }
    Ok(v)
}

/// `readv` (`write == false`) and `writev`: one operation on a pipe, a
/// socket or a device, whatever the pieces.
pub(super) fn vector(
    p: &mut LinuxProcess,
    fd: u64,
    iov: u64,
    iovcnt: usize,
    is_write: bool,
) -> Result<u64, i64> {
    let f = p.fd(fd).ok_or(EBADF)?;
    let iov = read_iov(p, iov, iovcnt)?;
    let total: usize = iov.iter().map(|&(_, n)| n).sum();
    if total == 0 {
        return Ok(0);
    }
    if !matches!(f, Fd::File(_) | Fd::Console | Fd::Dev(_)) {
        if is_write {
            return stream_gather(p, &f, &iov, false, true).map(|n| n as u64);
        }
        let bytes = stream_read(p, &f, total, false)?;
        let mut at = 0;
        for (base, len) in iov {
            let n = len.min(bytes.len() - at);
            if p.copy_to_user(base, &bytes[at..at + n]) != n {
                return Err(EFAULT);
            }
            at += n;
        }
        return Ok(at as u64);
    }
    let mut done = 0u64;
    for (base, len) in iov {
        let r = if is_write {
            write(p, fd, base, len)
        } else {
            read(p, fd, base, len)
        };
        match r {
            Ok(n) => {
                done += n;
                if (n as usize) < len {
                    break;
                }
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

/// `preadv`/`pwritev` (and the `2` forms with no flags): the vector I/O
/// above at file offset `offset`, leaving the file position alone; an
/// offset of -1 (the `2` forms) uses and moves the position instead.
pub(super) fn vector_at(
    p: &mut LinuxProcess,
    fd: u64,
    iov: u64,
    iovcnt: usize,
    offset: u64,
    flags: u64,
    is_write: bool,
) -> Result<u64, i64> {
    const EOPNOTSUPP: i64 = 95;
    if flags != 0 {
        return Err(EOPNOTSUPP); // RWF_HIPRI, RWF_DSYNC, RWF_NOWAIT, ...
    }
    if offset == u64::MAX {
        return vector(p, fd, iov, iovcnt, is_write);
    }
    if (offset as i64) < 0 {
        return Err(EINVAL);
    }
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
        let at = offset.checked_add(total).ok_or(EINVAL)?;
        let n = if is_write {
            pwrite(p, fd, base, len, at)?
        } else {
            pread(p, fd, base, len, at)?
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
    // A closed descriptor is EBADF; an open one that has no position is
    // ESPIPE.
    if let Some(Fd::Object(o)) = p.fd(fd) {
        return o.obj.seek(offset, whence);
    }
    let f = file(p, fd).map_err(|e| if e == EBADF { EBADF } else { ESPIPE })?;
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
    if f.flags & O_ACCMODE == 0 || (len as i64) < 0 {
        return Err(EINVAL);
    }
    check_length(p, len)?;
    p.fs().truncate(f.ino, len)?;
    Ok(0)
}

pub(super) fn truncate(p: &mut LinuxProcess, addr: u64, len: u64) -> Result<u64, i64> {
    if (len as i64) < 0 {
        return Err(EINVAL);
    }
    check_length(p, len)?;
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

/// What an extended-attribute call does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Xattr {
    Set,
    Get,
    List,
    Remove,
}

/// The `*xattr` family, as a filesystem without extended attributes
/// answers: the file must exist (or the descriptor be open); lists are
/// empty, reads and removals ENODATA, writes ENOTSUP. `target` is a path
/// (`follow` for the non-`l` forms) or, with `fd`, a descriptor.
pub(super) fn xattr(
    p: &mut LinuxProcess,
    op: Xattr,
    target: u64,
    fd: bool,
    follow: bool,
) -> Result<u64, i64> {
    const ENODATA: i64 = 61;
    const ENOTSUP: i64 = 95;
    if fd {
        p.fd(target).ok_or(EBADF)?;
    } else {
        let (start, path) = path_at(p, AT_FDCWD, target)?;
        p.fs().resolve(start, &path, follow)?;
    }
    match op {
        Xattr::List => Ok(0),
        Xattr::Get | Xattr::Remove => Err(ENODATA),
        Xattr::Set => Err(ENOTSUP),
    }
}

/// `sync_file_range`: as `fsync`, nothing to write back; the arguments are
/// checked as Linux checks them.
pub(super) fn sync_file_range(
    p: &mut LinuxProcess,
    fd: u64,
    off: u64,
    len: u64,
    flags: u64,
) -> Result<u64, i64> {
    const VALID: u64 = 0b111; // WAIT_BEFORE | WRITE | WAIT_AFTER
    if flags & !VALID != 0 || (off as i64) < 0 || (len as i64) < 0 {
        return Err(EINVAL);
    }
    let _ = file(p, fd)?;
    Ok(0)
}

/// `fallocate(fd, mode, offset, len)`: mode 0 makes the file at least
/// `offset + len` long (the upper layer is sparse, so nothing is reserved
/// ahead; a later write can still find the byte budget spent), and
/// FALLOC_FL_KEEP_SIZE alone has nothing to do. Punching holes, collapsing
/// and zeroing ranges are EOPNOTSUPP.
pub(super) fn fallocate(
    p: &mut LinuxProcess,
    fd: u64,
    mode: u64,
    off: u64,
    len: u64,
) -> Result<u64, i64> {
    const KEEP_SIZE: u64 = 1;
    const EOPNOTSUPP: i64 = 95;
    if (off as i64) < 0 || (len as i64) <= 0 {
        return Err(EINVAL);
    }
    let f = file(p, fd)?;
    if f.flags & O_ACCMODE == 0 {
        return Err(EBADF);
    }
    let end = off.checked_add(len).ok_or(EFBIG)?;
    check_length(p, end)?;
    match mode {
        0 => {
            let mut fs = p.fs();
            if fs.stat(f.ino)?.size < end {
                fs.truncate(f.ino, end)?;
            }
            Ok(0)
        }
        KEEP_SIZE => Ok(0),
        _ => Err(EOPNOTSUPP),
    }
}

// ---------------------------------------------------------------------------
// stat.
// ---------------------------------------------------------------------------

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;
const S_IFSOCK: u32 = 0o140_000;

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
        Kind::Socket => S_IFSOCK,
        Kind::Fifo => S_IFIFO,
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
    let f = p.fd(fd).ok_or(EBADF)?;
    Ok(match &f {
        Fd::Console => stat_bytes(0, S_IFCHR | 0o620, 1, 0),
        Fd::Pipe(e) => {
            let ino = alloc::sync::Arc::as_ptr(&e.pipe) as u64;
            apart(DEV_PIPE, ino, S_IFIFO | 0o600, 1, 0)
        }
        // A terminal stats as the node it was opened through, which
        // `ttyname` checks.
        Fd::Object(o) if let Some(t) = o.obj.tty() => to_stat(&p.fs().stat(t.ino())?),
        Fd::Object(o) if let Some(d) = o.obj.proc_dir() => {
            apart(DEV_PROC, path_ino(d), S_IFDIR | 0o555, 2, 0)
        }
        Fd::Object(o) => {
            let ino = match (o.obj.socket(), o.obj.unix()) {
                (Some(s), _) => s.inode(),
                (_, Some(u)) => u.inode(),
                _ => alloc::sync::Arc::as_ptr(&o.obj).cast::<u8>() as u64,
            };
            let (dev, perm) = match o.obj.mode() {
                S_IFSOCK => (DEV_SOCKET, 0o777),
                _ => (DEV_ANON, 0o600),
            };
            apart(dev, ino, o.obj.mode() | perm, 1, 0)
        }
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
    let st = stat_raw(p, dirfd, addr, flags)?;
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
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (start, path) = from_dir(p, dirfd, path)?;
    match place(p, start, &path, follow)? {
        Place::Proc(path) => stat_proc(p, &path, follow, 0),
        Place::Tree(ino) => Ok(to_stat(&p.fs().stat(ino)?)),
    }
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
    // Checked with the real ids (AT_EACCESS: effective), as Linux does.
    const AT_EACCESS: u64 = 0x200;
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 || mode & !7 != 0 {
        return Err(EINVAL);
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let path = user_path(p, addr)?;
    let named = if flags & AT_EMPTY_PATH != 0 && path.is_empty() {
        // The descriptor itself (the working directory, for AT_FDCWD).
        match p.fd(dirfd as u64) {
            _ if dirfd == AT_FDCWD => Ok(base(p, dirfd, "")?),
            Some(Fd::File(f)) => Ok(f.ino),
            Some(_) => return Ok(0),
            None => return Err(EBADF),
        }
    } else {
        let (start, path) = from_dir(p, dirfd, path.clone())?;
        if let Place::Proc(path) = place(p, start, &path, follow)? {
            return stat_proc(p, &path, follow, 0).map(|_| 0);
        }
        Err(start)
    };
    let c = p.group.creds();
    let cred = if flags & AT_EACCESS != 0 {
        c.fs()
    } else {
        c.real()
    };
    let mut fs = p.vfs.lock_as(cred);
    let ino = match named {
        Ok(ino) => ino,
        Err(start) => fs.resolve(start, &path, follow)?,
    };
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
    const DT_FIFO: u8 = 1;
    const DT_CHR: u8 = 2;
    const DT_DIR: u8 = 4;
    const DT_REG: u8 = 8;
    const DT_LNK: u8 = 10;
    const DT_SOCK: u8 = 12;
    const HEADER: usize = 19; // d_ino, d_off, d_reclen, d_type
    // What one call returns at most, whatever the buffer holds.
    let count = count.min(256 << 10);
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
    let mut fs = p.fs();
    let me = fs.stat(f.ino)?;
    if me.kind != Kind::Directory {
        return Err(ENOTDIR);
    }
    let parent = fs.lookup(f.ino, "..")?;
    let parent = fs.stat(parent)?.ino;
    let mut out: Vec<u8> = Vec::new();
    // Offsets: 0 is `.`, 1 is `..`, and 2 + a place in the listing (0 being
    // its start) what comes after that place.
    let mut index = f.offset;
    let mut full = false;
    let mut add = |next: u64, name: &str, ino: u64, kind: Kind| {
        let dtype = match kind {
            Kind::Directory => DT_DIR,
            Kind::File => DT_REG,
            Kind::Symlink => DT_LNK,
            Kind::CharDevice => DT_CHR,
            Kind::Socket => DT_SOCK,
            Kind::Fifo => DT_FIFO,
        };
        let name = overlay::name::decode(name);
        let reclen = (HEADER + name.len() + 1).next_multiple_of(8);
        if out.len() + reclen > count {
            full = true;
            return false;
        }
        let start = out.len();
        out.extend_from_slice(&ino.to_le_bytes());
        out.extend_from_slice(&next.to_le_bytes()); // d_off
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(dtype);
        out.extend_from_slice(&name);
        out.resize(start + reclen, 0);
        index = next;
        true
    };
    if (f.offset > 0 || add(1, ".", me.ino, Kind::Directory))
        && (f.offset > 1 || add(2, "..", parent, Kind::Directory))
    {
        let after = f.offset.saturating_sub(2);
        fs.list(f.ino, after, |place, name, ino, kind| {
            add(place + 2, name, ino, kind)
        })?;
    }
    drop(fs);
    if out.is_empty() && full {
        return Err(EINVAL);
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

/// Checks a path's trailing slash, which only a directory has: what `name`
/// is in `dir` (itself, if a symlink) has to be one.
fn check_slash(fs: &mut vfs::Tree, path: &str, dir: Ino, name: &str) -> Result<(), i64> {
    if !path.ends_with('/') {
        return Ok(());
    }
    let ino = fs.lookup(dir, name)?;
    match fs.stat(ino)?.kind {
        Kind::Directory => Ok(()),
        _ => Err(ENOTDIR),
    }
}

/// The directory and name a new non-directory goes to: no trailing slash.
fn new_name(fs: &mut vfs::Tree, start: Ino, path: &str) -> Result<(Ino, String), i64> {
    let (dir, name) = fs.resolve_parent(start, path)?;
    if path.ends_with('/') {
        let there = fs.lookup(dir, &name).is_ok();
        return Err(if there { EEXIST } else { ENOENT });
    }
    Ok((dir, name))
}

/// `mknod`/`mknodat`: FIFOs, regular files and socket nodes. Device nodes
/// need CAP_MKNOD, which is outside the cell bounding set: EPERM, as for an
/// unprivileged Linux process (a cell's devices are its `/dev`).
pub(super) fn mknod(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    mode: u64,
    _dev: u64,
) -> Result<u64, i64> {
    const S_IFMT: u32 = 0o170_000;
    const S_IFBLK: u32 = 0o060_000;
    let mode = mode as u32;
    let (start, path) = path_at(p, dirfd, addr)?;
    let perm = mode & 0o7777 & !p.umask();
    let mut fs = p.fs();
    let (dir, name) = new_name(&mut fs, start, &path)?;
    match mode & S_IFMT {
        0 | S_IFREG => fs.create(dir, &name, perm)?,
        S_IFIFO => fs.mkfifo(dir, &name, perm)?,
        S_IFSOCK => fs.mksocket(dir, &name, perm)?,
        S_IFCHR | S_IFBLK => return Err(EPERM),
        _ => return Err(EINVAL),
    };
    Ok(0)
}

pub(super) fn unlink(p: &mut LinuxProcess, dirfd: i64, addr: u64, flags: u64) -> Result<u64, i64> {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(EINVAL);
    }
    let (start, path) = path_at(p, dirfd, addr)?;
    let mut fs = p.fs();
    let (dir, name) = fs.resolve_parent(start, &path)?;
    check_slash(&mut fs, &path, dir, &name)?;
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
    check_slash(&mut fs, &opath, odir, &oname)?;
    if npath.ends_with('/') {
        let old = fs.lookup(odir, &oname)?;
        if fs.stat(old)?.kind != Kind::Directory {
            return Err(ENOTDIR);
        }
    }
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
    let (dir, name) = new_name(&mut fs, start, &path)?;
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
    let (dir, name) = new_name(&mut fs, start, &path)?;
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
    let target = match place(p, start, &path, false)? {
        Place::Proc(path) => match procfs::lookup(p, &path, false).ok_or(ENOENT)?? {
            procfs::Node::Link(t) => overlay::name::decode(&t),
            _ => return Err(EINVAL),
        },
        Place::Tree(ino) => overlay::name::decode(&p.fs().readlink(ino)?),
    };
    // No NUL terminator, truncated to the buffer (like Linux).
    let n = target.len().min(size as usize);
    if p.copy_to_user(buf, &target[..n]) != n {
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

/// `fchmodat2(dirfd, path, mode, flags)`: symbolic links have no mode.
pub(super) fn fchmodat2(
    p: &mut LinuxProcess,
    dirfd: i64,
    addr: u64,
    mode: u64,
    flags: u64,
) -> Result<u64, i64> {
    const EOPNOTSUPP: i64 = 95;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(EINVAL);
    }
    let ino = inode_at(p, dirfd, addr, flags)?;
    let mut fs = p.fs();
    if fs.stat(ino)?.kind == Kind::Symlink {
        return Err(EOPNOTSUPP);
    }
    fs.chmod(ino, mode as u32)?;
    Ok(0)
}

pub(super) fn fchmod(p: &mut LinuxProcess, fd: u64, mode: u64) -> Result<u64, i64> {
    let f = match p.fd(fd).ok_or(EBADF)? {
        Fd::File(f) => f,
        // An inode nobody else opens by its mode (a bound socket's name is
        // another one): nothing keeps it.
        Fd::Pipe(_) | Fd::Object(_) => return Ok(0),
        Fd::Console | Fd::Dev(_) => return Err(EPERM),
    };
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
    let mut path = overlay::name::decode(&p.fs().path(cwd)?);
    path.push(0);
    if (size as usize) < path.len() {
        return Err(ERANGE);
    }
    if p.copy_to_user(buf, &path) != path.len() {
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
    let src = match p.fd(in_fd).ok_or(EBADF)? {
        Fd::File(f) => f,
        Fd::Pipe(_) | Fd::Object(_) if offp != 0 => return Err(ESPIPE),
        // Not something to read pages of (callers read and write instead).
        _ => return Err(EINVAL),
    };
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
    // What counts is what was written, not what was read: a socket or a
    // pipe may take part of a chunk, and an error after some progress
    // (EAGAIN on a full non-blocking socket, a signal) returns the
    // progress, as Linux does. Otherwise a non-blocking caller told EAGAIN
    // sends again what already went out (asyncio did, without end).
    while done < count {
        let want = CHUNK.min(count - done);
        let n = match p.vfs.read(src.ino, offset, &mut buf[..want]) {
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        let wrote: Result<usize, i64> = match p.fd(out_fd).ok_or(EBADF)? {
            Fd::File(o) => {
                let at = if o.flags & O_APPEND != 0 {
                    p.fs().stat(o.ino)?.size
                } else {
                    o.offset
                };
                let r = p.fs().write(o.ino, at, &buf[..n]);
                if let Ok(m) = r {
                    p.with_file(out_fd, |of| {
                        of.offset = at + m as u64;
                    });
                }
                r
            }
            f => stream_write(p, &f, &buf[..n], false),
        };
        let m = match wrote {
            Ok(m) => m,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        offset += m as u64;
        done += m;
        if m < n {
            break; // the rest did not fit: report what went
        }
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

/// `pipe2`: a new pipe; `[read fd, write fd]` go to `fds` as two `int`s.
pub(super) fn pipe2(p: &mut LinuxProcess, fds: u64, flags: u64) -> Result<u64, i64> {
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let pipe = Pipe::new(p.cell.account());
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
    let proc = match place(p, start, &path, true)? {
        Place::Proc(path) => {
            stat_proc(p, &path, true, 0)?;
            true
        }
        Place::Tree(_) => false,
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
