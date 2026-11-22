//! Moving bytes between descriptors inside the kernel: `splice`, `tee`,
//! `vmsplice` and `copy_file_range`. Bytes are copied (no pages change
//! hands), which is all these promise; what matters to their callers (Go's
//! `io.Copy`, nginx, coreutils) is which descriptors they accept, what they
//! return after part of the work, and what they leave behind.

use alloc::vec::Vec;

use super::fs::{self, O_ACCMODE, O_WRONLY, stream_read, stream_write};
use super::{EBADF, EFAULT, EINVAL};
use crate::proc;
use crate::process::{Fd, LinuxProcess, OpenFile, PipeEnd};
use crate::vfs::Kind;
use crate::vfs::errno::EISDIR;

const EPIPE: i64 = 32;
const ESPIPE: i64 = 29;
const EAGAIN: i64 = 11;
const EOVERFLOW: i64 = 75;

const SPLICE_F_NONBLOCK: u64 = 2;
/// MOVE, NONBLOCK, MORE, GIFT.
const SPLICE_F_ALL: u64 = 15;
/// Most bytes moved at a time.
const STEP: usize = 64 * 1024;

fn read_off(p: &mut LinuxProcess, at: u64) -> Result<Option<u64>, i64> {
    if at == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 8];
    if p.copy_from_user(at, &mut b) != 8 {
        return Err(EFAULT);
    }
    let v = u64::from_le_bytes(b);
    if v > i64::MAX as u64 {
        return Err(EINVAL);
    }
    Ok(Some(v))
}

/// Where in a file a splice is: at the caller's offset, or the
/// description's.
struct At {
    /// The user's `loff_t *`, and its value.
    given: Option<(u64, u64)>,
    fd: u64,
}

impl At {
    fn get(&self, of: &OpenFile) -> u64 {
        self.given.map_or(of.offset, |(_, v)| v)
    }

    /// Moves on by `n` (to `to` exactly, if given).
    fn advance(&mut self, p: &LinuxProcess, to: u64) {
        match &mut self.given {
            Some((_, v)) => *v = to,
            None => {
                p.with_file(self.fd, |f| f.offset = to);
            }
        }
    }

    /// Writes the offset back to the user.
    fn store(&self, p: &mut LinuxProcess) -> Result<(), i64> {
        match self.given {
            Some((at, v)) if p.copy_to_user(at, &v.to_le_bytes()) != 8 => Err(EFAULT),
            _ => Ok(()),
        }
    }
}

/// Writes `data` to `f` (a file, at `at`; anything else), in one go.
fn put(p: &mut LinuxProcess, f: &Fd, at: &mut At, data: &[u8], nb: bool) -> Result<usize, i64> {
    match f {
        Fd::File(_) => {
            let Some(Fd::File(of)) = p.fd(at.fd) else {
                return Err(EBADF);
            };
            let pos = at.get(&of);
            let n = p.fs().write(of.ino, pos, data)?;
            at.advance(p, pos + n as u64);
            Ok(n)
        }
        _ => stream_write(p, f, data, nb),
    }
}

/// `splice(fd_in, off_in, fd_out, off_out, len, flags)`: at least one is a
/// pipe. Returns what was moved, as soon as some was: what a pipe holds, or
/// what one read of the other side gives. Bytes taken out of a pipe that
/// the other side does not take go back.
pub(super) fn splice(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let (fd_in, off_in, fd_out, off_out, len, flags) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    let nb = flags & SPLICE_F_NONBLOCK != 0;
    if flags & !SPLICE_F_ALL != 0 {
        return Err(EINVAL);
    }
    let (src, dst) = (p.fd(fd_in).ok_or(EBADF)?, p.fd(fd_out).ok_or(EBADF)?);
    for (f, off, write) in [(&src, off_in, false), (&dst, off_out, true)] {
        match f {
            Fd::Pipe(_) if off != 0 => return Err(ESPIPE),
            Fd::Pipe(e) if e.write != write => return Err(EBADF),
            Fd::Pipe(_) => {}
            Fd::File(of) => {
                let mode = of.flags & O_ACCMODE;
                if (write && mode == 0) || (!write && mode == O_WRONLY) {
                    return Err(EBADF);
                }
                if write && of.flags & fs::O_APPEND != 0 {
                    return Err(EINVAL);
                }
            }
            _ if off != 0 => return Err(ESPIPE),
            _ => {}
        }
    }
    let given = |p: &mut LinuxProcess, at: u64| read_off(p, at).map(|v| v.map(|v| (at, v)));
    let mut at_in = At {
        given: given(p, off_in)?,
        fd: fd_in,
    };
    let mut at_out = At {
        given: given(p, off_out)?,
        fd: fd_out,
    };
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    if len == 0 {
        return Ok(0);
    }
    let entry = p.entry.clone();
    let interrupted = || proc::interrupted(&entry);
    let moved = match (&src, &dst) {
        (Fd::Pipe(i), Fd::Pipe(o)) if alloc::sync::Arc::ptr_eq(&i.pipe, &o.pipe) => {
            return Err(EINVAL);
        }
        // Out of a pipe.
        (Fd::Pipe(i), _) => {
            let data = i.pipe.take(len.min(STEP), i.nonblock || nb, &interrupted)?;
            let r = put(p, &dst, &mut at_out, &data, nb);
            i.pipe.give_back(&data[r.unwrap_or(0).min(data.len())..]);
            r?
        }
        // Into a pipe: no more than it has room for.
        (_, Fd::Pipe(o)) => {
            let room = match o.pipe.room(o.nonblock || nb, &interrupted) {
                Err(EPIPE) => {
                    proc::post(&p.entry, crate::signal::SIGPIPE);
                    return Err(EPIPE);
                }
                r => r?,
            };
            let want = len.min(room).min(STEP);
            let data = match &src {
                Fd::File(_) => {
                    let Some(Fd::File(of)) = p.fd(fd_in) else {
                        return Err(EBADF);
                    };
                    let mut b = alloc::vec![0u8; want];
                    let pos = at_in.get(&of);
                    let n = p.vfs.read(of.ino, pos, &mut b)?;
                    b.truncate(n);
                    at_in.advance(p, pos + n as u64);
                    b
                }
                f => stream_read(p, f, want, nb)?,
            };
            fill(p, o, &data)?
        }
        _ => return Err(EINVAL),
    };
    at_in.store(p)?;
    at_out.store(p)?;
    Ok(moved as u64)
}

/// Writes all of `data` to a pipe that had room for it: another writer may
/// have taken the room since, so this may wait (what was read must not be
/// lost) until a reader makes some or is gone.
fn fill(p: &LinuxProcess, o: &PipeEnd, data: &[u8]) -> Result<usize, i64> {
    let mut done = 0;
    while done < data.len() {
        match o.pipe.write(&data[done..], false, &|| false) {
            Ok(n) => done += n,
            Err(e) => {
                if e == EPIPE {
                    proc::post(&p.entry, crate::signal::SIGPIPE);
                }
                return if done == 0 { Err(e) } else { Ok(done) };
            }
        }
    }
    Ok(done)
}

/// `tee(fd_in, fd_out, len, flags)`: copies what pipe `fd_in` holds to pipe
/// `fd_out`, leaving it there.
pub(super) fn tee(
    p: &mut LinuxProcess,
    fd_in: u64,
    fd_out: u64,
    len: u64,
    flags: u64,
) -> Result<u64, i64> {
    if flags & !SPLICE_F_ALL != 0 {
        return Err(EINVAL);
    }
    let (Fd::Pipe(i), Fd::Pipe(o)) = (p.fd(fd_in).ok_or(EBADF)?, p.fd(fd_out).ok_or(EBADF)?) else {
        return Err(EINVAL);
    };
    if i.write || !o.write {
        return Err(EBADF);
    }
    if alloc::sync::Arc::ptr_eq(&i.pipe, &o.pipe) {
        return Err(EINVAL);
    }
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    if len == 0 {
        return Ok(0);
    }
    let nb = flags & SPLICE_F_NONBLOCK != 0;
    let entry = p.entry.clone();
    let interrupted = || proc::interrupted(&entry);
    let room = o.pipe.room(o.nonblock || nb, &interrupted)?;
    let data = i
        .pipe
        .peek(len.min(room).min(STEP), i.nonblock || nb, &interrupted)?;
    if data.is_empty() {
        return Ok(0);
    }
    // Without waiting: nothing is lost if another writer was faster.
    let n = o.pipe.write(&data, true, &interrupted)?;
    if n == 0 { Err(EAGAIN) } else { Ok(n as u64) }
}

/// `vmsplice(fd, iov, nr_segs, flags)`: user memory into a pipe's write end
/// (or out of its read end), which without moving pages is `writev` (or
/// `readv`).
pub(super) fn vmsplice(
    p: &mut LinuxProcess,
    fd: u64,
    iov: u64,
    n: usize,
    flags: u64,
) -> Result<u64, i64> {
    if flags & !SPLICE_F_ALL != 0 {
        return Err(EINVAL);
    }
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Pipe(e) => {
            if flags & SPLICE_F_NONBLOCK != 0 && e.write {
                e.pipe.room(true, &|| false)?;
            }
            fs::vector(p, fd, iov, n, e.write)
        }
        _ => Err(EBADF),
    }
}

/// `copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)`: between
/// two regular files (or two ranges of one that do not overlap).
pub(super) fn copy_file_range(p: &mut LinuxProcess, a: &[u64; 6]) -> Result<u64, i64> {
    let (fd_in, off_in, fd_out, off_out, len, flags) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    if flags != 0 {
        return Err(EINVAL);
    }
    let open = |p: &LinuxProcess, fd: u64| match p.fd(fd).ok_or(EBADF)? {
        Fd::File(f) => Ok(f),
        _ => Err(EINVAL),
    };
    let (src, dst) = (open(p, fd_in)?, open(p, fd_out)?);
    if src.flags & O_ACCMODE == O_WRONLY
        || dst.flags & O_ACCMODE == 0
        || dst.flags & fs::O_APPEND != 0
    {
        return Err(EBADF);
    }
    for ino in [src.ino, dst.ino] {
        match p.vfs.lock().stat(ino)?.kind {
            Kind::File => {}
            Kind::Directory => return Err(EISDIR),
            _ => return Err(EINVAL),
        }
    }
    let given = |p: &mut LinuxProcess, at: u64| read_off(p, at).map(|v| v.map(|v| (at, v)));
    let mut at_in = At {
        given: given(p, off_in)?,
        fd: fd_in,
    };
    let mut at_out = At {
        given: given(p, off_out)?,
        fd: fd_out,
    };
    let (from, to) = (at_in.get(&src), at_out.get(&dst));
    let len = len.min(i64::MAX as u64);
    let ends = (from.checked_add(len), to.checked_add(len));
    let (Some(from_end), Some(to_end)) = ends else {
        return Err(EOVERFLOW);
    };
    if src.ino == dst.ino && from < to_end && to < from_end {
        return Err(EINVAL);
    }
    let mut buf: Vec<u8> = alloc::vec![0u8; STEP.min(len as usize)];
    let mut done = 0u64;
    while done < len {
        let want = buf.len().min((len - done) as usize);
        let n = match p.vfs.read(src.ino, from + done, &mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        let wrote = p.fs().write(dst.ino, to + done, &buf[..n]);
        match wrote {
            Ok(m) => {
                done += m as u64;
                if m < n {
                    break;
                }
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    at_in.advance(p, from + done);
    at_out.advance(p, to + done);
    at_in.store(p)?;
    at_out.store(p)?;
    Ok(done)
}
