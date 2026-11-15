//! A Linux-personality process: the cell it runs in, its root file system,
//! working directory, memory, and file-descriptor table.
//!
//! In ADR-0002 terms the fd table is a per-process view mapping fd numbers
//! to objects the process holds. For now the objects are the console and
//! open files on the root; sockets, pipes and the rest join as the Linux ABI
//! grows. Every descriptor holds an open reference on its inode, so a file
//! survives `unlink` while open.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::kcell::Cell;
use crate::umem::Mm;
use crate::vfs::{Ino, ROOT, Vfs};

/// Most descriptors a process may hold (Linux's default `RLIMIT_NOFILE`).
pub(crate) const MAX_FDS: usize = 1024;

/// An open file on the root.
///
/// `dup` copies the offset rather than sharing it (Linux shares one open
/// file description); nothing in milestone 3 depends on the difference.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenFile {
    pub(crate) ino: Ino,
    pub(crate) offset: u64,
    /// The `open` flags that matter after opening (access mode, append).
    pub(crate) flags: u64,
}

/// What a descriptor refers to.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Fd {
    /// The kernel console (stdin reads EOF, stdout/stderr print).
    Console,
    File(OpenFile),
}

/// A Linux process.
pub(crate) struct LinuxProcess {
    pub(crate) cell: Arc<Cell>,
    pub(crate) vfs: Arc<Vfs>,
    pub(crate) mm: Mm,
    /// The working directory (holds an open reference).
    pub(crate) cwd: Ino,
    pub(crate) umask: u32,
    fds: Vec<Option<Fd>>,
}

impl LinuxProcess {
    /// A process in `cell` with `vfs` as its root, `/` as its working
    /// directory, and the console on fds 0–2.
    pub(crate) fn new(cell: Arc<Cell>, vfs: Arc<Vfs>) -> Self {
        let _ = vfs.lock().open(ROOT);
        Self {
            cell,
            vfs,
            mm: Mm::new(),
            cwd: ROOT,
            umask: 0o022,
            fds: alloc::vec![Some(Fd::Console); 3],
        }
    }

    /// Copies `data` to user memory at `va`, faulting in demand-paged
    /// memory first. Returns how many bytes were copied.
    pub(crate) fn copy_to_user(&mut self, va: u64, data: &[u8]) -> usize {
        self.mm.populate(&self.cell, va, data.len(), true);
        self.cell.space().copy_to_user(va, data)
    }

    /// Copies user memory at `va` into `out`, faulting in demand-paged
    /// memory first. Returns how many bytes were copied.
    pub(crate) fn copy_from_user(&mut self, va: u64, out: &mut [u8]) -> usize {
        self.mm.populate(&self.cell, va, out.len(), false);
        self.cell.space().copy_from_user(va, out)
    }

    /// Changes the working directory to `ino` (a directory).
    pub(crate) fn set_cwd(&mut self, ino: Ino) {
        let mut fs = self.vfs.lock();
        if fs.open(ino).is_ok() {
            fs.close(self.cwd);
            self.cwd = ino;
        }
    }

    /// The descriptor `fd`, if open.
    pub(crate) fn fd(&self, fd: u64) -> Option<Fd> {
        self.fds.get(usize::try_from(fd).ok()?).copied().flatten()
    }

    /// Mutable access to an open file's state.
    pub(crate) fn file_mut(&mut self, fd: u64) -> Option<&mut OpenFile> {
        match self.fds.get_mut(usize::try_from(fd).ok()?)? {
            Some(Fd::File(f)) => Some(f),
            _ => None,
        }
    }

    /// Takes an open reference for a descriptor about to be stored.
    fn hold(&self, f: Fd) {
        if let Fd::File(of) = f {
            let _ = self.vfs.lock().open(of.ino);
        }
    }

    /// Drops the open reference a descriptor held.
    fn release(&self, f: Fd) {
        if let Fd::File(of) = f {
            self.vfs.lock().close(of.ino);
        }
    }

    /// Stores `f` at the lowest free descriptor at or above `min` (POSIX
    /// semantics). The caller's open reference moves into the table.
    fn place(&mut self, f: Fd, min: usize) -> Option<u64> {
        if min >= MAX_FDS {
            return None;
        }
        if self.fds.len() <= min {
            self.fds.resize(min + 1, None);
        }
        let i = (min..self.fds.len())
            .find(|&i| self.fds.get(i).is_some_and(Option::is_none))
            .unwrap_or(self.fds.len());
        if i >= MAX_FDS {
            return None;
        }
        if i == self.fds.len() {
            self.fds.push(None);
        }
        *self.fds.get_mut(i)? = Some(f);
        Some(i as u64)
    }

    /// Installs a freshly opened `f` (whose open reference the caller took)
    /// at the lowest free descriptor. On failure the reference is dropped.
    pub(crate) fn install(&mut self, f: Fd) -> Option<u64> {
        let r = self.place(f, 0);
        if r.is_none() {
            self.release(f);
        }
        r
    }

    /// Duplicates `fd` to the lowest free descriptor at or above `min`.
    pub(crate) fn dup_from(&mut self, fd: u64, min: u64) -> Option<u64> {
        let f = self.fd(fd)?;
        self.hold(f);
        let r = self.place(f, usize::try_from(min).ok()?);
        if r.is_none() {
            self.release(f);
        }
        r
    }

    /// Makes `new` refer to what `old` refers to (closing `new` first).
    pub(crate) fn dup_to(&mut self, old: u64, new: u64) -> Option<u64> {
        let f = self.fd(old)?;
        if old == new {
            return Some(new);
        }
        let n = usize::try_from(new).ok().filter(|&n| n < MAX_FDS)?;
        if self.fds.len() <= n {
            self.fds.resize(n + 1, None);
        }
        self.hold(f);
        let prev = self.fds.get_mut(n)?.replace(f);
        if let Some(p) = prev {
            self.release(p);
        }
        Some(new)
    }

    /// Closes `fd`. Returns false if it was not open.
    pub(crate) fn close(&mut self, fd: u64) -> bool {
        let taken = usize::try_from(fd)
            .ok()
            .and_then(|i| self.fds.get_mut(i))
            .and_then(Option::take);
        match taken {
            Some(f) => {
                self.release(f);
                true
            }
            None => false,
        }
    }
}

impl Drop for LinuxProcess {
    fn drop(&mut self) {
        let fds = core::mem::take(&mut self.fds);
        let mut fs = self.vfs.lock();
        for f in fds.into_iter().flatten() {
            if let Fd::File(of) = f {
                fs.close(of.ino);
            }
        }
        fs.close(self.cwd);
    }
}
