//! A Linux-personality process: the cell it runs in, its root file system,
//! and its file-descriptor table.
//!
//! In ADR-0002 terms the fd table is a per-process view mapping fd numbers
//! to objects the process holds. For now the objects are the console and
//! open files on the read-only root; sockets, pipes and the rest join as the
//! Linux ABI grows.

use alloc::sync::Arc;
use alloc::vec::Vec;

use image::Node;

use crate::kcell::Cell;
use crate::umem::Mm;
use crate::vfs::Vfs;

/// Most descriptors a process may hold (Linux's default `RLIMIT_NOFILE`).
pub(crate) const MAX_FDS: usize = 1024;

/// An open file on the read-only root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenFile {
    pub(crate) node: Node<'static>,
    pub(crate) offset: u64,
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
    fds: Vec<Option<Fd>>,
}

impl LinuxProcess {
    /// A process in `cell` with `vfs` as its root and the console on fds 0–2.
    pub(crate) fn new(cell: Arc<Cell>, vfs: Arc<Vfs>) -> Self {
        Self {
            cell,
            vfs,
            mm: Mm::new(),
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

    /// Duplicates `fd` to the lowest free descriptor at or above `min`.
    pub(crate) fn dup_from(&mut self, fd: u64, min: u64) -> Option<u64> {
        let f = self.fd(fd)?;
        let min = usize::try_from(min).ok()?;
        if min >= MAX_FDS {
            return None;
        }
        if self.fds.len() <= min {
            self.fds.resize(min + 1, None);
        }
        let i = (min..self.fds.len())
            .find(|&i| self.fds[i].is_none())
            .unwrap_or(self.fds.len());
        if i >= MAX_FDS {
            return None;
        }
        if i == self.fds.len() {
            self.fds.push(None);
        }
        self.fds[i] = Some(f);
        Some(i as u64)
    }

    /// Makes `new` refer to what `old` refers to (closing `new` first).
    pub(crate) fn dup_to(&mut self, old: u64, new: u64) -> Option<u64> {
        let f = self.fd(old)?;
        let n = usize::try_from(new).ok().filter(|&n| n < MAX_FDS)?;
        if self.fds.len() <= n {
            self.fds.resize(n + 1, None);
        }
        self.fds[n] = Some(f);
        Some(new)
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

    /// Installs `f` at the lowest free descriptor (POSIX semantics).
    pub(crate) fn install(&mut self, f: Fd) -> Option<u64> {
        if let Some(i) = self.fds.iter().position(Option::is_none) {
            self.fds[i] = Some(f);
            return Some(i as u64);
        }
        if self.fds.len() >= MAX_FDS {
            return None;
        }
        self.fds.push(Some(f));
        Some(self.fds.len() as u64 - 1)
    }

    /// Closes `fd`. Returns false if it was not open.
    pub(crate) fn close(&mut self, fd: u64) -> bool {
        match usize::try_from(fd).ok().and_then(|i| self.fds.get_mut(i)) {
            Some(slot @ Some(_)) => {
                *slot = None;
                true
            }
            _ => false,
        }
    }
}
