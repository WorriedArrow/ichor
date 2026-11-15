//! Linux processes and threads.
//!
//! A [`Group`] is a Linux process (a thread group): its address space,
//! file-descriptor table, working directory, umask and signal dispositions,
//! shared by its threads behind sleeping locks. A [`LinuxProcess`] is one
//! thread of a group: its table entry (tid, pending signals), signal mask,
//! and `clear_child_tid` address. `fork` makes a new group; `clone` with
//! `CLONE_VM | CLONE_THREAD` adds a thread to the caller's group.
//!
//! In ADR-0002 terms the fd table is a per-process view mapping fd numbers
//! to objects the process holds: the console, open files on the root,
//! pipes and devices. Every descriptor holds a reference on what it names
//! (an open count on an inode, a reader/writer count on a pipe), so a file
//! survives `unlink` while open.

use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::sync::{Mutex, MutexGuard, SpinLock};

use crate::kcell::Cell;
use crate::pipe::Pipe;
use crate::proc::{self, ProcEntry};
use crate::signal::{Actions, Signals};
use crate::umem::Mm;
use crate::vfs::{Ino, ROOT, Vfs};

/// Most descriptors a process may hold (Linux's default `RLIMIT_NOFILE`).
pub(crate) const MAX_FDS: usize = 1024;

/// An open file on the root.
///
/// `dup` copies the offset rather than sharing it (Linux shares one open
/// file description); nothing so far depends on the difference.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenFile {
    pub(crate) ino: Ino,
    pub(crate) offset: u64,
    /// The `open` flags that matter after opening (access mode, append).
    pub(crate) flags: u64,
}

/// One end of a pipe, as a descriptor holds it.
#[derive(Clone, Debug)]
pub(crate) struct PipeEnd {
    pub(crate) pipe: Arc<Pipe>,
    /// The write end (otherwise the read end).
    pub(crate) write: bool,
    pub(crate) nonblock: bool,
}

/// What a descriptor refers to.
#[derive(Clone, Debug)]
pub(crate) enum Fd {
    /// The kernel console (stdin reads EOF, stdout/stderr print).
    Console,
    File(OpenFile),
    Pipe(PipeEnd),
    /// A character device other than the console.
    Dev(crate::dev::Device),
    /// A kernel object: eventfd, epoll instance, ...
    Object(ObjectEnd),
}

/// A descriptor's reference to a kernel object.
#[derive(Clone, Debug)]
pub(crate) struct ObjectEnd {
    pub(crate) obj: Arc<dyn crate::poll::Object>,
    pub(crate) nonblock: bool,
}

/// A group's files: descriptors, working directory (holding an open
/// reference) and umask.
struct Files {
    fds: Vec<Option<Fd>>,
    cwd: Ino,
    umask: u32,
}

/// A Linux process: what its threads share.
pub(crate) struct Group {
    /// The thread group id (the leader's tid; `getpid`).
    pub(crate) tgid: u64,
    /// The leader's table entry, which carries the group's exit status.
    pub(crate) leader: Arc<ProcEntry>,
    vfs: Arc<Vfs>,
    mm: Mutex<Mm>,
    files: Mutex<Files>,
    pub(crate) actions: Mutex<Actions>,
    /// Live threads.
    threads: SpinLock<Vec<Arc<ProcEntry>>>,
    /// Set by `exit_group` or a fatal signal: the group's wait status.
    exit: SpinLock<Option<u32>>,
    /// The program's path and argv (NUL-separated), for `/proc`.
    exe: SpinLock<(alloc::string::String, Vec<u8>)>,
}

impl Group {
    /// Takes the references a descriptor needs.
    fn hold(&self, f: &Fd) {
        match f {
            Fd::Console | Fd::Dev(_) | Fd::Object(_) => {}
            Fd::File(of) => {
                let _ = self.vfs.lock().open(of.ino);
            }
            Fd::Pipe(e) => e.pipe.add(e.write),
        }
    }

    /// Drops the references a descriptor held.
    fn release(&self, f: Fd) {
        match f {
            Fd::Console | Fd::Dev(_) | Fd::Object(_) => {}
            Fd::File(of) => self.vfs.lock().close(of.ino),
            Fd::Pipe(e) => e.pipe.drop_end(e.write),
        }
    }

    /// Records the program the process runs (load or `execve`).
    pub(crate) fn set_exec(&self, path: &str, argv: &[&str]) {
        let mut cmd = Vec::new();
        for a in argv {
            cmd.extend_from_slice(a.as_bytes());
            cmd.push(0);
        }
        *self.exe.lock() = (alloc::string::String::from(path), cmd);
    }

    /// The program's path (`/proc/<pid>/exe`).
    pub(crate) fn exe(&self) -> alloc::string::String {
        self.exe.lock().0.clone()
    }

    /// The program's argv, NUL-separated (`/proc/<pid>/cmdline`).
    pub(crate) fn cmdline(&self) -> Vec<u8> {
        self.exe.lock().1.clone()
    }

    /// The threads still running.
    pub(crate) fn threads(&self) -> Vec<Arc<ProcEntry>> {
        self.threads.lock().clone()
    }

    /// Records the group's exit status (the first one wins) and kills its
    /// other threads.
    pub(crate) fn begin_exit(&self, status: u32, me: &ProcEntry) {
        {
            let mut e = self.exit.lock();
            if e.is_none() {
                *e = Some(status);
            }
        }
        for t in self.threads() {
            if t.pid != me.pid {
                proc::post(&t, crate::signal::SIGKILL);
            }
        }
    }

    /// Removes `me` from the live threads; returns the group's wait status
    /// if it was the last (its exit status, or `status`, the last thread's).
    pub(crate) fn thread_exited(&self, me: &ProcEntry, status: u32) -> Option<u32> {
        let mut t = self.threads.lock();
        t.retain(|e| e.pid != me.pid);
        if !t.is_empty() {
            return None;
        }
        drop(t);
        Some(self.exit.lock().unwrap_or(status))
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        let (fds, cwd) = {
            let mut files = self.files.lock();
            (core::mem::take(&mut files.fds), files.cwd)
        };
        let mut fs = self.vfs.lock();
        for f in fds.into_iter().flatten() {
            match f {
                Fd::Console | Fd::Dev(_) | Fd::Object(_) => {}
                Fd::File(of) => fs.close(of.ino),
                Fd::Pipe(e) => e.pipe.drop_end(e.write),
            }
        }
        fs.close(cwd);
    }
}

/// A thread of a Linux process.
pub(crate) struct LinuxProcess {
    /// This thread's table entry (its tid, pending signals).
    pub(crate) entry: Arc<ProcEntry>,
    pub(crate) group: Arc<Group>,
    pub(crate) cell: Arc<Cell>,
    pub(crate) vfs: Arc<Vfs>,
    /// Signal mask (dispositions are the group's).
    pub(crate) sig: Signals,
    /// `CLONE_CHILD_CLEARTID` / `set_tid_address`: zeroed and futex-woken
    /// when the thread exits.
    pub(crate) clear_tid: u64,
}

impl LinuxProcess {
    /// A process in `cell` with an empty address space, `vfs` as its root,
    /// `/` as its working directory, and the console on fds 0–2. `None` if
    /// memory runs out.
    pub(crate) fn new(cell: Arc<Cell>, vfs: Arc<Vfs>) -> Option<Self> {
        let mm = Mm::new(cell.account())?;
        let _ = vfs.lock().open(ROOT);
        let entry = proc::register(0, None);
        let group = Arc::new(Group {
            tgid: entry.pid,
            leader: entry.clone(),
            vfs: vfs.clone(),
            mm: Mutex::new(mm),
            files: Mutex::new(Files {
                fds: alloc::vec![Some(Fd::Console); 3],
                cwd: ROOT,
                umask: 0o022,
            }),
            actions: Mutex::new(Actions::new()),
            threads: SpinLock::new(alloc::vec![entry.clone()]),
            exit: SpinLock::new(None),
            exe: SpinLock::new(Default::default()),
        });
        Some(Self {
            entry,
            group,
            cell,
            vfs,
            sig: Signals::new(),
            clear_tid: 0,
        })
    }

    /// A copy of this process for `fork`: a copy-on-write copy of its
    /// memory, the same open files (each with a new reference), working
    /// directory, umask and signal state, in a new group whose parent is
    /// this process. Only the calling thread is copied.
    pub(crate) fn fork(&mut self) -> Option<Self> {
        let mm = self.mm().fork()?;
        let (fds, cwd, umask) = {
            let f = self.group.files.lock();
            (f.fds.clone(), f.cwd, f.umask)
        };
        let _ = self.vfs.lock().open(cwd);
        for f in fds.iter().flatten() {
            self.group.hold(f);
        }
        let actions = self.group.actions.lock().clone();
        let exe = self.group.exe.lock().clone();
        let entry = proc::register(self.group.tgid, None);
        let group = Arc::new(Group {
            tgid: entry.pid,
            leader: entry.clone(),
            vfs: self.vfs.clone(),
            mm: Mutex::new(mm),
            files: Mutex::new(Files { fds, cwd, umask }),
            actions: Mutex::new(actions),
            threads: SpinLock::new(alloc::vec![entry.clone()]),
            exit: SpinLock::new(None),
            exe: SpinLock::new(exe),
        });
        Some(Self {
            entry,
            group,
            cell: self.cell.clone(),
            vfs: self.vfs.clone(),
            sig: self.sig.clone(),
            clear_tid: 0,
        })
    }

    /// A new thread in this process (`clone` with `CLONE_VM |
    /// CLONE_THREAD`): shares everything but its tid and signal mask.
    pub(crate) fn new_thread(&self) -> Self {
        let entry = proc::register(self.entry.ppid(), Some(self.group.tgid));
        self.group.threads.lock().push(entry.clone());
        Self {
            entry,
            group: self.group.clone(),
            cell: self.cell.clone(),
            vfs: self.vfs.clone(),
            sig: self.sig.clone(),
            clear_tid: 0,
        }
    }

    /// The process's address space (locked).
    pub(crate) fn mm(&self) -> MutexGuard<'_, Mm> {
        self.group.mm.lock()
    }

    /// Replaces the address space (`execve`), returning the old one.
    pub(crate) fn replace_mm(&self, mm: Mm) -> Mm {
        core::mem::replace(&mut *self.group.mm.lock(), mm)
    }

    /// Copies `data` to user memory at `va`, faulting in demand-paged
    /// memory first. Returns how many bytes were copied.
    pub(crate) fn copy_to_user(&mut self, va: u64, data: &[u8]) -> usize {
        let mut mm = self.mm();
        mm.populate(va, data.len(), true);
        mm.space().copy_to_user(va, data)
    }

    /// Copies user memory at `va` into `out`, faulting in demand-paged
    /// memory first. Returns how many bytes were copied.
    pub(crate) fn copy_from_user(&mut self, va: u64, out: &mut [u8]) -> usize {
        let mut mm = self.mm();
        mm.populate(va, out.len(), false);
        mm.space().copy_from_user(va, out)
    }

    /// The working directory.
    pub(crate) fn cwd(&self) -> Ino {
        self.group.files.lock().cwd
    }

    pub(crate) fn umask(&self) -> u32 {
        self.group.files.lock().umask
    }

    /// Sets the umask, returning the old one.
    pub(crate) fn set_umask(&self, mask: u32) -> u32 {
        core::mem::replace(&mut self.group.files.lock().umask, mask)
    }

    /// Changes the working directory to `ino` (a directory).
    pub(crate) fn set_cwd(&mut self, ino: Ino) {
        let mut files = self.group.files.lock();
        let mut fs = self.vfs.lock();
        if fs.open(ino).is_ok() {
            fs.close(files.cwd);
            files.cwd = ino;
        }
    }

    /// The descriptor `fd`, if open.
    pub(crate) fn fd(&self, fd: u64) -> Option<Fd> {
        let files = self.group.files.lock();
        files.fds.get(usize::try_from(fd).ok()?).cloned().flatten()
    }

    /// Runs `f` on an open file's state (its offset, say).
    pub(crate) fn with_file<R>(&self, fd: u64, f: impl FnOnce(&mut OpenFile) -> R) -> Option<R> {
        let mut files = self.group.files.lock();
        match files.fds.get_mut(usize::try_from(fd).ok()?)? {
            Some(Fd::File(of)) => Some(f(of)),
            _ => None,
        }
    }

    /// Stores `f` at the lowest free descriptor at or above `min` (POSIX
    /// semantics); the caller's reference moves into the table. Hands `f`
    /// back if the table is full.
    fn place(&self, f: Fd, min: usize) -> Result<u64, Fd> {
        let mut files = self.group.files.lock();
        let fds = &mut files.fds;
        if min >= MAX_FDS {
            return Err(f);
        }
        if fds.len() <= min {
            fds.resize(min + 1, None);
        }
        let i = (min..fds.len())
            .find(|&i| fds.get(i).is_some_and(Option::is_none))
            .unwrap_or(fds.len());
        if i >= MAX_FDS {
            return Err(f);
        }
        if i == fds.len() {
            fds.push(None);
        }
        match fds.get_mut(i) {
            Some(slot) => {
                *slot = Some(f);
                Ok(i as u64)
            }
            None => Err(f),
        }
    }

    /// Installs a freshly opened `f` (whose reference the caller took) at
    /// the lowest free descriptor. On failure the reference is dropped.
    pub(crate) fn install(&mut self, f: Fd) -> Option<u64> {
        match self.place(f, 0) {
            Ok(n) => Some(n),
            Err(f) => {
                self.group.release(f);
                None
            }
        }
    }

    /// Duplicates `fd` to the lowest free descriptor at or above `min`.
    pub(crate) fn dup_from(&mut self, fd: u64, min: u64) -> Option<u64> {
        let f = self.fd(fd)?;
        let min = usize::try_from(min).ok()?;
        self.group.hold(&f);
        match self.place(f, min) {
            Ok(n) => Some(n),
            Err(f) => {
                self.group.release(f);
                None
            }
        }
    }

    /// Makes `new` refer to what `old` refers to (closing `new` first).
    pub(crate) fn dup_to(&mut self, old: u64, new: u64) -> Option<u64> {
        let f = self.fd(old)?;
        if old == new {
            return Some(new);
        }
        let n = usize::try_from(new).ok().filter(|&n| n < MAX_FDS)?;
        self.group.hold(&f);
        let prev = {
            let mut files = self.group.files.lock();
            if files.fds.len() <= n {
                files.fds.resize(n + 1, None);
            }
            files.fds.get_mut(n)?.replace(f)
        };
        if let Some(p) = prev {
            self.group.release(p);
        }
        Some(new)
    }

    /// Closes `fd`. Returns false if it was not open.
    pub(crate) fn close(&mut self, fd: u64) -> bool {
        let taken = {
            let mut files = self.group.files.lock();
            usize::try_from(fd)
                .ok()
                .and_then(|i| files.fds.get_mut(i))
                .and_then(Option::take)
        };
        match taken {
            Some(f) => {
                self.group.release(f);
                true
            }
            None => false,
        }
    }
}
