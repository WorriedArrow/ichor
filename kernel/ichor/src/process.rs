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

/// An open file description: what `open`, `pipe`, `eventfd`, ... create.
/// `dup`, `dup2`, `F_DUPFD` and `fork` share one, so its offset and status
/// flags (`O_APPEND`, `O_NONBLOCK`) are shared too. It holds the reference
/// on what it names (an inode's open count, a pipe end) and drops it, and
/// its `flock`/OFD locks, when the last descriptor goes.
#[derive(Debug)]
pub(crate) struct Description {
    state: Mutex<Fd>,
    vfs: Arc<Vfs>,
}

impl Description {
    /// A description for `fd`, whose reference the caller took.
    pub(crate) fn new(fd: Fd, vfs: &Arc<Vfs>) -> Arc<Description> {
        Arc::new(Description {
            state: Mutex::new(fd),
            vfs: vfs.clone(),
        })
    }

    /// The description's state, locked. File I/O holds it for the whole
    /// operation, which serializes users of one offset (like Linux's
    /// `f_pos` lock).
    pub(crate) fn state(&self) -> MutexGuard<'_, Fd> {
        self.state.lock()
    }

    /// Identity for lock ownership.
    pub(crate) fn id(&self) -> usize {
        core::ptr::from_ref(self) as usize
    }

    /// The lock-table key of the file this names, if it is a file.
    pub(crate) fn lock_key(&self) -> Option<crate::locks::Key> {
        match &*self.state.lock() {
            Fd::File(of) => Some((Arc::as_ptr(&self.vfs) as usize, of.ino)),
            _ => None,
        }
    }
}

impl Drop for Description {
    fn drop(&mut self) {
        crate::locks::release_owner(crate::locks::Owner::Desc(self.id()));
        let st = self.state.lock();
        match &*st {
            Fd::Console | Fd::Dev(_) | Fd::Object(_) => {}
            Fd::File(of) => self.vfs.lock().close(of.ino),
            Fd::Pipe(e) => e.pipe.drop_end(e.write),
        }
    }
}

/// A descriptor-table slot.
#[derive(Clone, Debug)]
struct Slot {
    desc: Arc<Description>,
    cloexec: bool,
}

/// A group's files: descriptors, working directory (holding an open
/// reference) and umask.
struct Files {
    fds: Vec<Option<Slot>>,
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
        // Descriptions release their references as they drop.
        drop(fds);
        crate::locks::release_owner(crate::locks::Owner::Proc(self.tgid));
        self.vfs.lock().close(cwd);
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
                // One console description on 0, 1 and 2, as a terminal is.
                fds: {
                    let console = Slot {
                        desc: Description::new(Fd::Console, &vfs),
                        cloexec: false,
                    };
                    alloc::vec![Some(console.clone()), Some(console.clone()), Some(console)]
                },
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
        // The child shares the parent's open file descriptions.
        let _ = self.vfs.lock().open(cwd);
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

    /// The descriptor `fd`'s description, if open.
    pub(crate) fn desc(&self, fd: u64) -> Option<Arc<Description>> {
        let files = self.group.files.lock();
        let slot = files.fds.get(usize::try_from(fd).ok()?)?.as_ref()?;
        Some(slot.desc.clone())
    }

    /// A snapshot of what descriptor `fd` names, if open.
    pub(crate) fn fd(&self, fd: u64) -> Option<Fd> {
        let d = self.desc(fd)?;
        let f = d.state().clone();
        Some(f)
    }

    /// Runs `f` on an open file's state (its offset, say), shared by every
    /// descriptor of its description.
    pub(crate) fn with_file<R>(&self, fd: u64, f: impl FnOnce(&mut OpenFile) -> R) -> Option<R> {
        let d = self.desc(fd)?;
        let mut st = d.state();
        match &mut *st {
            Fd::File(of) => Some(f(of)),
            _ => None,
        }
    }

    /// Whether `fd` closes on exec (`F_GETFD`).
    pub(crate) fn cloexec(&self, fd: u64) -> Option<bool> {
        let files = self.group.files.lock();
        Some(files.fds.get(usize::try_from(fd).ok()?)?.as_ref()?.cloexec)
    }

    /// Sets `FD_CLOEXEC` (`F_SETFD`); false if `fd` is not open.
    pub(crate) fn set_cloexec(&self, fd: u64, on: bool) -> bool {
        let mut files = self.group.files.lock();
        match usize::try_from(fd).ok().and_then(|i| files.fds.get_mut(i)) {
            Some(Some(slot)) => {
                slot.cloexec = on;
                true
            }
            _ => false,
        }
    }

    /// Stores `slot` at the lowest free descriptor at or above `min`
    /// (POSIX semantics). `None` if the table is full.
    fn place(&self, slot: Slot, min: usize) -> Option<u64> {
        let mut files = self.group.files.lock();
        let fds = &mut files.fds;
        if min >= MAX_FDS {
            return None;
        }
        if fds.len() <= min {
            fds.resize(min + 1, None);
        }
        let i = (min..fds.len())
            .find(|&i| fds.get(i).is_some_and(Option::is_none))
            .unwrap_or(fds.len());
        if i >= MAX_FDS {
            return None;
        }
        if i == fds.len() {
            fds.push(None);
        }
        *fds.get_mut(i)? = Some(slot);
        Some(i as u64)
    }

    /// Installs a freshly opened `f` (whose reference the caller took) as a
    /// new description at the lowest free descriptor, with `FD_CLOEXEC` as
    /// asked (`O_CLOEXEC`). If the table is full the description is
    /// dropped, releasing the reference.
    pub(crate) fn install_flags(&mut self, f: Fd, cloexec: bool) -> Option<u64> {
        let slot = Slot {
            desc: Description::new(f, &self.vfs),
            cloexec,
        };
        self.place(slot, 0)
    }

    /// Duplicates `fd` (same description) to the lowest free descriptor at
    /// or above `min`.
    pub(crate) fn dup_from(&mut self, fd: u64, min: u64, cloexec: bool) -> Option<u64> {
        let desc = self.desc(fd)?;
        let min = usize::try_from(min).ok()?;
        self.place(Slot { desc, cloexec }, min)
    }

    /// Makes `new` refer to `old`'s description (closing `new` first).
    pub(crate) fn dup_to(&mut self, old: u64, new: u64, cloexec: bool) -> Option<u64> {
        let desc = self.desc(old)?;
        if old == new {
            return Some(new);
        }
        let n = usize::try_from(new).ok().filter(|&n| n < MAX_FDS)?;
        let prev = {
            let mut files = self.group.files.lock();
            if files.fds.len() <= n {
                files.fds.resize(n + 1, None);
            }
            files.fds.get_mut(n)?.replace(Slot { desc, cloexec })
        };
        if let Some(p) = prev {
            self.closed(p.desc);
        }
        Some(new)
    }

    /// A descriptor of `desc` went away: POSIX drops this process's record
    /// locks on the file (the description itself may live on).
    fn closed(&self, desc: Arc<Description>) {
        if let Some(key) = desc.lock_key() {
            crate::locks::release_process_file(self.group.tgid, key);
        }
    }

    /// `execve`: closes every `FD_CLOEXEC` descriptor.
    pub(crate) fn close_on_exec(&mut self) {
        let gone: Vec<Slot> = {
            let mut files = self.group.files.lock();
            files
                .fds
                .iter_mut()
                .filter_map(|s| {
                    if s.as_ref().is_some_and(|s| s.cloexec) {
                        s.take()
                    } else {
                        None
                    }
                })
                .collect()
        };
        for s in gone {
            self.closed(s.desc);
        }
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
            Some(s) => {
                self.closed(s.desc);
                true
            }
            None => false,
        }
    }
}
