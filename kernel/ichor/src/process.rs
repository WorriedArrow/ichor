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

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use frame::mm::VmSpace;
use frame::sync::{Mutex, MutexGuard, SpinLock};

use crate::kcell::Cell;
use crate::loader::Args;
use crate::page::Reserved;
use crate::pipe::Pipe;
use crate::proc::{self, ProcEntry};
use crate::signal::{Actions, Signals};
use crate::umem::{self, Mm, UserBuf};
use crate::vfs::{Ino, ROOT, Vfs};

/// Most descriptors a process may hold: the hard `RLIMIT_NOFILE` ceiling.
/// The table grows on demand, so servers that raise their soft limit
/// (redis asks for 10,032) pay only for the descriptors they open.
pub(crate) const MAX_FDS: usize = 65536;
/// The default soft `RLIMIT_NOFILE` (Linux's).
pub(crate) const DEFAULT_NOFILE: u64 = 1024;

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

/// One end of a pipe, as a descriptor holds it, or (a FIFO opened O_RDWR)
/// both.
#[derive(Clone, Debug)]
pub(crate) struct PipeEnd {
    pub(crate) pipe: Arc<Pipe>,
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) nonblock: bool,
    /// The FIFO it was opened through (counted as open).
    pub(crate) fifo: Option<Ino>,
}

impl PipeEnd {
    /// The read end, or the write end.
    pub(crate) fn one(pipe: Arc<Pipe>, write: bool, nonblock: bool) -> PipeEnd {
        PipeEnd {
            pipe,
            read: !write,
            write,
            nonblock,
            fifo: None,
        }
    }

    /// The ends an open with access mode `acc` gives, opened.
    pub(crate) fn open(pipe: Arc<Pipe>, acc: u64, nonblock: bool) -> PipeEnd {
        let (read, write) = (acc != 1, acc != 0);
        for (opens, end) in [(read, false), (write, true)] {
            if opens {
                pipe.add_end(end);
            }
        }
        PipeEnd {
            pipe,
            read,
            write,
            nonblock,
            fifo: None,
        }
    }

    /// Lets go of what it holds.
    fn close(&self) {
        for (held, end) in [(self.read, false), (self.write, true)] {
            if held {
                self.pipe.drop_end(end);
            }
        }
    }

    /// Readiness, as `poll` reports it.
    pub(crate) fn poll(&self) -> u16 {
        [(self.read, false), (self.write, true)]
            .into_iter()
            .filter(|&(held, _)| held)
            .fold(0, |r, (_, end)| r | self.pipe.poll(end))
    }
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
            Fd::File(of) => {
                let write = of.flags & 0o3 != 0; // not O_RDONLY
                crate::linuxabi::inotify::note_close(&self.vfs, of.ino, write);
                self.vfs.lock().close(of.ino)
            }
            Fd::Pipe(e) => {
                e.close();
                if let Some(ino) = e.fifo {
                    self.vfs.lock().close(ino);
                }
            }
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
    /// `mm`'s address space, for copies that run without the `Mm` lock
    /// (changed only with `mm` locked, by `replace_mm`).
    space: SpinLock<Arc<VmSpace>>,
    files: Mutex<Files>,
    pub(crate) actions: Mutex<Actions>,
    /// Live threads.
    threads: SpinLock<Vec<Arc<ProcEntry>>>,
    /// Woken when a thread leaves the group (removed from `threads`, or its
    /// reference to the group dropped): `execve` and the last thread out
    /// wait on it. Shared so a leaving thread can wake it after dropping
    /// its group reference.
    pub(crate) gone: Arc<frame::task::WaitQueue>,
    /// Set by `exit_group` or a fatal signal: the group's wait status.
    exit: SpinLock<Option<u32>>,
    /// The thread ending the others for its `execve`.
    execing: SpinLock<Option<u64>>,
    /// The program's path, and where its argv is, for `/proc`.
    exe: SpinLock<(alloc::string::String, Args)>,
    /// Resource limits (soft, hard), by `RLIMIT_*`.
    limits: SpinLock<Limits>,
    /// Set in a `vfork` child: released when it execs or exits.
    vfork: SpinLock<Option<Arc<Vfork>>>,
    /// Who the process is (ADR-0009).
    creds: SpinLock<crate::cred::Creds>,
    /// `PR_SET_NAME` (per process here; Linux's is per thread), and the
    /// `PR_SET_DUMPABLE` / `PR_SET_NO_NEW_PRIVS` flags.
    pub(crate) prctl: SpinLock<Prctl>,
    /// CPU time of threads that have exited (`cpu_ns`).
    gone_cpu_ns: core::sync::atomic::AtomicU64,
    /// The io_uring instances operations of it wait in, and whether one's
    /// object has changed (looked at after each system call).
    pub(crate) rings: SpinLock<Vec<Weak<crate::linuxabi::uring::Ring>>>,
    pub(crate) ring_due: Arc<core::sync::atomic::AtomicBool>,
}

/// State `prctl` sets.
#[derive(Clone, Debug)]
pub(crate) struct Prctl {
    pub(crate) name: Option<alloc::string::String>,
    pub(crate) dumpable: bool,
    pub(crate) no_new_privs: bool,
    /// The nice value (`setpriority`), -20..=19; kept across fork and
    /// exec. The scheduler does not use it yet.
    pub(crate) nice: i32,
    /// `sched_setaffinity`'s CPU mask (bit n: CPU n; `None`: every CPU),
    /// kept across fork and exec. The scheduler does not apply it yet.
    pub(crate) affinity: Option<u64>,
    /// `personality`.
    pub(crate) personality: u32,
}

impl Default for Prctl {
    fn default() -> Self {
        Prctl {
            name: None,
            dumpable: true,
            no_new_privs: false,
            nice: 0,
            affinity: None,
            personality: 0,
        }
    }
}

/// A `vfork` parent's wait for its child to exec or exit.
#[derive(Debug)]
pub(crate) struct Vfork {
    done: core::sync::atomic::AtomicBool,
    parent: Arc<ProcEntry>,
}

impl Vfork {
    pub(crate) fn new(parent: Arc<ProcEntry>) -> Arc<Vfork> {
        Arc::new(Vfork {
            done: core::sync::atomic::AtomicBool::new(false),
            parent,
        })
    }

    /// Lets the parent go on.
    pub(crate) fn release(&self) {
        self.done.store(true, core::sync::atomic::Ordering::Release);
        proc::wake(&self.parent);
    }

    /// The parent's side: waits for [`Vfork::release`] or `SIGKILL`.
    pub(crate) fn wait(&self) {
        proc::wait_killable(&self.parent, || {
            self.done.load(core::sync::atomic::Ordering::Acquire)
        });
    }
}

/// `RLIM_INFINITY`.
pub(crate) const RLIM_INFINITY: u64 = u64::MAX;
pub(crate) const RLIMIT_FSIZE: usize = 1;
pub(crate) const RLIMIT_STACK: usize = 3;
pub(crate) const RLIMIT_NOFILE: usize = 7;
/// Number of Linux resource limits.
pub(crate) const RLIM_NLIMITS: usize = 16;

/// A process's resource limits. `NOFILE`, `STACK` and `FSIZE` (but in
/// `splice` and `copy_file_range`) are enforced; the others are stored and reported (nothing yet consumes them).
pub(crate) type Limits = [(u64, u64); RLIM_NLIMITS];

/// Descriptor `fd`'s place in a table of `len` slots, clamped so that the
/// CPU does not run past the bound with a larger one (Spectre v1, ADR-0004
/// §2).
fn fd_index(fd: u64, len: usize) -> Option<usize> {
    let i = usize::try_from(fd).ok().filter(|&i| i < len)?;
    Some(frame::nospec::index(i, len))
}

fn default_limits() -> Limits {
    let mut l = [(RLIM_INFINITY, RLIM_INFINITY); RLIM_NLIMITS];
    l[RLIMIT_STACK] = (8 << 20, RLIM_INFINITY);
    l[RLIMIT_NOFILE] = (DEFAULT_NOFILE, MAX_FDS as u64);
    l
}

/// Most of a command line that `/proc` shows.
const CMDLINE_MAX: u64 = 1 << 20;

impl Group {
    /// Records the program the process runs (load or `execve`).
    /// `name` is what the process is called (`comm`).
    pub(crate) fn set_exec(&self, path: &str, name: &str, args: Args) {
        *self.exe.lock() = (alloc::string::String::from(path), args);
        self.prctl.lock().name = Some(name.chars().take(15).collect());
    }

    /// The program's path (`/proc/<pid>/exe`).
    pub(crate) fn exe(&self) -> alloc::string::String {
        self.exe.lock().0.clone()
    }

    /// The program's argv, NUL-separated (`/proc/<pid>/cmdline`): what is
    /// in its memory now, as a program may write a title for itself there.
    /// A title that is longer (it took the last NUL) ends at the next.
    pub(crate) fn cmdline(&self) -> Vec<u8> {
        let mut mm = self.mm();
        let args = self.exe.lock().1;
        let mut read = |from: u64, to: u64| {
            let mut b = alloc::vec![0u8; to.saturating_sub(from).min(CMDLINE_MAX) as usize];
            let n = mm.copy_from_user(from, &mut b);
            b.truncate(n);
            b
        };
        let cmd = read(args.start, args.end);
        if cmd.last().is_none_or(|&b| b == 0) {
            return cmd;
        }
        let mut title = read(args.start, args.env_end);
        if let Some(end) = title.iter().position(|&b| b == 0) {
            title.truncate(end);
        }
        title
    }

    /// The address space (locked).
    pub(crate) fn mm(&self) -> MutexGuard<'_, Mm> {
        self.mm.lock()
    }

    /// The root.
    pub(crate) fn vfs(&self) -> &Arc<Vfs> {
        &self.vfs
    }

    /// The working directory.
    pub(crate) fn cwd(&self) -> Ino {
        self.files.lock().cwd
    }

    pub(crate) fn umask(&self) -> u32 {
        self.files.lock().umask
    }

    /// Its address space now.
    pub(crate) fn space(&self) -> Arc<VmSpace> {
        self.space.lock().clone()
    }

    /// The descriptor `fd`'s description, if open.
    pub(crate) fn desc(&self, fd: u64) -> Option<Arc<Description>> {
        let files = self.files.lock();
        let slot = files.fds[fd_index(fd, files.fds.len())?].as_ref()?;
        Some(slot.desc.clone())
    }

    /// The open descriptor numbers, ascending.
    pub(crate) fn open_fds(&self) -> Vec<u64> {
        let files = self.files.lock();
        (0u64..)
            .zip(files.fds.iter())
            .filter_map(|(n, s)| s.as_ref().map(|_| n))
            .collect()
    }

    /// A snapshot of what descriptor `fd` names, if open.
    pub(crate) fn fd(&self, fd: u64) -> Option<Fd> {
        let d = self.desc(fd)?;
        let f = d.state().clone();
        Some(f)
    }

    /// A copy of the process's credentials.
    pub(crate) fn creds(&self) -> crate::cred::Creds {
        self.creds.lock().clone()
    }

    /// Changes the credentials with `f`; on success, publishes the new real
    /// and saved uids for `kill`'s permission check.
    pub(crate) fn update_creds<R>(
        &self,
        f: impl FnOnce(&mut crate::cred::Creds) -> Result<R, i64>,
    ) -> Result<R, i64> {
        let mut c = self.creds.lock().clone();
        let r = f(&mut c)?;
        self.leader.set_uids(c.ruid, c.suid);
        *self.creds.lock() = c;
        Ok(r)
    }

    /// Makes this (new) process a `vfork` child.
    pub(crate) fn set_vfork(&self, v: Arc<Vfork>) {
        *self.vfork.lock() = Some(v);
    }

    /// Takes the `vfork` parent's wait, if any, to release it.
    pub(crate) fn take_vfork(&self) -> Option<Arc<Vfork>> {
        self.vfork.lock().take()
    }

    /// The process's resource limits.
    pub(crate) fn limits(&self) -> Limits {
        *self.limits.lock()
    }

    /// Replaces one limit.
    pub(crate) fn set_limit(&self, resource: usize, soft: u64, hard: u64) {
        if let Some(l) = self.limits.lock().get_mut(resource) {
            *l = (soft, hard);
        }
    }

    /// The threads still running.
    pub(crate) fn threads(&self) -> Vec<Arc<ProcEntry>> {
        self.threads.lock().clone()
    }

    /// Sleeps until at most `n` threads are left.
    pub(crate) fn wait_threads(&self, n: usize) {
        self.gone
            .wait_until(|| (self.threads.lock().len() <= n).then_some(()));
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
        self.end_others(me);
    }

    /// Tells every thread but `me` to end.
    pub(crate) fn end_others(&self, me: &ProcEntry) {
        let others = {
            let threads = self.threads.lock();
            let mut others = threads.clone();
            others.retain(|t| t.pid != me.pid);
            // Under the lock: a thread one of them is making (it takes the
            // lock to add it) is marked here, or inherits the mark.
            others.iter().for_each(|t| proc::end_thread(t));
            others
        };
        others.iter().for_each(|t| proc::wake(t));
    }

    /// `execve` by thread `me`: the others end, and it is the process's
    /// first thread from here on (its entry is returned). `None` if another
    /// thread was first, or the process is exiting: `me` is to end too.
    pub(crate) fn sole_thread(&self, me: &Arc<ProcEntry>) -> Option<Arc<ProcEntry>> {
        {
            let mut by = self.execing.lock();
            if by.is_some() || proc::ending(me) {
                return None;
            }
            *by = Some(me.pid);
        }
        self.end_others(me);
        self.wait_threads(1);
        if self.exit.lock().is_some() {
            return None; // `exit_group` was called meanwhile
        }
        let entry = proc::take_over_leader(me, &self.leader);
        *self.threads.lock() = alloc::vec![entry.clone()];
        *self.execing.lock() = None;
        Some(entry)
    }

    /// Takes a thread that was made but never ran out of the live threads.
    pub(crate) fn never_ran(&self, tid: u64) {
        self.threads.lock().retain(|e| e.pid != tid);
        self.gone.wake_all();
    }

    /// The process's CPU time, user and system together (ADR-0021): its
    /// live threads' and those gone.
    pub(crate) fn cpu_ns(&self) -> u64 {
        use core::sync::atomic::Ordering::Relaxed;
        let live: u64 = self.threads.lock().iter().map(|e| e.cpu_ns()).sum();
        live + self.gone_cpu_ns.load(Relaxed)
    }

    /// Removes `me` from the live threads; returns the group's wait status
    /// if it was the last (its exit status, or `status`, the last thread's).
    pub(crate) fn thread_exited(&self, me: &ProcEntry, status: u32) -> Option<u32> {
        let mut t = self.threads.lock();
        self.gone_cpu_ns
            .fetch_add(me.cpu_ns(), core::sync::atomic::Ordering::Relaxed);
        t.retain(|e| e.pid != me.pid);
        let last = t.is_empty();
        drop(t);
        self.gone.wake_all();
        if !last {
            return None;
        }
        self.wake_rings();
        Some(self.exit.lock().unwrap_or(status))
    }

    /// Wakes the workers of the process's io_uring instances, to see that
    /// it ends, or runs another program.
    fn wake_rings(&self) {
        let rings: Vec<_> = {
            let rings = self.rings.lock();
            rings.iter().filter_map(Weak::upgrade).collect()
        };
        for r in rings {
            r.wake();
        }
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
        if let Some(v) = self.take_vfork() {
            v.release();
        }
        crate::locks::release_owner(crate::locks::Owner::Proc(self.tgid));
        crate::itimer::clear(self.leader.cell, self.tgid);
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
    /// `set_robust_list`: the head of the thread's robust futex list,
    /// walked when it exits (`futex::exit_robust_list`). Not inherited.
    pub(crate) robust_list: u64,
    /// The deadline of a timed wait that a signal interrupted, for when the
    /// call is restarted (no handler ran): it waits on, not over.
    pub(crate) resume_until: Option<core::time::Duration>,
    /// What the thread keeps for io_uring. Not inherited.
    pub(crate) uring: crate::linuxabi::uring::Thread,
    /// The cell pays for its kernel stack.
    _stack: Reserved,
}

/// Pages a thread's kernel stack takes, and those that its entry in the
/// process table (with what hangs off it) is counted as. A cell that forks
/// without end runs out of its own memory, not the machine's.
const STACK_PAGES: u64 = 16;
const ENTRY_PAGES: u64 = 1;

/// What a new thread costs its cell; `None` if that cannot pay.
fn thread_cost(cell: &Cell) -> Option<(Reserved, Reserved)> {
    let stack = Reserved::new(cell.account(), STACK_PAGES)?;
    Some((stack, Reserved::new(cell.account(), ENTRY_PAGES)?))
}

impl LinuxProcess {
    /// A process in `cell` with an empty address space, `vfs` as its root,
    /// `/` as its working directory, and the console on fds 0–2. `None` if
    /// memory runs out.
    pub(crate) fn new(cell: Arc<Cell>, vfs: Arc<Vfs>) -> Option<Self> {
        let (stack, kept) = thread_cost(&cell)?;
        let mm = Mm::new(cell.account())?;
        let _ = vfs.lock().open(ROOT);
        let entry = proc::register(cell.id(), 0, None, None, None, kept);
        let group = Arc::new(Group {
            tgid: entry.pid,
            leader: entry.clone(),
            vfs: vfs.clone(),
            space: SpinLock::new(mm.shared_space()),
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
            gone: Arc::new(frame::task::WaitQueue::new()),
            exit: SpinLock::new(None),
            execing: SpinLock::new(None),
            exe: SpinLock::new(Default::default()),
            limits: SpinLock::new(default_limits()),
            vfork: SpinLock::new(None),
            creds: SpinLock::new(crate::cred::Creds::root()),
            prctl: SpinLock::new(Prctl::default()),
            gone_cpu_ns: core::sync::atomic::AtomicU64::new(0),
            rings: SpinLock::new(Vec::new()),
            ring_due: Default::default(),
        });
        entry.set_group(&group);
        Some(Self {
            entry,
            group,
            cell,
            vfs,
            sig: Signals::new(),
            clear_tid: 0,
            robust_list: 0,
            resume_until: None,
            uring: Default::default(),
            _stack: stack,
        })
    }

    /// A copy of this process for `fork`: a copy-on-write copy of its
    /// memory, the same open files (each with a new reference), working
    /// directory, umask and signal state, in a new group whose parent is
    /// this process. Only the calling thread is copied.
    pub(crate) fn fork(&mut self) -> Option<Self> {
        let (stack, kept) = thread_cost(&self.cell)?;
        let mm = self.mm().fork()?;
        let (fds, cwd, umask) = {
            let f = self.group.files.lock();
            (f.fds.clone(), f.cwd, f.umask)
        };
        // The child shares the parent's open file descriptions.
        let _ = self.vfs.lock().open(cwd);
        let actions = self.group.actions.lock().clone();
        let exe = self.group.exe.lock().clone();
        let entry = proc::register(
            self.cell.id(),
            self.group.tgid,
            None,
            Some(self.group.leader.group()),
            None,
            kept,
        );
        let group = Arc::new(Group {
            tgid: entry.pid,
            leader: entry.clone(),
            vfs: self.vfs.clone(),
            space: SpinLock::new(mm.shared_space()),
            mm: Mutex::new(mm),
            files: Mutex::new(Files { fds, cwd, umask }),
            actions: Mutex::new(actions),
            threads: SpinLock::new(alloc::vec![entry.clone()]),
            gone: Arc::new(frame::task::WaitQueue::new()),
            exit: SpinLock::new(None),
            execing: SpinLock::new(None),
            exe: SpinLock::new(exe),
            limits: SpinLock::new(self.group.limits()),
            vfork: SpinLock::new(None),
            creds: SpinLock::new(self.group.creds()),
            prctl: SpinLock::new(self.group.prctl.lock().clone()),
            gone_cpu_ns: core::sync::atomic::AtomicU64::new(0),
            rings: SpinLock::new(Vec::new()),
            ring_due: Default::default(),
        });
        entry.set_group(&group);
        let c = group.creds();
        entry.set_uids(c.ruid, c.suid);
        Some(Self {
            entry,
            group,
            cell: self.cell.clone(),
            vfs: self.vfs.clone(),
            sig: self.sig.clone(),
            clear_tid: 0,
            robust_list: 0,
            resume_until: None,
            uring: Default::default(),
            _stack: stack,
        })
    }

    /// A new thread in this process (`clone` with `CLONE_VM |
    /// CLONE_THREAD`): shares everything but its tid and signal mask.
    /// `None` if the cell cannot pay for it.
    pub(crate) fn new_thread(&self) -> Option<Self> {
        let (stack, kept) = thread_cost(&self.cell)?;
        let entry = proc::register(
            self.cell.id(),
            self.entry.ppid(),
            Some(self.group.tgid),
            None,
            Some(self.entry.shared.clone()),
            kept,
        );
        {
            let mut threads = self.group.threads.lock();
            if proc::ending(&self.entry) {
                proc::end_thread(&entry);
            }
            threads.push(entry.clone());
        }
        let mut sig = self.sig.clone();
        sig.clear_alt_stack();
        Some(Self {
            entry,
            group: self.group.clone(),
            cell: self.cell.clone(),
            vfs: self.vfs.clone(),
            sig,
            clear_tid: 0,
            robust_list: 0,
            resume_until: None,
            uring: Default::default(),
            _stack: stack,
        })
    }

    /// A kernel helper thread of this process (an io_uring worker): it
    /// shares the process's memory, files and credentials, has its own
    /// thread id, blocks every signal SIGKILL and SIGSTOP aside, and is not
    /// one of the group's threads, so it neither keeps the process alive
    /// nor is waited for by `exit_group` or `execve`. Start it with
    /// [`crate::proc::start_helper`]. `None` if the cell cannot pay for it.
    pub(crate) fn helper(&self) -> Option<Self> {
        let (stack, kept) = thread_cost(&self.cell)?;
        let entry = proc::register(
            self.cell.id(),
            self.entry.ppid(),
            Some(self.group.tgid),
            None,
            None,
            kept,
        );
        let mut sig = Signals::new();
        sig.mask = !(crate::signal::bit(crate::signal::SIGKILL) | crate::signal::bit(19));
        proc::set_masks(&entry, sig.mask, 0);
        Some(Self {
            entry,
            group: self.group.clone(),
            cell: self.cell.clone(),
            vfs: self.vfs.clone(),
            sig,
            clear_tid: 0,
            robust_list: 0,
            resume_until: None,
            uring: Default::default(),
            _stack: stack,
        })
    }

    /// The process's address space (locked).
    /// The root, locked and checked against this process's filesystem
    /// credentials (ADR-0009).
    pub(crate) fn fs(&self) -> crate::vfs::VfsGuard<'_> {
        self.vfs.lock_as(self.group.creds().fs())
    }

    pub(crate) fn mm(&self) -> MutexGuard<'_, Mm> {
        self.group.mm.lock()
    }

    /// Replaces the address space (`execve`) by that of the program at
    /// `path`, returning the old one.
    pub(crate) fn replace_mm(&self, mm: Mm, path: &str, name: &str, args: Args) -> Mm {
        let mut cur = self.group.mm.lock();
        // Together, so that nobody looks for one's arguments in the other.
        self.group.set_exec(path, name, args);
        // Not the old space's last reference: the old `Mm` holds one.
        *self.group.space.lock() = mm.shared_space();
        let old = core::mem::replace(&mut *cur, mm);
        drop(cur);
        self.group.wake_rings();
        old
    }

    /// Copies `data` to user memory at `va` with the permissions a user
    /// store has (faulting pages in, breaking copy-on-write). Returns how
    /// many bytes were copied.
    pub(crate) fn copy_to_user(&mut self, va: u64, data: &[u8]) -> usize {
        if let Some(b) = self.uring.written(va, data.len()) {
            b.copy_from_slice(data);
            return data.len();
        }
        self.copy_user(va, UserBuf::To(data))
    }

    /// Copies user memory at `va` into `out` with the permissions a user
    /// load has (faulting pages in). Returns how many bytes were copied.
    pub(crate) fn copy_from_user(&mut self, va: u64, out: &mut [u8]) -> usize {
        if let Some(kept) = self.uring.kept(va, out.len()) {
            out.copy_from_slice(kept);
            return out.len();
        }
        self.copy_user(va, UserBuf::From(out))
    }

    /// Both copies. The `Mm` lock is taken only to fault a page in where
    /// frame's copy stopped (`umem::copy_user`), so a copy into resident
    /// pages never waits for it, and other threads' `mmap`, `munmap`,
    /// `mprotect` and page faults do not wait for the copy. If an `execve`
    /// (by another thread, for a helper) replaced the space meanwhile, the
    /// copy ends where it stopped: it never faults pages into the new
    /// space for a copy into the old one.
    fn copy_user(&self, va: u64, buf: UserBuf<'_>) -> usize {
        let space = self.group.space.lock().clone();
        let me: &LinuxProcess = self;
        umem::copy_user(&space, va, buf, |at, write| {
            let mut mm = me.mm();
            (mm.owns(&space) && mm.fault(at, write, false)).then_some(mm)
        })
    }

    /// The working directory.
    pub(crate) fn cwd(&self) -> Ino {
        self.group.cwd()
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
        match self.uring.lent(fd) {
            Some(d) => Some(d.clone()),
            None => self.group.desc(fd),
        }
    }

    /// A snapshot of what descriptor `fd` names, if open. One lent to an
    /// io_uring operation does not block.
    pub(crate) fn fd(&self, fd: u64) -> Option<Fd> {
        let Some(d) = self.uring.lent(fd) else {
            return self.group.fd(fd);
        };
        let mut f = d.state().clone();
        match &mut f {
            Fd::Pipe(e) => e.nonblock = true,
            Fd::Object(o) => o.nonblock = true,
            Fd::Console | Fd::File(_) | Fd::Dev(_) => {}
        }
        Some(f)
    }

    /// Takes a descriptor out of the table, open as it is (an io_uring
    /// direct descriptor).
    pub(crate) fn take_desc(&mut self, fd: u64) -> Option<Arc<Description>> {
        let mut files = self.group.files.lock();
        let i = fd_index(fd, files.fds.len())?;
        let slot = files.fds[i].take()?;
        Some(slot.desc)
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
        Some(files.fds[fd_index(fd, files.fds.len())?].as_ref()?.cloexec)
    }

    /// Sets `FD_CLOEXEC` (`F_SETFD`); false if `fd` is not open.
    pub(crate) fn set_cloexec(&self, fd: u64, on: bool) -> bool {
        let mut files = self.group.files.lock();
        let len = files.fds.len();
        match fd_index(fd, len).map(|i| &mut files.fds[i]) {
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
        let cap = (self.group.limits()[RLIMIT_NOFILE].0 as usize).min(MAX_FDS);
        let mut files = self.group.files.lock();
        let fds = &mut files.fds;
        if min >= cap {
            return None;
        }
        if fds.len() <= min {
            fds.resize(min + 1, None);
        }
        let i = (min..fds.len())
            .find(|&i| fds.get(i).is_some_and(Option::is_none))
            .unwrap_or(fds.len());
        if i >= cap {
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

    /// Installs an existing open file description (one passed with
    /// `SCM_RIGHTS`) at the lowest free descriptor.
    pub(crate) fn install_desc(&mut self, desc: Arc<Description>, cloexec: bool) -> Option<u64> {
        self.place(Slot { desc, cloexec }, 0)
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
        let cap = (self.group.limits()[RLIMIT_NOFILE].0 as usize).min(MAX_FDS);
        let n = usize::try_from(new).ok().filter(|&n| n < cap)?;
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

    /// `close_range`: closes every open descriptor in `[first, last]`, or
    /// with `cloexec` marks them close-on-exec instead.
    pub(crate) fn close_range(&mut self, first: u64, last: u64, cloexec: bool) {
        let gone: Vec<Slot> = {
            let mut files = self.group.files.lock();
            let len = files.fds.len();
            let end = usize::try_from(last)
                .map_or(len, |l| l.saturating_add(1))
                .min(len);
            let start = usize::try_from(first).map_or(end, |f| f.min(end));
            let range = &mut files.fds[start..end];
            if cloexec {
                for s in range.iter_mut().flatten() {
                    s.cloexec = true;
                }
                Vec::new()
            } else {
                range.iter_mut().filter_map(Option::take).collect()
            }
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
