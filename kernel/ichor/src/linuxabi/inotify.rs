//! `inotify`: a descriptor that reads what happens to the files and
//! directories it watches. While anyone watches a root, its overlay records
//! what changes (`overlay::Change`), and every syscall that may have changed
//! something hands that on as it ends ([`flush`]); opens, closes and reads
//! are told of as they happen ([`note`]).
//!
//! Partial: a watch is of an inode by whatever name, as on Linux, but a file
//! with several names reports events to one of its directories only;
//! `IN_UNMOUNT` never comes; stores through a shared mapping are not
//! events (nor on Linux).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use frame::sync::SpinLock;
use overlay::Change;

use super::fs::{AT_FDCWD, O_CLOEXEC, O_NONBLOCK};
use super::socket::block_on;
use super::{EBADF, EINVAL, EMFILE, fs};
use crate::netstack::Waiters;
use crate::poll::{Object, POLLIN, Watchers};
use crate::process::{Description, Fd, LinuxProcess, ObjectEnd};
use crate::vfs::{Ino, Kind, Vfs};

const EEXIST: i64 = 17;
const ENOTDIR: i64 = 20;
const ENOSPC: i64 = 28;

pub(super) const IN_ACCESS: u32 = 0x1;
const IN_MODIFY: u32 = 0x2;
const IN_ATTRIB: u32 = 0x4;
const IN_CLOSE_WRITE: u32 = 0x8;
const IN_CLOSE_NOWRITE: u32 = 0x10;
pub(super) const IN_OPEN: u32 = 0x20;
const IN_MOVED_FROM: u32 = 0x40;
const IN_MOVED_TO: u32 = 0x80;
const IN_CREATE: u32 = 0x100;
const IN_DELETE: u32 = 0x200;
const IN_DELETE_SELF: u32 = 0x400;
const IN_MOVE_SELF: u32 = 0x800;
const IN_ALL: u32 = 0xfff;
const IN_Q_OVERFLOW: u32 = 0x4000;
const IN_IGNORED: u32 = 0x8000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
const IN_ISDIR: u32 = 0x4000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;

/// `fs.inotify.max_queued_events` and `max_user_watches`, per instance.
const QUEUE_MAX: usize = 16384;
const WATCHES_MAX: usize = 65536;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}

impl Event {
    /// `struct inotify_event`: wd, mask, cookie, the name's length with its
    /// padding (to 16 bytes, at least one NUL), the name.
    fn bytes(&self) -> Vec<u8> {
        let mut name = overlay::name::decode(&self.name);
        if !name.is_empty() {
            let len = (name.len() + 1).next_multiple_of(16);
            name.resize(len, 0);
        }
        let mut b = Vec::with_capacity(16 + name.len());
        b.extend_from_slice(&self.wd.to_le_bytes());
        b.extend_from_slice(&self.mask.to_le_bytes());
        b.extend_from_slice(&self.cookie.to_le_bytes());
        b.extend_from_slice(&(name.len() as u32).to_le_bytes());
        b.extend_from_slice(&name);
        b
    }
}

#[derive(Debug, Default)]
struct State {
    /// Watches by descriptor: the inode and what is wanted of it.
    watches: BTreeMap<i32, (Ino, u32)>,
    queue: VecDeque<Event>,
    last_wd: i32,
}

/// An inotify instance.
#[derive(Debug)]
pub(crate) struct Inotify {
    vfs: Arc<Vfs>,
    state: SpinLock<State>,
    wait: Waiters,
}

/// A root's inotify instances.
#[derive(Debug)]
pub(crate) struct Instances {
    list: SpinLock<Vec<Weak<Inotify>>>,
    /// dnotify registrations (`fcntl(F_NOTIFY)`).
    dnotify: SpinLock<Vec<Dnotify>>,
    /// Some instance or registration is watching: changes are recorded.
    watching: AtomicBool,
}

impl Instances {
    pub(crate) fn new() -> Instances {
        Instances {
            list: SpinLock::new(Vec::new()),
            dnotify: SpinLock::new(Vec::new()),
            watching: AtomicBool::new(false),
        }
    }

    fn live(&self) -> Vec<Arc<Inotify>> {
        self.list.lock().iter().filter_map(Weak::upgrade).collect()
    }

    /// Whether any dnotify registration is left (its description open).
    fn dnotified(&self) -> bool {
        self.dnotify
            .lock()
            .iter()
            .any(|d| d.desc.strong_count() > 0)
    }

    /// `what` (inotify's bits) happened to an entry of directory `dir`: the
    /// dnotify registrations that asked for it signal their owners, and a
    /// one-shot one ends.
    fn dnotify(&self, dir: Ino, what: u32) {
        let dn = dn_of(what);
        if dn == 0 {
            return;
        }
        let mut fire = Vec::new();
        self.dnotify.lock().retain(|d| {
            if d.desc.strong_count() == 0 {
                return false;
            }
            if d.dir != dir || d.mask & dn == 0 {
                return true;
            }
            fire.push((d.cell, d.pid));
            d.mask & DN_MULTISHOT != 0
        });
        for (cell, pid) in fire {
            let _ = crate::proc::send(cell, pid, crate::signal::SIGIO);
        }
    }
}

// dnotify (`fcntl(F_NOTIFY)`): what happens to a directory's entries,
// told by `SIGIO` to the process that asked.
const DN_ACCESS: u32 = 0x1;
const DN_MODIFY: u32 = 0x2;
const DN_CREATE: u32 = 0x4;
const DN_DELETE: u32 = 0x8;
const DN_RENAME: u32 = 0x10;
const DN_ATTRIB: u32 = 0x20;
const DN_ALL: u32 = 0x3f;
const DN_MULTISHOT: u32 = 0x8000_0000;

/// One `F_NOTIFY` registration: the directory, what of it, whom to signal,
/// and the description it was made on (it ends when that closes).
#[derive(Debug)]
struct Dnotify {
    dir: Ino,
    mask: u32,
    cell: u64,
    pid: u64,
    desc: Weak<Description>,
}

/// inotify's bits as dnotify's (as Linux maps them).
fn dn_of(what: u32) -> u32 {
    [
        (IN_ACCESS, DN_ACCESS),
        (IN_MODIFY, DN_MODIFY),
        (IN_CREATE, DN_CREATE),
        (IN_DELETE, DN_DELETE),
        (IN_MOVED_FROM | IN_MOVED_TO, DN_RENAME),
        (IN_ATTRIB, DN_ATTRIB),
    ]
    .iter()
    .filter(|(i, _)| what & i != 0)
    .fold(0, |d, (_, n)| d | n)
}

/// `fcntl(fd, F_NOTIFY, mask)`: the caller gets `SIGIO` when entries of
/// directory `fd` change as `mask` says, until the description closes, once
/// unless `DN_MULTISHOT`. A mask without events ends the registration.
/// Partial: `F_SETSIG` is not taken, so the signal is always `SIGIO`, with
/// no `si_fd`.
pub(super) fn dnotify_set(
    p: &mut LinuxProcess,
    desc: &Arc<Description>,
    mask: u64,
) -> Result<u64, i64> {
    let ino = match &*desc.state() {
        Fd::File(of) => of.ino,
        _ => return Err(EINVAL),
    };
    let mask = mask as u32;
    let mut tree = p.vfs.lock();
    if tree.stat(ino)?.kind != Kind::Directory {
        return Err(ENOTDIR);
    }
    let inst = &p.vfs.inotify;
    let me = Arc::downgrade(desc);
    let mut l = inst.dnotify.lock();
    l.retain(|d| d.desc.strong_count() > 0 && !(d.dir == ino && Weak::ptr_eq(&d.desc, &me)));
    if mask & DN_ALL != 0 {
        l.push(Dnotify {
            dir: ino,
            mask: mask & (DN_ALL | DN_MULTISHOT),
            cell: p.entry.cell,
            pid: p.group.tgid,
            desc: me,
        });
        tree.watch(true);
        inst.watching.store(true, Ordering::Release);
    }
    Ok(0)
}

impl Inotify {
    /// Queues what watches of `ino` want of `what`.
    fn tell(&self, ino: Ino, what: u32, cookie: u32, name: &str) -> bool {
        let mut s = self.state.lock();
        let State { watches, queue, .. } = &mut *s;
        let mut told = false;
        let mut spent = Vec::new();
        for (&wd, &(_, mask)) in watches.iter().filter(|(_, w)| w.0 == ino) {
            if mask & what & IN_ALL == 0 && what & IN_IGNORED == 0 {
                continue;
            }
            let e = Event {
                wd,
                mask: what,
                cookie,
                name: String::from(name),
            };
            if queue.len() >= QUEUE_MAX {
                let over = Event {
                    wd: -1,
                    mask: IN_Q_OVERFLOW,
                    cookie: 0,
                    name: String::new(),
                };
                if queue.back() != Some(&over) {
                    queue.push_back(over);
                }
            } else if queue.back() != Some(&e) || cookie != 0 {
                queue.push_back(e);
            }
            if mask & IN_ONESHOT != 0 {
                spent.push(wd);
            }
            told = true;
        }
        drop(s);
        for wd in spent {
            self.forget(wd);
        }
        told
    }

    /// Ends watch `wd`, saying so; its inode, to be closed.
    fn forget(&self, wd: i32) -> Option<Ino> {
        let ino = {
            let mut s = self.state.lock();
            let (ino, _) = s.watches.remove(&wd)?;
            s.queue.push_back(Event {
                wd,
                mask: IN_IGNORED,
                cookie: 0,
                name: String::new(),
            });
            ino
        };
        self.vfs.lock().close(ino);
        self.wait.wake();
        Some(ino)
    }

    /// Ends every watch of `ino`, which is gone.
    fn forget_inode(&self, ino: Ino) {
        let wds: Vec<i32> = self
            .state
            .lock()
            .watches
            .iter()
            .filter(|(_, w)| w.0 == ino)
            .map(|(&wd, _)| wd)
            .collect();
        for wd in wds {
            self.forget(wd);
        }
    }
}

impl Drop for Inotify {
    fn drop(&mut self) {
        let watches = core::mem::take(&mut self.state.lock().watches);
        let mut l = self.vfs.inotify.list.lock();
        l.retain(|w| w.strong_count() > 0);
        let none = l.is_empty() && !self.vfs.inotify.dnotified();
        drop(l);
        let mut fs = self.vfs.lock();
        for (ino, _) in watches.into_values() {
            fs.close(ino);
        }
        if none {
            self.vfs.inotify.watching.store(false, Ordering::Release);
            fs.watch(false);
        }
    }
}

impl Object for Inotify {
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        block_on(&self.wait, nonblock, 0, interrupted, || {
            let mut s = self.state.lock();
            let first = s.queue.front()?.bytes();
            if first.len() > max {
                return Some(Err(EINVAL));
            }
            let mut out = Vec::new();
            while let Some(e) = s.queue.front().map(Event::bytes) {
                if out.len() + e.len() > max {
                    break;
                }
                out.extend_from_slice(&e);
                s.queue.pop_front();
            }
            Some(Ok(out))
        })
    }

    fn write(&self, _: &[u8], _: bool, _: &dyn Fn() -> bool) -> Result<usize, i64> {
        Err(EBADF)
    }

    fn poll(&self) -> u16 {
        if self.state.lock().queue.is_empty() {
            0
        } else {
            POLLIN
        }
    }

    fn changes(&self) -> u64 {
        self.wait.changes.load(Ordering::Acquire)
    }

    fn watchers(&self) -> Option<&Watchers> {
        Some(&self.wait.watchers)
    }

    fn inotify(&self) -> Option<&Inotify> {
        Some(self)
    }

    fn readable(&self) -> Option<usize> {
        Some(
            self.state
                .lock()
                .queue
                .iter()
                .map(|e| e.bytes().len())
                .sum(),
        )
    }
}

/// Tells the watches of `ino`, and of the directory that names it, of
/// something that happened to it.
fn tell_of(
    inst: &Instances,
    all: &[Arc<Inotify>],
    ino: Ino,
    named: Option<&(Ino, String)>,
    what: u32,
    dir: bool,
) {
    let what = if dir { what | IN_ISDIR } else { what };
    if let Some((parent, _)) = named {
        inst.dnotify(*parent, what);
    }
    for i in all {
        let mut told = i.tell(ino, what, 0, "");
        if let Some((parent, name)) = named {
            told |= i.tell(*parent, what, 0, name);
        }
        if told {
            i.wait.wake();
        }
    }
}

/// An open, close or read of `ino` (`what`), if anyone watches its root.
pub(super) fn note(vfs: &Vfs, ino: Ino, what: u32) {
    if !vfs.inotify.watching.load(Ordering::Acquire) {
        return;
    }
    flush(vfs); // what happened before it
    let (named, dir) = {
        let fs = vfs.lock();
        let dir = fs.stat(ino).is_ok_and(|s| s.kind == Kind::Directory);
        (fs.name_of(ino), dir)
    };
    tell_of(
        &vfs.inotify,
        &vfs.inotify.live(),
        ino,
        named.as_ref(),
        what,
        dir,
    );
}

/// The close of a description of `ino`, open for writing or not.
pub(crate) fn note_close(vfs: &Vfs, ino: Ino, write: bool) {
    let what = if write {
        IN_CLOSE_WRITE
    } else {
        IN_CLOSE_NOWRITE
    };
    note(vfs, ino, what);
}

/// Hands the changes recorded in `vfs` on to whoever watches them.
/// Inlined: every system call asks, and usually nothing watches.
#[inline]
pub(crate) fn flush(vfs: &Vfs) {
    if vfs.inotify.watching.load(Ordering::Acquire) {
        flush_watched(vfs);
    }
}

#[inline(never)]
fn flush_watched(vfs: &Vfs) {
    static COOKIE: AtomicU32 = AtomicU32::new(1);
    // Each with the directory and name of the inode it is about (while they
    // can be told), and whether that is a directory.
    let changes: Vec<_> = {
        let mut fs = vfs.lock();
        let list = fs.take_changes();
        list.into_iter()
            .map(|c| {
                let (named, dir) = match c {
                    Change::Modified(i) | Change::Attributes(i) | Change::Gone(i) => (
                        fs.name_of(i),
                        fs.stat(i).is_ok_and(|s| s.kind == Kind::Directory),
                    ),
                    _ => (None, false),
                };
                (c, named, dir)
            })
            .collect()
    };
    if changes.is_empty() {
        return;
    }
    let all = vfs.inotify.live();
    let inst = &vfs.inotify;
    let in_dir = |dir: Ino, what: u32, cookie: u32, name: &str, is_dir: bool| {
        let what = if is_dir { what | IN_ISDIR } else { what };
        inst.dnotify(dir, what);
        for i in &all {
            if i.tell(dir, what, cookie, name) {
                i.wait.wake();
            }
        }
    };
    for (c, named, dir) in changes {
        match c {
            Change::Created { dir, name, is_dir } => in_dir(dir, IN_CREATE, 0, &name, is_dir),
            Change::Removed { dir, name, is_dir } => in_dir(dir, IN_DELETE, 0, &name, is_dir),
            Change::Moved {
                from,
                to,
                ino,
                is_dir,
            } => {
                let cookie = COOKIE.fetch_add(1, Ordering::Relaxed);
                in_dir(from.0, IN_MOVED_FROM, cookie, &from.1, is_dir);
                in_dir(to.0, IN_MOVED_TO, cookie, &to.1, is_dir);
                tell_of(inst, &all, ino, None, IN_MOVE_SELF, is_dir);
            }
            Change::Modified(ino) => tell_of(inst, &all, ino, named.as_ref(), IN_MODIFY, false),
            Change::Attributes(ino) => tell_of(inst, &all, ino, named.as_ref(), IN_ATTRIB, dir),
            Change::Gone(ino) => {
                if !dir {
                    tell_of(inst, &all, ino, None, IN_ATTRIB, false);
                }
                tell_of(inst, &all, ino, None, IN_DELETE_SELF, dir);
                for i in &all {
                    i.forget_inode(ino);
                }
            }
        }
    }
}

/// `inotify_init1(flags)`.
pub(super) fn init(p: &mut LinuxProcess, flags: u64) -> Result<u64, i64> {
    if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    let i = Arc::new(Inotify {
        vfs: p.vfs.clone(),
        state: SpinLock::new(State::default()),
        wait: Waiters::default(),
    });
    p.vfs.inotify.list.lock().push(Arc::downgrade(&i));
    p.install_flags(
        Fd::Object(ObjectEnd {
            obj: i,
            nonblock: flags & O_NONBLOCK != 0,
        }),
        flags & O_CLOEXEC != 0,
    )
    .ok_or(EMFILE)
}

fn of(p: &LinuxProcess, fd: u64) -> Result<Arc<dyn Object>, i64> {
    match p.fd(fd).ok_or(EBADF)? {
        Fd::Object(o) if o.obj.inotify().is_some() => Ok(o.obj),
        _ => Err(EINVAL),
    }
}

/// `inotify_add_watch(fd, path, mask)`.
pub(super) fn add(p: &mut LinuxProcess, fd: u64, path: u64, mask: u64) -> Result<u64, i64> {
    let mask = mask as u32;
    let obj = of(p, fd)?;
    let i = obj.inotify().ok_or(EINVAL)?;
    if mask & IN_ALL == 0 || mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0 {
        return Err(EINVAL);
    }
    let path = fs::user_path(p, path)?;
    let start = fs::base(p, AT_FDCWD, &path)?;
    let mut tree = p.fs();
    let ino = tree.resolve(start, &path, mask & IN_DONT_FOLLOW == 0)?;
    if mask & IN_ONLYDIR != 0 && tree.stat(ino)?.kind != Kind::Directory {
        return Err(ENOTDIR);
    }
    tree.permission(ino, overlay::MAY_READ)?;
    let mut s = i.state.lock();
    let found = s
        .watches
        .iter_mut()
        .find(|(_, w)| w.0 == ino)
        .map(|(&wd, w)| (wd, &mut w.1));
    if let Some((wd, old)) = found {
        if mask & IN_MASK_CREATE != 0 {
            return Err(EEXIST);
        }
        let keep = mask & (IN_ALL | IN_ONESHOT | IN_EXCL_UNLINK);
        *old = if mask & IN_MASK_ADD != 0 {
            *old | keep
        } else {
            keep
        };
        return Ok(wd as u64);
    }
    if s.watches.len() >= WATCHES_MAX {
        return Err(ENOSPC);
    }
    // The inode stays while it is watched, so its number means it.
    tree.open(ino)?;
    tree.watch(true);
    p.vfs.inotify.watching.store(true, Ordering::Release);
    s.last_wd += 1;
    let wd = s.last_wd;
    s.watches.insert(wd, (ino, mask));
    Ok(wd as u64)
}

/// `inotify_rm_watch(fd, wd)`.
pub(super) fn remove(p: &mut LinuxProcess, fd: u64, wd: u64) -> Result<u64, i64> {
    let obj = of(p, fd)?;
    let i = obj.inotify().ok_or(EINVAL)?;
    flush(&p.vfs);
    i.forget(wd as u32 as i32).ok_or(EINVAL)?;
    Ok(0)
}
