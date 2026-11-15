//! Pseudo-terminals: `/dev/ptmx` and `/dev/pts/N`, with an `N_TTY`-style
//! line discipline.
//!
//! Each root has its own devpts: opening `/dev/ptmx` allocates the lowest
//! free index in the root's table ([`Table`], held by the `Vfs`), creates
//! the node `/dev/pts/N` (mode 0620, owned by the opener, group `tty`) and
//! returns the master. A slave node opens only the pty of that index in the
//! same root, and only through the node created for it, so a pty is never
//! reachable from another root. New ptys start locked (`unlockpt` is
//! `TIOCSPTLCK 0`). Closing the master hangs the terminal up (SIGHUP and
//! SIGCONT to the foreground group), removes the node and frees the index;
//! slaves then read EOF and fail writes with EIO, and the master reads EIO
//! once every slave that was opened is closed.
//!
//! The line discipline, applied as the master writes: input flags ISTRIP,
//! INLCR, IGNCR, ICRNL; canonical editing (ERASE, KILL, WERASE, EOF, EOL,
//! EOL2; reads return at most one line); ECHO with ECHOE/ECHOK/ECHOKE/
//! ECHONL/ECHOCTL; ISIG (INTR, QUIT, SUSP signal the foreground group and
//! flush unless NOFLSH); non-canonical MIN/TIME. Output: OPOST with ONLCR.
//!
//! Controlling terminals: a session leader without one that opens a slave
//! (no `O_NOCTTY`) or calls `TIOCSCTTY` acquires it; `/dev/tty` opens the
//! caller's controlling terminal (the console if it has none). Partial: no
//! job-control checks on background reads/writes (SIGTTIN/SIGTTOU), no
//! flow control (IXON, `TCXONC`), no packet mode; a master writing into a
//! full input queue drops bytes instead of blocking; MIN/TIME's timer runs
//! from the start of the read rather than between bytes.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use frame::sync::SpinLock;
use frame::task::WaitQueue;

use crate::poll::{Object, POLLHUP, POLLIN, POLLOUT};
use crate::process::{Fd, LinuxProcess, ObjectEnd};
use crate::vfs::{Ino, ROOT, Vfs};

const EPERM: i64 = 1;
const EIO: i64 = 5;
const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOSPC: i64 = 28;
const ENOTTY: i64 = 25;
const EMFILE: i64 = 24;

const SIGHUP: u32 = 1;
const SIGINT: u32 = 2;
const SIGQUIT: u32 = 3;
const SIGCONT: u32 = 18;
const SIGTSTP: u32 = 20;
const SIGWINCH: u32 = 28;

/// The first major number of slave nodes (Linux's UNIX98 pty slaves).
pub(crate) const PTS_MAJOR: u32 = 136;
/// Ptys per root.
const MAX_PTYS: u32 = 256;
/// The `tty` group, which owns slave nodes.
const TTY_GID: u32 = 5;
/// Most bytes queued for the slave to read (lines plus raw input).
const INPUT_MAX: usize = 4096;
/// Longest canonical line.
const LINE_MAX: usize = 4095;
/// Most bytes queued for the master to read.
const OUTPUT_MAX: usize = 16384;

// c_iflag
const ISTRIP: u32 = 0o40;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const ICRNL: u32 = 0o400;
const IXON: u32 = 0o2000;
// c_oflag
const OPOST: u32 = 0o1;
const ONLCR: u32 = 0o4;
// c_cflag
const B38400: u32 = 0o17;
const CS8: u32 = 0o60;
const CREAD: u32 = 0o200;
const HUPCL: u32 = 0o2000;
// c_lflag
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const ECHONL: u32 = 0o100;
const NOFLSH: u32 = 0o200;
const ECHOCTL: u32 = 0o1000;
const ECHOKE: u32 = 0o4000;
const IEXTEN: u32 = 0o100000;
// c_cc indices
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VSUSP: usize = 10;
const VEOL: usize = 11;
const VWERASE: usize = 14;
const VEOL2: usize = 16;
const NCCS: usize = 19;

/// The kernel's `struct termios` (what TCGETS/TCSETS copy: 36 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; NCCS],
}

impl Termios {
    /// Linux's `tty_std_termios`.
    const STD: Termios = Termios {
        iflag: ICRNL | IXON,
        oflag: OPOST | ONLCR,
        cflag: B38400 | CS8 | CREAD | HUPCL,
        lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
        line: 0,
        cc: [
            3, 0x1c, 0x7f, 0x15, 4, 0, 1, 0, 0x11, 0x13, 0x1a, 0, 0x12, 0x0f, 0x17, 0x16, 0, 0, 0,
        ],
    };

    fn to_bytes(self) -> [u8; 36] {
        let mut b = [0u8; 36];
        for (i, v) in [self.iflag, self.oflag, self.cflag, self.lflag]
            .into_iter()
            .enumerate()
        {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[16] = self.line;
        b[17..36].copy_from_slice(&self.cc);
        b
    }

    fn from_bytes(b: &[u8; 36]) -> Termios {
        let w = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let mut cc = [0u8; NCCS];
        cc.copy_from_slice(&b[17..36]);
        Termios {
            iflag: w(0),
            oflag: w(4),
            cflag: w(8),
            lflag: w(12),
            line: b[16],
            cc,
        }
    }

    /// Whether `c` is the (enabled) special character `i`.
    fn is(&self, i: usize, c: u8) -> bool {
        self.cc[i] != 0 && self.cc[i] == c
    }
}

#[derive(Debug)]
struct State {
    termios: Termios,
    /// `ws_row, ws_col, ws_xpixel, ws_ypixel`.
    winsize: [u16; 4],
    /// Completed canonical lines (an empty one is an EOF).
    lines: VecDeque<Vec<u8>>,
    /// The canonical line being edited.
    line: Vec<u8>,
    /// Non-canonical input.
    raw: VecDeque<u8>,
    /// Bytes for the master to read: slave output and echoes.
    output: VecDeque<u8>,
    master: bool,
    slaves: usize,
    slave_opened: bool,
    locked: bool,
    /// The session this is the controlling terminal of: `(cell, sid)`.
    session: Option<(u64, u64)>,
    /// The foreground process group.
    fg: u64,
}

impl State {
    fn queued(&self) -> usize {
        self.lines.iter().map(Vec::len).sum::<usize>() + self.line.len() + self.raw.len()
    }

    fn readable(&self) -> usize {
        if self.termios.lflag & ICANON != 0 {
            self.lines.iter().map(Vec::len).sum()
        } else {
            self.raw.len()
        }
    }

    fn has_input(&self) -> bool {
        if self.termios.lflag & ICANON != 0 {
            !self.lines.is_empty()
        } else {
            !self.raw.is_empty()
        }
    }

    fn flush_input(&mut self) {
        self.lines.clear();
        self.line.clear();
        self.raw.clear();
    }

    /// Queues one output byte for the master, with output processing.
    fn emit(&mut self, c: u8) {
        let t = self.termios;
        if t.oflag & OPOST != 0 && t.oflag & ONLCR != 0 && c == b'\n' {
            self.push_out(b'\r');
        }
        self.push_out(c);
    }

    fn push_out(&mut self, c: u8) {
        if self.output.len() < OUTPUT_MAX {
            self.output.push_back(c);
        }
    }

    fn echo(&mut self, c: u8) {
        let l = self.termios.lflag;
        if l & ECHO == 0 {
            return;
        }
        if l & ECHOCTL != 0 && ((c < 0x20 && c != b'\n' && c != b'\t') || c == 0x7f) {
            self.emit(b'^');
            self.emit(if c == 0x7f { b'?' } else { c + 0x40 });
        } else {
            self.emit(c);
        }
    }

    /// Erases the last character of the line being edited (on screen too).
    fn erase_one(&mut self) -> bool {
        let Some(_) = self.line.pop() else {
            return false;
        };
        let l = self.termios.lflag;
        if l & ECHO != 0 && l & ECHOE != 0 {
            for &b in b"\x08 \x08" {
                self.emit(b);
            }
        }
        true
    }

    /// Runs bytes written to the master through the line discipline.
    /// Returns the signals to post to the foreground group.
    fn input(&mut self, data: &[u8]) -> Vec<u32> {
        let mut sigs = Vec::new();
        for &b in data {
            let t = self.termios;
            let mut c = b;
            if t.iflag & ISTRIP != 0 {
                c &= 0x7f;
            }
            if c == b'\r' {
                if t.iflag & IGNCR != 0 {
                    continue;
                }
                if t.iflag & ICRNL != 0 {
                    c = b'\n';
                }
            } else if c == b'\n' && t.iflag & INLCR != 0 {
                c = b'\r';
            }
            if t.lflag & ISIG != 0 {
                let sig = if t.is(VINTR, c) {
                    Some(SIGINT)
                } else if t.is(VQUIT, c) {
                    Some(SIGQUIT)
                } else if t.is(VSUSP, c) {
                    Some(SIGTSTP)
                } else {
                    None
                };
                if let Some(s) = sig {
                    sigs.push(s);
                    if t.lflag & NOFLSH == 0 {
                        self.flush_input();
                    }
                    self.echo(c);
                    continue;
                }
            }
            if self.queued() >= INPUT_MAX {
                continue; // full: dropped
            }
            if t.lflag & ICANON == 0 {
                self.raw.push_back(c);
                self.echo(c);
                continue;
            }
            if t.is(VERASE, c) {
                self.erase_one();
            } else if t.is(VKILL, c) {
                if t.lflag & ECHOKE != 0 || t.lflag & ECHOE != 0 {
                    while self.erase_one() {}
                } else {
                    self.line.clear();
                    self.echo(c);
                    if t.lflag & ECHOK != 0 && t.lflag & ECHO != 0 {
                        self.emit(b'\n');
                    }
                }
            } else if t.lflag & IEXTEN != 0 && t.is(VWERASE, c) {
                while self.line.last() == Some(&b' ') && self.erase_one() {}
                while self.line.last().is_some_and(|&x| x != b' ') && self.erase_one() {}
            } else if t.is(VEOF, c) {
                let l = core::mem::take(&mut self.line);
                self.lines.push_back(l);
            } else if c == b'\n' || t.is(VEOL, c) || t.is(VEOL2, c) {
                self.line.push(c);
                let l = core::mem::take(&mut self.line);
                self.lines.push_back(l);
                if t.lflag & ECHO != 0 || (c == b'\n' && t.lflag & ECHONL != 0) {
                    self.emit(c);
                }
            } else if self.line.len() < LINE_MAX {
                self.line.push(c);
                self.echo(c);
            }
        }
        sigs
    }

    /// Installs new settings, moving queued input between the canonical
    /// and raw queues if ICANON changed.
    fn set_termios(&mut self, t: Termios) {
        let was = self.termios.lflag & ICANON != 0;
        let now = t.lflag & ICANON != 0;
        if was && !now {
            for l in self.lines.drain(..) {
                self.raw.extend(l);
            }
            self.raw.extend(self.line.drain(..));
        } else if !was && now && !self.raw.is_empty() {
            let l: Vec<u8> = self.raw.drain(..).collect();
            self.lines.push_back(l);
        }
        self.termios = t;
    }
}

/// One pseudo-terminal pair.
#[derive(Debug)]
pub(crate) struct Pty {
    index: u32,
    /// The slave node, `/dev/pts/<index>`.
    node: Ino,
    vfs: Weak<Vfs>,
    state: SpinLock<State>,
    queue: WaitQueue,
    changes: AtomicU64,
    /// Tasks polling either end.
    watchers: crate::poll::Watchers,
}

/// A root's ptys by index.
pub(crate) type Table = SpinLock<BTreeMap<u32, Weak<Pty>>>;

impl Pty {
    fn changed(&self) {
        self.changes.fetch_add(1, Ordering::AcqRel);
        self.queue.wake_all();
        self.watchers.notify();
    }

    fn name(&self) -> String {
        alloc::format!("{}", self.index)
    }

    fn signal(&self, sigs: &[u32]) {
        let (session, fg) = {
            let s = self.state.lock();
            (s.session, s.fg)
        };
        if let Some((cell, _)) = session {
            for &sig in sigs {
                crate::proc::signal_pgrp(cell, fg, sig);
            }
        }
    }
}

/// One open end of a pty (each open of a slave is its own).
#[derive(Debug)]
pub(crate) struct End {
    pty: Arc<Pty>,
    master: bool,
    /// The node it was opened through (`/dev/ptmx` or the slave node), for
    /// `fstat`.
    ino: Ino,
}

impl End {
    /// The inode `fstat` reports.
    pub(crate) fn ino(&self) -> Ino {
        self.ino
    }

    /// Its path, for `/proc/<pid>/fd`.
    pub(crate) fn path(&self) -> String {
        if self.master {
            String::from("/dev/ptmx")
        } else {
            alloc::format!("/dev/pts/{}", self.pty.index)
        }
    }
}

impl Drop for End {
    fn drop(&mut self) {
        if !self.master {
            {
                let mut s = self.pty.state.lock();
                s.slaves = s.slaves.saturating_sub(1);
            }
            self.pty.changed();
            return;
        }
        let (session, fg) = {
            let mut s = self.pty.state.lock();
            s.master = false;
            (s.session, s.fg)
        };
        self.pty.changed();
        if let Some((cell, _)) = session {
            crate::proc::signal_pgrp(cell, fg, SIGHUP);
            crate::proc::signal_pgrp(cell, fg, SIGCONT);
        }
        let Some(vfs) = self.pty.vfs.upgrade() else {
            return;
        };
        {
            let mut t = vfs.ptys.lock();
            if t.get(&self.pty.index)
                .is_some_and(|w| core::ptr::eq(w.as_ptr(), Arc::as_ptr(&self.pty)))
            {
                t.remove(&self.pty.index);
            }
        }
        let mut fs = vfs.lock();
        if let Ok(pts) = pts_dir(&mut fs) {
            let name = self.pty.name();
            if fs.lookup(pts, &name) == Ok(self.pty.node) {
                let _ = fs.unlink(pts, &name);
            }
        }
    }
}

fn pts_dir(fs: &mut overlay::Overlay<'static>) -> Result<Ino, i64> {
    let dev = fs.lookup(ROOT, "dev")?;
    fs.lookup(dev, "pts")
}

/// Creates `/dev/pts` in a freshly mounted root.
pub(crate) fn populate(fs: &mut overlay::Overlay<'static>, dev: Ino) {
    if fs.lookup(dev, "pts").is_err() {
        let _ = fs.mkdir(dev, "pts", 0o755);
    }
}

fn end_fd(end: End, nonblock: bool) -> Fd {
    Fd::Object(ObjectEnd {
        obj: Arc::new(end),
        nonblock,
    })
}

/// Opening `/dev/ptmx` (inode `ino`): a new pty's master.
pub(crate) fn open_master(p: &mut LinuxProcess, ino: Ino, nonblock: bool) -> Result<Fd, i64> {
    let vfs = p.vfs.clone();
    let creds = p.group.creds();
    // The root's tree lock serializes allocation: the index is chosen and
    // its node made under it, so two openers cannot pick the same index.
    let mut fs = vfs.lock();
    let index = {
        let mut table = vfs.ptys.lock();
        table.retain(|_, w| w.strong_count() > 0);
        (0..MAX_PTYS)
            .find(|i| !table.contains_key(i))
            .ok_or(ENOSPC)?
    };
    let pts = pts_dir(&mut fs)?;
    let name = alloc::format!("{index}");
    // A node left for a free index is stale (its master is gone).
    let _ = fs.unlink(pts, &name);
    let rdev = ((PTS_MAJOR + index / 256) << 8) | (index % 256);
    let node = fs.mknod(pts, &name, 0o620, rdev)?;
    let _ = fs.chown(node, Some(creds.fsuid), Some(TTY_GID));
    let pty = Arc::new(Pty {
        index,
        node,
        vfs: Arc::downgrade(&vfs),
        state: SpinLock::new(State {
            termios: Termios::STD,
            winsize: [0; 4],
            lines: VecDeque::new(),
            line: Vec::new(),
            raw: VecDeque::new(),
            output: VecDeque::new(),
            master: true,
            slaves: 0,
            slave_opened: false,
            locked: true,
            session: None,
            fg: 0,
        }),
        queue: WaitQueue::new(),
        changes: AtomicU64::new(0),
        watchers: crate::poll::Watchers::new(),
    });
    vfs.ptys.lock().insert(index, Arc::downgrade(&pty));
    drop(fs);
    Ok(end_fd(
        End {
            pty,
            master: true,
            ino,
        },
        nonblock,
    ))
}

/// Whether session `sid` of `cell` already has a controlling pty here.
fn has_ctty(vfs: &Vfs, cell: u64, sid: u64) -> Option<Arc<Pty>> {
    let ptys: Vec<Arc<Pty>> = vfs.ptys.lock().values().filter_map(Weak::upgrade).collect();
    ptys.into_iter()
        .find(|t| t.state.lock().session == Some((cell, sid)))
}

fn open_slave_end(
    p: &mut LinuxProcess,
    pty: Arc<Pty>,
    noctty: bool,
    nonblock: bool,
) -> Result<Fd, i64> {
    let leader = p.group.leader.clone();
    let (pgid, sid) = leader.group();
    let cell = leader.cell;
    let acquire = !noctty && sid == leader.pid && has_ctty(&p.vfs, cell, sid).is_none();
    {
        let mut s = pty.state.lock();
        if s.locked || !s.master {
            return Err(EIO);
        }
        s.slaves += 1;
        s.slave_opened = true;
        if acquire && s.session.is_none() {
            s.session = Some((cell, sid));
            s.fg = pgid;
        }
    }
    pty.changed();
    let ino = pty.node;
    Ok(end_fd(
        End {
            pty,
            master: false,
            ino,
        },
        nonblock,
    ))
}

/// Opening slave node `ino` with device number `rdev`.
pub(crate) fn open_slave(
    p: &mut LinuxProcess,
    rdev: u32,
    ino: Ino,
    noctty: bool,
    nonblock: bool,
) -> Result<Fd, i64> {
    let index = ((rdev >> 8) - PTS_MAJOR) * 256 + (rdev & 0xff);
    let pty = p
        .vfs
        .ptys
        .lock()
        .get(&index)
        .and_then(Weak::upgrade)
        .ok_or(EIO)?;
    // Only the node made for this pty opens it.
    if pty.node != ino {
        return Err(EIO);
    }
    open_slave_end(p, pty, noctty, nonblock)
}

/// Opening `/dev/tty`: the caller's controlling terminal, if it has one.
pub(crate) fn open_controlling(p: &mut LinuxProcess, nonblock: bool) -> Option<Result<Fd, i64>> {
    let leader = p.group.leader.clone();
    let (_, sid) = leader.group();
    let pty = has_ctty(&p.vfs, leader.cell, sid)?;
    Some(open_slave_end(p, pty, true, nonblock))
}

impl Object for End {
    fn read(
        &self,
        max: usize,
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, i64> {
        let pty = &self.pty;
        if self.master {
            let r = pty.queue.wait_until(|| {
                let mut s = pty.state.lock();
                if !s.output.is_empty() {
                    let n = max.min(s.output.len());
                    Some(Ok(s.output.drain(..n).collect()))
                } else if s.slave_opened && s.slaves == 0 {
                    Some(Err(EIO))
                } else if nonblock {
                    Some(Err(EAGAIN))
                } else if interrupted() {
                    Some(Err(crate::signal::ERESTARTSYS))
                } else {
                    None
                }
            });
            if r.is_ok() {
                pty.changed();
            }
            return r;
        }
        let (canon, vmin, vtime) = {
            let s = pty.state.lock();
            let t = s.termios;
            (t.lflag & ICANON != 0, t.cc[VMIN], t.cc[VTIME])
        };
        let deadline = (!canon && vtime > 0)
            .then(|| frame::time::now() + Duration::from_millis(100 * u64::from(vtime)));
        let attempt = |expired: bool| -> Option<Result<Vec<u8>, i64>> {
            let mut s = pty.state.lock();
            if s.termios.lflag & ICANON != 0 {
                if let Some(mut l) = s.lines.pop_front() {
                    if l.len() > max {
                        let rest = l.split_off(max);
                        s.lines.push_front(rest);
                    }
                    return Some(Ok(l));
                }
            } else {
                let avail = s.raw.len();
                let need = usize::from(vmin).min(max).max(1);
                let poll_only = vmin == 0 && vtime == 0;
                if avail >= need || poll_only || (expired && avail > 0) || (vmin == 0 && avail > 0)
                {
                    let n = avail.min(max);
                    return Some(Ok(s.raw.drain(..n).collect()));
                }
                if expired {
                    return Some(Ok(Vec::new()));
                }
            }
            if !s.master {
                Some(Ok(Vec::new()))
            } else if nonblock {
                Some(Err(EAGAIN))
            } else if interrupted() {
                Some(Err(crate::signal::ERESTARTSYS))
            } else {
                None
            }
        };
        let r = match deadline {
            None => pty.queue.wait_until(|| attempt(false)),
            Some(dl) => match pty.queue.wait_until_deadline(dl, || attempt(false)) {
                Some(r) => r,
                None => attempt(true).unwrap_or(Ok(Vec::new())),
            },
        };
        if r.is_ok() {
            pty.changed();
        }
        r
    }

    fn write(
        &self,
        data: &[u8],
        nonblock: bool,
        interrupted: &dyn Fn() -> bool,
    ) -> Result<usize, i64> {
        let pty = &self.pty;
        if self.master {
            let sigs = pty.state.lock().input(data);
            pty.changed();
            pty.signal(&sigs);
            return Ok(data.len());
        }
        let r = pty.queue.wait_until(|| {
            let mut s = pty.state.lock();
            if !s.master {
                return Some(Err(EIO));
            }
            // Room for every byte even if each becomes "\r\n".
            let room = OUTPUT_MAX.saturating_sub(s.output.len()) / 2;
            if room > 0 {
                let n = room.min(data.len());
                for &c in &data[..n] {
                    s.emit(c);
                }
                Some(Ok(n))
            } else if nonblock {
                Some(Err(EAGAIN))
            } else if interrupted() {
                Some(Err(crate::signal::ERESTARTSYS))
            } else {
                None
            }
        });
        if r.is_ok() {
            pty.changed();
        }
        r
    }

    fn poll(&self) -> u16 {
        let s = self.pty.state.lock();
        if self.master {
            let mut r = POLLOUT;
            if !s.output.is_empty() {
                r |= POLLIN;
            }
            if s.slave_opened && s.slaves == 0 {
                r |= POLLHUP;
            }
            r
        } else {
            let mut r = 0;
            if s.has_input() {
                r |= POLLIN;
            }
            if !s.master {
                r |= POLLIN | POLLHUP;
            } else if s.output.len() < OUTPUT_MAX {
                r |= POLLOUT;
            }
            r
        }
    }

    fn changes(&self) -> u64 {
        self.pty.changes.load(Ordering::Acquire)
    }

    fn mode(&self) -> u32 {
        0o020_000 // S_IFCHR
    }

    fn tty(&self) -> Option<&End> {
        Some(self)
    }

    fn watchers(&self) -> Option<&crate::poll::Watchers> {
        Some(&self.pty.watchers)
    }
}

fn get_int(p: &mut LinuxProcess, arg: u64) -> Result<i32, i64> {
    let mut b = [0u8; 4];
    if p.copy_from_user(arg, &mut b) != 4 {
        return Err(EFAULT);
    }
    Ok(i32::from_le_bytes(b))
}

fn put(p: &mut LinuxProcess, arg: u64, bytes: &[u8]) -> Result<u64, i64> {
    if p.copy_to_user(arg, bytes) != bytes.len() {
        return Err(EFAULT);
    }
    Ok(0)
}

/// Terminal ioctls on a pty end.
pub(crate) fn ioctl(p: &mut LinuxProcess, end: &End, request: u64, arg: u64) -> Result<u64, i64> {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TCSBRK: u64 = 0x5409;
    const TCFLSH: u64 = 0x540B;
    const TIOCSCTTY: u64 = 0x540E;
    const TIOCGPGRP: u64 = 0x540F;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCOUTQ: u64 = 0x5411;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONREAD: u64 = 0x541B;
    const TIOCNOTTY: u64 = 0x5422;
    const TCSBRKP: u64 = 0x5425;
    const TIOCGSID: u64 = 0x5429;
    const TCGETS2: u64 = 0x802C_542A;
    const TCSETS2: u64 = 0x402C_542B;
    const TCSETSW2: u64 = 0x402C_542C;
    const TCSETSF2: u64 = 0x402C_542D;
    const TIOCGPTN: u64 = 0x8004_5430;
    const TIOCSPTLCK: u64 = 0x4004_5431;
    const TIOCGPTLCK: u64 = 0x8004_5439;
    const TIOCGPTPEER: u64 = 0x5441;
    const O_NOCTTY: u64 = 0o400;
    const O_NONBLOCK: u64 = 0o4000;
    const O_CLOEXEC: u64 = 0o2000000;
    let pty = &end.pty;
    let leader = p.group.leader.clone();
    let (pgid, sid) = leader.group();
    let me = (leader.cell, sid);
    match request {
        TCGETS | TCGETS2 => {
            let t = pty.state.lock().termios.to_bytes();
            if request == TCGETS {
                return put(p, arg, &t);
            }
            let mut b = [0u8; 44];
            b[..36].copy_from_slice(&t);
            b[36..40].copy_from_slice(&38400u32.to_le_bytes());
            b[40..44].copy_from_slice(&38400u32.to_le_bytes());
            put(p, arg, &b)
        }
        TCSETS | TCSETSW | TCSETSF | TCSETS2 | TCSETSW2 | TCSETSF2 => {
            let mut b = [0u8; 36];
            if p.copy_from_user(arg, &mut b) != 36 {
                return Err(EFAULT);
            }
            {
                let mut s = pty.state.lock();
                if request == TCSETSF || request == TCSETSF2 {
                    s.flush_input();
                }
                s.set_termios(Termios::from_bytes(&b));
            }
            pty.changed();
            Ok(0)
        }
        // Output reaches the master as it is written: a drain or a break
        // has nothing to wait for.
        TCSBRK | TCSBRKP => Ok(0),
        TCFLSH => {
            let (input, output) = match arg {
                0 => (true, false),
                1 => (false, true),
                2 => (true, true),
                _ => return Err(EINVAL),
            };
            // On the master the queues are the other way round.
            let (input, output) = if end.master {
                (output, input)
            } else {
                (input, output)
            };
            {
                let mut s = pty.state.lock();
                if input {
                    s.flush_input();
                }
                if output {
                    s.output.clear();
                }
            }
            pty.changed();
            Ok(0)
        }
        TIOCSCTTY => {
            if sid != leader.pid {
                return Err(EPERM);
            }
            if let Some(other) = has_ctty(&p.vfs, me.0, sid) {
                return if Arc::ptr_eq(&other, pty) {
                    Ok(0)
                } else {
                    Err(EPERM)
                };
            }
            let mut s = pty.state.lock();
            if s.session.is_some() {
                return Err(EPERM);
            }
            s.session = Some(me);
            s.fg = pgid;
            Ok(0)
        }
        TIOCNOTTY => {
            let mut s = pty.state.lock();
            if s.session != Some(me) {
                return Err(ENOTTY);
            }
            s.session = None;
            Ok(0)
        }
        TIOCGPGRP | TIOCGSID => {
            let (session, fg) = {
                let s = pty.state.lock();
                (s.session, s.fg)
            };
            let Some((_, tsid)) = session.filter(|&s| end.master || s == me) else {
                return Err(ENOTTY);
            };
            let v = if request == TIOCGPGRP { fg } else { tsid };
            put(p, arg, &(v as u32).to_le_bytes())
        }
        TIOCSPGRP => {
            let g = get_int(p, arg)?;
            if g < 0 {
                return Err(EINVAL);
            }
            if !crate::proc::pgrp_in_session(me.0, g as u64, sid) {
                return Err(EPERM);
            }
            let mut s = pty.state.lock();
            if s.session != Some(me) {
                return Err(ENOTTY);
            }
            s.fg = g as u64;
            Ok(0)
        }
        TIOCOUTQ => {
            let n = if end.master {
                0
            } else {
                pty.state.lock().output.len()
            };
            put(p, arg, &(n as u32).to_le_bytes())
        }
        FIONREAD => {
            let n = {
                let s = pty.state.lock();
                if end.master {
                    s.output.len()
                } else {
                    s.readable()
                }
            };
            put(p, arg, &(n as u32).to_le_bytes())
        }
        TIOCGWINSZ => {
            let w = pty.state.lock().winsize;
            let mut b = [0u8; 8];
            for (i, v) in w.iter().enumerate() {
                b[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
            }
            put(p, arg, &b)
        }
        TIOCSWINSZ => {
            let mut b = [0u8; 8];
            if p.copy_from_user(arg, &mut b) != 8 {
                return Err(EFAULT);
            }
            let w = [0, 2, 4, 6].map(|i| u16::from_le_bytes([b[i], b[i + 1]]));
            let changed = {
                let mut s = pty.state.lock();
                let c = s.winsize != w;
                s.winsize = w;
                c
            };
            if changed {
                pty.signal(&[SIGWINCH]);
            }
            Ok(0)
        }
        TIOCGPTN if end.master => put(p, arg, &pty.index.to_le_bytes()),
        TIOCSPTLCK if end.master => {
            let lock = get_int(p, arg)? != 0;
            pty.state.lock().locked = lock;
            Ok(0)
        }
        TIOCGPTLCK if end.master => {
            let l = u32::from(pty.state.lock().locked);
            put(p, arg, &l.to_le_bytes())
        }
        TIOCGPTPEER if end.master => {
            let fd = open_slave_end(p, pty.clone(), arg & O_NOCTTY != 0, arg & O_NONBLOCK != 0)?;
            p.install_flags(fd, arg & O_CLOEXEC != 0).ok_or(EMFILE)
        }
        _ => Err(ENOTTY),
    }
}
