//! Linux signals for a process: dispositions (`rt_sigaction`), the mask
//! (`rt_sigprocmask`), delivery onto a Linux-compatible `rt_sigframe`, and
//! `rt_sigreturn`.
//!
//! Pending signals live in the process's table entry (`proc::ProcEntry`),
//! because other tasks post them (`kill`, `SIGCHLD`, `SIGPIPE`). Delivery
//! happens on the process's own task in the run loop, after each syscall or
//! fault. Blocking syscalls return `ERESTARTSYS` when a deliverable signal
//! arrives; delivery then either restarts the call (`SA_RESTART`, or no
//! handler ran) or turns it into `EINTR`, as Linux does.
//!
//! A signal is sent to a thread (`tgkill`, SIGPIPE) or to a process, whose
//! first thread to look that does not block it takes it. Stop signals park
//! every thread of the process in the run loop until `SIGCONT`.

use frame::user::UserContext;

use crate::proc;
use crate::process::LinuxProcess;

pub(crate) const SIGKILL: u32 = 9;
pub(crate) const SIGSEGV: u32 = 11;
pub(crate) const SIGPIPE: u32 = 13;
pub(crate) const SIGALRM: u32 = 14;
pub(crate) const SIGIO: u32 = 29;
pub(crate) const SIGCHLD: u32 = 17;
pub(crate) const SIGCONT: u32 = 18;
pub(crate) const SIGSTOP: u32 = 19;
pub(crate) const SIGTTIN: u32 = 21;
pub(crate) const SIGTTOU: u32 = 22;
pub(crate) const NSIG: u32 = 64;

/// The signals that stop a process: STOP, TSTP, TTIN, TTOU.
pub(crate) const STOPS: u64 = 0xf << (SIGSTOP - 1);

/// `siginfo_t` codes: who sent it.
pub(crate) const SI_USER: i32 = 0;
pub(crate) const SI_KERNEL: i32 = 0x80;
const SI_TKILL: i32 = -6;
/// Codes of CPU exceptions.
pub(crate) const FPE_INTDIV: i32 = 1;
pub(crate) const FPE_FLTINV: i32 = 7;
pub(crate) const TRAP_TRACE: i32 = 2;
pub(crate) const ILL_ILLOPN: i32 = 2;
pub(crate) const SEGV_MAPERR: i32 = 1;
pub(crate) const SEGV_ACCERR: i32 = 2;

/// What a signal carries besides its number: the fields of a `siginfo_t`
/// at 8 (the code), 16 and 24 (by kind: sender's pid and uid, then a
/// value; a child's pid and uid, then its status; a fault's address).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Info {
    code: i32,
    a: u64,
    b: u64,
}

impl Info {
    fn ids(pid: u64, uid: u32) -> u64 {
        (pid & 0xffff_ffff) | u64::from(uid) << 32
    }

    /// From process `pid`, real uid `uid`.
    pub(crate) fn sent(code: i32, pid: u64, uid: u32) -> Info {
        Info {
            code,
            a: Info::ids(pid, uid),
            b: 0,
        }
    }

    /// From the kernel.
    pub(crate) fn kernel() -> Info {
        Info {
            code: SI_KERNEL,
            a: 0,
            b: 0,
        }
    }

    /// About child process `c`: `SIGCHLD` with a `CLD_*` code, and its exit
    /// status or the signal.
    pub(crate) fn child(c: &proc::ProcEntry, code: i32, status: u32) -> Info {
        Info {
            code,
            a: Info::ids(c.pid, c.uids().0),
            b: u64::from(status),
        }
    }

    /// An expiry of POSIX timer `id`.
    pub(crate) fn timer(id: i32, overrun: u32, value: u64) -> Info {
        const SI_TIMER: i32 = -2;
        Info {
            code: SI_TIMER,
            a: Info::ids(id as u64, overrun),
            b: value,
        }
    }

    /// A CPU exception at `addr`.
    fn fault(code: i32, addr: u64) -> Info {
        Info {
            code,
            a: addr,
            b: 0,
        }
    }

    /// The `siginfo_t` for signal `sig`.
    fn bytes(&self, sig: u32) -> [u8; INFO_SIZE as usize] {
        let mut f = [0u8; INFO_SIZE as usize];
        f[0..4].copy_from_slice(&sig.to_le_bytes());
        f[8..12].copy_from_slice(&self.code.to_le_bytes());
        f[16..24].copy_from_slice(&self.a.to_le_bytes());
        f[24..32].copy_from_slice(&self.b.to_le_bytes());
        f
    }

    /// One a process made (`rt_sigqueueinfo`).
    fn from_bytes(f: &[u8; INFO_SIZE as usize]) -> Info {
        Info {
            code: i32::from_le_bytes([f[8], f[9], f[10], f[11]]),
            a: crate::linuxabi::le_u64(&f[16..24]),
            b: crate::linuxabi::le_u64(&f[24..32]),
        }
    }
}

/// Internal errnos, which never reach user space. A signal interrupted the
/// call: it restarts if no handler ran, or if the one that did asked for
/// that (`SA_RESTART`).
pub(crate) const ERESTARTSYS: i64 = 512;
/// As [`ERESTARTSYS`], but a handler always ends it with EINTR.
pub(crate) const ERESTARTNOHAND: i64 = 514;

/// A syscall that a signal interrupted and that may be restarted.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Restart {
    nr: u64,
    /// A handler with `SA_RESTART` restarts it too.
    handled: bool,
}

impl Restart {
    /// From syscall `nr`'s result.
    pub(crate) fn of(nr: u64, result: i64) -> Option<Restart> {
        match -result {
            ERESTARTSYS => Some(Restart { nr, handled: true }),
            ERESTARTNOHAND => Some(Restart { nr, handled: false }),
            _ => None,
        }
    }
}

/// What becomes of a thread after its signals were looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fate {
    Goes,
    /// A signal ends the process, with this wait status.
    ProcessEnds(u32),
    /// Only the thread ends (its process is exiting, or in `execve`).
    ThreadEnds,
}

const EINTR: i64 = 4;
const EAGAIN: i64 = 11;
const EINVAL: i64 = 22;
const EFAULT: i64 = 14;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SA_NOCLDSTOP: u64 = 1;
const SA_NOCLDWAIT: u64 = 2;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_ONSTACK: u64 = 0x0800_0000;
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
const SS_AUTODISARM: u32 = 1 << 31;
const MINSIGSTKSZ: u64 = 2048;
const SA_RESTART: u64 = 0x1000_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;

/// The bit for `sig` in a signal set.
pub(crate) fn bit(sig: u32) -> u64 {
    1u64 << (sig - 1)
}

/// Signals that can be neither caught, blocked nor ignored.
const UNBLOCKABLE: u64 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

enum DefaultAction {
    Ignore,
    Terminate,
    /// Terminate and report a core dump in the wait status.
    Core,
    Stop,
}

fn default_action(sig: u32) -> DefaultAction {
    match sig {
        // CHLD, CONT (what it does happens as it is sent), URG, WINCH.
        17 | 18 | 23 | 28 => DefaultAction::Ignore,
        // STOP, TSTP, TTIN, TTOU.
        19..=22 => DefaultAction::Stop,
        3..=8 | 11 | 24 | 25 | 31 => DefaultAction::Core,
        _ => DefaultAction::Terminate,
    }
}

/// One signal's disposition (`struct kernel_sigaction` on x86-64).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Action {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

/// A thread's signal mask.
#[derive(Clone, Debug)]
pub(crate) struct Signals {
    pub(crate) mask: u64,
    /// The mask to restore after `rt_sigsuspend`'s handler.
    saved_mask: Option<u64>,
    /// The alternate signal stack (`sigaltstack`): base and size.
    alt: Option<(u64, u64)>,
}

impl Signals {
    pub(crate) fn new() -> Signals {
        Signals {
            mask: 0,
            saved_mask: None,
            alt: None,
        }
    }

    /// `execve` and new threads start without an alternate stack.
    pub(crate) fn clear_alt_stack(&mut self) {
        self.alt = None;
    }

    fn on_alt(&self, sp: u64) -> bool {
        self.alt
            .is_some_and(|(base, size)| sp > base && sp <= base + size)
    }
}

/// A process's signal dispositions, shared by its threads.
#[derive(Clone, Debug)]
pub(crate) struct Actions {
    actions: [Action; NSIG as usize],
}

/// Signal `sig`'s place in the actions table. Every caller has checked
/// that `sig` is 1 to `NSIG`; the index is clamped so that the CPU does not
/// run past that check with another (Spectre v1, ADR-0004 §2).
fn slot(sig: u32) -> usize {
    frame::nospec::index((sig as usize).wrapping_sub(1), NSIG as usize)
}

impl Actions {
    pub(crate) fn new() -> Actions {
        Actions {
            actions: [Action::default(); NSIG as usize],
        }
    }

    fn get(&self, sig: u32) -> Action {
        self.actions[slot(sig)]
    }

    /// `execve`: caught signals revert to the default; ignored ones stay
    /// ignored (the mask is kept too).
    pub(crate) fn exec_reset(&mut self) {
        for a in &mut self.actions {
            if a.handler != SIG_IGN {
                *a = Action::default();
            }
        }
    }

    /// Signals set to SIG_IGN, and signals with a handler.
    pub(crate) fn set_ignored(&self) -> u64 {
        self.those(|h| h == SIG_IGN)
    }

    pub(crate) fn caught(&self) -> u64 {
        self.those(|h| h != SIG_IGN && h != SIG_DFL)
    }

    fn those(&self, which: impl Fn(u64) -> bool) -> u64 {
        (1..=NSIG)
            .filter(|&s| which(self.get(s).handler))
            .fold(0, |set, s| set | bit(s))
    }

    /// Signals whose arrival would be discarded right away.
    pub(crate) fn ignored(&self) -> u64 {
        let mut set = 0;
        for sig in 1..=NSIG {
            let a = self.get(sig);
            let ignore = a.handler == SIG_IGN
                || (a.handler == SIG_DFL && matches!(default_action(sig), DefaultAction::Ignore));
            if ignore {
                set |= bit(sig);
            }
        }
        set & !UNBLOCKABLE
    }
}

/// Publishes `p`'s mask, and its process's ignored set to every thread's
/// table entry, which senders and interruptible waits consult.
pub(crate) fn sync(p: &LinuxProcess) {
    use core::sync::atomic::Ordering::Relaxed;
    let (ignored, chld) = {
        let a = p.group.actions.lock();
        (a.ignored(), a.get(SIGCHLD))
    };
    let shared = &p.entry.shared;
    shared
        .nocldstop
        .store(chld.flags & SA_NOCLDSTOP != 0, Relaxed);
    let nowait = chld.flags & SA_NOCLDWAIT != 0 || chld.handler == SIG_IGN;
    shared.nocldwait.store(nowait, Relaxed);
    for t in p.group.threads() {
        let mask = if t.pid == p.entry.pid {
            p.sig.mask
        } else {
            proc::blocked(&t)
        };
        proc::set_masks(&t, mask, ignored);
    }
}

fn read_u64(p: &mut LinuxProcess, addr: u64) -> Result<u64, i64> {
    let mut b = [0u8; 8];
    if p.copy_from_user(addr, &mut b) != 8 {
        return Err(EFAULT);
    }
    Ok(u64::from_le_bytes(b))
}

fn write_u64(p: &mut LinuxProcess, addr: u64, v: u64) -> Result<(), i64> {
    if p.copy_to_user(addr, &v.to_le_bytes()) != 8 {
        return Err(EFAULT);
    }
    Ok(())
}

/// `rt_sigaction`.
pub(crate) fn sigaction(
    p: &mut LinuxProcess,
    sig: u64,
    act: u64,
    oact: u64,
    size: u64,
) -> Result<u64, i64> {
    let sig = u32::try_from(sig)
        .ok()
        .filter(|s| (1..=NSIG).contains(s))
        .ok_or(EINVAL)?;
    if size != 8 {
        return Err(EINVAL);
    }
    let old = p.group.actions.lock().get(sig);
    if act != 0 {
        if sig == SIGKILL || sig == SIGSTOP {
            return Err(EINVAL);
        }
        let mut b = [0u8; 32];
        if p.copy_from_user(act, &mut b) != 32 {
            return Err(EFAULT);
        }
        let word = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
        let ignored = {
            let mut acts = p.group.actions.lock();
            acts.actions[slot(sig)] = Action {
                handler: word(0),
                flags: word(1),
                restorer: word(2),
                mask: word(3) & !UNBLOCKABLE,
            };
            acts.ignored()
        };
        sync(p);
        // Setting SIG_IGN discards pending instances in every thread.
        if ignored & bit(sig) != 0 {
            for t in p.group.threads() {
                proc::clear_pending(&t, bit(sig));
            }
        }
    }
    if oact != 0 {
        let mut b = [0u8; 32];
        for (i, w) in [old.handler, old.flags, old.restorer, old.mask]
            .iter()
            .enumerate()
        {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        if p.copy_to_user(oact, &b) != 32 {
            return Err(EFAULT);
        }
    }
    Ok(0)
}

/// `rt_sigprocmask`.
pub(crate) fn sigprocmask(
    p: &mut LinuxProcess,
    how: u64,
    set: u64,
    oset: u64,
    size: u64,
) -> Result<u64, i64> {
    const SIG_BLOCK: u64 = 0;
    const SIG_UNBLOCK: u64 = 1;
    const SIG_SETMASK: u64 = 2;
    if size != 8 {
        return Err(EINVAL);
    }
    let old = p.sig.mask;
    if set != 0 {
        let s = read_u64(p, set)?;
        p.sig.mask = match how {
            SIG_BLOCK => old | s,
            SIG_UNBLOCK => old & !s,
            SIG_SETMASK => s,
            _ => return Err(EINVAL),
        } & !UNBLOCKABLE;
        sync(p);
    }
    if oset != 0 {
        write_u64(p, oset, old)?;
    }
    Ok(0)
}

/// `rt_sigpending`: the signals pending for the thread or its process that
/// its mask holds back (unblocked ones are delivered before returning to
/// user code, so they are never seen here).
pub(crate) fn sigpending(p: &mut LinuxProcess, set: u64, size: u64) -> Result<u64, i64> {
    if size != 8 {
        return Err(EINVAL);
    }
    let pending = proc::pending(&p.entry);
    write_u64(p, set, pending & p.sig.mask)?;
    Ok(0)
}

/// `rt_sigsuspend`: waits with `mask` in place until a signal is delivered.
pub(crate) fn sigsuspend(p: &mut LinuxProcess, mask: u64, size: u64) -> Result<u64, i64> {
    if size != 8 {
        return Err(EINVAL);
    }
    let m = read_u64(p, mask)?;
    p.sig.saved_mask = Some(p.sig.mask);
    p.sig.mask = m & !UNBLOCKABLE;
    sync(p);
    proc::wait_for_signal(&p.entry);
    Err(ERESTARTNOHAND)
}

/// Puts the signal mask at user `addr` (a `sigset_t` of `size` bytes) in
/// place for a wait (`ppoll`, `pselect6`, `epoll_pwait`); null leaves the
/// mask alone. Pair with [`end_wait_mask`].
pub(crate) fn begin_wait_mask(p: &mut LinuxProcess, addr: u64, size: u64) -> Result<(), i64> {
    if addr == 0 {
        return Ok(());
    }
    if size != 8 {
        return Err(EINVAL);
    }
    let m = read_u64(p, addr)?;
    p.sig.saved_mask = Some(p.sig.mask);
    p.sig.mask = m & !UNBLOCKABLE;
    sync(p);
    Ok(())
}

/// Ends a wait's temporary mask. When a signal ended the wait it stays
/// until the handler is set up (which saves the original mask in its
/// frame), as on Linux; otherwise the original comes back now.
pub(crate) fn end_wait_mask(p: &mut LinuxProcess, r: &Result<u64, i64>) {
    if matches!(*r, Err(EINTR | ERESTARTNOHAND)) {
        return;
    }
    if let Some(m) = p.sig.saved_mask.take() {
        p.sig.mask = m;
        sync(p);
    }
}

/// `pause`.
pub(crate) fn pause(p: &mut LinuxProcess) -> Result<u64, i64> {
    proc::wait_for_signal(&p.entry);
    Err(ERESTARTNOHAND)
}

/// `rt_sigtimedwait(set, info, timeout, size)`: takes a pending signal of
/// `set` (which the caller blocks), waiting for one.
pub(crate) fn sigtimedwait(
    p: &mut LinuxProcess,
    set: u64,
    info: u64,
    timeout: u64,
    size: u64,
) -> Result<u64, i64> {
    if size != 8 {
        return Err(EINVAL);
    }
    let set = read_u64(p, set)? & !UNBLOCKABLE;
    let deadline = match timeout {
        0 => None,
        t => Some(frame::time::now().saturating_add(crate::poll::read_timespec(p, t)?)),
    };
    let (sig, what) = proc::await_signal(&p.entry, set, deadline)?.ok_or(EAGAIN)?;
    let bytes = what.bytes(sig);
    if info != 0 && p.copy_to_user(info, &bytes) != bytes.len() {
        return Err(EFAULT);
    }
    Ok(u64::from(sig))
}

/// A `siginfo_t` a process made, for `sig`: only the kernel claims to be
/// the kernel (a code of zero or above, or `tkill`'s), unless the process
/// signals itself.
fn read_info(p: &mut LinuxProcess, info: u64, own: bool) -> Result<Info, i64> {
    const EPERM: i64 = 1;
    let mut b = [0u8; INFO_SIZE as usize];
    if p.copy_from_user(info, &mut b) != b.len() {
        return Err(EFAULT);
    }
    let i = Info::from_bytes(&b);
    if !own && (i.code >= 0 || i.code == SI_TKILL) {
        return Err(EPERM);
    }
    Ok(i)
}

/// `rt_sigqueueinfo(tgid, sig, info)`.
pub(crate) fn sigqueueinfo(
    p: &mut LinuxProcess,
    tgid: u64,
    sig: u64,
    info: u64,
) -> Result<u64, i64> {
    let i = read_info(p, info, tgid == p.group.tgid)?;
    let sig = signal_number(sig)?;
    may_signal(p, tgid, sig)?;
    proc::send_info(p.entry.cell, tgid, sig, i)?;
    Ok(0)
}

/// `rt_tgsigqueueinfo(tgid, tid, sig, info)`.
pub(crate) fn tgsigqueueinfo(
    p: &mut LinuxProcess,
    tgid: u64,
    tid: u64,
    sig: u64,
    info: u64,
) -> Result<u64, i64> {
    let i = read_info(p, info, tgid == p.group.tgid)?;
    let sig = signal_number(sig)?;
    may_signal(p, tgid, sig)?;
    proc::send_thread(p.entry.cell, Some(tgid), tid, sig, i)?;
    Ok(0)
}

/// What reading a signal descriptor gives for `sig`: `signalfd_siginfo`.
pub(crate) fn signalfd_record(sig: u32, info: &Info) -> [u8; 128] {
    let mut b = [0u8; 128];
    b[0..4].copy_from_slice(&sig.to_le_bytes());
    b[8..12].copy_from_slice(&info.code.to_le_bytes());
    b[12..20].copy_from_slice(&info.a.to_le_bytes()); // pid, uid
    if sig == SIGCHLD {
        b[40..44].copy_from_slice(&(info.b as u32).to_le_bytes()); // status
    } else {
        b[44..48].copy_from_slice(&(info.b as u32).to_le_bytes()); // int
        b[48..56].copy_from_slice(&info.b.to_le_bytes()); // ptr
    }
    b
}

/// A signal number argument, 0 included.
pub(crate) fn signal_number(sig: u64) -> Result<u32, i64> {
    u32::try_from(sig).ok().filter(|&s| s <= NSIG).ok_or(EINVAL)
}

/// Whether the caller may send `sig` to process `pid`: EPERM by its
/// credentials (anyone may continue a process of their session), ESRCH.
pub(crate) fn may_signal(p: &LinuxProcess, pid: u64, sig: u32) -> Result<(), i64> {
    const EPERM: i64 = 1;
    let me = &p.group.leader;
    if p.group.creds().may_signal(proc::uids_of(me.cell, pid)?) {
        return Ok(());
    }
    let same_session = proc::group_of(me, pid).is_ok_and(|(_, sid)| sid == me.group().1);
    if sig == SIGCONT && same_session {
        return Ok(());
    }
    Err(EPERM)
}

/// Whether `p`'s process ignores `sig`.
pub(crate) fn is_ignored(p: &LinuxProcess, sig: u32) -> bool {
    p.group.actions.lock().ignored() & bit(sig) != 0
}

/// What a signal this process sends says of it.
fn from_me(p: &LinuxProcess, code: i32) -> Info {
    Info::sent(code, p.group.tgid, p.group.creds().ruid)
}

/// `nanosleep` / `clock_nanosleep` (relative): sleeps on a frame timed
/// wait; a signal that runs a handler ends it early with `EINTR` and the
/// time left in `rem`.
pub(crate) fn nanosleep(p: &mut LinuxProcess, req: u64, rem: u64) -> Result<u64, i64> {
    let sec = read_u64(p, req)?;
    let nsec = read_u64(p, req + 8)?;
    if nsec >= 1_000_000_000 || sec > i64::MAX as u64 {
        return Err(EINVAL);
    }
    let deadline = p.resume_until.take().unwrap_or_else(|| {
        frame::time::now()
            .saturating_add(core::time::Duration::from_secs(sec))
            .saturating_add(core::time::Duration::from_nanos(nsec))
    });
    if !proc::sleep_until(&p.entry, deadline) {
        return Ok(0);
    }
    p.resume_until = Some(deadline);
    if rem != 0 {
        let left = deadline.saturating_sub(frame::time::now());
        write_u64(p, rem, left.as_secs())?;
        write_u64(p, rem + 8, u64::from(left.subsec_nanos()))?;
    }
    Err(ERESTARTNOHAND)
}

/// `clock_nanosleep(clock, flags, req, rem)`: relative sleeps as
/// `nanosleep`; with TIMER_ABSTIME, until `req` on `clock` (CPython's
/// `time.sleep` sleeps this way on CLOCK_MONOTONIC). A realtime deadline
/// is converted once to monotonic time, so a clock step during the sleep
/// is not followed (the wall clock here never steps). An interrupted
/// absolute sleep is EINTR and leaves `rem` alone, as on Linux.
pub(crate) fn clock_nanosleep(
    p: &mut LinuxProcess,
    clock: u64,
    flags: u64,
    req: u64,
    rem: u64,
) -> Result<u64, i64> {
    const REALTIME: u64 = 0;
    const MONOTONIC: u64 = 1;
    const BOOTTIME: u64 = 7;
    const TIMER_ABSTIME: u64 = 1;
    const ENOTSUP: i64 = 95;
    match clock {
        REALTIME | MONOTONIC | BOOTTIME => {}
        2 | 3 => return Err(ENOTSUP), // CPU-time clocks are not accounted
        _ => return Err(EINVAL),
    }
    if flags & TIMER_ABSTIME == 0 {
        return nanosleep(p, req, rem);
    }
    let sec = read_u64(p, req)?;
    let nsec = read_u64(p, req + 8)?;
    if nsec >= 1_000_000_000 || sec > i64::MAX as u64 {
        return Err(EINVAL);
    }
    let target =
        core::time::Duration::from_secs(sec).saturating_add(core::time::Duration::from_nanos(nsec));
    let now = frame::time::now();
    let deadline = if clock == REALTIME {
        now.saturating_add(target.saturating_sub(crate::vfs::wall_clock()))
    } else {
        target
    };
    if deadline <= now || !proc::sleep_until(&p.entry, deadline) {
        return Ok(0);
    }
    Err(ERESTARTNOHAND)
}

/// `kill`: process-directed (any thread of the target may take it). `pid`
/// 0 is the caller's process group, `-pgid` another group, -1 every other
/// process in the cell. Never crosses the cell.
pub(crate) fn kill(p: &mut LinuxProcess, pid: i64, sig: u64) -> Result<u64, i64> {
    let sig = signal_number(sig)?;
    let me = p.group.leader.clone();
    let creds = p.group.creds();
    let info = from_me(p, SI_USER);
    let allowed = |target: (u32, u32)| creds.may_signal(target);
    match pid {
        pid if pid > 0 => {
            may_signal(p, pid as u64, sig)?;
            proc::send_info(me.cell, pid as u64, sig, info)?
        }
        0 => proc::send_group(&me, Some(me.group().0), sig, info, &allowed)?,
        -1 => proc::send_group(&me, None, sig, info, &allowed)?,
        g => proc::send_group(&me, Some(g.unsigned_abs()), sig, info, &allowed)?,
    }
    Ok(0)
}

/// `tkill` / `tgkill`: thread-directed.
pub(crate) fn tkill(p: &LinuxProcess, tgid: Option<u64>, tid: u64, sig: u64) -> Result<u64, i64> {
    let sig = signal_number(sig)?;
    may_signal(p, tid, sig)?;
    proc::send_thread(p.entry.cell, tgid, tid, sig, from_me(p, SI_TKILL))?;
    Ok(0)
}

fn restart_syscall(ctx: &mut UserContext, nr: u64) {
    ctx.rax = nr;
    ctx.rip -= 2; // back over `syscall`
}

/// Delivers pending, unblocked signals after a syscall (`restart` if a
/// signal interrupted it) or fault, and stops here while the process is
/// stopped.
pub(crate) fn deliver(
    p: &mut LinuxProcess,
    ctx: &mut UserContext,
    mut restart: Option<Restart>,
) -> Fate {
    loop {
        if proc::ending(&p.entry) {
            return Fate::ThreadEnds;
        }
        if proc::stopping(&p.entry) && !proc::dying(&p.entry) {
            proc::park(&p.entry, p.group.threads().len());
            continue;
        }
        let pending = proc::pending(&p.entry);
        // (What comes after this look is seen on the way to user code.)
        let wanted = match pending & bit(SIGKILL) {
            0 => pending & !p.sig.mask,
            kill => kill,
        };
        let seen = if pending & STOPS == 0 {
            0
        } else {
            proc::continues(&p.entry)
        };
        let Some((sig, info)) = proc::take_signal(&p.entry, wanted) else {
            // A wait's temporary mask (sigsuspend, ppoll, ...) ends here if
            // no handler took it over; the restored mask may let more in.
            if let Some(r) = restart.take() {
                restart_syscall(ctx, r.nr);
            }
            if let Some(m) = p.sig.saved_mask.take() {
                p.sig.mask = m;
                sync(p);
                continue;
            }
            return Fate::Goes;
        };
        let act = p.group.actions.lock().get(sig);
        match act.handler {
            SIG_IGN if sig != SIGKILL => continue,
            SIG_DFL | SIG_IGN => match default_action(sig) {
                DefaultAction::Ignore => continue,
                DefaultAction::Stop => {
                    proc::begin_stop(&p.entry, sig, seen);
                    continue;
                }
                DefaultAction::Core => return Fate::ProcessEnds(sig | 0x80),
                DefaultAction::Terminate => return Fate::ProcessEnds(sig),
            },
            _ => {
                if let Some(r) = restart {
                    if r.handled && act.flags & SA_RESTART != 0 {
                        restart_syscall(ctx, r.nr);
                    } else {
                        ctx.set_return((-EINTR) as u64);
                    }
                }
                p.resume_until = None;
                return match setup_frame(p, ctx, sig, info, Trap::default(), &act) {
                    Ok(()) => Fate::Goes,
                    Err(status) => Fate::ProcessEnds(status),
                };
            }
        }
    }
}

/// A fault the process did not handle: runs its handler if it has one and
/// the signal is not blocked, else kills it. Returns the wait status if
/// the process ends.
pub(crate) fn fault(
    p: &mut LinuxProcess,
    ctx: &mut UserContext,
    sig: u32,
    code: i32,
    addr: u64,
    trap: Trap,
) -> Option<u32> {
    let act = p.group.actions.lock().get(sig);
    let caught = act.handler != SIG_DFL && act.handler != SIG_IGN && p.sig.mask & bit(sig) == 0;
    if !caught {
        return Some(sig | 0x80);
    }
    setup_frame(p, ctx, sig, Info::fault(code, addr), trap, &act).err()
}

/// The CPU exception behind a signal, as its frame shows it.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Trap {
    pub(crate) vector: u64,
    pub(crate) error: u64,
    pub(crate) cr2: u64,
}

// Signal frame layout (x86-64 Linux `struct rt_sigframe`).
const UC_SIZE: u64 = 304; // uc_flags, uc_link, uc_stack, uc_mcontext, uc_sigmask
const MCONTEXT: usize = 40;
/// In `struct sigcontext`, after the registers, flags and segments: err,
/// trapno, oldmask, cr2, then the pointer to the extended state.
const MCONTEXT_ERR: usize = 152;
const MCONTEXT_FPSTATE: usize = 184;
const SIGMASK: usize = MCONTEXT + 256;
const INFO_SIZE: u64 = 128;
const FRAME_SIZE: u64 = 8 + UC_SIZE + INFO_SIZE;
const REDZONE: u64 = 128;
/// `uc_flags`: the frame's `fpstate` is an XSAVE area (sw bytes valid).
const UC_FP_XSTATE: u64 = 1;
/// The frame says what SS was.
const UC_SIGCONTEXT_SS: u64 = 2;
const UC_STRICT_RESTORE_SS: u64 = 4;
/// `struct _fpx_sw_bytes` markers (ADR-0008 §6).
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// Offset of `sw_reserved` in the FXSAVE region.
const SW_BYTES: usize = 464;

/// The `fpstate` the frame carries: the thread's extended state, plus (with
/// XSAVE) the software bytes and the trailing `FP_XSTATE_MAGIC2`.
fn fpstate_image(ctx: &UserContext) -> alloc::vec::Vec<u8> {
    let mut v = ctx.fpu_state().to_vec();
    let xfeatures = frame::cpu::xstate_features();
    if xfeatures != 0 {
        let size = v.len() as u32;
        v[SW_BYTES..SW_BYTES + 4].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
        v[SW_BYTES + 4..SW_BYTES + 8].copy_from_slice(&(size + 4).to_le_bytes());
        v[SW_BYTES + 8..SW_BYTES + 16].copy_from_slice(&xfeatures.to_le_bytes());
        v[SW_BYTES + 16..SW_BYTES + 20].copy_from_slice(&size.to_le_bytes());
        v[SW_BYTES + 20..512].fill(0);
        v.extend_from_slice(&FP_XSTATE_MAGIC2.to_le_bytes());
    } else {
        v[SW_BYTES..512].fill(0);
    }
    v
}

/// The most stack one signal frame takes (`AT_MINSIGSTKSZ`): the frame,
/// the extended state with its magic, and alignment slack.
pub(crate) fn frame_stack_size() -> u64 {
    FRAME_SIZE + frame::cpu::xstate_size() as u64 + 4 + 64 + 16
}

/// The general registers in `struct sigcontext` order (r8..r15, rdi, rsi,
/// rbp, rbx, rdx, rax, rcx, rsp, rip).
fn gregs(ctx: &UserContext) -> [u64; 17] {
    [
        ctx.r8, ctx.r9, ctx.r10, ctx.r11, ctx.r12, ctx.r13, ctx.r14, ctx.r15, ctx.rdi, ctx.rsi,
        ctx.rbp, ctx.rbx, ctx.rdx, ctx.rax, ctx.rcx, ctx.rsp, ctx.rip,
    ]
}

/// Builds the frame for `sig` on the user stack and points `ctx` at the
/// handler. `Err` carries the wait status if the frame cannot be built.
fn setup_frame(
    p: &mut LinuxProcess,
    ctx: &mut UserContext,
    sig: u32,
    info_fields: Info,
    trap: Trap,
    act: &Action,
) -> Result<(), u32> {
    let die = SIGSEGV | 0x80;
    if act.flags & SA_RESTORER == 0 {
        return Err(die); // x86-64 has no kernel-provided trampoline
    }
    // SA_ONSTACK handlers run on the alternate stack, unless already on it.
    let top = match p.sig.alt {
        Some((base, size)) if act.flags & SA_ONSTACK != 0 && !p.sig.on_alt(ctx.rsp) => base + size,
        _ => ctx.rsp.wrapping_sub(REDZONE),
    };
    let fp = fpstate_image(ctx);
    let fpstate = (top.wrapping_sub(fp.len() as u64)) & !63;
    let sp = ((fpstate - FRAME_SIZE + 8) & !15) - 8; // rsp % 16 == 8 at entry
    let uc = sp + 8;
    let info = uc + UC_SIZE;
    let old_mask = p.sig.saved_mask.take().unwrap_or(p.sig.mask);

    let mut f = alloc::vec![0u8; FRAME_SIZE as usize];
    f[0..8].copy_from_slice(&act.restorer.to_le_bytes());
    let u = 8usize;
    let mut uc_flags = UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS;
    if frame::cpu::xstate_features() != 0 {
        uc_flags |= UC_FP_XSTATE;
    }
    f[u..u + 8].copy_from_slice(&uc_flags.to_le_bytes());
    // uc_stack: the alternate stack as it stood when the signal came.
    let (ss_sp, ss_flags, ss_size) = match p.sig.alt {
        None => (0, SS_DISABLE, 0),
        Some((b, s)) => (b, if p.sig.on_alt(ctx.rsp) { SS_ONSTACK } else { 0 }, s),
    };
    f[u + 16..u + 24].copy_from_slice(&ss_sp.to_le_bytes());
    f[u + 24..u + 28].copy_from_slice(&ss_flags.to_le_bytes());
    f[u + 32..u + 40].copy_from_slice(&ss_size.to_le_bytes());
    let m = u + MCONTEXT;
    for (i, r) in gregs(ctx).iter().enumerate() {
        f[m + i * 8..m + i * 8 + 8].copy_from_slice(&r.to_le_bytes());
    }
    f[m + 136..m + 144].copy_from_slice(&ctx.rflags().to_le_bytes());
    let segs: u64 = 0x33 | (0x2b << 48); // cs, gs, fs, ss
    f[m + 144..m + 152].copy_from_slice(&segs.to_le_bytes());
    let words = [trap.error, trap.vector, old_mask, trap.cr2, fpstate];
    for (i, w) in words.iter().enumerate() {
        let at = m + MCONTEXT_ERR + i * 8;
        f[at..at + 8].copy_from_slice(&w.to_le_bytes());
    }
    f[u + SIGMASK..u + SIGMASK + 8].copy_from_slice(&old_mask.to_le_bytes());
    let i = (8 + UC_SIZE) as usize;
    f[i..].copy_from_slice(&info_fields.bytes(sig));

    if p.copy_to_user(fpstate, &fp) != fp.len() || p.copy_to_user(sp, &f) != f.len() {
        return Err(die);
    }
    let mut mask = p.sig.mask | act.mask;
    if act.flags & SA_NODEFER == 0 {
        mask |= bit(sig);
    }
    p.sig.mask = mask & !UNBLOCKABLE;
    if act.flags & SA_RESETHAND != 0 {
        p.group.actions.lock().actions[slot(sig)] = Action::default();
    }
    sync(p);
    ctx.rdi = u64::from(sig);
    ctx.rsi = info;
    ctx.rdx = uc;
    ctx.rax = 0;
    ctx.rsp = sp;
    ctx.rip = act.handler;
    // The handler starts as a function call does: direction flag clear.
    // The frame keeps the interrupted code's flag for `rt_sigreturn`.
    ctx.clear_direction();
    Ok(())
}

/// `rt_sigreturn`: restores the context a handler interrupted from the
/// frame at the stack pointer (the restorer's `ret` popped `pretcode`).
pub(crate) fn sigreturn(p: &mut LinuxProcess, ctx: &mut UserContext) -> Result<(), i64> {
    let uc = ctx.rsp;
    let mut f = [0u8; UC_SIZE as usize];
    if p.copy_from_user(uc, &mut f) != f.len() {
        return Err(EFAULT);
    }
    let word = |off: usize| u64::from_le_bytes(f[off..off + 8].try_into().unwrap_or([0; 8]));
    let m = MCONTEXT;
    let r: [u64; 17] = core::array::from_fn(|i| word(m + i * 8));
    [
        ctx.r8, ctx.r9, ctx.r10, ctx.r11, ctx.r12, ctx.r13, ctx.r14, ctx.r15, ctx.rdi, ctx.rsi,
        ctx.rbp, ctx.rbx, ctx.rdx, ctx.rax, ctx.rcx, ctx.rsp, ctx.rip,
    ] = r;
    ctx.set_rflags(word(m + 136));
    let fpstate = word(m + MCONTEXT_FPSTATE);
    if fpstate != 0 {
        let mut fx = alloc::vec![0u8; 512];
        if p.copy_from_user(fpstate, &mut fx) != fx.len() {
            return Err(EFAULT);
        }
        // The full XSAVE area only if the frame says it holds one, sized as
        // ours, with the trailing magic; otherwise just the legacy region.
        let sw = |o: usize| {
            u32::from_le_bytes(
                fx[SW_BYTES + o..SW_BYTES + o + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        };
        let size = frame::cpu::xstate_size();
        let xsave = frame::cpu::xstate_features() != 0
            && sw(0) == FP_XSTATE_MAGIC1
            && sw(16) as usize == size
            && sw(4) as usize == size + 4;
        if xsave {
            let mut full = alloc::vec![0u8; size + 4];
            if p.copy_from_user(fpstate, &mut full) != full.len() {
                return Err(EFAULT);
            }
            let magic2 = u32::from_le_bytes(full[size..size + 4].try_into().unwrap_or([0; 4]));
            if magic2 == FP_XSTATE_MAGIC2 {
                fx = full;
                fx.truncate(size);
            }
        }
        ctx.set_fpu_state(&fx);
    }
    p.sig.mask = word(SIGMASK) & !UNBLOCKABLE;
    sync(p);
    Ok(())
}

/// `sigaltstack(ss, old_ss)` over `stack_t { void *ss_sp; int ss_flags;
/// size_t ss_size; }`.
pub(crate) fn sigaltstack(
    p: &mut LinuxProcess,
    ctx: &UserContext,
    ss: u64,
    old: u64,
) -> Result<u64, i64> {
    const EPERM: i64 = 1;
    const ENOMEM: i64 = 12;
    let on = p.sig.on_alt(ctx.rsp);
    if old != 0 {
        let mut b = [0u8; 24];
        let (sp, flags, size) = match p.sig.alt {
            None => (0, SS_DISABLE, 0),
            Some((s, z)) => (s, if on { SS_ONSTACK } else { 0 }, z),
        };
        b[0..8].copy_from_slice(&sp.to_le_bytes());
        b[8..12].copy_from_slice(&flags.to_le_bytes());
        b[16..24].copy_from_slice(&size.to_le_bytes());
        if p.copy_to_user(old, &b) != 24 {
            return Err(EFAULT);
        }
    }
    if ss != 0 {
        let mut b = [0u8; 24];
        if p.copy_from_user(ss, &mut b) != 24 {
            return Err(EFAULT);
        }
        if on {
            return Err(EPERM); // cannot change the stack we are running on
        }
        let sp = u64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
        let flags = u32::from_le_bytes(b[8..12].try_into().unwrap_or([0; 4])) & !SS_AUTODISARM;
        let size = u64::from_le_bytes(b[16..24].try_into().unwrap_or([0; 8]));
        match flags {
            SS_DISABLE => p.sig.alt = None,
            0 | SS_ONSTACK => {
                if size < MINSIGSTKSZ {
                    return Err(ENOMEM);
                }
                p.sig.alt = Some((sp, size));
            }
            _ => return Err(EINVAL),
        }
    }
    Ok(0)
}
