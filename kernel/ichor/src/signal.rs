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
//! Partial: no job control (stop signals are ignored), one thread per
//! process, no `sigaltstack`, and `siginfo` carries the signal and code
//! (plus the fault address) but not the sender.

use frame::user::UserContext;

use crate::proc;
use crate::process::LinuxProcess;

pub(crate) const SIGKILL: u32 = 9;
pub(crate) const SIGSEGV: u32 = 11;
pub(crate) const SIGPIPE: u32 = 13;
pub(crate) const SIGCHLD: u32 = 17;
const SIGSTOP: u32 = 19;
pub(crate) const NSIG: u32 = 64;

/// Internal errno: interrupted by a signal, maybe restart (never reaches
/// user space).
pub(crate) const ERESTARTSYS: i64 = 512;
const EINTR: i64 = 4;
const EINVAL: i64 = 22;
const EFAULT: i64 = 14;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
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
}

fn default_action(sig: u32) -> DefaultAction {
    match sig {
        // CHLD, CONT, STOP/TSTP/TTIN/TTOU (no job control yet), URG, WINCH.
        17..=23 | 28 => DefaultAction::Ignore,
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

impl Actions {
    pub(crate) fn new() -> Actions {
        Actions {
            actions: [Action::default(); NSIG as usize],
        }
    }

    fn get(&self, sig: u32) -> Action {
        self.actions[(sig - 1) as usize]
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
    let ignored = p.group.actions.lock().ignored();
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
            acts.actions[(sig - 1) as usize] = Action {
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
    Err(EINTR)
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

/// Ends a wait's temporary mask. After `EINTR` it stays until the handler
/// is set up (which saves the original mask in its frame), as on Linux;
/// otherwise the original comes back now.
pub(crate) fn end_wait_mask(p: &mut LinuxProcess, r: &Result<u64, i64>) {
    if *r == Err(EINTR) {
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
    Err(EINTR)
}

/// `nanosleep` / `clock_nanosleep` (relative): sleeps on a frame timed
/// wait; a signal the process would act on ends it early with `EINTR` and
/// the time left in `rem`.
pub(crate) fn nanosleep(p: &mut LinuxProcess, req: u64, rem: u64) -> Result<u64, i64> {
    let sec = read_u64(p, req)?;
    let nsec = read_u64(p, req + 8)?;
    if nsec >= 1_000_000_000 || sec > i64::MAX as u64 {
        return Err(EINVAL);
    }
    let deadline = frame::time::now()
        .saturating_add(core::time::Duration::from_secs(sec))
        .saturating_add(core::time::Duration::from_nanos(nsec));
    if !proc::sleep_until(&p.entry, deadline) {
        return Ok(0);
    }
    if rem != 0 {
        let left = deadline.saturating_sub(frame::time::now());
        write_u64(p, rem, left.as_secs())?;
        write_u64(p, rem + 8, u64::from(left.subsec_nanos()))?;
    }
    Err(EINTR)
}

/// `kill`: process-directed (any thread of the target may take it). `pid`
/// 0 is the caller's process group, `-pgid` another group, -1 every other
/// process in the cell. Never crosses the cell.
pub(crate) fn kill(p: &mut LinuxProcess, pid: i64, sig: u64) -> Result<u64, i64> {
    let sig = u32::try_from(sig)
        .ok()
        .filter(|&s| s <= NSIG)
        .ok_or(EINVAL)?;
    const EPERM: i64 = 1;
    let me = p.group.leader.clone();
    let creds = p.group.creds();
    let allowed = |target: (u32, u32)| creds.may_signal(target);
    match pid {
        pid if pid > 0 => {
            if !allowed(proc::uids_of(me.cell, pid as u64)?) {
                return Err(EPERM);
            }
            proc::send(me.cell, pid as u64, sig)?
        }
        0 => proc::send_group(&me, Some(me.group().0), sig, &allowed)?,
        -1 => proc::send_group(&me, None, sig, &allowed)?,
        g => proc::send_group(&me, Some(g.unsigned_abs()), sig, &allowed)?,
    }
    Ok(0)
}

/// `tkill` / `tgkill`: thread-directed.
pub(crate) fn tkill(p: &LinuxProcess, tgid: Option<u64>, tid: u64, sig: u64) -> Result<u64, i64> {
    let sig = u32::try_from(sig)
        .ok()
        .filter(|&s| s <= NSIG)
        .ok_or(EINVAL)?;
    proc::send_thread(p.entry.cell, tgid, tid, sig)?;
    Ok(0)
}

fn restart_syscall(ctx: &mut UserContext, nr: u64) {
    ctx.rax = nr;
    ctx.rip -= 2; // back over `syscall`
}

/// Delivers pending, unblocked signals after a syscall (whose number is
/// `restart` if it returned `ERESTARTSYS`) or fault. Returns the wait
/// status if a signal ends the process.
pub(crate) fn deliver(
    p: &mut LinuxProcess,
    ctx: &mut UserContext,
    restart: Option<u64>,
) -> Option<u32> {
    loop {
        let deliverable = proc::pending(&p.entry) & !p.sig.mask;
        if deliverable == 0 {
            // A wait's temporary mask (sigsuspend, ppoll, ...) ends here if
            // no handler took it over; the restored mask may let more in.
            if let Some(m) = p.sig.saved_mask.take() {
                p.sig.mask = m;
                sync(p);
                continue;
            }
            if let Some(nr) = restart {
                restart_syscall(ctx, nr);
            }
            return None;
        }
        let sig = deliverable.trailing_zeros() + 1;
        proc::clear_pending(&p.entry, bit(sig));
        let act = p.group.actions.lock().get(sig);
        match act.handler {
            SIG_IGN if sig != SIGKILL => continue,
            SIG_DFL | SIG_IGN => match default_action(sig) {
                DefaultAction::Ignore if sig != SIGKILL => continue,
                DefaultAction::Core => return Some(sig | 0x80),
                _ => return Some(sig),
            },
            _ => {
                if let Some(nr) = restart {
                    if act.flags & SA_RESTART != 0 {
                        restart_syscall(ctx, nr);
                    } else {
                        ctx.set_return((-EINTR) as u64);
                    }
                }
                return setup_frame(p, ctx, sig, 0, 0, &act).err();
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
    addr: u64,
) -> Option<u32> {
    let act = p.group.actions.lock().get(sig);
    let caught = act.handler != SIG_DFL && act.handler != SIG_IGN && p.sig.mask & bit(sig) == 0;
    if !caught {
        return Some(sig | 0x80);
    }
    const SEGV_MAPERR: u32 = 1;
    setup_frame(p, ctx, sig, SEGV_MAPERR, addr, &act).err()
}

// Signal frame layout (x86-64 Linux `struct rt_sigframe`).
const UC_SIZE: u64 = 304; // uc_flags, uc_link, uc_stack, uc_mcontext, uc_sigmask
const MCONTEXT: usize = 40;
const SIGMASK: usize = MCONTEXT + 256;
const INFO_SIZE: u64 = 128;
const FRAME_SIZE: u64 = 8 + UC_SIZE + INFO_SIZE;
const REDZONE: u64 = 128;
/// `uc_flags`: the frame's `fpstate` is an XSAVE area (sw bytes valid).
const UC_FP_XSTATE: u64 = 1;
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
    code: u32,
    addr: u64,
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
    if frame::cpu::xstate_features() != 0 {
        f[u..u + 8].copy_from_slice(&UC_FP_XSTATE.to_le_bytes());
    }
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
    f[m + 176..m + 184].copy_from_slice(&old_mask.to_le_bytes()); // oldmask
    f[m + 184..m + 192].copy_from_slice(&addr.to_le_bytes()); // cr2
    f[m + 192..m + 200].copy_from_slice(&fpstate.to_le_bytes());
    f[u + SIGMASK..u + SIGMASK + 8].copy_from_slice(&old_mask.to_le_bytes());
    let i = (8 + UC_SIZE) as usize;
    f[i..i + 4].copy_from_slice(&sig.to_le_bytes()); // si_signo
    f[i + 8..i + 12].copy_from_slice(&code.to_le_bytes()); // si_code
    f[i + 16..i + 24].copy_from_slice(&addr.to_le_bytes()); // si_addr

    if p.copy_to_user(fpstate, &fp) != fp.len() || p.copy_to_user(sp, &f) != f.len() {
        return Err(die);
    }
    let mut mask = p.sig.mask | act.mask;
    if act.flags & SA_NODEFER == 0 {
        mask |= bit(sig);
    }
    p.sig.mask = mask & !UNBLOCKABLE;
    if act.flags & SA_RESETHAND != 0 {
        p.group.actions.lock().actions[(sig - 1) as usize] = Action::default();
    }
    sync(p);
    ctx.rdi = u64::from(sig);
    ctx.rsi = info;
    ctx.rdx = uc;
    ctx.rax = 0;
    ctx.rsp = sp;
    ctx.rip = act.handler;
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
    let fpstate = word(m + 192);
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
