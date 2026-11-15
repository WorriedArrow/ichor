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
const NSIG: u32 = 64;

/// Internal errno: interrupted by a signal, maybe restart (never reaches
/// user space).
pub(crate) const ERESTARTSYS: i64 = 512;
const EINTR: i64 = 4;
const EINVAL: i64 = 22;
const EFAULT: i64 = 14;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SA_RESTORER: u64 = 0x0400_0000;
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

/// A process's dispositions and mask.
#[derive(Clone, Debug)]
pub(crate) struct Signals {
    actions: [Action; NSIG as usize],
    pub(crate) mask: u64,
    /// The mask to restore after `rt_sigsuspend`'s handler.
    saved_mask: Option<u64>,
}

impl Signals {
    pub(crate) fn new() -> Signals {
        Signals {
            actions: [Action::default(); NSIG as usize],
            mask: 0,
            saved_mask: None,
        }
    }

    /// `execve`: caught signals revert to the default; ignored ones stay
    /// ignored, and the mask is kept.
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
            let a = self.actions[(sig - 1) as usize];
            let ignore = a.handler == SIG_IGN
                || (a.handler == SIG_DFL && matches!(default_action(sig), DefaultAction::Ignore));
            if ignore {
                set |= bit(sig);
            }
        }
        set & !UNBLOCKABLE
    }
}

/// Publishes `p`'s mask and ignored set to its table entry, which senders
/// and interruptible waits consult.
pub(crate) fn sync(p: &LinuxProcess) {
    proc::set_masks(&p.entry, p.sig.mask, p.sig.ignored());
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
    let old = p.sig.actions[(sig - 1) as usize];
    if act != 0 {
        if sig == SIGKILL || sig == SIGSTOP {
            return Err(EINVAL);
        }
        let mut b = [0u8; 32];
        if p.copy_from_user(act, &mut b) != 32 {
            return Err(EFAULT);
        }
        let word = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
        p.sig.actions[(sig - 1) as usize] = Action {
            handler: word(0),
            flags: word(1),
            restorer: word(2),
            mask: word(3) & !UNBLOCKABLE,
        };
        sync(p);
        // Setting SIG_IGN discards a pending instance.
        if p.sig.ignored() & bit(sig) != 0 {
            proc::clear_pending(&p.entry, bit(sig));
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

/// `kill` (and `tkill`/`tgkill`, threads being processes for now).
pub(crate) fn kill(p: &mut LinuxProcess, pid: i64, sig: u64) -> Result<u64, i64> {
    const EPERM: i64 = 1;
    let sig = u32::try_from(sig)
        .ok()
        .filter(|&s| s <= NSIG)
        .ok_or(EINVAL)?;
    if pid <= 0 {
        // Process groups and "every process" need sessions (job control).
        return Err(EPERM);
    }
    let _ = p;
    proc::send(pid as u64, sig)?;
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
            if let Some(nr) = restart {
                restart_syscall(ctx, nr);
            }
            return None;
        }
        let sig = deliverable.trailing_zeros() + 1;
        proc::clear_pending(&p.entry, bit(sig));
        let act = p.sig.actions[(sig - 1) as usize];
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
    let act = p.sig.actions[(sig - 1) as usize];
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
    let fpstate = (ctx.rsp.wrapping_sub(REDZONE).wrapping_sub(512)) & !63;
    let sp = ((fpstate - FRAME_SIZE + 8) & !15) - 8; // rsp % 16 == 8 at entry
    let uc = sp + 8;
    let info = uc + UC_SIZE;
    let old_mask = p.sig.saved_mask.take().unwrap_or(p.sig.mask);

    let mut f = alloc::vec![0u8; FRAME_SIZE as usize];
    f[0..8].copy_from_slice(&act.restorer.to_le_bytes());
    let u = 8usize;
    // uc_stack: ss_sp = 0, ss_flags = SS_DISABLE, ss_size = 0.
    f[u + 24..u + 28].copy_from_slice(&2u32.to_le_bytes());
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

    if p.copy_to_user(fpstate, &ctx.fpu_state()) != 512 || p.copy_to_user(sp, &f) != f.len() {
        return Err(die);
    }
    let mut mask = p.sig.mask | act.mask;
    if act.flags & SA_NODEFER == 0 {
        mask |= bit(sig);
    }
    p.sig.mask = mask & !UNBLOCKABLE;
    if act.flags & SA_RESETHAND != 0 {
        p.sig.actions[(sig - 1) as usize] = Action::default();
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
        let mut fx = [0u8; 512];
        if p.copy_from_user(fpstate, &mut fx) != fx.len() {
            return Err(EFAULT);
        }
        ctx.set_fpu_state(&fx);
    }
    p.sig.mask = word(SIGMASK) & !UNBLOCKABLE;
    sync(p);
    Ok(())
}
