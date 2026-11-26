//! Entering and leaving ring 3.
//!
//! A user thread runs through `iretq`, or `sysretq` where its context is
//! what a `syscall` leaves (`rcx` its RIP, `r11` its RFLAGS), and traps back
//! into the kernel by a
//! `syscall` instruction, by a CPU exception, or by an interrupt. On the way
//! back the user registers are saved into the thread's [`UserContext`], and
//! control returns to the kernel stack frame that called
//! [`UserMode::execute`]. Every way back into ring 3 goes through `execute`
//! and `ichor_enter_user` (the entry code is in `entry.rs`), interrupts
//! included: one that needs no reschedule just loops in `execute`.
//!
//! **GS stays pointed at the per-CPU block even in ring 3** (there is no
//! `swapgs`), which sidesteps the NMI-in-`swapgs` window (asterinas#3904).
//! Per-thread TLS uses the FS base, which covers static glibc and musl
//! binaries. The cost is that ring 3 can read the kernel's per-CPU block
//! base through `%gs`; that leaks no writable kernel state and is noted as a
//! hardening item for the side-channel ADR.
//!
//! The kernel never trusts the user's RFLAGS or segment selectors: entry
//! loads the kernel's, and [`UserContext`] only exposes a safe RFLAGS subset.

use core::sync::atomic::{AtomicBool, AtomicU64};

use super::regs::{self, rdmsr, wrmsr};
use super::trap::{self, KERNEL_CS};
use crate::cpu;

const USER_CS: u16 = 0x23; // GDT 0x20 (user code) | RPL 3

/// `IA32_PRED_CMD`: writing bit 0 is an indirect branch prediction barrier.
const MSR_PRED_CMD: u32 = 0x49;

/// Side-channel mitigations on the way to ring 3 (ADR-0004 §2), chosen at
/// boot from the CPU's enumerated vulnerabilities.
/// VERW before `iretq` (MDS/TAA, with MD_CLEAR microcode); copied into each
/// CPU's block, which the entry code tests.
static VERW_ON: AtomicBool = AtomicBool::new(false);
/// IBPB when this CPU starts running user code of another domain (cell).
static IBPB_ON: AtomicBool = AtomicBool::new(false);
/// IBPBs issued (all CPUs).
static IBPBS: AtomicU64 = AtomicU64::new(0);

crate::cpu_local! {
    /// What this CPU's FS base MSR holds (`u64::MAX`: not known). Only
    /// `execute` writes the MSR, and ring 3 cannot (CR4.FSGSBASE is off).
    static FS_BASE: AtomicU64 = AtomicU64::new(u64::MAX);
}

/// `IA32_SPEC_CTRL`, and the bits Ichor sets in it.
const MSR_SPEC_CTRL: u32 = 0x48;
const SPEC_CTRL_IBRS: u64 = 1;
const SPEC_CTRL_BHI_DIS_S: u64 = 1 << 10;
/// What every CPU writes to `IA32_SPEC_CTRL` as it comes up (0: nothing;
/// ADR-0004 §2: Spectre v2 and BHI in the kernel). With enhanced IBRS that
/// is left on; without, it counts only for the mode it was written in, so
/// the entry code writes it on every entry from ring 3.
static SPEC_CTRL: AtomicU64 = AtomicU64::new(0);
static IBRS_ON_ENTRY: AtomicBool = AtomicBool::new(false);
/// AMD's automatic IBRS (EFER.AIBRSE), set on every CPU.
static AUTO_IBRS: AtomicBool = AtomicBool::new(false);
const EFER_AIBRSE: u64 = 1 << 21;
/// The branch history cleared, and IBPB, on every entry from ring 3.
static BHB_CLEAR: AtomicBool = AtomicBool::new(false);
static IBPB_ENTRY: AtomicBool = AtomicBool::new(false);

/// What the boot CPU's vulnerabilities call for, switched on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mitigations {
    /// VERW on every return to ring 3.
    pub verw: bool,
    /// MDS or TAA applies but the microcode lacks MD_CLEAR: VERW would not
    /// clear the buffers, so cells are not separated (an operator must
    /// update microcode).
    pub verw_missing: bool,
    /// IBPB between user code of different cells.
    pub ibpb: bool,
    /// Page-table isolation (Meltdown), and whether it uses PCID.
    pub pti: bool,
    pub pcid: bool,
    /// Enhanced IBRS on (Spectre v2 in the kernel), and BHI_DIS_S with it.
    pub eibrs: bool,
    pub bhi_dis_s: bool,
    /// AMD's automatic IBRS on, in place of IBRS on entry.
    pub auto_ibrs: bool,
    /// The branch history cleared on every entry from ring 3.
    pub bhb_clear: bool,
    /// IBPB on every entry from ring 3 (Retbleed, SRSO), and whether it is
    /// needed but impossible (no IBPB) or incomplete (SRSO without
    /// IBPB_BRTYPE microcode).
    pub ibpb_entry: bool,
    pub ibpb_entry_missing: bool,
    pub srso_incomplete: bool,
    /// Safe-RET return thunks in place of IBPB on entry, or why they could
    /// not be installed.
    pub safe_ret: Option<super::rethunk::SafeRet>,
    pub safe_ret_failed: Option<&'static str>,
}

/// Mitigations a test may force on any CPU.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Forced {
    /// VERW on every return to ring 3 (it clears buffers only with MD_CLEAR
    /// microcode).
    pub verw: bool,
    pub pti: bool,
    /// The branch-history clearing sequence on every entry from ring 3.
    pub bhb: bool,
    /// IBPB on every entry from ring 3 (where IBPB exists).
    pub ibpb_entry: bool,
    /// The Zen 3/4 safe-RET return thunks.
    pub safe_ret: bool,
    /// IBPB on entry instead of safe RET where the CPU needs one (`srso=ibpb`).
    pub ibpb_not_safe_ret: bool,
}

/// Switches on the mitigations `v` calls for (once, on the boot CPU,
/// before any user code runs; all CPUs are assumed alike), and those
/// `forced` (tests: they run on any CPU).
pub(crate) fn enable_mitigations(
    v: &super::cpu::Vulnerabilities,
    forced: Forced,
) -> Result<Mitigations, &'static str> {
    use core::sync::atomic::Ordering::Relaxed;
    let needs_verw = v.mds || v.taa;
    let verw = (needs_verw && v.md_clear) || forced.verw;
    VERW_ON.store(verw, Relaxed);
    IBPB_ON.store(v.pred_cmd, Relaxed);
    let pti = v.meltdown || forced.pti;
    if pti {
        super::entry::enable()?;
    }
    // Enhanced IBRS: set once per CPU and left on, it keeps user-trained
    // branch predictions out of the kernel's indirect branches; BHI_DIS_S
    // does the same for branch history. Written only where enumerated
    // (`IA32_SPEC_CTRL` needs IBRS enumerated: Intel's CPUID.7:EDX[26] or
    // AMD's CPUID 8000_0008h EBX[14]; a reserved bit would fault). AMD's
    // automatic IBRS does the same through EFER. Without either, IBRS is
    // written on every entry from ring 3, on Intel and AMD alike.
    let eibrs = v.eibrs && v.ibrs;
    let auto_ibrs = v.auto_ibrs && !eibrs;
    let bhi_dis_s = eibrs && v.bhi_ctrl;
    let spec = if v.ibrs && !auto_ibrs {
        SPEC_CTRL_IBRS
    } else {
        0
    } | if bhi_dis_s { SPEC_CTRL_BHI_DIS_S } else { 0 };
    SPEC_CTRL.store(spec, Relaxed);
    IBRS_ON_ENTRY.store(v.ibrs && !eibrs && !auto_ibrs, Relaxed);
    AUTO_IBRS.store(auto_ibrs, Relaxed);
    // Branch history without BHI_DIS_S: cleared in software on entry.
    let bhb_clear = (v.bhi && !bhi_dis_s) || forced.bhb;
    BHB_CLEAR.store(bhb_clear, Relaxed);
    // AMD's return-prediction issues: safe-RET return thunks (`rethunk`)
    // where there is a sequence for the CPU, else IBPB on every entry.
    let wanted = match (forced.safe_ret, forced.ibpb_not_safe_ret) {
        (true, _) => Some(super::rethunk::SafeRet::Alias),
        (false, true) => None,
        (false, false) => v.safe_ret,
    };
    let (safe_ret, safe_ret_failed) = match wanted.map(super::rethunk::install) {
        Some(Ok(())) => (wanted, None),
        Some(Err(e)) => (None, Some(e)),
        None => (None, None),
    };
    let ibpb_needed = (v.retbleed || v.srso) && safe_ret.is_none();
    let ibpb_entry = (ibpb_needed || forced.ibpb_entry) && v.pred_cmd;
    IBPB_ENTRY.store(ibpb_entry, Relaxed);
    enable_cpu_mitigations();
    Ok(Mitigations {
        verw,
        verw_missing: needs_verw && !v.md_clear,
        ibpb: v.pred_cmd,
        pti,
        pcid: pti && super::entry::pcid(),
        eibrs,
        bhi_dis_s,
        auto_ibrs,
        bhb_clear,
        ibpb_entry,
        ibpb_entry_missing: ibpb_needed && !v.pred_cmd,
        srso_incomplete: v.srso && !v.ibpb_brtype,
        safe_ret,
        safe_ret_failed,
    })
}

/// Copies the mitigation switches into this CPU's block (the entry code
/// reads them there) and turns isolation on here if it is on.
pub(crate) fn enable_cpu_mitigations() {
    use core::sync::atomic::Ordering::Relaxed;
    let block = cpu::this_block();
    block.verw.store(u64::from(VERW_ON.load(Relaxed)), Relaxed);
    block
        .bhb_clear
        .store(u64::from(BHB_CLEAR.load(Relaxed)), Relaxed);
    block
        .ibpb_entry
        .store(u64::from(IBPB_ENTRY.load(Relaxed)), Relaxed);
    block
        .untrain
        .store(super::rethunk::UNTRAIN.load(Relaxed), Relaxed);
    block
        .rethunk
        .store(super::rethunk::RETHUNK.load(Relaxed), Relaxed);
    if AUTO_IBRS.load(Relaxed) {
        // SAFETY: EFER exists on every x86_64 CPU, and AIBRSE only where
        // CPUID 8000_0021h:EAX[8] enumerates it (on the boot CPU; all CPUs
        // are assumed alike). It only restricts speculation.
        let efer = unsafe { rdmsr(regs::MSR_EFER) };
        // SAFETY: as above; no other EFER bit changes.
        unsafe { wrmsr(regs::MSR_EFER, efer | EFER_AIBRSE) };
    }
    super::entry::enable_cpu(block);
    let spec = SPEC_CTRL.load(Relaxed);
    if spec != 0 {
        // SAFETY: `spec` is nonzero only when CPUID enumerates
        // IA32_SPEC_CTRL (on the boot CPU; all CPUs are assumed alike).
        // Reading it has no side effects.
        let firmware = unsafe { rdmsr(MSR_SPEC_CTRL) };
        // SAFETY: the MSR exists, as above, and so does every bit set:
        // those firmware set, IBRS (with the MSR) and BHI_DIS_S (only with
        // its own CPUID bit). They only restrict speculation on this CPU.
        unsafe { wrmsr(MSR_SPEC_CTRL, firmware | spec) };
        if IBRS_ON_ENTRY.load(Relaxed) {
            block.spec_ctrl.store(firmware | spec, Relaxed);
        }
    }
}

/// Whether the kernel runs with IBRS on this CPU, if it is to.
pub fn ibrs_in_kernel() -> Option<bool> {
    if SPEC_CTRL.load(core::sync::atomic::Ordering::Relaxed) == 0 {
        return None;
    }
    // SAFETY: the MSR exists (as in `enable_cpu_mitigations`); reading it
    // has no side effects.
    Some(unsafe { rdmsr(MSR_SPEC_CTRL) } & SPEC_CTRL_IBRS != 0)
}

/// How many IBPBs cross-cell switches have issued since boot.
pub fn ibpb_count() -> u64 {
    IBPBS.load(core::sync::atomic::Ordering::Relaxed)
}

const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_FMASK: u32 = 0xC000_0084;
const EFER_SCE: u64 = 1; // syscall enable

// RFLAGS bits the user may hold; everything else is forced safe (IF set,
// IOPL 0, no TF/AC). Reserved bit 1 is always set. DF is the user's: a
// backward `rep movs` (memmove) interrupted by a fault, a preemption or
// any interrupt must resume backward, or it copies the rest forward over
// the bytes past its buffer. The kernel never runs with it: `syscall`
// clears it (FMASK) and the trap tail clears every flag (`entry.rs`).
const USER_RFLAGS_ALLOWED: u64 = 0x0000_0cd5; // CF PF AF ZF SF DF OF
const RFLAGS_DF: u64 = 1 << 10;
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_RESERVED1: u64 = 1 << 1;

/// A user thread's saved register state. The field order matches the offsets
/// the entry stubs use (`UC_*` in `entry.rs`).
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct UserContext {
    pub rax: u64,     // 0
    pub rbx: u64,     // 8
    pub rcx: u64,     // 16
    pub rdx: u64,     // 24
    pub rsi: u64,     // 32
    pub rdi: u64,     // 40
    pub rbp: u64,     // 48
    pub rsp: u64,     // 56
    pub r8: u64,      // 64
    pub r9: u64,      // 72
    pub r10: u64,     // 80
    pub r11: u64,     // 88
    pub r12: u64,     // 96
    pub r13: u64,     // 104
    pub r14: u64,     // 112
    pub r15: u64,     // 120
    pub rip: u64,     // 128
    rflags: u64,      // 136
    pub fs_base: u64, // 144
    pub gs_base: u64, // 152
    /// x87/SSE/AVX state (ADR-0008), saved and restored around ring 3.
    fpu: super::xstate::ExtState, // 160 (a pointer; the stubs never touch it)
}

impl UserContext {
    /// A context that will start at `rip` with stack `rsp`.
    pub fn new(rip: u64, rsp: u64) -> Self {
        Self {
            rip,
            rsp,
            rflags: RFLAGS_IF | RFLAGS_RESERVED1,
            ..Self::default()
        }
    }

    /// The syscall number (`rax`) and six arguments, by the Linux
    /// convention (`rdi, rsi, rdx, r10, r8, r9`).
    pub fn syscall_args(&self) -> (u64, [u64; 6]) {
        (
            self.rax,
            [self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9],
        )
    }

    /// Sets the syscall return value.
    pub fn set_return(&mut self, value: u64) {
        self.rax = value;
    }

    /// The user-visible flags (as a signal frame saves them).
    pub fn rflags(&self) -> u64 {
        self.rflags & USER_RFLAGS_ALLOWED
    }

    /// Sets the user-modifiable flags (`rt_sigreturn`); privileged bits
    /// (IOPL, IF, ...) are not taken from `value`.
    pub fn set_rflags(&mut self, value: u64) {
        self.rflags = (value & USER_RFLAGS_ALLOWED) | RFLAGS_IF | RFLAGS_RESERVED1;
    }

    /// Whether the direction flag is set (string instructions run down).
    pub fn direction_down(&self) -> bool {
        self.rflags & RFLAGS_DF != 0
    }

    /// Clears the direction flag, as the ABI requires on entry to a
    /// function the kernel calls (a signal handler).
    pub fn clear_direction(&mut self) {
        self.rflags &= !RFLAGS_DF;
    }

    /// The extended register state as a signal frame saves it: the
    /// standard-format XSAVE area ([`crate::cpu::xstate_size`] bytes), or a
    /// 512-byte FXSAVE image on CPUs without XSAVE.
    pub fn fpu_state(&self) -> &[u8] {
        self.fpu.bytes()
    }

    /// Replaces the extended state (`rt_sigreturn`) from a full area or
    /// just the 512-byte legacy region (the other components then return
    /// to their init state). Bits the restore would fault on (reserved
    /// MXCSR bits, unknown or compacted XSAVE header bits) are cleared.
    pub fn set_fpu_state(&mut self, state: &[u8]) {
        self.fpu.set_from(state);
    }
}

/// Why [`UserMode::execute`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserEvent {
    /// A `syscall` instruction.
    Syscall,
    /// A CPU exception while in ring 3.
    Exception { vector: u8, error: u64, cr2: u64 },
    /// The thread's timeslice ran out while it was in ring 3. The caller
    /// should yield (`task::yield_now`) and then execute again.
    Preempted,
}

/// Enables `syscall` on this CPU, entering at the syscall entry's alias in
/// the entry area. Call during per-CPU init, after the GDT/TSS and the
/// entry area exist.
pub(crate) fn init_cpu() {
    let star = (u64::from(KERNEL_CS) << 32) | (u64::from(USER_CS - 16) << 48);
    let lstar = super::entry::syscall_entry();
    // SAFETY: STAR/LSTAR/FMASK/EFER are the architectural syscall MSRs.
    // LSTAR is our entry stub (its alias, mapped in every root); FMASK
    // clears IF/DF/TF/AC on entry; EFER.SCE enables the instruction.
    // KERNEL_CS matches the GDT in `trap`.
    unsafe { wrmsr(MSR_STAR, star) };
    // SAFETY: as above.
    unsafe { wrmsr(MSR_LSTAR, lstar) };
    // SAFETY: as above.
    unsafe { wrmsr(MSR_FMASK, RFLAGS_IF | (1 << 8) | (1 << 10) | (1 << 18)) };
    // SAFETY: as above; only sets EFER.SCE.
    let efer = unsafe { rdmsr(regs::MSR_EFER) };
    // SAFETY: as above.
    unsafe { wrmsr(regs::MSR_EFER, efer | EFER_SCE) };
}

/// Runs a user thread until it traps back into the kernel.
#[derive(Debug)]
pub struct UserMode<'a> {
    ctx: &'a mut UserContext,
}

impl<'a> UserMode<'a> {
    /// Prepares to run `ctx`.
    pub fn new(ctx: &'a mut UserContext) -> Self {
        Self { ctx }
    }

    /// Enters ring 3 and returns when the thread traps, updating the context
    /// with the user's registers.
    pub fn execute(&mut self) -> UserEvent {
        self.execute_unless(|| false)
    }

    /// [`Self::execute`], unless `hold` says not to enter: then
    /// [`UserEvent::Preempted`] at once. It is asked with interrupts off, so
    /// what becomes true later, announced with
    /// [`Task::interrupt`](crate::task::Task::interrupt), ends the run.
    pub fn execute_unless(&mut self, hold: impl FnOnce() -> bool) -> UserEvent {
        use core::sync::atomic::Ordering::Relaxed;
        // Never enter ring 3 with state `iretq` or `wrmsr` would fault on in
        // the kernel: RIP and RSP must be user addresses, and so must the FS
        // base. Report such a context as a #GP from the thread instead.
        let user = |a: u64| a < super::paging::USER_END;
        if !user(self.ctx.rip) || !user(self.ctx.rsp) || !user(self.ctx.fs_base) {
            return UserEvent::Exception {
                vector: 13,
                error: 0,
                cr2: 0,
            };
        }
        let guard = cpu::IrqGuard::new();
        if hold() {
            return UserEvent::Preempted;
        }
        let block = cpu::this_block();
        self.ctx.rflags = (self.ctx.rflags & USER_RFLAGS_ALLOWED) | RFLAGS_IF | RFLAGS_RESERVED1;
        block
            .user_ctx
            .store(core::ptr::from_mut(self.ctx) as u64, Relaxed);
        block.event_kind.store(0, Relaxed);
        // Per-thread FS/GS bases. GS base here is the thread's own, loaded
        // only while in ring 3 would require swapgs; instead we keep the
        // kernel block in GS and let the thread use FS for TLS. We still
        // honour an explicit gs_base request via the MSR for the rare user
        // of GS-relative TLS, restoring the block afterwards on return.
        let fs = FS_BASE.get(&guard);
        if fs.load(Relaxed) != self.ctx.fs_base {
            // SAFETY: FS base holds a user TLS pointer; it never affects
            // kernel memory safety.
            unsafe { wrmsr(regs::MSR_FS_BASE, self.ctx.fs_base) };
            fs.store(self.ctx.fs_base, Relaxed);
        }
        // A predictor barrier when this CPU last ran another cell's user
        // code (ADR-0004 §2), so its training cannot steer this one's.
        if IBPB_ON.load(Relaxed) {
            let domain = block.task_domain.load(Relaxed);
            if block.user_domain.swap(domain, Relaxed) != domain {
                // SAFETY: IA32_PRED_CMD exists: IBPB_ON is set only when
                // CPUID enumerates IBPB (`pred_cmd`). Writing bit 0 issues the
                // barrier and has no other effect.
                unsafe { wrmsr(MSR_PRED_CMD, 1) };
                IBPBS.fetch_add(1, Relaxed);
            }
        }
        // Interrupts stay off from here until the save below, and the kernel
        // never uses the FPU, so the registers hold only this thread's state.
        self.ctx.fpu.restore(&guard);
        loop {
            // `sysretq` loads RIP from rcx and RFLAGS from r11: where they
            // already hold them, it returns as `iretq` would (CS and SS
            // from STAR are the same selectors; RIP is below USER_END, so
            // canonical, and the sanitized RFLAGS hold no TF or RF).
            let sysret = self.ctx.rcx == self.ctx.rip && self.ctx.r11 == self.ctx.rflags;
            // SAFETY: entry returns to ring 3 from `ctx` (an `iretq` frame,
            // or `sysretq` as above) and comes back here when the thread
            // traps (the stubs load this kernel stack back). The guard
            // keeps us on this CPU across the round trip.
            unsafe {
                ichor_enter_user(
                    core::ptr::from_mut(self.ctx).cast::<u8>(),
                    u64::from(sysret),
                )
            };
            // An interrupt the thread need not hear about: straight back.
            // The trap recorded the registers ring 3 really had, apart from
            // flags it may not keep.
            if block.event_kind.load(Relaxed) != 4 {
                break;
            }
            self.ctx.rflags =
                (self.ctx.rflags & USER_RFLAGS_ALLOWED) | RFLAGS_IF | RFLAGS_RESERVED1;
        }
        self.ctx.fpu.save(&guard);
        let info = block.event_info.load(Relaxed);
        match block.event_kind.load(Relaxed) {
            1 => UserEvent::Syscall,
            3 => UserEvent::Preempted,
            _ => UserEvent::Exception {
                vector: info as u8,
                error: info >> 8,
                cr2: block.event_cr2.load(Relaxed),
            },
        }
    }
}

unsafe extern "sysv64" {
    /// Takes a `*mut UserContext` (the stubs in `entry.rs` only touch its
    /// register fields, at the offsets above) and whether to leave by
    /// `sysretq` (nonzero) rather than `iretq`.
    fn ichor_enter_user(ctx: *mut u8, sysret: u64);
}

/// Records a ring-3 exception into the per-CPU `UserContext` and event
/// slots. Called from the trap path when a trap came from ring 3; the
/// assembler tail then longjmps back into [`UserMode::execute`].
pub(super) fn record_user_trap(frame: &trap::TrapFrame) {
    use core::sync::atomic::Ordering::Relaxed;
    let block = cpu::this_block();
    let ctx_ptr = block.user_ctx.load(Relaxed) as *mut UserContext;
    if ctx_ptr.is_null() {
        return;
    }
    // SAFETY: `ctx_ptr` is the `&mut UserContext` passed to `execute`, which
    // is still borrowed for the duration of the user run (the `UserMode`
    // holds it and `execute` has not returned). Only this CPU writes it.
    let ctx = unsafe { &mut *ctx_ptr };
    ctx.rax = frame.rax;
    ctx.rbx = frame.rbx;
    ctx.rcx = frame.rcx;
    ctx.rdx = frame.rdx;
    ctx.rsi = frame.rsi;
    ctx.rdi = frame.rdi;
    ctx.rbp = frame.rbp;
    ctx.rsp = frame.rsp;
    ctx.r8 = frame.r8;
    ctx.r9 = frame.r9;
    ctx.r10 = frame.r10;
    ctx.r11 = frame.r11;
    ctx.r12 = frame.r12;
    ctx.r13 = frame.r13;
    ctx.r14 = frame.r14;
    ctx.r15 = frame.r15;
    ctx.rip = frame.rip;
    ctx.rflags = frame.rflags;
    let cr2 = regs::read_cr2();
    block.event_info.store(
        (frame.error_code << 8) | u64::from(frame.vector as u8),
        Relaxed,
    );
    block.event_cr2.store(cr2, Relaxed);
    block.event_kind.store(2, Relaxed);
}

/// Records the registers of ring-3 code interrupted when this CPU should
/// reschedule, ending the user run with [`UserEvent::Preempted`].
pub(super) fn record_user_preempt(frame: &trap::TrapFrame) {
    use core::sync::atomic::Ordering::Relaxed;
    record_user_trap(frame);
    cpu::this_block().event_kind.store(3, Relaxed);
}

/// Records the registers of ring-3 code interrupted by an NMI or an
/// interrupt that needs nothing more; [`UserMode::execute`] resumes it.
pub(super) fn record_user_interrupt(frame: &trap::TrapFrame) {
    use core::sync::atomic::Ordering::Relaxed;
    record_user_trap(frame);
    cpu::this_block().event_kind.store(4, Relaxed);
}
