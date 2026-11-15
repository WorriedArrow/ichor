//! Entering and leaving ring 3.
//!
//! A user thread runs through `iretq` and traps back into the kernel by a
//! `syscall` instruction, by a CPU exception, or by an interrupt. On the way
//! back the user registers are saved into the thread's [`UserContext`], and
//! control returns to the kernel stack frame that called
//! [`UserMode::execute`].
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

use core::arch::global_asm;

use super::regs::{self, rdmsr, wrmsr};
use super::trap::{self, KERNEL_CS};
use crate::cpu;

const USER_CS: u16 = 0x23; // GDT 0x20 (user code) | RPL 3

const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_FMASK: u32 = 0xC000_0084;
const EFER_SCE: u64 = 1; // syscall enable

// RFLAGS bits the user may hold; everything else is forced safe (IF set,
// IOPL 0, no DF/TF/AC). Reserved bit 1 is always set.
const USER_RFLAGS_ALLOWED: u64 = 0x0000_08d5; // CF PF AF ZF SF OF
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_RESERVED1: u64 = 1 << 1;

/// A user thread's saved register state. The field order matches the offsets
/// the entry stubs use (see `usermode_asm`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
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
    /// x87/SSE state (FXSAVE format), saved and restored around ring 3.
    fpu: FpuState, // 160 (after padding to 16)
}

/// A thread's x87/SSE register file in FXSAVE format. Only created in the
/// reset state ([`Default`]) or by `fxsave`, so `fxrstor` of it can never
/// fault on reserved MXCSR bits.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct FpuState([u8; 512]);

impl Default for FpuState {
    fn default() -> Self {
        let mut s = [0u8; 512];
        s[0..2].copy_from_slice(&0x037fu16.to_le_bytes()); // FCW: all masked
        s[24..28].copy_from_slice(&0x1f80u32.to_le_bytes()); // MXCSR: all masked
        FpuState(s)
    }
}

impl core::fmt::Debug for FpuState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FpuState")
    }
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

    /// The x87/SSE state in FXSAVE format (as a signal frame saves it).
    pub fn fpu_state(&self) -> [u8; 512] {
        self.fpu.0
    }

    /// Replaces the x87/SSE state (`rt_sigreturn`). MXCSR bits the CPU does
    /// not support are cleared, so the next `fxrstor` cannot fault.
    pub fn set_fpu_state(&mut self, state: &[u8; 512]) {
        let mask = match u32::from_le_bytes([
            self.fpu.0[28],
            self.fpu.0[29],
            self.fpu.0[30],
            self.fpu.0[31],
        ]) {
            0 => 0xffbf, // MXCSR_MASK 0 means the architectural default
            m => m,
        };
        let mut s = *state;
        let mxcsr = u32::from_le_bytes([s[24], s[25], s[26], s[27]]) & mask;
        s[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        // Keep this CPU's MXCSR_MASK (read-only to software).
        s[28..32].copy_from_slice(&self.fpu.0[28..32]);
        self.fpu.0 = s;
    }
}

/// Why [`UserMode::execute`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserEvent {
    /// A `syscall` instruction.
    Syscall,
    /// A CPU exception while in ring 3.
    Exception { vector: u8, error: u64, cr2: u64 },
}

/// Enables `syscall`/`sysret` on this CPU, and sets the kernel stack the CPU
/// switches to on a trap from ring 3 (TSS RSP0). Call during per-CPU init,
/// after the GDT/TSS and a fault stack exist.
pub(crate) fn init_cpu(fault_stack_top: u64) {
    trap::set_rsp0(fault_stack_top);
    let star = (u64::from(KERNEL_CS) << 32) | (u64::from(USER_CS - 16) << 48);
    let lstar = ichor_syscall_entry as *const () as u64;
    // SAFETY: STAR/LSTAR/FMASK/EFER are the architectural syscall MSRs.
    // LSTAR is our entry stub; FMASK clears IF/DF/TF/AC on entry; EFER.SCE
    // enables the instruction. KERNEL_CS matches the GDT in `trap`.
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
        let _guard = cpu::IrqGuard::new();
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
        // SAFETY: FS base holds a user TLS pointer; it never affects kernel
        // memory safety.
        unsafe { wrmsr(regs::MSR_FS_BASE, self.ctx.fs_base) };
        // SAFETY: `fpu` is a 16-byte-aligned 512-byte FXSAVE area holding
        // the reset state or an earlier `fxsave`, so it is valid to load.
        unsafe {
            core::arch::asm!("fxrstor64 [{}]", in(reg) &raw const self.ctx.fpu, options(nostack, readonly, preserves_flags));
        };
        // SAFETY: entry builds a ring-3 `iretq` frame from `ctx` and returns
        // here when the thread traps (the stubs load this kernel stack back).
        // The guard keeps us on this CPU across the round trip.
        unsafe { ichor_enter_user(core::ptr::from_mut(self.ctx)) };
        // SAFETY: stores the thread's x87/SSE state into its own aligned
        // 512-byte area before any other thread can run on this CPU (the
        // guard above keeps interrupts off; the kernel never uses the FPU).
        unsafe {
            core::arch::asm!("fxsave64 [{}]", in(reg) &raw mut self.ctx.fpu, options(nostack, preserves_flags));
        };
        let info = block.event_info.load(Relaxed);
        match block.event_kind.load(Relaxed) {
            1 => UserEvent::Syscall,
            _ => UserEvent::Exception {
                vector: info as u8,
                error: info >> 8,
                cr2: block.event_cr2.load(Relaxed),
            },
        }
    }
}

unsafe extern "sysv64" {
    fn ichor_enter_user(ctx: *mut UserContext);
    fn ichor_syscall_entry();
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

// GPR offsets within UserContext, shared with the stubs.
global_asm!(
    ".set UC_RAX, 0",
    ".set UC_RBX, 8",
    ".set UC_RCX, 16",
    ".set UC_RDX, 24",
    ".set UC_RSI, 32",
    ".set UC_RDI, 40",
    ".set UC_RBP, 48",
    ".set UC_RSP, 56",
    ".set UC_R8, 64",
    ".set UC_R9, 72",
    ".set UC_R10, 80",
    ".set UC_R11, 88",
    ".set UC_R12, 96",
    ".set UC_R13, 104",
    ".set UC_R14, 112",
    ".set UC_R15, 120",
    ".set UC_RIP, 128",
    ".set UC_RFLAGS, 136",
    // Per-CPU block (GS) offsets.
    ".set GS_RESUME, 16",
    ".set GS_UCTX, 32",
    ".set GS_SCRATCH, 40",
    ".set GS_EVENT, 56",
    ".set GS_RSP0PTR, 80",
    ".set SEL_USER_CS, 0x23",
    ".set SEL_USER_SS, 0x1b",
    // fn ichor_enter_user(ctx: *mut UserContext)  [ctx in rdi]
    ".global ichor_enter_user",
    ".global ichor_user_resume",
    "ichor_enter_user:",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov gs:[GS_RESUME], rsp",  // kernel stack to come back to
    "mov rax, gs:[GS_RSP0PTR]", // land ring-3 traps just below this frame,
    "mov [rax], rsp",           // not at the stack top (which `execute` uses)
    "mov gs:[GS_UCTX], rdi",
    // Build the iretq frame for ring 3.
    "push SEL_USER_SS",
    "mov rax, [rdi + UC_RSP]",
    "push rax",
    "mov rax, [rdi + UC_RFLAGS]",
    "push rax",
    "push SEL_USER_CS",
    "mov rax, [rdi + UC_RIP]",
    "push rax",
    // Load user GPRs (rdi last, since it is our pointer).
    "mov rax, [rdi + UC_RAX]",
    "mov rbx, [rdi + UC_RBX]",
    "mov rcx, [rdi + UC_RCX]",
    "mov rdx, [rdi + UC_RDX]",
    "mov rsi, [rdi + UC_RSI]",
    "mov rbp, [rdi + UC_RBP]",
    "mov r8,  [rdi + UC_R8]",
    "mov r9,  [rdi + UC_R9]",
    "mov r10, [rdi + UC_R10]",
    "mov r11, [rdi + UC_R11]",
    "mov r12, [rdi + UC_R12]",
    "mov r13, [rdi + UC_R13]",
    "mov r14, [rdi + UC_R14]",
    "mov r15, [rdi + UC_R15]",
    "mov rdi, [rdi + UC_RDI]",
    "iretq",
    // The syscall/exception stubs jump here to return to the kernel caller.
    "ichor_user_resume:",
    "mov rsp, gs:[GS_RESUME]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "ret",
    // fn ichor_syscall_entry()  [via LSTAR: rcx=rip, r11=rflags, GS=block]
    ".global ichor_syscall_entry",
    "ichor_syscall_entry:",
    "mov gs:[GS_SCRATCH], rdi", // free rdi (holds user rdi)
    "mov rdi, gs:[GS_UCTX]",
    "mov [rdi + UC_RAX], rax",
    "mov [rdi + UC_RBX], rbx",
    "mov [rdi + UC_RCX], rcx",
    "mov [rdi + UC_RIP], rcx", // syscall puts the return rip in rcx
    "mov [rdi + UC_RDX], rdx",
    "mov [rdi + UC_RSI], rsi",
    "mov [rdi + UC_RBP], rbp",
    "mov [rdi + UC_RSP], rsp", // syscall does not change rsp: still the user's
    "mov [rdi + UC_R8], r8",
    "mov [rdi + UC_R9], r9",
    "mov [rdi + UC_R10], r10",
    "mov [rdi + UC_R11], r11",
    "mov [rdi + UC_RFLAGS], r11", // syscall puts rflags in r11
    "mov [rdi + UC_R12], r12",
    "mov [rdi + UC_R13], r13",
    "mov [rdi + UC_R14], r14",
    "mov [rdi + UC_R15], r15",
    "mov rax, gs:[GS_SCRATCH]",
    "mov [rdi + UC_RDI], rax",
    "mov qword ptr gs:[GS_EVENT], 1", // Syscall
    "jmp ichor_user_resume",
);
