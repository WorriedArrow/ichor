//! x86_64 implementation of the architecture boundary.

pub(crate) mod apic;
pub mod cpu;
pub(crate) mod early_console;
mod io;
pub mod paging;
pub(crate) mod qemu;
pub(crate) mod regs;
pub(crate) mod smp;
pub(crate) mod switch;
pub(crate) mod trap;
pub(crate) mod usermode;

pub use self::trap::TrapFrame;
pub use self::usermode::{UserContext, UserEvent, UserMode};

use core::arch::asm;

const RFLAGS_IF: u64 = 1 << 9;

/// Masks maskable interrupts on the current CPU.
pub fn disable_local_interrupts() {
    // SAFETY: `cli` only clears RFLAGS.IF. Frame code never relies on
    // interrupts being enabled for memory safety, so masking them is always
    // sound (at worst it delays interrupt delivery).
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// Masks interrupts and reports whether they were enabled before.
pub(crate) fn save_and_disable_interrupts() -> bool {
    let rflags: u64;
    // SAFETY: reads RFLAGS through the stack, then `cli` (see
    // `disable_local_interrupts`).
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) rflags, options(nomem)) };
    rflags & RFLAGS_IF != 0
}

/// Re-enables interrupts if `was_enabled` (from
/// [`save_and_disable_interrupts`]).
pub(crate) fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        // SAFETY: interrupts were enabled when the matching save ran, so an
        // IDT that can handle them is installed.
        unsafe { asm!("sti", options(nomem, nostack)) };
    }
}

/// Enables interrupts and halts until one arrives. `sti` delays interrupt
/// delivery by one instruction, so an interrupt cannot slip in between.
pub(crate) fn enable_and_halt() {
    // SAFETY: frame installs the IDT before any caller can reach this;
    // `hlt` just waits.
    unsafe { asm!("sti", "hlt", options(nomem, nostack)) };
}

/// Points GS at this CPU's per-CPU block.
pub(crate) fn set_cpu_block(addr: u64) {
    // SAFETY: GS base is used only by frame to find the per-CPU block; `addr`
    // is a leaked, 'static block. Clearing KERNEL_GS_BASE keeps `swapgs`
    // (milestone 2) from ever loading a stale value.
    unsafe { regs::wrmsr(regs::MSR_GS_BASE, addr) };
    // SAFETY: as above.
    unsafe { regs::wrmsr(regs::MSR_KERNEL_GS_BASE, 0) };
}

/// The current CPU's index, from its per-CPU block.
pub(crate) fn cpu_index() -> u32 {
    let index: u64;
    // SAFETY: every CPU sets its GS base to its block (offset 8 holds the
    // index) before any code that can ask for the CPU index runs.
    unsafe { asm!("mov {}, gs:[8]", out(reg) index, options(nostack, preserves_flags, readonly)) };
    index as u32
}

/// Increments this CPU's atomic depth (`gs:[48]`). One instruction, so it
/// cannot be torn by an interrupt or a migration.
pub(crate) fn atomic_depth_inc() {
    // SAFETY: GS points at this CPU's block (callers check that blocks are
    // ready); offset 48 is its `atomic_depth` counter, otherwise accessed only
    // atomically.
    unsafe { asm!("inc qword ptr gs:[48]", options(nostack)) };
}

/// Decrements this CPU's atomic depth.
pub(crate) fn atomic_depth_dec() {
    // SAFETY: as in `atomic_depth_inc`.
    unsafe { asm!("dec qword ptr gs:[48]", options(nostack)) };
}

/// This CPU's atomic depth.
pub(crate) fn atomic_depth() -> u64 {
    let d: u64;
    // SAFETY: as in `atomic_depth_inc`; a plain load.
    unsafe { asm!("mov {}, gs:[48]", out(reg) d, options(nostack, preserves_flags, readonly)) };
    d
}

/// Switches to page table root `root` (0 means the kernel's), if it is
/// not already active.
pub(crate) fn activate_root(root: u64) {
    let target = if root == 0 {
        crate::mm::kspace::kernel_root()
    } else {
        root
    };
    if regs::read_cr3() & 0x000f_ffff_ffff_f000 != target {
        // SAFETY: `target` is the kernel PML4 or a user root built by frame,
        // which shares every kernel-half entry, so the running code, stack
        // and data stay mapped.
        unsafe { regs::write_cr3(target) };
    }
}

/// Copies `len` bytes of untyped memory (memory that other agents, such as
/// user threads, may access concurrently). The copy is done by `rep movsb`
/// and so is outside the Rust memory model: concurrent writes give
/// unspecified bytes, not undefined behaviour.
///
/// # Safety
///
/// `src` must be mapped and readable for `len` bytes and `dst` mapped and
/// writable for `len` bytes, and `dst` must not overlap memory that Rust
/// code holds a reference to.
pub(crate) unsafe fn copy_untyped(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: caller contract.
    unsafe {
        asm!(
            "rep movsb",
            inout("rcx") len => _,
            inout("rdi") dst => _,
            inout("rsi") src => _,
            options(nostack, preserves_flags)
        )
    };
}

/// Fills `len` bytes of untyped memory with `byte`.
///
/// # Safety
///
/// `dst` must be mapped and writable for `len` bytes and must not overlap
/// memory that Rust code holds a reference to.
pub(crate) unsafe fn fill_untyped(dst: *mut u8, byte: u8, len: usize) {
    // SAFETY: caller contract.
    unsafe {
        asm!(
            "rep stosb",
            inout("rcx") len => _,
            inout("rdi") dst => _,
            in("al") byte,
            options(nostack, preserves_flags)
        )
    };
}

/// Stops the current CPU forever with interrupts masked.
///
/// NMIs and SMIs can still wake the CPU from `hlt`, so this loops.
pub fn halt_forever() -> ! {
    disable_local_interrupts();
    loop {
        // SAFETY: `hlt` pauses the CPU until the next interrupt. It has no
        // memory effects; with IF clear only NMI/SMI/INIT resume it, after
        // which we halt again.
        unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}

/// Flushes every TLB entry on this CPU, including global ones.
pub(crate) fn flush_tlb_all() {
    let cr4 = regs::read_cr4();
    if cr4 & regs::CR4_PGE != 0 {
        // SAFETY: toggling PGE flushes all TLB entries and changes nothing
        // else; the original value is restored immediately.
        unsafe { regs::write_cr4(cr4 & !regs::CR4_PGE) };
        // SAFETY: restores the previous CR4.
        unsafe { regs::write_cr4(cr4) };
    } else {
        // SAFETY: reloading CR3 with its current value only flushes the TLB.
        unsafe { regs::write_cr3(regs::read_cr3()) };
    }
}

/// Switches to `stack_top` and jumps to the higher-half alias of
/// `crate::boot::kernel_space_entry` (its current address plus `delta`).
///
/// # Safety
///
/// `stack_top` must be the 16-byte aligned top of a mapped, writable, unused
/// stack. The image must be mapped at its current address plus `delta` with
/// base relocations already applied for that address. Nothing on the current
/// stack may be used again.
pub(crate) unsafe fn jump_to_high_half(stack_top: u64, delta: u64) -> ! {
    // SAFETY: caller contract. The target is computed RIP-relatively from
    // the symbol (not loaded from data, which has been rebased already). The
    // pushed zero is a fake return address so the entry sees the stack
    // alignment of a normal call.
    unsafe {
        asm!(
            "mov rsp, rdi",
            "xor ebp, ebp",
            "lea rax, [rip + {entry}]",
            "add rax, rsi",
            "push 0",
            "jmp rax",
            entry = sym crate::boot::kernel_space_entry,
            in("rdi") stack_top,
            in("rsi") delta,
            options(noreturn)
        )
    }
}
