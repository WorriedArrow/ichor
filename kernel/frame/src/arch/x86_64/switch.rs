//! Kernel context switch.
//!
//! A task that is not running is fully described by its saved stack
//! pointer: the callee-saved registers (rbx, rbp, r12-r15) and the return
//! address into `switch_stacks` live on its own kernel stack. Caller-saved
//! registers are already saved by the compiler around the call.

/// Saves the current context, storing its stack pointer in `*save`, and
/// resumes the context whose stack pointer is `next`.
///
/// # Safety
///
/// `save` must be valid for a write and owned by the task being switched
/// away from; `next` must be a stack pointer produced by an earlier
/// `switch_stacks` or by [`prepare_stack`], belonging to a task that is not
/// running anywhere and whose stack is mapped.
#[unsafe(naked)]
pub(crate) unsafe extern "sysv64" fn switch_stacks(save: *mut u64, next: u64) {
    core::arch::naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, rsi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    )
}

/// Lays out a fresh kernel stack so that the first `switch_stacks` to it
/// "returns" into `entry`; returns the stack pointer to switch to.
///
/// # Safety
///
/// `top` must be the 16-byte aligned top of a mapped, writable stack that
/// nothing else uses.
pub(crate) unsafe fn prepare_stack(top: u64, entry: extern "sysv64" fn() -> !) -> u64 {
    // From the top: a zero fake return address (so `entry` sees the stack
    // alignment of a normal call), `entry` as the return address of
    // `switch_stacks`, then the six callee-saved registers.
    let frame: [u64; 8] = [0, 0, 0, 0, 0, 0, entry as usize as u64, 0];
    let sp = top - 64;
    let ptr = core::ptr::with_exposed_provenance_mut::<[u64; 8]>(sp as usize);
    // SAFETY: caller contract: `[top - 64, top)` is mapped, writable, unused
    // stack memory, and `sp` is 8-byte aligned.
    unsafe { ptr.write(frame) };
    sp
}
