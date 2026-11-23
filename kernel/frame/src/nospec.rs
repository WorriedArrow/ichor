//! Spectre v1 (bounds-check bypass): table indexes a user chooses, clamped
//! without a branch (ADR-0004 §2 and its 2026-11-23 amendment).

/// `index` if `index < len`, else 0, without a branch: past a bounds
/// check that the CPU predicts true, the index it runs ahead with stays
/// inside the table. Callers still check the bound (an out-of-range index
/// comes back as 0, not as an error).
#[inline(always)]
pub fn index(index: usize, len: usize) -> usize {
    let mask: usize;
    // SAFETY: two register-only instructions: CMP sets the carry when
    // `index < len`, SBB turns it into all ones (or zero). No memory, no
    // stack; the flags they change are declared clobbered (the default).
    unsafe {
        core::arch::asm!(
            "cmp {i}, {n}",
            "sbb {m}, {m}",
            i = in(reg) index,
            n = in(reg) len,
            m = out(reg) mask,
            options(pure, nomem, nostack),
        );
    }
    index & mask
}
