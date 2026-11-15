//! Hooks for tests that exercise frame's fault handling.

use crate::arch;

/// Executes a breakpoint instruction. Frame's handler counts it and
/// resumes after it.
pub fn breakpoint() {
    arch::trap::breakpoint();
}

/// Breakpoints handled so far.
pub fn breakpoint_count() -> u64 {
    arch::trap::breakpoint_count()
}
