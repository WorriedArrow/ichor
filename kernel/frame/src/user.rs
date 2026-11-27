//! Running ring-3 (user-mode) threads.
//!
//! A [`UserContext`] holds a thread's registers; [`UserMode::execute`] enters
//! ring 3 and returns the [`UserEvent`] that brought control back (a syscall
//! or an exception). Both syscall personalities (`kernel/linux-abi`,
//! `kernel/native-abi`) are built on this in safe code.

pub use crate::arch::entry::{isolating, isolation_selftest};
pub use crate::arch::usermode::{ibpb_count, ibrs_in_kernel, store_bypass};
pub use crate::arch::{UserContext, UserEvent, UserMode};
