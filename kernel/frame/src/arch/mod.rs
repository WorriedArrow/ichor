//! Architecture boundary.
//!
//! Everything instruction-set specific lives under `arch/<isa>/`. The rest of
//! frame (and the rest of the kernel) only uses the items re-exported here, so
//! bringing up a new architecture means implementing this same set of items in
//! a sibling module.
//!
//! Items every architecture provides:
//!
//! * `halt_forever() -> !` — stop this CPU with interrupts masked.
//! * `disable_local_interrupts()` — mask interrupts on this CPU.
//! * `pub(crate) mod early_console` — a byte sink usable from the first
//!   instruction of boot and from the panic handler.
//! * `pub(crate) mod qemu` — the QEMU test-exit device.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Ichor currently supports only x86_64; aarch64 is milestone 10");
