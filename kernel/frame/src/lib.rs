//! `frame`: the trusted computing base of the Ichor kernel.
//!
//! This is the only kernel crate permitted to contain `unsafe` code. Every
//! public item is safe, and the soundness of the whole kernel rests on one
//! claim: **no sequence of calls to frame's public API from safe Rust can cause
//! undefined behaviour.** See `docs/adr/0001-kernel-architecture.md` for the
//! API surface this crate is growing toward and the rules for extending it.
//!
//! Rules for code in this crate:
//!
//! * Every `unsafe` block holds exactly one unsafe operation and carries a
//!   `// SAFETY:` comment naming the invariant it relies on (enforced by
//!   clippy's `undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block`).
//! * Every `unsafe fn` documents its contract under `# Safety`.
//! * Raw firmware and hardware types stay private. Public types encode their
//!   invariants so that safe callers cannot break them.
//! * Size is budgeted: `cargo xtask frame-audit` fails if the line count or
//!   unsafe-site count exceeds `kernel/frame/audit.toml`. Raising the budget
//!   requires an ADR.

#![no_std]

extern crate alloc;

mod acpi;
pub mod arch;
pub mod boot;
pub mod console;
pub mod cpu;
pub mod debug;
pub mod irq;
pub mod mm;
pub mod power;
pub mod smp;
pub mod sync;
pub mod task;
pub mod time;
pub mod user;

mod panic;
