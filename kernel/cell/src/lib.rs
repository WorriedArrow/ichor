//! Cells and resource accounts (ADR-0002).
//!
//! This crate holds the parts of the cell model that are pure, safe logic and
//! testable on the host: the hierarchical resource [`account`] tree. The
//! kernel-object graph that ties a cell to its CSpace, address spaces and
//! processes lives in `kernel/ichor` (it references frame's `VmSpace`, tasks
//! and `cap::CSpace`), so that this crate stays `no_std` and dependency-light.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod account;

pub use account::{Account, ChargeError, UNLIMITED};
