//! Shared helpers for the QEMU integration tests.
//!
//! Each test boots the kernel once with a chosen command line and asserts on
//! the serial log and on the exit status the kernel reports through QEMU's
//! `isa-debug-exit` device.
//!
//! `cargo xtask test` builds the kernel first and passes its path in
//! `ICHOR_KERNEL`. Run directly (`cargo test -p ichor-tests`), the tests build
//! the dev kernel themselves.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

pub use xtask::qemu::{Exit, Outcome};
use xtask::qemu::{RunConfig, run};

/// Generous enough for OVMF under TCG on a slow CI machine. Under KVM a boot
/// takes about a second.
pub const BOOT_TIMEOUT: Duration = Duration::from_secs(120);

fn kernel() -> PathBuf {
    static KERNEL: OnceLock<PathBuf> = OnceLock::new();
    KERNEL
        .get_or_init(|| match std::env::var_os("ICHOR_KERNEL") {
            Some(p) => PathBuf::from(p),
            None => xtask::build::kernel(xtask::build::Profile::Dev).expect("kernel build failed"),
        })
        .clone()
}

/// Boots the kernel with `cmdline` (plus `qemu_debug_exit`) and returns the
/// outcome. `name` must be unique per test: it names the run directory.
pub fn boot(name: &str, cmdline: &str, smp: u32) -> Outcome {
    let mut cfg = RunConfig::new(format!("test-{name}"), kernel());
    cfg.cmdline = format!("qemu_debug_exit {cmdline}");
    cfg.smp = smp;
    cfg.capture = true;
    cfg.timeout = Some(BOOT_TIMEOUT);
    run(&cfg).expect("failed to run QEMU")
}
