//! Host-side tooling for Ichor, used both by `cargo xtask` and by the QEMU
//! integration tests in `tests/`.
//!
//! Deliberately dependency-free: it must build fast and run anywhere a Rust
//! toolchain and QEMU are installed (Linux CI, Windows and macOS laptops).

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // host tool

pub mod audit;
pub mod build;
pub mod busybox;
pub mod linux_abi;
pub mod qemu;
pub mod sha256;

use std::path::{Path, PathBuf};

/// Result type used throughout xtask. Errors are human-readable messages.
pub type Result<T, E = String> = std::result::Result<T, E>;

/// The workspace root (the directory containing the top-level Cargo.toml).
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the workspace root")
        .to_path_buf()
}

/// The `cargo` binary that is running us (respects rustup's toolchain
/// selection), falling back to `cargo` on PATH.
pub fn cargo() -> std::process::Command {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = std::process::Command::new(cargo);
    cmd.current_dir(workspace_root());
    cmd
}

/// Runs a command to completion, failing on a non-zero exit.
pub fn run_cmd(cmd: &mut std::process::Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| format!("failed to spawn {cmd:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed ({status}): {cmd:?}"))
    }
}
