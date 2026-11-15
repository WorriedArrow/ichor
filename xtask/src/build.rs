//! Building the kernel image.

use std::path::PathBuf;

use crate::{Result, cargo, run_cmd, workspace_root};

/// The kernel's target triple. The kernel is a PE/COFF UEFI application.
pub const KERNEL_TARGET: &str = "x86_64-unknown-uefi";

/// Cargo profile to build the kernel with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Dev,
    Release,
}

impl Profile {
    fn dir(self) -> &'static str {
        match self {
            Profile::Dev => "debug",
            Profile::Release => "release",
        }
    }
}

/// Kernel builds use their own target directory so that they never contend
/// for the cargo build lock with the host build that is running xtask or the
/// integration tests.
pub fn kernel_target_dir() -> PathBuf {
    workspace_root().join("target").join("kernel")
}

/// Builds the kernel and returns the path to `ichor.efi`.
pub fn kernel(profile: Profile) -> Result<PathBuf> {
    let mut cmd = cargo();
    cmd.args(["build", "--package", "ichor", "--target", KERNEL_TARGET])
        .arg("--target-dir")
        .arg(kernel_target_dir());
    if profile == Profile::Release {
        cmd.arg("--release");
    }
    run_cmd(&mut cmd)?;
    let efi = kernel_target_dir()
        .join(KERNEL_TARGET)
        .join(profile.dir())
        .join("ichor.efi");
    if !efi.is_file() {
        return Err(format!("build succeeded but {} is missing", efi.display()));
    }
    Ok(efi)
}
