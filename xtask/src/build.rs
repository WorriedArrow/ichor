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

/// The native-ABI services' target (ADR-0012): static ELF executables.
pub const SERVICES_TARGET: &str = "x86_64-unknown-none";

/// The service binaries the kernel image embeds.
pub const SERVICES: &[&str] = &["ichor-nativetest"];

/// Where service builds go (their own directory, like the kernel's).
pub fn services_target_dir() -> PathBuf {
    workspace_root().join("target").join("services")
}

/// Builds the embedded services; returns the directory holding them,
/// which the kernel build reads as `ICHOR_SERVICES_DIR`.
pub fn services(profile: Profile) -> Result<PathBuf> {
    let mut cmd = cargo();
    cmd.arg("build");
    for s in SERVICES {
        cmd.args(["--package", s]);
    }
    cmd.args(["--target", SERVICES_TARGET])
        .arg("--target-dir")
        .arg(services_target_dir());
    if profile == Profile::Release {
        cmd.arg("--release");
    }
    run_cmd(&mut cmd)?;
    Ok(services_target_dir()
        .join(SERVICES_TARGET)
        .join(profile.dir()))
}

/// Builds the kernel and returns the path to `ichor.efi`.
pub fn kernel(profile: Profile) -> Result<PathBuf> {
    let services = services(profile)?;
    let mut cmd = cargo();
    cmd.args(["build", "--package", "ichor", "--target", KERNEL_TARGET])
        .arg("--target-dir")
        .arg(kernel_target_dir())
        .env("ICHOR_SERVICES_DIR", &services);
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
