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
pub const SERVICES: &[&str] = &["ichor-nativetest", "ichor-control"];

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
    // Release services use their own profile: whole-program LTO cannot mix
    // the small code model they are built with and the kernel code model of
    // the target's prebuilt `core`/`alloc`.
    let dir = if profile == Profile::Release {
        cmd.args(["--profile", "services-release"]);
        "services-release"
    } else {
        profile.dir()
    };
    run_cmd(&mut cmd)?;
    Ok(services_target_dir().join(SERVICES_TARGET).join(dir))
}

/// Builds the kernel and returns the path to `ichor.efi`.
pub fn kernel(profile: Profile) -> Result<PathBuf> {
    let services = services(profile)?;
    let mut cmd = cargo();
    cmd.args(["build", "--package", "ichor", "--target", KERNEL_TARGET])
        .arg("--target-dir")
        .arg(kernel_target_dir())
        .env("ICHOR_SERVICES_DIR", &services);
    // Return thunks (ADR-0004's amendment of 2026-11-23): every `ret` the
    // compiler emits becomes `jmp __x86_return_thunk`, which frame points at
    // AMD's safe-RET sequence where SRSO applies. `core`, `alloc` and
    // `compiler_builtins` are rebuilt with it, or their returns would stay
    // plain (but for `compiler_builtins`' stack probe, which is assembly:
    // frame patches its return at boot). Both flags are unstable; the
    // pinned stable compiler takes them
    // with RUSTC_BOOTSTRAP, for this build only (AGENTS.md, "Unstable
    // features").
    cmd.args([
        "-Zbuild-std=core,alloc,compiler_builtins",
        "-Zbuild-std-features=compiler-builtins-mem",
    ])
    .env("RUSTC_BOOTSTRAP", "1")
    // No compiler wrapper: sccache on Windows hangs on the kernel crate's
    // command line, which the rebuilt standard library lengthens.
    .env("RUSTC_WRAPPER", "")
    .env(
        "CARGO_TARGET_X86_64_UNKNOWN_UEFI_RUSTFLAGS",
        "-Zfunction-return=thunk-extern",
    );
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
