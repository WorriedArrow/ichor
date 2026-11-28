//! OpenVMM, Microsoft's VMM, as a second way to run Ichor for long jobs
//! (`cargo xtask workloads --vmm openvmm`). On Windows it runs on the
//! hypervisor platform with hardware virtualization, where QEMU has only
//! TCG (`docs/cloud.md` has the manual command). Ichor boots it as a
//! Hyper-V Gen 2 machine: a UEFI disk on VMBus SCSI and a VMBus NIC behind
//! consomme, OpenVMM's user-mode network, whose `hostfwd` forwards a host
//! port in.
//!
//! The binary and firmware come from `ICHOR_OPENVMM` and `ICHOR_MSVM`, else
//! `target/hyperv/build/debug/openvmm.exe` and `target/hyperv/fw/FV/MSVM.fd`
//! (OpenVMM's own `dev` profile is optimized).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::Result;
use crate::qemu::{Exit, Outcome, RunConfig};

/// The OpenVMM binary and its UEFI firmware.
pub fn find() -> Result<(PathBuf, PathBuf)> {
    let root = crate::workspace_root().join("target").join("hyperv");
    let exe = std::env::var_os("ICHOR_OPENVMM")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("build").join("debug").join("openvmm.exe"));
    let fw = std::env::var_os("ICHOR_MSVM")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("fw").join("FV").join("MSVM.fd"));
    for p in [&exe, &fw] {
        if !p.exists() {
            return Err(format!(
                "{} not found (set ICHOR_OPENVMM and ICHOR_MSVM)",
                p.display()
            ));
        }
    }
    Ok((exe, fw))
}

/// Boots `cfg`'s kernel under OpenVMM from a GPT disk with its command line
/// (without `qemu_debug_exit`, which has no device here), `hostfwd`
/// forwarding host port `.0` to the guest's `.1`, until `done` says the
/// job is over, the VM exits, or `cfg.timeout` passes. Ichor halts rather
/// than powering off at the end of a run, so the VM is then stopped.
pub fn run(cfg: &RunConfig, hostfwd: (u16, u16), done: impl Fn() -> bool) -> Result<Outcome> {
    let (exe, fw) = find()?;
    let dir = crate::workspace_root().join("target").join("openvmm");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let cmdline: Vec<&str> = cfg
        .cmdline
        .split_whitespace()
        .filter(|w| *w != "qemu_debug_exit")
        .collect();
    let disk = crate::disk::image_sized(
        &cfg.kernel,
        &cmdline.join(" "),
        0,
        cfg.api_token.as_deref().map(str::as_bytes),
        cfg.api_tls.as_deref().map(str::as_bytes),
    )?;
    let img = dir.join(format!("{}.img", cfg.name));
    std::fs::write(&img, disk).map_err(|e| format!("{}: {e}", img.display()))?;
    let com1 = dir.join(format!("{}.com1.log", cfg.name));
    let _ = std::fs::remove_file(&com1);
    let mut cmd = Command::new(&exe);
    cmd.arg("--uefi")
        .arg(format!("firmware={}", fw.display()))
        .args(["--processors", &cfg.smp.to_string()])
        .args(["--memory", &format!("{}GB", cfg.memory_mib.div_ceil(1024))])
        .args(["--vmbus-scsi", "id=scsi0"])
        .arg("--disk")
        .arg(format!("file:{},on=scsi0,ro", img.display()))
        .arg("--net")
        .arg(format!(
            "consomme:hostfwd=tcp:127.0.0.1:{}-:{}",
            hostfwd.0, hostfwd.1
        ))
        .arg("--com1")
        .arg(format!("file={}", com1.display()))
        // It runs until its standard input closes.
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", exe.display()))?;
    let limit = cfg.timeout.unwrap_or(Duration::from_secs(24 * 3600));
    let exit = loop {
        if let Ok(Some(_)) = child.try_wait() {
            break Exit::Other(None);
        }
        if done() {
            break Exit::Success;
        }
        if started.elapsed() > limit {
            break Exit::Timeout;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let _ = child.kill();
    let _ = child.wait();
    let serial = std::fs::read(&com1)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    Ok(Outcome {
        exit,
        serial,
        elapsed: started.elapsed(),
    })
}
