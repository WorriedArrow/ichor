//! The static busybox the milestone 3 test runs in a cell.
//!
//! It is the official prebuilt binary from busybox.net (musl, static,
//! x86-64), fetched once into `target/busybox/` and checked against a
//! pinned SHA-256 on every use. Busybox is GPL-2.0; it is only downloaded
//! for testing and never committed or redistributed with Ichor.
//!
//! `ICHOR_BUSYBOX=<path>` uses a local copy instead (still hash-checked),
//! for offline machines.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::{Result, sha256, workspace_root};

pub const VERSION: &str = "1.35.0";
const URL: &str = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox";
const SHA256: &str = "6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348";

fn check(bytes: &[u8], what: &str) -> Result<()> {
    let got = sha256::hex(&sha256::digest(bytes));
    if got != SHA256 {
        return Err(format!(
            "{what}: SHA-256 is {got}, expected {SHA256} (busybox {VERSION})"
        ));
    }
    Ok(())
}

/// The busybox binary's bytes, downloading and caching it if needed.
pub fn bytes() -> Result<Vec<u8>> {
    if let Some(p) = std::env::var_os("ICHOR_BUSYBOX") {
        let p = PathBuf::from(p);
        let b = fs::read(&p).map_err(|e| format!("reading {}: {e}", p.display()))?;
        check(&b, &p.display().to_string())?;
        return Ok(b);
    }
    let dir = workspace_root()
        .join("target")
        .join("busybox")
        .join(VERSION);
    let path = dir.join("busybox");
    if let Ok(b) = fs::read(&path)
        && check(&b, "cached busybox").is_ok()
    {
        return Ok(b);
    }
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let partial = dir.join("busybox.partial");
    let status = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--retry",
            "3",
        ])
        .arg("--output")
        .arg(&partial)
        .arg(URL)
        .status()
        .map_err(|e| format!("running curl to fetch busybox: {e} (or set ICHOR_BUSYBOX)"))?;
    if !status.success() {
        return Err(format!(
            "downloading {URL} failed ({status}); set ICHOR_BUSYBOX to a local copy"
        ));
    }
    let b = fs::read(&partial).map_err(|e| format!("reading {}: {e}", partial.display()))?;
    check(&b, URL)?;
    fs::rename(&partial, &path).map_err(|e| format!("caching busybox: {e}"))?;
    Ok(b)
}
