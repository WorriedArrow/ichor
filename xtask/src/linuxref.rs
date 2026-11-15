//! The Linux reference for the Phase E benchmarks: boots Alpine's official
//! `linux-virt` kernel in the same QEMU machine as Ichor (q35, same CPU
//! model, vCPU count and memory) with an initramfs holding the static
//! busybox and the benchmark programs from `testprog::bench`, the same
//! bytes Ichor runs. Each program prints its own `ichor-bench:` line, so
//! both kernels report one measurement of identical work.
//!
//! Linux runs with its defaults, including its CPU-vulnerability
//! mitigations (page-table isolation on affected CPUs, for one), which
//! Ichor does not all apply yet (ADR-0004); read the comparison with that
//! in mind.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::artifact::{ALPINE_LINUX_VIRT, BUSYBOX};
use crate::inflate::gunzip_all;
use crate::qemu::{self, Accel, Outcome};
use crate::{Result, workspace_root};

/// Where the kernel sits in the `linux-virt` package.
const VMLINUZ: &str = "boot/vmlinuz-virt";

fn octal(field: &[u8]) -> Option<usize> {
    let mut v = 0usize;
    for &b in field.iter().skip_while(|&&b| b == b' ') {
        match b {
            b'0'..=b'7' => v = v.checked_mul(8)?.checked_add(usize::from(b - b'0'))?,
            0 | b' ' => break,
            _ => return None,
        }
    }
    Some(v)
}

/// The bytes of regular file `path` in a tar stream. Zero blocks are
/// skipped rather than ending the scan, because an `.apk` is several tar
/// fragments back to back.
fn tar_file<'a>(tar: &'a [u8], path: &str) -> Option<&'a [u8]> {
    let mut pos = 0;
    while pos + 512 <= tar.len() {
        let h = &tar[pos..pos + 512];
        if h.iter().all(|&b| b == 0) {
            pos += 512;
            continue;
        }
        let size = octal(&h[124..136])?;
        let end = h[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let start = pos + 512;
        if &h[..end] == path.as_bytes() && matches!(h[156], b'0' | 0) {
            return tar.get(start..start + size);
        }
        pos = start + size.next_multiple_of(512);
    }
    None
}

/// The Linux kernel image, from the pinned `linux-virt` package.
pub fn vmlinuz() -> Result<Vec<u8>> {
    let apk = ALPINE_LINUX_VIRT.bytes()?;
    let tar = gunzip_all(&apk)?;
    tar_file(&tar, VMLINUZ)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| format!("{VMLINUZ} not found in {}", ALPINE_LINUX_VIRT.file))
}

/// A `newc` cpio archive (what the Linux kernel unpacks as an initramfs).
#[derive(Debug, Default)]
pub struct Cpio {
    out: Vec<u8>,
    ino: u32,
}

impl Cpio {
    fn pad(&mut self) {
        while !self.out.len().is_multiple_of(4) {
            self.out.push(0);
        }
    }

    /// Adds one entry: `mode` includes the file type bits; `rdev` is
    /// `(major, minor)` for device nodes.
    pub fn entry(&mut self, name: &str, mode: u32, rdev: (u32, u32), data: &[u8]) {
        self.ino += 1;
        let fields = [
            self.ino,
            mode,
            0, // uid
            0, // gid
            if mode & 0o170_000 == 0o040_000 { 2 } else { 1 },
            0, // mtime
            u32::try_from(data.len()).unwrap_or(u32::MAX),
            0, // devmajor
            0, // devminor
            rdev.0,
            rdev.1,
            u32::try_from(name.len() + 1).unwrap_or(u32::MAX),
            0, // check
        ];
        self.out.extend_from_slice(b"070701");
        for f in fields {
            self.out.extend_from_slice(format!("{f:08x}").as_bytes());
        }
        self.out.extend_from_slice(name.as_bytes());
        self.out.push(0);
        self.pad();
        self.out.extend_from_slice(data);
        self.pad();
    }

    pub fn dir(&mut self, name: &str) {
        self.entry(name, 0o040_755, (0, 0), &[]);
    }

    pub fn file(&mut self, name: &str, mode: u32, data: &[u8]) {
        self.entry(name, 0o100_000 | mode, (0, 0), data);
    }

    pub fn symlink(&mut self, name: &str, target: &str) {
        self.entry(name, 0o120_777, (0, 0), target.as_bytes());
    }

    /// The archive, with its trailer.
    pub fn finish(mut self) -> Vec<u8> {
        self.entry("TRAILER!!!", 0, (0, 0), &[]);
        self.out
    }
}

/// `/init`: runs every benchmark, then powers the machine off.
const INIT: &str = "#!/bin/sh
for p in /bench/*; do
  \"$p\" || echo \"ichor-bench: $p failed\"
done
echo ichor-linux-bench: done
/bin/busybox poweroff -f
";

/// The initramfs: busybox (as `/bin/sh` and `/bin/true` too), a console
/// node, `/init`, and each benchmark program at its iteration count.
pub fn initramfs() -> Result<Vec<u8>> {
    let busybox = BUSYBOX.bytes()?;
    let mut c = Cpio::default();
    for d in ["bin", "dev", "proc", "bench"] {
        c.dir(d);
    }
    c.entry("dev/console", 0o020_600, (5, 1), &[]);
    c.file("bin/busybox", 0o755, &busybox);
    c.symlink("bin/sh", "busybox");
    c.symlink("bin/true", "busybox");
    c.file("init", 0o755, INIT.as_bytes());
    for (name, prog, n) in testprog::bench::ALL {
        c.file(&format!("bench/{name}"), 0o755, &prog(*n));
    }
    Ok(c.finish())
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Boots Linux with the benchmark initramfs and returns its serial output.
pub fn run(smp: u32, memory_mib: u32, accel: Accel, timeout: Duration) -> Result<Outcome> {
    let dir: PathBuf = workspace_root()
        .join("target")
        .join("qemu")
        .join("linux-bench");
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let kernel = dir.join("vmlinuz-virt");
    let initrd = dir.join("initramfs.cpio");
    write(&kernel, &vmlinuz()?)?;
    write(&initrd, &initramfs()?)?;
    let accel = accel.resolve();
    let mut cmd = Command::new(qemu::find_qemu()?);
    cmd.args(["-machine", "q35", "-accel", accel.qemu_name()])
        .args(["-cpu", accel.cpu_model()])
        .args(["-smp", &smp.to_string()])
        .args(["-m", &format!("{memory_mib}M")])
        .args(["-nodefaults", "-no-user-config", "-no-reboot"])
        .args(["-display", "none", "-serial", "stdio"])
        .arg("-kernel")
        .arg(&kernel)
        .arg("-initrd")
        .arg(&initrd)
        .args(["-append", "console=ttyS0 quiet panic=-1"])
        .stdin(Stdio::null());
    qemu::run_command(cmd, true, Some(timeout))
}

/// Per-operation results from a serial log: for each benchmark, the run
/// with the most iterations, as `(iterations, nanoseconds)`.
pub fn results(serial: &str) -> BTreeMap<String, (u64, u64)> {
    let mut out: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for line in serial.lines() {
        if let Some((name, n, ns)) = testprog::bench::parse(line) {
            let e = out.entry(name.to_string()).or_insert((n, ns));
            if n > e.0 {
                *e = (n, ns);
            }
        }
    }
    out
}

/// A per-operation cost for a table cell.
pub fn per_op(n: u64, ns: u64) -> String {
    let per = ns as f64 / n.max(1) as f64;
    if per >= 10_000.0 {
        format!("{:.1} us", per / 1000.0)
    } else {
        format!("{per:.0} ns")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpio_entries_are_aligned_newc() {
        let mut c = Cpio::default();
        c.dir("bin");
        c.file("bin/x", 0o755, b"abc");
        c.symlink("bin/y", "x");
        let a = c.finish();
        assert!(a.starts_with(b"070701"));
        assert!(a.len().is_multiple_of(4));
        // Header fields are 8 hex digits; the name follows the 110-byte header.
        assert_eq!(&a[110..114], b"bin\0");
        let s = String::from_utf8_lossy(&a);
        assert!(s.contains("bin/x\0") && s.contains("abc") && s.contains("TRAILER!!!"));
    }

    #[test]
    fn tar_file_finds_entries_across_fragments() {
        fn header(name: &str, size: usize) -> Vec<u8> {
            let mut h = vec![0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
            h[156] = b'0';
            h
        }
        let mut tar = header("a", 3);
        tar.extend_from_slice(&[b'x'; 512]);
        tar.extend_from_slice(&[0; 1024]); // end of one fragment
        tar.extend_from_slice(&header("boot/k", 5));
        let mut data = b"hello".to_vec();
        data.resize(512, 0);
        tar.extend_from_slice(&data);
        assert_eq!(tar_file(&tar, "boot/k"), Some(&b"hello"[..]));
        assert_eq!(tar_file(&tar, "a"), Some(&b"xxx"[..]));
        assert_eq!(tar_file(&tar, "nope"), None);
    }

    #[test]
    fn results_keep_the_largest_run() {
        let log = "ichor-bench: null-syscall n=1000 ns=5000\n\
                   noise\n\
                   ichor-bench: null-syscall n=201000 ns=1005000\n";
        let r = results(log);
        assert_eq!(r["null-syscall"], (201_000, 1_005_000));
        assert_eq!(per_op(201_000, 1_005_000), "5 ns");
        assert_eq!(per_op(10, 1_000_000), "100.0 us");
    }
}
