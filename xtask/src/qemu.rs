//! Booting the kernel under QEMU + OVMF.
//!
//! The kernel is a UEFI application, so a run needs only firmware and a FAT
//! volume laid out like an EFI system partition:
//!
//! ```text
//! esp/EFI/BOOT/BOOTX64.EFI   the kernel
//! esp/ichor/cmdline          the kernel command line
//! esp/ichor/roots.pem        the control plane's CA bundle (Mozilla's, pinned)
//! esp/ichor/apitoken         the control plane's API token (when configured)
//! root.img                   the root image, attached as virtio-blk and NVMe disks
//! ```
//!
//! OVMF finds `BOOTX64.EFI` through the removable-media boot path, so no boot
//! entries need to be configured.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

use crate::{Result, workspace_root};

/// Hardware acceleration for QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accel {
    /// KVM if `/dev/kvm` is usable, otherwise TCG.
    Auto,
    Kvm,
    Whpx,
    Hvf,
    Tcg,
}

impl std::str::FromStr for Accel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "auto" => Accel::Auto,
            "kvm" => Accel::Kvm,
            "whpx" => Accel::Whpx,
            "hvf" => Accel::Hvf,
            "tcg" => Accel::Tcg,
            _ => return Err(format!("unknown accelerator {s:?} (auto|kvm|whpx|hvf|tcg)")),
        })
    }
}

impl Accel {
    /// Resolves `Auto` to a concrete accelerator.
    pub fn resolve(self) -> Accel {
        if self != Accel::Auto {
            return self;
        }
        if let Ok(a) = env::var("ICHOR_ACCEL")
            && let Ok(a) = a.parse::<Accel>()
            && a != Accel::Auto
        {
            return a;
        }
        let kvm_usable = cfg!(target_os = "linux")
            && fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .is_ok();
        if kvm_usable { Accel::Kvm } else { Accel::Tcg }
    }

    /// The `-accel` value. TCG's translation buffer is 256 MiB rather than
    /// QEMU's 1 GiB default: every boot test runs at once, and eleven
    /// default buffers exhausted a shared machine's commit limit.
    pub fn qemu_name(self) -> &'static str {
        match self {
            Accel::Auto | Accel::Tcg => "tcg,tb-size=256",
            Accel::Kvm => "kvm",
            Accel::Whpx => "whpx",
            Accel::Hvf => "hvf",
        }
    }

    /// The `-cpu` model.
    pub fn cpu_model(self) -> &'static str {
        match self {
            Accel::Kvm | Accel::Hvf => "host",
            _ => "max",
        }
    }
}

/// A pair of OVMF firmware images.
#[derive(Clone, Debug)]
pub struct Firmware {
    /// Read-only code volume.
    pub code: PathBuf,
    /// Template for the writable variable store (copied per run).
    pub vars: PathBuf,
}

/// Locates the QEMU binary: `$ICHOR_QEMU`, then `PATH`, then the default
/// Windows install location.
pub fn find_qemu() -> Result<PathBuf> {
    if let Some(p) = env::var_os("ICHOR_QEMU") {
        return Ok(PathBuf::from(p));
    }
    let exe = if cfg!(windows) {
        "qemu-system-x86_64.exe"
    } else {
        "qemu-system-x86_64"
    };
    if let Some(path) = env::var_os("PATH") {
        for dir in env::split_paths(&path) {
            let candidate = dir.join(exe);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let windows_default = Path::new(r"C:\Program Files\qemu").join(exe);
    if windows_default.is_file() {
        return Ok(windows_default);
    }
    Err("qemu-system-x86_64 not found; install QEMU or set ICHOR_QEMU".into())
}

/// Locates OVMF: `$ICHOR_OVMF_CODE`/`$ICHOR_OVMF_VARS`, then the usual distro
/// locations, then the edk2 images QEMU ships in its own `share` directory.
pub fn find_firmware(qemu: &Path) -> Result<Firmware> {
    if let (Some(code), Some(vars)) = (
        env::var_os("ICHOR_OVMF_CODE"),
        env::var_os("ICHOR_OVMF_VARS"),
    ) {
        return Ok(Firmware {
            code: code.into(),
            vars: vars.into(),
        });
    }
    let mut candidates: Vec<(PathBuf, PathBuf)> = [
        (
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/OVMF/OVMF_VARS_4M.fd",
        ),
        (
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/OVMF/OVMF_VARS.fd",
        ),
        (
            "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
            "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
        ),
        (
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ),
        (
            "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
            "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
        ),
    ]
    .iter()
    .map(|(c, v)| (PathBuf::from(c), PathBuf::from(v)))
    .collect();
    let mut share_dirs = vec![
        PathBuf::from("/usr/share/qemu"),
        PathBuf::from("/usr/local/share/qemu"),
        PathBuf::from("/opt/homebrew/share/qemu"),
    ];
    if let Some(dir) = qemu.parent() {
        share_dirs.insert(0, dir.join("share"));
    }
    for dir in share_dirs {
        // QEMU uses the i386 variable store template for x86_64 too.
        candidates.push((
            dir.join("edk2-x86_64-code.fd"),
            dir.join("edk2-i386-vars.fd"),
        ));
    }
    candidates
        .into_iter()
        .find(|(c, v)| c.is_file() && v.is_file())
        .map(|(code, vars)| Firmware { code, vars })
        .ok_or_else(|| {
            "OVMF firmware not found; install ovmf/edk2-ovmf or set ICHOR_OVMF_CODE and ICHOR_OVMF_VARS"
                .into()
        })
}

/// Everything needed to boot the kernel once.
#[derive(Clone, Debug)]
pub struct RunConfig {
    /// Names the run directory under `target/qemu/`.
    pub name: String,
    /// Path to `ichor.efi`.
    pub kernel: PathBuf,
    /// Contents of `\ichor\cmdline`.
    pub cmdline: String,
    pub smp: u32,
    pub memory_mib: u32,
    pub accel: Accel,
    /// Kill QEMU after this long.
    pub timeout: Option<Duration>,
    /// Capture serial output (tests) instead of attaching it to the terminal.
    pub capture: bool,
    /// Extra raw QEMU arguments.
    pub extra_args: Vec<String>,
    /// Show a window (GTK, serial console in it) instead of serial on stdio.
    pub window: bool,
    /// Boot this whole-disk image (GPT: ESP + Ichor root, see `disk.rs`)
    /// from an NVMe controller, as a cloud VM does, instead of the vvfat
    /// ESP and the separate test disks. `cmdline` is then ignored: the
    /// image carries its own.
    pub disk_image: Option<PathBuf>,
    /// Disk mode: extra properties for the boot NVMe controller (for
    /// example `mdts=1`, a small maximum transfer).
    pub disk_nvme_props: String,
    /// Disk mode: put the boot disk on a virtio-scsi controller (as GCP's
    /// general-purpose machine types attach theirs) instead of NVMe, at
    /// this SCSI target.
    pub disk_scsi_target: Option<u8>,
    /// Disk mode: QEMU arguments placed before the boot disk, so devices
    /// they add come first in PCI order (a blank volume ahead of the boot
    /// disk, as instance storage can be).
    pub disk_devices_before: Vec<String>,
    /// Extra `-machine q35,...` properties (for example `pit=off,hpet=off`:
    /// legacy timers some cloud VMs lack).
    pub machine_props: String,
    /// `-smp` topology beyond the CPU count (for example
    /// `sockets=2,cores=3`, which gives sparse APIC ids as multi-socket
    /// cloud hosts do).
    pub smp_topology: String,
    /// Extra options for the user-mode network backend (for example
    /// `hostfwd=tcp:127.0.0.1:8080-:80`).
    pub net_user_opts: String,
    /// The control plane's API token, written to `\ichor\apitoken`.
    pub api_token: Option<String>,
}

impl RunConfig {
    /// A virtio-net device on QEMU's user-mode network (slirp: the guest
    /// is 10.0.2.15, the gateway 10.0.2.2, which reaches the host's
    /// loopback). No option ROM, so the firmware never tries to network
    /// boot.
    fn net_args(&self) -> [String; 4] {
        let extra = if self.net_user_opts.is_empty() {
            String::new()
        } else {
            format!(",{}", self.net_user_opts)
        };
        [
            "-netdev".into(),
            format!("user,id=net0{extra}"),
            "-device".into(),
            "virtio-net-pci,netdev=net0,disable-legacy=on,romfile=".into(),
        ]
    }

    fn machine(&self) -> String {
        if self.machine_props.is_empty() {
            "q35".into()
        } else {
            format!("q35,{}", self.machine_props)
        }
    }

    fn smp_arg(&self) -> String {
        if self.smp_topology.is_empty() {
            self.smp.to_string()
        } else {
            format!("{},{}", self.smp, self.smp_topology)
        }
    }
}

impl RunConfig {
    pub fn new(name: impl Into<String>, kernel: PathBuf) -> Self {
        Self {
            name: name.into(),
            kernel,
            cmdline: String::new(),
            smp: 2,
            memory_mib: 512,
            accel: Accel::Auto,
            timeout: None,
            capture: false,
            extra_args: Vec::new(),
            window: false,
            disk_image: None,
            disk_nvme_props: String::new(),
            disk_scsi_target: None,
            disk_devices_before: Vec::new(),
            machine_props: String::new(),
            smp_topology: String::new(),
            net_user_opts: String::new(),
            api_token: None,
        }
    }
}

/// How a run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Kernel reported success through `isa-debug-exit`.
    Success,
    /// Kernel reported failure (for example a panic) through `isa-debug-exit`.
    Failure,
    /// QEMU exited with some other status (QEMU error, or killed by a signal
    /// when `None`).
    Other(Option<i32>),
    /// The run exceeded its timeout and was killed.
    Timeout,
}

/// The result of a run.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub exit: Exit,
    /// Everything the guest wrote to the serial port (when captured).
    pub serial: String,
    pub elapsed: Duration,
}

impl Outcome {
    /// Panics with the serial log unless the kernel reported success.
    pub fn assert_exit(&self, expected: Exit) {
        assert_eq!(
            self.exit, expected,
            "unexpected exit after {:?}; serial log:\n{}",
            self.elapsed, self.serial
        );
    }

    /// Panics unless each marker appears in the serial log, in order.
    pub fn assert_in_order(&self, markers: &[&str]) {
        let mut rest = self.serial.as_str();
        for marker in markers {
            match rest.find(marker) {
                Some(i) => rest = &rest[i + marker.len()..],
                None => panic!(
                    "serial log missing {marker:?} (after previous markers); serial log:\n{}",
                    self.serial
                ),
            }
        }
    }
}

/// QEMU's `-drive` option parser treats `,` as a separator; a literal comma
/// in a path is written as `,,`.
fn drive_path(p: &Path) -> String {
    p.to_string_lossy().replace(',', ",,")
}

/// Lays out the ESP for a run and returns the run directory.
fn prepare_run_dir(cfg: &RunConfig, fw: &Firmware) -> Result<PathBuf> {
    let dir = workspace_root().join("target").join("qemu").join(&cfg.name);
    let esp = dir.join("esp");
    if esp.exists() {
        fs::remove_dir_all(&esp).map_err(|e| format!("cleaning {}: {e}", esp.display()))?;
    }
    let boot = esp.join("EFI").join("BOOT");
    let cfg_dir = esp.join("ichor");
    for d in [&boot, &cfg_dir] {
        fs::create_dir_all(d).map_err(|e| format!("creating {}: {e}", d.display()))?;
    }
    fs::copy(&cfg.kernel, boot.join("BOOTX64.EFI"))
        .map_err(|e| format!("copying kernel {}: {e}", cfg.kernel.display()))?;
    fs::write(cfg_dir.join("cmdline"), &cfg.cmdline)
        .map_err(|e| format!("writing cmdline: {e}"))?;
    fs::write(
        cfg_dir.join("roots.pem"),
        crate::artifact::MOZILLA_ROOTS.bytes()?,
    )
    .map_err(|e| format!("writing roots.pem: {e}"))?;
    if let Some(t) = &cfg.api_token {
        fs::write(cfg_dir.join("apitoken"), t).map_err(|e| format!("writing apitoken: {e}"))?;
    }
    fs::write(dir.join("root.img"), root_image()?)
        .map_err(|e| format!("writing root image: {e}"))?;
    fs::write(dir.join("alpine.img"), alpine_image()?)
        .map_err(|e| format!("writing root image: {e}"))?;
    fs::copy(&fw.vars, dir.join("vars.fd"))
        .map_err(|e| format!("copying OVMF vars {}: {e}", fw.vars.display()))?;
    Ok(dir)
}

/// Text of `/usr/share/motd` on the root disk; tests look for it.
pub const DISK_MOTD: &str = "hello from /etc/motd on the root disk\n";

/// Size of `/usr/share/pattern`, large enough that reading the disk takes
/// several requests and multi-page DMA buffers.
pub const DISK_PATTERN_LEN: usize = 300 * 1024;

/// Byte `i` of `/usr/share/pattern` (the kernel checks the same formula).
pub fn pattern_byte(i: usize) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 9)) as u8
}

/// Busybox applets linked into `/bin` on the root disk.
pub const BUSYBOX_APPLETS: &[&str] = &[
    "cat", "echo", "grep", "head", "ls", "sh", "sleep", "true", "wc", "yes",
];

/// The root disk: an Ichor image with `/usr/share/motd`,
/// `/etc/motd -> /usr/share/motd`, `/usr/share/pattern`, and a static
/// busybox at `/bin/busybox` with applet symlinks.
pub fn root_image() -> Result<Vec<u8>> {
    let busybox = crate::artifact::BUSYBOX.bytes()?;
    let mut b = image::builder::Builder::new();
    let mut bin = alloc_bin(&mut b, &busybox);
    bin.sort_by(|a, b| a.0.cmp(b.0));
    let bin_ids: Vec<_> = bin.into_iter().map(|(_, id)| id).collect();
    let bin = b.dir("bin", &bin_ids, 0o755);
    let motd = b.file("motd", DISK_MOTD.as_bytes(), 0o644);
    let data: Vec<u8> = (0..DISK_PATTERN_LEN).map(pattern_byte).collect();
    let pattern = b.file("pattern", &data, 0o644);
    let share = b.dir("share", &[motd, pattern], 0o755);
    let usr = b.dir("usr", &[share], 0o755);
    let link = b.symlink("motd", "/usr/share/motd");
    let etc = b.dir("etc", &[link], 0o755);
    let root = b.dir("/", &[bin, etc, usr], 0o755);
    let mut img = b.finish(root);
    // Whole 4 KiB blocks, so it also fits a 4Kn NVMe namespace.
    img.resize(img.len().next_multiple_of(4096), 0);
    Ok(img)
}

/// `/bin` entries: busybox itself and one symlink per applet, by name.
fn alloc_bin(
    b: &mut image::builder::Builder,
    busybox: &[u8],
) -> Vec<(&'static str, image::builder::NodeId)> {
    let mut v = vec![("busybox", b.file("busybox", busybox, 0o755))];
    for &a in BUSYBOX_APPLETS {
        v.push((a, b.symlink(a, "busybox")));
    }
    v
}

/// Alpine's minirootfs as an Ichor image: the root of a second cell.
pub fn alpine_image() -> Result<Vec<u8>> {
    let tgz = crate::artifact::ALPINE_MINIROOTFS.bytes()?;
    let tar = crate::inflate::gunzip(&tgz)?;
    let mut t = crate::rootfs::Tree::new();
    t.add_tar(&tar)?;
    // A local package mirror for `apk`.
    for a in crate::artifact::ALPINE_PACKAGES {
        t.add_file(&format!("/mirror/{}", a.file), &a.bytes()?, 0o644)?;
    }
    Ok(t.image())
}

/// Debian bookworm-slim (pinned layer) as an Ichor image: the root of a
/// third cell. Built once per image-format version and cached under
/// `target/debian/` (it is large), then attached read-only by every run.
pub fn debian_image_path() -> Result<std::path::PathBuf> {
    static BUILT: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);
    let mut built = BUILT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(p) = built.as_ref() {
        return Ok(p.clone());
    }
    let a = &crate::artifact::DEBIAN_BOOKWORM_SLIM;
    let dir = workspace_root().join("target").join(a.dir);
    // Bump MIRROR when the local repository's contents change.
    const MIRROR: u32 = 1;
    let path = dir.join(format!(
        "debian-{}-v{}-m{MIRROR}.img",
        &a.sha256[..12],
        image::VERSION
    ));
    if !path.exists() {
        let tar = crate::inflate::gunzip(&a.bytes()?)?;
        let mut t = crate::rootfs::Tree::new();
        t.add_tar(&tar)?;
        // A local repository for `apt` instead of deb.debian.org (there is
        // no network): the pinned .debs and a Packages index.
        let mut index = String::new();
        for d in crate::artifact::DEBIAN_PACKAGES {
            let bytes = d.artifact.bytes()?;
            t.add_file(&format!("/mirror/{}", d.artifact.file), &bytes, 0o644)?;
            index.push_str(&format!(
                "Package: {}\nVersion: {}\nArchitecture: amd64\nMaintainer: Debian\n\
                 Depends: {}\nFilename: ./{}\nSize: {}\nSHA256: {}\n\
                 Description: pinned test package\n\n",
                d.package,
                d.version,
                d.depends,
                d.artifact.file,
                bytes.len(),
                d.artifact.sha256
            ));
        }
        t.add_file("/mirror/Packages", index.as_bytes(), 0o644)?;
        t.add_file("/etc/apt/sources.list.d/debian.sources", b"", 0o644)?;
        t.add_file(
            "/etc/apt/sources.list.d/mirror.list",
            b"deb [trusted=yes] file:/mirror ./\n",
            0o644,
        )?;
        let partial = dir.join(format!("debian.img.partial.{}", std::process::id()));
        fs::write(&partial, t.image())
            .map_err(|e| format!("writing {}: {e}", partial.display()))?;
        fs::rename(&partial, &path).map_err(|e| format!("caching {}: {e}", path.display()))?;
    }
    *built = Some(path.clone());
    Ok(path)
}

/// Builds the QEMU command line for a run.
pub fn command(cfg: &RunConfig) -> Result<Command> {
    let qemu = find_qemu()?;
    let fw = find_firmware(&qemu)?;
    if let Some(img) = &cfg.disk_image {
        return disk_command(cfg, &qemu, &fw, img);
    }
    let dir = prepare_run_dir(cfg, &fw)?;
    let accel = cfg.accel.resolve();

    let mut cmd = Command::new(&qemu);
    // vvfat takes the directory after a `fat:` prefix; a Windows drive
    // letter's colon confuses it, so pass a path relative to the workspace.
    cmd.current_dir(workspace_root());
    let esp_rel = dir
        .join("esp")
        .strip_prefix(workspace_root())
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .map_err(|_| "run directory is outside the workspace".to_string())?;

    cmd.args(["-machine", &cfg.machine(), "-accel", accel.qemu_name()])
        .args(["-cpu", accel.cpu_model()])
        .args(["-smp", &cfg.smp_arg()])
        .args(["-m", &format!("{}M", cfg.memory_mib)])
        .args(["-nodefaults", "-no-user-config", "-no-reboot"])
        .args(if cfg.window {
            ["-display", "gtk,show-tabs=on", "-serial", "vc"]
        } else {
            ["-display", "none", "-serial", "stdio"]
        })
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            drive_path(&fw.code)
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=1,file={}",
            drive_path(&dir.join("vars.fd"))
        ))
        .arg("-drive")
        .arg(format!("if=none,id=esp,format=raw,file=fat:rw:{esp_rel}"))
        // Boot from the ESP first; OVMF would otherwise try the root disk.
        .args(["-device", "ide-hd,drive=esp,bus=ide.0,bootindex=0"])
        .arg("-drive")
        .arg(format!(
            "if=none,id=root,format=raw,readonly=on,file={}",
            drive_path(&dir.join("root.img"))
        ))
        .args(["-device", "virtio-blk-pci,drive=root,disable-legacy=on"])
        .args(["-device", "virtio-rng-pci,disable-legacy=on"])
        .args(cfg.net_args())
        // Alpine's root file system, for a cell that runs its userland.
        .arg("-drive")
        .arg(format!(
            "if=none,id=alpine,format=raw,readonly=on,file={}",
            drive_path(&dir.join("alpine.img"))
        ))
        .args(["-device", "virtio-blk-pci,drive=alpine,disable-legacy=on"])
        // Debian's root file system (glibc), for a cell that runs it.
        .arg("-drive")
        .arg(format!(
            "if=none,id=debian,format=raw,readonly=on,file={}",
            drive_path(&debian_image_path()?)
        ))
        .args(["-device", "virtio-blk-pci,drive=debian,disable-legacy=on"])
        // The same image again on an NVMe controller (both read-only).
        .arg("-drive")
        .arg(format!(
            "if=none,id=nvme0,format=raw,readonly=on,file={}",
            drive_path(&dir.join("root.img"))
        ))
        .args([
            "-device",
            "nvme,serial=ichor0,drive=nvme0,logical_block_size=4096,physical_block_size=4096",
        ])
        .args(&cfg.extra_args);
    Ok(cmd)
}

/// The QEMU command for booting a whole-disk image: OVMF, the image on an
/// NVMe controller (512-byte blocks, the boot device), virtio-rng, and
/// nothing else: what a cloud VM gives the guest, minus the network.
fn disk_command(cfg: &RunConfig, qemu: &Path, fw: &Firmware, img: &Path) -> Result<Command> {
    let dir = workspace_root().join("target").join("qemu").join(&cfg.name);
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    fs::copy(&fw.vars, dir.join("vars.fd"))
        .map_err(|e| format!("copying OVMF vars {}: {e}", fw.vars.display()))?;
    let accel = cfg.accel.resolve();
    let mut cmd = Command::new(qemu);
    cmd.args(["-machine", &cfg.machine(), "-accel", accel.qemu_name()])
        .args(["-cpu", accel.cpu_model()])
        .args(["-smp", &cfg.smp_arg()])
        .args(["-m", &format!("{}M", cfg.memory_mib)])
        .args(["-nodefaults", "-no-user-config", "-no-reboot"])
        .args(["-display", "none", "-serial", "stdio"])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            drive_path(&fw.code)
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,unit=1,file={}",
            drive_path(&dir.join("vars.fd"))
        ))
        .args(&cfg.disk_devices_before)
        .arg("-drive")
        .arg(format!(
            "if=none,id=disk,format=raw,readonly=on,file={}",
            drive_path(img)
        ))
        .arg("-device")
        .arg(match cfg.disk_scsi_target {
            // On the virtio-scsi controller the test's earlier devices
            // may have added (`scsi0`), or one of its own.
            Some(t) => format!("scsi-hd,drive=disk,bus=scsi0.0,scsi-id={t},bootindex=0"),
            None => format!(
                "nvme,serial=ichor-boot,drive=disk,bootindex=0{}{}",
                if cfg.disk_nvme_props.is_empty() {
                    ""
                } else {
                    ","
                },
                cfg.disk_nvme_props
            ),
        })
        .args(["-device", "virtio-rng-pci,disable-legacy=on"])
        .args(cfg.net_args())
        .args(&cfg.extra_args);
    Ok(cmd)
}

/// Boots the kernel and waits for QEMU to exit (or the timeout).
pub fn run(cfg: &RunConfig) -> Result<Outcome> {
    run_command(command(cfg)?, cfg.capture, cfg.timeout)
}

/// A loopback port nothing listens on right now.
fn free_port() -> Option<u16> {
    let l = TcpListener::bind(("127.0.0.1", 0)).ok()?;
    l.local_addr().ok().map(|a| a.port())
}

/// What QEMU's human monitor on `port` answers to each command (with a
/// half-second silence taken as the end of an answer).
fn monitor(port: u16, commands: &[String]) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    for c in core::iter::once("").chain(commands.iter().map(String::as_str)) {
        if !c.is_empty() {
            s.write_all(format!("{c}\n").as_bytes())?;
        }
        while let Ok(n) = s.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Where every vCPU of a run that will not end is: registers twice, a
/// second apart (does it move? is it halted?), its local APIC's timer and
/// pending interrupts, and the top of its stack.
fn vcpu_state(port: u16) -> String {
    let regs = ["info registers -a".to_string()];
    let first = match monitor(port, &regs) {
        Ok(t) => t,
        Err(e) => return format!("(no monitor: {e})"),
    };
    thread::sleep(Duration::from_secs(1));
    let cpus = first.matches("CPU#").count();
    let mut commands = regs.to_vec();
    for n in 0..cpus {
        commands.push(format!("cpu {n}"));
        commands.push("info lapic".into());
        commands.push("x /8i $rip".into());
        commands.push("x /96gx $rsp".into());
    }
    let second = monitor(port, &commands).unwrap_or_else(|e| format!("(monitor: {e})"));
    format!("{first}\n--- one second later ---\n{second}")
}

/// Runs a prepared QEMU command to exit (or `timeout`), capturing its
/// serial output on stdout if `capture`. A run that times out has its
/// vCPUs' state ([`vcpu_state`]) appended to the captured output.
pub fn run_command(mut cmd: Command, capture: bool, timeout: Option<Duration>) -> Result<Outcome> {
    let monitor_port = timeout
        .filter(|_| capture)
        .and_then(|_| free_port())
        .inspect(|port| {
            cmd.arg("-monitor")
                .arg(format!("tcp:127.0.0.1:{port},server=on,wait=off"));
        });
    let mut stuck = String::new();
    if capture {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
    }
    let echo = env::var_os("ICHOR_TEST_VERBOSE").is_some();
    let start = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to start QEMU: {e}"))?;

    let serial = Arc::new(Mutex::new(Vec::<u8>::new()));
    let reader = child.stdout.take().map(|mut out| {
        let serial = Arc::clone(&serial);
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = out.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if echo {
                    eprint!("{}", String::from_utf8_lossy(&buf[..n]));
                }
                serial.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        })
    });

    let exit = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("waiting for QEMU: {e}"))?
        {
            break match status.code() {
                Some(33) => Exit::Success,
                Some(35) => Exit::Failure,
                code => Exit::Other(code),
            };
        }
        if timeout.is_some_and(|t| start.elapsed() > t) {
            if let Some(port) = monitor_port {
                stuck = format!(
                    "\n=== vCPUs at the timeout ===\n{}\n",
                    vcpu_state(port).replace('\r', "")
                );
            }
            let _ = child.kill();
            let _ = child.wait();
            break Exit::Timeout;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let elapsed = start.elapsed();
    if let Some(reader) = reader {
        let _ = reader.join();
    }
    let mut serial = String::from_utf8_lossy(&serial.lock().unwrap()).into_owned();
    serial.push_str(&stuck);
    Ok(Outcome {
        exit,
        serial,
        elapsed,
    })
}
