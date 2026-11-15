//! Booting the kernel under QEMU + OVMF.
//!
//! The kernel is a UEFI application, so a run needs only firmware and a FAT
//! volume laid out like an EFI system partition:
//!
//! ```text
//! esp/EFI/BOOT/BOOTX64.EFI   the kernel
//! esp/ichor/cmdline          the kernel command line
//! root.img                   the root image, attached as a virtio-blk disk
//! ```
//!
//! OVMF finds `BOOTX64.EFI` through the removable-media boot path, so no boot
//! entries need to be configured.

use std::io::Read;
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

    fn qemu_name(self) -> &'static str {
        match self {
            Accel::Auto | Accel::Tcg => "tcg",
            Accel::Kvm => "kvm",
            Accel::Whpx => "whpx",
            Accel::Hvf => "hvf",
        }
    }

    fn cpu_model(self) -> &'static str {
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
    fs::write(dir.join("root.img"), root_image())
        .map_err(|e| format!("writing root image: {e}"))?;
    fs::copy(&fw.vars, dir.join("vars.fd"))
        .map_err(|e| format!("copying OVMF vars {}: {e}", fw.vars.display()))?;
    Ok(dir)
}

/// Text of `/usr/share/motd` on the root disk; tests look for it.
pub const DISK_MOTD: &str = "hello from /etc/motd on a virtio-blk disk
";

/// Size of `/usr/share/pattern`, large enough that reading the disk takes
/// several requests and multi-page DMA buffers.
pub const DISK_PATTERN_LEN: usize = 300 * 1024;

/// Byte `i` of `/usr/share/pattern` (the kernel checks the same formula).
pub fn pattern_byte(i: usize) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 9)) as u8
}

/// The root disk: an Ichor image with `/usr/share/motd`,
/// `/etc/motd -> /usr/share/motd` and `/usr/share/pattern`, padded to
/// whole sectors.
pub fn root_image() -> Vec<u8> {
    let mut b = image::builder::Builder::new();
    let motd = b.file("motd", DISK_MOTD.as_bytes(), 0o644);
    let data: Vec<u8> = (0..DISK_PATTERN_LEN).map(pattern_byte).collect();
    let pattern = b.file("pattern", &data, 0o644);
    let share = b.dir("share", &[motd, pattern], 0o755);
    let usr = b.dir("usr", &[share], 0o755);
    let link = b.symlink("motd", "/usr/share/motd");
    let etc = b.dir("etc", &[link], 0o755);
    let root = b.dir("/", &[etc, usr], 0o755);
    let mut img = b.finish(root);
    img.resize(img.len().next_multiple_of(512), 0);
    img
}

/// Builds the QEMU command line for a run.
pub fn command(cfg: &RunConfig) -> Result<Command> {
    let qemu = find_qemu()?;
    let fw = find_firmware(&qemu)?;
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

    cmd.args(["-machine", "q35", "-accel", accel.qemu_name()])
        .args(["-cpu", accel.cpu_model()])
        .args(["-smp", &cfg.smp.to_string()])
        .args(["-m", &format!("{}M", cfg.memory_mib)])
        .args([
            "-nodefaults",
            "-no-user-config",
            "-display",
            "none",
            "-no-reboot",
        ])
        .args(["-serial", "stdio"])
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
        .args(&cfg.extra_args);
    Ok(cmd)
}

/// Boots the kernel and waits for QEMU to exit (or the timeout).
pub fn run(cfg: &RunConfig) -> Result<Outcome> {
    let mut cmd = command(cfg)?;
    if cfg.capture {
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
        if cfg.timeout.is_some_and(|t| start.elapsed() > t) {
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
    let serial = String::from_utf8_lossy(&serial.lock().unwrap()).into_owned();
    Ok(Outcome {
        exit,
        serial,
        elapsed,
    })
}
