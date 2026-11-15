//! `cargo xtask <command>`: see `cargo xtask help`.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // host tool

use std::process::ExitCode;
use std::time::Duration;

use xtask::build::{self, KERNEL_TARGET, Profile};
use xtask::qemu::{self, Accel, Exit, RunConfig};
use xtask::{Result, audit, cargo, linux_abi, run_cmd};

const HELP: &str = "\
cargo xtask <command> [options]

Commands:
  build        Build the kernel (target/kernel/x86_64-unknown-uefi/<profile>/ichor.efi)
  run          Build and boot the kernel in QEMU + OVMF, serial on stdio
  test         Host unit tests, then QEMU integration tests (tests/)
  lint         rustfmt check, clippy (host + kernel target), unsafe policy, frame budget
  frame-audit  Print frame's size and unsafe-site count; fail if over budget
  linux-abi-table  Regenerate docs/linux-abi.md from the Linux syscall table
  help         Show this message

Options:
  --release              Build the kernel with the release profile
  --accel <a>            auto|kvm|whpx|hvf|tcg (default auto: KVM if usable, else TCG)
  --cmdline <text>       Kernel command line for `run` (default: qemu_debug_exit)
  --smp <n>              vCPUs for `run` (default 2)
  --memory <MiB>         Guest memory for `run` (default 512)
  --timeout <secs>       Kill QEMU after this long (`run` only; default none)
  --gdb                  `run`: wait for a debugger on tcp::1234
  -- <args>              Extra arguments passed to QEMU (`run`)

Environment:
  ICHOR_QEMU, ICHOR_OVMF_CODE, ICHOR_OVMF_VARS   override tool discovery
  ICHOR_ACCEL                                    default accelerator
  ICHOR_TEST_VERBOSE=1                           echo guest serial during tests
";

#[derive(Debug)]
struct Opts {
    profile: Profile,
    accel: Accel,
    cmdline: String,
    smp: u32,
    memory_mib: u32,
    timeout: Option<Duration>,
    gdb: bool,
    extra: Vec<String>,
}

fn parse(args: &[String]) -> Result<Opts> {
    let mut o = Opts {
        profile: Profile::Dev,
        accel: Accel::Auto,
        cmdline: "qemu_debug_exit".into(),
        smp: 2,
        memory_mib: 512,
        timeout: None,
        gdb: false,
        extra: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--release" => o.profile = Profile::Release,
            "--accel" => o.accel = value("--accel")?.parse()?,
            "--cmdline" => o.cmdline = value("--cmdline")?,
            "--smp" => o.smp = value("--smp")?.parse().map_err(|e| format!("--smp: {e}"))?,
            "--memory" => {
                o.memory_mib = value("--memory")?
                    .parse()
                    .map_err(|e| format!("--memory: {e}"))?
            }
            "--timeout" => {
                let secs: u64 = value("--timeout")?
                    .parse()
                    .map_err(|e| format!("--timeout: {e}"))?;
                o.timeout = Some(Duration::from_secs(secs));
            }
            "--gdb" => o.gdb = true,
            "--" => {
                o.extra.extend(it.by_ref().cloned());
                break;
            }
            other => return Err(format!("unknown option {other:?}; see `cargo xtask help`")),
        }
    }
    Ok(o)
}

fn cmd_run(o: &Opts) -> Result<()> {
    let kernel = build::kernel(o.profile)?;
    let mut cfg = RunConfig::new("run", kernel);
    cfg.cmdline = o.cmdline.clone();
    cfg.smp = o.smp;
    cfg.memory_mib = o.memory_mib;
    cfg.accel = o.accel;
    cfg.timeout = o.timeout;
    cfg.extra_args = o.extra.clone();
    if o.gdb {
        cfg.extra_args.extend(["-s".into(), "-S".into()]);
        eprintln!("xtask: waiting for gdb on tcp::1234");
    }
    eprintln!("xtask: booting with accel={:?}", cfg.accel.resolve());
    let out = qemu::run(&cfg)?;
    eprintln!(
        "xtask: QEMU exited after {:.2?}: {:?}",
        out.elapsed, out.exit
    );
    match out.exit {
        Exit::Success => Ok(()),
        Exit::Other(Some(0)) => Ok(()),
        other => Err(format!("kernel run ended with {other:?}")),
    }
}

/// Crates that only build for the kernel target (they depend on frame).
const KERNEL_ONLY: &[&str] = &[
    "ichor",
    "ichor-frame",
    "ichor-virtio-pci",
    "ichor-virtio-blk",
    "ichor-virtio-rng",
    "ichor-nvme",
];

fn exclude_kernel_only(cmd: &mut std::process::Command) -> &mut std::process::Command {
    for c in KERNEL_ONLY {
        cmd.args(["--exclude", c]);
    }
    cmd
}

fn cmd_test(o: &Opts) -> Result<()> {
    // CI sets ICHOR_REQUIRE_KVM=1: a silent fallback to TCG would hide
    // timing problems and make the suite slow. QEMU itself fails rather than
    // falling back when `-accel kvm` cannot start, so this check suffices.
    let accel = o.accel.resolve();
    println!("xtask: QEMU tests will use accel={accel:?}");
    if std::env::var("ICHOR_REQUIRE_KVM").as_deref() == Ok("1") && accel != Accel::Kvm {
        return Err(format!(
            "ICHOR_REQUIRE_KVM=1 but the accelerator is {accel:?}: /dev/kvm is missing or not usable"
        ));
    }
    // Host unit tests for every host-buildable crate except the QEMU suite.
    run_cmd(exclude_kernel_only(cargo().args([
        "test",
        "--workspace",
        "--exclude",
        "ichor-tests",
    ])))?;
    // Build the kernel and fetch the test busybox once, then hand both to
    // the integration tests.
    let kernel = build::kernel(o.profile)?;
    xtask::artifact::BUSYBOX.bytes()?;
    xtask::artifact::ALPINE_MINIROOTFS.bytes()?;
    for a in xtask::artifact::ALPINE_PACKAGES {
        a.bytes()?;
    }
    let mut cmd = cargo();
    cmd.args(["test", "--package", "ichor-tests"]);
    if std::env::var_os("ICHOR_TEST_VERBOSE").is_some() {
        cmd.args(["--", "--nocapture"]);
    }
    cmd.env("ICHOR_KERNEL", &kernel).env(
        "ICHOR_ACCEL",
        format!("{:?}", o.accel.resolve()).to_lowercase(),
    );
    run_cmd(&mut cmd)
}

fn cmd_lint() -> Result<()> {
    run_cmd(cargo().args(["fmt", "--all", "--check"]))?;
    run_cmd(
        exclude_kernel_only(cargo().args(["clippy", "--workspace"])).args([
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ]),
    )?;
    let mut kernel_clippy = cargo();
    kernel_clippy.arg("clippy");
    for c in KERNEL_ONLY {
        kernel_clippy.args(["--package", c]);
    }
    run_cmd(
        kernel_clippy
            .args(["--target", KERNEL_TARGET])
            .arg("--target-dir")
            .arg(build::kernel_target_dir())
            .args(["--", "-D", "warnings"]),
    )?;
    audit::check_forbid_unsafe()?;
    audit::check_frame_budget()?;
    linux_abi::check_table()?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = args
        .split_first()
        .map_or(("help", &[][..]), |(c, r)| (c.as_str(), r));
    let result = parse(rest).and_then(|o| match command {
        "build" => build::kernel(o.profile).map(|p| println!("{}", p.display())),
        "run" => cmd_run(&o),
        "test" => cmd_test(&o),
        "lint" => cmd_lint(),
        "frame-audit" => audit::check_frame_budget().map(|_| ()),
        "linux-abi-table" => linux_abi::write_table(),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n\n{HELP}")),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: error: {e}");
            ExitCode::FAILURE
        }
    }
}
