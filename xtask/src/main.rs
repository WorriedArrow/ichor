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

fn cmd_test(o: &Opts) -> Result<()> {
    // Host unit tests for every host-buildable crate except the QEMU suite.
    run_cmd(cargo().args([
        "test",
        "--workspace",
        "--exclude",
        "ichor-tests",
        "--exclude",
        "ichor",
        "--exclude",
        "ichor-frame",
    ]))?;
    // Build the kernel once, then hand it to the integration tests.
    let kernel = build::kernel(o.profile)?;
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
    run_cmd(cargo().args([
        "clippy",
        "--workspace",
        "--exclude",
        "ichor",
        "--exclude",
        "ichor-frame",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(
        cargo()
            .args([
                "clippy",
                "--package",
                "ichor",
                "--package",
                "ichor-frame",
                "--target",
                KERNEL_TARGET,
            ])
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
