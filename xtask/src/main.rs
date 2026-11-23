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
  bench        Run the benchmarks on Ichor and on a pinned Linux kernel, same
               machine and programs; prints a Markdown table (CI: --smp 4)
  x509-limbo   Score services/x509 against the pinned x509-limbo suite; writes
               docs/x509-limbo.md and fails below the recorded floors
  fuzz [TARGET] [--iterations N]
               Mutation-fuzz every parser (or one); failing inputs go to
               target/fuzz/ (replay with ICHOR_FUZZ_REPLAY=FILE)
  disk-image   Write target/ichor-disk.img: a bootable GPT disk (FAT32 ESP with
               ichor.efi, Ichor root partition), for cloud import or bare metal;
               the kernel command line is --cmdline (default: empty);
               --size-gib N pads it; --gcp also writes target/ichor-gcp.tar.gz;
               --api-token-file F puts the control plane's API token on it,
               --api-tls-file F its TLS certificate and Ed25519 key (PEM)
  api HOST:PORT --name NAME --ca F --token-file F IMAGE [-- COMMAND ...]
               Have a running machine pull IMAGE and run it in a cell
               (--memory MiB: the cell's, default 256)
  help        Show this message

Options:
  --release              Build the kernel with the release profile
  --accel <a>            auto|kvm|whpx|hvf|tcg (default auto: KVM if usable, else TCG)
  --cmdline <text>       Kernel command line for `run` (default: qemu_debug_exit)
  --smp <n>              vCPUs for `run` (default 2)
  --memory <MiB>         Guest memory for `run` (default 512)
  --timeout <secs>       Kill QEMU after this long (`run` only; default none)
  --gdb                  `run`: wait for a debugger on tcp::1234
  --window               `run`: show a QEMU window with the serial console (run dir `window`)
  --name NAME            `run`: run directory under target/qemu/ (default `run`)
  --disk FILE            `run`: boot this disk image (from `disk-image`) from NVMe, cloud-style
  --size-gib N, --gcp    `disk-image`: pad to N GiB; also write the GCP import archive
  -- <args>              Extra arguments passed to QEMU (`run`)

Environment:
  ICHOR_QEMU, ICHOR_OVMF_CODE, ICHOR_OVMF_VARS   override tool discovery
  ICHOR_ACCEL                                    default accelerator
  ICHOR_TEST_VERBOSE=1                           echo guest serial during tests
  ICHOR_TEST_CMDLINE=<opts>                      extra kernel options for every test boot
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
    window: bool,
    name: Option<String>,
    /// `disk-image`: pad the disk to this many GiB.
    size_gib: Option<u64>,
    /// `disk-image`: also write the GCP import archive.
    gcp: bool,
    /// `disk-image`: the control plane's API token, from this file.
    api_token_file: Option<std::path::PathBuf>,
    /// `disk-image`: the API's TLS certificates and key, from this file.
    api_tls_file: Option<std::path::PathBuf>,
    /// `run`: boot this whole-disk image from NVMe instead.
    disk: Option<std::path::PathBuf>,
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
        window: false,
        name: None,
        size_gib: None,
        gcp: false,
        api_token_file: None,
        api_tls_file: None,
        disk: None,
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
            "--window" => o.window = true,
            "--name" => o.name = Some(value("--name")?),
            "--size-gib" => {
                o.size_gib = Some(
                    value("--size-gib")?
                        .parse()
                        .map_err(|e| format!("--size-gib: {e}"))?,
                )
            }
            "--gcp" => o.gcp = true,
            "--api-token-file" => o.api_token_file = Some(value("--api-token-file")?.into()),
            "--api-tls-file" => o.api_tls_file = Some(value("--api-tls-file")?.into()),
            "--disk" => o.disk = Some(value("--disk")?.into()),
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
    let name = o
        .name
        .clone()
        .unwrap_or_else(|| if o.window { "window" } else { "run" }.to_string());
    let mut cfg = RunConfig::new(name, kernel);
    cfg.cmdline = o.cmdline.clone();
    cfg.smp = o.smp;
    cfg.memory_mib = o.memory_mib;
    cfg.accel = o.accel;
    cfg.timeout = o.timeout;
    cfg.extra_args = o.extra.clone();
    cfg.window = o.window;
    cfg.disk_image = o.disk.clone();
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

/// Boots Ichor with `bench`, then Linux with the same programs, and prints
/// both kernels' per-operation costs side by side.
fn cmd_bench(o: &Opts) -> Result<()> {
    let timeout = o.timeout.unwrap_or(Duration::from_secs(900));
    let accel = o.accel.resolve();
    let mut cfg = RunConfig::new("bench", build::kernel(o.profile)?);
    cfg.cmdline = "qemu_debug_exit bench".into();
    cfg.smp = o.smp;
    cfg.memory_mib = o.memory_mib;
    cfg.accel = accel;
    cfg.timeout = Some(timeout);
    cfg.capture = true;
    eprintln!("xtask: bench: Ichor, accel={accel:?}, {} vCPUs", o.smp);
    let ichor = qemu::run(&cfg)?;
    if ichor.exit != Exit::Success {
        return Err(format!(
            "Ichor benchmark boot ended with {:?}:\n{}",
            ichor.exit, ichor.serial
        ));
    }
    eprintln!("xtask: bench: Linux (Alpine linux-virt 6.6.142)");
    let linux = xtask::linuxref::run(o.smp, o.memory_mib, accel, timeout)?;
    if !linux.serial.contains("ichor-linux-bench: done") {
        return Err(format!(
            "Linux benchmark boot ended with {:?} before finishing:\n{}",
            linux.exit, linux.serial
        ));
    }
    let (a, b) = (
        xtask::linuxref::results(&ichor.serial),
        xtask::linuxref::results(&linux.serial),
    );
    println!("| Benchmark | Ichor | Linux | Ichor / Linux |");
    println!("|---|---|---|---|");
    for (name, _, _) in testprog::bench::ALL {
        let cell = |r: &std::collections::BTreeMap<String, (u64, u64)>| {
            r.get(*name)
                .map(|&(n, ns)| (ns as f64 / n.max(1) as f64, n, ns))
        };
        match (cell(&a), cell(&b)) {
            (Some((pa, na, sa)), Some((pb, nb, sb))) => println!(
                "| {name} | {} | {} | {:.2}x |",
                xtask::linuxref::per_op(na, sa),
                xtask::linuxref::per_op(nb, sb),
                pa / pb
            ),
            _ => return Err(format!("{name}: missing from one of the runs")),
        }
    }
    for line in ichor.serial.lines() {
        if let Some(v) = line.strip_prefix("ichor: bench: container start: ") {
            println!("| container start | {v} | (no equivalent) | |");
        }
    }
    println!();
    let cpu = linux
        .serial
        .lines()
        .find_map(|l| l.strip_prefix("ichor-linux-cpu:"))
        .map_or("unknown CPU", str::trim);
    println!(
        "{} vCPUs, {} MiB, accel {accel:?}, host CPU {cpu}. Each program times its own loop; Linux runs with its default mitigations. Runners differ: compare ratios within one run.",
        o.smp, o.memory_mib
    );
    Ok(())
}

/// Writes a bootable GPT disk image. Its command line is `--cmdline` when
/// given; otherwise empty (no `qemu_debug_exit`: real hardware has no
/// debug-exit port, and the kernel then halts at the end).
fn cmd_disk_image(o: &Opts, args: &[String]) -> Result<()> {
    let cmdline = if args.iter().any(|a| a == "--cmdline") {
        o.cmdline.clone()
    } else {
        String::new()
    };
    let kernel = build::kernel(o.profile)?;
    // GCP requires a whole number of GiB; cloud volumes are sized in GiB.
    let gib = o.size_gib.unwrap_or(if o.gcp { 1 } else { 0 });
    let read = |p: &Option<std::path::PathBuf>| match p {
        Some(p) => std::fs::read(p)
            .map(Some)
            .map_err(|e| format!("reading {}: {e}", p.display())),
        None => Ok(None),
    };
    let token = read(&o.api_token_file)?;
    let tls = read(&o.api_tls_file)?;
    // What the service would refuse at boot, said now.
    if let Some(pem) = &tls {
        tls::server::Identity::from_pem(&String::from_utf8_lossy(pem))
            .map_err(|e| format!("--api-tls-file: {e:?}"))?;
    }
    let img = xtask::disk::image_sized(
        &kernel,
        &cmdline,
        gib << 30,
        token.as_deref(),
        tls.as_deref(),
    )?;
    if o.gcp && !img.len().is_multiple_of(1 << 30) {
        return Err(format!(
            "the disk is {} MiB, more than --size-gib {gib}; give a larger size",
            img.len() >> 20
        ));
    }
    let target = xtask::workspace_root().join("target");
    let path = target.join("ichor-disk.img");
    std::fs::write(&path, &img).map_err(|e| format!("writing {}: {e}", path.display()))?;
    println!(
        "{} ({} MiB, GPT: EFI system partition + Ichor root; cmdline {cmdline:?})",
        path.display(),
        img.len() >> 20
    );
    if o.gcp {
        // GCP imports `disk.raw` from a gzip'd GNU tar.
        let tgz = xtask::deflate::gzip(&xtask::deflate::tar("disk.raw", &img));
        let path = target.join("ichor-gcp.tar.gz");
        std::fs::write(&path, &tgz).map_err(|e| format!("writing {}: {e}", path.display()))?;
        println!(
            "{} ({} KiB): upload to a bucket, then `gcloud compute images create ICHOR \
             --source-uri gs://BUCKET/ichor-gcp.tar.gz --guest-os-features UEFI_COMPATIBLE`",
            path.display(),
            tgz.len() >> 10
        );
    }
    Ok(())
}

/// Crates that only build for the kernel target (they depend on frame).
const KERNEL_ONLY: &[&str] = &[
    "ichor",
    "ichor-frame",
    "ichor-virtio-pci",
    "ichor-virtio-blk",
    "ichor-virtio-rng",
    "ichor-virtio-net",
    "ichor-intel-gbe",
    "ichor-nvme",
    "ichor-virtio-scsi",
];

/// Crates that only build for the services target (the native runtime
/// and the binaries on it, ADR-0012).
const SERVICE_ONLY: &[&str] = &["ichor-rt", "ichor-nativetest", "ichor-control"];

fn exclude_kernel_only(cmd: &mut std::process::Command) -> &mut std::process::Command {
    for c in KERNEL_ONLY.iter().chain(SERVICE_ONLY) {
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
    xtask::artifact::MOZILLA_ROOTS.bytes()?;
    xtask::artifact::ALPINE_MINIROOTFS.bytes()?;
    for a in xtask::artifact::ALPINE_PACKAGES {
        a.bytes()?;
    }
    let mut cmd = cargo();
    // Every test file runs even if an earlier one failed.
    cmd.args(["test", "--no-fail-fast", "--package", "ichor-tests"]);
    if std::env::var_os("ICHOR_TEST_VERBOSE").is_some() {
        cmd.args(["--", "--nocapture"]);
    }
    cmd.env("ICHOR_KERNEL", &kernel).env(
        "ICHOR_ACCEL",
        format!("{:?}", o.accel.resolve()).to_lowercase(),
    );
    run_cmd(&mut cmd)
}

/// `cargo xtask api HOST:PORT --name NAME --ca FILE --token-file FILE
/// [--memory MiB] IMAGE [-- COMMAND ...]`: has a running machine pull
/// `IMAGE`, make a cell of it and run a command there (the image's own
/// without one); prints the output and fails if the command did.
fn cmd_api(args: &[String]) -> Result<()> {
    use std::io::Write;
    use std::time::Instant;
    use xtask::api::{Session, Trust};
    let mut it = args.iter();
    let (mut name, mut ca, mut token) = (None, None, None);
    let mut memory_mib = 256u64;
    let mut words = Vec::new();
    let mut argv = Vec::new();
    let read = |f: &str| std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"));
    while let Some(a) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--name" => name = Some(value()?.clone()),
            "--ca" => ca = Some(read(value()?)?),
            "--token-file" => token = Some(read(value()?)?.trim().to_string()),
            "--memory" => memory_mib = value()?.parse().map_err(|e| format!("--memory: {e}"))?,
            "--" => {
                argv.extend(it.by_ref().map(String::as_str));
                break;
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s:?}")),
            s => words.push(s),
        }
    }
    let [address, image] = words[..] else {
        return Err("api needs HOST:PORT and an image".into());
    };
    let trust = match (name, ca) {
        (Some(host), Some(pem)) => Some(Trust {
            roots: std::sync::Arc::new(x509::RootStore::from_pem(&pem)),
            host,
        }),
        (None, None) => None,
        _ => return Err("--name and --ca go together".into()),
    };
    if trust.is_none() && token.is_some() {
        return Err("a token goes only to a machine that proves who it is: --name and --ca".into());
    }
    let until = Instant::now() + Duration::from_secs(300);
    let mut s = Session::connect_to(address, token.as_deref(), trust.as_ref(), until)?;
    let start = Instant::now();
    let pulled = s.pull(image, Vec::new(), Duration::from_secs(1800))?;
    eprintln!(
        "api: {} is image {} ({} KiB), pulled in {:.1?}",
        pulled.digest,
        pulled.image_id,
        pulled.size / 1024,
        start.elapsed()
    );
    let cell = s.create_cell(&pulled.image_id, memory_mib << 20)?;
    eprintln!("api: cell {} at {}", cell.cell_id, cell.address);
    let day = Duration::from_secs(24 * 3600);
    let status = s.run_with(&cell.cell_id, &argv, &[], day, &mut |b| {
        let mut out = std::io::stdout();
        let _ = out.write_all(b).and_then(|()| out.flush());
    })?;
    eprintln!("api: wait status {status}");
    if status == 0 {
        Ok(())
    } else {
        Err(format!("the command ended with wait status {status}"))
    }
}

/// `cargo xtask workloads SUITE [--tests "a b"] [--cmd "shell command"]
/// [--follow FILE] [--accel A] [--cmdline "kernel options"] [--image REF]
/// [--memory MiB]`: a runtime's own test suite through the control plane
/// (ADR-0013 §2); prints the pass rate.
fn cmd_workloads(args: &[String]) -> Result<()> {
    use xtask::workloads;
    let mut it = args.iter();
    let mut suite = None;
    let (mut tests, mut cmd, mut accel) = (None, None, None);
    let (mut image, mut memory) = (None, None);
    let mut follow = None;
    let mut extra = String::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tests" => tests = Some(it.next().ok_or("--tests needs a value")?.clone()),
            "--cmd" => cmd = Some(it.next().ok_or("--cmd needs a value")?.clone()),
            "--follow" => follow = Some(it.next().ok_or("--follow needs a value")?.into()),
            "--accel" => accel = Some(it.next().ok_or("--accel needs a value")?.clone()),
            // For exploring on a machine too small for the suite's own.
            "--image" => image = Some(it.next().ok_or("--image needs a value")?.clone()),
            "--memory" => {
                let mib = it.next().and_then(|m| m.parse::<u32>().ok());
                memory = Some(mib.ok_or("--memory needs a number of MiB")?);
            }
            // Extra kernel options (`trace_errors`, `trace_pid=N`).
            "--cmdline" => extra = it.next().ok_or("--cmdline needs a value")?.clone(),
            s if !s.starts_with('-') => {
                suite = Some(
                    workloads::SUITES
                        .iter()
                        .find(|x| x.name == s)
                        .ok_or_else(|| format!("no suite {s:?}"))?,
                );
            }
            other => return Err(format!("workloads: unknown option {other:?}")),
        }
    }
    let mut suite = *suite.ok_or_else(|| {
        let names: Vec<&str> = workloads::SUITES.iter().map(|s| s.name).collect();
        format!("which suite? ({})", names.join(", "))
    })?;
    if (image.is_some() || memory.is_some()) && cmd.is_none() {
        return Err("--image and --memory go with --cmd".into());
    }
    if let Some(i) = image {
        // (The process ends with the run.)
        suite.image = Box::leak(i.into_boxed_str());
    }
    if let Some(mib) = memory {
        suite.memory_mib = mib;
        suite.cell_bytes = u64::from(mib) << 19;
    }
    let suite = &suite;
    let argv: Vec<String> = match &cmd {
        Some(c) => vec!["/bin/sh".into(), "-c".into(), c.clone()],
        None => {
            let mut v: Vec<String> = suite.argv.iter().map(|s| s.to_string()).collect();
            match &tests {
                Some(t) => v.extend(t.split_whitespace().map(str::to_string)),
                None => v.extend(suite.all.iter().map(|s| s.to_string())),
            }
            v
        }
    };
    let kernel = build::kernel(Profile::Release)?;
    let accel = match accel.as_deref() {
        Some(a) => a.parse().map_err(|e| format!("--accel: {e}"))?,
        None => Accel::Auto,
    };
    let started = std::time::Instant::now();
    let (out, status) = workloads::run(suite, argv, follow, kernel, |c| {
        c.accel = accel;
        if !extra.is_empty() {
            c.cmdline = format!("{} {extra}", c.cmdline);
        }
    })?;
    print!("{out}");
    println!("workloads: {} exited with status {status:#x}", suite.name);
    if cmd.is_some() {
        return Ok(());
    }
    let s = (suite.parse)(&out);
    let total = s.run();
    println!(
        "workloads: {}: {} of {total} {} passed ({} skipped); failed: {}",
        suite.name,
        s.passed.len(),
        suite.unit,
        s.skipped.len(),
        s.failed.join(" ")
    );
    // A run that scored nothing did not run the suite (a usage error, a
    // crash before the summary): that is a failure, not 0 of 0.
    if total == 0 {
        return Err(format!(
            "workloads: {} reported no results (status {status:#x})",
            suite.name
        ));
    }
    // Only a full run is recorded and held to its floor.
    if tests.is_some() {
        return Ok(());
    }
    let root = xtask::workspace_root();
    let floors = std::fs::read_to_string(root.join("workloads.toml")).unwrap_or_default();
    let floor = workloads::floors(&floors)
        .into_iter()
        .find(|(n, _)| n == suite.name)
        .map_or(0, |(_, f)| f);
    let doc_path = root.join("docs").join("workloads.md");
    let old = std::fs::read_to_string(&doc_path).unwrap_or_default();
    let machine = format!("{:?}", accel.resolve()).to_lowercase();
    let secs = started.elapsed().as_secs();
    let section = workloads::section(suite, &s, secs, &machine, floor);
    std::fs::write(&doc_path, workloads::merge_doc(&old, suite.name, &section))
        .map_err(|e| format!("{}: {e}", doc_path.display()))?;
    println!("workloads: wrote {}", doc_path.display());
    if s.per_mille() < floor {
        return Err(format!(
            "workloads: {} passed {} per mille, below its floor of {floor}",
            suite.name,
            s.per_mille()
        ));
    }
    Ok(())
}

/// `cargo xtask fuzz [TARGET] [--iterations N] [--seed S]`: the fuzz
/// targets, longer than CI's run, with overflow checks (the dev profile).
fn cmd_fuzz(args: &[String]) -> Result<()> {
    let mut cmd = cargo();
    cmd.args(["test", "--package", "ichor-fuzz", "--", "--nocapture"]);
    let mut it = args.iter();
    cmd.env("ICHOR_FUZZ_ITERATIONS", "100000");
    while let Some(a) = it.next() {
        match a.as_str() {
            "--iterations" => {
                cmd.env(
                    "ICHOR_FUZZ_ITERATIONS",
                    it.next().ok_or("--iterations needs a value")?,
                );
            }
            "--seed" => {
                cmd.env("ICHOR_FUZZ_SEED", it.next().ok_or("--seed needs a value")?);
            }
            t if !t.starts_with('-') => {
                cmd.env("ICHOR_FUZZ_TARGET", t);
            }
            other => return Err(format!("fuzz: unknown option {other:?}")),
        }
    }
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
    let mut services_clippy = cargo();
    services_clippy.arg("clippy");
    for c in SERVICE_ONLY {
        services_clippy.args(["--package", c]);
    }
    run_cmd(
        services_clippy
            .args(["--target", build::SERVICES_TARGET])
            .arg("--target-dir")
            .arg(build::services_target_dir())
            .args(["--", "-D", "warnings"]),
    )?;
    // The kernel embeds the services' binaries.
    let services = build::services(build::Profile::Dev)?;
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
            .env("ICHOR_SERVICES_DIR", &services)
            .args(["--", "-D", "warnings"]),
    )?;
    audit::check_forbid_unsafe()?;
    audit::check_frame_budget()?;
    audit::check_rt_budget()?;
    audit::check_trusted_lints()?;
    linux_abi::check_table()?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = args
        .split_first()
        .map_or(("help", &[][..]), |(c, r)| (c.as_str(), r));
    // These take their own arguments.
    let rest_for_parse = if matches!(command, "fuzz" | "workloads" | "api") {
        &[][..]
    } else {
        rest
    };
    let result = parse(rest_for_parse).and_then(|o| match command {
        "build" => build::kernel(o.profile).map(|p| println!("{}", p.display())),
        "run" => cmd_run(&o),
        "test" => cmd_test(&o),
        "lint" => cmd_lint(),
        "frame-audit" => {
            audit::check_frame_budget().and_then(|_| audit::check_rt_budget().map(|_| ()))
        }
        "linux-abi-table" => linux_abi::write_table(),
        "bench" => cmd_bench(&o),
        "x509-limbo" => xtask::limbo::run(),
        "fuzz" => cmd_fuzz(rest),
        "workloads" => cmd_workloads(rest),
        "disk-image" => cmd_disk_image(&o, rest),
        "api" => cmd_api(rest),
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
