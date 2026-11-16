//! `cargo xtask workloads`: real runtimes' own test suites, run the way
//! users run containers (ADR-0013 §2). Ichor boots with the control plane
//! published (and an API token); from the host, the suite's official
//! image is pulled by digest through the API, with the source tree's tests
//! (pinned by SHA-256) added as a layer; a cell is made and the suite run;
//! its own summary is parsed into a pass rate.
//!
//! `cargo xtask workloads python [--tests "test_os test_json"]` runs one
//! suite (all tests, or the named ones); `--cmd "..."` runs a shell command
//! in the suite's cell instead (exploration).

use std::time::{Duration, Instant};

use grpc::control::LayerSource;

use crate::Result;
use crate::api::Session;
use crate::qemu::{self, RunConfig};

/// A layer added to the image: an upstream archive's subtree, pinned.
#[derive(Debug, Clone, Copy)]
pub struct LayerPin {
    pub url: &'static str,
    pub sha256: &'static str,
    pub from: &'static str,
    pub to: &'static str,
}

/// One suite.
#[derive(Debug, Clone, Copy)]
pub struct Suite {
    pub name: &'static str,
    /// The official image, by index digest.
    pub image: &'static str,
    pub layers: &'static [LayerPin],
    /// The suite's command; `{tests}` is replaced by the chosen tests.
    pub argv: &'static [&'static str],
    pub env: &'static [&'static str],
}

/// CPython 3.12.16: `python:3.12-slim-bookworm` strips `Lib/test`, so the
/// matching source release supplies it.
pub const PYTHON: Suite = Suite {
    name: "python",
    image: "docker.io/library/python@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df",
    layers: &[LayerPin {
        url: "https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tgz",
        sha256: "sha256:710c3e75dac8b2f258d9cd0f76e5c4c2e9175fac9e249c98901552f7cf33b7dd",
        from: "Python-3.12.16/Lib/test/",
        to: "/usr/local/lib/python3.12/test/",
    }],
    argv: &[
        "python3",
        "-m",
        "test",
        "--timeout",
        "600",
        "-u",
        "-network",
    ],
    env: &["PYTHONUNBUFFERED=1"],
};

pub const SUITES: &[Suite] = &[PYTHON];

/// A suite's result, from its own summary.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Score {
    pub passed: Vec<String>,
    pub failed: Vec<String>,
    pub skipped: Vec<String>,
}

/// Parses `python -m test`'s final summary: sections like "12 tests OK.",
/// "3 tests failed:", "5 tests skipped:" followed by indented test names.
pub fn parse_python(out: &str) -> Score {
    let mut s = Score::default();
    let mut section: Option<&mut Vec<String>> = None;
    for line in out.lines() {
        let t = line.trim();
        let head = |w: &str| t.contains(" test") && t.contains(w) && t.ends_with(':');
        if head("failed") && !t.contains("re-run") {
            section = Some(&mut s.failed);
            continue;
        }
        if head("skipped") || head("altered the execution environment") || head("omitted") {
            section = Some(&mut s.skipped);
            continue;
        }
        if head("OK") {
            section = Some(&mut s.passed);
            continue;
        }
        if t.is_empty() || t.starts_with("==") || t.starts_with("Total") {
            section = None;
            continue;
        }
        if let Some(v) = section.as_deref_mut() {
            v.extend(t.split_whitespace().map(str::to_string));
        }
    }
    // "N tests OK." lists no names when every test passed.
    if s.passed.is_empty()
        && let Some(n) = out
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_suffix(" tests OK.")
                    .or_else(|| l.trim().strip_suffix(" test OK."))
            })
            .filter_map(|n| n.trim_start_matches("All ").parse::<usize>().ok())
            .next_back()
    {
        s.passed = (0..n).map(|i| format!("#{i}")).collect();
    }
    s
}

fn layers(suite: &Suite) -> Vec<LayerSource> {
    suite
        .layers
        .iter()
        .map(|l| LayerSource {
            url: l.url.into(),
            digest: l.sha256.into(),
            from: l.from.into(),
            to: l.to.into(),
        })
        .collect()
}

/// Boots Ichor, pulls the suite, runs `argv` in a fresh cell, and returns
/// its output and wait status.
pub fn run(
    suite: &Suite,
    argv: Vec<String>,
    kernel: std::path::PathBuf,
    cfg_tweak: impl FnOnce(&mut RunConfig),
) -> Result<(String, u32)> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map_err(|e| e.to_string())?
        .port();
    let token = format!(
        "workloads-{:x}",
        Instant::now().elapsed().as_nanos() ^ u128::from(std::process::id())
    );
    let mut cfg = RunConfig::new(format!("workloads-{}", suite.name), kernel);
    cfg.cmdline = "qemu_debug_exit control=50051 control_publish=50051 control_exit".into();
    cfg.net_user_opts = format!("hostfwd=tcp:127.0.0.1:{port}-:50051");
    cfg.api_token = Some(token.clone());
    cfg.capture = true;
    cfg.memory_mib = 6144;
    cfg.smp = 4;
    cfg.timeout = Some(Duration::from_secs(6 * 3600));
    cfg_tweak(&mut cfg);
    let suite = *suite;
    let client = std::thread::spawn(move || -> Result<(String, u32)> {
        let mut s = Session::connect(
            port,
            Some(&token),
            Instant::now() + Duration::from_secs(900),
        )?;
        eprintln!("workloads: pulling {}", suite.image);
        let pulled = s.pull(suite.image, layers(&suite), Duration::from_secs(3600))?;
        eprintln!(
            "workloads: image {} ({} MiB)",
            pulled.image_id,
            pulled.size >> 20
        );
        let cell = s.create_cell(&pulled.image_id, 3 << 30)?;
        let a: Vec<&str> = argv.iter().map(String::as_str).collect();
        eprintln!("workloads: cell {} runs {a:?}", cell.cell_id);
        let (out, status) = s.run(&cell.cell_id, &a, suite.env, Duration::from_secs(5 * 3600))?;
        Ok((String::from_utf8_lossy(&out).into_owned(), status))
    });
    let outcome = qemu::run(&cfg)?;
    let result = client
        .join()
        .map_err(|_| "the API client panicked".to_string())?;
    if result.is_err() {
        eprintln!(
            "workloads: guest log tail:\n{}",
            outcome
                .serial
                .lines()
                .rev()
                .take(40)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    result
}
