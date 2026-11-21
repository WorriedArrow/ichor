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
    // No `-u`: regrtest enables no optional resources (network, cpu-heavy,
    // largefile, ...) by default, which is what a sealed cell can offer.
    // `-j0` (ADR-0013): each module in a worker process, so a module that
    // crashes or hangs its interpreter costs that module, not the run.
    argv: &["python3", "-m", "test", "-j0", "--timeout", "600"],
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
/// Only what follows the last "== Tests result" line counts: tests print
/// tracebacks and warnings of their own before it.
pub fn parse_python(out: &str) -> Score {
    let out = out.rfind("== Tests result").map_or(out, |at| &out[at..]);
    let mut s = Score::default();
    let mut section: Option<&mut Vec<String>> = None;
    for line in out.lines() {
        let t = line.trim();
        // Headers count first: "4 tests failed:", "All 3 tests OK.".
        let counted = t
            .trim_start_matches("All ")
            .starts_with(|c: char| c.is_ascii_digit());
        let head = |w: &str| counted && t.contains(" test") && t.contains(w) && t.ends_with(':');
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

impl Score {
    /// Modules run (passed or failed; skipped ones are not run).
    pub fn run(&self) -> usize {
        self.passed.len() + self.failed.len()
    }

    /// The pass rate in per mille of modules run.
    pub fn per_mille(&self) -> u32 {
        match self.run() {
            0 => 0,
            n => (self.passed.len() * 1000 / n) as u32,
        }
    }
}

/// The floors in `workloads.toml`: lines `name = per_mille`, `#` comments.
pub fn floors(text: &str) -> Vec<(String, u32)> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_string(), v.trim().parse().ok()?))
        })
        .collect()
}

/// One suite's section of `docs/workloads.md`.
pub fn section(suite: &Suite, s: &Score, secs: u64, floor: u32) -> String {
    let mut out = format!("## {}\n\n", suite.name);
    out += &format!("- Image: `{}`\n", suite.image);
    for l in suite.layers {
        out += &format!(
            "- Layer: `{}` ({}), `{}` at `{}`\n",
            l.url, l.sha256, l.from, l.to
        );
    }
    out += &format!("- Command: `{}`\n", suite.argv.join(" "));
    out += &format!(
        "- Result: {} of {} modules passed ({}.{}%), {} skipped; floor {}.{}%\n",
        s.passed.len(),
        s.run(),
        s.per_mille() / 10,
        s.per_mille() % 10,
        s.skipped.len(),
        floor / 10,
        floor % 10
    );
    out += &format!("- Run time: {} min\n\n", secs.div_ceil(60));
    if !s.failed.is_empty() {
        out += "Failed:\n\n";
        for f in &s.failed {
            out += &format!("- `{f}`\n");
        }
        out.push('\n');
    }
    out
}

/// `docs/workloads.md` with `name`'s section replaced by `new` (others kept).
pub fn merge_doc(old: &str, name: &str, new: &str) -> String {
    const HEAD: &str = "# Workload test suites\n\n\
        Generated by `cargo xtask workloads SUITE` (a full run; ADR-0013 §2):\n\
        each runtime's own suite, run in a cell through the control plane\n\
        from its pinned official image. Rates are per test module (or the\n\
        suite's own unit), passed / run. Floors are in `workloads.toml`.\n\n";
    let mut sections: Vec<(String, String)> = Vec::new();
    for part in old.split("\n## ").skip(1) {
        let title = part.lines().next().unwrap_or("").trim().to_string();
        sections.push((title, format!("## {}\n", part.trim_end())));
    }
    let new = new.trim_end().to_string() + "\n";
    match sections.iter_mut().find(|(t, _)| t == name) {
        Some(s) => s.1 = new,
        None => sections.push((name.to_string(), new)),
    }
    let mut out = HEAD.to_string();
    for (i, (_, body)) in sections.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out += body;
    }
    out
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
        // The output also goes to a file as it comes, so a run that fails
        // partway keeps what it printed.
        let path = crate::workspace_root()
            .join("target")
            .join(format!("workloads-{}.out", suite.name));
        let mut file =
            std::fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        eprintln!("workloads: output in {}", path.display());
        let mut out = Vec::new();
        let status = s.run_with(
            &cell.cell_id,
            &a,
            suite.env,
            Duration::from_secs(5 * 3600),
            &mut |b| {
                use std::io::Write;
                let _ = file.write_all(b);
                let _ = file.flush();
                out.extend_from_slice(b);
            },
        )?;
        Ok((String::from_utf8_lossy(&out).into_owned(), status))
    });
    let outcome = qemu::run(&cfg)?;
    // The whole guest log, for traces (`--cmdline trace_errors`) and
    // post-mortems.
    let log = crate::workspace_root()
        .join("target")
        .join(format!("workloads-{}.serial.log", suite.name));
    if std::fs::write(&log, &outcome.serial).is_ok() {
        eprintln!("workloads: guest log in {}", log.display());
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of regrtest 3.12's final summary.
    const SUMMARY: &str = "\
0:00:01 load avg: 0.00 [1/4] test_bool
0:00:02 load avg: 0.00 [2/4] test_os
test_os failed (1 error)
== Tests result: FAILURE ==

1 test skipped:
    test_winreg

2 tests OK.

1 test failed:
    test_os

Total duration: 3 sec
Total tests: run=100 failures=1 skipped=2
Total test files: run=3 failed=1 skipped=1
Result: FAILURE
";

    #[test]
    fn the_summary_scores_modules() {
        let s = parse_python(SUMMARY);
        assert_eq!(s.failed, ["test_os"]);
        assert_eq!(s.skipped, ["test_winreg"]);
        assert_eq!(s.passed.len(), 2);
        assert_eq!(s.run(), 3);
        assert_eq!(s.per_mille(), 666);
    }

    #[test]
    fn tracebacks_before_the_summary_are_ignored() {
        let out = format!(
            "Traceback (most recent call last):\n  File \"x.py\", in test failed:\n    \
             self.fail(x)\n\n{SUMMARY}"
        );
        let s = parse_python(&out);
        assert_eq!(s.failed, ["test_os"]);
        assert_eq!(s.run(), 3);
    }

    #[test]
    fn named_ok_tests_are_listed() {
        let s = parse_python("2 tests OK:\n    test_bool test_int\n\nTotal duration: 1 sec\n");
        assert_eq!(s.passed, ["test_bool", "test_int"]);
        assert!(s.failed.is_empty());
    }

    #[test]
    fn floors_parse_with_comments() {
        let f = floors("# floors\npython = 850 # CPython\n\ngo=10\nbad = x\n");
        assert_eq!(f, [("python".to_string(), 850), ("go".to_string(), 10)]);
    }

    #[test]
    fn the_doc_keeps_other_suites() {
        let a = merge_doc("", "python", "## python\n\n- Result: 1\n");
        let b = merge_doc(&a, "go", "## go\n\n- Result: 2\n");
        let c = merge_doc(&b, "python", "## python\n\n- Result: 3\n");
        assert!(c.starts_with("# Workload test suites"));
        assert!(c.contains("## python\n\n- Result: 3\n"));
        assert!(c.contains("## go\n\n- Result: 2\n"));
        assert!(!c.contains("Result: 1"));
        assert!(c.find("## python") < c.find("## go"));
    }
}
