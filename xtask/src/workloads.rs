//! `cargo xtask workloads`: real runtimes' own test suites, run the way
//! users run containers (ADR-0013 §2). Ichor boots with the control plane
//! published (and an API token); from the host, the suite's official
//! image is pulled by digest through the API, with the source tree's tests
//! (pinned by SHA-256) added as a layer; a cell is made and the suite run;
//! its own summary is parsed into a pass rate.
//!
//! `cargo xtask workloads python [--tests "test_os test_json"]` runs one
//! suite (all tests, or the named ones); `--cmd "..."` runs a shell command
//! in the suite's cell instead, and `--follow FILE` then runs each line
//! added to FILE there until one is `exit` (exploration).

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
    /// The suite's command; the chosen tests are added, or `all` for a full
    /// run.
    pub argv: &'static [&'static str],
    pub all: &'static [&'static str],
    pub env: &'static [&'static str],
    /// What the suite counts, in the plural.
    pub unit: &'static str,
    /// The machine's memory, and the cell's.
    pub memory_mib: u32,
    pub cell_bytes: u64,
    /// Reads the score out of the suite's output.
    pub parse: fn(&str) -> Score,
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
    all: &[],
    env: &["PYTHONUNBUFFERED=1"],
    unit: "modules",
    memory_mib: 6144,
    cell_bytes: 3 << 30,
    parse: parse_python,
};

/// Go 1.27: the image's own source tree has the standard library's tests.
/// `-short` is what upstream's builders run on slow machines; vet checks
/// the sources, not the platform. Compiling makes it heavy: the cell holds
/// the build cache (its root's upper layer is in memory).
pub const GO: Suite = Suite {
    name: "go",
    image: "docker.io/library/golang@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea",
    layers: &[],
    argv: &["go", "test", "-short", "-vet=off", "-timeout", "30m"],
    all: &["std"],
    env: &["HOME=/root", "GOFLAGS=-buildvcs=false"],
    unit: "packages",
    memory_mib: 12 * 1024,
    cell_bytes: 6 << 30,
    parse: parse_go,
};

/// PostgreSQL 16, `make check`: its regression suite needs `pg_regress` and
/// `regress.so`, which the official image does not carry and only the
/// source tree makes, so the suite builds the server too, in the official
/// image Docker's own images are built on (a compiler, make, and Debian's
/// libraries). Named tests run with the schedule's setup tests.
pub const POSTGRES: Suite = Suite {
    name: "postgres",
    image: "docker.io/library/buildpack-deps@sha256:f53cd4c58cdb96a467b98696cd510a949ef4ccd7d23e07b75107de754773007a",
    layers: &[LayerPin {
        url: "https://ftp.postgresql.org/pub/source/v16.16/postgresql-16.16.tar.gz",
        sha256: "sha256:3e930f3366f675ab26e873d16201201f8e9b6d9bc13686e4465380271145ea2d",
        from: "postgresql-16.16/",
        to: "/usr/src/postgresql/",
    }],
    argv: &[
        "sh",
        "-c",
        // The server refuses to run as root, and its tests write where they
        // are built.
        "set -e; useradd -m pg; cp -r /usr/src/postgresql /home/pg/src; \
         chown -R pg /home/pg/src; \
         exec su pg -c 'set -e; cd ~/src; \
         ./configure --prefix=/home/pg/inst --without-icu --without-readline \
         --without-zlib CFLAGS=-O1 >../configure.log 2>&1 || { tail ../configure.log; exit 1; }; \
         make -s -j4 >../make.log 2>&1 || { tail ../make.log; exit 1; }; \
         echo built; cd src/test/regress; \
         if [ $# -gt 0 ]; then make -s check-tests TESTS=\"test_setup $*\"; \
         else make -s check; fi; s=$?; \
         cat regression.diffs 2>/dev/null | head -c 2000000; exit $s' -- \"$0\" \"$@\"",
        "postgres",
    ],
    all: &[],
    env: &["HOME=/root"],
    unit: "tests",
    memory_mib: 10 * 1024,
    cell_bytes: 5 << 30,
    parse: parse_tap,
};

/// A part of Node.js 24's source release.
const fn node_source(from: &'static str, to: &'static str) -> LayerPin {
    LayerPin {
        url: "https://nodejs.org/dist/v24.22.3/node-v24.22.3.tar.gz",
        sha256: "sha256:4690edccae352134bbe31d844b37898f2a28b2c3d67901d0112fb6c4996d556a",
        from,
        to,
    }
}

/// Node.js 24's `test/parallel` and `test/sequential`, from the release the
/// image holds, run by its own `tools/test.py` (the full image, not the slim
/// one, has the Python that needs).
pub const NODE: Suite = Suite {
    name: "node",
    image: "docker.io/library/node@sha256:9d266751ca3d7fdbe651c878ffd5ad0a42fed49a18c283509267c97f025b7496",
    layers: &[
        node_source("node-v24.22.3/test/", "/usr/src/node/test/"),
        node_source("node-v24.22.3/tools/", "/usr/src/node/tools/"),
        // What some tests compare the program with, or run.
        node_source("node-v24.22.3/benchmark/", "/usr/src/node/benchmark/"),
        node_source("node-v24.22.3/doc/", "/usr/src/node/doc/"),
        node_source("node-v24.22.3/lib/", "/usr/src/node/lib/"),
        node_source("node-v24.22.3/src/", "/usr/src/node/src/"),
        node_source("node-v24.22.3/deps/acorn/", "/usr/src/node/deps/acorn/"),
        node_source(
            "node-v24.22.3/deps/corepack/",
            "/usr/src/node/deps/corepack/",
        ),
        node_source("node-v24.22.3/deps/npm/", "/usr/src/node/deps/npm/"),
        node_source("node-v24.22.3/deps/undici/", "/usr/src/node/deps/undici/"),
        node_source(
            "node-v24.22.3/deps/v8/src/objects/",
            "/usr/src/node/deps/v8/src/objects/",
        ),
    ],
    argv: &[
        "sh",
        "-c",
        // As the image's `node` user, as upstream's CI does: some tests are
        // refused things that root is not.
        "chown -R node /usr/src/node && cd /usr/src/node && \
         { [ $# -gt 0 ] || set -- parallel sequential; } && \
         exec su node -c 'exec python3 tools/test.py -J --shell=/usr/local/bin/node -p tap \
         --timeout 600 \"$@\"' -- \"$0\" \"$@\"",
        "node",
    ],
    all: &[],
    env: &["HOME=/root"],
    unit: "tests",
    memory_mib: 10 * 1024,
    cell_bytes: 4 << 30,
    parse: parse_node,
};

/// Where Temurin publishes the sources of its JDK 21.
const JDK_SOURCES: &str = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13.1%2B2/OpenJDK21U-jdk-sources_21.0.13.1_2.tar.gz";
const JDK_SHA256: &str = "sha256:427e3eaec042f61c93258b5a42c86f3ddbad45a2ba95132dd4a3e3c07414bc8c";

/// OpenJDK 21's tier 1 tests of the libraries (java.lang, java.util, math,
/// ...), from the sources Temurin built the image's JDK of, run by jtreg
/// (Adoptium's build, which its own CI uses). Tests with native parts need
/// libraries only an OpenJDK build has: they count as failed.
pub const JVM: Suite = Suite {
    name: "jvm",
    image: "docker.io/library/eclipse-temurin@sha256:a09e64f4976df9c4f2029c6abe64fc26f069a342ec9a7f147dce7b1933ebda16",
    layers: &[
        LayerPin {
            url: "https://ci.adoptium.net/view/Dependencies/job/dependency_pipeline/lastSuccessfulBuild/artifact/jtreg/jtreg-7.5.2+1.tar.gz",
            sha256: "sha256:50ec25adec1e6a4b1bc023fda2f706c524beec5d9f022a7901f009efa08033f8",
            from: "jtreg/",
            to: "/opt/jtreg/",
        },
        LayerPin {
            url: JDK_SOURCES,
            sha256: JDK_SHA256,
            from: "jdk-21.0.13.1+2-src/test/jdk/",
            to: "/usr/src/jdk/test/jdk/",
        },
        LayerPin {
            url: JDK_SOURCES,
            sha256: JDK_SHA256,
            from: "jdk-21.0.13.1+2-src/test/lib/",
            to: "/usr/src/jdk/test/lib/",
        },
    ],
    argv: &[
        "sh",
        "-c",
        "cd /usr/src/jdk/test/jdk && [ $# -gt 0 ] || set -- :tier1; \
         exec sh /opt/jtreg/bin/jtreg -jdk:\"$JAVA_HOME\" -agentvm -automatic -ignore:quiet \
         -conc:4 -timeoutFactor:10 -verbose:summary -exclude:ProblemList.txt \
         -w:/tmp/work -r:/tmp/report \"$@\"",
        "jvm",
    ],
    all: &[],
    env: &["HOME=/root"],
    unit: "tests",
    memory_mib: 10 * 1024,
    cell_bytes: 5 << 30,
    parse: parse_jtreg,
};

pub const SUITES: &[Suite] = &[PYTHON, GO, POSTGRES, NODE, JVM];

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

/// Parses `go test PACKAGES`: one line per package ("ok  \tstrings\t0.1s",
/// "FAIL\tnet\t2s", "?   \terrors\t[no test files]"), tabs at fixed places.
pub fn parse_go(out: &str) -> Score {
    let mut s = Score::default();
    for line in out.lines() {
        let mut f = line.trim_end().split('\t');
        let (Some(head), Some(pkg)) = (f.next(), f.next()) else {
            continue;
        };
        // "FAIL\tnet/http [build failed]" has its remark after a space.
        let pkg = pkg.split(' ').next().unwrap_or(pkg).to_string();
        match head {
            "ok  " => s.passed.push(pkg),
            "FAIL" => s.failed.push(pkg),
            "?   " => s.skipped.push(pkg),
            _ => {}
        }
    }
    s
}

/// Parses TAP as `pg_regress` 16 writes it ("ok 2         + boolean  59 ms",
/// "not ok 5     - copy  10 ms"): a number, `+` or `-` (in a parallel group
/// or not), the test's name.
pub fn parse_tap(out: &str) -> Score {
    let mut s = Score::default();
    for line in out.lines() {
        let (into, rest) = match (line.strip_prefix("ok "), line.strip_prefix("not ok ")) {
            (Some(r), _) => (&mut s.passed, r),
            (_, Some(r)) => (&mut s.failed, r),
            _ => continue,
        };
        let mut f = rest.split_whitespace();
        if let (Some(n), Some("+" | "-"), Some(name)) = (f.next(), f.next(), f.next())
            && n.parse::<u32>().is_ok()
        {
            into.push(name.to_string());
        }
    }
    s
}

/// Parses TAP as Node.js's `tools/test.py` writes it ("ok 3
/// parallel/test-x", "not ok 4 ...", "ok 5 ... # skip why").
pub fn parse_node(out: &str) -> Score {
    let mut s = Score::default();
    for line in out.lines() {
        let (ok, rest) = match (line.strip_prefix("ok "), line.strip_prefix("not ok ")) {
            (Some(r), _) => (true, r),
            (_, Some(r)) => (false, r),
            _ => continue,
        };
        let mut f = rest.split_whitespace();
        let (Some(n), Some(name)) = (f.next(), f.next()) else {
            continue;
        };
        if n.parse::<u32>().is_err() {
            continue;
        }
        if rest.contains(" # skip") || rest.contains(" # SKIP") {
            s.skipped.push(name.to_string());
        } else if ok {
            s.passed.push(name.to_string());
        } else {
            s.failed.push(name.to_string());
        }
    }
    s
}

/// Parses `jtreg -verbose:summary`: "Passed: java/lang/X.java", "FAILED:
/// ..." and "Error: ..." (a test that could not be run).
pub fn parse_jtreg(out: &str) -> Score {
    let mut s = Score::default();
    for line in out.lines() {
        let test = |head: &str| {
            let t = line.strip_prefix(head)?.trim();
            (t.contains('/') && !t.contains(' ')).then(|| t.to_string())
        };
        if let Some(t) = test("Passed: ") {
            s.passed.push(t);
        } else if let Some(t) = test("FAILED: ").or_else(|| test("Error: ")) {
            s.failed.push(t);
        }
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
/// `machine` is what it ran on ("kvm").
pub fn section(suite: &Suite, s: &Score, secs: u64, machine: &str, floor: u32) -> String {
    let mut out = format!("## {}\n\n", suite.name);
    out += &format!("- Image: `{}`\n", suite.image);
    for l in suite.layers {
        out += &format!(
            "- Layer: `{}` ({}), `{}` at `{}`\n",
            l.url, l.sha256, l.from, l.to
        );
    }
    out += &format!(
        "- Command: `{}`\n",
        [suite.argv, suite.all].concat().join(" ")
    );
    out += &format!(
        "- Result: {} of {} {} passed ({}.{}%), {} skipped; floor {}.{}%\n",
        s.passed.len(),
        s.run(),
        suite.unit,
        s.per_mille() / 10,
        s.per_mille() % 10,
        s.skipped.len(),
        floor / 10,
        floor % 10
    );
    out += &format!(
        "- Run time: {} min ({machine}, 4 vCPUs, the cell given {} GiB)\n\n",
        secs.div_ceil(60),
        suite.cell_bytes >> 30
    );
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

/// Runs the lines of `follow` as they are added, each as a shell command in
/// `cell`, until one is `exit` (a pull takes minutes: exploring should not
/// need one per command). Output goes to `to`.
fn follow_commands(
    s: &mut Session,
    cell: &str,
    suite: &Suite,
    follow: &std::path::Path,
    to: &mut std::fs::File,
) -> Result<()> {
    use std::io::Write;
    let mut done = 0;
    loop {
        let text = std::fs::read_to_string(follow).unwrap_or_default();
        // Only whole lines: the last may still be being written.
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let Some(line) = lines.get(done).filter(|l| l.ends_with('\n')) else {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        done += 1;
        let line = line.trim();
        if line == "exit" {
            return Ok(());
        }
        let _ = writeln!(to, "\n$ {line}");
        let mut out = |b: &[u8]| {
            let _ = to.write_all(b);
            let _ = to.flush();
        };
        let hour = Duration::from_secs(3600);
        let status = s.run_with(cell, &["/bin/sh", "-c", line], suite.env, hour, &mut out)?;
        let _ = writeln!(to, "[status {status:#x}]");
    }
}

/// Boots Ichor, pulls the suite, runs `argv` in a fresh cell (then the
/// commands in `follow`, see [`follow_commands`]), and returns its output
/// and wait status.
pub fn run(
    suite: &Suite,
    argv: Vec<String>,
    follow: Option<std::path::PathBuf>,
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
    cfg.api_tls = Some(crate::api::TEST_IDENTITY.into());
    cfg.capture = true;
    cfg.memory_mib = suite.memory_mib;
    cfg.smp = 4;
    cfg.timeout = Some(Duration::from_secs(6 * 3600));
    cfg_tweak(&mut cfg);
    let suite = *suite;
    let client = std::thread::spawn(move || -> Result<(String, u32)> {
        let mut s = Session::connect(
            port,
            Some(&token),
            Some(&crate::api::test_trust()),
            Instant::now() + Duration::from_secs(900),
        )?;
        eprintln!("workloads: pulling {}", suite.image);
        let pulled = s.pull(suite.image, layers(&suite), Duration::from_secs(3600))?;
        eprintln!(
            "workloads: image {} ({} MiB)",
            pulled.image_id,
            pulled.size >> 20
        );
        let cell = s.create_cell(&pulled.image_id, suite.cell_bytes)?;
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
        if let Some(f) = follow {
            follow_commands(&mut s, &cell.cell_id, &suite, &f, &mut file)?;
        }
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
    fn pg_regress_tests_are_scored() {
        let s = parse_tap(
            "# initializing database system by copying initdb template\n\
             ok 1         - test_setup                                480 ms\n\
             # parallel group (2 tests):  boolean char\n\
             ok 2         + boolean                                    59 ms\n\
             not ok 3     + char                                       12 ms\n\
             1..3\n\
             # 1 of 3 tests failed.\n\
             ok, whatever\n",
        );
        assert_eq!(s.passed, ["test_setup", "boolean"]);
        assert_eq!(s.failed, ["char"]);
    }

    #[test]
    fn jtreg_tests_are_scored() {
        let s = parse_jtreg(
            "Passed: java/lang/Math/Tests.java\nFAILED: java/util/Map/Get.java#id0\n\
             Error: java/lang/Native.java\nPassed. Execution successful\n\
             Error: Some tests failed or other problems occurred.\n\
             Test results: passed: 1; failed: 1; error: 1\n",
        );
        assert_eq!(s.passed, ["java/lang/Math/Tests.java"]);
        assert_eq!(
            s.failed,
            ["java/util/Map/Get.java#id0", "java/lang/Native.java"]
        );
    }

    #[test]
    fn node_tests_are_scored() {
        let s = parse_node(
            "TAP version 13\n1..3\nok 1 parallel/test-a\n  ---\n  duration_ms: 100\n  ...\n\
             not ok 2 parallel/test-b\n  ---\n  severity: fail\n\
             ok 3 sequential/test-c # skip missing crypto\n",
        );
        assert_eq!(s.passed, ["parallel/test-a"]);
        assert_eq!(s.failed, ["parallel/test-b"]);
        assert_eq!(s.skipped, ["sequential/test-c"]);
    }

    #[test]
    fn go_packages_are_scored() {
        let s = parse_go(
            "ok  \tarchive/tar\t0.512s\n--- FAIL: TestX (0.00s)\n    x_test.go:1: bad\nFAIL\n\
             FAIL\tnet/http\t12.3s\nFAIL\tcmd/x [build failed]\n\
             ?   \tcrypto/internal/cryptotest\t[no test files]\nok  \tstrings\t(cached)\nFAIL\n",
        );
        assert_eq!(s.passed, ["archive/tar", "strings"]);
        assert_eq!(s.failed, ["net/http", "cmd/x"]);
        assert_eq!(s.skipped, ["crypto/internal/cryptotest"]);
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
