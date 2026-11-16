//! Cell access control through the Linux ABI (`cell_access` on the
//! command line; `tests/cell_access.rs`).
//!
//! Two cells, A and B, each with its own root mounted from the same Debian
//! disk (separate overlays, devpts and socket names; the same shared page
//! cache pages). A long-lived helper in B (`cellaccess/b_helper.pl`) makes
//! one object of every kind and reports their names; each section runs
//! Debian's perl in A, which makes the real syscall on B's object and
//! asserts the exact errno, and the same call on A's own object as a
//! control. A learns B's names only from this harness.
//!
//! The harness talks to the perl programs through files under
//! `/run/ichor/` of each root, which it reads and writes through that
//! root's overlay: `out-NAME` from perl, `in-NAME` to it, each written
//! under a temporary name and renamed. After every section B's helper
//! reports what it saw (signals, accepted connections, its files, its
//! view of the shared page), and the harness checks it.
//!
//! Plan and checklist: `docs/reports/cell-access-tests-plan.md`.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use frame::println;
use frame::sync::SpinLock;
use frame::task::TaskOptions;

use crate::kcell::{Cell, System};
use crate::loader;
use crate::pagecache::Mounted;
use crate::process::LinuxProcess;
use crate::runtest::{fail, run_linux};
use crate::vfs::{ROOT, Vfs};

/// Pages each test cell may use (64 MiB).
const CELL_PAGES: u64 = 16384;
/// B's TCP port on its own address, and the port it listens on for the
/// uplink check.
const B_PORT: u16 = 7100;
const B_UPLINK_PORT: u16 = 7300;

const PRELUDE: &str = include_str!("cellaccess/prelude.pl");
const B_HELPER: &str = include_str!("cellaccess/b_helper.pl");
const SMOKE: &str = include_str!("cellaccess/smoke.pl");
const S1_PROCESS: &str = include_str!("cellaccess/s1_process.pl");
const S2_PROC: &str = include_str!("cellaccess/s2_proc.pl");
const S4_PAGES: &str = include_str!("cellaccess/s4_pages.pl");
const S4_FILL: &str = include_str!("cellaccess/s4_fill.pl");
const S4_PRIVATE: &str = include_str!("cellaccess/s4_private.pl");
/// The file both cells map (B's helper reports it too); the checks use its
/// page 1.
const SHARED_FILE: &str = "/usr/bin/dash";

static ENABLED: AtomicBool = AtomicBool::new(false);
/// Set once the harness has ended B's futex wait (section 4); until then
/// B's futex child must still be waiting after every section.
static FUTEX_RELEASED: AtomicBool = AtomicBool::new(false);

/// Asks for the suite to run (`cell_access` on the command line).
pub(crate) fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

pub(crate) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// A section: the rule it checks (its test's name in
/// `tests/cell_access.rs`) and the function that checks it.
type Section = (&'static str, fn(&Ctx) -> bool);

/// Every section, in order.
const SECTIONS: &[Section] = &[
    ("harness", smoke),
    ("process_ids_and_signals_are_scoped_to_their_cell", |c| {
        in_a(c, S1_PROCESS)
    }),
    ("proc_and_sys_show_only_their_cell", |c| in_a(c, S2_PROC)),
    ("shared_cache_pages_never_carry_writes_between_cells", s4),
];

/// One cell with its own root.
struct Side {
    cell: Arc<Cell>,
    root: Arc<Vfs>,
    ip: String,
}

/// What every section can reach.
struct Ctx {
    a: Side,
    b: Side,
    /// B's identifiers, as `key=value` words (B's own report).
    ids: Vec<String>,
    /// The helper's exit code, once it has exited.
    helper: Arc<SpinLock<Option<i32>>>,
    /// Page 1 of the shared file as B first saw it (hex, 16 bytes).
    view0: String,
    /// The disk both roots come from, and the account cells are carved
    /// from (for section 4's opted-out cell).
    disk: Mounted,
    accounts: Arc<cell::Account>,
}

impl Ctx {
    /// B's identifier `key`.
    fn id(&self, key: &str) -> &str {
        self.ids
            .iter()
            .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or("")
    }
}

/// Runs the suite on the Debian disk `m`; fails the boot at the end if any
/// section failed.
pub(crate) fn run(m: &Mounted) {
    let system = System::new(CELL_PAGES * 4).unwrap_or_else(|| fail("cellaccess: no system cell"));
    let side = |name: &str| {
        let cell = Cell::new(&system.root_account, CELL_PAGES)
            .unwrap_or_else(|| fail("cellaccess: no cell"));
        let root = Arc::new(
            Vfs::mount_disk(m).unwrap_or_else(|_| fail("cellaccess: could not mount a root")),
        );
        prepare(&root);
        let ip = match crate::netstack::stack_for(&cell).addr() {
            Some(a) => alloc::format!("{a}"),
            None => fail("cellaccess: a cell got no address from the switch"),
        };
        println!(
            "ichor: cellaccess: cell {name} is cell {} at {ip}, with its own root",
            cell.id()
        );
        Side { cell, root, ip }
    };
    let (a, b) = (side("A"), side("B"));
    let helper = spawn_perl(
        &b,
        B_HELPER,
        alloc::vec![
            alloc::format!("ip={}", b.ip),
            alloc::format!("port={B_PORT}"),
            alloc::format!("uplink={B_UPLINK_PORT}"),
        ],
    );
    let ids = take(&b.root, "ids", &helper);
    println!("ichor: cellaccess: B's helper reports {ids}");
    let mut ctx = Ctx {
        a,
        b,
        ids: ids.split_whitespace().map(ToString::to_string).collect(),
        helper,
        view0: String::new(),
        disk: Mounted {
            metadata: m.metadata,
            disk: m.disk,
        },
        accounts: system.root_account.clone(),
    };
    ctx.view0 = word(&b_status(&ctx), "view").to_string();
    let mut failed: Vec<&str> = Vec::new();
    for &(rule, f) in SECTIONS {
        if f(&ctx) {
            println!("ichor: cellaccess: {rule} passed");
        } else {
            println!("ichor: cellaccess FAILED: {rule}");
            failed.push(rule);
        }
        if !b_intact(&ctx, rule) {
            failed.push("B's helper");
        }
    }
    put(&ctx.b.root, "exit", "");
    match wait_for(&ctx.helper, 120) {
        Some(0) => {}
        code => {
            println!("ichor: cellaccess: B's helper exited {code:?}");
            failed.push("B's helper exit");
        }
    }
    // run_linux checked each program's memory came back; nothing else in
    // either cell may still hold any.
    for (name, s) in [("A", &ctx.a), ("B", &ctx.b)] {
        let used = s.cell.account().used();
        if used != 0 {
            println!("ichor: cellaccess FAILED: cell {name} still has {used} pages charged");
            failed.push("memory returned");
        }
    }
    if failed.is_empty() {
        println!(
            "ichor: cellaccess: every section passed; both cells exited and their memory returned"
        );
    } else {
        println!("ichor: cellaccess FAILED: {failed:?}");
        fail("cellaccess");
    }
}

/// The harness's directory in a fresh root.
fn prepare(root: &Vfs) {
    let mut fs = root.lock();
    let run = fs
        .resolve(ROOT, "/run", true)
        .unwrap_or_else(|_| fail("cellaccess: no /run"));
    if fs.mkdir(run, "ichor", 0o777).is_err() {
        fail("cellaccess: mkdir /run/ichor");
    }
}

/// Writes `in-NAME` into `root`'s channel directory.
fn put(root: &Vfs, name: &str, text: &str) {
    let mut fs = root.lock();
    let dir = fs
        .resolve(ROOT, "/run/ichor", true)
        .unwrap_or_else(|_| fail("cellaccess: no /run/ichor"));
    let tmp = alloc::format!(".in-{name}");
    let ino = fs
        .create(dir, &tmp, 0o644)
        .unwrap_or_else(|_| fail("cellaccess: create"));
    if fs.write(ino, 0, text.as_bytes()) != Ok(text.len())
        || fs
            .rename(dir, &tmp, dir, &alloc::format!("in-{name}"))
            .is_err()
    {
        fail("cellaccess: write");
    }
}

/// Reads a whole file of `root`, if it exists.
fn read(root: &Vfs, path: &str) -> Option<Vec<u8>> {
    let ino = root.lock().resolve(ROOT, path, true).ok()?;
    let size = root.lock().stat(ino).ok()?.size as usize;
    let mut v = alloc::vec![0u8; size];
    let n = root.read(ino, 0, &mut v).ok()?;
    v.truncate(n);
    Some(v)
}

/// Waits for `out-NAME` in `root`, removes it and returns its text. Fails
/// the boot if `who` (the program meant to write it) exits first or it
/// takes longer than two minutes.
fn take(root: &Vfs, name: &str, who: &SpinLock<Option<i32>>) -> String {
    let path = alloc::format!("/run/ichor/out-{name}");
    let deadline = frame::time::now() + Duration::from_secs(120);
    loop {
        if let Some(v) = read(root, &path) {
            let mut fs = root.lock();
            if let Ok(dir) = fs.resolve(ROOT, "/run/ichor", true) {
                let _ = fs.unlink(dir, &alloc::format!("out-{name}"));
            }
            return String::from_utf8_lossy(&v).into_owned();
        }
        if let Some(code) = *who.lock() {
            println!("ichor: cellaccess: the program exited {code} before writing out-{name}");
            fail("cellaccess: no report");
        }
        if frame::time::now() > deadline {
            println!("ichor: cellaccess: no out-{name} after 120 s");
            fail("cellaccess: no report");
        }
        frame::task::sleep_until(frame::time::now() + Duration::from_millis(10));
    }
}

fn wait_for(slot: &SpinLock<Option<i32>>, secs: u64) -> Option<i32> {
    let deadline = frame::time::now() + Duration::from_secs(secs);
    loop {
        if let Some(code) = *slot.lock() {
            return Some(code);
        }
        if frame::time::now() > deadline {
            return None;
        }
        frame::task::sleep_until(frame::time::now() + Duration::from_millis(10));
    }
}

/// Debian's perl running `PRELUDE` + `script` with `args`, in `side`'s
/// cell and root, on this task. `run_linux` checks that the cell's memory
/// came back once it exits.
fn perl(side: (&Arc<Cell>, &Arc<Vfs>), script: &str, args: &[String]) -> i32 {
    let (cell, root) = side;
    let exe = read(root, "/usr/bin/perl").unwrap_or_else(|| fail("cellaccess: no perl"));
    let interp = match loader::interp_path(&crate::file::Bytes(&exe)) {
        Ok(Some(p)) => read(root, &p).unwrap_or_else(|| fail("cellaccess: no ld.so")),
        _ => fail("cellaccess: perl is not dynamically linked"),
    };
    let p = LinuxProcess::new(cell.clone(), root.clone())
        .unwrap_or_else(|| fail("cellaccess: no process"));
    let mut text = String::from(PRELUDE);
    text.push_str(script);
    // argv[0] is also what /proc/self/exe names, so it is the full path.
    let mut argv: Vec<&str> = alloc::vec!["/usr/bin/perl", "-e", &text];
    argv.extend(args.iter().map(String::as_str));
    run_linux(p, &exe, Some(&interp), &argv).0
}

/// [`perl`] on a task of its own; the slot gets the exit code.
fn spawn_perl(side: &Side, script: &'static str, args: Vec<String>) -> Arc<SpinLock<Option<i32>>> {
    let done = Arc::new(SpinLock::new(None));
    let (cell, root, slot) = (side.cell.clone(), side.root.clone(), done.clone());
    TaskOptions::new(move || {
        let code = perl((&cell, &root), script, &args);
        *slot.lock() = Some(code);
    })
    .spawn()
    .unwrap_or_else(|| fail("cellaccess: no task"));
    done
}

/// Runs `script` in A with B's identifiers and A's address as arguments;
/// true if every check in it passed.
fn in_a(ctx: &Ctx, script: &str) -> bool {
    let mut args = ctx.ids.clone();
    args.push(alloc::format!("self_ip={}", ctx.a.ip));
    perl((&ctx.a.cell, &ctx.a.root), script, &args) == 0
}

/// B's helper's status words (see `status` in the helper).
fn b_status(ctx: &Ctx) -> String {
    put(&ctx.b.root, "status", "");
    take(&ctx.b.root, "status", &ctx.helper)
}

fn word<'a>(status: &'a str, key: &str) -> &'a str {
    status
        .split_whitespace()
        .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or("")
}

/// After each section: B's helper still runs, nothing A did reached it
/// (no signal, no connection other than the cross-cell TCP ones section 5
/// makes on purpose), and its objects are as it made them.
fn b_intact(ctx: &Ctx, after: &str) -> bool {
    let s = b_status(ctx);
    let accepted_ok = word(&s, "accepted")
        .split(';')
        .all(|a| a == "none" || a.starts_with("tcp from ") || a.starts_with("uplink from "));
    let ok = word(&s, "alive") == "1"
        && word(&s, "child") == "live"
        && word(&s, "signals") == "none"
        && accepted_ok
        && word(&s, "hostname") == ctx.id("hostname")
        && word(&s, "secret") == "intact"
        && word(&s, "pts") == ctx.id("pts")
        && (FUTEX_RELEASED.load(Ordering::Relaxed) || word(&s, "futex") == "waiting")
        && word(&s, "view") == ctx.view0
        && word(&s, "file") == ctx.view0;
    if ok {
        println!("ichor: cellaccess: B alive and unchanged after {after}");
    } else {
        println!("ichor: cellaccess FAILED: B after {after}: {s}");
    }
    ok
}

/// The harness itself: A got B's identifiers and runs; B's helper answers.
fn smoke(ctx: &Ctx) -> bool {
    in_a(ctx, SMOKE)
}

/// Prints a harness-side check in the perl checks' format; returns `good`.
fn report(rule: &str, check: &str, good: bool, detail: &str) -> bool {
    if good {
        println!("cellaccess: {rule}: {check}: ok");
    } else {
        println!("cellaccess FAILED: {rule}: {check}: {detail}");
    }
    good
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&alloc::format!("{b:02x}"));
    }
    s
}

/// A static ELF that maps page 0-1 of [`SHARED_FILE`] `MAP_PRIVATE`
/// writable, stores a word at the start of page 1 with an ordinary CPU
/// store, and reads it back. Exits 0 if the store landed in its copy (1:
/// it did not read back, 2: the page already held that word).
fn store_program() -> Vec<u8> {
    use testprog::{Asm, BLOB_VADDR, Reg, static_elf};
    let word = u64::from_le_bytes(*b"A-store!");
    let mut a = Asm::new();
    let path = a.data(b"/usr/bin/dash\0");
    let bad = a.label();
    a.mov_data(Reg::Rdi, path);
    a.mov_imm(Reg::Rsi, 0);
    a.sys(2); // open
    a.mov(Reg::R13, Reg::Rax);
    a.mov_imm(Reg::Rdi, 0);
    a.mov_imm(Reg::Rsi, 8192);
    a.mov_imm(Reg::Rdx, 3); // PROT_READ | PROT_WRITE
    a.mov_imm(Reg::R10, 2); // MAP_PRIVATE
    a.mov(Reg::R8, Reg::R13);
    a.mov_imm(Reg::R9, 0);
    a.sys(9); // mmap
    a.mov(Reg::R14, Reg::Rax);
    a.load(Reg::Rbx, Reg::R14, 4096);
    a.mov_imm(Reg::R8, word);
    a.store(Reg::R14, 4096, Reg::R8);
    a.mov_imm(Reg::R15, 1);
    a.load(Reg::Rax, Reg::R14, 4096);
    a.cmp(Reg::Rax, Reg::R8);
    a.jne(bad);
    a.mov_imm(Reg::R15, 2);
    a.cmp(Reg::Rbx, Reg::R8);
    a.je(bad);
    a.mov_imm(Reg::R15, 0);
    a.bind(bad);
    a.mov(Reg::Rdi, Reg::R15);
    a.sys(231); // exit_group
    static_elf(
        &a.finish(BLOB_VADDR)
            .unwrap_or_else(|| fail("cellaccess: assembler")),
    )
}

/// Section 4: shared page-cache pages.
fn s4(ctx: &Ctx) -> bool {
    const RULE: &str = "shared_cache_pages_never_carry_writes_between_cells";
    let mut ok = true;
    let b_view = |when: &str| {
        let s = b_status(ctx);
        let (v, f) = (word(&s, "view"), word(&s, "file"));
        report(
            RULE,
            &alloc::format!("B's mapping and file are unchanged after {when}"),
            v == ctx.view0 && f == ctx.view0,
            &alloc::format!("expected {}, B's mapping {v}, B's file {f}", ctx.view0),
        )
    };

    // A CPU store into A's private mapping of the shared page.
    let p = LinuxProcess::new(ctx.a.cell.clone(), ctx.a.root.clone())
        .unwrap_or_else(|| fail("cellaccess: no process"));
    let (code, _) = run_linux(p, &store_program(), None, &["/cellaccess-store"]);
    ok &= report(
        RULE,
        "A's CPU store through MAP_PRIVATE landed in A's own copy",
        code == 0,
        &alloc::format!("the store program exited {code}"),
    );
    ok &= b_view("A's CPU store");

    // A's futex wake, read() into its mappings, and copy-up (perl).
    ok &= in_a(ctx, S4_PAGES);
    ok &= b_view("A's read() into its private mapping and its copy-up write");

    // The cache page itself, as B's root reads it, kept its bytes.
    let ino = ctx.b.root.lock().resolve(ROOT, SHARED_FILE, true);
    let page = ino.ok().and_then(|i| ctx.b.root.cached_page(i, 1));
    let bytes = page.map(|f| {
        let mut b = [0u8; 16];
        f.reader().read(&mut b);
        hex(&b)
    });
    ok &= report(
        RULE,
        "the shared cache page B's root maps kept its bytes",
        bytes.as_deref() == Some(ctx.view0.as_str()),
        &alloc::format!("expected {}, got {bytes:?}", ctx.view0),
    );
    // A's file is now in A's upper layer, so A's root no longer maps it.
    let a_ino = ctx.a.root.lock().resolve(ROOT, SHARED_FILE, true);
    ok &= report(
        RULE,
        "A's write copied the file up into A's own root",
        a_ino.is_ok_and(|i| ctx.a.root.cached_page(i, 1).is_none()),
        "A's root still maps the lower file",
    );

    // B's futex waiter is still waiting; the harness ends the wait with a
    // signal, and B reports how it ended.
    let s = b_status(ctx);
    ok &= report(
        RULE,
        "B's futex waiter was not woken by A",
        word(&s, "futex") == "waiting",
        &alloc::format!("B's waiter: {}", word(&s, "futex")),
    );
    let pid: u64 = ctx.id("futex_pid").parse().unwrap_or(0);
    let sent = crate::proc::send(ctx.b.cell.id(), pid, 10).is_ok(); // SIGUSR1
    let deadline = frame::time::now() + Duration::from_secs(30);
    let ended = loop {
        let s = b_status(ctx);
        let f = String::from(word(&s, "futex"));
        if f != "waiting" || frame::time::now() > deadline {
            break f;
        }
        frame::task::sleep_until(frame::time::now() + Duration::from_millis(50));
    };
    FUTEX_RELEASED.store(true, Ordering::Relaxed);
    ok &= report(
        RULE,
        "B's futex wait ended only when the harness signalled it (EINTR)",
        sent && ended == "EINTR",
        &alloc::format!("signal sent: {sent}; the wait ended with {ended}"),
    );

    ok &= opted_out(ctx);
    ok
}

/// Section 4, ADR-0004 §4: a cell whose root opted out of page sharing
/// (B') keeps its private cache pages while A fills the shared cache, and
/// is charged for them itself.
fn opted_out(ctx: &Ctx) -> bool {
    const RULE: &str = "shared_cache_pages_never_carry_writes_between_cells";
    let cell = Cell::new(&ctx.accounts, CELL_PAGES).unwrap_or_else(|| fail("cellaccess: no cell"));
    let root = Arc::new(
        Vfs::mount_disk_private(&ctx.disk, cell.account().clone())
            .unwrap_or_else(|_| fail("cellaccess: could not mount a private root")),
    );
    prepare(&root);
    let Some(ns) = root.private_ns() else {
        return report(
            RULE,
            "the opted-out root has a private namespace",
            false,
            "none",
        );
    };
    let mut ok = perl((&cell, &root), S4_PRIVATE, &[]) == 0;
    let ino = root
        .lock()
        .resolve(ROOT, SHARED_FILE, true)
        .unwrap_or_else(|_| fail("cellaccess: no shared file"));
    let phys = |root: &Vfs| -> Vec<u64> {
        (0..8)
            .filter_map(|i| root.cached_page(ino, i).map(|f| f.phys().as_u64()))
            .collect()
    };
    let before = phys(&root);
    let pages = crate::pagecache::private_pages(ns);
    let used = cell.account().used();
    ok &= report(
        RULE,
        "B' is charged for its own private cache pages",
        pages > 0 && used == pages as u64,
        &alloc::format!("{pages} private pages, {used} charged"),
    );
    let (_, _, misses0, _, _) = crate::pagecache::stats();
    ok &= in_a(ctx, S4_FILL);
    let (_, _, misses1, _, _) = crate::pagecache::stats();
    ok &= report(
        RULE,
        "A's reads went through more pages than the shared cache holds",
        misses1 - misses0 > 8192,
        &alloc::format!("{} chunks read", misses1 - misses0),
    );
    let after = phys(&root);
    ok &= report(
        RULE,
        "A filling the shared cache evicted none of the opted-out cell's pages",
        after == before
            && crate::pagecache::private_pages(ns) == pages
            && cell.account().used() == pages as u64,
        &alloc::format!(
            "pages {before:x?} -> {after:x?}, {pages} -> {} private pages, {} charged",
            crate::pagecache::private_pages(ns),
            cell.account().used()
        ),
    );
    drop(root);
    ok &= report(
        RULE,
        "the opted-out cell's private pages were returned with its root",
        crate::pagecache::private_pages(ns) == 0 && cell.account().used() == 0,
        &alloc::format!("{} still charged", cell.account().used()),
    );
    ok
}
