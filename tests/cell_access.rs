//! Cell access control through the Linux ABI
//! (`kernel/ichor/src/cellaccess.rs`; `docs/reports/cell-access-tests.md`).
//!
//! One boot with `cell_access` runs every section: two cells with their
//! own roots from the same Debian disk, a helper in B owning one object of
//! each kind, and checks from A that make the real syscall on B's object
//! (exact errno) and on A's own (the control). Each test below asserts one
//! rule's section of that boot, so a failure names the rule; they share
//! the boot.

use std::sync::OnceLock;

use ichor_tests::{Exit, Outcome};

fn suite() -> &'static Outcome {
    static OUT: OnceLock<Outcome> = OnceLock::new();
    OUT.get_or_init(|| ichor_tests::boot("cell-access", "cell_access", 2))
}

/// Panics unless `rule`'s section passed, quoting its failed checks.
fn assert_rule(rule: &str) {
    let out = suite();
    let failures: Vec<&str> = out
        .serial
        .lines()
        .filter(|l| l.contains("cellaccess FAILED") && l.contains(rule))
        .collect();
    let passed = format!("ichor: cellaccess: {rule} passed");
    assert!(
        failures.is_empty() && out.serial.contains(&passed),
        "{rule}: {} failed checks (exit {:?}):\n{}\n--- the section's log ---\n{}",
        failures.len(),
        out.exit,
        failures.join("\n"),
        out.serial
            .lines()
            .filter(|l| l.contains(rule))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_harness_gives_a_only_what_b_reports() {
    assert_rule("harness");
    suite().assert_in_order(&[
        "ichor: cellaccess: cell A is cell ",
        "ichor: cellaccess: cell B is cell ",
        "ichor: cellaccess: B's helper reports pid=",
        "ichor: cellaccess: B alive and unchanged after harness",
    ]);
}

/// Section 1: B's pids and tids are ESRCH (wait4: ECHILD) from A for kill,
/// tkill, tgkill, getpgid, getsid, setpgid, prlimit64 and
/// sched_getaffinity; a kill(p, 0) sweep over every pid finds only A's;
/// group signals and kill(-1) reach only A; B received nothing.
#[test]
fn process_ids_and_signals_are_scoped_to_their_cell() {
    assert_rule("process_ids_and_signals_are_scoped_to_their_cell");
    suite().assert_in_order(&[
        "finds only A's processes: ok",
        "ichor: cellaccess: process_ids_and_signals_are_scoped_to_their_cell passed",
        "ichor: cellaccess: B alive and unchanged after process_ids_and_signals_are_scoped_to_their_cell",
    ]);
}

/// Section 2: /proc/<B pid> is absent in A, /proc lists only A, and
/// /proc/self's links stay in A. Global files are printed for the report.
#[test]
fn proc_and_sys_show_only_their_cell() {
    assert_rule("proc_and_sys_show_only_their_cell");
    suite().assert_in_order(&[
        "/proc lists only A's process: ok",
        "cellaccess: global: /proc/loadavg: ",
        "ichor: cellaccess: proc_and_sys_show_only_their_cell passed",
        "ichor: cellaccess: B alive and unchanged after proc_and_sys_show_only_their_cell",
    ]);
}

/// Section 4: A and B map the same cache page. A's CPU store, its read()
/// into a private mapping and its copy-up write leave B's mapping, B's
/// file and the cache page unchanged; read() into PROT_READ is EFAULT; a
/// FUTEX_WAKE at B's futex (same page, offset and address) wakes nobody;
/// an opted-out root keeps and pays for its own pages while A fills the
/// shared cache.
#[test]
fn shared_cache_pages_never_carry_writes_between_cells() {
    assert_rule("shared_cache_pages_never_carry_writes_between_cells");
    suite().assert_in_order(&[
        "B's mapping and file are unchanged after A's CPU store: ok",
        "FUTEX_WAKE at B's futex wakes nobody: ok",
        "the shared cache page B's root maps kept its bytes: ok",
        "B's futex wait ended only when the harness signalled it (EINTR): ok",
        "evicted none of the opted-out cell's pages: ok",
        "ichor: cellaccess: shared_cache_pages_never_carry_writes_between_cells passed",
    ]);
}

#[test]
fn cells_clean_up_after_themselves() {
    let out = suite();
    out.assert_in_order(&[
        "ichor: cellaccess: every section passed; both cells exited and their memory returned",
    ]);
    out.assert_exit(Exit::Success);
}
