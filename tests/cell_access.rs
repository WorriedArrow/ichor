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

use ichor_tests::Outcome;

/// Sections the kernel runs (`SECTIONS` in cellaccess.rs).
const SECTIONS: usize = 9;
/// B's uplink-facing port inside the guest (`B_UPLINK_PORT` in
/// cellaccess.rs).
const B_UPLINK_PORT: u16 = 7300;

/// The boot, and how many of the host's connections B answered.
fn suite() -> &'static (Outcome, usize) {
    static OUT: OnceLock<(Outcome, usize)> = OnceLock::new();
    OUT.get_or_init(|| {
        use std::io::Read;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        // A host client that keeps connecting to B's uplink port through a
        // QEMU forward: the guest checks it is refused until the port is
        // published for B, and counts what reaches B.
        let host_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let halt = stop.clone();
        let client = std::thread::spawn(move || {
            let mut answers = 0;
            while !halt.load(Ordering::Acquire) {
                if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", host_port)) {
                    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                    let mut resp = String::new();
                    let _ = s.read_to_string(&mut resp);
                    if resp.contains("hello from cell B") {
                        answers += 1;
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            answers
        });
        let out = ichor_tests::boot_with("cell-access", "cell_access cell_access_uplink", 2, |c| {
            c.net_user_opts = format!("hostfwd=tcp:127.0.0.1:{host_port}-:{B_UPLINK_PORT}");
        });
        stop.store(true, Ordering::Release);
        (out, client.join().unwrap())
    })
}

/// Panics unless `rule`'s section passed, quoting its failed checks.
fn assert_rule(rule: &str) {
    let out = &suite().0;
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
    suite().0.assert_in_order(&[
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
    suite().0.assert_in_order(&[
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
    suite().0.assert_in_order(&[
        "/proc lists only A's processes: ok",
        "cellaccess: global: /proc/loadavg: ",
        "ichor: cellaccess: proc_and_sys_show_only_their_cell passed",
        "ichor: cellaccess: B alive and unchanged after proc_and_sys_show_only_their_cell",
    ]);
}

/// Section 4: A and B map the same cache page. A's CPU stores (private and
/// shared mappings), its read() into a private mapping and its copy-up
/// write leave B's mapping, B's file and the cache page unchanged; read()
/// into PROT_READ is EFAULT; a FUTEX_WAKE at B's futexes (same physical
/// page, offset and address, through shared and private mappings) wakes
/// nobody; an opted-out root keeps and pays for its own pages while A
/// fills the shared cache.
#[test]
fn shared_cache_pages_never_carry_writes_between_cells() {
    assert_rule("shared_cache_pages_never_carry_writes_between_cells");
    suite().0.assert_in_order(&[
        "B's mapping and file are unchanged after A's CPU store: ok",
        "B's file is unchanged after A's store through MAP_SHARED: ok",
        "both roots' page 1 of the file is the same physical page: ok",
        "FUTEX_WAKE at B's futex (shared mapping) wakes nobody: ok",
        "FUTEX_WAKE at B's futex (private mapping) wakes nobody: ok",
        "the shared cache page B's root maps kept its bytes: ok",
        "B's futex wait (shared mapping) ended only when the harness signalled it (EINTR): ok",
        "B's futex wait (private mapping) ended only when the harness signalled it (EINTR): ok",
        "A's reads brought in more pages than the shared cache holds: ok",
        "evicted none of the opted-out cell's pages: ok",
        "ichor: cellaccess: shared_cache_pages_never_carry_writes_between_cells passed",
    ]);
}

/// Section 5: A cannot bind B's address; cell to cell TCP is allowed
/// (ADR-0010) and comes from A's address; loopback is per cell; B's Unix
/// path and abstract names do not reach from A, and SCM_RIGHTS stays in
/// A. At the uplink, B's port is refused until it is published for B (a
/// port published for A never reaches B); then the host gets B's answer.
#[test]
fn networks_are_scoped_to_their_cell() {
    assert_rule("networks_are_scoped_to_their_cell");
    let (out, answers) = suite();
    out.assert_in_order(&[
        "bind(B's address) (EADDRNOTAVAIL): ok",
        "connect(B's Unix path) (ENOENT): ok",
        "B saw A's connection come from A's own address: ok",
        "an unpublished uplink port refuses the host while B listens on it: ok",
        "a port published for A delivers to A, never to B: ok",
        "published for B, the host reaches B's listener: ok",
        "ichor: cellaccess: networks_are_scoped_to_their_cell passed",
    ]);
    assert!(*answers >= 1, "the host never got B's answer");
}

/// Section 6: B's System V segment is not there for A under its key
/// (ENOENT) or id (EINVAL), and A's segment under the same key is another
/// one; io_uring operations from A that name B's path, abstract socket or
/// descriptor number fail as the plain syscalls do; sethostname is EPERM
/// and B's hostname unchanged; semaphores and message queues are ENOSYS
/// today (recorded).
#[test]
fn other_kernel_state_is_per_cell() {
    assert_rule("other_kernel_state_is_per_cell");
    suite().0.assert_in_order(&[
        "shmget(B's key) (ENOENT): ok",
        "A's segment under B's key is another one: ok",
        "IORING_OP_OPENAT(B's path) (ENOENT): ok",
        "IORING_OP_CONNECT(B's abstract name) (ECONNREFUSED): ok",
        "ichor: cellaccess: other_kernel_state_is_per_cell passed",
        "ichor: cellaccess: B alive and unchanged after other_kernel_state_is_per_cell",
    ]);
}

/// Section 7: uid 0 in A cannot mount, make device nodes, set the clock or
/// unshare namespaces (EPERM); the host superuser's other calls do not
/// exist (ENOSYS, recorded); it cannot chown or chmod B's files (ENOENT)
/// and signals none of B's processes (ESRCH).
#[test]
fn uid_0_in_a_cell_has_no_authority_outside_it() {
    assert_rule("uid_0_in_a_cell_has_no_authority_outside_it");
    suite().0.assert_in_order(&[
        "A runs as uid 0: ok",
        "mount (EPERM): ok",
        "chown(/b-only/secret) as uid 0 (ENOENT): ok",
        "ichor: cellaccess: uid_0_in_a_cell_has_no_authority_outside_it passed",
        "ichor: cellaccess: B alive and unchanged after uid_0_in_a_cell_has_no_authority_outside_it",
    ]);
}

/// Section 8: with A's memory used up its fork is EAGAIN, and its forks
/// stop at its account's limit; meanwhile B allocates and forks.
#[test]
fn resource_limits_are_per_cell() {
    assert_rule("resource_limits_are_per_cell");
    suite().0.assert_in_order(&[
        "A is at its memory limit: ok",
        "B allocates 8 MiB and forks while A is at its memory limit: ok",
        "A's fork at its memory limit failed with EAGAIN: ok",
        "A is at its process limit: ok",
        "B allocates 8 MiB and forks while A is at its process limit: ok",
        "A's fork at its process limit failed with EAGAIN: ok",
        "ichor: cellaccess: resource_limits_are_per_cell passed",
    ]);
}

/// Section 9: B's helper was alive and unchanged after every section, and
/// both cells' memory came back once they exited.
#[test]
fn cells_clean_up_after_themselves() {
    let out = &suite().0;
    let failed: Vec<&str> = out
        .serial
        .lines()
        .filter(|l| {
            l.contains("cellaccess FAILED: B after ") || l.contains("cellaccess FAILED: cell ")
        })
        .collect();
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    let alive = out
        .serial
        .matches("ichor: cellaccess: B alive and unchanged after ")
        .count();
    assert_eq!(alive, SECTIONS, "sections after which B was alive");
    out.assert_in_order(&["ichor: cellaccess: both cells exited and their memory returned"]);
}

/// A destroyed cell's System V segments go with it (ADR-0002 §7). Fails
/// until `linuxabi/shm.rs` frees them: a documented bug
/// (`docs/reports/cell-access-tests.md`).
#[test]
fn a_destroyed_cell_leaves_no_shared_memory() {
    assert_rule("a_destroyed_cell_leaves_no_shared_memory");
}
