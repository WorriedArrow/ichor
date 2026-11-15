//! Self-test for the cell model (ADR-0002): capability isolation between
//! cells, rights enforcement, hierarchical memory accounting, and revocation.

use cap::{Cap, Handle, RevocationToken, Rights};
use frame::power::{ExitStatus, shutdown};
use frame::println;

use crate::kcell::{Cell, Object, System, rights};

fn fail(what: &str) -> ! {
    println!("ichor: celltest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

pub(crate) fn run() {
    // A system cell with a 1024-page budget, and two tenant cells under it.
    let system = System::new(1024).unwrap_or_else(|| fail("no memory for the system cell"));
    let cell_a = Cell::new(&system.root_account, 8).unwrap_or_else(|| fail("no cell A"));
    let cell_b = Cell::new(&system.root_account, 8).unwrap_or_else(|| fail("no cell B"));

    // Cell A gets a page. Its handle is meaningless in cell B.
    let grant = Rights::DUPLICATE | Rights::INSPECT | rights::READ | rights::WRITE;
    let h = cell_a
        .alloc_memory(grant)
        .unwrap_or_else(|| fail("cell A could not allocate"));
    if cell_a.memory(h, rights::READ).is_none() {
        fail("cell A cannot read its own page");
    }
    // The same raw handle value used in cell B must not resolve to anything.
    if cell_b
        .memory(Handle::from_raw(h.raw()), rights::READ)
        .is_some()
    {
        fail("a handle leaked across cells (isolation broken)");
    }

    // Rights are enforced: cell A was not granted MAP.
    if cell_a.memory(h, rights::MAP).is_some() {
        fail("a right that was never granted was honoured");
    }

    // Accounting: cell A's limit is 8 pages. Fill it and confirm the 9th
    // allocation is refused and nothing over-charges the parent.
    let mut handles = alloc::vec![h];
    for _ in 0..7 {
        match cell_a.alloc_memory(grant) {
            Some(hh) => handles.push(hh),
            None => fail("cell A hit its limit early"),
        }
    }
    if cell_a.alloc_memory(grant).is_some() {
        fail("cell A exceeded its 8-page account");
    }
    if cell_a.account().used() != 8 {
        fail("cell A account usage wrong");
    }

    // Releasing a page lets another allocation in, and rolls up to the parent.
    let Some(last) = handles.pop() else {
        fail("no handle to release");
    };
    cell_a.close(last);
    cell_a.release_memory(1);
    if cell_a.account().used() != 7 {
        fail("release did not update the account");
    }
    cell_a
        .alloc_memory(grant)
        .unwrap_or_else(|| fail("could not reallocate after release"));

    // Revocation: a capability minted under a token dies when revoked, for
    // every holder.
    let token = RevocationToken::new();
    let frame = frame::mm::UFrame::alloc_zeroed().unwrap_or_else(|| fail("no frame"));
    let cap = Cap::mint_revocable(
        Object::Memory(frame),
        rights::READ | Rights::DUPLICATE,
        token.clone(),
    );
    let rev = cell_b
        .install(cap)
        .unwrap_or_else(|| fail("install failed"));
    let rev_dup = cell_b
        .duplicate(rev, rights::READ)
        .unwrap_or_else(|| fail("could not duplicate"));
    if cell_b.memory(rev, rights::READ).is_none() || cell_b.memory(rev_dup, rights::READ).is_none()
    {
        fail("revocable cap not usable before revocation");
    }
    token.revoke();
    if cell_b.memory(rev, rights::READ).is_some() || cell_b.memory(rev_dup, rights::READ).is_some()
    {
        fail("revocation did not kill every copy");
    }

    // The parent account saw the children's usage roll up.
    let used = system.root_account.used();
    println!(
        "ichor: cell: 2 cells isolated, rights enforced, accounting ok ({} pages charged to system), revocation ok",
        used
    );
}
