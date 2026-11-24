//! Boot self-test of native ABI v2 (ADR-0012 §2): runs the
//! `services/nativetest` binary, embedded in the kernel image, as a native
//! process in a system cell holding that cell's own handle (with
//! `CREATE_CELL`) and the switch's.

use cap::{Cap, Rights};
use frame::power::{ExitStatus, shutdown};
use frame::println;

use crate::kcell::{Object, System};

/// The test service (built by xtask for `x86_64-unknown-none`).
pub(crate) static NATIVETEST: &[u8] =
    include_bytes!(concat!(env!("ICHOR_SERVICES_DIR"), "/ichor-nativetest"));

fn fail(what: &str) -> ! {
    println!("ichor: nativetest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

pub(crate) fn run() {
    // Room for the test's heap, its image, and the 4096-page cell it makes.
    let system = System::new(16384).unwrap_or_else(|| fail("no system cell"));
    let cell = system.cell.clone();
    let me = cell
        .install(Cap::mint(Object::Cell(cell.clone()), Rights::ALL))
        .unwrap_or_else(|| fail("no cell handle"));
    let switch = cell
        .install(Cap::mint(Object::Switch, Rights::ALL))
        .unwrap_or_else(|| fail("no switch handle"));
    let (me_hex, switch_hex) = (
        alloc::format!("{:x}", me.raw()),
        alloc::format!("{:x}", switch.raw()),
    );
    match crate::native::run(&cell, NATIVETEST, &["nativetest", &me_hex, &switch_hex]) {
        Some(0) => println!(
            "ichor: native: v2 self-test passed ({} KiB service)",
            NATIVETEST.len() / 1024
        ),
        Some(code) => {
            println!("ichor: native: the self-test exited {code}");
            fail("native ABI v2");
        }
        None => fail("the native self-test did not run to its end"),
    }
    // The cell holds a handle to itself; closing it breaks the cycle. (The
    // service closed its copies on exit only if it dropped them.)
    let _ = cell.close(me);
    let _ = cell.close(switch);
}
