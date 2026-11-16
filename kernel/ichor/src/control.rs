//! Starts the control plane (ADR-0012 §1): `services/control`, embedded in
//! the kernel image, as a native process in the system cell holding the
//! root capabilities: the cell itself (`CREATE_CELL`), the switch, and
//! the boot volume's CA bundle.

use cap::{Cap, Rights};
use frame::println;

use crate::kcell::{Object, System, rights};

static CONTROL: &[u8] = include_bytes!(concat!(env!("ICHOR_SERVICES_DIR"), "/ichor-control"));

/// Runs the control plane on the calling task until it exits; returns its
/// exit code (`None`: it could not start or was killed).
pub(crate) fn run(
    roots: &'static [u8],
    port: u16,
    resolver: &str,
    exit_on_close: bool,
) -> Option<u64> {
    // Most of memory: the control plane holds pulled layers and images,
    // and the cells it makes are carved from its account.
    let pages = frame::mm::stats().free_pages as u64 * 3 / 4;
    let system = System::new(pages)?;
    let cell = system.cell.clone();
    let me = cell.install(Cap::mint(Object::Cell(cell.clone()), Rights::ALL))?;
    let switch = cell.install(Cap::mint(Object::Switch, Rights::ALL))?;
    let blob = cell.install(Cap::mint(
        Object::Blob(roots),
        Rights::DUPLICATE | Rights::INSPECT | rights::READ,
    ))?;
    println!(
        "ichor: control: starting ({} KiB service, {} KiB CA bundle, {} MiB)",
        CONTROL.len() / 1024,
        roots.len() / 1024,
        pages / 256
    );
    let hex = |h: cap::Handle| alloc::format!("{:x}", h.raw());
    let (me_s, switch_s, blob_s) = (hex(me), hex(switch), hex(blob));
    let port = alloc::format!("{port}");
    let mut argv = alloc::vec!["control", &me_s, &switch_s, &blob_s, &port, resolver];
    if exit_on_close {
        argv.push("exit-on-close");
    }
    let code = crate::native::run(&cell, CONTROL, &argv);
    // The cell's handle to itself would keep it alive forever.
    let _ = cell.close(me);
    code
}
