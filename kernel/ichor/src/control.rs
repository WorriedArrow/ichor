//! Starts the control plane (ADR-0012 §1): `services/control`, embedded in
//! the kernel image, as a native process in the system cell holding the
//! root capabilities: the cell itself (`CREATE_CELL`), the switch, and
//! the boot volume's CA bundle.

use cap::{Cap, Rights};
use frame::println;

use crate::kcell::{Object, System, rights};

static CONTROL: &[u8] = include_bytes!(concat!(env!("ICHOR_SERVICES_DIR"), "/ichor-control"));

/// The service's options from the kernel command line: `control=PORT`
/// (required), `control_listen=ADDR`, `control_publish=PORT`, `dns=ADDR`,
/// `control_exit`, `control_exit_after=SECONDS`. Without `control_listen`
/// or `control_publish` the API is local to the system cell.
pub(crate) fn options(c: &cmdline::Cmdline<'_>) -> Option<alloc::vec::Vec<alloc::string::String>> {
    use alloc::format;
    let port: u16 = c.get("control")?.parse().ok()?;
    let mut o = alloc::vec![format!("port={port}")];
    if let Some(a) = c.get("control_listen") {
        o.push(format!("listen={a}"));
    }
    if let Some(p) = c.get("control_publish") {
        o.push(format!("publish={p}"));
    }
    o.push(format!("dns={}", c.get("dns").unwrap_or("10.0.2.3")));
    if c.flag("control_exit") {
        o.push("exit-on-close".into());
    }
    if let Some(s) = c.get("control_exit_after") {
        o.push(format!("exit-after={s}"));
    }
    Some(o)
}

/// Runs the control plane on the calling task until it exits; returns its
/// exit code (`None`: it could not start or was killed).
pub(crate) fn run(
    roots: &'static [u8],
    token: &'static [u8],
    options: &[alloc::string::String],
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
    // The API token, if the boot volume has one (`\ichor\apitoken`).
    let token_blob = if token.is_empty() {
        None
    } else {
        Some(cell.install(Cap::mint(
            Object::Blob(token),
            Rights::DUPLICATE | Rights::INSPECT | rights::READ,
        ))?)
    };
    println!(
        "ichor: control: starting ({} KiB service, {} KiB CA bundle, {} MiB, {})",
        CONTROL.len() / 1024,
        roots.len() / 1024,
        pages / 256,
        if token.is_empty() {
            "no API token"
        } else {
            "API token from the boot volume"
        }
    );
    let hex = |h: cap::Handle| alloc::format!("{:x}", h.raw());
    let (me_s, switch_s, blob_s) = (hex(me), hex(switch), hex(blob));
    let token_opt = token_blob.map(|h| alloc::format!("token-blob={:x}", h.raw()));
    let mut argv = alloc::vec!["control", me_s.as_str(), &switch_s, &blob_s];
    argv.extend(options.iter().map(alloc::string::String::as_str));
    argv.extend(token_opt.as_deref());
    let code = crate::native::run(&cell, CONTROL, &argv);
    // The cell's handle to itself would keep it alive forever.
    let _ = cell.close(me);
    code
}
