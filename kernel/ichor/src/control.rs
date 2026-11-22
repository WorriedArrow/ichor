//! Starts the control plane (ADR-0012 §1): `services/control`, embedded in
//! the kernel image, as a native process in the system cell holding the
//! root capabilities: the cell itself (`CREATE_CELL`), the switch, and
//! the boot volume's CA bundle.

use cap::{Cap, Rights};
use frame::println;

use crate::kcell::{Object, System, rights};

static CONTROL: &[u8] = include_bytes!(concat!(env!("ICHOR_SERVICES_DIR"), "/ichor-control"));

/// The service's options from the kernel command line: `control=PORT`
/// (required), `control_listen=ADDR`, `control_publish=PORT`, `dns=ADDR`
/// (default: the uplink's DHCP-given DNS server, else QEMU's 10.0.2.3),
/// `control_plaintext`, `control_exit`, `control_exit_after=SECONDS`.
/// Without `control_listen` or `control_publish` the API is local to the
/// system cell.
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
    // The resolver: `dns=`, else the one the uplink's DHCP lease named,
    // else QEMU's.
    let dns = match c.get("dns") {
        Some(d) => alloc::string::String::from(d),
        None => match crate::switch::uplink_dns() {
            Some(ip) => format!("{ip}"),
            None => "10.0.2.3".into(),
        },
    };
    o.push(format!("dns={dns}"));
    if c.flag("control_plaintext") {
        o.push("plaintext".into());
    }
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
    tls: &'static [u8],
    options: &[alloc::string::String],
) -> Option<u64> {
    // Most of memory: the control plane holds pulled layers and images,
    // and the cells it makes are carved from its account.
    let pages = frame::mm::stats().free_pages as u64 * 3 / 4;
    let system = System::new(pages)?;
    let cell = system.cell.clone();
    let me = cell.install(Cap::mint(Object::Cell(cell.clone()), Rights::ALL))?;
    let switch = cell.install(Cap::mint(Object::Switch, Rights::ALL))?;
    let blob = |bytes: &'static [u8]| {
        cell.install(Cap::mint(
            Object::Blob(bytes),
            Rights::DUPLICATE | Rights::INSPECT | rights::READ,
        ))
    };
    let roots_blob = blob(roots)?;
    println!(
        "ichor: control: starting ({} KiB service, {} KiB CA bundle, {} MiB, {}, {})",
        CONTROL.len() / 1024,
        roots.len() / 1024,
        pages / 256,
        if token.is_empty() {
            "no API token"
        } else {
            "API token from the boot volume"
        },
        if tls.is_empty() {
            "no API certificate"
        } else {
            "API certificate from the boot volume"
        }
    );
    let hex = |h: cap::Handle| alloc::format!("{:x}", h.raw());
    let (me_s, switch_s, roots_s) = (hex(me), hex(switch), hex(roots_blob));
    // The API's token and TLS identity, if the boot volume has them
    // (`\ichor\apitoken`, `\ichor\apitls.pem`).
    let mut secrets = alloc::vec::Vec::new();
    for (name, bytes) in [("token-blob", token), ("tls-blob", tls)] {
        if !bytes.is_empty() {
            secrets.push(alloc::format!("{name}={}", hex(blob(bytes)?)));
        }
    }
    let mut argv = alloc::vec!["control", me_s.as_str(), &switch_s, &roots_s];
    argv.extend(options.iter().map(alloc::string::String::as_str));
    argv.extend(secrets.iter().map(alloc::string::String::as_str));
    let code = crate::native::run(&cell, CONTROL, &argv);
    // The cell's handle to itself would keep it alive forever.
    let _ = cell.close(me);
    code
}
