//! Starts the control plane (ADR-0012 §1): `services/control`, embedded in
//! the kernel image, as a native process in the system cell holding the
//! root capabilities: the cell itself (`CREATE_CELL`), the switch, and
//! the boot volume's CA bundle.

use cap::{Cap, Rights};
use frame::println;
use frame::sync::SpinLock;

use crate::kcell::{Object, System, rights};

static CONTROL: &[u8] = include_bytes!(concat!(env!("ICHOR_SERVICES_DIR"), "/ichor-control"));

/// The control plane's DNS resolver, which its cells use too.
static RESOLVER: SpinLock<Option<alloc::string::String>> = SpinLock::new(None);

/// The resolver for a cell's `/etc/resolv.conf`.
pub(crate) fn resolver() -> Option<alloc::string::String> {
    RESOLVER.lock().clone()
}

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
    *RESOLVER.lock() = Some(dns);
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
/// The id of the cell the control plane runs in (0 until it starts).
static CONTROL_CELL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Whether `id` is the control plane's cell.
pub(crate) fn is_control_cell(id: u64) -> bool {
    id != 0 && id == CONTROL_CELL.load(core::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn run(
    roots: &'static [u8],
    suffixes: &'static [u8],
    (token, token_from): (&'static [u8], &str),
    (tls, tls_from): (&'static [u8], &str),
    options: &[alloc::string::String],
    api_bench: Option<&str>,
) -> Option<u64> {
    use alloc::format;
    // Most of memory: the control plane holds pulled layers and images,
    // and the cells it makes are carved from its account.
    let pages = frame::mm::stats().free_pages as u64 * 3 / 4;
    let system = System::new(pages)?;
    let cell = system.cell.clone();
    CONTROL_CELL.store(cell.id(), core::sync::atomic::Ordering::Relaxed);
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
            "no API token".into()
        } else {
            format!("API token from {token_from}")
        },
        if tls.is_empty() {
            "no API certificate".into()
        } else {
            format!("API certificate from {tls_from}")
        }
    );
    let hex = |h: cap::Handle| alloc::format!("{:x}", h.raw());
    let (me_s, switch_s, roots_s) = (hex(me), hex(switch), hex(roots_blob));
    // The API's token and TLS identity, if the boot volume has them
    // (`\ichor\apitoken`, `\ichor\apitls.pem`) or the cloud does.
    // The Public Suffix List's rules too (`\ichor\suffixes.dat`).
    let mut blobs = alloc::vec::Vec::new();
    for (name, bytes) in [
        ("token-blob", token),
        ("tls-blob", tls),
        ("suffix-blob", suffixes),
    ] {
        if !bytes.is_empty() {
            blobs.push(alloc::format!("{name}={}", hex(blob(bytes)?)));
        }
    }
    let mut argv = alloc::vec!["control", me_s.as_str(), &switch_s, &roots_s];
    argv.extend(options.iter().map(alloc::string::String::as_str));
    argv.extend(blobs.iter().map(alloc::string::String::as_str));
    if let Some(image) = api_bench {
        start_api_bench(&cell, options, image);
    }
    let code = crate::native::run(&cell, CONTROL, &argv);
    // The cell's handle to itself would keep it alive forever.
    let _ = cell.close(me);
    code
}

/// Container start through the API, timed by a client beside the control
/// plane (`api_bench=IMAGE`; Docker's client beside `dockerd`):
/// `nativetest api-bench` on its own task in the control plane's cell,
/// reaching it on that cell's loopback. It pulls `IMAGE` once, then times
/// 20 rounds of `CreateCell`, `Run` of `/bin/true` and `Destroy`, and logs
/// `native: api-bench n=.. ns=.. per_ns=..`; with `control_exit`, its
/// hanging up ends the run.
fn start_api_bench(
    cell: &alloc::sync::Arc<crate::kcell::Cell>,
    options: &[alloc::string::String],
    image: &str,
) {
    let port = options
        .iter()
        .find_map(|o| o.strip_prefix("port="))
        .unwrap_or("50051");
    let port = alloc::string::String::from(port);
    let (cell, image) = (cell.clone(), alloc::string::String::from(image));
    let task = frame::task::TaskOptions::new(move || {
        let argv = ["nativetest", "api-bench", &port, &image, "20"];
        if crate::native::run(&cell, crate::nativetest::NATIVETEST, &argv) != Some(0) {
            println!("ichor: bench: the API container start failed");
        }
    })
    .spawn();
    if task.is_none() {
        println!("ichor: bench: could not start the API client");
    }
}
