//! `autorun=PATH`: after the boot's self-tests, a cell over the root of
//! the disk that holds `PATH` (a second disk, not the boot disk's test
//! root: `cargo xtask root-image` makes one) runs `PATH` for as long as the
//! machine runs, with `autorun_publish=PORT[,PORT...]` published on the
//! uplink to the same ports of the cell, and `autorun_mib=N` of memory
//! (default 1024). The way a machine whose only job is one container
//! starts it without a control-plane client: an sshd for a fuzzer that
//! drives the Linux ABI over ssh (syzkaller), for one.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use frame::println;
use frame::sync::SpinLock;
use frame::user::UserContext;

use crate::kcell::{Cell, System};
use crate::pagecache::Mounted;
use crate::process::LinuxProcess;
use crate::vfs::{ROOT, Vfs};

#[derive(Clone)]
struct Config {
    path: String,
    publish: Vec<u16>,
    mib: u64,
}

static CONFIG: SpinLock<Option<Config>> = SpinLock::new(None);
/// The disk that holds the program, once a disk scan found it.
static DISK: SpinLock<Option<Mounted>> = SpinLock::new(None);

const ENVP: &[&str] = &[
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root",
    "TERM=dumb",
];

/// Takes `autorun`, `autorun_publish` and `autorun_mib` from the command
/// line.
pub(crate) fn configure(cmdline: &cmdline::Cmdline<'_>) {
    let Some(path) = cmdline.get("autorun").filter(|p| p.starts_with('/')) else {
        return;
    };
    let publish = cmdline
        .get("autorun_publish")
        .map(|ports| ports.split(',').filter_map(|p| p.parse().ok()).collect())
        .unwrap_or_default();
    let mib = cmdline
        .get("autorun_mib")
        .and_then(|m| m.parse().ok())
        .unwrap_or(1024);
    *CONFIG.lock() = Some(Config {
        path: path.into(),
        publish,
        mib,
    });
}

/// Whether `vfs`, a disk's root, is the one autorun runs from: it holds
/// the program. Such a disk gets none of the boot's disk checks.
pub(crate) fn wants(vfs: &Vfs) -> bool {
    let Some(path) = CONFIG.lock().as_ref().map(|c| c.path.clone()) else {
        return false;
    };
    DISK.lock().is_none() && vfs.lock().resolve(ROOT, &path, true).is_ok()
}

/// Keeps the disk [`wants`] chose.
pub(crate) fn keep(m: Mounted) {
    *DISK.lock() = Some(m);
}

/// Whether the command line asked for autorun.
pub(crate) fn enabled() -> bool {
    CONFIG.lock().is_some()
}

/// Runs the program on this task until it exits; its wait status, or
/// `None` if it could not be started.
pub(crate) fn run() -> Option<u32> {
    let cfg = CONFIG.lock().clone()?;
    let Some(m) = DISK.lock().take() else {
        println!(
            "ichor: autorun: FAILED: no disk holds {} (attach it as a second disk)",
            cfg.path
        );
        return None;
    };
    let pages = cfg.mib.saturating_mul(256);
    let Some(system) = System::new(pages.saturating_add(256)) else {
        println!("ichor: autorun: FAILED: no system cell of {} MiB", cfg.mib);
        return None;
    };
    let Some(cell) = Cell::new(&system.root_account, pages) else {
        println!("ichor: autorun: FAILED: no cell of {} MiB", cfg.mib);
        return None;
    };
    let Ok(vfs) = Vfs::mount_disk(&m) else {
        println!("ichor: autorun: FAILED: mounting its disk");
        return None;
    };
    let addr = crate::netstack::stack_for(&cell).addr();
    for &port in &cfg.publish {
        if !crate::switch::publish(net::wire::PROTO_TCP, port, cell.id(), port) {
            println!("ichor: autorun: could not publish port {port}");
        }
    }
    println!(
        "ichor: autorun: {} in cell {} at {addr:?}, {} MiB, TCP ports {:?} published",
        cfg.path,
        cell.id(),
        cfg.mib,
        cfg.publish
    );
    let Some(mut p) = LinuxProcess::new(cell, Arc::new(vfs)) else {
        println!("ichor: autorun: FAILED: no process");
        return None;
    };
    let leader = p.group.leader.clone();
    let mut ctx = UserContext::new(0, 0);
    let argv = alloc::vec![cfg.path.clone().into_bytes()];
    let envp = ENVP.iter().map(|e| e.as_bytes().to_vec()).collect();
    if let Err(e) = crate::linuxabi::exec::exec(&mut p, &mut ctx, cfg.path.clone(), argv, envp) {
        println!("ichor: autorun: FAILED: exec {}: errno {e}", cfg.path);
        frame::mm::activate_kernel_space();
        crate::proc::discard(p);
        return None;
    }
    crate::proc::run(p, ctx);
    let status = loop {
        if let Some(s) = crate::proc::exit_status(&leader) {
            break s;
        }
        frame::task::sleep_until(frame::time::now() + Duration::from_millis(50));
    };
    println!(
        "ichor: autorun: {} ended, wait status {status:#x}",
        cfg.path
    );
    Some(status)
}
