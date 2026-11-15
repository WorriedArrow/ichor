//! The Ichor kernel.
//!
//! Built as a UEFI application (`x86_64-unknown-uefi`). Frame owns the firmware
//! entry point; this crate receives control once boot services are gone and
//! wires the subsystems together.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

mod alpinetest;
mod bench;
mod blktest;
mod busytest;
mod celltest;
mod cred;
mod debiantest;
mod dev;
mod file;
mod futex;
mod kcell;
mod linuxabi;
mod loader;
mod locks;
mod nativeabi;
mod pagecache;
mod pipe;
mod poll;
mod proc;
mod process;
mod procfs;
mod proctest;
mod pty;
mod random;
mod runtest;
mod sched;
mod selftest;
mod signal;
mod testprog;
mod umem;
mod usertest;
mod vfs;

use frame::boot::{BootInfo, MemoryKind};
use frame::cpu::CpuId;
use frame::power::{ExitStatus, shutdown};
use frame::println;

frame::main!(kmain);

fn kmain(info: BootInfo) -> ! {
    let (major, minor) = info.uefi_revision();
    println!(
        "ichor: kernel {} on {} (firmware rev {:#x}, UEFI {}.{})",
        env!("CARGO_PKG_VERSION"),
        info.firmware_vendor(),
        info.firmware_revision(),
        major,
        minor / 10,
    );
    println!("ichor: cmdline: {:?}", info.cmdline());
    let cmdline = cmdline::Cmdline::new(info.cmdline());
    if let Some(pid) = cmdline.get("trace_pid").and_then(|v| v.parse().ok()) {
        linuxabi::TRACE_PID.store(pid, core::sync::atomic::Ordering::Relaxed);
    }
    if cmdline.flag("trace_errors") {
        linuxabi::TRACE_ERRORS.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    if cmdline.flag("bench") {
        bench::enable();
    }

    let image = info.kernel_image();
    println!("ichor: image at {} ({} KiB)", image.base, image.len / 1024);
    let mut usable = 0u64;
    let mut boot_services = 0u64;
    for region in info.memory_map() {
        match region.kind {
            MemoryKind::Usable => usable += region.len,
            MemoryKind::BootServices => boot_services += region.len,
            _ => {}
        }
        if cmdline.flag("memmap") {
            println!("ichor:   {region:?}");
        }
    }
    println!(
        "ichor: memory: {} regions, {} MiB usable, {} MiB reclaimable from boot services",
        info.memory_map().len(),
        usable >> 20,
        boot_services >> 20,
    );
    match info.acpi_rsdp() {
        Some(rsdp) => println!("ichor: acpi: rsdp at {rsdp}"),
        None => println!("ichor: acpi: no rsdp"),
    }
    println!(
        "ichor: kernel entry at {:#x}",
        kmain as fn(BootInfo) -> ! as usize
    );

    // Milestone 1: memory, traps, SMP, timers.
    selftest::heap();
    selftest::breakpoint();
    selftest::install_timer_handler();
    let cpus = frame::smp::start_aps(ap_main);
    selftest::timers_on_every_cpu(cpus);

    random::init();
    match frame::cpu::xstate_features() {
        0 => println!("ichor: xstate: no XSAVE; x87/SSE via FXSAVE"),
        x => println!(
            "ichor: xstate: XCR0 {x:#x}, {} bytes per thread (ADR-0008)",
            frame::cpu::xstate_size()
        ),
    }
    match frame::time::wall_clock() {
        Some(t) => println!(
            "ichor: time: wall clock from UEFI, {} s since the epoch",
            t.as_secs()
        ),
        None => println!("ichor: time: no wall clock; CLOCK_REALTIME counts from boot"),
    }

    // Milestone 2: tasks and scheduling.
    frame::task::inject_scheduler(&sched::SCHEDULER);
    selftest::threads();
    selftest::preemption();
    selftest::timed_waits();
    selftest::user_mode();
    celltest::run();
    proctest::run();
    runtest::run();
    blktest::run();

    if cmdline.flag("test_stack_overflow") {
        selftest::stack_overflow();
    }
    if cmdline.flag("test_panic") {
        // Exercises the panic path end to end (tests/boot.rs).
        #[allow(clippy::panic)]
        {
            panic!("test_panic requested on the command line");
        }
    }

    // Nothing may need more contiguous memory than MAX_ORDER (4 MiB).
    let largest = frame::mm::stats().largest_request_order;
    println!(
        "ichor: memory: largest contiguous request 2^{largest} pages (MAX_ORDER {})",
        frame::mm::MAX_ORDER
    );
    if largest > u32::from(frame::mm::MAX_ORDER) {
        println!("ichor: FAILED: a request exceeded MAX_ORDER");
        shutdown(ExitStatus::Failure);
    }

    println!("ichor: boot complete; halting");
    shutdown(ExitStatus::Success)
}

/// Entry for every other CPU once frame has initialized it.
fn ap_main(_cpu: CpuId) -> ! {
    selftest::wait_for_ticks();
    frame::task::become_idle()
}
