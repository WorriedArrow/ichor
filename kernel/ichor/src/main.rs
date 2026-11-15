//! The Ichor kernel.
//!
//! Built as a UEFI application (`x86_64-unknown-uefi`). Frame owns the firmware
//! entry point; this crate receives control once boot services are gone and
//! wires the subsystems together.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
use core::time::Duration;

use frame::boot::{BootInfo, MemoryKind};
use frame::cpu::{CpuId, IrqGuard};
use frame::power::{ExitStatus, shutdown};
use frame::println;

frame::main!(kmain);

frame::cpu_local! {
    static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);
}

/// Timer interrupts each CPU takes during the boot self-test.
const TICKS_WANTED: u64 = 5;

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
    }
    let cmdline = cmdline::Cmdline::new(info.cmdline());
    if cmdline.flag("memmap") {
        for region in info.memory_map() {
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
    heap_selftest();

    frame::debug::breakpoint();
    println!(
        "ichor: trap: breakpoint handled ({} so far)",
        frame::debug::breakpoint_count()
    );

    frame::time::set_timer_handler(on_timer);
    let cpus = frame::smp::start_aps(ap_main);
    wait_for_ticks();
    let deadline = frame::time::now() + Duration::from_secs(5);
    let all_ticked = || {
        TIMER_TICKS
            .iter()
            .all(|(_, t)| t.load(Relaxed) >= TICKS_WANTED)
    };
    while !all_ticked() && frame::time::now() < deadline {
        core::hint::spin_loop();
    }
    if all_ticked() {
        println!("ichor: smp: {cpus} CPUs online, every CPU took {TICKS_WANTED} timer interrupts");
    } else {
        for (cpu, t) in TIMER_TICKS.iter() {
            println!("ichor: smp: {cpu:?}: {} timer interrupts", t.load(Relaxed));
        }
        println!("ichor: smp: timer self-test FAILED");
        shutdown(ExitStatus::Failure);
    }

    if cmdline.flag("test_stack_overflow") {
        println!("ichor: overflowing the kernel stack");
        let r = recurse(0);
        println!("unreachable: {r}");
    }

    if cmdline.flag("test_panic") {
        // Exercises the panic path end to end (tests/boot.rs).
        #[allow(clippy::panic)]
        {
            panic!("test_panic requested on the command line");
        }
    }

    println!("ichor: boot complete; halting");
    shutdown(ExitStatus::Success)
}

/// Exercises the heap: many small objects of every size class, a large
/// block, and frees that must return all memory.
fn heap_selftest() {
    let before = frame::mm::stats();
    {
        let mut v: Vec<u64> = Vec::new();
        for i in 0..100_000 {
            v.push(i);
        }
        let sum: u64 = v.iter().sum();
        let mut map = BTreeMap::new();
        for i in 0..2_000u32 {
            map.insert(i, Box::new([i; 7]));
        }
        let boxes: Vec<Box<[u8]>> = (1..300)
            .map(|n| alloc::vec![n as u8; n * 7].into_boxed_slice())
            .collect();
        let big = alloc::vec![0xA5u8; 3 << 20];
        let ok = sum == 4_999_950_000
            && map.get(&1234).is_some_and(|b| b[6] == 1234)
            && boxes
                .iter()
                .enumerate()
                .all(|(i, b)| b.len() == (i + 1) * 7 && b[0] == (i + 1) as u8)
            && big.iter().all(|&b| b == 0xA5);
        println!(
            "ichor: heap: selftest {}",
            if ok { "passed" } else { "FAILED" }
        );
    }
    let after = frame::mm::stats();
    println!(
        "ichor: heap: {} MiB managed, {} MiB free ({} pages not returned)",
        after.total_pages / 256,
        after.free_pages / 256,
        before.free_pages.saturating_sub(after.free_pages),
    );
}

fn on_timer() {
    let guard = IrqGuard::new();
    let ticks = TIMER_TICKS.get(&guard).fetch_add(1, Relaxed) + 1;
    if ticks < TICKS_WANTED {
        frame::time::arm_timer(Duration::from_millis(2));
    }
}

/// Arms this CPU's timer and sleeps until it has fired `TICKS_WANTED` times.
fn wait_for_ticks() {
    frame::time::arm_timer(Duration::from_millis(2));
    loop {
        let done = {
            let guard = IrqGuard::new();
            TIMER_TICKS.get(&guard).load(Relaxed) >= TICKS_WANTED
        };
        if done {
            break;
        }
        frame::irq::enable_and_wait();
    }
}

fn ap_main(_cpu: CpuId) -> ! {
    wait_for_ticks();
    loop {
        frame::irq::enable_and_wait();
    }
}

/// Recurses until the stack overflows into its guard page.
#[allow(unconditional_recursion)]
fn recurse(n: u64) -> u64 {
    let frame = core::hint::black_box([n; 32]);
    recurse(frame[0] + 1).wrapping_add(frame[31])
}
