//! The Ichor kernel.
//!
//! Built as a UEFI application (`x86_64-unknown-uefi`). Frame owns the firmware
//! entry point; this crate receives control once boot services are gone and
//! wires the subsystems together.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use frame::boot::{BootInfo, MemoryKind};
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

    if cmdline.flag("test_panic") {
        // Exercises the panic path end to end (tests/boot.rs).
        #[allow(clippy::panic)]
        {
            panic!("test_panic requested on the command line");
        }
    }

    println!("ichor: milestone 0 complete; halting");
    shutdown(ExitStatus::Success)
}
