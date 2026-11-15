//! Milestone 0: the kernel boots as a UEFI application, prints to serial,
//! exits boot services and halts cleanly.

use ichor_tests::{Exit, boot};

#[test]
fn m0_boots_exits_boot_services_and_halts() {
    let out = boot("m0-boot", "memmap", 2);
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: frame: entered from UEFI",
        "ichor: frame: boot services exited",
        "ichor: kernel ",
        "ichor: cmdline: \"qemu_debug_exit memmap\"",
        " Usable",
        "ichor: memory: ",
        "ichor: acpi: rsdp at 0x",
        "ichor: milestone 0 complete; halting",
    ]);
    // Sanity-check the memory map against the 512 MiB the harness configures:
    // somewhere between 300 MiB and 512 MiB should be usable.
    let usable_mib: u64 = out
        .serial
        .lines()
        .find_map(|l| {
            l.split(" MiB usable")
                .next()?
                .rsplit(' ')
                .next()?
                .parse()
                .ok()
        })
        .expect("memory summary line");
    assert!(
        (300..=512).contains(&usable_mib),
        "usable memory {usable_mib} MiB"
    );
}

#[test]
fn panic_reports_failure() {
    let out = boot("panic", "test_panic", 1);
    out.assert_exit(Exit::Failure);
    out.assert_in_order(&[
        "ichor: frame: boot services exited",
        "ichor: KERNEL PANIC: ",
        "test_panic requested",
    ]);
}
