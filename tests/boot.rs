//! Boot tests.
//!
//! Milestone 0: the kernel boots as a UEFI application, prints to serial,
//! exits boot services and halts cleanly.
//!
//! Milestone 1: frame builds its own page tables and runs in the higher
//! half, the page allocator and heap work, traps are handled (including a
//! stack overflow caught by a guard page), and every CPU comes online and
//! takes timer interrupts.
//!
//! Milestone 2 (scheduler): kernel threads run on every CPU, block and wake
//! through wait queues, and never-yielding threads are preempted.
//!
//! Milestone 2 (user mode): a ring-3 program runs in its own address space,
//! makes a syscall, faults, and is isolated from another address space.
//!
//! Milestone 2 (cells): capabilities isolate cells, rights are enforced,
//! memory is accounted hierarchically, revocation works, and a native-ABI
//! ring-3 process can act only on handles its cell holds.
//!
//! Milestone 3 (Linux ABI, in progress): a real static Linux x86-64 ELF runs
//! unmodified in a cell, writing to stdout and exiting through the Linux
//! syscall personality.

use ichor_tests::{Exit, boot};

const BOOT_MARKERS: &[&str] = &[
    "ichor: frame: entered from UEFI",
    "ichor: frame: boot services exited",
    "ichor: frame: running in the higher half",
    "ichor: frame: cpu0 ready (x2APIC id ",
    "ichor: kernel ",
    "ichor: memory: ",
    "ichor: acpi: rsdp at 0x",
    "ichor: kernel entry at 0xffffffff8",
    "ichor: heap: selftest passed",
    "ichor: trap: breakpoint handled (1 so far)",
];

#[test]
fn m1_boots_on_four_cpus() {
    let out = boot("m1-smp4", "memmap", 4);
    out.assert_exit(Exit::Success);
    out.assert_in_order(BOOT_MARKERS);
    out.assert_in_order(&[
        "ichor: smp: 4 CPUs online, every CPU took 5 timer interrupts",
        "ichor: sched: 32 threads finished",
        "ichor: sched: 9 spinners on 4 CPUs all ran (preemption works",
        "ichor: user: ring-3 program ran, 1 syscall(s), page fault at 0 handled, isolation ok",
        "ichor: cell: 2 cells isolated, rights enforced, accounting ok",
        "ichor: proc: native process ran, MEM_SIZE ok (4096), forged handle denied (error 2)",
        "hello from a real Linux ELF running on Ichor",
        "ichor: linux: static ELF ran via the Linux ABI, exited 7 after 2 syscalls",
        "ichor: boot complete; halting",
    ]);
    // Every page the heap self-test used came back.
    out.assert_in_order(&["(0 pages not returned)"]);
    // Between 300 MiB and 512 MiB of the 512 MiB guest is usable.
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
fn m1_boots_on_one_cpu() {
    let out = boot("m1-smp1", "", 1);
    out.assert_exit(Exit::Success);
    out.assert_in_order(BOOT_MARKERS);
    out.assert_in_order(&[
        "ichor: smp: 1 CPUs online, every CPU took 5 timer interrupts",
        "ichor: sched: 32 threads finished",
        "ichor: sched: 3 spinners on 1 CPUs all ran (preemption works",
        "ichor: user: ring-3 program ran, 1 syscall(s), page fault at 0 handled, isolation ok",
        "ichor: cell: 2 cells isolated, rights enforced, accounting ok",
        "ichor: proc: native process ran, MEM_SIZE ok (4096), forged handle denied (error 2)",
        "hello from a real Linux ELF running on Ichor",
        "ichor: linux: static ELF ran via the Linux ABI, exited 7 after 2 syscalls",
        "ichor: boot complete; halting",
    ]);
}

#[test]
fn m2_scheduler_on_eight_cpus() {
    let out = boot("m2-smp8", "", 8);
    out.assert_exit(Exit::Success);
    out.assert_in_order(&[
        "ichor: smp: 8 CPUs online, every CPU took 5 timer interrupts",
        "ichor: sched: 32 threads finished",
        "ichor: sched: 17 spinners on 8 CPUs all ran (preemption works",
        "ichor: user: ring-3 program ran, 1 syscall(s), page fault at 0 handled, isolation ok",
        "ichor: cell: 2 cells isolated, rights enforced, accounting ok",
        "ichor: proc: native process ran, MEM_SIZE ok (4096), forged handle denied (error 2)",
        "hello from a real Linux ELF running on Ichor",
        "ichor: linux: static ELF ran via the Linux ABI, exited 7 after 2 syscalls",
        "ichor: boot complete; halting",
    ]);
}

#[test]
fn panic_reports_failure_and_stops_other_cpus() {
    let out = boot("panic", "test_panic", 2);
    out.assert_exit(Exit::Failure);
    out.assert_in_order(&[
        "ichor: smp: 2 CPUs online",
        "ichor: KERNEL PANIC: ",
        "test_panic requested",
    ]);
}

#[test]
fn stack_overflow_hits_the_guard_page() {
    let out = boot("stack-overflow", "test_stack_overflow", 1);
    out.assert_exit(Exit::Failure);
    out.assert_in_order(&[
        "ichor: overflowing the kernel stack",
        "ichor: KERNEL PANIC: ",
        "double fault (kernel stack overflow)",
    ]);
}
