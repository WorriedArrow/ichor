# ADR-0024: Boot time is measured, and four waits leave the boot path

- Status: Accepted
- Date: 2026-11-28
- Amends: ADR-0001 §8 (frame budget), ADR-0005 (PCI enumeration), ADR-0019
  (the console)
- Milestone: 8 (clouds)

## Context

Nothing timed a boot. To compare Ichor's boot with Linux's, directly on a
cloud VM and as a Firecracker guest (`docs/benchmarks.md`), the kernel needs
to say when it is ready for containers, measured the same way each time.

Timed under OpenVMM on the development PC (2 vCPUs, Hyper-V's platform,
release build, the control plane on loopback), a boot went from frame's
entry to the control plane serving its API in 326 ms. Of that:

- **144 ms: PCI enumeration.** Frame read the vendor ID of device 0 of
  every one of 256 buses' 32 slots: 8,192 reads through ports 0xCF8/0xCFC,
  two VM exits each, on a machine with no PCI devices at all.
- **About 60 ms: the serial console.** ADR-0019 made writers stop waiting
  for a slow port, but they still handed it what it took at once. An
  emulated 16550 always has room, so every byte of the 3 KB boot log was
  written by the code that logged it: one VM exit a byte, about 20 us each
  under Hyper-V.
- **10.4 ms a further CPU: the MultiProcessor Specification's delays**
  (10 ms after INIT, 200 us after each STARTUP), written for external
  APICs.
- **About 20 ms: self-tests.** The timer test made every CPU take five 2 ms
  ticks, and the APs waited for theirs before going idle. The rest of the
  self-tests (cells, processes, copies, huge pages, the runtime programs,
  the native ABI, the disks' userlands) take seconds with test disks
  attached.

## Decision

- **Boot is timed from frame's entry.** Frame reads the TSC first thing in
  `efi_main` (`time::record_entry`) and at each of its steps (firmware
  files read, boot services exited, higher half, memory, TSC, PCI,
  mitigations), which it logs in one line (`ichor: frame: boot steps`).
  The kernel logs `ichor: boot: PHASE at T ms` at its own milestones
  (kernel entered, every CPU online, scheduler, network, self-tests) and
  `ready` when the control plane logs that it serves its API (the first
  `control: serving` line from the control plane's cell). It also logs the
  TSC's count at entry as time: a vCPU's TSC starts at 0 when the
  hypervisor makes it, so that is about how long the VMM and firmware took.
- **`boot_timer`** writes 123 to port 0x3F0 at `ready`: Firecracker's boot
  timer (`--boot-timer`) then logs the time since it started. Elsewhere the
  port is a floppy controller's read-only status register, or nothing.
- **`no_selftests`** is a production boot: the CPUs, the scheduler, the
  network, then the control plane. No self-test runs, the APs do not wait
  for timer ticks, and the disks are not probed (so `autorun` finds none).
  The tests and CI keep the default.
- **PCI enumeration follows bridges** (amends ADR-0005): bus 0; for a
  multi-function host bridge at 0:0, function N's bus N; and every
  PCI-to-PCI bridge's secondary bus, as Linux scans a root bus.
  `pci_scan_all` scans all 256 buses, as before, for a machine with a
  second root bus that only its ACPI tables name (frame has no AML
  interpreter to read `_BBN`).
- **Only the console task writes to the port** (amends ADR-0019). Writers
  format into the ring and return. The task takes a FIFO-full (16 bytes)
  at a time under the ring's lock and writes it outside, so a writer never
  waits behind a backlog; a second lock keeps the chunks in order, and
  `flush` takes it too. Before the scheduler starts, output waits in the
  ring (64 KiB, against a 3 KB boot log) until the task runs; a panic or
  shutdown flushes it. `console_sync` restores writers that hand the port
  what it takes, for chasing a hang before the console task starts.
- **APs start without the MP Specification's delays:** INIT, then two
  STARTUP IPIs 20 us apart, as Linux does on every CPU that can run in
  64-bit mode (`smp_quirk_init_udelay`).

## Alternatives considered

- **Leaving PCI as it was:** 8,192 probes cost a few milliseconds on bare
  metal, but every one is an exit in a VM, and 140 ms under Hyper-V. A
  nested Firecracker guest's exits are dearer still.
- **ECAM (memory-mapped configuration) through the MCFG table:** a probe
  is still an exit (a VMM emulates the page), so it saves the second exit
  of each probe, not the 8,000 probes; frame would also need to parse the
  MCFG and map the region.
- **A quieter boot log:** Ichor's log is its only local record; it should
  cost the boot nothing, not be shorter. Linux 7.3's 8250 console prints
  from its own thread too (nbcon).
- **Timing from the VMM's side only:** right for Firecracker, which the
  measurements do too, but it does not split the boot into steps or work on
  a cloud, where the start of the VM is not visible.

## Consequences

- Under OpenVMM the same boot is ready in about 56-90 ms instead of 326:
  frame 18 ms (of which PCI's bus 0 is 10, port I/O being slow under
  Hyper-V's platform), the second CPU 10 ms, and the rest mostly the
  VMBus network device's bring-up, which varies from 55 to 250 ms with
  when the host's offers arrive.
- Console output can now lag by the boot's backlog until the console task
  runs (a few milliseconds of boot). A hang before then shows nothing
  without `console_sync`; a QEMU test that times out still appends every
  vCPU's state to its log.
- A device behind a second root bus is not found without `pci_scan_all`.
  None of the machines Ichor has run on has one (QEMU's q35 and i440fx,
  GCP, AWS's m7i-flex, OpenVMM).
- Frame grows by about 95 lines (to 8,442 / 320); audit step 24 is
  8,450 / 325.
