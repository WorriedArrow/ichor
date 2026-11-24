# ADR-0019: Console writes do not wait for the serial port

- Status: Accepted
- Date: 2026-11-23
- Amends: ADR-0001 §8 (frame budget)
- Milestone: 8 (clouds)

## Context

Frame's console wrote every byte to the 16550 UART before `print!`
returned, polling the line status once per FIFO-full. Under QEMU and
OpenVMM the emulated port takes bytes as fast as they come. A cloud's does
not: GCP's serial port runs at 115,200 baud, about 87 us a byte, and a
writer waited for all of it.

Timing container start through the control-plane API on GCP
(`api_bench`, `docs/benchmarks.md`) showed the cost: 16.8 ms a container
on every machine type, against 1.83 ms under OpenVMM. The control plane
logs three lines a container, about 190 bytes, which take 16.5 ms at
115,200 baud, and its one request loop waits for them. Every kernel log
line and every Linux process writing to the console paid the same way.

## Decision

Console output goes through a ring in frame (`console.rs`, 64 KiB, about
5.7 s of output at 115,200 baud):

- `print!` and `write_bytes` format into the ring under the console lock
  (which still serializes whole calls, so lines do not interleave), then
  hand the port what it takes without waiting (`early_console::room_now`:
  a FIFO-full if the transmitter is empty) and return.
- A full ring makes the writer wait for room, a FIFO-full at a time:
  nothing is dropped, and order is kept.
- The kernel's console task (`drain_console` in `main.rs`) calls
  `frame::console::drain` every millisecond while output waits and every
  20 ms otherwise. Writers do not wake it: they print from any context,
  the scheduler's own included, where waking a task could deadlock.
- `power::shutdown` and `power::power_off` flush the ring before the
  machine stops, so a test's serial log is complete. The panic handler
  flushes it if it can take the lock (it may be the holder: then what the
  ring holds is lost, and the report still goes out directly).
- Under QEMU and OpenVMM the port always has room, so output still leaves
  at once and test logs are unchanged.

## Alternatives considered

- **Interrupt-driven UART** (THR-empty interrupts drain the ring): no
  polling task, but frame would own another interrupt source, and the
  handler would contend with writers for the lock with interrupts masked.
  The 1 ms poll costs one task wake-up a millisecond only while output
  waits.
- **Fewer log lines in the control plane**: helps that one caller; the
  kernel's own logs and Linux processes writing to `/dev/console` would
  still wait.
- **Dropping output when the ring is full**: never waits, but loses log
  lines, which are the only local record of a headless machine.

## Consequences

- Logging no longer slows the code that logs, on clouds; a burst larger
  than 64 KiB still does. Measured on GCP the same day (n2, n2d Milan and
  Rome): container start through the API went from 16.8-17 ms to
  0.88-1.07 ms.
- Output can lag the code that wrote it by up to the ring's backlog. A hang
  can leave the last lines in the ring; the drain task keeps running on
  any CPU that is not stuck.
- Frame grows by about 80 lines (to 7,283 / 292); audit step 15 is
  7,350 / 310.
