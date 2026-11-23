# ADR-0017: The ACPI power button and soft off

- Status: Accepted
- Date: 2026-11-22
- Amends: ADR-0001 §8 (frame budget)
- Milestone: 8 (clouds)

## Context

A cloud stops or deletes a machine by pressing its ACPI power button and
waiting for the guest to turn itself off. Ichor heard nothing, so every
stop waited out the cloud's timeout before the machine was pulled: about two
minutes on Google Cloud and several on AWS (2026-11-22). Turning off is
ACPI's S5 sleep state: a sleep type, read from the DSDT's `\_S5` object,
written with SLP_EN into the PM1 control registers.

Both need frame. The PM1 registers and the SMI command port are I/O ports,
which only frame touches. The S5 sleep types are in AML, which Ichor does
not interpret.

## Decision

- At boot, frame reads the FADT (`acpi::fadt_pm1`). A hardware-reduced FADT
  (flag 20) has no fixed hardware and is skipped. Otherwise frame owns the
  PM1a/PM1b event and control blocks and the SMI command port from then on.
  If ACPI mode is off (SCI_EN clear), frame turns it on by writing
  ACPI_ENABLE to SMI_CMD.
- `\_S5`'s two sleep types are read from the DSDT by matching that one
  object's usual encoding, `Name (_S5, Package { a, b, ... })`
  (`acpi::s5_sleep_types`, host-tested), and from the SSDTs if the DSDT
  has none (2026-11-23: GCP's is in Google's `GOOGSSDT`, not its DSDT).
  No AML is run. A table that computes them in a method gets no soft off.
- The power button is the fixed-hardware one (FADT flag 4 clear). Frame
  clears its status and sets its enable bit: hardware (QEMU's among it)
  records a press only while that bit is set. No SCI is taken: the
  IOAPIC stays masked, as it always has. `frame::power::power_button()`
  reads and clears the status. The kernel polls it four times a second
  from a task, and on a press calls `frame::power::power_off()`. That
  writes the sleep type and then SLP_EN to each control register, and
  halts if the machine is still running.
- If firmware left the SCI's IOAPIC pin unmasked, a press raises
  interrupts on whatever vector it set, until the next poll clears the
  status. Frame acknowledges vectors it does not know without panicking,
  so the cost is a few interrupts.

## Alternatives considered

- Taking the SCI: route IRQ 9 through the IOAPIC, which frame does not
  drive yet. A poll every 250 ms costs nothing worth that, and a stop has
  minutes to spare.
- An AML interpreter: thousands of lines for two integers, and it would sit
  in the TCB or beside it. Every cloud's DSDT tried has a plain `\_S5`.

## Consequences

- On GCP and AWS (KVM and Nitro, both with fixed-hardware FADTs) a stop
  should end the machine at once, not at the cloud's timeout. That is
  tested in QEMU, not yet on either cloud.
- Azure's generation 2 machines have a hardware-reduced FADT. Their stop
  goes through Hyper-V's shutdown integration service, a VMBus channel
  (ADR-0016), which is not written yet.
- `the_power_button_turns_the_machine_off` presses QEMU's button
  (`system_powerdown`) while the control plane serves, and expects QEMU
  to end with status 0.
- `TaskOptions::spawn` now returns `None` before a scheduler is
  injected. The first version of the button's poller was spawned that
  early and silently never ran: `enqueue` dropped the task, and `spawn`
  still answered `Some`.
- Frame grows by 66 lines, to 6,663 lines and 279 unsafe sites. Audit
  step 11 is 6,700 / 290.
