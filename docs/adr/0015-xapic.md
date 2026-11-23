# ADR-0015: Machines without x2APIC

- Status: Accepted
- Date: 2026-11-22
- Amends: ADR-0001 §8 (frame budget)
- Milestone: 8 (Azure)

## Context

Frame has required x2APIC: every server CPU of the last decade has it, and
its registers are MSRs, with no memory mapping. What a hypervisor shows its
guests is another matter. Hyper-V's guests here (a WSL 2 kernel, read on
2026-11-22) have neither x2APIC nor a TSC-deadline timer, and Azure is
Hyper-V. QEMU's WHPX has no x2APIC either.

## Decision

Where CPUID has no x2APIC, frame drives the local APIC as an xAPIC: the same
registers, in the page `IA32_APIC_BASE` names, mapped uncached once, on the
boot CPU, for all of them (each sees its own).

- The registers are the x2APIC's, 16 bytes each: one accessor pair takes the
  MSR's number for both.
- The interrupt command register is two: the destination is written first
  and the second write sends. Interrupts are off in between, and the sender
  waits until it is delivered.
- APIC IDs are 8 bits: 255 CPUs at most (`MAX_CPUS` is 1,024). Machines
  with more have x2APIC.
- `IoMem` goes on refusing the system devices' range: no driver can map the
  APIC's page.

Where there is an x2APIC, nothing changes. A test boots a machine without
one, nor a TSC-deadline timer (`boots_without_x2apic`).

## Alternatives considered

- **Hyper-V's synthetic APIC MSRs** (EOI, ICR and TPR). They save VM exits
  on Hyper-V, but cover three registers: the timer and the rest would be an
  xAPIC's all the same, and QEMU could not test it. They can come later, as
  the optimization they are.
- **Requiring x2APIC**, and so leaving out Azure.

## Budget

Frame's audit step 9 is 6,450 code lines / 270 unsafe sites, within
ADR-0007's ceiling of 9,500 / 420 (6,357 / 262 at this change). The rest is
for what a Hyper-V guest needs next, which gets an ADR of its own.
