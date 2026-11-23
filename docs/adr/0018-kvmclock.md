# ADR-0018: kvmclock is the clock on KVM

- Status: Accepted
- Date: 2026-11-23
- Amends: ADR-0001 §8 (frame budget)
- Milestone: 8 (clouds)

## Context

Frame's clock was the TSC divided by a frequency found once at boot: from
CPUID, a hypervisor's leaf, or a calibration against the ACPI PM timer or
the PIT. GCP's E2 machines report no frequency, so it was calibrated.

The live-migration campaign (`tests/migration`) showed two things on such
a machine, measured against the metadata server's NTP:

- A 10 ms calibration window was 14 ppm off (one PM timer tick is 28 ppm of
  10 ms). Windows are now 100 ms (0.25 ppm), without this ADR.
- A live migration moved the guest to a host whose TSC ran about 96 ppm
  differently. The clock did not jump, but from then on it lost 96 ppm, about
  8 s a day, and every later migration would add its own error. No
  calibration at boot can know a rate that changes after it.

KVM tells its guests how the TSC turns into nanoseconds in kvmclock: a page
the guest names in `MSR_KVM_SYSTEM_TIME_NEW`, holding a TSC stamp, the
host's time at that stamp, a multiplier and a shift, under a version that
is odd while the host writes. The host writes the page again whenever these
change, migrations included. Linux on KVM uses it as its clock source.

## Decision

On KVM with kvmclock (CPUID signature `KVMKVMKVM`, feature bit 3),
`frame::kvm` registers a page for the boot CPU, and it becomes the clock:

- `now()` is the host's time (stamp plus scaled TSC delta) less its value
  at boot. `wall_clock()` is the firmware's reading plus `now()`, so it
  follows too.
- The TSC frequency timers are programmed with is the one the multiplier
  and shift mean, which also replaces the boot calibration (the boot log
  says `TSC ... from kvmclock`).
- The page's numbers are copied into atomics under a sequence counter, and
  every CPU reads those, without a lock. Whichever CPU finds them more than
  10 ms old copies them again (one at a time; the others go on with what is
  there), so a migration's new rate is followed within 10 ms.

Only the boot CPU's page is registered. KVM keeps guest TSCs synchronized,
and frame assumes that already. A host updates a vCPU's page when that vCPU
next runs, and the boot CPU runs at least every few hundred milliseconds.

Other hypervisors keep the current source. Hyper-V's reference TSC page is
the same idea for Azure, and is not done yet.

Frame grows by about 130 lines and one unsafe site (the MSR write). Audit
step 12 is 6,850 lines / 295 sites.

## Alternatives considered

- **Calibrate again from time to time** (against the PM timer, or NTP). A
  migration would still go wrong until the next calibration, and calibrating
  takes time and a source that may be absent.
- **Discipline the wall clock with NTP.** That would hide the drift in the
  wall clock, but leave `now()`, which timers and timeouts use, running at the
  wrong rate. An NTP client is still worth having for the wall clock's
  absolute error, as a separate step.
- **Read each CPU's own page.** That would need a page per CPU, and preemption
  off while reading. Synchronized TSCs make the boot CPU's numbers right
  for all of them.

## Consequences

- On KVM (GCP, local QEMU with KVM, CI) the clock follows the host through
  migrations, and its rate is the host's measurement rather than a
  calibration.
- TCG and other hypervisors are unchanged.
- The live-migration campaign checks this: the clock's offset from NTP
  should stay flat across migrations.
