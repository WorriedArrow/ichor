# Ichor's speculation mitigations against Linux's, machine by machine

Benchmark round 18 (2026-11-27) booted Debian 13 beside Ichor on GCP's n2
(Ice Lake), c3 (Sapphire Rapids), n2d Milan and n2d Rome, and on AWS's
m7i-flex (Sapphire Rapids). On each Debian machine the script
(`linux13.sh`) listed `/sys/devices/system/cpu/vulnerabilities/*`, the CPU
`bugs` and the speculation flags, and the kernel's own mitigation lines in
`dmesg`, twice: on Debian 13's kernel (6.12.117 in GCP's image, 6.12.118 in
AWS's) and on the newest kernel
trixie-backports has (7.3.4). The two listed the same mitigations
everywhere; 7.3 only adds rows (`ghostwrite`, `old_microcode`, both "Not
affected") and names `spectre_v2_user` among the bugs. Ichor's side is its
boot log (`cpu0 speculation` and `mitigations` lines) on the same machine
type in the same zone, and its code (`arch::cpu::vulnerabilities`,
`usermode::enable_mitigations`).

**Since round 19 (the same day) the gaps below are closed** (ADR-0004's
second 2026-11-27 amendment):

- ITS on n2: aligned thunks.
- TSA on Milan: VERW on the way to ring 3.
- STIBP on Milan and Rome: always on.
- Speculative store bypass: disabled by prctl.
- MMIO stale data: detected, and no VERW, as Linux does for user space.
- TAA and GDS: tested as Linux tests them, so VERW is off on AWS's m7i.

Every machine's boot log in round 19 agrees with Linux's sysfs above, but
for three differences, each by design:

- Ichor puts IBPB between cells unconditionally.
- Ichor keeps STIBP always on where Linux's default on Milan is
  conditional.
- Indirect-branch speculation cannot be set by prctl.

The costs are in `docs/benchmarks.md`, round 19. What follows is the
comparison as it stood in round 18.

Both kernels see the CPU through the hypervisor: what a guest is told
(CPUID, `IA32_ARCH_CAPABILITIES`) decides what is "affected". So "Not
affected" below is per cloud and machine type, not per microarchitecture.

## The issues that apply somewhere

| Issue | Machine | Linux 7.3.4 (sysfs) | Ichor | Verdict |
|---|---|---|---|---|
| Spectre v2, kernel | n2, c3, m7i | Enhanced / Automatic IBRS | eIBRS | same |
| Spectre v2, kernel | Milan, Rome | Retpolines | retpolines | same |
| Spectre v2, firmware | Milan | `IBRS_FW` (IBRS around firmware calls) | firmware is called only at boot, before user code | not needed |
| Spectre v2, user to user, time-sliced | all | `IBPB: conditional` (only for tasks that ask, by prctl or seccomp) | IBPB on every switch to another cell's task | Ichor stronger |
| Spectre v2, user to user, SMT siblings | Milan | `STIBP: conditional` | nothing | **gap** (Linux's default protects only tasks that ask) |
| Spectre v2, user to user, SMT siblings | Rome | `STIBP: always-on` | nothing | **gap** |
| Branch history injection | n2 | `BHI: SW loop` | the clearing sequence on every entry | same |
| Branch history injection | c3, m7i | `BHI: BHI_DIS_S` | `BHI_DIS_S` | same |
| RSB underflow | all | RSB filling on context switch | RSB filled on context switch | same |
| PBRSB (eIBRS) | n2, c3, m7i | `SW sequence` (on VM exit) | — | host only: Ichor runs no guests |
| Indirect target selection (ITS) | n2 | `Mitigation: Aligned branch/return thunks` | not detected | **gap** |
| Retbleed | Rome | `untrained return thunk; SMT enabled with STIBP protection` | safe RET (Zen 1/2 untraining thunk), no STIBP | **partial**: no protection between SMT siblings |
| SRSO (Inception) | Milan, Rome | `Safe RET` | safe RET | same |
| Transient scheduler attacks (TSA) | Milan | `Mitigation: Clear CPU buffers` (VERW on the way to user space) | not detected, no VERW | **gap** |
| Speculative store bypass | all | `disabled via prctl` (only for tasks that ask) | not offered | **gap** in what a program can ask for; the default is the same (unprotected) |
| Spectre v1 | all | usercopy/swapgs barriers, `__user` pointer sanitization | masked indices (system call numbers, descriptors, signals, capability slots, io_uring tables); user memory read through page-table walks, never by dereferencing a user pointer; GS never switched, so no `swapgs` | same in kind (different mechanism; neither is exhaustive) |

## Where Ichor does more than it needs: TAA and GDS on AWS

On the m7i-flex (Xeon Platinum 8488C) Ichor's boot log says `taa affected,
gds affected` and turns on VERW on every return to ring 3; Linux lists
`tsx_async_abort` and `gather_data_sampling` as "Not affected". The c3 is
the same CPU generation, and there Ichor agrees with Linux: GCP's
hypervisor sets `TAA_NO` and `GDS_NO` in `IA32_ARCH_CAPABILITIES`, AWS's
does not. Ichor reads only those bits. Linux also asks:

- TAA needs TSX: Linux sets the bug only where the CPU has RTM
  (CPUID.7:EBX[11]) or `TSX_CTRL` (`ARCH_CAPABILITIES` bit 7), and the
  8488C there has neither.
- GDS affects a list of models (Skylake to Tiger Lake and Ice Lake);
  Sapphire Rapids is not on it, whatever `GDS_NO` says.

The GDS error is only in the log (Ichor relies on microcode for it), but
the TAA one costs a VERW on every system call, fault and interrupt return
on AWS's m7i: the round's null system call there is a tie with Linux 7.3
(80 ns each) while Ichor pays it.

## The issues that apply nowhere here

Both kernels agree that none of these five machines is affected by
Meltdown, MDS, MMIO stale data, L1TF, SRBDS, RFDS (register file data
sampling), iTLB multihit, VMScape, GhostWrite or old microcode, nor (but
for Ichor on the m7i, above) by TAA or GDS. Ichor's boot log says
`meltdown no, mds no` on each, and switches page-table isolation on
nowhere.

Two latent gaps, invisible on these machines:

- **MMIO stale data.** Ichor clears CPU buffers only where MDS or TAA
  applies. A CPU with `MDS_NO` and `TAA_NO` that is still affected by MMIO
  stale data (an Ice Lake server on bare metal, for one; Linux reads
  `SBDR_SSDP_NO`, `FBSDP_NO`, `PSDP_NO` and `FB_CLEAR` for it) would get no
  VERW. ADR-0004's table names MMIO stale data beside MDS and TAA, but the
  code does not test for it.
- **RFDS and SRBDS** are not detected (Atom cores and client parts, so not
  cloud machines today); GDS is detected and logged, its mitigation being
  microcode, as ADR-0004 says.

`itlb_multihit` and VMScape are a hypervisor's to mitigate, and Ichor is
not one.

## SMT

Linux 7.3 logs `Enabled attack vectors: user_kernel, user_user,
guest_host, guest_guest, SMT mitigations: auto`. ADR-0004 §3 plans
dedicated cores (no other cell on a core's sibling) and an SMT-off mode
for untrusted tenants; neither is built, and frame does not know the CPU
topology yet. Every GCP machine here has two threads a core. On eIBRS
parts (n2, c3, m7i) enhanced IBRS also keeps siblings' branch predictions
apart, which is why Linux shows no STIBP there; on Milan and Rome nothing
in Ichor does.

## What closing the gaps takes

- **TSA (Milan, Zen 3 and 4):** read `TSA_SQ_NO`/`TSA_L1_NO` (CPUID
  8000_0021h ECX[1:2]) and `VERW_CLEAR` (EAX[5]), and turn on the existing
  VERW on return to ring 3 where they call for it. Linux pays this too.
- **ITS (Ice Lake, Tiger Lake, Cascade Lake with eIBRS):** read `ITS_NO`
  (`IA32_ARCH_CAPABILITIES` bit 62) and, where it is clear, put the
  indirect `jmp r11` of `__x86_indirect_thunk_r11` and the `ret` of the
  return thunk in the upper half of a cache line, as Linux's aligned
  thunks do. The kernel already sends every indirect branch and return
  through those two thunks (`-Zretpoline-external-thunk`,
  `-Zfunction-return=thunk-extern`), so this is the thunks' bytes and
  alignment, patched at boot.
- **STIBP on Milan and Rome:** `IA32_SPEC_CTRL.STIBP` while a CPU runs a
  cell whose sibling may run another; always on (Linux's choice on Rome)
  is the simple form. Or ADR-0004 §3's dedicated cores.
- **Speculative store bypass:** `PR_SET_SPECULATION_CTRL` and SSBD
  (`IA32_SPEC_CTRL` bit 2, or AMD's `VIRT_SPEC_CTRL`) for the threads
  that ask.
- **MMIO stale data:** the `ARCH_CAPABILITIES` bits above, and VERW where
  they say so.
- **TAA and GDS over-detection:** TAA only with RTM or `TSX_CTRL`; GDS
  only on the affected models. This one makes Ichor faster on AWS.

Each of these but the last costs something on the affected parts. Linux
pays it in the round-18 numbers (`docs/benchmarks.md`), and Ichor's
figures there are without them: ITS on n2 (Linux 6.12 and 7.3 both use
aligned thunks there), TSA's VERW on Milan, STIBP on Rome.

The raw listings (both kernels, every machine) and Ichor's boot logs are
not checked in; the lines quoted here are from them.
