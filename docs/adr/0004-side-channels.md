# ADR-0004: Side-channel posture

- Status: Accepted
- Date: 2026-11-15
- Required by: ADR-0001 §4.7, ADR-0002 §6

## Context

Cells are hostile-tenant boundaries (ADR-0002). Memory safety and
capabilities stop a tenant from *naming* another tenant's data. They do not
stop it from *inferring* that data through shared microarchitectural state:
caches, branch predictors, the TLB, store and fill buffers, SMT siblings,
and the page cache. Linux mitigates these with a large set of per-CPU
mitigations and boot options. Ichor needs a written posture: what it
defends against, what it does by default, and what is left to operators.

## Threat model

- **In scope.** A malicious tenant cell co-resident on the same machine,
  running arbitrary user code and choosing its timing. It tries to read
  kernel memory or another cell's memory, or to steer kernel or other-cell
  execution through shared predictors.
- **Out of scope for the default posture.** Physical attacks, Rowhammer
  against non-ECC memory (clouds use ECC), and the hypervisor or cloud
  provider itself. Also out of scope are cache-timing channels with
  bandwidth too low to matter for anything but key material. Tenants with
  such secrets should take dedicated cores (below).

## Decisions

### 1. Detect per CPU, mitigate only where needed

At boot, frame reads the CPU's enumerated immunities (CPUID leaf 7 and
`IA32_ARCH_CAPABILITIES`) and records which known vulnerabilities apply. It
logs them, and later exports them as node metrics. Mitigations are switched
on only for the vulnerabilities a CPU has; a CPU that reports `RDCL_NO`,
`MDS_NO` and the rest pays nothing. This matches the brief's "detected per
CPU and applied only where needed".

### 2. The default mitigation set

| Issue | Exposure in Ichor | Default |
|---|---|---|
| Meltdown (rogue data cache load) | The kernel half is mapped in every user page table | Untrusted cells need `RDCL_NO`. On CPUs without it, frame will add kernel page-table isolation (separate user and kernel roots, with PCID) before such a node may host untrusted cells. Until then frame logs the CPU as unsafe for multi-tenancy. |
| Spectre v1 (bounds-check bypass) | Syscall paths indexing by user values | User pointers are never dereferenced: copies walk the page tables (`VmSpace::copy_*_user`). Table indices from user input (fd numbers, handle slots) are bounds-checked by Rust; where a value indexes a hot table, use a masked index (`array_index_nospec` pattern) as the Linux ABI grows. |
| Spectre v2 / BHI (branch target injection) | Indirect calls in the kernel | Use eIBRS where enumerated, plus BHI_DIS_S where supported. On CPUs without eIBRS, use IBRS on entry. Retpolines would need unstable rustc target features; they are deferred, and that decision is recorded here. |
| Cross-cell predictor poisoning | Switching between tasks of different cells | IBPB when the scheduler switches to a task of a *different* cell, on CPUs that need it. Same-cell switches skip it. |
| Return stack underflow (RSB) | Context switch, VM exit | Fill the RSB on context switch on affected CPUs. |
| MDS / TAA / MMIO stale data | Store/fill buffers on return to user | `VERW` before returning to ring 3 on CPUs without `MDS_NO`/`TAA_NO`. |
| L1TF | Non-present PTEs | Not-present user PTEs are all-zero, so they point at frame 0, which is never handed out. Nothing to do at the PTE level; SMT still matters (§3). |
| Retbleed, SRSO/Inception (AMD) | Kernel returns | Use the vendor-recommended IBPB-on-entry or safe-RET on affected parts. These come with the first AMD bare-metal or cloud target (milestone 8). |
| Downfall/GDS, SRBDS | Microcode-level | Rely on microcode, which the cloud provider supplies. Log if the CPU reports itself unmitigated. |

Each "on affected CPUs" item is implemented as it becomes reachable. VERW
and IBPB come with multi-cell scheduling in milestone 4, and kernel
page-table isolation comes when needed for an untrusted deployment on old
hardware. Until an item exists, the boot log names the gap rather than
hiding it.

### 3. SMT and dedicated cores

SMT siblings share L1, branch predictors and fill buffers, so no software
mitigation fully separates two cells on sibling hyperthreads. Policy:

- By default, cells may share cores. This is the density trade-off most
  container platforms make.
- A cell can request **dedicated cores**: whole physical cores whose SMT
  siblings never run another cell's tasks (they idle or run the same cell).
  This is scheduler policy (`kernel/sched`) over frame's CPU topology.
- A node can be configured **SMT-off for untrusted tenants**, scheduling at
  most one cell per physical core.

### 4. Page-cache and memory sharing

Sharing image pages across cells (ADR-0002 §4) opens cache-timing channels
on shared code and data, of the Flush+Reload kind. Sharing is per-cell
policy, and a cell can opt out and get private copies. The control plane
defaults to opt-out for cells marked sensitive.

### 5. Known leak: the per-CPU GS base

Ring 3 runs with GS pointing at the kernel's per-CPU block (see the
ADR-0001 user-mode notes). A tenant can therefore read that block's address
with `rdgsbase` (only if FSGSBASE is enabled, which it is not), or infer it
through GS-relative loads. It can read only the block's virtual address,
not its contents: the page is kernel-only, so loads fault. This weakens
kernel address-space layout randomization, which Ichor does not implement
yet anyway. Fix: switch to a `swapgs`-based entry with the NMI window
handled once ring 3 needs GS-based TLS or KASLR lands. Tracked here.

## Consequences

- Nodes on modern cloud CPUs (Ice Lake and later, EPYC Milan and later)
  need almost none of the expensive mitigations, which keeps the
  performance targets reachable.
- Old or vulnerable CPUs are reported as unsuitable for untrusted cells
  until the matching mitigation exists, rather than silently running
  unprotected.
- Dedicated cores and the page-sharing opt-out give tenants with high-value
  secrets a stronger boundary, at a density cost they choose.
