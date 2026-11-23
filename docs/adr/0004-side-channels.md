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
| Meltdown (rogue data cache load) | The kernel half is mapped in every user page table | On CPUs without `RDCL_NO`, kernel page-table isolation: ring 3 runs on a user root that maps only the entry area, with PCID where the CPU has it (built: see the second amendment of 2026-11-16). |
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

Implementation (`kernel/ichor/src/pagecache.rs`): a root mounted for an
opted-out cell (`Vfs::mount_disk_private`) reads through a private cache
namespace. Its pages are filled and verified from the device like shared
ones but never looked up by, or handed to, any other namespace; they are
charged to the cell's account, evicted only by that cell's own pressure
(so another cell cannot evict them, or observe its own evictions caused
by them), and freed when the root is dropped. Sharing roots still share
pages keyed by the verified BLAKE3 hash. The boot self-test
(`blktest::opt_out`) checks distinct physical pages in both read orders,
between two opted-out cells, the charge, eviction at the cell's limit, and
release on drop. Still open: shared-namespace pages are not yet charged to
an `Image` account (ADR-0002 §4).

### 5. Known leak: the per-CPU GS base

Ring 3 runs with GS pointing at the kernel's per-CPU block (see the
ADR-0001 user-mode notes). A tenant can therefore read that block's address
with `rdgsbase` (only if FSGSBASE is enabled, which it is not), or infer it
through GS-relative loads. It can read only the block's virtual address,
not its contents: the page is kernel-only, so loads fault. This weakens
kernel address-space layout randomization, which Ichor does not implement
yet anyway. Fix: switch to a `swapgs`-based entry with the NMI window
handled once ring 3 needs GS-based TLS or KASLR lands. Tracked here.

## Amendment (2026-11-16): VERW and IBPB implemented; page-table isolation next

What §2 owed since multi-cell scheduling landed (milestone 4), as built:

- **VERW** (MDS, TAA): `ichor_enter_user`, the single path into ring 3,
  executes `verw` on the kernel data selector after loading every user
  register and immediately before `iretq`, when the boot CPU reports MDS
  or TAA and has MD_CLEAR microcode. A CPU that needs it but lacks
  MD_CLEAR is logged as `MISSING`: VERW would not clear its buffers, and
  the node is not safe for untrusted cells until the microcode is
  updated. The `force_verw` command-line option turns it on everywhere
  (tests: the instruction runs on any CPU), and one boot test runs the
  whole boot that way.
- **IBPB between cells**: every task carries a security domain, the
  kernel's cell id (`frame::task::set_current_domain`, set by the Linux
  and native personalities when a task starts running a cell's user
  code). The context switch copies it into the per-CPU block, and
  `UserMode::execute` issues IBPB (`IA32_PRED_CMD`) when this CPU last
  ran user code of a different domain. It is on wherever CPUID
  enumerates IBPB; switches within a cell, and kernel-only tasks, cost
  nothing. The boot reports how many barriers were issued.
- **Boot log**: `ichor: frame: mitigations (ADR-0004): VERW ..., IBPB
  ..., page-table isolation ...`, each `on`, `off (not needed)` or
  `MISSING`.
- **Page-table isolation** (Meltdown-affected Intel CPUs, Skylake-SP
  among them, so common cloud instance types; built since, see the next
  amendment) is not built yet; the boot
  logs it as `MISSING` on such CPUs. It is the next frame change (a user
  root per address space mapping only the entry trampolines and per-CPU
  entry state, CR3 switched on entry and exit, PCID so the switch does
  not flush the TLB), and it raises frame's budget step within ADR-0007's
  ceiling.

## Amendment (2026-11-16): page-table isolation implemented

What §2 owed for Meltdown-affected CPUs, as built in frame
(`kernel/frame/src/arch/x86_64/entry.rs`):

- **The entry area.** One upper-half PML4 slot (`mm::ENTRY_BASE`,
  `0xffff_f000_0000_0000`) holds everything the CPU and the entry code
  touch before the kernel's page tables are loaded: an alias of the entry
  code (the 256 trap stubs, the trap tail, `ichor_enter_user`, the syscall
  entry; one page-aligned block of assembly that reaches outside itself
  only through GS and calls the dispatcher through an absolute pointer in
  the per-CPU block), an alias of the IDT, and per CPU an alias of its
  block (GS) and of its GDT/TSS page, a one-page entry stack (TSS RSP0)
  and the three IST stacks, each above a guard page. The IDT gates, LSTAR,
  GDTR, IDTR and the TSS descriptor all name the aliases, isolated or not,
  so every boot runs this path.
- **Two roots per address space.** With isolation on, `VmSpace::new`
  allocates an 8 KiB block: the full root (the whole kernel half, as
  before, and the user half), which the kernel runs on, and above it the
  shadow root, whose kernel half is only the entry area's slot and whose
  user slots point at the same lower-level tables (`VmSpace::map` copies a
  user slot's PML4 entry into the shadow under the space lock whenever it
  creates one; nothing else changes PML4 user entries before teardown).
  Ring 3 runs on the shadow. User code without an address space of its own
  uses a shadow of the kernel root.
- **Switches.** Every entry from ring 3 (the syscall entry, and the trap
  tail for exceptions, interrupts and the IST vectors) loads the full root
  before touching anything outside the entry area. `ichor_enter_user`
  builds the `iretq` frame on the entry stack, loads the shadow, then
  VERW, then `iretq`. An NMI, #MC or #DF can land while CR3 still holds a
  shadow (the last instructions before `iretq`, the first of the syscall
  entry): the trap tail compares CR3 with this CPU's shadow, switches if
  they match and restores it before its own `iretq`. A trap from ring 3
  never returns to ring 3 from the trap tail any more: it is recorded into
  the thread's context and `UserMode::execute` re-enters through
  `ichor_enter_user`, which is now in fact the single way into ring 3 (so
  VERW, IBPB and the shadow load cover interrupts too; before, an
  interrupt from ring 3 with no reschedule returned by its own `iretq`
  without VERW). The trap tail also clears RFLAGS on entry, so neither a
  user's AC (which would suspend SMAP) nor DF survives into the kernel.
- **TLB.** Kernel mappings are global, so isolation turns CR4.PGE off.
  With PCID, full roots run as PCID 0 and shadows as PCID 1; the entry
  switches set bit 63 and keep each other's entries. A flush of the user
  side is owed whenever this CPU loads a different full root and on every
  shootdown flush (`mm::tlb`), because those flush PCID 0 only; the next
  shadow load then flushes PCID 1 once, before any user instruction runs.
  Without PCID every CR3 load flushes.
- **When.** On every CPU whose `IA32_ARCH_CAPABILITIES` lacks `RDCL_NO`
  (Intel), and with `force_pti` on the command line on any CPU (tests).
  The boot logs `page-table isolation on (PCID)`, `on (no PCID)` or
  `on (forced, ...)`. `m2_scheduler_on_eight_cpus` boots the whole suite
  with `force_pti` (PCID under CI's KVM, none under TCG), and the kernel
  checks on every isolated boot (`frame::user::isolation_selftest`) that a
  user root maps a mapped user page and the entry area exactly as the full
  root does, and none of kernel text, the current kernel stack, the heap,
  the linear map or the per-CPU block's own address.
- **What the user root still exposes** to a Meltdown-style read: the entry
  code and IDT (public anyway), the GDT/TSS, and the per-CPU block, which
  holds kernel stack and context pointers and the two roots' physical
  addresses (layout, not data; it weakens a future KASLR, see §5), the
  entry stack (only the user's own registers ever land there), and the IST
  stacks, which hold the registers of whatever an NMI or #MC interrupted,
  kernel code included. Linux maps the same set. Zeroing an IST frame
  before its `iretq` would close the last; it is not done yet.
- **Cost and budget.** One entry stack page and the IST stacks move into
  the entry area (the per-CPU fallback ring-3 stack is gone), plus 4 KiB
  per address space under isolation. Frame's audit step 7 is 6,250 lines /
  265 unsafe sites, within ADR-0007's ceiling of 9,500 / 420.

## Amendment (2026-11-21): enhanced IBRS

What §2 says for Spectre v2 and BHI on CPUs with enhanced IBRS, as built:

- Where CPUID enumerates `IA32_SPEC_CTRL` (leaf 7 EDX[26]) and
  `IA32_ARCH_CAPABILITIES` reports `IBRS_ALL`, every CPU sets IBRS once as
  it comes up and leaves it on, with `BHI_DIS_S` where CPUID.(7,2):EDX[4]
  enumerates it. Bits firmware set are kept. Nothing is written on any
  other CPU.
- The boot log's mitigations line ends with `Spectre v2 in the kernel`
  and one of `eIBRS + BHI_DIS_S`, `eIBRS`, `eIBRS (BHI NOT MITIGATED: no
  BHI_DIS_S)`, `IBRS on entry` (the next amendment), or `NOT MITIGATED (no
  IBRS)`.
- **Not verified on hardware.** Neither TCG nor CI's KVM guests report
  enhanced IBRS, so tests cover only the CPUs where nothing is written.
  The first cloud boot on a CPU that has it is the first run of this code.
- Still owed from §2: the BHB-clearing sequence for affected CPUs without
  `BHI_DIS_S` (Cascade Lake, Ice Lake), IBRS on entry for CPUs without
  enhanced IBRS, RSB filling, masked indices for Spectre v1, and AMD's
  AutoIBRS, Retbleed and SRSO measures.

## Amendment (2026-11-22): IBRS on entry

The first cloud machine (GCP E2) has a CPU without enhanced IBRS and said
so: `Spectre v2 in the kernel NOT MITIGATED`. Stable Rust has no
retpolines, so what is left for such CPUs is IBRS as it first was, which
protects the mode it was last written in:

- Where CPUID enumerates `IA32_SPEC_CTRL` and the CPU has no enhanced IBRS
  (on AMD too, under a hypervisor that says so), the entry code writes it
  with IBRS on every entry from ring 3, after the kernel's page tables are
  loaded and before the first indirect branch or return, and without IBRS
  before it goes back (ring 3 does not pay for it; an NMI from the moment
  the kernel still has the user's page tables does the same around
  itself). Two MSR writes for each system call, fault or interrupt from
  ring 3. Firmware's bits are kept.
- The boot log says `IBRS on entry`; the boot fails if the kernel finds
  itself without IBRS. Verified on that machine, where it costs Redis about
  a tenth and PostgreSQL a twentieth (`docs/cloud.md`).
- Not covered: an NMI between IBRS going off and the user's page tables
  (Ichor takes none), and what IBRS does not do (BHI, the RSB across VM
  exits).

## Amendment (2026-11-23): the rest of §2

What §2 and the amendments above still owed, as built. With it every row
of §2's table has its mitigation on the CPUs it applies to.

- **Branch history (BHI) without `BHI_DIS_S`** (Intel parts before Alder
  Lake that enumerate no BHI_NO, eIBRS or not): every entry from ring 3
  runs a software sequence that overwrites the branch history with the
  kernel's own taken branches (five calls, each around five taken jumps,
  then LFENCE; Intel's BHI guidance), before the first indirect branch.
  CPUs with `BHI_DIS_S` keep using it (the 2026-11-21 amendment).
- **IBPB on entry** (AMD's Retbleed, family 15h to 17h, and SRSO, 17h and
  19h without SRSO_NO; Hygon 18h): stable Rust cannot emit untrained or
  safe-RET return thunks, so the mitigation is the one without compiler
  help: an IBPB on every entry from ring 3, before any return. Zen 3 and 4
  need microcode that makes IBPB flush return predictions too
  (IBPB_BRTYPE); without it the boot log says SRSO is NOT MITIGATED. It is
  expensive (a few hundred cycles each entry), as Linux's `ibpb` modes are.
- **AutoIBRS** (AMD Zen 4 and later, CPUID 8000_0021h EAX[8]): EFER.AIBRSE
  on every CPU, in place of IBRS on entry, as enhanced IBRS is for Intel.
- **RSB filling on context switch**: every `switch_stacks` fills the return
  stack buffer with 32 harmless entries (each call's speculation lands on
  an INT3) before its `ret`, so a task never returns through predictions
  another left, on every CPU (a few tens of cycles a switch).
- **Masked indices (Spectre v1)**: `frame::nospec::index(i, len)` returns
  `i` if `i < len` and 0 otherwise without a branch (CMP and SBB, which the
  compiler cannot turn into one). It guards the indexes a user picks for a
  table: the Linux and native system call numbers (before their jump
  tables), descriptors, signal numbers, io_uring's registered files and
  buffers, and capability slots (`kernel/cap` has the same mask in
  portable Rust: it is host-tested and does not depend on frame).
- IBPB is found on AMD by its own CPUID bit (8000_0008h EBX[12]) as well
  as Intel's, for IBPB between cells and on entry alike.
- The boot log's mitigations line goes on: `branch history` (`BHI_DIS_S`,
  `cleared on entry`, or `not affected`), `IBPB on entry` (`on (Retbleed,
  SRSO)`, `not needed`, or `NOT MITIGATED`), `RSB filled on context switch`,
  `Spectre v1 masked indices`.
- Not covered still: SMT (§3, dedicated cores), Downfall/GDS and SRBDS
  (microcode; logged), and speculative store bypass, which §2 leaves to
  programs (Linux's default too: opt-in per process; not offered yet).
- **Not verified on affected hardware.** TCG and CI's KVM report neither
  BHI nor an affected AMD part, so tests run the RSB fill and masked indices
  everywhere, and the BHB sequence and IBPB on entry only when forced
  (`force_bhb`, `force_ibpb_entry` on the command line).
- Frame grows by about 155 lines and 3 unsafe sites (to 6,978 / 283; the
  wall clock's steering, ADR-0018's amendment, had taken it to 6,824);
  audit step 13 is 7,000 / 300.

## Consequences

- Nodes on modern cloud CPUs (Ice Lake and later, EPYC Milan and later)
  need almost none of the expensive mitigations, which keeps the
  performance targets reachable.
- Old or vulnerable CPUs are reported as unsuitable for untrusted cells
  until the matching mitigation exists, rather than silently running
  unprotected.
- Dedicated cores and the page-sharing opt-out give tenants with high-value
  secrets a stronger boundary, at a density cost they choose.
