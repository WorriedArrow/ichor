# ADR-0001: Kernel architecture and the frame crate's API surface

- Status: Accepted
- Date: 2026-11-14
- Amended: 2026-11-14 (milestone 1 implementation notes, at the end)
- Amended: 2026-11-16 by ADR-0014 (`services/rt`, user-mode services'
  runtime, is a second crate allowed `unsafe`, under the same rules)
- Supersedes: nothing (amends the founding brief only where noted)

## Context

Ichor's founding brief sets three requirements that pull against each other:

1. **Performance**: a monolithic, single-address-space kernel. Every syscall
   from a container traps once and is served in the kernel, with no IPC hop.
2. **Rust safety pushed as far as it goes**: unsafe code confined to one small,
   audited crate (`kernel/frame`), with everything else `#![forbid(unsafe_code)]`,
   drivers included.
3. **Hostile multi-tenancy**: cells are security boundaries.

This combination is a *framekernel*, the design Asterinas introduced (USENIX
ATC'25). Its trusted crate is OSTD. We studied OSTD 0.19.0 (main @ a0de225,
2026-11-13), its soundness book, the 2026 audit issues (asterinas#3920 and
children), and Theseus (OSDI'20). The decisions below borrow their ideas. **No
code is copied.** Asterinas is MPL-2.0 (file-level copyleft), and Ichor is
MIT/Apache-2.0. Any file ever vendored from Asterinas must keep its MPL-2.0
header and live in its own file. The default is to re-implement from the
published invariants.

Two lessons from that prior art shape this ADR:

- **The holes cluster at the edges.** The 2026 audit of OSTD found about 30
  safe-API soundness bugs. They sit in boot-protocol parsing, trap/entry
  assembly, guard tokens shared across CPUs (`Sync` impls on lock guards and
  preemption guards), unwinding across injected policy traits, and DMA without
  an IOMMU (#3905). Ichor's frame design names each of these edges explicitly.
- **TCB size grows unless budgeted.** OSTD was 10.6 kLoC at publication. Today
  it is roughly 22 kLoC for generic + x86 code, with about 670 unsafe blocks.
  Ichor enforces a budget mechanically (section 8).

## Decision

### 1. Shape

- One address space and one privilege level for the whole kernel (ring 0 /
  EL1). User code (both personalities) runs in ring 3 / EL0 in per-process
  address spaces. The upper half is the kernel; the lower half is user.
- **`kernel/frame` is the only crate that may contain `unsafe`.** Every other
  kernel crate, including drivers and both syscall personalities, starts with
  `#![forbid(unsafe_code)]`. `services/` crates do as well, since the control
  plane is in the TCB of every tenant.
- **The soundness claim:** no sequence of calls to frame's public API from
  safe Rust causes undefined behaviour. This holds regardless of how buggy the
  caller is, and regardless of what user programs or (with an IOMMU, see 4.6)
  devices do.
- The claim does *not* cover deadlock, panics, resource exhaustion, or logic
  bugs. A safe filesystem that leaks one cell's file to another is a security
  bug that types do not prevent; capabilities (ADR-0002) are the defence there.
- **Theseus's "cell" (a crate as a runtime-loadable unit) is unrelated to
  Ichor's cell** (an isolation domain, ADR-0002). We do not adopt runtime
  crate loading. Ichor is one statically linked image, built with LTO.

### 2. Trusted computing base

| Trusted for memory safety | Why |
|---|---|
| CPU, and the IOMMU when present | Hardware root |
| Firmware, until `ExitBootServices` | Loads us; we never call it afterwards |
| `kernel/frame` | The audited unsafe crate |
| `core`, `alloc`, the pinned rustc | Toolchain |
| Third-party `no_std` dependencies of the kernel | Their `unsafe` is our `unsafe`; see 7.3 |
| Drivers of DMA-capable devices **when no IOMMU is present** | See 4.6 |

Everything else in the kernel is trusted only for *correctness*, not for
memory safety. Cells, their processes, and (with an IOMMU) devices are
untrusted.

### 3. Boot (amends nothing; makes the brief concrete)

- The kernel is itself a UEFI application (PE/COFF, target
  `x86_64-unknown-uefi`, later `aarch64-unknown-uefi`). There is no bootloader.
- **Frame owns the firmware entry point** (`efi_main`). It is the only code that
  ever touches UEFI. It reads the firmware identity, the ACPI RSDP (and later
  SMBIOS), the boot volume handle, and the command line. Then it takes the final
  memory map into static `.bss` storage (no allocation between `GetMemoryMap`
  and `ExitBootServices`, which would invalidate the map key), exits boot
  services, and masks interrupts. Only then does kernel code run.
- **UEFI bindings are hand-written** (`frame/src/boot/uefi.rs`, about 500 lines).
  We do not use the `uefi`/`r-efi` crates. Only the four services we call are
  typed as callable. Every other table slot is an opaque `usize`. Protocols are
  tied to their GUID through a trait, so a lookup cannot be cast to the wrong
  interface. Firmware objects are copied out rather than referenced.
- **Ichor never calls UEFI runtime services.** Reboot and power-off go through
  ACPI. The runtime regions stay reserved in the memory map.
- **Configuration.** In milestone 0 the command line is read from
  `\ichor\cmdline` on the boot volume, which is convenient for QEMU tests.
  Before Secure Boot is enabled (milestone 8), the production command line moves
  into a PE section of the signed image, as with a UKI. Frame will then ignore
  the ESP file whenever Secure Boot is on, and measure the embedded command line
  into the TPM. Per-instance configuration comes from cloud metadata, read by
  the control plane, not by the kernel.
- **Higher half (milestone 1).** Firmware loads the image at an arbitrary
  physical address, identity-mapped. After `ExitBootServices`, frame:
  1. builds its own page tables, with a linear map of all physical memory at
     `0xffff_8000_0000_0000` and the image at `0xffff_ffff_8000_0000`;
  2. applies the image's PE base relocations (UEFI images always carry
     `.reloc`) for the new base;
  3. switches to a frame-allocated stack and jumps high;
  4. drops the identity map.

  This replaces Asterinas's `bsp_boot.S` + Linux boot protocol path. The
  firmware memory map is the only boot data structure we parse, and we parse it
  from bytes with bounds-checked, safe code (`convert_memory_map`). That closes
  the class of bugs in asterinas#3913–3917.
- **Boot-time memory.** `BootServices` regions stay in use until frame has
  switched stacks (milestone 1). The memory map keeps them distinct from
  `Usable`, so the frame allocator cannot hand out the stack we are running on.

### 4. Frame's public API surface

This is the API frame grows into. Milestone numbers say when each part lands.
Anything not listed here belongs in a safe crate. Adding a module to frame
requires amending this ADR.

**4.1 `boot`, `console`, `power`, `panic` (M0).**
- `boot::BootInfo` (command line, memory map, RSDP, firmware identity, image
  range) and `boot::MemoryRegion`/`MemoryKind`.
- `frame::main!(fn)` declares the kernel entry (see section 5).
- `println!`/`print!` go to the serial console. In M1 these move under a `log`
  facade with a per-CPU ring buffer that the control plane can export.
- `power::shutdown(ExitStatus)`. Under QEMU with `qemu_debug_exit` it exits the
  VM; in M1 it gains ACPI power-off and reset.
- The panic handler prints and shuts down. A kernel panic is always a bug.

**4.2 `arch` (M0 →).** The whole ISA boundary. Other crates see only
arch-neutral items (`halt_forever`, `disable_local_interrupts`, CPU feature
queries, and the `UserContext` register file). Adding aarch64 means a sibling
`arch/aarch64` module implementing the same items. Nothing outside `arch/`
names an x86 register, instruction, or port.

**4.3 `mm` (M1).** Modelled on OSTD's typed/untyped split, which seL4's untyped
retyping also inspired:
- A **frame metadata array** with one slot per physical page (refcount,
  metadata type, flags), like Linux's `struct page`.
- `Frame<M: FrameMeta>` is a typed frame holding Rust objects: page tables,
  kernel stacks, slab pages. It is never mappable to user space or to devices.
- `UFrame`/`USegment` are untyped frames, whose contents may change underneath
  the kernel (user mappings, DMA). **No `&`/`&mut` can be formed into untyped
  memory.** Access is only through `VmReader`/`VmWriter` POD copies. These use
  volatile/atomic-width accesses so that concurrent user or device writes are
  not Rust data races (this answers asterinas#3893).
- **Fallible user-memory copies** use an exception-table `memcpy`. A fault
  returns a short count, never UB. `copy_from_user` can never touch kernel
  addresses: the user VA range check happens in frame, and SMAP is toggled
  (`stac`/`clac`) only inside the copy routine. *(Amended 2026-11-15 by
  ADR-0011: copies go through the linear map instead, one page at a time
  under the space lock, after checking the PTE's permissions; SMAP is
  never opened.)*
- `VmSpace` holds the user half of an address space. Its cursor API is
  `map(UFrame, Prop)`, `unmap`, `protect`, and TLB flush. Kernel top-level
  entries are shared, pre-allocated, and unreachable through `VmSpace`. Because
  `map` takes `UFrame`, typed frames cannot reach user space by construction.
- **Shared image pages** (ADR-0002, ADR on the image format): the page cache
  maps the same `UFrame` read-only into many cells. Frame tracks the sharing
  through the metadata refcount. Breaking the share (copy-on-write, or a
  tenant's opt-out) is a policy decision made in safe `kernel/mm`.
- **Allocator policy is safe code; frame validates its output.** The physical
  page allocator algorithm (buddy plus per-CPU caches, NUMA-aware) lives in a
  host-testable safe crate. Frame calls it and then checks the metadata
  refcount before minting a `Frame`. A buggy allocator that returns a page
  twice panics instead of aliasing. The same pattern applies to the kernel heap:
  slab policy is safe, and the `GlobalAlloc` shim lives in frame. The shim
  aborts rather than unwinding if policy code panics (asterinas#3910). We
  build with `panic = "abort"` anyway.
- Kernel stacks have guard pages.

**4.4 `cpu`, `sync`, `task`, `timer`, `irq`, `trap` (M1 → M2).**
- `cpu_local!` per-CPU statics, plus `CpuId` and `CpuSet`. Borrows of per-CPU
  data are tied to a `DisabledPreemptGuard`/`IrqDisabledGuard` lifetime.
- **Guards are `!Send` and `!Sync`.** Where a lock guard must be `Sync`, its
  `Sync` bound is `T: Sync`, never auto-derived. This closes asterinas#3909
  and #3891. The M0 `SpinLock` already follows this rule.
- Preemption counts are saturating and checked (asterinas#3895).
- The `sync` module provides `SpinLock<T, G: Guardian>` (preempt-off or
  IRQ-off), `RwLock`, a sleeping `Mutex` and `WaitQueue` (M2, once the scheduler
  exists), and `Rcu`.
- Trap entry, exceptions, and IRQ dispatch: IDT, IST stacks for NMI, #DF and
  #MC, and `swapgs` discipline, including the NMI-in-`swapgs` window
  (asterinas#3904). IRQ lines are allocated objects that hold handler closures.
- Interrupt controller and timer: x2APIC, IPIs, TSC-deadline timer, and
  tickless idle. The safe API is `timer::Deadline` and `irq::IrqLine`.
- **Scheduler injection.** Frame owns context switching and a `Task` type with a
  "running on CPU n" atomic, so one task can never run on two CPUs. Policy (the
  per-CPU run queues, work stealing, hierarchical fair share between and within
  cells) lives in safe `kernel/sched` and is installed through a `Scheduler`
  trait at boot. Frame's soundness does not depend on the policy being correct.
- SMP bring-up (INIT-SIPI-SIPI and the AP trampoline) is in frame. Topology
  comes from ACPI MADT/SRAT, parsed in a safe crate from byte slices that
  frame provides.

**4.5 `user` (M2).**
- `UserContext` is the user register file. Only a safe subset of RFLAGS is
  writable (no IF, IOPL, or AC). FS/GS base and XSAVE area management are
  included.
- `UserMode::execute(&mut ctx) -> ReturnReason::{Syscall, Exception(info),
  Interrupt}`. Both syscall personalities (`kernel/linux-abi`,
  `kernel/native-abi`) sit on top of this in safe code. The personality is a
  property of the process (ADR-0002), not of the trap path.
- Syscalls arrive only through `syscall`/`sysret`. Frame enforces canonical-RIP
  checks before `sysret`. `int 0x80` is not supported.
- vDSO: frame provides the safe ability to map a kernel-built read-only `UFrame`
  for the vDSO and a vvar page updated by the timer code.

**4.6 `io`, `pci`, `dma`, `iommu` (M3).**
- `IoPort::acquire(range)` and `IoMem::acquire(range)` come from allocators that
  frame populates at boot. MMIO ranges come from firmware tables, minus RAM and
  minus system devices (LAPIC, IOAPIC, IOMMU, HPET). Port ranges come from the
  full port space minus PIC, PIT, CMOS, PCI config ports, and frame's own
  console and test ports. Drivers can only name their own device's registers.
- **PCI configuration space is mediated by frame.** OSTD gives safe code raw
  ECAM and 0xCF8/0xCFC access, so a safe driver can move a BAR over RAM or
  enable bus mastering at will. Frame instead exposes `PciDevice` with typed
  accessors. BAR assignment, the Bus Master and Memory Space bits, and
  MSI/MSI-X address programming are performed by frame, and are validated
  against the IOMMU configuration and the `IoMem` allocator. Capability-list
  reads and vendor-specific registers are passed through.
- `DmaCoherent` and `DmaStream` allocate untyped memory only.
  **Bus addresses are an opaque `DmaAddr`** that is only obtainable from a live
  DMA mapping. There is no `DmaAddr::from(u64)`, and the type is not `Pod`.
- **IOMMU.** When VT-d (or SMMU on aarch64) is present, frame gives each device
  its own IOMMU domain. That domain contains exactly the DMA mappings created
  for the device, with interrupt remapping on, and the full soundness claim
  holds even against malicious devices. Most cloud guests do not expose a
  vIOMMU. **Without an IOMMU, a driver that writes a wrong bus address into a
  descriptor can corrupt memory.** This is the one known exception to the
  soundness claim, as in asterinas#3905. We accept it and contain it:
  1. Drivers for DMA-capable devices are listed in
     `kernel/drivers/DMA_TRUSTED.md`, and changes to them need review against
     the DMA rules.
  2. The opaque `DmaAddr` keeps a correct driver from forging addresses by
     accident. Writing a raw integer as a bus address requires a deliberate
     `as_u64()`, which review and grep can find.
  3. For virtio, the split/packed virtqueue descriptor tables are owned by frame
     (`dma::virtqueue`, M3). Frame writes descriptor addresses only from
     `DmaAddr`. This removes the exception for virtio-blk and virtio-net, the
     devices most Ichor nodes run on. An ADR at M8 decides whether ENA, gVNIC,
     and MANA rings get the same treatment.

  Whether a node runs with or without an IOMMU is reported in the boot log and
  exported in node metrics, so operators know which guarantee they have.

**4.7 Security hardware (M1 → M2; details in a side-channel ADR before M2 ends).**
Frame enables SMEP, SMAP, UMIP, NX, and WP. It uses PCID per address space,
and adds CET (supervisor shadow stacks and IBT) when the toolchain supports it
on stable. The speculative-execution mitigations (IBRS/eIBRS, IBPB on cell
switch, RSB stuffing, L1D flush, VERW, and retpolines where needed) are detected
per CPU from CPUID and `ARCH_CAPABILITIES`, and applied only where needed. Core
pinning with SMT-sibling exclusivity is mechanism in frame (CPU topology,
affinity masks) and policy in `kernel/sched` and `kernel/cell`.

### 5. Entry point and the forbid boundary

`frame::main!(kmain)` is a `macro_rules!` macro exported by frame. It expands,
in the kernel binary, to a function exported as `__ichor_kernel_main` with
exactly the signature frame declares in an `unsafe extern "Rust"` block. Frame
calls it after `ExitBootServices`.

- rustc does not report the `unsafe_code` lint for tokens produced by a
  *foreign* crate's macro. So the `#[unsafe(export_name)]` in the expansion is
  permitted in a `#![forbid(unsafe_code)]` crate. This is verified on our
  toolchain: `kernel/ichor` builds and boots this way.
- The function-pointer coercion inside the expansion checks `kmain`'s signature
  in the caller's crate. A missing or duplicate entry is a link error.
- **Consequence:** any macro, `macro_rules!` or proc-macro, from any dependency
  can inject `unsafe` into a forbid crate. Therefore, **kernel crates may depend
  on proc-macro or macro-exporting crates only if they are in-tree or listed in
  `supply-chain/` (cargo-vet) with an audit of their expansions.** CI enforces
  the forbid attribute (`cargo xtask lint`). The dependency rule is enforced by
  cargo-vet from the first external kernel dependency onward.

### 6. Toolchain

Pinned stable `1.100.0`. **No unstable features are used.** Everything
milestone 0 needs is stable, including `extern "efiapi"`, `asm!`/`global_asm!`,
naked functions, `#[unsafe(...)]` attributes, and let-chains, and the UEFI
targets ship a prebuilt `core`/`alloc`. Two things are known to push toward
nightly later. CET/IBT codegen (`-Zcf-protection`) and retpoline codegen are
decided in the side-channel ADR. Kani, Miri, and cargo-fuzz run on their own
toolchains and do not affect the build toolchain. Every unstable feature that
gets adopted is listed in `AGENTS.md` with its reason.

### 7. Unsafe policy and its enforcement

1. Every `unsafe` block holds exactly one unsafe operation and has a
   `// SAFETY:` comment naming the invariant. Clippy enforces this with
   `undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block` (deny).
   Every `unsafe fn` has a `# Safety` section (`missing_safety_doc`, deny).
   `unsafe_op_in_unsafe_fn` is denied.
2. **Kernel code may not `unwrap`, `expect`, or `panic!`.** This is enforced by
   workspace clippy lints and relaxed only in tests (`clippy.toml`). Errors
   propagate. Where a panic is genuinely a "can't happen" kernel bug, an
   `#[allow]` with a justification comment is required.
3. Kernel dependencies are `no_std` and minimal. Each one's `unsafe` counts as
   TCB and must be audited (cargo-vet) before it is added. Milestone 0 has
   **zero** external kernel dependencies.
4. Verification ladder:
   - Frame logic that can be factored out of hardware access (allocator
     algorithms, memory-map conversion, page-table index arithmetic, ACPI and
     ELF parsing) goes into safe, host-testable crates. These get `cargo test`,
     Miri, proptest, and cargo-fuzz.
   - Kani proves bounded invariants of the remaining frame data structures
     (metadata refcount transitions, page-table cursor range math).
   - loom covers lock-free structures.
   - In-kernel tests run under QEMU through `tests/`.

### 8. Frame budget

`kernel/frame/audit.toml` holds the ceilings. `cargo xtask frame-audit` (part
of `cargo xtask lint`, run in CI) fails if frame exceeds them. *Code lines* are
non-blank, non-comment lines. *Unsafe sites* are every `unsafe` keyword outside
comments and strings: blocks, fns, impls, extern blocks, fn-pointer types, and
attributes.

| Phase | Max code lines | Max unsafe sites | Authorized by |
|---|---:|---:|---|
| Milestone 0 | 900 | 48 | this ADR |
| Milestone 1 (ceiling) | 6,000 | 320 | this ADR |
| Milestones 2–5 (target) | 15,000 | 700 | requires a new ADR |

During milestone 1, `audit.toml` may be raised in steps up to the milestone-1
ceiling, citing this section. Any raise beyond that needs a new ADR that
explains what moved into frame and why it could not be safe code. Milestone 0
measured 823 lines and 44 sites.

## Alternatives considered

- **Microkernel** (seL4, Hubris, Redox, Fuchsia style). It isolates drivers by
  address space, but costs an IPC round trip on the I/O and syscall paths that
  the brief says must be as fast as Linux. Rejected.
- **Conventional monolithic Rust kernel with `unsafe` wherever convenient**
  (Kerla, Redox's kernel). This gives up the brief's core safety property.
  Rejected.
- **Theseus-style single privilege level** (applications in ring 0, isolation
  by language alone). This cannot run unmodified Linux binaries. Rejected.
  Theseus ideas we do adopt: ownership-bound resource handles (`MappedPages` →
  our `UFrame`/`VmSpace` mappings), and APIs that return owned state to the
  caller (less state spill, easier restart of subsystems).
- **Depending on OSTD directly.** It is MPL-2.0, which we could legally
  combine with our code. But OSTD boots through Multiboot, the Linux boot
  protocol, or its own bzImage stub; its API is still changing; it has open
  soundness issues; and it would put about 22 kLoC we did not design into our
  TCB. Rejected. We re-implement from its published invariants.
- **`uefi`/`r-efi` crates for firmware bindings.** These are larger than the
  roughly 500 lines we need, and their unsafe would sit in our TCB. Rejected.
- **A separate bootloader** (Limine, GRUB, systemd-boot). It adds a component
  to sign, measure, and audit, and the brief forbids it. Rejected.

## Consequences

- One crate to audit, with a mechanically enforced size budget and per-site
  SAFETY documentation.
- Some designs are harder than in C. Every new hardware mechanism needs a safe
  API whose soundness holds against arbitrary callers, and frame's API design
  is where most review effort goes.
- Without an IOMMU, drivers of DMA-capable devices are trusted for memory
  safety. Moving virtqueue descriptor ownership into frame shrinks this to
  non-virtio cloud NICs, and that exception is visible to operators.

## Amendment: milestone 1 implementation notes (2026-11-14)

What landed, and where it differs from the plan above:

- **Kernel virtual layout.** The linear map of all RAM is at
  `0xffff_8000_0000_0000` (RW, NX, global; 1 GiB pages where the CPU allows,
  and only firmware-reported RAM, never MMIO holes). Kernel stacks are at
  `0xffff_e000_0000_0000`, each 64 KiB above an unmapped guard page. The
  image is at `0xffff_ffff_8000_0000` with per-section permissions
  (`.text` RX, `.rdata` R, `.data` RW, no W+X). All 256 upper-half PML4
  slots get a PDPT at boot, so future address spaces share the kernel half by
  copying PML4 entries.
- **Higher-half switch.** This was implemented as planned in §3. While the
  relocations are applied, both the low and the high alias are mapped, so
  the code doing the switch is ordinary Rust. Relocations are written
  through the linear map, because the image's own `.rdata` mapping is
  read-only. PE parsing is in the safe `kernel/pe` crate.
- **Page metadata.** There are 32 bytes per page: kind, order, size class,
  refcount, list links, and a 128-slot bitmap. The buddy policy lives in the
  safe, host-tested `kernel/buddy` crate. Frame validates every block it
  returns against the metadata, as §4.3 requires.
- **Heap.** The slab bookkeeping (a slot bitmap per page) lives in the page
  metadata, not in freed memory. So a use-after-free in a caller cannot
  corrupt the allocator, and double or mismatched frees panic. *Deviation:*
  the slab policy is inside frame for now (about 200 lines), not in a safe
  crate. Splitting it out is on the milestone 2 list, along with per-CPU slab
  caches.
- **Deferred to milestone 2.** The typed/untyped frame API (`Frame<M>`,
  `UFrame`, `VmReader`/`VmWriter`) is deferred, together with its first
  consumer, `VmSpace`. Milestone 1 hands out no physical frames outside
  frame.
- **ACPI.** Tables are *copied* out of firmware memory with volatile byte
  reads, only from regions the firmware map marks as ACPI or runtime memory,
  and parsed by the safe `kernel/acpi` crate. No Rust reference into
  firmware-owned memory is ever created, which matters because ACPI NVS can
  change under us.
- **Traps.** There is one IDT for all CPUs. A per-CPU GDT and TSS provides
  IST stacks for #DF, NMI and #MC, so a kernel stack overflow (which hits the
  guard page) is reported from the #DF handler. Entry stubs are 16 bytes per
  vector, generated by the assembler.
- **Interrupts and time.** x2APIC is required; the 8259 PICs are masked. The
  TSC frequency comes from CPUID 0x15, then the hypervisor leaf
  0x40000010, then PIT calibration. The per-CPU timer is one-shot and
  tickless, in TSC-deadline mode when available, otherwise LAPIC one-shot
  calibrated against the TSC. `SpinLock` now masks local interrupts while it
  is held.
- **SMP.** The real-mode trampoline is copied below 1 MiB. APs start in
  parallel (one INIT/SIPI round for all of them) and claim CPU indices with
  `lock xadd`. Each AP runs on a small page table, identity-mapping 2 MiB
  plus the shared kernel half, until it reaches Rust.
- **Per-CPU data.** GS points at a per-CPU block. `CpuLocal<T>` borrows the
  current CPU's slot only for the lifetime of an `IrqGuard`, which is `!Send`.
  With a scheduler, this is sound only if a task cannot sleep or yield while
  holding an `IrqGuard`. Milestone 2 must enforce that, by panicking on a
  sleep in atomic context.
- **Budget.** Frame is at 2,894 lines and 150 unsafe sites. `audit.toml` was
  raised in two steps, to 3,000 and 160, within the milestone 1 ceiling.
