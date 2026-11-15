# AGENTS.md

Working notes for anyone (human or agent) picking up Ichor. Keep this file
current: when a session changes build commands, conventions, or the active
milestone, update it in the same commit.

Ichor is a cloud-first server OS in Rust that runs OCI containers natively on
a framekernel. The founding brief is the source of truth until an ADR in
`docs/adr/` supersedes part of it. Read these first:

- `docs/adr/0001-kernel-architecture.md`: the framekernel shape, the trust
  model, frame's planned API surface, the unsafe policy, and the frame budget.
- `docs/adr/0002-cells-and-capabilities.md`: cells, capabilities, and how the
  Linux ABI's namespaces and cgroups map onto them.

## Status

**Active milestone: 2.** Its scope is the scheduler, kernel threads,
native-ABI user processes, capabilities, and cells.

Milestones 0 and 1 are done. The kernel boots as a UEFI application, builds
its own page tables, and runs in the higher half. It reclaims boot-services
memory and has a validated buddy page allocator and a heap. It handles traps
with IST stacks (stack overflows hit a guard page and are reported), and
brings up every CPU listed in the ACPI MADT in parallel. Each CPU gets
x2APIC, a tickless TSC-deadline or one-shot timer, and per-CPU data.
`tests/boot.rs` proves all of this on 1 and 4 vCPUs, including the panic and
stack-overflow paths. ADR-0001's amendment records what landed and what
deviated from the plan.

Suggested order for milestone 2 (see ADR-0001 §4.3–4.5 and ADR-0002):

1. Frame: `Task` and the context switch (callee-saved registers plus the
   stack pointer). Add the "running on CPU n" atomic so a task can never run
   on two CPUs, preemption counting, and atomic-mode checks: sleeping while
   holding an `IrqGuard` or a spinlock must panic. Also scheduler injection
   through a `Scheduler` trait.
2. Safe `kernel/sched`: per-CPU run queues, work stealing, and hierarchical
   fair share. Host-testable policy core plus QEMU tests. The timer handler
   drives preemption, and IPIs wake idle CPUs (`apic::send_ipi` is ready).
3. Frame: the typed/untyped frame API (`Frame<M>`, `UFrame`, `Segment`),
   `VmReader`/`VmWriter` with fallible user copies (exception table, SMAP
   `stac`/`clac`), `VmSpace` with a cursor API and PCID. Move the slab policy
   out of frame into a safe crate and add per-CPU caches.
4. Frame: `UserMode::execute` and `UserContext`, using `syscall`/`sysret`
   and `swapgs`, with the NMI-in-`swapgs` window handled.
5. Safe `kernel/cap` (`Cap<T>`, rights, revocation tokens, CSpace with
   generation-tagged handles) and `kernel/cell` (cells, accounts, the system
   cell).
6. Safe `kernel/native-abi` plus `abi/` (the ABI definitions, documented in
   `docs/abi/`). Add a tiny native-ABI user program, embedded in the image
   for now, that runs in a cell and makes capability calls. A QEMU test proves
   that isolation holds: a stale or foreign handle is rejected.
7. Write the side-channel ADR (it is due before milestone 2 completes).

Raise `kernel/frame/audit.toml` in steps as frame grows. Milestone 1's
ceiling was 6,000 lines and 320 sites, and frame is at 2,894 and 150. Going
past that ceiling needs a new ADR, as ADR-0001 §8 requires.

The goal set for this effort is milestone 8. Milestone 8's acceptance test
(booting on AWS, GCP, Azure and one bare-metal machine) needs cloud
accounts and hardware from the owner. Ask for them when you get there.

## Commands

```bash
cargo xtask build          # kernel -> target/kernel/x86_64-unknown-uefi/debug/ichor.efi
cargo xtask run            # boot in QEMU + OVMF, serial on stdio, exits on halt
cargo xtask run --cmdline "memmap"   # without qemu_debug_exit: halts; Ctrl-C to quit
cargo xtask test           # host unit tests, then QEMU integration tests (tests/)
cargo xtask lint           # fmt check, clippy (host + UEFI target), forbid check, frame budget
cargo xtask frame-audit    # frame line and unsafe-site counts against the budget
cargo deny check           # licenses, advisories, sources
```

Useful options: `--release`, `--accel auto|kvm|whpx|hvf|tcg`, `--smp N`,
`--memory MiB`, `--timeout secs`, `--gdb` (waits on tcp::1234), and `-- <raw
qemu args>`.

Environment overrides: `ICHOR_QEMU`, `ICHOR_OVMF_CODE` + `ICHOR_OVMF_VARS`,
`ICHOR_ACCEL`, and `ICHOR_TEST_VERBOSE=1` (echo guest serial during tests).

Plain `cargo build` / `cargo test` at the root only touch host crates
(`default-members`). The kernel and frame build for `x86_64-unknown-uefi`
through xtask, into `target/kernel` so they never contend for cargo's build
lock with the host build.

### Kernel command line

The kernel reads `\ichor\cmdline` from the boot volume, which xtask writes per
run. Options are whitespace-separated `key` or `key=value`; `#` starts a
comment.

| Option | Effect |
|---|---|
| `qemu_debug_exit` | `shutdown()` exits QEMU through `isa-debug-exit`: status 33 = success, 35 = failure |
| `memmap` | print the full memory map |
| `test_panic` | panic after boot (exercises the panic path) |
| `test_stack_overflow` | recurse until the kernel stack hits its guard page |

## Layout

```
kernel/frame     the unsafe TCB (only crate allowed `unsafe`); owns efi_main
  src/boot         UEFI entry, boot state, higher-half entry, per-CPU init
  src/mm           linear map/kspace switch, page metadata, page allocator, heap
  src/arch/x86_64  paging, GDT/TSS/IDT + trap stubs, x2APIC/timer, AP trampoline
  src/cpu.rs       CpuId, IrqGuard, CpuLocal<T>, cpu_local!
kernel/cmdline   command line parser (no_std, host-tested)
kernel/pe        PE32+ headers + base relocations (no_std, host-tested)
kernel/buddy     buddy allocator policy over abstract links (no_std, host-tested)
kernel/acpi      RSDP/XSDT/MADT parsing from byte slices (no_std, host-tested)
kernel/ichor     the kernel binary; `frame::main!(kmain)`
xtask/           build/run/test/lint tooling (lib + bin, no dependencies)
tests/           QEMU integration tests (host crate using xtask's runner)
docs/adr/        architecture decision records
```

Planned crates (create as milestones need them): `kernel/{mm,sched,cap,cell,
vfs,block,net,linux-abi,native-abi}`, `kernel/drivers/*`, `abi/`, `services/`.

## Conventions

- **Unsafe lives only in `kernel/frame`.** Every other kernel crate (and later
  `services/`) starts with `#![forbid(unsafe_code)]`; `cargo xtask lint`
  checks this. In frame, each `unsafe` block holds one operation and has a
  `// SAFETY:` comment, and each `unsafe fn` has a `# Safety` section. Clippy
  denies violations.
- Frame's public API must be sound for *any* safe caller. Raw firmware and
  hardware types stay private.
- No `unwrap`/`expect`/`panic!` in kernel code (workspace clippy lints).
  Tests may use them (`clippy.toml`). A justified `#[allow]` with a comment is
  the only exception.
- Kernel dependencies: `no_std`, minimal, and audited before adding (cargo-deny
  now, cargo-vet from the first external kernel dependency). There are none
  today. Macro-exporting or proc-macro dependencies of kernel crates need an
  audit of their expansions, because a foreign macro's output bypasses
  `forbid(unsafe_code)` (ADR-0001 §5).
- Put logic that does not touch hardware into host-testable crates
  (`cargo test`, and later Miri, proptest, fuzzing).
- Every milestone ends with an automated test in CI. Add a QEMU test by
  calling `ichor_tests::boot(name, cmdline, smp)` and asserting on serial
  markers and the exit status.
- Write an ADR for decisions that would be expensive to reverse. Update
  `docs/adr/README.md`.
- Commit in small steps that build and pass `cargo xtask lint` and
  `cargo xtask test`. Commit messages say what changed and why. A tracked
  benchmark regression needs a justification in the message.
- Code is MIT OR Apache-2.0. Never copy Asterinas code (MPL-2.0) into
  differently licensed files. Re-implement from its documented invariants.

## Toolchain

Pinned stable `1.100.0` (`rust-toolchain.toml`) with target
`x86_64-unknown-uefi`.

### Unstable features

None. If one becomes necessary, pin a dated nightly and list it here with the
reason. Known candidates: CET/IBT codegen and retpolines (side-channel ADR).

## Environment notes

- CI (GitHub Actions, `ubuntu-24.04`) installs `qemu-system-x86` and `ovmf`,
  enables `/dev/kvm`, and runs lint, test, and cargo-deny.
- On Windows, QEMU's own `share/edk2-x86_64-code.fd` + `edk2-i386-vars.fd`
  are found automatically. There is no KVM there, so runs use TCG: about 2 s
  per boot. WHPX is untested.
- The ESP is a QEMU `vvfat` directory under `target/qemu/<run>/esp`, passed
  as a workspace-relative path, because a Windows drive-letter colon breaks
  `fat:` parsing.

## Needs the owner

Settled by the owner:

- License: MIT OR Apache-2.0 (confirmed 2026-11-14).

The brief cannot decide these, so ask the owner:

- Secure Boot signing keys and how they are custodied (before milestone 8).
- Cloud accounts and bare-metal hardware for milestones 8 and benchmarks.
