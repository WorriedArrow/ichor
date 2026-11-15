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

**Active milestone: 1**: the frame crate gets paging, the frame allocator,
heap, IDT and traps, x2APIC, timer, SMP bring-up on every core, and per-CPU
data.

Milestone 0 is done. The kernel boots as a UEFI application under QEMU + OVMF,
prints to serial, reads `\ichor\cmdline`, exits boot services, and reports the
memory map and ACPI RSDP. It then halts, or under the test harness exits QEMU
with a status. `tests/boot.rs` proves this, including the panic path.

Suggested order for milestone 1 (see ADR-0001 §3 and §4.3–4.4):

1. Host-testable safe crates first: physical page allocator (buddy + per-CPU
   caches) and page-table index math. Give them Miri and proptests.
2. Frame: own page tables, a linear map at `0xffff_8000_0000_0000`, the image
   at `0xffff_ffff_8000_0000` via PE base relocations, a frame-allocated stack,
   dropping the identity map, then reclaiming `BootServices` memory.
3. Frame metadata array, `Frame<M>`/`UFrame`, kernel heap (`GlobalAlloc` shim
   in frame, slab policy in safe code).
4. GDT/TSS/IDT with IST stacks, exception handlers, x2APIC, TSC-deadline
   timer.
5. ACPI MADT parsing (safe crate, over byte slices from frame), AP
   trampoline, `cpu_local!`, and an integration test that every vCPU checks in
   (`-smp 4`).

Raise `kernel/frame/audit.toml` in steps as frame grows, citing ADR-0001 §8.
The milestone-1 ceiling is 6,000 lines and 320 unsafe sites.

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

## Layout

```
kernel/frame     the unsafe TCB (only crate allowed `unsafe`); owns efi_main
kernel/cmdline   command line parser (no_std, host-tested)
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

The brief cannot decide these, so ask the owner:

- License: MIT OR Apache-2.0 was chosen as the Rust-ecosystem default in
  session 1 and is not yet confirmed by the owner.
- Secure Boot signing keys and how they are custodied (before milestone 8).
- Cloud accounts and bare-metal hardware for milestones 8 and benchmarks.
