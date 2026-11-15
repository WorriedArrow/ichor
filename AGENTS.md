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

**Active milestone: 3.** Its scope is NVMe / virtio-blk, a read-only image
format, the VFS, and the ELF loader, ending with a static busybox running in
a cell through the Linux ABI.

Milestones 0-2 are done.

- M0/M1: boots as a UEFI app into the higher half; buddy page allocator and
  heap; traps with IST stacks; x2APIC + tickless timer; SMP bring-up; per-CPU
  data.
- M2 (scheduler): frame owns tasks, the context switch, atomic-mode tracking
  and preemption; `kernel/sched` is the injected weighted-fair-share policy.
  Kernel threads run, block/wake on wait queues, and are preempted.
- M2 (user mode): typed/untyped frames (`UFrame`, `VmReader`/`VmWriter`),
  `VmSpace`, and `UserMode::execute` run ring-3 code. A ring-3 program makes
  a syscall, faults, and is isolated from other address spaces.
- M2 (cells): `kernel/cap` (rights, revocation, generation-tagged CSpace
  handles) and `kernel/cell` (hierarchical accounts). The kernel's `kcell`
  ties CSpace + Account + VmSpace into a `Cell`. `kernel/abi` + the kernel's
  `nativeabi` dispatcher give native-ABI processes capability syscalls
  (`docs/abi/native.md`). Self-tests prove isolation, rights, accounting,
  revocation, and that a ring-3 native process acts only on handles its cell
  holds.

- M3 so far: `kernel/elf` (load plans), `kernel/image` (read-only,
  content-addressed image format; `builder` feature is the writer), and in
  the kernel: `loader` (ELF into a cell's `VmSpace`), `vfs` (root mounted
  from an image; `.`/`..`, bounded symlink following), `process` (Linux
  process + fd table), `linuxabi` (console I/O, open/openat/read/close,
  stat family, lseek, arch_prctl, exit). Coverage is generated into
  `docs/linux-abi.md` (`cargo xtask linux-abi-table`; lint checks it).
  `testprog` is a tiny assembler for self-test binaries. Real static Linux
  ELFs run in cells and read files from a mounted image.
- M3 device I/O (ADR-0005): frame enumerates PCI and offers `IoMem`
  (bounds-checked MMIO from `PciDevice::map_bar` only), `DmaBuf`/`DmaAddr`
  and a frame-owned split `VirtQueue`. `kernel/block` is the block-device
  trait; `kernel/drivers/virtio-blk` is a safe, polled virtio-blk driver.
  Every QEMU run attaches `target/qemu/<run>/root.img` (built by xtask with
  the image builder) as a virtio-blk disk; the kernel reads it, verifies a
  300 KiB pattern file, mounts it, and runs `cat` against it.
- M3 memory: `kernel/vma` (region map, host-tested) and the kernel's
  `umem` give Linux processes `brk`, `mmap` (anonymous, and private copies
  of files), `mprotect` and `munmap`, with demand paging from user page
  faults; syscalls fault user buffers in before copying. The loader builds
  a real argv/envp/auxv stack (AT_PHDR, AT_RANDOM, ...) and tolerates
  segments sharing a page. `linuxabi` also has uname, getdents64, dup*,
  fcntl, ioctl(TIOCGWINSZ), clock_gettime, prlimit64, and signal/futex
  stubs. A process's memory is freed and its charge returned at exit.

`tests/boot.rs` proves all of this on 1, 4 and 8 vCPUs.

Next for milestone 3: the busybox QEMU test (waiting on the owner's choice
of where the static binary comes from), whatever else busybox traces to,
and paging the root image in from the device on demand (today the kernel
reads the whole disk into memory, capped at 64 MiB).

ADR-0004 records the side-channel posture; its per-CPU mitigations (VERW,
IBPB on cross-cell switch, page-table isolation for Meltdown-affected CPUs)
are owed as multi-cell scheduling lands in milestone 4. Boot logs which apply.

Suggested order for milestone 3 (see the brief and ADR-0001 §4.6):

1. The volume-format ADR (ext4 read/write is the candidate).
2. A safe block layer trait and a virtio-blk driver (safe, over frame's
   `IoMem`/DMA types, which milestone 3 adds to frame per a new budget ADR).
3. The read-only, content-addressed image format (host-testable crate) and
   the in-kernel VFS with a copy-on-write upper layer.
4. An ELF loader (`PT_INTERP` later) that maps a static binary into a cell's
   `VmSpace`, and enough Linux ABI (the process personality, `brk`, `mmap`,
   `write`, `exit`, `uname`, ...) to run static busybox.
5. A QEMU test that runs a real static busybox applet in a cell.

Frame budget: ADR-0005 sets the milestone 3 ceiling at 8,500 lines / 380
sites; `audit.toml` is at step 5 (5,100 / 235) and frame is at 4,963 / 223.

The goal set for this effort is milestone 8, whose acceptance test needs
cloud accounts and bare-metal hardware from the owner.

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
(`default-members`). Crates that depend on frame (`ichor`, `ichor-frame`,
`ichor-virtio-blk`) are kernel-only: xtask's `KERNEL_ONLY` list keeps them
out of host clippy and tests and lints them for the UEFI target. The kernel and frame build for `x86_64-unknown-uefi`
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
  src/bus, io.rs, dma.rs, virtio.rs   PCI, IoMem, DmaBuf, VirtQueue
kernel/cmdline   command line parser (no_std, host-tested)
kernel/pe        PE32+ headers + base relocations (no_std, host-tested)
kernel/buddy     buddy allocator policy over abstract links (no_std, host-tested)
kernel/acpi      RSDP/XSDT/MADT parsing from byte slices (no_std, host-tested)
kernel/pe,buddy  (above) PE + buddy allocator
kernel/sched     scheduling policy: group fair-share + work stealing (host-tested)
kernel/cap       capabilities, rights, revocation, CSpace (host-tested)
kernel/cell      hierarchical resource accounts (host-tested)
kernel/abi       native ABI definitions (docs/abi/native.md)
kernel/elf       ELF64 parsing into load plans (host-tested)
kernel/image     read-only content-addressed image format (host-tested)
kernel/block     block-device trait and helpers (host-tested)
kernel/vma       user address-space region map for mmap/brk (host-tested)
kernel/drivers/virtio-blk  safe virtio-blk driver over frame's IoMem/DMA
kernel/ichor     the kernel binary; frame::main!(kmain); kcell/nativeabi tie it together
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
