# Ichor

Ichor is a cloud-first server operating system, written from scratch in Rust,
that runs OCI containers on cloud and bare-metal machines.

- **Native segmentation.** There is no global kernel namespace. Each container
  runs in a *cell* that can reach only what it holds a capability to.
- **Zero-overhead OCI.** Unmodified Linux container images run directly on the
  Ichor kernel through an in-kernel Linux syscall ABI. There is no VM per
  container and no userspace kernel.
- **Rust safety pushed as far as it goes.** All `unsafe` code lives in one
  small, audited crate (`kernel/frame`). Every other kernel crate, drivers
  included, is `#![forbid(unsafe_code)]`.

Status: early. Milestone 0 is done: the kernel boots as a UEFI application,
exits boot services, and halts cleanly under QEMU + OVMF. See
[AGENTS.md](AGENTS.md) for the roadmap and status, and [docs/adr](docs/adr) for
the design.

## Quick start

You need Rust (rustup installs the pinned toolchain automatically) and QEMU
with OVMF. On Debian or Ubuntu, install them with
`apt install qemu-system-x86 ovmf`. On Windows, the QEMU installer ships the
firmware.

```bash
cargo xtask run     # boot in QEMU, serial console on stdio
cargo xtask test    # unit tests + QEMU integration tests
cargo xtask lint    # fmt, clippy, unsafe policy, frame size budget
```

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.
