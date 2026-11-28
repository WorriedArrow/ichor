# Ichor

Ichor is a cloud-first server operating system, written from scratch in Rust,
that runs OCI containers directly on its own kernel.

- **Native segmentation.** There is no global kernel namespace. Each container
  runs in a *cell* that can reach only what it holds a capability to.
- **Containers without a VM or a userspace kernel.** Unmodified Linux images
  (Alpine, Debian, and the official Python, Go, Node.js and OpenJDK images)
  run on an in-kernel Linux system-call ABI, io_uring included.
- **Rust safety pushed as far as it goes.** All `unsafe` kernel code lives in
  one small, audited crate (`kernel/frame`, about 8,800 lines under a budget
  that only an ADR raises). Every other kernel crate, drivers included, is
  `#![forbid(unsafe_code)]`.
- **Its own stack, top to bottom.** TCP/IP, TLS 1.2/1.3, X.509, HTTP/2, gRPC,
  the OCI registry protocol and the image format are Ichor's own crates, tested
  on the host and fuzzed.

## Status

Milestones 0-8 are done. Ichor boots on AWS, GCP and Azure, and under
Firecracker without firmware. It pulls images from
registries, verifies them, and runs them through a gRPC API. Next is
milestone 9: a Kubernetes kubelet scheduling onto Ichor (CRI).

The language runtimes' own test suites run weekly in CI:

| Suite | Passing |
|---|---|
| CPython 3.12 | 454 of 457 modules |
| Go `std` | 260 of 262 packages |
| PostgreSQL 16 `make check` | 223 of 224 |
| Node.js `test/parallel` and `test/sequential` | 4,398 of 4,404 |
| liburing 2.5 | 150 of 156 |
| OpenJDK 21 tier 1 | 2,283 of 2,376 |

[AGENTS.md](AGENTS.md) has the roadmap and the detailed status, and
[docs/adr](docs/adr) has the design decisions.

## Numbers

Measured on the same cloud machine types, against Debian 13 on Linux 7.3
([docs/benchmarks.md](docs/benchmarks.md) has every round, with its method):

| | Ichor | Linux 7.3 |
|---|---|---|
| fork + exec + wait (AWS m7i, one host) | 49 us | 83 us |
| pipe round trip (AWS m7i, one host) | 3.3 us | 10.9 us |
| null system call (AWS m7i, one host) | 76 ns | 76 ns |
| boot to ready for containers, GCP n2-standard-2 (VM start → ready) | 1.6 s | 14.2 s (containerd) |
| boot to ready, Firecracker guest (vCPU → ready) | 37 ms | 5.9 s (containerd) |
| container start through the API (GCP) | 0.5-0.7 ms | 4-7 ms (crun), 94-124 ms (`ctr run`) |

## Quick start

You need Rust (rustup installs the pinned toolchain automatically) and QEMU
with OVMF. On Debian or Ubuntu: `apt install qemu-system-x86 ovmf`. On
Windows, the QEMU installer ships the firmware.

```bash
cargo xtask run     # boot in QEMU, serial console on stdio
cargo xtask test    # host unit tests, then the QEMU integration tests
cargo xtask lint    # fmt, clippy, unsafe policy, frame size budget
```

To run it somewhere real:

```bash
cargo xtask disk-image --gcp --size-gib 1   # a bootable GPT disk for clouds or bare metal
cargo xtask pvh-image --release             # kernel + initrd for Firecracker (PVH)
cargo xtask api HOST:50051 --name NAME --ca ca.pem --token-file F IMAGE -- CMD   # pull and run a container
```

[docs/cloud.md](docs/cloud.md) walks through AWS, GCP, Azure and OpenVMM.

## License

Ichor is licensed under the [Functional Source License, Version 1.1, ALv2
Future License](LICENSE.md) (FSL-1.1-ALv2). You may use, copy, modify and
redistribute it for any purpose except a Competing Use, as the license
defines it. Two years after each version is made available, that version
is also licensed under the Apache License 2.0. Code published before
2026-11-28 was licensed MIT OR Apache-2.0.
