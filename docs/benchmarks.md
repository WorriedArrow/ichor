# Benchmarks

Phase E (scalability, before milestone 5) is measured with `bench.rs`:
boot with `bench` on the kernel command line, or read the "Benchmarks
(KVM, 4 vCPUs)" section of a CI run's job summary. Each microbenchmark is a
tiny static ELF run in a fresh cell at a small and a large iteration count;
the cost per operation is the time difference over the iteration
difference, so process start and exit cancel out.

GitHub's hosted runners vary from run to run, so compare within a run or
across several runs, not one number against another.

## Baseline (Ichor, KVM, 4 vCPUs, GitHub `ubuntu-24.04` runner)

Commit `e719b45` (after the futex buckets and unlocked lower-file reads):

| Benchmark | Cost |
|---|---|
| null syscall (`getpid`) | 297 ns |
| pipe round trip (1 byte there and back, forked child) | 12 us |
| page fault (first touch of anonymous memory) | 2.4 us |
| fork + wait | 26 us |
| fork + exec (busybox `true`) + wait | 375 us |
| container start (mount a root, new cell, busybox `true`) | 529 us |

## Linux reference

`cargo xtask bench --accel kvm --smp 4` boots Ichor with `bench`, then
Alpine 3.20's official `linux-virt` kernel (Linux 6.6.142, pinned by
SHA-256 in `xtask/src/artifact.rs`) in the same QEMU machine (q35, same
CPU model, vCPUs and memory) with an initramfs of the static busybox and
the benchmark programs from `kernel/testprog/src/bench.rs`, the same bytes
Ichor runs. Each program times its own loop with `clock_gettime` and prints
an `ichor-bench:` line; the table compares those. CI runs it after the
tests and puts the table in the job summary.

Caveats: Linux runs with its default CPU-vulnerability mitigations, which
Ichor does not all apply yet (ADR-0004). Container start has no Linux
equivalent here. Numbers from TCG (no KVM, as on a Windows laptop) say
little about either kernel.
