# Benchmarks

Phase E (scalability, before milestone 5) is measured with `bench.rs`:
boot with `bench` on the kernel command line, or read the "Benchmarks
(KVM, 4 vCPUs)" section of a CI run's job summary. Each microbenchmark is a
tiny static ELF run in a fresh cell at a small and a large iteration count;
the cost per operation is the time difference over the iteration
difference, so process start and exit cancel out.

GitHub's hosted runners vary from run to run, so compare within a run or
across several runs, not one number against another. The variance is
large: between two consecutive runs (`2e36e95` and `036189f`) Linux's null
syscall went from 366 ns to 135 ns with no change to Linux, which points to a
different host CPU (one that needs no page-table isolation). The table's
footer names the host CPU since then; a change is only measured by
several runs on the same CPU model.

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

First comparison, commit `2c2e830` (KVM, 4 vCPUs, 512 MiB, GitHub
`ubuntu-24.04` runner; one run, so read ratios, not digits):

| Benchmark | Ichor | Linux 6.6 | Ichor / Linux |
|---|---|---|---|
| null syscall | 261 ns | 367 ns | 0.71x |
| pipe round trip | 10.5 us | 17.8 us | 0.59x |
| page fault | 1961 ns | 1590 ns | 1.23x |
| fork + wait | 20.7 us | 43.2 us | 0.48x |
| fork + exec + wait | 307.5 us | 109.9 us | 2.80x |

After `e21529e` (programs' whole file pages mapped lazily on exec, no
zero-fill on page-cache faults), same setup:

| Benchmark | Ichor | Linux 6.6 | Ichor / Linux |
|---|---|---|---|
| null syscall | 239 ns | 366 ns | 0.65x |
| pipe round trip | 10.2 us | 17.9 us | 0.57x |
| page fault | 1988 ns | 1578 ns | 1.26x |
| fork + wait | 21.1 us | 47.3 us | 0.45x |
| fork + exec + wait | 148.8 us | 123.0 us | 1.21x (was 2.80x) |

Reading it: Ichor's cheaper syscalls and switches are partly Linux's
mitigations (Linux pays for page-table isolation and friends on this CPU;
Ichor does not yet apply all of ADR-0004's). The remaining gaps are
anonymous page faults and exec, each about 1.2x Linux.

Caveats: Linux runs with its default CPU-vulnerability mitigations, which
Ichor does not all apply yet (ADR-0004). Container start has no Linux
equivalent here. Numbers from TCG (no KVM, as on a Windows laptop) say
little about either kernel.
