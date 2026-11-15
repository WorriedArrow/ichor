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

Not measured yet. The plan is to run the same static programs under a
pinned Linux kernel on the same runner, so the comparison shares hardware
and hypervisor.
