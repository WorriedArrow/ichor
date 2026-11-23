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

## Google Cloud, Intel and AMD (2026-11-23)

Every mitigation ADR-0004 calls for is on in Ichor since `91a5a17`, so
these replace the numbers above as the current picture. Same machine type
for both kernels, 4 vCPUs, real hardware (KVM under GCP), the same
`testprog::bench` programs:

- **Ichor**: the release disk image with `bench` on the command line
  (`cargo xtask disk-image --release --gcp --cmdline bench`), booted as
  its own machine; two boots per machine type.
- **Linux**: Debian 12's GCE image (kernel `6.1.0-56-cloud-amd64`, its
  default mitigations), running the programs in a chroot whose
  `/bin/true` is the static busybox 1.35.0 that Ichor and the QEMU
  reference run; five rounds, the median shown. Linux's figure is the
  program's whole loop over its count, so process start and exit are in
  it (small at these counts); Ichor's is the difference of two counts.

**n2-standard-4, Intel Ice Lake (Xeon @ 2.60 GHz), us-central1-a.** Ichor:
eIBRS, branch history cleared on entry (BHI applies, no `BHI_DIS_S` on Ice
Lake), IBPB between cells.

| Benchmark | Ichor (two boots) | Linux 6.1 | Ichor / Linux |
|---|---|---|---|
| null syscall | 325, 308 ns | 107 ns | 2.9x |
| pipe round trip | 4.2, 3.9 us | 8.7 us | 0.47x |
| page fault | 2.90, 2.36 us | 0.90 us | 2.9x |
| fork + wait | 30, 27 us | 37.6 us | 0.76x |
| fork + exec + wait | 167, 145 us | 98.5 us | 1.6x |
| container start | 571, 477 us | | |

**n2d-standard-4, AMD EPYC 7B13 (Milan, Zen 3), us-central1-b.** Ichor:
IBRS on entry (Spectre v2), IBPB on every entry (SRSO: stable Rust has no
safe-RET thunks), IBPB between cells. Linux uses retpolines and safe RET
instead, which need compiler support, and is cheaper per entry. The first
boot ran before AMD's IBRS bit was read (below), so without IBRS on entry.

| Benchmark | Ichor (with IBRS on entry; first boot without) | Linux 6.1 | Ichor / Linux |
|---|---|---|---|
| null syscall | 1051 ns (940) | 387 ns | 2.7x |
| pipe round trip | 10.2 us (9.8) | 12.9 us | 0.79x |
| page fault | 2.87 us (2.76) | 0.45 us | 6.4x |
| fork + wait | 23 us (23) | 53.8 us | 0.43x |
| fork + exec + wait | 151 us (154) | 175 us | 0.86x |
| container start | 340 us (345) | | |

Reading it:

- Entries cost Ichor more than Linux on both machines. On Intel the
  difference is not the mitigations alone: on GitHub's runners Ichor's
  null syscall was already 240-300 ns. On AMD, IBPB on every entry
  (about 600 ns against the Intel machine) is the price of SRSO without
  compiler-made return thunks; IBRS on entry adds about 110 ns.
- Pipes and fork are cheaper on Ichor everywhere, and so is fork + exec
  on AMD.
- Anonymous page faults are Ichor's worst case here: 2.4-2.9 us on both
  machines, where the QEMU comparison had them at 1.26x Linux. (The
  second round below found most of the gap was Linux's transparent huge
  pages: with them off, Linux's 4 KiB faults cost 1.6-1.8 us on AMD.)
- The runs found that frame read only Intel's IBRS bit (CPUID.7:EDX[26]),
  so on AMD it reported `ibpb false` and "Spectre v2 in the kernel NOT
  MITIGATED". AMD enumerates IBRS in CPUID 8000_0008h EBX[14]. That is
  fixed; the second n2d boot logged `ibrs true, ibpb true, srso affected`
  and "IBRS on entry".
- Mitigations seen working on real hardware: the branch-history clearing
  sequence (Ice Lake), IBPB on entry and IBRS on entry (Milan), IBPB
  between cells (both).

## Google Cloud, second round (2026-11-23): fault-around, safe RET, containers

After `f5f9472` (anonymous faults map 64 KiB ahead; safe-RET return thunks
in place of IBPB on entry on AMD). Same machine types, plus n2d on AMD
Rome (EPYC 7B12, Zen 2); one Ichor boot per row, Linux the median of five
rounds. Debian's kernel runs with transparent huge pages `[always]`; the
Linux rows show it as is and with THP off (`never`).

**Ichor** (`bench`; on AMD also `bench srso=ibpb`, the old IBPB on entry):

| Benchmark | n2 (Ice Lake) | Milan, safe RET | Milan, IBPB | Rome, safe RET | Rome, IBPB |
|---|---|---|---|---|---|
| null syscall | 309 ns | 572 ns | 1086 ns | 575 ns | 1075 ns |
| pipe round trip | 3.9 us | 5.3 us | 10 us | 5.3 us | 10 us |
| page fault | 1.86 us | 1.09 us | 1.02 us | 1.09 us | 1.12 us |
| fork + wait | 27 us | 19 us | 25 us | 18 us | 23 us |
| fork + exec + wait | 149 us | 135 us | 159 us | 132 us | 156 us |
| container start | 489 us | 413 us | 317 us | 414 us | 329 us |

**Linux 6.1** (THP always / never):

| Benchmark | n2 | Milan | Rome |
|---|---|---|---|
| null syscall | 107 / 106 ns | 393 / 387 ns | 154 / 154 ns |
| pipe round trip | 9.1 / 9.3 us | 17.1 / 14.1 us | 17.2 / 16.3 us |
| page fault | 1.36 / 1.26 us | 0.42 / 1.82 us | 0.44 / 1.61 us |
| fork + wait | 36.8 / 36.1 us | 51.8 / 51.9 us | 49.9 / 61.5 us |
| fork + exec + wait | 94 / 92 us | 174 / 172 us | 175 / 182 us |

**Container start on Linux**, the same busybox root running `/bin/true`,
each timed over its runs after three to warm up (crun 1.8.1, runc 1.1.5,
Docker 20.10.24, Debian 12's packages); Ichor's is the table above:

| How | n2 | Milan | Rome |
|---|---|---|---|
| `unshare` (mount, UTS, IPC, net, PID, cgroup namespaces) `--root` | 1.29 ms | 2.06 ms | 1.92 ms |
| `crun run` (OCI bundle) | 4.9 ms | 6.7 ms | 6.5 ms |
| `runc run` | 15.4 ms | 22.1 ms | 21.8 ms |
| `docker run --rm --network none` | 251 ms | 264 ms | 256 ms |
| `docker run --rm` | 583 ms | 591 ms | 602 ms |

Reading it:

- Safe RET beats IBPB on entry on both AMD generations for system calls,
  pipes, fork and exec (about half the cost of a null system call), and
  loses only on container start (about 90 us more: much kernel code, each
  return mispredicted on purpose). It stays the default; `srso=ibpb`
  selects the other. Both sequences ran on real hardware: Zen 3/4's on
  Milan, Zen 1/2's on Rome.
- Ichor now beats Linux's 4 KiB anonymous faults on AMD (1.0-1.1 us
  against 1.6-1.8 us), not its huge-page ones (0.42 us), and is still
  slower than Linux on Ice Lake (1.86 against 1.26-1.36 us; that was
  2.4-2.9 us before fault-around). The first round's Linux page-fault
  figures were huge-page faults: THP is on by default in Debian.
- Starting a container from a root that is already there: Ichor takes
  0.3-0.5 ms, Linux's bare `unshare` 1.3-2.1 ms, crun 5-7 ms, runc 15-22
  ms, Docker 250-600 ms. Ichor's figure is one kernel operation, measured
  in the kernel; Linux's include starting the tool's own process from a
  shell, which is what a container runtime there pays.
- Entries still cost Ichor more than Linux on Intel (309 against 107 ns),
  where neither has an expensive mitigation: Ichor's syscall path itself.

Caveats: in the QEMU comparisons above (before `91a5a17`), Linux runs with
its default CPU-vulnerability mitigations, which Ichor did not all apply
yet (ADR-0004). Container start has no Linux
equivalent here. Numbers from TCG (no KVM, as on a Windows laptop) say
little about either kernel.
