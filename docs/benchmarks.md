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
- The n2 THP row is suspect: with THP on, Linux's faults took 1.36 us,
  more than with it off (1.26 us), where on AMD THP cut them to 0.42 us.
  `AnonHugePages` was not checked during the run. The third round below
  checked: huge pages do form on n2 (31 huge-page faults per 64 MiB run),
  and Linux's n2 fault took 0.76 us with them, 1.22 us without. Do not
  read this round's n2 "THP always" figure as a huge-page fault.

## Local, OpenVMM: the system call and user memory paths (2026-11-25)

What the null system call paid for on its way back to ring 3 (ADR-0008's
2026-11-25 amendment), and the bookkeeping behind each anonymous page.
Under OpenVMM on this development PC (Ryzen 5 5600X, Zen 3: safe-RET
thunks, no IBRS or IBPB enumerated, XCR0 0x7), 4 vCPUs, a release boot
with `bench`; the minimum of five rounds in one boot, since the host makes
single runs vary by about 20%. Not comparable with the GCP tables above,
only with each other.

| Benchmark | Before (`31bc1f4`) | After |
|---|---|---|
| null syscall | 356 ns | 160 ns |
| pipe round trip | 4.24 us | 2.83 us |
| page fault | 1.26 us | 0.44 us |
| fork + wait | 15 us | 13 us |
| fork + exec + wait | 161 us | 114 us |
| container start (in the kernel) | 426 us | 330-410 us |
| container start, native caller | 235 us | 171 us |

What changed:

- **System calls**: `sysretq` where the context is what a `syscall` left
  (it was `iretq` every time); no XRSTOR when the CPU's registers still
  hold the thread's state (a per-CPU stamp of the last save; XSAVEOPT
  still runs after every trap); the FS base MSR written only when it
  changes; the TSC clock read with a multiply instead of a 128-bit
  division, twice per call (CPU-time accounting).
- **Anonymous pages**, per page of fault-around (timed with counters):
  the `VmSpace` no longer keeps its own tree of pages, since each PTE's
  counted reference already keeps the page (map: about 170 ns to 35 ns),
  and the kernel's resident pages and copy-on-write set are chunked maps
  of 64 pages, `vma::PageMap` and `PageSet` (insert: about 160 ns to 35
  ns). What is left is mostly the page's allocation and zeroing (about
  220 ns: memory bandwidth, which Linux pays as well).
- **Fork** turns the parent's writable pages read-only a batch at a time
  with one TLB shootdown (`VmSpace::write_protect`), not one per page.

## Local, OpenVMM: 2 MiB anonymous pages (2026-11-26)

ADR-0020: a sequential touch of private anonymous memory takes a 2 MiB page
per aligned block. The page-fault row (4,112 pages, 16 MiB) run four times
in one boot each way, same machine and setup as above, under heavier host
load than that section (null syscall 223-267 ns there, not 160), so compare
these two columns only with each other. The in-program timing
(`ichor-bench: page-fault n=4112`), per 4 KiB page:

| Round | 4 KiB pages | 2 MiB pages |
|---|---|---|
| first (memory the guest never touched) | 1,088-1,561 ns | 693 ns |
| best of the next three | 455 ns | 261 ns |

- The first round pays the host for backing guest memory touched for the
  first time; 2 MiB blocks come from such memory more often than single
  pages do. Timed inside the kernel, a cold 2 MiB block took about 570 us
  to allocate and zero, a warm one about 115 us.
- Of a warm 2 MiB fault, zeroing is about 225 ns a 4 KiB page; mapping is
  about 3 us a block, and the `Mm`'s 512 charges and entries about 30 us.
- On GCP: the next section.

## Local, OpenVMM: exec maps per segment (2026-11-26)

Where fork + exec + wait's time went, timed step by step with temporary
counters (same machine and setup as the 2026-11-25 section, SRSO's
safe-RET thunks forced off to come closer to an Intel CPU's paths): of 93
us an iteration, `execve` took 65, and of that the loader took 49. It
walked every page of the image (busybox: 274 text pages) through two
`BTreeMap`s and several lookups, about 180 ns a page, though those pages
were already mapped lazily. The rest of the iteration: the exiting
process's teardown 12 us, freeing the forked copy's memory in `execve` 7
us, finding and opening `/bin/true` 6.5 us, 18 page faults 6 us, fork 3
us.

The loader now works per piece of address space between segment
boundaries: the lazily mapped file pages are one region each, `.bss` is
demand-zero, and only a segment's partial first and last pages (and pages
two segments share) are built at exec. It reads 4 KiB of the image for its
headers, not 64 KiB (it parses them twice an exec). Five rounds in one
boot, the thunks on as in the table above (null syscall 160-166 ns there,
as in that section's 160):

| Benchmark | Before (2026-11-25 table) | After |
|---|---|---|
| fork + exec + wait | 114 us | 75-82 us |
| container start (in the kernel) | 330-410 us | 187 us |

Then CPU time from the scheduler (ADR-0021): the clock read once per
context switch instead of twice per return from ring 3. Null syscall
160-166 → 137-148 ns in the same setup (the TSC clock; under kvmclock each
read costs more), pipe round trip unchanged (2.72-2.86 us against
2.83-2.89).

Then the user's registers saved only when they must be (ADR-0008's
2026-11-26 amendment: at a switch-out, or when the kernel reads or copies
them), not after every trap: null syscall 137-148 → 98-102 ns, pipe round
trip 2.63-2.78 us, page fault and fork + exec unchanged (247-368 ns,
75-80 us).

## Google Cloud, third round (2026-11-26): 2 MiB pages, THP checked

After `c6e5b77` (ADR-0020) and ADR-0008's 2026-11-25 amendment (`sysretq`,
skipped XRSTORs, no page tree in a `VmSpace`). n2-standard-4 (Ice Lake,
us-central1-a) and n2d-standard-4 (Milan, us-central1-b), each Ichor
machine in the same zone as its Linux one, booted once.

- **Ichor**: `bench bench_rounds=5`, five rounds in one boot; the median
  shown, the range after it. Its page-fault row touches 16 MiB (4,096
  pages, 8 of them 2 MiB blocks).
- **Linux**: Debian 12 (`6.1.0-56-cloud-amd64`), the same programs as
  before, five rounds with THP `[always]` (defrag `[madvise]`) and five
  with `never`; the median. Its page-fault program touches 64 MiB. Around
  every page-fault run the script read `thp_fault_alloc` and
  `thp_fault_fallback` from `/proc/vmstat`: with THP on, every run took
  31 huge-page faults and no fallback, on both machines (the 64 MiB
  mapping is not 2 MiB aligned on 6.1, so 31 of its 32 blocks); with it
  off, none. `AnonHugePages`, sampled during an extra run, rose by about
  62 MiB on both.

| Benchmark | n2: Ichor | n2: Linux THP / off | Milan: Ichor | Milan: Linux THP / off |
|---|---|---|---|---|
| null syscall | 163 ns (161-166) | 106 / 106 ns | 403 ns (401-405) | 386 / 388 ns |
| pipe round trip | 3.34 us (3.34-3.40) | 9.4 / 9.4 us | 4.83 us (4.82-4.87) | 16.5 / 16.4 us |
| page fault | 547 ns (544-763) | 756 / 1220 ns | 342 ns (338-404) | 415 / 1814 ns |
| fork + wait | 27 us (26-28) | 34.3 / 34.4 us | 18 us (18-19) | 60.5 / 58.1 us |
| fork + exec + wait | 141 us (138-141) | 85.4 / 86.3 us | 129 us (124-131) | 173 / 178 us |
| container start | 474 us | | 369 us | |
| container start, native caller | 197 us | | 204 us | |

Reading it:

- Anonymous page faults are now cheaper on Ichor than Linux's huge-page
  faults on both machines: 547 against 756 ns on Ice Lake (1.86 us in the
  second round), 342 against 415 ns on Milan (1.09 us). Ichor's first
  round (763 and 404 ns) pays for memory the machine had not touched.
- The null system call halved on Ice Lake (309 to 163 ns) and is now
  1.5x Linux's 106 ns; on Milan it is 403 ns against Linux's 386 (572 in
  the second round). Pipes and fork stay well ahead of Linux.
- fork + exec is the row Ichor still loses on Ice Lake (141 against 85
  us), and wins on Milan (129 against 173).
- Linux's huge pages form on n2 as well; the second round's n2 THP figure
  (1.36 us) is not what THP costs there (0.76 us).

## Google Cloud, fourth round (2026-11-27): the Ice Lake losses

After `dbf5a6a` (exec maps per segment), `3bbe2d6` (ADR-0021: CPU time
from the scheduler), ADR-0008's 2026-11-26 amendments (user registers
saved only when they must be; signal handlers start reset), ADR-0022
and ADR-0023 (`0ee287c`). Same machine types and zone as the third
round (us-central1-a), one boot each, `bench bench_rounds=5`; the median
and the range. Linux's figures are the third round's (Debian 12, same
programs, THP on), not run again. A c3-standard-4 (Sapphire Rapids) ran
too, for AMX; there is no Linux figure for it.

| Benchmark | n2: Ichor (third round) | n2: Linux | Milan: Ichor (third round) | Milan: Linux | c3: Ichor |
|---|---|---|---|---|---|
| null syscall | 116 ns (115-118; was 163) | 106 ns | 295 ns (291-298; was 403) | 386 ns | 161 ns (160-163) |
| pipe round trip | 3.43 us (3.41-3.45; was 3.34) | 9.4 us | 4.66 us (4.60-4.68; was 4.83) | 16.5 us | 5.46 us |
| page fault | 545 ns (506-750; was 547) | 756 ns | 357 ns (346-398; was 342) | 415 ns | 737 ns (732-775) |
| fork + wait | 28 us (was 27) | 34.3 us | 19 us (was 18) | 60.5 us | 41 us |
| fork + exec + wait | 100 us (98-101; was 141) | 85.4 us | 83 us (81-87; was 129) | 173 us | 143 us (140-146) |
| container start | 293 us (was 474) | | 265 us (was 369) | | 385 us |
| container start, native caller | 148 us (was 197) | | 159 us (was 204) | | 173 us |

Reading it:

- On Ice Lake the null system call went from 1.54x Linux's to 1.09x (116
  against 106 ns), and fork + exec from 1.65x to 1.17x (100 against 85
  us). Both are still behind Linux there; everything else is ahead.
- On Milan every row is ahead of Linux: the null system call 295 against
  386 ns, fork + exec 83 against 173 us.
- c3 is slower than n2 on every row (null syscall 161 ns, fork + exec 143
  us, page faults 737 ns). Without a Linux run on c3 this says nothing
  about Ichor against Linux there; the boot log's mitigation line is the
  first place to look.
- Correctness on the same boots: the XSAVE test (every component, after
  every system call) passed with ZMM0-31 and k0-k7 on n2 and c3 (XCR0
  0xe7 and 0x600e7), and on c3 also with AMX tile data (11,008-byte
  areas); `amxtest` passed on c3, including a signal frame with a tile
  configuration LDTILECFG refuses. None of the three VMs exposes PKU to
  its guest (XCR0 without PKRU, `pkey test skipped`): protection keys
  have run under QEMU's TCG only.

## Container start from the caller's side

Linux's container starts above are timed by the caller: a shell starts
`unshare`, `crun` or `docker`, which asks the kernel for the container
and waits until `/bin/true` has exited and been reaped. Ichor's "container
start" row is timed inside the kernel instead, and it loads busybox from a
byte buffer, copying all 1.1 MB of it into the new process on every start:
not what a container gets. Since 2026-11-23, `bench` also
times it the Linux way: `services/nativetest` (`start-bench`), a native
process in a system cell holding that cell and the root disk as an image,
runs `CELL_CREATE`, `CELL_SPAWN` of `/bin/true` from the container's root,
`PROCESS_WAIT` until it is reaped, and closes both handles (the cell ends
with its last one), 20 times after three to warm up, timed with the
native clock. It logs `native: start-bench n=20 ns=.. per_ns=..`. This is
the path the control plane's `CreateCell` and `Run` take, without the API
around it.

Through the API too, as `docker run --rm` is timed against `dockerd`:
`api_bench=IMAGE` (with `control=PORT control_exit`) starts
`nativetest api-bench` in the control plane's own cell, reaching it on
that cell's loopback over HTTP/2 (Docker's client reaches `dockerd` over
a local socket). It pulls the image once, untimed (Docker's was already
present), then times 20 rounds of `CreateCell`, `Run` of `/bin/true`
until its exit status arrives, and `Destroy`, after three to warm up. The
image is Docker Hub's `busybox:1.36.1-musl`
(`sha256:3c6ae8008e2c2eedd141725c30b20d9c36b026eb796688f88205845ef17aa213`),
a static busybox like the Linux runs'.

Results (2026-11-23; GCP the same machine types as the Linux rows above,
one boot each):

| Container start, from the caller | n2 (Ice Lake) | Milan | Rome | OpenVMM, Ryzen 5600X |
|---|---|---|---|---|
| Ichor, native ABI | 223 us | 209 us | 210 us | 165-186 us |
| Ichor, gRPC API | 17.0 ms | 16.8 ms | 16.8 ms | 1.83 ms |
| Ichor, gRPC API, console buffered (ADR-0019) | 1.07 ms | 0.88 ms | 0.98 ms | |
| Linux, `unshare` | 1.29 ms | 2.06 ms | 1.92 ms | |
| Linux, crun | 4.9 ms | 6.7 ms | 6.5 ms | |
| Linux, runc | 15.4 ms | 22.1 ms | 21.8 ms | |
| Linux, containerd `ctr run --rm` (no CNI) | 126.5 ms | 122.8 ms | 122.2 ms | |
| Linux, `docker run --rm --network none` | 251 ms | 264 ms | 256 ms | |
| Linux, `docker run --rm` | 583 ms | 591 ms | 602 ms | |

Reading it:

- From a caller, an Ichor container starts in about 0.2 ms: 6-10x faster
  than Linux's bare `unshare` and 25-30x faster than crun on the same
  machines.
- Through the API it took 16.8-17 ms on every GCP machine, whatever the
  CPU, and 1.83 ms under OpenVMM. The difference is the console: the
  control plane logs three lines per container (about 190 bytes), and a
  kernel console write waits for the serial port, which on GCP runs at
  115,200 baud (190 bytes take 16.5 ms); OpenVMM's port has no such
  rate. `dockerd` logs to journald without waiting. ADR-0019 made console
  writes buffered, drained by a kernel task: the API then took 0.88-1.07
  ms on GCP (the native path 203-226 us in the same boots), so a
  container through the API starts about 250x faster than `docker run
  --rm --network none` and 5-6x faster than crun on the same machines.

## End to end with networking: Ichor against containerd + CNI

Process start is a small slice of a container's start in an orchestrated
node: the image pull, the root file system snapshot and the network
setup are where the time goes. This compares the whole path, with the
image cached and networking attached, on the same three GCP machine types
(2026-11-23), both pulling Docker Hub's `busybox:1.36.1-musl` by digest:

- **Ichor**: the API client (`api_bench`) times `PullImage`, then the
  first container from the image on its own (cold), then 20 after three to
  warm up. Each is `CreateCell` (a root over the image and an address on
  the cell switch, with NAT to the uplink), `Run` of `/bin/true` to its
  exit, `Destroy`. A container's own `ip -4 -o addr` shows `10.88.0.30/16`.
- **Linux**: Debian 12 with its containerd 1.6.20, runc 1.1.5 and CNI
  plugins (`bridge` with `host-local` IPAM and masquerading: a veth into
  the container's network namespace). `ctr image pull` timed, then the
  first `ctr run --rm --cni` on its own (cold), then 50 after three to
  warm up; and 50 without `--cni`, the same boot. A container's own `ip -4
  -o addr` shows `10.22.0.3/16`. `ctr run --rm` includes the overlay
  snapshot of the image's layers, the CNI add and delete, and runc.

| | n2 (Ice Lake) | Milan | Rome |
|---|---|---|---|
| Ichor: pull, 19-27 s after boot | 0.87 s | 0.88 s | |
| containerd: pull | 1.08 s | 1.09 s | 1.08 s |
| Ichor: pull at boot (3.7 s after) | 15.3 s | 23.1 s | |
| Ichor: first container, network attached | 1.63 ms | 1.48 ms | 1.51 ms |
| containerd + CNI: first container | 958 ms | 976 ms | 955 ms |
| Ichor: container, network attached | 1.04 ms | 0.97 ms | 0.94 ms |
| containerd + CNI: container | 152 ms | 157 ms | 153 ms |
| containerd, no CNI: container | 118 ms | 119 ms | 117 ms |

Reading it:

- With the image cached and networking attached, a container starts about
  150x faster on Ichor (about 1 ms against 152-157 ms), and the first one
  about 600x faster (1.5 ms against 0.96 s, most of which is the first
  CNI bridge and iptables setup). CNI adds 35 ms a container to
  containerd's own 117-119 ms; Ichor's switch address costs nothing
  measurable.
- **The pull** (2026-11-24, the same image, n2 and Milan) takes 0.87-0.88
  s on Ichor against containerd's 1.08 s, once the machine has been up
  about 20 s; from an empty node, pull plus first start is then about 0.9
  s against about 2 s. It first measured 11-16.5 s. Timing each request
  (`control: ... answered` lines: DNS, TCP, first byte, body) and the
  uplink (`trace_uplink`: every SYN, FIN and RST) found two causes:
  - Converting took 1.05-1.3 s of it: busybox's image links some 400
    applets to one 1 MB binary, and each hard link was hashed, compared
    and listed in the image again. Links now share the file's chunks
    (`image::builder::Builder::same_file`): 30 ms, and the image is 1.5
    MiB, not 7.
  - In its first 20-30 s after boot, the machine's TCP connections to
    Docker Hub's registry (AWS) and auth server (Cloudflare) wait 1-15 s:
    SYNs go out and nothing comes back until a retransmission 3-7 s
    later; DHCP, DNS and the metadata server answer at once, and CDN
    (CloudFront) connections rarely wait. Later connections never do.
    Choosing source ports at random (as Linux does, RFC 6056; they had
    been sequential from 49152 at every boot) changed nothing. A Linux
    VM can only look from 15.7 s of uptime on: it lost one SYN in 80
    connections there, at 17 s. So this is most likely GCP's network
    in a VM's first seconds, which an Ichor machine, booted in under a
    second, meets and a Linux one mostly boots through; not proven. A
    pull right at boot took 15-23 s; `api_bench` now pulls twice and
    reports both (`first_pull_ns`, `pull_ns`).
  Under OpenVMM the same pull takes 1.55 s (its NAT proxies TCP through
  the host, so the guest's own SYNs never cross a network).

Caveats: in the QEMU comparisons above (before `91a5a17`), Linux runs with
its default CPU-vulnerability mitigations, which Ichor did not all apply
yet (ADR-0004). Container start has no Linux
equivalent here. Numbers from TCG (no KVM, as on a Windows laptop) say
little about either kernel.
