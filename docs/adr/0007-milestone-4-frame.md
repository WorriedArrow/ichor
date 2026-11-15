# ADR-0007: Frame work for milestone 4, and its budget

- Status: Accepted
- Date: 2026-11-15
- Amends: ADR-0001 §8 (frame budget), after ADR-0003 and ADR-0005

## Context

Milestone 4 makes the Linux ABI good enough for real distributions:
dynamic linking, signals, futexes and threads, full `mmap` semantics,
`epoll` and `/proc`. Most of that is policy and lives in safe kernel
crates, but some of it needs new mechanism in frame, the only crate allowed
`unsafe`.

When this ADR was written, frame stood at 5,096 code lines and 226 unsafe
sites. That is just under `audit.toml`'s step 5 (5,100 / 235), and well
under ADR-0005's milestone 3 ceiling of 8,500 / 380.

Some milestone 4 work turned out to need no new frame code:

- **Copy-on-write `fork`.** Parent and child map the same `UFrame`s
  read-only (`VmSpace::map` and `protect` already exist). The first write
  fault copies the page in the kernel's `umem`.
- **Timed waits.** These are a third deadline kind on the existing
  multiplexed per-CPU timer, plus a sleeper list. They landed within
  step 5.
- **Signal frames.** These needed only accessors on `UserContext`. The
  setters sanitize their input (privileged flag bits are dropped, and MXCSR
  is masked with the CPU's `MXCSR_MASK`), so an `fxrstor`/`iretq` can never
  fault on state user code supplied.

## Decision

Frame gains the following in milestone 4.

1. **Shared address spaces (threads).** A `VmSpace` can be active on
   several CPUs at once: the threads of one process.
   - Frame records, per space, the set of CPUs that have it loaded. It
     updates the set at context switch, where it already loads CR3.
   - `unmap` and `protect` flush the local TLB and send a TLB-shootdown IPI
     to every other CPU in the set. They wait for those CPUs to acknowledge
     before returning, so a page is never reused while a stale translation
     exists.
   - This replaces today's comment in `VmSpace::flush` ("a space is only
     modified while not running on another CPU").
2. **Atomic user-memory operations (futexes).**
   `VmSpace::load_u32_atomic(va)` and `compare_exchange_u32(va, old, new)`
   operate on a 4-byte-aligned user word through the linear map. They
   resolve the page under the space's lock, so the word cannot be unmapped
   mid-operation.

   `FUTEX_WAIT` needs a real atomic read: a torn `rep movsb` copy could
   match the expected value spuriously. `FUTEX_WAKE_OP`, robust lists and
   PI futexes need compare-exchange. The futex hash table, wait queues and
   requeue logic stay in the kernel.
3. **Per-thread kernel state.** This is one `UserContext` per thread (it
   already is per task) and one FS base per thread. No new unsafe code
   beyond the shootdown and the atomic operations is expected.
4. **PCID**, where supported. It tags TLB entries per space, so a switch
   does not flush and shootdowns can be precise. It is optional, and gated
   by CPU feature detection like SMEP/SMAP.

Out of scope: a vDSO (`clock_gettime` without a syscall). That is a
performance feature for milestone 7, and needs a frame-mapped shared
read-only page.

### Budget

The milestone 4 ceiling is **9,500 code lines and 420 unsafe sites**,
superseding ADR-0005's milestone 3 ceiling. Expected additions:

| Area | Lines / sites |
|---|---:|
| CPU sets per space, shootdown IPI and acknowledgement | 250 / 15 |
| Atomic user `u32` load and compare-exchange | 80 / 4 |
| PCID allocation and tagged switches | 150 / 10 |
| Slack for fixes found by milestone 4 workloads | 300 / 10 |

`audit.toml` moves in steps, the first being step 6 at 5,800 / 250.

## Alternatives considered

- **Futexes over plain `copy_from_user`.** Simpler, but a concurrent store
  can make the comparison see a value that never existed. That breaks
  glibc's and musl's lock algorithms in rare, hard-to-debug ways. Rejected.
- **Copy-on-write in frame,** as a `VmSpace::fork` that marks pages.
  Rejected: the policy (when to copy, charging, interaction with
  `mprotect`) belongs in the kernel. Frame's existing primitives are
  enough, and keeping them minimal keeps the TCB small.
- **Flushing the whole TLB on every unmap in a shared space** instead of
  targeted shootdowns. Rejected, because it is slow under multithreaded
  workloads. It remains a fallback if PCID is unavailable and precise
  tracking proves buggy.

## Consequences

- **Multithreaded programs** (glibc's and musl's `pthread`, Go, the JVM)
  become possible in milestone 4. Their correctness rests on the shootdown
  protocol, which gets its own SMP self-test: a thread keeps touching a
  page while another unmaps it, and must fault afterwards.
- **Frame's soundness argument gains one obligation:** a page freed after
  `unmap` is not reachable through any CPU's TLB. The shootdown's
  acknowledgement wait is what discharges it.
