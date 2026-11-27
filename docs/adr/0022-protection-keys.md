# ADR-0022: Protection keys for user pages

- Status: Accepted
- Date: 2026-11-26
- Amends: ADR-0001 §8 (frame budget), ADR-0008 §1 (the components frame
  enables)
- Milestone: 7 (workloads)

## Context

Intel CPUs since Skylake-SP and AMD's since Zen 3 have protection keys
for user pages (PKU): four bits in each user PTE name one of 16 keys,
and a per-thread register, PKRU, holds two bits for each key (access
disable, write disable) that limit data accesses to user pages without
a system call or a TLB flush. Linux has exposed them since 4.9:
`pkey_alloc`, `pkey_free`, `pkey_mprotect`, a SIGSEGV with `SEGV_PKUERR`
and `si_pkey` when a key denies an access, PKRU saved with the rest of
the extended state, set to `init_pkru_value` (0x55555554: every key but
0 denies access) at `execve` and for every signal handler, and restored
by `rt_sigreturn` from the frame's XSAVE area. glibc wraps the calls;
JITs and memory-safety runtimes (V8, Wasmtime's pooling allocator)
use them where `pkey_alloc` succeeds.

Ichor enabled neither CR4.PKE nor PKRU in XCR0. `WRPKRU` was SIGILL, and
`pkey_*` were ENOSYS. Nothing was silently wrong, but a container that
uses keys on Linux had to go without.

## Decision

1. **PKRU exists exactly when it is saved.** Frame adds PKRU (XCR0 bit 9)
   to the components it may enable when CPUID says PKU, and sets CR4.PKE
   exactly when XCR0 has it. So a thread's PKRU is saved, restored,
   copied at `fork` and carried in signal frames with the rest of its
   extended state (ADR-0008), and no CPU has keys without that.
2. **The kernel is not limited by the user's PKRU.** With CR4.PKE, PKRU
   limits supervisor accesses to user-mode pages too, and Ichor keeps the
   interrupted thread's PKRU loaded while the kernel runs (it saves the
   registers only when it must, ADR-0008's amendment). That is sound
   because the kernel never reaches user memory through user addresses:
   frame's user copies go through the linear map (ADR-0011), SMAP is on,
   and AC is never set.
3. **Keys in PTEs.** `UserProt` gains `key` (bits 59-62 of a leaf, kept
   when a 2 MiB leaf is split); `vma::Prot` gains `key`, so regions with
   different keys do not merge and `mprotect` keeps each region's key
   (`RegionMap::protect_with`). A process's allocated keys are a bitmap
   in its `Mm`, key 0 allocated from the start, copied by `fork`, reset by
   `execve` (a new `Mm`).
4. **Linux's semantics.** `pkey_alloc(flags, rights)`: flags must be 0
   and rights at most `PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE`
   (EINVAL); the lowest free key, with the calling thread's PKRU set to
   `rights` for it; ENOSPC when none is free, and always without PKU (as
   Linux, whose only key is then 0). `pkey_free` of a key not allocated
   is EINVAL (key 0 may be freed, as on Linux). `pkey_mprotect` with -1
   is `mprotect`, otherwise the key must be allocated. A page fault whose
   error code has the PK bit is never served by paging: it is SIGSEGV
   with `SEGV_PKUERR`, `si_addr` and `si_pkey` (the region's key). New
   states (`execve`, signal handlers) start with PKRU 0x55555554.

### Departures from Linux

- **System calls ignore keys.** Linux's user copies run under the
  caller's PKRU, so `read` into a page whose key denies writes is
  EFAULT. Ichor's copies go through the linear map (point 2) and the
  fault-in path serves any present page, so a system call reaches the
  memory whatever its key. Honoring it means passing the calling
  thread's PKRU to every copy and teaching the fault-in path that a key,
  not a mapping, stopped it. Left for later.
- **No execute-only key.** Linux gives `PROT_EXEC`-only mappings a key
  of their own that denies reads; Ichor maps them readable, as Linux
  does without PKU.
- `/proc/<pid>/smaps` (`ProtectionKey:`) does not exist in Ichor.

## Alternatives considered

- **Refusing keys as a Linux without PKU does.** Smallest, and honest,
  but containers that use keys would run without them on hardware that
  has them.
- **Saving PKRU separately with RDPKRU/WRPKRU at each switch.** XSAVE
  already saves it with the rest when XCR0 has it, and the save is
  deferred (ADR-0008); a separate path would be a second copy of the
  state to keep coherent.

## Consequences

- `pkey_program` (every boot where the CPU has PKU: QEMU's TCG `max`,
  and KVM on a host that passes PKU through; GCP's n2, n2d and c3 and
  OpenVMM here do not, so on 2026-11-27 it had run under TCG only): key 1
  allocated with PKRU opened for it, a
  page put under it, a read with access denied is SIGSEGV with
  `SEGV_PKUERR`, the key and the address; the handler starts with
  0x55555554, opens the key in its frame, and the read goes through
  after `rt_sigreturn`; the same for a write with writes denied, and
  after `mprotect` (a build where `mprotect` drops the key fails check
  14); the errors; all fifteen keys, then ENOSPC; a forked child's PKRU
  and keys. `xstate_program` covers PKRU as one more component (random
  keys, key 0 open).
- Frame: CR4.PKE, PKRU in XCR0 and its default, `UserProt::key`, and
  PKRU accessors: 7,800 code lines / 309 unsafe sites. `audit.toml` step
  20: 7,850 / 315.
