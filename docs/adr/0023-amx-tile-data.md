# ADR-0023: AMX tile data behind XFD

- Status: Accepted
- Date: 2026-11-26
- Amends: ADR-0001 §8 (frame budget), ADR-0008 (the per-thread area)
- Milestone: 8 (clouds: Sapphire Rapids is AWS's m7i and GCP's c3)

## Context

Intel's Advanced Matrix Extensions (Sapphire Rapids and later) add eight
tile registers of 1 KiB each, configured by a 64-byte tile configuration.
Their XSAVE components are XTILECFG (17, 64 bytes) and XTILEDATA (18, 8
KiB). With them, a standard-format area grows from about 2.8 KiB to about
11 KiB, for every thread, though few threads ever touch a tile.

Intel added Extended Feature Disable for that: IA32_XFD arms a component
so that any instruction touching it faults (#NM, the armed components in
IA32_XFD_ERR), and saves treat it as in its init state. Linux (5.16 on)
builds on it: a process asks with `arch_prctl(ARCH_REQ_XCOMP_PERM,
XFEATURE_XTILEDATA)`; until then a tile instruction is SIGILL; after it,
each thread's first tile instruction traps, the kernel gives that thread
the larger buffer and disarms XFD for it. `ARCH_GET_XCOMP_SUPP` and
`ARCH_GET_XCOMP_PERM` say what exists and what is permitted. Permission
is per process, inherited by `fork`, cleared by `execve`; tile data
itself is caller-saved: a new thread or a forked child starts with tiles
in their init state. Because a signal frame with tiles is about 11 KiB,
the request fails with ENOSPC while an alternate stack is too small for
one, and `sigaltstack` refuses small stacks afterwards (ENOMEM);
`AT_MINSIGSTKSZ` counts tile data. Users are oneDNN (PyTorch, TensorFlow)
and anything built on it: on a c3 or m7i, ML containers ask for AMX.

Ichor did not enable XCR0's AMX bits. A tile instruction was SIGILL and
`ARCH_REQ_XCOMP_PERM` EINVAL: nothing was left unsaved, but such
containers ran on vector code only.

## Decision

1. **AMX only with XFD.** Frame enables XCR0 bits 17 and 18 (together)
   only when CPUID says AMX-TILE, XFD (`CPUID.(0xD,1):EAX[4]`) and XFD
   for tile data (`CPUID.(0xD,18):ECX[2]`). Every CPU starts with
   IA32_XFD arming tile data.
2. **Two area sizes.** A thread's area is a heap buffer of 64-byte blocks
   (it was a fixed 4 KiB array): without room for tile data it ends where
   the other components do (`size`), with room it is the whole XCR0 area
   (`tile_size`). A thread without room is saved and restored with an
   RFBM that leaves tile data out, and runs with tile data armed; one
   with room uses all of XCR0 with XFD clear. `restore` writes IA32_XFD,
   when it differs from the CPU's cached value, after saving the previous
   owner (with its own XFD) and before loading the new one. A small
   thread restored after a large one leaves that thread's tiles in the
   registers, armed: no instruction of the small thread can reach them,
   and they are replaced (by the init state) when it gets room.
3. **First use.** A #NM from ring 3 reports IA32_XFD_ERR (read and
   cleared under the same interrupt guard) in `UserEvent::Exception`'s
   `error`. The kernel then gives the thread room (`enable_tiles`: the
   small area copied into a large one, tile data in its init state),
   charging its cell three pages (`LinuxProcess::tile_charge`), and the
   instruction runs again. Without permission: SIGILL, `ILL_ILLOPC`, at
   the instruction; when the cell cannot pay: SIGSEGV, as Linux.
4. **Linux's interface.** `ARCH_GET_XCOMP_SUPP`: XCR0 with x87 and SSE.
   `ARCH_GET_XCOMP_PERM`: that without tile data until it is granted.
   `ARCH_REQ_XCOMP_PERM(n)`: as Linux's `xstate.c`, EINVAL for n at or
   past its last component (`XFEATURE_MAX`, 20), EOPNOTSUPP for any
   component but tile data (only it is asked for) and for tile data the
   CPU lacks; for tile data, ENOSPC while the calling thread's alternate
   stack is smaller than a frame with tiles, else granted (`Prctl::xtile`, copied by `fork`,
   cleared by `execve`). Then `sigaltstack` with a stack no larger than
   such a frame is ENOMEM. `AT_MINSIGSTKSZ` counts tile data where the
   CPU has AMX.
5. **What `rt_sigreturn` gives is checked.** The tile configuration is
   static (no permission needed, every thread restores it), and XRSTOR of
   one LDTILECFG would refuse faults in the kernel: `set_from` resets one
   that is not all zeros or a valid palette 1 (eight tiles at most, 16
   rows of 64 bytes, reserved bytes zero). An independent review before
   the first AMX run found this hole; each area's size and components are
   also fixed when it is made, so no save can reach past it.
6. **Signal frames carry the thread's own state**: its size and its
   components in `_fpx_sw_bytes`. `rt_sigreturn` accepts a frame of
   either size (a thread may first use tiles inside a handler); tile data
   it does not hold whole returns to its init state. A handler starts
   with the reset state but keeps the room, as on Linux. A `fork`'s child
   and a new thread get a copy without tile data (init), and no room.

### Departures from Linux

- The permission request checks the calling thread's alternate stack,
  not every thread's (Linux walks the thread group).
- No guest permissions (`ARCH_*_XCOMP_GUEST_PERM`): no KVM in cells.

## Alternatives considered

- **Room for tile data in every area** (no XFD): 8 KiB more for every
  thread, and a context switch saving tiles nobody uses. Linux rejected
  it for the same reasons.
- **Refusing AMX** as a Linux without it: honest, but ML containers on
  Sapphire Rapids would run slower than on Linux.

## Consequences

- `amx_program` (every boot; the full test only on a CPU with AMX: GCP's
  c3, AWS's m7i): the arch_prctl answers, SIGILL without permission,
  ENOSPC, EINVAL, EOPNOTSUPP, ENOMEM and a large alternate stack, a tile
  loaded and stored back across `sched_yield`, a forked child whose save
  says no tile data and whose tile stores zeros. `xstate_program` runs a
  second time with tile data in every image: permission first, every
  child's first XRSTOR trapping for room, the signal frame carrying the
  tiles, the orphan starting with them in their init state. On other
  CPUs `amx_program` checks that arch_prctl says there is no AMX.
- None of this runs under TCG or on the development PC (no AMX there).
  First run on GCP's c3-standard-4 (2026-11-27): XCR0 0x600e7, both
  `xstate_program` runs (2,816 and 11,008 bytes) and `amx_program`
  passed.
- Frame: XFD, the two sizes, the heap area (two unsafe sites for its byte
  views, in place of four reaching into the old array), `take_xfd_err`,
  the tile configuration check: 7,976 code lines / 311 unsafe sites. `audit.toml` step 21: 8,000 / 315.
