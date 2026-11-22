# The direction flag was cleared on every return to ring 3

## Symptom

The control plane, pulling `python:3.12-slim-bookworm` plus CPython's
source tree, died in two of three runs while converting the layers into
an Ichor image:

```
ichor: native: cell 93 killed: exception 13 at rip 0x22d100 (cr2 ...)
ichor: native: cell 93 killed: exception 13 (error 0x0) at rip 0x22ccb2 (cr2 ...)
```

Both faults were in `image::builder::Builder::file`, inside the inlined
`BTreeMap<[u8; 32], Vec<(u64, u64)>>` insert, dereferencing a
non-canonical pointer read from a map node. One was the node's parent
pointer (offset 0x160), the other the first value's `Vec` pointer
(offset 0x170). Both offsets fall in the 32 bytes just past the node's
eleven 32-byte keys, and the bad values looked like hashes (the keys
are BLAKE3 hashes). Earlier, rarer user-space failures had the same
feel and were never explained: a redis crash under load (Alpine, musl),
and a page fault in dpkg's decompressor on the held-back `pcp-page-lists`
branch.

## Cause

`frame`'s `UserContext` kept only CF, PF, AF, ZF, SF and OF of the user's
RFLAGS (`USER_RFLAGS_ALLOWED = 0x08d5`). DF (bit 10) was dropped, so
every return to ring 3, after a syscall, a page fault or a preemption,
ran with the direction flag clear.

User code runs with DF set during a backward string copy: `memmove`
for overlapping buffers where the destination is above the source, which
is how a sorted array (a `BTreeMap` node's keys) shifts up to make room.
Rust's `compiler_builtins` on `x86_64-unknown-none` and musl both do
`std; rep movs; cld`. A `rep movs` is interruptible: if a fault or an
interrupt lands mid-copy, the CPU saves RIP at the instruction with RCX,
RSI and RDI updated, and resumes it on return. With DF cleared in
between, the rest of the copy ran *forward* from where it stopped,
copying source bytes over memory past the end of the destination. For
a node's key shift that is the parent pointer and the first values.

A demand-paging fault mid-copy needs the destination page to be fresh,
and a preemption needs the timer to land on the copy, which is why it
was intermittent and showed up under memory-heavy load.

## Fix

- `USER_RFLAGS_ALLOWED` includes DF (`0x0cd5`). The kernel never runs
  with the user's DF: `syscall` clears it through `FMASK`, and every trap
  stub runs `cld` before calling Rust. So keeping it in the user context
  costs nothing on the kernel side.
- Signal delivery clears DF before entering a handler, as the SysV ABI
  requires at function entry and Linux does. The signal frame still
  records the interrupted code's flag, and `rt_sigreturn` restores it.
- `UserContext::direction_down` and `clear_direction` expose just that
  bit to the kernel.

## Test

`runtest::direction_program`, run from ring 3 on every boot: it fills
64 KiB with a pattern, copies it with `std; rep movsq` from the last
qword down into 64 KiB of untouched anonymous memory (16 demand faults
mid-copy), and checks every qword. It then sets DF, makes a syscall, and
checks DF is still set. With the old mask the copy runs off the end of
the mapping and the program dies with SIGSEGV (`direction flag test
failed check -11`); with the fix it passes. `tests/boot.rs` asserts the
marker on 1, 4 and 8 vCPUs.

Native services now print every general register when killed by an
exception, which is how the two corrupted fields were identified.
