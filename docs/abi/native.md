# Ichor native ABI (version 1)

The native ABI is the small, capability-based syscall interface used by
Ichor's own services (ADR-0002 §5). It is defined in `kernel/abi` and shared
by the kernel and user services.

This document covers version 1, which is the subset implemented in milestone
2 to prove the model end to end. It will grow (channels, object waiting,
address-space and cell management) through milestones 2–6.

## Calling convention

A native process makes a call with the `syscall` instruction. Registers
follow the Linux convention so the same trap entry serves both personalities:

| Register | Use |
|---|---|
| `rax` | syscall number on entry, result on return |
| `rdi, rsi, rdx, r10, r8, r9` | arguments 0–5 |
| `rcx, r11` | clobbered by `syscall` (return RIP, RFLAGS) |

The kernel dispatches on the calling process's personality, so a Linux
process cannot reach native calls by choosing syscall numbers, and vice
versa.

A handle is a 64-bit value meaningful only inside the calling cell's
capability space: a 32-bit slot index and a 32-bit generation. A handle from
another cell, or a closed handle, simply fails to resolve.

## Results

`rax` holds a non-negative value on success. On failure it holds the negated
error code. `ichor_abi::decode` turns `rax` back into `Result<u64, i64>`.

| Code | Name | Meaning |
|---:|---|---|
| 1 | `NoSys` | Unknown syscall number |
| 2 | `BadHandle` | Handle invalid, foreign, revoked, or wrong type |
| 3 | `Denied` | Capability lacks a required right |
| 4 | `Invalid` | An argument was invalid |

## Calls

| # | Name | Args | Returns |
|---:|---|---|---|
| 0 | `VERSION` | — | the ABI version (1) |
| 1 | `MEM_SIZE` | `arg0` = memory handle | the object's size in bytes; needs the INSPECT right |
| 2 | `HANDLE_DUP` | `arg0` = handle, `arg1` = rights mask | a new handle with reduced rights; needs DUPLICATE |
| 3 | `HANDLE_CLOSE` | `arg0` = handle | 0 |
| 4 | `EXIT` | `arg0` = exit code | does not return |

## Rights

Generic rights occupy the low bits of the 32-bit mask; object-specific rights
the high bits.

| Bit | Right |
|---:|---|
| 0 | `DUPLICATE` |
| 1 | `TRANSFER` |
| 2 | `INSPECT` |
| 3 | `WAIT` |
| 8 | `READ` |
| 9 | `WRITE` |
| 10 | `MAP` |
| 11 | `CREATE_CELL` |

`HANDLE_DUP` can only drop rights, never add them, and only with the
`DUPLICATE` right.
