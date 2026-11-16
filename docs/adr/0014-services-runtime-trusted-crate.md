# ADR-0014: `services/rt`, the second crate allowed `unsafe`

- Status: Accepted
- Date: 2026-11-16
- Amends: ADR-0001 §1 and §6 ("`kernel/frame` is the only crate that may
  contain `unsafe`"), for user-mode services only. Records what ADR-0012
  §1 decided in one paragraph.

## Context

The founding brief, and ADR-0001, allow `unsafe` in one place:
`kernel/frame`, the kernel's trusted computing base. Every other crate,
`services/` included, is `#![forbid(unsafe_code)]`.

Milestone 6 put Ichor's control plane in user mode: `services/control` is
a native-ABI process in the system cell (ADR-0012 §1), not kernel code.
A user-mode program cannot be written in safe Rust alone, because some
operations have no safe form:

- the process entry point (`_start`, reading `argc`/`argv` off the
  initial stack the kernel built);
- the `syscall` instruction (inline assembly);
- a global allocator (`GlobalAlloc` is an `unsafe trait`, and it hands out
  raw memory);
- the panic handler and its exit path.

Frame cannot provide these. It is kernel code and is not linked into a
user process. The control plane is in the trusted computing base of
every tenant, so the same audit discipline that applies to frame has to
apply to whatever holds this code.

## Decision

### 1. One crate, `services/rt`, holds all of the services' `unsafe`

`services/rt` (library `rt`) is the only crate outside `kernel/frame`
whose crate root does not declare `#![forbid(unsafe_code)]`. `cargo xtask
lint` exempts exactly these two paths and fails on any other crate root
without the attribute. Every other `services/` crate, the binaries built
on `rt` (`services/control`, `services/nativetest`) included, is
`#![forbid(unsafe_code)]`.

`rt` contains only:

| What | Why it needs `unsafe` |
|---|---|
| `_start` (`global_asm!`) and `start` | reading the initial stack the loader wrote |
| `syscall` | the instruction, through `asm!` |
| the safe call wrappers in `sys.rs` | lending the kernel a slice for one call (each states the access) |
| the heap (`heap.rs`) | `GlobalAlloc`; free-list links in freed blocks |
| the panic handler | none beyond the exit call; it lives here because it is the runtime's |
| `rt::main!` | its expansion carries `#[unsafe(export_name)]`, as `frame::main!` does (ADR-0001 §5) |

Protocol code, parsers and policy never go in `rt`. They live in
host-tested `no_std` crates (`services/tls`, `services/oci`, and the
rest) that forbid `unsafe`.

### 2. The same rules as frame

ADR-0001 §6's rules apply to `rt` word for word:

1. Each `unsafe` block holds one unsafe operation and has a `// SAFETY:`
   comment. Clippy's `undocumented_unsafe_blocks` and
   `multiple_unsafe_ops_per_block` are denied.
2. Each `unsafe fn` has a `# Safety` section (`missing_safety_doc`,
   deny). `unsafe_op_in_unsafe_fn` is denied.
3. The public API is sound for any safe caller. No raw pointer or address
   is accepted from safe code where the kernel would write through it;
   wrappers take slices and pass their own pointer and length.
4. `rt` has no dependencies except `ichor-abi` (which forbids `unsafe`).

Both trusted crates get these lints from the workspace (`[lints]
workspace = true`). `cargo xtask lint` now also fails if either crate's
manifest stops inheriting the workspace lints, or if any of the four
lints is relaxed by an `allow` or `expect` attribute anywhere in its
sources.

### 3. Its own budget

`services/rt/audit.toml` sets `rt`'s ceiling in non-comment lines and
`unsafe` sites, counted the way frame's are (`xtask/src/audit.rs`). Both
`cargo xtask frame-audit` and `cargo xtask lint` report and enforce it.
The ceiling is **500 lines / 40 sites**; at this writing `rt` is at 406 /
29. Raising it takes an amendment to this ADR, cited in `audit.toml`,
as frame's does.

### 4. What the kernel still guarantees

`rt`'s `unsafe` can only break its own process. The kernel never trusts
a native process's memory: it copies every buffer in or out with bounds
checks, and resolves every handle through the calling cell's capability
space (ADR-0002). An `rt` bug lets a confused service corrupt itself or
misuse the capabilities it already holds; it cannot reach another cell
or the kernel. That is why `rt` does not join frame's budget: it is a
second, smaller TCB, the control plane's, not an extension of the
kernel's.

## Alternatives considered

- **Put the services' `unsafe` in frame.** Frame is kernel code and does
  not exist in a user process, and mixing user-mode runtime code into the
  kernel's TCB would grow the most trusted budget for no gain. Rejected.
- **Write the entry point and syscall stub in a separate assembly file.**
  It would hide the `unsafe` from the lints and the budget, not remove
  it. Rejected.
- **A runtime per service.** Each would need its own audit. Rejected; one
  shared crate.
- **A third-party runtime or allocator** (for example a `linked_list_allocator`
  crate). Adds external `unsafe` that ADR-0001 §6.3 would make ours to
  audit, for little code saved. Rejected.

## Consequences

- Two crates are allowed `unsafe`, each with an explicit budget and the
  same lints. The lint step names both.
- A service that needs a new kind of system interaction adds one wrapper
  to `rt`, with its safety argument, and stays `forbid(unsafe_code)`
  itself.
- The heap is single-threaded by construction (the native ABI has no
  threads). Threads for services would need a different allocator design
  and an amendment here.
