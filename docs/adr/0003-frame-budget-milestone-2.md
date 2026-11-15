# ADR-0003: Frame growth for milestone 2

- Status: Accepted
- Date: 2026-11-15
- Amends: ADR-0001 §8 (frame budget)

## Context

ADR-0001 §8 sets frame's size budget and requires a new ADR for growth past
milestone 1. Milestone 1 ended at 2,894 lines and 150 unsafe sites, well
inside its 6,000 / 320 ceiling. Milestone 2 (scheduler, kernel threads,
native-ABI user processes, capabilities, cells) adds mechanisms that cannot
be written in safe Rust, and this ADR accounts for each of them.

## Decision

The milestone 2 ceiling is **7,000 code lines and 300 unsafe sites**.
`kernel/frame/audit.toml` is raised in steps up to it, each step citing this
ADR. The table lists what goes into frame and why it must be there; the
estimates are code lines and unsafe sites.

| Mechanism | Est. lines / sites | Why it cannot be safe code |
|---|---:|---|
| Tasks: context switch, task stacks, the run/claim protocol, idle tasks, preemption at interrupt exit | 600 / 15 | Switching stacks and registers is assembly. The claim protocol is what makes "a task runs on one CPU" hold for *any* scheduler policy, so it belongs to the TCB. |
| Atomic-mode tracking (per-CPU guard depth; panics on sleeping, yielding or enabling interrupts inside a guard) | 80 / 4 | Needed for `CpuLocal` borrows to stay sound once tasks migrate. |
| User mode: `UserContext`, `UserMode::execute`, `syscall` entry, `swapgs`, return to user, user traps routed back to the kernel | 450 / 40 | Privilege transitions are assembly plus MSR setup. `UserContext` must reject unsafe register values (non-canonical RIP, privileged RFLAGS bits). |
| Typed/untyped frames (`Frame<M>`, `UFrame`), `VmSpace` with a mapping cursor, TLB shootdown, PCID | 700 / 40 | Page tables and physical-memory ownership are the core of memory safety. |
| `VmReader`/`VmWriter` and fallible user copies (exception table, SMAP `stac`/`clac`) | 250 / 20 | A copy that may fault has to be recovered by the trap handler. |

The policies stay outside frame, in safe crates: scheduling (`kernel/sched`,
already), capabilities, cells, accounting, and both syscall personalities.
The slab policy moves out of frame in this milestone, as ADR-0001's
amendment promised; that saves about 150 lines.

## Consequences

Frame will be about half the size of Asterinas's OSTD for the same set of
mechanisms. Any milestone 2 change that would cross 7,000 lines or 300 sites
needs another ADR. Milestones 3–5 (device I/O, IOMMU, DMA, the PCI mediation
in ADR-0001 §4.6) need their own budget ADR.
