# ADR-0008: Extended CPU state (XSAVE), saved eagerly

Status: Accepted (2026-11-15); amended 2026-11-25 and twice 2026-11-26
(the save deferred to when it must be: the title's "eagerly" is now the
restore's; signal handlers start with the reset state)

## Context

glibc and the binaries Debian ships probe CPUID for AVX and pick AVX2 (and on
some CPUs AVX-512) code paths when the kernel enables them. The Phase B plan
requires that before glibc: XSAVE, XCR0 set to what the CPU supports,
per-thread extended state, and the Linux XSAVE layout in signal frames.

### What Ichor does today (before this ADR)

- **The kernel never uses the FPU.** It is built for `x86_64-unknown-uefi`,
  a soft-float target. No kernel code emits x87, SSE or AVX instructions, so
  the user's register file can stay in the registers while the kernel runs.
- **Every CPU enables SSE for ring 3** (`cpu::enable_protections`):
  CR0.MP set, CR0.EM and CR0.TS clear (no #NM trap, so nothing is lazy),
  CR4.OSFXSR and CR4.OSXMMEXCPT set.
- **CR4.OSXSAVE is off.** CPUID.1:ECX.OSXSAVE therefore reads 0, AVX
  instructions fault with #UD, and libc picks its SSE2 code paths.
- **Each `UserContext` holds a 512-byte FXSAVE area.** It starts in the reset
  state (FCW 0x37f, MXCSR 0x1f80). `UserMode::execute` runs `fxrstor64` just
  before entering ring 3 and `fxsave64` right after the thread traps back,
  with interrupts off in between. The save and restore happen on every trap,
  syscalls included: eager, and not tied to context switches.
- **Isolation holds:** a thread always runs with its own complete x87/SSE
  state. No other register state is architecturally usable, because AVX is
  off.
- **Signal frames** carry the 512-byte FXSAVE image, 64-byte aligned, with
  `fpstate` pointing at it. `rt_sigreturn` takes it back after clearing MXCSR
  bits the CPU does not support (MXCSR_MASK), so `fxrstor` can never fault.
  The `sw_reserved` bytes are zero, which tells libc "no XSAVE".

## Decision

1. **XSAVE where the CPU has it.**
   - On every CPU, frame sets CR4.OSXSAVE and writes XCR0 with `xsetbv`.
   - The bootstrap CPU picks XCR0 once: CPUID.(EAX=0xD,ECX=0) supported bits,
     intersected with an allow list:
     - x87 (0), SSE (1), AVX (2);
     - AVX-512 (5, 6, 7) only if all three are supported.
   - Excluded:
     - MPX (3, 4): deprecated;
     - PKRU (9): needs CR4.PKE and a protection-key ABI that does not exist
       yet;
     - AMX (17, 18): 8 KiB of tile state per thread, and Linux gates it behind
       `arch_prctl` permission;
     - every supervisor state (`IA32_XSS` stays 0).
   - Each application processor must support the chosen mask, or frame stops
     with a fatal error. There is no CPU-by-CPU XCR0: a thread may migrate.
   - The XSAVE area size comes from CPUID.(0xD,0).EBX after `xsetbv`. With the
     allow list it is at most about 2.7 KiB; frame refuses anything above
     4 KiB.
   - CPUs without XSAVE keep today's FXSAVE path.
2. **Standard (non-compacted) format, with XSAVEOPT where available.**
   - That is the layout the Linux signal frame carries, so the area can be
     copied to and from user memory unchanged.
   - XSAVEOPT's modified-component tracking is safe here: a context's area
     is never written between its own `xrstor` and the matching `xsaveopt`.
     Software changes the area only while the thread is in the kernel, which
     is after the save.
   - XSAVES and the compacted format are not used: they would need a
     translation step for signal frames, and supervisor states are excluded.
3. **Eager, as today: no lazy switching.**
   - The state is restored right before ring 3 and saved right after the
     trap. CR0.TS stays clear and #NM is never used to defer a restore.
   - **Lazy switching is rejected for security.** It leaves the previous
     thread's registers live in the CPU until the next thread's first FPU
     instruction traps. LazyFP (CVE-2018-3665) showed that a speculative read
     of those registers leaks them across processes, and here that would mean
     across cells.
   - Eager switching also removes a trap path and a per-CPU "owner" pointer
     from frame. Linux made eager the default in 4.6 and dropped lazy in 4.14.
   - **Cost:** about 2.7 KiB of save and restore per trap with AVX-512. XSAVEOPT
     skips components still in their init state or unmodified, which makes the
     common no-AVX case close to the FXSAVE cost.
   - Phase E may still skip the save and restore when a trap does not switch
     threads. That is a later optimization and does not change the model.
4. **Per-thread state on the heap.**
   - `UserContext` keeps its register layout (the entry stubs use fixed
     offsets) but now owns a boxed, 64-byte-aligned 4 KiB area.
   - `UserContext` becomes `Clone` instead of `Copy`, so a context copy
     (fork, a new thread) is an explicit deep copy.
   - The area is created in the init state: legacy FCW and MXCSR, and an
     XSAVE header with XSTATE_BV 0.
5. **State the kernel takes from user memory is sanitized.** `rt_sigreturn`
   hands frame an area, and before it is ever loaded frame clears:
   - XSTATE_BV bits outside XCR0;
   - XCOMP_BV and the reserved header bytes;
   - MXCSR bits outside MXCSR_MASK.

   Those are exactly the #GP conditions of a standard-format `xrstor`, so the
   restore can never fault in the kernel.
6. **The signal frame is the Linux layout.** `fpstate` points at a 64-byte
   aligned XSAVE area. Its `sw_reserved` bytes (FXSAVE offset 464) hold
   `struct _fpx_sw_bytes`:
   - `magic1` = `FP_XSTATE_MAGIC1` (0x46505853);
   - `extended_size` = area + 4;
   - `xfeatures` = XCR0;
   - `xstate_size` = area size.

   The area is followed by `FP_XSTATE_MAGIC2` (0x46505845), and `uc_flags`
   has `UC_FP_XSTATE`. On `rt_sigreturn` the full area is restored only if
   both magics are present and `xstate_size` matches. Otherwise only the
   legacy 512 bytes are taken, and the extended components return to their
   init state, as Linux does for FXSAVE-only frames. The auxiliary vector
   gains `AT_MINSIGSTKSZ`, so libc's `sysconf(_SC_MINSIGSTKSZ)` accounts for
   the larger frames.

## Alternatives considered

- **Lazy FPU switching (CR0.TS + #NM):** rejected for the LazyFP leak
  described above.
- **XSAVES and the compacted format:** smaller areas when components are
  sparse, but every signal frame would need converting to and from the
  standard format. Revisit if supervisor states (CET, for example) are
  adopted; see ADR-0004 on CET.
- **Enabling AMX and PKRU now:** no workload needs them yet. Each needs an ABI
  first (`arch_prctl(ARCH_REQ_XCOMP_PERM)`, `pkey_*`).
- **A fixed inline 4 KiB area in `UserContext`:** keeps it `Copy`, but every
  context copy and stack temporary would move 4 KiB. Rejected.

## Consequences

- AVX and AVX2 (and AVX-512 where present) work in user space, and their
  state is per thread and survives signals.
- glibc's ifunc selection and `ld.so`'s `_dl_runtime_resolve_xsave` path work
  as on Linux.
- The frame budget grows by 4 unsafe sites (`xsetbv`, `xrstor`, `xsaveopt`,
  `xsave`; FXSAVE/FXRSTOR moved into the same module) and about 125 lines:
  frame is at 5,504 lines / 242 sites after this change. That is inside
  `audit.toml` step 6 (5,800 / 250) and ADR-0007's 9,500 / 420.
- Every thread costs one more 4 KiB heap allocation.

## Amendment (2026-11-25): no restore when the registers hold the state

§3's "later optimization", with the rest of what a system call paid for on
its way back to ring 3. On GCP a null system call took 309-575 ns against
Linux's 107-393 ns (`docs/benchmarks.md`).

- **The restore is skipped when the registers already hold the area.**
  Every save stamps the area with a value unique to its CPU and that save
  (`ExtState::stamp`), and records it as what that CPU's registers hold
  (`LOADED`, per CPU). `restore` returns at once when the two match: the
  thread's last save was on this CPU, and nothing loaded the registers
  since. Only `restore` loads them (the kernel is soft-float, and the
  firmware runs at boot only), so a match means the registers are exactly
  the area. Software writing the area (`set_fpu_state`) clears its stamp,
  which forces the next restore; a copy keeps the stamp, as it keeps the
  bytes. A thread that ran on another CPU in between carries that CPU's
  stamp, so it never matches a stale one. The save stays eager.
  - Security: ring 3 never runs with another thread's registers, which is
    what LazyFP needs; nothing is deferred to a trap, and CR0.TS stays
    clear.
  - XSAVEOPT stays sound: a skipped XRSTOR leaves its tracking on the
    area's earlier XRSTOR, and software has not written the area since.
- **`sysretq` instead of `iretq`** when the context is what a `syscall`
  left: rcx its RIP and r11 its (sanitized) RFLAGS. CS and SS come from
  STAR as the same selectors, RIP is below `USER_END` (canonical, so no
  Intel SYSRET #GP in ring 0), and the sanitized RFLAGS hold no TF or RF.
  Ring 0 runs on the user's stack from loading RSP to `sysretq`, as it
  already did at the syscall entry: NMI, #MC and #DF use IST stacks, and
  interrupts are off. AMD's SYSRET leaves SS's hidden attributes as they
  were, which matters only to 32-bit code; Ichor runs none.
- **The FS base MSR is written only when it changes** (per-CPU, not in the
  block the entry area maps: another thread's TLS pointer is not the
  block's to show). Ring 3 cannot write it: CR4.FSGSBASE is off.
- **The TSC clock reads with a multiply and a shift**, not a 128-bit
  division (two per system call, from the CPU-time accounting), and timer
  deadlines convert in 64-bit halves.

With the user-memory changes of the same commit (a `VmSpace` keeps no tree
of its pages: each PTE's counted reference is the record, and range
unmaps walk the tables; `write_protect` turns a batch read-only with one
shootdown), frame grows to 7,390 lines / 295 sites: `audit.toml` step 16,
7,450 / 310, inside ADR-0007's 9,500 / 420.

Measured under OpenVMM on a Ryzen 5 5600X (Zen 3, safe-RET thunks, no IBRS
enumerated), the minimum of five rounds in one boot, before and after this
amendment and the user-memory changes: null system call 356 → 160 ns, pipe
round trip 4.24 → 2.83 us, anonymous page fault 1.26 → 0.44 us, fork +
wait 15 → 13 us, fork + exec + wait 161 → 114 us, container start from a
native caller 235 → 171 us.

## Amendment (2026-11-26): saved only when it must be

The rest of §3's "later optimization". The XSAVEOPT after every trap was
the largest software cost of a null system call: about 29 of 100 ns
locally (with SRSO's thunks off), more on CPUs whose XCR0 has AVX-512.
Ichor's null system call on GCP's Ice Lake (n2) was 163 ns against Debian
12's 106. Linux saves a task's registers only when it switches away from
it (or the kernel needs them); so does Ichor now.

- **The state stays in the registers while the kernel runs** ("live" on
  that CPU), and is saved:
  - when the task running it switches out (`xstate::switch_out`, from
    `schedule_inner`), so a state never reaches another CPU unsaved and a
    migrated thread restores what it last ran with;
  - when another state is loaded on that CPU (another context of the same
    task);
  - when software reads, copies or replaces it: the signal frame
    (`fpu_state`), `fork` and `clone` (`Clone`), `rt_sigreturn`
    (`set_fpu_state`, saved first so that no later save overwrites what
    it writes).

  A context dropped while live (exit, `execve`) is not saved.
- **The restore stays eager**: before every entry to ring 3, unless the
  registers already hold the state (live here, or this CPU saved it last
  and loaded nothing since). Ring 3 never runs with another thread's
  registers, CR0.TS stays clear and #NM is never used, so this is not lazy
  switching and LazyFP does not apply. What is newly in the registers
  while the kernel runs is the interrupted thread's own state, as on
  Linux.
- **Why the kernel cannot clobber them.** The target is soft-float
  (`-mmx,-sse,+soft-float`), so the compiler emits no FPU or vector
  instruction; using them otherwise needs `asm!`, intrinsics or a call to
  a `#[target_feature]` function, all `unsafe`, which only frame may hold
  (ADR-0001 §5). On 2026-11-26 the release kernel image disassembled to
  no x87, MMX, SSE, AVX or AVX-512 instruction outside this module's
  FXSAVE/XSAVE/XRSTOR sites. The firmware runs at boot only, and
  frame's one Hyper-V fast hypercall passes its input in general
  registers, not XMM.
- **The record** (`xstate.rs`'s invariants): each area is an `Arc` shared
  by the context and, while live, its CPU's `OWNER`; `live` names the CPU,
  and both change together on it with interrupts off. Only that CPU
  touches a live area (to save into it); software reaches an area only
  while it is live nowhere, and only `restore`, which takes `&mut`, makes
  it live, so no reference into an area outlives that. A state live on
  another CPU (possible only if a context moved to another task before
  the task that ran it switched out) is waited for, not read. The
  per-CPU stamp of what the registers hold (the 2026-11-25 amendment) is
  cleared when a state goes live, since the registers then move on from
  every area: else a fork's child, which shares its parent's stamp, could
  start with registers the parent changed before exiting.
- XSAVEOPT stays sound for the same reason as before: an area is written
  between its XRSTOR and its next save only by saves.

Tests, on every boot (1, 4 and 8 vCPUs): `fpu_stress_program` (three
processes with their own YMM0 and YMM15 patterns, blocking ping-pong over
pipes, spinning so that wakers run elsewhere, `sched_yield`, each checked
after every system call; and a child forked by a process that changes its
registers and exits at once), and `avx_program`'s signal check now sets
YMM15 just before `kill`, so a frame written from a stale save fails.
Each was checked against a broken build: without the clearing of the
stamp the AVX test fails (check 1); without the save before a signal
frame, check 3; with one `pxor xmm15` added to frame's return from ring
3, check 5; without the save at switch-out the boot hangs (a migrated
thread waits for its old CPU to save).

Frame: 84 more lines and 4 unsafe sites (the `Sync` claim and three
references into an area), 7,738 / 308: `audit.toml` step 19, 7,800 /
315, inside ADR-0007's 9,500 / 420.

Measured as before (OpenVMM, Ryzen 5 5600X, safe-RET thunks on, five
rounds in one boot), with ADR-0021 (CPU time from the scheduler) in
between: null system call 160-166 → 137-148 ns (ADR-0021) → 98-102 ns
(this amendment); pipe round trip 2.83-2.89 → 2.63-2.78 us.

## Amendment (2026-11-26, second): handlers start reset; every component tested

A signal handler used to start with the interrupted code's extended
state, so a rounding mode or flush-to-zero the code had set reached the
handler. Linux starts every handler with the reset state
(`fpu__clear_user_states`): x87 control word 0x037f, MXCSR 0x1f80,
everything else in its init state, PKRU at its default. Ichor now does
the same: once the frame holds the interrupted state, the context's is
replaced by the default one (`UserContext::reset_fpu_state`), and
`rt_sigreturn` brings the frame's back.

`fpu_stress_program` checked YMM0 and YMM15 only. `xstate_program`
replaces it and checks every component XCR0 enables, whatever the CPU:
it loads the registers from an image with its own XRSTOR (x87 registers
and control word, MXCSR, XMM, YMM, ZMM0-31, k0-k7, and later components
as they are enabled, at the offsets CPUID gives), saves them with its own
XSAVE, and after every system call compares a fresh save byte for byte.
The same three processes, fork and orphan as before, each with its own
image; first a signal whose handler must find the reset state (control
words by FNSTCW and STMXCSR, the rest zero in a save to fresh memory),
the interrupted area in its frame, values of its own that survive its
system calls, and, after `rt_sigreturn`, exactly the registers it
interrupted. A mismatch prints the check, the offset in the area and the
two quadwords. Checked against broken builds: a save leaving out AVX
(check 15: the frame's XSTATE_BV), no reset for the handler (11), one
bit flipped by `rt_sigreturn` (17, at its offset), and the stamp not
cleared when a state goes live (2 on four vCPUs: the first process found
another's registers). AVX-512 components are covered only where the CPU
has them: not under TCG or on the development PC, so on GCP's n2.
