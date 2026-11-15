# ADR-0008: Extended CPU state (XSAVE), saved eagerly

Status: Accepted (2026-11-15)

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
