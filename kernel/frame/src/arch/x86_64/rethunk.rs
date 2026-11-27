//! Return thunks: AMD's safe RET for SRSO (and Retbleed on Zen 1/2)
//! (ADR-0004's amendment of 2026-11-23, "Return thunks").
//!
//! The kernel is built with `-Zfunction-return=thunk-extern`, `core` and
//! `alloc` included, so every return the compiler emits is
//! `jmp __x86_return_thunk`; frame's own assembly returns the same way. The
//! thunk below starts as a plain `ret`. Where SRSO applies, [`install`]
//! patches it, once, on the boot CPU, before any other CPU or user code
//! runs, into a jump to a safe-RET sequence: a `call` to a routine that
//! drops its own return address and returns, so that every return is
//! predicted to land on a `ud2` the kernel placed there, whatever a user
//! trained. The entry code calls the matching untraining routine on every
//! entry from ring 3, before the kernel's first return. The sequences
//! follow AMD's published mitigation (and Linux's layout of it):
//!
//! - Zen 1/2 (family 17h, Hygon 18h): `ichor_srso_untrain` hides the
//!   safe-RET routine inside a `movabs` immediate, the routine starting on a
//!   cache line; ordinary `.text` gives it that.
//! - Zen 3/4 (family 19h): the untraining routine and the safe-RET routine
//!   must sit at virtual addresses that differ in exactly bits 2, 8, 14 and
//!   20, the first 2 MiB-aligned. The image's addresses are the linker's,
//!   so frame writes the two sequences into pages of their own and maps
//!   them at `THUNK_BASE` and `THUNK_BASE + 0x104000`.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::mm::meta::kind;
use crate::mm::{PAGE_SIZE, PhysAddr, THUNK_BASE, kspace, page_alloc, phys_to_virt};

core::arch::global_asm!(
    ".p2align 4",
    ".global __x86_return_thunk",
    "__x86_return_thunk:",
    "ret",
    // Room for the `jmp rel32` `install` writes over the `ret`.
    "int3",
    "int3",
    "int3",
    "int3",
    // Zen 1/2: the routine at `ichor_srso_safe_ret` begins a cache line and
    // is the 8-byte immediate of the `movabs` at `ichor_srso_untrain`.
    ".p2align 6",
    ".skip 62, 0xcc",
    "ichor_srso_untrain:",
    ".byte 0x48, 0xb8",
    "ichor_srso_safe_ret:",
    "lea rsp, [rsp + 8]",
    "ret",
    "int3",
    "int3",
    "lfence",
    "call ichor_srso_safe_ret",
    "ud2",
    "ichor_srso_return_thunk:",
    "call ichor_srso_safe_ret",
    "ud2",
    // What the entry code calls to untrain (`install` makes it a jump to
    // the CPU's routine; it is called only then).
    ".p2align 4",
    ".global ichor_untrain_stub",
    "ichor_untrain_stub:",
    "ud2",
    "int3",
    "int3",
    "int3",
    // Every indirect call and jump of the compiled kernel, target in r11:
    // a plain jump, or (`install_retpoline`) a jump to the retpoline after
    // it, whose speculation is caught in the loop and whose return is the
    // kernel's return thunk, as Linux's.
    ".p2align 4",
    ".global __x86_indirect_thunk_r11",
    "__x86_indirect_thunk_r11:",
    "jmp r11",
    "int3",
    "int3",
    "ichor_retpoline_r11:",
    "call 2f",
    "1:",
    "pause",
    "lfence",
    "jmp 1b",
    "2:",
    "mov [rsp], r11",
    "jmp __x86_return_thunk",
);

/// The safe-RET sequence a CPU needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SafeRet {
    /// Zen 1/2 (and Hygon 18h): `movabs` untraining.
    Zen12,
    /// Zen 3/4: the aliased pair at `THUNK_BASE`.
    Alias,
}

/// Nonzero once `install` has pointed `ichor_untrain_stub` at the CPU's
/// untraining routine: every CPU's block tells the entry code (`usermode`).
pub(crate) static UNTRAIN: AtomicU64 = AtomicU64::new(0);

fn labels() -> [u64; 4] {
    let (t, u, r, s): (u64, u64, u64, u64);
    // SAFETY: computes four addresses RIP-relatively; no memory access.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + __x86_return_thunk]",
            "lea {u}, [rip + ichor_srso_untrain]",
            "lea {r}, [rip + ichor_srso_return_thunk]",
            "lea {s}, [rip + ichor_untrain_stub]",
            t = out(reg) t, u = out(reg) u, r = out(reg) r, s = out(reg) s,
            options(nomem, nostack, preserves_flags)
        )
    };
    [t, u, r, s]
}

/// `jmp rel32` at `from` to `to`, as bytes.
fn jmp(op: u8, from: u64, to: u64) -> [u8; 5] {
    let rel = (to.wrapping_sub(from + 5) as i64) as i32;
    let r = rel.to_le_bytes();
    [op, r[0], r[1], r[2], r[3]]
}

/// A page of `int3`s with `code` at `offset`, mapped at `va`.
fn code_page(va: u64, offset: usize, code: &[u8]) -> Option<()> {
    let pa = page_alloc::alloc(0, kind::ALLOCATED)?;
    let dst = core::ptr::with_exposed_provenance_mut::<u8>(phys_to_virt(pa) as usize);
    // SAFETY: a fresh, exclusively owned page reachable RW through the
    // linear map; no Rust reference points into it.
    unsafe { super::fill_untyped(dst, 0xcc, PAGE_SIZE as usize) };
    let at = dst.wrapping_add(offset);
    // SAFETY: as above; `offset + code.len()` is within the page (callers
    // write a few bytes near its start).
    unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), at, code.len()) };
    kspace::map_thunk(va, pa.as_u64())
}

/// `N` bytes of the image's code at `at`.
fn code<const N: usize>(at: u64) -> [u8; N] {
    let p = core::ptr::with_exposed_provenance::<[u8; N]>(at as usize);
    // SAFETY: callers read within, or just past, compiled functions of the
    // image's text, which is mapped readable; read, never written.
    unsafe { p.read_unaligned() }
}

/// Whether frame's own compiled code returns through `__x86_return_thunk`
/// (the build's `-Zfunction-return`): a plain `ret` would bypass it.
fn compiled_with_thunks(thunk: u64) -> bool {
    #[inline(never)]
    fn probe() -> u64 {
        core::hint::black_box(0x1c40)
    }
    let start = probe as *const () as usize as u64;
    (start..start + 48).any(|at| code::<1>(at)[0] == 0xe9 && jmp(0xe9, at, thunk) == code(at))
}

/// Where `compiler_builtins`' stack probe returns: it is assembly the
/// compiler's thunks never reach, ending `leave; ret` and then at least
/// four bytes of `int3` padding, room for a `jmp`. Found through a call
/// of it from a function with a large frame, the target checked against
/// the probe's first instructions (`push rbp; mov rbp, rsp; mov r11, rax`).
fn stack_probe_ret() -> Option<u64> {
    #[inline(never)]
    fn large() -> u8 {
        core::hint::black_box([0u8; 3 * 4096])[4096]
    }
    let start = large as *const () as usize as u64;
    let probe = (start..start + 32).find_map(|at| {
        let c: [u8; 5] = code(at);
        let target = (at + 5).wrapping_add(i32::from_le_bytes([c[1], c[2], c[3], c[4]]) as u64);
        (c[0] == 0xe8 && code::<7>(target) == [0x55, 0x48, 0x89, 0xe5, 0x49, 0x89, 0xc3])
            .then_some(target)
    })?;
    (probe..probe + 128)
        .find(|&at| code::<6>(at) == [0xc9, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc])
        .map(|at| at + 1)
}

/// Writes `jmp rel32` to `target` over the five bytes at `at`, the first
/// byte last.
///
/// # Safety
///
/// Only this CPU runs. The five bytes are image text; until the last
/// store, nothing executes the four after the first.
unsafe fn patch(at: u64, target: u64) -> Result<(), &'static str> {
    let bytes = jmp(0xe9, at, target);
    let pa = kspace::kernel_phys(at).ok_or("image text is not mapped")?;
    let dst =
        core::ptr::with_exposed_provenance_mut::<u8>(phys_to_virt(PhysAddr::new(pa)) as usize);
    // SAFETY: `dst` is the linear-map alias of those bytes (the firmware
    // loads the image physically contiguous), image memory no Rust object
    // occupies; the caller's contract covers what runs.
    unsafe { core::ptr::copy_nonoverlapping(bytes[1..].as_ptr(), dst.wrapping_add(1), 4) };
    // SAFETY: as above; this one store makes the five bytes a whole `jmp`.
    unsafe { core::ptr::write_volatile(dst, bytes[0]) };
    // Serializes, so this CPU fetches no stale bytes.
    super::regs::cpuid(0, 0);
    Ok(())
}

/// Points `__x86_return_thunk` at `kind`'s safe-RET sequence (mapping the
/// Zen 3/4 pair first) and records the routines for the entry code. Must
/// run on the boot CPU before any other CPU or user code runs.
pub(crate) fn install(kind: SafeRet) -> Result<(), &'static str> {
    let [thunk, zen12_untrain, zen12_thunk, untrain_stub] = labels();
    if !compiled_with_thunks(thunk) {
        return Err("the kernel was built without return thunks");
    }
    let probe_ret = stack_probe_ret().ok_or("the stack probe's return was not found")?;
    let (untrain, target) = match kind {
        SafeRet::Zen12 => (zen12_untrain, zen12_thunk),
        SafeRet::Alias => {
            // Untraining at U (2 MiB-aligned): two-byte NOP, LFENCE, then a
            // jump to the return thunk. Safe RET at S = U | bits 2, 8, 14,
            // 20: drop the return address and return; the thunk follows it.
            let (u, s) = (THUNK_BASE, THUNK_BASE + 0x0010_4104);
            let mut untrain = [0x66, 0x90, 0x0f, 0xae, 0xe8, 0, 0, 0, 0, 0];
            untrain[5..].copy_from_slice(&jmp(0xe9, u + 5, s + 7));
            let mut safe = [
                0x48, 0x8d, 0x64, 0x24, 0x08, 0xc3, 0xcc, 0, 0, 0, 0, 0, 0x0f, 0x0b,
            ];
            safe[7..12].copy_from_slice(&jmp(0xe8, s + 7, s));
            code_page(u, 0, &untrain).ok_or("no room for the untraining page")?;
            code_page(s & !(PAGE_SIZE - 1), (s % PAGE_SIZE) as usize, &safe)
                .ok_or("no room for the safe-RET page")?;
            (u, s + 7)
        }
    };
    // SAFETY: only the boot CPU runs (the caller's contract); it executes
    // the thunk's first byte, a `ret`, never the four `int3`s after it.
    unsafe { patch(thunk, target) }?;
    // SAFETY: as above; the probe's `ret` is followed by four `int3`s of
    // padding (`stack_probe_ret` checked them) that nothing executes.
    unsafe { patch(probe_ret, thunk) }?;
    // SAFETY: as above; the entry code calls the stub only once UNTRAIN is
    // set, below.
    unsafe { patch(untrain_stub, untrain) }?;
    UNTRAIN.store(1, Relaxed);
    Ok(())
}

/// Points `__x86_indirect_thunk_r11`, through which every indirect call and
/// jump the compiler emits goes (`-Zretpoline-external-thunk`), at a
/// retpoline: Spectre v2 in the kernel on AMD CPUs without automatic IBRS
/// (ADR-0004's 2026-11-27 amendment). Same contract as [`install`].
pub(crate) fn install_retpoline() -> Result<(), &'static str> {
    let [thunk, retpoline] = retpoline_labels();
    // The thunk starts `jmp r11` (41 ff e3), then two `int3`s.
    if code::<5>(thunk) != [0x41, 0xff, 0xe3, 0xcc, 0xcc] {
        return Err("the indirect-branch thunk is not as built");
    }
    // An indirect call of frame's own reaches it as a `call` or `jmp rel32`.
    #[inline(never)]
    fn probe() -> u64 {
        let f: fn() -> u64 = || 7;
        core::hint::black_box(f)()
    }
    let start = probe as *const () as usize as u64;
    let direct = |at| {
        [0xe8, 0xe9]
            .iter()
            .any(|&op| code::<5>(at) == jmp(op, at, thunk))
    };
    if !(start..start + 64).any(direct) {
        return Err("the kernel was built without retpolines");
    }
    // SAFETY: only the boot CPU runs; until the last store it may execute
    // the thunk's first three bytes, which `patch` leaves until then.
    unsafe { patch(thunk, retpoline) }
}

fn retpoline_labels() -> [u64; 2] {
    let (t, r): (u64, u64);
    // SAFETY: computes two addresses RIP-relatively; no memory access.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + __x86_indirect_thunk_r11]",
            "lea {r}, [rip + ichor_retpoline_r11]",
            t = out(reg) t, r = out(reg) r,
            options(nomem, nostack, preserves_flags)
        )
    };
    [t, r]
}
