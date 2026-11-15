//! A user thread's extended register state: x87, SSE, AVX, AVX-512
//! (ADR-0008).
//!
//! With XSAVE, every CPU runs with the same XCR0, chosen once by the first
//! CPU to initialize. Each thread's state lives in a boxed, 64-byte-aligned
//! area in the standard (non-compacted) XSAVE format, the format Linux
//! signal frames carry. It is restored eagerly before ring 3 and saved right
//! after the trap. Without XSAVE, the same area holds an FXSAVE image and
//! FXSAVE/FXRSTOR are used.
//!
//! An area only ever holds the init state, a hardware save, or user data
//! that [`ExtState::set_from`] sanitized against every #GP condition of the
//! restore instruction, so restoring it cannot fault.

use alloc::boxed::Box;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::regs::cpuid;

/// Bytes reserved per thread. CPUID-reported sizes above this make frame
/// drop AVX-512; the allowed components fit in about 2.7 KiB.
const MAX_AREA: usize = 4096;
/// The legacy (FXSAVE) region.
pub(crate) const LEGACY: usize = 512;
const HEADER: usize = 512;
const X87_SSE: u64 = 0b11;
const AVX: u64 = 1 << 2;
const AVX512: u64 = 0b111 << 5;
/// Components frame may enable (ADR-0008 §1).
const ALLOWED: u64 = X87_SSE | AVX | AVX512;
const MXCSR_DEFAULT_MASK: u32 = 0xffbf;

/// XCR0 every CPU uses; 0 means no XSAVE (FXSAVE only); `u64::MAX` means
/// not decided yet.
static XCR0: AtomicU64 = AtomicU64::new(u64::MAX);
static SIZE: AtomicUsize = AtomicUsize::new(LEGACY);
static XSAVEOPT: AtomicBool = AtomicBool::new(false);

fn supported() -> u64 {
    if cpuid(0, 0)[0] < 0xd || cpuid(1, 0)[2] & (1 << 26) == 0 {
        return 0;
    }
    let [eax, _, _, edx] = cpuid(0xd, 0);
    u64::from(eax) | (u64::from(edx) << 32)
}

/// A valid XCR0 from `mask`: x87 and SSE always, AVX only with SSE,
/// AVX-512 only whole and with AVX.
fn valid(mut mask: u64) -> u64 {
    if mask & X87_SSE != X87_SSE {
        return 0;
    }
    if mask & AVX == 0 || mask & AVX512 != AVX512 {
        mask &= !AVX512;
    }
    mask
}

/// The XCR0 this CPU must load (deciding it on the first call), or 0 for
/// the FXSAVE path. Stops the machine if this CPU cannot run the XCR0 the
/// first CPU chose.
pub(crate) fn decide() -> u64 {
    let here = supported();
    let chosen = XCR0.load(Ordering::Acquire);
    if chosen != u64::MAX {
        if here & chosen != chosen {
            crate::boot::fatal("CPU lacks the extended state the boot CPU enabled");
        }
        return chosen;
    }
    let mask = valid(here & ALLOWED);
    XCR0.store(mask, Ordering::Release);
    mask
}

/// Loads `mask` into XCR0 on this CPU and, on the first CPU, records the
/// area size. CR4.OSXSAVE must already be set if `mask` is nonzero.
pub(crate) fn enable(mask: u64) {
    if mask == 0 {
        return;
    }
    // SAFETY: CR4.OSXSAVE is set (the caller's contract), and `mask` is a
    // subset of what CPUID.(0xD,0) reports with x87/SSE set and AVX-512
    // whole and with AVX, so XSETBV accepts it.
    unsafe {
        asm!("xsetbv", in("ecx") 0u32, in("eax") mask as u32, in("edx") (mask >> 32) as u32, options(nomem, nostack, preserves_flags))
    };
    let size = cpuid(0xd, 0)[1] as usize;
    if size > MAX_AREA && mask & AVX512 != 0 {
        // Too big for the per-thread area: run without AVX-512 everywhere.
        let smaller = mask & !AVX512;
        XCR0.store(smaller, Ordering::Release);
        return enable(smaller);
    }
    SIZE.store(size.clamp(LEGACY + 64, MAX_AREA), Ordering::Release);
    XSAVEOPT.store(cpuid(0xd, 1)[0] & 1 != 0, Ordering::Release);
}

/// The XCR0 in use (0: no XSAVE, FXSAVE only).
pub(crate) fn features() -> u64 {
    match XCR0.load(Ordering::Acquire) {
        u64::MAX => 0,
        m => m,
    }
}

/// Bytes of a thread's state: the XSAVE area size, or 512 for FXSAVE.
pub(crate) fn size() -> usize {
    if features() == 0 {
        LEGACY
    } else {
        SIZE.load(Ordering::Acquire)
    }
}

#[repr(C, align(64))]
#[derive(Clone)]
struct Area([u8; MAX_AREA]);

/// One thread's extended state (see the module docs for its invariant).
#[derive(Clone)]
pub(crate) struct ExtState(Box<Area>);

impl Default for ExtState {
    /// The reset state: x87 and SSE with all exceptions masked, everything
    /// else in its init state (XSTATE_BV 0).
    fn default() -> Self {
        let mut a = Box::new(Area([0; MAX_AREA]));
        a.0[0..2].copy_from_slice(&0x037fu16.to_le_bytes()); // FCW
        a.0[24..28].copy_from_slice(&0x1f80u32.to_le_bytes()); // MXCSR
        ExtState(a)
    }
}

impl core::fmt::Debug for ExtState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ExtState")
    }
}

impl ExtState {
    /// The state as the signal frame carries it: [`size`] bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0.0[..size()]
    }

    /// Replaces the state from user-supplied bytes: a full area ([`size`]
    /// bytes) or just the 512-byte legacy region, in which case the
    /// extended components return to their init state. Anything the restore
    /// instruction would fault on is cleared.
    pub(crate) fn set_from(&mut self, src: &[u8]) {
        let a = &mut self.0.0;
        let mask = match u32::from_le_bytes([a[28], a[29], a[30], a[31]]) {
            0 => MXCSR_DEFAULT_MASK,
            m => m,
        };
        let own_mask = [a[28], a[29], a[30], a[31]];
        let xcr0 = features();
        let full = xcr0 != 0 && src.len() >= size();
        let n = if full { size() } else { LEGACY.min(src.len()) };
        a[..n].copy_from_slice(&src[..n]);
        let mxcsr = u32::from_le_bytes([a[24], a[25], a[26], a[27]]) & mask;
        a[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        a[28..32].copy_from_slice(&own_mask); // MXCSR_MASK is read-only
        if xcr0 != 0 {
            let bv = if full {
                u64::from_le_bytes(a[HEADER..HEADER + 8].try_into().unwrap_or([0; 8])) & xcr0
            } else {
                X87_SSE // the legacy region was given; the rest is init
            };
            a[HEADER..HEADER + 8].copy_from_slice(&bv.to_le_bytes());
            a[HEADER + 8..HEADER + 64].fill(0); // XCOMP_BV and reserved
        }
    }

    /// Loads this state into the registers.
    pub(crate) fn restore(&self) {
        let p = self.0.0.as_ptr();
        if features() != 0 {
            // SAFETY: the area is 64-byte aligned, MAX_AREA >= the XSAVE
            // size, in standard format with a header that passes every
            // XRSTOR check (module invariant), and XCR0 is loaded.
            unsafe {
                asm!("xrstor64 [{}]", in(reg) p, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack, readonly, preserves_flags))
            };
        } else {
            // SAFETY: a 16-byte-aligned FXSAVE image with a valid MXCSR
            // (module invariant).
            unsafe {
                asm!("fxrstor64 [{}]", in(reg) p, options(nostack, readonly, preserves_flags))
            };
        }
    }

    /// Stores the registers into this state.
    pub(crate) fn save(&mut self) {
        let p = self.0.0.as_mut_ptr();
        if features() == 0 {
            // SAFETY: a 16-byte-aligned 512-byte (or larger) area owned by
            // this thread; the kernel never uses the FPU, so the registers
            // hold this thread's state.
            unsafe { asm!("fxsave64 [{}]", in(reg) p, options(nostack, preserves_flags)) };
        } else if XSAVEOPT.load(Ordering::Relaxed) {
            // SAFETY: as above, 64-byte aligned and at least the XSAVE size.
            // XSAVEOPT's tracking is sound because software never writes
            // the area between its XRSTOR and this save (ADR-0008 §2).
            unsafe {
                asm!("xsaveopt64 [{}]", in(reg) p, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack, preserves_flags))
            };
        } else {
            // SAFETY: as above.
            unsafe {
                asm!("xsave64 [{}]", in(reg) p, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack, preserves_flags))
            };
        }
    }
}
