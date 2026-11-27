//! A user thread's extended register state: x87, SSE, AVX, AVX-512
//! (ADR-0008).
//!
//! With XSAVE, every CPU runs with the same XCR0, chosen once by the first
//! CPU to initialize. Each thread's state lives in a 64-byte-aligned heap
//! area in the standard (non-compacted) XSAVE format, the format Linux
//! signal frames carry. Without XSAVE, the same area holds an FXSAVE image
//! and FXSAVE/FXRSTOR are used.
//!
//! The state is restored before every entry to ring 3, unless the
//! registers hold it already, and saved only when it must be (ADR-0008's
//! 2026-11-26 amendment): when the task running it switches out, when
//! another state is loaded on its CPU, and when software reads, copies or
//! replaces it. Until then the registers are newer than the area: the
//! state is *live* on that CPU. This is sound because nothing but this
//! module touches the registers: the kernel is soft-float (no other crate
//! may hold `unsafe`, so none can reach them), and the firmware runs at
//! boot only.
//!
//! An area only ever holds the init state, a hardware save, or user data
//! that [`ExtState::set_from`] sanitized against every #GP condition of the
//! restore instruction, so restoring it cannot fault.
//!
//! # Invariants
//!
//! 1. A state is live on CPU `c` (its `live` is `c + 1`) exactly when CPU
//!    `c`'s [`OWNER`] holds it; both change together, on `c`, with
//!    interrupts off.
//! 2. While a state is live on `c`, CPU `c`'s registers hold it and only
//!    `c` touches its area, by saving into it ([`flush`]).
//! 3. Software reads or writes an area only while its state is not live,
//!    and only [`ExtState::restore`], which takes `&mut`, makes it live, so
//!    no reference into an area outlives that.
//! 4. A live state belongs to the task running on its CPU: a switch saves
//!    it first ([`switch_out`]), so a state never moves between CPUs
//!    unsaved.

use alloc::sync::Arc;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::regs::cpuid;
use crate::cpu::IrqGuard;
use crate::sync::SpinLock;

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

/// A thread's area, and where its state is live.
struct Shared {
    area: UnsafeCell<Area>,
    /// The save that wrote the area, unique to a CPU and a save (0: software
    /// wrote it). Only [`ExtState::restore`] loads the registers and only
    /// [`flush`] stamps, so a CPU whose [`LOADED`] equals the stamp holds
    /// exactly the area: it saved it and loaded nothing since. A copy keeps
    /// the stamp, as it keeps the bytes.
    stamp: AtomicU64,
    /// The CPU (index + 1) the state is live on; 0: none (invariant 1).
    live: AtomicU32,
}

// SAFETY: the area is reached only by the CPU its state is live on, to save
// into it (invariant 2), or, while it is live nowhere, through its one
// `ExtState` (invariant 3); everything else in it is atomic.
unsafe impl Sync for Shared {}

impl Shared {
    fn new(area: Area, stamp: u64) -> Arc<Self> {
        Arc::new(Shared {
            area: UnsafeCell::new(area),
            stamp: AtomicU64::new(stamp),
            live: AtomicU32::new(0),
        })
    }
}

crate::cpu_local! {
    /// The stamp of the state this CPU's registers hold (0: none, or a live
    /// state's, which the registers have moved on from).
    static LOADED: AtomicU64 = AtomicU64::new(0);
    /// Saves made on this CPU, numbering its stamps.
    static SAVES: AtomicU64 = AtomicU64::new(0);
    /// The state live on this CPU, if any (invariant 1).
    static OWNER: SpinLock<Option<Arc<Shared>>> = SpinLock::new(None);
}

/// This CPU as a `live` value.
fn this_cpu(guard: &IrqGuard) -> u32 {
    guard.cpu().index() as u32 + 1
}

/// Saves the state live on this CPU, if there is one, into its area; then it
/// is live nowhere.
fn flush(guard: &IrqGuard) {
    let Some(s) = OWNER.get(guard).lock().take() else {
        return;
    };
    let n = SAVES.get(guard).fetch_add(1, Ordering::Relaxed) + 1;
    let stamp = ((guard.cpu().index() as u64 + 1) << 48) | (n & ((1 << 48) - 1));
    s.stamp.store(stamp, Ordering::Relaxed);
    LOADED.get(guard).store(stamp, Ordering::Relaxed);
    let p = s.area.get().cast::<u8>();
    if features() == 0 {
        // SAFETY: a 16-byte-aligned area of at least 512 bytes that only this
        // CPU reaches while the state is live here (invariant 2); the
        // registers hold that state (the kernel never uses the FPU).
        unsafe { asm!("fxsave64 [{}]", in(reg) p, options(nostack, preserves_flags)) };
    } else if XSAVEOPT.load(Ordering::Relaxed) {
        // SAFETY: as above, 64-byte aligned and at least the XSAVE size.
        // XSAVEOPT's tracking is sound because software never writes the
        // area between its XRSTOR and this save (ADR-0008 §2).
        unsafe {
            asm!("xsaveopt64 [{}]", in(reg) p, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack, preserves_flags))
        };
    } else {
        // SAFETY: as above.
        unsafe {
            asm!("xsave64 [{}]", in(reg) p, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack, preserves_flags))
        };
    }
    s.live.store(0, Ordering::Release);
}

/// Saves the state live on this CPU before the task running it switches
/// out (invariant 4).
pub(crate) fn switch_out() {
    flush(&IrqGuard::new());
}

/// One thread's extended state (see the module docs for its invariants).
pub(crate) struct ExtState {
    s: Arc<Shared>,
}

impl Default for ExtState {
    /// The reset state: x87 and SSE with all exceptions masked, everything
    /// else in its init state (XSTATE_BV 0).
    fn default() -> Self {
        let mut a = Area([0; MAX_AREA]);
        a.0[0..2].copy_from_slice(&0x037fu16.to_le_bytes()); // FCW
        a.0[24..28].copy_from_slice(&0x1f80u32.to_le_bytes()); // MXCSR
        ExtState {
            s: Shared::new(a, 0),
        }
    }
}

impl Clone for ExtState {
    /// A copy of the state as it is now (saved first if it is live).
    fn clone(&self) -> Self {
        self.settle(true);
        // SAFETY: the state is live nowhere, and only `restore`, which needs
        // `&mut self`, could make it live (invariant 3).
        let area = unsafe { (*self.s.area.get()).clone() };
        ExtState {
            s: Shared::new(area, self.s.stamp.load(Ordering::Relaxed)),
        }
    }
}

impl Drop for ExtState {
    fn drop(&mut self) {
        let g = IrqGuard::new();
        if self.s.live.load(Ordering::Relaxed) == this_cpu(&g) {
            // Live here: no save, since nothing will read it.
            let owner = OWNER.get(&g).lock().take();
            self.s.live.store(0, Ordering::Relaxed);
            drop(owner);
        }
        // Live on another CPU (the context left the task running it): that
        // CPU saves into the area at its next switch, then lets it go.
    }
}

impl core::fmt::Debug for ExtState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ExtState")
    }
}

impl ExtState {
    /// Waits until the state is live on no other CPU, then, with
    /// `save_here`, saves it if it is live on this one, leaving it live
    /// nowhere. It is live on another CPU only if its context left the task
    /// running it before that task switched out, which saves it.
    pub(crate) fn settle(&self, save_here: bool) {
        loop {
            {
                let g = IrqGuard::new();
                let live = self.s.live.load(Ordering::Acquire);
                if live == 0 {
                    return;
                }
                if live == this_cpu(&g) {
                    if save_here {
                        flush(&g);
                    }
                    return;
                }
            }
            core::hint::spin_loop();
        }
    }

    /// The state as the signal frame carries it: [`size`] bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.settle(true);
        // SAFETY: live nowhere now, and only `restore`, which needs `&mut
        // self`, could make it live while this borrow lasts (invariant 3).
        let a = unsafe { &*self.s.area.get() };
        &a.0[..size()]
    }

    /// Replaces the state from user-supplied bytes: a full area ([`size`]
    /// bytes) or just the 512-byte legacy region, in which case the
    /// extended components return to their init state. Anything the restore
    /// instruction would fault on is cleared.
    pub(crate) fn set_from(&mut self, src: &[u8]) {
        // Saved first, so that no later save overwrites what is written here.
        self.settle(true);
        self.s.stamp.store(0, Ordering::Relaxed);
        // SAFETY: live nowhere, and `&mut self` is the only way to the area
        // (no CPU's OWNER holds it: invariant 1).
        let a = unsafe { &mut (*self.s.area.get()).0 };
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

    /// Makes this state the registers' and live on this CPU, for ring 3.
    /// Loads it unless they hold it already: it is live here still, or this
    /// CPU saved it last and has loaded nothing since (the kernel is
    /// soft-float). The skipped XRSTOR leaves XSAVEOPT's tracking on the
    /// area's earlier one, which software has not written since. The
    /// caller settles the state first, before taking `guard`, so it is live
    /// nowhere else (invariant 4 keeps it so through a migration).
    pub(crate) fn restore(&mut self, guard: &IrqGuard) {
        let here = this_cpu(guard);
        match self.s.live.load(Ordering::Acquire) {
            l if l == here => return,
            0 => {}
            _ => crate::boot::fatal("extended state live on another CPU"),
        }
        // Another state live here (another context of this task) first.
        flush(guard);
        let loaded = LOADED.get(guard);
        let stamp = self.s.stamp.load(Ordering::Relaxed);
        if stamp == 0 || loaded.load(Ordering::Relaxed) != stamp {
            let p = self.s.area.get().cast::<u8>().cast_const();
            if features() != 0 {
                // SAFETY: the area is 64-byte aligned, MAX_AREA >= the XSAVE
                // size, in standard format with a header that passes every
                // XRSTOR check (module invariant), XCR0 is loaded, and
                // nothing else reaches the area (live nowhere, `&mut self`).
                unsafe {
                    asm!("xrstor64 [{}]", in(reg) p, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack, readonly, preserves_flags))
                };
            } else {
                // SAFETY: a 16-byte-aligned FXSAVE image with a valid MXCSR
                // (module invariant), reached by nothing else.
                unsafe {
                    asm!("fxrstor64 [{}]", in(reg) p, options(nostack, readonly, preserves_flags))
                };
            }
        }
        // From here the registers move on from every area.
        loaded.store(0, Ordering::Relaxed);
        *OWNER.get(guard).lock() = Some(self.s.clone());
        self.s.live.store(here, Ordering::Release);
    }
}
