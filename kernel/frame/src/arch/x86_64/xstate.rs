//! A user thread's extended register state: x87, SSE, AVX, AVX-512, PKRU
//! and AMX (ADR-0008, ADR-0022, ADR-0023).
//!
//! With XSAVE, every CPU runs with the same XCR0, chosen once by the first
//! CPU to initialize. Each thread's state lives in a 64-byte-aligned heap
//! area in the standard (non-compacted) XSAVE format, the format Linux
//! signal frames carry. Without XSAVE, the same area holds an FXSAVE image
//! and FXSAVE/FXRSTOR are used.
//!
//! With AMX, an area has room for tile data or not. Without room it ends
//! where the other components do, is saved and restored with an RFBM that
//! leaves tile data out, and its thread runs with tile data armed in
//! IA32_XFD, so a tile instruction faults (#NM) instead of reaching the
//! registers; the kernel then gives it room (`enable_tiles`), with XFD
//! clear. IA32_XFD changes only in `restore`, after the previous state on
//! that CPU was saved under its own.
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

/// Most bytes of a thread's area without tile data. CPUID-reported sizes
/// above this make frame drop AVX-512; the allowed components fit in about
/// 2.8 KiB.
const MAX_AREA: usize = 4096;
/// Most bytes of an area with tile data (8 KiB more); above this, frame
/// drops AMX.
const MAX_TILE_AREA: usize = 16384;
/// The legacy (FXSAVE) region.
pub(crate) const LEGACY: usize = 512;
const HEADER: usize = 512;
const X87_SSE: u64 = 0b11;
const AVX: u64 = 1 << 2;
const AVX512: u64 = 0b111 << 5;
/// Protection keys' rights register (ADR-0022): enabled with CR4.PKE.
pub(crate) const PKRU: u64 = 1 << 9;
/// PKRU's reset value, Linux's `init_pkru_value`: every key but 0 denies
/// access.
const INIT_PKRU: u32 = 0x5555_5554;
/// AMX (ADR-0023): the tile configuration (64 bytes) and the tiles' data
/// (8 KiB), which XFD keeps from a thread until its first tile instruction
/// and the process's permission (`ARCH_REQ_XCOMP_PERM`) give it room.
const XTILECFG: u64 = 1 << 17;
pub(crate) const XTILEDATA: u64 = 1 << 18;
const AMX: u64 = XTILECFG | XTILEDATA;
/// Components frame may enable (ADR-0008 §1, ADR-0022, ADR-0023).
const ALLOWED: u64 = X87_SSE | AVX | AVX512 | PKRU | AMX;
const MXCSR_DEFAULT_MASK: u32 = 0xffbf;
const MSR_XFD: u32 = 0x1c4;
const MSR_XFD_ERR: u32 = 0x1c5;

/// XCR0 every CPU uses; 0 means no XSAVE (FXSAVE only); `u64::MAX` means
/// not decided yet.
static XCR0: AtomicU64 = AtomicU64::new(u64::MAX);
/// Bytes of an area without tile data, and with it (0 without AMX).
static SIZE: AtomicUsize = AtomicUsize::new(LEGACY);
static TILE_SIZE: AtomicUsize = AtomicUsize::new(0);
static XSAVEOPT: AtomicBool = AtomicBool::new(false);
/// Where PKRU lives in the area, when it is enabled.
static PKRU_AT: AtomicUsize = AtomicUsize::new(0);
/// Where the tile configuration lives in the area, when AMX is enabled.
static TILECFG_AT: AtomicUsize = AtomicUsize::new(0);

/// Whether XRSTOR would take this 64-byte tile configuration, as LDTILECFG
/// checks one: all zeros (palette 0, tiles off), or palette 1 with its
/// reserved bytes zero, at most eight tiles of at most 16 rows of 64 bytes,
/// each with both rows and bytes or neither, and a start row below 16.
/// Stricter than the CPU where unsure: what fails is reset, not loaded.
fn tilecfg_valid(c: &[u8]) -> bool {
    match c[0] {
        0 => c.iter().all(|&b| b == 0),
        1 => {
            let reserved = c[2..16].iter().chain(&c[32..48]).chain(&c[56..64]);
            let tiles_ok = (0..8).all(|t| {
                let colsb = u16::from_le_bytes([c[16 + 2 * t], c[17 + 2 * t]]);
                let rows = c[48 + t];
                colsb <= 64 && rows <= 16 && (colsb == 0) == (rows == 0)
            });
            c[1] < 16 && reserved.into_iter().all(|&b| b == 0) && tiles_ok
        }
        _ => false,
    }
}

fn supported() -> u64 {
    if cpuid(0, 0)[0] < 0xd || cpuid(1, 0)[2] & (1 << 26) == 0 {
        return 0;
    }
    let [eax, _, _, edx] = cpuid(0xd, 0);
    let mut mask = u64::from(eax) | (u64::from(edx) << 32);
    // PKRU only with protection keys (CPUID.7.0:ECX.PKU), which CR4.PKE
    // then turns on: the register exists exactly when it is saved.
    if cpuid(7, 0)[2] & (1 << 3) == 0 {
        mask &= !PKRU;
    }
    // AMX only with XFD for its data (CPUID.(0xD,1):EAX[4] and
    // CPUID.(0xD,18):ECX[2]), as Linux: without it every thread would carry
    // 8 KiB of tiles.
    let tiles = cpuid(7, 0)[3] & (1 << 24) != 0
        && cpuid(0xd, 1)[0] & (1 << 4) != 0
        && cpuid(0xd, 18)[2] & (1 << 2) != 0;
    if !tiles {
        mask &= !AMX;
    }
    mask
}

/// A valid XCR0 from `mask`: x87 and SSE always, AVX only with SSE,
/// AVX-512 only whole and with AVX, AMX's two components together.
fn valid(mut mask: u64) -> u64 {
    if mask & X87_SSE != X87_SSE {
        return 0;
    }
    if mask & AVX == 0 || mask & AVX512 != AVX512 {
        mask &= !AVX512;
    }
    if mask & AMX != AMX {
        mask &= !AMX;
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
    let full = cpuid(0xd, 0)[1] as usize;
    // Without tile data: up to the end of every other component.
    let mut size = LEGACY + 64;
    for c in 2..64 {
        if mask & (1 << c) != 0 && 1 << c != XTILEDATA {
            let [len, off, _, _] = cpuid(0xd, c);
            size = size.max(off as usize + len as usize);
        }
    }
    let smaller = if size > MAX_AREA && mask & AVX512 != 0 {
        // Too big for the per-thread area: run without AVX-512 everywhere.
        mask & !AVX512
    } else if mask & AMX != 0 && (full > MAX_TILE_AREA || size > MAX_AREA) {
        mask & !AMX
    } else {
        mask
    };
    if smaller != mask {
        XCR0.store(smaller, Ordering::Release);
        return enable(smaller);
    }
    SIZE.store(size.min(MAX_AREA), Ordering::Release);
    XSAVEOPT.store(cpuid(0xd, 1)[0] & 1 != 0, Ordering::Release);
    if mask & PKRU != 0 {
        PKRU_AT.store(cpuid(0xd, 9)[1] as usize, Ordering::Release);
    }
    if mask & XTILEDATA != 0 {
        TILE_SIZE.store(full, Ordering::Release);
        TILECFG_AT.store(cpuid(0xd, 17)[1] as usize, Ordering::Release);
        // SAFETY: IA32_XFD exists (`supported` checked CPUID for it); arming
        // tile data only makes tile instructions fault (#NM) until a
        // thread's state has room for it. Every CPU starts armed, as
        // `XFD_NOW` says.
        unsafe { super::regs::wrmsr(MSR_XFD, XTILEDATA) };
    }
}

/// The XCR0 in use (0: no XSAVE, FXSAVE only).
pub(crate) fn features() -> u64 {
    match XCR0.load(Ordering::Acquire) {
        u64::MAX => 0,
        m => m,
    }
}

/// PKRU's offset in the area, if it is enabled.
fn pkru_at() -> Option<usize> {
    (features() & PKRU != 0).then(|| PKRU_AT.load(Ordering::Acquire))
}

/// Bytes of a thread's state: the XSAVE area size, or 512 for FXSAVE.
pub(crate) fn size() -> usize {
    if features() == 0 {
        LEGACY
    } else {
        SIZE.load(Ordering::Acquire)
    }
}

/// Bytes of an area with tile data, 0 without AMX.
pub(crate) fn tile_size() -> usize {
    TILE_SIZE.load(Ordering::Acquire)
}

/// A 64-byte piece of an area (the alignment XSAVE needs).
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct Block([u8; 64]);

/// A thread's area, and where its state is live.
struct Shared {
    /// At least the area's bytes ([`Shared::len`]), in the standard format.
    area: alloc::boxed::Box<[UnsafeCell<Block>]>,
    /// With room for tile data, which XFD then lets the thread use.
    tiles: bool,
    /// Bytes that hold the state, and the components the save and restore
    /// instructions cover: both decided with the area.
    len: usize,
    rfbm: u64,
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
    /// A zeroed area, with room for tile data or without.
    fn zeroed(tiles: bool) -> Arc<Self> {
        let len = if tiles { tile_size() } else { size() };
        let rfbm = if tiles {
            features()
        } else {
            features() & !XTILEDATA
        };
        let area = (0..len.div_ceil(64))
            .map(|_| UnsafeCell::new(Block([0; 64])))
            .collect();
        Arc::new(Shared {
            area,
            tiles,
            len,
            rfbm,
            stamp: AtomicU64::new(0),
            live: AtomicU32::new(0),
        })
    }

    /// Bytes of the area that hold the state (what a signal frame carries).
    fn len(&self) -> usize {
        self.len
    }

    /// The components saved and restored: XCR0's, tile data only with room.
    /// Fixed with the area's size, so a save never reaches past it.
    fn rfbm(&self) -> u64 {
        self.rfbm
    }

    /// The IA32_XFD the thread runs with: tile data armed until it has room.
    fn xfd(&self) -> u64 {
        features() & XTILEDATA & !self.rfbm()
    }

    /// The area's address, for the save and restore instructions (writes
    /// through it are what `UnsafeCell` allows).
    fn ptr(&self) -> *mut u8 {
        self.area.as_ptr().cast::<u8>().cast_mut()
    }
}

crate::cpu_local! {
    /// The IA32_XFD this CPU runs with (`enable` arms it).
    static XFD_NOW: AtomicU64 = AtomicU64::new(XTILEDATA);
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
    let p = s.ptr();
    let (lo, hi) = (s.rfbm() as u32, (s.rfbm() >> 32) as u32);
    if features() == 0 {
        // SAFETY: a 16-byte-aligned area of at least 512 bytes that only this
        // CPU reaches while the state is live here (invariant 2); the
        // registers hold that state (the kernel never uses the FPU).
        unsafe { asm!("fxsave64 [{}]", in(reg) p, options(nostack, preserves_flags)) };
    } else if XSAVEOPT.load(Ordering::Relaxed) {
        // SAFETY: as above, 64-byte aligned and at least as long as the
        // components of `rfbm` reach (tile data only where there is room).
        // XSAVEOPT's tracking is sound because software never writes the
        // area between its XRSTOR and this save (ADR-0008 §2).
        unsafe {
            asm!("xsaveopt64 [{}]", in(reg) p, in("eax") lo, in("edx") hi, options(nostack, preserves_flags))
        };
    } else {
        // SAFETY: as above.
        unsafe {
            asm!("xsave64 [{}]", in(reg) p, in("eax") lo, in("edx") hi, options(nostack, preserves_flags))
        };
    }
    s.live.store(0, Ordering::Release);
}

/// Saves the state live on this CPU before the task running it switches
/// out (invariant 4).
pub(crate) fn switch_out() {
    flush(&IrqGuard::new());
}

/// After a #NM from ring 3: the components XFD stopped (IA32_XFD_ERR),
/// cleared for the next one. 0 without AMX.
pub(crate) fn take_xfd_err(_guard: &IrqGuard) -> u64 {
    if features() & XTILEDATA == 0 {
        return 0;
    }
    // SAFETY: IA32_XFD_ERR exists (AMX is enabled only with XFD); reading it
    // has no effect. The guard keeps this on the CPU that took the #NM.
    let err = unsafe { super::regs::rdmsr(MSR_XFD_ERR) };
    // SAFETY: as above; zero is its reset value, which the next #NM needs.
    unsafe { super::regs::wrmsr(MSR_XFD_ERR, 0) };
    err
}

/// One thread's extended state (see the module docs for its invariants).
pub(crate) struct ExtState {
    s: Arc<Shared>,
}

impl Default for ExtState {
    /// The reset state, without room for tile data.
    fn default() -> Self {
        ExtState::reset_state(false)
    }
}

impl Clone for ExtState {
    /// A copy of the state as it is now (saved first if it is live), for a
    /// `fork` or a new thread: everything but tile data, which starts in its
    /// init state with no room, as on Linux (tiles are caller-saved).
    fn clone(&self) -> Self {
        let mut copy = ExtState {
            s: Shared::zeroed(false),
        };
        let from = self.area();
        let n = size();
        let to = copy.area_mut();
        to[..n].copy_from_slice(&from[..n]);
        if self.s.tiles && features() != 0 {
            let bv = header(to) & !XTILEDATA;
            to[HEADER..HEADER + 8].copy_from_slice(&bv.to_le_bytes());
        } else {
            // The very bytes the registers held, so a CPU that saved them
            // may skip the restore (ADR-0008's 2026-11-25 amendment).
            copy.s
                .stamp
                .store(self.s.stamp.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        copy
    }
}

/// An area's XSTATE_BV.
fn header(a: &[u8]) -> u64 {
    u64::from_le_bytes(a[HEADER..HEADER + 8].try_into().unwrap_or([0; 8]))
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

    /// The reset state: x87 and SSE with all exceptions masked, PKRU at
    /// Linux's default, everything else (tiles too) in its init state;
    /// with room for tile data or without.
    fn reset_state(tiles: bool) -> Self {
        let mut st = ExtState {
            s: Shared::zeroed(tiles),
        };
        let a = st.area_mut();
        a[0..2].copy_from_slice(&0x037fu16.to_le_bytes()); // FCW
        a[24..28].copy_from_slice(&0x1f80u32.to_le_bytes()); // MXCSR
        if let Some(at) = pkru_at() {
            a[at..at + 4].copy_from_slice(&INIT_PKRU.to_le_bytes());
            a[HEADER..HEADER + 8].copy_from_slice(&PKRU.to_le_bytes());
        }
        st
    }

    /// Back to the reset state (a signal handler's start, as on Linux),
    /// keeping any room for tile data.
    pub(crate) fn reset(&mut self) {
        *self = ExtState::reset_state(self.s.tiles);
    }

    /// The whole area, saved first if the state is live here.
    fn area(&self) -> &[u8] {
        self.settle(true);
        // SAFETY: `Block` is 64 plain bytes (`repr(C)`, no padding), so the
        // area is `64 * len` initialized bytes, which nothing writes while
        // this borrow lasts: the state is live nowhere, and only `restore`
        // and `area_mut`, which need `&mut self`, could change that
        // (invariant 3).
        unsafe { core::slice::from_raw_parts(self.s.ptr(), self.s.area.len() * 64) }
    }

    /// The whole area, for software to write: saved first if live here, so
    /// that no later save overwrites what is written, and unstamped.
    fn area_mut(&mut self) -> &mut [u8] {
        self.settle(true);
        self.s.stamp.store(0, Ordering::Relaxed);
        // SAFETY: as in `area`, and no other reference to the area exists:
        // `&mut self` is the only way to it while no CPU's `OWNER` holds it
        // (invariant 1), and a clone has an area of its own.
        unsafe { core::slice::from_raw_parts_mut(self.s.ptr(), self.s.area.len() * 64) }
    }

    /// The state as the signal frame carries it: [`ExtState::len`] bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.area()[..self.s.len()]
    }

    /// Bytes of the state (more once tile data has room).
    pub(crate) fn len(&self) -> usize {
        self.s.len()
    }

    /// The components the state holds (XCR0's, but tile data until it has
    /// room).
    pub(crate) fn components(&self) -> u64 {
        self.s.rfbm()
    }

    /// Whether the state has room for tile data.
    pub(crate) fn tiles(&self) -> bool {
        self.s.tiles
    }

    /// Gives the state room for tile data, in its init state, and so the
    /// thread its use (XFD disarmed for it): a tile instruction's first
    /// #NM. Nothing without AMX, or with room already.
    pub(crate) fn enable_tiles(&mut self) {
        if self.s.tiles || tile_size() == 0 {
            return;
        }
        let mut big = ExtState {
            s: Shared::zeroed(true),
        };
        let n = size();
        let to = big.area_mut();
        to[..n].copy_from_slice(&self.area()[..n]);
        let bv = header(to) & !XTILEDATA;
        to[HEADER..HEADER + 8].copy_from_slice(&bv.to_le_bytes());
        *self = big;
    }

    /// The thread's PKRU (0 without protection keys).
    pub(crate) fn pkru(&self) -> u32 {
        let Some(at) = pkru_at() else {
            return 0;
        };
        let a = self.area();
        if header(a) & PKRU == 0 {
            return 0; // in its init state
        }
        u32::from_le_bytes([a[at], a[at + 1], a[at + 2], a[at + 3]])
    }

    /// Sets the thread's PKRU (nothing without protection keys).
    pub(crate) fn set_pkru(&mut self, pkru: u32) {
        let Some(at) = pkru_at() else {
            return;
        };
        let a = self.area_mut();
        a[at..at + 4].copy_from_slice(&pkru.to_le_bytes());
        a[at + 4..at + 8].fill(0);
        let bv = header(a) | PKRU;
        a[HEADER..HEADER + 8].copy_from_slice(&bv.to_le_bytes());
    }

    /// Replaces the state from user-supplied bytes: an area without tile
    /// data ([`size`] bytes) or with it (as long as this state's), or just
    /// the 512-byte legacy region; what is not given returns to its init
    /// state. Anything the restore instruction would fault on is cleared.
    pub(crate) fn set_from(&mut self, src: &[u8]) {
        let own = self.s.len();
        let rfbm = self.s.rfbm();
        let a = self.area_mut();
        let mask = match u32::from_le_bytes([a[28], a[29], a[30], a[31]]) {
            0 => MXCSR_DEFAULT_MASK,
            m => m,
        };
        let own_mask = [a[28], a[29], a[30], a[31]];
        let xcr0 = features();
        let full = xcr0 != 0 && src.len() >= size();
        let n = if full {
            src.len().min(own)
        } else {
            LEGACY.min(src.len())
        };
        a[..n].copy_from_slice(&src[..n]);
        let mxcsr = u32::from_le_bytes([a[24], a[25], a[26], a[27]]) & mask;
        a[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        a[28..32].copy_from_slice(&own_mask); // MXCSR_MASK is read-only
        if xcr0 != 0 {
            let bv = if full {
                // Tile data only if it was given whole.
                let given = if n < own { !XTILEDATA } else { u64::MAX };
                let mut bv = header(a) & rfbm & given;
                // A tile configuration XRSTOR would fault on (#GP in the
                // kernel) is reset instead; the program asked for nothing
                // LDTILECFG would have given it.
                let at = TILECFG_AT.load(Ordering::Acquire);
                if bv & XTILECFG != 0 && !tilecfg_valid(&a[at..at + 64]) {
                    bv &= !XTILECFG;
                }
                bv
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
    /// Inlined: on the system call path the state is live here already.
    #[inline]
    pub(crate) fn restore(&mut self, guard: &IrqGuard) {
        if self.s.live.load(Ordering::Acquire) != this_cpu(guard) {
            self.load(guard);
        }
    }

    #[inline(never)]
    fn load(&mut self, guard: &IrqGuard) {
        let here = this_cpu(guard);
        if self.s.live.load(Ordering::Acquire) != 0 {
            crate::boot::fatal("extended state live on another CPU");
        }
        // Another state live here (another context of this task) first,
        // with its own XFD.
        flush(guard);
        let xfd = self.s.xfd();
        let now = XFD_NOW.get(guard);
        if features() & XTILEDATA != 0 && now.load(Ordering::Relaxed) != xfd {
            // SAFETY: IA32_XFD exists (AMX is enabled only with XFD); it only
            // decides which tile instructions fault, and this thread's area
            // has room for what it allows.
            unsafe { super::regs::wrmsr(MSR_XFD, xfd) };
            now.store(xfd, Ordering::Relaxed);
        }
        let loaded = LOADED.get(guard);
        let stamp = self.s.stamp.load(Ordering::Relaxed);
        if stamp == 0 || loaded.load(Ordering::Relaxed) != stamp {
            let p = self.s.ptr().cast_const();
            let (lo, hi) = (self.s.rfbm() as u32, (self.s.rfbm() >> 32) as u32);
            if features() != 0 {
                // SAFETY: the area is 64-byte aligned, as long as the
                // components of `rfbm` reach, in standard format with a
                // header that passes every XRSTOR check (module invariant),
                // XCR0 is loaded, and nothing else reaches the area (live
                // nowhere, `&mut self`). Tile data, armed in XFD for a
                // thread without room, is outside `rfbm` then.
                unsafe {
                    asm!("xrstor64 [{}]", in(reg) p, in("eax") lo, in("edx") hi, options(nostack, readonly, preserves_flags))
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
