//! CPUs and per-CPU data.
//!
//! Each CPU has a small block reached through its GS base, holding its index.
//! [`CpuLocal<T>`] gives every CPU its own `T`. The current CPU's slot is
//! borrowed for the lifetime of an [`IrqGuard`]: with interrupts masked
//! (and, from milestone 2, preemption off) nothing else can run on this CPU
//! while the borrow lives, so `T` need not be `Sync`. Another CPU's slot can
//! be read only when `T: Sync`.

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch;

/// The most CPUs Ichor supports.
pub const MAX_CPUS: usize = 1024;

/// Index of a CPU: 0 is the boot CPU, the rest are numbered in the order
/// they came online.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CpuId(u32);

impl CpuId {
    /// The boot CPU.
    pub const BOOT: CpuId = CpuId(0);

    pub(crate) const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The index as a `usize`, always `< MAX_CPUS`.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for CpuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cpu{}", self.0)
    }
}

impl fmt::Display for CpuId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

static ONLINE: AtomicU32 = AtomicU32::new(0);

/// Number of CPUs that have completed bring-up.
/// The XSAVE components user threads may use (XCR0), or 0 if the CPU has
/// no XSAVE and only x87/SSE state exists (ADR-0008).
pub fn xstate_features() -> u64 {
    crate::arch::xstate::features()
}

/// Bytes of a thread's extended state as a signal frame carries it, without
/// AMX tile data.
pub fn xstate_size() -> usize {
    crate::arch::xstate::size()
}

/// Bytes of a thread's extended state with AMX tile data (0 without AMX,
/// ADR-0023).
pub fn xstate_tile_size() -> usize {
    crate::arch::xstate::tile_size()
}

/// The XSAVE component that holds AMX tile data, which threads use only
/// with room for it (ADR-0023).
pub const XSTATE_TILE_DATA: u64 = crate::arch::xstate::XTILEDATA;

/// Whether user pages have protection keys: CR4.PKE, with PKRU saved per
/// thread (ADR-0022).
pub fn protection_keys() -> bool {
    crate::arch::xstate::features() & crate::arch::xstate::PKRU != 0
}

/// Where the standard-format XSAVE area keeps `component` (an XCR0 bit
/// number, 2 or above): its offset and size in bytes, as CPUID reports them.
pub fn xstate_component(component: u32) -> (usize, usize) {
    let [size, offset, _, _] = crate::arch::regs::cpuid(0xd, component);
    (offset as usize, size as usize)
}

pub fn online_count() -> usize {
    ONLINE.load(Ordering::Acquire) as usize
}

/// The CPUs that are online: `0..online_count()`.
pub fn online() -> impl Iterator<Item = CpuId> {
    (0..online_count() as u32).map(CpuId)
}

/// The per-CPU block GS points at. Field offsets are used by assembly
/// (`arch::x86_64`), so the layout is fixed. A block fills its own page,
/// which the entry area aliases (GS holds the alias): the entry code reads
/// it before it switches to the kernel root (ADR-0004 §2), so nothing in
/// it may be secret.
#[repr(C, align(4096))]
#[derive(Debug)]
pub(crate) struct CpuBlock {
    /// 0: the block's own address.
    pub(crate) self_addr: AtomicU64,
    /// 8: the CPU index.
    pub(crate) index: AtomicU64,
    /// 16: kernel stack pointer saved by user-mode entry.
    pub(crate) kernel_rsp: AtomicU64,
    /// 24: user stack pointer saved by the syscall entry.
    pub(crate) user_rsp: AtomicU64,
    /// 32: the `UserContext` being executed.
    pub(crate) user_ctx: AtomicU64,
    /// 40: scratch for the syscall entry.
    pub(crate) scratch: AtomicU64,
    /// 48: number of live `IrqGuard`s and spinlock guards ("atomic depth").
    pub(crate) atomic_depth: AtomicU64,
    /// 56: why the last user run trapped back (0 none, 1 syscall, 2 exception).
    pub(crate) event_kind: AtomicU64,
    /// 64: exception vector and error code, packed (vector in low byte).
    pub(crate) event_info: AtomicU64,
    /// 72: faulting address (CR2) for a user exception.
    pub(crate) event_cr2: AtomicU64,
    /// 80: top of this CPU's entry stack (TSS RSP0, in the entry area),
    /// where ring-3 traps land and `iretq` frames to ring 3 are built.
    pub(crate) entry_rsp: AtomicU64,
    /// 88: the security domain (cell) of the task running here, set on
    /// every switch (ADR-0004 §2).
    pub(crate) task_domain: AtomicU64,
    /// 96: the domain whose user code last ran on this CPU (IBPB when the
    /// next one differs).
    pub(crate) user_domain: AtomicU64,
    /// 104: CR3 for the kernel side of the current address space (its full
    /// root), loaded on entry from ring 3 under page-table isolation.
    pub(crate) kernel_cr3: AtomicU64,
    /// 112: CR3 of its shadow (user) root, loaded right before ring 3; bit
    /// 63 (keep the PCID's TLB entries) is clear while a flush is owed.
    pub(crate) user_cr3: AtomicU64,
    /// 120: bit 63 if CR3 loads may keep a PCID's entries (PCID on), else 0.
    pub(crate) cr3_noflush: AtomicU64,
    /// 128, 136: unused (the entry code's alias and the trap dispatcher's
    /// address, before the entry code ran at its image address).
    _unused: [AtomicU64; 2],
    /// 144: nonzero when page-table isolation is on.
    pub(crate) pti: AtomicU64,
    /// 152: nonzero for VERW before `iretq` to ring 3.
    pub(crate) verw: AtomicU64,
    /// 160: VERW's operand, a writable data selector.
    pub(crate) verw_sel: AtomicU64,
    /// 168: what `IA32_SPEC_CTRL` holds in the kernel, if that is written on
    /// every entry from ring 3 (ring 3 has it without IBRS); else 0.
    pub(crate) spec_ctrl: AtomicU64,
    /// 176: nonzero to clear the branch history on every entry from ring 3
    /// (BHI without `BHI_DIS_S`).
    pub(crate) bhb_clear: AtomicU64,
    /// 184: nonzero for IBPB on every entry from ring 3 (AMD Retbleed and
    /// SRSO, without safe-RET return thunks).
    pub(crate) ibpb_entry: AtomicU64,
    /// 192: nonzero to untrain on every entry from ring 3 (AMD SRSO with
    /// safe-RET return thunks, `arch::rethunk`).
    pub(crate) untrain: AtomicU64,
}

impl CpuBlock {
    const fn new(index: u64) -> Self {
        Self {
            self_addr: AtomicU64::new(0),
            index: AtomicU64::new(index),
            kernel_rsp: AtomicU64::new(0),
            user_rsp: AtomicU64::new(0),
            user_ctx: AtomicU64::new(0),
            scratch: AtomicU64::new(0),
            atomic_depth: AtomicU64::new(0),
            event_kind: AtomicU64::new(0),
            event_info: AtomicU64::new(0),
            event_cr2: AtomicU64::new(0),
            entry_rsp: AtomicU64::new(0),
            task_domain: AtomicU64::new(0),
            user_domain: AtomicU64::new(0),
            kernel_cr3: AtomicU64::new(0),
            user_cr3: AtomicU64::new(0),
            cr3_noflush: AtomicU64::new(0),
            _unused: [AtomicU64::new(0), AtomicU64::new(0)],
            pti: AtomicU64::new(0),
            verw: AtomicU64::new(0),
            verw_sel: AtomicU64::new(0),
            spec_ctrl: AtomicU64::new(0),
            bhb_clear: AtomicU64::new(0),
            ibpb_entry: AtomicU64::new(0),
            untrain: AtomicU64::new(0),
        }
    }
}

static BOOT_CPU_BLOCK: CpuBlock = CpuBlock::new(0);
/// Set once the boot CPU's GS points at its block. Until then (early boot,
/// one CPU, no scheduler) the atomic depth is not tracked.
static BLOCKS_READY: AtomicBool = AtomicBool::new(false);

/// Points the boot CPU's GS at its (static) block.
pub(crate) fn init_boot_cpu_block() {
    let addr = core::ptr::addr_of!(BOOT_CPU_BLOCK) as u64;
    BOOT_CPU_BLOCK.self_addr.store(addr, Ordering::Relaxed);
    arch::set_cpu_block(addr);
    BLOCKS_READY.store(true, Ordering::Release);
}

/// AP blocks' addresses, indexed by CPU index (0, the boot CPU, unused).
static AP_BLOCKS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Allocates the block for AP `id` (before it starts). Blocks are leaked:
/// CPUs never go away.
pub(crate) fn register_ap_block(id: CpuId) {
    let block: &'static CpuBlock = Box::leak(Box::new(CpuBlock::new(u64::from(id.0))));
    let addr = core::ptr::addr_of!(*block) as u64;
    block.self_addr.store(addr, Ordering::Relaxed);
    if let Some(slot) = AP_BLOCKS.get(id.index()) {
        slot.store(addr, Ordering::Release);
    }
}

/// Points an AP's GS at the block registered for it.
pub(crate) fn init_ap_block(id: CpuId) {
    let addr = AP_BLOCKS
        .get(id.index())
        .map_or(0, |b| b.load(Ordering::Acquire));
    arch::set_cpu_block(addr);
}

/// This CPU's per-CPU block. Resolved from the CPU index, not from the raw
/// GS value, so a user thread cannot have forged it.
pub(crate) fn this_block() -> &'static CpuBlock {
    let index = current().index();
    if index == 0 {
        return &BOOT_CPU_BLOCK;
    }
    let addr = AP_BLOCKS
        .get(index)
        .map_or(0, |b| b.load(Ordering::Acquire));
    let ptr = core::ptr::with_exposed_provenance::<CpuBlock>(addr as usize);
    // SAFETY: AP blocks are leaked `&'static CpuBlock`s (see
    // `register_ap_block`); `addr` is the one registered for this CPU index,
    // or 0 before registration, in which case we fall back to the boot
    // block. All fields are atomics, so sharing is sound.
    if addr != 0 {
        // SAFETY: AP blocks are leaked `&'static CpuBlock`s; `addr` is the
        // one registered for this CPU index. All fields are atomics.
        unsafe { &*ptr }
    } else {
        &BOOT_CPU_BLOCK
    }
}

/// Counts the calling CPU as online (after all of its initialization).
pub(crate) fn mark_online() {
    ONLINE.fetch_add(1, Ordering::AcqRel);
}

/// Enters atomic mode (a guard that masks interrupts was created).
pub(crate) fn atomic_enter() {
    if BLOCKS_READY.load(Ordering::Relaxed) {
        arch::atomic_depth_inc();
    }
}

/// Leaves atomic mode (that guard was dropped).
pub(crate) fn atomic_leave() {
    if BLOCKS_READY.load(Ordering::Relaxed) {
        arch::atomic_depth_dec();
    }
}

/// How many interrupt-masking guards are live on this CPU.
pub(crate) fn atomic_depth() -> u64 {
    if BLOCKS_READY.load(Ordering::Relaxed) {
        arch::atomic_depth()
    } else {
        0
    }
}

/// The CPU this code is running on.
///
/// Without a guard the answer may be stale by the time it is used, because
/// the scheduler can migrate tasks; hold an [`IrqGuard`] when that matters.
pub fn current() -> CpuId {
    if !BLOCKS_READY.load(Ordering::Relaxed) {
        return CpuId::BOOT;
    }
    CpuId(arch::cpu_index())
}

/// Interrupts are masked on this CPU while the guard lives; restores the
/// previous state on drop. While any guard is live the CPU is in *atomic
/// mode*: the current task cannot be preempted, and sleeping, yielding or
/// re-enabling interrupts panics. Not `Send` or `Sync`: it describes this
/// CPU.
pub struct IrqGuard {
    was_enabled: bool,
    _not_send: PhantomData<*mut ()>,
}

impl IrqGuard {
    /// Masks interrupts on this CPU.
    pub fn new() -> Self {
        let was_enabled = arch::save_and_disable_interrupts();
        atomic_enter();
        Self {
            was_enabled,
            _not_send: PhantomData,
        }
    }

    /// The CPU this guard pins the caller to.
    pub fn cpu(&self) -> CpuId {
        current()
    }
}

impl Default for IrqGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        atomic_leave();
        arch::restore_interrupts(self.was_enabled);
    }
}

impl fmt::Debug for IrqGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IrqGuard").finish_non_exhaustive()
    }
}

/// Pads a value to its own cache line to avoid false sharing between CPUs.
#[repr(align(64))]
#[derive(Debug)]
#[doc(hidden)]
pub struct CachePadded<T>(pub T);

/// One `T` per CPU. Declare with [`cpu_local!`](crate::cpu_local).
pub struct CpuLocal<T> {
    slots: [CachePadded<T>; MAX_CPUS],
}

// SAFETY: a slot is only reached through `get` (the current CPU's slot,
// while an `IrqGuard` keeps anything else from running on this CPU, so the
// slot is never shared between execution contexts) or through `get_on` /
// `iter`, which require `T: Sync`. Values may be created on one CPU and used
// on another, hence `T: Send`.
unsafe impl<T: Send> Sync for CpuLocal<T> {}

impl<T> CpuLocal<T> {
    #[doc(hidden)]
    pub const fn from_slots(slots: [CachePadded<T>; MAX_CPUS]) -> Self {
        Self { slots }
    }

    /// This CPU's value, borrowed while interrupts stay masked.
    pub fn get<'a>(&'a self, guard: &'a IrqGuard) -> &'a T {
        &self.slots[guard.cpu().index()].0
    }
}

impl<T: Sync> CpuLocal<T> {
    /// Another CPU's value.
    pub fn get_on(&self, cpu: CpuId) -> &T {
        &self.slots[cpu.index()].0
    }

    /// The values of all online CPUs.
    pub fn iter(&self) -> impl Iterator<Item = (CpuId, &T)> {
        online().map(|c| (c, self.get_on(c)))
    }
}

impl<T> fmt::Debug for CpuLocal<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpuLocal").finish_non_exhaustive()
    }
}

/// Declares per-CPU statics. The initializer must be a constant expression.
///
/// ```ignore
/// frame::cpu_local! {
///     static TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// }
/// ```
#[macro_export]
macro_rules! cpu_local {
    ($($(#[$attr:meta])* $vis:vis static $name:ident: $ty:ty = $init:expr;)+) => {
        $(
            $(#[$attr])*
            $vis static $name: $crate::cpu::CpuLocal<$ty> = $crate::cpu::CpuLocal::from_slots(
                [const { $crate::cpu::CachePadded($init) }; $crate::cpu::MAX_CPUS],
            );
        )+
    };
}
