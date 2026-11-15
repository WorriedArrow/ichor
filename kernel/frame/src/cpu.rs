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
use core::sync::atomic::{AtomicU32, Ordering};

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
pub fn online_count() -> usize {
    ONLINE.load(Ordering::Acquire) as usize
}

/// The CPUs that are online: `0..online_count()`.
pub fn online() -> impl Iterator<Item = CpuId> {
    (0..online_count() as u32).map(CpuId)
}

/// The per-CPU block GS points at.
#[repr(C)]
pub(crate) struct CpuBlock {
    /// Offset 0: the block's own address.
    self_addr: u64,
    /// Offset 8: the CPU index.
    index: u64,
}

/// Sets up the calling CPU's block (GS base).
pub(crate) fn init_this_cpu(id: CpuId) {
    let block = Box::leak(Box::new(CpuBlock {
        self_addr: 0,
        index: u64::from(id.0),
    }));
    block.self_addr = core::ptr::addr_of!(*block) as u64;
    arch::set_cpu_block(block.self_addr);
}

/// Counts the calling CPU as online (after all of its initialization).
pub(crate) fn mark_online() {
    ONLINE.fetch_add(1, Ordering::AcqRel);
}

/// The CPU this code is running on.
///
/// Without a guard the answer may be stale by the time it is used once
/// the scheduler can migrate tasks (milestone 2); hold an [`IrqGuard`] when
/// that matters.
pub fn current() -> CpuId {
    CpuId(arch::cpu_index())
}

/// Interrupts are masked on this CPU while the guard lives; restores the
/// previous state on drop. Not `Send` or `Sync`: it describes this CPU.
pub struct IrqGuard {
    was_enabled: bool,
    _not_send: PhantomData<*mut ()>,
}

impl IrqGuard {
    /// Masks interrupts on this CPU.
    pub fn new() -> Self {
        Self {
            was_enabled: arch::save_and_disable_interrupts(),
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
    ($($vis:vis static $name:ident: $ty:ty = $init:expr;)+) => {
        $(
            $vis static $name: $crate::cpu::CpuLocal<$ty> = $crate::cpu::CpuLocal::from_slots(
                [const { $crate::cpu::CachePadded($init) }; $crate::cpu::MAX_CPUS],
            );
        )+
    };
}
