//! Synchronization primitives.
//!
//! `SpinLock` masks local interrupts for the lifetime of its guard, so a
//! lock taken in an interrupt handler can never deadlock against the code it
//! interrupted on the same CPU. Preemption control joins it with the
//! scheduler (milestone 2).

use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch;

/// A mutual-exclusion spinlock.
pub struct SpinLock<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: the lock hands out at most one `&mut T` at a time, so sharing the
// lock across threads only ever moves access to `T` between threads, which is
// sound when `T: Send` (same reasoning as `std::sync::Mutex`).
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Creates an unlocked spinlock holding `value`.
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Spins until the lock is acquired.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let irq = arch::save_and_disable_interrupts();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinLockGuard {
            lock: self,
            irq,
            _not_send: PhantomData,
        }
    }

    /// Acquires the lock if it is free.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let irq = arch::save_and_disable_interrupts();
        match self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => Some(SpinLockGuard {
                lock: self,
                irq,
                _not_send: PhantomData,
            }),
            Err(_) => {
                arch::restore_interrupts(irq);
                None
            }
        }
    }
}

impl<T: ?Sized> fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpinLock")
            .field("locked", &self.locked.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Exclusive access to the data in a [`SpinLock`]; unlocks on drop.
///
/// Not `Send`: a guard is released on the CPU that took it, which milestone 1
/// relies on when the guard also holds the CPU's interrupt state.
pub struct SpinLockGuard<'a, T: ?Sized> {
    lock: &'a SpinLock<T>,
    /// Whether interrupts were enabled before locking.
    irq: bool,
    _not_send: PhantomData<*mut ()>,
}

// SAFETY: `&SpinLockGuard<T>` only exposes `&T`, so sharing the guard is sound
// exactly when sharing `&T` is, i.e. when `T: Sync`. (The `PhantomData<*mut ()>`
// that suppresses `Send` also suppresses `Sync`; this restores it.)
unsafe impl<T: ?Sized + Sync> Sync for SpinLockGuard<'_, T> {}

impl<T: ?Sized> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while `locked` is held by us, so no
        // other reference to the data exists.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`; `&mut self` additionally guarantees this is
        // the only borrow derived from the guard.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        arch::restore_interrupts(self.irq);
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
