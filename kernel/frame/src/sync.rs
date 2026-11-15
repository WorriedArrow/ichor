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
        crate::cpu::atomic_enter();
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
        crate::cpu::atomic_enter();
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
                crate::cpu::atomic_leave();
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
        crate::cpu::atomic_leave();
        arch::restore_interrupts(self.irq);
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

/// A sleeping mutual-exclusion lock: waiters block (other tasks run)
/// instead of spinning. Must not be taken in atomic mode.
pub struct Mutex<T: ?Sized> {
    locked: AtomicBool,
    waiters: crate::task::WaitQueue,
    data: UnsafeCell<T>,
}

// SAFETY: as for `SpinLock`: at most one `&mut T` exists at a time.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            waiters: crate::task::WaitQueue::new(),
            data: UnsafeCell::new(value),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquires the lock, sleeping while another task holds it.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        loop {
            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return MutexGuard {
                    lock: self,
                    _not_send: PhantomData,
                };
            }
            self.waiters
                .wait_until(|| (!self.locked.load(Ordering::Relaxed)).then_some(()));
        }
    }
}

impl<T: ?Sized> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mutex")
            .field("locked", &self.locked.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Exclusive access to the data in a [`Mutex`]; unlocks on drop.
pub struct MutexGuard<'a, T: ?Sized> {
    lock: &'a Mutex<T>,
    _not_send: PhantomData<*mut ()>,
}

// SAFETY: `&MutexGuard<T>` only exposes `&T` (see `SpinLockGuard`).
unsafe impl<T: ?Sized + Sync> Sync for MutexGuard<'_, T> {}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while the lock is held by us.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as in `deref`, and `&mut self` makes this borrow unique.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        self.lock.waiters.wake_one();
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
