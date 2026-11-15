//! Hierarchical resource accounts (ADR-0002 §4).
//!
//! Accounts form a tree that mirrors cell creation. Each account has a limit
//! and a usage; a charge succeeds only if it fits under the account's own
//! limit *and* every ancestor's. Charges and releases are atomic, so the
//! point-of-use accounting in the allocator, scheduler and drivers needs no
//! lock. A child's limit is clamped to what the parent can delegate.
//!
//! This is the accounting algebra, generic over the resource kind. The kernel
//! instantiates one tree per resource (memory pages, IO tokens, ...).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// Unlimited, for the root account.
pub const UNLIMITED: u64 = u64::MAX;

/// One node in a resource account tree.
#[derive(Debug)]
pub struct Account {
    limit: AtomicU64,
    used: AtomicU64,
    /// Usage charged directly to this account (not via descendants).
    local: AtomicU64,
    parent: Option<Arc<Account>>,
}

impl Account {
    /// The root account, with the given limit (often [`UNLIMITED`]).
    pub fn root(limit: u64) -> Arc<Account> {
        Arc::new(Account {
            limit: AtomicU64::new(limit),
            used: AtomicU64::new(0),
            local: AtomicU64::new(0),
            parent: None,
        })
    }

    /// Creates a child account with `limit`, clamped to this account's limit.
    pub fn new_child(self: &Arc<Self>, limit: u64) -> Arc<Account> {
        Arc::new(Account {
            limit: AtomicU64::new(limit.min(self.limit.load(Ordering::Relaxed))),
            used: AtomicU64::new(0),
            local: AtomicU64::new(0),
            parent: Some(self.clone()),
        })
    }

    /// This account's limit.
    pub fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Total charged to this account, including descendants.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// Charged directly to this account.
    pub fn local(&self) -> u64 {
        self.local.load(Ordering::Relaxed)
    }

    /// Headroom left under this account's own limit.
    pub fn available(&self) -> u64 {
        self.limit().saturating_sub(self.used())
    }

    /// Charges `amount` to this account and up the chain. On failure nothing
    /// is charged (the partial charge is rolled back).
    pub fn charge(self: &Arc<Self>, amount: u64) -> Result<(), ChargeError> {
        // Reserve against every ancestor, from here up. Record how far we got
        // so a failure can roll back exactly those.
        let mut node: Option<Arc<Account>> = Some(self.clone());
        let mut charged: Vec<Arc<Account>> = Vec::new();
        while let Some(acc) = node {
            if !acc.try_add_used(amount) {
                for done in &charged {
                    done.sub_used(amount);
                }
                return Err(ChargeError::Exceeded);
            }
            charged.push(acc.clone());
            node = acc.parent.clone();
        }
        self.local.fetch_add(amount, Ordering::Relaxed);
        Ok(())
    }

    /// Releases `amount` previously charged to this account.
    pub fn release(self: &Arc<Self>, amount: u64) {
        self.local
            .fetch_sub(amount.min(self.local()), Ordering::Relaxed);
        let mut node = Some(self.clone());
        while let Some(acc) = node {
            acc.sub_used(amount);
            node = acc.parent.clone();
        }
    }

    /// Lowers or raises this account's limit, never above the parent's limit.
    /// Returns the limit actually set.
    pub fn set_limit(self: &Arc<Self>, limit: u64) -> u64 {
        let capped = match &self.parent {
            Some(p) => limit.min(p.limit.load(Ordering::Relaxed)),
            None => limit,
        };
        self.limit.store(capped, Ordering::Relaxed);
        capped
    }

    fn try_add_used(&self, amount: u64) -> bool {
        let limit = self.limit.load(Ordering::Relaxed);
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = match cur.checked_add(amount) {
                Some(n) if n <= limit => n,
                _ => return false,
            };
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    fn sub_used(&self, amount: u64) {
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(amount);
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Why a charge was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeError {
    /// The charge would exceed this account's or an ancestor's limit.
    Exceeded,
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn charge_and_release_roll_up() {
        let root = Account::root(1000);
        let child = root.new_child(400);
        child.charge(100).unwrap();
        assert_eq!(child.used(), 100);
        assert_eq!(root.used(), 100);
        child.release(100);
        assert_eq!(child.used(), 0);
        assert_eq!(root.used(), 0);
    }

    #[test]
    fn child_limit_clamped_to_parent() {
        let root = Account::root(500);
        let child = root.new_child(1000);
        assert_eq!(child.limit(), 500);
        assert_eq!(child.set_limit(800), 500);
        assert_eq!(child.set_limit(200), 200);
    }

    #[test]
    fn ancestor_limit_enforced() {
        let root = Account::root(300);
        let a = root.new_child(250);
        let b = root.new_child(250);
        a.charge(200).unwrap();
        // b's own limit (250) allows 200, but the root only has 100 left.
        assert_eq!(b.charge(200), Err(ChargeError::Exceeded));
        assert_eq!(b.charge(100), Ok(()));
        assert_eq!(root.used(), 300);
        // Nothing leaked from the failed charge.
        assert_eq!(b.used(), 100);
    }

    #[test]
    fn own_limit_enforced() {
        let root = Account::root(UNLIMITED);
        let child = root.new_child(50);
        assert_eq!(child.charge(60), Err(ChargeError::Exceeded));
        child.charge(50).unwrap();
        assert_eq!(child.charge(1), Err(ChargeError::Exceeded));
        assert_eq!(child.available(), 0);
    }

    #[test]
    fn deep_tree_accounts_correctly() {
        let root = Account::root(UNLIMITED);
        let mut acc = root.clone();
        let chain: std::vec::Vec<_> = (0..5)
            .map(|_| {
                acc = acc.new_child(UNLIMITED);
                acc.clone()
            })
            .collect();
        chain.last().unwrap().charge(42).unwrap();
        for a in &chain {
            assert_eq!(a.used(), 42);
        }
        assert_eq!(root.used(), 42);
        assert_eq!(root.local(), 0);
        assert_eq!(chain.last().unwrap().local(), 42);
    }

    #[test]
    fn concurrent_charges_never_exceed() {
        use std::sync::Arc as StdArc;
        use std::thread;
        let root = Account::root(1000);
        let root2 = StdArc::new(root);
        let mut handles = std::vec::Vec::new();
        for _ in 0..8 {
            let r = root2.clone();
            handles.push(thread::spawn(move || {
                let mut ok = 0;
                for _ in 0..1000 {
                    if r.charge(1).is_ok() {
                        ok += 1;
                    }
                }
                ok
            }));
        }
        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        // Exactly the limit was granted across threads, never more.
        assert_eq!(total, 1000);
        assert_eq!(root2.used(), 1000);
    }
}
