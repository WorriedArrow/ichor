//! Capabilities: unforgeable references to kernel objects, each carrying a
//! rights mask and optional revocation (ADR-0002 §1–2).
//!
//! This crate is the capability *algebra* and the per-cell capability table
//! (CSpace). It is generic over the object type `T` the kernel plugs in (an
//! enum of `Arc<KernelObject>`), so it is pure safe code and host-testable.
//!
//! Three rules hold by construction:
//!
//! * **Rights only shrink.** [`Cap::derive`] can only drop rights, and needs
//!   the [`Rights::DUPLICATE`] right to make any copy at all.
//! * **Handles are unforgeable and non-aliasing.** A [`Handle`] is a slot
//!   index plus a generation. Closing a slot bumps its generation, so a stale
//!   handle never names a later object (no ABA).
//! * **Revocation is one atomic check.** A capability minted against a
//!   [`RevocationToken`] is dead the instant the token is revoked, however
//!   many copies exist.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// A set of rights on a capability. The generic rights live in the low bits;
/// object-specific rights (READ, WRITE, MAP, ...) are defined by the kernel
/// in the high bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(pub u32);

impl Rights {
    /// No rights.
    pub const NONE: Rights = Rights(0);
    /// Every right.
    pub const ALL: Rights = Rights(u32::MAX);
    /// May be copied (with [`Cap::derive`]) or duplicated into another slot.
    pub const DUPLICATE: Rights = Rights(1 << 0);
    /// May be transferred to another cell.
    pub const TRANSFER: Rights = Rights(1 << 1);
    /// May be inspected (status, metadata).
    pub const INSPECT: Rights = Rights(1 << 2);
    /// May be waited on.
    pub const WAIT: Rights = Rights(1 << 3);

    /// Whether every right in `other` is present.
    pub fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    /// The intersection of two rights sets.
    pub fn intersection(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    /// This set with `other` removed.
    pub fn minus(self, other: Rights) -> Rights {
        Rights(self.0 & !other.0)
    }
}

impl core::ops::BitOr for Rights {
    type Output = Rights;
    fn bitor(self, rhs: Rights) -> Rights {
        Rights(self.0 | rhs.0)
    }
}

impl core::fmt::Debug for Rights {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Rights({:#x})", self.0)
    }
}

/// A revocation token shared by a capability and everything derived from it.
/// Revoking it invalidates them all at once.
#[derive(Debug, Default)]
pub struct RevocationToken {
    revoked: AtomicBool,
}

impl RevocationToken {
    /// A fresh, live token.
    pub fn new() -> Arc<RevocationToken> {
        Arc::new(RevocationToken {
            revoked: AtomicBool::new(false),
        })
    }

    /// Marks every capability under this token dead.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    /// Whether it has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

/// A capability: a reference to an object `T`, a rights mask, and optional
/// revocation.
#[derive(Debug)]
pub struct Cap<T> {
    object: T,
    rights: Rights,
    revoke: Option<Arc<RevocationToken>>,
}

impl<T: Clone> Clone for Cap<T> {
    fn clone(&self) -> Self {
        Cap {
            object: self.object.clone(),
            rights: self.rights,
            revoke: self.revoke.clone(),
        }
    }
}

impl<T> Cap<T> {
    /// Mints a fresh capability with full control. Used by the kernel when it
    /// creates an object; not reachable from a cell.
    pub fn mint(object: T, rights: Rights) -> Self {
        Cap {
            object,
            rights,
            revoke: None,
        }
    }

    /// Mints a capability governed by `token`.
    pub fn mint_revocable(object: T, rights: Rights, token: Arc<RevocationToken>) -> Self {
        Cap {
            object,
            rights,
            revoke: Some(token),
        }
    }

    /// The rights this capability grants (ignoring revocation).
    pub fn rights(&self) -> Rights {
        self.rights
    }

    /// Whether the capability is still live (its token, if any, is not
    /// revoked).
    pub fn is_live(&self) -> bool {
        self.revoke.as_ref().is_none_or(|t| !t.is_revoked())
    }

    /// The object, if the capability is live and holds every right in
    /// `required`.
    pub fn access(&self, required: Rights) -> Option<&T> {
        (self.is_live() && self.rights.contains(required)).then_some(&self.object)
    }

    /// The object without a rights check, if live. For the kernel's own use
    /// where the right was already checked.
    pub fn object(&self) -> Option<&T> {
        self.is_live().then_some(&self.object)
    }
}

impl<T: Clone> Cap<T> {
    /// Derives a weaker copy: requires [`Rights::DUPLICATE`] and `new_rights`
    /// must be a subset of this capability's rights. The copy keeps the same
    /// revocation token, so revoking the original kills the copy too.
    pub fn derive(&self, new_rights: Rights) -> Option<Cap<T>> {
        if !self.is_live()
            || !self.rights.contains(Rights::DUPLICATE)
            || !self.rights.contains(new_rights)
        {
            return None;
        }
        Some(Cap {
            object: self.object.clone(),
            rights: new_rights,
            revoke: self.revoke.clone(),
        })
    }
}

/// A handle: a cell-local name for a slot in its [`CSpace`]. Meaningless in
/// any other cell. The generation guards against reuse.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(u64);

impl Handle {
    const INDEX_BITS: u32 = 32;
    const INDEX_MASK: u64 = (1 << Self::INDEX_BITS) - 1;

    fn new(index: u32, generation: u32) -> Handle {
        Handle((u64::from(generation) << Self::INDEX_BITS) | u64::from(index))
    }

    fn index(self) -> u32 {
        (self.0 & Self::INDEX_MASK) as u32
    }

    fn generation(self) -> u32 {
        (self.0 >> Self::INDEX_BITS) as u32
    }

    /// The raw 64-bit value passed across the native ABI.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Reconstructs a handle from a raw ABI value. It is validated against the
    /// CSpace on use, so a forged value simply fails to resolve.
    pub fn from_raw(raw: u64) -> Handle {
        Handle(raw)
    }
}

impl core::fmt::Debug for Handle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Handle(#{}, gen {})", self.index(), self.generation())
    }
}

struct Slot<T> {
    generation: u32,
    cap: Option<Cap<T>>,
}

/// A cell's capability table. Handles index into it; the generation makes a
/// closed handle fail to resolve.
#[derive(Debug)]
pub struct CSpace<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
    len: usize,
}

impl<T> core::fmt::Debug for Slot<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Slot")
            .field("generation", &self.generation)
            .field("occupied", &self.cap.is_some())
            .finish()
    }
}

impl<T> Default for CSpace<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> CSpace<T> {
    /// An empty capability space.
    pub fn new() -> Self {
        CSpace {
            slots: Vec::new(),
            free: Vec::new(),
            len: 0,
        }
    }

    /// Live capabilities in this space.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Installs `cap`, returning a fresh handle, or `None` if the space is
    /// full (more than `u32::MAX` slots).
    pub fn insert(&mut self, cap: Cap<T>) -> Option<Handle> {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.cap = Some(cap);
            self.len += 1;
            return Some(Handle::new(index, slot.generation));
        }
        let index = u32::try_from(self.slots.len()).ok()?;
        self.slots.push(Slot {
            generation: 0,
            cap: Some(cap),
        });
        self.len += 1;
        Some(Handle::new(index, 0))
    }

    fn slot(&self, handle: Handle) -> Option<&Slot<T>> {
        let slot = self.slots.get(handle.index() as usize)?;
        (slot.generation == handle.generation() && slot.cap.is_some()).then_some(slot)
    }

    /// The capability a handle names, if it is valid and live.
    pub fn get(&self, handle: Handle) -> Option<&Cap<T>> {
        let cap = self.slot(handle)?.cap.as_ref()?;
        cap.is_live().then_some(cap)
    }

    /// Resolves a handle and checks it grants `required`, returning the
    /// object.
    pub fn access(&self, handle: Handle, required: Rights) -> Option<&T> {
        self.get(handle)?.access(required)
    }

    /// Removes the capability a handle names, bumping the slot's generation
    /// so the handle can never resolve again. Returns the removed capability.
    pub fn close(&mut self, handle: Handle) -> Option<Cap<T>> {
        let index = handle.index() as usize;
        let slot = self.slots.get_mut(index)?;
        if slot.generation != handle.generation() || slot.cap.is_none() {
            return None;
        }
        let cap = slot.cap.take();
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(handle.index());
        self.len -= 1;
        cap
    }
}

impl<T: Clone> CSpace<T> {
    /// Duplicates the capability at `handle` into a new slot with
    /// `new_rights` (a subset), returning the new handle. Needs
    /// [`Rights::DUPLICATE`].
    pub fn duplicate(&mut self, handle: Handle, new_rights: Rights) -> Option<Handle> {
        let derived = self.get(handle)?.derive(new_rights)?;
        self.insert(derived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type C = CSpace<u64>;

    #[test]
    fn rights_shrink_only() {
        let full = Cap::mint(7u64, Rights::ALL);
        let ro = full.derive(Rights::DUPLICATE | Rights::INSPECT).unwrap();
        assert!(ro.rights().contains(Rights::INSPECT));
        // Cannot widen: deriving rights not held fails.
        let widened = Rights(0xffff);
        let narrow = Cap::mint(7u64, Rights::DUPLICATE | Rights::INSPECT);
        assert!(narrow.derive(widened).is_none());
        // Without DUPLICATE, no derivation at all.
        let no_dup = Cap::mint(7u64, Rights::INSPECT);
        assert!(no_dup.derive(Rights::INSPECT).is_none());
    }

    #[test]
    fn revocation_kills_all_copies() {
        let token = RevocationToken::new();
        let a = Cap::mint_revocable(1u64, Rights::ALL, token.clone());
        let b = a.derive(Rights::DUPLICATE).unwrap();
        assert!(a.is_live() && b.is_live());
        token.revoke();
        assert!(!a.is_live() && !b.is_live());
        assert!(a.access(Rights::NONE).is_none());
        assert!(a.object().is_none());
    }

    #[test]
    fn handles_do_not_alias_after_close() {
        let mut cs = C::new();
        let h1 = cs.insert(Cap::mint(10, Rights::ALL)).unwrap();
        assert_eq!(cs.access(h1, Rights::NONE), Some(&10));
        assert!(cs.close(h1).is_some());
        // Stale handle no longer resolves.
        assert!(cs.get(h1).is_none());
        assert!(cs.close(h1).is_none());
        // The slot is reused, but the new handle differs (generation bumped).
        let h2 = cs.insert(Cap::mint(20, Rights::ALL)).unwrap();
        assert_eq!(h1.index(), h2.index());
        assert_ne!(h1, h2);
        assert!(cs.get(h1).is_none());
        assert_eq!(cs.access(h2, Rights::NONE), Some(&20));
    }

    #[test]
    fn access_enforces_rights() {
        let mut cs = C::new();
        let read = Rights(1 << 8);
        let write = Rights(1 << 9);
        let h = cs.insert(Cap::mint(5, Rights::INSPECT | read)).unwrap();
        assert_eq!(cs.access(h, read), Some(&5));
        assert!(cs.access(h, write).is_none());
        assert!(cs.access(h, read | write).is_none());
    }

    #[test]
    fn duplicate_into_new_slot() {
        let mut cs = C::new();
        let h = cs
            .insert(Cap::mint(99, Rights::DUPLICATE | Rights::INSPECT))
            .unwrap();
        let dup = cs.duplicate(h, Rights::INSPECT).unwrap();
        assert_ne!(h, dup);
        assert_eq!(cs.access(dup, Rights::INSPECT), Some(&99));
        // The duplicate lacks DUPLICATE, so it cannot be duplicated again.
        assert!(cs.duplicate(dup, Rights::INSPECT).is_none());
        assert_eq!(cs.len(), 2);
    }

    #[test]
    fn revoked_cap_in_cspace_does_not_resolve() {
        let mut cs = C::new();
        let token = RevocationToken::new();
        let h = cs
            .insert(Cap::mint_revocable(3, Rights::ALL, token.clone()))
            .unwrap();
        assert!(cs.get(h).is_some());
        token.revoke();
        assert!(cs.get(h).is_none());
        assert!(cs.access(h, Rights::NONE).is_none());
    }

    #[test]
    fn close_accounts_length() {
        let mut cs = C::new();
        let handles: Vec<_> = (0..100)
            .map(|i| cs.insert(Cap::mint(i, Rights::ALL)).unwrap())
            .collect();
        assert_eq!(cs.len(), 100);
        for h in &handles {
            cs.close(*h);
        }
        assert!(cs.is_empty());
        // Reinserting reuses slots without growing unboundedly.
        for i in 0..100 {
            cs.insert(Cap::mint(i, Rights::ALL)).unwrap();
        }
        assert_eq!(cs.len(), 100);
    }
}
