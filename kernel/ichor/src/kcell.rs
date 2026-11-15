//! The kernel object graph for cells (ADR-0002).
//!
//! This lives in the kernel binary, not in a `no_std` library crate, because
//! it ties together frame's `VmSpace`/`UFrame` and `cap::CSpace`. A [`Cell`]
//! owns a capability space, a resource account, and an address space. Objects
//! a cell can act on are reached only through capabilities in its CSpace, so
//! one cell cannot name another's objects.

use alloc::sync::Arc;

use cap::{CSpace, Cap, Handle, Rights};
use cell::Account;
use frame::mm::{UFrame, VmSpace};
use frame::sync::SpinLock;

/// Object-specific rights (ADR-0002 §1). The generic rights occupy the low
/// bits of [`Rights`]; these the high bits.
pub(crate) mod rights {
    use cap::Rights;
    pub(crate) const READ: Rights = Rights(1 << 8);
    pub(crate) const WRITE: Rights = Rights(1 << 9);
    pub(crate) const MAP: Rights = Rights(1 << 10);
    #[allow(dead_code)] // Granted when cell-creation syscalls land (milestone 3).
    pub(crate) const CREATE_CELL: Rights = Rights(1 << 11);
}

/// A kernel object a capability can refer to. Cloning a handle to one clones
/// the `Arc`, keeping the object alive while any cell holds a capability.
#[derive(Clone)]
#[allow(dead_code)] // `Cell`: capabilities to child cells (milestone 3).
pub(crate) enum Object {
    /// An untyped page of memory.
    Memory(UFrame),
    /// Another cell.
    Cell(Arc<Cell>),
}

impl core::fmt::Debug for Object {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Object::Memory(_) => write!(f, "Object::Memory"),
            Object::Cell(_) => write!(f, "Object::Cell"),
        }
    }
}

/// A cell: a hostile-tenant isolation domain.
pub(crate) struct Cell {
    id: u64,
    cspace: SpinLock<CSpace<Object>>,
    account: Arc<Account>,
    space: VmSpace,
}

impl core::fmt::Debug for Cell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Cell")
            .field("id", &self.id)
            .field("caps", &self.cspace.lock().len())
            .field("mem_used", &self.account.used())
            .finish()
    }
}

static NEXT_CELL_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

impl Cell {
    /// Creates a cell with a memory account limited to `mem_limit` pages,
    /// carved from `parent_account`.
    pub(crate) fn new(parent_account: &Arc<Account>, mem_limit: u64) -> Option<Arc<Cell>> {
        Some(Arc::new(Cell {
            id: NEXT_CELL_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            cspace: SpinLock::new(CSpace::new()),
            account: parent_account.new_child(mem_limit),
            space: VmSpace::new()?,
        }))
    }

    #[allow(dead_code)] // Reported by cell_inspect (milestone 3).
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn account(&self) -> &Arc<Account> {
        &self.account
    }

    pub(crate) fn space(&self) -> &VmSpace {
        &self.space
    }

    /// Installs a capability in this cell's CSpace, returning its handle
    /// (or `None` if the space is full).
    pub(crate) fn install(&self, cap: Cap<Object>) -> Option<Handle> {
        self.cspace.lock().insert(cap)
    }

    /// Allocates a page, charges it to this cell's account, and installs a
    /// capability with `grant` rights. Returns `None` if the account limit is
    /// hit or memory runs out.
    pub(crate) fn alloc_memory(&self, grant: Rights) -> Option<Handle> {
        if self.account.charge(1).is_err() {
            return None;
        }
        let Some(frame) = UFrame::alloc_zeroed() else {
            self.account.release(1);
            return None;
        };
        match self.install(Cap::mint(Object::Memory(frame), grant)) {
            Some(h) => Some(h),
            None => {
                self.account.release(1);
                None
            }
        }
    }

    /// Releases one page of this cell's memory account (on unmap/free).
    pub(crate) fn release_memory(&self, pages: u64) {
        self.account.release(pages);
    }

    /// Resolves a handle in this cell to its memory frame, checking `required`
    /// rights. Returns `None` for an invalid, foreign, revoked, or
    /// insufficiently-privileged handle.
    pub(crate) fn memory(&self, handle: Handle, required: Rights) -> Option<UFrame> {
        let cs = self.cspace.lock();
        match cs.access(handle, required)? {
            Object::Memory(f) => Some(f.clone()),
            _ => None,
        }
    }

    /// Returns a clone of the object a handle names, if the capability grants
    /// INSPECT. Used by the native ABI's metadata queries.
    pub(crate) fn object_inspect(&self, handle: Handle) -> Option<Object> {
        self.cspace.lock().access(handle, Rights::INSPECT).cloned()
    }

    /// Duplicates a handle within this cell with reduced rights.
    pub(crate) fn duplicate(&self, handle: Handle, new_rights: Rights) -> Option<Handle> {
        self.cspace.lock().duplicate(handle, new_rights)
    }

    /// Closes a handle, dropping the capability.
    pub(crate) fn close(&self, handle: Handle) -> bool {
        self.cspace.lock().close(handle).is_some()
    }

    /// Number of capabilities held.
    #[allow(dead_code)] // Reported by cell_inspect (milestone 3).
    pub(crate) fn cap_count(&self) -> usize {
        self.cspace.lock().len()
    }
}

/// The system cell's root account and cell, created once at boot.
pub(crate) struct System {
    pub(crate) root_account: Arc<Account>,
    /// The privileged system cell that runs the control plane (milestone 6).
    #[allow(dead_code)]
    pub(crate) cell: Arc<Cell>,
}

impl System {
    /// Creates the system cell with `total_pages` of memory budget.
    pub(crate) fn new(total_pages: u64) -> Option<System> {
        let root_account = Account::root(total_pages);
        let cell = Cell::new(&root_account, total_pages)?;
        Some(System { root_account, cell })
    }
}
