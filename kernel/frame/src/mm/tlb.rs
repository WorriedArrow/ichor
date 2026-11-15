//! TLB shootdown for address spaces shared by several CPUs (ADR-0007).
//!
//! Every CPU records the user root it has loaded (`note_loaded`, called
//! just before CR3 is written). After a mapping is removed or downgraded,
//! [`shootdown`] flushes the current CPU, sends an IPI to every other CPU
//! with that root loaded, and waits until each has flushed. Only then may
//! the caller free the page or rely on the downgrade.
//!
//! Why this is enough: the page-table entry changes before `shootdown`
//! reads the loaded roots (both `SeqCst`). A CPU whose root store comes
//! later in that order loads CR3 afterwards and walks the new tables; one
//! whose store comes earlier is seen, and gets an IPI. Switching between two
//! tasks with the same root does not reload CR3, which is why the
//! requester always flushes the CPU it is on.
//!
//! One shootdown runs at a time. The requester waits with interrupts
//! enabled, so two CPUs shooting down at once cannot deadlock: each keeps
//! servicing the other's IPI while it waits.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::*};

use crate::arch::{self, regs};
use crate::cpu::{self, IrqGuard};

/// The IPI vector of a shootdown request.
pub(crate) const VECTOR: u8 = 0xF1;
/// `REQ_VA` meaning "flush every user entry".
const ALL: u64 = u64::MAX;

crate::cpu_local! {
    /// The root this CPU has loaded in CR3.
    static LOADED_ROOT: AtomicU64 = AtomicU64::new(0);
}

static BUSY: AtomicBool = AtomicBool::new(false);
static REQ_ROOT: AtomicU64 = AtomicU64::new(0);
static REQ_VA: AtomicU64 = AtomicU64::new(0);
static PENDING: AtomicU32 = AtomicU32::new(0);

/// Records that this CPU is about to load `root` into CR3.
pub(crate) fn note_loaded(root: u64) {
    let g = IrqGuard::new();
    LOADED_ROOT.get(&g).store(root, SeqCst);
}

fn flush_here(va: u64) {
    if va == ALL {
        // SAFETY: reloading CR3 with its own value only drops non-global
        // TLB entries; the address space is unchanged.
        unsafe { regs::write_cr3(regs::read_cr3()) };
    } else {
        arch::paging::flush_page(va);
    }
}

/// Makes every CPU forget translations of `va` (or all user addresses, for
/// `None`) in the space whose root is `root`. Call after changing its page
/// tables and before freeing what they pointed at. Must not be called in
/// atomic mode (interrupts masked).
pub(crate) fn shootdown(root: u64, va: Option<u64>) {
    crate::irq::assert_not_atomic("tlb shootdown");
    let va = va.unwrap_or(ALL);
    while BUSY
        .compare_exchange_weak(false, true, Acquire, Relaxed)
        .is_err()
    {
        core::hint::spin_loop(); // interrupts are on: we serve others' IPIs
    }
    let mut targets: Vec<u32> = Vec::new();
    {
        let g = IrqGuard::new();
        let me = cpu::current();
        if LOADED_ROOT.get(&g).load(SeqCst) == root {
            flush_here(va);
        }
        REQ_ROOT.store(root, SeqCst);
        REQ_VA.store(va, SeqCst);
        for c in cpu::online() {
            if c != me && LOADED_ROOT.get_on(c).load(SeqCst) == root {
                let id = crate::task::apic_id_of(c);
                if id != u32::MAX {
                    targets.push(id);
                }
            }
        }
        PENDING.store(targets.len() as u32, SeqCst);
        for &id in &targets {
            arch::apic::send_ipi(id, VECTOR);
        }
        drop(g);
    }
    while PENDING.load(Acquire) != 0 {
        core::hint::spin_loop();
    }
    BUSY.store(false, Release);
}

/// The shootdown IPI: flushes if this CPU still has the root loaded, then
/// acknowledges.
pub(crate) fn on_ipi() {
    let g = IrqGuard::new();
    if LOADED_ROOT.get(&g).load(SeqCst) == REQ_ROOT.load(SeqCst) {
        flush_here(REQ_VA.load(SeqCst));
    }
    PENDING.fetch_sub(1, Release);
}
