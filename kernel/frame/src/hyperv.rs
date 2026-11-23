//! The Hyper-V hypervisor's own interface (ADR-0016): hypercalls, and the
//! synthetic interrupt controller's messages. What is said through it
//! (VMBus) is the drivers' business.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering, fence};

use crate::arch::regs::{cpuid, rdmsr, wrmsr};
use crate::cpu::IrqGuard;
use crate::dma::DmaBuf;
use crate::mm::kspace;
use crate::sync::SpinLock;

pub(crate) const VECTOR: u8 = 0xF2;
/// The synthetic interrupt messages come by.
pub const SINT: u8 = 2;
/// The most bytes in a message.
pub const MAX_MESSAGE: usize = 240;

const MSR_GUEST_OS_ID: u32 = 0x4000_0000;
const MSR_HYPERCALL: u32 = 0x4000_0001;
const MSR_VP_INDEX: u32 = 0x4000_0002;
const MSR_TSC_FREQUENCY: u32 = 0x4000_0022;
const MSR_SCONTROL: u32 = 0x4000_0080;
const MSR_SIEFP: u32 = 0x4000_0082;
const MSR_SIMP: u32 = 0x4000_0083;
const MSR_EOM: u32 = 0x4000_0084;
const MSR_SINT0: u32 = 0x4000_0090;

const POST_MESSAGE: u64 = 0x5c;
const SIGNAL_EVENT: u64 = 0x5d;
/// The input is in registers.
const FAST: u64 = 1 << 16;

/// A message slot: type, length, flags, two words of origin, the bytes.
const SLOT: usize = 256;
const PENDING: u8 = 1;

/// Messages taken from their slot and not yet from here.
static RECEIVED: SpinLock<VecDeque<Vec<u8>>> = SpinLock::new(VecDeque::new());
/// The page of the connected processor's slots.
static SLOTS: SpinLock<Option<DmaBuf>> = SpinLock::new(None);
static CONNECTED: AtomicBool = AtomicBool::new(false);

/// The connection to the hypervisor.
#[derive(Debug)]
pub struct Hyperv {
    /// Where its hypercall page is mapped.
    entry: u64,
    /// The input of a hypercall that takes memory.
    input: SpinLock<DmaBuf>,
    /// The processor whose messages come.
    vp: u32,
}

/// The registers Hyper-V gives this guest, and what it may do.
fn offered() -> Option<[u32; 2]> {
    let hypervisor = crate::arch::cpu::features().hypervisor;
    if !hypervisor || cpuid(0x4000_0001, 0)[0] != u32::from_le_bytes(*b"Hv#1") {
        return None;
    }
    let [registers, may, ..] = cpuid(0x4000_0003, 0);
    Some([registers, may])
}

/// The TSC's frequency, which Hyper-V knows.
pub(crate) fn tsc_hz() -> Option<u64> {
    const FREQUENCIES: u32 = 1 << 11;
    if offered()?[0] & FREQUENCIES == 0 {
        return None;
    }
    // SAFETY: a register CPUID says this guest has; reading it has no side
    // effects.
    Some(unsafe { rdmsr(MSR_TSC_FREQUENCY) }).filter(|&hz| hz != 0)
}

/// Tells Hyper-V of this guest and has messages come to this CPU. `None` on
/// other machines, and after the first time.
pub fn connect() -> Option<Hyperv> {
    // SynIC and hypercall registers, posting and signalling.
    let [registers, may] = offered()?;
    if registers & 0x24 != 0x24 || may & 0x30 != 0x30 || CONNECTED.swap(true, Ordering::AcqRel) {
        return None;
    }
    let page = || DmaBuf::alloc(4096);
    let (code, slots, events, input) = (page()?, page()?, page()?, page()?);
    let at = |b: &DmaBuf| b.dma_addr(0).map(|a| a.as_u64());
    let entry = kspace::map_code(at(&code)?)?;
    let (code_at, slots_at, events_at) = (at(&code)?, at(&slots)?, at(&events)?);
    let set = |msr, v| {
        // SAFETY: the registers CPUID says this guest has (above). The pages
        // they name are this function's, given up to the hypervisor for
        // good (below); the interrupt is one `handle_irq` knows.
        unsafe { wrmsr(msr, v) }
    };
    *SLOTS.lock() = Some(slots);
    core::mem::forget((code, events));
    let g = IrqGuard::new();
    // An open-source guest of no registered kind.
    set(MSR_GUEST_OS_ID, 1 << 63 | 1);
    set(MSR_HYPERCALL, code_at | 1);
    set(MSR_SIMP, slots_at | 1);
    set(MSR_SIEFP, events_at | 1);
    set(MSR_SINT0 + u32::from(SINT), u64::from(VECTOR));
    set(MSR_SCONTROL, 1);
    // SAFETY: as above; reading has no side effects.
    let vp = unsafe { rdmsr(MSR_VP_INDEX) } as u32;
    // SAFETY: as above.
    let ready = unsafe { rdmsr(MSR_HYPERCALL) } & 1 != 0;
    drop(g);
    ready.then_some(Hyperv {
        entry,
        input: SpinLock::new(input),
        vp,
    })
}

/// Takes what is in this CPU's slot (the one that connected).
pub(crate) fn on_interrupt() {
    let slots = SLOTS.lock();
    let Some(page) = &*slots else { return };
    let at = usize::from(SINT) * SLOT;
    while page.read_u32(at) != 0 {
        fence(Ordering::SeqCst);
        let mut head = [0u8; 2];
        page.read(at + 4, &mut head);
        let mut m = alloc::vec![0u8; usize::from(head[0]).min(MAX_MESSAGE)];
        page.read(at + 16, &mut m);
        RECEIVED.lock().push_back(m);
        page.write_u32(at, 0);
        fence(Ordering::SeqCst);
        // Another waits for the slot; it comes once told.
        page.read(at + 5, &mut head[1..]);
        if head[1] & PENDING == 0 {
            break;
        }
        // SAFETY: the connected processor's (its interrupt runs this).
        unsafe { wrmsr(MSR_EOM, 0) };
    }
}

impl Hyperv {
    /// The processor messages come to.
    pub fn vp(&self) -> u32 {
        self.vp
    }

    fn call(&self, control: u64, input: u64) -> u16 {
        let status: u64;
        // SAFETY: the hypervisor's page of code, which follows this calling
        // convention and touches no other memory than `input`, the page
        // of input (or, in a fast call, none).
        unsafe {
            core::arch::asm!(
                "call {entry}",
                entry = in(reg) self.entry,
                inout("rcx") control => _,
                inout("rdx") input => _,
                inout("r8") 0u64 => _,
                out("rax") status,
                out("r9") _, out("r10") _, out("r11") _,
            )
        };
        status as u16
    }

    /// Posts a message (at most [`MAX_MESSAGE`] bytes) to `connection`;
    /// the hypervisor's status, 0 if it took it.
    pub fn post(&self, connection: u32, message: &[u8]) -> Result<(), u16> {
        const VMBUS: u32 = 1; // the kind of message
        if message.len() > MAX_MESSAGE {
            return Err(u16::MAX);
        }
        let input = self.input.lock();
        for (i, v) in [connection, 0, VMBUS, message.len() as u32]
            .into_iter()
            .enumerate()
        {
            input.write_u32(4 * i, v);
        }
        input.write(16, message);
        let at = input.dma_addr(0).map_or(0, |a| a.as_u64());
        match self.call(POST_MESSAGE, at) {
            0 => Ok(()),
            status => Err(status),
        }
    }

    /// Signals `connection`.
    pub fn signal(&self, connection: u32) {
        self.call(SIGNAL_EVENT | FAST, u64::from(connection));
    }

    /// The next message to this guest.
    pub fn message(&self) -> Option<Vec<u8>> {
        RECEIVED.lock().pop_front()
    }
}
