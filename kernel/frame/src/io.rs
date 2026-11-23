//! Device registers, memory-mapped and behind I/O ports (ADR-0005).
//!
//! An [`IoMem`] is obtained only from [`PciDevice::map_bar`](crate::bus::pci::PciDevice::map_bar),
//! which refuses ranges that overlap RAM. Accessors are bounds-checked,
//! naturally aligned, volatile, and never panic: an out-of-range read
//! returns all ones (like a PCI master abort) and an out-of-range write is
//! dropped.

use crate::boot::{self, MemoryKind};
use crate::mm::kspace;

/// The x86 system-device range (IOAPIC, HPET, local APIC). Never mappable
/// through `IoMem`: frame drives those devices itself.
const SYSTEM_DEVICES: (u64, u64) = (0xfec0_0000, 0xff00_0000);

/// A mapped region of device registers.
#[derive(Debug)]
pub struct IoMem {
    va: u64,
    len: u64,
}

fn is_ram(k: MemoryKind) -> bool {
    !matches!(k, MemoryKind::Mmio | MemoryKind::Reserved)
}

impl IoMem {
    /// Maps `[pa, pa + len)`. Frame-internal; see `PciDevice::map_bar`.
    pub(crate) fn map(pa: u64, len: u64) -> Option<IoMem> {
        let end = pa.checked_add(len)?;
        if len == 0 {
            return None;
        }
        let overlaps = |s: u64, e: u64| pa < e && s < end;
        if boot::memory_map()
            .iter()
            .any(|r| is_ram(r.kind) && overlaps(r.base.as_u64(), r.end().as_u64()))
        {
            return None;
        }
        if overlaps(SYSTEM_DEVICES.0, SYSTEM_DEVICES.1) {
            return None;
        }
        let va = kspace::map_mmio(pa, len)?;
        Some(IoMem { va, len })
    }

    /// Size of the region in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn slot(&self, offset: u64, size: u64) -> Option<usize> {
        let end = offset.checked_add(size)?;
        (end <= self.len && offset.is_multiple_of(size)).then(|| (self.va + offset) as usize)
    }
}

/// The I/O ports of a device's BAR, from
/// [`PciDevice::map_ports`](crate::bus::pci::PciDevice::map_ports) only.
/// Accessors behave as [`IoMem`]'s do.
#[derive(Debug)]
pub struct IoPorts {
    base: u16,
    len: u16,
}

impl IoPorts {
    /// The ports below this are the platform's (frame drives the interrupt
    /// controllers, timers, the console and PCI configuration there).
    const PLATFORM: u32 = 0x1000;

    /// Frame-internal; see `PciDevice::map_ports`.
    pub(crate) fn new(base: u32, len: u32) -> Option<IoPorts> {
        let end = base.checked_add(len)?;
        let ours = base >= Self::PLATFORM && end <= 0x1_0000 && len != 0;
        Some(IoPorts {
            base: u16::try_from(base).ok().filter(|_| ours)?,
            len: u16::try_from(len).ok()?,
        })
    }

    fn slot(&self, offset: u64, size: u64) -> Option<u16> {
        let end = offset.checked_add(size)?;
        let inside = end <= u64::from(self.len) && offset.is_multiple_of(size);
        inside.then(|| self.base + offset as u16)
    }
}

macro_rules! port_accessors {
    ($($read:ident, $write:ident, $in:ident, $out:ident, $t:ty;)*) => {
        impl IoPorts {
            $(
                /// Reads the port at `offset` (all ones if out of range or
                /// misaligned).
                pub fn $read(&self, offset: u64) -> $t {
                    match self.slot(offset, core::mem::size_of::<$t>() as u64) {
                        // SAFETY: a port of this device's BAR (checked by
                        // `slot`), which only this `IoPorts` was given.
                        Some(port) => unsafe { crate::arch::io::$in(port) },
                        None => <$t>::MAX,
                    }
                }

                /// Writes the port at `offset` (dropped if out of range or
                /// misaligned).
                pub fn $write(&self, offset: u64, value: $t) {
                    if let Some(port) = self.slot(offset, core::mem::size_of::<$t>() as u64) {
                        // SAFETY: as in the read.
                        unsafe { crate::arch::io::$out(port, value) };
                    }
                }
            )*
        }
    };
}

port_accessors! {
    read8, write8, inb, outb, u8;
    read16, write16, inw, outw, u16;
    read32, write32, inl, outl, u32;
}

macro_rules! accessors {
    ($($read:ident, $write:ident, $t:ty;)*) => {
        impl IoMem {
            $(
                /// Volatile read at `offset` (all ones if out of range or
                /// misaligned).
                pub fn $read(&self, offset: u64) -> $t {
                    let Some(addr) = self.slot(offset, core::mem::size_of::<$t>() as u64) else {
                        return <$t>::MAX;
                    };
                    let p = core::ptr::with_exposed_provenance::<$t>(addr);
                    // SAFETY: `addr` is inside this mapping (checked by
                    // `slot`), naturally aligned, and maps device registers,
                    // which only volatile accesses touch.
                    unsafe { p.read_volatile() }
                }

                /// Volatile write at `offset` (dropped if out of range or
                /// misaligned).
                pub fn $write(&self, offset: u64, value: $t) {
                    let Some(addr) = self.slot(offset, core::mem::size_of::<$t>() as u64) else {
                        return;
                    };
                    let p = core::ptr::with_exposed_provenance_mut::<$t>(addr);
                    // SAFETY: as in the read: inside this mapping, aligned,
                    // device registers only.
                    unsafe { p.write_volatile(value) };
                }
            )*
        }
    };
}

accessors! {
    read8, write8, u8;
    read16, write16, u16;
    read32, write32, u32;
    read64, write64, u64;
}
