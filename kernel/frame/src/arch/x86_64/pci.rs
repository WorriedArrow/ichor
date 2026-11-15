//! PCI configuration-space access through the legacy 0xCF8/0xCFC ports.
//! Frame owns both ports; nothing outside frame can reach config space
//! except through the mediated `frame::bus::pci` API (ADR-0005).

use super::io::{inl, outl};
use crate::sync::SpinLock;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

/// Serializes the address/data port pair.
static CONFIG_LOCK: SpinLock<()> = SpinLock::new(());

fn address(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    0x8000_0000
        | (u32::from(bus) << 16)
        | (u32::from(dev & 0x1f) << 11)
        | (u32::from(func & 0x7) << 8)
        | u32::from(offset & 0xfc)
}

/// Reads a 32-bit config register (offset rounded down to 4).
pub(crate) fn read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let _g = CONFIG_LOCK.lock();
    // SAFETY: frame owns ports 0xCF8/0xCFC (ADR-0005); selecting a config
    // register has no effect beyond the following data access.
    unsafe { outl(CONFIG_ADDRESS, address(bus, dev, func, offset)) };
    // SAFETY: as above; reading the data port returns the selected register.
    unsafe { inl(CONFIG_DATA) }
}

/// Writes a 32-bit config register. Frame-internal: callers must keep the
/// device's BARs pointing at MMIO, never RAM (ADR-0005).
pub(crate) fn write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    let _g = CONFIG_LOCK.lock();
    // SAFETY: as in `read32`.
    unsafe { outl(CONFIG_ADDRESS, address(bus, dev, func, offset)) };
    // SAFETY: frame callers only write the command register and, while
    // memory decode is off, BAR sizing patterns that they restore.
    unsafe { outl(CONFIG_DATA, value) };
}
