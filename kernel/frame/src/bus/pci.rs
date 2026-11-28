//! PCI devices (ADR-0005).
//!
//! Frame enumerates PCI once at boot and owns configuration space. Drivers
//! get [`PciDevice`]s: config *reads*, capability iteration, BAR
//! descriptions, one mediated write ([`PciDevice::enable`]), and
//! [`PciDevice::map_bar`] and [`PciDevice::map_ports`], which are the only
//! ways to obtain an [`IoMem`](crate::io::IoMem) and
//! [`IoPorts`](crate::io::IoPorts).

use alloc::vec::Vec;

use crate::arch::pci::{read32, write32};
use crate::io::{IoMem, IoPorts};
use crate::sync::SpinLock;

const COMMAND: u8 = 0x04;
const CMD_IO: u32 = 1 << 0;
const CMD_MEMORY: u32 = 1 << 1;
const CMD_BUS_MASTER: u32 = 1 << 2;
const STATUS_CAP_LIST: u32 = 1 << 20; // bit 4 of the status word (high half)
const CAP_POINTER: u8 = 0x34;
const BAR0: u8 = 0x10;

/// A base address register's decoded region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    /// Unimplemented, or the upper half of a 64-bit BAR.
    None,
    /// A memory-mapped region.
    Memory {
        base: u64,
        size: u64,
        prefetchable: bool,
    },
    /// An I/O-port region.
    Io { base: u32, size: u32 },
}

/// One PCI function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    bars: [Bar; 6],
}

static DEVICES: SpinLock<Vec<PciDevice>> = SpinLock::new(Vec::new());
/// BARs already handed out: (bus, device, function, bar).
static CLAIMED: SpinLock<Vec<(u8, u8, u8, usize)>> = SpinLock::new(Vec::new());

impl PciDevice {
    fn cfg(&self, offset: u8) -> u32 {
        read32(self.bus, self.device, self.function, offset)
    }

    /// Reads a 32-bit config register (offset rounded down to 4).
    pub fn read_config_u32(&self, offset: u8) -> u32 {
        self.cfg(offset)
    }

    /// Reads a 16-bit config register.
    pub fn read_config_u16(&self, offset: u8) -> u16 {
        (self.cfg(offset) >> ((offset & 2) * 8)) as u16
    }

    /// Reads an 8-bit config register.
    pub fn read_config_u8(&self, offset: u8) -> u8 {
        (self.cfg(offset) >> ((offset & 3) * 8)) as u8
    }

    /// The capability list as `(config offset, capability id)` pairs.
    pub fn capabilities(&self) -> impl Iterator<Item = (u8, u8)> + '_ {
        let mut next = if self.cfg(COMMAND) & STATUS_CAP_LIST != 0 {
            self.read_config_u8(CAP_POINTER) & 0xfc
        } else {
            0
        };
        let mut budget = 48; // bounded walk: a looping list cannot hang us
        core::iter::from_fn(move || {
            if next < 0x40 || budget == 0 {
                return None;
            }
            budget -= 1;
            let at = next;
            let id = self.read_config_u8(at);
            next = self.read_config_u8(at + 1) & 0xfc;
            Some((at, id))
        })
    }

    /// BAR `index` (0–5).
    pub fn bar(&self, index: usize) -> Bar {
        self.bars.get(index).copied().unwrap_or(Bar::None)
    }

    /// Enables memory decoding and/or bus mastering. This is the only config
    /// write drivers can make.
    pub fn enable(&self, memory: bool, bus_master: bool) {
        let mut cmd = self.cfg(COMMAND) & 0xffff;
        if memory {
            cmd |= CMD_MEMORY;
        }
        if bus_master {
            cmd |= CMD_BUS_MASTER;
        }
        write32(self.bus, self.device, self.function, COMMAND, cmd);
    }

    /// Maps memory BAR `index` as uncached MMIO. Fails for I/O or absent
    /// BARs, for a BAR already mapped, or if the BAR overlaps RAM.
    pub fn map_bar(&self, index: usize) -> Option<IoMem> {
        let Bar::Memory { base, size, .. } = self.bar(index) else {
            return None;
        };
        self.claim(index, || IoMem::map(base, size))
    }

    /// The ports of I/O BAR `index`, with port decoding on. Fails for other
    /// BARs, for a BAR already taken, or for ports that are the platform's.
    pub fn map_ports(&self, index: usize) -> Option<IoPorts> {
        let Bar::Io { base, size } = self.bar(index) else {
            return None;
        };
        let ports = self.claim(index, || IoPorts::new(base, size))?;
        let cmd = self.cfg(COMMAND) & 0xffff;
        write32(self.bus, self.device, self.function, COMMAND, cmd | CMD_IO);
        Some(ports)
    }

    /// What `map` gives for BAR `index`, once.
    fn claim<T>(&self, index: usize, map: impl FnOnce() -> Option<T>) -> Option<T> {
        let key = (self.bus, self.device, self.function, index);
        let mut claimed = CLAIMED.lock();
        if claimed.contains(&key) {
            return None;
        }
        let mapped = map()?;
        claimed.push(key);
        Some(mapped)
    }
}

/// Every PCI function found at boot.
pub fn devices() -> Vec<PciDevice> {
    DEVICES.lock().clone()
}

/// A memory BAR the firmware left without an address: (bus, device,
/// function, BAR, size, 64-bit, prefetchable).
type Unplaced = (u8, u8, u8, usize, u64, bool, bool);

/// The windows of the bridge to `bus`: memory, then prefetchable memory, as
/// (first, last) addresses (first > last if it has none).
fn windows(found: &[PciDevice], bus: u8) -> Option<[(u64, u64); 2]> {
    let b = found.iter().find(|d| {
        let cfg = |o| read32(d.bus, d.device, d.function, o);
        (cfg(0x0c) >> 16) & 0x7f == 1 && (cfg(0x18) >> 8) as u8 == bus
    })?;
    let cfg = |o| u64::from(read32(b.bus, b.device, b.function, o));
    let (mem, pf) = (cfg(0x20), cfg(0x24));
    let wide = |o| if pf & 0xf == 1 { cfg(o) << 32 } else { 0 };
    Some([
        ((mem & 0xfff0) << 16, (mem >> 16 & 0xfff0) << 16 | 0xfffff),
        (
            wide(0x28) | (pf & 0xfff0) << 16,
            wide(0x2c) | (pf >> 16 & 0xfff0) << 16 | 0xfffff,
        ),
    ])
}

/// Gives each unplaced BAR an address in its bridge's window, clear of
/// every other BAR, as an OS does when the firmware did not (AWS leaves
/// its network devices' BARs at 0). Decode is off while a BAR is written.
fn place(found: &mut [PciDevice], unplaced: &[Unplaced]) {
    let mut used: Vec<(u64, u64)> = found
        .iter()
        .flat_map(|d| d.bars)
        .filter_map(|b| match b {
            Bar::Memory { base, size, .. } => Some((base, base + size)),
            _ => None,
        })
        .collect();
    for &(bus, dev, func, i, size, is64, prefetchable) in unplaced {
        let Some(w) = windows(found, bus) else {
            continue;
        };
        let (lo, hi) = w[usize::from(prefetchable && is64 && w[1].0 <= w[1].1)];
        let mut at = lo.next_multiple_of(size);
        while let Some(&(_, end)) = used.iter().find(|&&(s, e)| s < at + size && at < e) {
            at = end.next_multiple_of(size);
        }
        if lo == 0 || at + size - 1 > hi || (!is64 && at + size > 1 << 32) {
            continue;
        }
        used.push((at, at + size));
        let (get, set) = (
            |o| read32(bus, dev, func, o),
            |o, v| write32(bus, dev, func, o, v),
        );
        let (cmd, off) = (get(COMMAND) & 0xffff, BAR0 + 4 * i as u8);
        set(COMMAND, cmd & !CMD_MEMORY);
        set(off, at as u32 | get(off) & 0xf);
        if is64 {
            set(off + 4, (at >> 32) as u32);
        }
        set(COMMAND, cmd);
        let base = at;
        for d in found.iter_mut().filter(|d| d.bus == bus && d.device == dev) {
            if d.function == func {
                d.bars[i] = Bar::Memory {
                    base,
                    size,
                    prefetchable,
                };
            }
        }
    }
}

/// Sizes the BARs of a type-0 function. Memory and I/O decode are off while
/// the all-ones pattern is in a BAR, and every BAR is restored. Memory BARs
/// without an address go on `unplaced`.
fn probe_bars(bus: u8, dev: u8, func: u8, unplaced: &mut Vec<Unplaced>) -> [Bar; 6] {
    let mut bars = [Bar::None; 6];
    let cmd = read32(bus, dev, func, COMMAND) & 0xffff;
    write32(bus, dev, func, COMMAND, cmd & !(CMD_IO | CMD_MEMORY));
    let mut i = 0;
    while i < 6 {
        let off = BAR0 + (i as u8) * 4;
        let orig = read32(bus, dev, func, off);
        write32(bus, dev, func, off, u32::MAX);
        let mask = read32(bus, dev, func, off);
        write32(bus, dev, func, off, orig);
        if orig & 1 == 1 {
            let m = mask & !0x3;
            if m != 0 {
                bars[i] = Bar::Io {
                    base: orig & !0x3,
                    size: (!m).wrapping_add(1) & 0xffff,
                };
            }
            i += 1;
            continue;
        }
        let is64 = (orig >> 1) & 0x3 == 0x2;
        let prefetchable = orig & 0x8 != 0;
        let (base, size) = if is64 && i < 5 {
            let off_hi = off + 4;
            let orig_hi = read32(bus, dev, func, off_hi);
            write32(bus, dev, func, off_hi, u32::MAX);
            let mask_hi = read32(bus, dev, func, off_hi);
            write32(bus, dev, func, off_hi, orig_hi);
            let base = (u64::from(orig_hi) << 32) | u64::from(orig & !0xf);
            let mask = (u64::from(mask_hi) << 32) | u64::from(mask & !0xf);
            (base, (!mask).wrapping_add(1))
        } else {
            let m = mask & !0xf;
            (u64::from(orig & !0xf), u64::from((!m).wrapping_add(1)))
        };
        if mask & !0xf != 0 && size != 0 && base != 0 {
            bars[i] = Bar::Memory {
                base,
                size,
                prefetchable,
            };
        } else if mask & !0xf != 0 && size.is_power_of_two() {
            unplaced.push((bus, dev, func, i, size, is64, prefetchable));
        }
        i += if is64 { 2 } else { 1 };
    }
    write32(bus, dev, func, COMMAND, cmd);
    bars
}

/// Enumerates the buses reachable from bus 0 (through the host bridge's
/// functions and every PCI-to-PCI bridge's secondary bus, as Linux scans a
/// root bus), or with `all`, every one of the 256 (ADR-0005's 2026-11-28
/// amendment: each probe of an absent bus is two VM exits, which made the
/// whole scan 140 ms of a boot under Hyper-V). Runs once at boot.
pub(crate) fn init(all: bool) -> usize {
    let mut found = Vec::new();
    let mut unplaced = Vec::new();
    let mut queued = [false; 256];
    let mut buses: Vec<u8> = if all {
        (0..=255).collect()
    } else {
        alloc::vec![0]
    };
    queued[0] = true;
    // A multi-function host bridge at 0:0: function N is the bridge of bus N.
    if !all && read32(0, 0, 0, 0) & 0xffff != 0xffff && (read32(0, 0, 0, 0x0c) >> 16) & 0x80 != 0 {
        for func in 1..8u8 {
            if read32(0, 0, func, 0) & 0xffff != 0xffff && !queued[usize::from(func)] {
                queued[usize::from(func)] = true;
                buses.push(func);
            }
        }
    }
    let mut next = 0;
    while let Some(&bus) = buses.get(next) {
        next += 1;
        for dev in 0..32u8 {
            if read32(bus, dev, 0, 0) & 0xffff == 0xffff {
                continue;
            }
            let multi = (read32(bus, dev, 0, 0x0c) >> 16) & 0x80 != 0;
            for func in 0..if multi { 8 } else { 1 } {
                let id = read32(bus, dev, func, 0);
                if id & 0xffff == 0xffff {
                    continue;
                }
                let class = read32(bus, dev, func, 0x08);
                let header_type = (read32(bus, dev, func, 0x0c) >> 16) & 0x7f;
                let bars = if header_type == 0 {
                    probe_bars(bus, dev, func, &mut unplaced)
                } else {
                    [Bar::None; 6]
                };
                // A PCI-to-PCI bridge: scan its secondary bus too (the
                // number the firmware or VMM gave it; 0 means none).
                if header_type == 1 && !all {
                    let secondary = (read32(bus, dev, func, 0x18) >> 8) as u8;
                    if secondary != 0 && !queued[usize::from(secondary)] {
                        queued[usize::from(secondary)] = true;
                        buses.push(secondary);
                    }
                }
                found.push(PciDevice {
                    bus,
                    device: dev,
                    function: func,
                    vendor_id: id as u16,
                    device_id: (id >> 16) as u16,
                    class: (class >> 24) as u8,
                    subclass: (class >> 16) as u8,
                    prog_if: (class >> 8) as u8,
                    bars,
                });
            }
        }
    }
    place(&mut found, &unplaced);
    let n = found.len();
    *DEVICES.lock() = found;
    n
}
