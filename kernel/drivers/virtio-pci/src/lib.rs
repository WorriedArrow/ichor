//! The modern (virtio 1.x) PCI transport, shared by the virtio drivers.
//!
//! Safe code only: registers are reached through frame's bounds-checked
//! `IoMem`, and queues are frame's `VirtQueue`, so a driver never handles a
//! bus address (ADR-0005). A driver finds its device with [`find`], brings
//! it up with [`Transport::new`] (reset, feature negotiation), sets up its
//! queues with [`Transport::queue`], calls [`Transport::driver_ok`], and then
//! notifies the device after each submission.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use frame::bus::pci::{self, PciDevice};
use frame::io::IoMem;
use frame::virtio::VirtQueue;

/// The PCI vendor id of every virtio device.
pub const VENDOR_VIRTIO: u16 = 0x1af4;

const CAP_VENDOR: u8 = 0x09;
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_DEVICE: u8 = 4;

// Common configuration registers.
const DEVICE_FEATURE_SELECT: u64 = 0;
const DEVICE_FEATURE: u64 = 4;
const DRIVER_FEATURE_SELECT: u64 = 8;
const DRIVER_FEATURE: u64 = 12;
const DEVICE_STATUS: u64 = 20;
const QUEUE_SELECT: u64 = 22;
const QUEUE_SIZE: u64 = 24;
const QUEUE_ENABLE: u64 = 28;
const QUEUE_NOTIFY_OFF: u64 = 30;
const QUEUE_DESC: u64 = 32;
const QUEUE_DRIVER: u64 = 40;
const QUEUE_DEVICE: u64 = 48;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
/// `VIRTIO_F_VERSION_1` (feature bit 32).
const F_VERSION_1_HI: u32 = 1;

const RESET_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a device could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    MissingCapability,
    MapFailed,
    NoVersion1,
    FeaturesRejected,
    NoQueue,
    NoMemory,
}

/// The virtio devices with one of `device_ids`, in PCI order.
pub fn find(device_ids: &[u16]) -> Vec<PciDevice> {
    pci::devices()
        .into_iter()
        .filter(|d| d.vendor_id == VENDOR_VIRTIO && device_ids.contains(&d.device_id))
        .collect()
}

/// A register window: one of the mapped BARs plus an offset.
#[derive(Clone, Copy, Debug)]
struct Window {
    bar: usize,
    offset: u64,
}

/// Where to notify the device about one queue.
#[derive(Clone, Copy, Debug)]
pub struct Notifier(Window);

/// A device's registers: the mapped BARs and the configuration windows.
#[derive(Debug)]
pub struct Transport {
    bars: Vec<(u8, IoMem)>,
    common: Window,
    device: Window,
    notify: Window,
    multiplier: u32,
}

impl Transport {
    /// Resets `dev` and negotiates features: `VIRTIO_F_VERSION_1` plus the
    /// low 32 feature bits in `features` that the device offers. Returns
    /// the transport and the low feature bits accepted.
    pub fn new(dev: &PciDevice, features: u32) -> Result<(Transport, u32), InitError> {
        dev.enable(true, true);
        let mut bars: Vec<(u8, IoMem)> = Vec::new();
        let mut window = |bar: u8, offset: u32| -> Result<Window, InitError> {
            let idx = match bars.iter().position(|(b, _)| *b == bar) {
                Some(i) => i,
                None => {
                    let m = dev.map_bar(usize::from(bar)).ok_or(InitError::MapFailed)?;
                    bars.push((bar, m));
                    bars.len() - 1
                }
            };
            Ok(Window {
                bar: idx,
                offset: u64::from(offset),
            })
        };
        let (mut common, mut device, mut notify) = (None, None, None);
        let mut multiplier = 0u32;
        let caps: Vec<(u8, u8)> = dev.capabilities().collect();
        for (at, id) in caps {
            if id != CAP_VENDOR {
                continue;
            }
            let cfg_type = dev.read_config_u8(at.saturating_add(3));
            let bar = dev.read_config_u8(at.saturating_add(4));
            let offset = dev.read_config_u32(at.saturating_add(8));
            match cfg_type {
                CFG_COMMON if common.is_none() => common = Some(window(bar, offset)?),
                CFG_DEVICE if device.is_none() => device = Some(window(bar, offset)?),
                CFG_NOTIFY if notify.is_none() => {
                    multiplier = dev.read_config_u32(at.saturating_add(16));
                    notify = Some(window(bar, offset)?);
                }
                _ => {}
            }
        }
        // Devices without device-specific configuration (virtio-rng) have
        // no CFG_DEVICE window; reads from it then return all ones.
        let (Some(common), Some(notify)) = (common, notify) else {
            return Err(InitError::MissingCapability);
        };
        let t = Transport {
            bars,
            common,
            device: device.unwrap_or(Window {
                bar: usize::MAX,
                offset: 0,
            }),
            notify,
            multiplier,
        };
        let c = t.common;
        t.w8(c, DEVICE_STATUS, 0);
        let deadline = frame::time::now() + RESET_TIMEOUT;
        while t.r8(c, DEVICE_STATUS) != 0 && frame::time::now() < deadline {
            core::hint::spin_loop();
        }
        t.w8(c, DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        t.w32(c, DEVICE_FEATURE_SELECT, 1);
        if t.r32(c, DEVICE_FEATURE) & F_VERSION_1_HI == 0 {
            return Err(InitError::NoVersion1);
        }
        t.w32(c, DEVICE_FEATURE_SELECT, 0);
        let accepted = t.r32(c, DEVICE_FEATURE) & features;
        t.w32(c, DRIVER_FEATURE_SELECT, 0);
        t.w32(c, DRIVER_FEATURE, accepted);
        t.w32(c, DRIVER_FEATURE_SELECT, 1);
        t.w32(c, DRIVER_FEATURE, F_VERSION_1_HI);
        let status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
        t.w8(c, DEVICE_STATUS, status);
        if t.r8(c, DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
            return Err(InitError::FeaturesRejected);
        }
        Ok((t, accepted))
    }

    /// Sets up queue `index` with at most `max` entries (rounded down to a
    /// power of two the device allows).
    pub fn queue(&self, index: u16, max: u16) -> Result<(VirtQueue, Notifier), InitError> {
        let c = self.common;
        self.w16(c, QUEUE_SELECT, index);
        let dev_max = self.r16(c, QUEUE_SIZE);
        if dev_max == 0 || dev_max == u16::MAX {
            return Err(InitError::NoQueue);
        }
        let cap = max.min(dev_max).max(1);
        let size = 1u16 << (15 - cap.leading_zeros());
        let queue = VirtQueue::new(size).ok_or(InitError::NoMemory)?;
        self.w16(c, QUEUE_SIZE, size);
        let (desc, avail, used) = queue.addresses();
        self.w64(c, QUEUE_DESC, desc.as_u64());
        self.w64(c, QUEUE_DRIVER, avail.as_u64());
        self.w64(c, QUEUE_DEVICE, used.as_u64());
        let off = u64::from(self.r16(c, QUEUE_NOTIFY_OFF));
        let at = Window {
            bar: self.notify.bar,
            offset: self.notify.offset + off * u64::from(self.multiplier),
        };
        self.w16(c, QUEUE_ENABLE, 1);
        Ok((queue, Notifier(at)))
    }

    /// Tells the device the driver is ready (after its queues are set up).
    pub fn driver_ok(&self) {
        let status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK;
        self.w8(self.common, DEVICE_STATUS, status);
    }

    /// Tells the device that queue `index` (behind `n`) has new buffers.
    pub fn notify(&self, n: Notifier, index: u16) {
        self.w16(n.0, 0, index);
    }

    /// Reads 32 bits of device-specific configuration.
    pub fn device_r32(&self, off: u64) -> u32 {
        self.r32(self.device, off)
    }

    fn mem(&self, w: Window) -> Option<&IoMem> {
        self.bars.get(w.bar).map(|(_, m)| m)
    }
    fn r8(&self, w: Window, off: u64) -> u8 {
        self.mem(w).map_or(u8::MAX, |m| m.read8(w.offset + off))
    }
    fn w8(&self, w: Window, off: u64, v: u8) {
        if let Some(m) = self.mem(w) {
            m.write8(w.offset + off, v);
        }
    }
    fn r16(&self, w: Window, off: u64) -> u16 {
        self.mem(w).map_or(u16::MAX, |m| m.read16(w.offset + off))
    }
    fn w16(&self, w: Window, off: u64, v: u16) {
        if let Some(m) = self.mem(w) {
            m.write16(w.offset + off, v);
        }
    }
    fn r32(&self, w: Window, off: u64) -> u32 {
        self.mem(w).map_or(u32::MAX, |m| m.read32(w.offset + off))
    }
    fn w32(&self, w: Window, off: u64, v: u32) {
        if let Some(m) = self.mem(w) {
            m.write32(w.offset + off, v);
        }
    }
    fn w64(&self, w: Window, off: u64, v: u64) {
        self.w32(w, off, v as u32);
        self.w32(w, off + 4, (v >> 32) as u32);
    }
}
