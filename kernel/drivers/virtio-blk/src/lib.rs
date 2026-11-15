//! virtio-blk over the modern (virtio 1.x) PCI transport, polled.
//!
//! Safe code only: registers are reached through frame's bounds-checked
//! `IoMem`, buffers are `DmaBuf`s, and descriptors are written by frame's
//! `VirtQueue`, so this driver never handles a bus address (ADR-0005).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use block::{BlockDevice, BlockError, SECTOR_SIZE, check};
use frame::bus::pci::{self, PciDevice};
use frame::dma::DmaBuf;
use frame::io::IoMem;
use frame::virtio::{Segment, VirtQueue};

const VENDOR_VIRTIO: u16 = 0x1af4;
const DEVICE_BLK_MODERN: u16 = 0x1042;
const DEVICE_BLK_TRANSITIONAL: u16 = 0x1001;

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
const F_VERSION_1_HI: u32 = 1; // feature bit 32

const REQ_IN: u32 = 0;
const MAX_QUEUE: u16 = 64;
/// Largest single request (a power of two the DMA allocator can satisfy).
const MAX_REQUEST: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Why the device could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    MissingCapability,
    MapFailed,
    NoVersion1,
    FeaturesRejected,
    NoQueue,
    NoMemory,
}

/// A register window: one of the mapped BARs plus an offset.
#[derive(Clone, Copy, Debug)]
struct Window {
    bar: usize,
    offset: u64,
}

/// The mapped BARs and the device configuration window.
#[derive(Debug)]
struct Regs {
    bars: Vec<(u8, IoMem)>,
    device: Window,
}

impl Regs {
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

/// A virtio-blk device.
#[derive(Debug)]
pub struct VirtioBlk {
    regs: Regs,
    notify_at: Window,
    queue: VirtQueue,
    capacity: u64,
}

/// Finds and initializes the first virtio-blk device.
pub fn probe() -> Option<Result<VirtioBlk, InitError>> {
    let dev = pci::devices().into_iter().find(|d| {
        d.vendor_id == VENDOR_VIRTIO
            && matches!(d.device_id, DEVICE_BLK_MODERN | DEVICE_BLK_TRANSITIONAL)
    })?;
    Some(VirtioBlk::init(&dev))
}

impl VirtioBlk {
    fn init(dev: &PciDevice) -> Result<VirtioBlk, InitError> {
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
        let (Some(common), Some(device), Some(notify)) = (common, device, notify) else {
            return Err(InitError::MissingCapability);
        };
        let regs = Regs { bars, device };
        let c = common;

        regs.w8(c, DEVICE_STATUS, 0);
        let deadline = frame::time::now() + TIMEOUT;
        while regs.r8(c, DEVICE_STATUS) != 0 && frame::time::now() < deadline {
            core::hint::spin_loop();
        }
        regs.w8(c, DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        regs.w32(c, DEVICE_FEATURE_SELECT, 1);
        if regs.r32(c, DEVICE_FEATURE) & F_VERSION_1_HI == 0 {
            return Err(InitError::NoVersion1);
        }
        regs.w32(c, DRIVER_FEATURE_SELECT, 0);
        regs.w32(c, DRIVER_FEATURE, 0);
        regs.w32(c, DRIVER_FEATURE_SELECT, 1);
        regs.w32(c, DRIVER_FEATURE, F_VERSION_1_HI);
        let status = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
        regs.w8(c, DEVICE_STATUS, status);
        if regs.r8(c, DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
            return Err(InitError::FeaturesRejected);
        }

        regs.w16(c, QUEUE_SELECT, 0);
        let max = regs.r16(c, QUEUE_SIZE);
        if max == 0 || max == u16::MAX {
            return Err(InitError::NoQueue);
        }
        // Largest power of two not above min(max, MAX_QUEUE).
        let cap = MAX_QUEUE.min(max);
        let size = 1u16 << (15 - cap.leading_zeros());
        let queue = VirtQueue::new(size).ok_or(InitError::NoMemory)?;
        regs.w16(c, QUEUE_SIZE, size);
        let (desc, avail, used) = queue.addresses();
        regs.w64(c, QUEUE_DESC, desc.as_u64());
        regs.w64(c, QUEUE_DRIVER, avail.as_u64());
        regs.w64(c, QUEUE_DEVICE, used.as_u64());
        let notify_off = u64::from(regs.r16(c, QUEUE_NOTIFY_OFF));
        let notify_at = Window {
            bar: notify.bar,
            offset: notify.offset + notify_off * u64::from(multiplier),
        };
        regs.w16(c, QUEUE_ENABLE, 1);
        regs.w8(c, DEVICE_STATUS, status | STATUS_DRIVER_OK);

        let d = regs.device;
        let capacity = u64::from(regs.r32(d, 0)) | (u64::from(regs.r32(d, 4)) << 32);
        Ok(VirtioBlk {
            regs,
            notify_at,
            queue,
            capacity,
        })
    }

    /// Reads up to `MAX_REQUEST` bytes in one request.
    fn read_one(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let header = DmaBuf::alloc(17).ok_or(BlockError::NoMemory)?;
        header.write_u32(0, REQ_IN);
        header.write_u32(4, 0);
        header.write_u64(8, sector);
        header.write(16, &[0xff]);
        let data = DmaBuf::alloc(buf.len()).ok_or(BlockError::NoMemory)?;
        let segs = [
            Segment {
                buf: &header,
                offset: 0,
                len: 16,
                device_writes: false,
            },
            Segment {
                buf: &data,
                offset: 0,
                len: buf.len(),
                device_writes: true,
            },
            Segment {
                buf: &header,
                offset: 16,
                len: 1,
                device_writes: true,
            },
        ];
        let token = self.queue.submit(&segs).map_err(|_| BlockError::Io)?;
        self.regs.w16(self.notify_at, 0, 0);
        let deadline = frame::time::now() + TIMEOUT;
        loop {
            if let Some((done, _)) = self.queue.poll() {
                if done == token {
                    break;
                }
                continue;
            }
            if frame::time::now() >= deadline {
                return Err(BlockError::Timeout);
            }
            core::hint::spin_loop();
        }
        let mut status = [0u8; 1];
        header.read(16, &mut status);
        if status[0] != 0 {
            return Err(BlockError::Io);
        }
        data.read(0, buf);
        Ok(())
    }
}

impl BlockDevice for VirtioBlk {
    fn sector_count(&self) -> u64 {
        self.capacity
    }

    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check(self, sector, buf.len())?;
        let mut done = 0;
        while done < buf.len() {
            let n = MAX_REQUEST.min(buf.len() - done);
            let s = sector + (done / SECTOR_SIZE) as u64;
            self.read_one(s, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }
}
