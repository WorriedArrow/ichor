//! virtio-blk over the modern (virtio 1.x) PCI transport, polled.
//!
//! Safe code only: the transport is `virtio-pci`, buffers are `DmaBuf`s,
//! and descriptors are written by frame's `VirtQueue`, so this driver
//! never handles a bus address (ADR-0005).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::time::Duration;

use block::{BlockDevice, BlockError, SECTOR_SIZE, check};
use frame::dma::DmaBuf;
use frame::virtio::{Segment, VirtQueue};
use virtio_pci::{Notifier, Transport};

pub use virtio_pci::InitError;

const DEVICE_BLK_MODERN: u16 = 0x1042;
const DEVICE_BLK_TRANSITIONAL: u16 = 0x1001;

const REQ_IN: u32 = 0;
const MAX_QUEUE: u16 = 64;
/// Largest single request (a power of two the DMA allocator can satisfy).
const MAX_REQUEST: usize = 64 * 1024;
/// How long one request may take (as NVMe's commands: a busy host, or a
/// cloud disk, can be slow).
const TIMEOUT: Duration = Duration::from_secs(30);

/// A virtio-blk device.
#[derive(Debug)]
pub struct VirtioBlk {
    transport: Transport,
    notifier: Notifier,
    queue: VirtQueue,
    capacity: u64,
}

/// Finds and initializes the first virtio-blk device.
pub fn probe() -> Option<Result<VirtioBlk, InitError>> {
    probe_all().into_iter().next()
}

/// Finds and initializes every virtio-blk device, in PCI order.
pub fn probe_all() -> Vec<Result<VirtioBlk, InitError>> {
    virtio_pci::find(&[DEVICE_BLK_MODERN, DEVICE_BLK_TRANSITIONAL])
        .iter()
        .map(VirtioBlk::init)
        .collect()
}

impl VirtioBlk {
    fn init(dev: &frame::bus::pci::PciDevice) -> Result<VirtioBlk, InitError> {
        let (transport, _) = Transport::new(dev, 0)?;
        let (queue, notifier) = transport.queue(0, MAX_QUEUE)?;
        transport.driver_ok();
        let capacity =
            u64::from(transport.device_r32(0)) | (u64::from(transport.device_r32(4)) << 32);
        Ok(VirtioBlk {
            transport,
            notifier,
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
        self.transport.notify(self.notifier, 0);
        let deadline = frame::time::now() + TIMEOUT;
        loop {
            if let Some((done, _)) = self.queue.poll() {
                if done == token {
                    break;
                }
                continue;
            }
            if frame::time::now() >= deadline {
                // The device still owns the buffers and may write them
                // later: leak them rather than free memory it could
                // scribble on once it is someone else's.
                frame::println!(
                    "ichor: virtio-blk: request for sector {sector} timed out after {} s",
                    TIMEOUT.as_secs()
                );
                core::mem::forget(header);
                core::mem::forget(data);
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
