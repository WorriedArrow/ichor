//! virtio-scsi (virtio 1.x §5.6) over the modern PCI transport, polled:
//! the disks behind a virtio-scsi controller as read-only block devices.
//! GCP's general-purpose machine types (E2, N1, N2, ...) attach their
//! persistent disks this way, as targets of one controller.
//!
//! One request queue (queue 2; the control and event queues are set up
//! but given no buffers, so the device drops events, which a polled,
//! read-only driver does not need). At probe every target's LUN 0 gets an
//! INQUIRY; each direct-access disk gets TEST UNIT READY (a fresh device
//! reports a unit attention first) and READ CAPACITY, (16) when (10)
//! saturates. Reads are READ(10), or READ(16) past 2^32 blocks, of at
//! most [`MAX_REQUEST`] bytes. The disks of one controller share its
//! queue through a mutex.
//!
//! Safe code only: buffers are `DmaBuf`s and descriptors are written by
//! frame's `VirtQueue` (ADR-0005).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use block::{BlockDevice, BlockError, SECTOR_SIZE, check};
use frame::dma::DmaBuf;
use frame::sync::Mutex;
use frame::virtio::{Segment, VirtQueue};
use virtio_pci::{Notifier, Transport};

pub use virtio_pci::InitError;

const DEVICE_SCSI_MODERN: u16 = 0x1048;
const DEVICE_SCSI_TRANSITIONAL: u16 = 0x1004;

const CONTROL_QUEUE: u16 = 0;
const EVENT_QUEUE: u16 = 1;
const REQUEST_QUEUE: u16 = 2;
const QUEUE_SIZE: u16 = 64;
/// Largest single read.
pub const MAX_REQUEST: usize = 64 * 1024;
/// How long one command may take (a busy host, or a cloud disk).
const TIMEOUT: Duration = Duration::from_secs(30);
/// Targets scanned at most (QEMU offers 256; clouds attach a handful).
const MAX_TARGETS: u16 = 256;

/// `virtio_scsi_config` offsets (in the device configuration).
const CFG_SENSE_SIZE: u64 = 20;
const CFG_CDB_SIZE: u64 = 24;
const CFG_MAX_TARGET: u64 = 28; // u16 max_channel, then u16 max_target

/// `virtio_scsi_resp_cmd.response`.
const S_OK: u8 = 0;
const S_BAD_TARGET: u8 = 3;

/// SCSI status bytes.
const GOOD: u8 = 0;

/// SCSI opcodes.
const TEST_UNIT_READY: u8 = 0x00;
const INQUIRY: u8 = 0x12;
const READ_CAPACITY_10: u8 = 0x25;
const READ_10: u8 = 0x28;
const READ_16: u8 = 0x88;
const SERVICE_ACTION_IN_16: u8 = 0x9e;
const READ_CAPACITY_16: u8 = 0x10;

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ended {
    /// The command ran: its SCSI status (GOOD, CHECK CONDITION, ...).
    Ran(u8),
    /// No device at that target.
    NoTarget,
    /// The transport failed it (`response`).
    Failed(u8),
}

/// One controller: its request queue, shared by its disks.
#[derive(Debug)]
struct Hba {
    transport: Transport,
    notifier: Notifier,
    queue: VirtQueue,
    // Kept so the device has them, though they carry no buffers.
    _control: VirtQueue,
    _event: VirtQueue,
    cdb_size: usize,
    sense_size: usize,
    next_tag: u64,
}

impl Hba {
    fn init(dev: &frame::bus::pci::PciDevice) -> Result<Hba, InitError> {
        let (transport, _) = Transport::new(dev, 0)?;
        let (control, _) = transport.queue(CONTROL_QUEUE, 8)?;
        let (event, _) = transport.queue(EVENT_QUEUE, 8)?;
        let (queue, notifier) = transport.queue(REQUEST_QUEUE, QUEUE_SIZE)?;
        transport.driver_ok();
        // The sizes the device uses by default (the spec's 96 and 32);
        // bounded so a strange device cannot make the headers huge.
        let sense_size = (transport.device_r32(CFG_SENSE_SIZE) as usize).clamp(18, 252);
        let cdb_size = (transport.device_r32(CFG_CDB_SIZE) as usize).clamp(16, 252);
        Ok(Hba {
            transport,
            notifier,
            queue,
            _control: control,
            _event: event,
            cdb_size,
            sense_size,
            next_tag: 1,
        })
    }

    fn max_target(&self) -> u16 {
        (self.transport.device_r32(CFG_MAX_TARGET) >> 16) as u16
    }

    /// Runs `cdb` on LUN 0 of `target`, reading up to `data.len()` bytes
    /// into `data`.
    fn command(&mut self, target: u16, cdb: &[u8], data: &mut [u8]) -> Result<Ended, BlockError> {
        // virtio_scsi_req_cmd: lun[8], id, task_attr, prio, crn, cdb[].
        let req_len = 19 + self.cdb_size;
        let resp_len = 12 + self.sense_size;
        let req = DmaBuf::alloc(req_len).ok_or(BlockError::NoMemory)?;
        let lun = [1, target as u8, 0x40, 0, 0, 0, 0, 0]; // flat LUN 0
        req.write(0, &lun);
        req.write_u64(8, self.next_tag);
        self.next_tag = self.next_tag.wrapping_add(1);
        req.write(16, &[0, 0, 0]); // SIMPLE, no priority, no CRN
        req.write(19, &cdb[..cdb.len().min(self.cdb_size)]);
        let resp = DmaBuf::alloc(resp_len).ok_or(BlockError::NoMemory)?;
        let buf = if data.is_empty() {
            None
        } else {
            Some(DmaBuf::alloc(data.len()).ok_or(BlockError::NoMemory)?)
        };
        let mut segs = alloc::vec![
            Segment {
                buf: &req,
                offset: 0,
                len: req_len,
                device_writes: false,
            },
            Segment {
                buf: &resp,
                offset: 0,
                len: resp_len,
                device_writes: true,
            },
        ];
        if let Some(b) = &buf {
            segs.push(Segment {
                buf: b,
                offset: 0,
                len: data.len(),
                device_writes: true,
            });
        }
        let token = self.queue.submit(&segs).map_err(|_| BlockError::Io)?;
        self.transport.notify(self.notifier, REQUEST_QUEUE);
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
                // later: leak them rather than free memory it could write.
                frame::println!(
                    "ichor: virtio-scsi: command {:#04x} to target {target} timed out after {} s",
                    cdb.first().copied().unwrap_or(0),
                    TIMEOUT.as_secs()
                );
                core::mem::forget(req);
                core::mem::forget(resp);
                core::mem::forget(buf);
                return Err(BlockError::Timeout);
            }
            core::hint::spin_loop();
        }
        // virtio_scsi_resp_cmd: sense_len, resid, status_qualifier, status,
        // response, sense[].
        let mut tail = [0u8; 2];
        resp.read(10, &mut tail);
        let (status, response) = (tail[0], tail[1]);
        Ok(match response {
            S_OK => {
                if let Some(b) = &buf {
                    b.read(0, data);
                }
                Ended::Ran(status)
            }
            S_BAD_TARGET => Ended::NoTarget,
            r => Ended::Failed(r),
        })
    }
}

/// A disk behind a virtio-scsi controller (LUN 0 of one target).
#[derive(Debug)]
pub struct ScsiDisk {
    hba: Arc<Mutex<Hba>>,
    target: u16,
    blocks: u64,
    block_shift: u32,
}

/// Every disk behind every virtio-scsi controller, in PCI and target
/// order. A controller that fails to initialize is one `Err`.
pub fn probe_all() -> Vec<Result<ScsiDisk, InitError>> {
    let mut out = Vec::new();
    for dev in virtio_pci::find(&[DEVICE_SCSI_MODERN, DEVICE_SCSI_TRANSITIONAL]) {
        match Hba::init(&dev) {
            Ok(hba) => out.extend(disks(hba).into_iter().map(Ok)),
            Err(e) => out.push(Err(e)),
        }
    }
    out
}

/// The direct-access disks of one controller.
fn disks(hba: Hba) -> Vec<ScsiDisk> {
    let hba = Arc::new(Mutex::new(hba));
    let last = hba.lock().max_target().min(MAX_TARGETS - 1);
    let mut found = Vec::new();
    for target in 0..=last {
        let mut h = hba.lock();
        let mut inq = [0u8; 36];
        let cdb = [INQUIRY, 0, 0, 0, inq.len() as u8, 0];
        match h.command(target, &cdb, &mut inq) {
            Ok(Ended::Ran(GOOD)) => {}
            _ => continue,
        }
        // Peripheral qualifier 0 (connected), device type 0 (disk).
        if inq[0] != 0 {
            continue;
        }
        // A fresh device answers its first command with a unit attention.
        let ready = (0..4).any(|_| {
            matches!(
                h.command(target, &[TEST_UNIT_READY, 0, 0, 0, 0, 0], &mut []),
                Ok(Ended::Ran(GOOD))
            )
        });
        if !ready {
            frame::println!("ichor: virtio-scsi: target {target} is not ready; skipped");
            continue;
        }
        let Some((blocks, block_len)) = capacity(&mut h, target) else {
            frame::println!("ichor: virtio-scsi: target {target}: no capacity; skipped");
            continue;
        };
        if !block_len.is_power_of_two() || !(512..=4096).contains(&block_len) {
            frame::println!(
                "ichor: virtio-scsi: target {target}: {block_len}-byte blocks; skipped"
            );
            continue;
        }
        drop(h);
        found.push(ScsiDisk {
            hba: hba.clone(),
            target,
            blocks,
            block_shift: block_len.trailing_zeros(),
        });
    }
    found
}

/// The disk's block count and block length: READ CAPACITY (10), or (16)
/// for a disk of 2^32 blocks or more.
fn capacity(h: &mut Hba, target: u16) -> Option<(u64, u32)> {
    let mut d = [0u8; 8];
    let cdb = [READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if h.command(target, &cdb, &mut d).ok()? != Ended::Ran(GOOD) {
        return None;
    }
    let last = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    let len = u32::from_be_bytes([d[4], d[5], d[6], d[7]]);
    if last != u32::MAX {
        return Some((u64::from(last) + 1, len));
    }
    let mut d = [0u8; 32];
    let mut cdb = [0u8; 16];
    cdb[0] = SERVICE_ACTION_IN_16;
    cdb[1] = READ_CAPACITY_16;
    cdb[10..14].copy_from_slice(&(d.len() as u32).to_be_bytes());
    if h.command(target, &cdb, &mut d).ok()? != Ended::Ran(GOOD) {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[0..8]);
    let last = u64::from_be_bytes(b);
    let len = u32::from_be_bytes([d[8], d[9], d[10], d[11]]);
    Some((last.checked_add(1)?, len))
}

impl ScsiDisk {
    /// The disk's target number on its controller.
    pub fn target(&self) -> u16 {
        self.target
    }

    /// The disk's block size in bytes.
    pub fn block_size(&self) -> usize {
        1 << self.block_shift
    }

    /// Reads whole blocks from `lba` into `buf` (at most `MAX_REQUEST`).
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let count = (buf.len() >> self.block_shift) as u32;
        let mut cdb = [0u8; 16];
        let cdb: &[u8] = match u32::try_from(lba) {
            Ok(l) if count <= u32::from(u16::MAX) && l.checked_add(count).is_some() => {
                cdb[0] = READ_10;
                cdb[2..6].copy_from_slice(&l.to_be_bytes());
                cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
                &cdb[..10]
            }
            _ => {
                cdb[0] = READ_16;
                cdb[2..10].copy_from_slice(&lba.to_be_bytes());
                cdb[10..14].copy_from_slice(&count.to_be_bytes());
                &cdb[..16]
            }
        };
        match self.hba.lock().command(self.target, cdb, buf)? {
            Ended::Ran(GOOD) => Ok(()),
            Ended::Ran(_) | Ended::NoTarget | Ended::Failed(_) => Err(BlockError::Io),
        }
    }
}

impl BlockDevice for ScsiDisk {
    fn sector_count(&self) -> u64 {
        self.blocks << (self.block_shift - 9)
    }

    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check(self, sector, buf.len())?;
        let block = self.block_size();
        let byte = sector * SECTOR_SIZE as u64;
        if !byte.is_multiple_of(block as u64) || !buf.len().is_multiple_of(block) {
            return Err(BlockError::Unaligned);
        }
        let mut done = 0;
        while done < buf.len() {
            let n = MAX_REQUEST.min(buf.len() - done);
            let lba = (byte + done as u64) >> self.block_shift;
            self.read_blocks(lba, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }
}
