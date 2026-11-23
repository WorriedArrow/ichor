//! virtio-scsi (virtio 1.x §5.6), polled:
//! the disks behind a virtio-scsi controller as read-only block devices.
//! GCP's general-purpose machine types (E2, N1, N2, ...) attach their
//! persistent disks this way, as targets of one controller.
//!
//! One request queue (queue 2; the control and event queues are set up
//! but given no buffers, so the device drops events, which a polled,
//! read-only driver does not need). At probe every target's LUN 0 is looked
//! at (`block::scsi`). Reads are of at most [`MAX_REQUEST`] bytes. The disks
//! of one controller share its queue through a mutex.
//!
//! Safe code only: buffers are `DmaBuf`s and descriptors are written by
//! frame's `VirtQueue` (ADR-0005).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use block::BlockError;
use block::scsi::{self, Ended, Found};
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

/// LUN 0 of one target of a controller.
#[derive(Debug)]
pub struct Target {
    hba: Arc<Mutex<Hba>>,
    pub target: u16,
}

impl scsi::Unit for Target {
    fn command(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<Ended, BlockError> {
        self.hba.lock().command(self.target, cdb, data)
    }
}

/// A disk behind a virtio-scsi controller.
pub type ScsiDisk = scsi::Disk<Target>;

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
    let last = hba.max_target().min(MAX_TARGETS - 1);
    let hba = Arc::new(Mutex::new(hba));
    let mut found = Vec::new();
    for target in 0..=last {
        let mut unit = Target {
            hba: hba.clone(),
            target,
        };
        match scsi::probe(&mut unit) {
            Found::Nothing => {}
            Found::Unusable(why) => {
                frame::println!("ichor: virtio-scsi: target {target}: {why}; skipped");
            }
            Found::Disk(geometry) => found.push(scsi::Disk {
                unit,
                geometry,
                max: MAX_REQUEST,
            }),
        }
    }
    found
}
