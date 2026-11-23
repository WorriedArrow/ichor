//! The disks of the SCSI controllers: one request at a time on a
//! controller's channel, read-only.

use alloc::sync::Arc;
use alloc::vec::Vec;

use block::BlockError;
use block::scsi::{self, Ended, Found};
use frame::dma::DmaBuf;
use frame::sync::Mutex;
use vmbus::SCSI;
use vmbus::ring::{Kind, Range};
use vmbus::storvsc::{self, Next, PACKET, Setup};

use crate::{Bus, Channel, Error, REQUEST_TIMEOUT, pages};

/// Bytes of each ring.
const RING: usize = 64 * 1024;
/// Largest single read (and no more than the host says).
const MAX_REQUEST: usize = 64 * 1024;
/// Logical units of a controller (Hyper-V's have 64).
const LUNS: u8 = 64;

/// A controller's channel.
#[derive(Debug)]
struct Controller {
    channel: Channel,
    max: usize,
}

/// A logical unit.
#[derive(Debug)]
pub struct Lun {
    controller: Arc<Mutex<Controller>>,
    /// The controller's number, and the unit's on it.
    pub controller_number: usize,
    pub lun: u8,
}

/// A disk.
pub type ScsiDisk = scsi::Disk<Lun>;

impl Bus {
    /// The disks of every SCSI controller. One that fails is one `Err`.
    pub fn disks(self: &Arc<Bus>) -> Vec<Result<ScsiDisk, Error>> {
        let mut out = Vec::new();
        for (n, offer) in self.offers(SCSI).into_iter().enumerate() {
            let controller = match self.open(offer, RING).and_then(Controller::new) {
                Ok(c) => c,
                Err(e) => {
                    out.push(Err(e));
                    continue;
                }
            };
            let max = controller.max;
            let controller = Arc::new(Mutex::new(controller));
            for lun in 0..LUNS {
                let mut unit = Lun {
                    controller: controller.clone(),
                    controller_number: n,
                    lun,
                };
                match scsi::probe(&mut unit) {
                    Found::Nothing => {}
                    Found::Unusable(why) => {
                        frame::println!("ichor: hyper-v: disk {n}:{lun}: {why}; skipped");
                    }
                    Found::Disk(geometry) => out.push(Ok(scsi::Disk {
                        unit,
                        geometry,
                        max,
                    })),
                }
            }
        }
        out
    }
}

impl Controller {
    /// Sets the channel up.
    fn new(channel: Channel) -> Result<Controller, Error> {
        let mut c = Controller {
            channel,
            max: MAX_REQUEST,
        };
        let mut setup = Setup::default();
        let mut send = setup.first();
        loop {
            let answer = c.transact(&send, None).map_err(|_| Error::Silent)?;
            match setup.answer(&answer) {
                Next::Send(p) => send = p,
                Next::Done => break,
                Next::Failed => return Err(Error::Failed("the disks' set-up")),
            }
        }
        // (Whole pages of it.)
        c.max = match setup.max_transfer as usize & !4095 {
            0 => MAX_REQUEST,
            n => n.min(MAX_REQUEST),
        };
        Ok(c)
    }

    /// Sends a packet and waits for its answer. An error leaves the host
    /// perhaps still at it.
    fn transact(&mut self, packet: &[u8; PACKET], data: Option<&Range>) -> Result<Vec<u8>, Error> {
        let id = self.channel.id();
        self.channel.send(packet, data, id, true)?;
        let deadline = frame::time::now() + REQUEST_TIMEOUT;
        loop {
            match self.channel.receive()? {
                Some(p) if p.kind == Kind::Completion && p.transaction == id => {
                    return Ok(p.payload);
                }
                // An answer too late, or news of the bus (a disk that comes
                // or goes: the disks are those there were).
                Some(_) => {}
                None if frame::time::now() >= deadline => return Err(Error::Silent),
                None => core::hint::spin_loop(),
            }
        }
    }

    fn command(&mut self, lun: u8, cdb: &[u8], data: &mut [u8]) -> Result<Ended, BlockError> {
        let buf = match data.len() {
            0 => None,
            n => Some(DmaBuf::alloc(n).ok_or(BlockError::NoMemory)?),
        };
        let range = buf.as_ref().map(|b| Range {
            len: data.len() as u32,
            offset: 0,
            pages: pages(b, data.len()),
        });
        let packet = storvsc::command(0, 0, lun, cdb, data.len() as u32);
        let answer = match self.transact(&packet, range.as_ref()) {
            Ok(a) => a,
            Err(e) => {
                frame::println!(
                    "ichor: hyper-v: disk command {:#04x} to unit {lun}: {e:?}",
                    cdb.first().copied().unwrap_or(0)
                );
                // The host may still write it.
                core::mem::forget(buf);
                return Err(BlockError::Timeout);
            }
        };
        Ok(match storvsc::ended(&answer) {
            Some(storvsc::Ended::Ran { status, .. }) => {
                if let Some(b) = &buf {
                    b.read(0, data);
                }
                Ended::Ran(status)
            }
            Some(storvsc::Ended::Not(_)) => Ended::NoTarget,
            None => Ended::Failed(0),
        })
    }
}

impl scsi::Unit for Lun {
    fn command(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<Ended, BlockError> {
        self.controller.lock().command(self.lun, cdb, data)
    }
}
