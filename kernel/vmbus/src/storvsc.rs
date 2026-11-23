//! The storage channel: what sets it up, and SCSI requests. Every packet is
//! [`PACKET`] bytes, answered by a completion that carries another.

use crate::{u16_at, u32_at};

/// A packet's length: 12 bytes of header, 52 of what is asked.
pub const PACKET: usize = 64;
const REQUEST: usize = 52;

const COMPLETE_IO: u32 = 1;
const EXECUTE: u32 = 3;
const BEGIN_INITIALIZATION: u32 = 7;
const END_INITIALIZATION: u32 = 8;
const QUERY_VERSION: u32 = 9;
const QUERY_PROPERTIES: u32 = 10;

/// Protocol versions, best first (Windows 10's, 8.1's, 8's).
const VERSIONS: [u16; 3] = [0x0602, 0x0600, 0x0501];

/// `srb_flags`: data comes in; no synchronous-transfer negotiation.
const DATA_IN: u32 = 0x40;
const NO_SYNC_TRANSFER: u32 = 0x08;
/// `srb_status` (its low 6 bits): done, and the two that say there is
/// nothing at that address.
const SRB_SUCCESS: u8 = 1;
const SRB_STATUS: u8 = 0x3f;

type Packet = [u8; PACKET];

fn packet(operation: u32) -> Packet {
    let mut p = [0u8; PACKET];
    p[..4].copy_from_slice(&operation.to_le_bytes());
    // The host is to complete it.
    p[4..8].copy_from_slice(&1u32.to_le_bytes());
    p
}

/// Where the set-up is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Begin,
    Version(usize),
    Properties,
    End,
}

/// The channel's set-up: a packet, its answer, the next.
#[derive(Debug)]
pub struct Setup {
    step: Step,
    /// The most bytes of one request.
    pub max_transfer: u32,
}

/// What the set-up comes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next {
    Send(Packet),
    Done,
    Failed,
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            step: Step::Begin,
            max_transfer: 0,
        }
    }
}

impl Setup {
    /// The first packet.
    pub fn first(&self) -> Packet {
        packet(BEGIN_INITIALIZATION)
    }

    fn version(v: usize) -> Packet {
        let mut p = packet(QUERY_VERSION);
        p[12..14].copy_from_slice(&VERSIONS[v].to_le_bytes());
        p
    }

    /// Takes the answer to the packet before.
    pub fn answer(&mut self, a: &[u8]) -> Next {
        if a.len() < 12 || u32_at(a, 0) != COMPLETE_IO {
            return Next::Failed;
        }
        let ok = u32_at(a, 8) == 0;
        let (step, send) = match self.step {
            Step::Begin if ok => (Step::Version(0), Self::version(0)),
            Step::Version(_) if ok => (Step::Properties, packet(QUERY_PROPERTIES)),
            // (An older host refuses it.)
            Step::Version(v) if v + 1 < VERSIONS.len() => {
                (Step::Version(v + 1), Self::version(v + 1))
            }
            Step::Properties if ok => {
                self.max_transfer = u32_at(a, 24);
                (Step::End, packet(END_INITIALIZATION))
            }
            Step::End if ok => return Next::Done,
            _ => return Next::Failed,
        };
        self.step = step;
        Next::Send(send)
    }
}

/// A SCSI command that reads `data` bytes from a disk, or moves none.
pub fn command(path: u8, target: u8, lun: u8, cdb: &[u8], data: u32) -> Packet {
    let mut p = packet(EXECUTE);
    let cdb = &cdb[..cdb.len().min(16)];
    let r = &mut p[12..];
    r[..2].copy_from_slice(&(REQUEST as u16).to_le_bytes());
    r[5] = path;
    r[6] = target;
    r[7] = lun;
    r[8] = cdb.len() as u8;
    r[9] = SENSE as u8;
    // 1 reads, 2 moves nothing.
    r[10] = if data == 0 { 2 } else { 1 };
    r[12..16].copy_from_slice(&data.to_le_bytes());
    r[16..16 + cdb.len()].copy_from_slice(cdb);
    let flags = NO_SYNC_TRANSFER | if data == 0 { 0 } else { DATA_IN };
    r[40..44].copy_from_slice(&flags.to_le_bytes());
    r[44..48].copy_from_slice(&60u32.to_le_bytes()); // seconds
    p
}

/// Sense bytes there is room for in a packet.
const SENSE: usize = 20;

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It ran: its SCSI status, and how much was read.
    Ran { status: u8, data: u32 },
    /// The host did not run it (`srb_status`; nothing there, often).
    Not(u8),
}

/// Reads a command's answer; `None` if it is not one.
pub fn ended(a: &[u8]) -> Option<Ended> {
    if a.len() < PACKET || u32_at(a, 0) != COMPLETE_IO || u16_at(a, 12) as usize > REQUEST {
        return None;
    }
    let (srb, status) = (a[14] & SRB_STATUS, a[15]);
    let data = u32_at(a, 24);
    // A command that ended with a check condition ran.
    Some(if srb == SRB_SUCCESS || status != 0 {
        Ended::Ran { status, data }
    } else {
        Ended::Not(srb)
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn answer(status: u32, body: &[u8]) -> Packet {
        let mut p = packet(COMPLETE_IO);
        p[8..12].copy_from_slice(&status.to_le_bytes());
        p[12..12 + body.len()].copy_from_slice(body);
        p
    }

    fn sent(n: Next) -> Packet {
        match n {
            Next::Send(p) => p,
            n => panic!("{n:?}"),
        }
    }

    #[test]
    fn the_set_up_falls_back_to_an_older_version() {
        let mut s = Setup::default();
        assert_eq!(u32_at(&s.first(), 0), 7);
        let p = sent(s.answer(&answer(0, &[])));
        assert_eq!((u32_at(&p, 0), u16_at(&p, 12)), (9, 0x0602));
        let p = sent(s.answer(&answer(0xc000_0059, &[])));
        assert_eq!((u32_at(&p, 0), u16_at(&p, 12)), (9, 0x0600));
        assert_eq!(u32_at(&sent(s.answer(&answer(0, &[]))), 0), 10);
        // reserved, sub-channels, reserved, flags, max_transfer_bytes
        let properties = [0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 0, 8, 0];
        assert_eq!(u32_at(&sent(s.answer(&answer(0, &properties))), 0), 8);
        assert_eq!(s.max_transfer, 0x8_0000);
        assert_eq!(s.answer(&answer(0, &[])), Next::Done);
        assert_eq!(Setup::default().answer(&answer(1, &[])), Next::Failed);
        assert_eq!(Setup::default().answer(&[0; 5]), Next::Failed);
    }

    #[test]
    fn a_command_is_laid_out_as_the_host_reads_it() {
        let cdb = [0x28, 0, 0, 0, 1, 0, 0, 0, 8, 0];
        let p = command(0, 1, 2, &cdb, 4096);
        assert_eq!((u32_at(&p, 0), u32_at(&p, 4)), (3, 1));
        assert_eq!(u16_at(&p, 12), 0x34);
        assert_eq!(p[17..24], [0, 1, 2, 10, 20, 1, 0]);
        assert_eq!(u32_at(&p, 24), 4096);
        assert_eq!(p[28..38], cdb);
        assert_eq!((u32_at(&p, 52), u32_at(&p, 56)), (0x48, 60));
        assert_eq!(command(0, 0, 0, &[0; 6], 0)[22], 2);
    }

    #[test]
    fn how_a_command_ended() {
        let mut a = command(0, 0, 0, &[0; 6], 0);
        a[..4].copy_from_slice(&1u32.to_le_bytes());
        a[14] = 1;
        a[24..28].copy_from_slice(&512u32.to_le_bytes());
        let ran = |status, data| Some(Ended::Ran { status, data });
        assert_eq!(ended(&a), ran(0, 512));
        // An error, with sense data, of a command that ran.
        (a[14], a[15]) = (0x84, 2);
        assert_eq!(ended(&a), ran(2, 512));
        // No such unit.
        (a[14], a[15]) = (0x20, 0);
        assert_eq!(ended(&a), Some(Ended::Not(0x20)));
        assert_eq!(ended(&a[..63]), None);
    }
}
