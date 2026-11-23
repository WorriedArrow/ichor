//! SCSI disks, whatever carries the commands: what finds one and reads it.
//!
//! A logical unit gets an INQUIRY; a disk then TEST UNIT READY (a fresh
//! device reports a unit attention first) and READ CAPACITY, (16) when (10)
//! saturates. Reads are READ(10), or READ(16) past 2^32 blocks.

use crate::{BlockDevice, BlockError, SECTOR_SIZE};

/// The status of a command that did what it was asked.
pub const GOOD: u8 = 0;

const TEST_UNIT_READY: u8 = 0x00;
const INQUIRY: u8 = 0x12;
const READ_CAPACITY_10: u8 = 0x25;
const READ_10: u8 = 0x28;
const READ_16: u8 = 0x88;
const SERVICE_ACTION_IN_16: u8 = 0x9e;
const READ_CAPACITY_16: u8 = 0x10;

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It ran: its SCSI status (GOOD, CHECK CONDITION, ...).
    Ran(u8),
    /// There is nothing at that address.
    NoTarget,
    /// What carries commands failed it.
    Failed(u8),
}

/// One logical unit.
pub trait Unit {
    /// Runs `cdb`, reading up to `data.len()` bytes into `data`.
    fn command(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<Ended, BlockError>;
}

/// What is at an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    Nothing,
    /// A disk that cannot be used, and why.
    Unusable(&'static str),
    Disk(Geometry),
}

/// A disk's size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub blocks: u64,
    /// A block's size, as a power of two.
    pub block_shift: u32,
}

/// Looks at a unit.
pub fn probe(u: &mut impl Unit) -> Found {
    let mut inq = [0u8; 36];
    let cdb = [INQUIRY, 0, 0, 0, inq.len() as u8, 0];
    // Peripheral qualifier 0 (connected), device type 0 (disk).
    if !matches!(u.command(&cdb, &mut inq), Ok(Ended::Ran(GOOD))) || inq[0] != 0 {
        return Found::Nothing;
    }
    let mut ready = || u.command(&[TEST_UNIT_READY, 0, 0, 0, 0, 0], &mut []);
    if !(0..4).any(|_| matches!(ready(), Ok(Ended::Ran(GOOD)))) {
        return Found::Unusable("not ready");
    }
    match capacity(u) {
        Some((blocks, len)) if len.is_power_of_two() && (512..=4096).contains(&len) => {
            Found::Disk(Geometry {
                blocks,
                block_shift: len.trailing_zeros(),
            })
        }
        Some(_) => Found::Unusable("its block size"),
        None => Found::Unusable("no capacity"),
    }
}

/// The disk's block count and block length.
fn capacity(u: &mut impl Unit) -> Option<(u64, u32)> {
    let mut d = [0u8; 8];
    let cdb = [READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if u.command(&cdb, &mut d).ok()? != Ended::Ran(GOOD) {
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
    if u.command(&cdb, &mut d).ok()? != Ended::Ran(GOOD) {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[0..8]);
    let last = u64::from_be_bytes(b);
    let len = u32::from_be_bytes([d[8], d[9], d[10], d[11]]);
    Some((last.checked_add(1)?, len))
}

impl Geometry {
    /// The disk's size in sectors.
    pub fn sectors(self) -> u64 {
        self.blocks << (self.block_shift - 9)
    }

    /// Reads sectors, at most `max` bytes (whole blocks) a command. The
    /// caller has checked that they are on the disk.
    pub fn read(
        self,
        u: &mut impl Unit,
        sector: u64,
        buf: &mut [u8],
        max: usize,
    ) -> Result<(), BlockError> {
        let block = 1usize << self.block_shift;
        let byte = sector * SECTOR_SIZE as u64;
        if !byte.is_multiple_of(block as u64) || !buf.len().is_multiple_of(block) {
            return Err(BlockError::Unaligned);
        }
        let mut done = 0;
        while done < buf.len() {
            let n = max.min(buf.len() - done);
            let lba = (byte + done as u64) >> self.block_shift;
            let (cdb, len) = read_cdb(lba, (n >> self.block_shift) as u32);
            match u.command(&cdb[..len], &mut buf[done..done + n])? {
                Ended::Ran(GOOD) => done += n,
                _ => return Err(BlockError::Io),
            }
        }
        Ok(())
    }
}

/// The command that reads `count` blocks, and its length.
fn read_cdb(lba: u64, count: u32) -> ([u8; 16], usize) {
    let mut cdb = [0u8; 16];
    match u32::try_from(lba) {
        Ok(l) if count <= u32::from(u16::MAX) && l.checked_add(count).is_some() => {
            cdb[0] = READ_10;
            cdb[2..6].copy_from_slice(&l.to_be_bytes());
            cdb[7..9].copy_from_slice(&(count as u16).to_be_bytes());
            (cdb, 10)
        }
        _ => {
            cdb[0] = READ_16;
            cdb[2..10].copy_from_slice(&lba.to_be_bytes());
            cdb[10..14].copy_from_slice(&count.to_be_bytes());
            (cdb, 16)
        }
    }
}

/// A disk as a block device: a unit, its size, and the most of one read.
#[derive(Debug)]
pub struct Disk<U> {
    pub unit: U,
    pub geometry: Geometry,
    pub max: usize,
}

impl<U: Unit> BlockDevice for Disk<U> {
    fn sector_count(&self) -> u64 {
        self.geometry.sectors()
    }

    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        crate::check(self, sector, buf.len())?;
        self.geometry.read(&mut self.unit, sector, buf, self.max)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A disk of `blocks` blocks of `len` bytes, each its number's bytes.
    struct Fake {
        blocks: u64,
        len: u32,
        attention: u32,
        seen: Vec<u8>,
    }

    impl Unit for Fake {
        fn command(&mut self, cdb: &[u8], data: &mut [u8]) -> Result<Ended, BlockError> {
            self.seen.push(cdb[0]);
            let last = self.blocks - 1;
            match cdb[0] {
                INQUIRY => data.fill(0),
                TEST_UNIT_READY if self.attention > 0 => {
                    self.attention -= 1;
                    return Ok(Ended::Ran(2));
                }
                TEST_UNIT_READY => {}
                READ_CAPACITY_10 => {
                    let l = u32::try_from(last).unwrap_or(u32::MAX);
                    data[..4].copy_from_slice(&l.to_be_bytes());
                    data[4..].copy_from_slice(&self.len.to_be_bytes());
                }
                SERVICE_ACTION_IN_16 => {
                    data[..8].copy_from_slice(&last.to_be_bytes());
                    data[8..12].copy_from_slice(&self.len.to_be_bytes());
                }
                READ_10 | READ_16 => {
                    let (lba, n) = if cdb[0] == READ_10 {
                        let l = u32::from_be_bytes(cdb[2..6].try_into().unwrap());
                        let n = u16::from_be_bytes([cdb[7], cdb[8]]);
                        (u64::from(l), u32::from(n))
                    } else {
                        let n = u32::from_be_bytes(cdb[10..14].try_into().unwrap());
                        (u64::from_be_bytes(cdb[2..10].try_into().unwrap()), n)
                    };
                    assert_eq!(data.len(), (n * self.len) as usize);
                    for (i, b) in data.chunks_mut(self.len as usize).enumerate() {
                        b.fill((lba + i as u64) as u8);
                    }
                }
                _ => return Ok(Ended::Failed(1)),
            }
            Ok(Ended::Ran(GOOD))
        }
    }

    fn fake(blocks: u64, len: u32) -> Fake {
        Fake {
            blocks,
            len,
            attention: 1,
            seen: Vec::new(),
        }
    }

    #[test]
    fn a_disk_is_found_and_read_in_parts() {
        let mut u = fake(100, 4096);
        let Found::Disk(geometry) = probe(&mut u) else {
            panic!("no disk")
        };
        assert_eq!(geometry.sectors(), 800);
        let mut d = Disk {
            unit: u,
            geometry,
            max: 8192,
        };
        let mut buf = [0u8; 5 * 4096];
        d.read(16, &mut buf).unwrap();
        for (i, b) in buf.chunks(4096).enumerate() {
            assert!(b.iter().all(|&x| x == 2 + i as u8));
        }
        assert_eq!(d.unit.seen[d.unit.seen.len() - 3..], [READ_10; 3]);
        assert_eq!(d.read(1, &mut buf[..4096]), Err(BlockError::Unaligned));
        assert_eq!(d.read(800, &mut buf[..4096]), Err(BlockError::OutOfRange));
    }

    #[test]
    fn a_large_disk_takes_the_long_commands() {
        let mut u = fake(1 << 33, 512);
        let Found::Disk(geometry) = probe(&mut u) else {
            panic!("no disk")
        };
        assert_eq!(geometry.blocks, 1 << 33);
        let mut buf = [0u8; 512];
        geometry
            .read(&mut u, (1 << 32) + 7, &mut buf, 65536)
            .unwrap();
        assert_eq!((u.seen.last(), buf[0]), (Some(&READ_16), 7));
        // One whose last block's number does not fit.
        assert_eq!(read_cdb(u64::from(u32::MAX), 1).1, 16);
        assert_eq!(read_cdb(u64::from(u32::MAX) - 1, 1).1, 10);
    }

    #[test]
    fn what_is_not_a_usable_disk() {
        struct Nothing;
        impl Unit for Nothing {
            fn command(&mut self, _: &[u8], _: &mut [u8]) -> Result<Ended, BlockError> {
                Ok(Ended::NoTarget)
            }
        }
        assert_eq!(probe(&mut Nothing), Found::Nothing);
        assert_eq!(probe(&mut fake(10, 520)), Found::Unusable("its block size"));
        let mut u = fake(10, 512);
        u.attention = 9;
        assert_eq!(probe(&mut u), Found::Unusable("not ready"));
    }
}
