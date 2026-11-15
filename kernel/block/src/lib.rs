//! The block layer: the [`BlockDevice`] trait drivers implement, and
//! helpers on top of it. Milestone 3 is synchronous and polled; multiqueue,
//! per-CPU queues and interrupt-driven completion come with NVMe.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// Sector size every Ichor block device exposes.
pub const SECTOR_SIZE: usize = 512;

/// Why a block operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// The request runs past the end of the device.
    OutOfRange,
    /// The buffer is not a whole number of sectors.
    Unaligned,
    /// The device reported an I/O error.
    Io,
    /// The device did not answer in time.
    Timeout,
    /// Out of memory for the request.
    NoMemory,
}

/// A device addressed in [`SECTOR_SIZE`] sectors.
pub trait BlockDevice {
    /// Size of the device in sectors.
    fn sector_count(&self) -> u64;

    /// Reads `buf.len() / SECTOR_SIZE` sectors starting at `sector`.
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError>;
}

/// Checks that a request of `len` bytes at `sector` fits the device.
pub fn check(dev: &impl BlockDevice, sector: u64, len: usize) -> Result<(), BlockError> {
    if !len.is_multiple_of(SECTOR_SIZE) {
        return Err(BlockError::Unaligned);
    }
    let end = sector
        .checked_add((len / SECTOR_SIZE) as u64)
        .ok_or(BlockError::OutOfRange)?;
    if end > dev.sector_count() {
        return Err(BlockError::OutOfRange);
    }
    Ok(())
}

/// Reads the first `bytes` bytes of the device (rounded up to a sector) in
/// requests of at most `chunk` bytes.
pub fn read_prefix(
    dev: &mut impl BlockDevice,
    bytes: usize,
    chunk: usize,
) -> Result<Vec<u8>, BlockError> {
    let total = bytes.next_multiple_of(SECTOR_SIZE);
    let chunk = chunk.max(SECTOR_SIZE) / SECTOR_SIZE * SECTOR_SIZE;
    let mut out = alloc::vec![0u8; total];
    let mut done = 0;
    while done < total {
        let n = chunk.min(total - done);
        dev.read((done / SECTOR_SIZE) as u64, &mut out[done..done + n])?;
        done += n;
    }
    out.truncate(bytes);
    Ok(out)
}

/// A device backed by memory, for tests.
#[derive(Debug)]
pub struct RamDisk {
    pub data: Vec<u8>,
}

impl BlockDevice for RamDisk {
    fn sector_count(&self) -> u64 {
        (self.data.len() / SECTOR_SIZE) as u64
    }

    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check(self, sector, buf.len())?;
        let at = sector as usize * SECTOR_SIZE;
        buf.copy_from_slice(&self.data[at..at + buf.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(sectors: usize) -> RamDisk {
        RamDisk {
            data: (0..sectors * SECTOR_SIZE)
                .map(|i| (i % 253) as u8)
                .collect(),
        }
    }

    #[test]
    fn read_prefix_spans_chunks() {
        let mut d = disk(10);
        let want: Vec<u8> = d.data[..3000].to_vec();
        assert_eq!(read_prefix(&mut d, 3000, 1024).unwrap(), want);
    }

    #[test]
    fn bounds_and_alignment() {
        let mut d = disk(4);
        let mut buf = [0u8; 512];
        assert_eq!(d.read(4, &mut buf), Err(BlockError::OutOfRange));
        assert_eq!(d.read(u64::MAX, &mut buf), Err(BlockError::OutOfRange));
        let mut odd = [0u8; 100];
        assert_eq!(d.read(0, &mut odd), Err(BlockError::Unaligned));
        assert!(d.read(3, &mut buf).is_ok());
        assert_eq!(read_prefix(&mut d, 5000, 512), Err(BlockError::OutOfRange));
    }
}
