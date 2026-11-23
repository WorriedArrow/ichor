//! VMBus, the channel protocol between a Hyper-V host and its guests
//! (ADR-0016), without I/O: [`client`] is the connection, [`ring`] a
//! channel's data, [`storvsc`] and [`netvsc`] what is said on the storage
//! and network channels. Everything the host writes is checked.
//!
//! Layouts are from the hypervisor's published interface and OpenVMM's
//! definitions (MIT).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod client;
pub mod netvsc;
pub mod ring;
pub mod storvsc;

use core::fmt;

/// A page of guest memory, as page numbers count them.
pub const PAGE: usize = 4096;
/// The most bytes in one message.
pub const MAX_MESSAGE: usize = 240;

/// A GUID, as it is in memory (the first three parts little-endian).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// From the parts of its text (`aabbccdd-eeff-gghh-iijj-kkllmmnnoopp`).
    pub const fn new(a: u32, b: u16, c: u16, d: [u8; 8]) -> Guid {
        let (a, b, c) = (a.to_le_bytes(), b.to_le_bytes(), c.to_le_bytes());
        Guid([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5],
            d[6], d[7],
        ])
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let g = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-",
            g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9]
        )?;
        g[10..].iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// The storage channel (SCSI controllers).
pub const SCSI: Guid = Guid::new(
    0xba61_63d9,
    0x04a1,
    0x4d29,
    [0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f],
);
/// The network channel.
pub const NET: Guid = Guid::new(
    0xf861_5163,
    0xdf3e,
    0x46c5,
    [0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed, 0x0e],
);

/// The little-endian value at `at` (0 past the end).
pub(crate) fn u16_at(b: &[u8], at: usize) -> u16 {
    let bytes = b.get(at..at + 2).and_then(|b| b.try_into().ok());
    bytes.map_or(0, u16::from_le_bytes)
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> u32 {
    let bytes = b.get(at..at + 4).and_then(|b| b.try_into().ok());
    bytes.map_or(0, u32::from_le_bytes)
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> u64 {
    let bytes = b.get(at..at + 8).and_then(|b| b.try_into().ok());
    bytes.map_or(0, u64::from_le_bytes)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[test]
    fn guids_are_mixed_endian() {
        assert_eq!(format!("{SCSI:?}"), "ba6163d9-04a1-4d29-b605-72e2ffb1dc7f");
        assert_eq!(format!("{NET:?}"), "f8615163-df3e-46c5-913f-f2d2f965ed0e");
        assert_eq!(SCSI.0[..4], [0xd9, 0x63, 0x61, 0xba]);
    }
}
