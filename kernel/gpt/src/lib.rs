//! GUID partition tables (UEFI 2.10 §5.3): what a cloud or bare-metal boot
//! disk carries. The kernel reads one to find the Ichor root partition on a
//! disk that also holds the EFI system partition; xtask writes one (the
//! `builder` feature) to make such a disk.
//!
//! The reader trusts nothing: the header's own CRC32, the entry array's
//! CRC32, the header size, the entry size and every partition's bounds are
//! checked before a partition is reported. Only the primary header is
//! read; a damaged primary is an error rather than a silent fall-back to
//! the backup.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// A GUID in its on-disk byte order (the first three fields little-endian).
pub type Guid = [u8; 16];

/// A GUID from its textual fields, in on-disk order.
pub const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> Guid {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// The EFI system partition (C12A7328-F81F-11D2-BA4B-00A0C93EC93B).
pub const ESP: Guid = guid(
    0xC12A_7328,
    0xF81F,
    0x11D2,
    [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
);

/// An Ichor root image partition (7E1C4A3B-92D6-4F1E-B5A8-3C6D0F2E9A17;
/// Ichor's own type, holding an Ichor image from its first byte).
pub const ICHOR_ROOT: Guid = guid(
    0x7E1C_4A3B,
    0x92D6,
    0x4F1E,
    [0xB5, 0xA8, 0x3C, 0x6D, 0x0F, 0x2E, 0x9A, 0x17],
);

const SIGNATURE: &[u8; 8] = b"EFI PART";
const HEADER_SIZE: usize = 92;
const ENTRY_SIZE: usize = 128;

/// Why a table was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No GPT signature (not a GPT disk, or the wrong block size).
    NotGpt,
    /// A CRC did not match.
    BadCrc,
    /// A size or bound in the table is impossible.
    Corrupt,
}

/// The parts of the header a reader needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub first_usable: u64,
    pub last_usable: u64,
    pub entries_lba: u64,
    pub entry_count: u32,
    pub entry_size: u32,
    entries_crc: u32,
}

impl Header {
    /// Bytes of the partition entry array.
    pub fn entries_len(&self) -> usize {
        self.entry_count as usize * self.entry_size as usize
    }
}

/// One used partition entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    /// First and last logical block, inclusive.
    pub first_lba: u64,
    pub last_lba: u64,
}

impl Partition {
    /// Length in logical blocks.
    pub fn blocks(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
}

/// CRC-32 (IEEE 802.3, reflected), as GPT uses.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Parses the primary header from LBA 1 (`block`: one logical block) of a
/// disk of `blocks` logical blocks.
pub fn header(block: &[u8], blocks: u64) -> Result<Header, Error> {
    if block.len() < HEADER_SIZE || &block[..8] != SIGNATURE {
        return Err(Error::NotGpt);
    }
    let size = u32_at(block, 12) as usize;
    if !(HEADER_SIZE..=block.len()).contains(&size) {
        return Err(Error::Corrupt);
    }
    let mut copy = Vec::from(&block[..size]);
    copy[16..20].fill(0);
    if crc32(&copy) != u32_at(block, 16) {
        return Err(Error::BadCrc);
    }
    let h = Header {
        first_usable: u64_at(block, 40),
        last_usable: u64_at(block, 48),
        entries_lba: u64_at(block, 72),
        entry_count: u32_at(block, 80),
        entry_size: u32_at(block, 84),
        entries_crc: u32_at(block, 88),
    };
    let sane = u64_at(block, 24) == 1
        && h.entry_size as usize >= ENTRY_SIZE
        && h.entry_size.is_multiple_of(8)
        && h.entry_count <= 1024
        && h.first_usable <= h.last_usable
        && h.last_usable < blocks
        && h.entries_lba >= 2
        && h.entries_lba < blocks;
    if !sane {
        return Err(Error::Corrupt);
    }
    Ok(h)
}

/// The used entries of the entry array `bytes` (`h.entries_len()` bytes
/// from `h.entries_lba`), checked against the header's CRC and bounds.
pub fn partitions(h: &Header, bytes: &[u8]) -> Result<Vec<Partition>, Error> {
    let len = h.entries_len();
    let table = bytes.get(..len).ok_or(Error::Corrupt)?;
    if crc32(table) != h.entries_crc {
        return Err(Error::BadCrc);
    }
    let mut out = Vec::new();
    for e in table.chunks_exact(h.entry_size as usize) {
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&e[..16]);
        if type_guid == [0; 16] {
            continue; // unused
        }
        let mut unique_guid = [0u8; 16];
        unique_guid.copy_from_slice(&e[16..32]);
        let p = Partition {
            type_guid,
            unique_guid,
            first_lba: u64_at(e, 32),
            last_lba: u64_at(e, 40),
        };
        if p.first_lba > p.last_lba || p.first_lba < h.first_usable || p.last_lba > h.last_usable {
            return Err(Error::Corrupt);
        }
        out.push(p);
    }
    Ok(out)
}

/// Writing GPT disks (xtask).
#[cfg(feature = "builder")]
pub mod builder {
    use super::*;

    /// A partition to place: type, unique GUID, name, contents and the
    /// size to reserve (at least the contents).
    #[derive(Debug)]
    pub struct Part<'a> {
        pub type_guid: Guid,
        pub unique_guid: Guid,
        pub name: &'a str,
        pub data: &'a [u8],
        pub size: u64,
    }

    /// Entries in the array (the usual 128, 16 KiB).
    const ENTRIES: usize = 128;
    /// Partitions start on 1 MiB boundaries.
    const ALIGN: u64 = 1 << 20;

    #[allow(clippy::too_many_arguments)] // the header's fields, one each
    fn header_bytes(
        disk_guid: Guid,
        current: u64,
        backup: u64,
        first_usable: u64,
        last_usable: u64,
        entries_lba: u64,
        entries_crc: u32,
        block: usize,
    ) -> Vec<u8> {
        let mut h = alloc::vec![0u8; block];
        h[..8].copy_from_slice(SIGNATURE);
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
        h[12..16].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        h[24..32].copy_from_slice(&current.to_le_bytes());
        h[32..40].copy_from_slice(&backup.to_le_bytes());
        h[40..48].copy_from_slice(&first_usable.to_le_bytes());
        h[48..56].copy_from_slice(&last_usable.to_le_bytes());
        h[56..72].copy_from_slice(&disk_guid);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&(ENTRIES as u32).to_le_bytes());
        h[84..88].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
        h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let crc = crc32(&h[..HEADER_SIZE]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    }

    /// A whole disk image with `block`-byte logical blocks: protective MBR,
    /// primary header and entries, the partitions (1 MiB aligned, in
    /// order), backup entries and header. Returns the image and each
    /// partition's first LBA. The disk is at least `min_bytes` long (a
    /// cloud may want whole GiB); the space past the last partition is
    /// usable but unallocated, and the backup table sits at the true end.
    pub fn disk(
        disk_guid: Guid,
        block: usize,
        parts: &[Part<'_>],
        min_bytes: u64,
    ) -> (Vec<u8>, Vec<u64>) {
        let bs = block as u64;
        let entries_blocks = (ENTRIES * ENTRY_SIZE).div_ceil(block) as u64;
        let mut starts = Vec::new();
        let mut at = ALIGN;
        for p in parts {
            starts.push(at / bs);
            at = (at + p.size.max(p.data.len() as u64)).next_multiple_of(ALIGN);
        }
        let first_usable = 2 + entries_blocks;
        let tail = entries_blocks + 1; // backup entries and header
        let total = (at / bs + tail).max(min_bytes.div_ceil(bs));
        let last_usable = total - tail - 1;
        let mut img = alloc::vec![0u8; (total * bs) as usize];
        // Entries.
        let mut table = alloc::vec![0u8; ENTRIES * ENTRY_SIZE];
        for (i, (p, &start)) in parts.iter().zip(&starts).enumerate() {
            let e = &mut table[i * ENTRY_SIZE..(i + 1) * ENTRY_SIZE];
            let blocks = p.size.max(p.data.len() as u64).div_ceil(bs);
            e[..16].copy_from_slice(&p.type_guid);
            e[16..32].copy_from_slice(&p.unique_guid);
            e[32..40].copy_from_slice(&start.to_le_bytes());
            e[40..48].copy_from_slice(&(start + blocks - 1).to_le_bytes());
            for (j, u) in p.name.encode_utf16().take(36).enumerate() {
                e[56 + 2 * j..58 + 2 * j].copy_from_slice(&u.to_le_bytes());
            }
            let off = (start * bs) as usize;
            img[off..off + p.data.len()].copy_from_slice(p.data);
        }
        let entries_crc = crc32(&table);
        // Protective MBR: one 0xEE partition over the disk.
        let mbr = &mut img[..512];
        mbr[446 + 4] = 0xEE;
        mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        let size = u32::try_from(total - 1).unwrap_or(u32::MAX);
        mbr[446 + 12..446 + 16].copy_from_slice(&size.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        let backup_lba = total - 1;
        let backup_entries = backup_lba - entries_blocks;
        let primary = header_bytes(
            disk_guid,
            1,
            backup_lba,
            first_usable,
            last_usable,
            2,
            entries_crc,
            block,
        );
        let backup = header_bytes(
            disk_guid,
            backup_lba,
            1,
            first_usable,
            last_usable,
            backup_entries,
            entries_crc,
            block,
        );
        img[block..2 * block].copy_from_slice(&primary);
        let e = (2 * bs) as usize;
        img[e..e + table.len()].copy_from_slice(&table);
        let b = (backup_entries * bs) as usize;
        img[b..b + table.len()].copy_from_slice(&table);
        let h = (backup_lba * bs) as usize;
        img[h..h + block].copy_from_slice(&backup);
        (img, starts)
    }
}

#[cfg(all(test, feature = "builder"))]
mod tests {
    use super::builder::{Part, disk};
    use super::*;

    const DISK: Guid = guid(1, 2, 3, [4, 5, 6, 7, 8, 9, 10, 11]);

    fn sample(block: usize) -> (Vec<u8>, Vec<u64>) {
        sample_sized(block, 0)
    }

    fn sample_sized(block: usize, min_bytes: u64) -> (Vec<u8>, Vec<u64>) {
        disk(
            DISK,
            block,
            &[
                Part {
                    type_guid: ESP,
                    unique_guid: guid(9, 9, 9, [9; 8]),
                    name: "EFI system",
                    data: b"fat",
                    size: 4 << 20,
                },
                Part {
                    type_guid: ICHOR_ROOT,
                    unique_guid: guid(8, 8, 8, [8; 8]),
                    name: "Ichor root",
                    data: b"ichor image",
                    size: 0,
                },
            ],
            min_bytes,
        )
    }

    #[test]
    fn padded_disks_keep_the_backup_at_the_end() {
        let (img, _) = sample_sized(512, 64 << 20);
        assert_eq!(img.len(), 64 << 20);
        let parts = read_back(&img, 512).unwrap();
        assert_eq!(parts.len(), 2);
        let last = img.len() / 512 - 1;
        assert_eq!(&img[last * 512..last * 512 + 8], SIGNATURE);
        let h = header(&img[512..1024], (img.len() / 512) as u64).unwrap();
        // The primary header names the true last block as the backup's home.
        assert_eq!(u64_at(&img[512..1024], 32), last as u64);
        assert!(h.last_usable < last as u64);
    }

    fn read_back(img: &[u8], block: usize) -> Result<Vec<Partition>, Error> {
        let blocks = (img.len() / block) as u64;
        let h = header(&img[block..2 * block], blocks)?;
        let at = h.entries_lba as usize * block;
        partitions(&h, &img[at..at + h.entries_len()])
    }

    #[test]
    fn written_disks_read_back_at_both_block_sizes() {
        for block in [512, 4096] {
            let (img, starts) = sample(block);
            let parts = read_back(&img, block).unwrap();
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0].type_guid, ESP);
            assert_eq!(parts[1].type_guid, ICHOR_ROOT);
            assert_eq!(parts[0].first_lba, starts[0]);
            assert_eq!(parts[0].first_lba * block as u64, 1 << 20);
            assert!(parts[0].blocks() * block as u64 >= 4 << 20);
            let root = parts[1].first_lba as usize * block;
            assert_eq!(&img[root..root + 11], b"ichor image");
            assert_eq!(&img[510..512], &[0x55, 0xAA]);
            // The backup header points back at the primary.
            let last = img.len() / block - 1;
            assert_eq!(&img[last * block..last * block + 8], SIGNATURE);
        }
    }

    #[test]
    fn damage_is_detected() {
        let (img, _) = sample(512);
        let mut bad = img.clone();
        bad[512 + 40] ^= 1; // header field
        assert_eq!(read_back(&bad, 512), Err(Error::BadCrc));
        let mut bad = img.clone();
        bad[2 * 512 + 32] ^= 1; // an entry's first LBA
        assert_eq!(read_back(&bad, 512), Err(Error::BadCrc));
        // Read with the wrong block size: no signature where it looks.
        assert_eq!(read_back(&img, 4096), Err(Error::NotGpt));
        assert_eq!(header(&[0u8; 512], 100), Err(Error::NotGpt));
    }

    #[test]
    fn crc32_matches_the_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
