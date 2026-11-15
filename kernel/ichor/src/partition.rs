//! Finding the root image on a partitioned disk. A cloud or bare-metal boot
//! disk is one GPT disk: the EFI system partition the firmware boots
//! `ichor.efi` from, and an Ichor root partition (`gpt::ICHOR_ROOT`)
//! holding an Ichor image. A disk with no GPT is an image from its first
//! sector (the QEMU test disks).
//!
//! Only the primary GPT header is trusted, and only after its CRC, the
//! entry array's CRC and every bound check (the `gpt` crate); a disk whose
//! table is damaged is treated as unpartitioned, so its sector 0 must then
//! be an image (it is not), and mounting fails.

use block::{BlockDevice, SECTOR_SIZE, Slice};

/// Logical block sizes a GPT may use: 512-byte and 4 KiB-native disks.
const BLOCK_SIZES: [usize; 2] = [512, 4096];

/// Reads `len` bytes at byte `offset` (both sector-aligned).
fn read_bytes(dev: &mut impl BlockDevice, offset: u64, len: usize) -> Option<alloc::vec::Vec<u8>> {
    let mut buf = alloc::vec![0u8; len.next_multiple_of(SECTOR_SIZE)];
    dev.read(offset / SECTOR_SIZE as u64, &mut buf).ok()?;
    buf.truncate(len);
    Some(buf)
}

/// The first Ichor root partition in `dev`'s GPT, as `(first sector,
/// sectors)` in 512-byte sectors.
fn find(dev: &mut impl BlockDevice) -> Option<(u64, u64)> {
    let bytes = dev.sector_count().checked_mul(SECTOR_SIZE as u64)?;
    for bs in BLOCK_SIZES {
        let Some(block) = read_bytes(dev, bs as u64, bs) else {
            continue;
        };
        let Ok(h) = gpt::header(&block, bytes / bs as u64) else {
            continue;
        };
        let entries = read_bytes(dev, h.entries_lba.checked_mul(bs as u64)?, h.entries_len())?;
        let parts = gpt::partitions(&h, &entries).ok()?;
        let p = parts.iter().find(|p| p.type_guid == gpt::ICHOR_ROOT)?;
        let per = (bs / SECTOR_SIZE) as u64;
        return Some((p.first_lba.checked_mul(per)?, p.blocks().checked_mul(per)?));
    }
    None
}

/// `dev`'s Ichor root partition if it has a GPT with one, else `dev`.
pub(crate) fn root<D: BlockDevice>(mut dev: D) -> Result<Slice<D>, D> {
    match find(&mut dev) {
        Some((start, sectors)) => Slice::new(dev, start, sectors),
        None => Err(dev),
    }
}
