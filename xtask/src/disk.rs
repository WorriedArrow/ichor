//! A bootable Ichor disk, as a cloud VM or bare-metal server would boot it:
//! one GPT disk with an EFI system partition (FAT32, `ichor.efi` as the
//! default loader `\EFI\BOOT\BOOTX64.EFI`, the command line in
//! `\ichor\cmdline`) and an Ichor root partition holding the root image.
//! The firmware boots the ESP; the kernel finds its root by the partition
//! type (`gpt::ICHOR_ROOT`).

use std::fs;
use std::path::Path;

use gpt::builder::{Part, disk};

use crate::fat::Volume;
use crate::{Result, qemu};

/// The ESP's size: 64 MiB, enough clusters for FAT32 at 512-byte clusters.
const ESP_SECTORS: u32 = 131_072;
/// Where the GPT builder places the first partition (1 MiB).
const ESP_START: u32 = 2048;

const DISK_GUID: gpt::Guid = gpt::guid(
    0x1C4A_3B7E,
    0x0001,
    0x4000,
    [0x80, 0x00, 0x49, 0x43, 0x48, 0x4F, 0x52, 0x00],
);
const ESP_GUID: gpt::Guid = gpt::guid(
    0x1C4A_3B7E,
    0x0002,
    0x4000,
    [0x80, 0x00, 0x49, 0x43, 0x48, 0x4F, 0x52, 0x01],
);
const ROOT_GUID: gpt::Guid = gpt::guid(
    0x1C4A_3B7E,
    0x0003,
    0x4000,
    [0x80, 0x00, 0x49, 0x43, 0x48, 0x4F, 0x52, 0x02],
);

/// The disk image: `kernel` (`ichor.efi`) booted with `cmdline`, and the
/// test root image (busybox, motd, the pattern file) as its root.
pub fn image(kernel: &Path, cmdline: &str) -> Result<Vec<u8>> {
    let efi = fs::read(kernel).map_err(|e| format!("reading {}: {e}", kernel.display()))?;
    let mut esp = Volume::default();
    esp.add("EFI/BOOT/BOOTX64.EFI", &efi)?;
    esp.add("ICHOR/CMDLINE", cmdline.as_bytes())?;
    let esp = esp.image(ESP_SECTORS, ESP_START)?;
    let root = qemu::root_image()?;
    let (img, starts) = disk(
        DISK_GUID,
        512,
        &[
            Part {
                type_guid: gpt::ESP,
                unique_guid: ESP_GUID,
                name: "EFI system partition",
                data: &esp,
                size: esp.len() as u64,
            },
            Part {
                type_guid: gpt::ICHOR_ROOT,
                unique_guid: ROOT_GUID,
                name: "Ichor root",
                data: &root,
                size: 0,
            },
        ],
    );
    if starts.first() != Some(&u64::from(ESP_START)) {
        return Err("disk: the ESP did not land where its boot sector says".into());
    }
    Ok(img)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_disk_has_an_esp_and_a_root_partition() {
        let kernel =
            std::env::temp_dir().join(format!("ichor-disk-test-{}.efi", std::process::id()));
        fs::write(&kernel, b"MZ fake kernel").unwrap();
        let img = image(&kernel, "qemu_debug_exit").unwrap();
        let _ = fs::remove_file(&kernel);
        let h = gpt::header(&img[512..1024], (img.len() / 512) as u64).unwrap();
        let at = h.entries_lba as usize * 512;
        let parts = gpt::partitions(&h, &img[at..at + h.entries_len()]).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].type_guid, gpt::ESP);
        assert_eq!(parts[0].first_lba, u64::from(ESP_START));
        assert_eq!(parts[1].type_guid, gpt::ICHOR_ROOT);
        // The ESP is FAT32 and the root partition starts with an Ichor image.
        let esp = parts[0].first_lba as usize * 512;
        assert_eq!(&img[esp + 82..esp + 90], b"FAT32   ");
        let root = parts[1].first_lba as usize * 512;
        assert!(image::metadata_len(&img[root..root + 4096]).is_ok());
    }
}
