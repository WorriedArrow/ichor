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
    image_sized(kernel, cmdline, 0, None, None)
}

/// [`image`], at least `min_bytes` long (clouds want whole GiB), with the
/// control plane's API token (`\ichor\apitoken`) and its TLS certificates
/// and key (`\ichor\apitls.pem`) if they are given.
pub fn image_sized(
    kernel: &Path,
    cmdline: &str,
    min_bytes: u64,
    api_token: Option<&[u8]>,
    api_tls: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let efi = fs::read(kernel).map_err(|e| format!("reading {}: {e}", kernel.display()))?;
    let mut esp = Volume::default();
    esp.add("EFI/BOOT/BOOTX64.EFI", &efi)?;
    esp.add("ICHOR/CMDLINE", cmdline.as_bytes())?;
    esp.add("ICHOR/ROOTS.PEM", &crate::artifact::MOZILLA_ROOTS.bytes()?)?;
    if let Some(t) = api_token {
        esp.add("ICHOR/APITOKEN", t)?;
    }
    if let Some(t) = api_tls {
        esp.add("ICHOR/APITLS.PEM", t)?;
    }
    let esp = esp.image(ESP_SECTORS, ESP_START)?;
    let root = qemu::root_image()?;
    // On a padded disk the root partition takes the rest (less room for
    // alignment and the backup table, so the disk stays `min_bytes`): a
    // whole disk for `disk_hammer` to read.
    let root_size =
        min_bytes.saturating_sub(u64::from(ESP_START) * 512 + esp.len() as u64 + (2 << 20));
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
                size: root_size,
            },
        ],
        min_bytes,
    );
    if starts.first() != Some(&u64::from(ESP_START)) {
        return Err("disk: the ESP did not land where its boot sector says".into());
    }
    Ok(img)
}

/// What makes a raw disk of `len` bytes a fixed VHD (Azure's format): the
/// 512 bytes that follow it.
pub fn vhd_footer(len: u64) -> [u8; 512] {
    let mut f = [0u8; 512];
    let mut put = |at: usize, bytes: &[u8]| f[at..at + bytes.len()].copy_from_slice(bytes);
    put(0, b"conectix");
    put(8, &2u32.to_be_bytes()); // features: reserved, always set
    put(12, &0x0001_0000u32.to_be_bytes()); // format version
    put(16, &u64::MAX.to_be_bytes()); // a fixed disk has no header
    put(28, b"ichr");
    put(32, &0x0001_0000u32.to_be_bytes());
    put(36, b"Wi2k");
    put(40, &len.to_be_bytes());
    put(48, &len.to_be_bytes());
    let (cylinders, heads, sectors) = vhd_geometry(len / 512);
    put(56, &cylinders.to_be_bytes());
    put(58, &[heads, sectors]);
    put(60, &2u32.to_be_bytes()); // fixed
    put(68, b"ichor disk image");
    // The checksum is the complement of the sum of the rest.
    let sum = f.iter().fold(0u32, |s, &b| s.wrapping_add(u32::from(b)));
    f[64..68].copy_from_slice(&(!sum).to_be_bytes());
    f
}

/// The geometry the VHD specification derives from a size in sectors.
fn vhd_geometry(sectors: u64) -> (u16, u8, u8) {
    let total = sectors.min(65_535 * 16 * 255) as u32;
    let (mut per_track, mut heads);
    let mut tracks;
    if total >= 65_535 * 16 * 63 {
        (per_track, heads) = (255, 16);
        tracks = total / per_track;
    } else {
        per_track = 17;
        tracks = total / per_track;
        heads = tracks.div_ceil(1024).max(4);
        for more in [31, 63] {
            if tracks >= heads * 1024 || heads > 16 {
                (per_track, heads) = (more, 16);
                tracks = total / per_track;
            }
        }
    }
    ((tracks / heads) as u16, heads as u8, per_track as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vhd_footer_is_what_the_format_says() {
        let f = vhd_footer(1 << 30);
        assert_eq!(&f[..8], b"conectix");
        assert_eq!(f[48..56], (1u64 << 30).to_be_bytes());
        // 2080 cylinders of 16 heads of 63 sectors, as Windows makes for 1 GiB.
        assert_eq!(f[56..60], [0x08, 0x20, 16, 63]);
        assert_eq!(f[60..64], [0, 0, 0, 2]);
        let sum = |skip: std::ops::Range<usize>| {
            let rest = f.iter().enumerate().filter(|(i, _)| !skip.contains(i));
            rest.fold(0u32, |s, (_, &b)| s + u32::from(b))
        };
        assert_eq!(f[64..68], (!sum(64..68)).to_be_bytes());
    }

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
