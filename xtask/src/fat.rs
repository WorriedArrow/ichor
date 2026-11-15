//! A minimal FAT32 writer for the EFI system partition of a boot disk
//! (Microsoft's FAT specification, "FAT: General Overview of On-Disk
//! Format"). 512-byte sectors, one sector per cluster, two FATs, an FSInfo
//! sector and a backup boot sector; directories and files are laid out in
//! contiguous cluster chains. Names are 8.3 (upper case), which is all the
//! ESP needs (`EFI\BOOT\BOOTX64.EFI`, `ICHOR\CMDLINE`).

use std::collections::BTreeMap;

use crate::Result;

const SECTOR: usize = 512;
const RESERVED: u32 = 32;
const FATS: u32 = 2;
/// FAT32 needs at least this many clusters (the specification's bound).
const MIN_CLUSTERS: u32 = 65_525;
const EOC: u32 = 0x0FFF_FFFF;

#[derive(Debug)]
enum Node {
    File(Vec<u8>),
    Dir(BTreeMap<String, Node>),
}

/// A tree of files to put in the volume.
#[derive(Debug, Default)]
pub struct Volume {
    root: BTreeMap<String, Node>,
}

/// `name` as an 8.3 directory-entry name, if it is one.
fn short_name(name: &str) -> Result<[u8; 11]> {
    let (base, ext) = name.split_once('.').unwrap_or((name, ""));
    let valid = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || !valid(base) || !valid(ext) {
        return Err(format!("fat: {name:?} is not an upper-case 8.3 name"));
    }
    let mut out = [b' '; 11];
    out[..base.len()].copy_from_slice(base.as_bytes());
    out[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    Ok(out)
}

impl Volume {
    /// Adds a file at `path` (`/`-separated 8.3 components), creating its
    /// directories.
    pub fn add(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let (file, dirs) = parts.split_last().ok_or("fat: empty path")?;
        let mut dir = &mut self.root;
        for d in dirs {
            short_name(d)?;
            let node = dir
                .entry((*d).to_string())
                .or_insert_with(|| Node::Dir(BTreeMap::new()));
            dir = match node {
                Node::Dir(m) => m,
                Node::File(_) => return Err(format!("fat: {d} is a file")),
            };
        }
        short_name(file)?;
        dir.insert((*file).to_string(), Node::File(data.to_vec()));
        Ok(())
    }

    /// The formatted volume, `sectors` 512-byte sectors long; `hidden` is
    /// the partition's first sector on the disk (recorded in the boot
    /// sector, as firmware expects).
    pub fn image(&self, sectors: u32, hidden: u32) -> Result<Vec<u8>> {
        // FAT size: each FAT holds an entry per cluster plus two reserved.
        let mut fat_sectors = 1u32;
        let clusters = loop {
            let data = sectors
                .checked_sub(RESERVED + FATS * fat_sectors)
                .ok_or("fat: volume too small")?;
            let need = ((data + 2) * 4).div_ceil(SECTOR as u32);
            if need <= fat_sectors {
                break data;
            }
            fat_sectors = need;
        };
        if clusters < MIN_CLUSTERS {
            return Err(format!(
                "fat: {clusters} clusters is too few for FAT32 (at least {MIN_CLUSTERS}); make the volume larger"
            ));
        }
        // Byte offset of cluster 2.
        let data_start = (RESERVED + FATS * fat_sectors) as usize * SECTOR;
        let mut img = vec![0u8; sectors as usize * SECTOR];
        let mut fat = vec![0u32; clusters as usize + 2];
        fat[0] = 0x0FFF_FFF8;
        fat[1] = EOC;
        let mut next = 2u32;
        let mut alloc = |len: usize, fat: &mut Vec<u32>| -> Result<u32> {
            let n = len.div_ceil(SECTOR).max(1) as u32;
            let first = next;
            if first + n > clusters + 2 {
                return Err("fat: volume full".into());
            }
            for c in first..first + n {
                fat[c as usize] = if c + 1 < first + n { c + 1 } else { EOC };
            }
            next += n;
            Ok(first)
        };

        // Directories first get their clusters, then their entries: a
        // directory's size is known from its children.
        fn dir_bytes(entries: usize) -> usize {
            (entries * 32).max(SECTOR)
        }
        #[allow(clippy::too_many_arguments)] // the recursion's whole state
        fn place(
            dir: &BTreeMap<String, Node>,
            cluster: u32,
            parent: u32,
            is_root: bool,
            img: &mut [u8],
            fat: &mut Vec<u32>,
            alloc: &mut dyn FnMut(usize, &mut Vec<u32>) -> Result<u32>,
            data_start: usize,
        ) -> Result<()> {
            let mut entries: Vec<[u8; 32]> = Vec::new();
            let entry = |name: [u8; 11], attr: u8, first: u32, size: u32| {
                let mut e = [0u8; 32];
                e[..11].copy_from_slice(&name);
                e[11] = attr;
                e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
                e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
                e[28..32].copy_from_slice(&size.to_le_bytes());
                e
            };
            if !is_root {
                let mut dot = [b' '; 11];
                dot[0] = b'.';
                entries.push(entry(dot, 0x10, cluster, 0));
                let mut dotdot = [b' '; 11];
                dotdot[..2].copy_from_slice(b"..");
                // A parent that is the root is written as cluster 0.
                entries.push(entry(dotdot, 0x10, parent, 0));
            }
            for (name, node) in dir {
                let short = short_name(name)?;
                match node {
                    Node::File(data) => {
                        let first = alloc(data.len(), fat)?;
                        let at = data_start + (first as usize - 2) * SECTOR;
                        img[at..at + data.len()].copy_from_slice(data);
                        let size = u32::try_from(data.len()).map_err(|_| "fat: file too large")?;
                        entries.push(entry(short, 0x20, first, size));
                    }
                    Node::Dir(children) => {
                        let first = alloc(dir_bytes(children.len() + 2), fat)?;
                        place(
                            children,
                            first,
                            if is_root { 0 } else { cluster },
                            false,
                            img,
                            fat,
                            alloc,
                            data_start,
                        )?;
                        entries.push(entry(short, 0x10, first, 0));
                    }
                }
            }
            let at = data_start + (cluster as usize - 2) * SECTOR;
            for (i, e) in entries.iter().enumerate() {
                img[at + i * 32..at + i * 32 + 32].copy_from_slice(e);
            }
            Ok(())
        }
        let root = alloc(dir_bytes(self.root.len()), &mut fat)?;
        place(
            &self.root, root, 0, true, &mut img, &mut fat, &mut alloc, data_start,
        )?;

        // Boot sector (and its backup at sector 6), FSInfo at sector 1.
        let mut bs = [0u8; SECTOR];
        bs[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        bs[3..11].copy_from_slice(b"ICHOR   ");
        bs[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        bs[13] = 1; // sectors per cluster
        bs[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        bs[16] = FATS as u8;
        bs[21] = 0xF8; // fixed media
        bs[24..26].copy_from_slice(&32u16.to_le_bytes()); // sectors per track
        bs[26..28].copy_from_slice(&64u16.to_le_bytes()); // heads
        bs[28..32].copy_from_slice(&hidden.to_le_bytes());
        bs[32..36].copy_from_slice(&sectors.to_le_bytes());
        bs[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
        bs[44..48].copy_from_slice(&root.to_le_bytes());
        bs[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
        bs[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector
        bs[64] = 0x80; // drive number
        bs[66] = 0x29; // extended boot signature
        bs[67..71].copy_from_slice(&0x1C4A_3B7Eu32.to_le_bytes()); // volume id
        bs[71..82].copy_from_slice(b"ICHOR ESP  ");
        bs[82..90].copy_from_slice(b"FAT32   ");
        bs[510] = 0x55;
        bs[511] = 0xAA;
        img[..SECTOR].copy_from_slice(&bs);
        img[6 * SECTOR..7 * SECTOR].copy_from_slice(&bs);
        let mut info = [0u8; SECTOR];
        info[..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        let free = clusters + 2 - next;
        info[488..492].copy_from_slice(&free.to_le_bytes());
        info[492..496].copy_from_slice(&next.to_le_bytes());
        info[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
        img[SECTOR..2 * SECTOR].copy_from_slice(&info);
        img[7 * SECTOR..8 * SECTOR].copy_from_slice(&info);
        // The FATs.
        for i in 0..FATS as usize {
            let at = (RESERVED as usize + i * fat_sectors as usize) * SECTOR;
            for (j, e) in fat.iter().enumerate() {
                img[at + j * 4..at + j * 4 + 4].copy_from_slice(&e.to_le_bytes());
            }
        }
        Ok(img)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_at(b: &[u8], at: usize) -> usize {
        usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
    }
    fn u32_at(b: &[u8], at: usize) -> usize {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
    }

    /// A tiny independent reader: follows the path from the root cluster,
    /// using only the boot sector's geometry and the FAT chains.
    fn read(img: &[u8], path: &str) -> Option<Vec<u8>> {
        let reserved = u16_at(img, 14);
        let fats = usize::from(img[16]);
        let fat_sectors = u32_at(img, 36);
        let data = (reserved + fats * fat_sectors) * SECTOR;
        let fat = |c: usize| u32_at(img, reserved * SECTOR + c * 4) & 0x0FFF_FFFF;
        let chain = |first: usize| {
            let mut out = Vec::new();
            let mut c = first;
            loop {
                out.extend_from_slice(&img[data + (c - 2) * SECTOR..data + (c - 1) * SECTOR]);
                let n = fat(c);
                if n >= 0x0FFF_FFF8 {
                    return out;
                }
                c = n;
            }
        };
        let mut cluster = u32_at(img, 44);
        let parts: Vec<&str> = path.split('/').collect();
        for (i, name) in parts.iter().enumerate() {
            let want = short_name(name).ok()?;
            let dir = chain(cluster);
            let e = dir.chunks(32).find(|e| e[..11] == want)?;
            cluster = (u16_at(e, 20) << 16) | u16_at(e, 26);
            if i == parts.len() - 1 {
                let size = u32_at(e, 28);
                return Some(chain(cluster)[..size].to_vec());
            }
        }
        None
    }

    #[test]
    fn files_read_back_through_directories() {
        let mut v = Volume::default();
        let big: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        v.add("EFI/BOOT/BOOTX64.EFI", &big).unwrap();
        v.add("ICHOR/CMDLINE", b"qemu_debug_exit").unwrap();
        let img = v.image(131_072, 2048).unwrap();
        assert_eq!(&img[82..90], b"FAT32   ");
        assert_eq!(&img[510..512], &[0x55, 0xAA]);
        assert_eq!(u32_at(&img, 28), 2048);
        assert_eq!(read(&img, "EFI/BOOT/BOOTX64.EFI").unwrap(), big);
        assert_eq!(read(&img, "ICHOR/CMDLINE").unwrap(), b"qemu_debug_exit");
        assert!(read(&img, "EFI/NOPE").is_none());
        // Subdirectories start with "." and "..".
        let reserved = u16_at(&img, 14);
        let data = (reserved + 2 * u32_at(&img, 36)) * SECTOR;
        let efi = img[data..data + SECTOR]
            .chunks(32)
            .find(|e| &e[..11] == b"EFI        ")
            .map(|e| (u16_at(e, 20) << 16) | u16_at(e, 26))
            .unwrap();
        let at = data + (efi - 2) * SECTOR;
        assert_eq!(&img[at..at + 2], b". ");
        assert_eq!(&img[at + 32..at + 34], b"..");
    }

    #[test]
    fn rejects_bad_names_and_small_volumes() {
        let mut v = Volume::default();
        assert!(v.add("efi/boot", b"x").is_err());
        assert!(v.add("TOOLONGNAME/X", b"x").is_err());
        assert!(v.add("A.TOOLONG", b"x").is_err());
        assert!(Volume::default().image(40_000, 0).is_err());
    }
}
