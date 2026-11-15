//! Minimal PE32+ (x86_64/aarch64 UEFI image) parsing.
//!
//! Frame uses this to re-map the running kernel image into the higher half:
//! it needs the section table (to map each section with the right
//! permissions) and the base relocations (to rebase absolute pointers). Both
//! are parsed from byte slices with bounds checks; nothing here can fail by
//! reading out of range, and malformed input yields an [`Error`].

#![no_std]
#![forbid(unsafe_code)]

/// Why an image could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ends before a structure it should contain.
    Truncated,
    /// Missing `MZ` or `PE\0\0` signature.
    BadSignature,
    /// Not a PE32+ (64-bit) optional header.
    NotPe32Plus,
    /// The image has more sections than [`MAX_SECTIONS`].
    TooManySections,
    /// A relocation block is malformed.
    BadRelocBlock,
    /// A relocation type other than `ABSOLUTE` or `DIR64`.
    UnsupportedReloc(u8),
}

/// Maximum number of sections this parser records.
pub const MAX_SECTIONS: usize = 16;

/// Section characteristic: contains executable code.
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Section characteristic: readable.
pub const SCN_MEM_READ: u32 = 0x4000_0000;
/// Section characteristic: writable.
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const DIRECTORY_BASERELOC: usize = 5;

const REL_ABSOLUTE: u8 = 0;
const REL_DIR64: u8 = 10;

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    let s = b
        .get(at..at.checked_add(2).ok_or(Error::Truncated)?)
        .ok_or(Error::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    let s = b
        .get(at..at.checked_add(4).ok_or(Error::Truncated)?)
        .ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    let lo = u32_at(b, at)? as u64;
    let hi = u32_at(b, at.checked_add(4).ok_or(Error::Truncated)?)? as u64;
    Ok(lo | (hi << 32))
}

/// One entry of the section table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Section {
    /// Section name, NUL-padded (not necessarily NUL-terminated).
    pub name: [u8; 8],
    /// Offset of the section from the image base.
    pub virtual_address: u32,
    /// Size of the section in memory.
    pub virtual_size: u32,
    /// `IMAGE_SCN_*` flags.
    pub characteristics: u32,
}

impl Section {
    /// The name as a string, without padding (lossy on non-UTF-8).
    pub fn name_str(&self) -> &str {
        let len = self
            .name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..len]).unwrap_or("?")
    }

    /// Whether the section is executable.
    pub fn is_exec(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    /// Whether the section is writable.
    pub fn is_write(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }
}

/// An RVA range from a data directory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataDir {
    pub rva: u32,
    pub size: u32,
}

/// The parts of the PE headers Ichor needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Headers {
    /// `IMAGE_FILE_MACHINE_*`.
    pub machine: u16,
    /// Preferred base address the image was linked at.
    pub image_base: u64,
    /// Section alignment in memory.
    pub section_alignment: u32,
    /// Total size of the loaded image.
    pub size_of_image: u32,
    /// Size of the headers at the start of the image.
    pub size_of_headers: u32,
    /// Base relocation directory, if the image has one.
    pub base_relocs: Option<DataDir>,
    sections: [Section; MAX_SECTIONS],
    section_count: usize,
}

impl Headers {
    /// The section table.
    pub fn sections(&self) -> &[Section] {
        &self.sections[..self.section_count]
    }
}

/// Parses PE32+ headers from the start of an image (in memory or on disk; the
/// headers are laid out the same way in both).
pub fn parse_headers(b: &[u8]) -> Result<Headers, Error> {
    if b.get(0..2) != Some(b"MZ") {
        return Err(Error::BadSignature);
    }
    let pe = u32_at(b, 0x3c)? as usize;
    if b.get(pe..pe.checked_add(4).ok_or(Error::Truncated)?) != Some(b"PE\0\0") {
        return Err(Error::BadSignature);
    }
    let coff = pe + 4;
    let machine = u16_at(b, coff)?;
    if machine != IMAGE_FILE_MACHINE_AMD64 && machine != IMAGE_FILE_MACHINE_ARM64 {
        return Err(Error::BadSignature);
    }
    let section_count = u16_at(b, coff + 2)? as usize;
    let opt_size = u16_at(b, coff + 16)? as usize;
    let opt = coff + 20;
    if u16_at(b, opt)? != PE32_PLUS_MAGIC {
        return Err(Error::NotPe32Plus);
    }
    let image_base = u64_at(b, opt + 24)?;
    let section_alignment = u32_at(b, opt + 32)?;
    let size_of_image = u32_at(b, opt + 56)?;
    let size_of_headers = u32_at(b, opt + 60)?;
    let dir_count = u32_at(b, opt + 108)? as usize;
    let base_relocs = if dir_count > DIRECTORY_BASERELOC {
        let at = opt + 112 + DIRECTORY_BASERELOC * 8;
        let dir = DataDir {
            rva: u32_at(b, at)?,
            size: u32_at(b, at + 4)?,
        };
        (dir.size != 0).then_some(dir)
    } else {
        None
    };

    if section_count > MAX_SECTIONS {
        return Err(Error::TooManySections);
    }
    let mut sections = [Section::default(); MAX_SECTIONS];
    let table = opt + opt_size;
    for (i, s) in sections.iter_mut().take(section_count).enumerate() {
        let at = table + i * 40;
        let name = b.get(at..at + 8).ok_or(Error::Truncated)?;
        s.name.copy_from_slice(name);
        s.virtual_size = u32_at(b, at + 8)?;
        s.virtual_address = u32_at(b, at + 12)?;
        s.characteristics = u32_at(b, at + 36)?;
    }
    Ok(Headers {
        machine,
        image_base,
        section_alignment,
        size_of_image,
        size_of_headers,
        base_relocs,
        sections,
        section_count,
    })
}

/// Iterates over the RVAs of the 64-bit slots a base relocation table asks
/// to adjust. `ABSOLUTE` padding entries are skipped; any other type is an
/// error (Ichor images contain only `DIR64`).
pub fn dir64_relocations(table: &[u8]) -> Relocations<'_> {
    Relocations {
        table,
        block: 0,
        entry: 0,
    }
}

/// Iterator returned by [`dir64_relocations`].
#[derive(Clone, Debug)]
pub struct Relocations<'a> {
    table: &'a [u8],
    /// Offset of the current block header.
    block: usize,
    /// Index of the next entry within the current block.
    entry: usize,
}

impl Iterator for Relocations<'_> {
    type Item = Result<u32, Error>;

    fn next(&mut self) -> Option<Result<u32, Error>> {
        loop {
            if self.block >= self.table.len() {
                return None;
            }
            let header = (|| {
                let page = u32_at(self.table, self.block)?;
                let size = u32_at(self.table, self.block + 4)? as usize;
                if size < 8 || !size.is_multiple_of(2) || self.block + size > self.table.len() {
                    return Err(Error::BadRelocBlock);
                }
                Ok((page, size))
            })();
            let (page, size) = match header {
                Ok(h) => h,
                Err(e) => {
                    self.block = self.table.len(); // stop after reporting
                    return Some(Err(e));
                }
            };
            let entries = (size - 8) / 2;
            if self.entry >= entries {
                self.block += size;
                self.entry = 0;
                continue;
            }
            let at = self.block + 8 + self.entry * 2;
            self.entry += 1;
            let e = match u16_at(self.table, at) {
                Ok(e) => e,
                Err(err) => return Some(Err(err)),
            };
            let kind = (e >> 12) as u8;
            match kind {
                REL_ABSOLUTE => continue,
                REL_DIR64 => return Some(Ok(page.wrapping_add(u32::from(e & 0xfff)))),
                other => {
                    self.block = self.table.len();
                    return Some(Err(Error::UnsupportedReloc(other)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Builds a minimal PE32+ header with the given sections.
    fn image(sections: &[(&[u8], u32, u32, u32)], reloc: Option<DataDir>) -> Vec<u8> {
        let mut b = std::vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        b[coff..coff + 2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        b[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        b[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        b[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        b[opt + 56..opt + 60].copy_from_slice(&0x5000u32.to_le_bytes());
        b[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        if let Some(r) = reloc {
            let at = opt + 112 + 5 * 8;
            b[at..at + 4].copy_from_slice(&r.rva.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&r.size.to_le_bytes());
        }
        let table = opt + 240;
        for (i, (name, va, vs, ch)) in sections.iter().enumerate() {
            let at = table + i * 40;
            b[at..at + name.len()].copy_from_slice(name);
            b[at + 8..at + 12].copy_from_slice(&vs.to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&va.to_le_bytes());
            b[at + 36..at + 40].copy_from_slice(&ch.to_le_bytes());
        }
        b
    }

    #[test]
    fn parses_synthetic_headers() {
        let img = image(
            &[
                (b".text", 0x1000, 0x123, SCN_MEM_EXECUTE | SCN_MEM_READ),
                (b".data", 0x2000, 0x2000, SCN_MEM_READ | SCN_MEM_WRITE),
            ],
            Some(DataDir {
                rva: 0x4000,
                size: 12,
            }),
        );
        let h = parse_headers(&img).unwrap();
        assert_eq!(h.image_base, 0x1_4000_0000);
        assert_eq!(h.section_alignment, 0x1000);
        assert_eq!(h.size_of_image, 0x5000);
        assert_eq!(
            h.base_relocs,
            Some(DataDir {
                rva: 0x4000,
                size: 12
            })
        );
        assert_eq!(h.sections().len(), 2);
        assert_eq!(h.sections()[0].name_str(), ".text");
        assert!(h.sections()[0].is_exec() && !h.sections()[0].is_write());
        assert!(h.sections()[1].is_write() && !h.sections()[1].is_exec());
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(parse_headers(b""), Err(Error::BadSignature));
        assert_eq!(parse_headers(b"MZ"), Err(Error::Truncated));
        let mut img = image(&[], None);
        img[0x80] = b'X';
        assert_eq!(parse_headers(&img), Err(Error::BadSignature));
        let mut img = image(&[], None);
        img[0x84 + 20] = 0x0b; // PE32 magic 0x10b
        img[0x84 + 21] = 0x01;
        assert_eq!(parse_headers(&img), Err(Error::NotPe32Plus));
        // Every truncation of a valid header fails cleanly.
        let img = image(&[(b".text", 0x1000, 0x10, 0)], None);
        for len in 0..0x84 + 20 + 240 + 40 {
            assert!(parse_headers(&img[..len]).is_err(), "len {len}");
        }
    }

    fn block(page: u32, entries: &[u16]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&page.to_le_bytes());
        v.extend_from_slice(&((8 + entries.len() * 2) as u32).to_le_bytes());
        for e in entries {
            v.extend_from_slice(&e.to_le_bytes());
        }
        v
    }

    #[test]
    fn iterates_dir64_and_skips_padding() {
        let mut t = block(0x1000, &[0xA008, 0xA010, 0x0000]);
        t.extend(block(0x3000, &[0xAFF8, 0x0000]));
        let rvas: Vec<u32> = dir64_relocations(&t).map(Result::unwrap).collect();
        assert_eq!(rvas, [0x1008, 0x1010, 0x3ff8]);
    }

    #[test]
    fn reloc_errors() {
        let t = block(0x1000, &[0x3004]); // HIGHLOW
        let r: Vec<_> = dir64_relocations(&t).collect();
        assert_eq!(r, [Err(Error::UnsupportedReloc(3))]);
        let mut t = block(0x1000, &[0xA000]);
        t[4] = 200; // block size past the end
        let r: Vec<_> = dir64_relocations(&t).collect();
        assert_eq!(r, [Err(Error::BadRelocBlock)]);
        // Arbitrary garbage never panics.
        let mut x: u32 = 12345;
        for len in 0..64 {
            let g: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            let _ = dir64_relocations(&g).take(1000).count();
            let _ = parse_headers(&g);
        }
    }

    /// Parses the real kernel image if one has been built.
    #[test]
    fn parses_built_kernel_if_present() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for profile in ["debug", "release"] {
            let path = root
                .join("target/kernel/x86_64-unknown-uefi")
                .join(profile)
                .join("ichor.efi");
            let Ok(file) = std::fs::read(&path) else {
                continue;
            };
            let h = parse_headers(&file).unwrap();
            assert_eq!(h.section_alignment, 0x1000);
            assert!(
                h.sections()
                    .iter()
                    .any(|s| s.name_str() == ".text" && s.is_exec())
            );
            let dir = h.base_relocs.unwrap();
            // Find the relocation table in the file via its section.
            let sec = h
                .sections()
                .iter()
                .find(|s| {
                    s.virtual_address <= dir.rva && dir.rva < s.virtual_address + s.virtual_size
                })
                .unwrap();
            // Section raw data offset is at +20 in the header; re-read it.
            let pe = u32_at(&file, 0x3c).unwrap() as usize;
            let opt_size = u16_at(&file, pe + 4 + 16).unwrap() as usize;
            let table = pe + 24 + opt_size;
            let idx = h.sections().iter().position(|s| s == sec).unwrap();
            let raw = u32_at(&file, table + idx * 40 + 20).unwrap() as usize;
            let off = raw + (dir.rva - sec.virtual_address) as usize;
            let relocs = &file[off..off + dir.size as usize];
            let n = dir64_relocations(relocs).map(Result::unwrap).count();
            assert!(n > 0);
        }
    }
}
