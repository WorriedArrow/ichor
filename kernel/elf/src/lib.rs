//! ELF64 parsing for the program loader.
//!
//! This computes a *load plan* from an ELF image: the segments to map, their
//! permissions and file/memory extents, the entry point, and the interpreter
//! path (`PT_INTERP`) for a dynamically linked binary. It copies nothing and
//! maps nothing; the kernel's loader walks the plan and populates a `VmSpace`
//! through frame. Every field is bounds-checked, so a malformed binary yields
//! an [`Error`], never a panic or an out-of-range read.

#![no_std]
#![forbid(unsafe_code)]

/// Why an image was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadMagic,
    NotElf64,
    NotLittleEndian,
    UnsupportedMachine,
    BadType,
    TooManySegments,
    BadSegment,
}

const EI_NIDENT: usize = 16;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 0x3e;
const EM_AARCH64: u16 = 0xb7;

/// Maximum `PT_LOAD` segments recorded.
pub const MAX_SEGMENTS: usize = 16;

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    let s = b.get(at..at + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    let s = b.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    let lo = u32_at(b, at)? as u64;
    let hi = u32_at(b, at + 4)? as u64;
    Ok(lo | (hi << 32))
}

/// Access permissions of a loadable segment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

/// One `PT_LOAD` segment to map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Offset of the segment's bytes in the file.
    pub file_offset: u64,
    /// Number of bytes present in the file.
    pub file_size: u64,
    /// Virtual address to map at.
    pub vaddr: u64,
    /// Size in memory; bytes beyond `file_size` are zero (`.bss`).
    pub mem_size: u64,
    pub flags: Flags,
}

impl Segment {
    /// The page-aligned `[start, end)` virtual range this segment occupies.
    pub fn page_range(&self, page: u64) -> (u64, u64) {
        let start = self.vaddr / page * page;
        let end = (self.vaddr + self.mem_size).div_ceil(page) * page;
        (start, end)
    }
}

/// Which architecture an image targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Machine {
    X86_64,
    Aarch64,
}

/// A plan for loading an ELF image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadPlan {
    pub machine: Machine,
    /// True for a position-independent executable (`ET_DYN`).
    pub pie: bool,
    /// Entry point as stated in the header (before any load bias).
    pub entry: u64,
    /// `[interp_offset, interp_offset+len)` of the interpreter path in the
    /// file, if the binary is dynamically linked.
    pub interp: Option<(u64, u64)>,
    segments: [Segment; MAX_SEGMENTS],
    segment_count: usize,
}

impl LoadPlan {
    /// The loadable segments.
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.segment_count]
    }

    /// The lowest and highest page-aligned virtual addresses the image spans.
    pub fn address_span(&self, page: u64) -> Option<(u64, u64)> {
        let mut lo = u64::MAX;
        let mut hi = 0;
        for s in self.segments() {
            let (a, b) = s.page_range(page);
            lo = lo.min(a);
            hi = hi.max(b);
        }
        (self.segment_count > 0).then_some((lo, hi))
    }
}

/// Parses an ELF64 image into a load plan. `len` is the full image length so
/// that segment extents can be validated against it.
pub fn parse(image: &[u8]) -> Result<LoadPlan, Error> {
    if image.get(0..4) != Some(&[0x7f, b'E', b'L', b'F']) {
        return Err(Error::BadMagic);
    }
    if image.get(4) != Some(&2) {
        return Err(Error::NotElf64);
    }
    if image.get(5) != Some(&1) {
        return Err(Error::NotLittleEndian);
    }
    let e_type = u16_at(image, EI_NIDENT)?;
    let pie = match e_type {
        ET_EXEC => false,
        ET_DYN => true,
        _ => return Err(Error::BadType),
    };
    let machine = match u16_at(image, EI_NIDENT + 2)? {
        EM_X86_64 => Machine::X86_64,
        EM_AARCH64 => Machine::Aarch64,
        _ => return Err(Error::UnsupportedMachine),
    };
    let entry = u64_at(image, 24)?;
    let phoff = u64_at(image, 32)? as usize;
    let phentsize = u16_at(image, 54)? as usize;
    let phnum = u16_at(image, 56)? as usize;
    if phentsize < 56 {
        return Err(Error::BadSegment);
    }

    let mut segments = [Segment {
        file_offset: 0,
        file_size: 0,
        vaddr: 0,
        mem_size: 0,
        flags: Flags::default(),
    }; MAX_SEGMENTS];
    let mut count = 0;
    let mut interp = None;
    let mut last_end = 0u64;

    for i in 0..phnum {
        let ph = phoff
            .checked_add(i.checked_mul(phentsize).ok_or(Error::Truncated)?)
            .ok_or(Error::Truncated)?;
        let p_type = u32_at(image, ph)?;
        let p_flags = u32_at(image, ph + 4)?;
        let p_offset = u64_at(image, ph + 8)?;
        let p_vaddr = u64_at(image, ph + 16)?;
        let p_filesz = u64_at(image, ph + 32)?;
        let p_memsz = u64_at(image, ph + 40)?;

        match p_type {
            PT_INTERP => {
                let end = p_offset.checked_add(p_filesz).ok_or(Error::BadSegment)?;
                if end as usize > image.len() || p_filesz == 0 {
                    return Err(Error::BadSegment);
                }
                // Drop a trailing NUL from the length.
                let len = if image.get((end - 1) as usize) == Some(&0) {
                    p_filesz - 1
                } else {
                    p_filesz
                };
                interp = Some((p_offset, len));
            }
            PT_LOAD => {
                if p_memsz < p_filesz {
                    return Err(Error::BadSegment);
                }
                let fend = p_offset.checked_add(p_filesz).ok_or(Error::BadSegment)?;
                if fend as usize > image.len() {
                    return Err(Error::BadSegment);
                }
                let vend = p_vaddr.checked_add(p_memsz).ok_or(Error::BadSegment)?;
                // Segments must be sorted and non-overlapping by vaddr.
                if p_vaddr < last_end {
                    return Err(Error::BadSegment);
                }
                last_end = vend;
                if count >= MAX_SEGMENTS {
                    return Err(Error::TooManySegments);
                }
                segments[count] = Segment {
                    file_offset: p_offset,
                    file_size: p_filesz,
                    vaddr: p_vaddr,
                    mem_size: p_memsz,
                    flags: Flags {
                        read: p_flags & PF_R != 0,
                        write: p_flags & PF_W != 0,
                        exec: p_flags & PF_X != 0,
                    },
                };
                count += 1;
            }
            _ => {}
        }
    }

    if count == 0 {
        return Err(Error::BadSegment);
    }
    Ok(LoadPlan {
        machine,
        pie,
        entry,
        interp,
        segments,
        segment_count: count,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Builds a minimal ELF64 with the given program headers
    /// `(type, flags, offset, vaddr, filesz, memsz)`.
    fn elf(
        e_type: u16,
        machine: u16,
        entry: u64,
        phs: &[(u32, u32, u64, u64, u64, u64)],
    ) -> Vec<u8> {
        let phoff = 64u64;
        let phentsize = 56usize;
        let min = 64 + phs.len() * phentsize;
        let extent = phs
            .iter()
            .map(|&(_, _, off, _, fsz, _)| (off + fsz) as usize)
            .max()
            .unwrap_or(0);
        let mut b = std::vec![0u8; min.max(extent) + 64];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // ELF64
        b[5] = 1; // little endian
        b[EI_NIDENT..EI_NIDENT + 2].copy_from_slice(&e_type.to_le_bytes());
        b[EI_NIDENT + 2..EI_NIDENT + 4].copy_from_slice(&machine.to_le_bytes());
        b[24..32].copy_from_slice(&entry.to_le_bytes());
        b[32..40].copy_from_slice(&phoff.to_le_bytes());
        b[54..56].copy_from_slice(&(phentsize as u16).to_le_bytes());
        b[56..58].copy_from_slice(&(phs.len() as u16).to_le_bytes());
        for (i, &(t, f, off, va, fsz, msz)) in phs.iter().enumerate() {
            let p = phoff as usize + i * phentsize;
            b[p..p + 4].copy_from_slice(&t.to_le_bytes());
            b[p + 4..p + 8].copy_from_slice(&f.to_le_bytes());
            b[p + 8..p + 16].copy_from_slice(&off.to_le_bytes());
            b[p + 16..p + 24].copy_from_slice(&va.to_le_bytes());
            b[p + 32..p + 40].copy_from_slice(&fsz.to_le_bytes());
            b[p + 40..p + 48].copy_from_slice(&msz.to_le_bytes());
        }
        b
    }

    #[test]
    fn parses_static_executable() {
        let img = elf(
            ET_EXEC,
            EM_X86_64,
            0x401000,
            &[
                (PT_LOAD, PF_R | PF_X, 0x1000, 0x401000, 0x200, 0x200),
                (PT_LOAD, PF_R | PF_W, 0x1200, 0x402000, 0x50, 0x400),
            ],
        );
        let plan = parse(&img).unwrap();
        assert_eq!(plan.machine, Machine::X86_64);
        assert!(!plan.pie);
        assert_eq!(plan.entry, 0x401000);
        assert!(plan.interp.is_none());
        assert_eq!(plan.segments().len(), 2);
        let text = plan.segments()[0];
        assert!(text.flags.exec && text.flags.read && !text.flags.write);
        let data = plan.segments()[1];
        assert_eq!(data.file_size, 0x50);
        assert_eq!(data.mem_size, 0x400); // has .bss
        assert_eq!(data.page_range(0x1000), (0x402000, 0x403000));
        assert_eq!(plan.address_span(0x1000), Some((0x401000, 0x403000)));
    }

    #[test]
    fn parses_pie_with_interp() {
        let mut img = elf(
            ET_DYN,
            EM_X86_64,
            0x1000,
            &[
                (PT_INTERP, PF_R, 0x300, 0, 18, 18),
                (PT_LOAD, PF_R | PF_X, 0, 0, 0x400, 0x400),
            ],
        );
        let interp_path = b"/lib/ld-musl.so.1\0";
        img[0x300..0x300 + interp_path.len()].copy_from_slice(interp_path);
        let plan = parse(&img).unwrap();
        assert!(plan.pie);
        let (off, len) = plan.interp.unwrap();
        assert_eq!(off, 0x300);
        assert_eq!(
            &img[off as usize..(off + len) as usize],
            b"/lib/ld-musl.so.1"
        );
    }

    #[test]
    fn rejects_bad_images() {
        assert_eq!(parse(b""), Err(Error::BadMagic));
        assert_eq!(parse(&[0x7f, b'E', b'L', b'F', 1]), Err(Error::NotElf64));
        let bad_type = elf(99, EM_X86_64, 0, &[(PT_LOAD, PF_R, 0, 0, 0x10, 0x10)]);
        assert_eq!(parse(&bad_type), Err(Error::BadType));
        let bad_mach = elf(ET_EXEC, 0x28, 0, &[(PT_LOAD, PF_R, 0, 0, 0x10, 0x10)]);
        assert_eq!(parse(&bad_mach), Err(Error::UnsupportedMachine));
        // memsz < filesz
        let bad_seg = elf(ET_EXEC, EM_X86_64, 0, &[(PT_LOAD, PF_R, 0, 0, 0x20, 0x10)]);
        assert_eq!(parse(&bad_seg), Err(Error::BadSegment));
        // segment extends past the file
        let mut oob = elf(
            ET_EXEC,
            EM_X86_64,
            0,
            &[(PT_LOAD, PF_R, 0, 0, 0x100, 0x100)],
        );
        // Point the segment's file offset past the (truncated) image.
        let ph = 64;
        oob[ph + 8..ph + 16].copy_from_slice(&0x100000u64.to_le_bytes());
        assert_eq!(parse(&oob), Err(Error::BadSegment));
        // no loadable segments
        let empty = elf(ET_EXEC, EM_X86_64, 0, &[]);
        assert_eq!(parse(&empty), Err(Error::BadSegment));
    }

    #[test]
    fn overlapping_segments_rejected() {
        let img = elf(
            ET_EXEC,
            EM_X86_64,
            0,
            &[
                (PT_LOAD, PF_R, 0, 0x1000, 0x100, 0x2000),
                (PT_LOAD, PF_R, 0x100, 0x1500, 0x100, 0x100), // overlaps the first
            ],
        );
        assert_eq!(parse(&img), Err(Error::BadSegment));
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 1;
        for len in 0..300 {
            let g: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    (x >> 16) as u8
                })
                .collect();
            let _ = parse(&g);
        }
    }
}
