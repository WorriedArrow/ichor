//! A kernel a PVH loader can start (ADR-0025): Firecracker, Cloud
//! Hypervisor, or QEMU's `-kernel`.
//!
//! The kernel is a UEFI application, a PE image. A PVH loader loads ELF
//! segments at their physical addresses and enters, in 32-bit protected
//! mode, at the address a `XEN_ELFNOTE_PHYS32_ENTRY` note gives. So
//! [`elf`] does what a UEFI loader would (sections at their RVAs, the rest
//! zero, DIR64 base relocations applied for the load address), fills in
//! the header of frame's entry stub (`kernel/frame/src/arch/x86_64/pvh.rs`)
//! and wraps the result in one `PT_LOAD` segment and the note.
//!
//! [`boot_files`] is what UEFI would read from `\ichor\` on the boot volume,
//! as the loader's first module (Firecracker's initrd).

use crate::Result;

/// Where the image is loaded: 16 MiB, Linux's default physical start, clear
/// of what loaders put in the first megabytes (Firecracker: start info,
/// command line, ACPI tables, the boot GDT).
pub const LOAD_ADDRESS: u64 = 0x100_0000;
/// The stub's scratch area past the image: six page-table pages, then a
/// 64 KiB stack.
const SCRATCH: u64 = 0x6000 + 0x1_0000;
const SIGNATURE: &[u8; 16] = b"IchorPVH32entry\0";
const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

/// The PE `efi` laid out at [`LOAD_ADDRESS`], in an ELF with a PVH note.
pub fn elf(efi: &[u8]) -> Result<Vec<u8>> {
    let h = pe::parse_headers(efi).map_err(|e| format!("kernel image: {e:?}"))?;
    let size = u64::from(h.size_of_image).next_multiple_of(0x1000);
    let mut img = vec![0u8; size as usize];
    let headers = (h.size_of_headers as usize).min(efi.len()).min(img.len());
    img[..headers].copy_from_slice(&efi[..headers]);
    for s in h.sections() {
        let n = s.raw_size.min(s.virtual_size) as usize;
        let (from, to) = (s.raw_offset as usize, s.virtual_address as usize);
        let src = efi
            .get(from..from + n)
            .ok_or_else(|| format!("section {} past the end of the file", s.name_str()))?;
        img.get_mut(to..to + n)
            .ok_or_else(|| format!("section {} past the image's size", s.name_str()))?
            .copy_from_slice(src);
    }
    // Base relocations, as a UEFI loader applies them for its address.
    if let Some(dir) = h.base_relocs {
        let (at, len) = (dir.rva as usize, dir.size as usize);
        let table = img
            .get(at..at + len)
            .ok_or("base relocations past the image")?
            .to_vec();
        let delta = LOAD_ADDRESS.wrapping_sub(h.image_base);
        for rva in pe::dir64_relocations(&table) {
            let rva = rva.map_err(|e| format!("base relocation: {e:?}"))? as usize;
            let slot = img
                .get_mut(rva..rva + 8)
                .ok_or("base relocation outside the image")?;
            let v = u64::from_le_bytes(slot.try_into().map_err(|_| "short slot")?);
            slot.copy_from_slice(&v.wrapping_add(delta).to_le_bytes());
        }
    }
    // The stub's header.
    let sig = img
        .windows(SIGNATURE.len())
        .position(|w| w == SIGNATURE)
        .ok_or("the kernel has no PVH entry stub (frame's arch::pvh)")?;
    let total = size + SCRATCH;
    let field = |img: &mut [u8], off: usize, v: u64| -> Result<()> {
        let v = u32::try_from(v).map_err(|_| "the image does not fit below 4 GiB")?;
        img[sig + off..sig + off + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    };
    field(&mut img, 16, LOAD_ADDRESS)?;
    field(&mut img, 20, total)?;
    field(&mut img, 24, LOAD_ADDRESS + size)?;
    // The entry's first instruction, `mov $imm32, %esp` (0xbc): the stack's
    // top, the scratch area's end (PVH gives the kernel no stack).
    if img.get(sig + 32) != Some(&0xbc) {
        return Err("the PVH entry stub does not start with `mov $imm32, %esp`".into());
    }
    field(&mut img, 33, LOAD_ADDRESS + total)?;
    let entry = LOAD_ADDRESS + sig as u64 + 32;
    Ok(wrap(&img, total, entry))
}

/// An ELF64 executable of one `PT_LOAD` segment (`img`, then zeros to
/// `memsz`) at [`LOAD_ADDRESS`], and a `PT_NOTE` with the PVH entry.
fn wrap(img: &[u8], memsz: u64, entry: u64) -> Vec<u8> {
    const EHDR: u64 = 64;
    const PHDR: u64 = 56;
    const DATA: u64 = 0x1000;
    let note_at = EHDR + 2 * PHDR;
    let mut note = Vec::new();
    note.extend_from_slice(&4u32.to_le_bytes()); // namesz
    note.extend_from_slice(&4u32.to_le_bytes()); // descsz
    note.extend_from_slice(&XEN_ELFNOTE_PHYS32_ENTRY.to_le_bytes());
    note.extend_from_slice(b"Xen\0");
    note.extend_from_slice(&(entry as u32).to_le_bytes());

    let mut e = Vec::new();
    e.extend_from_slice(b"\x7fELF");
    e.extend_from_slice(&[2, 1, 1, 0]); // 64-bit, little-endian, version 1, SysV
    e.extend_from_slice(&[0; 8]);
    e.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    e.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    e.extend_from_slice(&1u32.to_le_bytes());
    e.extend_from_slice(&entry.to_le_bytes());
    e.extend_from_slice(&EHDR.to_le_bytes()); // e_phoff
    e.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    e.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    e.extend_from_slice(&(EHDR as u16).to_le_bytes());
    e.extend_from_slice(&(PHDR as u16).to_le_bytes());
    e.extend_from_slice(&2u16.to_le_bytes()); // e_phnum
    e.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    e.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    // Type and flags, then offset, address (virtual and physical), sizes
    // in the file and in memory, alignment.
    let phdr = |e: &mut Vec<u8>, kind_flags: [u32; 2], v: [u64; 5]| {
        e.extend_from_slice(&kind_flags[0].to_le_bytes());
        e.extend_from_slice(&kind_flags[1].to_le_bytes());
        for v in [v[0], v[1], v[1], v[2], v[3], v[4]] {
            e.extend_from_slice(&v.to_le_bytes());
        }
    };
    let (n, img_len) = (note.len() as u64, img.len() as u64);
    phdr(&mut e, [1, 7], [DATA, LOAD_ADDRESS, img_len, memsz, 0x1000]); // PT_LOAD, RWX
    phdr(&mut e, [4, 4], [note_at, 0, n, n, 4]); // PT_NOTE
    e.extend_from_slice(&note);
    e.resize(DATA as usize, 0);
    e.extend_from_slice(img);
    e
}

/// The boot files module: `ICHORBF1`, then each file's `u16` name length,
/// name, `u32` length and bytes (`kernel/frame/src/boot/pvh.rs` reads it).
pub fn boot_files(token: Option<&[u8]>, tls: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut out = b"ICHORBF1".to_vec();
    let mut add = |name: &str, data: &[u8]| -> Result<()> {
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let len = u32::try_from(data.len()).map_err(|_| format!("{name} is too large"))?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(data);
        Ok(())
    };
    add("roots.pem", &crate::artifact::trust_bundle()?)?;
    add(
        "suffixes.dat",
        crate::artifact::public_suffix_rules()?.as_bytes(),
    )?;
    if let Some(t) = token {
        add("apitoken", t)?;
    }
    if let Some(t) = tls {
        add("apitls.pem", t)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PE32+ with one section holding the stub's signature at 0x10 and a
    /// pointer at 0x40 that a DIR64 relocation adjusts.
    fn pe() -> Vec<u8> {
        let mut f = vec![0u8; 0x600];
        f[0..2].copy_from_slice(b"MZ");
        f[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        f[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        f[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        f[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
        f[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        let opt = coff + 20;
        f[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        f[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        f[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        f[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
        f[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        let reloc = opt + 112 + 5 * 8;
        f[reloc..reloc + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        f[reloc + 4..reloc + 8].copy_from_slice(&12u32.to_le_bytes());
        let table = opt + 240;
        let section = |f: &mut [u8], i: usize, name: &[u8], va: u32, raw: u32, at: u32| {
            let s = table + i * 40;
            f[s..s + name.len()].copy_from_slice(name);
            f[s + 8..s + 12].copy_from_slice(&0x100u32.to_le_bytes());
            f[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
            f[s + 16..s + 20].copy_from_slice(&raw.to_le_bytes());
            f[s + 20..s + 24].copy_from_slice(&at.to_le_bytes());
        };
        section(&mut f, 0, b".text", 0x1000, 0x200, 0x200);
        section(&mut f, 1, b".reloc", 0x2000, 0x200, 0x400);
        f[0x210..0x220].copy_from_slice(SIGNATURE);
        f[0x230] = 0xbc; // the entry: `mov $imm32, %esp`
        f[0x240..0x248].copy_from_slice(&0x1_4000_1234u64.to_le_bytes());
        // One block: page 0x1000, a DIR64 at 0x40, padding.
        f[0x400..0x404].copy_from_slice(&0x1000u32.to_le_bytes());
        f[0x404..0x408].copy_from_slice(&12u32.to_le_bytes());
        f[0x408..0x40a].copy_from_slice(&0xA040u16.to_le_bytes());
        f
    }

    #[test]
    fn lays_out_relocates_and_notes_the_entry() {
        let e = elf(&pe()).unwrap();
        assert_eq!(&e[..4], b"\x7fELF");
        let entry = u64::from_le_bytes(e[24..32].try_into().unwrap());
        assert_eq!(entry, LOAD_ADDRESS + 0x1010 + 32);
        // PT_LOAD: file offset 0x1000, at LOAD_ADDRESS, image then scratch.
        let ph = &e[64..64 + 56];
        assert_eq!(u32::from_le_bytes(ph[0..4].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(ph[8..16].try_into().unwrap()), 0x1000);
        let paddr = u64::from_le_bytes(ph[24..32].try_into().unwrap());
        assert_eq!(paddr, LOAD_ADDRESS);
        assert_eq!(u64::from_le_bytes(ph[32..40].try_into().unwrap()), 0x3000);
        assert_eq!(
            u64::from_le_bytes(ph[40..48].try_into().unwrap()),
            0x3000 + SCRATCH
        );
        // The note names the entry.
        let note = &e[64 + 112..64 + 112 + 20];
        assert_eq!(&note[12..16], b"Xen\0");
        assert_eq!(
            u32::from_le_bytes(note[16..20].try_into().unwrap()) as u64,
            entry
        );
        let img = &e[0x1000..];
        // Relocated for the load address.
        assert_eq!(
            u64::from_le_bytes(img[0x1040..0x1048].try_into().unwrap()),
            LOAD_ADDRESS + 0x1234
        );
        // The stub's header: image, its length with scratch, the scratch.
        let field = |o: usize| u32::from_le_bytes(img[0x1010 + o..0x1014 + o].try_into().unwrap());
        assert_eq!(u64::from(field(16)), LOAD_ADDRESS);
        assert_eq!(u64::from(field(20)), 0x3000 + SCRATCH);
        assert_eq!(u64::from(field(24)), LOAD_ADDRESS + 0x3000);
        // The entry's stack pointer: the scratch area's end.
        assert_eq!(img[0x1010 + 32], 0xbc);
        assert_eq!(u64::from(field(33)), LOAD_ADDRESS + 0x3000 + SCRATCH);
    }

    #[test]
    fn refuses_an_image_without_the_stub() {
        let mut f = pe();
        f[0x210] = b'X';
        assert!(elf(&f).is_err());
    }
}
