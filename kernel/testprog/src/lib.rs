//! Building small static Linux test programs: a tiny x86-64 assembler (the
//! handful of instructions self-tests need, with labels and data
//! references) and a wrapper that turns the result into a static ELF.
//!
//! The kernel builds its boot self-tests and benchmarks with it at runtime;
//! xtask builds the same benchmark programs on the host to run them under
//! Linux, so both kernels execute identical bytes.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod bench;

use alloc::vec::Vec;

/// x86-64 general-purpose registers, by encoding number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl Reg {
    fn low(self) -> u8 {
        self as u8 & 7
    }
    fn ext(self) -> u8 {
        (self as u8 >> 3) & 1
    }
}

/// A forward-referenceable code position.
#[derive(Clone, Copy, Debug)]
pub struct Label(usize);

/// A piece of data placed after the code.
#[derive(Clone, Copy, Debug)]
pub struct Data(usize);

/// A minimal assembler.
#[derive(Debug, Default)]
pub struct Asm {
    code: Vec<u8>,
    labels: Vec<Option<usize>>,
    /// (position of rel32, label)
    jumps: Vec<(usize, usize)>,
    data: Vec<Vec<u8>>,
    /// (position of imm64, data index)
    data_refs: Vec<(usize, usize)>,
    /// (position of imm64, label)
    label_refs: Vec<(usize, usize)>,
}

impl Asm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len() - 1)
    }

    pub fn bind(&mut self, l: Label) {
        self.labels[l.0] = Some(self.code.len());
    }

    pub fn data(&mut self, bytes: &[u8]) -> Data {
        self.data.push(bytes.to_vec());
        Data(self.data.len() - 1)
    }

    fn rex_w(&mut self, r: u8, b: u8) {
        self.code.push(0x48 | (r << 2) | b);
    }

    /// `mov dst, imm64`
    pub fn mov_imm(&mut self, dst: Reg, imm: u64) {
        self.rex_w(0, dst.ext());
        self.code.push(0xB8 + dst.low());
        self.code.extend_from_slice(&imm.to_le_bytes());
    }

    /// `mov dst, <address of data>`
    pub fn mov_data(&mut self, dst: Reg, d: Data) {
        self.mov_imm(dst, 0);
        let pos = self.code.len() - 8;
        self.data_refs.push((pos, d.0));
    }

    /// `mov dst, <address of label>`
    pub fn mov_label(&mut self, dst: Reg, l: Label) {
        self.mov_imm(dst, 0);
        let pos = self.code.len() - 8;
        self.label_refs.push((pos, l.0));
    }

    /// `mov dst, src`
    pub fn mov(&mut self, dst: Reg, src: Reg) {
        self.rex_w(src.ext(), dst.ext());
        self.code.push(0x89);
        self.code.push(0xC0 | (src.low() << 3) | dst.low());
    }

    /// `mov dst, [base + disp32]`
    pub fn load(&mut self, dst: Reg, base: Reg, disp: i32) {
        self.rex_w(dst.ext(), base.ext());
        self.code.push(0x8B);
        self.code.push(0x80 | (dst.low() << 3) | base.low());
        if base.low() == 4 {
            self.code.push(0x24); // SIB for rsp/r12
        }
        self.code.extend_from_slice(&disp.to_le_bytes());
    }

    /// `mov [base + disp32], src`
    pub fn store(&mut self, base: Reg, disp: i32, src: Reg) {
        self.rex_w(src.ext(), base.ext());
        self.code.push(0x89);
        self.code.push(0x80 | (src.low() << 3) | base.low());
        if base.low() == 4 {
            self.code.push(0x24); // SIB for rsp/r12
        }
        self.code.extend_from_slice(&disp.to_le_bytes());
    }

    fn rex_32(&mut self, r: u8, b: u8) {
        if r | b != 0 {
            self.code.push(0x40 | (r << 2) | b);
        }
    }

    /// `mov dst32, [base + disp32]` (zero-extends into `dst`).
    pub fn load32(&mut self, dst: Reg, base: Reg, disp: i32) {
        self.rex_32(dst.ext(), base.ext());
        self.code.push(0x8B);
        self.code.push(0x80 | (dst.low() << 3) | base.low());
        if base.low() == 4 {
            self.code.push(0x24);
        }
        self.code.extend_from_slice(&disp.to_le_bytes());
    }

    /// `mov [base + disp32], src32`
    pub fn store32(&mut self, base: Reg, disp: i32, src: Reg) {
        self.rex_32(src.ext(), base.ext());
        self.code.push(0x89);
        self.code.push(0x80 | (src.low() << 3) | base.low());
        if base.low() == 4 {
            self.code.push(0x24);
        }
        self.code.extend_from_slice(&disp.to_le_bytes());
    }

    /// `add dst, imm32`
    pub fn add_imm(&mut self, dst: Reg, imm: i32) {
        self.rex_w(0, dst.ext());
        self.code.push(0x81);
        self.code.push(0xC0 | dst.low());
        self.code.extend_from_slice(&imm.to_le_bytes());
    }

    /// `sub dst, imm32`
    pub fn sub_imm(&mut self, dst: Reg, imm: i32) {
        self.rex_w(0, dst.ext());
        self.code.push(0x81);
        self.code.push(0xE8 | dst.low());
        self.code.extend_from_slice(&imm.to_le_bytes());
    }

    /// `cmp a, imm32` (sign-extended)
    pub fn cmp_imm(&mut self, a: Reg, imm: i32) {
        self.rex_w(0, a.ext());
        self.code.push(0x81);
        self.code.push(0xF8 | a.low());
        self.code.extend_from_slice(&imm.to_le_bytes());
    }

    /// `cmp a, b`
    pub fn cmp(&mut self, a: Reg, b: Reg) {
        self.rex_w(b.ext(), a.ext());
        self.code.push(0x39);
        self.code.push(0xC0 | (b.low() << 3) | a.low());
    }

    fn jump(&mut self, opcode: &[u8], l: Label) {
        self.code.extend_from_slice(opcode);
        self.jumps.push((self.code.len(), l.0));
        self.code.extend_from_slice(&[0; 4]);
    }

    /// `jne label`
    pub fn jne(&mut self, l: Label) {
        self.jump(&[0x0F, 0x85], l);
    }

    /// `jmp label`
    pub fn jmp(&mut self, l: Label) {
        self.jump(&[0xE9], l);
    }

    /// Raw instruction bytes (for encodings the assembler has no method
    /// for, such as VEX).
    pub fn raw(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    /// `je label`
    pub fn je(&mut self, l: Label) {
        self.jump(&[0x0F, 0x84], l);
    }

    /// `jbe label` (unsigned <=)
    pub fn jbe(&mut self, l: Label) {
        self.jump(&[0x0F, 0x86], l);
    }

    /// `ja label` (unsigned >)
    pub fn ja(&mut self, l: Label) {
        self.jump(&[0x0F, 0x87], l);
    }

    /// `ret`
    pub fn ret(&mut self) {
        self.code.push(0xC3);
    }

    pub fn syscall(&mut self) {
        self.code.extend_from_slice(&[0x0F, 0x05]);
    }

    /// `mov rax, nr; syscall` with arguments already in place.
    pub fn sys(&mut self, nr: u64) {
        self.mov_imm(Reg::Rax, nr);
        self.syscall();
    }

    /// Resolves labels and data references for code loaded at `base`, and
    /// returns code followed by data. Returns `None` on an unbound label.
    pub fn finish(mut self, base: u64) -> Option<Vec<u8>> {
        for &(pos, l) in &self.jumps {
            let target = self.labels[l]? as i64;
            let rel = (target - (pos as i64 + 4)) as i32;
            self.code[pos..pos + 4].copy_from_slice(&rel.to_le_bytes());
        }
        for &(pos, l) in &self.label_refs {
            let addr = base + self.labels[l]? as u64;
            self.code[pos..pos + 8].copy_from_slice(&addr.to_le_bytes());
        }
        let mut offsets = Vec::new();
        let mut at = self.code.len();
        for d in &self.data {
            offsets.push(at);
            at += d.len();
        }
        for &(pos, d) in &self.data_refs {
            let addr = base + offsets[d] as u64;
            self.code[pos..pos + 8].copy_from_slice(&addr.to_le_bytes());
        }
        let mut out = self.code;
        for d in self.data {
            out.extend_from_slice(&d);
        }
        Some(out)
    }
}

/// Where test programs are loaded.
pub const LOAD_VADDR: u64 = 0x40_0000;
const EHDR: usize = 64;
const PHDR: usize = 56;
/// Virtual address the assembled blob starts at (after the ELF headers,
/// which share the one segment).
pub const BLOB_VADDR: u64 = LOAD_VADDR + (EHDR + PHDR) as u64;

/// Wraps a blob assembled for `BLOB_VADDR` into a static ET_EXEC ELF with one
/// read+execute segment; the entry point is the start of the blob.
pub fn static_elf(blob: &[u8]) -> Vec<u8> {
    let mut img = Vec::new();
    img.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    img.extend_from_slice(&[0; 8]);
    img.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    img.extend_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    img.extend_from_slice(&1u32.to_le_bytes());
    img.extend_from_slice(&BLOB_VADDR.to_le_bytes()); // e_entry
    img.extend_from_slice(&(EHDR as u64).to_le_bytes()); // e_phoff
    img.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    img.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    img.extend_from_slice(&(EHDR as u16).to_le_bytes());
    img.extend_from_slice(&(PHDR as u16).to_le_bytes());
    img.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    img.extend_from_slice(&[0; 6]); // shentsize, shnum, shstrndx
    let filesz = (EHDR + PHDR + blob.len()) as u64;
    img.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    img.extend_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    img.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    img.extend_from_slice(&LOAD_VADDR.to_le_bytes()); // p_vaddr
    img.extend_from_slice(&LOAD_VADDR.to_le_bytes()); // p_paddr
    img.extend_from_slice(&filesz.to_le_bytes());
    img.extend_from_slice(&filesz.to_le_bytes());
    img.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    img.extend_from_slice(blob);
    img
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_resolves_labels_and_data() {
        let mut a = Asm::new();
        let msg = a.data(b"hi");
        let top = a.label();
        a.bind(top);
        a.mov_imm(Reg::R12, 7); // 49 BC imm64
        a.mov_data(Reg::Rsi, msg);
        a.sub_imm(Reg::R12, 1); // 49 81 EC imm32
        a.jne(top);
        a.sys(60);
        let blob = a.finish(BLOB_VADDR).unwrap();
        assert_eq!(&blob[..2], &[0x49, 0xBC]);
        assert_eq!(&blob[2..10], &7u64.to_le_bytes());
        // The data follows the code; mov_data loads its absolute address.
        let data_at = blob.len() - 2;
        assert_eq!(&blob[data_at..], b"hi");
        let addr = u64::from_le_bytes(blob[12..20].try_into().unwrap());
        assert_eq!(addr, BLOB_VADDR + data_at as u64);
        // jne jumps back to the start: rel32 = -(end of the jne).
        let jne_end = 10 + 10 + 7 + 6;
        let rel = i32::from_le_bytes(blob[jne_end - 4..jne_end].try_into().unwrap());
        assert_eq!(rel, -(jne_end as i32));
        // An unbound label is an error.
        let mut b = Asm::new();
        let l = b.label();
        b.jmp(l);
        assert!(b.finish(BLOB_VADDR).is_none());
    }

    #[test]
    fn static_elf_has_one_loadable_segment_at_the_blob() {
        let elf = static_elf(&[0xC3]);
        assert_eq!(&elf[..4], b"\x7fELF");
        assert_eq!(
            u64::from_le_bytes(elf[24..32].try_into().unwrap()),
            BLOB_VADDR
        );
        assert_eq!(elf.len(), 64 + 56 + 1);
        assert_eq!(*elf.last().unwrap(), 0xC3);
    }
}
