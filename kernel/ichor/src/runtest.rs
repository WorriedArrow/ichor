//! Milestone 3 capstone-in-progress: load and run a real static Linux
//! x86-64 ELF binary, unmodified, in a cell through the Linux syscall ABI.
//!
//! The binary is a raw-syscall program (no libc) built here so the test is
//! self-contained; the loader and the Linux ABI path it exercises are the
//! same ones a busybox image will use once the block/image layers land.

use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::power::{ExitStatus, shutdown};
use frame::println;
use frame::user::{UserContext, UserEvent, UserMode};

use crate::kcell::{Cell, System};
use crate::linuxabi::{self, Outcome};
use crate::loader;

fn fail(what: &str) -> ! {
    println!("ichor: runtest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

const LOAD_VADDR: u64 = 0x40_0000;

/// Builds a static ET_EXEC ELF64 whose single RX segment contains the ELF
/// headers, code, and a message. The program does `write(1, msg, len)` then
/// `exit_group(7)`.
fn hello_elf() -> Vec<u8> {
    let msg = b"hello from a real Linux ELF running on Ichor\n";
    const EHDR: usize = 64;
    const PHDR: usize = 56;
    let code_off = EHDR + PHDR; // 120
    let msg_vaddr = LOAD_VADDR + (code_off + 49) as u64; // 49 = code length below

    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]); // mov rax,1 (write)
    code.extend_from_slice(&[0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00]); // mov rdi,1 (stdout)
    code.extend_from_slice(&[0x48, 0xBE]); // movabs rsi, msg_vaddr
    code.extend_from_slice(&msg_vaddr.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xC7, 0xC2]); // mov rdx, imm32 (len)
    code.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    code.extend_from_slice(&[0x48, 0xC7, 0xC0, 0xE7, 0x00, 0x00, 0x00]); // mov rax,231 (exit_group)
    code.extend_from_slice(&[0x48, 0xC7, 0xC7, 0x07, 0x00, 0x00, 0x00]); // mov rdi,7
    code.extend_from_slice(&[0x0F, 0x05]); // syscall
    assert_eq!(code.len(), 49);

    let entry = LOAD_VADDR + code_off as u64;
    let mut img = Vec::new();
    // ELF header.
    img.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    img.extend_from_slice(&[0; 8]);
    img.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    img.extend_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    img.extend_from_slice(&1u32.to_le_bytes()); // version
    img.extend_from_slice(&entry.to_le_bytes()); // e_entry
    img.extend_from_slice(&(EHDR as u64).to_le_bytes()); // e_phoff
    img.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    img.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    img.extend_from_slice(&(EHDR as u16).to_le_bytes()); // e_ehsize
    img.extend_from_slice(&(PHDR as u16).to_le_bytes()); // e_phentsize
    img.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    img.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    img.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    img.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(img.len(), EHDR);

    // One PT_LOAD covering the whole file, read+exec.
    let filesz = (code_off + code.len() + msg.len()) as u64;
    img.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    img.extend_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    img.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    img.extend_from_slice(&LOAD_VADDR.to_le_bytes()); // p_vaddr
    img.extend_from_slice(&LOAD_VADDR.to_le_bytes()); // p_paddr
    img.extend_from_slice(&filesz.to_le_bytes()); // p_filesz
    img.extend_from_slice(&filesz.to_le_bytes()); // p_memsz
    img.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    assert_eq!(img.len(), code_off);

    img.extend_from_slice(&code);
    img.extend_from_slice(msg);
    img
}

pub(crate) fn run() {
    let system = System::new(4096).unwrap_or_else(|| fail("no system cell"));
    let cell = Cell::new(&system.root_account, 128).unwrap_or_else(|| fail("no process cell"));

    let image = hello_elf();
    let loaded = match loader::load(&cell, &image) {
        Ok(l) => l,
        Err(e) => {
            println!("ichor: runtest: load error {e:?}");
            fail("could not load the ELF");
        }
    };

    cell.space().bind_to_current_task();
    let mut ctx = UserContext::new(loaded.entry, loaded.stack_pointer);

    let cell_arc: Arc<Cell> = cell;
    let mut syscalls = 0u32;
    let status = loop {
        match UserMode::new(&mut ctx).execute() {
            UserEvent::Syscall => {
                syscalls += 1;
                if let Outcome::Exit(code) = linuxabi::dispatch(&cell_arc, &mut ctx) {
                    break code;
                }
            }
            UserEvent::Exception { vector, cr2, .. } => {
                frame::mm::activate_kernel_space();
                println!(
                    "ichor: runtest: unexpected fault vector {vector} cr2 {cr2:#x} rip {:#x}",
                    ctx.rip
                );
                fail("the Linux binary faulted");
            }
        }
        if syscalls > 50 {
            fail("the Linux binary made too many syscalls");
        }
    };

    frame::mm::activate_kernel_space();
    if status != 7 {
        fail("the Linux binary did not exit with status 7");
    }
    println!(
        "ichor: linux: static ELF ran via the Linux ABI, exited {status} after {syscalls} syscalls"
    );
}
