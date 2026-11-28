//! The PVH entry stub (ADR-0025): where a PVH loader such as Firecracker
//! starts the kernel, in 32-bit protected mode with paging off and `%ebx`
//! pointing at its `hvm_start_info`.
//!
//! xtask lays the PE image out at a physical address, as a UEFI loader
//! would (sections at their RVAs, base relocations applied for that
//! address), wraps it in an ELF whose PVH note points at
//! `ichor_pvh_start32`, and fills in the header below. The stub then:
//!
//! 1. loads the stack pointer xtask wrote into its first instruction (PVH
//!    promises no stack), then finds its own address (`call`/`pop`: no
//!    relocation of 32-bit code),
//! 2. takes the scratch area past the image for a stack and records the TSC,
//! 3. identity-maps the first 4 GiB with 2 MiB pages in six scratch pages,
//! 4. enables PAE, OSFXSR/OSXMMEXCPT, long mode with NX, paging and WP,
//! 5. loads a GDT of its own and far-returns into 64-bit code, which calls
//!    `pvh_main(start_info, image_base, image_len, entry_tsc)`.
//!
//! Header (16-byte aligned, just before the entry; xtask finds it by its
//! signature and fills the three fields):
//!
//! | Offset | Field |
//! |---|---|
//! | 0x00 | signature `IchorPVH32entry\0` |
//! | 0x10 | physical address of the image (its PE headers) (u32) |
//! | 0x14 | length of the image region, scratch included (u32) |
//! | 0x18 | physical address of the scratch area: six table pages, then a 64 KiB stack (u32) |
//! | 0x1c | zero |
//! | 0x20 | `ichor_pvh_start32`: `mov $imm32, %esp`, the stack's top (the scratch area's end) filled in at 0x21 |

use core::arch::{asm, global_asm};

global_asm!(
    ".section .text",
    ".balign 16",
    ".global ichor_pvh_header",
    "ichor_pvh_header:",
    ".ascii \"IchorPVH32entry\\0\"",
    ".long 0",
    ".long 0",
    ".long 0",
    ".long 0",
    ".code32",
    "ichor_pvh_start32:",
    // `mov $STACK, %esp`, the immediate filled in by xtask: PVH gives no
    // stack (Firecracker enters with %esp 0), and `call` needs one.
    ".byte 0xbc",
    ".long 0",
    "cli",
    "cld",
    "call 1f",
    "1:",
    "pop %ebp",
    "sub $(1b - ichor_pvh_start32), %ebp",
    "mov -8(%ebp), %esi", // the scratch area
    "lea 0x16000(%esi), %esp",
    "rdtsc",
    "push %edx",
    "push %eax",
    // Six zeroed pages: PML4, PDPT, four page directories.
    "mov %esi, %edi",
    "xor %eax, %eax",
    "mov $6144, %ecx",
    "rep stosl",
    "lea 0x1003(%esi), %eax",
    "mov %eax, (%esi)",
    "lea 0x2003(%esi), %eax",
    "mov %eax, 0x1000(%esi)",
    "lea 0x3003(%esi), %eax",
    "mov %eax, 0x1008(%esi)",
    "lea 0x4003(%esi), %eax",
    "mov %eax, 0x1010(%esi)",
    "lea 0x5003(%esi), %eax",
    "mov %eax, 0x1018(%esi)",
    // 2,048 directory entries: 4 GiB of present, writable 2 MiB pages.
    "lea 0x2000(%esi), %edi",
    "mov $0x83, %eax",
    "mov $2048, %ecx",
    "2:",
    "mov %eax, (%edi)",
    "add $0x200000, %eax",
    "add $8, %edi",
    "loop 2b",
    "mov %cr4, %eax",
    "or $0x620, %eax", // PAE | OSFXSR | OSXMMEXCPT
    "mov %eax, %cr4",
    "mov %esi, %cr3",
    "mov $0xC0000080, %ecx",
    "rdmsr",
    "or $0x900, %eax", // EFER.LME | EFER.NXE
    "wrmsr",
    "mov %cr0, %eax",
    "and $0xfffffffb, %eax", // EM off
    "or $0x80010002, %eax",  // PG | WP | MP
    "mov %eax, %cr0",
    "lea (ichor_pvh_gdt - ichor_pvh_start32)(%ebp), %eax",
    "push %eax",
    "pushw $23",
    "lgdtl (%esp)",
    "add $6, %esp",
    "lea (ichor_pvh_start64 - ichor_pvh_start32)(%ebp), %eax",
    "push $0x08",
    "push %eax",
    "lret",
    ".code64",
    "ichor_pvh_start64:",
    "mov $0x10, %eax",
    "mov %eax, %ds",
    "mov %eax, %es",
    "mov %eax, %ss",
    "xor %eax, %eax",
    "mov %eax, %fs",
    "mov %eax, %gs",
    // Upper halves are undefined after the switch: zero-extend.
    "mov %esp, %esp",
    "mov %ebp, %ebp",
    "mov %ebx, %ebx",
    "pop %rcx", // the TSC at entry
    "mov %rbx, %rdi",
    "mov -16(%rbp), %esi",
    "mov -12(%rbp), %edx",
    "and $-16, %rsp",
    "call {main}",
    "ud2",
    ".balign 8",
    "ichor_pvh_gdt:",
    ".quad 0",
    ".quad 0x00af9a000000ffff",
    ".quad 0x00cf92000000ffff",
    main = sym crate::boot::pvh::pvh_main,
    options(att_syntax),
);

/// The header's address. Taking it keeps the linker from dropping the stub,
/// which nothing else in the image refers to.
pub(crate) fn header() -> usize {
    let at: usize;
    // SAFETY: computes an address RIP-relatively; no memory access.
    unsafe {
        asm!(
            "lea {a}, [rip + ichor_pvh_header]",
            a = out(reg) at,
            options(nomem, nostack, preserves_flags)
        )
    };
    at
}
