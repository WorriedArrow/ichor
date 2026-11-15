//! Application processor start-up: the real-mode trampoline and its page
//! tables.
//!
//! The trampoline is assembled into the kernel image and copied to a page
//! below 1 MiB (a SIPI vector is a page number). Each AP starts there in real
//! mode, computes its own load address, switches to protected and then long
//! mode on a tiny page table that identity-maps the first 2 MiB and shares
//! the kernel's upper half, claims a CPU index with `lock xadd`, loads that
//! index's stack and jumps to the high-half Rust entry. All APs can run the
//! trampoline at once.
//!
//! Layout of the trampoline page (offsets are shared with the asm):
//!
//! | Offset | Field |
//! |---|---|
//! | 0x00 | `jmp 0x60` |
//! | 0x08 | GDT: null, 32-bit code, data, 64-bit code |
//! | 0x28 | GDTR (limit, base) - filled by each AP |
//! | 0x30 | far pointer to the 32-bit entry - filled by each AP |
//! | 0x38 | far pointer to the 64-bit entry - filled by each AP |
//! | 0x40 | CR3 (u32) - filled by the BSP |
//! | 0x44 | next CPU index (u32) - filled by the BSP, claimed by APs |
//! | 0x48 | address of the stack-top table (u64) - filled by the BSP |
//! | 0x50 | address of the Rust entry (u64) - filled by the BSP |
//! | 0x60 | code |

use core::arch::{asm, global_asm};

pub(crate) const OFF_CR3: usize = 0x40;
pub(crate) const OFF_NEXT_CPU: usize = 0x44;
pub(crate) const OFF_STACKS: usize = 0x48;
pub(crate) const OFF_ENTRY: usize = 0x50;

global_asm!(
    ".section .text",
    ".balign 16",
    ".global ichor_ap_trampoline",
    ".global ichor_ap_trampoline_end",
    "ichor_ap_trampoline:",
    ".byte 0xeb, 0x5e", // jmp short to 0x60
    ".balign 8, 0",
    // 0x08: GDT
    ".quad 0",
    ".quad 0x00cf9a000000ffff",
    ".quad 0x00cf92000000ffff",
    ".quad 0x00af9a000000ffff",
    // 0x28: GDTR
    ".word 31",
    ".long 0",
    ".word 0",
    // 0x30: far pointer to pm32 (selector 0x08)
    ".long 0",
    ".word 0x08",
    ".word 0",
    // 0x38: far pointer to lm64 (selector 0x18)
    ".long 0",
    ".word 0x18",
    ".word 0",
    // 0x40: cr3, 0x44: next cpu, 0x48: stacks, 0x50: entry, 0x58: spare
    ".long 0",
    ".long 0",
    ".quad 0",
    ".quad 0",
    ".quad 0",
    // 0x60
    ".code16",
    "cli",
    "cld",
    "mov %cs, %ax",
    "mov %ax, %ds",
    "xor %ebx, %ebx",
    "mov %cs, %bx",
    "shl $4, %ebx",
    "lea 8(%ebx), %eax",
    "mov %eax, (0x2a)",
    "lea (ichor_ap_pm32 - ichor_ap_trampoline)(%ebx), %eax",
    "mov %eax, (0x30)",
    "lea (ichor_ap_lm64 - ichor_ap_trampoline)(%ebx), %eax",
    "mov %eax, (0x38)",
    "lgdtl (0x28)",
    "mov %cr0, %eax",
    "or $1, %eax",
    "mov %eax, %cr0",
    "ljmpl *(0x30)",
    ".code32",
    "ichor_ap_pm32:",
    "mov $0x10, %ax",
    "mov %ax, %ds",
    "mov %ax, %es",
    "mov %ax, %ss",
    "mov %cr4, %eax",
    "or $0x20, %eax", // PAE
    "mov %eax, %cr4",
    "mov 0x40(%ebx), %eax",
    "mov %eax, %cr3",
    "mov $0xC0000080, %ecx",
    "rdmsr",
    "or $0x900, %eax", // EFER.LME | EFER.NXE
    "wrmsr",
    "mov %cr0, %eax",
    "or $0x80010000, %eax", // PG | WP
    "mov %eax, %cr0",
    "ljmpl *0x38(%ebx)",
    ".code64",
    "ichor_ap_lm64:",
    "mov %ebx, %ebx", // zero-extend the page base
    "mov $1, %eax",
    "lock xadd %eax, 0x44(%rbx)",
    "mov 0x48(%rbx), %rcx",
    "mov (%rcx,%rax,8), %rsp",
    "mov %eax, %edi",
    "mov 0x50(%rbx), %rax",
    "push $0",
    "jmp *%rax",
    "ichor_ap_trampoline_end:",
    ".code64",
    options(att_syntax),
);

/// The trampoline's bytes as assembled into the kernel image.
pub(crate) fn trampoline_code() -> &'static [u8] {
    let (start, end): (usize, usize);
    // SAFETY: computes two addresses RIP-relatively; no memory access.
    unsafe {
        asm!(
            "lea {s}, [rip + ichor_ap_trampoline]",
            "lea {e}, [rip + ichor_ap_trampoline_end]",
            s = out(reg) start,
            e = out(reg) end,
            options(nomem, nostack, preserves_flags)
        )
    };
    let ptr = core::ptr::with_exposed_provenance::<u8>(start);
    // SAFETY: `[start, end)` is code in the kernel image's `.text`, which is
    // mapped read-only/executable for the life of the system and never
    // written, so a shared byte slice over it is valid.
    unsafe { core::slice::from_raw_parts(ptr, end.saturating_sub(start)) }
}

/// Loads `cr3` and the kernel GS base for an AP entering the kernel.
///
/// # Safety
///
/// `cr3` must be the kernel PML4, which maps everything the AP runs from.
pub(crate) unsafe fn load_kernel_cr3(cr3: u64) {
    // SAFETY: caller contract; the AP executes from the high image alias and
    // its high stack, both mapped in the kernel PML4.
    unsafe { super::regs::write_cr3(cr3) };
}
