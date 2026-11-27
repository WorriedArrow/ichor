//! The entry area and kernel page-table isolation (ADR-0004 §2).
//!
//! Everything the CPU and the entry code touch while CR3 may still hold a
//! user root is the entry code below (trap stubs, the trap tail, the way
//! into and out of ring 3, the syscall entry: whole pages of the image) and
//! what lives in one PML4 slot, the *entry area* (`mm::ENTRY_BASE`): an
//! alias of the IDT, and per CPU an alias of its block (GS) and GDT/TSS, its
//! entry stack (TSS RSP0) and its IST stacks. The CPU always loads its
//! descriptor tables through these aliases, isolated or not, so there is
//! one path. The entry code runs at its image address (ADR-0004's
//! 2026-11-27 amendment; it ran at an alias in the entry area before), so
//! its calls into the kernel and its untraining and returns are direct.
//!
//! With isolation on (Meltdown-affected CPUs, or `force_pti`), each user
//! address space has two roots in one 8 KiB block: the full root (kernel
//! half and user half), which the kernel runs on, and above it a shadow
//! root whose kernel half is only the entry area's slot and the entry
//! code's pages, and whose user
//! slots point at the same tables as the full root's. Ring 3 runs on the
//! shadow. Every entry from ring 3 loads the full root first; the way back
//! loads the shadow right before `iretq`. Kernel mappings are global, so
//! CR4.PGE is turned off: no kernel translation survives the switch. With
//! PCID the full root runs as PCID 0 and the shadow as PCID 1, and the
//! switches keep each other's entries; a user-side flush that is owed (a
//! shootdown, a new address space) is done on the next load of the shadow.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use super::paging::{self, Props, UserProt};
use super::regs;
use crate::cpu::{CpuBlock, MAX_CPUS};
use crate::mm::kspace::{self, map_entry};
use crate::mm::meta::kind;
use crate::mm::{ENTRY_BASE, PAGE_SIZE, PhysAddr, align_down, align_up, page_alloc};

/// The most pages of entry code (in shadow roots under isolation).
const TEXT_PAGES: u64 = 256;
/// IDT alias.
pub(crate) const IDT: u64 = ENTRY_BASE + 0x10_0000;
/// Per-CPU parts, `CPU_STRIDE` apart: block, GDT/TSS, guard, entry stack,
/// then each IST stack above a guard page.
const CPUS: u64 = ENTRY_BASE + 0x100_0000;
const CPU_STRIDE: u64 = 0x4_0000;
/// Pages per IST stack.
const IST_PAGES: u64 = 16;

const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
/// CR3 bit 63: keep the new PCID's TLB entries.
const NOFLUSH: u64 = 1 << 63;
/// The shadow roots' PCID (full roots use 0).
const USER_PCID: u64 = 1;

static PTI: AtomicBool = AtomicBool::new(false);
static PCID: AtomicBool = AtomicBool::new(false);
/// The shadow of the kernel root, for user code run without an address
/// space of its own.
static KERNEL_SHADOW: AtomicU64 = AtomicU64::new(0);

// The block offsets the assembler below uses.
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(CpuBlock, kernel_rsp) == 16);
    assert!(offset_of!(CpuBlock, user_ctx) == 32);
    assert!(offset_of!(CpuBlock, scratch) == 40);
    assert!(offset_of!(CpuBlock, event_kind) == 56);
    assert!(offset_of!(CpuBlock, entry_rsp) == 80);
    assert!(offset_of!(CpuBlock, kernel_cr3) == 104);
    assert!(offset_of!(CpuBlock, user_cr3) == 112);
    assert!(offset_of!(CpuBlock, cr3_noflush) == 120);
    assert!(offset_of!(CpuBlock, pti) == 144);
    assert!(offset_of!(CpuBlock, verw) == 152);
    assert!(offset_of!(CpuBlock, verw_sel) == 160);
    assert!(offset_of!(CpuBlock, spec_ctrl) == 168);
    assert!(offset_of!(CpuBlock, bhb_clear) == 176);
    assert!(offset_of!(CpuBlock, ibpb_entry) == 184);
    assert!(offset_of!(CpuBlock, untrain) == 192);
    assert!(core::mem::size_of::<CpuBlock>() == PAGE_SIZE as usize);
};

/// Image addresses of the entry code: its start, end, the trap stubs and
/// the syscall entry.
fn symbols() -> [u64; 4] {
    let (s, e, t, y): (u64, u64, u64, u64);
    // SAFETY: computes four addresses RIP-relatively; no memory access.
    unsafe {
        asm!(
            "lea {s}, [rip + ichor_entry_start]",
            "lea {e}, [rip + ichor_entry_end]",
            "lea {t}, [rip + ichor_trap_stubs]",
            "lea {y}, [rip + ichor_syscall_entry]",
            s = out(reg) s, e = out(reg) e, t = out(reg) t, y = out(reg) y,
            options(nomem, nostack, preserves_flags)
        )
    };
    [s, e, t, y]
}

/// Trap stub `vector` (IDT gates point here).
pub(crate) fn stub(vector: u8) -> u64 {
    symbols()[2] + u64::from(vector) * 16
}

/// The syscall entry (LSTAR).
pub(crate) fn syscall_entry() -> u64 {
    symbols()[3]
}

/// The entry code's pages.
fn text() -> core::ops::Range<u64> {
    let [s, e, ..] = symbols();
    align_down(s, PAGE_SIZE)..align_up(e, PAGE_SIZE)
}

/// Maps the IDT page (at `idt`, page-aligned) into the entry area. Once,
/// on the boot CPU.
pub(crate) fn map_shared(idt: u64) -> Option<()> {
    let t = text();
    if (t.end - t.start) / PAGE_SIZE > TEXT_PAGES || !idt.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    map_entry(IDT, kspace::kernel_phys(idt)?, PAGE_SIZE, Props::RO_DATA)
}

/// Where one CPU's entry state is reached through the entry area.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CpuArea {
    pub(crate) block: u64,
    pub(crate) tables: u64,
    pub(crate) ist: [u64; 3],
}

/// Builds CPU `index`'s part of the entry area: aliases of its block and
/// of its GDT/TSS page (both page-aligned), a fresh entry stack and three
/// IST stacks. Fills the block's entry fields.
pub(crate) fn map_cpu(index: usize, block: &CpuBlock, tables: u64) -> Option<CpuArea> {
    if index >= MAX_CPUS {
        return None;
    }
    let base = CPUS + index as u64 * CPU_STRIDE;
    let block_addr = core::ptr::from_ref(block) as u64;
    map_entry(
        base,
        kspace::kernel_phys(block_addr)?,
        PAGE_SIZE,
        Props::RW_DATA,
    )?;
    map_entry(
        base + PAGE_SIZE,
        kspace::kernel_phys(tables)?,
        PAGE_SIZE,
        Props::RW_DATA,
    )?;
    let stack = page_alloc::alloc(0, kind::ALLOCATED)?;
    map_entry(
        base + 3 * PAGE_SIZE,
        stack.as_u64(),
        PAGE_SIZE,
        Props::RW_DATA,
    )?;
    let mut ist = [0; 3];
    for (k, top) in (0u64..).zip(ist.iter_mut()) {
        let bottom = base + (5 + k * (IST_PAGES + 1)) * PAGE_SIZE;
        let pages = page_alloc::alloc(IST_PAGES.trailing_zeros() as u8, kind::ALLOCATED)?;
        map_entry(
            bottom,
            pages.as_u64(),
            IST_PAGES * PAGE_SIZE,
            Props::RW_DATA,
        )?;
        *top = bottom + IST_PAGES * PAGE_SIZE;
    }
    block.entry_rsp.store(base + 4 * PAGE_SIZE, Relaxed);
    block
        .verw_sel
        .store(u64::from(super::trap::KERNEL_SS), Relaxed);
    Some(CpuArea {
        block: base,
        tables: base + PAGE_SIZE,
        ist,
    })
}

/// The entry stack top of the calling CPU (TSS RSP0).
pub(crate) fn entry_stack(block: &CpuBlock) -> u64 {
    block.entry_rsp.load(Relaxed)
}

/// Whether page-table isolation is on.
pub fn isolating() -> bool {
    PTI.load(Relaxed)
}

/// Whether isolation uses PCID.
pub(crate) fn pcid() -> bool {
    PCID.load(Relaxed)
}

/// Turns page-table isolation on: once, on the boot CPU, before any user
/// address space exists (CPUs that start later turn it on in
/// [`enable_cpu`]).
pub(crate) fn enable() -> Result<(), &'static str> {
    let shadow = page_alloc::alloc(0, kind::PAGE_TABLE).ok_or("out of memory")?;
    let kernel = PhysAddr::new(kspace::kernel_root());
    // SAFETY: `shadow` is a fresh page about to become a page table and the
    // kernel root a live one, both reachable via the linear map. The shadow
    // gets the entry area's slot only.
    unsafe { paging::zero_page(shadow) };
    // SAFETY: as above.
    unsafe { paging::copy_entry(kernel, shadow, paging::slot_of(ENTRY_BASE)) };
    // The entry code at its image address, in tables of the shadow's own.
    let t = text();
    kspace::map_entry_text(shadow, t.start, t.end - t.start).ok_or("out of memory")?;
    KERNEL_SHADOW.store(shadow.as_u64(), Relaxed);
    PCID.store(super::cpu::features().pcid, Relaxed);
    PTI.store(true, Relaxed);
    enable_cpu(crate::cpu::this_block());
    Ok(())
}

/// Isolation on this CPU (no-op when it is off): no global pages, PCID if
/// the CPU has it, and the roots the entry code switches between.
pub(crate) fn enable_cpu(block: &CpuBlock) {
    if !isolating() {
        return;
    }
    let mut cr4 = regs::read_cr4() & !regs::CR4_PGE;
    if pcid() {
        cr4 |= regs::CR4_PCIDE;
    }
    // SAFETY: clearing PGE makes kernel mappings non-global (and flushes
    // every TLB entry); PCIDE only tags TLB entries with CR3's PCID, and is
    // allowed because CR3 holds PCID 0 (frame never set one before). Frame
    // flushes per PCID wherever it changes page tables (`note_root`,
    // `user_tlb_stale`).
    unsafe { regs::write_cr4(cr4) };
    block
        .cr3_noflush
        .store(if pcid() { NOFLUSH } else { 0 }, Relaxed);
    note_root(block, regs::read_cr3() & ADDR_MASK);
    block.pti.store(1, Relaxed);
}

/// Records that this CPU is about to load full root `root`: the entry code
/// returns to it, and ring 3 runs on its shadow, whose (PCID's) entries
/// are flushed on the next load because they may belong to another space.
pub(crate) fn note_root(block: &CpuBlock, root: u64) {
    if !isolating() {
        return;
    }
    let shadow = if root == kspace::kernel_root() {
        KERNEL_SHADOW.load(Relaxed)
    } else {
        root + PAGE_SIZE
    };
    let pcid = if pcid() { USER_PCID } else { 0 };
    block
        .kernel_cr3
        .store(root | block.cr3_noflush.load(Relaxed), Relaxed);
    block.user_cr3.store(shadow | pcid, Relaxed);
}

/// Owes a flush of this CPU's user-side TLB entries (they are tagged with
/// the shadow's PCID, so flushes under the full root miss them).
pub(crate) fn user_tlb_stale() {
    if isolating() {
        crate::cpu::this_block()
            .user_cr3
            .fetch_and(!NOFLUSH, Relaxed);
    }
}

/// The shadow root of a full root that `VmSpace::new` allocated under
/// isolation (the second page of its 8 KiB block).
pub(crate) fn shadow_of(root: PhysAddr) -> PhysAddr {
    PhysAddr::new(root.as_u64() + PAGE_SIZE)
}

/// Gives a new shadow root the kernel half every shadow has: the entry
/// area's slot and the entry code's.
///
/// # Safety
///
/// `shadow` must satisfy `paging::table`'s contract; isolation is on.
pub(crate) unsafe fn share_kernel_half(shadow: PhysAddr) {
    let kernel = PhysAddr::new(KERNEL_SHADOW.load(Relaxed));
    for slot in [paging::slot_of(ENTRY_BASE), paging::slot_of(text().start)] {
        // SAFETY: the kernel's shadow is a frame-built root; caller contract.
        unsafe { paging::copy_entry(kernel, shadow, slot) };
    }
}

/// Checks, with isolation on, that a user root maps its user pages and the
/// entry area and none of the kernel: its text, the current stack, the
/// heap, the linear map, the per-CPU block outside the entry area. Ok(false)
/// if isolation is off.
pub fn isolation_selftest() -> Result<bool, &'static str> {
    if !isolating() {
        return Ok(false);
    }
    let space = crate::mm::VmSpace::new().ok_or("out of memory")?;
    let page = crate::mm::UFrame::alloc_zeroed().ok_or("out of memory")?;
    let va = 0x40_0000;
    let prot = UserProt {
        write: false,
        exec: false,
        key: 0,
    };
    space
        .map(va, &page, prot)
        .map_err(|_| "cannot map a user page")?;
    let (full, shadow) = (space.root(), shadow_of(space.root()));
    // SAFETY: both are frame-built roots of `space`, alive until it drops
    // at the end of this function; the walks only read.
    let walk = |root: PhysAddr, a: u64| unsafe { paging::translate(root, a) };
    let on_stack = 0u64;
    let heap = alloc::boxed::Box::new(0u64);
    let block = crate::cpu::this_block();
    let kernel_only = [
        isolation_selftest as fn() -> _ as usize as u64,
        core::ptr::from_ref(&on_stack) as u64,
        core::ptr::from_ref(&*heap) as u64,
        crate::mm::phys_to_virt(page.phys()),
        core::ptr::from_ref(block) as u64,
    ];
    for a in kernel_only {
        if walk(full, a).is_none() {
            return Err("a kernel address is missing from the full root");
        }
        if walk(shadow, a).is_some() {
            return Err("a kernel-only address is mapped in the user root");
        }
    }
    let entry = [syscall_entry(), IDT, entry_stack(block) - 8, va];
    for a in entry {
        if walk(shadow, a).is_none() || walk(shadow, a) != walk(full, a) {
            return Err("the entry area or a user page differs between the roots");
        }
    }
    Ok(true)
}

global_asm!(
    ".set GS_RESUME, 16",
    ".set GS_UCTX, 32",
    ".set GS_SCRATCH, 40",
    ".set GS_EVENT, 56",
    ".set GS_ESTACK, 80",
    ".set GS_KCR3, 104",
    ".set GS_UCR3, 112",
    ".set GS_NOFLUSH, 120",
    ".set GS_PTI, 144",
    ".set GS_VERW, 152",
    ".set GS_VERWSEL, 160",
    ".set GS_SPEC, 168",
    // Spectre v2 without enhanced IBRS: IA32_SPEC_CTRL is written on every
    // entry from ring 3, before any indirect branch or return, and again
    // without IBRS on the way back (mask -1 and -2). Uses rax, rcx and rdx.
    ".macro ichor_spec_ctrl mask",
    "mov eax, gs:[GS_SPEC]",
    "and eax, \\mask",
    "cmp dword ptr gs:[GS_SPEC], 0",
    "je 90f",
    "mov ecx, 0x48",
    "xor edx, edx",
    "wrmsr",
    "90:",
    ".endm",
    ".set GS_BHB, 176",
    ".set GS_IBPBE, 184",
    ".set GS_UNTRAIN, 192",
    // The rest of what an entry from ring 3 owes (ADR-0004's 2026-11-23
    // amendment), after `ichor_spec_ctrl -1`, on a stack of the kernel's
    // and before any indirect branch: IBPB (AMD's Retbleed and SRSO), then
    // the branch history cleared (BHI without BHI_DIS_S). Uses rax, rcx
    // and rdx.
    ".macro ichor_entry_barriers",
    "cmp dword ptr gs:[GS_IBPBE], 0",
    "je 91f",
    "mov ecx, 0x49",
    "mov eax, 1",
    "xor edx, edx",
    "wrmsr",
    "91:",
    "cmp dword ptr gs:[GS_BHB], 0",
    "je 92f",
    "call ichor_clear_bhb",
    "92:",
    // AMD's SRSO with safe-RET return thunks: untrain before the kernel's
    // first return (`rethunk` points the stub at the routine; IBRS is on by
    // now where the CPU needs it). The Zen 1/2 routine uses rax.
    "cmp qword ptr gs:[GS_UNTRAIN], 0",
    "je 97f",
    "call ichor_untrain_stub",
    "97:",
    ".endm",
    // UserContext offsets (`usermode::UserContext`).
    ".set UC_RAX, 0",
    ".set UC_RBX, 8",
    ".set UC_RCX, 16",
    ".set UC_RDX, 24",
    ".set UC_RSI, 32",
    ".set UC_RDI, 40",
    ".set UC_RBP, 48",
    ".set UC_RSP, 56",
    ".set UC_R8, 64",
    ".set UC_R9, 72",
    ".set UC_R10, 80",
    ".set UC_R11, 88",
    ".set UC_R12, 96",
    ".set UC_R13, 104",
    ".set UC_R14, 112",
    ".set UC_R15, 120",
    ".set UC_RIP, 128",
    ".set UC_RFLAGS, 136",
    ".set SEL_USER_CS, 0x23",
    ".set SEL_USER_SS, 0x1b",
    // TrapFrame offset of the interrupted CS, after the 15 pushed GPRs.
    ".set TF_CS, 144",
    // Everything up to `ichor_entry_end` is whole pages that shadow roots
    // map: until CR3 holds the full root it reaches outside them only
    // through GS (the block's alias) and the stacks. Calls out are direct.
    ".section .text",
    ".balign 4096",
    ".global ichor_entry_start",
    "ichor_entry_start:",
    // One 16-byte stub per vector; vectors that push no error code push 0.
    ".global ichor_trap_stubs",
    "ichor_trap_stubs:",
    ".set vec, 0",
    ".rept 256",
    ".balign 16",
    ".if (vec == 8) || (vec == 10) || (vec == 11) || (vec == 12) || (vec == 13) || (vec == 14) || (vec == 17) || (vec == 21) || (vec == 29) || (vec == 30)",
    ".else",
    "push 0",
    ".endif",
    "push vec",
    "jmp ichor_trap_common",
    ".set vec, vec + 1",
    ".endr",
    // The shared tail: save registers as a TrapFrame and dispatch.
    "ichor_trap_common:",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rbp",
    "push rdi",
    "push rsi",
    "push rdx",
    "push rcx",
    "push rbx",
    "push rax",
    // Clear every flag ring 3 or the interrupted code may hold (AC would
    // suspend SMAP, DF breaks string code); IF is already clear.
    "push 0",
    "popfq",
    "test byte ptr [rsp + TF_CS], 3",
    "jnz 4f",
    // From the kernel. Only an NMI, #MC or #DF can arrive while CR3 still
    // holds the user root (the last instructions before `iretq` to ring 3,
    // the first of the syscall entry, both with IF clear): switch to the
    // kernel side and put the user root back on the way out (r12, which
    // the dispatcher preserves).
    "xor r12d, r12d",
    "cmp byte ptr gs:[GS_PTI], 0",
    "je 2f",
    "mov rax, cr3",
    "mov rcx, gs:[GS_UCR3]",
    "xor rcx, rax",
    "shl rcx, 12",
    "shr rcx, 24", // bits 12..51 (the root address) only
    "jnz 2f",
    "mov r12, rax",
    "mov rax, gs:[GS_KCR3]",
    "mov cr3, rax",
    "ichor_spec_ctrl -1",
    "ichor_entry_barriers",
    "2:",
    // 22 quadwords from the 16-byte aligned interrupt frame: aligned.
    "mov rdi, rsp",
    "call {dispatch}",
    "test r12, r12",
    "jz 3f",
    "ichor_spec_ctrl -2",
    "mov cr3, r12",
    "3:",
    "pop rax",
    "pop rbx",
    "pop rcx",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "pop rbp",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "add rsp, 16",
    "iretq",
    // From ring 3 (on the entry stack or an IST stack): the kernel side
    // first, then the dispatcher on the kernel stack of the
    // `UserMode::execute` that entered ring 3. It records the trap into the
    // thread's context, and the run ends there: the way back to ring 3 is
    // always `ichor_enter_user`.
    "4:",
    "cmp byte ptr gs:[GS_PTI], 0",
    "je 5f",
    "mov rax, gs:[GS_KCR3]",
    "mov cr3, rax",
    "5:",
    "ichor_spec_ctrl -1",
    "ichor_entry_barriers",
    "mov rdi, rsp",
    "mov rsp, gs:[GS_RESUME]",
    "and rsp, -16",
    "call {dispatch}",
    "jmp ichor_user_resume",
    // fn ichor_enter_user(ctx: *mut UserContext)  [ctx in rdi]
    ".global ichor_enter_user",
    "ichor_enter_user:",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov gs:[GS_RESUME], rsp", // kernel stack to come back to
    "mov gs:[GS_UCTX], rdi",
    "test rsi, rsi",
    "jnz 20f",
    // The iretq frame, and the two registers loaded last, on the entry
    // stack: the kernel stack is not mapped in the user root.
    "mov rsp, gs:[GS_ESTACK]",
    "push SEL_USER_SS",
    "push qword ptr [rdi + UC_RSP]",
    "push qword ptr [rdi + UC_RFLAGS]",
    "push SEL_USER_CS",
    "push qword ptr [rdi + UC_RIP]",
    "push qword ptr [rdi + UC_RAX]",
    "push qword ptr [rdi + UC_RDI]",
    "ichor_spec_ctrl -2",
    "mov rbx, [rdi + UC_RBX]",
    "mov rcx, [rdi + UC_RCX]",
    "mov rdx, [rdi + UC_RDX]",
    "mov rsi, [rdi + UC_RSI]",
    "mov rbp, [rdi + UC_RBP]",
    "mov r8,  [rdi + UC_R8]",
    "mov r9,  [rdi + UC_R9]",
    "mov r10, [rdi + UC_R10]",
    "mov r11, [rdi + UC_R11]",
    "mov r12, [rdi + UC_R12]",
    "mov r13, [rdi + UC_R13]",
    "mov r14, [rdi + UC_R14]",
    "mov r15, [rdi + UC_R15]",
    // The user root, flushing its PCID once if a flush is owed.
    "cmp byte ptr gs:[GS_PTI], 0",
    "je 7f",
    "mov rax, gs:[GS_UCR3]",
    "mov cr3, rax",
    "or rax, gs:[GS_NOFLUSH]",
    "mov gs:[GS_UCR3], rax",
    "7:",
    "pop rdi",
    "pop rax",
    // MDS/TAA: clear the CPU buffers last, with every user register loaded
    // (VERW changes only ZF, and iretq reloads RFLAGS).
    "test byte ptr gs:[GS_VERW], 1",
    "jz 8f",
    "verw word ptr gs:[GS_VERWSEL]",
    "8:",
    "iretq",
    // The same by `sysretq` (rsi nonzero: `ctx` has rcx = RIP and r11 =
    // RFLAGS, as a `syscall` left them): RSP, rax and rdi, loaded last, on
    // the entry stack; RIP and RFLAGS from rcx and r11. Ring 0 runs on the
    // user's RSP from its load to `sysretq`, with IF clear, as at the
    // syscall entry: NMI, #MC and #DF have IST stacks.
    "20:",
    "mov rsp, gs:[GS_ESTACK]",
    "push qword ptr [rdi + UC_RSP]",
    "push qword ptr [rdi + UC_RAX]",
    "push qword ptr [rdi + UC_RDI]",
    "ichor_spec_ctrl -2",
    "mov rbx, [rdi + UC_RBX]",
    "mov rdx, [rdi + UC_RDX]",
    "mov rsi, [rdi + UC_RSI]",
    "mov rbp, [rdi + UC_RBP]",
    "mov r8,  [rdi + UC_R8]",
    "mov r9,  [rdi + UC_R9]",
    "mov r10, [rdi + UC_R10]",
    "mov r12, [rdi + UC_R12]",
    "mov r13, [rdi + UC_R13]",
    "mov r14, [rdi + UC_R14]",
    "mov r15, [rdi + UC_R15]",
    "mov rcx, [rdi + UC_RIP]",
    "mov r11, [rdi + UC_RFLAGS]",
    "cmp byte ptr gs:[GS_PTI], 0",
    "je 21f",
    "mov rax, gs:[GS_UCR3]",
    "mov cr3, rax",
    "or rax, gs:[GS_NOFLUSH]",
    "mov gs:[GS_UCR3], rax",
    "21:",
    "pop rdi",
    "pop rax",
    "pop rsp",
    "test byte ptr gs:[GS_VERW], 1",
    "jz 22f",
    "verw word ptr gs:[GS_VERWSEL]",
    "22:",
    "sysretq",
    // The syscall and trap paths come here to return to the kernel caller.
    "ichor_user_resume:",
    "mov rsp, gs:[GS_RESUME]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    // The kernel's first return after ring 3: through the return thunk, as
    // every return of the kernel's.
    "jmp __x86_return_thunk",
    // fn ichor_syscall_entry()  [via LSTAR: rcx=rip, r11=rflags, GS=block]
    ".global ichor_syscall_entry",
    "ichor_syscall_entry:",
    "mov gs:[GS_SCRATCH], rdi", // free rdi (holds user rdi)
    "cmp byte ptr gs:[GS_PTI], 0",
    "je 9f",
    "mov rdi, gs:[GS_KCR3]",
    "mov cr3, rdi",
    "9:",
    "mov rdi, gs:[GS_UCTX]",
    "mov [rdi + UC_RAX], rax",
    "mov [rdi + UC_RBX], rbx",
    "mov [rdi + UC_RCX], rcx",
    "mov [rdi + UC_RIP], rcx", // syscall puts the return rip in rcx
    "mov [rdi + UC_RDX], rdx",
    "mov [rdi + UC_RSI], rsi",
    "mov [rdi + UC_RBP], rbp",
    "mov [rdi + UC_RSP], rsp", // syscall does not change rsp: still the user's
    "mov [rdi + UC_R8], r8",
    "mov [rdi + UC_R9], r9",
    "mov [rdi + UC_R10], r10",
    "mov [rdi + UC_R11], r11",
    "mov [rdi + UC_RFLAGS], r11", // syscall puts rflags in r11
    "mov [rdi + UC_R12], r12",
    "mov [rdi + UC_R13], r13",
    "mov [rdi + UC_R14], r14",
    "mov [rdi + UC_R15], r15",
    "mov rax, gs:[GS_SCRATCH]",
    "mov [rdi + UC_RDI], rax",
    "mov qword ptr gs:[GS_EVENT], 1", // Syscall
    "ichor_spec_ctrl -1",
    // rsp is still the user's: the barriers call and return, so they run
    // on the kernel stack the run returns to.
    "mov rsp, gs:[GS_RESUME]",
    "ichor_entry_barriers",
    "jmp ichor_user_resume",
    // Clears the branch history: a software sequence for CPUs with BHI and
    // without BHI_DIS_S (Intel's BHI guidance): five times a call and a
    // return around five taken jumps, so that the history ends up made of
    // branches the kernel chose, then LFENCE so that nothing runs ahead of
    // it. Uses rax and rcx.
    ".balign 64",
    "ichor_clear_bhb:",
    "mov ecx, 5",
    "93:",
    "call 94f",
    "dec ecx",
    "jnz 93b",
    "lfence",
    "ret",
    ".balign 64",
    "94:",
    "mov eax, 5",
    "95:",
    "jmp 96f",
    "int3",
    "96:",
    "dec eax",
    "jnz 95b",
    "ret",
    ".balign 4096",
    ".global ichor_entry_end",
    "ichor_entry_end:",
    dispatch = sym super::trap::trap_dispatch,
);
