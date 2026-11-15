//! Bringing up the other CPUs.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;

use crate::arch::{self, apic, paging, smp as asm};
use crate::boot::{self, MemoryKind};
use crate::cpu::{self, CpuId, MAX_CPUS};
use crate::mm::kspace;
use crate::mm::{PAGE_SIZE, PhysAddr, phys_to_virt};
use crate::sync::SpinLock;

/// What each AP runs once frame has set it up.
static AP_MAIN: SpinLock<Option<fn(CpuId) -> !>> = SpinLock::new(None);
/// APs that have reached `ap_entry`.
static ARRIVED: AtomicUsize = AtomicUsize::new(0);
/// Physical address of the kernel PML4, for APs to load.
static KERNEL_CR3: AtomicU64 = AtomicU64::new(0);

const ONE_MIB: u64 = 1 << 20;

/// Picks `n` free pages below 1 MiB (never given to the page allocator).
fn low_pages(n: usize) -> Option<Vec<u64>> {
    let mut pages = Vec::new();
    for r in boot::memory_map()
        .iter()
        .filter(|r| r.kind == MemoryKind::Usable)
    {
        let mut p = r.base.as_u64().max(PAGE_SIZE).next_multiple_of(PAGE_SIZE);
        while p + PAGE_SIZE <= r.end().as_u64().min(ONE_MIB) && pages.len() < n {
            pages.push(p);
            p += PAGE_SIZE;
        }
    }
    (pages.len() == n).then_some(pages)
}

/// The trampoline page as bytes.
fn trampoline_page(pa: u64) -> &'static mut [u8] {
    let ptr =
        core::ptr::with_exposed_provenance_mut::<u8>(phys_to_virt(PhysAddr::new(pa)) as usize);
    // SAFETY: `pa` is a page below 1 MiB that `low_pages` chose: usable RAM
    // excluded from the page allocator, mapped by the linear map, and used
    // only as the trampoline. This is the only reference ever made to it, as
    // bring-up runs once (guarded by AP_MAIN).
    unsafe { core::slice::from_raw_parts_mut(ptr, PAGE_SIZE as usize) }
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Starts every enabled CPU the ACPI MADT lists, running `ap_main` on each
/// once frame has initialized it (GDT/TSS/IDT, x2APIC, timer, per-CPU
/// data, protections). Returns the number of CPUs online, including this one.
/// Only the first call does anything.
pub fn start_aps(ap_main: fn(CpuId) -> !) -> usize {
    {
        let mut slot = AP_MAIN.lock();
        if slot.is_some() {
            return cpu::online_count();
        }
        *slot = Some(ap_main);
    }
    let Some(madt) = crate::acpi::find_table(b"APIC") else {
        crate::println!("ichor: smp: no MADT; running on one CPU");
        return cpu::online_count();
    };
    let me = apic::apic_id();
    let targets: Vec<u32> = acpi::madt_local_apics(&madt)
        .filter(|a| a.enabled && a.apic_id != me)
        .map(|a| a.apic_id)
        .take(MAX_CPUS - 1)
        .collect();
    if targets.is_empty() {
        return cpu::online_count();
    }
    let Some(pages) = low_pages(4) else {
        crate::println!("ichor: smp: no free memory below 1 MiB; running on one CPU");
        return cpu::online_count();
    };
    let (tramp, pml4, pdpt, pd) = (pages[0], pages[1], pages[2], pages[3]);

    // One stack per AP, indexed by the CPU index the AP claims (1..).
    let mut stacks: Vec<u64> = Vec::with_capacity(targets.len() + 1);
    stacks.push(0);
    for _ in &targets {
        match kspace::alloc_stack() {
            Some(top) => stacks.push(top),
            None => break,
        }
    }
    let count = stacks.len() - 1;
    for i in 1..=count {
        cpu::register_ap_block(CpuId::new(i as u32));
    }
    let stacks: &'static [u64] = stacks.leak();

    // AP page tables: identity map of the first 2 MiB plus the kernel half.
    let kernel_cr3 = arch::regs::read_cr3() & 0x000f_ffff_ffff_f000;
    KERNEL_CR3.store(kernel_cr3, Ordering::Release);
    let (pml4, pdpt, pd) = (PhysAddr::new(pml4), PhysAddr::new(pdpt), PhysAddr::new(pd));
    for p in [pml4, pdpt, pd] {
        // SAFETY: a page below 1 MiB reserved for SMP bring-up (never given
        // to the page allocator), mapped by the linear map, about to become
        // part of the APs' boot page table.
        unsafe { paging::zero_page(p) };
    }
    // SAFETY: `kernel_cr3` is the live kernel PML4 (only read) and `pml4`
    // the fresh AP PML4; both are page-table pages reachable via the linear
    // map. The entries installed point at the other fresh tables and an
    // identity 2 MiB page covering the trampoline.
    unsafe {
        paging::copy_upper_half(PhysAddr::new(kernel_cr3), pml4);
    }
    // SAFETY: as above.
    unsafe { paging::set_entry(pml4, 0, pdpt.as_u64() | 0b11) };
    // SAFETY: as above.
    unsafe { paging::set_entry(pdpt, 0, pd.as_u64() | 0b11) };
    // SAFETY: as above; 2 MiB page at 0: present, writable, huge.
    unsafe { paging::set_entry(pd, 0, 0b1000_0011) };

    let code = asm::trampoline_code();
    let t = trampoline_page(tramp);
    t[..code.len()].copy_from_slice(code);
    put_u32(t, asm::OFF_CR3, pml4.as_u64() as u32);
    put_u32(t, asm::OFF_NEXT_CPU, 1);
    put_u64(t, asm::OFF_STACKS, stacks.as_ptr() as u64);
    put_u64(
        t,
        asm::OFF_ENTRY,
        ap_entry as extern "sysv64" fn(u32) -> ! as usize as u64,
    );

    let page = (tramp / PAGE_SIZE) as u8;
    for &id in targets.iter().take(count) {
        apic::start_ap(id, page);
    }
    // Wait (bounded) for every AP to finish initializing.
    let deadline = crate::time::now() + Duration::from_secs(2);
    while cpu::online_count() < count + 1 && crate::time::now() < deadline {
        core::hint::spin_loop();
    }
    let online = cpu::online_count();
    if online < count + 1 {
        crate::println!(
            "ichor: smp: only {} of {} CPUs came online ({} reached the kernel)",
            online,
            count + 1,
            ARRIVED.load(Ordering::Relaxed)
        );
    }
    online
}

/// Where each AP lands after the trampoline, on its own stack in the
/// higher half.
extern "sysv64" fn ap_entry(index: u32) -> ! {
    ARRIVED.fetch_add(1, Ordering::Relaxed);
    // SAFETY: KERNEL_CR3 is the kernel PML4, which maps this code and this
    // CPU's stack (both in the shared upper half).
    unsafe { asm::load_kernel_cr3(KERNEL_CR3.load(Ordering::Acquire)) };
    if index as usize >= MAX_CPUS {
        arch::halt_forever();
    }
    let id = CpuId::new(index);
    cpu::init_ap_block(id);
    crate::boot::init_cpu(id);
    let main = *AP_MAIN.lock();
    match main {
        Some(f) => f(id),
        None => arch::halt_forever(),
    }
}
