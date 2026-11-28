//! Entry from a PVH loader (ADR-0025): Firecracker, Cloud Hypervisor, or
//! QEMU's `-kernel` with an ELF that carries a PVH note. The stub in
//! `arch::pvh` arrives here in long mode, on its own identity map of the
//! first 4 GiB. This reads the loader's `hvm_start_info` (Xen's
//! `start_info.h`, version 1) into the [`BootState`] that `efi_main` fills
//! under UEFI, and goes on as it does.
//!
//! What UEFI's files on the boot volume carry comes as the loader's first
//! module (Firecracker's initrd), in the format xtask writes
//! (`xtask::pvh`): `ICHORBF1`, then for each file a `u16` name length, the
//! name (`roots.pem`, `suffixes.dat`, `apitoken`, `apitls.pem`), a `u32`
//! data length and the data, little-endian. The command line is the
//! loader's (Firecracker's `boot_args`).

use super::{
    BootState, CMDLINE_MAX, MAX_REGIONS, MemoryKind, MemoryRegion, Phase, fatal, take_boot_state,
};
use crate::mm::{PAGE_SIZE, PhysAddr};
use crate::power::{self, ExitStatus};
use crate::{arch, println};

const START_INFO_MAGIC: u32 = 0x336e_c578;
const START_INFO_LEN: usize = 56;
const MEMMAP_ENTRY_LEN: usize = 24;
const MODLIST_ENTRY_LEN: usize = 32;
/// How much the entry stub identity-maps.
const IDENTITY: u64 = 4 << 30;
const ONE_MIB: u64 = 1 << 20;
/// The legacy BIOS area, where a loader may put the RSDP.
const BIOS_AREA: (u64, u64) = (0xE_0000, 0x10_0000);
const BOOT_FILES_MAGIC: &[u8; 8] = b"ICHORBF1";

/// `len` bytes of physical memory at `addr`, below 4 GiB.
fn phys<'a>(addr: u64, len: usize) -> Option<&'a [u8]> {
    let end = addr.checked_add(len as u64)?;
    if addr == 0 || end > IDENTITY {
        return None;
    }
    let ptr = core::ptr::with_exposed_provenance::<u8>(addr as usize);
    // SAFETY: the range lies below 4 GiB, which the entry stub
    // identity-maps. The loader's structures and modules there are not Rust
    // objects, and nothing writes them while `pvh_main` reads them: it copies
    // what it needs into the boot state before `start`, which may reuse the
    // memory, and no slice outlives that.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

/// Where the stub's 64-bit code calls: `start_info` is what `%ebx` held,
/// `image_base` and `image_len` the image region xtask recorded (the PE
/// image laid out at its physical address, then the stub's scratch area),
/// `entry_tsc` the TSC at the stub's first instructions.
pub(crate) extern "sysv64" fn pvh_main(
    start_info: u64,
    image_base: u64,
    image_len: u64,
    entry_tsc: u64,
) -> ! {
    crate::time::set_entry(entry_tsc);
    let Some(state) = take_boot_state(Phase::Firmware) else {
        power::shutdown(ExitStatus::Failure)
    };
    arch::early_console::init();
    println!();
    println!("ichor: frame: entered by a PVH loader");

    let Some(info) = phys(start_info, START_INFO_LEN) else {
        fatal("no PVH start info below 4 GiB")
    };
    if u32_at(info, 0) != START_INFO_MAGIC {
        fatal("PVH start info has the wrong magic number");
    }
    let version = u32_at(info, 4);
    if version < 1 {
        fatal("PVH start info older than version 1 (no memory map)");
    }
    let nr_modules = u32_at(info, 12);
    let modlist = u64_at(info, 16);
    let cmdline = u64_at(info, 24);
    let rsdp = u64_at(info, 32);
    let memmap = u64_at(info, 40);
    let entries = u32_at(info, 48) as usize;

    read_cmdline(state, cmdline);
    if nr_modules > 0
        && let Some(m) = phys(modlist, MODLIST_ENTRY_LEN)
    {
        match phys(u64_at(m, 0), u64_at(m, 8) as usize) {
            Some(files) => read_boot_files(state, files),
            None => println!("ichor: frame: warning: the boot files module is not below 4 GiB"),
        }
    }
    state.acpi_rsdp = if rsdp != 0 {
        Some(PhysAddr::new(rsdp))
    } else {
        find_rsdp()
    };
    let vendor = b"PVH loader";
    state.vendor[..vendor.len()].copy_from_slice(vendor);
    state.vendor_len = vendor.len();

    let image_end = (image_base + image_len).next_multiple_of(PAGE_SIZE);
    state.kernel_image = MemoryRegion {
        base: PhysAddr::new(image_base),
        len: image_end - image_base,
        kind: MemoryKind::Kernel,
    };
    let Some(map) = phys(memmap, entries.saturating_mul(MEMMAP_ENTRY_LEN)) else {
        fatal("the PVH memory map is not below 4 GiB")
    };
    state.region_count = convert_memory_map(map, (image_base, image_end), &mut state.regions);

    let flags = cmdline::Cmdline::new(state.cmdline());
    if flags.flag("qemu_debug_exit") {
        power::enable_qemu_debug_exit();
    }
    if flags.flag("console_sync") {
        crate::console::set_sync();
    }
    crate::time::record_step(crate::time::BootStep::Files);
    crate::time::record_step(crate::time::BootStep::Exited);
    println!(
        "ichor: frame: PVH start info v{version}: {entries} memory map entries, {nr_modules} modules, RSDP {}",
        if state.acpi_rsdp.is_some() {
            "found"
        } else {
            "missing"
        }
    );
    super::start(state, IDENTITY)
}

/// The loader's NUL-terminated command line, as much as fits.
fn read_cmdline(state: &mut BootState, at: u64) {
    let len = CMDLINE_MAX.min(IDENTITY.saturating_sub(at) as usize);
    let Some(bytes) = phys(at, len) else { return };
    let n = bytes.iter().position(|&b| b == 0).unwrap_or(len);
    state.cmdline[..n].copy_from_slice(&bytes[..n]);
    state.cmdline_len = match core::str::from_utf8(&state.cmdline[..n]) {
        Ok(s) => s.len(),
        Err(e) => {
            println!("ichor: frame: warning: command line is not UTF-8; truncating");
            e.valid_up_to()
        }
    };
}

/// The files UEFI would have read from `\ichor\` (see the module comment).
fn read_boot_files(state: &mut BootState, mut b: &[u8]) {
    if b.get(..8) != Some(&BOOT_FILES_MAGIC[..]) {
        println!("ichor: frame: warning: the first module is not Ichor's boot files; ignored");
        return;
    }
    b = &b[8..];
    while let Some(name_len) = u16_at(b, 0) {
        let name_end = 2 + usize::from(name_len);
        let (Some(name), Some(data_len)) = (b.get(2..name_end), b.get(name_end..name_end + 4))
        else {
            break;
        };
        let data_len = u32_at(data_len, 0) as usize;
        let start = name_end + 4;
        let Some(data) = b.get(start..start + data_len) else {
            println!("ichor: frame: warning: the boot files are truncated");
            break;
        };
        let (buf, len): (&mut [u8], &mut usize) = match name {
            b"roots.pem" => (&mut state.roots, &mut state.roots_len),
            b"suffixes.dat" => (&mut state.suffixes, &mut state.suffixes_len),
            b"apitoken" => (&mut state.token, &mut state.token_len),
            b"apitls.pem" => (&mut state.tls, &mut state.tls_len),
            _ => {
                b = &b[start + data_len..];
                continue;
            }
        };
        // As under UEFI: a file that does not fit is ignored, not cut.
        if data.len() < buf.len() {
            buf[..data.len()].copy_from_slice(data);
            *len = data.len();
        } else {
            println!(
                "ichor: frame: warning: boot file {} is {} bytes or more; ignored",
                core::str::from_utf8(name).unwrap_or("?"),
                buf.len()
            );
        }
        b = &b[start + data_len..];
    }
}

/// The RSDP's signature on a 16-byte boundary of the BIOS area.
fn find_rsdp() -> Option<PhysAddr> {
    let area = phys(BIOS_AREA.0, (BIOS_AREA.1 - BIOS_AREA.0) as usize)?;
    (0..area.len())
        .step_by(16)
        .find(|&i| area.get(i..i + 8) == Some(b"RSD PTR "))
        .map(|i| PhysAddr::new(BIOS_AREA.0 + i as u64))
}

/// Frame's regions from the loader's E820-style map (type 1 RAM, 3 ACPI,
/// 4 ACPI NVS, 5 unusable, anything else reserved), sorted:
///
/// - below 1 MiB, the RAM that starts at 0 (pages inward) is usable, and the
///   rest of the first megabyte, where loaders keep the ACPI tables and the
///   RSDP, is ACPI's, so frame's ACPI reader may read it;
/// - above, RAM is usable (pages inward) but for the image, which is the
///   kernel's; other kinds keep their pages outward.
fn convert_memory_map(map: &[u8], image: (u64, u64), out: &mut [MemoryRegion]) -> usize {
    let mut n = 0;
    let mut push = |base: u64, end: u64, kind| {
        if end > base
            && let Some(slot) = out.get_mut(n)
        {
            *slot = MemoryRegion {
                base: PhysAddr::new(base),
                len: end - base,
                kind,
            };
            n += 1;
        }
    };
    let entries = map.as_chunks::<MEMMAP_ENTRY_LEN>().0;
    let low_ram = entries
        .iter()
        .find(|e| u64_at(&e[..], 0) == 0 && u32_at(&e[..], 16) == 1)
        .map_or(0, |e| {
            u64_at(&e[..], 8).min(ONE_MIB) / PAGE_SIZE * PAGE_SIZE
        });
    push(0, low_ram, MemoryKind::Usable);
    push(low_ram, ONE_MIB, MemoryKind::AcpiReclaimable);
    for e in entries {
        let (addr, size, kind) = (u64_at(e, 0), u64_at(e, 8), u32_at(e, 16));
        let end = addr.saturating_add(size);
        if end <= ONE_MIB {
            continue;
        }
        let addr = addr.max(ONE_MIB);
        if kind == 1 {
            let b = addr.next_multiple_of(PAGE_SIZE);
            let e = (end / PAGE_SIZE) * PAGE_SIZE;
            if image.0 < e && b < image.1 {
                push(b, image.0, MemoryKind::Usable);
                push(image.0.max(b), image.1.min(e), MemoryKind::Kernel);
                push(image.1, e, MemoryKind::Usable);
            } else {
                push(b, e, MemoryKind::Usable);
            }
        } else {
            // A reserved block that starts where RAM ends, below 4 GiB, is
            // the firmware's: SeaBIOS (QEMU's PVH option ROM) keeps its ACPI
            // tables there. It is mapped and never allocated, as ACPI NVS
            // is; other reserved blocks may be chipset MMIO and stay unmapped.
            let after_ram = entries
                .iter()
                .any(|r| u32_at(r, 16) == 1 && u64_at(r, 0) + u64_at(r, 8) == addr);
            let kind = match kind {
                3 => MemoryKind::AcpiReclaimable,
                4 => MemoryKind::AcpiNvs,
                5 => MemoryKind::Unusable,
                2 if after_ram && end <= IDENTITY => MemoryKind::AcpiNvs,
                _ => MemoryKind::Reserved,
            };
            push(
                (addr / PAGE_SIZE) * PAGE_SIZE,
                end.next_multiple_of(PAGE_SIZE),
                kind,
            );
        }
    }
    let n = n.min(MAX_REGIONS);
    out[..n].sort_unstable_by_key(|r| r.base);
    n
}
