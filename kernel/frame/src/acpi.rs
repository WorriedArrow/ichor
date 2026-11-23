//! Reading firmware ACPI tables.
//!
//! Tables are *copied* out of physical memory with volatile reads into heap
//! buffers and parsed by the safe `acpi` crate. No reference into
//! firmware-owned memory is ever formed (some of it, like ACPI NVS, may be
//! written by firmware at any time), and only memory the firmware map marks
//! as firmware-owned RAM can be read this way.

use alloc::vec::Vec;

use acpi::{HEADER_LEN, RSDP_LEN, Root};

use crate::boot::{self, MemoryKind};
use crate::mm::{PhysAddr, phys_to_virt};

/// Upper bound on a table we are willing to copy.
const MAX_TABLE: usize = 1 << 20;

/// Copies `len` bytes of firmware memory at `pa`.
fn copy_phys(pa: u64, len: usize) -> Option<Vec<u8>> {
    let end = pa.checked_add(len as u64)?;
    let inside = boot::memory_map().iter().any(|r| {
        matches!(
            r.kind,
            MemoryKind::AcpiReclaimable | MemoryKind::AcpiNvs | MemoryKind::RuntimeServices
        ) && r.base.as_u64() <= pa
            && end <= r.end().as_u64()
    });
    if !inside || len > MAX_TABLE {
        return None;
    }
    let base = phys_to_virt(PhysAddr::new(pa)) as usize;
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        let p = core::ptr::with_exposed_provenance::<u8>(base + i);
        // SAFETY: the byte lies in firmware-owned RAM (checked above), which
        // the linear map covers and the page allocator never hands out. A
        // volatile byte read cannot conflict with Rust references because
        // none exist into this memory.
        out.push(unsafe { p.read_volatile() });
    }
    Some(out)
}

fn copy_table(pa: u64) -> Option<Vec<u8>> {
    let header = acpi::parse_header(&copy_phys(pa, HEADER_LEN)?).ok()?;
    copy_phys(pa, header.length as usize)
}

/// Copies the table at `pa` (one a FADT points at, such as the DSDT).
pub(crate) fn table_at(pa: u64) -> Option<Vec<u8>> {
    copy_table(pa)
}

/// Finds and copies the first table with `signature`, validated.
pub(crate) fn find_table(signature: &[u8; 4]) -> Option<Vec<u8>> {
    find_in_tables(signature, Some)
}

/// The first answer `f` gives for a validated copy of each table with
/// `signature` (there may be several SSDTs), in the root table's order.
pub(crate) fn find_in_tables<T>(
    signature: &[u8; 4],
    mut f: impl FnMut(Vec<u8>) -> Option<T>,
) -> Option<T> {
    let rsdp = copy_phys(boot::acpi_rsdp()?.as_u64(), RSDP_LEN)
        .or_else(|| copy_phys(boot::acpi_rsdp()?.as_u64(), 20))?;
    let root = acpi::parse_rsdp(&rsdp).ok()?;
    let (root_pa, sig) = match root {
        Root::Xsdt(a) => (a, b"XSDT"),
        Root::Rsdt(a) => (u64::from(a), b"RSDT"),
    };
    let root_table = copy_table(root_pa)?;
    acpi::validate(&root_table, sig).ok()?;
    acpi::root_entries(&root_table, root).find_map(|pa| {
        let t = copy_table(pa)?;
        acpi::validate(&t, signature).ok()?;
        f(t)
    })
}
