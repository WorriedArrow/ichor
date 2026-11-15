//! ACPI table parsing.
//!
//! Every function takes byte slices that the caller (frame) has already
//! mapped. Nothing here dereferences addresses: table pointers are returned
//! as physical addresses for the caller to resolve. All reads are bounds-
//! checked and checksums are verified, so malformed firmware tables produce
//! an [`Error`], never a panic.

#![no_std]
#![forbid(unsafe_code)]

/// Why a table was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BadSignature,
    BadChecksum,
    BadLength,
}

fn get<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    let end = at.checked_add(N).ok_or(Error::Truncated)?;
    let s = b.get(at..end).ok_or(Error::Truncated)?;
    let mut out = [0; N];
    out.copy_from_slice(s);
    Ok(out)
}

fn u8_at(b: &[u8], at: usize) -> Result<u8, Error> {
    Ok(get::<1>(b, at)?[0])
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(get(b, at)?))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(get(b, at)?))
}

fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) == 0
}

/// The root table the RSDP points at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Root {
    /// 64-bit XSDT (ACPI 2.0+).
    Xsdt(u64),
    /// 32-bit RSDT (ACPI 1.0).
    Rsdt(u32),
}

/// Length of the RSDP structure to map: 36 bytes for ACPI 2.0+.
pub const RSDP_LEN: usize = 36;
/// Length of a system description table header.
pub const HEADER_LEN: usize = 36;

/// Parses the RSDP (pass at least 20 bytes; 36 for ACPI 2.0+).
pub fn parse_rsdp(b: &[u8]) -> Result<Root, Error> {
    if b.get(0..8) != Some(b"RSD PTR ") {
        return Err(Error::BadSignature);
    }
    if !checksum_ok(b.get(..20).ok_or(Error::Truncated)?) {
        return Err(Error::BadChecksum);
    }
    let revision = u8_at(b, 15)?;
    if revision >= 2 {
        let len = u32_at(b, 20)? as usize;
        if len < RSDP_LEN {
            return Err(Error::BadLength);
        }
        if !checksum_ok(b.get(..len).ok_or(Error::Truncated)?) {
            return Err(Error::BadChecksum);
        }
        let xsdt = u64_at(b, 24)?;
        if xsdt != 0 {
            return Ok(Root::Xsdt(xsdt));
        }
    }
    Ok(Root::Rsdt(u32_at(b, 16)?))
}

/// The common header of a system description table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub signature: [u8; 4],
    pub length: u32,
}

/// Parses just the header (from at least [`HEADER_LEN`] bytes), so the
/// caller knows how much to map.
pub fn parse_header(b: &[u8]) -> Result<Header, Error> {
    let h = Header {
        signature: get(b, 0)?,
        length: u32_at(b, 4)?,
    };
    if (h.length as usize) < HEADER_LEN {
        return Err(Error::BadLength);
    }
    Ok(h)
}

/// Validates a complete table (`b` is exactly `length` bytes) and checks its
/// signature.
pub fn validate(b: &[u8], signature: &[u8; 4]) -> Result<(), Error> {
    let h = parse_header(b)?;
    if &h.signature != signature {
        return Err(Error::BadSignature);
    }
    if h.length as usize != b.len() {
        return Err(Error::BadLength);
    }
    if !checksum_ok(b) {
        return Err(Error::BadChecksum);
    }
    Ok(())
}

/// Physical addresses of the tables listed in a validated XSDT or RSDT.
pub fn root_entries(table: &[u8], root: Root) -> impl Iterator<Item = u64> + '_ {
    let width = match root {
        Root::Xsdt(_) => 8,
        Root::Rsdt(_) => 4,
    };
    let body = table.get(HEADER_LEN..).unwrap_or(&[]);
    body.chunks_exact(width).map(move |c| {
        if width == 8 {
            u64_at(c, 0).unwrap_or(0)
        } else {
            u64::from(u32_at(c, 0).unwrap_or(0))
        }
    })
}

/// One processor's local APIC, from the MADT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalApic {
    /// The (x2)APIC ID used to address IPIs.
    pub apic_id: u32,
    /// ACPI processor UID.
    pub uid: u32,
    /// Enabled now, or may be enabled later (online-capable).
    pub enabled: bool,
    pub online_capable: bool,
}

/// Local APIC entries of a validated MADT (types 0 and 9). Malformed
/// entries end the iteration.
pub fn madt_local_apics(madt: &[u8]) -> impl Iterator<Item = LocalApic> + '_ {
    let mut at = HEADER_LEN + 8;
    core::iter::from_fn(move || {
        loop {
            let kind = u8_at(madt, at).ok()?;
            let len = usize::from(u8_at(madt, at + 1).ok()?);
            if len < 2 || at + len > madt.len() {
                return None;
            }
            let entry = &madt[at..at + len];
            at += len;
            let parsed = match kind {
                0 if len >= 8 => {
                    let flags = u32_at(entry, 4).ok()?;
                    Some(LocalApic {
                        apic_id: u32::from(u8_at(entry, 3).ok()?),
                        uid: u32::from(u8_at(entry, 2).ok()?),
                        enabled: flags & 1 != 0,
                        online_capable: flags & 2 != 0,
                    })
                }
                9 if len >= 16 => {
                    let flags = u32_at(entry, 8).ok()?;
                    Some(LocalApic {
                        apic_id: u32_at(entry, 4).ok()?,
                        uid: u32_at(entry, 12).ok()?,
                        enabled: flags & 1 != 0,
                        online_capable: flags & 2 != 0,
                    })
                }
                _ => None,
            };
            if parsed.is_some() {
                return parsed;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn fix_checksum(b: &mut [u8], at: usize, range: core::ops::Range<usize>) {
        b[at] = 0;
        let sum = b[range].iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[at] = 0u8.wrapping_sub(sum);
    }

    fn rsdp(rev: u8, xsdt: u64, rsdt: u32) -> Vec<u8> {
        let mut b = std::vec![0u8; 36];
        b[0..8].copy_from_slice(b"RSD PTR ");
        b[15] = rev;
        b[16..20].copy_from_slice(&rsdt.to_le_bytes());
        b[20..24].copy_from_slice(&36u32.to_le_bytes());
        b[24..32].copy_from_slice(&xsdt.to_le_bytes());
        fix_checksum(&mut b, 8, 0..20);
        fix_checksum(&mut b, 32, 0..36);
        b
    }

    fn table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut b = std::vec![0u8; HEADER_LEN];
        b[0..4].copy_from_slice(sig);
        b.extend_from_slice(body);
        let len = b.len() as u32;
        b[4..8].copy_from_slice(&len.to_le_bytes());
        let n = b.len();
        fix_checksum(&mut b, 9, 0..n);
        b
    }

    #[test]
    fn rsdp_versions() {
        assert_eq!(
            parse_rsdp(&rsdp(2, 0x1234_5678_9000, 0x1000)),
            Ok(Root::Xsdt(0x1234_5678_9000))
        );
        assert_eq!(
            parse_rsdp(&rsdp(0, 0, 0xabc000)[..20]),
            Ok(Root::Rsdt(0xabc000))
        );
        let mut bad = rsdp(2, 1, 2);
        bad[30] ^= 1;
        assert_eq!(parse_rsdp(&bad), Err(Error::BadChecksum));
        assert_eq!(parse_rsdp(b"RSD PTX "), Err(Error::BadSignature));
    }

    #[test]
    fn xsdt_entries_and_validation() {
        let mut body = Vec::new();
        for a in [0x1000u64, 0x2000, 0x3000] {
            body.extend_from_slice(&a.to_le_bytes());
        }
        let t = table(b"XSDT", &body);
        validate(&t, b"XSDT").unwrap();
        assert_eq!(validate(&t, b"RSDT"), Err(Error::BadSignature));
        let e: Vec<u64> = root_entries(&t, Root::Xsdt(0)).collect();
        assert_eq!(e, [0x1000, 0x2000, 0x3000]);
        let mut corrupt = t.clone();
        corrupt[40] ^= 0xff;
        assert_eq!(validate(&corrupt, b"XSDT"), Err(Error::BadChecksum));
        assert_eq!(validate(&t[..40], b"XSDT"), Err(Error::BadLength));
    }

    #[test]
    fn madt_apics() {
        let mut body = std::vec![0u8; 8]; // local APIC address + flags
        body.extend_from_slice(&[0, 8, 0, 0, 1, 0, 0, 0]); // cpu uid 0, apic 0, enabled
        body.extend_from_slice(&[1, 12, 0, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0]); // IOAPIC (skipped)
        body.extend_from_slice(&[0, 8, 1, 2, 0, 0, 0, 0]); // apic 2, disabled
        let mut x2 = std::vec![9u8, 16, 0, 0];
        x2.extend_from_slice(&300u32.to_le_bytes());
        x2.extend_from_slice(&3u32.to_le_bytes()); // enabled + online capable
        x2.extend_from_slice(&7u32.to_le_bytes());
        body.extend_from_slice(&x2);
        body.extend_from_slice(&[0, 1]); // malformed: ends iteration
        let t = table(b"APIC", &body);
        let apics: Vec<LocalApic> = madt_local_apics(&t).collect();
        assert_eq!(apics.len(), 3);
        assert_eq!(
            apics[0],
            LocalApic {
                apic_id: 0,
                uid: 0,
                enabled: true,
                online_capable: false
            }
        );
        assert!(!apics[1].enabled);
        assert_eq!(
            apics[2],
            LocalApic {
                apic_id: 300,
                uid: 7,
                enabled: true,
                online_capable: true
            }
        );
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 7;
        for len in 0..200 {
            let g: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (x >> 24) as u8
                })
                .collect();
            let _ = parse_rsdp(&g);
            let _ = parse_header(&g);
            let _ = validate(&g, b"APIC");
            let _ = madt_local_apics(&g).count();
            let _ = root_entries(&g, Root::Rsdt(0)).count();
        }
    }
}
