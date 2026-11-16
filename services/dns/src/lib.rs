//! DNS for the control plane (ADR-0012 §3): the messages of a stub
//! resolver asking a recursive server for A records (RFC 1035), sans-I/O.
//! The caller sends [`query`] over UDP and hands the answer to
//! [`parse_a`], which follows the CNAME chain the server included.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Why an answer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    /// Not the answer to our query (id or question).
    Mismatch,
    /// The server's RCODE (3: no such name).
    Rcode(u8),
    /// A valid answer without an address.
    NoAddress,
    BadName,
}

/// A query for `name`'s A records with transaction `id`.
pub fn query(id: u16, name: &str) -> Result<Vec<u8>, Error> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(&mut q, name)?;
    q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    Ok(q)
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), Error> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(Error::BadName);
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::BadName);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Reads a (possibly compressed) name at `*at`, advancing past it.
fn read_name(msg: &[u8], at: &mut usize) -> Result<String, Error> {
    let mut name = String::new();
    let mut pos = *at;
    let mut jumped = false;
    for _ in 0..128 {
        let len = *msg.get(pos).ok_or(Error::Malformed)?;
        match len {
            0 => {
                if !jumped {
                    *at = pos + 1;
                }
                return Ok(name);
            }
            l if l & 0xc0 == 0xc0 => {
                let ptr = (usize::from(l & 0x3f) << 8)
                    | usize::from(*msg.get(pos + 1).ok_or(Error::Malformed)?);
                if !jumped {
                    *at = pos + 2;
                }
                jumped = true;
                pos = ptr;
            }
            l if l < 64 => {
                let label = msg
                    .get(pos + 1..pos + 1 + usize::from(l))
                    .ok_or(Error::Malformed)?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(core::str::from_utf8(label).map_err(|_| Error::Malformed)?);
                pos += 1 + usize::from(l);
            }
            _ => return Err(Error::Malformed),
        }
    }
    Err(Error::Malformed) // a pointer loop
}

/// The A records for `name` in the answer to query `id`.
pub fn parse_a(msg: &[u8], id: u16, name: &str) -> Result<Vec<[u8; 4]>, Error> {
    if msg.len() < 12 {
        return Err(Error::Malformed);
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != id || msg[2] & 0x80 == 0 {
        return Err(Error::Mismatch);
    }
    let rcode = msg[3] & 0x0f;
    if rcode != 0 {
        return Err(Error::Rcode(rcode));
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut at = 12;
    let want = name.trim_end_matches('.');
    for _ in 0..qd {
        let q = read_name(msg, &mut at)?;
        if !q.eq_ignore_ascii_case(want) {
            return Err(Error::Mismatch);
        }
        at += 4;
    }
    // Follow the CNAME chain from the name asked for.
    let mut current = String::from(want);
    let mut records = Vec::new();
    for _ in 0..an {
        let owner = read_name(msg, &mut at)?;
        let h = msg.get(at..at + 10).ok_or(Error::Malformed)?;
        let (ty, class) = (
            u16::from_be_bytes([h[0], h[1]]),
            u16::from_be_bytes([h[2], h[3]]),
        );
        let len = usize::from(u16::from_be_bytes([h[8], h[9]]));
        let rdata_at = at + 10;
        let rdata = msg.get(rdata_at..rdata_at + len).ok_or(Error::Malformed)?;
        records.push((owner, ty, class, rdata_at, rdata));
        at = rdata_at + len;
    }
    for _ in 0..16 {
        let mut next = None;
        let mut out = Vec::new();
        for (owner, ty, class, rdata_at, rdata) in &records {
            if *class != 1 || !owner.eq_ignore_ascii_case(&current) {
                continue;
            }
            match ty {
                1 if rdata.len() == 4 => out.push([rdata[0], rdata[1], rdata[2], rdata[3]]),
                5 => {
                    let mut p = *rdata_at;
                    next = Some(read_name(msg, &mut p)?);
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            return Ok(out);
        }
        match next {
            Some(n) => current = n,
            None => break,
        }
    }
    Err(Error::NoAddress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn answer(id: u16) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
        m.extend(query(id, "registry-1.docker.io").unwrap()[12..].iter());
        // registry-1.docker.io CNAME edge.example. (name at offset 12)
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 14]);
        m.extend_from_slice(&[4, b'e', b'd', b'g', b'e', 7]);
        m.extend_from_slice(b"example");
        m.push(0);
        // edge.example A 52.1.2.3, its name as a pointer to the CNAME data.
        let cname_at = m.len() - 14;
        m.extend_from_slice(&[
            0xc0,
            cname_at as u8,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            60,
            0,
            4,
            52,
            1,
            2,
            3,
        ]);
        m
    }

    #[test]
    fn queries_and_cname_chains() {
        let q = query(0x1234, "registry-1.docker.io.").unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 1, 0]);
        assert_eq!(q[12], 10);
        assert_eq!(
            parse_a(&answer(7), 7, "registry-1.docker.io").unwrap(),
            vec![[52, 1, 2, 3]]
        );
    }

    #[test]
    fn refuses_mismatches_and_garbage() {
        assert_eq!(
            parse_a(&answer(7), 8, "registry-1.docker.io"),
            Err(Error::Mismatch)
        );
        assert_eq!(
            parse_a(&answer(7), 7, "auth.docker.io"),
            Err(Error::Mismatch)
        );
        let mut nx = answer(7);
        nx[3] = 0x83;
        assert_eq!(
            parse_a(&nx, 7, "registry-1.docker.io"),
            Err(Error::Rcode(3))
        );
        let mut lp = answer(7);
        let n = lp.len();
        lp.truncate(n - 16);
        lp.extend_from_slice(&[0xc0, (n - 16) as u8]); // a name pointing at itself
        assert!(parse_a(&lp, 7, "registry-1.docker.io").is_err());
        assert!(query(1, "a..b").is_err());
        for n in 0..answer(7).len() {
            let _ = parse_a(&answer(7)[..n], 7, "registry-1.docker.io");
        }
    }
}
