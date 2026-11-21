//! File names are bytes on Linux; this crate keeps them as `String`. The
//! kernel crosses between the two at the syscall boundary with a reversible
//! escape: [`encode`] turns each byte that is not part of valid UTF-8 into
//! one character of a reserved private-use range (U+10FF80..=U+10FFFF, the
//! end of plane 16, which nothing assigns), and [`decode`] turns those
//! characters back into their bytes. A name that already uses the reserved
//! range is escaped byte by byte too, so `decode(encode(b)) == b` for every
//! byte string, and valid UTF-8 outside the range passes through unchanged.
//!
//! The cost: an escaped byte takes four bytes of the `String`, so a name
//! made mostly of undecodable bytes reaches NAME_MAX sooner than on Linux.

use alloc::string::String;
use alloc::vec::Vec;

/// The reserved range starts here; byte `b` (always >= 0x80) is `BASE + b`.
const BASE: u32 = 0x10_FF00;

fn reserved(c: char) -> bool {
    (BASE + 0x80..=BASE + 0xFF).contains(&u32::from(c))
}

fn escape(out: &mut String, b: u8) {
    // In range for every byte >= 0x80, which is all this is called with.
    out.push(char::from_u32(BASE + u32::from(b)).unwrap_or(char::REPLACEMENT_CHARACTER));
}

fn push_valid(out: &mut String, s: &str) {
    for c in s.chars() {
        if reserved(c) {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                escape(out, b);
            }
        } else {
            out.push(c);
        }
    }
}

/// A user-space name (bytes) as this crate's `String`.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(s) => {
                push_valid(&mut out, s);
                break;
            }
            Err(e) => {
                let (ok, bad) = rest.split_at(e.valid_up_to());
                if let Ok(s) = core::str::from_utf8(ok) {
                    push_valid(&mut out, s);
                }
                let n = e.error_len().unwrap_or(bad.len()).max(1);
                for &b in &bad[..n] {
                    escape(&mut out, b);
                }
                rest = &bad[n..];
            }
        }
    }
    out
}

/// A name from this crate back as the bytes user space gave.
pub fn decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        if reserved(c) {
            out.push((u32::from(c) - BASE) as u8);
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_passes_through() {
        for s in ["", "motd", "/etc/passwd", "caf\u{e9}", "\u{20ac}\u{1f600}"] {
            assert_eq!(encode(s.as_bytes()), s);
            assert_eq!(decode(s), s.as_bytes());
        }
    }

    #[test]
    fn undecodable_bytes_round_trip() {
        for b in [
            &b"@test_368_tmp-\xff"[..],
            b"\xff\xfe",
            b"a\x80b",
            b"\xc3",             // truncated sequence at the end
            b"\xe2\x82",         // truncated three-byte sequence
            b"\xed\xa0\x80",     // an encoded surrogate
            b"\xf4\x90\x80\x80", // above U+10FFFF
        ] {
            let s = encode(b);
            assert_eq!(decode(&s), b, "{b:?}");
        }
        assert_eq!(encode(b"x\xff").chars().count(), 2);
    }

    #[test]
    fn the_reserved_range_is_itself_escaped() {
        let real = "\u{10ff80}\u{10ffff}ok";
        let s = encode(real.as_bytes());
        assert_ne!(s, real);
        assert_eq!(decode(&s), real.as_bytes());
        // Every byte string survives, the escapes' own encodings included.
        for b in 0x80u8..=0xff {
            let raw = [b'a', b, b'z'];
            assert_eq!(decode(&encode(&raw)), raw);
            let esc = encode(&[b]);
            assert_eq!(decode(&encode(esc.as_bytes())), esc.as_bytes());
        }
    }
}
