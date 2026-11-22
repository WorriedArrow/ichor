//! DEFLATE (RFC 1951) and gzip (RFC 1952) decoding, in the style of
//! zlib's `puff.c`: canonical Huffman decoding one bit at a time. Fast
//! enough for tens of megabytes.

use alloc::vec;
use alloc::vec::Vec;

use crate::{ANY, Result, Room, fits};

const MAXBITS: usize = 15;

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    bitbuf: u32,
    bitcnt: u32,
}

impl Bits<'_> {
    fn need(&mut self, n: u32) -> Result<u32> {
        let mut val = self.bitbuf;
        while self.bitcnt < n {
            let byte = *self.data.get(self.pos).ok_or("deflate: input ends early")?;
            self.pos += 1;
            val |= u32::from(byte) << self.bitcnt;
            self.bitcnt += 8;
        }
        self.bitbuf = if n == 32 { 0 } else { val >> n };
        self.bitcnt -= n;
        Ok(if n == 32 { val } else { val & ((1 << n) - 1) })
    }
}

struct Huffman {
    count: [u16; MAXBITS + 1],
    symbol: Vec<u16>,
}

impl Huffman {
    /// Builds a canonical code from per-symbol code lengths. Incomplete codes
    /// are allowed (as DEFLATE permits for a single distance code).
    fn new(lengths: &[u8]) -> Result<Huffman> {
        let mut count = [0u16; MAXBITS + 1];
        for &l in lengths {
            *count
                .get_mut(usize::from(l))
                .ok_or("deflate: code length too long")? += 1;
        }
        let mut left: i32 = 1;
        for &c in &count[1..] {
            left = (left << 1) - i32::from(c);
            if left < 0 {
                return Err("deflate: over-subscribed Huffman code".into());
            }
        }
        let mut offs = [0u16; MAXBITS + 1];
        for len in 1..MAXBITS {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[usize::from(offs[usize::from(l)])] = sym as u16;
                offs[usize::from(l)] += 1;
            }
        }
        count[0] = 0;
        Ok(Huffman { count, symbol })
    }

    fn decode(&self, s: &mut Bits<'_>) -> Result<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAXBITS {
            code |= s.need(1)? as i32;
            let count = i32::from(self.count[len]);
            if code - count < first {
                return self
                    .symbol
                    .get((index + (code - first)) as usize)
                    .copied()
                    .ok_or_else(|| "deflate: bad code".into());
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err("deflate: ran out of codes".into())
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Makes room for `more` bytes in `out`.
fn reserve(out: &mut Vec<u8>, more: usize, room: Room<'_>) -> Result<()> {
    let need = out.len() + more;
    if need <= out.capacity() {
        return Ok(());
    }
    // It moves: for that, both are there. What was the old one's is for
    // the second half of the new one.
    fits(need, room)?;
    let want = need.max(out.capacity() * 2).max(64 * 1024);
    out.try_reserve_exact(want - out.len())
        .map_err(|_| "a layer does not fit in memory".into())
}

/// Longest match.
const MATCH: usize = 258;

/// Decodes one block's symbols into `out`, whose stream began at `from`.
fn codes(
    s: &mut Bits<'_>,
    out: &mut Vec<u8>,
    from: usize,
    lit: &Huffman,
    dist: &Huffman,
    room: Room<'_>,
) -> Result<()> {
    loop {
        reserve(out, MATCH, room)?;
        let sym = lit.decode(s)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            _ => {
                let i = usize::from(sym - 257);
                let len = usize::from(*LEN_BASE.get(i).ok_or("deflate: bad length")?)
                    + s.need(u32::from(LEN_EXTRA[i]))? as usize;
                let d = usize::from(dist.decode(s)?);
                let back = usize::from(*DIST_BASE.get(d).ok_or("deflate: bad distance")?)
                    + s.need(u32::from(DIST_EXTRA[d]))? as usize;
                if back > out.len() - from {
                    return Err("deflate: distance too far back".into());
                }
                let start = out.len() - back;
                for k in 0..len {
                    out.push(out[start + k]);
                }
            }
        }
    }
}

/// Inflates a raw DEFLATE stream; returns the output and the bytes consumed.
pub fn inflate(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let used = inflate_into(data, &mut out, ANY)?;
    Ok((out, used))
}

/// Inflates a stream onto the end of `out`; returns the bytes consumed.
fn inflate_into(data: &[u8], out: &mut Vec<u8>, room: Room<'_>) -> Result<usize> {
    let from = out.len();
    let mut s = Bits {
        data,
        pos: 0,
        bitbuf: 0,
        bitcnt: 0,
    };
    // A guess, if it fits.
    let _ = reserve(out, data.len().saturating_mul(3), room);
    loop {
        let last = s.need(1)?;
        match s.need(2)? {
            0 => {
                // Stored: skip to a byte boundary, then LEN, NLEN, bytes.
                s.bitbuf = 0;
                s.bitcnt = 0;
                let hdr = data
                    .get(s.pos..s.pos + 4)
                    .ok_or("deflate: short stored block")?;
                let len = usize::from(u16::from_le_bytes([hdr[0], hdr[1]]));
                let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
                if nlen != !(len as u16) {
                    return Err("deflate: stored length check failed".into());
                }
                s.pos += 4;
                let bytes = data
                    .get(s.pos..s.pos + len)
                    .ok_or("deflate: short stored data")?;
                reserve(out, len, room)?;
                out.extend_from_slice(bytes);
                s.pos += len;
            }
            1 => {
                let mut l = [0u8; 288];
                l[..144].fill(8);
                l[144..256].fill(9);
                l[256..280].fill(7);
                l[280..].fill(8);
                let lit = Huffman::new(&l)?;
                let dist = Huffman::new(&[5u8; 30])?;
                codes(&mut s, out, from, &lit, &dist, room)?;
            }
            2 => {
                let nlen = s.need(5)? as usize + 257;
                let ndist = s.need(5)? as usize + 1;
                let ncode = s.need(4)? as usize + 4;
                if nlen > 286 || ndist > 30 {
                    return Err("deflate: bad dynamic counts".into());
                }
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut cl = [0u8; 19];
                for &o in &ORDER[..ncode] {
                    cl[o] = s.need(3)? as u8;
                }
                let clh = Huffman::new(&cl)?;
                let mut lengths = vec![0u8; nlen + ndist];
                let mut i = 0;
                while i < nlen + ndist {
                    let sym = clh.decode(&mut s)?;
                    let (val, rep) = match sym {
                        0..=15 => (sym as u8, 1),
                        16 => {
                            let prev = *lengths
                                .get(i.wrapping_sub(1))
                                .filter(|_| i > 0)
                                .ok_or("deflate: repeat with no previous length")?;
                            (prev, 3 + s.need(2)? as usize)
                        }
                        17 => (0, 3 + s.need(3)? as usize),
                        _ => (0, 11 + s.need(7)? as usize),
                    };
                    if i + rep > nlen + ndist {
                        return Err("deflate: too many lengths".into());
                    }
                    lengths[i..i + rep].fill(val);
                    i += rep;
                }
                if lengths[256] == 0 {
                    return Err("deflate: no end-of-block code".into());
                }
                let lit = Huffman::new(&lengths[..nlen])?;
                let dist = Huffman::new(&lengths[nlen..])?;
                codes(&mut s, out, from, &lit, &dist, room)?;
            }
            _ => return Err("deflate: invalid block type".into()),
        }
        if last == 1 {
            return Ok(s.pos);
        }
    }
}

/// CRC-32 (IEEE), as gzip uses.
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *t = c;
    }
    let mut crc = !0u32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// Decompresses a gzip file (one member), checking its CRC and length.
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    gunzip_member(data, &mut out, ANY)?;
    Ok(out)
}

/// Decompresses every member of a multi-member gzip stream and joins them
/// (an Alpine `.apk` is a signature, a control and a data member, each a
/// tar fragment, which together make one tar stream).
pub fn gunzip_all(data: &[u8]) -> Result<Vec<u8>> {
    gunzip_within(data, ANY)
}

/// [`gunzip_all`] of something of unknown size, if it fits in `room`. (A
/// layer may have several members too: what makes it seekable.)
pub fn gunzip_within(mut data: &[u8], room: Room<'_>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let used = gunzip_member(data, &mut out, room)?;
        data = &data[used..];
    }
    Ok(out)
}

/// One gzip member at the start of `data`, onto the end of `out`; returns
/// how much of `data` it took (header, body and trailer).
fn gunzip_member(data: &[u8], out: &mut Vec<u8>, room: Room<'_>) -> Result<usize> {
    let from = out.len();
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return Err("gzip: not a deflate gzip file".into());
    }
    let flags = data[3];
    let mut pos = 10;
    if flags & 4 != 0 {
        let x = data.get(pos..pos + 2).ok_or("gzip: bad header")?;
        pos += 2 + usize::from(u16::from_le_bytes([x[0], x[1]]));
    }
    for bit in [8u8, 16] {
        // FNAME, FCOMMENT: NUL-terminated.
        if flags & bit != 0 {
            let nul = data
                .get(pos..)
                .and_then(|rest| rest.iter().position(|&b| b == 0))
                .ok_or("gzip: bad header")?;
            pos += nul + 1;
        }
    }
    if flags & 2 != 0 {
        pos += 2; // FHCRC
    }
    let body = data.get(pos..).ok_or("gzip: bad header")?;
    let used = inflate_into(body, out, room)?;
    let out = &out[from..];
    let trailer = body.get(used..used + 8).ok_or("gzip: missing trailer")?;
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    if crc != crc32(out) || isize != out.len() as u32 {
        return Err("gzip: CRC or length mismatch".into());
    }
    Ok(pos + used + 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn stored_and_fixed_blocks() {
        // A stored block holding "hi" (final, type 0).
        let stored = [0x01, 0x02, 0x00, 0xfd, 0xff, b'h', b'i'];
        assert_eq!(inflate(&stored).unwrap().0, b"hi");
        // zlib's fixed-Huffman encoding of "hello hello hello" (raw deflate).
        let fixed = [0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xc8, 0x40, 0x90, 0x00];
        assert_eq!(inflate(&fixed).unwrap().0, b"hello hello hello");
    }

    /// The text the dynamic-Huffman vectors below encode (zlib level 9).
    fn sample() -> Vec<u8> {
        (0..40)
            .flat_map(|i| {
                alloc::format!("line {i}: the quick brown fox jumps over the lazy dog\n")
                    .into_bytes()
            })
            .collect()
    }

    const DYNAMIC: [u8; 161] = [
        0x9d, 0xd5, 0x5b, 0x16, 0xc1, 0x50, 0x0c, 0x46, 0xe1, 0x77, 0xa3, 0xc8, 0x10, 0xe4, 0x0f,
        0x2d, 0x66, 0xe3, 0x72, 0x68, 0x39, 0x7a, 0x68, 0xd5, 0x6d, 0xf4, 0x16, 0x33, 0xb0, 0x9f,
        0xb3, 0xf6, 0x53, 0xbe, 0x95, 0xe4, 0xb6, 0x4b, 0x36, 0x5d, 0xd9, 0xad, 0x49, 0x76, 0x1d,
        0xdb, 0xed, 0xc9, 0x36, 0x7d, 0x79, 0x74, 0xb6, 0x2f, 0x4f, 0x3b, 0x8e, 0xe7, 0xcb, 0x60,
        0xe5, 0x9e, 0xfa, 0xdf, 0x38, 0xaf, 0xdf, 0x2f, 0xdb, 0x95, 0xc3, 0x24, 0x7f, 0x1b, 0x07,
        0x8d, 0x40, 0x13, 0xa0, 0x99, 0x81, 0x66, 0x0e, 0x9a, 0x0a, 0x34, 0x35, 0x68, 0x16, 0xa0,
        0x59, 0x92, 0x9d, 0x22, 0x08, 0x44, 0x82, 0x13, 0x0a, 0x4e, 0x2c, 0x38, 0xc1, 0xe0, 0x44,
        0x83, 0x13, 0x0e, 0x4e, 0x3c, 0x38, 0x01, 0xe1, 0x44, 0x84, 0x88, 0x08, 0xa1, 0xdb, 0x40,
        0x44, 0x88, 0x88, 0x10, 0x11, 0x21, 0x22, 0x42, 0x44, 0x84, 0x88, 0x08, 0x11, 0x11, 0x22,
        0x22, 0x82, 0x88, 0x08, 0x22, 0x22, 0xd0, 0xbb, 0x20, 0x22, 0x82, 0x88, 0x08, 0x22, 0x22,
        0x88, 0x88, 0x20, 0x22, 0x82, 0x88, 0x88, 0x3f, 0x45, 0x7c, 0x00,
    ];

    #[test]
    fn dynamic_block() {
        assert_eq!(inflate(&DYNAMIC).unwrap().0, sample());
    }

    #[test]
    fn gzip_member() {
        let mut g = alloc::vec![0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a];
        g.extend_from_slice(&DYNAMIC);
        g.extend_from_slice(&[0x64, 0x58, 0x7b, 0x18, 0x3e, 0x08, 0x00, 0x00]);
        assert_eq!(gunzip(&g).unwrap(), sample());
        // Two members back to back decompress to both payloads joined.
        let two = [g.as_slice(), g.as_slice()].concat();
        assert_eq!(gunzip_all(&two).unwrap(), [sample(), sample()].concat());
        let mut bad = g.clone();
        let n = bad.len();
        bad[n - 5] ^= 1; // corrupt the CRC
        assert!(gunzip(&bad).is_err());
        assert!(gunzip_all(&[g.as_slice(), bad.as_slice()].concat()).is_err());
        // What there is no memory for is an error before it is made.
        assert!(gunzip_within(&two, &|| 1 << 30).is_ok());
        let e = gunzip_within(&two, &|| 1 << 20).unwrap_err();
        assert!(e.0.contains("do not fit in memory"), "{e}");
        // A member does not reach back into the one before it: its first
        // match here would be 5 bytes back, with nothing written yet.
        let early = [0x03, 0x12, 0x00];
        let mut out = b"hello".to_vec();
        let e = inflate_into(&early, &mut out, ANY).unwrap_err();
        assert!(e.0.contains("too far back"), "{e}");
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        assert!(gunzip(b"not gzip at all, definitely").is_err());
        assert!(inflate(&[0x07]).is_err()); // block type 3
        // A header whose FEXTRA length runs past the end.
        let mut h = alloc::vec![0x1f, 0x8b, 0x08, 0x04, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
        h.resize(18, 0);
        assert!(gunzip(&h).is_err());
        // Every prefix of a valid member fails cleanly.
        let mut g = alloc::vec![0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0, 0, 0, b'n', 0];
        g.extend_from_slice(&DYNAMIC);
        for n in 0..g.len() {
            let _ = gunzip(&g[..n]);
        }
    }
}
