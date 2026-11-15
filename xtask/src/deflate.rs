//! A small DEFLATE (RFC 1951) encoder and gzip (RFC 1952) / GNU tar
//! writers, for the archives clouds import disk images from (GCP: a
//! `disk.raw` in a gzip'd GNU tar).
//!
//! The encoder uses one fixed-Huffman block and finds only runs of a
//! repeated byte (a match at distance 1): a disk image is mostly zeros,
//! which this squeezes about 160 to 1 (a 1 GiB disk to ~7 MB), and anything
//! else is stored as literals. `inflate.rs` decodes it in the tests.

use crate::inflate::crc32;

/// Writes bits least-significant first, as DEFLATE packs them.
#[derive(Debug, Default)]
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    fn put(&mut self, value: u32, count: u32) {
        self.acc |= u64::from(value) << self.n;
        self.n += count;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    /// A Huffman code: written most-significant bit first.
    fn code(&mut self, code: u32, len: u32) {
        let mut rev = 0;
        for i in 0..len {
            rev |= ((code >> i) & 1) << (len - 1 - i);
        }
        self.put(rev, len);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// The fixed literal/length code for `sym` (0..=287).
fn fixed(bits: &mut Bits, sym: u32) {
    match sym {
        0..=143 => bits.code(0x30 + sym, 8),
        144..=255 => bits.code(0x190 + sym - 144, 9),
        256..=279 => bits.code(sym - 256, 7),
        _ => bits.code(0xC0 + sym - 280, 8),
    }
}

/// Length codes 257..=285: base length and extra bits.
const LENGTHS: [(u32, u32); 29] = [
    (3, 0),
    (4, 0),
    (5, 0),
    (6, 0),
    (7, 0),
    (8, 0),
    (9, 0),
    (10, 0),
    (11, 1),
    (13, 1),
    (15, 1),
    (17, 1),
    (19, 2),
    (23, 2),
    (27, 2),
    (31, 2),
    (35, 3),
    (43, 3),
    (51, 3),
    (59, 3),
    (67, 4),
    (83, 4),
    (99, 4),
    (115, 4),
    (131, 5),
    (163, 5),
    (195, 5),
    (227, 5),
    (258, 0),
];

/// A match of `len` (3..=258) bytes at distance 1.
fn run(bits: &mut Bits, len: u32) {
    let i = LENGTHS
        .iter()
        .rposition(|&(base, _)| base <= len)
        .unwrap_or(0);
    let (base, extra) = LENGTHS[i];
    fixed(bits, 257 + i as u32);
    bits.put(len - base, extra);
    bits.code(0, 5); // distance code 0: distance 1
}

/// Compresses `data` into a raw DEFLATE stream.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut bits = Bits::default();
    bits.put(1, 1); // BFINAL
    bits.put(1, 2); // BTYPE = fixed Huffman
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        fixed(&mut bits, u32::from(b));
        i += 1;
        // The bytes after it that repeat it, as matches at distance 1.
        let mut same = data[i..].iter().take_while(|&&x| x == b).count();
        while same >= 3 {
            let len = same.min(258);
            run(&mut bits, len as u32);
            i += len;
            same -= len;
        }
    }
    fixed(&mut bits, 256); // end of block
    bits.finish()
}

/// `data` as a gzip file.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend_from_slice(&deflate(data));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

/// A GNU tar archive holding one regular file `name` (mode 0644).
pub fn tar(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[156] = b'0';
    h[257..265].copy_from_slice(b"ustar  \0"); // GNU magic and version
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(512) + 1024, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inflate::{gunzip, inflate};

    #[test]
    fn round_trips_through_the_decoder() {
        let mut data = vec![0u8; 100_000];
        data.extend_from_slice(b"hello, disk image");
        data.extend(std::iter::repeat_n(0xAA, 1000));
        data.extend((0..5000u32).map(|i| (i * 7 % 251) as u8));
        data.extend(vec![0u8; 3]);
        for d in [&data[..], &[][..], &[1, 1, 1, 1, 2][..], &[9][..]] {
            assert_eq!(inflate(&deflate(d)).unwrap().0, d);
            assert_eq!(gunzip(&gzip(d)).unwrap(), d);
        }
        // Zeros compress about 160 to 1 (13 bits per 258-byte match).
        assert!(deflate(&vec![0u8; 1 << 20]).len() < 7000);
    }

    #[test]
    fn tar_has_one_member_and_the_end_blocks() {
        let t = tar("disk.raw", b"abc");
        assert_eq!(t.len(), 512 + 512 + 1024);
        assert_eq!(&t[..8], b"disk.raw");
        assert_eq!(&t[257..263], b"ustar ");
        assert_eq!(&t[512..515], b"abc");
        // The checksum covers the header with its own field as spaces.
        let mut h = t[..512].to_vec();
        let stored = u32::from_str_radix(std::str::from_utf8(&h[148..154]).unwrap(), 8).unwrap();
        h[148..156].fill(b' ');
        assert_eq!(stored, h.iter().map(|&b| u32::from(b)).sum::<u32>());
        assert!(t[1024..].iter().all(|&b| b == 0));
    }
}
