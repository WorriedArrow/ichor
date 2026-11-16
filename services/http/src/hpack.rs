//! HPACK (RFC 7541), header compression for HTTP/2.
//!
//! The [`Decoder`] takes everything a peer may send: indexed fields,
//! literals with and without indexing, dynamic table size updates and
//! Huffman-coded strings. The [`Encoder`] sends every field as a literal
//! without indexing and without Huffman coding, which any decoder accepts
//! and which keeps the peer's dynamic table out of our state.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

/// A header field.
pub type Field = (String, String);

/// What was wrong with a header block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// It ended inside a representation.
    Truncated,
    /// An index past both tables.
    BadIndex,
    /// An integer too large, or bad Huffman padding.
    Malformed,
    /// A table size update above the limit we set.
    TableSize,
    /// The decoded fields would exceed the header list limit.
    TooLarge,
}

/// RFC 7541 Appendix A.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Huffman code lengths of symbols 0-255 (RFC 7541 Appendix B); the end
/// of string (symbol 256) is 30 bits. The code is canonical: codes of one
/// length are consecutive, in symbol order, after the shorter ones.
const HUFFMAN_LENGTHS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];
const EOS: u16 = 256;
const EOS_LEN: usize = 30;

/// The canonical code, arranged for decoding: for each length, the first
/// code and where its symbols start in `symbols`.
struct Huffman {
    first: [u32; 31],
    count: [u32; 31],
    offset: [u32; 31],
    symbols: [u16; 257],
}

impl Huffman {
    fn new() -> Huffman {
        let len = |s: usize| {
            if s == EOS as usize {
                EOS_LEN
            } else {
                HUFFMAN_LENGTHS[s] as usize
            }
        };
        let mut h = Huffman {
            first: [0; 31],
            count: [0; 31],
            offset: [0; 31],
            symbols: [0; 257],
        };
        for s in 0..257 {
            h.count[len(s)] += 1;
        }
        let (mut code, mut at) = (0u32, 0u32);
        for l in 1..=EOS_LEN {
            code <<= 1;
            h.first[l] = code;
            h.offset[l] = at;
            code += h.count[l];
            at += h.count[l];
        }
        let mut fill = h.offset;
        for s in 0..257u16 {
            let l = len(s as usize);
            h.symbols[fill[l] as usize] = s;
            fill[l] += 1;
        }
        h
    }

    /// The code of symbol `s` and its length (encoding, in tests).
    #[cfg(test)]
    fn code(&self, s: u16) -> (u32, usize) {
        for l in 1..=EOS_LEN {
            for i in 0..self.count[l] {
                if self.symbols[(self.offset[l] + i) as usize] == s {
                    return (self.first[l] + i, l);
                }
            }
        }
        (0, 0)
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(data.len() * 8 / 5);
        let (mut code, mut len) = (0u32, 0usize);
        // Bits since the last whole symbol, all ones so far (padding).
        let mut ones = true;
        for &byte in data {
            for bit in (0..8).rev() {
                let b = u32::from(byte >> bit) & 1;
                code = (code << 1) | b;
                len += 1;
                ones &= b == 1;
                let i = code.wrapping_sub(self.first[len]);
                if i < self.count[len] {
                    let s = self.symbols[(self.offset[len] + i) as usize];
                    if s == EOS {
                        return Err(Error::Malformed);
                    }
                    out.push(s as u8);
                    (code, len, ones) = (0, 0, true);
                } else if len >= EOS_LEN {
                    return Err(Error::Malformed);
                }
            }
        }
        // Padding: fewer than 8 bits, a prefix of EOS (all ones).
        if len > 7 || !ones {
            return Err(Error::Malformed);
        }
        Ok(out)
    }
}

/// Decodes an integer with an `n`-bit prefix from `b` at `*at`.
fn integer(b: &[u8], at: &mut usize, n: u32) -> Result<usize, Error> {
    let max = (1usize << n) - 1;
    let first = usize::from(*b.get(*at).ok_or(Error::Truncated)?) & max;
    *at += 1;
    if first < max {
        return Ok(first);
    }
    let mut v = max;
    let mut shift = 0;
    loop {
        let byte = *b.get(*at).ok_or(Error::Truncated)?;
        *at += 1;
        if shift > 28 {
            return Err(Error::Malformed);
        }
        v += usize::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
}

/// Encodes `v` with an `n`-bit prefix whose high bits are `flags`.
fn put_integer(out: &mut Vec<u8>, flags: u8, n: u32, mut v: usize) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// The dynamic table: newest first.
#[derive(Debug, Default)]
struct Table {
    entries: VecDeque<Field>,
    size: usize,
    max: usize,
}

fn entry_size(f: &Field) -> usize {
    f.0.len() + f.1.len() + 32
}

impl Table {
    fn evict(&mut self) {
        while self.size > self.max {
            let Some(e) = self.entries.pop_back() else {
                break;
            };
            self.size -= entry_size(&e);
        }
    }

    fn insert(&mut self, f: Field) {
        let size = entry_size(&f);
        self.entries.push_front(f);
        self.size += size;
        // An entry larger than the table empties it (RFC 7541 §4.4).
        self.evict();
    }
}

/// Decodes header blocks from one peer (state persists across blocks).
pub struct Decoder {
    table: Table,
    /// The most the peer may set the table to (our SETTINGS_HEADER_TABLE_SIZE).
    limit: usize,
    /// Most bytes of decoded fields per block (name + value + 32 each).
    max_list: usize,
    huffman: Huffman,
}

impl core::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Decoder")
            .field("table_size", &self.table.size)
            .field("limit", &self.limit)
            .finish()
    }
}

impl Decoder {
    /// A decoder with the protocol's default 4096-byte table.
    pub fn new(max_list: usize) -> Decoder {
        Decoder {
            table: Table {
                max: 4096,
                ..Table::default()
            },
            limit: 4096,
            max_list,
            huffman: Huffman::new(),
        }
    }

    /// The dynamic table's current size (tests).
    pub fn table_size(&self) -> usize {
        self.table.size
    }

    fn field(&self, index: usize) -> Result<Field, Error> {
        match index {
            0 => Err(Error::BadIndex),
            1..=61 => {
                let (n, v) = STATIC[index - 1];
                Ok((n.into(), v.into()))
            }
            _ => self
                .table
                .entries
                .get(index - 62)
                .cloned()
                .ok_or(Error::BadIndex),
        }
    }

    fn string(&self, b: &[u8], at: &mut usize) -> Result<String, Error> {
        let huffman = b.get(*at).ok_or(Error::Truncated)? & 0x80 != 0;
        let len = integer(b, at, 7)?;
        let raw = b.get(*at..*at + len).ok_or(Error::Truncated)?;
        *at += len;
        let bytes = if huffman {
            self.huffman.decode(raw)?
        } else {
            raw.to_vec()
        };
        // Header values are octets; ours are all ASCII, others are kept
        // lossily.
        Ok(String::from_utf8(bytes)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
    }

    /// Decodes one complete header block.
    pub fn decode(&mut self, b: &[u8]) -> Result<Vec<Field>, Error> {
        let mut out = Vec::new();
        let mut list = 0;
        let mut at = 0;
        while at < b.len() {
            let first = b[at];
            let field = if first & 0x80 != 0 {
                let i = integer(b, &mut at, 7)?;
                self.field(i)?
            } else if first & 0xe0 == 0x20 {
                let size = integer(b, &mut at, 5)?;
                if size > self.limit {
                    return Err(Error::TableSize);
                }
                self.table.max = size;
                self.table.evict();
                continue;
            } else {
                let (prefix, index) = if first & 0xc0 == 0x40 {
                    (6, true)
                } else {
                    (4, false)
                };
                let i = integer(b, &mut at, prefix)?;
                let name = if i == 0 {
                    self.string(b, &mut at)?
                } else {
                    self.field(i)?.0
                };
                let value = self.string(b, &mut at)?;
                let f = (name, value);
                if index {
                    self.table.insert(f.clone());
                }
                f
            };
            list += entry_size(&field);
            if list > self.max_list {
                return Err(Error::TooLarge);
            }
            out.push(field);
        }
        Ok(out)
    }
}

/// Encodes header blocks: literals without indexing (a static name index
/// where one matches), no Huffman.
#[derive(Debug, Default)]
pub struct Encoder;

impl Encoder {
    pub fn new() -> Encoder {
        Encoder
    }

    pub fn encode(&mut self, fields: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(name, value) in fields {
            // A fully matching static entry is one byte.
            if let Some(i) = STATIC.iter().position(|&(n, v)| n == name && v == value) {
                put_integer(&mut out, 0x80, 7, i + 1);
                continue;
            }
            match STATIC.iter().position(|&(n, _)| n == name) {
                Some(i) => put_integer(&mut out, 0x00, 4, i + 1),
                None => {
                    out.push(0x00);
                    put_integer(&mut out, 0x00, 7, name.len());
                    out.extend_from_slice(name.as_bytes());
                }
            }
            put_integer(&mut out, 0x00, 7, value.len());
            out.extend_from_slice(value.as_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fields(v: &[Field]) -> Vec<(&str, &str)> {
        v.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
    }

    #[test]
    fn canonical_codes_match_the_rfc_table() {
        let h = Huffman::new();
        // Spot checks against RFC 7541 Appendix B.
        assert_eq!(h.code(b'0' as u16), (0x0, 5));
        assert_eq!(h.code(b't' as u16), (0x9, 5));
        assert_eq!(h.code(b' ' as u16), (0x14, 6));
        assert_eq!(h.code(b':' as u16), (0x5c, 7));
        assert_eq!(h.code(b'&' as u16), (0xf8, 8));
        assert_eq!(h.code(b'"' as u16), (0x3f9, 10));
        assert_eq!(h.code(0), (0x1ff8, 13));
        assert_eq!(h.code(255), (0x3ffffee, 26));
        assert_eq!(h.code(EOS), (0x3fff_ffff, 30));
    }

    #[test]
    fn integers_round_trip() {
        // RFC 7541 C.1: 10 and 1337 with a 5-bit prefix, 42 with 8.
        let mut out = Vec::new();
        put_integer(&mut out, 0, 5, 1337);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        let mut at = 0;
        assert_eq!(integer(&out, &mut at, 5), Ok(1337));
        let mut at = 0;
        assert_eq!(integer(&[0x0a], &mut at, 5), Ok(10));
        let mut at = 0;
        assert_eq!(integer(&[0x2a], &mut at, 8), Ok(42));
    }

    #[test]
    fn rfc_c2_field_representations() {
        let mut d = Decoder::new(1 << 16);
        let f = d
            .decode(&hex(
                "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
            ))
            .unwrap();
        assert_eq!(fields(&f), [("custom-key", "custom-header")]);
        assert_eq!(d.table_size(), 55);
        let mut d = Decoder::new(1 << 16);
        let f = d
            .decode(&hex("040c 2f73 616d 706c 652f 7061 7468"))
            .unwrap();
        assert_eq!(fields(&f), [(":path", "/sample/path")]);
        assert_eq!(d.table_size(), 0);
        let f = d
            .decode(&hex("1008 7061 7373 776f 7264 0673 6563 7265 74"))
            .unwrap();
        assert_eq!(fields(&f), [("password", "secret")]);
        assert_eq!(fields(&d.decode(&[0x82]).unwrap()), [(":method", "GET")]);
    }

    /// RFC 7541 C.3 (plain) and C.4 (Huffman): the same three requests.
    fn requests(blocks: [&str; 3]) {
        let mut d = Decoder::new(1 << 16);
        let f = d.decode(&hex(blocks[0])).unwrap();
        assert_eq!(
            fields(&f),
            [
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com")
            ]
        );
        assert_eq!(d.table_size(), 57);
        let f = d.decode(&hex(blocks[1])).unwrap();
        assert_eq!(
            f.last().unwrap(),
            &("cache-control".into(), "no-cache".into())
        );
        assert_eq!(f[3].1, "www.example.com");
        assert_eq!(d.table_size(), 110);
        let f = d.decode(&hex(blocks[2])).unwrap();
        assert_eq!(
            fields(&f),
            [
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value")
            ]
        );
        assert_eq!(d.table_size(), 164);
    }

    #[test]
    fn rfc_c3_requests() {
        requests([
            "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
            "8286 84be 5808 6e6f 2d63 6163 6865",
            "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
        ]);
    }

    #[test]
    fn rfc_c4_huffman_requests() {
        requests([
            "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
            "8286 84be 5886 a8eb 1064 9cbf",
            "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
        ]);
    }

    #[test]
    fn table_size_updates_and_eviction() {
        let mut d = Decoder::new(1 << 16);
        d.decode(&hex(
            "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
        ))
        .unwrap();
        // Size 0 empties the table; index 62 is gone.
        d.decode(&[0x20]).unwrap();
        assert_eq!(d.table_size(), 0);
        assert_eq!(d.decode(&[0xbe]), Err(Error::BadIndex));
        // Up to our limit (4096) is fine; above it is an error.
        assert_eq!(d.decode(&hex("3fe1 1f")), Ok(alloc::vec![]));
        assert_eq!(d.decode(&hex("3fe2 1f")), Err(Error::TableSize));
    }

    #[test]
    fn bad_huffman_padding_is_refused() {
        let h = Huffman::new();
        assert_eq!(
            h.decode(&hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff")).unwrap(),
            b"www.example.com"
        );
        // 'a' (00011) padded with zeros instead of ones.
        assert_eq!(h.decode(&[0x18]), Err(Error::Malformed));
        // A whole byte of padding.
        assert_eq!(h.decode(&[0x1f, 0xff]), Err(Error::Malformed));
    }

    #[test]
    fn encoder_output_decodes() {
        let mut e = Encoder::new();
        let block = e.encode(&[
            (":method", "POST"),
            (":path", "/ichor.v1.Control/PullImage"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ]);
        assert_eq!(block[0], 0x83);
        let mut d = Decoder::new(1 << 16);
        assert_eq!(
            fields(&d.decode(&block).unwrap()),
            [
                (":method", "POST"),
                (":path", "/ichor.v1.Control/PullImage"),
                ("content-type", "application/grpc"),
                ("te", "trailers")
            ]
        );
        assert_eq!(d.table_size(), 0);
    }

    #[test]
    fn list_limit_applies() {
        let mut e = Encoder::new();
        let big = "x".repeat(200);
        let block = e.encode(&[("a", &big)]);
        assert_eq!(Decoder::new(100).decode(&block), Err(Error::TooLarge));
    }
}
