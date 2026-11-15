//! A DER reader (X.690), strict about lengths: definite, at most four
//! length bytes, contained in the input.

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// One encoded value.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The contents.
    pub body: &'a [u8],
    /// Tag, length and contents.
    pub raw: &'a [u8],
}

/// Reads values one after another.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b }
    }

    pub fn is_empty(&self) -> bool {
        self.b.is_empty()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.b.first().copied()
    }

    /// The next value.
    pub fn read(&mut self) -> Option<Tlv<'a>> {
        let b = self.b;
        let tag = *b.first()?;
        if tag & 0x1f == 0x1f {
            return None; // multi-byte tags do not occur in X.509
        }
        let first = *b.get(1)?;
        let (len, head) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for &byte in b.get(2..2 + n)? {
                len = (len << 8) | usize::from(byte);
            }
            if len < 0x80 {
                return None; // not minimal
            }
            (len, 2 + n)
        };
        let end = head.checked_add(len)?;
        let raw = b.get(..end)?;
        self.b = &b[end..];
        Some(Tlv {
            tag,
            body: &raw[head..],
            raw,
        })
    }

    /// The next value, which must have `tag`; its contents.
    pub fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let t = self.read()?;
        (t.tag == tag).then_some(t.body)
    }

    /// The next value if it has `tag` (its contents), else nothing read.
    pub fn optional(&mut self, tag: u8) -> Option<&'a [u8]> {
        if self.peek_tag() == Some(tag) {
            self.expect(tag)
        } else {
            None
        }
    }

    /// The rest of the input.
    pub fn rest(&self) -> &'a [u8] {
        self.b
    }
}

/// A BIT STRING's bits as bytes (only whole bytes are accepted).
pub fn bit_string(body: &[u8]) -> Option<&[u8]> {
    match body.split_first() {
        Some((0, bits)) => Some(bits),
        _ => None,
    }
}

/// A positive INTEGER's magnitude, without the sign byte.
pub fn unsigned(body: &[u8]) -> Option<&[u8]> {
    match body {
        [] => None,
        [b, ..] if b & 0x80 != 0 => None,
        [0, rest @ ..] if !rest.is_empty() => Some(rest),
        _ => Some(body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        let mut long = alloc::vec![0x04, 0x81, 0x80];
        long.extend([7u8; 0x80]);
        let t = Reader::new(&long).read().unwrap();
        assert_eq!((t.tag, t.body.len()), (OCTET_STRING, 0x80));
        assert!(
            Reader::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5])
                .read()
                .is_none(),
            "non-minimal"
        );
        assert!(Reader::new(&[0x04, 0x80]).read().is_none(), "indefinite");
        assert!(
            Reader::new(&[0x04, 0x05, 1, 2]).read().is_none(),
            "past the end"
        );
        let mut r = Reader::new(&[0x02, 0x01, 0x05, 0x05, 0x00]);
        assert_eq!(r.expect(INTEGER), Some(&[5u8][..]));
        assert_eq!(r.optional(BOOLEAN), None);
        assert_eq!(r.expect(NULL), Some(&[][..]));
        assert!(r.is_empty());
    }

    #[test]
    fn integers_and_bits() {
        assert_eq!(unsigned(&[0x00, 0x80]), Some(&[0x80u8][..]));
        assert_eq!(unsigned(&[0x80]), None);
        assert_eq!(bit_string(&[0, 1, 2]), Some(&[1u8, 2][..]));
        assert_eq!(bit_string(&[3, 1, 2]), None);
    }
}
