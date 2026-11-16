//! Protobuf's wire format: varints and length-delimited fields, which are
//! all the control API uses. Unknown fields (and the fixed-width types)
//! are skipped when reading, as protobuf requires.

use alloc::string::String;
use alloc::vec::Vec;

/// A malformed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error;

/// Builds a message.
#[derive(Clone, Debug, Default)]
pub struct Writer(pub Vec<u8>);

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

impl Writer {
    pub fn new() -> Writer {
        Writer(Vec::new())
    }

    /// A varint field (uint32/64, bool, enum); zero is left out, as proto3
    /// does.
    pub fn varint(&mut self, field: u32, v: u64) -> &mut Writer {
        if v != 0 {
            put_varint(&mut self.0, u64::from(field) << 3);
            put_varint(&mut self.0, v);
        }
        self
    }

    /// A varint field written even when zero (a `oneof` member).
    pub fn varint_always(&mut self, field: u32, v: u64) -> &mut Writer {
        put_varint(&mut self.0, u64::from(field) << 3);
        put_varint(&mut self.0, v);
        self
    }

    /// A bytes, string or embedded-message field.
    pub fn bytes(&mut self, field: u32, b: &[u8]) -> &mut Writer {
        put_varint(&mut self.0, (u64::from(field) << 3) | 2);
        put_varint(&mut self.0, b.len() as u64);
        self.0.extend_from_slice(b);
        self
    }

    /// A string field; empty is left out (proto3), unless `repeated`.
    pub fn string(&mut self, field: u32, s: &str) -> &mut Writer {
        if !s.is_empty() {
            self.bytes(field, s.as_bytes());
        }
        self
    }

    pub fn strings(&mut self, field: u32, v: &[String]) -> &mut Writer {
        for s in v {
            self.bytes(field, s.as_bytes());
        }
        self
    }

    pub fn finish(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

/// A field's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// A fixed64/fixed32 field (unused by the API, skipped).
    Fixed,
}

impl<'a> Value<'a> {
    pub fn as_u64(self) -> Result<u64, Error> {
        match self {
            Value::Varint(v) => Ok(v),
            _ => Err(Error),
        }
    }

    pub fn as_bytes(self) -> Result<&'a [u8], Error> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(Error),
        }
    }

    pub fn as_string(self) -> Result<String, Error> {
        core::str::from_utf8(self.as_bytes()?)
            .map(String::from)
            .map_err(|_| Error)
    }
}

/// Reads a message's fields in order.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, at: 0 }
    }

    fn varint(&mut self) -> Result<u64, Error> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.b.get(self.at).ok_or(Error)?;
            self.at += 1;
            v |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error)?;
        let s = self.b.get(self.at..end).ok_or(Error)?;
        self.at = end;
        Ok(s)
    }

    /// The next field, or `None` at the end.
    pub fn field(&mut self) -> Result<Option<(u32, Value<'a>)>, Error> {
        if self.at == self.b.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = u32::try_from(key >> 3).map_err(|_| Error)?;
        if field == 0 {
            return Err(Error);
        }
        let v = match key & 7 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Fixed
            }
            2 => {
                let n = usize::try_from(self.varint()?).map_err(|_| Error)?;
                Value::Bytes(self.take(n)?)
            }
            5 => {
                self.take(4)?;
                Value::Fixed
            }
            _ => return Err(Error),
        };
        Ok(Some((field, v)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_encodings() {
        // The protobuf documentation's examples: field 1 = 150, and
        // field 2 = "testing".
        assert_eq!(Writer::new().varint(1, 150).finish(), [0x08, 0x96, 0x01]);
        assert_eq!(
            Writer::new().string(2, "testing").finish(),
            [0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g']
        );
    }

    #[test]
    fn fields_round_trip_and_unknown_ones_are_skipped() {
        let mut w = Writer::new();
        w.varint(1, u64::MAX).string(2, "x").varint(7, 3);
        let mut b = w.finish();
        // A fixed32 field 9 and a fixed64 field 10.
        b.extend_from_slice(&[0x4d, 1, 2, 3, 4, 0x51, 1, 2, 3, 4, 5, 6, 7, 8]);
        let mut r = Reader::new(&b);
        assert_eq!(r.field(), Ok(Some((1, Value::Varint(u64::MAX)))));
        assert_eq!(r.field(), Ok(Some((2, Value::Bytes(b"x")))));
        assert_eq!(r.field(), Ok(Some((7, Value::Varint(3)))));
        assert_eq!(r.field(), Ok(Some((9, Value::Fixed))));
        assert_eq!(r.field(), Ok(Some((10, Value::Fixed))));
        assert_eq!(r.field(), Ok(None));
    }

    #[test]
    fn truncation_is_an_error() {
        assert_eq!(Reader::new(&[0x12, 0x05, b'a']).field(), Err(Error));
        assert_eq!(Reader::new(&[0x08, 0x96]).field(), Err(Error));
        assert_eq!(Reader::new(&[0x0b]).field(), Err(Error)); // group
    }
}
