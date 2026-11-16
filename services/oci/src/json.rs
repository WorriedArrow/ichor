//! A small JSON parser (RFC 8259) for registry documents: manifests,
//! indexes, image configs and token responses. Depth is bounded.

use alloc::string::String;
use alloc::vec::Vec;

/// A JSON value. Numbers are kept as their text.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

const MAX_DEPTH: usize = 64;

impl Value {
    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.parse().ok(),
            _ => None,
        }
    }

    /// An array of strings, as `Vec<String>`.
    pub fn strings(&self) -> Option<Vec<String>> {
        self.as_array()?
            .iter()
            .map(|v| v.as_str().map(String::from))
            .collect()
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) {
        while self
            .b
            .get(self.i)
            .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Option<()> {
        self.ws();
        (self.b.get(self.i) == Some(&c)).then(|| self.i += 1)
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Option<Value> {
        (self.b.get(self.i..self.i + word.len()) == Some(word)).then(|| {
            self.i += word.len();
            v
        })
    }

    fn hex4(&mut self) -> Option<u32> {
        let s = core::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
        self.i += 4;
        u32::from_str_radix(s, 16).ok()
    }

    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let c = *self.b.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = *self.b.get(self.i)?;
                    self.i += 1;
                    out.push(match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xd800..0xdc00).contains(&cp) {
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return None;
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return None;
                                }
                                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                            }
                            char::from_u32(cp)?
                        }
                        _ => return None,
                    });
                }
                c if c < 0x20 => return None,
                _ => {
                    // Copy one UTF-8 sequence.
                    let start = self.i - 1;
                    let len = match c {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf7 => 4,
                        _ => return None,
                    };
                    let s = core::str::from_utf8(self.b.get(start..start + len)?).ok()?;
                    out.push_str(s);
                    self.i = start + len;
                }
            }
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.i;
        while self
            .b
            .get(self.i)
            .is_some_and(|c| c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E'))
        {
            self.i += 1;
        }
        let s = core::str::from_utf8(&self.b[start..self.i]).ok()?;
        (!s.is_empty()).then(|| Value::Number(String::from(s)))
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        match *self.b.get(self.i)? {
            b'{' => {
                self.i += 1;
                let mut m = Vec::new();
                if self.eat(b'}').is_some() {
                    return Some(Value::Object(m));
                }
                loop {
                    let k = self.string()?;
                    self.eat(b':')?;
                    let v = self.value(depth + 1)?;
                    m.push((k, v));
                    if self.eat(b',').is_none() {
                        self.eat(b'}')?;
                        return Some(Value::Object(m));
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                if self.eat(b']').is_some() {
                    return Some(Value::Array(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    if self.eat(b',').is_none() {
                        self.eat(b']')?;
                        return Some(Value::Array(a));
                    }
                }
            }
            b'"' => self.string().map(Value::String),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            _ => self.number(),
        }
    }
}

/// Parses a whole document.
pub fn parse(b: &[u8]) -> Option<Value> {
    let mut p = P { b, i: 0 };
    let v = p.value(0)?;
    p.ws();
    (p.i == b.len()).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents() {
        let v = parse(br#" {"a": [1, -2.5e3, true, null], "b": {"c": "d\u00e9\n\ud83d\ude00"}} "#)
            .unwrap();
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 4);
        assert_eq!(v.get("a").unwrap().as_array().unwrap()[0].as_u64(), Some(1));
        assert_eq!(
            v.get("b").unwrap().get("c").unwrap().as_str(),
            Some("d\u{e9}\n\u{1f600}")
        );
        assert_eq!(parse(b"[]"), Some(Value::Array(Vec::new())));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            &b"{"[..],
            b"[1,]",
            b"{\"a\" 1}",
            b"\"\x01\"",
            b"[1] x",
            b"\"\\ud800\"",
            b"tru",
        ] {
            assert!(parse(bad).is_none(), "{:?}", core::str::from_utf8(bad));
        }
        let deep = [b'['; 100];
        assert!(parse(&deep).is_none());
    }
}
