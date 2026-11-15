//! Kernel command line parsing.
//!
//! The command line is a sequence of whitespace-separated options. Each option
//! is either a bare flag (`quiet`) or a `key=value` pair (`console=ttyS0`).
//! A value may be wrapped in double quotes to contain whitespace
//! (`motd="hello world"`). There are no escapes; a quote cannot appear inside a
//! quoted value. Lines starting with `#` are comments, so a config file can be
//! annotated.
//!
//! Parsing never allocates and never fails: malformed input degrades to options
//! with odd keys rather than an error, because the command line is read before
//! there is anywhere useful to report errors.

#![no_std]
#![forbid(unsafe_code)]

/// One option on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opt<'a> {
    /// The part before `=`, or the whole option for a bare flag.
    pub key: &'a str,
    /// The part after `=` with surrounding quotes removed, if present.
    pub value: Option<&'a str>,
}

/// A parsed view over a command line string.
#[derive(Clone, Copy, Debug)]
pub struct Cmdline<'a> {
    raw: &'a str,
}

impl<'a> Cmdline<'a> {
    /// Wraps a command line. Parsing happens lazily during iteration.
    pub const fn new(raw: &'a str) -> Self {
        Self { raw }
    }

    /// The raw text this view was built from.
    pub const fn as_str(&self) -> &'a str {
        self.raw
    }

    /// Iterates over every option in order.
    pub fn iter(&self) -> Iter<'a> {
        Iter { rest: self.raw }
    }

    /// Returns the value of the last `key=value` option with this key.
    /// Later options override earlier ones, matching Linux.
    pub fn get(&self, key: &str) -> Option<&'a str> {
        self.iter()
            .filter(|o| o.key == key)
            .filter_map(|o| o.value)
            .last()
    }

    /// Returns true if `key` appears as a bare flag, or as `key=1`, `key=true`,
    /// `key=yes`, or `key=on`. A later `key=0`/`false`/`no`/`off` turns it off.
    pub fn flag(&self, key: &str) -> bool {
        let mut on = false;
        for opt in self.iter().filter(|o| o.key == key) {
            on = match opt.value {
                None => true,
                Some(v) => matches!(v, "1" | "true" | "yes" | "on"),
            };
        }
        on
    }
}

impl<'a> IntoIterator for &Cmdline<'a> {
    type Item = Opt<'a>;
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// Iterator over options. See [`Cmdline::iter`].
#[derive(Clone, Debug)]
pub struct Iter<'a> {
    rest: &'a str,
}

impl<'a> Iterator for Iter<'a> {
    type Item = Opt<'a>;

    fn next(&mut self) -> Option<Opt<'a>> {
        loop {
            self.rest = self.rest.trim_start();
            if self.rest.is_empty() {
                return None;
            }
            if let Some(after) = self.rest.strip_prefix('#') {
                // Comment to end of line.
                self.rest = after.find('\n').map_or("", |i| &after[i + 1..]);
                continue;
            }
            return Some(self.take_opt());
        }
    }
}

impl<'a> Iter<'a> {
    fn take_opt(&mut self) -> Opt<'a> {
        let s = self.rest;
        let key_end = s
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(s.len());
        let key = &s[..key_end];
        let after_key = &s[key_end..];

        let Some(val_start) = after_key.strip_prefix('=') else {
            self.rest = after_key;
            return Opt { key, value: None };
        };

        if let Some(quoted) = val_start.strip_prefix('"') {
            // Unterminated quote: the value runs to the end of input.
            let end = quoted.find('"').unwrap_or(quoted.len());
            let value = &quoted[..end];
            self.rest = quoted.get(end + 1..).unwrap_or("");
            return Opt {
                key,
                value: Some(value),
            };
        }

        let end = val_start
            .find(char::is_whitespace)
            .unwrap_or(val_start.len());
        self.rest = &val_start[end..];
        Opt {
            key,
            value: Some(&val_start[..end]),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn opts(s: &str) -> Vec<(&str, Option<&str>)> {
        Cmdline::new(s).iter().map(|o| (o.key, o.value)).collect()
    }

    #[test]
    fn empty() {
        assert!(opts("").is_empty());
        assert!(opts("   \n\t ").is_empty());
    }

    #[test]
    fn flags_and_values() {
        assert_eq!(
            opts("quiet console=ttyS0  smp=4\n"),
            [
                ("quiet", None),
                ("console", Some("ttyS0")),
                ("smp", Some("4"))
            ]
        );
    }

    #[test]
    fn quoted_values() {
        assert_eq!(
            opts(r#"motd="hello world" x=1"#),
            [("motd", Some("hello world")), ("x", Some("1"))]
        );
        assert_eq!(opts(r#"a="unterminated"#), [("a", Some("unterminated"))]);
        assert_eq!(opts(r#"a="""#), [("a", Some(""))]);
    }

    #[test]
    fn empty_value_and_key() {
        assert_eq!(opts("a= b"), [("a", Some("")), ("b", None)]);
        assert_eq!(opts("=x"), [("", Some("x"))]);
    }

    #[test]
    fn comments() {
        assert_eq!(
            opts("# a comment\nfoo # trailing\nbar=2"),
            [("foo", None), ("bar", Some("2"))]
        );
        assert!(opts("# only a comment").is_empty());
    }

    #[test]
    fn get_last_wins() {
        let c = Cmdline::new("smp=2 smp=8 other");
        assert_eq!(c.get("smp"), Some("8"));
        assert_eq!(c.get("other"), None);
        assert_eq!(c.get("missing"), None);
    }

    #[test]
    fn flag_semantics() {
        let c = Cmdline::new("a b=1 c=off d=yes d=0 e=0 e");
        assert!(c.flag("a"));
        assert!(c.flag("b"));
        assert!(!c.flag("c"));
        assert!(!c.flag("d"));
        assert!(c.flag("e"));
        assert!(!c.flag("missing"));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Cheap exhaustive-ish check over short strings from a small alphabet
        // that exercises every branch of the tokenizer.
        let alphabet = ['a', '=', '"', ' ', '#', '\n', 'é'];
        let mut buf = std::string::String::new();
        fn rec(buf: &mut std::string::String, alphabet: &[char], depth: usize) {
            let _ = Cmdline::new(buf).iter().count();
            if depth == 0 {
                return;
            }
            for &c in alphabet {
                buf.push(c);
                rec(buf, alphabet, depth - 1);
                buf.pop();
            }
        }
        rec(&mut buf, &alphabet, 5);
    }
}
