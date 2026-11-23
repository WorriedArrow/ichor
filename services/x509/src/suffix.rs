//! The Public Suffix List (publicsuffix.org): which names are public
//! suffixes, under which anyone may register a name (`com`, `co.uk`,
//! `s3.amazonaws.com`). A wildcard certificate for a whole public suffix
//! is refused (CABF BR 3.2.2.6: no CA may issue one).
//!
//! The list is data, not code (MPL-2.0, fetched pinned by xtask and
//! carried in the boot volume's CA bundle as a `PUBLIC SUFFIX LIST`
//! block). Its rules are UTF-8; certificates carry A-labels, so rules are
//! kept punycode-encoded (RFC 3492).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// The rules of the list, lowercase A-labels: plain, wildcard (`*.x` kept
/// as `x`) and exception (`!x` kept as `x`) rules.
#[derive(Clone, Debug, Default)]
pub struct PublicSuffixes {
    plain: BTreeSet<String>,
    wildcard: BTreeSet<String>,
    exception: BTreeSet<String>,
}

impl PublicSuffixes {
    /// The rules in the list's text format: one per line, the first word
    /// of it; `//` comments and blank lines skipped. A rule that cannot be
    /// encoded is skipped.
    pub fn parse(text: &str) -> PublicSuffixes {
        let mut out = PublicSuffixes::default();
        for line in text.lines() {
            let Some(rule) = line.split_whitespace().next() else {
                continue;
            };
            if rule.starts_with("//") {
                continue;
            }
            let (set, rule) = if let Some(r) = rule.strip_prefix('!') {
                (&mut out.exception, r)
            } else if let Some(r) = rule.strip_prefix("*.") {
                (&mut out.wildcard, r)
            } else {
                (&mut out.plain, rule)
            };
            if let Some(name) = to_ascii(rule) {
                set.insert(name);
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.plain.len() + self.wildcard.len() + self.exception.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `name` (A-labels) is itself a public suffix: the list's
    /// prevailing rule for it covers all its labels. With no rule at all,
    /// the default rule `*` makes a single label one.
    pub fn is_public_suffix(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return true;
        }
        let suffixes = || {
            core::iter::once(name.as_str())
                .chain(name.match_indices('.').map(|(i, _)| &name[i + 1..]))
        };
        // An exception rule prevails, and leaves its leftmost label out of
        // the suffix: shorter than `name`.
        if suffixes().any(|s| self.exception.contains(s)) {
            return false;
        }
        let parent = name.split_once('.').map(|(_, p)| p);
        if self.plain.contains(&name) || parent.is_some_and(|p| self.wildcard.contains(p)) {
            return true;
        }
        // Some rule matches a shorter suffix, making that the public
        // suffix; or none does, and the default rule takes the last label.
        let matched = suffixes().any(|s| {
            self.plain.contains(s)
                || s.split_once('.')
                    .is_some_and(|(_, p)| self.wildcard.contains(p))
        });
        !matched && parent.is_none()
    }
}

/// A name with each non-ASCII label as `xn--` and its punycode, all
/// lowercase; `None` if a label cannot be encoded.
fn to_ascii(name: &str) -> Option<String> {
    let mut out = String::new();
    for (i, label) in name.split('.').enumerate() {
        if i > 0 {
            out.push('.');
        }
        if label.is_ascii() {
            out.push_str(&label.to_ascii_lowercase());
        } else {
            out.push_str("xn--");
            out.push_str(&punycode(&label.to_lowercase())?);
        }
    }
    Some(out)
}

/// RFC 3492's encoding of a label's code points.
fn punycode(label: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    fn adapt(delta: u32, points: u32, first: bool) -> u32 {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + 38)
    }
    fn digit(d: u32) -> char {
        char::from(if d < 26 {
            b'a' + d as u8
        } else {
            b'0' + (d - 26) as u8
        })
    }
    let input: Vec<u32> = label.chars().map(u32::from).collect();
    let mut out: String = label.chars().filter(char::is_ascii).collect();
    let basic = out.len() as u32;
    let mut handled = basic;
    if basic > 0 {
        out.push('-');
    }
    let (mut n, mut delta, mut bias) = (128u32, 0u32, 72u32);
    while (handled as usize) < input.len() {
        let m = input.iter().copied().filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in &input {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn punycode_matches_rfc_3492() {
        assert_eq!(punycode("bücher").as_deref(), Some("bcher-kva"));
        assert_eq!(punycode("münchen").as_deref(), Some("mnchen-3ya"));
        // RFC 3492 7.1 (A): Arabic (Egyptian).
        assert_eq!(
            punycode("\u{644}\u{64a}\u{647}\u{645}\u{627}\u{628}\u{62a}\u{643}\u{644}\u{645}\u{648}\u{634}\u{639}\u{631}\u{628}\u{64a}\u{61f}")
                .as_deref(),
            Some("egbpdaj6bu4bxfgehfvwxn")
        );
        assert_eq!(to_ascii("公司.cn").as_deref(), Some("xn--55qx5d.cn"));
        assert_eq!(to_ascii("Example.COM").as_deref(), Some("example.com"));
    }

    const LIST: &str =
        "// a comment\n\ncom\nuk\nco.uk\n*.ck\n!www.ck\ns3.amazonaws.com\n公司.cn\ncn\n";

    #[test]
    fn public_suffixes_follow_the_lists_algorithm() {
        let l = PublicSuffixes::parse(LIST);
        assert_eq!(l.len(), 8);
        for ps in [
            "com",
            "co.uk",
            "uk",
            "foo.ck",
            "s3.amazonaws.com",
            "xn--55qx5d.cn",
            "COM.",
            "unlisted",
        ] {
            assert!(l.is_public_suffix(ps), "{ps}");
        }
        for not in [
            "example.com",
            "a.co.uk",
            "www.ck",
            "a.foo.ck",
            "bucket.s3.amazonaws.com",
            "amazonaws.com",
            "x.unlisted",
        ] {
            assert!(!l.is_public_suffix(not), "{not}");
        }
        // Without a list, only the default rule.
        let none = PublicSuffixes::default();
        assert!(none.is_public_suffix("com"));
        assert!(!none.is_public_suffix("co.uk"));
    }
}
