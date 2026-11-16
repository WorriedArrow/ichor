//! HTTP/1.1 for the control plane's registry client (ADR-0012 §3),
//! sans-I/O: [`Request::encode`] gives the bytes to send, and a
//! [`ResponseParser`] takes the bytes that come back until it has a whole
//! [`Response`] (a `Content-Length` body, a chunked one, or one that ends
//! when the server closes).
//!
//! Requests always say `Connection: close`: one request per connection
//! keeps the client simple, and registries pipeline nothing anyway.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod h2;
pub mod hpack;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Largest header block accepted.
const MAX_HEADERS: usize = 64 * 1024;

/// What was wrong with a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    TooLarge,
    /// The connection ended before the body did.
    Truncated,
}

/// An HTTPS URL, split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

impl Url {
    /// Parses `https://host[:port]/path`; plain `http://` too (port 80).
    pub fn parse(s: &str) -> Option<Url> {
        let (rest, default_port) = if let Some(r) = s.strip_prefix("https://") {
            (r, 443)
        } else {
            (s.strip_prefix("http://")?, 80)
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok()?),
            None => (authority, default_port),
        };
        if host.is_empty() || authority.contains('@') {
            return None;
        }
        Some(Url {
            host: host.into(),
            port,
            path: path.into(),
        })
    }

    pub fn is_https(&self) -> bool {
        self.port != 80
    }

    /// Resolves `location` (absolute, or a path) against this URL.
    pub fn join(&self, location: &str) -> Option<Url> {
        if location.starts_with("https://") || location.starts_with("http://") {
            return Url::parse(location);
        }
        location.starts_with('/').then(|| Url {
            host: self.host.clone(),
            port: self.port,
            path: location.into(),
        })
    }
}

/// A request.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: &'static str,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn get(url: Url) -> Request {
        Request {
            method: "GET",
            url,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Request {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The bytes to send.
    pub fn encode(&self) -> Vec<u8> {
        let host = if self.url.port == 443 || self.url.port == 80 {
            self.url.host.clone()
        } else {
            format!("{}:{}", self.url.host, self.url.port)
        };
        let mut s = format!(
            "{} {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ichor\r\n",
            self.method, self.url.path
        );
        for (k, v) in &self.headers {
            s.push_str(k);
            s.push_str(": ");
            s.push_str(v);
            s.push_str("\r\n");
        }
        if !self.body.is_empty() || self.method == "POST" || self.method == "PUT" {
            s.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        s.push_str("\r\n");
        let mut out = s.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

/// A complete response.
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// The first header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A parsed status line and headers, and how the body ends.
type Head = (u16, Vec<(String, String)>, Body);

#[derive(Debug)]
enum Body {
    Length(usize),
    Chunked,
    UntilClose,
}

/// Parses one response as its bytes arrive.
#[derive(Debug, Default)]
pub struct ResponseParser {
    buf: Vec<u8>,
    head: Option<Head>,
    body: Vec<u8>,
    /// Largest body accepted.
    limit: usize,
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

impl ResponseParser {
    /// A parser accepting bodies of up to `limit` bytes.
    pub fn new(limit: usize) -> ResponseParser {
        ResponseParser {
            limit,
            ..ResponseParser::default()
        }
    }

    /// Takes more bytes; a whole response once it has one.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<Response>, Error> {
        self.buf.extend_from_slice(data);
        if self.head.is_none() {
            let Some(end) = find(&self.buf, b"\r\n\r\n") else {
                if self.buf.len() > MAX_HEADERS {
                    return Err(Error::TooLarge);
                }
                return Ok(None);
            };
            let head = core::str::from_utf8(&self.buf[..end]).map_err(|_| Error::Malformed)?;
            let mut lines = head.split("\r\n");
            let status_line = lines.next().ok_or(Error::Malformed)?;
            let mut parts = status_line.splitn(3, ' ');
            let version = parts.next().ok_or(Error::Malformed)?;
            if !version.starts_with("HTTP/1.") {
                return Err(Error::Malformed);
            }
            let status: u16 = parts
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or(Error::Malformed)?;
            let mut headers = Vec::new();
            for line in lines {
                let (k, v) = line.split_once(':').ok_or(Error::Malformed)?;
                headers.push((String::from(k.trim()), String::from(v.trim())));
            }
            let get = |n: &str| {
                headers
                    .iter()
                    .find(|(k, _): &&(String, String)| k.eq_ignore_ascii_case(n))
                    .map(|(_, v)| v.clone())
            };
            let body = if status == 204 || status == 304 || (100..200).contains(&status) {
                Body::Length(0)
            } else if get("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
                Body::Chunked
            } else if let Some(len) = get("content-length") {
                Body::Length(len.parse().map_err(|_| Error::Malformed)?)
            } else {
                Body::UntilClose
            };
            if let Body::Length(n) = body
                && n > self.limit
            {
                return Err(Error::TooLarge);
            }
            self.buf.drain(..end + 4);
            self.head = Some((status, headers, body));
        }
        self.take_body()
    }

    fn take_body(&mut self) -> Result<Option<Response>, Error> {
        let Some((_, _, body)) = &self.head else {
            return Ok(None);
        };
        match body {
            Body::Length(n) => {
                if self.buf.len() >= *n {
                    let rest = self.buf.split_off(*n);
                    self.body = core::mem::replace(&mut self.buf, rest);
                    return Ok(self.finish());
                }
            }
            Body::UntilClose => {
                if self.buf.len() > self.limit {
                    return Err(Error::TooLarge);
                }
            }
            Body::Chunked => {
                while let Some(eol) = find(&self.buf, b"\r\n") {
                    let line =
                        core::str::from_utf8(&self.buf[..eol]).map_err(|_| Error::Malformed)?;
                    let size_str = line.split(';').next().unwrap_or("").trim();
                    let size = usize::from_str_radix(size_str, 16).map_err(|_| Error::Malformed)?;
                    if size == 0 {
                        // The last chunk; skip any trailers up to the blank line.
                        let Some(end) = find(&self.buf[eol..], b"\r\n\r\n") else {
                            break;
                        };
                        self.buf.drain(..eol + end + 4);
                        return Ok(self.finish());
                    }
                    if self.body.len() + size > self.limit {
                        return Err(Error::TooLarge);
                    }
                    let start = eol + 2;
                    if self.buf.len() < start + size + 2 {
                        break;
                    }
                    if &self.buf[start + size..start + size + 2] != b"\r\n" {
                        return Err(Error::Malformed);
                    }
                    self.body.extend_from_slice(&self.buf[start..start + size]);
                    self.buf.drain(..start + size + 2);
                }
            }
        }
        Ok(None)
    }

    fn finish(&mut self) -> Option<Response> {
        let (status, headers, _) = self.head.take()?;
        Some(Response {
            status,
            headers,
            body: core::mem::take(&mut self.body),
        })
    }

    /// The connection closed: a close-delimited body ends here.
    pub fn eof(&mut self) -> Result<Response, Error> {
        match &self.head {
            Some((_, _, Body::UntilClose)) => {
                self.body = core::mem::take(&mut self.buf);
                self.finish().ok_or(Error::Truncated)
            }
            _ => Err(Error::Truncated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u =
            Url::parse("https://registry-1.docker.io/v2/library/alpine/manifests/3.20").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            (
                "registry-1.docker.io",
                443,
                "/v2/library/alpine/manifests/3.20"
            )
        );
        let u = Url::parse("http://10.0.2.2:5000").unwrap();
        assert_eq!((u.port, u.path.as_str()), (5000, "/"));
        assert!(Url::parse("ftp://x/").is_none());
        assert!(Url::parse("https://user@host/").is_none());
        let j = u.join("https://cdn.example/blob?x=1").unwrap();
        assert_eq!(
            (j.host.as_str(), j.path.as_str()),
            ("cdn.example", "/blob?x=1")
        );
        assert_eq!(u.join("/v2/").unwrap().host, "10.0.2.2");
    }

    #[test]
    fn requests() {
        let r = Request::get(Url::parse("https://h.test/a?b=c").unwrap()).header("Accept", "x/y");
        let s = String::from_utf8(r.encode()).unwrap();
        assert!(s.starts_with("GET /a?b=c HTTP/1.1\r\nHost: h.test\r\nConnection: close\r\n"));
        assert!(s.ends_with("Accept: x/y\r\n\r\n"));
    }

    #[test]
    fn content_length_in_pieces() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let mut p = ResponseParser::new(1 << 20);
        for (i, b) in raw.iter().enumerate() {
            let r = p.feed(&[*b]).unwrap();
            if i + 1 < raw.len() {
                assert!(r.is_none());
            } else {
                let r = r.unwrap();
                assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
                assert_eq!(r.header("content-type"), Some("text/plain"));
            }
        }
    }

    #[test]
    fn chunked_and_close_delimited() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;x=y\r\nWiki\r\n5\r\npedia\r\n0\r\nT: v\r\n\r\n";
        let r = ResponseParser::new(1 << 20).feed(raw).unwrap().unwrap();
        assert_eq!(r.body, b"Wikipedia");
        let mut p = ResponseParser::new(1 << 20);
        assert!(
            p.feed(b"HTTP/1.0 200 OK\r\n\r\nall of it")
                .unwrap()
                .is_none()
        );
        assert_eq!(p.eof().unwrap().body, b"all of it");
    }

    #[test]
    fn limits_and_garbage() {
        let mut p = ResponseParser::new(4);
        assert_eq!(
            p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
                .unwrap_err(),
            Error::TooLarge
        );
        assert_eq!(
            ResponseParser::new(9)
                .feed(b"SMTP 220\r\n\r\n")
                .unwrap_err(),
            Error::Malformed
        );
        let mut t = ResponseParser::new(99);
        t.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc")
            .unwrap();
        assert_eq!(t.eof().unwrap_err(), Error::Truncated);
        let bad = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n";
        assert_eq!(
            ResponseParser::new(99).feed(bad).unwrap_err(),
            Error::Malformed
        );
    }
}
