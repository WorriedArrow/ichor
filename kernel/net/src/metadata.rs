//! What a cloud tells a machine about itself, sans-I/O: the requests each
//! cloud's metadata service takes at 169.254.169.254 (over plain HTTP, which
//! stays on the machine's host), what its answers mean, and what Ichor reads
//! in the one it asks for: the configuration the machine was launched with.
//!
//! | Cloud | Where the configuration is |
//! |---|---|
//! | GCP | the instance attribute `ichor` |
//! | AWS | the instance's user data (by IMDSv2: a token first) |
//! | Azure | the instance's user data (base64 in the answer) |

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::Ipv4Addr;

/// Where clouds answer.
pub const ADDRESS: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
pub const PORT: u16 = 80;
/// The longest answer taken.
pub const MAX_ANSWER: usize = 64 * 1024;

/// A cloud whose metadata service this can ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cloud {
    Gcp,
    Aws,
    Azure,
}

impl Cloud {
    pub const ALL: [Cloud; 3] = [Cloud::Gcp, Cloud::Aws, Cloud::Azure];

    pub fn name(self) -> &'static str {
        match self {
            Cloud::Gcp => "gcp",
            Cloud::Aws => "aws",
            Cloud::Azure => "azure",
        }
    }

    pub fn parse(s: &str) -> Option<Cloud> {
        Cloud::ALL.into_iter().find(|c| c.name() == s)
    }
}

/// What comes of an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// There is another request to make.
    Ask,
    /// The machine's configuration, if it was given one.
    Config(Option<Vec<u8>>),
    /// Whoever answered is not this cloud's metadata service.
    NotThis,
}

/// Asks one cloud for the machine's configuration.
#[derive(Clone, Debug)]
pub struct Client {
    cloud: Cloud,
    /// AWS: the session's token.
    token: Option<String>,
}

impl Client {
    pub fn new(cloud: Cloud) -> Client {
        Client { cloud, token: None }
    }

    /// The next request. (HTTP/1.0: the answer ends with the connection,
    /// or says how long it is.)
    pub fn request(&self, host: &str) -> Vec<u8> {
        let (line, header) = match (self.cloud, &self.token) {
            (Cloud::Gcp, _) => (
                "GET /computeMetadata/v1/instance/attributes/ichor",
                "Metadata-Flavor: Google".to_string(),
            ),
            (Cloud::Aws, None) => (
                "PUT /latest/api/token",
                "X-aws-ec2-metadata-token-ttl-seconds: 60\r\nContent-Length: 0".to_string(),
            ),
            (Cloud::Aws, Some(t)) => (
                "GET /latest/user-data",
                format!("X-aws-ec2-metadata-token: {t}"),
            ),
            (Cloud::Azure, _) => (
                "GET /metadata/instance/compute/userData?api-version=2021-01-01&format=text",
                "Metadata: true".to_string(),
            ),
        };
        format!("{line} HTTP/1.0\r\nHost: {host}\r\n{header}\r\nConnection: close\r\n\r\n")
            .into_bytes()
    }

    /// Takes the whole answer to the last request.
    pub fn answer(&mut self, answer: &[u8]) -> Outcome {
        let Some(a) = Answer::parse(answer) else {
            return Outcome::NotThis;
        };
        match (self.cloud, &self.token) {
            (Cloud::Gcp, _) => {
                // Its service says so in every answer.
                if a.header("metadata-flavor") != Some("Google") {
                    return Outcome::NotThis;
                }
                match a.status {
                    200 => Outcome::Config(config(a.body)),
                    404 => Outcome::Config(None),
                    _ => Outcome::NotThis,
                }
            }
            (Cloud::Aws, None) => {
                // What a header may hold, and no more.
                let token = core::str::from_utf8(a.body).unwrap_or("").trim();
                let fits = (1..=1024).contains(&token.len())
                    && token.bytes().all(|b| b.is_ascii_graphic());
                if a.status != 200 || !fits {
                    return Outcome::NotThis;
                }
                self.token = Some(token.to_string());
                Outcome::Ask
            }
            (Cloud::Aws, Some(_)) => match a.status {
                200 => Outcome::Config(config(a.body)),
                404 => Outcome::Config(None),
                _ => Outcome::NotThis,
            },
            (Cloud::Azure, _) => match a.status {
                200 => match base64(a.body) {
                    Some(b) => Outcome::Config(config(&b)),
                    None => Outcome::NotThis,
                },
                _ => Outcome::NotThis,
            },
        }
    }
}

fn config(b: &[u8]) -> Option<Vec<u8>> {
    (!b.is_empty()).then(|| b.to_vec())
}

/// An HTTP answer.
struct Answer<'a> {
    status: u16,
    headers: &'a str,
    body: &'a [u8],
}

impl<'a> Answer<'a> {
    fn parse(b: &'a [u8]) -> Option<Answer<'a>> {
        let end = b.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = core::str::from_utf8(&b[..end]).ok()?;
        let (line, headers) = head.split_once("\r\n").unwrap_or((head, ""));
        let mut f = line.split(' ');
        if !f.next()?.starts_with("HTTP/1.") {
            return None;
        }
        let status = f.next()?.parse().ok()?;
        let mut a = Answer {
            status,
            headers,
            body: &b[end + 4..],
        };
        if let Some(n) = a.header("content-length") {
            let n: usize = n.parse().ok()?;
            // Cut short is not an answer.
            a.body = a.body.get(..n)?;
        }
        // (Nothing sends chunks to HTTP/1.0.)
        match a.header("transfer-encoding") {
            None => Some(a),
            Some(_) => None,
        }
    }

    fn header(&self, name: &str) -> Option<&'a str> {
        self.headers.split("\r\n").find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

/// Whether the answer so far is all of it, if it says how long it is.
pub fn complete(answer: &[u8]) -> bool {
    Answer::parse(answer).is_some_and(|a| a.header("content-length").is_some())
}

/// Decodes base64, with or without its padding; whitespace is skipped.
pub fn base64(b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0);
    let mut ended = false;
    for &c in b {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                ended = true;
                continue;
            }
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        };
        if ended {
            return None;
        }
        acc = acc << 6 | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // What is left is padding.
    (acc == 0 && bits < 6).then_some(out)
}

/// What Ichor reads in a machine's configuration: text, with a line
/// `api-token = ...`, the API's certificates and key (PEM), and kernel
/// options (as on the boot volume's command line), in any order; `#` begins
/// a comment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub api_token: String,
    pub api_tls: String,
    pub options: String,
}

impl Config {
    /// Reads a configuration. Anything may be in user data that is meant
    /// for someone else (a script, say): what is not text is not one, and
    /// a script (`#!`) has only comments.
    pub fn parse(b: &[u8]) -> Option<Config> {
        let text = core::str::from_utf8(b).ok()?;
        let mut c = Config::default();
        if text.starts_with("#!") {
            return Some(c);
        }
        let mut pem = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("-----BEGIN ") {
                pem = true;
            }
            if pem {
                c.api_tls.push_str(line);
                c.api_tls.push('\n');
                pem = !line.starts_with("-----END ");
                continue;
            }
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=')
                && k.trim() == "api-token"
            {
                c.api_token = v.trim().to_string();
                continue;
            }
            if !c.options.is_empty() {
                c.options.push(' ');
            }
            c.options.push_str(line);
        }
        Some(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(b: &[u8]) -> &str {
        core::str::from_utf8(b).unwrap()
    }

    #[test]
    fn gcp_says_who_it_is() {
        let mut c = Client::new(Cloud::Gcp);
        let req = c.request("169.254.169.254");
        assert_eq!(
            text(&req),
            "GET /computeMetadata/v1/instance/attributes/ichor HTTP/1.0\r\n\
             Host: 169.254.169.254\r\nMetadata-Flavor: Google\r\n\
             Connection: close\r\n\r\n"
        );
        let ok =
            b"HTTP/1.0 200 OK\r\nMetadata-Flavor: Google\r\nContent-Length: 5\r\n\r\nhellothe rest";
        assert!(complete(ok));
        assert!(!complete(&ok[..ok.len() - 12]));
        assert_eq!(c.answer(ok), Outcome::Config(Some(b"hello".to_vec())));
        let none = b"HTTP/1.0 404 Not Found\r\nmetadata-flavor:Google\r\n\r\n<html>";
        assert_eq!(c.answer(none), Outcome::Config(None));
        // Anyone else who answers there is not it.
        for other in [
            &b"HTTP/1.0 200 OK\r\n\r\nhello"[..],
            b"HTTP/1.0 403 Forbidden\r\nMetadata-Flavor: Google\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nMetadata-Flavor: Google\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nMetadata-Flavor: Google\r\nContent-Length: 9\r\n\r\nshort",
            b"SSH-2.0-x\r\n\r\n",
            b"",
        ] {
            assert_eq!(c.answer(other), Outcome::NotThis, "{other:?}");
        }
    }

    #[test]
    fn aws_wants_a_token_first() {
        let mut c = Client::new(Cloud::Aws);
        assert!(text(&c.request("h")).starts_with("PUT /latest/api/token HTTP/1.0\r\n"));
        // A token that would end its header is none.
        let bad = b"HTTP/1.1 200 OK\r\n\r\nabc\r\nX: y";
        assert_eq!(Client::new(Cloud::Aws).answer(bad), Outcome::NotThis);
        assert_eq!(
            c.answer(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nAQ=="),
            Outcome::Ask
        );
        let req = c.request("h");
        assert!(text(&req).starts_with("GET /latest/user-data HTTP/1.0\r\n"));
        assert!(text(&req).contains("\r\nX-aws-ec2-metadata-token: AQ==\r\n"));
        assert_eq!(
            c.answer(b"HTTP/1.1 200 OK\r\n\r\ncontrol=50051"),
            Outcome::Config(Some(b"control=50051".to_vec()))
        );
        assert_eq!(
            c.answer(b"HTTP/1.1 404 Not Found\r\n\r\n"),
            Outcome::Config(None)
        );
    }

    #[test]
    fn azure_answers_in_base64() {
        let mut c = Client::new(Cloud::Azure);
        assert!(text(&c.request("h")).contains("\r\nMetadata: true\r\n"));
        assert_eq!(
            c.answer(b"HTTP/1.1 200 OK\r\n\r\nY29udHJvbD01MDA1MQ=="),
            Outcome::Config(Some(b"control=50051".to_vec()))
        );
        assert_eq!(c.answer(b"HTTP/1.1 200 OK\r\n\r\n"), Outcome::Config(None));
        assert_eq!(c.answer(b"HTTP/1.1 200 OK\r\n\r\n!!"), Outcome::NotThis);
        assert_eq!(c.answer(b"HTTP/1.1 400 Bad\r\n\r\n"), Outcome::NotThis);
        for (coded, plain) in [
            (&b""[..], &b""[..]),
            (b"Zg==", b"f"),
            (b"Zm8=", b"fo"),
            (b"Zm9v\r\n", b"foo"),
            (b"Zm9vYg", b"foob"),
        ] {
            assert_eq!(base64(coded).unwrap(), plain);
        }
        assert!(base64(b"Z").is_none() && base64(b"Zg==Zg==").is_none());
    }

    #[test]
    fn a_configuration_has_options_a_token_and_certificates() {
        let c = Config::parse(
            b"# for this machine\ncontrol=50051 control_publish=50051\r\n\
              api-token = s3cret=1 \n-----BEGIN CERTIFICATE-----\nMIIB\n\
              -----END CERTIFICATE-----\n\ndns=10.0.0.2\n\
              -----BEGIN PRIVATE KEY-----\nMC4C\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        assert_eq!(c.api_token, "s3cret=1");
        assert_eq!(
            c.options,
            "control=50051 control_publish=50051 dns=10.0.0.2"
        );
        assert_eq!(
            c.api_tls,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n\
             -----BEGIN PRIVATE KEY-----\nMC4C\n-----END PRIVATE KEY-----\n"
        );
        // User data meant for someone else.
        assert_eq!(
            Config::parse(b"#!/bin/sh\napi-token = x\n"),
            Some(Config::default())
        );
        assert_eq!(Config::parse(&[0xff, 0x00]), None);
    }
}
