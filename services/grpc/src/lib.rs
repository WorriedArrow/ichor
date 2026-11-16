//! gRPC for the control plane (ADR-0012 §3, §5): protobuf's wire format
//! ([`proto`]), the `ichor.v1.Control` messages (`docs/abi/control.proto`,
//! [`control`]), and calls over an HTTP/2 connection, server side
//! ([`Server`], in `services/control`) and client side ([`Client`], in
//! the host tests). Sans-I/O like the HTTP/2 layer under it.
//!
//! Requests are unary (one message); responses are one message or a
//! stream of them, then the status in trailers. Messages are never
//! compressed.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod control;
pub mod proto;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use http::h2::{self, Connection, Event};

/// Most bytes of one message.
pub const MAX_MESSAGE: usize = 4 << 20;

/// gRPC status codes.
pub mod status {
    pub const OK: u32 = 0;
    pub const CANCELLED: u32 = 1;
    pub const UNKNOWN: u32 = 2;
    pub const INVALID_ARGUMENT: u32 = 3;
    pub const NOT_FOUND: u32 = 5;
    pub const RESOURCE_EXHAUSTED: u32 = 8;
    pub const FAILED_PRECONDITION: u32 = 9;
    pub const UNIMPLEMENTED: u32 = 12;
    pub const INTERNAL: u32 = 13;
    pub const UNAVAILABLE: u32 = 14;
}

/// A message with gRPC's length prefix.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 5);
    out.push(0);
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// A compressed or oversized message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadMessage;

/// Splits a stream of length-prefixed messages.
#[derive(Debug, Default)]
pub struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next whole message.
    pub fn next_message(&mut self) -> Result<Option<Vec<u8>>, BadMessage> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if self.buf[0] != 0 || len > MAX_MESSAGE {
            return Err(BadMessage);
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let m = self.buf[5..5 + len].to_vec();
        self.buf.drain(..5 + len);
        Ok(Some(m))
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

fn header<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// gRPC's percent-encoding of `grpc-message`.
fn encode_message(m: &str) -> String {
    let mut out = String::new();
    for b in m.bytes() {
        if (0x20..0x7f).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode_message(m: &str) -> String {
    let b = m.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = m
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A request that has fully arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub stream: u32,
    /// `/package.Service/Method`.
    pub path: String,
    pub message: Vec<u8>,
}

#[derive(Debug, Default)]
struct Incoming {
    path: String,
    body: Deframer,
    message: Option<Vec<u8>>,
    answered: bool,
}

/// The server side: turns HTTP/2 events into [`Call`]s and sends replies.
#[derive(Debug)]
pub struct Server {
    pub conn: Connection,
    calls: BTreeMap<u32, Incoming>,
}

impl Default for Server {
    fn default() -> Server {
        Server::new()
    }
}

impl Server {
    pub fn new() -> Server {
        Server {
            conn: Connection::server(),
            calls: BTreeMap::new(),
        }
    }

    /// Takes bytes from the client; returns the calls that completed.
    pub fn receive(&mut self, data: &[u8]) -> Result<Vec<Call>, h2::Error> {
        self.conn.receive(data)?;
        let mut done = Vec::new();
        while let Some(e) = self.conn.poll_event() {
            match e {
                Event::Headers {
                    stream,
                    fields,
                    end_stream,
                } => {
                    let ok = header(&fields, ":method") == Some("POST")
                        && header(&fields, "content-type")
                            .is_some_and(|c| c.starts_with("application/grpc"));
                    if !ok {
                        self.conn.send_headers(stream, &[(":status", "415")], true);
                        continue;
                    }
                    let path = header(&fields, ":path").unwrap_or("").into();
                    self.calls.insert(
                        stream,
                        Incoming {
                            path,
                            ..Incoming::default()
                        },
                    );
                    if end_stream {
                        self.complete(stream, &mut done);
                    }
                }
                Event::Data {
                    stream,
                    data,
                    end_stream,
                } => {
                    let Some(c) = self.calls.get_mut(&stream) else {
                        continue;
                    };
                    c.body.push(&data);
                    match c.body.next_message() {
                        Ok(Some(m)) if c.message.is_none() => c.message = Some(m),
                        Ok(None) => {}
                        _ => {
                            self.fail(
                                stream,
                                status::INVALID_ARGUMENT,
                                "one uncompressed message per call",
                            );
                            continue;
                        }
                    }
                    if end_stream {
                        self.complete(stream, &mut done);
                    }
                }
                Event::Reset { stream, .. } => {
                    self.calls.remove(&stream);
                }
                Event::GoAway { .. } => {}
            }
        }
        Ok(done)
    }

    fn complete(&mut self, stream: u32, done: &mut Vec<Call>) {
        let Some(c) = self.calls.get_mut(&stream) else {
            return;
        };
        match c.message.take() {
            Some(message) if c.body.is_empty() => done.push(Call {
                stream,
                path: core::mem::take(&mut c.path),
                message,
            }),
            _ => self.fail(
                stream,
                status::INVALID_ARGUMENT,
                "the request has no message",
            ),
        }
    }

    /// Whether `stream` is a call not yet finished.
    pub fn is_open(&self, stream: u32) -> bool {
        self.calls.contains_key(&stream)
    }

    fn respond(&mut self, stream: u32) {
        if let Some(c) = self.calls.get_mut(&stream)
            && !c.answered
        {
            c.answered = true;
            self.conn.send_headers(
                stream,
                &[(":status", "200"), ("content-type", "application/grpc")],
                false,
            );
        }
    }

    /// Sends one response message.
    pub fn reply(&mut self, stream: u32, message: &[u8]) {
        if !self.is_open(stream) {
            return;
        }
        self.respond(stream);
        self.conn.send_data(stream, &frame(message), false);
    }

    /// Ends the call with OK.
    pub fn finish(&mut self, stream: u32) {
        self.end(stream, status::OK, "");
    }

    /// Ends the call with an error status.
    pub fn fail(&mut self, stream: u32, code: u32, message: &str) {
        self.end(stream, code, message);
    }

    fn end(&mut self, stream: u32, code: u32, message: &str) {
        let Some(c) = self.calls.remove(&stream) else {
            return;
        };
        let status = format!("{code}");
        let msg = encode_message(message);
        let mut fields: Vec<(&str, &str)> = Vec::new();
        if !c.answered {
            // Trailers-only.
            fields.push((":status", "200"));
            fields.push(("content-type", "application/grpc"));
        }
        fields.push(("grpc-status", &status));
        if !message.is_empty() {
            fields.push(("grpc-message", &msg));
        }
        self.conn.send_headers(stream, &fields, true);
    }
}

/// What a call's response brought.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    Message {
        stream: u32,
        message: Vec<u8>,
    },
    /// The call is over.
    Status {
        stream: u32,
        code: u32,
        message: String,
    },
}

/// The client side.
#[derive(Debug)]
pub struct Client {
    pub conn: Connection,
    authority: String,
    bodies: BTreeMap<u32, Deframer>,
}

impl Client {
    pub fn new(authority: &str) -> Client {
        Client {
            conn: Connection::client(),
            authority: authority.into(),
            bodies: BTreeMap::new(),
        }
    }

    /// Starts a call of `path` with one request message.
    pub fn call(&mut self, path: &str, message: &[u8]) -> u32 {
        let id = self.conn.open();
        self.conn.send_headers(
            id,
            &[
                (":method", "POST"),
                (":scheme", "http"),
                (":path", path),
                (":authority", &self.authority),
                ("content-type", "application/grpc"),
                ("te", "trailers"),
            ],
            false,
        );
        self.conn.send_data(id, &frame(message), true);
        self.bodies.insert(id, Deframer::default());
        id
    }

    /// Takes bytes from the server.
    pub fn receive(&mut self, data: &[u8]) -> Result<Vec<Response>, h2::Error> {
        self.conn.receive(data)?;
        let mut out = Vec::new();
        while let Some(e) = self.conn.poll_event() {
            match e {
                Event::Headers {
                    stream,
                    fields,
                    end_stream,
                } => {
                    if let Some(code) = header(&fields, "grpc-status") {
                        out.push(Response::Status {
                            stream,
                            code: code.parse().unwrap_or(status::UNKNOWN),
                            message: decode_message(header(&fields, "grpc-message").unwrap_or("")),
                        });
                        self.bodies.remove(&stream);
                    } else if end_stream {
                        out.push(Response::Status {
                            stream,
                            code: status::UNKNOWN,
                            message: format!(
                                "HTTP status {}",
                                header(&fields, ":status").unwrap_or("?")
                            ),
                        });
                        self.bodies.remove(&stream);
                    }
                }
                Event::Data { stream, data, .. } => {
                    if let Some(d) = self.bodies.get_mut(&stream) {
                        d.push(&data);
                        while let Ok(Some(m)) = d.next_message() {
                            out.push(Response::Message { stream, message: m });
                        }
                    }
                }
                Event::Reset { stream, code } => {
                    self.bodies.remove(&stream);
                    out.push(Response::Status {
                        stream,
                        code: status::UNAVAILABLE,
                        message: format!("stream reset ({code})"),
                    });
                }
                Event::GoAway { .. } => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn pump(c: &mut Client, s: &mut Server) -> (Vec<Call>, Vec<Response>) {
        let (mut calls, mut resps) = (Vec::new(), Vec::new());
        for _ in 0..1000 {
            let (a, b) = (c.conn.take_output(), s.conn.take_output());
            if a.is_empty() && b.is_empty() {
                break;
            }
            calls.extend(s.receive(&a).unwrap());
            resps.extend(c.receive(&b).unwrap());
        }
        (calls, resps)
    }

    #[test]
    fn unary_and_streaming_calls() {
        let (mut c, mut s) = (Client::new("ichor"), Server::new());
        let a = c.call("/ichor.v1.Control/PullImage", b"one");
        let b = c.call("/ichor.v1.Control/Run", b"two");
        let (calls, _) = pump(&mut c, &mut s);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].path, "/ichor.v1.Control/PullImage");
        assert_eq!(calls[1].message, b"two");
        s.reply(a, b"pulled");
        s.finish(a);
        s.reply(b, b"out 1");
        s.reply(b, &vec![9; 100_000]);
        s.fail(b, status::NOT_FOUND, "no such cell: 50% gone");
        let (_, resps) = pump(&mut c, &mut s);
        assert_eq!(
            resps[0],
            Response::Message {
                stream: a,
                message: b"pulled".to_vec()
            }
        );
        assert_eq!(
            resps[1],
            Response::Status {
                stream: a,
                code: 0,
                message: String::new()
            }
        );
        assert!(matches!(&resps[3], Response::Message { message, .. } if message.len() == 100_000));
        assert_eq!(
            resps[4],
            Response::Status {
                stream: b,
                code: status::NOT_FOUND,
                message: "no such cell: 50% gone".into()
            }
        );
    }

    #[test]
    fn trailers_only_errors() {
        let (mut c, mut s) = (Client::new("ichor"), Server::new());
        let a = c.call("/nope", b"");
        let (calls, _) = pump(&mut c, &mut s);
        s.fail(calls[0].stream, status::UNIMPLEMENTED, "unknown method");
        let (_, resps) = pump(&mut c, &mut s);
        assert_eq!(
            resps,
            [Response::Status {
                stream: a,
                code: status::UNIMPLEMENTED,
                message: "unknown method".into()
            }]
        );
    }

    #[test]
    fn deframing_in_pieces() {
        let mut d = Deframer::default();
        let mut bytes = frame(b"hello");
        bytes.extend(frame(b""));
        for b in &bytes[..7] {
            d.push(core::slice::from_ref(b));
            assert_eq!(d.next_message(), Ok(None));
        }
        d.push(&bytes[7..]);
        assert_eq!(d.next_message(), Ok(Some(b"hello".to_vec())));
        assert_eq!(d.next_message(), Ok(Some(Vec::new())));
        let mut d = Deframer::default();
        d.push(&[1, 0, 0, 0, 0]);
        assert!(d.next_message().is_err());
    }
}
