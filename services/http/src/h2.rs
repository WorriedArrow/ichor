//! HTTP/2 over cleartext TCP (h2c with prior knowledge, RFC 9113), sans
//! I/O, for the control plane's gRPC API (ADR-0012 §4) and the host
//! tests' client. A [`Connection`] is either end: feed it what the socket
//! read ([`Connection::receive`]), take what it has to send
//! ([`Connection::take_output`]), and drain [`Event`]s.
//!
//! Flow control is honored both ways: data waits for the peer's windows,
//! and every DATA frame received is credited back at once (the
//! application consumes events as they come). Server push, priorities and
//! the peer's dynamic HPACK table size are not used (our encoder never
//! indexes).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use crate::hpack::{self, Field};

/// What a client sends first.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PUSH_PROMISE: u8 = 5;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

/// Error codes (RFC 9113 §7).
pub mod code {
    pub const NO_ERROR: u32 = 0;
    pub const PROTOCOL_ERROR: u32 = 1;
    pub const INTERNAL_ERROR: u32 = 2;
    pub const FLOW_CONTROL_ERROR: u32 = 3;
    pub const STREAM_CLOSED: u32 = 5;
    pub const FRAME_SIZE_ERROR: u32 = 6;
    pub const REFUSED_STREAM: u32 = 7;
    pub const CANCEL: u32 = 8;
    pub const COMPRESSION_ERROR: u32 = 9;
}

/// The largest frame payload we accept (the protocol's default).
const MAX_FRAME: usize = 16384;
/// What we let the peer send ahead, per stream and per connection.
const RECV_WINDOW: u32 = 1 << 20;
/// Most bytes of one header block (HEADERS plus CONTINUATIONs).
const MAX_HEADER_BLOCK: usize = 64 * 1024;
const MAX_WINDOW: i64 = (1 << 31) - 1;

/// Something the peer did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A header block: a request's or response's headers, or trailers.
    Headers {
        stream: u32,
        fields: Vec<Field>,
        end_stream: bool,
    },
    Data {
        stream: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    /// The peer ended the stream abnormally.
    Reset { stream: u32, code: u32 },
    /// The peer is closing the connection.
    GoAway { last_stream: u32, code: u32 },
}

/// A connection error: the connection is over (a GOAWAY with this code is
/// in the output).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: u32,
}

#[derive(Debug)]
enum Out {
    Headers(Vec<u8>, bool),
    Data(Vec<u8>, bool),
}

#[derive(Debug)]
struct Stream {
    send_window: i64,
    queue: VecDeque<Out>,
    local_closed: bool,
    remote_closed: bool,
}

/// One HTTP/2 connection.
#[derive(Debug)]
pub struct Connection {
    server: bool,
    /// Bytes of the client preface still to come (server).
    preface: usize,
    input: Vec<u8>,
    output: Vec<u8>,
    events: VecDeque<Event>,
    decoder: hpack::Decoder,
    encoder: hpack::Encoder,
    streams: BTreeMap<u32, Stream>,
    send_window: i64,
    peer_initial_window: i64,
    peer_max_frame: usize,
    next_stream: u32,
    last_peer_stream: u32,
    /// A header block awaiting CONTINUATION: stream, END_STREAM, bytes.
    partial: Option<(u32, bool, Vec<u8>)>,
    closed: bool,
}

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let len = payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

impl Connection {
    fn new(server: bool) -> Connection {
        let mut c = Connection {
            server,
            preface: if server { PREFACE.len() } else { 0 },
            input: Vec::new(),
            output: Vec::new(),
            events: VecDeque::new(),
            decoder: hpack::Decoder::new(MAX_HEADER_BLOCK),
            encoder: hpack::Encoder::new(),
            streams: BTreeMap::new(),
            send_window: 65535,
            peer_initial_window: 65535,
            peer_max_frame: MAX_FRAME,
            next_stream: if server { 2 } else { 1 },
            last_peer_stream: 0,
            partial: None,
            closed: false,
        };
        if !server {
            c.output.extend_from_slice(PREFACE);
        }
        let mut settings = Vec::new();
        let mut put = |id: u16, v: u32| {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&v.to_be_bytes());
        };
        put(2, 0); // ENABLE_PUSH
        put(3, 128); // MAX_CONCURRENT_STREAMS
        put(4, RECV_WINDOW); // INITIAL_WINDOW_SIZE
        put(6, MAX_HEADER_BLOCK as u32); // MAX_HEADER_LIST_SIZE
        frame(&mut c.output, SETTINGS, 0, 0, &settings);
        frame(
            &mut c.output,
            WINDOW_UPDATE,
            0,
            0,
            &(RECV_WINDOW - 65535).to_be_bytes(),
        );
        c
    }

    /// The server end of a connection a client opened.
    pub fn server() -> Connection {
        Connection::new(true)
    }

    /// The client end (its output starts with the preface).
    pub fn client() -> Connection {
        Connection::new(false)
    }

    /// Whether the connection is over (after a GOAWAY either way).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The bytes to send, taken.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }

    pub fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Whether any stream still has data waiting for window.
    pub fn is_blocked(&self) -> bool {
        self.streams.values().any(|s| !s.queue.is_empty())
    }

    fn fail(&mut self, code: u32) -> Error {
        if !self.closed {
            let mut p = Vec::new();
            p.extend_from_slice(&self.last_peer_stream.to_be_bytes());
            p.extend_from_slice(&code.to_be_bytes());
            frame(&mut self.output, GOAWAY, 0, 0, &p);
            self.closed = true;
        }
        Error { code }
    }

    /// Closes the connection gracefully.
    pub fn go_away(&mut self) {
        let _ = self.fail(code::NO_ERROR);
    }

    /// Takes bytes read from the peer.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.closed {
            return Err(Error {
                code: code::PROTOCOL_ERROR,
            });
        }
        self.input.extend_from_slice(data);
        if self.preface > 0 {
            let done = PREFACE.len() - self.preface;
            let n = self.preface.min(self.input.len());
            if self.input[..n] != PREFACE[done..done + n] {
                return Err(self.fail(code::PROTOCOL_ERROR));
            }
            self.input.drain(..n);
            self.preface -= n;
            if self.preface > 0 {
                return Ok(());
            }
        }
        while self.input.len() >= 9 {
            let len = (usize::from(self.input[0]) << 16)
                | (usize::from(self.input[1]) << 8)
                | usize::from(self.input[2]);
            if len > MAX_FRAME {
                return Err(self.fail(code::FRAME_SIZE_ERROR));
            }
            if self.input.len() < 9 + len {
                break;
            }
            let (kind, flags) = (self.input[3], self.input[4]);
            let stream = be32(&self.input[5..9]) & 0x7fff_ffff;
            let payload: Vec<u8> = self.input[9..9 + len].to_vec();
            self.input.drain(..9 + len);
            if let Err(code) = self.on_frame(kind, flags, stream, payload) {
                return Err(self.fail(code));
            }
            if self.closed {
                break;
            }
        }
        self.flush();
        Ok(())
    }

    fn on_frame(&mut self, kind: u8, flags: u8, id: u32, mut p: Vec<u8>) -> Result<(), u32> {
        if let Some((sid, _, _)) = &self.partial
            && (kind != CONTINUATION || id != *sid)
        {
            return Err(code::PROTOCOL_ERROR);
        }
        match kind {
            DATA => {
                if id == 0 {
                    return Err(code::PROTOCOL_ERROR);
                }
                let flow = p.len() as u32;
                let data = unpad(&mut p, flags)?;
                // Credit the connection window back whatever happens.
                if flow > 0 {
                    frame(&mut self.output, WINDOW_UPDATE, 0, 0, &flow.to_be_bytes());
                }
                let end = flags & END_STREAM != 0;
                match self.streams.get_mut(&id) {
                    Some(s) if !s.remote_closed => {
                        s.remote_closed = end;
                        if flow > 0 && !end {
                            frame(&mut self.output, WINDOW_UPDATE, 0, id, &flow.to_be_bytes());
                        }
                        self.events.push_back(Event::Data {
                            stream: id,
                            data,
                            end_stream: end,
                        });
                    }
                    _ => self.rst(id, code::STREAM_CLOSED),
                }
            }
            HEADERS => {
                if id == 0 {
                    return Err(code::PROTOCOL_ERROR);
                }
                let mut block = unpad(&mut p, flags)?;
                if flags & PRIORITY_FLAG != 0 {
                    if block.len() < 5 {
                        return Err(code::PROTOCOL_ERROR);
                    }
                    block.drain(..5);
                }
                let end = flags & END_STREAM != 0;
                if flags & END_HEADERS != 0 {
                    self.on_block(id, end, &block)?;
                } else {
                    self.partial = Some((id, end, block));
                }
            }
            CONTINUATION => {
                let Some((sid, end, mut block)) = self.partial.take() else {
                    return Err(code::PROTOCOL_ERROR);
                };
                block.extend_from_slice(&p);
                if block.len() > MAX_HEADER_BLOCK {
                    return Err(code::PROTOCOL_ERROR);
                }
                if flags & END_HEADERS != 0 {
                    self.on_block(sid, end, &block)?;
                } else {
                    self.partial = Some((sid, end, block));
                }
            }
            PRIORITY => {
                if p.len() != 5 {
                    return Err(code::FRAME_SIZE_ERROR);
                }
            }
            RST_STREAM => {
                if p.len() != 4 {
                    return Err(code::FRAME_SIZE_ERROR);
                }
                if id == 0 {
                    return Err(code::PROTOCOL_ERROR);
                }
                if self.streams.remove(&id).is_some() {
                    self.events.push_back(Event::Reset {
                        stream: id,
                        code: be32(&p),
                    });
                }
            }
            SETTINGS => {
                if id != 0 {
                    return Err(code::PROTOCOL_ERROR);
                }
                if flags & ACK != 0 {
                    return if p.is_empty() {
                        Ok(())
                    } else {
                        Err(code::FRAME_SIZE_ERROR)
                    };
                }
                if !p.len().is_multiple_of(6) {
                    return Err(code::FRAME_SIZE_ERROR);
                }
                for s in p.chunks(6) {
                    let v = be32(&s[2..]);
                    match u16::from_be_bytes([s[0], s[1]]) {
                        2 if v > 1 => return Err(code::PROTOCOL_ERROR),
                        4 => {
                            if i64::from(v) > MAX_WINDOW {
                                return Err(code::FLOW_CONTROL_ERROR);
                            }
                            let delta = i64::from(v) - self.peer_initial_window;
                            self.peer_initial_window = i64::from(v);
                            for st in self.streams.values_mut() {
                                st.send_window += delta;
                                if st.send_window > MAX_WINDOW {
                                    return Err(code::FLOW_CONTROL_ERROR);
                                }
                            }
                        }
                        5 => {
                            if !(MAX_FRAME as u32..=0xff_ffff).contains(&v) {
                                return Err(code::PROTOCOL_ERROR);
                            }
                            self.peer_max_frame = v as usize;
                        }
                        _ => {}
                    }
                }
                frame(&mut self.output, SETTINGS, ACK, 0, &[]);
            }
            PUSH_PROMISE => return Err(code::PROTOCOL_ERROR),
            PING => {
                if p.len() != 8 {
                    return Err(code::FRAME_SIZE_ERROR);
                }
                if id != 0 {
                    return Err(code::PROTOCOL_ERROR);
                }
                if flags & ACK == 0 {
                    frame(&mut self.output, PING, ACK, 0, &p);
                }
            }
            GOAWAY => {
                if p.len() < 8 {
                    return Err(code::FRAME_SIZE_ERROR);
                }
                self.events.push_back(Event::GoAway {
                    last_stream: be32(&p) & 0x7fff_ffff,
                    code: be32(&p[4..]),
                });
                self.closed = true;
            }
            WINDOW_UPDATE => {
                if p.len() != 4 {
                    return Err(code::FRAME_SIZE_ERROR);
                }
                let inc = i64::from(be32(&p) & 0x7fff_ffff);
                if id == 0 {
                    if inc == 0 {
                        return Err(code::PROTOCOL_ERROR);
                    }
                    self.send_window += inc;
                    if self.send_window > MAX_WINDOW {
                        return Err(code::FLOW_CONTROL_ERROR);
                    }
                } else if let Some(s) = self.streams.get_mut(&id) {
                    s.send_window += inc;
                    if inc == 0 || s.send_window > MAX_WINDOW {
                        self.streams.remove(&id);
                        self.rst(id, code::FLOW_CONTROL_ERROR);
                    }
                }
            }
            _ => {} // Unknown frame types are ignored (RFC 9113 §4.1).
        }
        Ok(())
    }

    fn on_block(&mut self, id: u32, end: bool, block: &[u8]) -> Result<(), u32> {
        let fields = self
            .decoder
            .decode(block)
            .map_err(|_| code::COMPRESSION_ERROR)?;
        if !self.streams.contains_key(&id) {
            // Only the peer opens a stream we have not seen: a client
            // opens odd ones, in increasing order.
            let peer_opens = self.server != id.is_multiple_of(2);
            if !peer_opens || id <= self.last_peer_stream {
                return Err(code::PROTOCOL_ERROR);
            }
            self.last_peer_stream = id;
            self.streams.insert(
                id,
                Stream {
                    send_window: self.peer_initial_window,
                    queue: VecDeque::new(),
                    local_closed: false,
                    remote_closed: false,
                },
            );
        }
        if let Some(s) = self.streams.get_mut(&id) {
            if s.remote_closed {
                self.streams.remove(&id);
                self.rst(id, code::STREAM_CLOSED);
                return Ok(());
            }
            s.remote_closed = end;
        }
        self.events.push_back(Event::Headers {
            stream: id,
            fields,
            end_stream: end,
        });
        Ok(())
    }

    fn rst(&mut self, id: u32, code: u32) {
        frame(&mut self.output, RST_STREAM, 0, id, &code.to_be_bytes());
    }

    /// Opens a stream (client); returns its id.
    pub fn open(&mut self) -> u32 {
        let id = self.next_stream;
        self.next_stream += 2;
        self.streams.insert(
            id,
            Stream {
                send_window: self.peer_initial_window,
                queue: VecDeque::new(),
                local_closed: false,
                remote_closed: false,
            },
        );
        id
    }

    /// Queues a header block (headers, or trailers after data). False if
    /// the stream is gone or already ended on our side.
    pub fn send_headers(&mut self, stream: u32, fields: &[(&str, &str)], end_stream: bool) -> bool {
        let block = self.encoder.encode(fields);
        self.queue(stream, Out::Headers(block, end_stream))
    }

    /// Queues data; it goes out as the peer's windows allow.
    pub fn send_data(&mut self, stream: u32, data: &[u8], end_stream: bool) -> bool {
        self.queue(stream, Out::Data(data.to_vec(), end_stream))
    }

    fn queue(&mut self, stream: u32, out: Out) -> bool {
        if self.closed {
            return false;
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            return false;
        };
        if s.local_closed
            || s.queue
                .iter()
                .any(|o| matches!(o, Out::Headers(_, true) | Out::Data(_, true)))
        {
            return false;
        }
        s.queue.push_back(out);
        self.flush();
        true
    }

    /// Ends a stream abnormally.
    pub fn reset(&mut self, stream: u32, code: u32) {
        if self.streams.remove(&stream).is_some() {
            self.rst(stream, code);
        }
    }

    /// Emits what the windows allow.
    fn flush(&mut self) {
        if self.closed {
            return;
        }
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        for id in ids {
            let Some(s) = self.streams.get_mut(&id) else {
                continue;
            };
            while let Some(front) = s.queue.front_mut() {
                match front {
                    Out::Headers(block, end) => {
                        let mut flags = if *end { END_STREAM } else { 0 };
                        let mut chunks = block.chunks(self.peer_max_frame).peekable();
                        let mut kind = HEADERS;
                        if block.is_empty() {
                            frame(&mut self.output, HEADERS, flags | END_HEADERS, id, &[]);
                        }
                        while let Some(c) = chunks.next() {
                            let last = chunks.peek().is_none();
                            let f = flags | if last { END_HEADERS } else { 0 };
                            frame(&mut self.output, kind, f, id, c);
                            (kind, flags) = (CONTINUATION, 0);
                        }
                        s.local_closed |= *end;
                        s.queue.pop_front();
                    }
                    Out::Data(data, end) => {
                        if data.is_empty() {
                            let f = if *end { END_STREAM } else { 0 };
                            frame(&mut self.output, DATA, f, id, &[]);
                            s.local_closed |= *end;
                            s.queue.pop_front();
                            continue;
                        }
                        let room = self.send_window.min(s.send_window).max(0) as usize;
                        let n = data.len().min(room).min(self.peer_max_frame);
                        if n == 0 {
                            break;
                        }
                        let last = n == data.len();
                        let f = if last && *end { END_STREAM } else { 0 };
                        frame(&mut self.output, DATA, f, id, &data[..n]);
                        self.send_window -= n as i64;
                        s.send_window -= n as i64;
                        if last {
                            s.local_closed |= *end;
                            s.queue.pop_front();
                        } else {
                            data.drain(..n);
                        }
                    }
                }
            }
        }
        self.streams
            .retain(|_, s| !(s.local_closed && s.remote_closed && s.queue.is_empty()));
    }
}

/// Strips a PADDED frame's padding.
fn unpad(p: &mut Vec<u8>, flags: u8) -> Result<Vec<u8>, u32> {
    if flags & PADDED == 0 {
        return Ok(core::mem::take(p));
    }
    let pad = usize::from(*p.first().ok_or(code::PROTOCOL_ERROR)?);
    if pad + 1 > p.len() {
        return Err(code::PROTOCOL_ERROR);
    }
    Ok(p[1..p.len() - pad].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    /// Moves bytes both ways until neither side has output.
    fn pump(c: &mut Connection, s: &mut Connection) {
        for _ in 0..10_000 {
            let (a, b) = (c.take_output(), s.take_output());
            if a.is_empty() && b.is_empty() {
                return;
            }
            s.receive(&a).unwrap();
            c.receive(&b).unwrap();
        }
        panic!("the connection never settled");
    }

    fn events(c: &mut Connection) -> Vec<Event> {
        core::iter::from_fn(|| c.poll_event()).collect()
    }

    fn get(fields: &[Field], name: &str) -> Option<String> {
        fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }

    #[test]
    fn a_request_and_a_response_with_trailers() {
        let (mut c, mut s) = (Connection::client(), Connection::server());
        let id = c.open();
        assert_eq!(id, 1);
        c.send_headers(
            id,
            &[
                (":method", "POST"),
                (":path", "/x"),
                (":scheme", "http"),
                (":authority", "h"),
            ],
            false,
        );
        c.send_data(id, b"request body", true);
        pump(&mut c, &mut s);
        let ev = events(&mut s);
        let Event::Headers {
            stream: 1,
            fields,
            end_stream: false,
        } = &ev[0]
        else {
            panic!("{ev:?}");
        };
        assert_eq!(get(fields, ":path").as_deref(), Some("/x"));
        assert_eq!(
            ev[1],
            Event::Data {
                stream: 1,
                data: b"request body".to_vec(),
                end_stream: true
            }
        );
        s.send_headers(1, &[(":status", "200")], false);
        s.send_data(1, b"reply", false);
        s.send_headers(1, &[("grpc-status", "0")], true);
        pump(&mut c, &mut s);
        let ev = events(&mut c);
        assert_eq!(ev.len(), 3);
        assert!(
            matches!(&ev[2], Event::Headers { stream: 1, end_stream: true, fields } if get(fields, "grpc-status").as_deref() == Some("0"))
        );
        // Both ends closed: the stream is forgotten.
        assert!(s.streams.is_empty() && c.streams.is_empty());
    }

    #[test]
    fn large_bodies_wait_for_window_updates() {
        let (mut c, mut s) = (Connection::client(), Connection::server());
        let id = c.open();
        c.send_headers(id, &[(":method", "GET"), (":path", "/big")], true);
        pump(&mut c, &mut s);
        events(&mut s);
        let body: Vec<u8> = (0..5_000_000u32).map(|i| (i % 251) as u8).collect();
        s.send_headers(1, &[(":status", "200")], false);
        s.send_data(1, &body, true);
        // Before the client credits anything, at most its window went out.
        let first = s.take_output();
        assert!(first.len() < (RECV_WINDOW as usize) + 64 * 1024);
        assert!(s.is_blocked());
        c.receive(&first).unwrap();
        pump(&mut c, &mut s);
        let mut got = Vec::new();
        let mut ended = false;
        for e in events(&mut c) {
            if let Event::Data {
                data, end_stream, ..
            } = e
            {
                assert!(data.len() <= MAX_FRAME);
                got.extend_from_slice(&data);
                ended |= end_stream;
            }
        }
        assert!(ended);
        assert_eq!(got, body);
        assert!(!s.is_blocked());
    }

    #[test]
    fn big_header_blocks_use_continuation() {
        let (mut c, mut s) = (Connection::client(), Connection::server());
        let id = c.open();
        let long = "v".repeat(40_000);
        c.send_headers(id, &[(":method", "GET"), ("x-long", &long)], true);
        let out = c.take_output();
        // HEADERS then CONTINUATION frames (type 9) follow the settings.
        assert!(out.windows(4).any(|w| w[3] == CONTINUATION && w[0] == 0));
        s.receive(&out).unwrap();
        let ev = events(&mut s);
        assert!(
            matches!(&ev[0], Event::Headers { fields, .. } if get(fields, "x-long").as_deref() == Some(long.as_str()))
        );
    }

    #[test]
    fn pings_are_answered_and_settings_acked() {
        let mut s = Connection::server();
        let mut input = PREFACE.to_vec();
        frame(&mut input, SETTINGS, 0, 0, &[0, 5, 0, 0, 0x80, 0]); // MAX_FRAME_SIZE 32768
        frame(&mut input, PING, 0, 0, b"12345678");
        s.receive(&input).unwrap();
        let out = s.take_output();
        let mut want_ack = Vec::new();
        frame(&mut want_ack, SETTINGS, ACK, 0, &[]);
        frame(&mut want_ack, PING, ACK, 0, b"12345678");
        assert!(out.ends_with(&want_ack));
        assert_eq!(s.peer_max_frame, 32768);
    }

    #[test]
    fn protocol_errors_end_the_connection() {
        let mut s = Connection::server();
        assert!(s.receive(b"GET / HTTP/1.1\r\n").is_err());

        let mut s = Connection::server();
        let mut input = PREFACE.to_vec();
        frame(&mut input, DATA, 0, 0, b"x"); // DATA on stream 0
        assert_eq!(
            s.receive(&input),
            Err(Error {
                code: code::PROTOCOL_ERROR
            })
        );
        assert!(s.is_closed());
        let out = s.take_output();
        assert_eq!(out[out.len() - 17 + 3], GOAWAY);

        // A stream id going backwards.
        let mut s = Connection::server();
        let mut e = hpack::Encoder::new();
        let block = e.encode(&[(":method", "GET")]);
        let mut input = PREFACE.to_vec();
        frame(&mut input, HEADERS, END_HEADERS, 5, &block);
        frame(&mut input, HEADERS, END_HEADERS, 3, &block);
        assert!(s.receive(&input).is_err());

        // A frame larger than we allow.
        let mut s = Connection::server();
        let mut input = PREFACE.to_vec();
        frame(&mut input, DATA, 0, 1, &vec![0; MAX_FRAME + 1]);
        assert_eq!(
            s.receive(&input),
            Err(Error {
                code: code::FRAME_SIZE_ERROR
            })
        );
    }

    #[test]
    fn input_split_anywhere_is_the_same() {
        let mut c = Connection::client();
        let id = c.open();
        c.send_headers(id, &[(":method", "POST"), (":path", "/p")], false);
        c.send_data(id, &[7; 3000], true);
        let bytes = c.take_output();
        let mut s = Connection::server();
        for b in &bytes {
            s.receive(core::slice::from_ref(b)).unwrap();
        }
        let ev = events(&mut s);
        let data: usize = ev
            .iter()
            .map(|e| match e {
                Event::Data { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(data, 3000);
    }

    #[test]
    fn padding_and_priority_are_stripped() {
        let mut s = Connection::server();
        let mut e = hpack::Encoder::new();
        let block = e.encode(&[(":method", "GET"), (":path", "/")]);
        let mut p = vec![3u8]; // pad length
        p.extend_from_slice(&[0, 0, 0, 0, 16]); // priority
        p.extend_from_slice(&block);
        p.extend_from_slice(&[0, 0, 0]);
        let mut input = PREFACE.to_vec();
        frame(
            &mut input,
            HEADERS,
            END_HEADERS | PADDED | PRIORITY_FLAG,
            1,
            &p,
        );
        frame(
            &mut input,
            DATA,
            PADDED | END_STREAM,
            1,
            &[2, b'h', b'i', 0, 0],
        );
        s.receive(&input).unwrap();
        let ev = events(&mut s);
        assert!(
            matches!(&ev[0], Event::Headers { fields, .. } if get(fields, ":path").as_deref() == Some("/"))
        );
        assert_eq!(
            ev[1],
            Event::Data {
                stream: 1,
                data: b"hi".to_vec(),
                end_stream: true
            }
        );
    }

    #[test]
    fn resets_reach_the_other_side() {
        let (mut c, mut s) = (Connection::client(), Connection::server());
        let id = c.open();
        c.send_headers(id, &[(":method", "GET")], false);
        pump(&mut c, &mut s);
        events(&mut s);
        s.reset(1, code::CANCEL);
        pump(&mut c, &mut s);
        assert_eq!(
            events(&mut c),
            [Event::Reset {
                stream: 1,
                code: code::CANCEL
            }]
        );
        assert!(!c.send_data(1, b"late", true));
    }
}
