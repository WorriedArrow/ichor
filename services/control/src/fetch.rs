//! One HTTP GET, without blocking: resolve the host (DNS over UDP to the
//! configured resolver), connect over TCP on the system cell's stack,
//! speak TLS (verified against the boot volume's roots) or plain HTTP,
//! and parse the response. The registry protocol (`oci::Puller`) asks for
//! these one at a time.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use http::{Request, Response, ResponseParser};
use rt::{Error, Handle, WaitItem};

/// Largest response body (a layer blob).
const MAX_BODY: usize = 512 << 20;
/// Left for everything else while a response comes.
const SPARE: usize = 16 << 20;
/// Give up on a request when nothing has come for this long, or after this
/// long in all (a large layer on a slow link takes a while; a server that
/// trickles bytes must not hold a pull forever).
const SILENCE_NS: u64 = 120_000_000_000;
const TIMEOUT_NS: u64 = 3_600_000_000_000;
/// How often a request whose connection failed is made anew.
const RETRIES: u32 = 3;
/// Resend an unanswered DNS query after this long.
const DNS_RETRY_NS: u64 = 2_000_000_000;

/// What every fetch shares: the resolver, its cache, the roots.
#[derive(Debug)]
pub(crate) struct Net {
    pub(crate) resolver: [u8; 4],
    pub(crate) roots: Arc<x509::RootStore>,
    cache: BTreeMap<String, [u8; 4]>,
    next_id: u16,
}

impl Net {
    pub(crate) fn new(resolver: [u8; 4], roots: Arc<x509::RootStore>) -> Net {
        let mut id = [0u8; 2];
        rt::random(&mut id);
        Net {
            resolver,
            roots,
            cache: BTreeMap::new(),
            next_id: u16::from_le_bytes(id),
        }
    }
}

enum Stage {
    Resolve {
        sock: Handle,
        id: u16,
        sent: u64,
        tries: u32,
    },
    Connect {
        sock: Handle,
    },
    Tls {
        sock: Handle,
        tls: Box<tls::Client>,
    },
    Plain {
        sock: Handle,
    },
    /// Between stages (while moving a socket from one to the next).
    Idle,
}

/// A request in flight.
pub(crate) struct Fetch {
    req: Request,
    stage: Stage,
    parser: ResponseParser,
    /// Bytes for the socket that it has not taken yet.
    out: Vec<u8>,
    started: u64,
    /// When the server last sent anything.
    heard: u64,
    /// How often this was started anew.
    again: u32,
    /// When the name resolved, the connection was made and the first byte
    /// came back (0: not yet), for [`Fetch::timings`].
    resolved: u64,
    connected: u64,
    first: u64,
}

/// Why a try failed.
enum Fault {
    /// The connection did: another may do better.
    Connection(String),
    Final(String),
}

impl From<String> for Fault {
    fn from(text: String) -> Fault {
        Fault::Final(text)
    }
}

impl core::fmt::Debug for Fetch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fetch({}{})", self.req.url.host, self.req.url.path)
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for o in &mut out {
        *o = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

impl Fetch {
    pub(crate) fn start(req: Request, net: &mut Net) -> Result<Fetch, String> {
        let host = req.url.host.clone();
        let now = rt::monotonic();
        let mut resolved = 0;
        let stage = match parse_ipv4(&host).or_else(|| net.cache.get(&host).copied()) {
            Some(ip) => {
                resolved = now;
                connect(ip, req.url.port)?
            }
            None => {
                let sock = rt::udp_bind(0).map_err(|e| format!("UDP socket: {e:?}"))?;
                net.next_id = net.next_id.wrapping_add(1);
                let id = net.next_id;
                let q =
                    dns::query(id, &host).map_err(|e| format!("DNS query for {host}: {e:?}"))?;
                rt::udp_send(&sock, &q, net.resolver, 53)
                    .map_err(|e| format!("DNS send: {e:?}"))?;
                Stage::Resolve {
                    sock,
                    id,
                    sent: rt::monotonic(),
                    tries: 1,
                }
            }
        };
        Ok(Fetch {
            req,
            stage,
            parser: ResponseParser::new(MAX_BODY),
            out: Vec::new(),
            started: now,
            heard: now,
            again: 0,
            resolved,
            connected: 0,
            first: 0,
        })
    }

    /// Where the time went, for the log: name, connection, first byte
    /// (TLS handshake and the server's answer) and the rest, in ms.
    pub(crate) fn timings(&self) -> String {
        let ms = |a: u64, b: u64| {
            if a == 0 || b < a {
                0
            } else {
                (b - a) / 1_000_000
            }
        };
        let done = rt::monotonic();
        format!(
            "{} at {} ms since boot: dns {} ms, tcp {} ms, first byte {} ms, body {} ms{}",
            self.req.url.host,
            self.started / 1_000_000,
            ms(self.started, self.resolved),
            ms(self.resolved, self.connected),
            ms(self.connected, self.first),
            ms(self.first, done),
            if self.again > 0 {
                format!(", {} retries", self.again)
            } else {
                String::new()
            }
        )
    }

    /// What to wait for.
    pub(crate) fn wait_item(&self) -> Option<WaitItem> {
        let (sock, events) = match &self.stage {
            Stage::Resolve { sock, .. } => (sock, rt::READABLE),
            Stage::Connect { sock } => (sock, rt::WRITABLE),
            Stage::Tls { sock, .. } | Stage::Plain { sock } => {
                let w = if self.out.is_empty() { 0 } else { rt::WRITABLE };
                (sock, rt::READABLE | w)
            }
            Stage::Idle => return None,
        };
        Some(WaitItem {
            handle: sock.raw(),
            events,
            revents: 0,
        })
    }

    /// Makes what progress it can; the response once it is complete. What
    /// a lost connection cut off is asked for again (it is always a GET).
    pub(crate) fn advance(&mut self, net: &mut Net) -> Result<Option<Response>, String> {
        match self.progress(net) {
            Ok(r) => Ok(r),
            Err(Fault::Connection(why)) if self.again < RETRIES => {
                rt::log!("control: {why}; trying again");
                net.cache.remove(&self.req.url.host);
                *self = Fetch {
                    started: self.started,
                    again: self.again + 1,
                    ..Fetch::start(self.req.clone(), net)?
                };
                Ok(None)
            }
            Err(Fault::Connection(why) | Fault::Final(why)) => Err(why),
        }
    }

    fn progress(&mut self, net: &mut Net) -> Result<Option<Response>, Fault> {
        let now = rt::monotonic();
        let timed_out = || format!("{} timed out", self.req.url.host);
        if now - self.started > TIMEOUT_NS {
            return Err(Fault::Final(timed_out()));
        }
        if now - self.heard > SILENCE_NS {
            return Err(Fault::Connection(timed_out()));
        }
        loop {
            match &mut self.stage {
                Stage::Resolve {
                    sock,
                    id,
                    sent,
                    tries,
                } => {
                    let mut buf = [0u8; 1500];
                    match rt::udp_recv(sock, &mut buf) {
                        Ok((n, from, 53)) if from == net.resolver => {
                            let host = &self.req.url.host;
                            match dns::parse_a(&buf[..n], *id, host) {
                                Ok(ips) if !ips.is_empty() => {
                                    net.cache.insert(host.clone(), ips[0]);
                                    self.resolved = now;
                                    self.stage = connect(ips[0], self.req.url.port)?;
                                }
                                Err(dns::Error::Mismatch) => {}
                                r => return Err(format!("DNS for {host}: {r:?}").into()),
                            }
                        }
                        Ok(_) => {}
                        Err(Error::WouldBlock) => {
                            if now - *sent < DNS_RETRY_NS {
                                return Ok(None);
                            }
                            if *tries >= 4 {
                                return Err(
                                    format!("no DNS answer for {}", self.req.url.host).into()
                                );
                            }
                            let q = dns::query(*id, &self.req.url.host)
                                .map_err(|e| format!("{e:?}"))?;
                            let _ = rt::udp_send(sock, &q, net.resolver, 53);
                            (*sent, *tries) = (now, *tries + 1);
                            return Ok(None);
                        }
                        Err(e) => return Err(format!("DNS receive: {e:?}").into()),
                    }
                }
                Stage::Connect { sock } => match rt::sock_error(sock) {
                    Ok(()) => {
                        self.connected = rt::monotonic();
                        // Move the socket on (never a stand-in handle: a
                        // dropped one would close whatever it named).
                        let Stage::Connect { sock } =
                            core::mem::replace(&mut self.stage, Stage::Idle)
                        else {
                            return Ok(None);
                        };
                        let request = self.req.encode();
                        if self.req.url.is_https() {
                            let mut random = [0u8; 128];
                            rt::random(&mut random);
                            let mut tls = Box::new(tls::Client::new(tls::Config {
                                host: self.req.url.host.clone(),
                                roots: net.roots.clone(),
                                now: rt::realtime() / 1_000_000_000,
                                random,
                                ed25519: false,
                                alpn: None,
                            }));
                            tls.write(&request);
                            self.out.extend(tls.take_output());
                            self.stage = Stage::Tls { sock, tls };
                        } else {
                            self.out.extend(request);
                            self.stage = Stage::Plain { sock };
                        }
                    }
                    Err(Error::WouldBlock) => return Ok(None),
                    Err(e) => {
                        let why = format!("connecting to {}: {e:?}", self.req.url.host);
                        return Err(Fault::Connection(why));
                    }
                },
                Stage::Tls { .. } | Stage::Plain { .. } => return self.exchange(),
                Stage::Idle => return Ok(None),
            }
        }
    }

    fn exchange(&mut self) -> Result<Option<Response>, Fault> {
        let (sock, mut tls) = match &mut self.stage {
            Stage::Tls { sock, tls } => (&*sock, Some(tls)),
            Stage::Plain { sock } => (&*sock, None),
            _ => return Ok(None),
        };
        let host = &self.req.url.host;
        let mut buf = alloc::vec![0u8; 64 * 1024];
        loop {
            // Send what the socket takes.
            while !self.out.is_empty() {
                match rt::send(sock, &self.out) {
                    Ok(n) => {
                        self.out.drain(..n);
                    }
                    Err(Error::WouldBlock) => break,
                    Err(e) => {
                        return Err(Fault::Connection(format!("sending to {host}: {e:?}")));
                    }
                }
            }
            let (data, eof) = match rt::recv(sock, &mut buf) {
                Ok(0) => (Vec::new(), true),
                Ok(n) => {
                    self.heard = rt::monotonic();
                    if self.first == 0 {
                        self.first = self.heard;
                    }
                    (buf[..n].to_vec(), false)
                }
                Err(Error::WouldBlock) => return Ok(None),
                Err(e) => return Err(Fault::Connection(format!("receiving from {host}: {e:?}"))),
            };
            let mut closed = eof;
            let plain = match tls.as_mut() {
                Some(t) => {
                    match t.feed(&data) {
                        Ok(()) => {}
                        Err(tls::Error::Closed) => closed = true,
                        Err(e) => return Err(format!("TLS with {host}: {e:?}").into()),
                    }
                    self.out.extend(t.take_output());
                    t.read()
                }
                None => data,
            };
            if let Some(resp) = self
                .parser
                .feed(&plain)
                .map_err(|e| format!("HTTP from {host}: {e:?}"))?
            {
                return Ok(Some(resp));
            }
            // What does not fit in memory would end the control plane.
            let wants = self.parser.wants();
            if rt::memory_available() < wants.saturating_add(SPARE) {
                return Err(format!(
                    "a response of {host} ({} KiB more) does not fit in memory",
                    wants / 1024
                )
                .into());
            }
            if closed {
                return self
                    .parser
                    .eof()
                    .map(Some)
                    .map_err(|e| Fault::Connection(format!("{host} closed early: {e:?}")));
            }
        }
    }
}

fn connect(ip: [u8; 4], port: u16) -> Result<Stage, String> {
    rt::tcp_connect(ip, port)
        .map(|sock| Stage::Connect { sock })
        .map_err(|e| format!("TCP_CONNECT {ip:?}:{port}: {e:?}"))
}
