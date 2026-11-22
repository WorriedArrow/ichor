//! TCP (RFC 9293), sans-I/O: one [`Tcp`] is one connection's state
//! machine. Feed it segments ([`Tcp::on_segment`]) and the time
//! ([`Tcp::poll`]); take segments to send from [`Tcp::transmit`]; move
//! bytes with [`Tcp::send`] and [`Tcp::recv`]. Listening (turning a SYN
//! into a connection) is the stack's job: [`Tcp::accept`] starts the
//! passive side from a received SYN.
//!
//! Implemented: all eleven states including simultaneous open and close;
//! sequence arithmetic modulo 2^32; RST and SYN acceptance with challenge
//! ACKs (RFC 5961); MSS and window scaling (RFC 7323); retransmission
//! timeouts with RTT estimation and Karn's rule (RFC 6298); NewReno
//! congestion control with fast retransmit and recovery (RFC 5681, 6582);
//! out-of-order reassembly; zero-window probes; TIME_WAIT. Not yet: SACK,
//! timestamps, delayed ACKs (every data segment is acknowledged at once).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::time::Duration;

use crate::Ipv4Addr;
use crate::wire::{PROTO_TCP, fold, pseudo_header, sum};

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// Our maximum segment size (a 1500-byte MTU less 40 bytes of headers).
pub const MSS: u16 = 1460;
/// Window-scale shift we offer: windows up to 65535 << 7 (8 MiB).
const OUR_WSCALE: u8 = 7;
/// Bytes each direction buffers.
pub const BUFFER: usize = 256 * 1024;
/// Most out-of-order bytes held for reassembly.
const OOO_MAX: usize = BUFFER;
const RTO_MIN: Duration = Duration::from_millis(200);
const RTO_MAX: Duration = Duration::from_secs(60);
const RTO_INITIAL: Duration = Duration::from_secs(1);
/// Retransmissions of one segment before the connection is abandoned.
const MAX_RETRIES: u32 = 12;
/// TIME_WAIT's length (Linux's 60 s, which is 2 MSL there).
pub const TIME_WAIT: Duration = Duration::from_secs(60);

/// `a < b` in sequence space.
fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn le(a: u32, b: u32) -> bool {
    a == b || lt(a, b)
}

/// A parsed TCP segment (checksum verified).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// Parses `b`, an IPv4 payload from `src` to `dst`.
    pub fn parse(b: &'a [u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<Segment<'a>> {
        if b.len() < 20 {
            return None;
        }
        let off = usize::from(b[12] >> 4) * 4;
        if off < 20 || off > b.len() {
            return None;
        }
        if fold(sum(pseudo_header(src, dst, PROTO_TCP, b.len()), b)) != 0 {
            return None;
        }
        let mut s = Segment {
            src_port: u16::from_be_bytes([b[0], b[1]]),
            dst_port: u16::from_be_bytes([b[2], b[3]]),
            seq: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            ack: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            flags: b[13],
            window: u16::from_be_bytes([b[14], b[15]]),
            mss: None,
            wscale: None,
            payload: &b[off..],
        };
        // Options: kind, len, data; 0 ends, 1 pads.
        let mut opts = &b[20..off];
        while let [kind, rest @ ..] = opts {
            match kind {
                0 => break,
                1 => opts = rest,
                _ => {
                    let len = usize::from(*rest.first()?);
                    if len < 2 || len > opts.len() {
                        return None;
                    }
                    let data = &opts[2..len];
                    match (kind, data) {
                        (2, [a, b]) => s.mss = Some(u16::from_be_bytes([*a, *b])),
                        (3, [shift]) => s.wscale = Some((*shift).min(14)),
                        _ => {}
                    }
                    opts = &opts[len..];
                }
            }
        }
        Some(s)
    }

    /// The sequence space this segment occupies (SYN and FIN count one).
    pub fn len(&self) -> u32 {
        self.payload.len() as u32
            + u32::from(self.flags & SYN != 0)
            + u32::from(self.flags & FIN != 0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Builds a TCP segment with its checksum.
#[allow(clippy::too_many_arguments)] // one per header field
pub fn segment(
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    syn_options: Option<(u16, u8)>,
    payload: &[u8],
) -> Vec<u8> {
    let opt_len = if syn_options.is_some() { 8 } else { 0 };
    let mut b = Vec::with_capacity(20 + opt_len + payload.len());
    b.extend_from_slice(&src.1.to_be_bytes());
    b.extend_from_slice(&dst.1.to_be_bytes());
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&ack.to_be_bytes());
    b.push((((20 + opt_len) / 4) as u8) << 4);
    b.push(flags);
    b.extend_from_slice(&window.to_be_bytes());
    b.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
    if let Some((mss, ws)) = syn_options {
        b.extend_from_slice(&[2, 4]);
        b.extend_from_slice(&mss.to_be_bytes());
        b.extend_from_slice(&[1, 3, 3, ws]); // NOP, window scale
    }
    b.extend_from_slice(payload);
    let c = fold(sum(pseudo_header(src.0, dst.0, PROTO_TCP, b.len()), &b));
    b[16..18].copy_from_slice(&c.to_be_bytes());
    b
}

/// A connection's state (RFC 9293 §3.3.2; LISTEN lives in the stack).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

/// Why a connection ended abnormally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The peer refused (RST to our SYN): ECONNREFUSED.
    Refused,
    /// The peer reset an open connection: ECONNRESET.
    Reset,
    /// Retransmissions gave up: ETIMEDOUT.
    TimedOut,
}

/// One TCP connection.
#[derive(Debug)]
pub struct Tcp {
    pub local: (Ipv4Addr, u16),
    pub remote: (Ipv4Addr, u16),
    state: State,
    error: Option<Error>,
    // Send side.
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence sent so far (for retransmission after a rewind).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    snd_shift: u8,
    peer_mss: u16,
    /// Bytes from `buf_seq` on: sent-but-unacknowledged, then unsent.
    send_buf: VecDeque<u8>,
    /// Sequence number of `send_buf[0]`.
    buf_seq: u32,
    /// The application closed its side: send FIN after the data.
    fin_queued: bool,
    /// How many bytes each buffer may hold (at most [`BUFFER`]); the owner
    /// lowers it when the memory it charges for buffers runs short.
    cap: usize,
    /// [`Tcp::discard_received`] was called.
    discarding: bool,
    // Receive side.
    irs: u32,
    rcv_nxt: u32,
    rcv_shift: u8,
    /// Where the window we last told the peer of ends.
    told_edge: u32,
    recv_buf: VecDeque<u8>,
    ooo: BTreeMap<u32, Vec<u8>>,
    ooo_bytes: usize,
    peer_fin: bool,
    // Timers and congestion control.
    rto: Duration,
    srtt: Option<Duration>,
    rttvar: Duration,
    /// The segment being timed: (end sequence, sent at).
    rtt_probe: Option<(u32, Duration)>,
    retransmit_at: Option<Duration>,
    retries: u32,
    time_wait_until: Option<Duration>,
    cwnd: u32,
    ssthresh: u32,
    dupacks: u32,
    /// NewReno: recovery ends when this is acknowledged.
    recover: Option<u32>,
    /// An ACK (or a segment carrying one) is owed.
    ack_now: bool,
    /// A SYN (or SYN-ACK) must be (re)sent.
    syn_pending: bool,
    out: VecDeque<Vec<u8>>,
}

impl Tcp {
    fn new(local: (Ipv4Addr, u16), remote: (Ipv4Addr, u16), iss: u32, state: State) -> Tcp {
        Tcp {
            local,
            remote,
            state,
            error: None,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            snd_shift: 0,
            peer_mss: 536,
            send_buf: VecDeque::new(),
            buf_seq: iss.wrapping_add(1),
            fin_queued: false,
            cap: BUFFER,
            discarding: false,
            irs: 0,
            rcv_nxt: 0,
            rcv_shift: 0,
            told_edge: 0,
            recv_buf: VecDeque::new(),
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
            peer_fin: false,
            rto: RTO_INITIAL,
            srtt: None,
            rttvar: Duration::ZERO,
            rtt_probe: None,
            retransmit_at: None,
            retries: 0,
            time_wait_until: None,
            cwnd: 0,
            ssthresh: u32::MAX,
            dupacks: 0,
            recover: None,
            ack_now: false,
            syn_pending: true,
            out: VecDeque::new(),
        }
    }

    /// An active open: sends a SYN.
    pub fn connect(
        local: (Ipv4Addr, u16),
        remote: (Ipv4Addr, u16),
        iss: u32,
        now: Duration,
    ) -> Tcp {
        let mut t = Tcp::new(local, remote, iss, State::SynSent);
        t.output(now);
        t
    }

    /// A passive open from a SYN that a listener received: answers it with
    /// a SYN-ACK.
    pub fn accept(
        local: (Ipv4Addr, u16),
        remote: (Ipv4Addr, u16),
        syn: &Segment<'_>,
        iss: u32,
        now: Duration,
    ) -> Tcp {
        let mut t = Tcp::new(local, remote, iss, State::SynReceived);
        t.take_syn(syn);
        t.output(now);
        t
    }

    /// Records the peer's SYN: its sequence start and options.
    fn take_syn(&mut self, syn: &Segment<'_>) {
        self.irs = syn.seq;
        self.rcv_nxt = syn.seq.wrapping_add(1);
        self.peer_mss = syn.mss.unwrap_or(536).clamp(64, MSS);
        if let Some(ws) = syn.wscale {
            self.snd_shift = ws;
            self.rcv_shift = OUR_WSCALE;
        }
        // The SYN's window is never scaled.
        self.snd_wnd = u32::from(syn.window);
        self.snd_wl1 = syn.seq;
        self.cwnd = 10 * u32::from(self.peer_mss); // RFC 6928
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn error(&self) -> Option<Error> {
        self.error
    }

    /// Bytes ready to read.
    pub fn readable(&self) -> usize {
        self.recv_buf.len()
    }

    /// Whether the peer has finished sending (reads past the data see EOF).
    pub fn peer_closed(&self) -> bool {
        self.peer_fin
    }

    /// Room in the send buffer (0 once our side is closed).
    pub fn writable(&self) -> usize {
        if self.fin_queued || !self.can_send() {
            0
        } else {
            self.cap.saturating_sub(self.send_buf.len())
        }
    }

    /// Bytes the connection holds in memory: received, out of order, and
    /// sent but not yet acknowledged or not yet sent.
    pub fn buffered(&self) -> usize {
        self.recv_buf.len() + self.ooo_bytes + self.send_buf.len()
    }

    /// Lets each buffer hold up to `cap` bytes (clamped to [`BUFFER`]).
    /// Lowering it keeps what is buffered but stops growth: the window
    /// closes and writes find no room. Raising it announces a window that
    /// reopens.
    pub fn set_cap(&mut self, cap: usize, now: Duration) {
        self.cap = cap.min(BUFFER);
        self.announce_window(now);
    }

    /// Tells the peer of a window that has grown by two segments (or half
    /// the buffer) past what it was last told (RFC 9293 §3.8.6.2.2). Until
    /// then it may be waiting for that: a sender does not fill a window
    /// with tiny segments, and if nothing more arrives from it, nothing
    /// else would carry the news. Not once it has finished sending (as
    /// Linux, after RCV_SHUTDOWN): nothing more will come, and the peer may
    /// already be gone, so the update would only draw a RST.
    fn announce_window(&mut self, now: Duration) {
        let open = matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        );
        if !open || self.peer_fin {
            return;
        }
        let step = (2 * u32::from(MSS)).min(self.cap as u32 / 2).max(1);
        let grown = self.window_edge().wrapping_sub(self.told_edge);
        if grown >= step && (grown as i32) > 0 {
            self.ack_now = true;
            self.output(now);
        }
    }

    fn can_send(&self) -> bool {
        matches!(
            self.state,
            State::SynSent | State::SynReceived | State::Established | State::CloseWait
        )
    }

    /// Whether the connection is fully gone (closed, reset, or timed out).
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Queues bytes to send; returns how many fit.
    pub fn send(&mut self, data: &[u8], now: Duration) -> usize {
        let n = data.len().min(self.writable());
        self.send_buf.extend(&data[..n]);
        self.output(now);
        n
    }

    /// Reads received bytes into `out`.
    pub fn recv(&mut self, out: &mut [u8], now: Duration) -> usize {
        let n = out.len().min(self.recv_buf.len());
        for (o, b) in out.iter_mut().zip(self.recv_buf.drain(..n)) {
            *o = b;
        }
        if n > 0 {
            self.announce_window(now);
        }
        n
    }

    /// Copies received bytes into `out`, leaving them to be read.
    pub fn peek(&self, out: &mut [u8]) -> usize {
        for (o, b) in out.iter_mut().zip(&self.recv_buf) {
            *o = *b;
        }
        out.len().min(self.recv_buf.len())
    }

    /// The application is gone: drops what it never read, and answers any
    /// new data with RST (Linux, closing a socket, does both).
    pub fn discard_received(&mut self) {
        self.recv_buf.clear();
        self.ooo.clear();
        self.ooo_bytes = 0;
        self.discarding = true;
    }

    /// Closes our side (FIN after the queued data).
    pub fn close(&mut self, now: Duration) {
        match self.state {
            State::SynSent => self.state = State::Closed,
            State::SynReceived | State::Established | State::CloseWait => {
                self.fin_queued = true;
                self.output(now);
            }
            _ => {}
        }
    }

    /// Aborts: sends RST and forgets the connection.
    pub fn abort(&mut self) {
        if matches!(
            self.state,
            State::SynReceived
                | State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
        ) {
            let seg = self.segment(self.snd_nxt, RST | ACK, &[], false);
            self.out.push_back(seg);
        }
        self.state = State::Closed;
    }

    /// The next segment to send (a TCP header and payload for
    /// `self.remote`).
    pub fn transmit(&mut self) -> Option<Vec<u8>> {
        self.out.pop_front()
    }

    fn rcv_window(&self) -> u32 {
        self.cap.saturating_sub(self.recv_buf.len()) as u32
    }

    fn window_field(&self) -> u16 {
        u16::try_from(self.rcv_window() >> self.rcv_shift).unwrap_or(u16::MAX)
    }

    /// Where the window we would advertise now ends.
    fn window_edge(&self) -> u32 {
        self.rcv_nxt
            .wrapping_add(u32::from(self.window_field()) << self.rcv_shift)
    }

    fn segment(&mut self, seq: u32, flags: u8, payload: &[u8], syn: bool) -> Vec<u8> {
        let ack = if flags & ACK != 0 { self.rcv_nxt } else { 0 };
        let window = if syn {
            // The SYN's window is never scaled.
            u16::try_from(self.rcv_window()).unwrap_or(u16::MAX)
        } else {
            self.window_field()
        };
        if flags & ACK != 0 {
            self.told_edge = if syn {
                self.rcv_nxt.wrapping_add(u32::from(window))
            } else {
                self.window_edge()
            };
        }
        let opts = syn.then_some((MSS, OUR_WSCALE));
        segment(
            self.local,
            self.remote,
            seq,
            ack,
            flags,
            window,
            opts,
            payload,
        )
    }

    fn fin_seq(&self) -> u32 {
        self.buf_seq.wrapping_add(self.send_buf.len() as u32)
    }

    fn arm_retransmit(&mut self, now: Duration) {
        if self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + self.rto);
        }
    }

    /// Emits whatever can be sent now: a SYN, data within the windows, a
    /// FIN, or a bare ACK if one is owed.
    fn output(&mut self, now: Duration) {
        if self.state == State::Closed {
            return;
        }
        if self.syn_pending && matches!(self.state, State::SynSent | State::SynReceived) {
            let flags = if self.state == State::SynSent {
                SYN
            } else {
                SYN | ACK
            };
            let seg = self.segment(self.iss, flags, &[], true);
            self.out.push_back(seg);
            self.syn_pending = false;
            self.snd_nxt = self.iss.wrapping_add(1);
            self.snd_max = seq_max(self.snd_max, self.snd_nxt);
            self.ack_now = false;
            self.arm_retransmit(now);
            return;
        }
        if matches!(self.state, State::SynSent | State::SynReceived) {
            return; // data waits for the handshake
        }
        let mut sent_any = false;
        let window = self.snd_wnd.min(self.cwnd.max(u32::from(self.peer_mss)));
        loop {
            let flight = self.snd_nxt.wrapping_sub(self.snd_una);
            let off = self.snd_nxt.wrapping_sub(self.buf_seq) as usize;
            let unsent = self.send_buf.len().saturating_sub(off);
            let room = window.saturating_sub(flight) as usize;
            let n = unsent.min(room).min(usize::from(self.peer_mss));
            if n > 0 {
                let data: Vec<u8> = self.send_buf.range(off..off + n).copied().collect();
                let last = off + n == self.send_buf.len();
                let mut flags = ACK | if last { PSH } else { 0 };
                // The FIN rides on the last data segment (it needs no window).
                let fin_now = last && self.fin_queued;
                if fin_now {
                    flags |= FIN;
                }
                let seg = self.segment(self.snd_nxt, flags, &data, false);
                self.out.push_back(seg);
                if self.rtt_probe.is_none() && !lt(self.snd_nxt, self.snd_max) {
                    self.rtt_probe = Some((self.snd_nxt.wrapping_add(n as u32), now));
                }
                self.snd_nxt = self.snd_nxt.wrapping_add(n as u32 + u32::from(fin_now));
                self.snd_max = seq_max(self.snd_max, self.snd_nxt);
                if fin_now {
                    self.enter_fin_sent();
                }
                sent_any = true;
                self.arm_retransmit(now);
                continue;
            }
            // A FIN with no data left to send (first time, or again after a
            // timeout rewound snd_nxt).
            if unsent == 0
                && self.fin_queued
                && self.snd_nxt == self.fin_seq()
                && matches!(
                    self.state,
                    State::Established
                        | State::CloseWait
                        | State::FinWait1
                        | State::Closing
                        | State::LastAck
                )
            {
                let seg = self.segment(self.snd_nxt, FIN | ACK, &[], false);
                self.out.push_back(seg);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                self.snd_max = seq_max(self.snd_max, self.snd_nxt);
                self.enter_fin_sent();
                sent_any = true;
                self.arm_retransmit(now);
            }
            break;
        }
        // Zero window with data waiting and nothing in flight: probe later.
        if self.snd_wnd == 0
            && self.send_buf.len() > self.snd_nxt.wrapping_sub(self.buf_seq) as usize
        {
            self.arm_retransmit(now);
        }
        if !sent_any && self.ack_now {
            let seg = self.segment(self.ack_seq(), ACK, &[], false);
            self.out.push_back(seg);
        }
        self.ack_now = false;
    }

    /// The sequence number of a bare ACK: past everything sent (not where a
    /// retransmission has gone back to), but within the peer's window, so
    /// that the peer takes it.
    fn ack_seq(&self) -> u32 {
        let end = self.snd_una.wrapping_add(self.snd_wnd);
        if lt(end, self.snd_max) {
            end
        } else {
            self.snd_max
        }
    }

    fn enter_fin_sent(&mut self) {
        self.state = match self.state {
            State::Established => State::FinWait1,
            State::CloseWait => State::LastAck,
            s => s,
        };
    }

    fn reset(&mut self, e: Error) {
        self.error = Some(e);
        self.state = State::Closed;
        self.out.clear();
    }

    /// Takes an incoming segment for this connection.
    pub fn on_segment(&mut self, seg: &Segment<'_>, now: Duration) {
        match self.state {
            State::Closed => {}
            State::SynSent => self.on_syn_sent(seg),
            _ => self.on_synchronized(seg, now),
        }
        self.output(now);
    }

    fn on_syn_sent(&mut self, seg: &Segment<'_>) {
        let acceptable_ack =
            seg.flags & ACK != 0 && lt(self.iss, seg.ack) && le(seg.ack, self.snd_nxt);
        if seg.flags & ACK != 0 && !acceptable_ack {
            if seg.flags & RST == 0 {
                let rst = segment(self.local, self.remote, seg.ack, 0, RST, 0, None, &[]);
                self.out.push_back(rst);
            }
            return;
        }
        if seg.flags & RST != 0 {
            if acceptable_ack {
                self.reset(Error::Refused);
            }
            return;
        }
        if seg.flags & SYN == 0 {
            return;
        }
        self.take_syn(seg);
        if acceptable_ack {
            self.snd_una = seg.ack;
            self.snd_wl2 = seg.ack;
            self.retransmit_at = None;
            self.retries = 0;
            self.state = State::Established;
            self.ack_now = true;
        } else {
            // Simultaneous open: answer with SYN-ACK.
            self.state = State::SynReceived;
            self.syn_pending = true;
            self.retransmit_at = None;
        }
    }

    fn on_synchronized(&mut self, seg: &Segment<'_>, now: Duration) {
        // 1. Sequence acceptability (RFC 9293 §3.10.7.4).
        let wnd = self.rcv_window();
        let len = seg.len();
        let start = seg.seq;
        let end = seg.seq.wrapping_add(len.max(1)).wrapping_sub(1);
        let in_window = |s: u32| le(self.rcv_nxt, s) && lt(s, self.rcv_nxt.wrapping_add(wnd));
        // What carries nothing may also be at the window's edge, as a peer
        // that has filled the window sends it, or (for a peer that counts
        // its zero-window probe) one past a closed one. Else the ACKs of a
        // peer we have stopped reading from would be lost, and what we send
        // it with them.
        let told = self.told_edge;
        let edge = seq_max(self.rcv_nxt.wrapping_add(wnd), told);
        let edge = if wnd == 0 { edge.wrapping_add(1) } else { edge };
        let at_edge = le(self.rcv_nxt, start) && le(start, edge);
        let acceptable = match (len, wnd) {
            (0, _) if seg.flags & RST == 0 => at_edge,
            (0, 0) => seg.seq == self.rcv_nxt,
            // A bare FIN at rcv_nxt needs no window (Linux takes it too),
            // so a reader with a full buffer still learns of the end.
            (_, 0) if seg.payload.is_empty() && seg.flags & FIN != 0 => seg.seq == self.rcv_nxt,
            (0, _) => in_window(start),
            (_, 0) => false,
            _ => in_window(start) || in_window(end),
        };
        // Data with no window for it: the ACK it carries counts all the
        // same (RFC 9293 asks for that), and it is answered with one.
        let only_ack = !acceptable
            && wnd == 0
            && at_edge
            && !seg.payload.is_empty()
            && seg.flags & (SYN | RST) == 0;
        if !acceptable {
            if seg.flags & RST == 0 {
                self.ack_now = true;
            }
            if !only_ack {
                return;
            }
        }
        // 2. RST: exact match resets, otherwise a challenge ACK (RFC 5961).
        if seg.flags & RST != 0 {
            if seg.seq == self.rcv_nxt && self.state == State::TimeWait {
                // Both sides have finished: the connection ends early, and
                // the reader still sees its data and EOF, as on Linux,
                // where TIME_WAIT is no longer the application's socket.
                self.state = State::Closed;
                self.time_wait_until = None;
            } else if seg.seq == self.rcv_nxt {
                let e = if self.state == State::SynReceived {
                    Error::Refused
                } else {
                    Error::Reset
                };
                self.reset(e);
            } else {
                self.ack_now = true;
            }
            return;
        }
        // 3. A SYN on a synchronized connection: challenge ACK.
        if seg.flags & SYN != 0 {
            self.ack_now = true;
            return;
        }
        // 4. ACK processing.
        if seg.flags & ACK == 0 {
            return;
        }
        if self.state == State::SynReceived {
            if lt(self.snd_una, seg.ack) && le(seg.ack, self.snd_nxt) {
                self.state = State::Established;
                self.snd_wnd = u32::from(seg.window) << self.snd_shift;
                self.snd_wl1 = seg.seq;
                self.snd_wl2 = seg.ack;
            } else {
                let rst = segment(self.local, self.remote, seg.ack, 0, RST, 0, None, &[]);
                self.out.push_back(rst);
                return;
            }
        }
        if lt(self.snd_max, seg.ack) {
            self.ack_now = true; // acknowledges something never sent
            return;
        }
        self.on_ack(seg, now);
        if self.state == State::Closed || only_ack {
            return;
        }
        // 5. Data and FIN. New data for an application that has gone away
        // is answered with RST, as Linux does after close().
        if self.discarding && lt(self.rcv_nxt, seg.seq.wrapping_add(seg.payload.len() as u32)) {
            self.abort();
            self.error = Some(Error::Reset);
            return;
        }
        if matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            self.take_data(seg);
        }
        if seg.flags & FIN != 0 && seg.seq.wrapping_add(seg.payload.len() as u32) == self.rcv_nxt {
            self.on_fin(now);
        } else if seg.flags & FIN != 0 {
            self.ack_now = true; // a FIN past a gap: wait for the data
        }
    }

    fn on_ack(&mut self, seg: &Segment<'_>, now: Duration) {
        let ack = seg.ack;
        let window = u32::from(seg.window) << self.snd_shift;
        if lt(self.snd_una, ack) {
            let acked = ack.wrapping_sub(self.snd_una);
            // Bytes leave the buffer; SYN and FIN occupy no buffer bytes.
            let data_acked = ack
                .wrapping_sub(self.buf_seq)
                .min(self.send_buf.len() as u32);
            if lt(self.buf_seq, ack) {
                self.send_buf.drain(..data_acked as usize);
                self.buf_seq = self.buf_seq.wrapping_add(data_acked);
            }
            self.snd_una = ack;
            if lt(self.snd_nxt, ack) {
                self.snd_nxt = ack;
            }
            self.retries = 0;
            // RTT sample (Karn: only segments never retransmitted).
            if let Some((end, at)) = self.rtt_probe
                && le(end, ack)
            {
                self.rtt_probe = None;
                self.update_rtt(now.saturating_sub(at));
            }
            // Congestion control.
            match self.recover {
                Some(r) if lt(ack, r) => {
                    // Partial ACK: retransmit the next hole, deflate.
                    self.retransmit_one(now);
                    self.cwnd = self
                        .cwnd
                        .saturating_sub(acked)
                        .max(u32::from(self.peer_mss))
                        + u32::from(self.peer_mss);
                }
                Some(_) => {
                    self.recover = None;
                    self.cwnd = self.ssthresh;
                }
                None => {
                    let mss = u32::from(self.peer_mss);
                    if self.cwnd < self.ssthresh {
                        self.cwnd = self.cwnd.saturating_add(acked.min(mss));
                    } else {
                        self.cwnd = self
                            .cwnd
                            .saturating_add((mss * mss / self.cwnd.max(1)).max(1));
                    }
                }
            }
            self.dupacks = 0;
            self.retransmit_at = if self.snd_una == self.snd_max {
                None
            } else {
                Some(now + self.rto)
            };
            // Our FIN acknowledged?
            if self.fin_queued && self.snd_una == self.fin_seq().wrapping_add(1) {
                self.state = match self.state {
                    State::FinWait1 => State::FinWait2,
                    State::Closing => {
                        self.time_wait_until = Some(now + TIME_WAIT);
                        State::TimeWait
                    }
                    State::LastAck => State::Closed,
                    s => s,
                };
            }
        } else if ack == self.snd_una && window == 0 {
            // The peer answers our probes: it is alive, keep probing.
            self.retries = 0;
        } else if ack == self.snd_una
            && seg.payload.is_empty()
            && seg.flags & (SYN | FIN) == 0
            && window == self.snd_wnd
            && self.snd_una != self.snd_max
        {
            self.dupacks += 1;
            if self.dupacks == 3 && self.recover.is_none() {
                // Fast retransmit, enter recovery (NewReno).
                let flight = self.snd_max.wrapping_sub(self.snd_una);
                let mss = u32::from(self.peer_mss);
                self.ssthresh = (flight / 2).max(2 * mss);
                self.recover = Some(self.snd_max);
                self.retransmit_one(now);
                self.cwnd = self.ssthresh + 3 * mss;
            } else if self.dupacks > 3 {
                self.cwnd = self.cwnd.saturating_add(u32::from(self.peer_mss));
            }
        }
        // Window update (RFC 9293 §3.10.7.4, SND.WL1/WL2).
        if lt(self.snd_wl1, seg.seq) || (self.snd_wl1 == seg.seq && le(self.snd_wl2, ack)) {
            self.snd_wnd = window;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = ack;
        }
    }

    fn update_rtt(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(s) => {
                let diff = s.abs_diff(r);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.srtt = Some((s * 7 + r) / 8);
            }
        }
        let s = self.srtt.unwrap_or(r);
        self.rto = (s + (self.rttvar * 4).max(Duration::from_millis(10))).clamp(RTO_MIN, RTO_MAX);
    }

    /// Resends one segment at `snd_una` (fast or timeout retransmission).
    fn retransmit_one(&mut self, now: Duration) {
        self.rtt_probe = None; // Karn
        let off = self.snd_una.wrapping_sub(self.buf_seq) as usize;
        let n = self
            .send_buf
            .len()
            .saturating_sub(off)
            .min(usize::from(self.peer_mss));
        let mut flags = ACK;
        let with_fin =
            self.fin_queued && off + n == self.send_buf.len() && lt(self.fin_seq(), self.snd_max);
        if with_fin {
            flags |= FIN;
        }
        if n == 0 && !with_fin {
            return;
        }
        let data: Vec<u8> = self.send_buf.range(off..off + n).copied().collect();
        let seg = self.segment(self.snd_una, flags, &data, false);
        self.out.push_back(seg);
        self.retransmit_at = Some(now + self.rto);
    }

    fn take_data(&mut self, seg: &Segment<'_>) {
        if seg.payload.is_empty() {
            return;
        }
        self.ack_now = true;
        let mut seq = seg.seq;
        let mut data = seg.payload;
        // Trim what we already have.
        if lt(seq, self.rcv_nxt) {
            let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= data.len() {
                return;
            }
            data = &data[skip..];
            seq = self.rcv_nxt;
        }
        let room = self.rcv_window() as usize;
        if seq == self.rcv_nxt {
            let n = data.len().min(room);
            self.recv_buf.extend(&data[..n]);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
            // Fill from the out-of-order store.
            while let Some((&s, _)) = self.ooo.first_key_value() {
                if lt(self.rcv_nxt, s) {
                    break;
                }
                let Some((s, bytes)) = self.ooo.pop_first() else {
                    break;
                };
                self.ooo_bytes -= bytes.len();
                let skip = self.rcv_nxt.wrapping_sub(s) as usize;
                if skip < bytes.len() {
                    let fresh = &bytes[skip..];
                    let n = fresh.len().min(self.rcv_window() as usize);
                    self.recv_buf.extend(&fresh[..n]);
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
                }
            }
        } else if self.ooo_bytes + data.len() <= OOO_MAX && !self.ooo.contains_key(&seq) {
            // Ahead of a gap: keep it (bounded) for when the gap fills.
            let n = data.len().min(room);
            self.ooo.insert(seq, data[..n].to_vec());
            self.ooo_bytes += n;
        }
    }

    fn on_fin(&mut self, now: Duration) {
        if self.peer_fin {
            self.ack_now = true;
            return;
        }
        self.peer_fin = true;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.ack_now = true;
        let our_fin_acked = self.fin_queued && self.snd_una == self.fin_seq().wrapping_add(1);
        self.state = match self.state {
            State::Established | State::SynReceived => State::CloseWait,
            State::FinWait1 if our_fin_acked => {
                self.time_wait_until = Some(now + TIME_WAIT);
                State::TimeWait
            }
            State::FinWait1 => State::Closing,
            State::FinWait2 => {
                self.time_wait_until = Some(now + TIME_WAIT);
                State::TimeWait
            }
            s => s,
        };
    }

    /// Runs the timers: retransmission (with backoff), zero-window probes,
    /// and the end of TIME_WAIT.
    pub fn poll(&mut self, now: Duration) {
        if let Some(t) = self.time_wait_until
            && now >= t
        {
            self.state = State::Closed;
            self.time_wait_until = None;
            return;
        }
        let Some(at) = self.retransmit_at else {
            return;
        };
        if now < at || self.state == State::Closed {
            return;
        }
        self.retries += 1;
        if self.retries > MAX_RETRIES {
            self.reset(Error::TimedOut);
            return;
        }
        self.rto = (self.rto * 2).min(RTO_MAX);
        self.retransmit_at = None;
        match self.state {
            State::SynSent | State::SynReceived => {
                self.syn_pending = true;
            }
            _ if self.snd_wnd == 0
                && self.send_buf.len() > self.snd_una.wrapping_sub(self.buf_seq) as usize =>
            {
                // Zero-window probe: the byte at snd_una, past the closed
                // window. A peer whose window has opened takes and
                // acknowledges it; until then it has not been sent.
                let off = self.snd_una.wrapping_sub(self.buf_seq) as usize;
                if let Some(&b) = self.send_buf.get(off) {
                    let seg = self.segment(self.snd_una, ACK, &[b], false);
                    self.out.push_back(seg);
                    self.snd_max = seq_max(self.snd_max, self.snd_una.wrapping_add(1));
                }
                self.retransmit_at = Some(now + self.rto);
                return;
            }
            _ => {
                // Timeout: collapse the window and go back to snd_una.
                let flight = self.snd_max.wrapping_sub(self.snd_una);
                let mss = u32::from(self.peer_mss);
                self.ssthresh = (flight / 2).max(2 * mss);
                self.cwnd = mss;
                self.recover = None;
                self.dupacks = 0;
                self.rtt_probe = None;
                // Go back to the oldest unacknowledged byte; output() sends
                // the data again, then the FIN if it was queued.
                self.snd_nxt = self.snd_una;
            }
        }
        self.output(now);
    }

    /// When [`Tcp::poll`] next has work.
    pub fn next_timer(&self) -> Option<Duration> {
        match (self.retransmit_at, self.time_wait_until) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// The later of two sequence numbers.
fn seq_max(a: u32, b: u32) -> u32 {
    if lt(a, b) { b } else { a }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    const A: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 0, 0, 1), 40000);
    const B: (Ipv4Addr, u16) = (Ipv4Addr::new(10, 0, 0, 2), 80);

    /// A lossy, duplicating, reordering link between an active end (A) and
    /// a passive end (B, created from the first SYN it sees), driven by a
    /// deterministic PRNG and event time.
    struct Sim {
        now: Duration,
        rng: u64,
        /// Per mille.
        loss: u64,
        dup: u64,
        /// Base one-way delay, plus up to as much again of jitter (which
        /// reorders).
        delay: Duration,
        /// (arrival, to B?, segment)
        flight: Vec<(Duration, bool, Vec<u8>)>,
        a: Tcp,
        b: Option<Tcp>,
        /// Drop everything after this time (a dead link).
        dead_after: Option<Duration>,
    }

    impl Sim {
        fn new(loss: u64, dup: u64, seed: u64, iss: u32) -> Sim {
            Sim {
                now: Duration::from_secs(1),
                rng: seed | 1,
                loss,
                dup,
                delay: Duration::from_millis(5),
                flight: Vec::new(),
                a: Tcp::connect(A, B, iss, Duration::from_secs(1)),
                b: None,
                dead_after: None,
            }
        }

        fn rand(&mut self, n: u64) -> u64 {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            self.rng % n.max(1)
        }

        fn launch(&mut self) {
            let mut out = Vec::new();
            while let Some(s) = self.a.transmit() {
                out.push((true, s));
            }
            if let Some(b) = &mut self.b {
                while let Some(s) = b.transmit() {
                    out.push((false, s));
                }
            }
            for (to_b, s) in out {
                if self.dead_after.is_some_and(|t| self.now >= t) || self.rand(1000) < self.loss {
                    continue;
                }
                let copies = if self.rand(1000) < self.dup { 2 } else { 1 };
                for _ in 0..copies {
                    let jitter = Duration::from_micros(self.rand(self.delay.as_micros() as u64));
                    self.flight
                        .push((self.now + self.delay + jitter, to_b, s.clone()));
                }
            }
        }

        /// Advances to the next event (a delivery or a timer).
        fn step(&mut self) -> bool {
            self.launch();
            let next_arrival = self.flight.iter().map(|f| f.0).min();
            let timers = [
                self.a.next_timer(),
                self.b.as_ref().and_then(Tcp::next_timer),
            ];
            let next = timers.into_iter().flatten().chain(next_arrival).min();
            let Some(t) = next else {
                return false;
            };
            self.now = self.now.max(t);
            let now = self.now;
            let (due, rest): (Vec<_>, Vec<_>) = core::mem::take(&mut self.flight)
                .into_iter()
                .partition(|f| f.0 <= now);
            self.flight = rest;
            for (_, to_b, bytes) in due {
                if to_b {
                    let seg = Segment::parse(&bytes, A.0, B.0).unwrap();
                    match &mut self.b {
                        Some(b) => b.on_segment(&seg, now),
                        None if seg.flags & SYN != 0 && seg.flags & ACK == 0 => {
                            self.b = Some(Tcp::accept(B, A, &seg, 0x8000_0000, now));
                        }
                        None => {}
                    }
                } else {
                    let seg = Segment::parse(&bytes, B.0, A.0).unwrap();
                    self.a.on_segment(&seg, now);
                }
            }
            self.a.poll(now);
            if let Some(b) = &mut self.b {
                b.poll(now);
            }
            self.launch();
            true
        }
    }

    fn pattern(n: usize, salt: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31) ^ salt).collect()
    }

    /// Sends `a_data` from A and `b_data` from B, reading everything on
    /// both sides, then both close. Returns what each side received.
    fn exchange(sim: &mut Sim, a_data: &[u8], b_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (mut a_sent, mut b_sent) = (0, 0);
        let (mut at_a, mut at_b) = (Vec::new(), Vec::new());
        let mut buf = vec![0u8; 65536];
        let mut closed = (false, false);
        for _ in 0..2_000_000 {
            let now = sim.now;
            a_sent += sim.a.send(&a_data[a_sent..], now);
            let n = sim.a.recv(&mut buf, now);
            at_a.extend_from_slice(&buf[..n]);
            if a_sent == a_data.len() && !closed.0 {
                sim.a.close(now);
                closed.0 = true;
            }
            if let Some(b) = &mut sim.b {
                b_sent += b.send(&b_data[b_sent..], now);
                let n = b.recv(&mut buf, now);
                at_b.extend_from_slice(&buf[..n]);
                if b_sent == b_data.len() && b.peer_closed() && !closed.1 {
                    b.close(now);
                    closed.1 = true;
                }
            }
            let done = sim.a.is_closed() && sim.b.as_ref().is_some_and(Tcp::is_closed);
            if done || !sim.step() {
                break;
            }
        }
        (at_a, at_b)
    }

    #[test]
    fn handshake_transfer_and_close_on_a_clean_link() {
        let mut sim = Sim::new(0, 0, 1, 1000);
        let (a, b) = (pattern(1 << 20, 1), pattern(300_000, 2));
        let (at_a, at_b) = exchange(&mut sim, &a, &b);
        assert_eq!(at_b, a, "B received A's bytes");
        assert_eq!(at_a, b, "A received B's bytes");
        // A closed first: it ends in TIME_WAIT then CLOSED; B (passive
        // closer) goes straight to CLOSED.
        assert!(sim.a.is_closed() && sim.b.as_ref().unwrap().is_closed());
        assert_eq!(sim.a.error(), None);
        assert_eq!(sim.b.as_ref().unwrap().error(), None);
    }

    #[test]
    fn survives_loss_duplication_and_reordering() {
        for seed in [7, 99, 12345] {
            let mut sim = Sim::new(50, 20, seed, 0xffff_ff00); // wraps soon
            let (a, b) = (pattern(400_000, 3), pattern(150_000, 4));
            let (at_a, at_b) = exchange(&mut sim, &a, &b);
            assert_eq!(at_b.len(), a.len(), "seed {seed}");
            assert_eq!(at_b, a, "seed {seed}");
            assert_eq!(at_a, b, "seed {seed}");
            assert!(sim.a.is_closed(), "seed {seed}: A in {:?}", sim.a.state());
        }
    }

    #[test]
    fn a_dead_link_times_out() {
        let mut sim = Sim::new(0, 0, 3, 5);
        // Let the handshake finish, then cut the link and send.
        for _ in 0..10 {
            sim.step();
        }
        assert_eq!(sim.a.state(), State::Established);
        sim.dead_after = Some(sim.now);
        let now = sim.now;
        sim.a.send(b"into the void", now);
        while sim.step() && !sim.a.is_closed() {}
        assert_eq!(sim.a.error(), Some(Error::TimedOut));
    }

    #[test]
    fn rst_to_a_syn_is_connection_refused() {
        let now = Duration::from_secs(1);
        let mut a = Tcp::connect(A, B, 77, now);
        let syn = a.transmit().unwrap();
        let s = Segment::parse(&syn, A.0, B.0).unwrap();
        assert_eq!(s.flags, SYN);
        assert_eq!(s.mss, Some(MSS));
        // What a closed port answers: RST|ACK acknowledging the SYN.
        let rst = segment(B, A, 0, s.seq.wrapping_add(1), RST | ACK, 0, None, &[]);
        a.on_segment(&Segment::parse(&rst, B.0, A.0).unwrap(), now);
        assert_eq!(a.error(), Some(Error::Refused));
        assert!(a.is_closed());
    }

    #[test]
    fn out_of_window_rst_gets_a_challenge_ack() {
        let mut sim = Sim::new(0, 0, 5, 9);
        for _ in 0..10 {
            sim.step();
        }
        let b = sim.b.as_ref().unwrap();
        assert_eq!(b.state(), State::Established);
        // A forged RST with a nearby but wrong sequence number.
        let wrong = sim.a.rcv_nxt.wrapping_add(10);
        let rst = segment(B, A, wrong, 0, RST, 0, None, &[]);
        let now = sim.now;
        sim.a
            .on_segment(&Segment::parse(&rst, B.0, A.0).unwrap(), now);
        assert_eq!(sim.a.state(), State::Established);
        let ack = sim.a.transmit().unwrap();
        assert_eq!(Segment::parse(&ack, A.0, B.0).unwrap().flags & ACK, ACK);
    }

    #[test]
    fn zero_window_then_open() {
        let mut sim = Sim::new(0, 0, 11, 1);
        for _ in 0..10 {
            sim.step();
        }
        // A fills B's buffer while B reads nothing.
        let data = pattern(BUFFER + 100_000, 5);
        let mut sent = 0;
        for _ in 0..200_000 {
            let now = sim.now;
            sent += sim.a.send(&data[sent..], now);
            if !sim.step() {
                break;
            }
            if sim.b.as_ref().unwrap().readable() == BUFFER {
                break;
            }
        }
        assert_eq!(sim.b.as_ref().unwrap().readable(), BUFFER);
        // Let time pass with the window shut: A probes and stays open.
        let until = sim.now + Duration::from_secs(30);
        while sim.now < until && sim.step() {}
        assert_eq!(sim.a.state(), State::Established);
        // B reads everything; the window opens and the rest arrives.
        let mut got = Vec::new();
        let mut buf = vec![0u8; 65536];
        for _ in 0..200_000 {
            let now = sim.now;
            sent += sim.a.send(&data[sent..], now);
            let b = sim.b.as_mut().unwrap();
            let n = b.recv(&mut buf, now);
            got.extend_from_slice(&buf[..n]);
            if got.len() == data.len() || !sim.step() {
                break;
            }
        }
        assert_eq!(got, data);
    }

    /// One direction's window is closed and probed (B does not read) while
    /// the other carries data: A's ACKs count all the same, and what B
    /// sends flows at its usual pace.
    #[test]
    fn a_closed_window_does_not_stop_the_other_direction() {
        for loss in [0, 20] {
            let mut sim = Sim::new(loss, 0, 23, 9);
            for _ in 0..10 {
                sim.step();
            }
            let up = pattern(2 * BUFFER, 7);
            let mut sent_up = 0;
            // B's buffer fills (the last bytes, less than the scaled window
            // tells of, by A's probes) and A probes it, for a while.
            let until = sim.now + Duration::from_secs(8000);
            while sim.now < until {
                let now = sim.now;
                sent_up += sim.a.send(&up[sent_up..], now);
                if !sim.step() {
                    break;
                }
            }
            assert_eq!(sim.b.as_ref().unwrap().readable(), BUFFER);
            assert_eq!(sim.a.state(), State::Established);
            let down = pattern(2 << 20, 8);
            let (mut sent, mut got) = (0, Vec::new());
            let mut buf = vec![0u8; 65536];
            let start = sim.now;
            while got.len() < down.len() {
                let now = sim.now;
                sent += sim.b.as_mut().unwrap().send(&down[sent..], now);
                let n = sim.a.recv(&mut buf, now);
                got.extend_from_slice(&buf[..n]);
                let more = sim.step();
                assert!(
                    more && sim.now < start + Duration::from_secs(60),
                    "loss {loss}: {} of {} bytes",
                    got.len(),
                    down.len()
                );
            }
            assert_eq!(got, down);
            // And once B reads, what waited arrives.
            let mut got = Vec::new();
            while got.len() < up.len() {
                let now = sim.now;
                sent_up += sim.a.send(&up[sent_up..], now);
                let n = sim.b.as_mut().unwrap().recv(&mut buf, now);
                got.extend_from_slice(&buf[..n]);
                assert!(sim.step() || got.len() == up.len());
            }
            assert_eq!(got, up);
        }
    }

    /// A slow reader whose buffer is full still takes the peer's FIN, and
    /// draining the buffer afterwards sends nothing: the peer may already
    /// be gone, and an update would only draw its stack's RST.
    #[test]
    fn a_full_reader_takes_the_fin_and_sends_no_late_window_update() {
        let mut sim = Sim::new(0, 0, 17, 5);
        for _ in 0..10 {
            sim.step();
        }
        let data = pattern(BUFFER, 6);
        let (mut sent, mut closed) = (0, false);
        for _ in 0..200_000 {
            let now = sim.now;
            sent += sim.a.send(&data[sent..], now);
            if sent == data.len() && !closed {
                sim.a.close(now);
                closed = true;
            }
            if sim.b.as_ref().unwrap().peer_closed() || !sim.step() {
                break;
            }
        }
        let now = sim.now;
        let b = sim.b.as_mut().unwrap();
        assert!(b.peer_closed(), "the FIN was not taken");
        assert_eq!(b.readable(), BUFFER);
        while b.transmit().is_some() {}
        let mut buf = vec![0u8; 4096];
        assert_eq!(b.recv(&mut buf, now), 4096);
        assert!(b.transmit().is_none(), "a window update after the FIN");
        assert_eq!(&buf[..], &data[..4096]);
    }

    /// A reader that leaves the window small but open tells the peer once it
    /// has read two segments' worth: a sender avoiding tiny segments is
    /// waiting for that, and would wait for its persist timer otherwise.
    #[test]
    fn a_small_window_that_grows_is_announced() {
        let mut sim = Sim::new(0, 0, 23, 9);
        for _ in 0..10 {
            sim.step();
        }
        // All but 800 bytes of the buffer.
        let data = pattern(BUFFER - 800, 4);
        let mut sent = 0;
        while sim.b.as_ref().unwrap().readable() < data.len() {
            let now = sim.now;
            sent += sim.a.send(&data[sent..], now);
            assert!(sim.step());
        }
        let now = sim.now;
        let b = sim.b.as_mut().unwrap();
        while b.transmit().is_some() {}
        let mut buf = vec![0u8; 8192];
        // Less than two segments: no news yet.
        assert_eq!(b.recv(&mut buf[..1000], now), 1000);
        assert!(b.transmit().is_none());
        // Now there is, once, whatever is read next.
        assert_eq!(b.recv(&mut buf[..4096], now), 4096);
        let (local, remote) = (b.local, b.remote);
        let update = b.transmit().expect("a window update");
        let seg = Segment::parse(&update, local.0, remote.0).unwrap();
        assert_eq!(
            usize::from(seg.window) << OUR_WSCALE,
            (800 + 5096) >> OUR_WSCALE << OUR_WSCALE
        );
        assert!(b.transmit().is_none());
        assert_eq!(b.recv(&mut buf[..1000], now), 1000);
        assert!(b.transmit().is_none());
    }

    /// A receiver whose cap drops to nothing closes its window (the sender
    /// waits, probing); raising the cap reopens it and the data arrives.
    /// A capped sender finds no room to write.
    #[test]
    fn a_cap_closes_the_window_and_raising_it_resumes() {
        let mut sim = Sim::new(0, 0, 21, 7);
        for _ in 0..10 {
            sim.step();
        }
        let now = sim.now;
        sim.b.as_mut().unwrap().set_cap(0, now);
        let data = pattern(100_000, 8);
        let mut sent = sim.a.send(&data, now);
        let until = sim.now + Duration::from_secs(20);
        while sim.now < until && sim.step() {}
        assert_eq!(
            sim.b.as_ref().unwrap().readable(),
            0,
            "nothing past a zero cap"
        );
        assert_eq!(sim.a.state(), State::Established);
        assert!(sim.a.buffered() >= sent);
        sim.a.set_cap(0, sim.now);
        assert_eq!(sim.a.writable(), 0);
        sim.a.set_cap(BUFFER, sim.now);
        let now = sim.now;
        sim.b.as_mut().unwrap().set_cap(BUFFER, now);
        let mut got = Vec::new();
        let mut buf = vec![0u8; 65536];
        for _ in 0..200_000 {
            let now = sim.now;
            sent += sim.a.send(&data[sent..], now);
            let b = sim.b.as_mut().unwrap();
            let n = b.recv(&mut buf, now);
            got.extend_from_slice(&buf[..n]);
            if got.len() == data.len() || !sim.step() {
                break;
            }
        }
        assert_eq!(got, data);
    }

    /// Closing with unread data drops it; data that arrives afterwards is
    /// answered with RST.
    #[test]
    fn data_after_the_application_left_is_reset() {
        let mut sim = Sim::new(0, 0, 23, 9);
        for _ in 0..10 {
            sim.step();
        }
        let now = sim.now;
        sim.a.send(b"unread", now);
        for _ in 0..10 {
            sim.step();
        }
        let now = sim.now;
        let b = sim.b.as_mut().unwrap();
        assert_eq!(b.readable(), 6);
        b.discard_received();
        b.close(now);
        assert_eq!(b.buffered(), 0);
        let now = sim.now;
        sim.a.send(b"more", now);
        while sim.step() && !sim.a.is_closed() {}
        assert_eq!(sim.a.error(), Some(Error::Reset), "the sender was reset");
        assert!(sim.b.as_ref().unwrap().is_closed());
    }

    /// A RST that ends TIME_WAIT is no error: both sides had finished.
    #[test]
    fn a_rst_in_time_wait_ends_it_quietly() {
        let mut sim = Sim::new(0, 0, 13, 3);
        for _ in 0..10 {
            sim.step();
        }
        let now = sim.now;
        sim.a.close(now);
        for _ in 0..100 {
            if sim.b.as_ref().unwrap().peer_closed() && sim.a.state() == State::FinWait2 {
                break;
            }
            sim.step();
        }
        let now = sim.now;
        sim.b.as_mut().unwrap().close(now);
        for _ in 0..100 {
            if sim.a.state() == State::TimeWait {
                break;
            }
            sim.step();
        }
        assert_eq!(sim.a.state(), State::TimeWait);
        let rst = segment(B, A, sim.a.rcv_nxt, 0, RST, 0, None, &[]);
        let now = sim.now;
        sim.a
            .on_segment(&Segment::parse(&rst, B.0, A.0).unwrap(), now);
        assert!(sim.a.is_closed());
        assert_eq!(sim.a.error(), None);
    }

    #[test]
    fn options_and_garbage() {
        let s = segment(A, B, 1, 2, SYN, 1000, Some((1400, 5)), b"");
        let p = Segment::parse(&s, A.0, B.0).unwrap();
        assert_eq!((p.mss, p.wscale, p.window), (Some(1400), Some(5), 1000));
        let mut bad = s.clone();
        bad[4] ^= 1;
        assert!(Segment::parse(&bad, A.0, B.0).is_none());
        let mut x = 3u32;
        for len in 0..120 {
            let g: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (x >> 16) as u8
                })
                .collect();
            let _ = Segment::parse(&g, A.0, B.0);
        }
    }
}
