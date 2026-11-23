//! What the kernel watches from its uplink, for the machine's own sake:
//! GCP's notice of host maintenance (`instance/maintenance-event`,
//! long-polled from the metadata service; it comes about a minute before
//! a live migration or a stop), and its wall clock against the metadata
//! server's NTP. Each is logged with the machine's uptime and wall clock,
//! so what a migration did (when it was announced, when the machine
//! stalled, how far the clock moved) can be read off the serial console.
//! A task also logs any stall in its own ticks.
//!
//! On with `metadata=gcp` (`watch_cloud` for any machine). Cells cannot
//! reach the metadata server; this runs in the uplink, as DHCP does.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use frame::println;
use net::iface::{Interface, Packet};
use net::metadata;
use net::ntp;
use net::tcp::{Segment, Tcp};
use net::wire::{self, Udp};

static WANTED: AtomicBool = AtomicBool::new(false);

/// Watches from the uplink (and ticks) once it is up.
pub(crate) fn want() {
    WANTED.store(true, Ordering::Relaxed);
}

/// How often the clock is compared, and how long a long poll may last.
const NTP_EVERY: Duration = Duration::from_secs(5);
const POLL_WAIT: u32 = 300;
/// A clock sample is logged when it moved this much, or this often.
const NTP_LOG_MOVE_NS: i64 = 2_000_000;
const NTP_LOG_EVERY: Duration = Duration::from_secs(60);
/// After a maintenance notice, every sample is logged for this long.
const AFTER_NOTICE: Duration = Duration::from_secs(600);
/// The port the clock is asked from, and the first of the long poll's.
const NTP_LOCAL: u16 = 20_123;
const POLL_PORTS: u16 = 20_200;

/// Uptime and wall clock, for logs.
fn stamp() -> String {
    let up = frame::time::now();
    let wall = frame::time::wall_clock().unwrap_or_default();
    format!(
        "uptime {}.{:03} s, wall {}.{:03}",
        up.as_secs(),
        up.subsec_millis(),
        wall.as_secs(),
        wall.subsec_millis()
    )
}

/// The long poll of the maintenance notice.
struct Poll {
    tcp: Tcp,
    port: u16,
    request: Vec<u8>,
    sent: usize,
    got: Vec<u8>,
    opened: Duration,
}

pub(crate) struct Watch {
    poll: Option<Poll>,
    next_port: u16,
    retry_at: Duration,
    etag: Option<String>,
    value: Option<String>,
    /// When the last notice that was not `NONE` came.
    noticed: Option<Duration>,
    /// The clock request in flight: when it left (wall clock).
    ntp_sent: Option<Duration>,
    next_ntp: Duration,
    logged_offset: Option<(i64, Duration)>,
    /// What steers the wall clock from the samples.
    discipline: ntp::Discipline,
    /// What to log, once the uplink is let go.
    pub(crate) log: Vec<String>,
}

impl Watch {
    /// A watch, if one was asked for.
    pub(crate) fn wanted() -> Option<Watch> {
        WANTED.load(Ordering::Relaxed).then(|| {
            start_tick_watch();
            Watch {
                poll: None,
                next_port: POLL_PORTS,
                retry_at: Duration::ZERO,
                etag: None,
                value: None,
                noticed: None,
                ntp_sent: None,
                next_ntp: Duration::ZERO,
                logged_offset: None,
                discipline: ntp::Discipline::default(),
                log: Vec::new(),
            }
        })
    }

    /// Sends what is due.
    pub(crate) fn poll(&mut self, t: Duration, ifc: &mut Interface) {
        let meta = metadata::ADDRESS;
        if t >= self.next_ntp
            && let Some(wall) = frame::time::wall_clock()
        {
            let d = wire::udp(ifc.addr, NTP_LOCAL, meta, ntp::PORT, &ntp::request(wall));
            ifc.send(t, meta, wire::PROTO_UDP, &d);
            self.ntp_sent = Some(wall);
            self.next_ntp = t + NTP_EVERY;
        }
        if self.poll.is_none() && t >= self.retry_at {
            let mut r = [0u8; 4];
            crate::random::fill(&mut r);
            let port = self.next_port;
            self.next_port = POLL_PORTS + (self.next_port - POLL_PORTS + 1) % 100;
            let host = format!("{meta}");
            self.poll = Some(Poll {
                tcp: Tcp::connect(
                    (ifc.addr, port),
                    (meta, metadata::PORT),
                    u32::from_le_bytes(r),
                    t,
                ),
                port,
                request: metadata::maintenance_request(&host, self.etag.as_deref(), POLL_WAIT),
                sent: 0,
                got: Vec::new(),
                opened: t,
            });
        }
        let Some(p) = &mut self.poll else {
            return;
        };
        p.sent += p.tcp.send(&p.request[p.sent..], t);
        let mut buf = [0u8; 1024];
        loop {
            let n = p.tcp.recv(&mut buf, t);
            if n == 0 {
                break;
            }
            p.got.extend_from_slice(&buf[..n]);
        }
        let whole = p.tcp.peer_closed() || metadata::complete(&p.got);
        let stuck = p.tcp.error().is_some()
            || t.saturating_sub(p.opened) > Duration::from_secs(u64::from(POLL_WAIT) + 30)
            || p.got.len() > metadata::MAX_ANSWER;
        p.tcp.poll(t);
        if whole || stuck {
            p.tcp.close(t);
        }
        while let Some(seg) = p.tcp.transmit() {
            ifc.send(t, meta, wire::PROTO_TCP, &seg);
        }
        if !(whole || stuck) {
            return;
        }
        let got = core::mem::take(&mut p.got);
        self.poll = None;
        match metadata::maintenance_answer(&got).filter(|_| whole) {
            Some((value, etag)) => {
                if self.value.as_deref() != Some(&value) {
                    self.log.push(format!(
                        "ichor: watch: maintenance-event {value} ({})",
                        stamp()
                    ));
                    if value != "NONE" {
                        self.noticed = Some(t);
                    }
                }
                self.value = Some(value);
                self.etag = etag;
                self.retry_at = t;
            }
            None => {
                if stuck && self.value.is_some() {
                    self.log.push(format!(
                        "ichor: watch: the maintenance long poll broke off ({}); asking again",
                        stamp()
                    ));
                }
                self.retry_at = t + Duration::from_secs(2);
            }
        }
    }

    /// Takes a packet meant for the watch; whether it was.
    pub(crate) fn take(&mut self, t: Duration, p: &Packet) -> bool {
        if p.src != metadata::ADDRESS {
            return false;
        }
        if p.protocol == wire::PROTO_UDP
            && let Some(u) = Udp::parse(&p.payload, p.src, p.dst)
            && (u.src_port, u.dst_port) == (ntp::PORT, NTP_LOCAL)
        {
            let received = frame::time::wall_clock().unwrap_or_default();
            if let Some(sent) = self.ntp_sent.take()
                && let Some(s) = ntp::answer(u.payload, sent, received)
            {
                self.clock(t, s);
            }
            return true;
        }
        if p.protocol == wire::PROTO_TCP
            && let Some(poll) = &mut self.poll
            && let Some(seg) = Segment::parse(&p.payload, p.src, p.dst)
            && (seg.src_port, seg.dst_port) == (metadata::PORT, poll.port)
        {
            poll.tcp.on_segment(&seg, t);
            return true;
        }
        false
    }

    /// Steers the wall clock by a sample (a quick one), and logs the sample
    /// if it moved, now and then, and around a notice. What is logged is
    /// the offset before steering; `steering` is the clock's learned rate
    /// error, so the unsteered clock's drift still shows.
    fn clock(&mut self, t: Duration, s: ntp::Sample) {
        let t_ns = u64::try_from(t.as_nanos()).unwrap_or(u64::MAX);
        let steer = self.discipline.sample(t_ns, s);
        if let Some(st) = steer {
            frame::time::steer_wall_clock(st.step_ns, st.ppb);
            if st.step_ns != 0 {
                self.log.push(format!(
                    "ichor: watch: clock stepped {}{}.{:06} ms to the metadata server's NTP ({})",
                    if st.step_ns < 0 { "-" } else { "+" },
                    st.step_ns.unsigned_abs() / 1_000_000,
                    st.step_ns.unsigned_abs() % 1_000_000,
                    stamp()
                ));
            }
        }
        let near = self
            .noticed
            .is_some_and(|n| t.saturating_sub(n) < AFTER_NOTICE);
        let due = match self.logged_offset {
            None => true,
            Some((o, at)) => {
                (s.offset_ns - o).abs() >= NTP_LOG_MOVE_NS || t.saturating_sub(at) >= NTP_LOG_EVERY
            }
        };
        if near || due {
            self.log.push(format!(
                "ichor: watch: clock {}{}.{:06} ms from the metadata server's NTP (rtt {}.{:03} ms, stratum {}; steering {}{}.{:03} ppm{}; {})",
                if s.offset_ns < 0 { "-" } else { "+" },
                s.offset_ns.unsigned_abs() / 1_000_000,
                s.offset_ns.unsigned_abs() % 1_000_000,
                s.rtt_ns / 1_000_000,
                (s.rtt_ns % 1_000_000).abs() / 1000,
                s.stratum,
                if self.discipline.freq_ppb() < 0 { "-" } else { "+" },
                self.discipline.freq_ppb().unsigned_abs() / 1000,
                self.discipline.freq_ppb().unsigned_abs() % 1000,
                if steer.is_some() { "" } else { ", not used" },
                stamp()
            ));
            self.logged_offset = Some((s.offset_ns, t));
        }
    }
}

/// How often the tick watch wakes, and the gap it reports.
const TICK: Duration = Duration::from_millis(20);
const STALL: Duration = Duration::from_millis(250);

/// Logs every time the machine did not run for a while: a task that asks
/// to wake every 20 ms and says when it woke much later (a migration's
/// blackout, if the clock went on through it; a starved scheduler).
fn start_tick_watch() {
    let watch = || {
        let mut last = frame::time::now();
        loop {
            frame::task::sleep_until(last + TICK);
            let now = frame::time::now();
            let gap = now.saturating_sub(last);
            if gap > STALL {
                println!(
                    "ichor: watch: no tick for {} ms ({})",
                    gap.as_millis(),
                    stamp()
                );
            }
            last = now;
        }
    };
    if frame::task::TaskOptions::new(watch).spawn().is_none() {
        println!("ichor: watch: no task for the tick watch");
    }
}

/// A read this slow is logged on its own.
const SLOW_READ: Duration = Duration::from_millis(500);
/// How often the hammer sums up, and the bytes of each read.
const HAMMER_REPORT: Duration = Duration::from_secs(10);
const HAMMER_READ: usize = 64 * 1024;

/// Reads the largest mounted disk without end (`disk_hammer`; on a cloud
/// disk the root partition fills the disk), at random places and past the
/// page cache, so its driver is busy through whatever happens to the
/// machine: errors, timeouts and slow reads are logged at once, and a
/// summary every 10 s.
pub(crate) fn start_disk_hammer() {
    let Some((disk, sectors)) = crate::pagecache::largest_disk() else {
        println!("ichor: hammer: no disk");
        return;
    };
    let span = (HAMMER_READ / block::SECTOR_SIZE) as u64;
    if sectors < span {
        println!("ichor: hammer: the disk is too small");
        return;
    }
    println!(
        "ichor: hammer: reading disk {disk} ({} MiB) at random",
        (sectors * block::SECTOR_SIZE as u64) >> 20
    );
    let hammer = move || {
        let mut buf = alloc::vec![0u8; HAMMER_READ];
        let (mut reads, mut errors, mut worst) = (0u64, 0u64, Duration::ZERO);
        let mut since = frame::time::now();
        loop {
            let mut r = [0u8; 8];
            crate::random::fill(&mut r);
            let at = u64::from_le_bytes(r) % (sectors - span + 1);
            let start = frame::time::now();
            let res = crate::pagecache::read_raw(disk, at, &mut buf);
            let took = frame::time::now().saturating_sub(start);
            reads += 1;
            worst = worst.max(took);
            if let Err(e) = res {
                errors += 1;
                println!(
                    "ichor: hammer: read at sector {at} failed after {} ms: {e:?} ({})",
                    took.as_millis(),
                    stamp()
                );
            } else if took > SLOW_READ {
                println!(
                    "ichor: hammer: read at sector {at} took {} ms ({})",
                    took.as_millis(),
                    stamp()
                );
            }
            let now = frame::time::now();
            if now.saturating_sub(since) >= HAMMER_REPORT {
                let secs = now.saturating_sub(since).as_secs_f64();
                println!(
                    "ichor: hammer: {reads} reads ({:.1} MiB/s), {errors} errors, slowest {} ms ({})",
                    (reads * HAMMER_READ as u64) as f64 / secs / (1 << 20) as f64,
                    worst.as_millis(),
                    stamp()
                );
                (reads, errors, worst, since) = (0, 0, Duration::ZERO, now);
            }
            frame::task::yield_now();
        }
    };
    if frame::task::TaskOptions::new(hammer).spawn().is_none() {
        println!("ichor: hammer: no task");
    }
}
