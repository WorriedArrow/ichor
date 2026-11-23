//! AWS's Elastic Network Adapter, polled: the network device of every
//! Nitro machine (`kernel/ena` has its protocol). One transmit and one
//! receive queue, no offloads, no interrupts.
//!
//! The device is brought up as Amazon's own drivers do: reset, the admin
//! queue (and the event queue, which is read and passed over), a page about
//! the driver, its attributes (MAC address) and limits, then the queues.
//! Transmit descriptors go in the device's memory (a low-latency queue)
//! when it has that, which newer machines require; else in host memory.
//! Registers are read through memory (the device writes the value) unless
//! its PCI revision says they are read directly.
//!
//! Safe code only. Descriptors and commands carry bus addresses, so this
//! driver is on ADR-0005's DMA-trusted list, as NVMe is: every address is
//! in a buffer that lives as long as the device knows it (the device is
//! reset before they are freed), and lengths and request IDs it reports
//! are checked against the buffers they name.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};
use core::time::Duration;

use ena::{
    Command, Completion, CreatedCq, CreatedSq, Cursor, DESC, DeviceAttributes, Direction, ENTRY,
    Event, Limits, Llq, LlqOffer, Placement, RX_COMPLETION, RxCompletion, TX_COMPLETION,
    TxCompletion, feature, reg,
};
use frame::bus::pci::{self, PciDevice};
use frame::dma::DmaBuf;
use frame::io::IoMem;

/// Entries in the admin queue and in the event queue.
const ADMIN_DEPTH: u16 = 32;
const EVENT_DEPTH: u16 = 16;
/// Entries in each I/O queue (fewer if the device allows fewer), and the
/// bytes of a frame's buffer.
const RING: u16 = 256;
const SLOT: usize = 2048;
/// The largest frame: a 1500-byte MTU plus the Ethernet header.
pub const MAX_FRAME: usize = 1514;
const MTU: u32 = 1500;
/// Receive descriptors are given back this many at a time.
const GIVE_BACK: u16 = 16;

/// How long a register read may take, and an admin command (unless the
/// device says).
const READ_PATIENCE: Duration = Duration::from_millis(200);
const ADMIN_PATIENCE: Duration = Duration::from_secs(3);

/// Why a device could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    MapFailed,
    NoMemory,
    /// A register read went unanswered.
    ReadTimeout,
    /// It was not ready, or did not come out of reset.
    NotReady,
    /// An admin command went unanswered (its opcode).
    AdminTimeout(u8),
    /// An admin command failed (its opcode, and the status).
    Admin(u8, u8),
    /// Our memory is beyond the addresses it can reach.
    Unreachable,
    /// It has no address.
    NoAddress,
}

/// The register BAR, and how registers are read from it.
#[derive(Debug)]
struct Registers {
    bar: IoMem,
    /// Read directly, not through `answer`.
    direct: bool,
    answer: DmaBuf,
    seq: u16,
}

impl Registers {
    fn write(&self, offset: u64, v: u32) {
        self.bar.write32(offset, v);
    }

    /// Tells the device where read answers go (again after a reset).
    fn point_answers(&self) -> Result<(), InitError> {
        let at = self.answer.dma_addr(0).ok_or(InitError::NoMemory)?.as_u64();
        self.write(reg::MMIO_RESP_LO, at as u32);
        self.write(reg::MMIO_RESP_HI, (at >> 32) as u32);
        Ok(())
    }

    fn read(&mut self, offset: u64) -> Result<u32, InitError> {
        if self.direct {
            return Ok(self.bar.read32(offset));
        }
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        // What is there must not look like the answer.
        self.answer.write_u16(0, seq.wrapping_add(0xdead));
        fence(Ordering::SeqCst);
        self.write(reg::MMIO_REG_READ, reg::read_request(offset as u16, seq));
        let deadline = frame::time::now() + READ_PATIENCE;
        while self.answer.read_u16(0) != seq {
            if frame::time::now() > deadline {
                return Err(InitError::ReadTimeout);
            }
            core::hint::spin_loop();
        }
        fence(Ordering::Acquire);
        let mut b = [0u8; ena::READ_ANSWER];
        self.answer.read(0, &mut b);
        let a = ena::ReadAnswer::parse(&b);
        if a.offset != offset as u16 {
            return Err(InitError::ReadTimeout);
        }
        Ok(a.value)
    }
}

/// Waits until `done` says so, or `patience` is over.
fn wait(
    patience: Duration,
    mut done: impl FnMut() -> Result<bool, InitError>,
) -> Result<(), InitError> {
    let deadline = frame::time::now() + patience;
    while !done()? {
        if frame::time::now() > deadline {
            return Err(InitError::NotReady);
        }
        core::hint::spin_loop();
    }
    Ok(())
}

/// The admin queue and its completions.
#[derive(Debug)]
struct Admin {
    sq: DmaBuf,
    cq: DmaBuf,
    sq_at: Cursor,
    cq_at: Cursor,
    id: u16,
    patience: Duration,
}

/// A transmit queue in device memory.
#[derive(Debug)]
struct LowLatency {
    llq: Llq,
    mem: IoMem,
    /// Offset of the queue's entries in `mem`.
    base: u64,
}

/// An Elastic Network Adapter.
#[derive(Debug)]
pub struct Ena {
    regs: Registers,
    admin: Admin,
    events: DmaBuf,
    event_at: Cursor,
    mac: [u8; 6],
    link_up: bool,
    dma_limit: u64,

    tx_depth: u16,
    tx_sq: Cursor,
    tx_cq: Cursor,
    tx_cq_ring: DmaBuf,
    /// The descriptors, if they are in host memory.
    tx_ring: Option<DmaBuf>,
    tx_llq: Option<LowLatency>,
    tx_doorbell: u64,
    tx_data: DmaBuf,
    /// How many queue entries each request (buffer) took; 0 when free.
    tx_used: Vec<u16>,
    /// Queue entries the device is done with.
    tx_done: u16,
    tx_next: u16,
    /// Of a frame, the most bytes counted as its header (host memory).
    tx_header: usize,
    /// Frames dropped because the queue was full.
    pub tx_dropped: u64,

    rx_sq: Cursor,
    rx_cq: Cursor,
    rx_ring: DmaBuf,
    rx_cq_ring: DmaBuf,
    rx_doorbell: u64,
    rx_data: DmaBuf,
    /// Buffers taken and not given back yet.
    rx_taken: Vec<u16>,
    /// Frames passed over (too long, or broken).
    pub rx_dropped: u64,
}

/// Every such device, brought up.
pub fn probe_all() -> Vec<Result<Ena, InitError>> {
    pci::devices()
        .iter()
        .filter(|d| d.vendor_id == ena::VENDOR && ena::DEVICES.contains(&d.device_id))
        .map(Ena::init)
        .collect()
}

/// The largest power of two that is at most `n` and `RING`.
fn depth(n: u32) -> u16 {
    let n = n.clamp(2, u32::from(RING));
    1 << (31 - n.leading_zeros())
}

impl Ena {
    fn init(dev: &PciDevice) -> Result<Ena, InitError> {
        dev.enable(true, true);
        let bar = dev.map_bar(ena::REGISTER_BAR).ok_or(InitError::MapFailed)?;
        let revision = dev.read_config_u8(0x08);
        let page = || DmaBuf::alloc(4096).ok_or(InitError::NoMemory);
        let mut regs = Registers {
            bar,
            direct: revision & ena::REVISION_DIRECT_READS != 0,
            answer: page()?,
            seq: 0,
        };
        regs.point_answers()?;

        // Reset, so nothing the firmware set up is left.
        wait(Duration::from_secs(5), || {
            Ok(regs.read(reg::DEV_STS)? & reg::DEV_STS_READY != 0)
        })?;
        let caps = regs.read(reg::CAPS)?;
        let patience = Duration::from_millis(100 * u64::from(reg::reset_timeout(caps).max(10)));
        regs.write(reg::DEV_CTL, reg::DEV_CTL_RESET);
        regs.point_answers()?;
        wait(patience, || {
            Ok(regs.read(reg::DEV_STS)? & reg::DEV_STS_RESET_IN_PROGRESS != 0)
        })?;
        regs.write(reg::DEV_CTL, 0);
        wait(patience, || {
            let s = regs.read(reg::DEV_STS)?;
            Ok(s & reg::DEV_STS_RESET_IN_PROGRESS == 0 && s & reg::DEV_STS_READY != 0)
        })?;
        let width = reg::dma_width(caps);
        if !(32..=64).contains(&width) {
            return Err(InitError::NotReady);
        }
        let dma_limit = if width == 64 {
            u64::MAX
        } else {
            (1 << width) - 1
        };
        let admin_patience = match reg::admin_timeout(caps) {
            0 => ADMIN_PATIENCE,
            t => Duration::from_millis(100 * u64::from(t)).max(ADMIN_PATIENCE),
        };

        let admin = Admin {
            sq: page()?,
            cq: page()?,
            sq_at: Cursor::new(ADMIN_DEPTH),
            cq_at: Cursor::new(ADMIN_DEPTH),
            id: 0,
            patience: admin_patience,
        };
        let events = page()?;
        let ring = |b: &DmaBuf| b.dma_addr(0).ok_or(InitError::NoMemory).map(|a| a.as_u64());
        for (lo, hi, caps, at, depth) in [
            (
                reg::AQ_BASE_LO,
                reg::AQ_BASE_HI,
                reg::AQ_CAPS,
                ring(&admin.sq)?,
                ADMIN_DEPTH,
            ),
            (
                reg::ACQ_BASE_LO,
                reg::ACQ_BASE_HI,
                reg::ACQ_CAPS,
                ring(&admin.cq)?,
                ADMIN_DEPTH,
            ),
            (
                reg::AENQ_BASE_LO,
                reg::AENQ_BASE_HI,
                reg::AENQ_CAPS,
                ring(&events)?,
                EVENT_DEPTH,
            ),
        ] {
            if at > dma_limit {
                return Err(InitError::Unreachable);
            }
            regs.write(lo, at as u32);
            regs.write(hi, (at >> 32) as u32);
            regs.write(caps, reg::queue_caps(depth, ENTRY as u16));
        }
        // Every event entry is the device's to write.
        regs.write(reg::AENQ_HEAD_DOORBELL, u32::from(EVENT_DEPTH));

        let rx_data = DmaBuf::alloc(usize::from(RING) * SLOT).ok_or(InitError::NoMemory)?;
        let tx_data = DmaBuf::alloc(usize::from(RING) * SLOT).ok_or(InitError::NoMemory)?;
        let mut nic = Ena {
            regs,
            admin,
            events,
            event_at: Cursor::at(EVENT_DEPTH, EVENT_DEPTH),
            mac: [0; 6],
            link_up: true,
            dma_limit,
            tx_depth: RING,
            tx_sq: Cursor::new(RING),
            tx_cq: Cursor::new(RING),
            tx_cq_ring: page()?,
            tx_ring: None,
            tx_llq: None,
            tx_doorbell: 0,
            tx_data,
            tx_used: vec![0; usize::from(RING)],
            tx_done: 0,
            tx_next: 0,
            tx_header: 0,
            tx_dropped: 0,
            rx_sq: Cursor::new(RING),
            rx_cq: Cursor::new(RING),
            rx_ring: page()?,
            rx_cq_ring: page()?,
            rx_doorbell: 0,
            rx_data,
            rx_taken: Vec::new(),
            rx_dropped: 0,
        };
        nic.configure(dev)?;
        Ok(nic)
    }

    /// The bus address of byte `at` of `b`, if the device reaches it.
    fn reach(&self, b: &DmaBuf, at: usize) -> Result<u64, InitError> {
        let a = b.dma_addr(at).ok_or(InitError::NoMemory)?.as_u64();
        let end = a + (b.len() - at) as u64 - 1;
        if end > self.dma_limit {
            return Err(InitError::Unreachable);
        }
        Ok(a)
    }

    /// Runs an admin command and waits for its completion.
    fn admin(&mut self, c: &Command) -> Result<Completion, InitError> {
        let a = &mut self.admin;
        let id = a.id;
        a.id = (a.id + 1) % ADMIN_DEPTH;
        a.sq.write(a.sq_at.slot() * ENTRY, &c.entry(id, a.sq_at.phase()));
        a.sq_at.advance();
        fence(Ordering::SeqCst);
        self.regs
            .write(reg::AQ_DOORBELL, u32::from(self.admin.sq_at.count()));
        let a = &mut self.admin;
        let deadline = frame::time::now() + a.patience;
        loop {
            let at = a.cq_at.slot() * ENTRY;
            let flags = a.cq.read_u32(at) >> 24;
            if (flags & 1 != 0) == a.cq_at.phase() {
                fence(Ordering::Acquire);
                let mut e = [0u8; ENTRY];
                a.cq.read(at, &mut e);
                a.cq_at.advance();
                let done = Completion(e);
                // (One that timed out before.)
                if done.id() != id {
                    continue;
                }
                return match done.status() {
                    0 => Ok(done),
                    s => Err(InitError::Admin(c.opcode(), s)),
                };
            }
            if frame::time::now() > deadline {
                return Err(InitError::AdminTimeout(c.opcode()));
            }
            core::hint::spin_loop();
        }
    }

    fn configure(&mut self, dev: &PciDevice) -> Result<(), InitError> {
        // What the driver is; a device that does not want to know is fine.
        let info = DmaBuf::alloc(4096).ok_or(InitError::NoMemory)?;
        let bdf = u16::from(dev.bus) << 8 | u16::from(dev.device) << 3 | u16::from(dev.function);
        let cpus = frame::cpu::online_count().min(usize::from(u16::MAX)) as u16;
        info.write(0, &ena::host_info(cpus, bdf));
        let at = self.reach(&info, 0)?;
        if let Err(e) = self.admin(&Command::set_host_attributes(at)) {
            frame::println!("ichor: ena: host attributes refused: {e:?}");
        }
        // The device keeps its address; the page lives as long as it.
        core::mem::forget(info);

        let attrs = self.admin(&Command::get_feature(feature::DEVICE_ATTRIBUTES, 0))?;
        let attrs = DeviceAttributes::parse(&attrs);
        let m = attrs.mac;
        if m == [0; 6] || m[0] & 1 != 0 {
            return Err(InitError::NoAddress);
        }
        self.mac = m;
        let limits = if attrs.has(feature::MAX_QUEUES_EXT) {
            let c = Command::get_feature(feature::MAX_QUEUES_EXT, feature::MAX_QUEUES_EXT_VERSION);
            Limits::extended(&self.admin(&c)?).ok_or(InitError::NotReady)?
        } else {
            Limits::basic(&self.admin(&Command::get_feature(feature::MAX_QUEUES_NUM, 0))?)
        };
        self.tx_header = limits.max_header as usize;

        // Transmit descriptors in the device's memory, if it has that.
        let mut placement = Placement::Host;
        if attrs.has(feature::LLQ)
            && let Some(mem) = dev.map_bar(ena::MEMORY_BAR)
        {
            let c = Command::get_feature(feature::LLQ, feature::LLQ_VERSION);
            let offer = LlqOffer::parse(&self.admin(&c)?);
            if let Some(llq) = offer.choose()
                && self.admin(&Command::set_llq(&llq)).is_ok()
            {
                placement = Placement::Device;
                self.tx_llq = Some(LowLatency { llq, mem, base: 0 });
            }
        }
        if attrs.has(feature::MTU) {
            let _ = self.admin(&Command::set_mtu(MTU.min(attrs.max_mtu.max(MTU))));
        }

        let llq_depth = self.tx_llq.as_ref().map_or(u32::MAX, |l| l.llq.max_depth);
        let tx_depth = depth(limits.tx_depth.min(limits.tx_cq_depth).min(llq_depth));
        let rx_depth = depth(limits.rx_depth.min(limits.rx_cq_depth));
        self.tx_depth = tx_depth;
        (self.tx_sq, self.tx_cq) = (Cursor::new(tx_depth), Cursor::new(tx_depth));
        (self.rx_sq, self.rx_cq) = (Cursor::new(rx_depth), Cursor::new(rx_depth));

        // Transmit: completions, then the queue.
        let cq_at = self.reach(&self.tx_cq_ring, 0)?;
        let cq = self.create_cq(TX_COMPLETION as u8, tx_depth, cq_at)?;
        let ring = match placement {
            Placement::Host => {
                let r = DmaBuf::alloc(usize::from(tx_depth) * DESC).ok_or(InitError::NoMemory)?;
                let at = self.reach(&r, 0)?;
                self.tx_ring = Some(r);
                Some(at)
            }
            Placement::Device => None,
        };
        let sq = Command::create_sq(Direction::Tx, placement, cq.index, tx_depth, ring);
        let sq = CreatedSq::parse(&self.admin(&sq)?);
        self.tx_doorbell = u64::from(sq.doorbell);
        if let Some(l) = &mut self.tx_llq {
            l.base = u64::from(sq.llq_entries);
        }
        self.reach(&self.tx_data, 0)?;

        // Receive.
        let cq_at = self.reach(&self.rx_cq_ring, 0)?;
        let cq = self.create_cq(RX_COMPLETION as u8, rx_depth, cq_at)?;
        let ring = self.reach(&self.rx_ring, 0)?;
        let sq = Command::create_sq(
            Direction::Rx,
            Placement::Host,
            cq.index,
            rx_depth,
            Some(ring),
        );
        let sq = CreatedSq::parse(&self.admin(&sq)?);
        self.rx_doorbell = u64::from(sq.doorbell);
        self.reach(&self.rx_data, 0)?;
        // Every buffer but one: a full ring would look empty.
        for id in 0..rx_depth - 1 {
            self.give(id);
        }
        fence(Ordering::SeqCst);
        self.regs
            .write(self.rx_doorbell, u32::from(self.rx_sq.count()));
        Ok(())
    }

    /// Creates a completion queue of `entry`-byte completions.
    fn create_cq(&mut self, entry: u8, depth: u16, ring: u64) -> Result<CreatedCq, InitError> {
        let c = self.admin(&Command::create_cq(entry, depth, ring))?;
        Ok(CreatedCq::parse(&c))
    }

    /// The device's MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Whether the device last said its link is up.
    pub fn link_up(&self) -> bool {
        self.link_up
    }

    /// Whether transmit descriptors go in the device's memory.
    pub fn low_latency(&self) -> bool {
        self.tx_llq.is_some()
    }

    /// Puts receive buffer `id` in the queue (no doorbell).
    fn give(&mut self, id: u16) {
        let addr = self
            .rx_data
            .dma_addr(usize::from(id) * SLOT)
            .map_or(0, |a| a.as_u64());
        let d = ena::rx_desc(self.rx_sq.phase(), id, addr, SLOT as u16);
        self.rx_ring.write(self.rx_sq.slot() * DESC, &d);
        self.rx_sq.advance();
    }

    /// Reads what the event queue has (link changes; the rest is passed
    /// over) and gives the entries back.
    fn events(&mut self) {
        let mut any = false;
        loop {
            let at = self.event_at.slot() * ENTRY;
            if (self.events.read_u32(at + 4) & 1 != 0) != self.event_at.phase() {
                break;
            }
            fence(Ordering::Acquire);
            let mut e = [0u8; ENTRY];
            self.events.read(at, &mut e);
            let ev = Event::parse(&e);
            if ev.group == Event::LINK_CHANGE {
                self.link_up = ev.link_up;
            }
            self.event_at.advance();
            any = true;
        }
        if any {
            fence(Ordering::SeqCst);
            self.regs
                .write(reg::AENQ_HEAD_DOORBELL, u32::from(self.event_at.count()));
        }
    }

    /// The next received frame, if any.
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        self.events();
        loop {
            let at = self.rx_cq.slot() * RX_COMPLETION;
            if (self.rx_cq_ring.read_u32(at) & 1 << 24 != 0) != self.rx_cq.phase() {
                self.give_back(1);
                return None;
            }
            fence(Ordering::Acquire);
            let mut b = [0u8; RX_COMPLETION];
            self.rx_cq_ring.read(at, &mut b);
            let c = RxCompletion::parse(&b);
            self.rx_cq.advance();
            let id = c.req_id;
            if usize::from(id) * SLOT >= self.rx_data.len() {
                // Not one of ours: nothing to give back.
                self.rx_dropped += 1;
                continue;
            }
            self.rx_taken.push(id);
            let (start, len) = (usize::from(c.offset), usize::from(c.len));
            // A frame in one buffer; one in several is longer than ours.
            let frame = (c.first && c.last && (14..=SLOT - start).contains(&len)).then(|| {
                let mut f = vec![0u8; len];
                self.rx_data.read(usize::from(id) * SLOT + start, &mut f);
                f
            });
            self.give_back(GIVE_BACK);
            match frame {
                Some(f) => return Some(f),
                None => self.rx_dropped += 1,
            }
        }
    }

    /// Gives taken buffers back to the device, if there are `enough`.
    fn give_back(&mut self, enough: u16) {
        if self.rx_taken.len() < usize::from(enough) {
            return;
        }
        for id in core::mem::take(&mut self.rx_taken) {
            self.give(id);
        }
        fence(Ordering::SeqCst);
        self.regs
            .write(self.rx_doorbell, u32::from(self.rx_sq.count()));
    }

    /// Takes the completions of sent frames.
    fn reap(&mut self) {
        loop {
            let at = self.tx_cq.slot() * TX_COMPLETION;
            if (self.tx_cq_ring.read_u32(at) & 1 << 24 != 0) != self.tx_cq.phase() {
                return;
            }
            fence(Ordering::Acquire);
            let mut b = [0u8; TX_COMPLETION];
            self.tx_cq_ring.read(at, &mut b);
            let c = TxCompletion::parse(&b);
            self.tx_cq.advance();
            if let Some(used) = self.tx_used.get_mut(usize::from(c.req_id)) {
                self.tx_done = self.tx_done.wrapping_add(*used);
                *used = 0;
            }
        }
    }

    /// Queues a frame for transmission. Returns false if it was dropped
    /// (too long, or the queue is full).
    pub fn transmit(&mut self, frame: &[u8]) -> bool {
        self.reap();
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return false;
        }
        let id = self.tx_next;
        if self.tx_used[usize::from(id)] != 0 {
            self.tx_dropped += 1;
            return false;
        }
        let at = usize::from(id) * SLOT;
        let Some(addr) = self.tx_data.dma_addr(at).map(|a| a.as_u64()) else {
            return false;
        };
        let mut sq = self.tx_sq;
        let used;
        if let Some(l) = &self.tx_llq {
            // The first bytes go with the descriptors; the device reads the
            // rest from the buffer.
            let pushed = frame.len().min(l.llq.max_header());
            let rest = &frame[pushed..];
            self.tx_data.write(at, rest);
            let buffer = (!rest.is_empty()).then_some((addr, rest.len() as u16));
            let Some(entries) = ena::tx_llq(&mut sq, &l.llq, id, &frame[..pushed], buffer) else {
                return false;
            };
            used = entries.len() as u16;
            if !self.room(used) || (l.llq.max_burst != 0 && usize::from(used) > l.llq.max_burst) {
                self.tx_dropped += 1;
                return false;
            }
            for (slot, bytes) in &entries {
                let base = l.base + (slot * l.llq.entry_size) as u64;
                for (i, w) in bytes.as_chunks::<8>().0.iter().enumerate() {
                    l.mem.write64(base + 8 * i as u64, u64::from_le_bytes(*w));
                }
            }
        } else {
            let Some(ring) = &self.tx_ring else {
                return false;
            };
            if !self.room(1) {
                self.tx_dropped += 1;
                return false;
            }
            self.tx_data.write(at, frame);
            let header = frame.len().min(self.tx_header).min(255) as u8;
            let (slot, d) = ena::tx_host(&mut sq, id, addr, frame.len() as u16, header);
            ring.write(slot * DESC, &d);
            used = 1;
        }
        self.tx_used[usize::from(id)] = used;
        self.tx_next = (id + 1) % self.tx_depth;
        self.tx_sq = sq;
        fence(Ordering::SeqCst);
        self.regs
            .write(self.tx_doorbell, u32::from(self.tx_sq.count()));
        true
    }

    /// Whether `entries` more fit in the transmit queue (one is always
    /// left empty).
    fn room(&self, entries: u16) -> bool {
        let in_flight = self.tx_sq.since(self.tx_done);
        u32::from(in_flight) + u32::from(entries) < u32::from(self.tx_depth)
    }
}

impl Drop for Ena {
    /// Its buffers are freed next: it must not know of them any more.
    fn drop(&mut self) {
        self.regs.write(reg::DEV_CTL, reg::DEV_CTL_RESET);
        let from = frame::time::now();
        while frame::time::now() - from < Duration::from_millis(100) {
            core::hint::spin_loop();
        }
        self.regs.write(reg::DEV_CTL, 0);
    }
}

impl net::link::Link for Ena {
    fn mac(&self) -> [u8; 6] {
        Ena::mac(self)
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        Ena::transmit(self, frame)
    }
    fn receive(&mut self) -> Option<Vec<u8>> {
        Ena::receive(self)
    }
    fn name(&self) -> &str {
        "ena"
    }
}
