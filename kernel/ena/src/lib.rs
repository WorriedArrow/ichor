//! AWS's Elastic Network Adapter (ENA), the network device of every Nitro
//! machine, without I/O: its registers, the admin commands and their
//! answers, what its I/O queues hold, and how a frame is laid out in a
//! low-latency queue (LLQ), whose descriptors and first bytes are written
//! into the device's own memory. `kernel/drivers/ena` does the I/O.
//!
//! The layouts and the order of things are from Amazon's `ena_com`
//! (BSD-3-Clause, as DPDK and FreeBSD carry it), written anew from its
//! definitions. Every queue is a ring of entries whose owner is told by a
//! phase bit that flips each time around; [`Cursor`] keeps a position and
//! its phase.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// Amazon's PCI vendor ID.
pub const VENDOR: u16 = 0x1d0f;
/// The ENA functions' device IDs (physical and virtual, with and without
/// low-latency queues).
pub const DEVICES: &[u16] = &[0x0ec2, 0x1ec2, 0xec20, 0xec21];
/// The BAR of the registers.
pub const REGISTER_BAR: usize = 0;
/// The BAR of the device memory low-latency queues live in.
pub const MEMORY_BAR: usize = 2;
/// PCI revision bit: registers are read directly, not by DMA.
pub const REVISION_DIRECT_READS: u8 = 1;

/// Registers (offsets in the register BAR) and their fields.
pub mod reg {
    pub const VERSION: u64 = 0x00;
    pub const CONTROLLER_VERSION: u64 = 0x04;
    pub const CAPS: u64 = 0x08;
    pub const AQ_BASE_LO: u64 = 0x10;
    pub const AQ_BASE_HI: u64 = 0x14;
    pub const AQ_CAPS: u64 = 0x18;
    pub const ACQ_BASE_LO: u64 = 0x20;
    pub const ACQ_BASE_HI: u64 = 0x24;
    pub const ACQ_CAPS: u64 = 0x28;
    /// The admin queue's tail.
    pub const AQ_DOORBELL: u64 = 0x2c;
    pub const AENQ_CAPS: u64 = 0x34;
    pub const AENQ_BASE_LO: u64 = 0x38;
    pub const AENQ_BASE_HI: u64 = 0x3c;
    /// The asynchronous event queue's head.
    pub const AENQ_HEAD_DOORBELL: u64 = 0x40;
    pub const DEV_CTL: u64 = 0x54;
    pub const DEV_STS: u64 = 0x58;
    /// Where a register read is asked for ...
    pub const MMIO_REG_READ: u64 = 0x5c;
    /// ... and where in memory its answer goes.
    pub const MMIO_RESP_LO: u64 = 0x60;
    pub const MMIO_RESP_HI: u64 = 0x64;

    pub const DEV_CTL_RESET: u32 = 1;
    pub const DEV_STS_READY: u32 = 1;
    pub const DEV_STS_RESET_IN_PROGRESS: u32 = 1 << 3;
    pub const DEV_STS_FATAL: u32 = 1 << 5;

    /// How long a reset may take, in units of 100 ms.
    pub fn reset_timeout(caps: u32) -> u32 {
        (caps >> 1) & 0x1f
    }

    /// How many bits a DMA address may have.
    pub fn dma_width(caps: u32) -> u32 {
        (caps >> 8) & 0xff
    }

    /// How long an admin command may take, in units of 100 ms (0: unsaid).
    pub fn admin_timeout(caps: u32) -> u32 {
        (caps >> 16) & 0xf
    }

    /// A queue's caps register: its depth and the size of an entry.
    pub fn queue_caps(depth: u16, entry: u16) -> u32 {
        u32::from(depth) | u32::from(entry) << 16
    }

    /// A request to read the register at `offset`, as request `id`.
    pub fn read_request(offset: u16, id: u16) -> u32 {
        u32::from(offset) << 16 | u32::from(id)
    }
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn get16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// An address as the device takes it: 32 low bits, then 16 high ones.
fn put_addr(b: &mut [u8], at: usize, addr: u64) {
    put32(b, at, addr as u32);
    put16(b, at + 4, (addr >> 32) as u16);
}

/// What the device writes to memory for a register read request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadAnswer {
    pub id: u16,
    pub offset: u16,
    pub value: u32,
}

/// The size of a [`ReadAnswer`] in memory.
pub const READ_ANSWER: usize = 8;

impl ReadAnswer {
    pub fn parse(b: &[u8; READ_ANSWER]) -> ReadAnswer {
        ReadAnswer {
            id: get16(b, 0),
            offset: get16(b, 2),
            value: get32(b, 4),
        }
    }
}

/// The size of every admin command, completion and event.
pub const ENTRY: usize = 64;

/// Admin opcodes.
pub mod opcode {
    pub const CREATE_SQ: u8 = 1;
    pub const CREATE_CQ: u8 = 3;
    pub const GET_FEATURE: u8 = 8;
    pub const SET_FEATURE: u8 = 9;
}

/// Features, as `GET_FEATURE` and `SET_FEATURE` name them.
pub mod feature {
    pub const DEVICE_ATTRIBUTES: u8 = 1;
    pub const MAX_QUEUES_NUM: u8 = 2;
    pub const LLQ: u8 = 4;
    pub const MAX_QUEUES_EXT: u8 = 7;
    pub const MTU: u8 = 14;
    pub const HOST_ATTR_CONFIG: u8 = 28;
    /// The versions of the answers this crate reads.
    pub const LLQ_VERSION: u8 = 1;
    pub const MAX_QUEUES_EXT_VERSION: u8 = 1;
}

/// A submission queue's direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Tx = 1,
    Rx = 2,
}

/// Where a submission queue's descriptors are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// In host memory, read by the device.
    Host = 1,
    /// In the device's memory, written by the driver (a low-latency queue).
    Device = 3,
}

/// No interrupt vector.
pub const NO_VECTOR: u32 = u32::MAX;

/// An admin command, without its id and phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command(pub [u8; ENTRY]);

impl Command {
    fn new(opcode: u8) -> Command {
        let mut b = [0; ENTRY];
        b[2] = opcode;
        Command(b)
    }

    /// The command of `opcode` about feature `id`, answered in `version`.
    fn about(opcode: u8, id: u8, version: u8) -> Command {
        let mut c = Command::new(opcode);
        c.0[17] = id;
        c.0[18] = version;
        c
    }

    /// Asks for feature `id`, answered in `version`.
    pub fn get_feature(id: u8, version: u8) -> Command {
        Command::about(opcode::GET_FEATURE, id, version)
    }

    /// Tells the device where its driver's description is
    /// ([`host_info`]).
    pub fn set_host_attributes(info: u64) -> Command {
        let mut c = Command::about(opcode::SET_FEATURE, feature::HOST_ATTR_CONFIG, 0);
        put_addr(&mut c.0, 20, info);
        c
    }

    /// Sets the largest IP packet (without the Ethernet header).
    pub fn set_mtu(mtu: u32) -> Command {
        let mut c = Command::about(opcode::SET_FEATURE, feature::MTU, 0);
        put32(&mut c.0, 20, mtu);
        c
    }

    /// Chooses how low-latency queues are laid out.
    pub fn set_llq(l: &Llq) -> Command {
        /// Every driver asks for both, whatever the device offers.
        const DISABLE_META_CACHING: u16 = 1;
        const LIMIT_TX_BURST: u16 = 2;
        let mut c = Command::about(opcode::SET_FEATURE, feature::LLQ, 0);
        put16(&mut c.0, 30, INLINE_HEADER);
        put16(&mut c.0, 34, l.entry_size_ctrl);
        put16(&mut c.0, 38, l.descs_before_header as u16);
        put16(&mut c.0, 42, l.stride_ctrl);
        put16(&mut c.0, 48, DISABLE_META_CACHING | LIMIT_TX_BURST);
        c
    }

    /// Creates a completion queue of `depth` entries of `entry_bytes` at
    /// bus address `ring`. It has no interrupt vector, as in DPDK's polled
    /// driver (vector 0, the admin queue's, is refused).
    pub fn create_cq(entry_bytes: u8, depth: u16, ring: u64) -> Command {
        const INTERRUPT_MODE: u8 = 1 << 5;
        let mut c = Command::new(opcode::CREATE_CQ);
        c.0[4] = INTERRUPT_MODE;
        c.0[5] = entry_bytes / 4;
        put16(&mut c.0, 6, depth);
        put32(&mut c.0, 8, NO_VECTOR);
        put_addr(&mut c.0, 12, ring);
        c
    }

    /// Creates a submission queue of `depth` entries completing into
    /// completion queue `cq`; its ring at bus address `ring` if the queue
    /// is in host memory. Every descriptor asks for a completion.
    pub fn create_sq(
        direction: Direction,
        placement: Placement,
        cq: u16,
        depth: u16,
        ring: Option<u64>,
    ) -> Command {
        const CONTIGUOUS: u8 = 1;
        let mut c = Command::new(opcode::CREATE_SQ);
        c.0[4] = (direction as u8) << 5;
        c.0[6] = placement as u8;
        c.0[7] = CONTIGUOUS;
        put16(&mut c.0, 8, cq);
        put16(&mut c.0, 10, depth);
        if let Some(r) = ring {
            put_addr(&mut c.0, 12, r);
        }
        c
    }

    pub fn opcode(&self) -> u8 {
        self.0[2]
    }

    /// The entry to put in the admin queue: this command as `id`, with the
    /// queue's current `phase`.
    pub fn entry(&self, id: u16, phase: bool) -> [u8; ENTRY] {
        let mut b = self.0;
        put16(&mut b, 0, id & 0xfff);
        b[3] |= u8::from(phase);
        b
    }
}

/// An admin completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion(pub [u8; ENTRY]);

impl Completion {
    /// The phase of a completion entry (to see whether it is new).
    pub fn phase_of(entry: &[u8; ENTRY]) -> bool {
        entry[3] & 1 != 0
    }

    /// The command it completes.
    pub fn id(&self) -> u16 {
        get16(&self.0, 0) & 0xfff
    }

    /// 0 for success.
    pub fn status(&self) -> u8 {
        self.0[2]
    }

    fn u16(&self, at: usize) -> u16 {
        get16(&self.0, at)
    }

    fn u32(&self, at: usize) -> u32 {
        get32(&self.0, at)
    }
}

/// What an admin status means.
pub fn status_name(status: u8) -> &'static str {
    match status {
        0 => "success",
        1 => "resource allocation failure",
        2 => "bad opcode",
        3 => "unsupported opcode",
        4 => "malformed request",
        5 => "illegal parameter",
        6 => "unknown error",
        7 => "resource busy",
        _ => "unknown status",
    }
}

/// The answer to `DEVICE_ATTRIBUTES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceAttributes {
    /// One bit per feature it has.
    pub supported: u32,
    pub dma_width: u32,
    pub mac: [u8; 6],
    pub max_mtu: u32,
}

impl DeviceAttributes {
    pub fn parse(c: &Completion) -> DeviceAttributes {
        let mut mac = [0; 6];
        mac.copy_from_slice(&c.0[32..38]);
        DeviceAttributes {
            supported: c.u32(16),
            dma_width: c.u32(24),
            mac,
            max_mtu: c.u32(40),
        }
    }

    /// Whether it has feature `id`.
    pub fn has(&self, id: u8) -> bool {
        id < 32 && self.supported & 1 << id != 0
    }
}

/// How deep the I/O queues may be, and how much of a frame its header may
/// be (in a queue in host memory).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub tx_depth: u32,
    pub tx_cq_depth: u32,
    pub rx_depth: u32,
    pub rx_cq_depth: u32,
    pub max_header: u32,
}

impl Limits {
    /// From `MAX_QUEUES_EXT`'s answer, if it is the version asked for.
    pub fn extended(c: &Completion) -> Option<Limits> {
        (c.0[8] == feature::MAX_QUEUES_EXT_VERSION).then(|| Limits {
            tx_depth: c.u32(28),
            tx_cq_depth: c.u32(32),
            rx_depth: c.u32(36),
            rx_cq_depth: c.u32(40),
            max_header: c.u32(44),
        })
    }

    /// From `MAX_QUEUES_NUM`'s (one depth for both directions).
    pub fn basic(c: &Completion) -> Limits {
        Limits {
            tx_depth: c.u32(12),
            tx_cq_depth: c.u32(20),
            rx_depth: c.u32(12),
            rx_cq_depth: c.u32(20),
            max_header: c.u32(32),
        }
    }
}

/// The header goes in the descriptors' own entry.
const INLINE_HEADER: u16 = 1;
const SINGLE_DESC_PER_ENTRY: u16 = 1;
const MULTIPLE_DESCS_PER_ENTRY: u16 = 2;

/// What the device offers of low-latency queues (`LLQ`'s answer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LlqOffer {
    pub max_queues: u32,
    pub max_depth: u32,
    pub header_locations: u16,
    pub entry_sizes: u16,
    pub descs_before_header: u16,
    pub strides: u16,
    pub accel_flags: u16,
    pub max_tx_burst: u16,
}

/// How low-latency queues are laid out (what [`LlqOffer::choose`] chose).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Llq {
    /// Bytes in an entry, and the device's name for that size.
    pub entry_size: usize,
    entry_size_ctrl: u16,
    /// Descriptors in a frame's first entry, before its header.
    pub descs_before_header: usize,
    /// Descriptors in each later entry.
    pub descs_per_entry: usize,
    stride_ctrl: u16,
    /// Every frame starts with a metadata descriptor.
    pub meta_every_frame: bool,
    /// The most entries written between doorbells (0: no limit).
    pub max_burst: usize,
    pub max_depth: u32,
}

impl LlqOffer {
    pub fn parse(c: &Completion) -> LlqOffer {
        LlqOffer {
            max_queues: c.u32(8),
            max_depth: c.u32(12),
            header_locations: c.u16(16),
            entry_sizes: c.u16(20),
            descs_before_header: c.u16(24),
            strides: c.u16(28),
            accel_flags: c.u16(36),
            max_tx_burst: c.u16(38),
        }
    }

    /// The layout Linux's driver chooses by default, or the nearest the
    /// device has: headers inline, 128-byte entries, two descriptors
    /// before the header, several descriptors in later entries. `None` if
    /// it has no low-latency queues (or none this driver can use).
    pub fn choose(&self) -> Option<Llq> {
        const DISABLE_META_CACHING: u16 = 1;
        const LIMIT_TX_BURST: u16 = 2;
        if self.max_queues == 0 || self.max_depth == 0 {
            return None;
        }
        if self.header_locations & INLINE_HEADER == 0 {
            return None;
        }
        let stride_ctrl = [MULTIPLE_DESCS_PER_ENTRY, SINGLE_DESC_PER_ENTRY]
            .into_iter()
            .find(|s| self.strides & s != 0)?;
        let (entry_size_ctrl, entry_size) = [(1, 128), (2, 192), (4, 256)]
            .into_iter()
            .find(|(bit, _)| self.entry_sizes & bit != 0)?;
        let descs_before_header = [2u16, 1, 4, 8]
            .into_iter()
            .find(|n| self.descs_before_header & n != 0)?
            as usize;
        if descs_before_header * DESC >= entry_size {
            return None;
        }
        let descs_per_entry = if stride_ctrl == MULTIPLE_DESCS_PER_ENTRY {
            entry_size / DESC
        } else {
            1
        };
        let max_burst = if self.accel_flags & LIMIT_TX_BURST != 0 {
            usize::from(self.max_tx_burst) / entry_size
        } else {
            0
        };
        Some(Llq {
            entry_size,
            entry_size_ctrl,
            descs_before_header,
            descs_per_entry,
            stride_ctrl,
            meta_every_frame: self.accel_flags & DISABLE_META_CACHING != 0,
            max_burst,
            max_depth: self.max_depth,
        })
    }
}

impl Llq {
    /// The most bytes of a frame its first entry holds.
    pub fn max_header(&self) -> usize {
        self.entry_size - DESC * self.descs_before_header
    }
}

/// The answer to `CREATE_SQ`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatedSq {
    pub index: u16,
    /// Offset of its doorbell in the register BAR.
    pub doorbell: u32,
    /// Offset of its entries in the memory BAR (a low-latency queue).
    pub llq_entries: u32,
}

impl CreatedSq {
    pub fn parse(c: &Completion) -> CreatedSq {
        CreatedSq {
            index: c.u16(8),
            doorbell: c.u32(12),
            llq_entries: c.u32(16),
        }
    }
}

/// The answer to `CREATE_CQ`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatedCq {
    pub index: u16,
    pub depth: u16,
    /// Offset of its head doorbell in the register BAR (0: it has none).
    pub head_doorbell: u32,
}

impl CreatedCq {
    pub fn parse(c: &Completion) -> CreatedCq {
        CreatedCq {
            index: c.u16(8),
            depth: c.u16(10),
            head_doorbell: c.u32(16),
        }
    }
}

/// The size of [`host_info`].
pub const HOST_INFO: usize = 196;

/// What the driver says of itself (`set_host_attributes` points at it):
/// the kind of system, names, a driver version, the specification version
/// it follows, its PCI address and the number of CPUs. It claims no
/// optional features.
///
/// The device reads more into the kind and the version than it should:
/// AWS's firmware refuses to create completion queues (status 6) for
/// kinds and versions it does not like, as iPXE's developers found, and as
/// this driver found with kind 3 and version 0.1.0. Linux's kind, and
/// version 2.0.0, are taken.
pub fn host_info(cpus: u16, bdf: u16) -> [u8; HOST_INFO] {
    const LINUX: u32 = 1;
    const DRIVER_VERSION: u32 = 2;
    const SPEC_VERSION: u16 = 2 << 8;
    let mut b = [0; HOST_INFO];
    put32(&mut b, 0, LINUX);
    b[4..9].copy_from_slice(b"Ichor");
    b[136..141].copy_from_slice(b"ichor");
    put32(&mut b, 172, DRIVER_VERSION);
    put16(&mut b, 184, SPEC_VERSION);
    put16(&mut b, 186, bdf);
    put16(&mut b, 188, cpus);
    b
}

/// An asynchronous event: its group, syndrome, and (for a link change) the
/// link's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub group: u16,
    pub syndrome: u16,
    pub link_up: bool,
}

impl Event {
    pub const LINK_CHANGE: u16 = 0;
    pub const FATAL_ERROR: u16 = 1;
    pub const KEEP_ALIVE: u16 = 4;

    /// The phase of an event entry.
    pub fn phase_of(entry: &[u8; ENTRY]) -> bool {
        entry[4] & 1 != 0
    }

    pub fn parse(entry: &[u8; ENTRY]) -> Event {
        Event {
            group: get16(entry, 0),
            syndrome: get16(entry, 2),
            link_up: get32(entry, 16) & 1 != 0,
        }
    }
}

/// A position in a ring of `depth` entries (a power of two): how many
/// entries went by, and the phase the current one is written with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    mask: u16,
    count: u16,
    phase: bool,
}

impl Cursor {
    /// At the start of a fresh ring (phase 1).
    pub fn new(depth: u16) -> Cursor {
        Cursor::at(depth, 0)
    }

    /// At `count`, which a doorbell will say (the event queue starts at its
    /// depth).
    pub fn at(depth: u16, count: u16) -> Cursor {
        debug_assert!(depth.is_power_of_two());
        Cursor {
            mask: depth.wrapping_sub(1),
            count,
            phase: true,
        }
    }

    /// The entry it is at.
    pub fn slot(&self) -> usize {
        usize::from(self.count & self.mask)
    }

    /// Entries gone by (what doorbells are told).
    pub fn count(&self) -> u16 {
        self.count
    }

    pub fn phase(&self) -> bool {
        self.phase
    }

    pub fn advance(&mut self) {
        self.count = self.count.wrapping_add(1);
        if self.count & self.mask == 0 {
            self.phase = !self.phase;
        }
    }

    /// Entries from `earlier` to here.
    pub fn since(&self, earlier: u16) -> u16 {
        self.count.wrapping_sub(earlier)
    }
}

/// The size of a descriptor.
pub const DESC: usize = 16;
/// The size of a transmit completion.
pub const TX_COMPLETION: usize = 8;
/// The size of a receive completion.
pub const RX_COMPLETION: usize = 16;

/// A transmit descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxDesc {
    pub len: u16,
    pub req_id: u16,
    pub phase: bool,
    pub first: bool,
    pub last: bool,
    pub completion: bool,
    pub addr: u64,
    /// Bytes of the frame that are its header (pushed, in an LLQ).
    pub header_len: u8,
}

impl TxDesc {
    pub fn bytes(&self) -> [u8; DESC] {
        let bit = |b: bool, at: u32| u32::from(b) << at;
        let mut d = [0; DESC];
        put32(
            &mut d,
            0,
            u32::from(self.len)
                | u32::from(self.req_id >> 10 & 0x3f) << 16
                | bit(self.phase, 24)
                | bit(self.first, 26)
                | bit(self.last, 27)
                | bit(self.completion, 28),
        );
        put32(&mut d, 4, u32::from(self.req_id & 0x3ff) << 22);
        put32(&mut d, 8, self.addr as u32);
        put32(
            &mut d,
            12,
            (self.addr >> 32) as u32 & 0xffff | u32::from(self.header_len) << 24,
        );
        d
    }
}

/// A metadata descriptor that asks for no offloads: the first of a frame
/// when the device wants one with every frame.
pub fn tx_meta(phase: bool) -> [u8; DESC] {
    const EXT_VALID: u32 = 1 << 14;
    const ETH_META_TYPE: u32 = 1 << 20;
    const META_STORE: u32 = 1 << 21;
    const META_DESC: u32 = 1 << 23;
    const FIRST: u32 = 1 << 26;
    let mut d = [0; DESC];
    let w = EXT_VALID | ETH_META_TYPE | META_STORE | META_DESC | FIRST | u32::from(phase) << 24;
    put32(&mut d, 0, w);
    d
}

/// The descriptor of a frame in a queue in host memory: `len` bytes at
/// `addr`, the first `header_len` of them its header. Advances `sq`;
/// returns the slot and the descriptor.
pub fn tx_host(
    sq: &mut Cursor,
    req_id: u16,
    addr: u64,
    len: u16,
    header_len: u8,
) -> (usize, [u8; DESC]) {
    let d = TxDesc {
        len,
        req_id,
        phase: sq.phase(),
        first: true,
        last: true,
        completion: true,
        addr,
        header_len,
    };
    let slot = sq.slot();
    sq.advance();
    (slot, d.bytes())
}

/// The entries of a frame in a low-latency queue: `header` (at most
/// [`Llq::max_header`] bytes) pushed into its first entry, the rest of the
/// frame (`buffer`: bus address and length) read by the device. Advances
/// `sq` past them; returns each entry's slot and bytes, or `None` if the
/// header does not fit.
pub fn tx_llq(
    sq: &mut Cursor,
    llq: &Llq,
    req_id: u16,
    header: &[u8],
    buffer: Option<(u64, u16)>,
) -> Option<Vec<(usize, Vec<u8>)>> {
    if header.len() > llq.max_header() {
        return None;
    }
    let mut entries = Vec::new();
    let mut entry = vec![0u8; llq.entry_size];
    let at = llq.descs_before_header * DESC;
    entry[at..at + header.len()].copy_from_slice(header);
    let (mut used, mut left) = (0, llq.descs_before_header);
    let meta = llq.meta_every_frame;
    let (addr, len) = buffer.unwrap_or((0, 0));
    for i in 0..1 + usize::from(meta) {
        let d = if meta && i == 0 {
            tx_meta(sq.phase())
        } else {
            TxDesc {
                len,
                req_id,
                phase: sq.phase(),
                first: !meta,
                last: true,
                completion: true,
                addr,
                header_len: header.len() as u8,
            }
            .bytes()
        };
        entry[used * DESC..(used + 1) * DESC].copy_from_slice(&d);
        used += 1;
        left -= 1;
        // A full entry goes to the device; later descriptors take the next.
        if left == 0 {
            let full = core::mem::replace(&mut entry, vec![0u8; llq.entry_size]);
            entries.push((sq.slot(), full));
            sq.advance();
            (used, left) = (0, llq.descs_per_entry);
        }
    }
    if used > 0 {
        entries.push((sq.slot(), entry));
        sq.advance();
    }
    Some(entries)
}

/// A receive descriptor: a buffer of `len` bytes at `addr`, as request
/// `req_id`.
pub fn rx_desc(phase: bool, req_id: u16, addr: u64, len: u16) -> [u8; DESC] {
    const FIRST: u8 = 1 << 2;
    const LAST: u8 = 1 << 3;
    const COMPLETION: u8 = 1 << 4;
    let mut d = [0; DESC];
    put16(&mut d, 0, len);
    d[3] = u8::from(phase) | FIRST | LAST | COMPLETION;
    put16(&mut d, 4, req_id);
    put_addr(&mut d, 8, addr);
    d
}

/// A transmit completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxCompletion {
    pub phase: bool,
    pub req_id: u16,
    pub status: u8,
}

impl TxCompletion {
    pub fn parse(b: &[u8; TX_COMPLETION]) -> TxCompletion {
        TxCompletion {
            phase: b[3] & 1 != 0,
            req_id: get16(b, 0),
            status: b[2],
        }
    }
}

/// A receive completion: one buffer of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxCompletion {
    pub phase: bool,
    pub first: bool,
    pub last: bool,
    pub len: u16,
    pub req_id: u16,
    /// Where in the buffer the frame starts.
    pub offset: u8,
}

impl RxCompletion {
    pub fn parse(b: &[u8; RX_COMPLETION]) -> RxCompletion {
        let status = get32(b, 0);
        RxCompletion {
            phase: status & 1 << 24 != 0,
            first: status & 1 << 26 != 0,
            last: status & 1 << 27 != 0,
            len: get16(b, 4),
            req_id: get16(b, 6),
            offset: b[14],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completion(fill: impl FnOnce(&mut [u8; ENTRY])) -> Completion {
        let mut b = [0; ENTRY];
        fill(&mut b);
        Completion(b)
    }

    #[test]
    fn register_fields() {
        assert_eq!(reg::read_request(0x58, 7), 0x0058_0007);
        assert_eq!(reg::queue_caps(32, 64), 0x0040_0020);
        let caps = 0x0003_3014; // admin 3, width 48, reset 10
        assert_eq!(reg::reset_timeout(caps), 10);
        assert_eq!(reg::dma_width(caps), 0x30);
        assert_eq!(reg::admin_timeout(caps), 3);
        let a = ReadAnswer::parse(&[7, 0, 0x58, 0, 1, 0, 0, 0x80]);
        assert_eq!((a.id, a.offset, a.value), (7, 0x58, 0x8000_0001));
    }

    #[test]
    fn commands_are_laid_out_as_the_device_reads_them() {
        let e = Command::get_feature(feature::LLQ, feature::LLQ_VERSION).entry(0x1005, true);
        assert_eq!(&e[..4], &[5, 0, opcode::GET_FEATURE, 1]);
        assert_eq!((e[17], e[18]), (feature::LLQ, 1));

        let c = Command::create_sq(Direction::Tx, Placement::Device, 3, 512, None);
        assert_eq!(&c.0[4..12], &[1 << 5, 0, 3, 1, 3, 0, 0, 2]);
        assert!(c.0[12..20].iter().all(|&b| b == 0));
        let c = Command::create_sq(
            Direction::Rx,
            Placement::Host,
            1,
            256,
            Some(0x1234_5678_9abc),
        );
        assert_eq!(&c.0[4..8], &[2 << 5, 0, 1, 1]);
        assert_eq!(&c.0[12..18], &[0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]);

        let c = Command::create_cq(16, 256, 0x2000);
        assert_eq!(&c.0[4..8], &[1 << 5, 4, 0, 1]);
        assert_eq!(&c.0[8..16], &[0xff, 0xff, 0xff, 0xff, 0, 0x20, 0, 0]);

        let c = Command::set_host_attributes(0x1_0000_3000);
        assert_eq!(
            (c.opcode(), c.0[17]),
            (opcode::SET_FEATURE, feature::HOST_ATTR_CONFIG)
        );
        assert_eq!(&c.0[20..26], &[0, 0x30, 0, 0, 1, 0]);
        let c = Command::set_mtu(1500);
        assert_eq!((c.0[17], get32(&c.0, 20)), (feature::MTU, 1500));
    }

    fn offer() -> LlqOffer {
        LlqOffer {
            max_queues: 8,
            max_depth: 1024,
            header_locations: 1,
            entry_sizes: 1 | 4,
            descs_before_header: 1 | 2 | 4 | 8,
            strides: 1 | 2,
            accel_flags: 3,
            max_tx_burst: 1024,
        }
    }

    #[test]
    fn llq_layout_is_chosen_as_linux_chooses() {
        let l = offer().choose().unwrap();
        assert_eq!(
            (l.entry_size, l.descs_before_header, l.descs_per_entry),
            (128, 2, 8)
        );
        assert_eq!(
            (l.max_header(), l.max_burst, l.meta_every_frame),
            (96, 8, true)
        );
        let c = Command::set_llq(&l);
        assert_eq!(c.0[17], feature::LLQ);
        let at = |o| get16(&c.0, o);
        assert_eq!((at(30), at(34), at(38), at(42), at(48)), (1, 1, 2, 2, 3));

        // What the device lacks, the next it has.
        let l = LlqOffer {
            entry_sizes: 4,
            descs_before_header: 1,
            strides: 1,
            ..offer()
        }
        .choose()
        .unwrap();
        assert_eq!(
            (l.entry_size, l.descs_before_header, l.descs_per_entry),
            (256, 1, 1)
        );
        assert_eq!(l.max_header(), 240);
        assert_eq!(
            LlqOffer {
                max_queues: 0,
                ..offer()
            }
            .choose(),
            None
        );
        assert_eq!(
            LlqOffer {
                header_locations: 2,
                ..offer()
            }
            .choose(),
            None
        );
        assert_eq!(
            LlqOffer {
                entry_sizes: 0,
                ..offer()
            }
            .choose(),
            None
        );
    }

    #[test]
    fn answers_are_read_where_the_device_writes_them() {
        let c = completion(|b| {
            put16(b, 0, 0x0102);
            b[2] = 5;
            b[3] = 1;
            put32(b, 16, 1 << feature::LLQ | 1 << feature::MTU);
            put32(b, 24, 48);
            b[32..38].copy_from_slice(&[2, 0, 0, 0, 0xab, 0xcd]);
            put32(b, 40, 9216);
        });
        assert!(Completion::phase_of(&c.0));
        assert_eq!(
            (c.id(), c.status(), status_name(c.status())),
            (0x102, 5, "illegal parameter")
        );
        let a = DeviceAttributes::parse(&c);
        assert!(a.has(feature::LLQ) && a.has(feature::MTU) && !a.has(feature::MAX_QUEUES_EXT));
        assert_eq!(
            (a.dma_width, a.mac, a.max_mtu),
            (48, [2, 0, 0, 0, 0xab, 0xcd], 9216)
        );

        let c = completion(|b| {
            b[8] = 1;
            for (i, v) in [8u32, 8, 8, 8, 1024, 1024, 2048, 2048, 96]
                .into_iter()
                .enumerate()
            {
                put32(b, 12 + 4 * i, v);
            }
        });
        let l = Limits::extended(&c).unwrap();
        assert_eq!(
            (l.tx_depth, l.tx_cq_depth, l.rx_depth, l.rx_cq_depth),
            (1024, 1024, 2048, 2048)
        );
        assert_eq!(l.max_header, 96);
        assert_eq!(Limits::extended(&completion(|b| b[8] = 2)), None);

        let c = completion(|b| {
            put16(b, 8, 3);
            put32(b, 12, 0x1008);
            put32(b, 16, 0x40_0000);
        });
        assert_eq!(
            CreatedSq::parse(&c),
            CreatedSq {
                index: 3,
                doorbell: 0x1008,
                llq_entries: 0x40_0000
            }
        );
        let c = completion(|b| {
            put16(b, 8, 2);
            put16(b, 10, 256);
            put32(b, 16, 0x2004);
        });
        assert_eq!(
            CreatedCq::parse(&c),
            CreatedCq {
                index: 2,
                depth: 256,
                head_doorbell: 0x2004
            }
        );

        let c = completion(|b| {
            b[8] = 0;
            put32(b, 8, 4);
            put32(b, 12, 1024);
            put16(b, 16, 1);
            put16(b, 20, 5);
            put16(b, 24, 0xf);
            put16(b, 28, 3);
            put16(b, 36, 3);
            put16(b, 38, 2048);
        });
        assert_eq!(
            LlqOffer::parse(&c),
            LlqOffer {
                max_queues: 4,
                max_tx_burst: 2048,
                ..offer()
            }
        );
    }

    #[test]
    fn host_info_says_what_it_is() {
        let h = host_info(4, 0x0028);
        assert_eq!((get32(&h, 0), get32(&h, 172)), (1, 2));
        assert_eq!(&h[4..10], b"Ichor\0");
        assert_eq!(
            (get16(&h, 184), get16(&h, 186), get16(&h, 188)),
            (0x200, 0x28, 4)
        );
        assert_eq!(get32(&h, 192), 0);
    }

    #[test]
    fn cursors_flip_their_phase_each_time_around() {
        let mut c = Cursor::new(4);
        let seen: Vec<_> = (0..9)
            .map(|_| {
                let s = (c.slot(), c.phase());
                c.advance();
                s
            })
            .collect();
        assert_eq!(
            seen[..5],
            [(0, true), (1, true), (2, true), (3, true), (0, false)]
        );
        assert_eq!(seen[8], (0, true));
        assert_eq!(c.count(), 9);
        assert_eq!(c.since(5), 4);
        // The event queue starts at its depth, at slot 0 and phase 1.
        let mut e = Cursor::at(16, 16);
        assert_eq!((e.slot(), e.phase()), (0, true));
        for _ in 0..16 {
            e.advance();
        }
        assert_eq!((e.slot(), e.phase(), e.count()), (0, false, 32));
    }

    #[test]
    fn transmit_descriptors_split_the_request_id() {
        let d = TxDesc {
            len: 1514,
            req_id: 0x2c05,
            phase: true,
            first: true,
            last: true,
            completion: true,
            addr: 0x12_3456_7000,
            header_len: 42,
        }
        .bytes();
        assert_eq!(
            get32(&d, 0),
            1514 | 0x0b << 16 | 1 << 24 | 1 << 26 | 1 << 27 | 1 << 28
        );
        assert_eq!(get32(&d, 4), 0x005 << 22);
        assert_eq!(
            (get32(&d, 8), get32(&d, 12)),
            (0x3456_7000, 0x12 | 42 << 24)
        );
        let m = get32(&tx_meta(false), 0);
        assert_eq!(m, 1 << 14 | 1 << 20 | 1 << 21 | 1 << 23 | 1 << 26);

        let mut sq = Cursor::new(2);
        let (slot, d) = tx_host(&mut sq, 1, 0x5000, 60, 60);
        assert_eq!((slot, get32(&d, 0) & 0xffff, d[15]), (0, 60, 60));
        tx_host(&mut sq, 2, 0x5000, 60, 60);
        let (slot, d) = tx_host(&mut sq, 3, 0x5000, 60, 60);
        assert_eq!((slot, get32(&d, 0) & 1 << 24), (0, 0));
    }

    #[test]
    fn a_frame_takes_one_llq_entry_its_header_pushed_after_two_descriptors() {
        let l = offer().choose().unwrap();
        let mut sq = Cursor::new(4);
        let frame: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let e = tx_llq(&mut sq, &l, 9, &frame[..96], Some((0x8000, 104))).unwrap();
        assert_eq!(e.len(), 1);
        let (slot, b) = &e[0];
        assert_eq!((*slot, b.len(), sq.count()), (0, 128, 1));
        // The metadata descriptor is the frame's first ...
        assert_eq!(get32(b, 0), get32(&tx_meta(true), 0));
        // ... then its data, the last, with the header's length ...
        let w = get32(b, 16);
        assert_eq!(w & 0xffff, 104);
        assert_eq!(
            w & (1 << 24 | 1 << 26 | 1 << 27 | 1 << 28),
            1 << 24 | 1 << 27 | 1 << 28
        );
        assert_eq!(get32(b, 20) >> 22, 9);
        assert_eq!((get32(b, 24), b[31]), (0x8000, 96));
        // ... and the header.
        assert_eq!(&b[32..], &frame[..96]);

        // A short frame is all header.
        let e = tx_llq(&mut sq, &l, 10, &frame[..60], None).unwrap();
        assert_eq!(e[0].0, 1);
        assert_eq!(get32(&e[0].1, 16) & 0xffff, 0);
        assert_eq!(get32(&e[0].1, 24), 0);
        assert!(tx_llq(&mut sq, &l, 11, &frame[..97], None).is_none());
        // Around the ring the phase flips.
        tx_llq(&mut sq, &l, 12, &frame[..60], None).unwrap();
        tx_llq(&mut sq, &l, 13, &frame[..60], None).unwrap();
        let e = tx_llq(&mut sq, &l, 14, &frame[..60], None).unwrap();
        assert_eq!(e[0].0, 0);
        assert_eq!(get32(&e[0].1, 0) & 1 << 24, 0);
        assert_eq!(get32(&e[0].1, 16) & 1 << 24, 0);
    }

    #[test]
    fn with_one_descriptor_before_the_header_the_data_takes_a_second_entry() {
        let l = LlqOffer {
            descs_before_header: 1,
            strides: 1,
            ..offer()
        }
        .choose()
        .unwrap();
        let mut sq = Cursor::new(2);
        sq.advance();
        let e = tx_llq(&mut sq, &l, 4, &[0xee; 112], Some((0x9000, 400))).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].0, e[1].0), (1, 0));
        assert_eq!(&e[0].1[16..], &[0xee; 112][..]);
        assert_eq!(get32(&e[0].1, 0) & 1 << 24, 1 << 24);
        // The data descriptor is in the next entry, which wrapped.
        assert_eq!(get32(&e[1].1, 0) & (0xffff | 1 << 24), 400);
        assert!(e[1].1[16..].iter().all(|&b| b == 0));
    }

    #[test]
    fn receive_descriptors_and_completions() {
        let d = rx_desc(true, 77, 0x1_2345_6000, 2048);
        assert_eq!(&d[..8], &[0, 8, 0, 0x1d, 77, 0, 0, 0]);
        assert_eq!(&d[8..14], &[0, 0x60, 0x45, 0x23, 1, 0]);
        let mut c = [0u8; RX_COMPLETION];
        put32(&mut c, 0, 1 << 24 | 1 << 26 | 1 << 27 | 1 << 30);
        put16(&mut c, 4, 1514);
        put16(&mut c, 6, 77);
        c[14] = 2;
        let r = RxCompletion::parse(&c);
        assert_eq!(
            r,
            RxCompletion {
                phase: true,
                first: true,
                last: true,
                len: 1514,
                req_id: 77,
                offset: 2
            }
        );
        let t = TxCompletion::parse(&[9, 0, 0, 1, 0, 0, 3, 0]);
        assert_eq!(
            t,
            TxCompletion {
                phase: true,
                req_id: 9,
                status: 0
            }
        );
    }

    #[test]
    fn events_are_read() {
        let mut e = [0u8; ENTRY];
        put16(&mut e, 0, Event::LINK_CHANGE);
        e[4] = 1;
        put32(&mut e, 16, 1);
        assert!(Event::phase_of(&e));
        assert_eq!(
            Event::parse(&e),
            Event {
                group: 0,
                syndrome: 0,
                link_up: true
            }
        );
    }
}
