//! Google's virtual NIC (gVNIC, `gve`), without I/O: its registers, the
//! admin commands, the device descriptor and its options, and the GQI
//! queue format with queue page lists (QPL), where the device reads and
//! writes only pages the driver registered and frames are copied through
//! them. `kernel/drivers/gve` does the I/O.
//!
//! Every multi-byte field the device reads or writes is big-endian. The
//! layouts are from Google's gve base code (MIT, as DPDK carries it) and
//! DPDK's driver (BSD-3-Clause), written anew from their definitions.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// Google's PCI vendor ID and the gVNIC's device ID.
pub const VENDOR: u16 = 0x1ae0;
pub const DEVICE: u16 = 0x0042;
/// The BAR of the registers, and of the doorbells.
pub const REGISTER_BAR: usize = 0;
pub const DOORBELL_BAR: usize = 2;
pub const PAGE: usize = 4096;

/// Registers (big-endian, offsets in the register BAR).
pub mod reg {
    pub const DEVICE_STATUS: u64 = 0x00;
    pub const DRIVER_STATUS: u64 = 0x04;
    pub const MAX_TX_QUEUES: u64 = 0x08;
    pub const MAX_RX_QUEUES: u64 = 0x0c;
    /// The admin queue's page number (devices of PCI revision 0).
    pub const ADMINQ_PFN: u64 = 0x10;
    pub const ADMINQ_DOORBELL: u64 = 0x14;
    pub const ADMINQ_EVENT_COUNTER: u64 = 0x18;
    /// One byte: the driver's version string is written here a byte at a
    /// time.
    pub const DRIVER_VERSION: u64 = 0x1f;
    /// The admin queue's address and length (devices of revision 1 on).
    pub const ADMINQ_BASE_HI: u64 = 0x20;
    pub const ADMINQ_BASE_LO: u64 = 0x24;
    pub const ADMINQ_LENGTH: u64 = 0x28;

    /// Device status: it wants the driver to reset it; its link is up; it
    /// has been reset (after the driver asked).
    pub const STATUS_RESET: u32 = 1 << 1;
    pub const STATUS_LINK: u32 = 1 << 2;
    pub const STATUS_IS_RESET: u32 = 1 << 4;
    /// Driver status: running; reset me.
    pub const DRIVER_RUN: u32 = 1;
    pub const DRIVER_RESET: u32 = 1 << 1;
}

/// The size of an admin command.
pub const COMMAND: usize = 64;

/// Admin opcodes.
pub mod opcode {
    pub const DESCRIBE_DEVICE: u32 = 0x1;
    pub const CONFIGURE_DEVICE_RESOURCES: u32 = 0x2;
    pub const REGISTER_PAGE_LIST: u32 = 0x3;
    pub const CREATE_TX_QUEUE: u32 = 0x5;
    pub const CREATE_RX_QUEUE: u32 = 0x6;
    pub const DECONFIGURE_DEVICE_RESOURCES: u32 = 0x9;
    pub const SET_DRIVER_PARAMETER: u32 = 0xb;
    pub const VERIFY_DRIVER_COMPATIBILITY: u32 = 0xf;
}

/// Admin statuses: not yet run, passed; the rest are errors.
pub const STATUS_UNSET: u32 = 0;
pub const STATUS_PASSED: u32 = 1;
pub const STATUS_UNIMPLEMENTED: u32 = 0xffff_fffe;

/// What an admin status means.
pub fn status_name(s: u32) -> &'static str {
    match s {
        STATUS_UNSET => "not run",
        STATUS_PASSED => "passed",
        0xffff_fff0 => "aborted",
        0xffff_fff1 => "already exists",
        0xffff_fff2 => "cancelled",
        0xffff_fff3 => "data loss",
        0xffff_fff4 => "deadline exceeded",
        0xffff_fff5 => "failed precondition",
        0xffff_fff6 => "internal error",
        0xffff_fff7 => "invalid argument",
        0xffff_fff8 => "not found",
        0xffff_fff9 => "out of range",
        0xffff_fffa => "permission denied",
        0xffff_fffb => "unauthenticated",
        0xffff_fffc => "resource exhausted",
        0xffff_fffd => "unavailable",
        STATUS_UNIMPLEMENTED => "unimplemented",
        _ => "unknown error",
    }
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_be_bytes());
}

fn get16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn get64(b: &[u8], at: usize) -> u64 {
    let mut a = [0; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(a)
}

/// An admin command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command(pub [u8; COMMAND]);

impl Command {
    fn new(op: u32) -> Command {
        let mut b = [0; COMMAND];
        put32(&mut b, 0, op);
        Command(b)
    }

    pub fn opcode(&self) -> u32 {
        get32(&self.0, 0)
    }

    /// The status the device wrote back into a command.
    pub fn status_of(entry: &[u8; COMMAND]) -> u32 {
        get32(entry, 4)
    }

    /// Asks the device to describe itself into `len` bytes at `addr`.
    pub fn describe_device(addr: u64, len: u32) -> Command {
        const VERSION: u32 = 1;
        let mut c = Command::new(opcode::DESCRIBE_DEVICE);
        put64(&mut c.0, 8, addr);
        put32(&mut c.0, 16, VERSION);
        put32(&mut c.0, 20, len);
        c
    }

    /// Tells the device what the driver is ([`driver_info`] at `addr`).
    pub fn verify_driver(addr: u64, len: u64) -> Command {
        let mut c = Command::new(opcode::VERIFY_DRIVER_COMPATIBILITY);
        put64(&mut c.0, 8, len);
        put64(&mut c.0, 16, addr);
        c
    }

    /// Gives the device its event counters and interrupt doorbells (it
    /// writes each doorbell's index into its slot), and the queue format.
    pub fn configure_resources(
        counters: u64,
        n_counters: u32,
        irq_dbs: u64,
        n_irq_dbs: u32,
        format: QueueFormat,
    ) -> Command {
        let mut c = Command::new(opcode::CONFIGURE_DEVICE_RESOURCES);
        put64(&mut c.0, 8, counters);
        put64(&mut c.0, 16, irq_dbs);
        put32(&mut c.0, 24, n_counters);
        put32(&mut c.0, 28, n_irq_dbs);
        put32(&mut c.0, 32, IRQ_DB_STRIDE as u32);
        // Notification blocks start at MSI-X vector 0.
        put32(&mut c.0, 36, 0);
        c.0[40] = format as u8;
        c
    }

    /// Registers queue page list `id`: `n` pages, whose (big-endian) bus
    /// addresses are at `list`.
    pub fn register_page_list(id: u32, n: u32, list: u64) -> Command {
        let mut c = Command::new(opcode::REGISTER_PAGE_LIST);
        put32(&mut c.0, 8, id);
        put32(&mut c.0, 12, n);
        put64(&mut c.0, 16, list);
        c
    }

    /// Creates transmit queue `id` of `size` descriptors at `ring`, its
    /// frames in page list `qpl`, its resources (doorbell and counter
    /// index, which the device writes) at `resources`.
    pub fn create_tx(
        id: u32,
        resources: u64,
        ring: u64,
        qpl: u32,
        ntfy: u32,
        size: u16,
    ) -> Command {
        let mut c = Command::new(opcode::CREATE_TX_QUEUE);
        put32(&mut c.0, 8, id);
        put64(&mut c.0, 16, resources);
        put64(&mut c.0, 24, ring);
        put32(&mut c.0, 32, qpl);
        put32(&mut c.0, 36, ntfy);
        put16(&mut c.0, 48, size);
        c
    }

    /// Creates receive queue `id` of `size` descriptors (at `desc`) and
    /// data slots (at `data`), its buffers of `buffer` bytes in page list
    /// `qpl`.
    #[allow(clippy::too_many_arguments)] // one per field of the command
    pub fn create_rx(
        id: u32,
        ntfy: u32,
        resources: u64,
        desc: u64,
        data: u64,
        qpl: u32,
        size: u16,
        buffer: u16,
    ) -> Command {
        let mut c = Command::new(opcode::CREATE_RX_QUEUE);
        put32(&mut c.0, 8, id);
        put32(&mut c.0, 12, id);
        put32(&mut c.0, 20, ntfy);
        put64(&mut c.0, 24, resources);
        put64(&mut c.0, 32, desc);
        put64(&mut c.0, 40, data);
        put32(&mut c.0, 48, qpl);
        put16(&mut c.0, 52, size);
        put16(&mut c.0, 54, buffer);
        c
    }

    /// Sets the largest IP packet the device sends and receives.
    pub fn set_mtu(mtu: u64) -> Command {
        const MTU: u32 = 1;
        let mut c = Command::new(opcode::SET_DRIVER_PARAMETER);
        put32(&mut c.0, 8, MTU);
        put64(&mut c.0, 16, mtu);
        c
    }

    /// Takes back what `configure_resources` gave (before a reset).
    pub fn deconfigure_resources() -> Command {
        Command::new(opcode::DECONFIGURE_DEVICE_RESOURCES)
    }
}

/// Bytes between interrupt doorbell slots (a cache line).
pub const IRQ_DB_STRIDE: usize = 64;

/// Queue formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueFormat {
    GqiRda = 1,
    GqiQpl = 2,
    DqoRda = 3,
}

/// The size of [`driver_info`].
pub const DRIVER_INFO: usize = 304;

/// What the driver says of itself: Linux's kind (the device has no other
/// kind for it), version 1.0.0, and only the GQI-QPL format.
pub fn driver_info() -> [u8; DRIVER_INFO] {
    const LINUX: u8 = 1;
    const GQI_QPL: u64 = 1;
    let mut b = [0; DRIVER_INFO];
    b[0] = LINUX;
    b[1] = 1;
    put64(&mut b, 16, GQI_QPL);
    b[48..53].copy_from_slice(b"Ichor");
    b
}

/// What the device said of itself (`DESCRIBE_DEVICE`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub max_registered_pages: u64,
    pub tx_entries: u16,
    pub rx_entries: u16,
    pub mtu: u16,
    pub counters: u16,
    pub tx_pages_per_qpl: u16,
    pub mac: [u8; 6],
    /// Its options: (id, required features, payload).
    pub options: Vec<(u16, u32, Vec<u8>)>,
}

/// Device option IDs.
pub mod option {
    pub const GQI_RAW_ADDRESSING: u16 = 0x1;
    pub const GQI_RDA: u16 = 0x2;
    pub const GQI_QPL: u16 = 0x3;
    pub const DQO_RDA: u16 = 0x4;
    pub const MODIFY_RING: u16 = 0x6;
    pub const JUMBO_FRAMES: u16 = 0x8;
}

impl Descriptor {
    /// Reads a descriptor, `None` if it is too short or an option runs past
    /// its stated length.
    pub fn parse(b: &[u8]) -> Option<Descriptor> {
        const LEN: usize = 40;
        if b.len() < LEN {
            return None;
        }
        let total = usize::from(get16(b, 32)).min(b.len());
        let mut mac = [0; 6];
        mac.copy_from_slice(&b[24..30]);
        let mut options = Vec::new();
        let mut at = LEN;
        for _ in 0..get16(b, 30) {
            if at + 8 > total {
                return None;
            }
            let (id, len) = (get16(b, at), usize::from(get16(b, at + 2)));
            let required = get32(b, at + 4);
            let end = at + 8 + len;
            if end > total {
                return None;
            }
            options.push((id, required, b[at + 8..end].to_vec()));
            at = end;
        }
        Some(Descriptor {
            max_registered_pages: get64(b, 0),
            tx_entries: get16(b, 10),
            rx_entries: get16(b, 12),
            mtu: get16(b, 16),
            counters: get16(b, 18),
            tx_pages_per_qpl: get16(b, 20),
            mac,
            options,
        })
    }

    pub fn has(&self, id: u16) -> bool {
        self.options.iter().any(|o| o.0 == id)
    }
}

/// Notification blocks for `msix` MSI-X vectors: one a vector but the
/// management one, an even number (half transmit, half receive).
pub fn notify_blocks(msix: u16) -> u32 {
    u32::from(msix.saturating_sub(1)) & !1
}

/// The size of a transmit descriptor.
pub const TX_DESC: usize = 16;

/// A transmit descriptor for a whole frame of `len` bytes at `offset` in
/// the queue's page list (one descriptor, no offloads).
pub fn tx_desc(len: u16, offset: u64) -> [u8; TX_DESC] {
    let mut d = [0; TX_DESC];
    d[3] = 1; // descriptors in the frame
    put16(&mut d, 4, len);
    put16(&mut d, 6, len);
    put64(&mut d, 8, offset);
    d
}

/// The size of a receive descriptor, and of a data slot.
pub const RX_DESC: usize = 64;
pub const RX_SLOT: usize = 8;
/// A received frame starts this far into its buffer.
pub const RX_PAD: usize = 2;

/// A receive descriptor's useful part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxDesc {
    /// 1 to 7; 0 means the device has not written it.
    pub seq: u8,
    /// Bytes, the padding included.
    pub len: u16,
    pub error: bool,
    /// More of the frame is in the next descriptor.
    pub more: bool,
}

impl RxDesc {
    pub fn parse(d: &[u8; RX_DESC]) -> RxDesc {
        let fs = get16(d, 62);
        RxDesc {
            seq: (fs & 7) as u8,
            len: get16(d, 60),
            error: fs & 1 << (3 + 8) != 0,
            more: fs & 1 << (3 + 10) != 0,
        }
    }
}

/// The sequence number after `s` (they run 1 to 7).
pub fn next_seq(s: u8) -> u8 {
    if s >= 7 { 1 } else { s + 1 }
}

/// A receive data slot: the buffer's offset in the queue's page list.
pub fn rx_slot(offset: u64) -> [u8; RX_SLOT] {
    offset.to_be_bytes()
}

/// A big-endian 32-bit value (doorbells, counters, doorbell indices).
pub fn be32(v: u32) -> u32 {
    u32::from_be_bytes(v.to_ne_bytes())
}

/// A queue's resources as the device wrote them: its doorbell's index in
/// the doorbell BAR (in 32-bit words), and its event counter's index.
pub fn queue_resources(b: &[u8; 8]) -> (u32, u32) {
    (get32(b, 0), get32(b, 4))
}

/// The transmit FIFO over a queue page list: each frame takes a run of
/// bytes that does not wrap, rounded up to a cache line; they are given
/// back in the order taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fifo {
    size: usize,
    head: usize,
    avail: usize,
}

impl Fifo {
    pub fn new(size: usize) -> Fifo {
        Fifo {
            size,
            head: 0,
            avail: size,
        }
    }

    /// Room for `len` bytes: their offset, and how many bytes they hold
    /// (what to give back), or `None` if there is no room.
    pub fn take(&mut self, len: usize) -> Option<(usize, usize)> {
        const LINE: usize = 64;
        let wrap = self.head + len > self.size;
        let skipped = if wrap { self.size - self.head } else { 0 };
        if len == 0 || len > self.size || skipped + len > self.avail {
            return None;
        }
        let at = if wrap { 0 } else { self.head };
        let end = (at + len).next_multiple_of(LINE).min(self.size);
        let held = skipped + (end - at);
        if held > self.avail {
            return None;
        }
        self.head = if end == self.size { 0 } else { end };
        self.avail -= held;
        Some((at, held))
    }

    /// Gives back `held` bytes of the oldest frame.
    pub fn give(&mut self, held: usize) {
        self.avail = (self.avail + held).min(self.size);
    }

    pub fn available(&self) -> usize {
        self.avail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn commands_are_big_endian_where_the_device_reads_them() {
        let c = Command::describe_device(0x1_2345_6000, 4096);
        assert_eq!(&c.0[..4], &[0, 0, 0, 1]);
        assert_eq!(
            &c.0[8..24],
            &[0, 0, 0, 1, 0x23, 0x45, 0x60, 0, 0, 0, 0, 1, 0, 0, 0x10, 0]
        );
        let c = Command::configure_resources(0x1000, 3, 0x2000, 2, QueueFormat::GqiQpl);
        assert_eq!(get64(&c.0, 8), 0x1000);
        assert_eq!(get64(&c.0, 16), 0x2000);
        assert_eq!(
            (get32(&c.0, 24), get32(&c.0, 28), get32(&c.0, 32)),
            (3, 2, 64)
        );
        assert_eq!(c.0[40], 2);
        let c = Command::create_tx(0, 0x3000, 0x4000, 0, 0, 512);
        assert_eq!(
            (c.opcode(), get64(&c.0, 16), get64(&c.0, 24)),
            (5, 0x3000, 0x4000)
        );
        assert_eq!(get16(&c.0, 48), 512);
        let c = Command::create_rx(0, 2, 0x5000, 0x6000, 0x7000, 16, 1024, 2048);
        assert_eq!(
            (get32(&c.0, 8), get32(&c.0, 12), get32(&c.0, 20)),
            (0, 0, 2)
        );
        assert_eq!(
            (get64(&c.0, 32), get64(&c.0, 40), get32(&c.0, 48)),
            (0x6000, 0x7000, 16)
        );
        assert_eq!((get16(&c.0, 52), get16(&c.0, 54)), (1024, 2048));
        let c = Command::register_page_list(16, 1024, 0x8000);
        assert_eq!(
            (get32(&c.0, 8), get32(&c.0, 12), get64(&c.0, 16)),
            (16, 1024, 0x8000)
        );
        let c = Command::set_mtu(1460);
        assert_eq!((get32(&c.0, 8), get64(&c.0, 16)), (1, 1460));
        let mut done = c.0;
        put32(&mut done, 4, STATUS_PASSED);
        assert_eq!(Command::status_of(&done), STATUS_PASSED);
        assert_eq!(status_name(0xffff_fff7), "invalid argument");
    }

    #[test]
    fn a_descriptor_and_its_options() {
        let mut b = vec![0u8; 40];
        put64(&mut b, 0, 4096);
        put16(&mut b, 10, 512);
        put16(&mut b, 12, 1024);
        put16(&mut b, 16, 1460);
        put16(&mut b, 18, 4);
        put16(&mut b, 20, 512);
        b[24..30].copy_from_slice(&[0x42, 1, 10, 0, 0, 2]);
        put16(&mut b, 30, 2);
        // GQI-QPL (4 bytes), then raw addressing (none).
        b.extend_from_slice(&[0, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        let total = b.len() as u16;
        put16(&mut b, 32, total);
        let d = Descriptor::parse(&b).unwrap();
        assert_eq!(
            (d.tx_entries, d.rx_entries, d.mtu, d.counters),
            (512, 1024, 1460, 4)
        );
        assert_eq!((d.max_registered_pages, d.tx_pages_per_qpl), (4096, 512));
        assert_eq!(d.mac, [0x42, 1, 10, 0, 0, 2]);
        assert!(d.has(option::GQI_QPL) && d.has(option::GQI_RAW_ADDRESSING));
        assert!(!d.has(option::DQO_RDA));
        // An option past the end is refused.
        put16(&mut b, 32, total - 1);
        assert_eq!(Descriptor::parse(&b), None);
        assert_eq!(Descriptor::parse(&b[..39]), None);
    }

    #[test]
    fn descriptors_and_counts() {
        let d = tx_desc(1514, 0x40);
        assert_eq!(
            d,
            [
                0, 0, 0, 1, 0x05, 0xea, 0x05, 0xea, 0, 0, 0, 0, 0, 0, 0, 0x40
            ]
        );
        let mut r = [0u8; RX_DESC];
        put16(&mut r, 60, 66);
        put16(&mut r, 62, 1 << 13 | 5);
        assert_eq!(
            RxDesc::parse(&r),
            RxDesc {
                seq: 5,
                len: 66,
                error: false,
                more: true
            }
        );
        put16(&mut r, 62, 1 << 11 | 7);
        assert!(RxDesc::parse(&r).error);
        assert_eq!((next_seq(7), next_seq(1), next_seq(0)), (1, 2, 1));
        assert_eq!(rx_slot(0x3000), [0, 0, 0, 0, 0, 0, 0x30, 0]);
        assert_eq!(queue_resources(&[0, 0, 0, 9, 0, 0, 0, 3]), (9, 3));
        assert_eq!(
            (notify_blocks(5), notify_blocks(4), notify_blocks(1)),
            (4, 2, 0)
        );
        assert_eq!(be32(1).to_ne_bytes(), [0, 0, 0, 1]);
        let i = driver_info();
        assert_eq!((i[0], i[1], get64(&i, 16)), (1, 1, 1));
    }

    #[test]
    fn the_fifo_never_splits_a_frame_and_gives_back_in_order() {
        let mut f = Fifo::new(256);
        assert_eq!(f.take(60), Some((0, 64)));
        assert_eq!(f.take(100), Some((64, 128)));
        // 64 bytes are left at the end: a 70-byte frame would wrap, which
        // costs those 64 too, so it waits until both earlier frames are back.
        assert_eq!(f.available(), 64);
        assert_eq!(f.take(70), None);
        f.give(64);
        assert_eq!(f.take(70), None);
        f.give(128);
        assert_eq!(f.take(70), Some((0, 64 + 128)));
        assert_eq!(f.available(), 64);
        f.give(192);
        assert_eq!(f.available(), 256);
        assert_eq!(f.take(0), None);
        assert_eq!(f.take(257), None);
        // From the middle a whole-FIFO frame cannot fit; to the end can.
        assert_eq!(f.take(256), None);
        assert_eq!(f.take(128), Some((128, 128)));
        assert_eq!(f.take(64), Some((0, 64)));
    }
}
