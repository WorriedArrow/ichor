//! Intel gigabit Ethernet, polled: the 82574L (`e1000e`) and the 82576,
//! I350 and I210 family (`igb`), which bare-metal servers have on board.
//! Tested on QEMU's 82574L and 82576; the others share their registers and
//! have not been tried.
//!
//! One receive and one transmit queue, no offloads, no interrupts. The two
//! families differ in their descriptors (the 82574's are the legacy ones,
//! the other's the "advanced" ones) and in that `igb` enables each queue.
//!
//! Safe code only. The rings are device-owned formats, so this driver
//! writes bus addresses into them and is on ADR-0005's DMA-trusted list, as
//! NVMe is: every address is in one of two buffers that live as long as it
//! does, and lengths the device reports are clamped to a frame's slot.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};
use core::time::Duration;

use frame::bus::pci::{self, PciDevice};
use frame::dma::DmaBuf;
use frame::io::IoMem;

const VENDOR_INTEL: u16 = 0x8086;
/// 82574L.
const E1000E: &[u16] = &[0x10d3];
/// 82576, I350, I210, I211.
const IGB: &[u16] = &[
    0x10c9, 0x1521, 0x1522, 0x1533, 0x1536, 0x1537, 0x1538, 0x1539,
];

const CTRL: u64 = 0x0000;
const STATUS: u64 = 0x0008;
const CTRL_EXT: u64 = 0x0018;
const MDIC: u64 = 0x0020;
const IMC: u64 = 0x00d8;
const IGB_EIMC: u64 = 0x1528;
const RCTL: u64 = 0x0100;
const TCTL: u64 = 0x0400;
const TIPG: u64 = 0x0410;
/// Queue 0's registers: base low and high, length, (`igb`: buffer format,)
/// head, tail, control.
const RX: u64 = 0x2800;
const TX: u64 = 0x3800;
const BASE_LO: u64 = 0x00;
const BASE_HI: u64 = 0x04;
const LENGTH: u64 = 0x08;
const SRRCTL: u64 = 0x0c;
const HEAD: u64 = 0x10;
const TAIL: u64 = 0x18;
const DCTL: u64 = 0x28;
/// The multicast table, and the first receive address.
const MTA: u64 = 0x5200;
const RAL0: u64 = 0x5400;
const RAH0: u64 = 0x5404;

const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
/// A write to the PHY (at address 1), and how it went.
const MDIC_WRITE: u32 = 1 << 26 | 1 << 21;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
/// The PHY's register 0: negotiate, from the start.
const PHY_CONTROL_NEGOTIATE: u32 = 0x1200;
const STATUS_LU: u32 = 1 << 1;
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
/// Retries after collisions, and their distance (half duplex only).
const TCTL_COLLISIONS: u32 = 0x0f << 4 | 0x40 << 12;
/// The gaps between frames every such device uses on copper.
const TIPG_COPPER: u32 = 8 | 8 << 10 | 6 << 20;
/// `igb`: one buffer per advanced descriptor, of 2 KiB.
const SRRCTL_ADVANCED_2K: u32 = 1 << 25 | 2;
const DCTL_ENABLE: u32 = 1 << 25;
/// 82574: transmit descriptors written back one by one, and a bit that must
/// be set.
const E1000E_TXDCTL: u32 = 1 << 24 | 1 << 22 | 1 << 16;
const RAH_VALID: u32 = 1 << 31;

/// Descriptors in each ring, and the bytes of one and of its buffer.
const RING: usize = 256;
const DESC: usize = 16;
const SLOT: usize = 2048;
/// The largest frame: a 1500-byte MTU plus the Ethernet header.
pub const MAX_FRAME: usize = 1514;
/// Receive descriptors are given back this many at a time.
const GIVE_BACK: usize = 16;

/// How long a reset and a queue's start may take.
const PATIENCE: Duration = Duration::from_secs(1);

/// Why a device could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    MapFailed,
    NoMemory,
    /// It did not come out of reset, or a queue did not start.
    NotReady,
    /// It has no address.
    NoAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    E1000e,
    Igb,
}

/// A ring of descriptors and the buffer each has.
#[derive(Debug)]
struct Ring {
    desc: DmaBuf,
    data: DmaBuf,
    /// The next descriptor to look at (receive) or to fill (transmit).
    next: usize,
}

impl Ring {
    fn new() -> Result<Ring, InitError> {
        Ok(Ring {
            desc: DmaBuf::alloc(RING * DESC).ok_or(InitError::NoMemory)?,
            data: DmaBuf::alloc(RING * SLOT).ok_or(InitError::NoMemory)?,
            next: 0,
        })
    }

    /// Where the device finds slot `i`'s buffer.
    fn address(&self, i: usize) -> u64 {
        self.data.dma_addr(i * SLOT).map_or(0, |a| a.as_u64())
    }
}

impl Drop for IntelGbe {
    /// Its buffers are freed next: it must not know of them any more.
    fn drop(&mut self) {
        self.regs.write32(RCTL, 0);
        self.regs.write32(TCTL, TCTL_PSP);
        self.regs.write32(CTRL, self.regs.read32(CTRL) | CTRL_RST);
        let from = frame::time::now();
        while frame::time::now() - from < Duration::from_millis(10) {
            core::hint::spin_loop();
        }
        let _ = self.regs.read32(STATUS);
    }
}

/// An Intel gigabit Ethernet device.
#[derive(Debug)]
pub struct IntelGbe {
    regs: IoMem,
    family: Family,
    mac: [u8; 6],
    rx: Ring,
    /// Receive descriptors read and not given back yet.
    rx_read: usize,
    tx: Ring,
    /// The oldest transmit descriptor the device may still have.
    tx_clean: usize,
    /// Frames dropped because the transmit ring was full.
    pub tx_dropped: u64,
}

/// Every such device, initialized.
pub fn probe_all() -> Vec<Result<IntelGbe, InitError>> {
    pci::devices()
        .iter()
        .filter(|d| d.vendor_id == VENDOR_INTEL)
        .filter_map(|d| {
            let family = if E1000E.contains(&d.device_id) {
                Family::E1000e
            } else if IGB.contains(&d.device_id) {
                Family::Igb
            } else {
                return None;
            };
            Some(IntelGbe::init(d, family))
        })
        .collect()
}

/// Waits until `done`.
fn wait(done: impl Fn() -> bool) -> Result<(), InitError> {
    let deadline = frame::time::now() + PATIENCE;
    while !done() {
        if frame::time::now() > deadline {
            return Err(InitError::NotReady);
        }
        core::hint::spin_loop();
    }
    Ok(())
}

impl IntelGbe {
    fn init(dev: &PciDevice, family: Family) -> Result<IntelGbe, InitError> {
        dev.enable(true, true);
        let regs = dev.map_bar(0).ok_or(InitError::MapFailed)?;

        // Reset, with interrupts off before and after.
        let mask_interrupts = || {
            regs.write32(IMC, u32::MAX);
            if family == Family::Igb {
                regs.write32(IGB_EIMC, u32::MAX);
            }
        };
        mask_interrupts();
        regs.write32(RCTL, 0);
        regs.write32(TCTL, TCTL_PSP);
        regs.write32(CTRL, regs.read32(CTRL) | CTRL_RST);
        // (Not to be touched for a moment.)
        let from = frame::time::now();
        wait(|| frame::time::now() - from > Duration::from_millis(10))?;
        wait(|| regs.read32(CTRL) & CTRL_RST == 0)?;
        mask_interrupts();
        regs.write32(CTRL_EXT, regs.read32(CTRL_EXT) | CTRL_EXT_DRV_LOAD);
        regs.write32(CTRL, regs.read32(CTRL) | CTRL_SLU | CTRL_ASDE);
        // Agree with the other end on a speed.
        regs.write32(MDIC, MDIC_WRITE | PHY_CONTROL_NEGOTIATE);
        wait(|| regs.read32(MDIC) & (MDIC_READY | MDIC_ERROR) != 0)?;

        // The reset loaded its address from its memory.
        let (lo, hi) = (regs.read32(RAL0), regs.read32(RAH0));
        let (l, h) = (lo.to_le_bytes(), hi.to_le_bytes());
        let mac = [l[0], l[1], l[2], l[3], h[0], h[1]];
        if hi & RAH_VALID == 0 || mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(InitError::NoAddress);
        }
        for i in 0..128 {
            regs.write32(MTA + 4 * i, 0);
        }

        let nic = IntelGbe {
            regs,
            family,
            mac,
            rx: Ring::new()?,
            rx_read: 0,
            tx: Ring::new()?,
            tx_clean: 0,
            tx_dropped: 0,
        };
        nic.start()?;
        Ok(nic)
    }

    /// Gives the device its rings and starts it.
    fn start(&self) -> Result<(), InitError> {
        let r = &self.regs;
        for (at, ring) in [(RX, &self.rx), (TX, &self.tx)] {
            let base = ring.desc.dma_addr(0).ok_or(InitError::NoMemory)?.as_u64();
            r.write32(at + BASE_LO, base as u32);
            r.write32(at + BASE_HI, (base >> 32) as u32);
            r.write32(at + LENGTH, (RING * DESC) as u32);
            r.write32(at + HEAD, 0);
            r.write32(at + TAIL, 0);
        }
        for i in 0..RING {
            self.refill(i);
        }
        match self.family {
            Family::E1000e => r.write32(TX + DCTL, r.read32(TX + DCTL) | E1000E_TXDCTL),
            Family::Igb => {
                r.write32(RX + SRRCTL, SRRCTL_ADVANCED_2K);
                for at in [RX, TX] {
                    r.write32(at + DCTL, r.read32(at + DCTL) | DCTL_ENABLE);
                    wait(|| r.read32(at + DCTL) & DCTL_ENABLE != 0)?;
                }
            }
        }
        r.write32(TIPG, TIPG_COPPER);
        r.write32(TCTL, TCTL_EN | TCTL_PSP | TCTL_COLLISIONS);
        // Frames for this address, and broadcasts, without their checksum.
        r.write32(RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC);
        // Every descriptor but one: equal head and tail mean none.
        fence(Ordering::SeqCst);
        r.write32(RX + TAIL, RING as u32 - 1);
        Ok(())
    }

    /// The device's MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Whether the link is up (a cable, and something at its other end).
    pub fn link_up(&self) -> bool {
        self.regs.read32(STATUS) & STATUS_LU != 0
    }

    /// Makes receive descriptor `i` an empty one.
    fn refill(&self, i: usize) {
        let at = i * DESC;
        // The status first: what it was would look like a new frame.
        self.rx.desc.write_u64(at + 8, 0);
        self.rx.desc.write_u64(at, self.rx.address(i));
    }

    /// The next received frame, if any.
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        loop {
            let i = self.rx.next;
            let at = i * DESC;
            // (done, whole, good, length)
            let (done, good, len) = match self.family {
                Family::E1000e => {
                    let s = self.rx.desc.read_u32(at + 12);
                    // Status in the low byte, errors in the next.
                    let good = s & 2 != 0 && (s >> 8) & 0x97 == 0;
                    fence(Ordering::Acquire);
                    (s & 1 != 0, good, self.rx.desc.read_u16(at + 8))
                }
                Family::Igb => {
                    let s = self.rx.desc.read_u32(at + 8);
                    // Receive error: the one that is not about offloads.
                    let good = s & 2 != 0 && s & 1 << 31 == 0;
                    fence(Ordering::Acquire);
                    (s & 1 != 0, good, self.rx.desc.read_u16(at + 12))
                }
            };
            if !done {
                self.give_back(1);
                return None;
            }
            let len = usize::from(len);
            let frame = (good && (14..=SLOT).contains(&len)).then(|| {
                let mut f = alloc::vec![0u8; len];
                self.rx.data.read(i * SLOT, &mut f);
                f
            });
            self.refill(i);
            self.rx.next = (i + 1) % RING;
            self.rx_read += 1;
            self.give_back(GIVE_BACK);
            if frame.is_some() {
                return frame;
            }
        }
    }

    /// Gives what was read back to the device, if it is `enough`.
    fn give_back(&mut self, enough: usize) {
        if self.rx_read >= enough {
            self.rx_read = 0;
            let last = (self.rx.next + RING - 1) % RING;
            fence(Ordering::SeqCst);
            self.regs.write32(RX + TAIL, last as u32);
        }
    }

    /// Queues a frame for transmission. Returns false if it was dropped
    /// (too long, or the ring is full).
    pub fn transmit(&mut self, frame: &[u8]) -> bool {
        /// End of packet, append the checksum, report when it is sent.
        const COMMAND: u32 = 0x0b << 24;
        /// Advanced: a data descriptor.
        const ADVANCED: u32 = 0x20 << 24 | 3 << 20;
        while self.tx_clean != self.tx.next
            && self.tx.desc.read_u32(self.tx_clean * DESC + 12) & 1 != 0
        {
            self.tx_clean = (self.tx_clean + 1) % RING;
        }
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return false;
        }
        let i = self.tx.next;
        let next = (i + 1) % RING;
        if next == self.tx_clean {
            self.tx_dropped += 1;
            return false;
        }
        self.tx.data.write(i * SLOT, frame);
        let len = frame.len() as u32;
        let at = i * DESC;
        let (command, status) = match self.family {
            Family::E1000e => (COMMAND | len, 0),
            Family::Igb => (COMMAND | ADVANCED | len, len << 14),
        };
        self.tx.desc.write_u64(at, self.tx.address(i));
        self.tx.desc.write_u32(at + 12, status);
        self.tx.desc.write_u32(at + 8, command);
        self.tx.next = next;
        fence(Ordering::SeqCst);
        self.regs.write32(TX + TAIL, next as u32);
        true
    }
}

impl net::link::Link for IntelGbe {
    fn mac(&self) -> [u8; 6] {
        IntelGbe::mac(self)
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        IntelGbe::transmit(self, frame)
    }
    fn receive(&mut self) -> Option<Vec<u8>> {
        IntelGbe::receive(self)
    }
    fn name(&self) -> &str {
        match self.family {
            Family::E1000e => "e1000e",
            Family::Igb => "igb",
        }
    }
}
