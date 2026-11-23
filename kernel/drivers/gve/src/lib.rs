//! Google's virtual NIC (gVNIC), polled, in the GQI format with queue page
//! lists (`kernel/gve` has the protocol): one transmit and one receive
//! queue, no offloads, no interrupts. Frames are copied through pages
//! registered with the device; it never sees any other address.
//!
//! The device's management interrupt says that its status changed: it
//! wants a reset, or its link went up or down. This driver takes no
//! interrupts, so it reads the status register instead, at most every
//! [`STATUS_POLL`] (as DPDK's driver does), and on a reset request tears
//! the device down and brings it up again, logging that it did.
//!
//! Safe code only. Admin commands carry bus addresses, so this driver is on
//! ADR-0005's DMA-trusted list, as NVMe and ENA are: every address is in a
//! buffer that lives as long as the device knows it (the device is reset
//! before they are freed), and lengths and indices the device reports are
//! checked against the buffers they name.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};
use core::time::Duration;

use frame::bus::pci::{self, PciDevice};
use frame::dma::DmaBuf;
use frame::io::IoMem;
use frame::println;
use gve::{
    COMMAND, Command, Descriptor, Fifo, PAGE, QueueFormat, RX_DESC, RX_PAD, RX_SLOT, TX_DESC, reg,
};

/// How often the device's status is read.
pub const STATUS_POLL: Duration = Duration::from_millis(100);
/// How long an admin command, and a reset, may take.
const ADMIN_PATIENCE: Duration = Duration::from_secs(5);
/// Pages in each piece of the transmit page list (they need not be one
/// block; smaller pieces are easier to find).
const CHUNK_PAGES: usize = 64;
/// The receive buffer the device is told of (a frame starts 2 bytes in).
const RX_BUFFER: u16 = 2048;
/// The largest frame: a 1500-byte MTU plus the Ethernet header.
pub const MAX_FRAME: usize = 1514;
/// Receive buffers are given back this many at a time.
const GIVE_BACK: u32 = 16;
/// The interrupt doorbell bit that masks a notification block.
const IRQ_MASK: u32 = 1 << 30;

/// Why a device could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    MapFailed,
    NoMemory,
    /// An admin command failed (its opcode and status).
    Admin(u32, u32),
    /// An admin command went unanswered (its opcode).
    AdminTimeout(u32),
    /// It described itself in a way this driver cannot use.
    Unusable(&'static str),
    /// It did not come out of reset.
    NotReset,
}

/// The transmit queue.
#[derive(Debug)]
struct Tx {
    ring: DmaBuf,
    /// The page list, in pieces of [`CHUNK_PAGES`] pages.
    pages: Vec<DmaBuf>,
    fifo: Fifo,
    size: u32,
    /// Descriptors written, and ones the device is done with.
    tail: u32,
    done: u32,
    /// FIFO bytes each descriptor holds.
    held: Vec<usize>,
    doorbell: u64,
    counter: usize,
}

/// The receive queue.
#[derive(Debug)]
struct Rx {
    desc: DmaBuf,
    /// One page per descriptor: descriptor `i`'s buffer is page `i`.
    pages: Vec<DmaBuf>,
    size: u32,
    /// Descriptors read, buffers given back, and the count the device was
    /// last told.
    next: u32,
    posted: u32,
    told: u32,
    /// The sequence number the next descriptor will carry.
    seq: u8,
    /// The frame being read spans descriptors, and is dropped.
    dropping: bool,
    doorbell: u64,
}

/// What the device keeps while it runs.
#[derive(Debug)]
struct Running {
    counters: DmaBuf,
    tx: Tx,
    rx: Rx,
    /// What else the device knows the address of (admin queue, doorbell
    /// slots, queue resources, data slots): kept until it is reset.
    _held: Vec<DmaBuf>,
}

/// A gVNIC.
#[derive(Debug)]
pub struct Gve {
    dev: PciDevice,
    regs: IoMem,
    dbs: IoMem,
    mac: [u8; 6],
    mtu: u16,
    run: Option<Running>,
    link_up: bool,
    polled: Duration,
    /// Times the device asked for a reset, and was reset.
    pub resets: u32,
    /// Frames dropped: no room to send, too long, or broken on receipt.
    pub tx_dropped: u64,
    pub rx_dropped: u64,
}

/// Every gVNIC, brought up.
pub fn probe_all() -> Vec<Result<Gve, InitError>> {
    pci::devices()
        .iter()
        .filter(|d| d.vendor_id == gve::VENDOR && d.device_id == gve::DEVICE)
        .map(|d| Gve::init(*d))
        .collect()
}

fn page(len: usize) -> Result<DmaBuf, InitError> {
    DmaBuf::alloc(len).ok_or(InitError::NoMemory)
}

fn bus(b: &DmaBuf, at: usize) -> u64 {
    b.dma_addr(at).map_or(0, |a| a.as_u64())
}

/// A big-endian 32-bit value at `at` of `b`.
fn get_be32(b: &DmaBuf, at: usize) -> u32 {
    b.read_u32(at).swap_bytes()
}

impl Gve {
    fn init(dev: PciDevice) -> Result<Gve, InitError> {
        dev.enable(true, true);
        let regs = dev.map_bar(gve::REGISTER_BAR).ok_or(InitError::MapFailed)?;
        let dbs = dev.map_bar(gve::DOORBELL_BAR).ok_or(InitError::MapFailed)?;
        let mut g = Gve {
            dev,
            regs,
            dbs,
            mac: [0; 6],
            mtu: 1500,
            run: None,
            link_up: true,
            polled: frame::time::now(),
            resets: 0,
            tx_dropped: 0,
            rx_dropped: 0,
        };
        for b in b"GVE-1.0.0 ichor\n" {
            g.regs.write8(reg::DRIVER_VERSION, *b);
        }
        g.bring_up()?;
        Ok(g)
    }

    fn reg(&self, at: u64) -> u32 {
        u32::from_be(self.regs.read32(at))
    }

    fn set_reg(&self, at: u64, v: u32) {
        self.regs.write32(at, v.to_be());
    }

    /// Rings doorbell `index` (in 32-bit words) with `v`.
    fn ring(&self, index: u64, v: u32) {
        self.dbs.write32(index * 4, v.to_be());
    }

    /// Hands the device its admin queue.
    fn start_admin(&self, admin: &DmaBuf) {
        let at = bus(admin, 0);
        if self.dev.read_config_u8(0x08) < 1 {
            self.set_reg(reg::ADMINQ_PFN, (at / PAGE as u64) as u32);
        } else {
            self.regs.write16(reg::ADMINQ_LENGTH, (PAGE as u16).to_be());
            self.set_reg(reg::ADMINQ_BASE_HI, (at >> 32) as u32);
            self.set_reg(reg::ADMINQ_BASE_LO, at as u32);
            self.set_reg(reg::DRIVER_STATUS, reg::DRIVER_RUN);
        }
    }

    /// Runs one admin command on `admin`, whose count of commands is
    /// `produced`.
    fn command(
        &self,
        admin: &DmaBuf,
        produced: &mut u32,
        c: &Command,
    ) -> Result<[u8; COMMAND], InitError> {
        let slot = (*produced as usize % (PAGE / COMMAND)) * COMMAND;
        admin.write(slot, &c.0);
        *produced = produced.wrapping_add(1);
        fence(Ordering::SeqCst);
        self.set_reg(reg::ADMINQ_DOORBELL, *produced);
        let deadline = frame::time::now() + ADMIN_PATIENCE;
        while self.reg(reg::ADMINQ_EVENT_COUNTER) != *produced {
            if frame::time::now() > deadline {
                return Err(InitError::AdminTimeout(c.opcode()));
            }
            core::hint::spin_loop();
        }
        fence(Ordering::Acquire);
        let mut done = [0u8; COMMAND];
        admin.read(slot, &mut done);
        match Command::status_of(&done) {
            gve::STATUS_PASSED => Ok(done),
            s => Err(InitError::Admin(c.opcode(), s)),
        }
    }

    /// The device's MSI-X vectors (its notification blocks follow from them).
    fn msix_vectors(&self) -> u16 {
        const MSIX: u8 = 0x11;
        self.dev
            .capabilities()
            .find(|&(_, id)| id == MSIX)
            .map_or(0, |(at, _)| (self.dev.read_config_u16(at + 2) & 0x7ff) + 1)
    }

    /// Brings the device from reset to running: describes it, gives it its
    /// resources, page lists and queues.
    fn bring_up(&mut self) -> Result<(), InitError> {
        let admin = page(PAGE)?;
        self.start_admin(&admin);
        let mut produced = 0;
        let mut cmd = |c: &Command| self.command(&admin, &mut produced, c);

        let info = page(PAGE)?;
        info.write(0, &gve::driver_info());
        match cmd(&Command::verify_driver(
            bus(&info, 0),
            gve::DRIVER_INFO as u64,
        )) {
            Ok(_) | Err(InitError::Admin(_, gve::STATUS_UNIMPLEMENTED)) => {}
            Err(e) => return Err(e),
        }
        let described = page(PAGE)?;
        cmd(&Command::describe_device(bus(&described, 0), PAGE as u32))?;
        let mut raw = vec![0u8; PAGE];
        described.read(0, &mut raw);
        let d = Descriptor::parse(&raw).ok_or(InitError::Unusable("its description"))?;
        if d.has(gve::option::DQO_RDA) && !d.has(gve::option::GQI_QPL) {
            return Err(InitError::Unusable("it offers DQO only"));
        }
        let max_tx = self.reg(reg::MAX_TX_QUEUES);
        let ntfy = gve::notify_blocks(self.msix_vectors());
        let (tx_size, rx_size) = (u32::from(d.tx_entries), u32::from(d.rx_entries));
        let tx_pages = usize::from(d.tx_pages_per_qpl);
        let pages = (tx_pages + rx_size as usize) as u64;
        if ntfy < 2
            || !tx_size.is_power_of_two()
            || !rx_size.is_power_of_two()
            || tx_pages == 0
            || d.counters == 0
            || pages > d.max_registered_pages
        {
            return Err(InitError::Unusable("its queues or limits"));
        }

        // Event counters and interrupt doorbells.
        let counters = page(usize::from(d.counters) * 4)?;
        let irq_dbs = page(ntfy as usize * gve::IRQ_DB_STRIDE)?;
        cmd(&Command::configure_resources(
            bus(&counters, 0),
            u32::from(d.counters),
            bus(&irq_dbs, 0),
            ntfy,
            QueueFormat::GqiQpl,
        ))?;

        // The page lists: transmit (id 0), receive (after the transmit ids).
        let chunks = tx_pages.div_ceil(CHUNK_PAGES);
        let tx_chunks = (0..chunks)
            .map(|i| page((tx_pages - i * CHUNK_PAGES).min(CHUNK_PAGES) * PAGE))
            .collect::<Result<Vec<_>, _>>()?;
        let tx_list: Vec<u64> = tx_chunks
            .iter()
            .enumerate()
            .flat_map(|(i, c)| {
                let n = (tx_pages - i * CHUNK_PAGES).min(CHUNK_PAGES);
                (0..n).map(move |p| bus(c, p * PAGE))
            })
            .collect();
        let rx_pages = (0..rx_size)
            .map(|_| page(PAGE))
            .collect::<Result<Vec<_>, _>>()?;
        let rx_list: Vec<u64> = rx_pages.iter().map(|p| bus(p, 0)).collect();
        let rx_qpl = max_tx;
        for (id, list) in [(0, &tx_list), (rx_qpl, &rx_list)] {
            let b = page(list.len() * 8)?;
            for (i, a) in list.iter().enumerate() {
                b.write(i * 8, &a.to_be_bytes());
            }
            cmd(&Command::register_page_list(
                id,
                list.len() as u32,
                bus(&b, 0),
            ))?;
        }

        // The queues.
        let tx_ring = page(tx_size as usize * TX_DESC)?;
        let tx_res = page(PAGE)?;
        cmd(&Command::create_tx(
            0,
            bus(&tx_res, 0),
            bus(&tx_ring, 0),
            0,
            0,
            tx_size as u16,
        ))?;
        let rx_desc = page(rx_size as usize * RX_DESC)?;
        let rx_data = page(rx_size as usize * RX_SLOT)?;
        for i in 0..rx_size as usize {
            rx_data.write(i * RX_SLOT, &gve::rx_slot((i * PAGE) as u64));
        }
        let rx_res = page(PAGE)?;
        let rx_ntfy = ntfy / 2;
        cmd(&Command::create_rx(
            0,
            rx_ntfy,
            bus(&rx_res, 0),
            bus(&rx_desc, 0),
            bus(&rx_data, 0),
            rx_qpl,
            rx_size as u16,
            RX_BUFFER,
        ))?;
        let res = |b: &DmaBuf| {
            let mut r = [0u8; 8];
            b.read(0, &mut r);
            gve::queue_resources(&r)
        };
        let ((tx_db, tx_counter), (rx_db, _)) = (res(&tx_res), res(&rx_res));
        if tx_counter >= u32::from(d.counters) {
            return Err(InitError::Unusable("its transmit counter"));
        }
        // No interrupts: both notification blocks masked.
        for n in [0, rx_ntfy] {
            let id = get_be32(&irq_dbs, n as usize * gve::IRQ_DB_STRIDE);
            self.ring(u64::from(id), IRQ_MASK);
        }
        // Every buffer but one: a full ring would look empty.
        let rx = Rx {
            desc: rx_desc,
            pages: rx_pages,
            size: rx_size,
            next: 0,
            posted: rx_size - 1,
            told: rx_size - 1,
            seq: 1,
            dropping: false,
            doorbell: u64::from(rx_db),
        };
        fence(Ordering::SeqCst);
        self.ring(rx.doorbell, rx.posted);
        self.mac = d.mac;
        self.mtu = d.mtu.min(1500);
        self.run = Some(Running {
            counters,
            _held: vec![admin, irq_dbs, tx_res, rx_res, rx_data],
            tx: Tx {
                ring: tx_ring,
                pages: tx_chunks,
                fifo: Fifo::new(tx_pages * PAGE),
                size: tx_size,
                tail: 0,
                done: 0,
                held: vec![0; tx_size as usize],
                doorbell: u64::from(tx_db),
                counter: tx_counter as usize,
            },
            rx,
        });
        drop(info);
        Ok(())
    }

    /// Asks the device to reset and waits until it has: then it no longer
    /// knows any of this driver's memory.
    fn release(&mut self) -> Result<(), InitError> {
        let deadline = frame::time::now() + ADMIN_PATIENCE;
        let pfn = self.dev.read_config_u8(0x08) < 1;
        if pfn {
            self.set_reg(reg::ADMINQ_PFN, 0);
        } else {
            self.set_reg(reg::DRIVER_STATUS, reg::DRIVER_RESET);
        }
        let done = || {
            if pfn {
                self.reg(reg::ADMINQ_PFN) == 0
            } else {
                self.reg(reg::DEVICE_STATUS) & reg::STATUS_IS_RESET != 0
            }
        };
        while !done() {
            if frame::time::now() > deadline {
                // It may still use the buffers: keep them, forever.
                if let Some(r) = self.run.take() {
                    core::mem::forget(r);
                }
                return Err(InitError::NotReset);
            }
            core::hint::spin_loop();
        }
        self.run = None;
        Ok(())
    }

    /// Reads the device's status (now and then): follows its link, and
    /// resets it if it asks.
    fn poll_status(&mut self) {
        let now = frame::time::now();
        // A device that failed to come back is retried less often.
        let every = if self.run.is_some() {
            STATUS_POLL
        } else {
            Duration::from_secs(5)
        };
        if now - self.polled < every {
            return;
        }
        self.polled = now;
        let s = self.reg(reg::DEVICE_STATUS);
        let link = s & reg::STATUS_LINK != 0;
        if link != self.link_up {
            println!("ichor: gve: link {}", if link { "up" } else { "down" });
            self.link_up = link;
        }
        if s & reg::STATUS_RESET == 0 && self.run.is_some() {
            return;
        }
        self.resets += 1;
        println!(
            "ichor: gve: the device asked for a reset (status {s:#x}); resetting ({})",
            self.resets
        );
        let r = self.release().and_then(|()| self.bring_up());
        match r {
            Ok(()) => println!("ichor: gve: up again after reset {}", self.resets),
            Err(e) => println!("ichor: gve: reset {} failed: {e:?}", self.resets),
        }
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn link_up(&self) -> bool {
        self.link_up
    }

    /// The next received frame, if any.
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        self.poll_status();
        let mut dropped = 0;
        let mut frame = None;
        let mut doorbell = None;
        if let Some(run) = &mut self.run {
            let rx = &mut run.rx;
            loop {
                let slot = (rx.next % rx.size) as usize;
                let mut b = [0u8; RX_DESC];
                rx.desc.read(slot * RX_DESC, &mut b);
                let d = gve::RxDesc::parse(&b);
                if d.seq != rx.seq {
                    break;
                }
                fence(Ordering::Acquire);
                rx.desc.read(slot * RX_DESC, &mut b);
                let d = gve::RxDesc::parse(&b);
                rx.seq = gve::next_seq(rx.seq);
                rx.next = rx.next.wrapping_add(1);
                let len = usize::from(d.len);
                let whole = !rx.dropping && !d.more && !d.error;
                if whole && (RX_PAD + 14..=usize::from(RX_BUFFER)).contains(&len) {
                    let mut f = vec![0u8; len - RX_PAD];
                    rx.pages[slot].read(RX_PAD, &mut f);
                    frame = Some(f);
                } else if !d.more {
                    dropped += 1;
                }
                rx.dropping = d.more;
                // That buffer is the device's again.
                rx.posted = rx.posted.wrapping_add(1);
                if frame.is_some() {
                    break;
                }
            }
            let owed = rx.posted.wrapping_sub(rx.told);
            if owed >= GIVE_BACK || (owed > 0 && frame.is_none()) {
                fence(Ordering::SeqCst);
                rx.told = rx.posted;
                doorbell = Some((rx.doorbell, rx.posted));
            }
        }
        if let Some((db, v)) = doorbell {
            self.ring(db, v);
        }
        self.rx_dropped += dropped;
        frame
    }

    /// Queues a frame for transmission. Returns false if it was dropped
    /// (too long, or no room).
    pub fn transmit(&mut self, frame: &[u8]) -> bool {
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return false;
        }
        let Some(run) = &mut self.run else {
            self.tx_dropped += 1;
            return false;
        };
        let tx = &mut run.tx;
        // What the device has sent gives its FIFO bytes back.
        let sent = get_be32(&run.counters, tx.counter * 4);
        while tx.done != sent && tx.done != tx.tail {
            let slot = (tx.done % tx.size) as usize;
            tx.fifo.give(core::mem::take(&mut tx.held[slot]));
            tx.done = tx.done.wrapping_add(1);
        }
        let room = tx.tail.wrapping_sub(tx.done) < tx.size - 1;
        let Some((at, held)) = room.then(|| tx.fifo.take(frame.len())).flatten() else {
            self.tx_dropped += 1;
            return false;
        };
        // Copy the frame into the page list (it may cross pieces).
        let piece = CHUNK_PAGES * PAGE;
        let mut done = 0;
        while done < frame.len() {
            let off = at + done;
            let (c, within) = (off / piece, off % piece);
            let n = (piece - within).min(frame.len() - done);
            if let Some(chunk) = tx.pages.get(c) {
                chunk.write(within, &frame[done..done + n]);
            }
            done += n;
        }
        let slot = (tx.tail % tx.size) as usize;
        tx.held[slot] = held;
        tx.ring
            .write(slot * TX_DESC, &gve::tx_desc(frame.len() as u16, at as u64));
        tx.tail = tx.tail.wrapping_add(1);
        let (db, tail) = (tx.doorbell, tx.tail);
        fence(Ordering::SeqCst);
        self.ring(db, tail);
        true
    }
}

impl Drop for Gve {
    /// Its buffers are freed next: it must not know of them any more.
    fn drop(&mut self) {
        let _ = self.release();
    }
}

impl net::link::Link for Gve {
    fn mac(&self) -> [u8; 6] {
        Gve::mac(self)
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        Gve::transmit(self, frame)
    }
    fn receive(&mut self) -> Option<Vec<u8>> {
        Gve::receive(self)
    }
    fn name(&self) -> &str {
        "gve"
    }
    fn mtu(&self) -> u16 {
        Gve::mtu(self)
    }
}
