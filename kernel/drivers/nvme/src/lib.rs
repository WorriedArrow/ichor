//! NVMe over PCIe: one admin queue pair and one I/O queue pair, polled.
//!
//! Safe code only. NVMe's queues and PRP lists are device-owned formats that
//! frame does not manage, so this driver writes bus addresses from
//! [`DmaAddr::as_u64`] into them, which puts it on ADR-0005's DMA-trusted
//! list until an IOMMU covers it. Every address it writes comes from a live
//! `DmaBuf` this driver owns for its whole lifetime (the queues, a PRP-list
//! page and one data buffer), so a bug here can misdirect the device only
//! within those buffers.
//!
//! [`DmaAddr::as_u64`]: frame::dma::DmaAddr::as_u64

#![no_std]
#![forbid(unsafe_code)]

use core::time::Duration;

use block::{BlockDevice, BlockError, SECTOR_SIZE, check};
use frame::bus::pci::{self, PciDevice};
use frame::dma::DmaBuf;
use frame::io::IoMem;

// PCI class: mass storage, non-volatile memory, NVM Express.
const CLASS_STORAGE: u8 = 0x01;
const SUBCLASS_NVM: u8 = 0x08;
const PROG_IF_NVME: u8 = 0x02;

// Controller registers.
const REG_CAP: u64 = 0x00;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1c;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;
const DOORBELLS: u64 = 0x1000;

const CC_EN: u32 = 1;
const CC_IOSQES: u32 = 6 << 16; // 64-byte submission entries
const CC_IOCQES: u32 = 4 << 20; // 16-byte completion entries
const CSTS_RDY: u32 = 1;
const CSTS_CFS: u32 = 2;

// Admin opcodes.
const ADMIN_CREATE_SQ: u32 = 0x01;
const ADMIN_CREATE_CQ: u32 = 0x05;
const ADMIN_IDENTIFY: u32 = 0x06;
// I/O opcodes.
const IO_READ: u32 = 0x02;

const QUEUE_SIZE: u16 = 64;
const SQE: usize = 64;
const CQE: usize = 16;
const PAGE: usize = 4096;
/// Largest single read: one data buffer, described by PRP1 plus a PRP list.
const MAX_REQUEST: usize = 64 * 1024;
const NSID: u32 = 1;

/// Why the controller could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    MapFailed,
    NoMemory,
    /// The controller did not become ready, or reported a fatal status.
    NotReady,
    /// An admin command failed.
    Command,
    /// Namespace 1 is missing or has an unsupported block size.
    Namespace,
}

#[derive(Debug)]
struct Queue {
    id: u16,
    sq: DmaBuf,
    cq: DmaBuf,
    tail: u16,
    head: u16,
    phase: bool,
}

impl Queue {
    fn new(id: u16) -> Option<Queue> {
        Some(Queue {
            id,
            sq: DmaBuf::alloc(usize::from(QUEUE_SIZE) * SQE)?,
            cq: DmaBuf::alloc(usize::from(QUEUE_SIZE) * CQE)?,
            tail: 0,
            head: 0,
            phase: true,
        })
    }
}

/// A command's dwords 10–15 and pointers.
#[derive(Clone, Copy, Debug, Default)]
struct Command {
    opcode: u32,
    nsid: u32,
    prp1: u64,
    prp2: u64,
    cdw: [u32; 6],
}

/// An NVMe controller with namespace 1 open.
#[derive(Debug)]
pub struct Nvme {
    regs: IoMem,
    doorbell_stride: u64,
    timeout: Duration,
    admin: Queue,
    io: Queue,
    next_cid: u16,
    /// Data buffer for every transfer (requests are synchronous).
    data: DmaBuf,
    /// PRP list page for transfers longer than two pages.
    prp_list: DmaBuf,
    /// Namespace size in logical blocks.
    blocks: u64,
    /// log2 of the logical block size.
    lba_shift: u32,
}

/// Finds and initializes the first NVMe controller.
pub fn probe() -> Option<Result<Nvme, InitError>> {
    let dev = pci::devices().into_iter().find(|d| {
        d.class == CLASS_STORAGE && d.subclass == SUBCLASS_NVM && d.prog_if == PROG_IF_NVME
    })?;
    Some(Nvme::init(&dev))
}

impl Nvme {
    fn init(dev: &PciDevice) -> Result<Nvme, InitError> {
        dev.enable(true, true);
        let regs = dev.map_bar(0).ok_or(InitError::MapFailed)?;
        let cap = regs.read64(REG_CAP);
        let doorbell_stride = 4u64 << ((cap >> 32) & 0xf);
        // CAP.TO is in 500 ms units; allow at least a second.
        let timeout = Duration::from_millis(((cap >> 24) & 0xff).max(2) * 500);
        let mqes = (cap & 0xffff) as u16 + 1;
        if mqes < QUEUE_SIZE {
            return Err(InitError::NotReady);
        }

        let mut nvme = Nvme {
            regs,
            doorbell_stride,
            timeout,
            admin: Queue::new(0).ok_or(InitError::NoMemory)?,
            io: Queue::new(1).ok_or(InitError::NoMemory)?,
            next_cid: 0,
            data: DmaBuf::alloc(MAX_REQUEST).ok_or(InitError::NoMemory)?,
            prp_list: DmaBuf::alloc(PAGE).ok_or(InitError::NoMemory)?,
            blocks: 0,
            lba_shift: 9,
        };

        // Reset, program the admin queues, enable.
        nvme.regs.write32(REG_CC, 0);
        nvme.wait_status(0)?;
        let n = u32::from(QUEUE_SIZE - 1);
        nvme.regs.write32(REG_AQA, (n << 16) | n);
        let (asq, acq) = (addr(&nvme.admin.sq)?, addr(&nvme.admin.cq)?);
        nvme.regs.write64(REG_ASQ, asq);
        nvme.regs.write64(REG_ACQ, acq);
        // 4 KiB pages (MPS = 0), NVM command set (CSS = 0).
        nvme.regs.write32(REG_CC, CC_EN | CC_IOSQES | CC_IOCQES);
        nvme.wait_status(CSTS_RDY)?;

        // Identify namespace 1: size and logical block format.
        let data = addr(&nvme.data)?;
        let identify = Command {
            opcode: ADMIN_IDENTIFY,
            nsid: NSID,
            prp1: data,
            cdw: [0, 0, 0, 0, 0, 0], // CNS = 0: namespace
            ..Command::default()
        };
        nvme.admin_command(identify)?;
        let mut ns = [0u8; 384];
        nvme.data.read(0, &mut ns);
        let blocks = u64::from_le_bytes(ns[0..8].try_into().unwrap_or([0; 8]));
        let format = usize::from(ns[26] & 0xf);
        let lbaf = u32::from_le_bytes(
            ns[128 + 4 * format..132 + 4 * format]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let lba_shift = (lbaf >> 16) & 0xff;
        // Our block layer speaks 512-byte sectors; accept 512 B..4 KiB blocks.
        if blocks == 0 || !(9..=12).contains(&lba_shift) {
            return Err(InitError::Namespace);
        }
        nvme.blocks = blocks;
        nvme.lba_shift = lba_shift;

        // One I/O queue pair, polled (no interrupts).
        let (sq, cq) = (addr(&nvme.io.sq)?, addr(&nvme.io.cq)?);
        let qsize = u32::from(QUEUE_SIZE - 1) << 16;
        nvme.admin_command(Command {
            opcode: ADMIN_CREATE_CQ,
            prp1: cq,
            cdw: [qsize | 1, 1, 0, 0, 0, 0], // physically contiguous
            ..Command::default()
        })?;
        nvme.admin_command(Command {
            opcode: ADMIN_CREATE_SQ,
            prp1: sq,
            cdw: [qsize | 1, (1 << 16) | 1, 0, 0, 0, 0], // CQ 1, contiguous
            ..Command::default()
        })?;
        Ok(nvme)
    }

    /// Logical block size in bytes.
    pub fn block_size(&self) -> usize {
        1 << self.lba_shift
    }

    fn wait_status(&self, want_ready: u32) -> Result<(), InitError> {
        let deadline = frame::time::now() + self.timeout;
        loop {
            let csts = self.regs.read32(REG_CSTS);
            if csts == u32::MAX || csts & CSTS_CFS != 0 {
                return Err(InitError::NotReady);
            }
            if csts & CSTS_RDY == want_ready {
                return Ok(());
            }
            if frame::time::now() >= deadline {
                return Err(InitError::NotReady);
            }
            core::hint::spin_loop();
        }
    }

    fn admin_command(&mut self, cmd: Command) -> Result<(), InitError> {
        self.submit(true, cmd).map_err(|_| InitError::Command)
    }

    /// Submits `cmd` on the admin or I/O queue and polls for its completion.
    fn submit(&mut self, admin: bool, cmd: Command) -> Result<(), BlockError> {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        let stride = self.doorbell_stride;
        let timeout = self.timeout;
        let q = if admin { &mut self.admin } else { &mut self.io };

        let at = usize::from(q.tail) * SQE;
        let mut sqe = [0u8; SQE];
        sqe[0..4].copy_from_slice(&(cmd.opcode | (u32::from(cid) << 16)).to_le_bytes());
        sqe[4..8].copy_from_slice(&cmd.nsid.to_le_bytes());
        sqe[24..32].copy_from_slice(&cmd.prp1.to_le_bytes());
        sqe[32..40].copy_from_slice(&cmd.prp2.to_le_bytes());
        for (i, d) in cmd.cdw.iter().enumerate() {
            sqe[40 + 4 * i..44 + 4 * i].copy_from_slice(&d.to_le_bytes());
        }
        q.sq.write(at, &sqe);
        q.tail = (q.tail + 1) % QUEUE_SIZE;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let qid = u64::from(q.id);
        self.regs
            .write32(DOORBELLS + 2 * qid * stride, u32::from(q.tail));

        let deadline = frame::time::now() + timeout;
        loop {
            let entry = usize::from(q.head) * CQE;
            let dw3 = q.cq.read_u32(entry + 12);
            let phase = dw3 & (1 << 16) != 0;
            if phase == q.phase {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                q.head = (q.head + 1) % QUEUE_SIZE;
                if q.head == 0 {
                    q.phase = !q.phase;
                }
                self.regs
                    .write32(DOORBELLS + (2 * qid + 1) * stride, u32::from(q.head));
                if (dw3 & 0xffff) as u16 != cid {
                    continue; // Not ours (cannot happen with one in flight).
                }
                let status = (dw3 >> 17) & 0x7fff;
                return if status == 0 {
                    Ok(())
                } else {
                    Err(BlockError::Io)
                };
            }
            if frame::time::now() >= deadline {
                return Err(BlockError::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    /// Reads `buf.len()` bytes (at most `MAX_REQUEST`, whole blocks) from
    /// logical block `lba`.
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let pages = buf.len().div_ceil(PAGE);
        let prp1 = self.data.dma_addr(0).ok_or(BlockError::NoMemory)?.as_u64();
        let prp2 = match pages {
            0 | 1 => 0,
            2 => self
                .data
                .dma_addr(PAGE)
                .ok_or(BlockError::NoMemory)?
                .as_u64(),
            _ => {
                for i in 1..pages {
                    let a = self.data.dma_addr(i * PAGE).ok_or(BlockError::NoMemory)?;
                    self.prp_list.write_u64((i - 1) * 8, a.as_u64());
                }
                self.prp_list
                    .dma_addr(0)
                    .ok_or(BlockError::NoMemory)?
                    .as_u64()
            }
        };
        let count = (buf.len() >> self.lba_shift) as u32;
        self.submit(
            false,
            Command {
                opcode: IO_READ,
                nsid: NSID,
                prp1,
                prp2,
                cdw: [lba as u32, (lba >> 32) as u32, count - 1, 0, 0, 0],
            },
        )?;
        self.data.read(0, buf);
        Ok(())
    }
}

fn addr(b: &DmaBuf) -> Result<u64, InitError> {
    b.dma_addr(0).map(|a| a.as_u64()).ok_or(InitError::NoMemory)
}

impl BlockDevice for Nvme {
    fn sector_count(&self) -> u64 {
        self.blocks << (self.lba_shift - 9)
    }

    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check(self, sector, buf.len())?;
        let block = self.block_size();
        let byte = sector * SECTOR_SIZE as u64;
        if !byte.is_multiple_of(block as u64) || !buf.len().is_multiple_of(block) {
            return Err(BlockError::Unaligned);
        }
        let mut done = 0;
        while done < buf.len() {
            let n = MAX_REQUEST.min(buf.len() - done);
            let lba = (byte + done as u64) >> self.lba_shift;
            self.read_blocks(lba, &mut buf[done..done + n])?;
            done += n;
        }
        Ok(())
    }
}
