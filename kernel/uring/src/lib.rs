//! io_uring (Linux's asynchronous submission interface) for the Linux
//! personality, sans-I/O (ADR-0013 §1): the ABI's structures and
//! constants, the ring layout this kernel offers, and the ordering rules
//! submissions follow (links, hard links, drains). The kernel moves the
//! bytes and runs the operations; this crate decides what may run when.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// Linux's constants (`include/uapi/linux/io_uring.h`).
pub mod abi {
    /// `mmap` offsets of the ring descriptor.
    pub const OFF_SQ_RING: u64 = 0;
    pub const OFF_CQ_RING: u64 = 0x800_0000;
    pub const OFF_SQES: u64 = 0x1000_0000;

    /// `io_uring_setup` flags.
    pub const SETUP_IOPOLL: u32 = 1 << 0;
    pub const SETUP_SQPOLL: u32 = 1 << 1;
    pub const SETUP_SQ_AFF: u32 = 1 << 2;
    pub const SETUP_CQSIZE: u32 = 1 << 3;
    pub const SETUP_CLAMP: u32 = 1 << 4;
    pub const SETUP_ATTACH_WQ: u32 = 1 << 5;
    pub const SETUP_R_DISABLED: u32 = 1 << 6;
    pub const SETUP_SUBMIT_ALL: u32 = 1 << 7;
    pub const SETUP_COOP_TASKRUN: u32 = 1 << 8;
    pub const SETUP_TASKRUN_FLAG: u32 = 1 << 9;
    pub const SETUP_SQE128: u32 = 1 << 10;
    pub const SETUP_CQE32: u32 = 1 << 11;
    pub const SETUP_SINGLE_ISSUER: u32 = 1 << 12;
    pub const SETUP_DEFER_TASKRUN: u32 = 1 << 13;
    pub const SETUP_NO_SQARRAY: u32 = 1 << 16;

    /// `io_uring_params.features`.
    pub const FEAT_SINGLE_MMAP: u32 = 1 << 0;
    pub const FEAT_NODROP: u32 = 1 << 1;
    pub const FEAT_SUBMIT_STABLE: u32 = 1 << 2;
    pub const FEAT_RW_CUR_POS: u32 = 1 << 3;
    pub const FEAT_CUR_PERSONALITY: u32 = 1 << 4;
    pub const FEAT_FAST_POLL: u32 = 1 << 5;
    pub const FEAT_POLL_32BITS: u32 = 1 << 6;
    pub const FEAT_SQPOLL_NONFIXED: u32 = 1 << 7;
    pub const FEAT_EXT_ARG: u32 = 1 << 8;
    pub const FEAT_NATIVE_WORKERS: u32 = 1 << 9;
    pub const FEAT_RSRC_TAGS: u32 = 1 << 10;
    pub const FEAT_CQE_SKIP: u32 = 1 << 11;
    pub const FEAT_LINKED_FILE: u32 = 1 << 12;
    pub const FEAT_REG_REG_RING: u32 = 1 << 13;

    /// `io_uring_enter` flags.
    pub const ENTER_GETEVENTS: u32 = 1 << 0;
    pub const ENTER_SQ_WAKEUP: u32 = 1 << 1;
    pub const ENTER_SQ_WAIT: u32 = 1 << 2;
    pub const ENTER_EXT_ARG: u32 = 1 << 3;
    pub const ENTER_REGISTERED_RING: u32 = 1 << 4;

    /// SQE flags.
    pub const SQE_FIXED_FILE: u8 = 1 << 0;
    pub const SQE_IO_DRAIN: u8 = 1 << 1;
    pub const SQE_IO_LINK: u8 = 1 << 2;
    pub const SQE_IO_HARDLINK: u8 = 1 << 3;
    pub const SQE_ASYNC: u8 = 1 << 4;
    pub const SQE_BUFFER_SELECT: u8 = 1 << 5;
    pub const SQE_CQE_SKIP_SUCCESS: u8 = 1 << 6;

    /// Opcodes.
    pub const OP_NOP: u8 = 0;
    pub const OP_READV: u8 = 1;
    pub const OP_WRITEV: u8 = 2;
    pub const OP_FSYNC: u8 = 3;
    pub const OP_READ_FIXED: u8 = 4;
    pub const OP_WRITE_FIXED: u8 = 5;
    pub const OP_POLL_ADD: u8 = 6;
    pub const OP_POLL_REMOVE: u8 = 7;
    pub const OP_SYNC_FILE_RANGE: u8 = 8;
    pub const OP_SENDMSG: u8 = 9;
    pub const OP_RECVMSG: u8 = 10;
    pub const OP_TIMEOUT: u8 = 11;
    pub const OP_TIMEOUT_REMOVE: u8 = 12;
    pub const OP_ACCEPT: u8 = 13;
    pub const OP_ASYNC_CANCEL: u8 = 14;
    pub const OP_LINK_TIMEOUT: u8 = 15;
    pub const OP_CONNECT: u8 = 16;
    pub const OP_FALLOCATE: u8 = 17;
    pub const OP_OPENAT: u8 = 18;
    pub const OP_CLOSE: u8 = 19;
    pub const OP_FILES_UPDATE: u8 = 20;
    pub const OP_STATX: u8 = 21;
    pub const OP_READ: u8 = 22;
    pub const OP_WRITE: u8 = 23;
    pub const OP_FADVISE: u8 = 24;
    pub const OP_MADVISE: u8 = 25;
    pub const OP_SEND: u8 = 26;
    pub const OP_RECV: u8 = 27;
    pub const OP_OPENAT2: u8 = 28;
    pub const OP_EPOLL_CTL: u8 = 29;
    pub const OP_SPLICE: u8 = 30;
    pub const OP_PROVIDE_BUFFERS: u8 = 31;
    pub const OP_REMOVE_BUFFERS: u8 = 32;
    pub const OP_TEE: u8 = 33;
    pub const OP_SHUTDOWN: u8 = 34;
    pub const OP_RENAMEAT: u8 = 35;
    pub const OP_UNLINKAT: u8 = 36;
    pub const OP_MKDIRAT: u8 = 37;
    pub const OP_SYMLINKAT: u8 = 38;
    pub const OP_LINKAT: u8 = 39;
    pub const OP_MSG_RING: u8 = 40;
    pub const OP_SOCKET: u8 = 45;
    /// A command to the file's driver; `off`'s low half is `cmd_op`.
    pub const OP_URING_CMD: u8 = 46;
    /// `uring_cmd_flags`: the command's buffer is a registered one.
    pub const URING_CMD_FIXED: u32 = 1 << 0;
    /// `SOCKET_URING_OP_*`: what a socket is asked.
    pub const SOCKET_URING_OP_SIOCINQ: u32 = 0;
    pub const SOCKET_URING_OP_SIOCOUTQ: u32 = 1;

    /// What opcodes' flags (`Sqe::op_flags`) ask for.
    pub const FSYNC_DATASYNC: u32 = 1 << 0;
    pub const TIMEOUT_ABS: u32 = 1 << 0;
    pub const TIMEOUT_UPDATE: u32 = 1 << 1;
    pub const TIMEOUT_BOOTTIME: u32 = 1 << 2;
    pub const TIMEOUT_REALTIME: u32 = 1 << 3;
    pub const LINK_TIMEOUT_UPDATE: u32 = 1 << 4;
    pub const TIMEOUT_ETIME_SUCCESS: u32 = 1 << 5;
    pub const TIMEOUT_MULTISHOT: u32 = 1 << 6;
    pub const ASYNC_CANCEL_ALL: u32 = 1 << 0;
    pub const ASYNC_CANCEL_FD: u32 = 1 << 1;
    pub const ASYNC_CANCEL_ANY: u32 = 1 << 2;
    pub const ASYNC_CANCEL_FD_FIXED: u32 = 1 << 3;
    pub const SPLICE_F_FD_IN_FIXED: u32 = 1 << 31;
    pub const MSG_RING_CQE_SKIP: u32 = 1 << 0;
    pub const MSG_RING_FLAGS_PASS: u32 = 1 << 1;
    /// `Sqe::addr` of MSG_RING.
    pub const MSG_DATA: u64 = 0;
    pub const MSG_SEND_FD: u64 = 1;
    /// `Sqe::len` of POLL_ADD and POLL_REMOVE.
    pub const POLL_ADD_MULTI: u32 = 1 << 0;
    pub const POLL_UPDATE_EVENTS: u32 = 1 << 1;
    pub const POLL_UPDATE_USER_DATA: u32 = 1 << 2;
    pub const POLL_ADD_LEVEL: u32 = 1 << 3;
    /// `Sqe::ioprio` of the socket opcodes.
    pub const RECVSEND_POLL_FIRST: u16 = 1 << 0;
    pub const RECV_MULTISHOT: u16 = 1 << 1;
    pub const ACCEPT_MULTISHOT: u16 = 1 << 0;
    /// `Sqe::file_index`: any free slot.
    pub const FILE_INDEX_ALLOC: u32 = u32::MAX;

    /// `Cqe::flags`.
    pub const CQE_F_BUFFER: u32 = 1 << 0;
    pub const CQE_F_MORE: u32 = 1 << 1;
    pub const CQE_F_SOCK_NONEMPTY: u32 = 1 << 2;
    pub const CQE_BUFFER_SHIFT: u32 = 16;

    /// `io_uring_register` opcodes.
    pub const REGISTER_BUFFERS: u32 = 0;
    pub const UNREGISTER_BUFFERS: u32 = 1;
    pub const REGISTER_FILES: u32 = 2;
    pub const UNREGISTER_FILES: u32 = 3;
    pub const REGISTER_EVENTFD: u32 = 4;
    pub const UNREGISTER_EVENTFD: u32 = 5;
    pub const REGISTER_FILES_UPDATE: u32 = 6;
    pub const REGISTER_EVENTFD_ASYNC: u32 = 7;
    pub const REGISTER_PROBE: u32 = 8;
    pub const REGISTER_RESTRICTIONS: u32 = 11;
    pub const REGISTER_ENABLE_RINGS: u32 = 12;
    pub const REGISTER_FILES2: u32 = 13;
    pub const REGISTER_FILES_UPDATE2: u32 = 14;
    pub const REGISTER_BUFFERS2: u32 = 15;
    pub const REGISTER_BUFFERS_UPDATE: u32 = 16;
    pub const REGISTER_IOWQ_AFF: u32 = 17;
    pub const UNREGISTER_IOWQ_AFF: u32 = 18;
    pub const REGISTER_IOWQ_MAX_WORKERS: u32 = 19;
    pub const REGISTER_RING_FDS: u32 = 20;
    pub const UNREGISTER_RING_FDS: u32 = 21;
    pub const REGISTER_PBUF_RING: u32 = 22;
    pub const UNREGISTER_PBUF_RING: u32 = 23;
    pub const REGISTER_SYNC_CANCEL: u32 = 24;
    pub const REGISTER_FILE_ALLOC_RANGE: u32 = 25;
    /// Beside the opcode: `fd` is a registered ring.
    pub const REGISTER_USE_REGISTERED_RING: u32 = 1 << 31;
    /// `io_uring_rsrc_register.flags`: no slot filled.
    pub const RSRC_REGISTER_SPARSE: u32 = 1 << 0;
    /// A file slot to leave alone in an update.
    pub const REGISTER_FILES_SKIP: i32 = -2;
    /// `io_uring_buf_reg.flags`: the kernel has the ring's memory.
    pub const PBUF_RING_MMAP: u16 = 1;

    /// SQ ring flags.
    pub const SQ_NEED_WAKEUP: u32 = 1 << 0;
    pub const SQ_CQ_OVERFLOW: u32 = 1 << 1;
    pub const SQ_TASKRUN: u32 = 1 << 2;
    /// CQ ring flags.
    pub const CQ_EVENTFD_DISABLED: u32 = 1 << 0;

    /// `mmap` of a provided-buffer ring: this, and its group above.
    pub const OFF_PBUF_RING: u64 = 0x8000_0000;
    pub const OFF_PBUF_SHIFT: u32 = 16;
    pub const OFF_MMAP_MASK: u64 = 0xf800_0000;

    /// `io_uring_probe_op.flags`: the opcode is supported.
    pub const OP_SUPPORTED: u16 = 1;
}

const EINVAL: i64 = 22;

/// Most SQ entries (Linux's `IORING_MAX_ENTRIES`).
pub const MAX_ENTRIES: u32 = 32768;
/// Most CQ entries.
pub const MAX_CQ_ENTRIES: u32 = 2 * MAX_ENTRIES;

/// Setup flags this kernel accepts. The others ask for memory the
/// application brings.
const ACCEPTED: u32 = abi::SETUP_IOPOLL
    | abi::SETUP_SQPOLL
    | abi::SETUP_SQ_AFF
    | abi::SETUP_ATTACH_WQ
    | abi::SETUP_CQSIZE
    | abi::SETUP_CLAMP
    | abi::SETUP_R_DISABLED
    | abi::SETUP_SUBMIT_ALL
    | abi::SETUP_COOP_TASKRUN
    | abi::SETUP_TASKRUN_FLAG
    | abi::SETUP_SQE128
    | abi::SETUP_CQE32
    | abi::SETUP_SINGLE_ISSUER
    | abi::SETUP_DEFER_TASKRUN
    | abi::SETUP_NO_SQARRAY;

/// The features this kernel offers.
pub const FEATURES: u32 = abi::FEAT_SINGLE_MMAP
    | abi::FEAT_NODROP
    | abi::FEAT_SUBMIT_STABLE
    | abi::FEAT_RW_CUR_POS
    | abi::FEAT_CUR_PERSONALITY
    | abi::FEAT_FAST_POLL
    | abi::FEAT_POLL_32BITS
    | abi::FEAT_SQPOLL_NONFIXED
    | abi::FEAT_EXT_ARG
    | abi::FEAT_NATIVE_WORKERS
    | abi::FEAT_RSRC_TAGS
    | abi::FEAT_CQE_SKIP
    | abi::FEAT_LINKED_FILE
    | abi::FEAT_REG_REG_RING;

/// Where the SQ ring's fields are in the ring mapping (byte offsets, as
/// `io_sqring_offsets` reports them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
}

/// The same for the CQ ring (`io_cqring_offsets`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CqOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
}

/// A ring's shape: one mapping holds both rings (`FEAT_SINGLE_MMAP`), the
/// SQE array is another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    /// 16, or 32 (`SETUP_CQE32`).
    pub cqe_bytes: u32,
    /// 64, or 128 (`SETUP_SQE128`).
    pub sqe_bytes: u32,
    pub sq: SqOffsets,
    pub cq: CqOffsets,
    /// Bytes of the ring mapping (whole pages).
    pub ring_bytes: u64,
    /// Bytes of the SQE mapping (whole pages).
    pub sqes_bytes: u64,
}

const PAGE: u64 = 4096;

/// `io_uring_setup(entries, params)`: the layout for `entries` SQEs, with
/// `params.flags` and (with `SETUP_CQSIZE`) `params.cq_entries`.
pub fn setup(entries: u32, flags: u32, cq_entries: u32) -> Result<Layout, i64> {
    let has = |f: u32| flags & f != 0;
    if flags & !ACCEPTED != 0
        // A thread that runs the completions is told of them by one that
        // would be interrupted for them.
        || (has(abi::SETUP_TASKRUN_FLAG)
            && !has(abi::SETUP_COOP_TASKRUN | abi::SETUP_DEFER_TASKRUN))
        || (has(abi::SETUP_SQPOLL)
            && has(abi::SETUP_COOP_TASKRUN
                | abi::SETUP_TASKRUN_FLAG
                | abi::SETUP_DEFER_TASKRUN))
        || (has(abi::SETUP_DEFER_TASKRUN) && !has(abi::SETUP_SINGLE_ISSUER))
        || (has(abi::SETUP_SQ_AFF) && !has(abi::SETUP_SQPOLL))
    {
        return Err(EINVAL);
    }
    let clamp = flags & abi::SETUP_CLAMP != 0;
    let fit = |n: u32, max: u32| -> Result<u32, i64> {
        if n == 0 {
            return Err(EINVAL);
        }
        if n > max {
            return if clamp { Ok(max) } else { Err(EINVAL) };
        }
        Ok(n.next_power_of_two())
    };
    let sq_entries = fit(entries, MAX_ENTRIES)?;
    let cq_entries = if flags & abi::SETUP_CQSIZE != 0 {
        let c = fit(cq_entries, MAX_CQ_ENTRIES)?;
        if c < sq_entries {
            return Err(EINVAL);
        }
        c
    } else {
        2 * sq_entries
    };
    // Fields grouped by writer, one 64-byte line each: the kernel's (the
    // SQ head, the CQ tail, the counters) from 0, the application's (the
    // SQ tail, the CQ head, the CQ flags) and the constants from 64. CQEs
    // (16 bytes each, or 32) from 128, then the SQ index array.
    let cqe_bytes = if has(abi::SETUP_CQE32) { 32 } else { 16 };
    let sqe_bytes = if has(abi::SETUP_SQE128) { 128 } else { 64 };
    let sq = SqOffsets {
        head: 0,
        tail: 64,
        ring_mask: 76,
        ring_entries: 80,
        flags: 8,
        dropped: 12,
        array: 128 + cq_entries * cqe_bytes,
    };
    let cq = CqOffsets {
        head: 68,
        tail: 4,
        ring_mask: 84,
        ring_entries: 88,
        overflow: 16,
        cqes: 128,
        flags: 72,
    };
    let ring_bytes = (u64::from(sq.array) + u64::from(sq_entries) * 4).next_multiple_of(PAGE);
    Ok(Layout {
        sq_entries,
        cq_entries,
        flags,
        cqe_bytes,
        sqe_bytes,
        sq,
        cq,
        ring_bytes,
        sqes_bytes: (u64::from(sq_entries) * u64::from(sqe_bytes)).next_multiple_of(PAGE),
    })
}

impl Layout {
    pub fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// `struct io_uring_params` as `io_uring_setup` writes it back (120
    /// bytes).
    pub fn params(&self) -> [u8; 120] {
        let mut b = [0u8; 120];
        let mut put = |at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put(0, self.sq_entries);
        put(4, self.cq_entries);
        put(8, self.flags);
        put(20, FEATURES);
        let s = self.sq;
        for (i, v) in [
            s.head,
            s.tail,
            s.ring_mask,
            s.ring_entries,
            s.flags,
            s.dropped,
            s.array,
        ]
        .into_iter()
        .enumerate()
        {
            put(40 + 4 * i, v);
        }
        let c = self.cq;
        for (i, v) in [
            c.head,
            c.tail,
            c.ring_mask,
            c.ring_entries,
            c.overflow,
            c.cqes,
            c.flags,
        ]
        .into_iter()
        .enumerate()
        {
            put(80 + 4 * i, v);
        }
        b
    }

    /// The initial contents of the ring mapping's constant fields: masks
    /// and entry counts (`(offset, value)` pairs).
    pub fn constants(&self) -> [(u32, u32); 4] {
        [
            (self.sq.ring_mask, self.sq_entries - 1),
            (self.sq.ring_entries, self.sq_entries),
            (self.cq.ring_mask, self.cq_entries - 1),
            (self.cq.ring_entries, self.cq_entries),
        ]
    }
}

/// A submission queue entry (64 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    /// The file offset (or `addr2`).
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    /// The opcode's flags (`rw_flags`, `poll32_events`, `msg_flags`, ...).
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub file_index: i32,
    pub addr3: u64,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

impl Sqe {
    pub fn parse(b: &[u8; 64]) -> Sqe {
        Sqe {
            opcode: b[0],
            flags: b[1],
            ioprio: u16_at(b, 2),
            fd: u32_at(b, 4) as i32,
            off: u64_at(b, 8),
            addr: u64_at(b, 16),
            len: u32_at(b, 24),
            op_flags: u32_at(b, 28),
            user_data: u64_at(b, 32),
            buf_index: u16_at(b, 40),
            personality: u16_at(b, 42),
            file_index: u32_at(b, 44) as i32,
            addr3: u64_at(b, 48),
        }
    }

    pub fn encode(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0] = self.opcode;
        b[1] = self.flags;
        b[2..4].copy_from_slice(&self.ioprio.to_le_bytes());
        b[4..8].copy_from_slice(&self.fd.to_le_bytes());
        b[8..16].copy_from_slice(&self.off.to_le_bytes());
        b[16..24].copy_from_slice(&self.addr.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..32].copy_from_slice(&self.op_flags.to_le_bytes());
        b[32..40].copy_from_slice(&self.user_data.to_le_bytes());
        b[40..42].copy_from_slice(&self.buf_index.to_le_bytes());
        b[42..44].copy_from_slice(&self.personality.to_le_bytes());
        b[44..48].copy_from_slice(&self.file_index.to_le_bytes());
        b[48..56].copy_from_slice(&self.addr3.to_le_bytes());
        b
    }
}

/// A completion queue entry (16 bytes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

impl Cqe {
    pub fn encode(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.user_data.to_le_bytes());
        b[8..12].copy_from_slice(&self.res.to_le_bytes());
        b[12..].copy_from_slice(&self.flags.to_le_bytes());
        b
    }

    pub fn parse(b: &[u8; 16]) -> Cqe {
        Cqe {
            user_data: u64_at(b, 0),
            res: u32_at(b, 8) as i32,
            flags: u32_at(b, 12),
        }
    }
}

/// SQEs waiting between the kernel's head and the application's tail
/// (never more than the ring holds, whatever the tail says).
pub fn pending(head: u32, tail: u32, entries: u32) -> u32 {
    tail.wrapping_sub(head).min(entries)
}

/// Free CQE slots.
pub fn cq_space(head: u32, tail: u32, entries: u32) -> u32 {
    entries.saturating_sub(tail.wrapping_sub(head))
}

/// An SQE that is not complete.
#[derive(Debug)]
struct Node {
    /// The chain member before this one, while that is not complete.
    prev: Option<u64>,
    next: Option<u64>,
    /// May the next member run if this one fails? (`IO_HARDLINK`)
    hard: bool,
    started: bool,
    /// The LINK_TIMEOUT that limits this one.
    timeout: Option<u64>,
    /// For a LINK_TIMEOUT: the SQE it limits. It is beside the chain, not
    /// in it: it starts with that one, and the next member follows that
    /// one.
    limits: Option<u64>,
}

/// What completing an SQE did to others.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Cancelled {
    /// Members of its chain, cancelled because a soft link broke, with
    /// their LINK_TIMEOUTs.
    pub chain: Vec<u64>,
    /// Its own LINK_TIMEOUT, which has nothing left to limit.
    pub timeout: Option<u64>,
}

/// The order submissions may run in (ADR-0013 §1): SQEs run concurrently
/// unless linked (`IO_LINK`: one after another, the rest cancelled if one
/// fails; `IO_HARDLINK`: one after another regardless) or drained
/// (`IO_DRAIN`: after everything before it, and before everything after).
/// Only SQEs that are not complete are kept.
#[derive(Debug, Default)]
pub struct Order {
    next_id: u64,
    nodes: BTreeMap<u64, Node>,
    /// SQEs that have not started, LINK_TIMEOUTs aside.
    waiting: BTreeSet<u64>,
    /// Drained SQEs that are not complete.
    drains: BTreeSet<u64>,
    /// The chain being assembled: its first member and its last, which
    /// asked to be linked to the next SQE.
    open: Option<(u64, u64)>,
    /// The last SQE was a LINK_TIMEOUT that asked to be linked.
    after_timeout: bool,
}

impl Order {
    pub fn new() -> Order {
        Order::default()
    }

    /// Records the next SQE, in submission order; returns its id.
    pub fn submit(&mut self, flags: u8) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let open = self.open.take();
        self.after_timeout = false;
        let prev = open.map(|(_, last)| last);
        if let Some(n) = prev.and_then(|p| self.nodes.get_mut(&p)) {
            n.next = Some(id);
        }
        let first = open.map_or(id, |(first, _)| first);
        self.nodes.insert(
            id,
            Node {
                prev,
                next: None,
                hard: flags & abi::SQE_IO_HARDLINK != 0,
                started: false,
                timeout: None,
                limits: None,
            },
        );
        self.waiting.insert(id);
        if flags & abi::SQE_IO_DRAIN != 0 {
            // A chain is drained as a whole.
            self.drains.extend([first, id]);
        }
        if flags & (abi::SQE_IO_LINK | abi::SQE_IO_HARDLINK) != 0 {
            self.open = Some((first, id));
        }
        id
    }

    /// Records a LINK_TIMEOUT, which limits the SQE before it: `None` if
    /// that is not linked to it, or is one itself.
    pub fn submit_timeout(&mut self, flags: u8) -> Option<u64> {
        let (first, last) = self.open.filter(|_| !self.after_timeout)?;
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.get_mut(&last)?.timeout = Some(id);
        self.nodes.insert(
            id,
            Node {
                prev: None,
                next: None,
                hard: false,
                started: false,
                timeout: None,
                limits: Some(last),
            },
        );
        if flags & (abi::SQE_IO_LINK | abi::SQE_IO_HARDLINK) != 0 {
            self.after_timeout = true;
            self.open = Some((first, last));
        } else {
            self.open = None;
        }
        Some(id)
    }

    /// The first member of the chain being assembled.
    pub fn chain(&self) -> Option<u64> {
        self.open.map(|(first, _)| first)
    }

    /// What a LINK_TIMEOUT limits, if that is not complete.
    pub fn limited_by(&self, id: u64) -> Option<u64> {
        self.nodes.get(&id)?.limits
    }

    /// The end of one `io_uring_enter`'s submissions: a link chain does not
    /// continue into the next call.
    pub fn end_batch(&mut self) {
        self.open = None;
        self.after_timeout = false;
    }

    /// The SQEs that may start now, each reported once, in order.
    pub fn ready(&mut self) -> Vec<u64> {
        let mut out = Vec::new();
        for &id in &self.waiting {
            match self.drains.first() {
                // Nothing after an unfinished drain may start, ...
                Some(&d) if d < id => break,
                // ... nor the drain before everything earlier is done.
                Some(&d) if d == id && self.nodes.keys().next() != Some(&id) => break,
                _ => {}
            }
            let Some(n) = self.nodes.get_mut(&id) else {
                continue;
            };
            if n.prev.is_some() {
                continue;
            }
            n.started = true;
            out.push(id);
            if let Some(t) = n.timeout {
                if let Some(tn) = self.nodes.get_mut(&t) {
                    tn.started = true;
                }
                out.push(t);
            }
        }
        for id in &out {
            self.waiting.remove(id);
        }
        out
    }

    /// Records that `id`, which was refused, is over: even a hard link ends
    /// with it.
    pub fn refuse(&mut self, id: u64) -> Cancelled {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.hard = false;
        }
        self.complete(id, false)
    }

    /// Records that `id` completed (`ok`: as the operation asked). Returns
    /// the SQEs that ends, which complete with `-ECANCELED`.
    pub fn complete(&mut self, id: u64, ok: bool) -> Cancelled {
        let mut gone = Cancelled::default();
        let Some(n) = self.remove(id) else {
            return gone;
        };
        if let Some(t) = n.timeout
            && self.remove(t).is_some()
        {
            gone.timeout = Some(t);
        }
        let mut next = n.next;
        if let Some(c) = next.and_then(|c| self.nodes.get_mut(&c)) {
            c.prev = None;
        }
        if !ok && !n.hard {
            while let Some(c) = next {
                let Some(cn) = self.remove(c) else {
                    break;
                };
                gone.chain.push(c);
                if let Some(t) = cn.timeout
                    && self.remove(t).is_some()
                {
                    gone.chain.push(t);
                }
                next = cn.next;
            }
        }
        gone
    }

    fn remove(&mut self, id: u64) -> Option<Node> {
        self.waiting.remove(&id);
        self.drains.remove(&id);
        let n = self.nodes.remove(&id)?;
        if let Some(limited) = n.limits.and_then(|l| self.nodes.get_mut(&l)) {
            limited.timeout = None;
        }
        Some(n)
    }

    /// SQEs submitted and not yet complete.
    pub fn in_flight(&self) -> usize {
        self.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::*;

    #[test]
    fn setup_rounds_clamps_and_refuses() {
        let l = setup(100, 0, 0).unwrap();
        assert_eq!((l.sq_entries, l.cq_entries), (128, 256));
        assert_eq!(l.sqes_bytes, 8192);
        assert_eq!(setup(0, 0, 0), Err(EINVAL));
        assert_eq!(setup(MAX_ENTRIES + 1, 0, 0), Err(EINVAL));
        assert_eq!(
            setup(MAX_ENTRIES + 1, SETUP_CLAMP, 0).unwrap().sq_entries,
            MAX_ENTRIES
        );
        assert_eq!(setup(8, SETUP_CQSIZE, 100).unwrap().cq_entries, 128);
        assert_eq!(setup(8, SETUP_CQSIZE, 4), Err(EINVAL));
        assert_eq!(setup(8, 1 << 14, 0), Err(EINVAL)); // NO_MMAP
        assert_eq!(setup(8, SETUP_SQ_AFF, 0), Err(EINVAL));
        assert_eq!(setup(8, SETUP_DEFER_TASKRUN, 0), Err(EINVAL));
        assert!(setup(8, SETUP_DEFER_TASKRUN | SETUP_SINGLE_ISSUER, 0).is_ok());
        assert_eq!(setup(8, SETUP_SQPOLL | SETUP_COOP_TASKRUN, 0), Err(EINVAL));
        let l = setup(64, SETUP_SQE128 | SETUP_CQE32, 0).unwrap();
        assert_eq!((l.sqe_bytes, l.cqe_bytes), (128, 32));
        assert_eq!((l.sqes_bytes, l.sq.array), (8192, 128 + 128 * 32));
    }

    #[test]
    fn the_layout_does_not_overlap() {
        let l = setup(4096, SETUP_CQSIZE, 8192).unwrap();
        let mut words: Vec<u32> = [
            l.sq.head,
            l.sq.tail,
            l.sq.ring_mask,
            l.sq.ring_entries,
            l.sq.flags,
            l.sq.dropped,
            l.cq.head,
            l.cq.tail,
            l.cq.ring_mask,
            l.cq.ring_entries,
            l.cq.overflow,
            l.cq.flags,
        ]
        .to_vec();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), 12);
        assert!(words.iter().all(|&w| w % 4 == 0 && w < l.cq.cqes));
        assert!(l.cq.cqes + l.cq_entries * 16 <= l.sq.array);
        assert!(u64::from(l.sq.array) + u64::from(l.sq_entries) * 4 <= l.ring_bytes);
        // Producer and consumer indices on separate cache lines.
        assert_ne!(l.sq.head / 64, l.sq.tail / 64);
        assert_ne!(l.cq.head / 64, l.cq.tail / 64);
        let p = l.params();
        assert_eq!(u32_at(&p, 0), 4096);
        assert_eq!(u32_at(&p, 20), FEATURES);
        assert_eq!(u32_at(&p, 40 + 24), l.sq.array);
        assert_eq!(u32_at(&p, 80 + 20), l.cq.cqes);
    }

    #[test]
    fn entries_round_trip() {
        let s = Sqe {
            opcode: OP_READ,
            flags: SQE_IO_LINK,
            fd: -100,
            off: u64::MAX,
            addr: 0x7fff_0000,
            len: 4096,
            op_flags: 7,
            user_data: 0xdead_beef,
            file_index: -1,
            ..Sqe::default()
        };
        assert_eq!(Sqe::parse(&s.encode()), s);
        let c = Cqe {
            user_data: 9,
            res: -11,
            flags: 2,
        };
        assert_eq!(Cqe::parse(&c.encode()), c);
        assert_eq!(pending(u32::MAX - 1, 3, 8), 5);
        assert_eq!(pending(0, 100, 8), 8);
        assert_eq!(cq_space(10, 12, 8), 6);
    }

    #[test]
    fn independent_sqes_all_start() {
        let mut o = Order::new();
        let ids: Vec<u64> = (0..3).map(|_| o.submit(0)).collect();
        o.end_batch();
        assert_eq!(o.ready(), ids);
        assert!(o.ready().is_empty());
        for id in ids {
            assert_eq!(o.complete(id, true), Cancelled::default());
        }
        assert_eq!(o.in_flight(), 0);
    }

    #[test]
    fn link_timeouts_stand_beside_the_chain() {
        let mut o = Order::new();
        assert_eq!(o.submit_timeout(0), None);
        let a = o.submit(SQE_IO_LINK);
        let t = o.submit_timeout(SQE_IO_LINK).unwrap();
        // One limits one.
        assert_eq!(o.submit_timeout(0), None);
        let b = o.submit(SQE_IO_LINK);
        let u = o.submit_timeout(0).unwrap();
        let c = o.submit(0);
        o.end_batch();
        assert_eq!(o.ready(), [a, t, c]);
        assert_eq!(o.limited_by(t), Some(a));
        // `a` is done in time: its timeout is over, and `b` follows it.
        let gone = o.complete(a, true);
        assert_eq!((gone.timeout, gone.chain), (Some(t), Vec::new()));
        assert_eq!(o.ready(), [b, u]);
        // The timeout of `b` fires: it completes, then what it limits.
        assert_eq!(o.complete(u, true), Cancelled::default());
        assert_eq!(o.complete(b, false), Cancelled::default());
        o.complete(c, true);
        assert_eq!(o.in_flight(), 0);
        // A broken chain takes the timeouts of what it cancels with it.
        let a = o.submit(SQE_IO_LINK);
        let b = o.submit(SQE_IO_LINK);
        let t = o.submit_timeout(0).unwrap();
        o.end_batch();
        assert_eq!(o.ready(), [a]);
        assert_eq!(o.complete(a, false).chain, [b, t]);
        assert_eq!(o.in_flight(), 0);
    }

    #[test]
    fn a_drained_chain_is_drained_as_a_whole() {
        let mut o = Order::new();
        let a = o.submit(0);
        let b = o.submit(SQE_IO_LINK);
        let c = o.submit(SQE_IO_DRAIN);
        let d = o.submit(0);
        o.end_batch();
        assert_eq!(o.ready(), [a]);
        o.complete(a, true);
        assert_eq!(o.ready(), [b]);
        o.complete(b, true);
        assert_eq!(o.ready(), [c]);
        o.complete(c, true);
        assert_eq!(o.ready(), [d]);
    }

    #[test]
    fn what_is_complete_is_forgotten() {
        let mut o = Order::new();
        let long = o.submit(0);
        for _ in 0..1000 {
            let id = o.submit(0);
            o.ready();
            o.complete(id, true);
        }
        assert_eq!((o.in_flight(), o.nodes.len()), (1, 1));
        o.complete(long, true);
        assert!(o.nodes.is_empty() && o.waiting.is_empty());
    }

    #[test]
    fn links_run_in_turn_and_break_on_failure() {
        let mut o = Order::new();
        let a = o.submit(SQE_IO_LINK);
        let b = o.submit(SQE_IO_LINK);
        let c = o.submit(0);
        let d = o.submit(0);
        o.end_batch();
        assert_eq!(o.ready(), [a, d]);
        assert_eq!(o.complete(a, true), Cancelled::default());
        assert_eq!(o.ready(), [b]);
        // b fails: c is cancelled.
        assert_eq!(o.complete(b, false).chain, [c]);
        assert!(o.ready().is_empty());
        o.complete(d, true);
        assert_eq!(o.in_flight(), 0);
    }

    #[test]
    fn hard_links_survive_failure() {
        let mut o = Order::new();
        let a = o.submit(SQE_IO_HARDLINK);
        let b = o.submit(0);
        o.end_batch();
        assert_eq!(o.ready(), [a]);
        assert_eq!(o.complete(a, false), Cancelled::default());
        assert_eq!(o.ready(), [b]);
        // But not its being refused.
        let a = o.submit(SQE_IO_HARDLINK);
        let b = o.submit(0);
        o.end_batch();
        assert_eq!(o.refuse(a).chain, [b]);
    }

    #[test]
    fn drains_wait_for_everything_before_and_hold_everything_after() {
        let mut o = Order::new();
        let a = o.submit(0);
        let b = o.submit(0);
        let d = o.submit(SQE_IO_DRAIN);
        let e = o.submit(0);
        o.end_batch();
        assert_eq!(o.ready(), [a, b]);
        o.complete(a, true);
        assert!(o.ready().is_empty());
        o.complete(b, true);
        assert_eq!(o.ready(), [d]);
        o.complete(d, true);
        assert_eq!(o.ready(), [e]);
    }

    #[test]
    fn a_chain_ends_with_its_batch() {
        let mut o = Order::new();
        let a = o.submit(SQE_IO_LINK);
        o.end_batch();
        let b = o.submit(0);
        assert_eq!(o.ready(), [a, b]);
        assert_eq!(o.complete(a, false), Cancelled::default());
    }
}
