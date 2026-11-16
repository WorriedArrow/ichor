//! io_uring (Linux's asynchronous submission interface) for the Linux
//! personality, sans-I/O (ADR-0013 §1): the ABI's structures and
//! constants, the ring layout this kernel offers, and the ordering rules
//! submissions follow (links, hard links, drains). The kernel moves the
//! bytes and runs the operations; this crate decides what may run when.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
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

    /// `io_uring_params.features`.
    pub const FEAT_SINGLE_MMAP: u32 = 1 << 0;
    pub const FEAT_NODROP: u32 = 1 << 1;
    pub const FEAT_SUBMIT_STABLE: u32 = 1 << 2;
    pub const FEAT_RW_CUR_POS: u32 = 1 << 3;
    pub const FEAT_EXT_ARG: u32 = 1 << 8;

    /// `io_uring_enter` flags.
    pub const ENTER_GETEVENTS: u32 = 1 << 0;
    pub const ENTER_SQ_WAKEUP: u32 = 1 << 1;
    pub const ENTER_SQ_WAIT: u32 = 1 << 2;
    pub const ENTER_EXT_ARG: u32 = 1 << 3;

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
    pub const OP_STATX: u8 = 21;
    pub const OP_READ: u8 = 22;
    pub const OP_WRITE: u8 = 23;
    pub const OP_SEND: u8 = 26;
    pub const OP_RECV: u8 = 27;
    pub const OP_SHUTDOWN: u8 = 34;
    pub const OP_RENAMEAT: u8 = 35;
    pub const OP_UNLINKAT: u8 = 36;
    pub const OP_MKDIRAT: u8 = 37;

    /// `io_uring_register` opcodes.
    pub const REGISTER_BUFFERS: u32 = 0;
    pub const UNREGISTER_BUFFERS: u32 = 1;
    pub const REGISTER_FILES: u32 = 2;
    pub const UNREGISTER_FILES: u32 = 3;
    pub const REGISTER_EVENTFD: u32 = 4;
    pub const UNREGISTER_EVENTFD: u32 = 5;
    pub const REGISTER_PROBE: u32 = 8;

    /// SQ ring flags.
    pub const SQ_NEED_WAKEUP: u32 = 1 << 0;
    pub const SQ_CQ_OVERFLOW: u32 = 1 << 1;

    /// `io_uring_probe_op.flags`: the opcode is supported.
    pub const OP_SUPPORTED: u16 = 1;
}

const EINVAL: i64 = 22;

/// Most SQ entries (Linux's `IORING_MAX_ENTRIES`).
pub const MAX_ENTRIES: u32 = 32768;
/// Most CQ entries.
pub const MAX_CQ_ENTRIES: u32 = 2 * MAX_ENTRIES;

/// Setup flags this kernel accepts. The others ask for kernel polling
/// threads (ADR-0013 §1 refuses them), larger entries, or sharing worker
/// pools.
const ACCEPTED: u32 = abi::SETUP_CQSIZE
    | abi::SETUP_CLAMP
    | abi::SETUP_SUBMIT_ALL
    | abi::SETUP_COOP_TASKRUN
    | abi::SETUP_TASKRUN_FLAG
    | abi::SETUP_SINGLE_ISSUER
    | abi::SETUP_DEFER_TASKRUN;

/// The features this kernel offers.
pub const FEATURES: u32 = abi::FEAT_SINGLE_MMAP
    | abi::FEAT_NODROP
    | abi::FEAT_SUBMIT_STABLE
    | abi::FEAT_RW_CUR_POS
    | abi::FEAT_EXT_ARG;

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
    if flags & !ACCEPTED != 0 {
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
    // (16 bytes each) from 128, then the SQ index array.
    let sq = SqOffsets {
        head: 0,
        tail: 64,
        ring_mask: 76,
        ring_entries: 80,
        flags: 8,
        dropped: 12,
        array: 128 + cq_entries * 16,
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
        sq,
        cq,
        ring_bytes,
        sqes_bytes: (u64::from(sq_entries) * 64).next_multiple_of(PAGE),
    })
}

impl Layout {
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

#[derive(Debug)]
struct Node {
    flags: u8,
    /// The chain member before this one.
    prev: Option<u64>,
    next: Option<u64>,
    /// May the next member run if this one fails? (`IO_HARDLINK`)
    hard: bool,
    started: bool,
    done: bool,
}

/// The order submissions may run in (ADR-0013 §1): SQEs run concurrently
/// unless linked (`IO_LINK`: one after another, the rest cancelled if one
/// fails; `IO_HARDLINK`: one after another regardless) or drained
/// (`IO_DRAIN`: after everything before it, and before everything after).
#[derive(Debug, Default)]
pub struct Order {
    next_id: u64,
    nodes: BTreeMap<u64, Node>,
    /// The last SQE, if it asked to be linked to the next one.
    open_link: Option<u64>,
}

impl Order {
    pub fn new() -> Order {
        Order::default()
    }

    /// Records the next SQE, in submission order; returns its id.
    pub fn submit(&mut self, flags: u8) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let prev = self.open_link.take();
        if let Some(p) = prev
            && let Some(n) = self.nodes.get_mut(&p)
        {
            n.next = Some(id);
        }
        let links = flags & (abi::SQE_IO_LINK | abi::SQE_IO_HARDLINK) != 0;
        self.nodes.insert(
            id,
            Node {
                flags,
                prev,
                next: None,
                hard: flags & abi::SQE_IO_HARDLINK != 0,
                started: false,
                done: false,
            },
        );
        if links {
            self.open_link = Some(id);
        }
        id
    }

    /// The end of one `io_uring_enter`'s submissions: a link chain does not
    /// continue into the next call.
    pub fn end_batch(&mut self) {
        self.open_link = None;
    }

    /// The SQEs that may start now, each reported once, in order.
    pub fn ready(&mut self) -> Vec<u64> {
        let mut out = Vec::new();
        // Whether every earlier SQE is done (for a drain), and whether an
        // unfinished drain blocks everything after it.
        let mut all_before_done = true;
        let mut ids = Vec::new();
        for (&id, n) in &self.nodes {
            let drain = n.flags & abi::SQE_IO_DRAIN != 0;
            if drain && !all_before_done {
                break;
            }
            let after_prev = n
                .prev
                .is_none_or(|p| self.nodes.get(&p).is_none_or(|pn| pn.done));
            if !n.started && after_prev {
                ids.push(id);
            }
            all_before_done &= n.done;
            if drain && !n.done {
                // Nothing after an unfinished drain may start.
                break;
            }
        }
        for id in ids {
            if let Some(n) = self.nodes.get_mut(&id) {
                n.started = true;
                out.push(id);
            }
        }
        out
    }

    /// Records that `id` completed (`ok`: as the operation asked). Returns
    /// the SQEs cancelled because a soft link broke, which complete with
    /// `-ECANCELED`.
    pub fn complete(&mut self, id: u64, ok: bool) -> Vec<u64> {
        let mut cancelled = Vec::new();
        let Some(n) = self.nodes.get_mut(&id) else {
            return cancelled;
        };
        n.done = true;
        let (mut next, hard) = (n.next, n.hard);
        if !ok && !hard {
            while let Some(c) = next {
                match self.nodes.get_mut(&c) {
                    Some(cn) if !cn.started => {
                        cn.started = true;
                        cn.done = true;
                        cancelled.push(c);
                        next = cn.next;
                    }
                    _ => break,
                }
            }
        }
        self.forget();
        cancelled
    }

    /// Drops finished SQEs nothing can wait on any more.
    fn forget(&mut self) {
        while let Some((&id, n)) = self.nodes.first_key_value() {
            let needed = n
                .next
                .is_some_and(|x| self.nodes.get(&x).is_some_and(|m| !m.done));
            if !n.done || needed || self.open_link == Some(id) {
                break;
            }
            self.nodes.remove(&id);
        }
    }

    /// SQEs submitted and not yet complete.
    pub fn in_flight(&self) -> usize {
        self.nodes.values().filter(|n| !n.done).count()
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
        assert_eq!(setup(8, SETUP_SQPOLL, 0), Err(EINVAL));
        assert_eq!(setup(8, SETUP_IOPOLL, 0), Err(EINVAL));
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
            assert!(o.complete(id, true).is_empty());
        }
        assert_eq!(o.in_flight(), 0);
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
        assert!(o.complete(a, true).is_empty());
        assert_eq!(o.ready(), [b]);
        // b fails: c is cancelled.
        assert_eq!(o.complete(b, false), [c]);
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
        assert!(o.complete(a, false).is_empty());
        assert_eq!(o.ready(), [b]);
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
        assert!(o.complete(a, false).is_empty());
    }
}
