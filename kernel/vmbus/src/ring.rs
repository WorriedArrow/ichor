//! A channel's rings. The guest writes one and reads the other; each is a
//! control page followed by the data, and both are one run of memory (the
//! channel's GPADL). A ring's indices are byte offsets into its data; a
//! packet is a descriptor (what kind, where its payload starts, how long),
//! the payload, padding to 8 bytes, and 8 more.

use alloc::vec::Vec;

use crate::{PAGE, u16_at, u32_at, u64_at};

/// The memory both rings are in: copies, and single accesses to the control
/// words (which the host uses at the same time).
pub trait Memory {
    fn read(&self, offset: usize, out: &mut [u8]);
    fn write(&self, offset: usize, data: &[u8]);
    fn load(&self, offset: usize) -> u32;
    fn store(&self, offset: usize, value: u32);
    /// Everything before is visible before anything after.
    fn fence(&self);
}

// The words of a control page.
const IN: usize = 0;
const OUT: usize = 4;
const INTERRUPT_MASK: usize = 8;
const PENDING_SEND: usize = 12;
const FEATURES: usize = 64;
/// The reader tells a writer that waits for room (`PENDING_SEND`).
const FEATURE_PENDING_SEND: u32 = 1;

const DESCRIPTOR: usize = 16;
const FOOTER: usize = 8;

const IN_BAND: u16 = 6;
const TRANSFER_PAGES: u16 = 7;
const GPA_DIRECT: u16 = 9;
const COMPLETION: u16 = 11;
const WANTS_COMPLETION: u16 = 1;

/// Part of a request's data: `len` bytes of guest memory from `offset` into
/// the first of `pages` (page numbers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    pub len: u32,
    pub offset: u32,
    pub pages: Vec<u64>,
}

/// What a packet says besides its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    InBand,
    /// The answer to the packet of that transaction.
    Completion,
    /// Data is in parts (offset, length) of the memory `set` names.
    TransferPages {
        set: u16,
        parts: Vec<(u32, u32)>,
    },
}

/// A packet from the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub kind: Kind,
    pub transaction: u64,
    /// The host wants a completion.
    pub wants_completion: bool,
    pub payload: Vec<u8>,
}

/// The ring broke its own rules: nothing more can be made of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Corrupt;

/// Why a packet was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// No room yet.
    Full,
    /// It never fits.
    TooLong,
    Corrupt,
}

/// Where one ring is.
#[derive(Clone, Copy, Debug)]
struct Area {
    control: usize,
    data: usize,
    len: u32,
}

impl Area {
    /// Copies `out` from the ring at `at`, around its end.
    fn read(&self, m: &impl Memory, at: u32, out: &mut [u8]) {
        let at = (at % self.len) as usize;
        let first = out.len().min(self.len as usize - at);
        m.read(self.data + at, &mut out[..first]);
        m.read(self.data, &mut out[first..]);
    }

    fn write(&self, m: &impl Memory, at: u32, data: &[u8]) {
        let at = (at % self.len) as usize;
        let first = data.len().min(self.len as usize - at);
        m.write(self.data + at, &data[..first]);
        m.write(self.data, &data[first..]);
    }

    /// The index in a control word, if it is one.
    fn index(&self, m: &impl Memory, word: usize) -> Result<u32, Corrupt> {
        let i = m.load(self.control + word);
        if i < self.len && i.is_multiple_of(8) {
            Ok(i)
        } else {
            Err(Corrupt)
        }
    }

    /// Bytes between `out` and `inp`.
    fn used(&self, inp: u32, out: u32) -> u32 {
        if inp >= out {
            inp - out
        } else {
            self.len - out + inp
        }
    }

    fn step(&self, at: u32, by: u32) -> u32 {
        (at + by) % self.len
    }
}

/// Both rings of a channel, over `m`.
#[derive(Debug)]
pub struct Rings<M> {
    pub m: M,
    send: Area,
    receive: Area,
}

impl<M: Memory> Rings<M> {
    /// How much memory two rings of `data` bytes (whole pages) take.
    pub fn size(data: usize) -> usize {
        2 * (PAGE + data)
    }

    /// Which page of that memory the host's ring starts at.
    pub fn downstream_page(data: usize) -> u32 {
        ((PAGE + data) / PAGE) as u32
    }

    /// The rings of `data` bytes each in `m` (zeroed, and of that size).
    /// `None` if `data` is not whole pages, or too much.
    pub fn new(m: M, data: usize) -> Option<Rings<M>> {
        if data == 0 || !data.is_multiple_of(PAGE) || data > 16 << 20 {
            return None;
        }
        let area = |at| Area {
            control: at,
            data: at + PAGE,
            len: data as u32,
        };
        let r = Rings {
            m,
            send: area(0),
            receive: area(PAGE + data),
        };
        // The host need not interrupt: the rings are polled.
        r.m.store(r.receive.control + INTERRUPT_MASK, 1);
        r.m.store(r.receive.control + FEATURES, FEATURE_PENDING_SEND);
        Some(r)
    }

    /// Writes a packet; whether the host wants to be told.
    fn put(&mut self, head: &[u8], payload: &[u8]) -> Result<bool, SendError> {
        let a = self.send;
        let body = head.len() + payload.len();
        let len = body.next_multiple_of(8);
        let total = (len + FOOTER) as u32;
        // (A full ring would look empty; one step is kept free.)
        if len / 8 > usize::from(u16::MAX) || total + 8 > a.len {
            return Err(SendError::TooLong);
        }
        let inp = a.index(&self.m, IN).map_err(|_| SendError::Corrupt)?;
        let out = a.index(&self.m, OUT).map_err(|_| SendError::Corrupt)?;
        if a.len - a.used(inp, out) < total + 8 {
            return Err(SendError::Full);
        }
        a.write(&self.m, inp, head);
        a.write(&self.m, a.step(inp, head.len() as u32), payload);
        let pad = [0u8; 8];
        a.write(&self.m, a.step(inp, body as u32), &pad[..len - body]);
        let footer = (u64::from(inp) << 32).to_le_bytes();
        a.write(&self.m, a.step(inp, len as u32), &footer);
        // The packet before the index that gives it to the host, and that
        // before looking whether the host sleeps.
        self.m.fence();
        self.m.store(a.control + IN, a.step(inp, total));
        self.m.fence();
        let masked = self.m.load(a.control + INTERRUPT_MASK) != 0;
        Ok(!masked && self.m.load(a.control + OUT) == inp)
    }

    fn descriptor(kind: u16, head: usize, payload: usize, flags: u16, id: u64) -> Vec<u8> {
        let mut d = Vec::with_capacity(head);
        let len = (head + payload).div_ceil(8);
        for v in [kind, (head / 8) as u16, len as u16, flags] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(&id.to_le_bytes());
        d
    }

    /// Sends `payload`, to be answered (under `id`) if `answered`. Whether
    /// the host is to be signalled.
    pub fn send(&mut self, payload: &[u8], id: u64, answered: bool) -> Result<bool, SendError> {
        let flags = if answered { WANTS_COMPLETION } else { 0 };
        let d = Self::descriptor(IN_BAND, DESCRIPTOR, payload.len(), flags, id);
        self.put(&d, payload)
    }

    /// Answers the host's packet `id`.
    pub fn complete(&mut self, id: u64, payload: &[u8]) -> Result<bool, SendError> {
        let d = Self::descriptor(COMPLETION, DESCRIPTOR, payload.len(), 0, id);
        self.put(&d, payload)
    }

    /// Sends `payload` with `data` in guest memory, to be answered.
    pub fn send_with(&mut self, payload: &[u8], data: &Range, id: u64) -> Result<bool, SendError> {
        let head = DESCRIPTOR + 8 + 8 + 8 * data.pages.len();
        if head / 8 > usize::from(u16::MAX) {
            return Err(SendError::TooLong);
        }
        let mut d = Self::descriptor(GPA_DIRECT, head, payload.len(), WANTS_COMPLETION, id);
        for v in [0, 1, data.len, data.offset] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        for p in &data.pages {
            d.extend_from_slice(&p.to_le_bytes());
        }
        self.put(&d, payload)
    }

    /// The next packet from the host, and whether it is to be told of the
    /// room that made.
    pub fn receive(&mut self) -> Result<Option<(Packet, bool)>, Corrupt> {
        let a = self.receive;
        let inp = a.index(&self.m, IN)?;
        let out = a.index(&self.m, OUT)?;
        // The packet after the index that gave it to us.
        self.m.fence();
        let used = a.used(inp, out);
        if used == 0 {
            return Ok(None);
        }
        let mut d = [0u8; DESCRIPTOR];
        if (used as usize) < DESCRIPTOR + FOOTER {
            return Err(Corrupt);
        }
        a.read(&self.m, out, &mut d);
        let head = usize::from(u16_at(&d, 2)) * 8;
        let len = usize::from(u16_at(&d, 4)) * 8;
        let (kind, flags) = (u16_at(&d, 0), u16_at(&d, 6));
        if head < DESCRIPTOR || len < head || len + FOOTER > used as usize {
            return Err(Corrupt);
        }
        let mut all = alloc::vec![0u8; len];
        a.read(&self.m, out, &mut all);
        let payload = all.split_off(head);
        let kind = match kind {
            IN_BAND => Kind::InBand,
            COMPLETION => Kind::Completion,
            TRANSFER_PAGES if head >= DESCRIPTOR + 8 => {
                let count = u32_at(&all, DESCRIPTOR + 4) as usize;
                let parts = &all[DESCRIPTOR + 8..];
                if count > parts.len() / 8 {
                    return Err(Corrupt);
                }
                Kind::TransferPages {
                    set: u16_at(&all, DESCRIPTOR),
                    parts: (0..count)
                        .map(|i| (u32_at(parts, 8 * i + 4), u32_at(parts, 8 * i)))
                        .collect(),
                }
            }
            _ => return Err(Corrupt),
        };
        let total = (len + FOOTER) as u32;
        self.m.fence();
        self.m.store(a.control + OUT, a.step(out, total));
        self.m.fence();
        // A host that waits for room says how much; it is told once there
        // is that much, not before and not again.
        let waits = self.m.load(a.control + PENDING_SEND) & !7;
        let free = a.len - used;
        let told = waits != 0 && free < waits && free + total >= waits;
        Ok(Some((
            Packet {
                kind,
                transaction: u64_at(&d, 8),
                wants_completion: flags & WANTS_COMPLETION != 0,
                payload,
            },
            told,
        )))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::vec;

    /// Plain memory that a test's host shares.
    #[derive(Clone)]
    pub(crate) struct Shared(pub(crate) Rc<RefCell<Vec<u8>>>);

    impl Memory for Shared {
        fn read(&self, o: usize, out: &mut [u8]) {
            out.copy_from_slice(&self.0.borrow()[o..o + out.len()]);
        }
        fn write(&self, o: usize, d: &[u8]) {
            self.0.borrow_mut()[o..o + d.len()].copy_from_slice(d);
        }
        fn load(&self, o: usize) -> u32 {
            u32_at(&self.0.borrow(), o)
        }
        fn store(&self, o: usize, v: u32) {
            self.write(o, &v.to_le_bytes());
        }
        fn fence(&self) {}
    }

    /// A guest's rings, and the host's view of the same memory.
    pub(crate) fn pair(data: usize) -> (Rings<Shared>, Rings<Shared>) {
        let m = Shared(Rc::new(RefCell::new(vec![0; Rings::<Shared>::size(data)])));
        let guest = Rings::new(m.clone(), data).unwrap();
        let host = Rings {
            m,
            send: guest.receive,
            receive: guest.send,
        };
        (guest, host)
    }

    #[test]
    fn packets_cross_the_end_of_the_ring() {
        let (mut guest, mut host) = pair(PAGE);
        for i in 0..500u64 {
            let payload = vec![i as u8; 1 + (i as usize * 37) % 900];
            // The host was asleep with nothing to do: it is to be told.
            assert_eq!(guest.send(&payload, i, true), Ok(true));
            let (p, _) = host.receive().unwrap().unwrap();
            assert_eq!((p.kind, p.transaction), (Kind::InBand, i));
            assert!(p.wants_completion);
            assert_eq!(p.payload[..payload.len()], payload);
            assert_eq!(p.payload.len(), payload.len().next_multiple_of(8));
            // The guest polls: no interrupt.
            assert_eq!(host.complete(i, &[7; 24]), Ok(false));
            let (p, _) = guest.receive().unwrap().unwrap();
            assert_eq!(
                (p.kind, p.transaction, p.payload),
                (Kind::Completion, i, vec![7; 24])
            );
        }
        assert_eq!(guest.receive(), Ok(None));
    }

    #[test]
    fn a_full_ring_waits_and_a_long_packet_never_fits() {
        let (mut guest, mut host) = pair(PAGE);
        let mut sent = 0;
        while guest.send(&[1; 100], sent, false).is_ok() {
            sent += 1;
        }
        // (128 bytes each, and never quite full.)
        assert_eq!(sent, 31);
        assert_eq!(guest.send(&[1; 100], 0, false), Err(SendError::Full));
        assert_eq!(guest.send(&[0; 5000], 0, false), Err(SendError::TooLong));
        for i in 0..sent {
            assert_eq!(host.receive().unwrap().unwrap().0.transaction, i);
        }
        assert_eq!(host.receive(), Ok(None));
    }

    #[test]
    fn a_host_waiting_for_room_is_told_once() {
        let (mut guest, mut host) = pair(PAGE);
        while host.send(&[1; 1000], 1, false).is_ok() {}
        host.m.store(guest.receive.control + PENDING_SEND, 2000);
        let told: Vec<bool> =
            core::iter::from_fn(|| guest.receive().unwrap().map(|(_, t)| t)).collect();
        assert_eq!(told, [true, false, false]);
    }

    #[test]
    fn data_in_guest_memory_is_named_by_page() {
        let (mut guest, host) = pair(PAGE);
        let data = Range {
            len: 5000,
            offset: 512,
            pages: vec![0x1234, 0x1235],
        };
        guest.send_with(&[9; 64], &data, 77).unwrap();
        let mut b = vec![0; 16 + 8 + 8 + 16 + 64 + 8];
        host.receive.read(&host.m, 0, &mut b);
        assert_eq!((u16_at(&b, 0), u16_at(&b, 2), u16_at(&b, 4)), (9, 6, 14));
        assert_eq!((u16_at(&b, 6), u64_at(&b, 8)), (1, 77));
        assert_eq!((u32_at(&b, 16), u32_at(&b, 20)), (0, 1));
        assert_eq!((u32_at(&b, 24), u32_at(&b, 28)), (5000, 512));
        assert_eq!((u64_at(&b, 32), u64_at(&b, 40)), (0x1234, 0x1235));
        assert_eq!(b[48..112], [9; 64]);
    }

    #[test]
    fn transfer_pages_have_parts() {
        let (mut guest, mut host) = pair(PAGE);
        let mut d = Rings::<Shared>::descriptor(TRANSFER_PAGES, 40, 8, WANTS_COMPLETION, 3);
        for v in [0xcafe_u32, 2, 100, 0, 60, 1728] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        host.put(&d, &[5; 8]).unwrap();
        let (p, _) = guest.receive().unwrap().unwrap();
        let parts = vec![(0, 100), (1728, 60)];
        assert_eq!(p.kind, Kind::TransferPages { set: 0xcafe, parts });
        assert_eq!(p.payload, [5; 8]);
        // More parts than there are.
        d[20] = 3;
        host.put(&d, &[5; 8]).unwrap();
        assert_eq!(guest.receive(), Err(Corrupt));
    }

    #[test]
    fn a_host_that_lies_is_caught() {
        let (mut guest, host) = pair(PAGE);
        let word = |w, v| host.m.store(guest.receive.control + w, v);
        word(IN, 4096);
        assert_eq!(guest.receive(), Err(Corrupt));
        let (mut guest, host) = pair(PAGE);
        host.m.store(guest.receive.control + IN, 12);
        assert_eq!(guest.receive(), Err(Corrupt));
        // A packet longer than what is there.
        let (mut guest, mut host) = pair(PAGE);
        host.send(&[1; 8], 1, false).unwrap();
        host.m.write(guest.receive.data + 4, &[200, 0]);
        assert_eq!(guest.receive(), Err(Corrupt));
        // The guest's own ring, with the host's index out of bounds.
        host.m.store(guest.send.control + OUT, 8192);
        assert_eq!(guest.send(&[1], 1, false), Err(SendError::Corrupt));
    }
}
