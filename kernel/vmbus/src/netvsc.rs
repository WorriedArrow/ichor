//! The network channel: NVSP messages, which set it up and say where the
//! RNDIS ones are (in the receive buffer, whose parts the host fills, and
//! the send buffer, whose sections the guest does), and the RNDIS messages:
//! commands, and frames.

use alloc::vec::Vec;

use crate::u32_at;

/// An NVSP message's length.
pub const MESSAGE: usize = 28;
/// NVSP versions, best first: 5.0, 4.0, 3.2.
pub const VERSIONS: [u32; 3] = [0x5_0000, 0x4_0000, 0x3_0002];
/// The receive buffer's number.
pub const RECEIVE_BUFFER: u16 = 0xcafe;
/// What goes before a frame.
pub const FRAME_HEADER: usize = 44;

const INIT: u32 = 1;
const INIT_COMPLETE: u32 = 2;
const NDIS_VERSION: u32 = 100;
const GIVE_RECEIVE_BUFFER: u32 = 101;
const RECEIVE_BUFFER_COMPLETE: u32 = 102;
const GIVE_SEND_BUFFER: u32 = 104;
const SEND_BUFFER_COMPLETE: u32 = 105;
const RNDIS: u32 = 107;
const RNDIS_COMPLETE: u32 = 108;
const NDIS_CONFIG: u32 = 125;
const SUCCESS: u32 = 1;

const PACKET: u32 = 1;
const INITIALIZE: u32 = 2;
const QUERY: u32 = 4;
const SET: u32 = 5;
const COMPLETED: u32 = 0x8000_0000;

/// The address a NIC was made with, and which frames it takes.
pub const PERMANENT_ADDRESS: u32 = 0x0101_0101;
pub const PACKET_FILTER: u32 = 0x0001_010e;
/// Frames to it, to everyone, and multicast.
pub const FILTER: u32 = 0x1 | 0x8 | 0x4;

type Message = [u8; MESSAGE];

fn nvsp(kind: u32, words: &[u32]) -> Message {
    let mut m = [0u8; MESSAGE];
    let all = core::iter::once(&kind).chain(words);
    for (at, v) in m.as_chunks_mut().0.iter_mut().zip(all) {
        *at = v.to_le_bytes();
    }
    m
}

/// Asks for a version of the protocol; answered.
pub fn init(version: u32) -> Message {
    nvsp(INIT, &[version, version])
}

/// Whether the host speaks the version asked for.
pub fn init_answer(a: &[u8]) -> bool {
    u32_at(a, 0) == INIT_COMPLETE && u32_at(a, 12) == SUCCESS
}

/// The frames' largest size (with the Ethernet header). Not answered.
pub fn config(frame: u32) -> Message {
    nvsp(NDIS_CONFIG, &[frame])
}

/// What a network driver for `version` is (NDIS 6.30, or 6.1). Not
/// answered.
pub fn ndis_version(version: u32) -> Message {
    let minor = if version >= VERSIONS[0] { 30 } else { 1 };
    nvsp(NDIS_VERSION, &[6, minor])
}

/// Gives the host the receive buffer; answered.
pub fn give_receive_buffer(gpadl: u32) -> Message {
    nvsp(GIVE_RECEIVE_BUFFER, &[gpadl, u32::from(RECEIVE_BUFFER)])
}

/// Whether the host took the receive buffer.
pub fn receive_buffer_answer(a: &[u8]) -> bool {
    u32_at(a, 0) == RECEIVE_BUFFER_COMPLETE && u32_at(a, 4) == SUCCESS
}

/// Gives the host the send buffer; answered.
pub fn give_send_buffer(gpadl: u32) -> Message {
    nvsp(GIVE_SEND_BUFFER, &[gpadl, 0])
}

/// How large the host makes the send buffer's sections.
pub fn send_buffer_answer(a: &[u8]) -> Option<u32> {
    let ok = u32_at(a, 0) == SEND_BUFFER_COMPLETE && u32_at(a, 4) == SUCCESS;
    Some(u32_at(a, 8)).filter(|&s| ok && s >= 2048)
}

/// Says that `len` bytes of RNDIS are in the send buffer's `section`: a
/// command (`control`) or a frame. Answered, once the host has them.
pub fn in_section(control: bool, section: u32, len: u32) -> Message {
    nvsp(RNDIS, &[u32::from(control), section, len])
}

/// Whether a packet of the host's brings RNDIS messages.
pub fn brings_rndis(payload: &[u8]) -> bool {
    u32_at(payload, 0) == RNDIS
}

/// The answer to one that did.
pub fn taken() -> [u8; 8] {
    let mut m = [0u8; 8];
    m[..4].copy_from_slice(&RNDIS_COMPLETE.to_le_bytes());
    m[4..].copy_from_slice(&SUCCESS.to_le_bytes());
    m
}

fn rndis(kind: u32, words: &[u32], more: &[u8]) -> Vec<u8> {
    let len = 8 + 4 * words.len() + more.len();
    let mut m = Vec::with_capacity(len);
    for v in [kind, len as u32].iter().chain(words) {
        m.extend_from_slice(&v.to_le_bytes());
    }
    m.extend_from_slice(more);
    m
}

/// The command that starts RNDIS.
pub fn initialize(request: u32) -> Vec<u8> {
    rndis(INITIALIZE, &[request, 1, 0, 0x4000], &[])
}

/// The command that asks for `oid`.
pub fn query(request: u32, oid: u32, room: u32) -> Vec<u8> {
    let buffer = alloc::vec![0u8; room as usize];
    rndis(QUERY, &[request, oid, room, 20, 0], &buffer)
}

/// The command that sets `oid`.
pub fn set(request: u32, oid: u32, value: &[u8]) -> Vec<u8> {
    rndis(SET, &[request, oid, value.len() as u32, 20, 0], value)
}

/// What precedes a frame of `len` bytes.
pub fn frame_header(len: u32) -> [u8; FRAME_HEADER] {
    let mut h = [0u8; FRAME_HEADER];
    let words = [PACKET, FRAME_HEADER as u32 + len, 36, len];
    for (at, v) in h.as_chunks_mut().0.iter_mut().zip(words) {
        *at = v.to_le_bytes();
    }
    h
}

/// An RNDIS message of the host's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received<'a> {
    Frame(&'a [u8]),
    /// The answer to command `request`: what was asked for, if it went well.
    Answer {
        request: u32,
        value: Option<&'a [u8]>,
    },
    Other(u32),
}

/// The part of `m` a length and an offset (from its first field) name.
fn part(m: &[u8], len: usize, offset: usize) -> Option<&[u8]> {
    let start = 8usize.checked_add(offset)?;
    m.get(start..start.checked_add(len)?)
}

/// Reads an RNDIS message; `None` if it is not whole.
pub fn received(m: &[u8]) -> Option<Received<'_>> {
    let (kind, len) = (u32_at(m, 0), u32_at(m, 4) as usize);
    let m = m.get(..len).filter(|m| m.len() >= 12)?;
    let word = |i: usize| u32_at(m, 8 + 4 * i) as usize;
    Some(match kind {
        PACKET => Received::Frame(part(m, word(1), word(0))?),
        k if k == QUERY | COMPLETED => Received::Answer {
            request: word(0) as u32,
            value: match word(1) {
                0 => Some(part(m, word(2), word(3))?),
                _ => None,
            },
        },
        k if k == INITIALIZE | COMPLETED || k == SET | COMPLETED => Received::Answer {
            request: word(0) as u32,
            value: (m.len() >= 16 && word(1) == 0).then_some(&[]),
        },
        k => Received::Other(k),
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn set_up_messages() {
        let m = init(VERSIONS[0]);
        assert_eq!(
            (u32_at(&m, 0), u32_at(&m, 4), u32_at(&m, 8)),
            (1, 0x50000, 0x50000)
        );
        assert!(init_answer(&nvsp(2, &[0, 0, 1])));
        assert!(!init_answer(&nvsp(2, &[0, 0, 2])));
        assert!(!init_answer(&[]));
        assert_eq!(u32_at(&give_receive_buffer(7), 8), 0xcafe);
        assert!(receive_buffer_answer(&nvsp(102, &[1, 1])));
        assert_eq!(send_buffer_answer(&nvsp(105, &[1, 6144])), Some(6144));
        assert_eq!(send_buffer_answer(&nvsp(105, &[1, 12])), None);
        assert_eq!(send_buffer_answer(&nvsp(105, &[2, 6144])), None);
        let m = in_section(true, 3, 24);
        assert_eq!(m[..16], [107, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 24, 0, 0, 0]);
        assert!(brings_rndis(&m));
        assert_eq!(taken(), [108, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn commands_and_answers() {
        assert_eq!(initialize(1).len(), 24);
        let q = query(2, PERMANENT_ADDRESS, 6);
        assert_eq!((u32_at(&q, 4), u32_at(&q, 16), u32_at(&q, 20)), (34, 6, 20));
        let s = set(3, PACKET_FILTER, &FILTER.to_le_bytes());
        assert_eq!(s[28..], [13, 0, 0, 0]);
        let mac = [0, 0x15, 0x5d, 1, 2, 3];
        let answer = |request, value| Some(Received::Answer { request, value });
        let a = rndis(QUERY | COMPLETED, &[2, 0, 6, 16], &mac);
        assert_eq!(received(&a), answer(2, Some(&mac[..])));
        let a = rndis(QUERY | COMPLETED, &[2, 0xc00000bb, 0, 0], &[]);
        assert_eq!(received(&a), answer(2, None));
        // Longer than it is.
        let a = rndis(QUERY | COMPLETED, &[2, 0, 7, 16], &mac);
        assert_eq!(received(&a), None);
        assert_eq!(
            received(&rndis(SET | COMPLETED, &[3, 0], &[])),
            answer(3, Some(&[]))
        );
        assert_eq!(
            received(&rndis(SET | COMPLETED, &[3, 1], &[])),
            answer(3, None)
        );
        assert_eq!(
            received(&rndis(7, &[0x4001000b, 0, 0], &[])),
            Some(Received::Other(7))
        );
    }

    #[test]
    fn frames() {
        let frame = vec![0xab; 60];
        let mut m = frame_header(60).to_vec();
        m.extend_from_slice(&frame);
        // (The part may be longer than the message.)
        m.extend_from_slice(&[0; 16]);
        assert_eq!(received(&m), Some(Received::Frame(&frame)));
        assert_eq!(received(&m[..100]), None);
        // Data that would be outside the message.
        m[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(received(&m), None);
        assert_eq!(received(&[]), None);
        assert_eq!(received(&[1, 0, 0, 0, 8, 0, 0, 0]), None);
    }
}
