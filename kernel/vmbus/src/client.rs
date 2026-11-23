//! The connection to the host: its version, the channels it offers, the
//! memory a channel's rings are in (a GPADL), and opening a channel.
//! Messages in, messages out: the caller posts what [`Client`] returns and
//! hands it what the host posts.

use alloc::vec::Vec;

use crate::{Guid, MAX_MESSAGE, u32_at};

const OFFER: u32 = 1;
const REQUEST_OFFERS: u32 = 3;
const ALL_OFFERS: u32 = 4;
const OPEN: u32 = 5;
const OPEN_RESULT: u32 = 6;
const GPADL_HEADER: u32 = 8;
const GPADL_BODY: u32 = 9;
const GPADL_CREATED: u32 = 10;
const INITIATE_CONTACT: u32 = 14;
const VERSION_RESPONSE: u32 = 15;

/// The connection the first message goes to (what later ones go to, the
/// host says).
pub const FIRST_CONNECTION: u32 = 4;
/// The versions to ask for, best first: 5.3, 5.2, 5.1, 5.0.
const VERSIONS: [u32; 4] = [0x5_0003, 0x5_0002, 0x5_0001, 0x5_0000];
/// Page numbers in a GPADL's first message (after the range that counts as
/// one) and in each of the rest.
const IN_HEADER: usize = (MAX_MESSAGE - 20) / 8 - 1;
const IN_BODY: usize = (MAX_MESSAGE - 16) / 8;

/// A message to post: where, and what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Post {
    pub connection: u32,
    pub message: Vec<u8>,
}

/// A channel the host offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    pub interface: Guid,
    pub instance: Guid,
    pub channel: u32,
    /// Signalled when the guest has written to the ring.
    pub connection: u32,
    /// 0 for a device's first channel; later ones come when asked for.
    pub subchannel: u16,
}

/// What became of something the host was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Connected, with this version; the offers come next.
    Connected(u32),
    /// The host speaks none of the versions.
    Refused,
    Offered(Offer),
    AllOffered,
    /// A GPADL was made (or not).
    Gpadl {
        channel: u32,
        gpadl: u32,
        made: bool,
    },
    /// A channel is open (or not).
    Opened {
        channel: u32,
        open: bool,
    },
    /// Something else.
    Other(u32),
}

/// The connection's state.
#[derive(Debug)]
pub struct Client {
    /// Which version was asked for.
    version: usize,
    connection: u32,
    /// The synthetic interrupt the host's messages come by, and the
    /// processor's number.
    sint: u8,
    vp: u32,
    monitors: [u64; 2],
    next_gpadl: u32,
}

fn message(kind: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(MAX_MESSAGE);
    m.extend_from_slice(&kind.to_le_bytes());
    m.extend_from_slice(&[0; 4]);
    m
}

impl Client {
    /// A connection whose messages come to processor `vp` by `sint`;
    /// `monitors` are two zeroed pages' addresses, the host's to use.
    pub fn new(sint: u8, vp: u32, monitors: [u64; 2]) -> Client {
        Client {
            version: 0,
            connection: FIRST_CONNECTION,
            sint,
            vp,
            monitors,
            next_gpadl: 1,
        }
    }

    /// The message that asks for the connection.
    pub fn contact(&self) -> Post {
        let mut m = message(INITIATE_CONTACT);
        m.extend_from_slice(&VERSIONS[self.version].to_le_bytes());
        m.extend_from_slice(&self.vp.to_le_bytes());
        m.extend_from_slice(&u64::from(self.sint).to_le_bytes());
        for page in self.monitors {
            m.extend_from_slice(&page.to_le_bytes());
        }
        Post {
            connection: FIRST_CONNECTION,
            message: m,
        }
    }

    fn post(&self, message: Vec<u8>) -> Post {
        Post {
            connection: self.connection,
            message,
        }
    }

    /// Takes a message of the host's: what it says, and what to post.
    pub fn receive(&mut self, m: &[u8]) -> (Event, Option<Post>) {
        let body = m.get(8..).unwrap_or(&[]);
        let kind = u32_at(m, 0);
        let event = match kind {
            VERSION_RESPONSE if body.len() >= 8 => {
                if body[0] != 0 && body[1] == 0 {
                    self.connection = u32_at(body, 4);
                    let ask = self.post(message(REQUEST_OFFERS));
                    return (Event::Connected(VERSIONS[self.version]), Some(ask));
                }
                if self.version + 1 == VERSIONS.len() {
                    return (Event::Refused, None);
                }
                self.version += 1;
                return (Event::Other(kind), Some(self.contact()));
            }
            OFFER if body.len() >= 188 => Event::Offered(Offer {
                interface: guid(body, 0),
                instance: guid(body, 16),
                subchannel: crate::u16_at(body, 172),
                channel: u32_at(body, 176),
                connection: u32_at(body, 184),
            }),
            ALL_OFFERS => Event::AllOffered,
            GPADL_CREATED if body.len() >= 12 => Event::Gpadl {
                channel: u32_at(body, 0),
                gpadl: u32_at(body, 4),
                made: u32_at(body, 8) == 0,
            },
            OPEN_RESULT if body.len() >= 12 => Event::Opened {
                channel: u32_at(body, 0),
                open: u32_at(body, 8) == 0,
            },
            k => Event::Other(k),
        };
        (event, None)
    }

    /// Has the host know `pages` (page numbers; whole pages of memory) on
    /// `channel`: the GPADL's number, and the messages. `None` if they are
    /// too many (or none).
    pub fn gpadl(&mut self, channel: u32, pages: &[u64]) -> Option<(u32, Vec<Post>)> {
        let bytes = u16::try_from(8 + 8 * pages.len()).ok()?;
        if pages.is_empty() {
            return None;
        }
        let gpadl = self.next_gpadl;
        self.next_gpadl += 1;
        let (first, rest) = pages.split_at(pages.len().min(IN_HEADER));
        let mut m = message(GPADL_HEADER);
        m.extend_from_slice(&channel.to_le_bytes());
        m.extend_from_slice(&gpadl.to_le_bytes());
        m.extend_from_slice(&bytes.to_le_bytes());
        m.extend_from_slice(&1u16.to_le_bytes());
        m.extend_from_slice(&((pages.len() * crate::PAGE) as u32).to_le_bytes());
        m.extend_from_slice(&[0; 4]);
        let numbers = |m: &mut Vec<u8>, pages: &[u64]| {
            pages
                .iter()
                .for_each(|p| m.extend_from_slice(&p.to_le_bytes()));
        };
        numbers(&mut m, first);
        let mut posts = alloc::vec![self.post(m)];
        for (i, part) in rest.chunks(IN_BODY).enumerate() {
            let mut m = message(GPADL_BODY);
            m.extend_from_slice(&(i as u32).to_le_bytes());
            m.extend_from_slice(&gpadl.to_le_bytes());
            numbers(&mut m, part);
            posts.push(self.post(m));
        }
        Some((gpadl, posts))
    }

    /// Opens `channel`, whose rings are in `gpadl`, the host's from page
    /// `downstream`.
    pub fn open(&self, channel: u32, gpadl: u32, downstream: u32) -> Post {
        let mut m = message(OPEN);
        for v in [channel, channel, gpadl, self.vp, downstream] {
            m.extend_from_slice(&v.to_le_bytes());
        }
        m.extend_from_slice(&[0; 120]);
        self.post(m)
    }
}

fn guid(b: &[u8], at: usize) -> Guid {
    let mut g = [0u8; 16];
    if let Some(s) = b.get(at..at + 16) {
        g.copy_from_slice(s);
    }
    Guid(g)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    fn response(supported: u8, connection: u32) -> Vec<u8> {
        let mut m = message(VERSION_RESPONSE);
        m.extend_from_slice(&[supported, 0, 0, 0]);
        m.extend_from_slice(&connection.to_le_bytes());
        m
    }

    #[test]
    fn an_older_host_is_asked_for_an_older_version() {
        let mut c = Client::new(2, 0, [0x1000, 0x2000]);
        let first = c.contact();
        assert_eq!(first.connection, 4);
        assert_eq!(u32_at(&first.message, 8), 0x5_0003);
        assert_eq!(first.message.len(), 40);
        assert_eq!(first.message[16], 2);
        let (_, again) = c.receive(&response(0, 0));
        assert_eq!(u32_at(&again.unwrap().message, 8), 0x5_0002);
        let (e, ask) = c.receive(&response(1, 0x2001));
        assert_eq!(e, Event::Connected(0x5_0002));
        let ask = ask.unwrap();
        assert_eq!((ask.connection, u32_at(&ask.message, 0)), (0x2001, 3));
    }

    #[test]
    fn a_host_that_speaks_none_is_given_up() {
        let mut c = Client::new(2, 0, [0; 2]);
        for _ in 0..3 {
            assert!(c.receive(&response(0, 0)).1.is_some());
        }
        assert_eq!(c.receive(&response(0, 0)), (Event::Refused, None));
    }

    #[test]
    fn offers_are_read() {
        let mut m = message(OFFER);
        m.extend_from_slice(&crate::SCSI.0);
        m.extend_from_slice(&crate::NET.0);
        m.extend_from_slice(&[0; 140]);
        m.extend_from_slice(&[1, 0, 0, 0]);
        m.extend_from_slice(&14u32.to_le_bytes());
        m.extend_from_slice(&[0; 4]);
        m.extend_from_slice(&0x2000eu32.to_le_bytes());
        assert_eq!(m.len(), 196);
        let mut c = Client::new(2, 0, [0; 2]);
        let offer = Offer {
            interface: crate::SCSI,
            instance: crate::NET,
            channel: 14,
            connection: 0x2000e,
            subchannel: 1,
        };
        assert_eq!(c.receive(&m), (Event::Offered(offer), None));
        // One cut short is not one.
        assert_eq!(c.receive(&m[..195]), (Event::Other(OFFER), None));
        assert_eq!(c.receive(&[]), (Event::Other(0), None));
    }

    #[test]
    fn a_large_gpadl_takes_several_messages() {
        let mut c = Client::new(2, 0, [0; 2]);
        let pages: Vec<u64> = (0..100).map(|i| 0x10_0000 + i).collect();
        let (id, posts) = c.gpadl(14, &pages).unwrap();
        assert_eq!(id, 1);
        // 26, then 28 each.
        assert_eq!(posts.len(), 1 + 3);
        assert!(posts.iter().all(|p| p.message.len() <= MAX_MESSAGE));
        let h = &posts[0].message;
        assert_eq!((u32_at(h, 8), u32_at(h, 12)), (14, 1));
        assert_eq!((crate::u16_at(h, 16), crate::u16_at(h, 18)), (808, 1));
        assert_eq!((u32_at(h, 20), u32_at(h, 24)), (100 * 4096, 0));
        let mut seen: Vec<u64> = vec![];
        seen.extend(h[28..].chunks(8).map(|c| crate::u64_at(c, 0)));
        for (i, p) in posts[1..].iter().enumerate() {
            assert_eq!(u32_at(&p.message, 8), i as u32);
            assert_eq!(u32_at(&p.message, 12), 1);
            seen.extend(p.message[16..].chunks(8).map(|c| crate::u64_at(c, 0)));
        }
        assert_eq!(seen, pages);
        assert!(c.gpadl(14, &[]).is_none());
        assert!(c.gpadl(14, &vec![0; 8192]).is_none());
    }

    #[test]
    fn results_are_read() {
        let mut c = Client::new(2, 0, [0; 2]);
        let open = c.open(14, 1, 17);
        assert_eq!(open.message.len(), 8 + 20 + 120);
        let mut m = message(OPEN_RESULT);
        m.extend_from_slice(&[14, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0]);
        let opened = Event::Opened {
            channel: 14,
            open: true,
        };
        assert_eq!(c.receive(&m).0, opened);
        let mut m = message(GPADL_CREATED);
        m.extend_from_slice(&[14, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0xc0]);
        let refused = Event::Gpadl {
            channel: 14,
            gpadl: 1,
            made: false,
        };
        assert_eq!(c.receive(&m).0, refused);
    }
}
