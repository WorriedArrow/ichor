//! The network: frames go out in the sections of a send buffer and come in
//! in the parts of a receive buffer, both shared with the host once.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::dma::DmaBuf;
use vmbus::NET;
use vmbus::netvsc::{self, FRAME_HEADER, Received};
use vmbus::ring::{Kind, Packet, SendError};

use crate::{Bus, Channel, Error, TIMEOUT};

/// Bytes of each ring, of the receive buffer and of the send buffer.
const RING: usize = 128 * 1024;
const RECEIVE: usize = 2 << 20;
const SEND: usize = 1 << 20;
/// The largest frame: a 1500-byte MTU plus the Ethernet header.
const MAX_FRAME: usize = 1514;
/// Sections used at most.
const SECTIONS: usize = 128;
/// The number of section 0's packet (others have numbers below).
const SECTION_IDS: u64 = 1 << 32;

/// A network device.
#[derive(Debug)]
pub struct HypervNet {
    channel: Channel,
    receive: DmaBuf,
    send: DmaBuf,
    section: usize,
    /// Sections the host has.
    busy: Vec<bool>,
    frames: VecDeque<Vec<u8>>,
    /// Answers to commands: which, and what was asked for.
    answers: Vec<(u32, Option<Vec<u8>>)>,
    mac: [u8; 6],
    /// The ring broke its rules, or the host stopped taking part.
    dead: bool,
}

impl Bus {
    /// Every network device.
    pub fn networks(self: &Arc<Bus>) -> Vec<Result<HypervNet, Error>> {
        let offers = self.offers(NET);
        offers
            .into_iter()
            .map(|o| HypervNet::new(self.open(o, RING)?))
            .collect()
    }
}

impl HypervNet {
    fn new(channel: Channel) -> Result<HypervNet, Error> {
        let buffer = |n| DmaBuf::alloc(n).ok_or(Error::NoMemory);
        let mut net = HypervNet {
            channel,
            receive: buffer(RECEIVE)?,
            send: buffer(SEND)?,
            section: 0,
            busy: Vec::new(),
            frames: VecDeque::new(),
            answers: Vec::new(),
            mac: [0; 6],
            dead: false,
        };
        let version = netvsc::VERSIONS.into_iter().find_map(|v| {
            let a = net.ask(&netvsc::init(v)).ok()?;
            netvsc::init_answer(&a).then_some(v)
        });
        let version = version.ok_or(Error::Refused)?;
        net.tell(&netvsc::config(MAX_FRAME as u32))?;
        net.tell(&netvsc::ndis_version(version))?;
        let (bus, id) = (net.channel.bus.clone(), net.channel.offer.channel);
        // What the host is told of, it may write from here on.
        core::mem::forget((net.receive.clone(), net.send.clone()));
        let gpadl = bus.share(id, &net.receive)?;
        let a = net.ask(&netvsc::give_receive_buffer(gpadl))?;
        if !netvsc::receive_buffer_answer(&a) {
            return Err(Error::Failed("the receive buffer"));
        }
        let gpadl = bus.share(id, &net.send)?;
        let a = net.ask(&netvsc::give_send_buffer(gpadl))?;
        let section = netvsc::send_buffer_answer(&a).ok_or(Error::Failed("the send buffer"))?;
        net.section = section as usize;
        net.busy = alloc::vec![false; (SEND / net.section).min(SECTIONS)];
        net.command(1, &netvsc::initialize(1))?;
        let mac = net.command(2, &netvsc::query(2, netvsc::PERMANENT_ADDRESS, 6))?;
        net.mac = mac
            .get(..6)
            .and_then(|m| m.try_into().ok())
            .ok_or(Error::Failed("the network's address"))?;
        let filter = netvsc::FILTER.to_le_bytes();
        net.command(3, &netvsc::set(3, netvsc::PACKET_FILTER, &filter))?;
        Ok(net)
    }

    /// Says something that is not answered.
    fn tell(&mut self, message: &[u8]) -> Result<(), Error> {
        let id = self.channel.id();
        self.channel.send(message, None, id, false)
    }

    /// Says something, and waits for its answer.
    fn ask(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let id = self.channel.id();
        self.channel.send(message, None, id, true)?;
        let deadline = frame::time::now() + TIMEOUT;
        while frame::time::now() < deadline {
            match self.channel.receive()? {
                Some(p) if p.kind == Kind::Completion && p.transaction == id => {
                    return Ok(p.payload);
                }
                Some(p) => self.take(p)?,
                None => frame::task::yield_now(),
            }
        }
        Err(Error::Silent)
    }

    /// Runs an RNDIS command; what it answers.
    fn command(&mut self, request: u32, message: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.put(true, &[message])? {
            return Err(Error::Failed("no section to send a command in"));
        }
        let deadline = frame::time::now() + TIMEOUT;
        while frame::time::now() < deadline {
            if let Some(i) = self.answers.iter().position(|(r, _)| *r == request) {
                let (_, value) = self.answers.swap_remove(i);
                return value.ok_or(Error::Failed("a network command"));
            }
            if !self.pump()? {
                frame::task::yield_now();
            }
        }
        Err(Error::Silent)
    }

    /// Sends what `parts` make up in a section; false if none is free.
    fn put(&mut self, control: bool, parts: &[&[u8]]) -> Result<bool, Error> {
        let Some(free) = self.busy.iter().position(|b| !b) else {
            return Ok(false);
        };
        let len: usize = parts.iter().map(|p| p.len()).sum();
        if len > self.section {
            return Ok(false);
        }
        let mut at = free * self.section;
        for p in parts {
            self.send.write(at, p);
            at += p.len();
        }
        let m = netvsc::in_section(control, free as u32, len as u32);
        match self.channel.rings.send(&m, SECTION_IDS + free as u64, true) {
            Ok(tell) => {
                if tell {
                    self.channel.signal();
                }
                self.busy[free] = true;
                Ok(true)
            }
            Err(SendError::Full) => Ok(false),
            Err(_) => Err(Error::Corrupt),
        }
    }

    /// Takes one packet of the host's; whether there was one.
    fn pump(&mut self) -> Result<bool, Error> {
        let Some(p) = self.channel.receive()? else {
            return Ok(false);
        };
        self.take(p)?;
        Ok(true)
    }

    fn take(&mut self, p: Packet) -> Result<(), Error> {
        match p.kind {
            // The host is done with a section.
            Kind::Completion => {
                let section = p.transaction.checked_sub(SECTION_IDS);
                let section = section.and_then(|s| usize::try_from(s).ok());
                if let Some(b) = section.and_then(|s| self.busy.get_mut(s)) {
                    *b = false;
                }
            }
            Kind::TransferPages { set, parts } => {
                if set == netvsc::RECEIVE_BUFFER && netvsc::brings_rndis(&p.payload) {
                    for (offset, len) in parts {
                        self.message(offset as usize, len as usize);
                    }
                }
                // The parts are the host's again.
                loop {
                    match self.channel.rings.complete(p.transaction, &netvsc::taken()) {
                        Ok(tell) => {
                            if tell {
                                self.channel.signal();
                            }
                            break;
                        }
                        Err(SendError::Full) => frame::task::yield_now(),
                        Err(_) => return Err(Error::Corrupt),
                    }
                }
            }
            // (Other news: of accelerated networking, which is not used.)
            Kind::InBand => {}
        }
        Ok(())
    }

    /// Takes the RNDIS message in a part of the receive buffer.
    fn message(&mut self, offset: usize, len: usize) {
        let fits = offset.checked_add(len).is_some_and(|e| e <= RECEIVE);
        if !fits || len > 2 * MAX_FRAME + 1024 {
            return;
        }
        let mut m = alloc::vec![0u8; len];
        self.receive.read(offset, &mut m);
        match netvsc::received(&m) {
            Some(Received::Frame(f)) => self.frames.push_back(f.to_vec()),
            Some(Received::Answer { request, value }) if self.answers.len() < 16 => {
                self.answers.push((request, value.map(<[u8]>::to_vec)));
            }
            _ => {}
        }
    }

    /// What went wrong is the end of the device.
    fn alive<T: Default>(&mut self, r: Result<T, Error>) -> T {
        r.unwrap_or_else(|e| {
            if !self.dead {
                frame::println!("ichor: hyper-v: the network failed: {e:?}");
            }
            self.dead = true;
            T::default()
        })
    }
}

impl net::link::Link for HypervNet {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> bool {
        if self.dead || frame.is_empty() || frame.len() > MAX_FRAME {
            return false;
        }
        let header: [u8; FRAME_HEADER] = netvsc::frame_header(frame.len() as u32);
        let sent = self.put(false, &[&header, frame]);
        if self.alive(sent) {
            return true;
        }
        // Sections come back with what else the host sent.
        for _ in 0..64 {
            let more = self.pump();
            if !self.alive(more) {
                break;
            }
        }
        let sent = self.put(false, &[&header, frame]);
        self.alive(sent)
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        while !self.dead && self.frames.is_empty() {
            let more = self.pump();
            if !self.alive(more) {
                break;
            }
        }
        self.frames.pop_front()
    }

    fn name(&self) -> &str {
        "hyper-v"
    }
}
