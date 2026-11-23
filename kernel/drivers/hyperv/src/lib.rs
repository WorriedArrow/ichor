//! A Hyper-V guest's devices, which are channels of VMBus (ADR-0016): the
//! disks of its SCSI controllers, and its network. Azure's machines have
//! these. Polled, and one channel each.
//!
//! Safe code, but DMA-trusted (ADR-0005): the host is told which pages a
//! channel's rings and a request's data are. Page numbers come from
//! `DmaBuf`s alone, and what the host may still write is never freed.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod disk;
mod link;

pub use disk::ScsiDisk;
pub use link::HypervNet;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};
use core::time::Duration;

use frame::dma::DmaBuf;
use frame::hyperv::{Hyperv, SINT};
use frame::sync::Mutex;
use vmbus::client::{Client, Event, Offer, Post};
use vmbus::ring::{Memory, Packet, Range, Rings, SendError};
use vmbus::{Guid, PAGE};

/// How long the host may take to answer.
const TIMEOUT: Duration = Duration::from_secs(10);
/// How long one request of a device may (a busy host, or a cloud disk).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a device could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The host speaks none of the versions.
    Refused,
    /// The host did not answer.
    Silent,
    /// It answered that it would not.
    Failed(&'static str),
    NoMemory,
    /// A ring broke its rules.
    Corrupt,
}

/// The connection to the host.
#[derive(Debug)]
pub struct Bus {
    hv: Hyperv,
    client: Mutex<Client>,
    offers: Mutex<Vec<Offer>>,
    _monitors: [DmaBuf; 2],
}

/// Connects to the host and learns what it offers; `None` on other
/// machines.
pub fn connect() -> Option<Result<Arc<Bus>, Error>> {
    Some(Bus::new(frame::hyperv::connect()?))
}

impl Bus {
    fn new(hv: Hyperv) -> Result<Arc<Bus>, Error> {
        let page = || DmaBuf::alloc(PAGE).ok_or(Error::NoMemory);
        let monitors = [page()?, page()?];
        let at = [address(&monitors[0]), address(&monitors[1])];
        let client = Client::new(SINT, hv.vp(), at);
        let contact = client.contact();
        let bus = Bus {
            hv,
            client: Mutex::new(client),
            offers: Mutex::new(Vec::new()),
            _monitors: monitors,
        };
        bus.post(&contact)?;
        let version = bus.wait(|e| match e {
            Event::Connected(v) => Some(Ok(v)),
            Event::Refused => Some(Err(Error::Refused)),
            _ => None,
        })??;
        bus.wait(|e| (e == Event::AllOffered).then_some(()))?;
        frame::println!(
            "ichor: vmbus: version {}.{}, {} channels offered",
            version >> 16,
            version & 0xffff,
            bus.offers.lock().len()
        );
        Ok(Arc::new(bus))
    }

    fn post(&self, p: &Post) -> Result<(), Error> {
        let deadline = frame::time::now() + TIMEOUT;
        loop {
            match self.hv.post(p.connection, &p.message) {
                Ok(()) => return Ok(()),
                // The host has no room for it yet.
                Err(_) if frame::time::now() < deadline => frame::task::yield_now(),
                Err(_) => return Err(Error::Failed("a message was not taken")),
            }
        }
    }

    /// Takes the host's messages until one is what `want` wants.
    fn wait<T>(&self, mut want: impl FnMut(Event) -> Option<T>) -> Result<T, Error> {
        let deadline = frame::time::now() + TIMEOUT;
        while frame::time::now() < deadline {
            let Some(m) = self.hv.message() else {
                frame::task::yield_now();
                continue;
            };
            let (event, post) = self.client.lock().receive(&m);
            if let Event::Offered(o) = event {
                self.offers.lock().push(o);
            }
            if let Some(p) = post {
                self.post(&p)?;
            }
            if let Some(t) = want(event) {
                return Ok(t);
            }
        }
        Err(Error::Silent)
    }

    /// The first channels of the devices of one kind.
    fn offers(&self, interface: Guid) -> Vec<Offer> {
        let all = self.offers.lock();
        let of = |o: &&Offer| o.interface == interface && o.subchannel == 0;
        all.iter().filter(of).copied().collect()
    }

    /// Has the host know `buf` on a channel; the GPADL's number.
    fn share(&self, channel: u32, buf: &DmaBuf) -> Result<u32, Error> {
        let made = self.client.lock().gpadl(channel, &pages(buf, buf.len()));
        let (id, posts) = made.ok_or(Error::NoMemory)?;
        for p in &posts {
            self.post(p)?;
        }
        let made = self.wait(|e| match e {
            Event::Gpadl { gpadl, made, .. } if gpadl == id => Some(made),
            _ => None,
        })?;
        if made {
            Ok(id)
        } else {
            Err(Error::Failed("memory was not shared"))
        }
    }

    /// Opens a channel with rings of `data` bytes each.
    fn open(self: &Arc<Bus>, offer: Offer, data: usize) -> Result<Channel, Error> {
        let size = Rings::<Ring>::size(data);
        let buf = DmaBuf::alloc(size).ok_or(Error::NoMemory)?;
        let made = self.client.lock().gpadl(offer.channel, &pages(&buf, size));
        let (id, posts) = made.ok_or(Error::NoMemory)?;
        // The host has it from here on.
        let rings = Rings::new(Ring(buf.clone()), data).ok_or(Error::NoMemory)?;
        core::mem::forget(buf);
        for p in &posts {
            self.post(p)?;
        }
        let made = self.wait(|e| match e {
            Event::Gpadl { gpadl, made, .. } if gpadl == id => Some(made),
            _ => None,
        })?;
        if !made {
            return Err(Error::Failed("the rings were not shared"));
        }
        let downstream = Rings::<Ring>::downstream_page(data);
        let open = self.client.lock().open(offer.channel, id, downstream);
        self.post(&open)?;
        let opened = self.wait(|e| match e {
            Event::Opened { channel, open } if channel == offer.channel => Some(open),
            _ => None,
        })?;
        if !opened {
            return Err(Error::Failed("the channel did not open"));
        }
        Ok(Channel {
            bus: self.clone(),
            offer,
            rings,
            next: 1,
        })
    }
}

/// The address of a buffer's first byte.
fn address(b: &DmaBuf) -> u64 {
    b.dma_addr(0).map_or(0, |a| a.as_u64())
}

/// The page numbers of a buffer's first `len` bytes.
fn pages(b: &DmaBuf, len: usize) -> Vec<u64> {
    (0..len.div_ceil(PAGE))
        .filter_map(|i| b.dma_addr(i * PAGE))
        .map(|a| a.as_u64() / PAGE as u64)
        .collect()
}

/// A channel's rings' memory.
#[derive(Debug)]
struct Ring(DmaBuf);

impl Memory for Ring {
    fn read(&self, offset: usize, out: &mut [u8]) {
        self.0.read(offset, out);
    }
    fn write(&self, offset: usize, data: &[u8]) {
        self.0.write(offset, data);
    }
    fn load(&self, offset: usize) -> u32 {
        self.0.read_u32(offset)
    }
    fn store(&self, offset: usize, value: u32) {
        self.0.write_u32(offset, value);
    }
    fn fence(&self) {
        fence(Ordering::SeqCst);
    }
}

/// An open channel.
#[derive(Debug)]
struct Channel {
    bus: Arc<Bus>,
    offer: Offer,
    rings: Rings<Ring>,
    next: u64,
}

impl Channel {
    fn signal(&self) {
        self.bus.hv.signal(self.offer.connection);
    }

    /// A number for a packet, of the channel's own.
    fn id(&mut self) -> u64 {
        self.next += 1;
        self.next
    }

    /// Sends a packet (with its data's pages), waiting for room.
    fn send(
        &mut self,
        payload: &[u8],
        data: Option<&Range>,
        id: u64,
        answered: bool,
    ) -> Result<(), Error> {
        let deadline = frame::time::now() + TIMEOUT;
        loop {
            let sent = match data {
                Some(d) => self.rings.send_with(payload, d, id),
                None => self.rings.send(payload, id, answered),
            };
            match sent {
                Ok(tell) => {
                    if tell {
                        self.signal();
                    }
                    return Ok(());
                }
                Err(SendError::Full) if frame::time::now() < deadline => {
                    frame::task::yield_now();
                }
                Err(SendError::Full) => return Err(Error::Silent),
                Err(SendError::TooLong | SendError::Corrupt) => return Err(Error::Corrupt),
            }
        }
    }

    /// The next packet of the host's, if there is one.
    fn receive(&mut self) -> Result<Option<Packet>, Error> {
        let Some((p, tell)) = self.rings.receive().map_err(|_| Error::Corrupt)? else {
            return Ok(None);
        };
        if tell {
            self.signal();
        }
        Ok(Some(p))
    }
}
