//! virtio-net over the modern PCI transport, polled (ADR-0010 §5).
//!
//! Negotiates only `VIRTIO_NET_F_MAC`: no checksum or segmentation
//! offloads and no mergeable receive buffers, so every frame on either
//! queue is preceded by the fixed 12-byte `virtio_net_hdr` (all zero on
//! transmit). Queue 0 receives: [`RX_BUFFERS`] device-writable buffers stay
//! posted and each is reposted once its frame is taken. Queue 1 transmits:
//! each frame gets its own buffer, which the queue holds until the device
//! reports it used.
//!
//! Safe code only (see `virtio-pci`).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use frame::dma::DmaBuf;
use frame::virtio::{Segment, VirtQueue};
use virtio_pci::{Notifier, Transport};

pub use virtio_pci::InitError;

const DEVICE_NET_MODERN: u16 = 0x1041;
const DEVICE_NET_TRANSITIONAL: u16 = 0x1000;
const F_MAC: u32 = 1 << 5;
/// `virtio_net_hdr` with VIRTIO_F_VERSION_1 (num_buffers included).
const HEADER: usize = 12;
/// The largest frame: a 1500-byte MTU plus the Ethernet header.
pub const MAX_FRAME: usize = 1514;
/// Receive buffers kept posted (a polled driver must hold what arrives
/// between two polls).
pub const RX_BUFFERS: u16 = 256;
/// Tell the device of reposted buffers at least this often.
const RX_NOTIFY: u16 = 32;
const TX_QUEUE: u16 = 256;

/// A virtio-net device.
#[derive(Debug)]
pub struct VirtioNet {
    transport: Transport,
    rx: VirtQueue,
    rx_notify: Notifier,
    tx: VirtQueue,
    tx_notify: Notifier,
    mac: [u8; 6],
    /// Posted receive buffers by token.
    rx_bufs: BTreeMap<u16, DmaBuf>,
    /// Buffers reposted that the device has not been told of (telling it
    /// costs a VM exit).
    rx_untold: u16,
    /// Frames dropped because the transmit queue was full.
    pub tx_dropped: u64,
}

/// Every virtio-net device, initialized.
pub fn probe_all() -> Vec<Result<VirtioNet, InitError>> {
    virtio_pci::find(&[DEVICE_NET_MODERN, DEVICE_NET_TRANSITIONAL])
        .iter()
        .map(VirtioNet::init)
        .collect()
}

impl VirtioNet {
    fn init(dev: &frame::bus::pci::PciDevice) -> Result<VirtioNet, InitError> {
        let (transport, features) = Transport::new(dev, F_MAC)?;
        let (rx, rx_notify) = transport.queue(0, RX_BUFFERS)?;
        let (tx, tx_notify) = transport.queue(1, TX_QUEUE)?;
        // The MAC is the first six bytes of the device configuration; with
        // no MAC feature, make up a locally administered one.
        let mac = if features & F_MAC != 0 {
            let lo = transport.device_r32(0).to_le_bytes();
            let hi = transport.device_r32(4).to_le_bytes();
            [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]]
        } else {
            [0x02, 0x49, 0x43, 0x48, 0x4f, 0x52]
        };
        let mut net = VirtioNet {
            transport,
            rx,
            rx_notify,
            tx,
            tx_notify,
            mac,
            rx_bufs: BTreeMap::new(),
            rx_untold: 0,
            tx_dropped: 0,
        };
        for _ in 0..net.rx.size() {
            if !net.post_rx(None) {
                break;
            }
        }
        net.transport.driver_ok();
        net.transport.notify(net.rx_notify, 0);
        Ok(net)
    }

    /// The device's MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Posts a receive buffer (a fresh one, or `reuse`).
    fn post_rx(&mut self, reuse: Option<DmaBuf>) -> bool {
        let Some(buf) = reuse.or_else(|| DmaBuf::alloc(HEADER + MAX_FRAME)) else {
            return false;
        };
        let seg = [Segment {
            buf: &buf,
            offset: 0,
            len: HEADER + MAX_FRAME,
            device_writes: true,
        }];
        match self.rx.submit(&seg) {
            Ok(token) => {
                self.rx_bufs.insert(token, buf);
                true
            }
            Err(_) => false,
        }
    }

    /// Tells the device of reposted buffers, if there are `enough`.
    fn tell_rx(&mut self, enough: u16) {
        if self.rx_untold >= enough {
            self.transport.notify(self.rx_notify, 0);
            self.rx_untold = 0;
        }
    }

    /// The next received frame, if any.
    pub fn receive(&mut self) -> Option<Vec<u8>> {
        let Some((token, len)) = self.rx.poll() else {
            self.tell_rx(1);
            return None;
        };
        let buf = self.rx_bufs.remove(&token)?;
        let len = (len as usize).min(HEADER + MAX_FRAME);
        let frame = if len > HEADER {
            let mut f = alloc::vec![0u8; len - HEADER];
            buf.read(HEADER, &mut f);
            Some(f)
        } else {
            None
        };
        if self.post_rx(Some(buf)) {
            self.rx_untold += 1;
        }
        self.tell_rx(RX_NOTIFY);
        // A runt (header only) is skipped; try the next one.
        frame.or_else(|| self.receive())
    }

    /// Queues a frame for transmission. Returns false if it was dropped
    /// (too long, or the transmit queue is full).
    pub fn transmit(&mut self, frame: &[u8]) -> bool {
        // Reclaim finished transmissions first.
        while self.tx.poll().is_some() {}
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return false;
        }
        let Some(buf) = DmaBuf::alloc(HEADER + frame.len()) else {
            self.tx_dropped += 1;
            return false;
        };
        buf.write(HEADER, frame);
        let seg = [Segment {
            buf: &buf,
            offset: 0,
            len: HEADER + frame.len(),
            device_writes: false,
        }];
        if self.tx.submit(&seg).is_err() {
            self.tx_dropped += 1;
            return false;
        }
        self.transport.notify(self.tx_notify, 1);
        true
    }
}

impl net::link::Link for VirtioNet {
    fn mac(&self) -> [u8; 6] {
        VirtioNet::mac(self)
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        VirtioNet::transmit(self, frame)
    }
    fn receive(&mut self) -> Option<Vec<u8>> {
        VirtioNet::receive(self)
    }
    fn name(&self) -> &str {
        "virtio-net"
    }
}
