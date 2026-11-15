//! virtio-rng: entropy from the host, over the modern PCI transport,
//! polled. One queue; each request is a device-writable buffer the device
//! fills with random bytes.
//!
//! Safe code only (see `virtio-pci`).

#![no_std]
#![forbid(unsafe_code)]

use core::time::Duration;

use frame::dma::DmaBuf;
use frame::virtio::{Segment, VirtQueue};
use virtio_pci::{Notifier, Transport};

pub use virtio_pci::InitError;

const DEVICE_RNG_MODERN: u16 = 0x1044;
const DEVICE_RNG_TRANSITIONAL: u16 = 0x1005;
const TIMEOUT: Duration = Duration::from_secs(2);
/// Largest request.
const MAX_REQUEST: usize = 4096;

/// A virtio-rng device.
#[derive(Debug)]
pub struct VirtioRng {
    transport: Transport,
    notifier: Notifier,
    queue: VirtQueue,
    /// Set when a request timed out: the device may still write into that
    /// buffer, so it is leaked and the device is not used again.
    dead: bool,
}

/// Finds and initializes the first virtio-rng device.
pub fn probe() -> Option<Result<VirtioRng, InitError>> {
    let dev = virtio_pci::find(&[DEVICE_RNG_MODERN, DEVICE_RNG_TRANSITIONAL])
        .into_iter()
        .next()?;
    Some(VirtioRng::init(&dev))
}

impl VirtioRng {
    fn init(dev: &frame::bus::pci::PciDevice) -> Result<VirtioRng, InitError> {
        let (transport, _) = Transport::new(dev, 0)?;
        let (queue, notifier) = transport.queue(0, 8)?;
        transport.driver_ok();
        Ok(VirtioRng {
            transport,
            notifier,
            queue,
            dead: false,
        })
    }

    /// Fills the front of `out` with bytes from the device; returns how
    /// many (0 if it did not answer in time).
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let len = out.len().min(MAX_REQUEST);
        if len == 0 || self.dead {
            return 0;
        }
        let Some(buf) = DmaBuf::alloc(len) else {
            return 0;
        };
        let seg = [Segment {
            buf: &buf,
            offset: 0,
            len,
            device_writes: true,
        }];
        let Ok(token) = self.queue.submit(&seg) else {
            return 0;
        };
        self.transport.notify(self.notifier, 0);
        let deadline = frame::time::now() + TIMEOUT;
        let written = loop {
            if let Some((done, n)) = self.queue.poll() {
                if done == token {
                    break n as usize;
                }
                continue;
            }
            if frame::time::now() >= deadline {
                self.dead = true;
                core::mem::forget(buf);
                return 0;
            }
            core::hint::spin_loop();
        };
        let n = written.min(len);
        buf.read(0, &mut out[..n]);
        n
    }
}
