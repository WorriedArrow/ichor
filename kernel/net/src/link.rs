//! A link: something that sends and receives Ethernet frames. The cell
//! switch's uplink is one, whatever it is underneath: a NIC driver
//! (virtio-net today; AWS ENA, GCP gVNIC and Hyper-V's network VSC are
//! next), or a software link wrapped around another one, such as a VPN that
//! encrypts what the cells send and decrypts what arrives (see
//! `docs/architecture.md`, "How extensible it is").
//!
//! The interface is polled, like the drivers: the uplink calls `receive`
//! until it returns `None` and `transmit` for each frame it sends, from the
//! network task. A link that needs time to pass (retransmits, keepalives,
//! rekeying) does that work in `receive` and `transmit` calls.

use alloc::boxed::Box;
use alloc::vec::Vec;

/// An Ethernet link.
pub trait Link: Send {
    /// The link's MAC address (the interface above it uses it as its own).
    fn mac(&self) -> [u8; 6];

    /// Queues one Ethernet frame (destination MAC first, no FCS); false if
    /// it was dropped (too long, or no room to queue it).
    fn transmit(&mut self, frame: &[u8]) -> bool;

    /// The next Ethernet frame that arrived, if any.
    fn receive(&mut self) -> Option<Vec<u8>>;

    /// A short name for logs ("virtio-net", "vpn over virtio-net", ...).
    fn name(&self) -> &str {
        "link"
    }

    /// The largest IP packet it carries (a network may say less, as DHCP
    /// does; one that says more, as AWS's says 9001, is not believed).
    fn mtu(&self) -> u16 {
        1500
    }
}

impl<L: Link + ?Sized> Link for Box<L> {
    fn mac(&self) -> [u8; 6] {
        (**self).mac()
    }
    fn transmit(&mut self, frame: &[u8]) -> bool {
        (**self).transmit(frame)
    }
    fn receive(&mut self) -> Option<Vec<u8>> {
        (**self).receive()
    }
    fn name(&self) -> &str {
        (**self).name()
    }
    fn mtu(&self) -> u16 {
        (**self).mtu()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;

    /// A loopback link: what it transmits it receives.
    struct Loop(VecDeque<Vec<u8>>);

    impl Link for Loop {
        fn mac(&self) -> [u8; 6] {
            [2, 0, 0, 0, 0, 1]
        }
        fn transmit(&mut self, frame: &[u8]) -> bool {
            self.0.push_back(frame.to_vec());
            true
        }
        fn receive(&mut self) -> Option<Vec<u8>> {
            self.0.pop_front()
        }
    }

    /// A link wrapped around another, as a VPN would be: here it flips
    /// every byte on the way out and back on the way in.
    struct Flip<L: Link>(L);

    impl<L: Link> Link for Flip<L> {
        fn mac(&self) -> [u8; 6] {
            self.0.mac()
        }
        fn transmit(&mut self, frame: &[u8]) -> bool {
            let f: Vec<u8> = frame.iter().map(|b| !b).collect();
            self.0.transmit(&f)
        }
        fn receive(&mut self) -> Option<Vec<u8>> {
            Some(self.0.receive()?.iter().map(|b| !b).collect())
        }
        fn name(&self) -> &str {
            "flip"
        }
    }

    #[test]
    fn links_stack_behind_a_box() {
        let mut l: Box<dyn Link> = Box::new(Flip(Loop(VecDeque::new())));
        assert_eq!(l.name(), "flip");
        assert_eq!(l.mac(), [2, 0, 0, 0, 0, 1]);
        assert!(l.transmit(&[1, 2, 3]));
        assert_eq!(l.receive(), Some(vec![1, 2, 3]));
        assert_eq!(l.receive(), None);
    }
}
