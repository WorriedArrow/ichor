//! Ichor's network protocols (ADR-0010), written sans-I/O: every type here
//! is a state machine that takes bytes and the current time and produces
//! bytes to send. Nothing here touches a device, a thread or the Linux
//! ABI, so all of it runs in host tests and under a fuzzer.
//!
//! - [`wire`]: parsing and building Ethernet II, ARP, IPv4, ICMP and UDP
//!   packets, and the Internet checksum. Every parser treats its input as
//!   hostile: it checks lengths and checksums and returns `None` rather
//!   than panic.
//! - [`iface`]: one IPv4 interface: ARP (request, reply, a cache with
//!   expiry, packets held until their next hop resolves) and ICMP echo.
//! - [`tcp`]: the TCP state machine.
//! - [`switch`]: the cell switch's forwarding decisions (assigned
//!   addresses, anti-spoofing, token-bucket rate limits).
//! - [`nat`]: source NAT and published ports at the uplink.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod iface;
pub mod nat;
pub mod switch;
pub mod tcp;
pub mod wire;

pub use core::net::Ipv4Addr;

/// An Ethernet MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const BROADCAST: Mac = Mac([0xff; 6]);
    pub const ZERO: Mac = Mac([0; 6]);
}
