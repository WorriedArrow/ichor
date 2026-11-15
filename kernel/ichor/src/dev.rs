//! Character devices: the `/dev` every cell root gets, and what opening
//! each node yields.
//!
//! `populate` creates the nodes in a root's upper layer when it is mounted
//! (like a devtmpfs a container runtime would mount). Opening a node maps
//! its device number to a [`Device`] descriptor, or to the console.
//!
//! Partial: `random`/`urandom` (and `getrandom`) come from a kernel
//! generator seeded from the TSC, which is unpredictable enough for hash
//! seeds and temp names but is not cryptographic. Frame needs an entropy
//! source (RDSEED/RDRAND, virtio-rng) before it can be.

use core::sync::atomic::{AtomicU64, Ordering};

use overlay::{Overlay, ROOT};

use crate::process::Fd;

const ENOSPC: i64 = 28;

const fn rdev(major: u32, minor: u32) -> u32 {
    (major << 8) | minor
}

const NULL: u32 = rdev(1, 3);
const ZERO: u32 = rdev(1, 5);
const FULL: u32 = rdev(1, 7);
const RANDOM: u32 = rdev(1, 8);
const URANDOM: u32 = rdev(1, 9);
const TTY: u32 = rdev(5, 0);
const CONSOLE: u32 = rdev(5, 1);

/// `(name, device number)` for every node in `/dev`.
const NODES: &[(&str, u32)] = &[
    ("console", CONSOLE),
    ("full", FULL),
    ("null", NULL),
    ("random", RANDOM),
    ("tty", TTY),
    ("urandom", URANDOM),
    ("zero", ZERO),
];

/// A device descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Device {
    Null,
    Zero,
    Full,
    Random,
}

/// Creates `/dev` and its nodes in a freshly mounted root (keeping any the
/// image already has).
pub(crate) fn populate(fs: &mut Overlay<'static>) {
    let dev = match fs.lookup(ROOT, "dev") {
        Ok(d) => d,
        Err(_) => match fs.mkdir(ROOT, "dev", 0o755) {
            Ok(d) => d,
            Err(_) => return,
        },
    };
    for &(name, num) in NODES {
        let _ = fs.mknod(dev, name, 0o666, num);
    }
}

/// What opening the node with device number `num` gives.
pub(crate) fn open(num: u32) -> Option<Fd> {
    Some(match num {
        NULL => Fd::Dev(Device::Null),
        ZERO => Fd::Dev(Device::Zero),
        FULL => Fd::Dev(Device::Full),
        RANDOM | URANDOM => Fd::Dev(Device::Random),
        TTY | CONSOLE => Fd::Console,
        _ => return None,
    })
}

impl Device {
    /// The device number (`st_rdev`).
    pub(crate) fn rdev(self) -> u32 {
        match self {
            Device::Null => NULL,
            Device::Zero => ZERO,
            Device::Full => FULL,
            Device::Random => URANDOM,
        }
    }

    /// Fills `out` as a read of the device would; returns the byte count.
    pub(crate) fn read(self, out: &mut [u8]) -> usize {
        match self {
            Device::Null => 0,
            Device::Zero | Device::Full => {
                out.fill(0);
                out.len()
            }
            Device::Random => {
                random_bytes(out);
                out.len()
            }
        }
    }

    /// A write of `len` bytes: discarded, or `ENOSPC` for `/dev/full`.
    pub(crate) fn write(self, len: usize) -> Result<usize, i64> {
        match self {
            Device::Full => Err(ENOSPC),
            _ => Ok(len),
        }
    }
}

static STATE: AtomicU64 = AtomicU64::new(0);

/// Fills `out` from the kernel generator: splitmix64 over a counter mixed
/// with the TSC-based clock. Not cryptographic (see the module docs).
pub(crate) fn random_bytes(out: &mut [u8]) {
    let mix = frame::time::now().as_nanos() as u64;
    for chunk in out.chunks_mut(8) {
        let mut z = STATE
            .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
            .wrapping_add(0x9e37_79b9_7f4a_7c15)
            ^ mix;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let b = z.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}
