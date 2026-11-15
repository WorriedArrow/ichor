//! Character devices: the `/dev` every cell root gets, and what opening
//! each node yields.
//!
//! `populate` creates the nodes in a root's upper layer when it is mounted
//! (like a devtmpfs a container runtime would mount). Opening a node maps
//! its device number to a [`Device`] descriptor, or to the console.
//!
//! `random` and `urandom` read the kernel's ChaCha20 generator
//! ([`crate::random`]), as `getrandom` does. `ptmx`, the `pts/` nodes and
//! `tty` (with a controlling terminal) are pseudo-terminals ([`crate::pty`]).

use overlay::{Overlay, ROOT};

use crate::process::{Fd, LinuxProcess};
use crate::vfs::Ino;

const ENOSPC: i64 = 28;
const ENXIO: i64 = 6;
const O_NOCTTY: u64 = 0o400;
const O_NONBLOCK: u64 = 0o4000;

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
const PTMX: u32 = rdev(5, 2);

/// `(name, device number)` for every node in `/dev`.
const NODES: &[(&str, u32)] = &[
    ("console", CONSOLE),
    ("full", FULL),
    ("null", NULL),
    ("ptmx", PTMX),
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
    crate::pty::populate(fs, dev);
}

/// What opening node `ino`, device number `num`, with open `flags` gives.
pub(crate) fn open(p: &mut LinuxProcess, num: u32, ino: Ino, flags: u64) -> Result<Fd, i64> {
    let nonblock = flags & O_NONBLOCK != 0;
    Ok(match num {
        NULL => Fd::Dev(Device::Null),
        ZERO => Fd::Dev(Device::Zero),
        FULL => Fd::Dev(Device::Full),
        RANDOM | URANDOM => Fd::Dev(Device::Random),
        PTMX => return crate::pty::open_master(p, ino, nonblock),
        TTY => match crate::pty::open_controlling(p, nonblock) {
            Some(r) => return r,
            None => Fd::Console,
        },
        CONSOLE => Fd::Console,
        n if (crate::pty::PTS_MAJOR..crate::pty::PTS_MAJOR + 8).contains(&(n >> 8)) => {
            return crate::pty::open_slave(p, n, ino, flags & O_NOCTTY != 0, nonblock);
        }
        _ => return Err(ENXIO),
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
                crate::random::fill(out);
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
