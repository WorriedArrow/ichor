//! The virtual file system: a cell's root is a read-only Ichor image with a
//! copy-on-write upper layer in memory (ADR-0002 §6, ADR-0006). The
//! `overlay` crate holds the logic (and path resolution); this wraps it in
//! a lock so the processes sharing a root see one consistent tree.

use frame::sync::{Mutex, MutexGuard};
use image::Image;
use overlay::Overlay;

pub(crate) use overlay::errno;
pub(crate) use overlay::{Ino, Kind, PATH_MAX, ROOT, Stat};

/// Bytes a root's upper layer may hold. Milestone 4 charges them to the
/// owning cell's account instead (ADR-0006).
const UPPER_BYTES: usize = 64 << 20;

/// A mounted root file system.
#[derive(Debug)]
pub(crate) struct Vfs {
    fs: Mutex<Overlay<'static>>,
}

impl Vfs {
    /// Mounts `bytes` (an Ichor image that lives for the life of the system)
    /// as the lower layer of a fresh root.
    pub(crate) fn mount(bytes: &'static [u8]) -> Result<Vfs, image::Error> {
        let image = Image::mount(bytes)?;
        Ok(Vfs {
            fs: Mutex::new(Overlay::new(&image, UPPER_BYTES)?),
        })
    }

    /// Locks the tree.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Overlay<'static>> {
        self.fs.lock()
    }
}
