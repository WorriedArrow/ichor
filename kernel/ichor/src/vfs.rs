//! The virtual file system: a cell's root is a read-only Ichor image with a
//! copy-on-write upper layer in memory (ADR-0002 §6, ADR-0006). The
//! `overlay` crate holds the logic (and path resolution); this wraps it in
//! a lock so the processes sharing a root see one consistent tree.

use frame::sync::{Mutex, MutexGuard};
use image::Image;
use overlay::Overlay;

pub(crate) use overlay::errno;
pub(crate) use overlay::{Ino, Kind, PATH_MAX, ROOT, Stat};

/// The time of day (`CLOCK_REALTIME`): the firmware clock read at boot plus
/// the monotonic time since, or time since boot if there was no clock.
pub(crate) fn wall_clock() -> core::time::Duration {
    frame::time::wall_clock().unwrap_or_else(frame::time::now)
}

/// The time file changes are stamped with: the realtime clock.
pub(crate) fn realtime() -> overlay::Time {
    let t = wall_clock();
    overlay::Time {
        sec: t.as_secs(),
        nsec: t.subsec_nanos(),
    }
}

/// Bytes a root's upper layer may hold. Milestone 4 charges them to the
/// owning cell's account instead (ADR-0006).
const UPPER_BYTES: usize = 64 << 20;

/// A mounted root file system.
#[derive(Debug)]
pub(crate) struct Vfs {
    fs: Mutex<Overlay<'static>>,
}

impl Vfs {
    /// Mounts an Ichor image as the lower layer of a fresh root: `metadata`
    /// (its root hash is checked here) and the source of its chunks, both
    /// living for the life of the system.
    pub(crate) fn mount(
        metadata: &'static [u8],
        src: &'static (dyn image::ChunkSource + Sync),
    ) -> Result<Vfs, image::Error> {
        let image = Image::mount(metadata)?;
        let mut fs = Overlay::new(&image, src, UPPER_BYTES)?;
        fs.set_clock(realtime);
        crate::dev::populate(&mut fs);
        Ok(Vfs { fs: Mutex::new(fs) })
    }

    /// Mounts a whole image held in memory (self-tests).
    pub(crate) fn mount_slice(bytes: &'static [u8]) -> Result<Vfs, image::Error> {
        let src = alloc::boxed::Box::leak(alloc::boxed::Box::new(image::SliceSource(bytes)));
        Vfs::mount(bytes, src)
    }

    /// The upper layer's budget and use, in bytes (for `statfs`).
    pub(crate) fn space(&self) -> (usize, usize) {
        (UPPER_BYTES, self.fs.lock().used_bytes())
    }

    /// Locks the tree.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Overlay<'static>> {
        self.fs.lock()
    }
}
