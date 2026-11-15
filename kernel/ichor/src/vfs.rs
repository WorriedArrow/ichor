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
    /// The disk the lower layer comes from, whose cache pages files map.
    disk: Option<&'static crate::pagecache::Disk>,
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
        Ok(Vfs {
            fs: Mutex::new(fs),
            disk: None,
        })
    }

    /// Mounts a disk's image (see [`crate::pagecache::mount_disk`]).
    pub(crate) fn mount_disk(m: &crate::pagecache::Mounted) -> Result<Vfs, image::Error> {
        let mut vfs = Vfs::mount(m.metadata, m.disk)?;
        vfs.disk = Some(m.disk);
        Ok(vfs)
    }

    /// The verified cache page holding page `index` of `ino`, if `ino` is
    /// an unmodified lower file on a disk.
    pub(crate) fn cached_page(&self, ino: Ino, index: u64) -> Option<frame::mm::UFrame> {
        let ext = self.fs.lock().lower_extent(ino, index)?;
        crate::pagecache::frame(self.disk?, &ext).ok()
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

    /// Locks the tree (unchecked: the kernel's own use).
    pub(crate) fn lock(&self) -> MutexGuard<'_, Overlay<'static>> {
        self.fs.lock()
    }

    /// Locks the tree with operations checked against `cred`.
    pub(crate) fn lock_as(&self, cred: overlay::Cred) -> VfsGuard<'_> {
        let mut g = self.fs.lock();
        g.set_cred(Some(cred));
        VfsGuard(g)
    }
}

/// The locked tree with credentials installed; they are removed again when
/// the guard drops, so unchecked users never inherit them.
pub(crate) struct VfsGuard<'a>(MutexGuard<'a, Overlay<'static>>);

impl<'a> core::ops::Deref for VfsGuard<'a> {
    type Target = Overlay<'static>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for VfsGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for VfsGuard<'_> {
    fn drop(&mut self) {
        self.0.set_cred(None);
    }
}
