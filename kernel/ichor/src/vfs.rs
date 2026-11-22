//! The virtual file system: a cell's root is a read-only Ichor image with a
//! copy-on-write upper layer in memory (ADR-0002 §6, ADR-0006). The
//! `overlay` crate holds the logic (and path resolution); this wraps it in
//! a lock so the processes sharing a root see one consistent tree. File
//! data from the lower image is read outside that lock ([`Vfs::read`]).

use alloc::sync::Arc;

use cell::Account;
use frame::sync::{Mutex, MutexGuard};
use image::Image;
use overlay::Overlay;

use crate::page::RootPages;
use crate::pagecache::{Mounted, View};

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

/// Bytes the upper layer of a root that no cell owns may hold (a cell's is
/// charged to the cell's account instead, ADR-0006).
const UPPER_BYTES: usize = 64 << 20;

/// A root's tree, its written files made of charged pages.
pub(crate) type Tree = Overlay<'static, RootPages>;

/// A mounted root file system.
#[derive(Debug)]
pub(crate) struct Vfs {
    fs: Mutex<Tree>,
    /// What written files are charged to.
    account: Option<Arc<Account>>,
    /// How the lower layer reads its disk through the page cache (shared or
    /// a private namespace), whose pages files map.
    view: Option<&'static crate::pagecache::View>,
    /// This root's devpts: its pseudo-terminals by index.
    pub(crate) ptys: crate::pty::Table,
    /// `AF_UNIX` sockets bound to paths in this root, by socket node.
    pub(crate) unix: crate::linuxabi::unix::Bound,
    /// Who watches this root's files.
    pub(crate) inotify: crate::linuxabi::inotify::Instances,
}

impl Drop for Vfs {
    fn drop(&mut self) {
        // A private namespace lives as long as its root.
        if let Some(v) = self.view {
            v.close();
        }
    }
}

impl Vfs {
    /// Mounts an Ichor image as the lower layer of a fresh root: the image
    /// (its root hash checked) and the source of its chunks, both living
    /// for the life of the system. What is written is charged to `account`.
    pub(crate) fn mount(
        image: Image<'static>,
        src: &'static (dyn image::ChunkSource + Sync),
        account: Option<Arc<Account>>,
    ) -> Result<Vfs, image::Error> {
        let max = match account {
            Some(_) => usize::MAX,
            None => UPPER_BYTES,
        };
        let pages = RootPages::new(account.clone());
        let mut fs = Overlay::with_pages(&image, src, pages, max)?;
        fs.set_clock(realtime);
        crate::dev::populate(&mut fs);
        Ok(Vfs {
            fs: Mutex::new(fs),
            account,
            view: None,
            ptys: frame::sync::SpinLock::new(alloc::collections::BTreeMap::new()),
            unix: frame::sync::SpinLock::new(alloc::collections::BTreeMap::new()),
            inotify: crate::linuxabi::inotify::Instances::new(),
        })
    }

    /// Mounts a disk's image (see [`crate::pagecache::mount_disk`]),
    /// sharing cache pages with every other sharing root. No cell owns it
    /// (self-tests share one between cells).
    pub(crate) fn mount_disk(m: &Mounted) -> Result<Vfs, image::Error> {
        Vfs::mount_view(m, View::shared(m.disk), None)
    }

    /// [`Vfs::mount_disk`], owned by the cell of `account`: what it writes
    /// is charged there.
    pub(crate) fn mount_disk_for(m: &Mounted, account: &Arc<Account>) -> Result<Vfs, image::Error> {
        Vfs::mount_view(m, View::shared(m.disk), Some(account.clone()))
    }

    /// Mounts a disk's image for a cell that opts out of page sharing: the
    /// root reads through a private cache namespace charged to `account`
    /// and freed when the root is dropped (ADR-0004 §4).
    pub(crate) fn mount_disk_private(
        m: &Mounted,
        account: Arc<Account>,
    ) -> Result<Vfs, image::Error> {
        let view = View::private(m.disk, account.clone());
        Vfs::mount_view(m, view, Some(account))
    }

    fn mount_view(
        m: &Mounted,
        view: View,
        account: Option<Arc<Account>>,
    ) -> Result<Vfs, image::Error> {
        // The overlay needs its chunk source for the life of the system:
        // the view is two words, and a private one's pages are freed when
        // the root drops.
        let view: &'static View = alloc::boxed::Box::leak(alloc::boxed::Box::new(view));
        match Vfs::mount(m.image, view, account) {
            Ok(mut vfs) => {
                vfs.view = Some(view);
                Ok(vfs)
            }
            Err(e) => {
                view.close();
                Err(e)
            }
        }
    }

    /// The private cache namespace this root reads through, if it opted
    /// out of sharing.
    pub(crate) fn private_ns(&self) -> Option<u64> {
        self.view?.private_ns()
    }

    /// Pages of its owner's this root holds: written files, inodes and
    /// private cache pages. None, if no cell owns it.
    pub(crate) fn charged(&self) -> u64 {
        if self.account.is_none() {
            return 0;
        }
        let fs = self.fs.lock();
        let cached = self.private_ns().map_or(0, crate::pagecache::private_pages);
        (fs.used_bytes() / 4096 + fs.kept_pages() + cached) as u64
    }

    /// The verified cache page holding page `index` of `ino`, if `ino` is
    /// an unmodified lower file on a disk.
    pub(crate) fn cached_page(&self, ino: Ino, index: u64) -> Option<frame::mm::UFrame> {
        let ext = self.fs.lock().lower_extent(ino, index)?;
        self.view?.frame(&ext).ok()
    }

    /// Mounts a whole image held in memory (self-tests).
    pub(crate) fn mount_slice(bytes: &'static [u8]) -> Result<Vfs, image::Error> {
        let src = alloc::boxed::Box::leak(alloc::boxed::Box::new(image::SliceSource(bytes)));
        Vfs::mount(Image::mount(bytes)?, src, None)
    }

    /// Reads file bytes at `offset`. An unmodified lower file is read after
    /// the tree lock is dropped, so readers of a root do not serialize on
    /// each other, or on the device read a page-cache miss makes. Upper
    /// files are copied under the lock.
    pub(crate) fn read(&self, ino: Ino, offset: u64, out: &mut [u8]) -> Result<usize, i64> {
        let fs = self.fs.lock();
        match fs.lower_reader(ino) {
            Some(r) => {
                drop(fs);
                r.read(offset, out)
            }
            None => fs.read(ino, offset, out),
        }
    }

    /// The upper layer's budget and use, in bytes (for `statfs`): the
    /// cell's whole account, which its memory shares, if a cell owns it.
    pub(crate) fn space(&self) -> (usize, usize) {
        match &self.account {
            Some(a) => (a.limit() as usize * 4096, a.used() as usize * 4096),
            None => (UPPER_BYTES, self.fs.lock().used_bytes()),
        }
    }

    /// Locks the tree (unchecked: the kernel's own use).
    pub(crate) fn lock(&self) -> MutexGuard<'_, Tree> {
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
pub(crate) struct VfsGuard<'a>(MutexGuard<'a, Tree>);

impl<'a> core::ops::Deref for VfsGuard<'a> {
    type Target = Tree;
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
