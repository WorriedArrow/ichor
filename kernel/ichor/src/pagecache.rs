//! The page cache: image chunks in pages, read from their device on demand
//! and kept by their verified BLAKE3 hash.
//!
//! A root image is mounted from its metadata alone ([`mount_disk`]); file
//! data is fetched a chunk (one page, one aligned device read) at a time
//! when the overlay reads a lower file. A chunk enters the cache only after
//! its bytes hash to the value the image's chunk table (itself covered by
//! the root hash) gives, so the cache key is a verified hash: two images, or
//! two devices, with the same chunk share one page, and a device that
//! returns wrong bytes yields EIO instead of corrupt data.
//!
//! The shared namespace is global and bounded ([`CAPACITY`] pages) with
//! clock eviction. The loader and file mappings map cached pages into
//! processes copy-on-write (see `file.rs`), so a library or executable that
//! many processes run shares one physical copy; each mapping is charged to
//! the process that maps it. Sharing is per-root policy (ADR-0004 §4): a
//! root mounted with a private [`View`] reads through a namespace of its
//! own, its pages charged to its cell's account and evicted only by its own
//! pressure. Partial: shared-namespace pages are not charged to the cells
//! that read them.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use block::{BlockDevice, SECTOR_SIZE};
use cell::Account;
use frame::mm::UFrame;
use frame::sync::Mutex;
use image::{CHUNK_SIZE, ChunkSource, Error, Extent, Hash};

/// Most pages the cache holds (32 MiB).
pub(crate) const CAPACITY: usize = 8192;
/// Largest image metadata read at mount: one contiguous buffer, so at most
/// the allocator's largest block (4 MiB, enough for ~80,000 files).
const MAX_METADATA: usize = 4 << 20;

struct Entry {
    frame: UFrame,
    /// Which disk filled it (to count sharing).
    disk: u64,
    referenced: bool,
}

/// Pages kept by verified hash, with clock eviction.
struct Pool {
    map: BTreeMap<Hash, Entry>,
    clock: VecDeque<Hash>,
}

impl Pool {
    const fn new() -> Pool {
        Pool {
            map: BTreeMap::new(),
            clock: VecDeque::new(),
        }
    }

    /// Evicts one page (clock, second chance). False if the pool is empty.
    fn evict_one(&mut self) -> bool {
        while let Some(victim) = self.clock.pop_front() {
            match self.map.get_mut(&victim) {
                Some(e) if e.referenced => {
                    e.referenced = false;
                    self.clock.push_back(victim);
                }
                Some(_) => {
                    self.map.remove(&victim);
                    return true;
                }
                None => {}
            }
        }
        false
    }

    fn put(&mut self, hash: Hash, frame: UFrame, disk: u64) {
        self.map.insert(
            hash,
            Entry {
                frame,
                disk,
                referenced: false,
            },
        );
        self.clock.push_back(hash);
    }
}

/// An opted-out root's own cache: its pages are charged to its cell's
/// account, and only its own pressure evicts them.
struct Private {
    pages: Pool,
    account: Arc<Account>,
}

struct Cache {
    /// The namespace every sharing root reads through, bounded by
    /// [`CAPACITY`].
    shared: Pool,
    /// Private namespaces by id.
    private: BTreeMap<u64, Private>,
}

static CACHE: Mutex<Cache> = Mutex::new(Cache {
    shared: Pool::new(),
    private: BTreeMap::new(),
});
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static SHARED: AtomicU64 = AtomicU64::new(0);
static MAPPED: AtomicU64 = AtomicU64::new(0);
static NEXT_DISK: AtomicU64 = AtomicU64::new(1);
/// The shared namespace's id; private ones count up from 1.
const SHARED_NS: u64 = 0;
static NEXT_NS: AtomicU64 = AtomicU64::new(1);

/// `(pages cached, hits, misses, hits on a page another disk filled,
/// pages handed out to be mapped into processes)`; pages cached counts the
/// shared namespace only.
pub(crate) fn stats() -> (usize, u64, u64, u64, u64) {
    (
        CACHE.lock().shared.map.len(),
        HITS.load(Ordering::Relaxed),
        MISSES.load(Ordering::Relaxed),
        SHARED.load(Ordering::Relaxed),
        MAPPED.load(Ordering::Relaxed),
    )
}

/// Pages held by private namespace `ns` (0 once it is gone).
pub(crate) fn private_pages(ns: u64) -> usize {
    CACHE
        .lock()
        .private
        .get(&ns)
        .map_or(0, |p| p.pages.map.len())
}

fn lookup(ns: u64, hash: &Hash, disk: u64) -> Option<UFrame> {
    let mut c = CACHE.lock();
    let pool = if ns == SHARED_NS {
        &mut c.shared
    } else {
        &mut c.private.get_mut(&ns)?.pages
    };
    let e = pool.map.get_mut(hash)?;
    e.referenced = true;
    HITS.fetch_add(1, Ordering::Relaxed);
    if e.disk != disk {
        SHARED.fetch_add(1, Ordering::Relaxed);
    }
    Some(e.frame.clone())
}

fn insert(ns: u64, hash: Hash, frame: UFrame, disk: u64) {
    let mut c = CACHE.lock();
    if ns == SHARED_NS {
        let pool = &mut c.shared;
        if pool.map.contains_key(&hash) {
            return; // another reader filled it meanwhile
        }
        while pool.map.len() >= CAPACITY && pool.evict_one() {}
        pool.put(hash, frame, disk);
        return;
    }
    // A namespace already closed caches nothing; the caller still has its
    // verified frame.
    let Some(p) = c.private.get_mut(&ns) else {
        return;
    };
    if p.pages.map.contains_key(&hash) {
        return;
    }
    // Make room among the cell's own pages: over the cell's limit (or the
    // per-namespace cap) it evicts its own, never another namespace's. A
    // cell with nothing left to evict reads uncached.
    loop {
        if p.pages.map.len() < CAPACITY && p.account.charge(1).is_ok() {
            break;
        }
        if !p.pages.evict_one() {
            return;
        }
        p.account.release(1);
    }
    p.pages.put(hash, frame, disk);
}

/// A block device holding an image. As a [`ChunkSource`] it reads through
/// the shared namespace.
pub(crate) struct Disk {
    id: u64,
    dev: Mutex<Box<dyn BlockDevice + Send>>,
}

impl core::fmt::Debug for Disk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Disk({})", self.id)
    }
}

impl Disk {
    /// Reads chunk `ext` from the device, verifies it, and caches it in
    /// namespace `ns`.
    fn fill(&self, ns: u64, ext: &Extent) -> Result<UFrame, Error> {
        let mut buf = alloc::vec![0u8; CHUNK_SIZE as usize];
        let len = usize::try_from(ext.len).map_err(|_| Error::Corrupt)?;
        self.dev
            .lock()
            .read(ext.offset / SECTOR_SIZE as u64, &mut buf)
            .map_err(|_| Error::Io)?;
        if blake3::hash(&buf[..len]) != ext.hash {
            return Err(Error::BadHash);
        }
        let frame = UFrame::alloc_zeroed().ok_or(Error::Io)?;
        frame.writer().write(&buf[..len]);
        MISSES.fetch_add(1, Ordering::Relaxed);
        insert(ns, ext.hash, frame.clone(), self.id);
        Ok(frame)
    }

    /// The verified page for chunk `ext` in namespace `ns`.
    fn page(&self, ns: u64, ext: &Extent) -> Result<UFrame, Error> {
        match lookup(ns, &ext.hash, self.id) {
            Some(f) => Ok(f),
            None => self.fill(ns, ext),
        }
    }

    /// Copies bytes `at..` of chunk `ext`, through namespace `ns`.
    fn read_in(&self, ns: u64, ext: &Extent, at: usize, out: &mut [u8]) -> Result<usize, Error> {
        let len = usize::try_from(ext.len).map_err(|_| Error::Corrupt)?;
        let n = out.len().min(len.saturating_sub(at));
        if n == 0 {
            return Ok(0);
        }
        let frame = self.page(ns, ext)?;
        let mut r = frame.reader();
        r.skip(at);
        Ok(r.read(&mut out[..n]))
    }
}

impl ChunkSource for Disk {
    fn read_chunk(&self, ext: &Extent, at: usize, out: &mut [u8]) -> Result<usize, Error> {
        self.read_in(SHARED_NS, ext, at, out)
    }
}

/// How one root reads its disk through the cache: the shared namespace
/// (pages shared by verified hash with every other sharing root), or a
/// private namespace of its own (ADR-0004 §4: a cell that opts out of
/// sharing gets private copies charged to its account, so no page it
/// reads is shared with, or evicted by, another cell).
#[derive(Debug)]
pub(crate) struct View {
    disk: &'static Disk,
    ns: u64,
}

impl View {
    /// Reads `disk` through the shared namespace.
    pub(crate) fn shared(disk: &'static Disk) -> View {
        View {
            disk,
            ns: SHARED_NS,
        }
    }

    /// Reads `disk` through a new private namespace whose pages are charged
    /// to `account`. Free it with [`View::close`].
    pub(crate) fn private(disk: &'static Disk, account: Arc<Account>) -> View {
        let ns = NEXT_NS.fetch_add(1, Ordering::Relaxed);
        CACHE.lock().private.insert(
            ns,
            Private {
                pages: Pool::new(),
                account,
            },
        );
        View { disk, ns }
    }

    /// The private namespace's id, if this view has one.
    pub(crate) fn private_ns(&self) -> Option<u64> {
        (self.ns != SHARED_NS).then_some(self.ns)
    }

    /// Frees a private namespace's pages and returns their charge. Reads
    /// through the view still work afterwards, uncached.
    pub(crate) fn close(&self) {
        if self.ns == SHARED_NS {
            return;
        }
        let gone = CACHE.lock().private.remove(&self.ns);
        if let Some(p) = gone {
            p.account.release(p.pages.map.len() as u64);
        }
    }

    /// The verified cache page for chunk `ext`, filling it if needed, to be
    /// mapped into a process.
    pub(crate) fn frame(&self, ext: &Extent) -> Result<UFrame, Error> {
        MAPPED.fetch_add(1, Ordering::Relaxed);
        self.disk.page(self.ns, ext)
    }
}

impl ChunkSource for View {
    fn read_chunk(&self, ext: &Extent, at: usize, out: &mut [u8]) -> Result<usize, Error> {
        self.disk.read_in(self.ns, ext, at, out)
    }
}

/// An image mounted from a disk: its metadata (read once, kept for the
/// life of the system) and the disk its chunks come from.
pub(crate) struct Mounted {
    pub(crate) metadata: &'static [u8],
    pub(crate) disk: &'static Disk,
}

/// Reads an image's metadata from `dev` (the header page, then everything
/// before the chunk data) and makes the device the image's chunk source.
/// The root hash is checked when the metadata is mounted.
pub(crate) fn mount_disk(mut dev: impl BlockDevice + Send + 'static) -> Result<Mounted, Error> {
    let mut head = alloc::vec![0u8; CHUNK_SIZE as usize];
    dev.read(0, &mut head).map_err(|_| Error::Io)?;
    let len = image::metadata_len(&head)?;
    if len > MAX_METADATA || len as u64 > dev.sector_count() * SECTOR_SIZE as u64 {
        return Err(Error::Corrupt);
    }
    let padded = len.next_multiple_of(CHUNK_SIZE as usize);
    let mut meta: Vec<u8> =
        block::read_prefix(&mut dev, padded, 64 * 1024).map_err(|_| Error::Io)?;
    meta.truncate(len);
    let disk = Box::leak(Box::new(Disk {
        id: NEXT_DISK.fetch_add(1, Ordering::Relaxed),
        dev: Mutex::new(Box::new(dev)),
    }));
    Ok(Mounted {
        metadata: meta.leak(),
        disk,
    })
}
