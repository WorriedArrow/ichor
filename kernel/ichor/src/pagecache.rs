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
//! The cache is global and bounded ([`CAPACITY`] pages) with clock
//! eviction. The loader and file mappings map cached pages into processes
//! copy-on-write (see `file.rs`), so a library or executable that many
//! processes run shares one physical copy. Partial: cache pages are not
//! charged to the cells that read them.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use block::{BlockDevice, SECTOR_SIZE};
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

struct Cache {
    map: BTreeMap<Hash, Entry>,
    clock: VecDeque<Hash>,
}

static CACHE: Mutex<Cache> = Mutex::new(Cache {
    map: BTreeMap::new(),
    clock: VecDeque::new(),
});
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static SHARED: AtomicU64 = AtomicU64::new(0);
static MAPPED: AtomicU64 = AtomicU64::new(0);
static NEXT_DISK: AtomicU64 = AtomicU64::new(1);

/// `(pages cached, hits, misses, hits on a page another disk filled,
/// pages handed out to be mapped into processes)`.
pub(crate) fn stats() -> (usize, u64, u64, u64, u64) {
    (
        CACHE.lock().map.len(),
        HITS.load(Ordering::Relaxed),
        MISSES.load(Ordering::Relaxed),
        SHARED.load(Ordering::Relaxed),
        MAPPED.load(Ordering::Relaxed),
    )
}

fn lookup(hash: &Hash, disk: u64) -> Option<UFrame> {
    let mut c = CACHE.lock();
    let e = c.map.get_mut(hash)?;
    e.referenced = true;
    HITS.fetch_add(1, Ordering::Relaxed);
    if e.disk != disk {
        SHARED.fetch_add(1, Ordering::Relaxed);
    }
    Some(e.frame.clone())
}

fn insert(hash: Hash, frame: UFrame, disk: u64) {
    let mut c = CACHE.lock();
    if c.map.contains_key(&hash) {
        return; // another reader filled it meanwhile
    }
    while c.map.len() >= CAPACITY {
        let Some(victim) = c.clock.pop_front() else {
            break;
        };
        let second_chance = c.map.get_mut(&victim).is_some_and(|e| {
            let r = e.referenced;
            e.referenced = false;
            r
        });
        if second_chance {
            c.clock.push_back(victim);
        } else {
            c.map.remove(&victim);
        }
    }
    c.map.insert(
        hash,
        Entry {
            frame,
            disk,
            referenced: false,
        },
    );
    c.clock.push_back(hash);
}

/// A block device holding an image, as a [`ChunkSource`] through the cache.
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
    /// Reads chunk `ext` from the device and verifies it.
    fn fill(&self, ext: &Extent) -> Result<UFrame, Error> {
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
        insert(ext.hash, frame.clone(), self.id);
        Ok(frame)
    }
}

/// The verified cache page for chunk `ext` of `disk`, filling it if needed.
pub(crate) fn frame(disk: &Disk, ext: &Extent) -> Result<UFrame, Error> {
    MAPPED.fetch_add(1, Ordering::Relaxed);
    match lookup(&ext.hash, disk.id) {
        Some(f) => Ok(f),
        None => disk.fill(ext),
    }
}

impl ChunkSource for Disk {
    fn read_chunk(&self, ext: &Extent, at: usize, out: &mut [u8]) -> Result<usize, Error> {
        let len = usize::try_from(ext.len).map_err(|_| Error::Corrupt)?;
        let n = out.len().min(len.saturating_sub(at));
        if n == 0 {
            return Ok(0);
        }
        let frame = match lookup(&ext.hash, self.id) {
            Some(f) => f,
            None => self.fill(ext)?,
        };
        let mut r = frame.reader();
        r.skip(at);
        Ok(r.read(&mut out[..n]))
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
