//! The root image comes off real block devices. For each of the virtio-blk
//! disks and the NVMe namespace, mounts the image from its metadata (root
//! hash checked) with data paged in through the page cache, verifies a
//! pattern file spanning many chunks, and runs the static `cat /etc/motd`
//! ELF against it in a fresh cell. The NVMe namespace holds the same image
//! as the first virtio disk, so its reads hit pages that disk filled.

use alloc::sync::Arc;

use block::{BlockDevice, SECTOR_SIZE};
use frame::println;
use image::{ChunkSource, Image};

use crate::kcell::{Cell, System};
use crate::pagecache::{self, Mounted};
use crate::process::LinuxProcess;
use crate::runtest::{cat_program, fail, run_linux};
use crate::vfs::Vfs;

pub(crate) fn run() {
    let disks = virtio_blk::probe_all();
    if disks.is_empty() {
        println!("ichor: blk: no virtio-blk device");
    }
    for d in disks {
        let d = d.unwrap_or_else(|e| {
            println!("ichor: blk: virtio-blk init failed: {e:?}");
            fail("virtio-blk init")
        });
        let m = mount("virtio-blk", d);
        let vfs =
            Arc::new(Vfs::mount_disk(&m).unwrap_or_else(|_| fail("disk is not an Ichor image")));
        // A disk carrying a distribution's userland is a container root.
        let is_alpine = vfs
            .lock()
            .resolve(crate::vfs::ROOT, "/etc/alpine-release", true)
            .is_ok();
        if is_alpine {
            crate::alpinetest::run(&vfs);
        } else {
            exercise("virtio-blk", &m, vfs);
        }
    }
    match nvme::probe() {
        None => println!("ichor: blk: no nvme controller"),
        Some(Err(e)) => {
            println!("ichor: blk: nvme init failed: {e:?}");
            fail("nvme init");
        }
        Some(Ok(d)) => {
            println!("ichor: blk: nvme block size {} bytes", d.block_size());
            let m = mount("nvme", d);
            let vfs = Arc::new(
                Vfs::mount_disk(&m).unwrap_or_else(|_| fail("disk is not an Ichor image")),
            );
            exercise("nvme", &m, vfs);
        }
    }
    tampering();
    let (pages, hits, misses, shared, mapped) = pagecache::stats();
    println!(
        "ichor: pagecache: {pages} pages, {misses} chunks read and verified, {hits} hits ({shared} on pages another disk filled), {mapped} mapped copy-on-write into processes"
    );
    if mapped == 0 {
        fail("no executable or library page was mapped from the page cache");
    }
}

/// Mounts a disk's image: metadata read and checked against the root hash
/// now, chunks paged in on demand.
fn mount(name: &str, disk: impl BlockDevice + Send + 'static) -> Mounted {
    let bytes = disk.sector_count().saturating_mul(SECTOR_SIZE as u64);
    let m = pagecache::mount_disk(disk).unwrap_or_else(|e| {
        println!("ichor: blk: {name}: cannot mount: {e:?}");
        fail("mounting the root disk")
    });
    let image = Image::mount(m.metadata).unwrap_or_else(|e| {
        println!("ichor: blk: {name}: image rejected: {e:?}");
        fail("root disk image rejected")
    });
    let h = image.root_hash();
    println!(
        "ichor: blk: {name} disk, {} KiB; root hash {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.. verified over {} KiB of metadata; data paged in on demand",
        bytes / 1024,
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        m.metadata.len() / 1024
    );
    m
}

/// Checks the root disk's pattern file, then runs `cat /etc/motd` (and, on
/// virtio-blk, busybox) against the mounted root in a fresh cell.
fn exercise(name: &str, m: &Mounted, vfs: Arc<Vfs>) {
    check_pattern(name, m);
    println!("ichor: blk: mounted the root image from the {name} disk");

    let system = System::new(4096).unwrap_or_else(|| fail("no system cell"));
    let cell = Cell::new(&system.root_account, 128).unwrap_or_else(|| fail("no process cell"));
    let (status, syscalls) = run_linux(
        LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process")),
        &cat_program(),
        None,
        &["cat", "/etc/motd"],
    );
    if status != 0 {
        fail("cat from disk: checks failed");
    }
    println!("ichor: blk: cat read /etc/motd from the {name} disk ({syscalls} syscalls)");
    if name == "virtio-blk" {
        crate::busytest::run(&vfs);
    }
}

/// A disk in memory, for the tampering checks.
struct MemDisk(alloc::vec::Vec<u8>);

impl BlockDevice for MemDisk {
    fn sector_count(&self) -> u64 {
        (self.0.len() / SECTOR_SIZE) as u64
    }
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), block::BlockError> {
        block::check(self, sector, buf.len())?;
        let at = sector as usize * SECTOR_SIZE;
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }
}

/// A flipped metadata byte fails the mount (root hash); a flipped data
/// byte makes reading that file EIO (chunk hash) while the rest still
/// reads.
fn tampering() {
    let good = crate::runtest::root_image();
    let padded = |mut v: alloc::vec::Vec<u8>| {
        v.resize(v.len().next_multiple_of(4096), 0);
        v
    };
    let mut meta_bad = padded(good.to_vec());
    meta_bad[200] ^= 1;
    if pagecache::mount_disk(MemDisk(meta_bad)).is_ok_and(|m| Image::mount(m.metadata).is_ok()) {
        fail("tampered metadata mounted");
    }
    let image = Image::mount(good).unwrap_or_else(|_| fail("root image"));
    let motd = image
        .lookup("/usr/share/motd")
        .and_then(|n| n.extent(0))
        .unwrap_or_else(|| fail("no motd extent"));
    let mut data_bad = padded(good.to_vec());
    data_bad[motd.offset as usize] ^= 0x20;
    let m = pagecache::mount_disk(MemDisk(data_bad)).unwrap_or_else(|_| fail("mount"));
    let vfs = Vfs::mount_disk(&m).unwrap_or_else(|_| fail("tampered-data image"));
    let mut fs = vfs.lock();
    let ino = fs
        .resolve(crate::vfs::ROOT, "/usr/share/motd", true)
        .unwrap_or_else(|_| fail("resolve"));
    let mut buf = [0u8; 64];
    if fs.read(ino, 0, &mut buf) != Err(5) {
        fail("tampered chunk was not EIO");
    }
    println!("ichor: blk: tampered metadata is refused at mount; a tampered chunk reads as EIO");
}

/// Must match xtask's `DISK_PATTERN_LEN` and `pattern_byte`.
const PATTERN_LEN: usize = 300 * 1024;

fn pattern_byte(i: usize) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 9)) as u8
}

/// Checks every byte of `/usr/share/pattern`, which spans many chunks, so
/// a misordered or short read shows up (and each chunk is hash-verified).
fn check_pattern(name: &str, m: &Mounted) {
    let img = Image::mount(m.metadata).unwrap_or_else(|_| fail("root disk is not an Ichor image"));
    let src: &dyn ChunkSource = m.disk;
    let node = img
        .lookup("/usr/share/pattern")
        .unwrap_or_else(|| fail("no /usr/share/pattern on the disk"));
    if node.size() != PATTERN_LEN as u64 {
        fail("/usr/share/pattern has the wrong size");
    }
    let mut buf = alloc::vec![0u8; 4096];
    let mut at = 0usize;
    while at < PATTERN_LEN {
        let n = node
            .read_at(at as u64, &mut buf, src)
            .unwrap_or_else(|_| fail("reading /usr/share/pattern"));
        if n == 0 {
            fail("short read of /usr/share/pattern");
        }
        for (k, &b) in buf.iter().take(n).enumerate() {
            if b != pattern_byte(at + k) {
                println!("ichor: blk: pattern mismatch at byte {}", at + k);
                fail("/usr/share/pattern corrupted");
            }
        }
        at += n;
    }
    println!(
        "ichor: blk: {name}: verified {} KiB read across multiple requests",
        PATTERN_LEN / 1024
    );
}
