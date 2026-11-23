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
        let Some(m) = mount("virtio-blk", d) else {
            continue;
        };
        let vfs =
            Arc::new(Vfs::mount_disk(&m).unwrap_or_else(|_| fail("disk is not an Ichor image")));
        // A disk carrying a distribution's userland is a container root.
        let is_alpine = vfs
            .lock()
            .resolve(crate::vfs::ROOT, "/etc/alpine-release", true)
            .is_ok();
        let is_debian = vfs
            .lock()
            .resolve(crate::vfs::ROOT, "/etc/debian_version", true)
            .is_ok();
        if is_alpine {
            crate::alpinetest::run(&vfs);
        } else if is_debian {
            crate::debiantest::run(&vfs);
        } else {
            exercise("virtio-blk", &m, vfs);
        }
    }
    // Every NVMe controller: a cloud VM may have several (boot volume,
    // instance storage, other volumes), in any order.
    let controllers = nvme::probe_all();
    if controllers.is_empty() {
        println!("ichor: blk: no nvme controller");
    }
    for c in controllers {
        let d = c.unwrap_or_else(|e| {
            println!("ichor: blk: nvme init failed: {e:?}");
            fail("nvme init")
        });
        println!("ichor: blk: nvme block size {} bytes", d.block_size());
        let Some(m) = mount("nvme", d) else {
            continue;
        };
        let vfs =
            Arc::new(Vfs::mount_disk(&m).unwrap_or_else(|_| fail("disk is not an Ichor image")));
        exercise("nvme", &m, vfs);
    }
    // Every disk behind a virtio-scsi controller (GCP's general-purpose
    // machine types attach their persistent disks so).
    for d in virtio_scsi::probe_all() {
        let d = d.unwrap_or_else(|e| {
            println!("ichor: blk: virtio-scsi init failed: {e:?}");
            fail("virtio-scsi init")
        });
        println!(
            "ichor: blk: virtio-scsi target {}, block size {} bytes",
            d.unit.target,
            1 << d.geometry.block_shift
        );
        let Some(m) = mount("virtio-scsi", d) else {
            continue;
        };
        let vfs =
            Arc::new(Vfs::mount_disk(&m).unwrap_or_else(|_| fail("disk is not an Ichor image")));
        exercise("virtio-scsi", &m, vfs);
    }
    // Every disk of a Hyper-V machine's SCSI controllers (Azure's).
    for d in crate::hv::bus().into_iter().flat_map(|b| b.disks()) {
        let d = match d {
            Ok(d) => d,
            // (Another controller may have the disk.)
            Err(e) => {
                println!("ichor: blk: a Hyper-V SCSI controller failed: {e:?}");
                continue;
            }
        };
        println!(
            "ichor: blk: hyper-v disk {}:{}, block size {} bytes",
            d.unit.controller_number,
            d.unit.lun,
            1 << d.geometry.block_shift
        );
        let Some(m) = mount("hyper-v", d) else {
            continue;
        };
        let vfs =
            Arc::new(Vfs::mount_disk(&m).unwrap_or_else(|_| fail("disk is not an Ichor image")));
        exercise("hyper-v", &m, vfs);
    }
    if !FIRST_DONE.load(core::sync::atomic::Ordering::Relaxed) {
        fail("no Ichor root disk found");
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

/// Mounts a disk's image: from its Ichor root partition if it has a GPT
/// (a cloud or bare-metal boot disk), else from its first sector. `None`
/// for a disk that holds no Ichor image at all (a blank or foreign volume,
/// instance storage), which is skipped; an Ichor image that fails its
/// checks, or a read error, still stops the boot.
fn mount<D: BlockDevice + Send + 'static>(name: &str, disk: D) -> Option<Mounted> {
    match crate::partition::root(disk) {
        Ok(part) => {
            println!(
                "ichor: blk: {name}: GPT disk, Ichor root partition at sector {}",
                part.start()
            );
            mount_image(name, part)
        }
        Err(disk) => mount_image(name, disk),
    }
}

/// Mounts the image on `disk`: metadata read and checked against the root
/// hash now, chunks paged in on demand.
fn mount_image(name: &str, disk: impl BlockDevice + Send + 'static) -> Option<Mounted> {
    let bytes = disk.sector_count().saturating_mul(SECTOR_SIZE as u64);
    let m = match pagecache::mount_disk(disk) {
        Ok(m) => m,
        Err(image::Error::BadMagic | image::Error::Truncated) => {
            println!(
                "ichor: blk: {name}: {} KiB, no Ichor image; skipped",
                bytes / 1024
            );
            return None;
        }
        Err(e) => {
            println!("ichor: blk: {name}: cannot mount: {e:?}");
            fail("mounting the root disk")
        }
    };
    let h = m.image.root_hash();
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
        m.image.metadata_len() / 1024
    );
    Some(m)
}

/// Set once the first root disk has had the full checks.
static FIRST_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Checks the root disk's pattern file, then runs `cat /etc/motd` against
/// the mounted root in a fresh cell. The first root disk found (virtio-blk
/// in the QEMU test runs, the GPT boot disk on NVMe in a cloud-style boot)
/// also gets the page-sharing opt-out check, busybox and the benchmarks.
fn exercise(name: &str, m: &Mounted, vfs: Arc<Vfs>) {
    let first = !FIRST_DONE.swap(true, core::sync::atomic::Ordering::Relaxed);
    if first {
        // Before anything else reads the disk, so the opted-out root can
        // be the first to read a chunk.
        opt_out(m);
        root_charges(m);
    }
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
    if first {
        crate::copytest::run(&vfs);
        crate::busytest::run(&vfs);
        if crate::bench::enabled() {
            crate::bench::run(m, &vfs, &crate::busytest::read_busybox(&vfs));
        }
    }
}

/// The physical address of the cache page holding page 0 of `path`.
fn page0(vfs: &Vfs, path: &str) -> u64 {
    let ino = vfs
        .lock()
        .resolve(crate::vfs::ROOT, path, true)
        .unwrap_or_else(|_| fail("opt-out: resolve"));
    vfs.cached_page(ino, 0)
        .unwrap_or_else(|| fail("opt-out: no cache page"))
        .phys()
        .as_u64()
}

/// Page sharing is per-cell policy (ADR-0004 §4). Mounts the disk as a
/// sharing root and as roots of two cells that opted out. Reading the same
/// chunk through a sharing and an opted-out root gives two physical pages
/// whichever reads first, and the two opted-out cells share with neither;
/// opted-out pages are charged to their cell, bounded by its limit (its
/// own pages are evicted, nobody else's), and returned when its root is
/// dropped.
fn opt_out(m: &Mounted) {
    let system = System::new(4096).unwrap_or_else(|| fail("no system cell"));
    let cell =
        |limit| Cell::new(&system.root_account, limit).unwrap_or_else(|| fail("opt-out: no cell"));
    let (a, b, tiny) = (cell(128), cell(128), cell(8));
    let mount = |acc: Option<&Arc<Cell>>| {
        let v = match acc {
            None => Vfs::mount_disk(m),
            Some(c) => Vfs::mount_disk_private(m, c.account().clone()),
        };
        Arc::new(v.unwrap_or_else(|_| fail("opt-out: mount")))
    };
    let shared = mount(None);
    let private = mount(Some(&a));
    let other = mount(Some(&b));
    let small = mount(Some(&tiny));
    let ns = private
        .private_ns()
        .unwrap_or_else(|| fail("opt-out: no private namespace"));
    if shared.private_ns().is_some() {
        fail("opt-out: a sharing root has a private namespace");
    }
    // What a root is charged before anything is read (its `/dev`).
    let base = a.account().used();
    if tiny.account().set_limit(base + 1) != base + 1 {
        fail("opt-out: limit");
    }

    // The sharing root reads first, then the opted-out one.
    let s_motd = page0(&shared, "/usr/share/motd");
    let p_motd = page0(&private, "/usr/share/motd");
    // The opted-out root reads first, then the sharing one.
    let p_pat = page0(&private, "/usr/share/pattern");
    let s_pat = page0(&shared, "/usr/share/pattern");
    if s_motd == p_motd || s_pat == p_pat {
        fail("opt-out: an opted-out root got a shared page");
    }
    if page0(&shared, "/usr/share/motd") != s_motd || page0(&private, "/usr/share/pattern") != p_pat
    {
        fail("opt-out: a namespace did not keep its own page");
    }
    let o_motd = page0(&other, "/usr/share/motd");
    if o_motd == s_motd || o_motd == p_motd {
        fail("opt-out: two opted-out cells share a page");
    }
    if pagecache::private_pages(ns) != 2
        || a.account().used() != base + 2
        || b.account().used() != base + 1
    {
        fail("opt-out: private pages are not charged to their cell");
    }

    // A process in the opted-out cell reads through its private namespace.
    let (status, _) = run_linux(
        LinuxProcess::new(a.clone(), private.clone()).unwrap_or_else(|| fail("no process")),
        &cat_program(),
        None,
        &["cat", "/etc/motd"],
    );
    if status != 0 {
        fail("opt-out: cat in an opted-out cell failed");
    }
    if a.account().used() != base + pagecache::private_pages(ns) as u64 {
        fail("opt-out: charge does not match the private pages after a process ran");
    }

    // A cell with one page left keeps one and evicts its own to read another.
    let t1 = page0(&small, "/usr/share/motd");
    let t2 = page0(&small, "/usr/share/pattern");
    if t1 == s_motd || t2 == s_pat || tiny.account().used() != base + 1 {
        fail("opt-out: a cell at its limit did not evict its own page");
    }

    // Dropping the root frees its namespace and returns the charge.
    if Arc::strong_count(&private) != 1 {
        fail("opt-out: the private root is still referenced");
    }
    drop(private);
    if pagecache::private_pages(ns) != 0 || a.account().used() != 0 {
        fail("opt-out: private pages outlived their root");
    }
    drop((other, small));
    if b.account().used() != 0 || tiny.account().used() != 0 {
        fail("opt-out: private pages outlived their root");
    }
    println!(
        "ichor: pagecache: opted-out cells read private copies charged to their own account; sharing cells share"
    );
}

/// What a cell writes to its root is charged to the cell: a page at a time,
/// up to its limit (a write that only partly fits is short, the next is
/// ENOSPC), and returned as files go, down to nothing with the root.
fn root_charges(m: &Mounted) {
    const PAGE: usize = 4096;
    let system = System::new(4096).unwrap_or_else(|| fail("no system cell"));
    let cell = Cell::new(&system.root_account, 64).unwrap_or_else(|| fail("root: no cell"));
    let vfs = Vfs::mount_disk_for(m, cell.account()).unwrap_or_else(|_| fail("root: mount"));
    let mut fs = vfs.lock();
    let f = fs
        .create(crate::vfs::ROOT, "big", 0o644)
        .unwrap_or_else(|_| fail("root: create"));
    // A root starts with its `/dev` nodes; what it has beyond them counts
    // from here.
    let base = cell.account().used();
    if base == 0 || base > 8 || cell.account().set_limit(base + 16) != base + 16 {
        fail("root: a fresh root's charge");
    }
    let used = || cell.account().used() - base;
    let data = alloc::vec![7u8; 10 * PAGE];
    if fs.write(f, 100, &data) != Ok(data.len()) || used() != 11 {
        fail("root: ten pages across eleven were not charged as eleven");
    }
    if fs.write(f, 11 * PAGE as u64, &data) != Ok(5 * PAGE) || used() != 16 {
        fail("root: a write past the limit was not short");
    }
    if fs.write(f, 16 * PAGE as u64, &data) != Err(crate::vfs::errno::ENOSPC) {
        fail("root: a write in a full cell was not ENOSPC");
    }
    if fs.truncate(f, PAGE as u64) != Ok(()) || used() != 1 {
        fail("root: truncating did not return the charge");
    }
    // Empty files are memory too.
    let name = |i: usize| alloc::format!("f{i}");
    let mut made = 0;
    while fs.create(crate::vfs::ROOT, &name(made), 0o644).is_ok() {
        made += 1;
    }
    if used() != 16 || !(100..200).contains(&made) {
        fail("root: empty files were not charged");
    }
    for i in 0..made {
        if fs.unlink(crate::vfs::ROOT, &name(i)).is_err() {
            fail("root: unlink");
        }
    }
    if used() != 1 {
        fail("root: removed files are still charged");
    }
    drop(fs);
    let (total, taken) = vfs.space();
    if (total, taken) != ((base as usize + 16) * PAGE, (base as usize + 1) * PAGE) {
        fail("root: statfs does not show the cell's account");
    }
    drop(vfs);
    if cell.account().used() != 0 {
        fail("root: file pages outlived their root");
    }
    println!("ichor: vfs: a root's files are charged to its cell, up to its limit");
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
    if pagecache::mount_disk(MemDisk(meta_bad)).is_ok() {
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
    let img = m.image;
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
