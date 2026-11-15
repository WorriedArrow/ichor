//! Milestone 3: the root image comes off real block devices. For each of
//! the virtio-blk disk and the NVMe namespace, reads the image, verifies a
//! pattern file spanning many requests, mounts it, and runs the static
//! `cat /etc/motd` ELF against it in a fresh cell.

use alloc::sync::Arc;

use block::{BlockDevice, SECTOR_SIZE};
use frame::println;

use crate::kcell::{Cell, System};
use crate::process::LinuxProcess;
use crate::runtest::{cat_program, fail, run_linux};
use crate::vfs::Vfs;

/// Largest root image read into memory. Paging the image in from the
/// device on demand replaces this with the page cache.
const MAX_IMAGE: u64 = 64 << 20;

pub(crate) fn run() {
    match virtio_blk::probe() {
        None => println!("ichor: blk: no virtio-blk device"),
        Some(Err(e)) => {
            println!("ichor: blk: virtio-blk init failed: {e:?}");
            fail("virtio-blk init");
        }
        Some(Ok(mut d)) => exercise("virtio-blk", &mut d),
    }
    match nvme::probe() {
        None => println!("ichor: blk: no nvme controller"),
        Some(Err(e)) => {
            println!("ichor: blk: nvme init failed: {e:?}");
            fail("nvme init");
        }
        Some(Ok(mut d)) => {
            println!("ichor: blk: nvme block size {} bytes", d.block_size());
            exercise("nvme", &mut d);
        }
    }
}

/// Reads the root image off `disk`, checks the pattern file, mounts it, and
/// runs `cat /etc/motd` against it in a fresh cell.
fn exercise(name: &str, disk: &mut impl BlockDevice) {
    let bytes = disk.sector_count().saturating_mul(SECTOR_SIZE as u64);
    println!(
        "ichor: blk: {name} disk, {} sectors ({} KiB)",
        disk.sector_count(),
        bytes / 1024
    );
    if bytes == 0 || bytes > MAX_IMAGE {
        fail("root disk is empty or too large");
    }
    let image = block::read_prefix(disk, bytes as usize, 64 * 1024)
        .unwrap_or_else(|e| {
            println!("ichor: blk: {name} read error {e:?}");
            fail("reading the root disk")
        })
        .leak();
    check_pattern(name, image);
    let vfs =
        Arc::new(Vfs::mount(image).unwrap_or_else(|_| fail("root disk is not an Ichor image")));
    println!("ichor: blk: mounted the root image from the {name} disk");

    let system = System::new(4096).unwrap_or_else(|| fail("no system cell"));
    let cell = Cell::new(&system.root_account, 128).unwrap_or_else(|| fail("no process cell"));
    let (status, syscalls) = run_linux(
        LinuxProcess::new(cell, vfs.clone()).unwrap_or_else(|| fail("no process")),
        &cat_program(),
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

/// Must match xtask's `DISK_PATTERN_LEN` and `pattern_byte`.
const PATTERN_LEN: usize = 300 * 1024;

fn pattern_byte(i: usize) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 9)) as u8
}

/// Checks every byte of `/usr/share/pattern`, which spans several device
/// requests, so a misordered or short read shows up.
fn check_pattern(name: &str, bytes: &[u8]) {
    let img =
        image::Image::mount(bytes).unwrap_or_else(|_| fail("root disk is not an Ichor image"));
    let node = img
        .lookup("/usr/share/pattern")
        .unwrap_or_else(|| fail("no /usr/share/pattern on the disk"));
    if node.size() != PATTERN_LEN as u64 {
        fail("/usr/share/pattern has the wrong size");
    }
    let mut buf = alloc::vec![0u8; 4096];
    let mut at = 0usize;
    while at < PATTERN_LEN {
        let n = node.read_at(at as u64, &mut buf);
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
