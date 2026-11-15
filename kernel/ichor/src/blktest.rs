//! Milestone 3: the root image comes off a real block device. Finds the
//! virtio-blk disk, reads the image from it, mounts it, and runs the same
//! static `cat /etc/motd` ELF against it in a fresh cell.

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
    let mut disk = match virtio_blk::probe() {
        None => {
            println!("ichor: blk: no virtio-blk device");
            return;
        }
        Some(Err(e)) => {
            println!("ichor: blk: virtio-blk init failed: {e:?}");
            fail("virtio-blk init");
        }
        Some(Ok(d)) => d,
    };
    let bytes = disk.sector_count().saturating_mul(SECTOR_SIZE as u64);
    println!(
        "ichor: blk: virtio-blk disk, {} sectors ({} KiB)",
        disk.sector_count(),
        bytes / 1024
    );
    if bytes == 0 || bytes > MAX_IMAGE {
        fail("root disk is empty or too large");
    }
    let image = block::read_prefix(&mut disk, bytes as usize, 64 * 1024)
        .unwrap_or_else(|e| {
            println!("ichor: blk: read error {e:?}");
            fail("reading the root disk")
        })
        .leak();
    check_pattern(image);
    let vfs =
        Arc::new(Vfs::mount(image).unwrap_or_else(|_| fail("root disk is not an Ichor image")));
    println!("ichor: blk: mounted the root image from the disk");

    let system = System::new(4096).unwrap_or_else(|| fail("no system cell"));
    let cell = Cell::new(&system.root_account, 128).unwrap_or_else(|| fail("no process cell"));
    let (status, syscalls) = run_linux(
        &mut LinuxProcess::new(cell, vfs),
        &cat_program(),
        &["cat", "/etc/motd"],
    );
    if status != 0 {
        fail("cat from disk: checks failed");
    }
    println!("ichor: blk: cat read /etc/motd from the virtio-blk disk ({syscalls} syscalls)");
}

/// Must match xtask's `DISK_PATTERN_LEN` and `pattern_byte`.
const PATTERN_LEN: usize = 300 * 1024;

fn pattern_byte(i: usize) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 9)) as u8
}

/// Checks every byte of `/usr/share/pattern`, which spans several device
/// requests, so a misordered or short read shows up.
fn check_pattern(bytes: &[u8]) {
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
        "ichor: blk: verified {} KiB read across multiple requests",
        PATTERN_LEN / 1024
    );
}
