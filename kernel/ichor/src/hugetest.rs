//! 2 MiB anonymous pages (ADR-0020), checked on every boot: a sequential
//! touch maps whole 2 MiB blocks, and what then changes part of one
//! (`mprotect`, `munmap`, `fork`'s copy-on-write, `MADV_DONTNEED`) splits it
//! into 4 KiB pages without moving or losing a byte.

use alloc::vec;

use cell::Account;
use frame::mm::{HUGE_PAGE_SIZE, PAGE_SIZE};
use frame::power::{ExitStatus, shutdown};
use frame::println;

use crate::umem::{Mm, flags};

const LEN: u64 = 4 * HUGE_PAGE_SIZE;
const CHUNK: u64 = 64 << 10;
const RW: u64 = 3;
const READ: u64 = 1;
const DONTNEED: u64 = 4;

fn fail(what: &str) -> ! {
    println!("ichor: hugetest FAILED: {what}");
    shutdown(ExitStatus::Failure)
}

/// What the test writes at offset `at` of the mapping.
fn byte(at: u64) -> u8 {
    (at / PAGE_SIZE * 7 + at % 251) as u8
}

/// Whether the block at `block` is mapped as one 2 MiB page would be: its
/// 512 pages one aligned run of physical memory.
fn whole(mm: &Mm, block: u64) -> bool {
    let Some((base, _)) = mm.space().translate(block) else {
        return false;
    };
    let base = base.as_u64();
    base.is_multiple_of(HUGE_PAGE_SIZE)
        && (0..HUGE_PAGE_SIZE / PAGE_SIZE).all(|i| {
            let at = i * PAGE_SIZE;
            mm.space()
                .translate(block + at)
                .is_some_and(|(pa, p)| pa.as_u64() == base + at && p.write)
        })
}

/// Reads the mapping at `start` back a chunk at a time, expecting
/// `want(offset)` wherever it says `Some`, and nothing readable where it
/// says `None` for a whole chunk.
fn check(mm: &mut Mm, start: u64, what: &str, want: impl Fn(u64) -> Option<u8>) {
    let mut buf = vec![0u8; CHUNK as usize];
    for off in (0..LEN).step_by(CHUNK as usize) {
        let n = mm.copy_from_user(start + off, &mut buf);
        let expect_hole = want(off).is_none();
        if expect_hole != (n == 0) {
            fail(what);
        }
        let bad = buf[..n]
            .iter()
            .zip(off..)
            .any(|(&b, at)| want(at) != Some(b));
        if bad {
            println!("ichor: hugetest: wrong bytes in the chunk at {off:#x}");
            fail(what);
        }
    }
}

pub(crate) fn run() {
    let account = Account::root(4096);
    let mut mm = Mm::new(&account).unwrap_or_else(|| fail("no address space"));
    let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
    let start = mm
        .mmap(0, LEN, RW, anon, None)
        .unwrap_or_else(|_| fail("mmap"));
    if !start.is_multiple_of(HUGE_PAGE_SIZE) {
        fail("an anonymous mapping of 2 MiB pages does not start on a 2 MiB boundary");
    }

    // A sequential touch: the first block in 64 KiB steps, the rest whole.
    let mut buf = vec![0u8; CHUNK as usize];
    for off in (0..LEN).step_by(CHUNK as usize) {
        for (b, at) in buf.iter_mut().zip(off..) {
            *b = byte(at);
        }
        if mm.copy_to_user(start + off, &buf) != buf.len() {
            fail("a write to fresh anonymous memory stopped short");
        }
    }
    let blocks = |mm: &Mm| {
        (1..LEN / HUGE_PAGE_SIZE)
            .filter(|b| whole(mm, start + b * HUGE_PAGE_SIZE))
            .count()
    };
    if blocks(&mm) != 3 {
        fail("a sequential touch did not map 2 MiB pages");
    }
    check(&mut mm, start, "the bytes written", |at| Some(byte(at)));
    // Each page counts once, from its first holder to its last; a 2 MiB
    // page's are charged together and released as they go.
    let full = LEN / PAGE_SIZE;
    let charged = |want: u64, what: &str| {
        if account.used() != want {
            println!(
                "ichor: hugetest: {} pages charged, {want} expected",
                account.used()
            );
            fail(what);
        }
    };
    charged(full, "the charge for a sequential touch");

    // One page of block 1 read-only: the rest of the block stays as it was.
    let b1 = start + HUGE_PAGE_SIZE;
    let ro = b1 + 5 * PAGE_SIZE;
    let before = mm.space().translate(b1 + 6 * PAGE_SIZE);
    if mm.mprotect(ro, PAGE_SIZE, READ, None).is_err()
        || mm.space().translate(ro).is_none_or(|(_, p)| p.write)
        || mm.space().translate(b1 + 6 * PAGE_SIZE) != before
        || mm.copy_to_user(ro, &[0]) != 0
        || mm.copy_to_user(ro + PAGE_SIZE, &[byte(ro + PAGE_SIZE - start)]) != 1
    {
        fail("mprotect of one page of a 2 MiB page");
    }

    // A 64 KiB hole in block 2.
    let hole = 2 * HUGE_PAGE_SIZE + CHUNK;
    if mm.munmap(start + hole, CHUNK).is_err()
        || mm.space().translate(start + hole).is_some()
        || mm.space().translate(start + hole - PAGE_SIZE).is_none()
        || mm.space().translate(start + hole + CHUNK).is_none()
    {
        fail("munmap of part of a 2 MiB page");
    }
    let unchanged = |at: u64| (!(hole..hole + CHUNK).contains(&at)).then(|| byte(at));
    check(
        &mut mm,
        start,
        "the bytes after mprotect and munmap",
        unchanged,
    );
    let holed = full - CHUNK / PAGE_SIZE;
    charged(holed, "the charge after munmap of part of a 2 MiB page");

    // Copy-on-write across fork, both ways.
    let mut child = mm.fork().unwrap_or_else(|| fail("fork"));
    check(&mut child, start, "the child's bytes", unchanged);
    let (theirs, ours) = (3 * HUGE_PAGE_SIZE + 9, HUGE_PAGE_SIZE + 77);
    if child.copy_to_user(start + theirs, &[0xa5]) != 1
        || mm.copy_to_user(start + ours, &[0x5a]) != 1
    {
        fail("a write after fork");
    }
    let written =
        |mine: u64, b: u8| move |at: u64| if at == mine { Some(b) } else { unchanged(at) };
    check(
        &mut child,
        start,
        "the child's bytes after writes",
        written(theirs, 0xa5),
    );
    check(
        &mut mm,
        start,
        "the parent's bytes after writes",
        written(ours, 0x5a),
    );
    charged(holed + 2, "the charge after a write on each side of fork");
    // The child's copy goes, and so does the original of the parent's,
    // which only the child still held.
    drop(child);
    charged(holed, "the charge after the forked child went");

    // MADV_DONTNEED on block 3 leaves zeros.
    let b3 = 3 * HUGE_PAGE_SIZE;
    if mm.madvise(start + b3, HUGE_PAGE_SIZE, DONTNEED).is_err() {
        fail("MADV_DONTNEED");
    }
    // (Before reading it back, which faults a fresh block in.)
    charged(
        holed - HUGE_PAGE_SIZE / PAGE_SIZE,
        "the charge after MADV_DONTNEED of a 2 MiB page",
    );
    check(&mut mm, start, "the bytes after MADV_DONTNEED", |at| {
        if at >= b3 {
            Some(0)
        } else {
            written(ours, 0x5a)(at)
        }
    });
    drop(mm);
    if account.used() != 0 {
        fail("pages still charged after the address spaces went");
    }
    println!(
        "ichor: hugetest: a sequential touch mapped 2 MiB pages; mprotect, munmap, fork and MADV_DONTNEED split them, every byte kept, every page charged once"
    );
}
