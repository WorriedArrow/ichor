# ADR-0011: Kernel copies to and from user memory

- Status: Accepted
- Date: 2026-11-15
- Amends: ADR-0001 (the "fallible user-memory copies" paragraph) and
  ADR-0003's planned exception table for user copies
- Amended: 2026-11-15, "Copies without the Mm lock" (Phase E's step this
  ADR unblocked)

## Context

ADR-0001 planned Linux-style user copies: a `memcpy` through the user
virtual address with SMAP opened (`stac`/`clac`) for the copy, and an
exception table that turns a fault into a short count. What was built
instead is a software walk: `VmSpace::copy_from_user`/`copy_to_user`
translate each page and copy through the kernel's linear map. SMAP stays on
and is never opened.

That walk (`walk_user`) had two defects
(`docs/reports/user-copy-fix.md`):

1. **It ignored the PTE's write bit.** A kernel write went through
   read-only mappings. Copy-on-write pages and page-cache pages are mapped
   read-only into every cell that uses them, so `read()` into a
   `PROT_READ` private file mapping wrote into the physical page every
   other cell sees. The kernel's `Mm::populate` breaks copy-on-write ahead
   of a copy, but it stops at the first page the region does not allow
   writing, and the copy then went on regardless.
2. **It copied after dropping the space lock.** Between the translation and
   the copy, another thread's `unmap` could clear the PTE, shoot down the
   TLBs, and free the page, so the copy wrote into a freed page that may
   since have been reused. Today the kernel's `Mm` mutex happens to
   serialize Linux syscalls against `munmap`, but frame's API must be sound
   for any safe caller (ADR-0001), and Phase E's "Mm lock not held across
   whole user copies" item would remove exactly that serialization.

Both designs on the table fix both defects:

- **Hardware-enforced copies** (ADR-0001's plan, and what Linux does).
- **The software walk, done correctly.**

## Decision

Frame keeps the software walk and makes it correct.

1. **Copies go through the linear map, never through user addresses.**
   SMAP stays on all the time and `AC` is never set. Every kernel `#PF`
   is still a kernel bug (frame's trap handler panics on it), which stays
   a simple, strong invariant.
2. **Each page is copied under the space lock, after a permission check
   on the PTE read under that lock.** `VmSpace::copy_user` takes the lock
   once per page, translates the page (the walk rejects anything outside
   the user half), stops if it is not present or, for a write, not
   writable, copies at most to the page end, and only then drops the lock.
   `map`, `unmap_range` and `protect` change PTEs only under this lock, and
   a page's mapping reference is dropped only after `unmap_range` cleared
   its PTE, so for the whole copy the page stays mapped with the
   permissions just checked. It cannot be freed or reused mid-copy, and
   no byte lands in it after `unmap` returns. `with_user_atomic` (futexes,
   ADR-0007) already worked this way.
3. **Frame enforces what the CPU would; the kernel decides what a fault
   means.** `copy_to_user` stops exactly where a user store would fault,
   and `copy_from_user` where a load would. It returns the count. The
   kernel's `Mm::copy_to_user`/`copy_from_user` then run the ordinary
   fault handler (`Mm::fault`: region check, demand paging, breaking
   copy-on-write) at the page where frame stopped, and copy on. A page is
   faulted at most once in a row, so the loop always ends. A page the
   process may not write ends the copy short, and the syscall returns
   `EFAULT` or a short count, as on Linux. Copy-on-write policy stays in
   the kernel, as ADR-0007 decided.
4. **A copy holds the lock for at most one page (4 KiB)**, with
   interrupts off (frame's `SpinLock`). `unmap_range` and `protect` drop
   the lock before their TLB shootdown, so a shootdown never waits on a CPU
   that waits for the lock. A shootdown IPI to a CPU in a copy is answered
   within one page copy.

### Copies without the Mm lock (amended 2026-11-15)

Until this amendment a Linux process's copies held its `Mm` mutex for the
whole copy, so a multi-page `read` or `recv` blocked every other thread's
`mmap`, `munmap`, `mprotect` and page fault. Frame's copy no longer needs
that lock, so the kernel now takes it only for faults. No frame change.

5. **The space is shared.** `Mm` holds its `VmSpace` in an `Arc`, and the
   process group keeps a second reference behind a spinlock, set by
   `replace_mm` (`execve`) with the `Mm` locked. A copy takes that
   reference and runs `umem::copy_user` with it, without the `Mm` lock.
   A copy racing an `execve` therefore writes into the old space, which
   lives until the copy drops its reference, never into a freed one.
6. **The `Mm` lock covers a fault and that page's copy.** Where frame's
   copy stops, the loop locks `Mm`, checks that the space is still the
   process's, runs `Mm::fault`, copies that one page and unlocks. A
   concurrent `munmap` or `mprotect` either runs before the fault (which
   then fails, and the copy ends short) or after that page's copy. A page
   that is still not copyable after its fault ends the copy, so a copy
   never loops, as decision 3 required. A copy of resident pages takes no
   sleeping lock at all.
7. **The last reference is dropped on a task not bound to the space.**
   Frame's `VmSpace` must be dropped only while no CPU runs it. `execve`
   and the last thread out wait for every other thread of the process to
   leave, so their copies are done. The only copier that can outlive the
   `Mm` is a helper thread (the io_uring worker), which `execve` does not
   wait for. Helpers therefore stay on the kernel address space; they
   never run user code. Before this, a helper stayed bound to the space
   that `execve` freed.
8. **Spaces nothing else can reach keep the old shape.**
   `Mm::copy_to_user`/`copy_from_user` hold the `Mm` throughout. The
   loader (a new image's stack) and native processes (which own their
   `Mm` outright) use them.

The cost: a copy that races an `execve` finishes into pages the old `Mm`
already released from the cell's account, for at most the length of that
copy. A helper copy that starts after `execve` still lands in the new
image at the old request's address, as it did before this amendment;
Linux cancels a ring's requests at `execve`, which is left for
io_uring's own work.

Rejected on the way: taking the `Mm` lock just long enough to clone the
space reference. Every copy would still wait for whoever holds the lock,
including a page fault reading a file, and the new boot test
(`copytest::mm_unlocked`) fails that way.

## Alternatives considered

- **Hardware-enforced copies** (`stac`, `rep movsb` through the user
  address, `clac`; a fault goes through an exception-fixup table). The CPU
  enforces the PTE permissions, there is no page walk, and large copies
  are faster. That is why it was the original plan. It loses here, for
  now, for four reasons:
  - **It only reaches the address space loaded in CR3.** The kernel
    writes into spaces that are not running: the loader builds a new
    image's stack before the process runs, and `clone` writes
    `CLONE_CHILD_SETTID` into a forked child's space. Frame would need the
    software walk for those anyway (or a temporary CR3 switch with
    shootdown bookkeeping), so the TCB would carry two copy paths instead
    of one.
  - **The fault cannot be resolved where it is taken.** Demand paging and
    copy-on-write live in the kernel, behind the `Mm` mutex (a sleeping
    lock) that the copying syscall already holds. The fixup can only
    return a short count, and the caller must fault and retry: the same
    loop as decision 3. The hardware path saves the walk, not the retry
    logic.
  - **More unsafe mechanism in frame:** the fixup table and a kernel `#PF`
    path that resumes instead of panicking, `stac`/`clac` with `AC`
    cleared on every interrupt and exception entry (or a copy that runs
    with interrupts off), and a check that the target space is the one in
    CR3 with preemption disabled. That is roughly 150 lines and 10 unsafe
    sites, against 3 lines and 1 site for this fix.
  - **No measured need yet.** Phase E's benchmarks (`docs/benchmarks.md`)
    do not measure large copies. The walk was already per page and already
    took the lock per page (in `translate`), so this fix does not change
    the cost model.

  We should revisit it once a benchmark shows large `read`/`recv` into
  user buffers to be slow, or when the kernel stops needing remote-space
  copies.
  This ADR would then be superseded, not amended.
- **Pin each page with a reference instead of holding the lock.** The
  copy could then run with interrupts on, and a page could not be freed
  mid-copy. But the copy would still land after a concurrent `munmap` or
  `mprotect(PROT_READ)` returned. For a page also mapped by another
  process (shared anonymous memory), that write is visible there after the
  caller's `munmap`. It also costs two refcount updates per page.
  Rejected: holding the lock is simpler and gives the stricter guarantee,
  for at most one page copy with interrupts off.
- **Fixing only the kernel side** (make `populate` and the copy agree).
  Rejected: frame's API would still be unsound for other safe callers, and
  the defect would come back as soon as a caller skips `populate`.

## Consequences

- **Frame's soundness argument gains one clause:** a kernel copy writes a
  page only while that page's PTE in the target space is writable, and
  only while holding that space's lock. The kernel keeps the matching
  invariant in `umem`: a page shared copy-on-write, or taken from the page
  cache, is never mapped writable (`mapped_prot`, `map_cow`, `fork`).
  Together they mean a kernel copy can never change a page another cell
  or process can see unless that page was mapped shared and writable on
  purpose.
- **Phase E's Mm-lock item is unblocked.** Frame's copies no longer rely
  on the kernel's `Mm` mutex for soundness. The kernel can stop holding
  `Mm` across a whole multi-page copy, as long as the fault-and-retry loop
  takes it again for each fault. (Done: "Copies without the Mm lock"
  above.)
- **Budget:** +3 code lines and +1 unsafe site (5,608 / 243 to 5,611 /
  244), inside `audit.toml`'s step 6 (5,800 / 250). No budget change.
- **Tests:** `kernel/ichor/src/copytest.rs` runs on every boot (1, 4 and
  8 vCPUs in `tests/boot.rs`). It checks the frame API directly (a
  read-only page refuses a write; nothing lands after `unmap`), the Linux
  ABI over the shared page cache (`read`/`stat` into read-only pages
  return `EFAULT`, a private file mapping breaks copy-on-write, a second
  cell and the cache page keep their bytes), and a stress race of large
  `read`s against `munmap`/`mmap`/`mprotect`. Since the amendment,
  `mm_unlocked` checks that a copy into resident pages finishes while
  another task holds the `Mm` lock, and that one which needs faults
  waits for it; the stress race now runs with no lock between the reader
  and the remapping thread.
