# Fixing frame's user-copy path

Branch `fix-user-copy`. Design decision: ADR-0011. Tests:
`kernel/ichor/src/copytest.rs`, asserted on 1, 4 and 8 vCPUs in
`tests/boot.rs`.

## Root cause

`VmSpace::copy_to_user` and `copy_from_user` (in `kernel/frame/src/mm/vmspace.rs`) went
through a helper, `walk_user`, that did this for each page:

```rust
let Some((pa, _prot)) = self.translate(page) else { break };  // takes and drops the lock
...
f(done, pa, poff, chunk)  // copies through the linear map, lock not held
```

It had two defects.

1. **The write permission was ignored.** `_prot` was never looked at, so
   `copy_to_user` wrote through read-only PTEs, which the CPU would have
   refused a user store. The doc comment claimed the check happened. The
   kernel's `Mm::populate` ran before each copy and broke copy-on-write
   for pages the region allows writing. But it stops at the first page the
   region does not allow writing, and the copy then carried on regardless.
   The case that matters is a `PROT_READ` private mapping of a file on a
   shared image. Its pages are the page cache's own physical pages, mapped
   read-only into every cell that uses the image. Once such a page has
   been touched (and so mapped), `read(fd, that_page, n)` went:
   `populate` (the region refuses the write, so it stops), then
   `copy_to_user` (writes into the cache page). Every other cell mapping
   that file, and every later read of it, saw the new bytes. A buffer that
   starts in a writable page and runs into a read-only one was written
   past the boundary in the same way. `stat`, `uname`, `getdents64`,
   `recvmsg` and the rest share the path.
2. **The copy ran after the lock was dropped.** Between `translate`
   returning and the copy, another CPU (or a preempting task on the same
   CPU) could `unmap` the page. `unmap` clears the PTE under the lock,
   shoots down the TLBs and drops the page's mapping reference. The
   shootdown does not help, because the copy goes through the linear map,
   not the user mapping. The page could therefore be freed and reused
   while the copy was still writing into it.

   Through the Linux ABI this is not reachable today: every syscall copy
   and every `munmap` hold the process's `Mm` mutex. Frame's API, though,
   is meant to be sound for any safe caller (ADR-0001), and Phase E's
   "Mm lock not held across whole user copies" item would have removed
   that serialization. The frame-level test below shows the race through
   frame's API, without the `Mm` lock.

## Design choice

ADR-0011 has the full reasoning. In short, frame keeps copying through
the linear map, and does it correctly:

- **`VmSpace::copy_user`** takes the space lock for each page. It reads
  the PTE under the lock, stops if the page is not present or (for a
  write) not writable, copies at most to the page end, and only then drops
  the lock. `map`, `unmap_range` and `protect` change PTEs only under that
  lock, and the mapping reference is dropped only after the PTE is
  cleared. So the page stays mapped, with the permissions just checked,
  for the whole copy: it cannot be freed mid-copy, and nothing lands in it
  after `unmap` returns. The lock is held for at most one 4 KiB copy.
- **`Mm::copy_to_user` and `Mm::copy_from_user`** in the kernel replace
  "populate, then copy". When frame stops, they run the ordinary fault
  handler (`Mm::fault`: region check, demand paging, breaking
  copy-on-write) at that page, as a user access would, and copy on. A page
  is faulted at most once in a row, so the loop always ends. A page the
  process may not write ends the copy, and the syscall returns `EFAULT` or
  a short count. `LinuxProcess::copy_*` and the loader use these.

The hardware-enforced design (STAC/CLAC with an exception-fixup table) was
considered and deferred. It only reaches the space loaded in CR3, but the
kernel also writes into spaces that are not running (the loader's stack
setup, `CLONE_CHILD_SETTID` into a forked child), so frame would carry two
copy paths. Its fault fixup could not run the kernel's copy-on-write
policy anyway (that sits behind a sleeping lock the syscall already
holds), so it would need the same retry loop. And it costs roughly 150
lines and 10 unsafe sites in the TCB. The ADR says when to revisit it.

Frame changes: +3 code lines and +1 unsafe site (see "Budget" below). No budget change is needed. All new unsafe code is in
`kernel/frame`, and each `unsafe` block's `// SAFETY:` comment states the
invariant it relies on.

### A second bug the stress test found

With 2,000 rounds the stress test killed its own process with SIGSEGV.
The main thread touched its freshly mapped buffer. Between that hardware
fault and its handler taking the `Mm` lock, the other thread's `pread`
had already faulted the same page in. `Mm::fault` then found the page
present and treated that as a protection violation ("never loop on it").
Two threads faulting the same page at once is legitimate. The fault
handler now retries the access when the present PTE already allows it,
as Linux does. The CPU drops the faulting translation on `#PF`, so the
retry cannot loop. A present page that does not allow the access is still
a SIGSEGV. The bug predates this branch: the old `populate` maps pages for
the copying thread in exactly the same way.

## Tests

All tests are in `copytest.rs` and run on every boot.

| Test | What it checks |
|---|---|
| `frame_race`, part 1 | Frame API directly: `copy_to_user` into a page mapped read-only copies 0 bytes and leaves it unchanged; `copy_from_user` still reads it. |
| `frame_race`, part 2 | A kernel thread runs `copy_to_user` into a page in a loop, writing a different byte each pass. 32 times, this thread maps a fresh page there, pauses, unmaps it, pauses, and checks that the page did not change after `unmap` returned. A pause is a yield (so a writer queued on the same CPU runs, often until preempted mid-copy) plus, with several CPUs, a 200 µs spin. The test fails if the writer never reached a mapped page, so it cannot pass vacuously. No `Mm` lock is involved. |
| `copy_program` (cell A) | On the root disk, whose file pages come from the shared page cache: `read()` and `stat()` into a touched `PROT_READ` private mapping of `/usr/share/pattern` return `EFAULT` and leave it alone; `pread()` into a `PROT_READ\|PROT_WRITE` private mapping of the same page succeeds, shows the new bytes, and leaves the read-only mapping of that page unchanged; a read-only anonymous page refuses too; a buffer running from a writable page into a read-only one gets a short read that stops at the boundary. |
| `reader_program` (cell B) | A second cell maps the same file read-only and reads the original bytes. |
| cache check | Before and after: pages 0-15 of the file in the page cache are the same physical pages and hold the file's bytes, compared byte for byte against `pattern_byte`. |
| `stress_program` | One thread `pread`s 64 KiB into a buffer over and over, while the other cycles the buffer 600+ times through munmap, fresh anonymous memory (touched), a read-only private mapping of the file (cache pages, touched), and `mprotect` of that to read-write. It keeps going until at least 300 reads ran. Every read must return 0..=64 KiB or `EFAULT`. `run_linux`'s "memory returned" check runs at the end, and so does the cache check. |

### Against the unfixed kernel

The tests were run on the unfixed frame first (`kernel/frame/src/mm/vmspace.rs`
from `4617b81`), with the failures turned into prints for that run so
every test reported (TCG):

```
ichor: usercopy: copy_to_user wrote 64 bytes through a read-only PTE
ichor: usercopy: 30 of 32 pages were written after unmap returned      (smp 1; 27 on smp 4, 29 on smp 8)
ichor: usercopy: copytest exit 1 (failed check), other cell exit 1, page cache intact: false
TEMP-UNFIXED: usercopy: the stress test changed the page cache
...
ichor: runtest FAILED: /usr/share/pattern corrupted
```

`frame_race` caught the late writes on every unfixed run: 183/200 and
179-180/200 in its first, slower form (three yields a round), then 35-61
of 64 over five runs, then the counts above for the final 32 rounds. The
Linux-level lines are from `--smp 1` and `--smp 4` runs; the stress
result is from its 400-round form.

- Check 1 of `copy_program` failed: `read()` into the read-only mapping
  returned 16, not `EFAULT`.
- The second cell read the bytes cell A's `read()` had written.
- The page-cache page itself was changed.
- The stress test corrupted the cache too. A later, unrelated check (the
  NVMe disk's pattern file, which shares those cache pages) then failed
  the boot.
- The writable-private case (checks 5-8) passes on the old code as well,
  because `populate` breaks copy-on-write when the region allows writing.
  The copy-on-write failure is the read-only case, where nothing broke
  the share and the write went straight to the shared page.

### With the fix

`cargo xtask run --cmdline qemu_debug_exit` on 1, 4 and 8 vCPUs (TCG):
every check passes, the stress program makes about 3,000 syscalls, all
memory is returned, and the boot completes (Alpine, Debian `apt-get`,
network tests included). Measured with a 64-round `frame_race`, the tests
took 1.0-1.2 s of guest time per boot on 4 or 8 vCPUs and 3.4 s on one.
`frame_race` dominated, because its yields wait out the writer's time
slice; the final 32 rounds halve its share. `cargo xtask lint` passes on
every commit of the branch.

### Test runs

`cargo xtask test` (TCG, 11 QEMU boots in parallel on a 12-thread host)
passes on the final branch: 11 of 11 boot tests and all host tests.
Earlier runs, recorded here because they shaped the tests:

- **First run, 2,000-round stress and 200-round `frame_race`:** 2 of 11
  failed, in parts this branch does not touch. Alpine's `kill -pgid` test
  found "152 pages still charged", and Debian's perl socket client exited
  13 (its `sysread` returned an error). Both tests passed twice when rerun
  on their own.
- **Second run, same branch, with another session's QEMU guests using the
  host:** 5 boots hit the 120 s boot timeout. The new tests passed in all
  of them, but they made each boot about 3-9 s longer, which used up the
  slack under that load. The base commit `4617b81` passed the whole suite
  in a run just before. This is why the stress program went from 2,000
  rounds to 600 and `frame_race` from 200 rounds with three yields each
  to 32 rounds with two pauses.
- **Debian socket failure:** it showed up once more in a single
  one-vCPU boot while the host was fully loaded. In twelve one-vCPU boots
  alternating base and branch (six each), it never recurred on either. I
  found no way this change could cause it. The only behavioral change
  for a well-formed address space is that kernel writes now fail where a
  user store would, and `umem` maps no page read-only in a writable region
  outside the copy-on-write set (checked: `fork`, `map_cow`, `fault`,
  `mprotect`, `mremap`, the loader). The client now prints its errno
  before exiting 13 (`debiantest.rs`), so a recurrence will name the
  error.

## Budget

`cargo xtask frame-audit`: 5,611 code lines and 244 unsafe sites after the
fix, against 5,608 / 243 before (budget 5,800 / 250).

## Not covered

- No KVM run here (Windows, TCG only), so there are no new benchmark
  numbers. The per-page cost is unchanged in kind: one lock and one walk
  per page, as `translate` already did. The lock is now held across the
  copy as well.
- The Phase E "Mm lock not held across whole user copies" item is now
  unblocked but not done. When it lands, the stress test and
  `frame_race` are the guards. (Since done: see ADR-0011's amendment,
  "Copies without the Mm lock".)
