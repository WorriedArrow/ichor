# ADR-0020: 2 MiB pages for anonymous memory

- Status: Accepted
- Date: 2026-11-26
- Amends: ADR-0001 §8 (frame budget)
- Milestone: 7 (workloads), Phase E (scalability)

## Context

Every anonymous page Ichor gives a process is a 4 KiB page: one fault, one
allocation, one page-table entry and one TLB entry per 4 KiB. Fault-around
(64 KiB a fault, `umem::FAULT_AROUND`) cut the faults, not the rest. On GCP,
Debian 12 with transparent huge pages on faults anonymous memory in at 0.42
us a 4 KiB page on AMD against Ichor's 1.0-1.1 us (`docs/benchmarks.md`),
and large heaps (the JVM's, Go's, PostgreSQL's buffers) run with 512 times
the TLB entries Linux needs for them.

After the bookkeeping cuts of ADR-0008's 2026-11-25 amendment, a 4 KiB
fault-around page costs about 220 ns of allocation and zeroing plus about
70 ns of mapping and bookkeeping, and a fault for every 16 pages.

## Decision

### Frame

- `UFrame::alloc_zeroed_huge` allocates one aligned 2 MiB block (buddy
  order 9) and hands it out as 512 ordinary untyped pages, each with its own
  metadata, reference count and free (`page_alloc::alloc_pages`), zeroed
  with one `rep stosb`.
- `VmSpace::map_huge(va, frames, prot)` maps 512 such frames, which must be
  one aligned block in address order, at a 2 MiB-aligned address as one
  2 MiB page (a PS leaf in the page directory). Each page takes the mapping
  reference it would take if mapped alone, so frame keeps no other record of
  a 2 MiB page: teardown and unmaps drop 512 references, the mapped count
  rises by 512, and `translate` and the user copies (ADR-0011) see each 4
  KiB page of it as before.
- What changes part of a 2 MiB page (`unmap_range` short of all of it,
  `protect`, `write_protect`) first splits it: a new page table of 512 4 KiB
  leaves with the same pages, permissions and memory type replaces the
  leaf. Every translation stays what it was, so the split needs no TLB
  flush of its own; the operation's shootdown follows as before (`invlpg` of
  an address drops a 2 MiB TLB entry covering it), and until it completes
  another CPU may use the old permissions, as with a 4 KiB page.
- A split needs a page for the table. With none, the whole 2 MiB page is
  unmapped instead. Its owner keeps its pages and maps them again, 4 KiB at
  a time, when they fault; `map_huge`'s documentation says so. Ichor's `Mm`
  already works that way, since a page it holds may be unmapped
  (`PROT_NONE`) and faults map what it holds.
- A page table with nothing in it, where a 2 MiB page is to go, is replaced
  and freed after a full shootdown: a CPU may still hold it in its
  paging-structure caches.

### The kernel

- Only private anonymous memory takes 2 MiB pages, and only on a
  sequential fault (`va == next_anon`, the signal fault-around uses) whose
  aligned 2 MiB block lies wholly in the region and holds no page yet, with
  room for 512 pages in the cell's account and an order-9 block free in
  memory. Otherwise the fault takes a 4 KiB page as before. Fault-around
  stops at 2 MiB boundaries, so a sequential touch lands on one.
- `mmap` places private anonymous mappings whose length is a whole number
  of 2 MiB on a 2 MiB boundary (`RegionMap::find_free_aligned`), as recent
  Linux kernels do, so their blocks can take 2 MiB pages from the start.
- The `Mm` still tracks every 4 KiB page (`PageMap`, copy-on-write set,
  one charge each, made at once by `page::charged_all`). `fork` shares the
  pages as before: the child maps them 4 KiB at a time, and write-protecting
  the parent's splits its 2 MiB pages.

## Alternatives considered

- **Linux's THP "always"**: every first fault in an empty aligned block
  takes 2 MiB. A sparse touch (a 64 MiB Go arena, a thread stack, malloc's
  arenas) would charge a cell 2 MiB for each page it touches, and Linux
  needs khugepaged's collapse and a shrinker of underused huge pages to live
  with that. Sequential faults only bound the waste to the end of a touch
  that stops inside a block: less than 2 MiB a stream.
- **A compound 2 MiB page with one reference count**: one entry in the
  `Mm` and one charge instead of 512, but every operation on part of one
  (unmap, `mprotect`, copy-on-write) would need to split the page itself,
  which frame's metadata cannot express today. 512 references cost about 3
  us a 2 MiB page; the `Mm`'s 512 entries and charges about 30 us.
- **Copying a 2 MiB page on a copy-on-write fault after `fork`**: Linux
  splits there too.

## Consequences

- A sequential first touch of anonymous memory costs a fault per 2 MiB,
  and the block's TLB entry is one. Locally (OpenVMM on a Ryzen 5 5600X,
  the `bench` page-fault row: 4,112 pages, warm memory, four rounds in a
  boot): 261 ns a 4 KiB page against 455 ns with 4 KiB pages, under the
  same host load. About 225 ns of the 261 is zeroing (memory bandwidth). On
  memory the guest has never touched, both pay the host for backing it:
  693 ns against 1,088 ns and more in the first round.
- Frame grows by about 220 lines (to 7,607 / 304); audit step 17 is 7,650
  / 310.
- A 2 MiB page that a split could not divide is unmapped whole, and costs
  its owner up to 512 faults later. That happens only with no free page.
- Not yet: `MADV_HUGEPAGE` / `MADV_NOHUGEPAGE` (accepted as hints, changing
  nothing), collapsing 4 KiB pages into 2 MiB ones later (khugepaged), 2 MiB
  pages in a child after `fork`, file and shared memory, 1 GiB pages, and
  `AnonHugePages` in `/proc/meminfo`.

## Amendment (2026-11-27): one charge a 2 MiB page

Debian 13's Linux 7.3 took the page-fault row back on four machines in
benchmark round 18. Timed locally (OpenVMM, Zen 3, temporary counters in
`Mm::fault_huge`), a 2 MiB fault spent about 87 us clearing, 1.8 us
mapping, 10.5 us making the 512 charged pages (`page::charged_all`: an
`Arc<Charged>` from the heap and a clone of the account's `Arc` each) and
8 us entering them in the `Mm` one by one; the process's exit then took
26-40 ns a page (a heap free, the account's chain released and a buddy
free each).

- **A block is charged once.** `page::Block` holds the account's charge for
  the 512 pages and, for each page, how many address spaces hold it
  (`fork` shares them). The `Mm`'s entries are `page::Resident`: a page
  charged on its own (`Page`, as before) or a page of a block (`InBlock`:
  its own `UFrame` and a hold on the block). Each page still counts until
  its last holder lets it go, as before: what has gone is released by
  `Block::settle`, which `munmap`, `MADV_DONTNEED` and `MADV_FREE`
  (`free_range`), a copy-on-write copy, and an address space's end call
  (`page::Settle`, one block at a time in address order), and the rest when
  the block goes. Between those points a page whose last holder went (a
  process that ended while another still shares the block) may stay
  charged: never less than what is held.
- **Entered a chunk at a time**: `PageMap::extend` looks up each 64-page
  chunk once, not each page.
- Frame does not change. Clearing the block a 256 KiB piece at a time from
  its end, so its start, where a sequential touch goes on, stayed in the
  caches, was tried and was slower here (120-150 us a block against 84-86).

Locally: making the entries 0.2 us a block, entering them 3.2 us, the
exit 10-12 ns a page; the page-fault program's own timing over 16 MiB 184-188
ns a 4 KiB page against 221-226 ns before, and 187-194 ns over the 64 MiB
the benchmark now touches (Linux's size). `hugetest` checks the charge after
each step (sequential touch, partial `munmap`, writes on both sides of
`fork`, the child's end, `MADV_DONTNEED`).
