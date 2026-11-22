# ADR-0006: The cell root file system and the volume format

- Status: Accepted
- Date: 2026-11-15
- Refines: ADR-0002 §6 (a cell's root is an `Image` plus a copy-on-write
  upper layer backed by a `Volume` or by memory)

## Context

A container's root file system is its image's layers plus private writes.
On Linux that is overlayfs over a directory per layer. Ichor already has a
read-only, content-addressed image format (`kernel/image`) whose pages can
be shared between cells. Writes need somewhere to go. Containers also need
persistent volumes: block devices the control plane attaches (cloud disks
over NVMe or virtio-blk) that outlive the container and that operators
expect to inspect with ordinary Linux tools.

Two decisions are expensive to reverse:

1. how a cell's writable root is built on top of the image, and
2. the on-disk format of persistent volumes.

## Decision

### Root: image plus a copy-on-write upper layer, inode-based

A cell's root is one `Overlay` (`kernel/overlay`, host-tested, no unsafe):

- **One inode table.** Lower (image) files and directories become inodes
  lazily, when a lookup first reaches them. After that, the upper directory
  entry names that inode. This keeps inode numbers stable and makes rename a
  move of one entry, including renames of whole lower directories. That is
  the case overlayfs handles with `redirect_dir`.
- **Copy-up on first write.** A lower file's bytes are copied into the upper
  layer on its first write or truncate. A truncate to zero skips the copy.
- **Whiteouts.** Removing a name that exists in the lower layer leaves a
  whiteout entry. The image itself is never modified, so many cells share
  one image and its page-cache pages.
- **Lifetime.** An inode is freed once it has no names and no open handles,
  so an open file outlives `unlink`.
- **Path resolution lives in the overlay too:** parent pointers for `..`,
  and symlinks with Linux's limit of 40 hops.

In milestone 3 the upper layer is memory, bounded by a per-root byte budget
(`ENOSPC`) and a per-file limit (`EFBIG`). Milestone 4, which runs multiple
cells, charges upper-layer bytes to the owning cell's account, the same way
memory pages are charged. A root may later put its upper layer on a
`Volume` instead (below), for containers whose writable layer must survive
a restart.

Hard links, extended attributes, and the timestamps and ownership a real
`chown` would set are out of milestone 3 scope. The overlay's inode model
admits them (`nlink` is already tracked) without a format change.

### Volumes: ext4

Persistent volumes are **ext4**:

- **Read/write.** The driver supports extents and 64-bit block numbers, plus
  `metadata_csum` and `flex_bg`, the defaults of current `mkfs.ext4`.
- **The journal is always honoured.** Mounting replays a dirty jbd2 journal
  before anything else. Writes go through the journal in `data=ordered`
  mode, Linux's default.
- **Refusal rules.** A volume with an unknown `incompat` feature is refused.
  One with an unknown `ro_compat` feature is mounted read-only. These are
  ext4's own compatibility rules.
- **Where the code lives.** The format logic is a host-testable crate
  (`kernel/ext4`), tested against images made by `mkfs.ext4` and checked
  with `e2fsck` in CI. It sits on the safe `BlockDevice` trait
  (`kernel/block`), so it contains no unsafe code.

`fsync` and `fdatasync` on a volume wait for the journal commit and a device
flush (virtio-blk `FLUSH`, NVMe `Flush`). On the memory-backed upper layer
they return immediately.

## Alternatives considered

- **overlayfs semantics with directory-per-layer upper storage.** Copying
  Linux's design would mean a second file system just to hold the upper
  layer, plus opaque directories and redirect xattrs to emulate the inode
  model we get for free. Rejected for the root. The external behaviour
  containers see (copy-up, whiteouts, rename) is the same.
- **A native Ichor volume format** (log-structured, content-addressed like
  the image). It is attractive for snapshots and dedup, but volumes must be
  readable by Linux tooling when an operator detaches a disk, and must
  interoperate with existing cloud disks and backups. It may come later as
  an opt-in volume type. ext4 stays the default.
- **XFS.** It has excellent large-file throughput, but a far larger format
  surface (B+trees everywhere, reflink, rmap). Its log format is also more
  complex to replay correctly. ext4 is the most widely deployed Linux file
  system and the default on the cloud images our users come from.
- **btrfs.** Its copy-on-write and snapshots overlap with what the image
  layer already provides. Its on-disk format is large and its repair
  tooling weaker. Rejected.
- **FAT or another minimal format.** It lacks permissions, symlinks and
  crash safety, so it cannot be a container volume. FAT stays the format of
  the ESP only.

## Consequences

- **Isolation.** The image is shared read-only by every cell that uses it.
  A cell's writes can never reach another cell's view or the image.
- **Memory pressure.** With a memory-backed upper layer, a container's
  writes are memory. That is the default Docker experience with tmpfs, but
  it means memory pressure from writes. Accounting this to the cell
  (milestone 4) is required before multi-tenant use.
- **The ext4 crate is a large, security-critical parser.** A volume can be
  attacker-controlled if a tenant can write raw blocks. So the crate must
  be fuzzed (milestone 5 fuzzing infrastructure) and must treat every
  on-disk field as untrusted. It is written in safe Rust, so the worst case
  is a wrong answer or an error, not memory corruption in the kernel.
- **Testing.** CI gains `e2fsprogs` for `mkfs.ext4` and `e2fsck`.

## Amendment (2026-11-21): charged pages, shared mappings, large images

- **A cell's writes are charged to the cell**, as this ADR required before
  multi-tenant use. The overlay takes its file pages from a source
  (`overlay::Pages`); the kernel's (`kernel/ichor/src/page.rs`) is a frame
  charged to the cell's account for as long as anything holds it, the same
  charged page process memory is made of. There is no separate budget: a
  root and the cell's processes share the cell's memory, as a container
  whose writable layer is tmpfs would. Full is ENOSPC, after a short write
  where part fits; `statfs` shows the account. A root no cell owns
  (self-tests) keeps a 64 MiB budget. Inodes, directory entries and
  metadata are kernel heap and not charged (partial).
- **Shared file mappings.** Since a file's pages are frames, `MAP_SHARED`
  maps them: mappings, `read` and `write` of a file (`/dev/shm` and
  `memfd_create` included) see one copy, across `fork` and processes. An
  image file is mapped from the page cache until somebody writes it
  through a mapping, which copies it up. Partial, because nothing records
  who maps a file page: a mapping that already touched an image page does
  not see another's later copy-up, nor one of a truncated-away page the
  file's growing again; and touching past the end is SIGSEGV, not SIGBUS.
- **Image format 4.** Metadata (names, nodes, and a 48-byte entry per
  chunk) was one contiguous buffer of at most 4 MiB, which Go's official
  image exceeds three times over. It is now read in 64 KiB segments, which
  table entries may straddle and names may not (the builder pads). The
  root hash is unchanged in meaning. Up to 64 MiB of metadata is accepted;
  it is kept in memory, charged to whoever handed the image in. Overlay
  inodes are boxed, so a root with many files needs no large table.
