# ADR-0005: Device I/O in frame, and the milestone 3 budget

- Status: Accepted
- Date: 2026-11-15
- Refines: ADR-0001 §4.6. Amends: ADR-0001 §8 (frame budget)

## Context

Milestone 3 needs block devices: virtio-blk first, then NVMe. Drivers are
`#![forbid(unsafe_code)]` (ADR-0001 §1), so frame must provide device access
that a buggy driver cannot use to corrupt memory. Three hazards matter:

1. **Mapping the wrong physical range.** A driver that can map arbitrary
   physical memory as MMIO can alias RAM.
2. **Forged DMA addresses.** A driver that writes a raw integer into a
   descriptor makes the device read or write arbitrary memory. Without an
   IOMMU, nothing in hardware stops that (asterinas#3905).
3. **DMA after free.** If the driver frees a buffer while the device still
   owns it, the device writes into memory that has been reused.

## Decision

### PCI (`frame::bus::pci`)

- Frame enumerates PCI at boot and owns configuration space. Milestone 3
  uses the legacy 0xCF8/0xCFC mechanism; ECAM through the ACPI MCFG table
  replaces it when a device needs extended configuration space.
- Frame sizes each BAR itself during enumeration, with memory decode
  disabled while probing.
- Drivers get a `PciDevice` with config-space *reads*, capability-list
  iteration, and BAR descriptions, but **no raw config writes**. The one
  mediated write is `enable(memory, bus_master)`. MSI/MSI-X programming will
  be a frame call too, when interrupts replace polling.

### MMIO (`frame::io::IoMem`)

- An `IoMem` comes only from `PciDevice::map_bar`. Frame checks the BAR's
  physical range against the firmware memory map and refuses any overlap
  with RAM. Each BAR can be mapped once.
- The mapping is uncached, in a kernel MMIO window at
  `0xffff_d000_0000_0000`.
- Accessors are bounds-checked volatile reads and writes of 8–64 bits. A
  driver can only touch its own device's registers.

### DMA (`frame::dma`)

- `DmaBuf` is a reference-counted run of physically contiguous untyped
  pages. The CPU accesses it only by copying (`read`, `write`), as with
  `UFrame`.
- `DmaAddr` is opaque: it is obtained only from `DmaBuf::dma_addr(offset)`
  and has no constructor from an integer. `as_u64()` exists for ring formats
  frame does not own (NVMe), and review should flag it there.
- Without an IOMMU the bus address is the physical address; with one,
  frame will program it at this same point.

### Virtqueues (`frame::virtio::VirtQueue`)

- Frame owns the split-ring memory (descriptor table, available ring, used
  ring) and **writes every descriptor itself**, from `DmaBuf`s the driver
  passes in. A virtio driver never handles an address at all, which closes
  hazard 2 for virtio devices even without an IOMMU (ADR-0001 §4.6 item 3).
- A submitted chain holds clones of its buffers until the device returns it
  in the used ring, so a driver dropping its handle early cannot cause DMA
  after free (hazard 3).
- Queue memory is never freed: a device may hold its addresses until it is
  reset, and devices live for the life of the system in this milestone.

### Drivers and the block layer

- Drivers live in `kernel/drivers/*` as safe crates over these types.
  `kernel/block` defines the `BlockDevice` trait.
- Milestone 3 uses polled completion. Interrupts (MSI-X) and per-CPU queues
  arrive with NVMe.

### Remaining trust

The device itself is trusted not to DMA outside the buffers it was given,
until frame programs an IOMMU (ADR-0001 §4.6). In QEMU and on clouds the
"device" is the hypervisor's emulation.

### Budget

The milestone 3 ceiling is **8,500 code lines and 380 unsafe sites**, which
supersedes ADR-0003's milestone 2 ceiling. Expected additions:

| Area | Lines / sites |
|---|---:|
| PCI enumeration and BAR sizing | 250 / 12 |
| `IoMem` mapping and accessors | 200 / 15 |
| `DmaBuf` and `DmaAddr` | 150 / 6 |
| `VirtQueue` | 300 / 4 |

## Consequences

- virtio-blk and virtio-net drivers contain no unsafe code and cannot forge
  DMA addresses. NVMe and the cloud NICs still write addresses into
  device-owned rings through `DmaAddr::as_u64()`. Those drivers stay on the
  DMA-trusted list until an IOMMU or a frame-owned ring format covers them.
- Frame grows by roughly 900 lines for device I/O.
