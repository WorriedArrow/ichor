# ADR-0016: Hyper-V guests: VMBus, its disks and its network

- Status: Accepted
- Date: 2026-11-22
- Refines: ADR-0005. Amends: ADR-0001 §8 (frame budget)
- Milestone: 8 (Azure)

## Context

Azure is Hyper-V. A generation 2 virtual machine there has no PCI disk
controller and no PCI network device: both are channels of VMBus, a message
protocol over the hypervisor's own interface (hypercalls and the synthetic
interrupt controller, SynIC), with rings in guest memory for the data.

The protocols' facts are taken from Microsoft's published hypervisor
interface (the TLFS) and the definitions in OpenVMM, Microsoft's own virtual
machine monitor, which is MIT licensed. Linux's drivers are GPL and were not
used.

## Decision

### Frame (`frame::hyperv`)

Frame does what takes privilege, and knows nothing of VMBus:

- it recognizes the hypervisor (CPUID `Hv#1`), tells it who the guest is,
  and has it put its hypercall page in a page of frame's, mapped executable
  and read-only;
- it gives the SynIC of the boot CPU its message and event pages and one
  interrupt source, whose interrupt does nothing but wake the CPU (drivers
  poll, as all of Ichor's do);
- it offers three safe calls: post a message (`HvPostMessage`), signal an
  event (`HvSignalEvent`), take the next message. They name connections by
  number and carry bytes: none can make the hypervisor touch memory frame
  does not give it, but for what the *other end* of a connection makes of
  a message (next).

### DMA

VMBus messages and packets name guest pages by number: for a channel's rings
(GPADLs) and for a request's data. Whoever writes them can have the host
read and write any page, as whoever writes an NVMe submission can. So the
VMBus drivers are DMA-trusted (ADR-0005), with the same rule: page numbers
come from `DmaBuf`s alone (`DmaAddr::as_u64`), and a buffer a request named
outlives it (leaked if it times out).

### `kernel/vmbus`

A `no_std`, safe, host-tested crate without I/O:

- `client`: the connection's state: version negotiation (5.0 to 5.3),
  offers, GPADLs, channel opening: messages in, messages out;
- `ring`: the two rings of a channel and their packets (in-band, GPA
  direct, transfer pages, completions), over a trait for the memory;
- `storvsc`: SCSI requests and the set-up of the storage channel;
- `netvsc`: NVSP and RNDIS: the set-up of the network channel, and frames
  in and out.

What the host writes is untrusted input: every length and offset is
checked, and the parsers are fuzzed with the rest.

### `kernel/drivers/hyperv`

One driver crate over both: it connects, and gives the SCSI disks as
`BlockDevice`s (read-only, polled; the SCSI commands shared with
virtio-scsi) and the network as a `net::link::Link`.

## Alternatives considered

- **PCI passthrough (Azure's NVMe and MANA).** Newer machine types have
  them, reached through PCI buses that VMBus offers (vPCI): VMBus comes
  first in any case, and the older types have nothing else.
- **Generation 1 machines' emulated devices.** Azure's have an emulated IDE
  disk, but no emulated network.
- **Frame writing the page numbers itself**, as it does for virtio. There
  are four places in two protocols where they go (GPADLs, GPA-direct
  packets); it would bring both into the trusted base.

## Budget

Frame's audit step 10 is 6,600 code lines / 285 unsafe sites, within
ADR-0007's ceiling of 9,500 / 420.
