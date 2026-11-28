# Architecture Decision Records

An ADR records a decision that would be expensive to reverse: the options
considered, the choice made, and the consequences. ADRs supersede the founding
brief where they conflict with it.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-kernel-architecture.md) | Kernel architecture and the frame crate's API surface | Accepted |
| [0002](0002-cells-and-capabilities.md) | Cell model and capabilities | Accepted |
| [0003](0003-frame-budget-milestone-2.md) | Frame growth for milestone 2 | Accepted |
| [0004](0004-side-channels.md) | Side-channel posture | Accepted |
| [0005](0005-device-io.md) | Device I/O in frame (PCI, IoMem, DMA, virtqueues) and the milestone 3 budget | Accepted |
| [0006](0006-root-and-volumes.md) | Cell root (image + copy-on-write upper layer) and ext4 volumes | Accepted |
| [0007](0007-milestone-4-frame.md) | Frame work for milestone 4 (shootdown, atomic user ops, PCID) and its budget | Accepted |
| [0008](0008-extended-cpu-state.md) | Extended CPU state: XSAVE, saved eagerly | Accepted |
| [0009](0009-identity-model.md) | Identity inside a cell: uids, what uid 0 means, enforcement | Accepted |
| [0010](0010-network-stack-and-cell-switch.md) | Network stack (own, sans-I/O, per cell) and the cell switch | Accepted |
| [0011](0011-user-copies.md) | Kernel copies to and from user memory: a checked walk under the space lock | Accepted |
| [0012](0012-control-plane.md) | The control plane: a native-ABI service, native ABI v2, our own TLS/HTTP/OCI crates | Accepted |
| [0013](0013-workloads-and-io-uring.md) | Milestone 7: io_uring, and real workloads' own test suites through the control plane | Accepted |
| [0014](0014-services-runtime-trusted-crate.md) | `services/rt`, the second crate allowed `unsafe`: scope, rules, budget | Accepted |
| [0015](0015-xapic.md) | Machines without x2APIC: the local APIC as an xAPIC | Accepted |
| [0016](0016-hyper-v.md) | Hyper-V guests: VMBus, its disks and its network | Accepted |
| [0017](0017-power-button.md) | The ACPI power button and soft off (S5) | Accepted |
| [0018](0018-kvmclock.md) | kvmclock is the clock on KVM | Accepted |
| [0019](0019-asynchronous-console.md) | Console writes do not wait for the serial port | Accepted |
| [0020](0020-huge-anonymous-pages.md) | 2 MiB pages for anonymous memory | Accepted |
| [0021](0021-cpu-time-from-the-scheduler.md) | CPU time comes from the scheduler | Accepted |
| [0022](0022-protection-keys.md) | Protection keys for user pages | Accepted |
| [0023](0023-amx-tile-data.md) | AMX tile data behind XFD | Accepted |
| [0024](0024-boot-time.md) | Boot time is measured, and four waits leave the boot path | Accepted |
| [0025](0025-pvh-boot.md) | Booting without firmware: the PVH entry (Firecracker) | Accepted |

## Planned

These are known decisions with deadlines, so a future session knows they are
owed:

- Read-only image format and page sharing (milestone 3)
- Secure Boot signing and measured boot (before milestone 8; needs signing keys from the owner)

## Writing one

Copy the structure of an existing ADR: Context, Decision, Alternatives
considered, Consequences. Number ADRs sequentially. To change an accepted ADR,
either amend it in place with a dated "Amended" line in the header (for
clarifications and pre-authorized steps), or write a new ADR that supersedes it
(for reversals).
