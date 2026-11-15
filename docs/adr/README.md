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

## Planned

These are known decisions with deadlines, so a future session knows they are
owed:

- Read-only image format and page sharing (milestone 3)
- Network stack architecture and the cell switch (milestone 5)
- Secure Boot signing and measured boot (before milestone 8; needs signing keys from the owner)

## Writing one

Copy the structure of an existing ADR: Context, Decision, Alternatives
considered, Consequences. Number ADRs sequentially. To change an accepted ADR,
either amend it in place with a dated "Amended" line in the header (for
clarifications and pre-authorized steps), or write a new ADR that supersedes it
(for reversals).
