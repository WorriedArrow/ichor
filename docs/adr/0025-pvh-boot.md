# ADR-0025: Booting without firmware: the PVH entry

- Status: Accepted
- Date: 2026-11-28
- Amends: ADR-0001 ("Boot", §8 frame budget)
- Milestone: 8 (clouds)

## Context

Ichor is a UEFI application (ADR-0001): firmware loads the PE image from
an EFI system partition, and frame's `efi_main` reads the memory map, the
ACPI RSDP and its files (`\ichor\cmdline`, `roots.pem`, `suffixes.dat`,
`apitoken`, `apitls.pem`) through boot services.

Firecracker, the VMM behind AWS Lambda and many microVM platforms, has no
firmware. It loads an ELF kernel's segments at their
physical addresses and enters it by the Linux boot protocol, or, if the
ELF carries a `XEN_ELFNOTE_PHYS32_ENTRY` note, by PVH (Firecracker 1.12
and later, and Firecracker prefers it): 32-bit protected mode, paging off,
`%ebx` at an `hvm_start_info` (Xen's `start_info.h`) naming the command
line, the modules (the initrd) and an E820-style memory map. Its ACPI
tables (MADT, FADT, DSDT, MCFG) sit below 1 MiB with the RSDP at 0xE0000;
with `--enable-pci` its virtio devices are modern virtio-pci, reached
through ports 0xCF8/0xCFC as well as ECAM. Cloud Hypervisor and QEMU's
`-kernel` boot PVH ELFs the same way.

Comparing Ichor's boot with Linux's under Firecracker
(`docs/benchmarks.md`) needs Ichor to boot there.

## Decision

- **The same image, two entries.** The kernel stays a PE. `xtask::pvh::elf`
  does what a UEFI loader does, at 16 MiB physical: headers and sections at
  their RVAs, the rest zero, DIR64 base relocations applied for that
  address. It wraps the result in an ELF with one `PT_LOAD` segment (the
  image, then a zeroed scratch area) and the PVH note. Frame's higher-half
  switch (`kspace`) then works unchanged: it sees an image loaded at some
  base, as under UEFI.
- **A 32-bit stub in frame** (`arch::pvh`), found by xtask by its
  signature, with a 16-byte header xtask fills (image base, image length,
  scratch address). It finds its own address with `call`/`pop` (32-bit code
  can have no base relocation: frame takes only DIR64), identity-maps the
  first 4 GiB with 2 MiB pages in the scratch area, enables PAE,
  OSFXSR/OSXMMEXCPT, long mode with NX, paging and WP, loads its own GDT and
  calls `boot::pvh::pvh_main` in 64-bit mode with the start info, the image
  region and the TSC it read first.
- **`pvh_main` fills the boot state UEFI would.** The command line is the
  loader's; the files are the first module, in a small format xtask writes
  (`ICHORBF1`, then name and length-prefixed files; `pvh-image` writes it as
  `target/pvh/bootfiles.img`, Firecracker's initrd). The RSDP is the start
  info's, else found in the BIOS area. The memory map becomes frame's
  regions: RAM usable (pages inward) but for the image; below 1 MiB, what
  is not RAM is ACPI's (Firecracker's tables live there); a reserved block
  starting where RAM ends is the firmware's (SeaBIOS's tables, under QEMU)
  and mapped but never allocated; other reserved blocks stay unmapped (they
  may be MMIO). Then it calls the same `boot::start` as `efi_main`, told the
  identity map ends at 4 GiB (the early allocator stays below it).
- **What PVH has no source for, Ichor does without:** no wall clock
  (`CLOCK_REALTIME` counts from boot, as before when `GetTime` fails), no
  firmware revision.
- **`a_pvh_loader_boots_the_kernel`** boots the ELF through QEMU's
  `-kernel` (SeaBIOS's PVH option ROM) on two CPUs, reaches the control
  plane, and checks the CA roots came through the module.

## Alternatives considered

- **A firmware for Firecracker** (rust-hypervisor-firmware gives PVH guests
  enough UEFI to start an EFI application): no frame change, but a second
  boot path's cost lands on Ichor's boot and not Linux's, which
  Firecracker starts directly, and the firmware is another TCB.
- **Building the kernel as an ELF as well** (a second target and linker
  script): two link layouts for frame to keep sound, and `kspace` would need
  an ELF reader beside the PE one. Laying the PE out in xtask keeps one
  binary and one loader path in frame.
- **The Linux 64-bit boot protocol** (`boot_params`, the zero page):
  Firecracker sets up page tables for it, but the protocol is Linux's own,
  and PVH is the one other kernels (FreeBSD, Xen guests) use.
- **Reading the wall clock from kvmclock** (`MSR_KVM_WALL_CLOCK_NEW`):
  owed, for TLS certificate checks under Firecracker; not needed to boot.

## Consequences

- Ichor boots under Firecracker, Cloud Hypervisor and QEMU `-kernel` from
  `cargo xtask pvh-image`: `target/pvh/ichor.elf` as the kernel,
  `target/pvh/bootfiles.img` as the initrd, the command line as the
  loader's.
- Every image carries the stub (about 150 bytes) and its header; under UEFI
  they are never run.
- Memory above 4 GiB is still used, through the linear map; only the
  early allocator, before the switch, keeps below the stub's identity map.
- Under PVH there is no wall clock until an NTP client steers one
  (`metadata=gcp` does; nothing does under Firecracker yet), so the control
  plane cannot check certificate dates there.
- Frame grows by about 340 lines and 2 unsafe sites (to 8,786 / 322);
  audit step 25 is 8,800 / 330.
