# Fuzzing Ichor's Linux ABI with syzkaller

syzkaller drives a Linux target over ssh: it copies `syz-executor` in, runs
it, and the executor makes the system calls syzkaller generates. Ichor runs
the executor in a cell, so what it fuzzes is Ichor's Linux personality, the
cell switch and the kernel under them. Since 2026-11-25 a manager runs
persistently on one of the owner's machines (a Debian 13 VM with nested
KVM, 6 vCPUs, 24 GiB; four Ichor instances of 2 vCPUs and 3 GiB). This page
is how to set one up again; the files are in `tools/syzkaller/`.

## How an Ichor target boots

- The boot disk is an ordinary `cargo xtask disk-image`, release, with
  `autorun=/sbin/ichor-autorun autorun_publish=22 autorun_mib=2048` on its
  command line. Its root partition is the test root; the boot runs its
  self-tests as always (seconds under KVM).
- A second, read-only disk is the autorun root: Alpine 3.20.3 with dropbear
  (`tools/syzkaller/autorun-root.sh`, then `cargo xtask root-image`). The
  kernel recognizes it by holding `/sbin/ichor-autorun`, gives it none of
  the disk checks (`ichor: blk: ...: the autorun disk; not checked`), and
  after the self-tests runs `/sbin/ichor-autorun` in a cell of its own
  (`autorun.rs`) with uplink port 22 published to it. syzkaller's QEMU
  forwards a host port to the guest's 22, so its ssh reaches dropbear in
  the cell; the executor reaches the manager back through ssh's reverse
  forward on the cell's loopback.
- syzkaller's QEMU backend: UEFI through `-bios OVMF.fd`, the boot disk as
  `if=virtio` (Ichor has no IDE or e1000), `virtio-net-pci`, `-snapshot`.
  `tools/syzkaller/ichor.cfg` is the manager's config.

## syzkaller changes

`tools/syzkaller/ichor.patch`, on syzkaller `9a575fe5` (2026-11-25):

- `pkg/vminfo/linux.go`: no `_stext`/`_etext` in `/proc/kallsyms` means no
  core-kernel module (there is no coverage to map without kcov).
- `pkg/report/linux.go`: `ichor: KERNEL PANIC: panicked at FILE:LINE` is a
  crash, titled `ichor panic in FILE:LINE`. Anything else that ends a
  machine shows as "lost connection to test machine", with its console log.
- `executor/common_linux.h`, sandbox `none`: where Ichor has no mount
  namespace (the tmpfs and bind mounts, `pivot_root`), no
  `/proc/self/ns/net` and no `capget`, the executor goes on in the cell's
  root instead of failing. A cell is already the namespace.

Without kcov there is no coverage: syzkaller still mutates and keeps a
corpus, but blindly. kcov for Ichor (per-thread coverage of kernel code
reached from a system call) is the step that would make it guided.

## Setting it up

On a Linux host with KVM (as the `syz` user, `sudo` allowed):

```bash
sudo apt-get install -y git make gcc g++ qemu-system-x86 qemu-utils ovmf curl
# Go from go.dev into /usr/local/go, then:
git clone https://github.com/google/syzkaller && cd syzkaller
git checkout 9a575fe511f5d38ab3d9b6977ffabb567c3927f0
git apply /path/to/ichor/tools/syzkaller/ichor.patch
make -j"$(nproc)"     # manager and executor from one tree: revisions must match
ssh-keygen -t ed25519 -N "" -f ~/syzkey
sudo bash /path/to/ichor/tools/syzkaller/autorun-root.sh ~/syzkey.pub
```

In the Ichor tree (any host):

```bash
cargo xtask disk-image --release --cmdline "autorun=/sbin/ichor-autorun autorun_publish=22 autorun_mib=2048"
cargo xtask root-image autorun-root.tar autorun.img
```

(On Windows' Git Bash, set `MSYS_NO_PATHCONV=1` for the first, or the
`/sbin/...` path is rewritten into a Windows one.) Copy `target/ichor-disk.img` and `autorun.img`
to `~/ichor/`, `tools/syzkaller/ichor.cfg` to `~/ichor.cfg`, and
`tools/syzkaller/syz-manager.service` to `/etc/systemd/system/`, then
`sudo systemctl enable --now syz-manager`. The dashboard is on port 56741;
crashes land in `~/workdir/crashes/`, the manager's log in `~/manager.log`.

To fuzz another Ichor version, rebuild the disk image, replace
`~/ichor/ichor-disk.img` and restart the service; the corpus stays.
