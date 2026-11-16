# Booting Ichor on a cloud VM

Status: the disk image boots in QEMU the way a cloud VM boots (UEFI
firmware, one GPT disk on NVMe, serial console), including with a blank
volume ahead of the boot disk, an 8 KiB NVMe transfer limit, and no
PIT. It has **not yet run on a real cloud**. This page is the runbook for
the first run.

## What a first boot shows

The kernel runs its self-tests and the busybox suite from the disk's root
partition, prints `ichor: boot complete; halting` on COM1, and halts (on a
VM without QEMU's debug-exit port it simply stops; terminate the instance).
Every line goes to the serial console, so read it there:

- the TSC source (`TSC ... MHz from cpuid 0x15 | hypervisor leaf | ACPI PM timer | PIT`)
- every NVMe controller found, and which one held the Ichor root
  (`GPT disk, Ichor root partition at sector ...`)
- NVMe command timeouts or error statuses, if any (opcode, queue, status)

The only network driver is virtio-net (milestone 5); cloud NICs (AWS ENA,
GCP gVNIC) come with milestone 8. On most cloud instance types the VM
therefore cannot be reached over the network, only through its serial
console.

## Build the images

```bash
cargo xtask disk-image --release --size-gib 1 --gcp
```

This writes `target/ichor-disk.img` (raw, 1 GiB, for AWS) and
`target/ichor-gcp.tar.gz` (`disk.raw` in a gzip'd GNU tar, for GCP). The
kernel command line is empty unless `--cmdline` is given; useful options:
`trace_errors` (log failing syscalls), `control=50051` (run the control
plane; its gRPC API stays local to the system cell unless
`control_publish=PORT` publishes it on the uplink, which must wait for
the API's authentication: no cloud boot publishes it before then) and
`dns=A.B.C.D` (its resolver; the cloud's, e.g. `169.254.169.253` on
AWS). The disk's ESP carries the pinned CA bundle as
`\ichor\roots.pem`.

## AWS (Nitro instances: NVMe boot volume, COM1 serial console)

Check each command against the current AWS documentation; flags change.

1. Upload: `aws s3 cp target/ichor-disk.img s3://BUCKET/ichor-disk.img`
2. Import a snapshot (needs the `vmimport` service role):
   `aws ec2 import-snapshot --disk-container "Format=RAW,UserBucket={S3Bucket=BUCKET,S3Key=ichor-disk.img}"`,
   then poll `aws ec2 describe-import-snapshot-tasks` for the snapshot id.
3. Register a UEFI image:
   `aws ec2 register-image --name ichor --architecture x86_64 --boot-mode uefi --ena-support --root-device-name /dev/xvda --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=snap-...}"`
4. Launch a small Nitro instance (for example `m6i.large`) from the AMI.
5. Read the console: `aws ec2 get-console-output --instance-id i-... --latest`,
   or the EC2 serial console (interactive; must be enabled for the
   account).

## GCP (C3 or other NVMe-only machine types)

1. Upload: `gcloud storage cp target/ichor-gcp.tar.gz gs://BUCKET/`
2. Create the image:
   `gcloud compute images create ichor --source-uri gs://BUCKET/ichor-gcp.tar.gz --guest-os-features UEFI_COMPATIBLE`
3. Launch on a machine type whose disks are NVMe (C3, for example):
   `gcloud compute instances create ichor-1 --image ichor --machine-type c3-standard-4`
4. Read the console: `gcloud compute instances get-serial-port-output ichor-1`

## Not supported yet

- Azure (Hyper-V VMBus storage), and GCP machine types that boot from
  virtio-scsi.
- Networking of any kind (ENA, gVNIC, virtio-net).
- Secure Boot: launch with it off (the default for custom AWS AMIs; on
  GCP, without Shielded VM Secure Boot).
