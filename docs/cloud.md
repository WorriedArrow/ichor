# Booting Ichor on a cloud VM

Status: the disk image boots in QEMU the way a cloud VM boots (UEFI
firmware, one GPT disk on NVMe, serial console), including with a blank
volume ahead of the boot disk, an 8 KiB NVMe transfer limit, and no
PIT. It **has run on Google Cloud** (2026-11-22, below), and on no other
cloud yet. This page is the runbook.

## Runs so far

**Google Cloud, 2026-11-22**, an `e2-standard-4` (4 vCPUs, 16 GB, a CPU without
enhanced IBRS) in us-central1-a, from the image of
`disk-image --release --size-gib 1 --gcp --cmdline "metadata=gcp
control=50051 control_publish=50051"` with a token and a certificate. It
boots in seconds; every self-test passes; page-table isolation, VERW, IBPB
and IBRS on entry are on. The uplink is GCP's virtio-net with a /32 DHCP
lease (renewed after half an hour) and its 1460 MTU, the metadata service
gave the instance's `ichor` attribute, and the root partition was found,
verified and read on the virtio-scsi persistent disk. Over the API, from
outside: Alpine 3.20 pulled from Docker Hub in 1.5 s (the 122 MiB
`python:3.12-slim` in 9.9 s) and run; Python fetched over HTTPS, nginx
served, Go compiled and ran a program, and (without and with IBRS on entry)
redis-benchmark made 226,000 and 203,000 pipelined SETs a second and
pgbench 4,656 and 4,423 transactions (8 clients, files in memory).

What it found: GCP's virtio devices are legacy ones, which the drivers did
not speak (ADR-0005's amendment; tested in QEMU since); glibc's resolver
gave up in cells (it insists on `IP_RECVERR`); and kernel Spectre v2 was not
mitigated on such a CPU (IBRS on entry, ADR-0004's amendment, since). Still
open: stopping or deleting the machine takes GCP about two minutes, since
Ichor does not hear the ACPI power button, and a recreated machine may have
another external address (look before connecting).

## What a first boot shows

The kernel runs its self-tests and the busybox suite from the disk's root
partition, prints `ichor: boot complete; halting` on COM1, and halts (on a
VM without QEMU's debug-exit port it simply stops; terminate the instance).
Every line goes to the serial console, so read it there:

- the TSC source (`TSC ... MHz from cpuid 0x15 | hypervisor leaf | ACPI PM timer | PIT`)
- every NVMe controller found, and which one held the Ichor root
  (`GPT disk, Ichor root partition at sector ...`)
- NVMe command timeouts or error statuses, if any (opcode, queue, status)

The network drivers are virtio-net (modern and legacy) and Intel gigabit
Ethernet (82574L, and the 82576/I350/I210 family, for bare metal); cloud
NICs (AWS ENA, GCP gVNIC) come with milestone 8. Machines with those alone
can be reached only through their serial console.

## Build the images

```bash
cargo xtask disk-image --release --size-gib 1 --gcp
```

This writes `target/ichor-disk.img` (raw, 1 GiB, for AWS) and
`target/ichor-gcp.tar.gz` (`disk.raw` in a gzip'd GNU tar, for GCP). The
kernel command line is empty unless `--cmdline` is given; useful options:
`trace_errors` (log failing syscalls), `control=50051` (run the control
plane; its gRPC API stays local to the system cell unless
`control_publish=PORT` publishes it on the uplink, which also needs a
token and a certificate, below) and `dns=A.B.C.D` (its resolver; the
cloud's, e.g. `169.254.169.253` on AWS). The disk's ESP carries the
pinned CA bundle as `\ichor\roots.pem`.

To publish the API, make a token and an Ed25519 certificate (here under a
CA of your own; name it what clients will check) and put both on the disk:

```bash
openssl rand -hex 32 > api-token
openssl req -x509 -newkey ed25519 -nodes -days 365 -subj "/CN=ichor CA" \
  -addext keyUsage=critical,keyCertSign -keyout ca-key.pem -out ca.pem
openssl req -newkey ed25519 -nodes -subj /CN=ichor -keyout api-key.pem -out api.csr
printf '%s\n' basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature \
  extendedKeyUsage=serverAuth subjectAltName=DNS:ichor.example > api.ext
openssl x509 -req -in api.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 365 -extfile api.ext -out api-cert.pem
cat api-cert.pem api-key.pem > api-tls.pem
cargo xtask disk-image --release --cmdline "control=50051 control_publish=50051" \
  --api-token-file api-token --api-tls-file api-tls.pem
```

Clients connect with gRPC over TLS 1.3 to the uplink's port 50051, trust
`ca.pem`, expect the name `ichor.example`, and send `authorization: Bearer
<token>` with every call; `cargo xtask api` is one:

```bash
cargo xtask api ADDRESS:50051 --name ichor.example --ca ca.pem \
  --token-file api-token docker.io/library/alpine:3.20 -- uname -a
```

The key and the token are on the disk unencrypted: whoever can read the
image has them.

### Configuration from the cloud

One image can serve many machines: with `metadata=gcp`, `aws`, `azure` or
`auto` on its command line, the kernel asks the cloud's metadata service
for the machine's configuration once, at boot, and puts no secret on the
disk. The configuration is the instance attribute `ichor` on GCP, and the
user data on AWS (IMDSv2) and Azure:

```text
# what this machine is for
control=50051 control_publish=50051
api-token = 6f1d...
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

`control*` and `dns` options, the token and the certificate are read; a
script (`#!`) has none of them. What the boot volume says goes over it.
Whoever may change a machine's metadata can so take its API; whoever may
read it has its secrets. Cells cannot reach the service (ADR-0010's
amendment).

This is tested against the host playing AWS
(`a_machine_is_configured_by_its_clouds_metadata_service`), and GCP's has
answered for real; Azure's answers only in host tests.

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

## GCP

Two kinds of machine type work. The general-purpose ones (E2, N1, N2,
N2D) attach persistent disks as targets of a virtio-scsi controller and,
unless gVNIC is asked for, give the VM a virtio-net NIC: both have Ichor
drivers, so these are the ones that can network. The uplink takes its
address, router and DNS server from the VPC's DHCP server (the boot log
shows `ichor: net: DHCP lease ...`), and the control plane resolves
through that DNS server unless `dns=` says otherwise. The uplink renews
the lease at half its time. GCP's VPC
MTU is 1460 by default: the lease says so, and the uplink clamps every
TCP SYN crossing it to an MSS of 1420 (`uplink_mtu=N` overrides).
The newer ones (C3, C4, ...) boot from NVMe and require gVNIC, which
Ichor does not drive yet: boot-only. Check the machine types' disk
interfaces and NIC types against current GCP documentation.

1. Upload: `gcloud storage cp target/ichor-gcp.tar.gz gs://BUCKET/`
   (into a private bucket: the archive has the token and the key)
2. Create the image:
   `gcloud compute images create ichor --source-uri gs://BUCKET/ichor-gcp.tar.gz --guest-os-features UEFI_COMPATIBLE`
3. Launch, for example on a general-purpose type with a virtio-net NIC, with
   no credentials of the project's and an end set to what it costs:
   `gcloud compute instances create ichor-1 --image ichor --machine-type e2-standard-4 --network-interface nic-type=VIRTIO_NET --tags ichor --no-service-account --no-scopes --no-shielded-secure-boot --max-run-duration 2h --instance-termination-action DELETE`,
   or boot-only on NVMe: `--machine-type c3-standard-4`.
4. Read the console: `gcloud compute instances get-serial-port-output ichor-1`
5. Let the API in, from where you are alone:
   `gcloud compute firewall-rules create ichor-api --allow tcp:50051 --source-ranges YOUR.ADDRESS/32 --target-tags ichor`

`cloud_disk_boots_from_virtio_scsi` boots the disk under OVMF from a
virtio-scsi controller (a blank disk on target 0, Ichor's on target 2)
with no NVMe at all, and `cloud_disk_boots_on_legacy_virtio_devices` on
legacy devices alone, as GCP's are.

## Not supported yet

- Azure (Hyper-V VMBus storage and network).
- Cloud NICs other than virtio-net (AWS ENA, GCP gVNIC).
- Secure Boot: launch with it off (the default for custom AWS AMIs; on
  GCP, without Shielded VM Secure Boot).
