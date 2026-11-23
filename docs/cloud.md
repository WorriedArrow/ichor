# Booting Ichor on a cloud VM

Status: the disk image boots in QEMU the way a cloud VM boots (UEFI
firmware, one GPT disk on NVMe, serial console), including with a blank
volume ahead of the boot disk, an 8 KiB NVMe transfer limit, and no
PIT. It **has run on Google Cloud, Azure and AWS** (2026-11-22, below).
This page is the runbook.

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
mitigated on such a CPU (IBRS on entry, ADR-0004's amendment, since).
Stopping or deleting the machine took GCP about two minutes (AWS several),
since Ichor did not hear the ACPI power button. It does now (ADR-0017) and
turns itself off (S5), tested in QEMU (`system_powerdown`) but not yet on
either cloud. A recreated machine may have another external address (look
before connecting).

**AWS, 2026-11-22**, an `m7i-flex.large` (2 vCPUs, 8 GiB; Sapphire
Rapids with enhanced IBRS, the first such CPU Ichor has met: eIBRS with
BHI_DIS_S, VERW and IBPB on, page-table isolation not needed) in
us-east-2, from the image of `disk-image --release --size-gib 1 --cmdline
metadata=aws` with a token and a certificate on the disk, and the user
data `control=50051 control_publish=50051`, read over IMDSv2. The root is
the EBS volume on NVMe; the uplink is the ENA (`kernel/drivers/ena`),
transmitting through a low-latency queue in device memory, with the VPC's
DHCP lease (its 9001 MTU taken as 1500). Over the API, from outside:
Alpine 3.20 pulled in 0.7 s and run (its `wget` reached the internet
through the cell switch's NAT), and redis-benchmark made 65,000 SETs and
60,000 GETs a second (unpipelined) in a cell.

What it found: the firmware leaves the ENA's BARs at 0, inside a bridge
whose windows are set, so frame now places such BARs itself (ADR-0005's
second amendment); and the ENA refuses to create completion queues
(status 6, "unknown error") unless the driver's host information says
Linux and a driver version it accepts (`ena::host_info`). Iterating took
about four minutes a round: an image built here, uploaded to CloudShell
(3 MB gzip'd), written to a snapshot with the EBS direct APIs, registered
and booted (below).

## What a first boot shows

The kernel runs its self-tests and the busybox suite from the disk's root
partition, prints `ichor: boot complete; halting` on COM1, and halts (on a
VM without QEMU's debug-exit port it simply stops; terminate the instance).
A running machine turns itself off when its ACPI power button is pressed,
which is what a cloud's stop does (`ichor: power button pressed: turning
off`; not on Azure, whose machines have no such button).
Every line goes to the serial console, so read it there:

- the TSC source (`TSC ... MHz from cpuid 0x15 | hypervisor leaf | ACPI PM timer | PIT`)
- every NVMe controller found, and which one held the Ichor root
  (`GPT disk, Ichor root partition at sector ...`)
- NVMe command timeouts or error statuses, if any (opcode, queue, status)

The network drivers are virtio-net (modern and legacy) and Intel gigabit
Ethernet (82574L, and the 82576/I350/I210 family, for bare metal); cloud
NICs: Hyper-V's (VMBus) and AWS's ENA have drivers; GCP's gVNIC does not,
so a machine with only that can be reached only through its serial
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

What worked (2026-11-22, from AWS CloudShell; no S3 bucket and no import
role needed):

1. `cargo xtask disk-image --release --size-gib 1 --cmdline metadata=aws
   --api-token-file ... --api-tls-file ...`, then `gzip -c
   target/ichor-disk.img > ichor.img.gz` (about 3 MB) and upload that to
   CloudShell.
2. Write it to a snapshot with the EBS direct APIs and register a UEFI AMI
   on it. A short boto3 script does both: `start_snapshot` (1 GiB),
   `put_snapshot_block` for each 512 KiB block that is not all zeros
   (about 15), with its SHA-256, `complete_snapshot`, wait for
   `snapshot_completed`, then `register_image(Architecture="x86_64",
   BootMode="uefi", EnaSupport=True, ImdsSupport="v2.0",
   RootDeviceName="/dev/xvda", BlockDeviceMappings=[{"DeviceName":
   "/dev/xvda", "Ebs": {"SnapshotId": ..., "VolumeType": "gp3"}}])`. About
   a minute and a half.
3. A security group with only TCP 50051 from the client's address, and
   `aws ec2 run-instances --image-id ami-... --instance-type
   m7i-flex.large --security-group-ids sg-... --user-data file://ud.txt
   --metadata-options HttpTokens=required,HttpEndpoint=enabled`, where
   `ud.txt` holds `control=50051 control_publish=50051`.
4. About 90 s later, `aws ec2 get-console-output --instance-id i-...
   --latest --output text` has the boot log; then `cargo xtask api
   PUBLIC_IP:50051 --name ... --ca ... --token-file ... IMAGE -- CMD`.
5. Afterwards: terminate the instance, deregister the AMIs, delete their
   snapshots and the security group.

`aws ec2 import-snapshot` from S3 (with the `vmimport` role) also takes a
raw image, more slowly.

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

## Azure (generation 2 machines)

The disk and the network are VMBus channels, which Ichor drives (ADR-0016).
The newest types (v6, v7) reach their NVMe disks and MANA network through
PCI over VMBus, which Ichor does not drive yet: use v5 or older.

**Run on 2026-11-22**: a `Standard_D4s_v5` (4 vCPUs, 16 GB) in Central US,
from a disk made of the VHD. VMBus 5.3 with 12 channels, the network's DHCP
lease from 168.63.129.16, the root found and verified on the VMBus SCSI
disk; over the API (from Cloud Shell) Alpine, Python (HTTPS) and
redis-benchmark (424,000 pipelined SETs a second) ran. The CPU Azure shows
there enumerates neither `IA32_SPEC_CTRL` nor MD_CLEAR while reporting TAA,
so Ichor reports VERW and IBRS as unavailable: to look into.

A new pay-as-you-go subscription had quota only for sizes Azure would not
place (v4: `SkuNotAvailable` in East US 2 and Central US, every zone) and
none for those it would (v5); a request for 4 vCPUs of the DSv5 family
(`az quota create`) was granted at once.

Check the commands against current documentation.

1. `cargo xtask disk-image --release --azure --cmdline "control=50051
   control_publish=50051" --api-token-file ... --api-tls-file ...` writes
   `target/ichor-azure.vhd`, a fixed VHD of 1 GiB.
   (Cloud Shell can build it: clone the repository, install rustup, run
   the command; nothing need leave Azure.)
2. Upload it as a page blob into a private container (`az storage blob
   upload --type page`) and make a disk of it: `az disk create --source
   BLOB_URL --source-storage-account-id ... --os-type Linux
   --hyper-v-generation V2`.
3. Attach it as the OS disk of a generation 2 machine (`az vm create
   --attach-os-disk DISK --os-type linux --size Standard_D4s_v5
   --security-type Standard --nsg-rule NONE --boot-diagnostics-storage
   ACCOUNT`): an attached disk is not waited on for a provisioning agent,
   which Ichor does not have. Open the API to where you are alone, read the
   serial log with `az vm boot-diagnostics get-boot-log`.

### The same devices, locally: OpenVMM

[OpenVMM](https://github.com/microsoft/openvmm) is Microsoft's own virtual
machine monitor (MIT): its VMBus, disk and network are what a Hyper-V host's
are to a guest, and it runs on Windows' hypervisor platform without
administrator rights (and on KVM). With its firmware (`MSVM.fd`, from
`microsoft/mu_msvm`'s releases):

```bash
openvmm --uefi firmware=MSVM.fd --processors 2 --memory 2GB \
  --vmbus-scsi id=scsi0 --disk file:target/ichor-disk.img,on=scsi0,ro \
  --net consomme:hostfwd=tcp:127.0.0.1:50061-:50051 --com1 file=com1.log
```

(It ends when its standard input does.) On 2026-11-22 (OpenVMM bf353460,
firmware 26.0.50) Ichor boots there, finds its root on the VMBus disk, gets
its address from DHCP over the VMBus network, and pulls and runs containers
through the API.

## Not supported yet

- GCP's gVNIC (GCP's general-purpose machines use virtio-net, which works),
  and Azure's MANA.
- Secure Boot: launch with it off (the default for custom AWS AMIs; on
  GCP, without Shielded VM Secure Boot).
