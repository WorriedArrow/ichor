# GCE live-migration campaign

What it asks: does Ichor come through GCE's live migrations with its
network, disk and clock intact, and with its connections alive? It hammers
a running Ichor VM with simulated maintenance events
(`gcloud compute instances simulate-maintenance-event`, on a VM with
`onHostMaintenance=MIGRATE`) while the VM is under load, and reports run by
run what the guest saw.

## What the guest logs

With `metadata=gcp` (or `watch_cloud`) and `disk_hammer` on its command line
the kernel itself logs, with its uptime and wall clock:

- `ichor: watch: maintenance-event VALUE`: GCP's notice, long-polled
  from the metadata service (`instance/maintenance-event`; about 60 s ahead).
- `ichor: watch: clock +X ms from the metadata server's NTP`: the wall
  clock against the metadata server's NTP, every 5 s (logged when it moves
  2 ms, each minute, and every sample for 10 minutes after a notice).
- `ichor: watch: no tick for N ms`: a 20 ms ticker that woke much later
  (a blackout the clock ran through, or a starved scheduler).
- `ichor: hammer: ...`: 64 KiB reads at random over the whole boot disk
  (the root partition fills a padded disk), past the page cache: each
  error and each read over 500 ms at once, a summary every 10 s.
- `ichor: gve: ...`: gVNIC's link changes and reset requests (the driver
  polls the status register the management interrupt would announce, and
  resets the device when it asks).

## The load

From the peer VM, through Ichor's API (each in a cell, run again if it
ends, and each end logged): `iperf3 -c PEER` for 1 s throughput, a steady
TCP stream (a line every 200 ms to `nc -l` on the peer, which stamps
arrivals), `fio` random read/write (on the cell's in-memory root: Ichor has
no writable disk), and a CPU loop. The disk is loaded by the kernel's
hammer.

## Running it

1. Build the image with the API's token and certificate:
   `cargo xtask disk-image --release --size-gib 10 --gcp --cmdline
   "metadata=gcp disk_hammer" --api-token-file api-token --api-tls-file
   api-tls.pem`, upload `target/ichor-gcp.tar.gz` to a bucket, and
   `gcloud compute images create ichor-mig --source-uri gs://.../ichor-gcp.tar.gz
   --guest-os-features=UEFI_COMPATIBLE,GVNIC`.
2. The Ichor VM: `gcloud compute instances create ichor-mig --zone Z
   --machine-type e2-standard-4 --image ichor-mig
   --network-interface=nic-type=GVNIC --maintenance-policy=MIGRATE
   --metadata=ichor="control=50051 control_publish=50051"`.
3. The peer VM, same zone: `--image-family debian-12 --image-project
   debian-cloud --scopes compute-rw --metadata-from-file
   startup-script=peer-setup.sh`; a firewall rule letting the two talk.
4. On the peer (as root, once `/root/ready` exists, with `ca.pem` and
   `api-token` copied there): `ICHOR_IP=... PEER_IP=... bash campaign.sh
   ichor-mig Z 50 /root/out`, then `python3 analyze.py /root/out`.
