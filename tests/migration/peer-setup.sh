#!/bin/bash
# Startup script of the peer VM (Debian 12 on GCE): the load's other end,
# the API client, and what runs the campaign. Logs to
# /var/log/peer-setup.log; done when /root/ready exists.
exec >> /var/log/peer-setup.log 2>&1
set -eux
[ -e /root/ready ] && exit 0
apt-get update
apt-get install -y iperf3 netcat-openbsd git build-essential python3 curl
export HOME=/root
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
. /root/.cargo/env
git clone --depth 1 https://github.com/WorriedArrow/ichor /root/ichor
cd /root/ichor
cargo build --release -p xtask
cp target/release/xtask /root/xtask
touch /root/ready
