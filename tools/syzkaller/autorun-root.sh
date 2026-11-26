#!/bin/bash
# Builds autorun-root.tar: Alpine 3.20.3's minirootfs (pinned like xtask's
# artifact) with dropbear, its scp and an sftp server, the public key
# syzkaller logs in with as root's authorized key, and /sbin/ichor-autorun,
# which starts dropbear in the foreground. Run as root on a Linux host
# (it chroots into the tree to run apk), from the directory that should
# get the tarball:
#
#   sudo bash autorun-root.sh /path/to/syzkey.pub
#
# Then, in the Ichor tree: cargo xtask root-image autorun-root.tar autorun.img
set -euo pipefail
pub=${1:?usage: autorun-root.sh SYZKALLER_SSH_PUBLIC_KEY}
out=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -sSLo "$work/alpine.tgz" \
  https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
echo "d4e6fd67dcf75e40c451560ac7265166c2b72a0f38ddc9aae756a7de3d1efa0c  $work/alpine.tgz" | sha256sum -c
root=$work/root
mkdir "$root"
tar -xzf "$work/alpine.tgz" -C "$root"
echo "nameserver 1.1.1.1" > "$root/etc/resolv.conf"
chroot "$root" /sbin/apk add --no-cache dropbear dropbear-scp openssh-sftp-server
install -d -m 700 "$root/root/.ssh"
install -m 600 "$pub" "$root/root/.ssh/authorized_keys"
cat > "$root/sbin/ichor-autorun" <<'EOF'
#!/bin/sh
# Ichor autorun: the ssh server syzkaller drives the machine through.
mkdir -p /etc/dropbear
exec /usr/sbin/dropbear -F -E -R -s -p 22
EOF
chmod 755 "$root/sbin/ichor-autorun"
tar --numeric-owner -C "$root" -cf "$out/autorun-root.tar" .
ls -la "$out/autorun-root.tar"
