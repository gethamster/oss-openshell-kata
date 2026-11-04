#!/usr/bin/env bash
set -euo pipefail
vm=${OPENSHELL_KATA_VM:-openshell-kata-enforcement}
here=$(cd -- "$(dirname -- "$0")" && pwd)
image=docker.io/library/docker@sha256:9e79b879b177fbd72c34376a3dd3d91747da5db49e1f560f76aea59561471977
run() { limactl shell "$vm" sudo nerdctl --snapshotter overlayfs "$@"; }
run pull "$image"
# Trusted image construction uses overlayfs. Flatten once before importing into the capped block snapshotter.
run run --runtime io.containerd.runc.v2 --name openshell-enforcement-seed --label openshell-kata.managed=true "$image" sh -ec 'apk add --no-cache openssh-server openssh-sftp-server bash coreutils curl python3 iproute2 bind-tools netcat-openbsd; addgroup -g 1000 sandbox; adduser -D -h /sandbox -u 1000 -G sandbox sandbox; passwd -d sandbox; mkdir -p /sandbox; chown 1000:1000 /sandbox'
limactl cp "$here/guest-init.sh" "$vm:/tmp/openshell-kata-init"
limactl cp "$here/sshd_config" "$vm:/tmp/openshell-kata.conf"
limactl shell "$vm" chmod +x /tmp/openshell-kata-init
run cp /tmp/openshell-kata-init openshell-enforcement-seed:/usr/local/sbin/openshell-kata-init
run cp /tmp/openshell-kata.conf openshell-enforcement-seed:/etc/ssh/openshell-kata.conf
run cp /opt/openshell-kata/kata-workspace openshell-enforcement-seed:/usr/local/bin/kata-workspace
limactl shell "$vm" sudo sh -c 'nerdctl --snapshotter overlayfs export openshell-enforcement-seed > /tmp/openshell-enforced-rootfs.tar'
# setup-devmapper.sh registers this snapshotter with containerd transfer unpack.
limactl shell "$vm" sudo nerdctl --snapshotter devmapper import --platform linux/arm64 /tmp/openshell-enforced-rootfs.tar openshell-kata-enforced:local
run rm openshell-enforcement-seed
limactl shell "$vm" sudo rm /tmp/openshell-enforced-rootfs.tar
