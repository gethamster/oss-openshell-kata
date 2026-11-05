#!/bin/sh
set -eu
# These mounts and credentials are inside the Kata VM, never node resources.
if grep -q ' /proc/sys ' /proc/mounts; then mount -o remount,rw /proc/sys; fi
if grep -q ' /sys/fs/cgroup ' /proc/mounts; then mount -o remount,rw /sys/fs/cgroup; fi
cp /run/guest-ssh/authorized_keys /etc/ssh/authorized_keys
cp /run/guest-ssh/host_key /etc/ssh/ssh_host_ed25519_key
chmod 644 /etc/ssh/authorized_keys
chmod 600 /etc/ssh/ssh_host_ed25519_key
mkdir -p /run/sshd /sandbox /var/log
# Proxy variables aid package tools and Docker; the external packet fence is authoritative.
if [ -n "${HTTP_PROXY:-}" ]; then
  printf 'SetEnv HTTP_PROXY=%s HTTPS_PROXY=%s NO_PROXY=localhost,127.0.0.1,::1 http_proxy=%s https_proxy=%s no_proxy=localhost,127.0.0.1,::1\n' "$HTTP_PROXY" "$HTTPS_PROXY" "$HTTP_PROXY" "$HTTPS_PROXY" > /etc/ssh/openshell-kata-env.conf
  mkdir -p /root/.docker /sandbox/.docker
  printf '{"proxies":{"default":{"httpProxy":"%s","httpsProxy":"%s","noProxy":"localhost,127.0.0.1,::1"}}}\n' "$HTTP_PROXY" "$HTTPS_PROXY" > /root/.docker/config.json
  cp /root/.docker/config.json /sandbox/.docker/config.json
  chown -R sandbox:sandbox /sandbox/.docker
else
  : > /etc/ssh/openshell-kata-env.conf
fi
chown sandbox:sandbox /sandbox
rm -f /var/run/docker.pid /var/run/docker.sock \
  /var/run/docker/containerd/containerd.pid /var/run/docker/containerd/containerd.sock
# A raw Docker disk reaches this VM as a virtio block device, so Docker can use
# overlay2. Format it only when it has no file system (first boot). Guests
# launched before the disk keep Docker data on the shared PVC, which needs VFS.
driver=vfs
if [ -b /dev/openshell-docker ]; then
  dumpe2fs -h /dev/openshell-docker >/dev/null 2>&1 || mkfs.ext4 -q -L openshell-docker /dev/openshell-docker
  mkdir -p /var/lib/docker
  mount /dev/openshell-docker /var/lib/docker
  driver=overlay2
fi
dockerd --host=unix:///var/run/docker.sock --group=sandbox --storage-driver="$driver" > /var/log/docker.log 2>&1 &
exec /usr/sbin/sshd -D -e -f /etc/ssh/openshell-kata.conf
