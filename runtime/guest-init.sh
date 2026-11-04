#!/bin/sh
set -eu
# Hosted guests receive projected SSH credentials and use PVC-backed Docker.
if [ -r /run/guest-ssh/authorized_keys ] && [ -r /run/guest-ssh/host_key ]; then
  exec /usr/local/sbin/openshell-kata-kubernetes-init
fi
# These mounts are inside the Kata guest. Never pass node block devices or sockets.
if awk '$2 == "/proc/sys" {found=1} END {exit !found}' /proc/mounts; then
  mount -o remount,rw /proc/sys
fi
mkdir -p /sys/fs/cgroup
if awk '$2 == "/sys/fs/cgroup" {found=1} END {exit !found}' /proc/mounts; then
  mount -o remount,rw /sys/fs/cgroup
else
  mount -t cgroup2 none /sys/fs/cgroup
fi
chown root:root /etc/ssh/authorized_keys /etc/ssh/ssh_host_ed25519_key
chmod 644 /etc/ssh/authorized_keys
chmod 600 /etc/ssh/ssh_host_ed25519_key
mkdir -p /run/sshd /sandbox /var/log
chown sandbox:sandbox /sandbox
# PID files survive in the container snapshot even though all guest processes died.
# At this fresh boot no Docker daemon exists; discard only its transient runtime handles.
rm -f /var/run/docker.pid /var/run/docker.sock \
  /var/run/docker/containerd/containerd.pid /var/run/docker/containerd/containerd.sock
# Proxies are convenience settings; the host packet fence remains authoritative.
if [ -n "${HTTP_PROXY:-}" ]; then
  printf 'SetEnv HTTP_PROXY=%s HTTPS_PROXY=%s NO_PROXY=localhost,127.0.0.1,::1 http_proxy=%s https_proxy=%s no_proxy=localhost,127.0.0.1,::1\n' "$HTTP_PROXY" "$HTTPS_PROXY" "$HTTP_PROXY" "$HTTPS_PROXY" > /etc/ssh/openshell-kata-env.conf
  mkdir -p /root/.docker /sandbox/.docker
  printf '{"proxies":{"default":{"httpProxy":"%s","httpsProxy":"%s","noProxy":"localhost,127.0.0.1,::1"}}}\n' "$HTTP_PROXY" "$HTTPS_PROXY" > /root/.docker/config.json
  cp /root/.docker/config.json /sandbox/.docker/config.json
  chown -R sandbox:sandbox /sandbox/.docker
else
  : > /etc/ssh/openshell-kata-env.conf
fi
# The only Docker API listener is a Unix socket inside this guest.
dockerd --host=unix:///var/run/docker.sock --group=sandbox --storage-driver=overlay2 > /var/log/docker.log 2>&1 &
# Log to a guest file: the task runs with null stdio on the host.
exec /usr/sbin/sshd -D -E /var/log/sshd.log -f /etc/ssh/openshell-kata.conf
