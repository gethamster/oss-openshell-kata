#!/usr/bin/env bash
# Install the official Rust Kata runtime on the dedicated disposable Linux node.
set -euo pipefail
case "${1:-local}" in
  local) cpus=1; memory=2048 ;;
  build) cpus=16; memory=49152 ;;
  *) echo 'Unsupported local resource profile.' >&2; exit 2 ;;
esac
archive=/tmp/kata-static-4.3.1-arm64.tar.zst
printf '%s  %s\n' 2c5bf7cde334ad5307d482f45cceda496f91c9b6b96f5278c47f4f4eac1bbae6 "$archive" | sha256sum -c -
command -v zstd >/dev/null || { sudo apt-get update -qq; sudo apt-get install -y -qq zstd; }
sudo tar --zstd -xf "$archive" -C /
config=/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-dragonball.toml
sudo sed -i -E \
 -e 's/virtio-blk-pci/virtio-blk-mmio/g' \
 -e 's/^shared_fs = .*/shared_fs = "none"/' \
 -e "s/^default_vcpus = .*/default_vcpus = $cpus/" \
 -e "s/^default_maxvcpus = .*/default_maxvcpus = $cpus/" \
 -e "s/^default_memory = .*/default_memory = $memory/" \
 -e "s/^default_maxmemory = .*/default_maxmemory = $memory/" \
 -e 's/^overhead_vcpus = .*/overhead_vcpus = 0/' \
 -e 's/^overhead_memory = .*/overhead_memory = 0/' "$config"
if [[ "${1:-local}" == build ]]; then
  # Transparent huge pages remain charged to the normal memory cgroup. Avoid
  # hundreds of thousands of nested page-table entries for a large local VM.
  printf 'w /sys/kernel/mm/transparent_hugepage/shmem_enabled - - - - advise\n' \
    | sudo tee /etc/tmpfiles.d/openshell-kata-build-thp.conf >/dev/null
  printf 'advise\n' | sudo tee /sys/kernel/mm/transparent_hugepage/shmem_enabled >/dev/null
  sudo sed -i -e 's/^enable_hugepages = .*/enable_hugepages = true/' \
    -e '/^enable_hugepages = true$/a hugepage_type = "thp"' \
    -e 's/^kernel_params = "\(.*\)"$/kernel_params = "\1 overlay.redirect_dir=off overlay.metacopy=off"/' "$config"
fi
sudo ln -sfn configuration-dragonball.toml /opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml
sudo ln -sfn /opt/kata/runtime-rs/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
sudo modprobe vhost_vsock
sudo modprobe vhost_net
