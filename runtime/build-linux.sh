#!/usr/bin/env bash
# Build native host entrypoints and the static guest helper using an existing shared cache.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname -- "$here")
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Build requires x86_64 Linux.' >&2; exit 2; }
[[ $# == 1 && "$1" == /* && ! -e "$1" ]] || { echo 'Usage: build-linux.sh /absolute/new-output-directory' >&2; exit 2; }
: "${CARGO_TARGET_DIR:?Set an existing bounded shared Cargo target directory}"
[[ "$CARGO_TARGET_DIR" == /* && -d "$CARGO_TARGET_DIR" ]] || exit 2
cd "$root"
# The operator controls build parallelism; this is never selected by a sandbox.
parallel=${CARGO_BUILD_JOBS:-32}
[[ "$parallel" =~ ^[1-9][0-9]{0,2}$ && "$parallel" -le 128 ]] || exit 2
cargo build --release --locked -j "$parallel" --bin openshell-kata --bin kata-runtime --bin kata-network --bin kata-operator
CC_x86_64_unknown_linux_musl=musl-gcc CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --release --locked --target x86_64-unknown-linux-musl -j "$parallel" --bin kata-workspace
mkdir -m 0755 "$1"
for binary in openshell-kata kata-runtime kata-network kata-operator; do install -m 0755 "$CARGO_TARGET_DIR/release/$binary" "$1/$binary"; done
install -m 0755 "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kata-workspace" "$1/kata-workspace"
(cd "$1" && sha256sum openshell-kata kata-runtime kata-network kata-operator kata-workspace > SHA256SUMS)
