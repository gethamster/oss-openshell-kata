#!/usr/bin/env bash
# Dedicated native Linux node only; no Lima, Kubernetes or hosted fleet services.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$here/linux_node.py" "$@"
