# OpenShell Kata adapter

A Rust external compute driver for Docker-capable Kata VMs, using the unmodified
OpenShell 0.1.6 gateway and CLI. The adapter, lifecycle helper, network broker,
file-transfer validation, and local development tools are Rust. Docker,
containerd, and Lima are upstream dependencies implemented in Go; the Kata
runtime used here is the official Rust runtime.

Each sandbox is an untrusted VM, including its kernel, root user, Docker daemon,
and nested containers. Enforcement belongs outside that VM:

- Filesystem: no host directory mounts; a capped private block device; validated,
  bounded archive transfers that never unpack guest data on the adapter host.
- Processes: host-enforced CPU and memory limits and an independent VM lifetime
  watchdog. These are VM limits, not per-executable restrictions inside Docker.
- Network: a host interface fence permits only the sandbox's TCP proxy and SSH
  response traffic. The proxy checks exact destinations, resolves DNS outside the
  guest, blocks private and node-local addresses, and revokes existing connections
  when policy changes.

A launch is not admitted from policy intent alone. The adapter requires fresh
host-runtime evidence before execution, before reporting readiness, and during
operation. A failed check closes access and attempts to stop the VM.

## Policy contract

The operator chooses an immutable JSON profile with `--vm-policy`. The native
OpenShell policy may narrow its TCP destination ceiling; it cannot expand it.
An empty native network policy denies all egress even if the operator profile
permits destinations. The compiler rejects unsupported native filesystem,
Landlock, process-identity, binary-identity, L7, and credential requirements.

The local resource profile is one vCPU, 2048 MiB RAM and 2048 MiB writable disk.
Unsupported capacities fail before launch. The VM lifetime is configurable and
continues across stop/start. See [the enforcement contract](docs/ENFORCEMENT_CONTRACT.md)
for the exact semantics and qualification matrix.

OpenShell upload/download uses validated regular-file and directory archives.
Links, special files, extension headers, ambiguous paths and quota violations
are rejected. Two transfers can run per VM; idle and total-stage deadlines are
bounded. Raw SFTP is rejected in enforced mode. Ordinary command output is not a
file-transfer API and is not subject to archive quotas.

The [Kubernetes profile](docs/HOSTED.md) uses the same adapter and the Rust
`kata-kubernetes` launcher, with explicit operator-owned image, private network
range and recovery settings. Its current network capability is deny-all guest
egress; the local TCP broker is a separate capability. `kata-operator` handles
trusted startup preparation and socket readiness without Python. Both guest
recipes include `kata-workspace` for System command/file operations and protocol
compatibility checks.

## Local development

The current local setup targets an Apple Silicon Mac with nested virtualization,
Lima 2.2+, OpenSSH, GitHub CLI, and Rust 1.98. It creates a dedicated Linux VM
without host mounts. The runtime uses containerd devmapper and the official
Kata 4.3.1 Rust Dragonball runtime. Other host platforms and cloud node types
require their own qualification; no cloud-specific API is in the adapter.

```sh
cargo build --locked --bins
target/debug/kata-dev fetch-openshell
runtime/setup-local.sh
target/debug/kata-dev setup-gateway
target/debug/kata-dev services start --vm-policy "$(pwd)/examples/docker-vm.json"
target/debug/kata-dev e2e --policy "$(pwd)/scripts/e2e-native-policy.yaml"
```

The example operator profile permits the exact public Docker Hub destinations
used by the qualification fixture. Review any additional registry redirect or
build dependency before adding it to both the operator and native policies.
Use `scripts/protocol-fixture.yaml` for a minimal native deny-all policy.

Run ordinary OpenShell commands through the isolated local configuration:

```sh
target/debug/kata-dev cli -- sandbox list
```

Generated credentials and runtime state stay under `.local/`. The gateway binds
`127.0.0.1:29670` with TLS and client authentication. Per-run evidence goes under
`evidence/local-runs/`; `--evidence-dir /absolute/path` selects another directory.
Existing user OpenShell and Docker configurations are not changed.

## Validation

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo doc --locked --no-deps
cargo audit
target/debug/kata-dev verify-upstream
```

The CLI integration suite covers repeated 16 MiB uploads/downloads with hash
checks, concurrent commands, Dockerfile `RUN`, Compose, a gateway HTTP preview,
stop/start, retained files and deletion. Network/resource qualification also
requires negative tests from guest root; passing parser tests is insufficient.

The [original qualification record](evidence/qualification.json) is the earlier
upload-repair milestone, using the former compatibility runtime. It does not
certify the new enforcement profile. The [enforcement qualification record](evidence/enforcement-qualification.json)
records the initial Rust Kata enforcement milestone: 139 tests, 84.85% implementation line coverage,
the complete CLI flow, guest-root network attacks, storage/resource bounds, and
independent deadline termination. This qualifies the tested Apple Silicon/Lima
profile; the broader production and platform matrix remains in
[the policy plan](docs/POLICY_PLAN.md). The subsequent shared-runtime and System
integration gates are tracked separately in [the delivery plan](docs/DELIVERY_PLAN.md).

The [shared-runtime qualification](evidence/integration-qualification.json)
records 247 macOS test results and 86.80% implementation line coverage. Both the
stock CLI and the actual System sandbox backend passed file operations, command
streams, Docker/Compose, preview, restart persistence and verified deletion with
unmodified OpenShell 0.1.6. The System run used the production access router with
a scoped local authorization fixture; hosted sign-in, immutable images and
tenant isolation remain separate deployment gates. Hosted egress is still
deny-all, so this does not qualify hosted internet-dependent builds.

## Cleanup and delivery scope

Delete sandboxes through the official CLI, then stop the local services:

```sh
target/debug/kata-dev cli -- sandbox delete rust-upload-check
target/debug/kata-dev services stop
limactl stop openshell-kata-enforcement
limactl delete --force openshell-kata-enforcement
```

Keep `.local/runtime` until guests and tunnels have been removed. The private
block storage persists through stop/start but is not a production backup system.
The hosted deployment is coordinated separately with its SRE owner. A passing
local profile does not qualify its Kubernetes artifacts or tenant cutover.

The external compute interface is versioned, while the supervisor protocol is
internal. Upgrading OpenShell requires requalification. See [porting notes](docs/PORTING.md)
and [the delivery plan](docs/DELIVERY_PLAN.md) for remaining production work.

## License

OpenShell Kata, including Hamster-authored additions and modifications, is
licensed under the [Apache License 2.0](LICENSE).

NVIDIA copyright notices and the [original upstream license](LICENSE-UPSTREAM)
are preserved. The vendored OpenShell protocol retains its [own license](proto/LICENSE)
and provenance.
