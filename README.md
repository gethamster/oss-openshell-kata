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
Attached OpenShell provider credentials are supported only through inspected
REST endpoints: the host broker terminates guest TLS with a per-sandbox CA and
substitutes placeholders, so real credentials never enter the guest (see
[the enforcement contract](docs/ENFORCEMENT_CONTRACT.md#provider-credentials-are-injected-by-the-host-broker)).

The local resource profile is one vCPU, 2048 MiB guest RAM and 2048 MiB writable disk.
The host reserves another 256 MiB for the Kata runtime, so both enclosing host
cgroups are capped at 2304 MiB while the guest remains limited to 2048 MiB.
The `build` profile grants 16 vCPUs, 48 GiB guest RAM and 32 GiB private disk;
its host memory cap is 48.75 GiB. Select it with `--resource-profile build`
and [the matching operator policy](examples/build-vm.json).
The native `foundry-build` profile (32 vCPU, 131072 MiB RAM, 262144 MiB disk)
reserves the larger of 256 MiB and 1/64 of guest RAM, so its host caps are
133120 MiB.
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
compatibility checks. When layering a new System environment with
`runtime/Dockerfile.layer`, pass `--build-arg WORKSPACE_HELPER_IMAGE=<image@sha256:...>`
to reuse the static helper from an already-qualified guest image. The default
builds the helper from this checkout. Release records must retain both the base
and helper image digests; layer smoke checks still run.

Normal OpenShell workloads can use [the standard image](runtime/Dockerfile.standard),
which runs as UID/GID 1000 and includes the same workspace helper without a Docker
daemon. Its Docker CLI wrappers execute help/version requests locally. A command
that needs a daemon records a `docker` capability request and returns status 125;
the application owner decides whether to move the authorized session to Kata.
This image does not change the adapter's Kata-only compute contract.

`kata-workspace capability <command-uuid>` returns that command's request or
`null`; `capabilities` lists pending requests and `capability-ack <uuid>` removes
one. A helper-managed command and its descendants are interrupted before status
125 is returned. Cancellation publishes a durable request to the command's
controller, including its retained PID and start identity. The controller verifies
that identity against its own launch record and acknowledges only after draining
its descendants. This does not require cross-process executable inspection.
The controller retains orphaned descendants as a Linux subreaper,
signals only its own unreaped children, and waits for all of them to exit. It
requires neither pidfds nor process-group signals, which normal OpenShell
workloads prohibit. A failed drain retains evidence and prevents a successful
quiescence check.

`hold <uuid>` keeps an interrupted owner workload available for file transfer.
`quiesce` blocks new helper commands, stops managed descendants and holders,
and refuses transfer preparation while any untracked live process remains.
A writable holder record never exempts a live process from this check.
`quiesce-export` performs quiescence and streams the archive within one already
admitted command; use it when holder exit completes the sandbox's main process
and prevents admitting another command. The source files remain intact on
failure. Recovery must restore an authorized running transport before using
`thaw`; do not recreate or discard the authoritative source to conceal failure.

`export` and `import` stream deterministic USTAR workspace archives for runtime
moves. They retain hidden files and executable permissions, allow only relative
symlinks contained by `/sandbox`, and reject hard links, special files, extensions,
duplicate paths, and escapes. Each archive is bounded to 1 GiB of content and
100,000 entries. Import validates in a private staging directory before replacing
the candidate's user files; retries replace the same data. Helper process records
and freeze markers never transfer. This guest convenience protocol is separate
from the host-enforced upload/download interface and its stricter archive limits.

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

For a dedicated local build node, provision with
`OPENSHELL_KATA_VM=openshell-kata-build OPENSHELL_KATA_RESOURCE_PROFILE=build runtime/setup-local.sh`.
Its Lima host has 16 CPUs, 56 GiB RAM and a 96 GiB sparse disk. The larger host
memory allocation covers the guest, VMM overhead and node services. Keep it
separate from an existing development node and pass `--vm openshell-kata-build
--resource-profile build --max-sandboxes 1` to the lifecycle helper.

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

Historical qualification receipts are retained under `evidence/`. Use the
[enforcement contract](docs/ENFORCEMENT_CONTRACT.md) and
[hosted profile](docs/HOSTED.md) for the current supported controls and setup.

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
internal. For an OpenShell upgrade, verify the changed protocol and runtime
behavior using the [porting notes](docs/PORTING.md).

## License

OpenShell Kata, including Hamster-authored additions and modifications, is
licensed under the [Apache License 2.0](LICENSE).

NVIDIA copyright notices and the [original upstream license](LICENSE-UPSTREAM)
are preserved. The vendored OpenShell protocol retains its [own license](proto/LICENSE)
and provenance.
