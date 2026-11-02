# Rust Kata runtime

`setup-local.sh` provisions the dedicated `openshell-kata-enforcement` Lima VM
on Apple Silicon macOS with nested virtualization. It requires Lima, OpenSSH,
GitHub CLI and Rust 1.98. No Python helper or Go Kata fallback is used.
Docker, containerd, nerdctl and Lima remain upstream dependencies.

The node has four CPUs, 8 GiB RAM, a 30 GiB disk, no host directory mounts and
no forwarded SSH agent. Tenant workloads always use the official Kata 4.3.1
Rust shim with Dragonball and `virtio-blk-mmio`. Trusted image assembly alone
uses runc. The source Docker image and Kata release archive are pinned by hash.

## Enforcement

Each guest has one vCPU, a 2048 MiB memory ceiling, a private 2048 MiB devmapper
block root and a persistent expiration deadline. Host cgroups constrain the
Rust VMM process and its threads. A separate systemd watchdog pins the cgroup
kill handle before readiness; it survives adapter exit and enforces expiration.
Restart does not renew the deadline.

Shared filesystems are disabled. The minimal OCI specification contains no
host bind mounts or host device entries. The guest agent image is read-only at
the block-device level. Thin-pool block zeroing is mandatory; an unsafe existing
pool is rejected. See `evidence/runtime-rust-summary.md` for the resource tests.

A generation-owned network namespace and veth are created before boot. Host nft
rules bind to their identity and permit only the guest's dedicated TCP broker
and replies to host-initiated SSH. The broker runs without root or capabilities,
uses a private control socket, and validates public destination addresses.
Direct guest DNS, UDP, IPv6, metadata, sibling traffic and forwarded inbound
traffic are denied. Restart boots behind deny-all egress until the adapter
applies the current gateway policy.

The guest owns a Docker daemon listening only on its own Unix socket. Docker
root and privileged nested containers remain inside the VM boundary. Proxy
settings are installed for noninteractive SSH commands, Docker image pulls,
build arguments and application containers; removing those settings cannot
remove the host packet fence.

## Lifecycle contract

Build the Rust binaries from the repository root. The adapter invokes
`kata-runtime ACTION ID` with trusted operator arguments:

- `create`, `start`, `verify`, and `update` require `--policy-file /absolute/path`
  and a fresh `--proof-nonce`. They emit the pinned loopback SSH route plus
  matching host-observed enforcement evidence.
- `stop` and `delete` operate on retained private state and verify cleanup.
- `abort` takes the failed launch nonce and can remove only resources owned by
  that launch. A different generation remains intact.

`OPENSHELL_KATA_STATE_DIR` or `--state-dir` selects an absolute private state
root. `--vm` selects the dedicated Lima node. Keep state until guests, watchdogs,
brokers and tunnels are removed. The private SSH client key and gateway
credentials never enter the guest. Guest SSH keys are generated and installed
before its first boot; untrusted guest filesystems are never mounted for that
operation after execution begins.

The operator profile is documented in `docs/ENFORCEMENT_CONTRACT.md`. Native
OpenShell guest filesystem/process restrictions remain unsupported with guest
root and are rejected. Windows and additional cloud node types must preserve this contract and pass
the adversarial suite before deployment. The native Linux setup below provides
the port; target-host qualification remains an explicit deployment gate.

## Validation and cleanup

`cargo test --locked` covers lifecycle identity, state privacy, command bounds,
resource/deadline validation, archive transfers and broker controls. The official
CLI suite is `kata-dev e2e`; the node-side adversarial network harness is
`test-network-enforcement.sh`. Run it only on this dedicated test node with an
explicit fixture and control socket.

Delete sandboxes through the official CLI, then stop local services and delete
the dedicated Lima VM as described in the repository README. Release archives,
node build outputs and VM disks are disposable after validation; preserve the
nonsecret qualification evidence in the repository.

Restart clears only the pinned Kata profile's stale tap/filter state inside its
verified namespace. Failed-start shims are matched by full ID, namespace,
executable and creation ownership, then signaled through Linux pidfds. Socket
cleanup follows [Kata 4.3.1's socket derivation](https://github.com/kata-containers/kata-containers/blob/4.3.1/src/runtime-rs/crates/shim/src/shim.rs#L64)
and refuses a live endpoint or an unexpected file type. Guest `/run` is tmpfs,
so Docker's runtime handles do not survive a reboot. Normal stop attempts a
bounded guest filesystem flush; the independent expiry watchdog always retains
its hard deadline.

## Dedicated native x86 Linux node

The `linux-local` transport runs bounded `sudo -n -- timeout` commands directly
on a dedicated Linux host. It does not invoke Lima or Kubernetes. The adapter
still uses `--runtime-profile local`; choose the node and resource contract with
trusted service environment settings:

```sh
OPENSHELL_KATA_NODE_TRANSPORT=linux-local
OPENSHELL_KATA_RESOURCE_PROFILE=foundry-build
OPENSHELL_KATA_STATE_DIR=/var/lib/system/kata/private-state
OPENSHELL_KATA_MAX_SANDBOXES=48
```

The lifecycle also accepts `--node-transport linux-local` and
`--resource-profile foundry-build`. The fixed build profile admits exactly
32 vCPUs, 131072 MiB RAM and 262144 MiB private disk. `VmPolicy` retains
`"profile":"docker-vm"`. CPU and memory appear in the OCI configuration and
host cgroups, and observations verify actual Dragonball CPU threads and block
device capacity. An immutable operator-selected OCI guest image is mandatory
for this profile.

Node capacity is an explicit operator setting: `OPENSHELL_KATA_MAX_SANDBOXES`
(1 to 64) is the most retained guests the node admits at once, stopped guests
included. Delete a guest to release its reservation. The adapter reads it as
`--max-sandboxes` (the same environment variable) and requires it whenever
native recovery is configured; the lifecycle reads the same variable and
requires it for `foundry-build`. Both refuse a new guest once the retained
count reaches the capacity. Capacity is not part of the recovery binding, so
raising it keeps retained guests; lowering it below the retained count makes
the adapter refuse to start until guests are deleted. Set it to the
`max_sandboxes` value in the node's `node.json` (see below).

Lifecycle operations on distinct guests run in parallel; operations on one
guest stay ordered behind a per-guest lock. A create holds the node-wide lock
only while it claims capacity, a private address and a tunnel port with its
state record, never during boot. Link, peer and namespace names derive from the
sandbox and its creation nonce, so concurrent creates never share one. The adapter runs at most 16 provisioning and
16 revalidation lifecycle processes at once, and each execution deadline starts
only when its slot is granted. Unchanged running guests are re-proven every 30
seconds (policy changes apply at the next 5-second heartbeat). A missed deadline
under host load defers the proof; a guest is stopped only for a verified
mismatch or after 300 seconds without a successful proof. Guest memory is
allocated lazily and disks are thin, so capacity is bounded by real use rather
than by 32 vCPU / 128 GiB / 256 GiB per guest.

Build native entrypoints on x86 Linux using `build-linux.sh /absolute/new/bin`.
Provide an existing bounded `CARGO_TARGET_DIR`, Rust 1.98, musl tools and the
`x86_64-unknown-linux-musl` target. The script builds native `openshell-kata`,
`kata-runtime`, `kata-network`, `kata-operator` and a static guest `kata-workspace`.
The native guest image uses `Dockerfile.local-guest`, whose initializer is
`guest-init.sh`; the hosted image uses a different initializer.

`Dockerfile.layer` turns any Ubuntu or Debian based environment image into an
admissible native guest. It installs OpenSSH server, Docker, curl, CA
certificates and iproute2, makes uid 1000 the `sandbox` user with home
`/sandbox` and no password (guest SSH stays key-only) (renaming an existing uid 1000 account, such as
Ubuntu's `ubuntu`), and adds `guest-init.sh`, `sshd_config` and a static
`kata-workspace` built from this tree. Build it from the repository root with a
digest-pinned base, then pin the result with `--guest-image` or
`--additional-guest-image`:

```sh
docker build -f runtime/Dockerfile.layer \
  --build-arg BASE=registry.example/env@sha256:... -t registry.example/env-guest .
``` Build and publish
that OCI artifact through the owning release pipeline and pass its digest via
`--guest-image` on the adapter.

Provision upstream containerd, ctr, nerdctl, nftables, iproute2, OpenSSH server,
LVM/device-mapper tools, zstd, binutils, Python 3 and sudo before node setup.
The host must expose nested `/dev/kvm` and cgroups v2. Run on the dedicated node
as root, after its retained SSD filesystem is mounted:

```sh
runtime/setup-linux.sh \
  --archive /trusted/kata-static-4.3.1-amd64.tar.zst \
  --binary-dir /trusted/bin \
  --pool-dir /var/lib/system/kata/pool \
  --resource-profile foundry-build --operator foundry --max-sandboxes 48
```

Setup verifies the official Kata 4.3.1 archive's 1,021,129,805-byte length and
SHA-256 `1463a2b86845f4d3d8e87f2f764ec59856fc0fee3520967a79ade32762be2e97`.
It installs the Rust Dragonball runtime, disables shared filesystems, preserves
x86 PCI block transport, and installs the five entrypoints in
`/opt/openshell-kata`. It requires a dedicated containerd configuration and
refuses to replace an unrelated one.

A 1280 GiB preallocated thin pool plus 1 GiB metadata file bounds retained SSD
use. Each private snapshot is capped at 256 GiB, so more than four full guests
overcommit the pool: a guest write that finds the pool exhausted fails with an
I/O error (`error_if_no_space`) rather than blocking or touching another
guest's blocks. Watch `dmsetup status openshell-kata-pool` data usage. Mandatory
zeroing prevents recycled block disclosure. Containerd metadata
and snapshotter state live beside the pool on the retained filesystem. Setup
never truncates or resizes existing backing files. It pins their filesystem UUID
and inode identities, rejects partial or unowned pool state, and treats a
matching installation as a verified no-op. The boot service reconstructs
loop and device-mapper identities before starting containerd and explicitly
requires the retained mount.

A separate localhost-only SSH daemon on port 22220 provides the node hop with
fixed host pinning. Its client cannot run interactive host commands; only trusted
operator forwarding is used. Guest SSH still has its unique private key and
strict host pinning. The trusted operator account receives passwordless access
to the bounded `timeout` command as root for node administration; do not expose
that account or its keys to guests.

Use a private absolute `--recovery-dir` on the adapter, separate from
`OPENSHELL_KATA_STATE_DIR`. Restart recovery stops retained compute and exposes
credential-free stopped intent; a fresh authenticated Start is required. Node
boot identity changes require complete absence of the old namespace and link,
confirmed stopped containerd tasks and the same private snapshot. Recovery
creates new generation-owned attachment observations and packet-fence proofs,
reserving all retained addresses before the adapter begins serving new requests.
It preserves the original disk and expiration deadline.

A retained sandbox the current operator profile no longer admits, for example
because a release dropped its image from `--additional-guest-image` or changed
the VM resources, is retired at recovery instead of failing the adapter. It is
deleted like an explicit delete (guest, network fence, snapshot and recovery
record), logged as `retiring retained sandbox the operator profile no longer
admits`, and reported to the gateway as deleted so its owner re-places it. If
that cleanup fails, the record is kept and retried at the next recovery.
Integrity failures (operator binding, record identity, stored credentials,
inventory bounds) still stop recovery.

`sudo runtime/setup-linux.sh --verify` prints public JSON with
`node_verified:true` after checking actual pool identity, zeroing, resource
configuration, KVM, cgroups, nft availability, devmapper health and service state.
The installed public configuration is `/etc/openshell-kata/node.json` (mode0600).
It records the operator capacity as `"max_sandboxes": <1..64>`, which verify
requires and echoes. Re-running setup with the installed inputs and a new
`--max-sandboxes` rewrites only that field. A node installed before the field
existed fails verification until it is added: as root, add
`"max_sandboxes": 48` to the JSON object (keep mode 0600), then rerun
`--verify` and restart the adapter with `OPENSHELL_KATA_MAX_SANDBOXES=48`.
Preserve it with the retained SSD recovery evidence before replacing a boot disk.
This node check does not certify guest execution: before activation, run the
real create/verify/stop/restart/delete and adversarial network, storage and
expiration suite on the target nested-KVM host, and repeat recovery after a node
reboot. Preserve those results in the deployment's release evidence.
