# Kubernetes runtime profile

The same Rust adapter supports local Kata guests and an explicitly selected
Kubernetes profile. The operator installs the Kata runtime and admission/network
controls separately. No cloud provider API is required by this launcher.

Select the hosted profile with `--runtime-profile kubernetes`, an immutable
`--guest-image repository@sha256:...`, a private `--guest-network-cidr`, an
absolute `--recovery-dir`, and `--lifecycle /usr/local/bin/kata-kubernetes`.
Repeat `--additional-guest-image repository@sha256:...` to admit operator-pinned
owner images alongside the default image. Every admitted image uses the same
network ceiling and the default resource shape, unless a declared resource shape
below applies. The authenticated sandbox
template selects only an admitted digest; workload inputs cannot alter the
allowlist or runtime settings. Lifecycle and proof checks use that selected
image. `--additional-guest-images-file /absolute/path.json` names a root-owned
JSON array of further digest-pinned images, read on every admission, so an
operator can change that set without restarting the adapter; the file only adds
to the command-line images, and a missing, symlinked, non-root-owned,
group/world-writable or invalid file admits none of its images (logged once)
while command-line images keep working. A retained sandbox keeps its original image across adapter restarts,
even after a release changes the default or stops admitting that image: a
dropped image only stops new sandboxes from selecting it, and the retained one
runs it, never another image, until its owner replaces or deletes it. Recovery
still retires a retained sandbox that any other admission rule now rejects.

The adapter passes the exact guest range to the launcher as
`OPENSHELL_KATA_GUEST_NETWORK_CIDR`; absent or public ranges fail closed.
The operator may select `OPENSHELL_KATA_KUBE_CONTEXT` and
`OPENSHELL_KATA_STATE_DIR`. `OPENSHELL_KATA_STORAGE_CLASS` is required: it must
name an operator-qualified Kubernetes storage class using a legal DNS subdomain
name. There is no implicit provider default or provider-name allowlist. The live
PVC must exactly match the selected class and private volume shape. Each provider's
actual storage behavior still needs qualification. Tenants cannot choose these settings.

`OPENSHELL_KATA_CONTROL_NAMESPACE` selects the single trusted control namespace
for the isolated profile (default `openshell-system`). It must be a Kubernetes
DNS label. Generated guest policies and create-time and ongoing verification
require that exact namespace and the `sandbox-control` role; the setting never
adds another allowed principal and is not accepted from workload requests.

The launcher derives `sandbox-<workspace>` from gateway-owned metadata and
checks existing namespace labels. It never creates namespaces. Each sandbox
has a Kata Pod, two private RWO PVCs, an SSH Secret and selecting network policy.
The `<name>` PVC holds `/sandbox`. The `<name>-docker` PVC is a raw block volume
(`volumeMode: Block`) of the same size that reaches the VM as
`/dev/openshell-docker`. The guest formats it as ext4 on first boot and mounts
it at `/var/lib/docker`, so Docker uses `overlay2`. A shared-folder PVC would
force `vfs`, which stores a full file system copy per image layer. The Docker
disk is a cache: deletion and a failed first launch remove it, and a relaunch
keeps it. Guests launched before this disk keep Docker data on the `<name>` PVC
with `vfs` until they are relaunched.
Ephemeral storage uses Kubernetes accounting and eviction, not an instantaneous
block quota. The local block-backed profile separately supports one vCPU and
2 GiB memory/disk. Operator-owned templates must match the selected shape.

### Resource shapes

The default shape is two vCPU, 4 GiB memory, a 19 GiB PVC and 1 GiB ephemeral
storage. A template with no resources, or with only these values, uses it.

The operator can declare a larger shape on the adapter, for example for the
System snapshot builder:

```sh
--resource-shape build=4,8Gi,100Gi
```

The format is `NAME=CPU,MEMORY,STORAGE`: whole vCPUs, whole GiB of memory and
whole GiB of PVC. A template selects a declared shape only when it requests
exactly that CPU and memory (System Access sends `4` and `8Gi` for the
`owner-4cpu-8gib` placement profile). Native policy, environment and guest input
cannot select a shape. Any other request, and a request for a shape that is not
declared, is refused.

The adapter refuses a declaration that:

- is above the hosted ceiling of 8 vCPU, 32 GiB memory and 200 GiB PVC (one
  `n2-standard-8` class Kata worker);
- uses the reserved name `default`, or the default CPU and memory;
- repeats a name, or the CPU and memory of another declared shape;
- is one of more than 8 declarations, or is set on the local runtime.

The adapter passes the selected declaration to the launcher as
`OPENSHELL_KATA_RESOURCE_SHAPE` on create and start. The launcher sizes the Pod
requests and limits and the PVC request from it, and keeps it in retained
state. Start refuses a different shape for retained state or an existing PVC
of another size. Live proof requires the exact Pod limits and PVC size of the
retained shape, and reports the shape in `resource_shape`. The adapter refuses a
proof whose CPU, memory or shape differs from the shape that the template
selected. Billing records the Pod's actual vCPU and memory. Removing a
declaration retires retained sandboxes that use it at the next adapter start.

The default shape keeps the earlier Pod, PVC, retained state and proof bytes.
Retained state and proof are `deny_unknown_fields` records, so an earlier
release cannot read a retained sandbox with a declared shape. To roll back,
first remove `--resource-shape` and delete the sandboxes that used it, then
install the earlier release.

The shape does not change the Docker storage driver. The guest uses `vfs`, which
copies each image layer in full, so Docker builds need much more PVC space than
the image size.

`OPENSHELL_KATA_BILLING_CONFIG` optionally selects a private JSON file containing
`url`, `token_file`, and `outbox_dir`. The authority file must be private and the
outbox must be durable. For an internal HTTPS authority, set `ca_pem` to its PEM
CA bundle; this replaces public trust roots for billing requests and never
disables certificate verification. The standalone launcher initializes the shared
OpenShell TLS provider before building its billing client. Leave billing
unconfigured for self-hosted installations.

## Guarantees and limits

The default `isolated` profile accepts version-1 policy with all fine-grained
sections absent. It enforces deny-all guest egress and permits SSH only from the trusted
control role. Before launch and during revalidation, it rejects additive
selecting policies that broaden that boundary and verifies the actual Pod UID,
nonce, runtime class, node qualification, image, storage and resource settings.
It never falls back to an ordinary container runtime.

Guest root and Docker do not imply selective native path, executable or process
identity enforcement. Unsupported policy is rejected. Public TCP brokering is
an additional explicit profile described below. Hosted promotion requires real
dependency downloads and builds; offline Docker tests do not prove internet access.

## Explicit public TCP brokering

Select `--hosted-network-config /absolute/operator.json` to request
`brokered-public-tcp-v1`. The default remains deny-all. The operator file pins
the trusted broker namespace UID, exact host/port ceiling, protected hostname
suffixes, baseline denied CIDRs, trusted resolver namespace/Pod selectors,
authorization lease and absolute path to a fresh infrastructure inventory.
Use immutable `OPENSHELL_KATA_BROKER_IMAGE` and `OPENSHELL_KATA_GUARD_IMAGE`
digests. Bind the actual source, broker, controller and guard namespace UIDs to
operator configuration or launch state. No namespace UID mirror label is needed.
Network policies select exact namespace names and immutable Pod labels carrying
the source namespace UID, sandbox identity and launch nonce.
Pod validation also permits the platform-added `topology.kubernetes.io/region`
and `topology.kubernetes.io/zone` labels. Required binding labels remain exact,
and additive network-policy checks use the complete observed label set.

This profile uses the local runtime's native TCP compiler. Rules must select
all executables with `/**`, exact DNS names or global IP literals, explicit TCP
ports and TLS skip. It provides TCP destination authorization. It does not
inspect TLS SNI or establish HTTP Host identity at an allowed shared address.
The only wildcard is the opt-in public-port capability below. There is no
credential, L7, guest filesystem or process identity capability. Native policy may narrow both the operator ceiling and the immutable
original caller capability. An empty caller policy never gains internet access.
Global effective policies are unsupported for this profile.

### Public hosts on chosen ports (build sandboxes)

An operator ceiling may list `tcp_allow_public_ports`, for example `[443, 80]`.
The field is optional; a ceiling without it keeps the exact behaviour above. It
is intended for build sandboxes, such as the System snapshot builder, that fetch
dependencies from hosts no one can list in advance. Do not grant it to thread
or workspace sandboxes.

A native rule requests a public port with host `**`, the all-executables
selector and `tls: skip`. An empty host is still refused:

```yaml
network_policies:
  build_downloads:
    endpoints:
      - host: "**"
        ports: [443, 80]
        tls: skip
    binaries:
      - path: "/**"
```

Each requested port must be a public port of the operator ceiling and of the
original caller capability; otherwise the policy is refused. Exact rules in the
same policy are unchanged. A public port never admits inspected REST: an
inspected host needs its own exact ceiling entry. The capability is
hosted-only; the local `docker-vm` profile refuses the field. On a public port
the broker:

- admits a well-formed DNS name only. It refuses every IP literal, a
  single-label name and a name whose last label starts with a digit, which a
  resolver can read as an IPv4 address (for example `8.8.1028`);
- refuses names under `protected_hostname_suffixes`;
- refuses the request when any resolved address is not globally routable or is
  inside the baseline or inventory denied CIDRs;
- applies the same checks to CONNECT tunnels and to plain-HTTP forward
  requests;
- relays TLS opaquely. It never inspects public-port traffic or injects
  credentials.

The protected-suffix check is name-based. It does not stop a guest-controlled
DNS name that resolves to the public address of a protected host. Address-level
denial comes only from the denied CIDRs. To deny a protected host by address,
the operator must list its addresses in `baseline_denied_cidrs`, or list its
exact name in the inventory configuration's `protected_hostnames` so that the
inventory denies its resolved addresses. A suffix in
`protected_hostname_suffixes` alone gives no address-level denial.

Port 80 is plain HTTP. The guest, the network path and the origin can read and
change that traffic. Grant port 80 only where a builder needs package mirrors
that serve plain HTTP, and rely on the package manager's own signatures.

The broker Pod's NetworkPolicy adds the public ports to its allowed egress ports
with the same private-range, baseline and inventory exclusions.

Each launch creates a tokenless trusted broker Pod outside the Kata namespace.
It starts denied. Proxy settings are installed before the guest starts, including
Docker daemon/client/build settings. External host fencing remains authoritative
when guest root removes those settings. Combined namespace and Pod selectors
limit guest-to-broker traffic; the observed Pod IP is routing information.

Every authorization uses a fresh admitted gateway snapshot and a private broker
control operation bound to the source namespace UID, sandbox, launch nonce,
original expiry, broker process epoch and expected generation. A lease lasts at
most thirty seconds and no longer than the infrastructure inventory or sandbox.
Inspection and cached supervisor acceptance do not renew it. Expiry, cancellation
after mutation and changed policy revoke existing streams. Revocation finishes
before its control acknowledgment. The inventory expires within sixty seconds,
and denied addresses accumulate for each broker's lifetime. Protect public
platform VIPs as well as private ranges; mixed DNS answers are rejected entirely.

The inventory collector includes a Service's `spec.externalName` only when
`include_external_names` is true and its exact `namespace/name` appears in
`trusted_external_name_services`, for example `["infrastructure/database"]`.
The trust list defaults to empty, including for existing configuration files.
Only grant this trust to Service identities whose creation, updates and DNS are
operator-controlled; tenants must not be able to replace or edit them. Other
Services still contribute their observed IP addresses, but their ExternalName
DNS cannot block shared inventory renewal. Configure known protected DNS names
in `protected_hostnames`; these and trusted Service names remain mandatory DNS
observations, so an absent trusted Service or unresolved protected infrastructure
still prevents publication.

When upgrading an existing inventory configuration, explicitly add every
infrastructure hostname that previously depended on automatic ExternalName
collection to `protected_hostnames`, or list its operator-owned Service in
`trusted_external_name_services`. Keeping only `include_external_names: true`
does not retain the old automatic discovery. No production configuration is
migrated by the adapter.

Kubernetes NetworkPolicy permits own-node traffic in cases relevant to this
guest. The hosted profile additionally requires a trusted preboot wrapper and
read-back proof of host-owned TCX ingress/egress programs outside the VM.
Brokered guests use the separate `kata-qemu-runtime-rs-guarded` runtime class
and handler. Scheduling uses the static `pool: kata-workers` selector; readiness
also checks the installed node's `openshell-kata.io/guarded-runtime: "true"` label.
An absent guarded handler prevents VM startup while a new node is configured.

`kata-node-intent` publishes root-owned generation intent from read-only API and
the actual CNI namespace. `kata-runtime-guard` installs the fence before delegating
to the pinned official Kata shim. Unsupported identities, absent intent or
unqualified packet paths fail before VM startup.

The inspected upstream containerd 2.2.7 `podsandbox` path completes CNI before
[sandbox creation/start](https://github.com/containerd/containerd/blob/v2.2.7/internal/cri/server/sandbox_run.go#L241).
It passes the configured
[runtime path to NewTask](https://github.com/containerd/containerd/blob/v2.2.7/internal/cri/server/podsandbox/sandbox_run.go#L219);
the task manager writes the OCI bundle and
[starts the shim before TaskCreate](https://github.com/containerd/containerd/blob/v2.2.7/core/runtime/v2/task_manager.go#L141).
The shim command runs in the
[bundle directory](https://github.com/containerd/containerd/blob/v2.2.7/pkg/shim/util.go#L63).
Qualify the deployed vendor build, sandbox controller, kernel and CNI against
this ordering and the actual traffic tests. Source inspection alone is not live
node qualification. Kata host OCI hooks cannot provide this barrier: the
[4.3.1 call site runs after VM startup](https://github.com/kata-containers/kata-containers/blob/4.3.1/src/runtime-rs/crates/runtimes/virt_container/src/sandbox.rs#L1388).

Never remove an expired host fence merely because an API Pod disappeared or a
timer fired. A partitioned guest may still run. The fence must continue dropping
traffic until exact sandbox termination and interface destruction are proven.

`OPENSHELL_KATA_LIFETIME_SECS` defaults to 3600 and accepts 60–86400 seconds.
The original expiry persists across stop/start. Pod `activeDeadlineSeconds` is
relative to `status.startTime`, so scheduling delay must not be added to the
original lease. The launcher checks expiry on every boot poll, including Pending,
and tightens the relative deadline as soon as startTime appears. Patches test UID,
resource version and launch nonce. Live proof also binds the absolute expiry,
raw sandbox identity and nonce to retained intent. Missing legacy deadlines and
expired leases fail launch and verification; explicit stop/delete remain available.

Deploy an **independent trusted controller** with
`kata-kubernetes reap-expired WORKSPACE`. It reconciles the existing workspace
namespace even after the adapter exits, tightening newly observed start times
and requesting deletion of expired Pending or Running Pods. `--once` executes
one bounded qualification batch and fails if it reports invalid leases or failed
requests. The controller polls every two seconds, bounds
each pass to 60 seconds and each resource operation to 10 seconds, and rotates
batches of 16 with four concurrent operations so persistent errors do not starve
other guests. It needs namespaced Pod get/list/patch/delete and get access to the
exact namespace for ownership validation. It never creates namespaces or retries
with another identity or broader credentials.

Only Pods with the exact managed labels, matching resource/sandbox identity,
canonical UUID nonce/UID, resource version and canonical absolute expiry are
eligible. The annotations are `openshell-kata.io/sandbox-id`,
`openshell-kata.io/launch-nonce` and `openshell-kata.io/expires-at` (Unix seconds).
Only the trusted runtime may write these Pods. Admission must reject updates that
change these identity/expiry annotations. Malformed or foreign objects are
reported and left untouched. Deletes carry UID and resource-version preconditions,
respect the Pod's normal grace period, and never force deletion or remove finalizers.

Controller output reports deletion **requests**, not confirmed VM termination.
Kubelet-relative termination and API/controller reconciliation depend on healthy
control and node agents. A partitioned node can keep running after an API delete;
this profile does not promise strict wall-clock node termination. The local
profile's independent node watchdog provides a different boundary. Proving the
independent hosted controller, admission immutability and failure recovery on a
real cluster remains part of hosted qualification.

Stop removes the Pod while retaining storage and private metadata. Start makes
new keys and a new Pod identity without extending the lease. Delete removes the
Pod, PVC, Secret, network policy and retained key files. Nonce-bound abort never
removes a preexisting generation and preserves a preexisting PVC on failed start.
Cleanup verifies ownership and absence; it never deletes shared namespaces.
Workspace deletion accepts an already absent namespace after a successful
authenticated lookup. Existing namespaces still require matching ownership and
an empty managed-guest inventory; failed observations never count as absence.

## Control and recovery

Lifecycle serialization is per sandbox, so a slow create cannot hold another
sandbox's cancellation behind a global lock. Access is withdrawn before bounded
cleanup. Gateway-session identity and compute-runtime identity are tracked
separately. Supervisor credentials remain in memory and refresh before expiry;
public observations and retained recovery records never contain them.

The private recovery registry retains bounded credential-free intent. Adapter
restart validates all records before mutation, stops retained guests and exposes
Stopped with Ready false. A fresh authenticated Start must repeat admission and
runtime verification. Corrupt records or unconfirmed cleanup prevent serving;
this is not a transparent session-resume mechanism.

Hosted recovery admits two retained sandboxes per workspace by default, including
stopped guests. An operator can set `--workspace-capacity tenant-a=3` for one
workspace; repeat the option for other explicit overrides. Counts must be between
1 and 64, and duplicate workspace entries are rejected. This changes only new
recovery reservations, preserves existing records, and does not enlarge Kubernetes
compute or storage quotas. Unlisted workspaces retain their default limit. Native
node capacity continues to use `--max-sandboxes` independently.

## Integration and qualification

The `kata-workspace` Rust helper is baked into both guest recipes at
`/usr/local/bin/kata-workspace`. `protocol` prints
`openshell-kata-workspace/1`; System checks that compatibility identifier before
use. File operations retain the bounded, digest-checked streaming contract.
The helper is an untrusted guest convenience, not the external security boundary.

Trusted startup can use `kata-operator socket-ready --socket
/run/openshell-kata/private/driver.sock`. Keep the adapter and gateway configured
for that same private child; do not weaken the socket parent's permissions to
accommodate a group-writable Kubernetes mount root.

After quiescing the existing owner and retaining its encrypted backup, restore
the known retained-state permissions in place with:

```sh
kata-operator prepare \
  --state-dir /var/openshell/kata \
  --registry-dir /var/openshell/kata/registry \
  --driver-dir /run/openshell-kata/private \
  --system-ca /etc/ssl/certs/ca-certificates.crt \
  --platform-ca /etc/internal-ca/ca.crt \
  --output /var/run/trust/private/ca-bundle.pem
```

This validates the complete bounded known inventory before changing state
permissions, including retained lock ownership and quiescence checks. It
preserves contents, names and inodes, restores directories to 0700/files to
0600, and invents no metadata or lease deadlines. Unknown entries, links,
foreign ownership and unsafe private-file permissions fail closed. Only known
public-key files and empty locks may carry legacy other-read permission.
Root-owned mount directories remain unchanged; driver/trust use private owned
children. The gateway's `SSL_CERT_FILE` must select the resulting private bundle.

The SRE deployment owner retains cluster installation, trusted identity/access,
namespace admission, image promotion and live tenant qualification. Use the [enforcement contract](ENFORCEMENT_CONTRACT.md) for the current runtime
requirements and qualify the changed hosted behavior against its exact artifacts.
