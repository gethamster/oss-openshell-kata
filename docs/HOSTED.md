# Kubernetes runtime profile

The same Rust adapter supports local Kata guests and an explicitly selected
Kubernetes profile. The operator installs the Kata runtime and admission/network
controls separately. No cloud provider API is required by this launcher.

Select the hosted profile with `--runtime-profile kubernetes`, an immutable
`--guest-image repository@sha256:...`, a private `--guest-network-cidr`, an
absolute `--recovery-dir`, and `--lifecycle /usr/local/bin/kata-kubernetes`.
Repeat `--additional-guest-image repository@sha256:...` to admit operator-pinned
owner images alongside the default image. Every admitted image uses the same
two-vCPU, 4-GiB resource profile and network ceiling. The authenticated sandbox
template selects only an admitted digest; workload inputs cannot alter the
allowlist or runtime settings. Lifecycle and proof checks use that selected
image. Recovery retains the original image while it remains admitted, even if
the default changes; removing it retires that sandbox rather than rebinding its
storage to another image.

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
has a Kata Pod, a private 19 GiB RWO PVC, an SSH Secret and selecting network
policy. The profile is two vCPU, 4 GiB memory and 1 GiB ephemeral storage.
Ephemeral storage uses Kubernetes accounting and eviction, not an instantaneous
block quota. The local block-backed profile separately supports one vCPU and
2 GiB memory/disk. Operator-owned templates must match the selected profile.

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
There is no wildcard, credential, L7, guest filesystem or process identity
capability. Native policy may narrow both the operator ceiling and the immutable
original caller capability. An empty caller policy never gains internet access.
Global effective policies are unsupported for this profile.

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
namespace admission, image promotion and live tenant qualification. The original
hosted sibling `e2d897e` and its image receipts are separate baseline evidence.
The reconciled Rust candidate must repeat the complete System/CLI flow, two-tenant
denials, token renewal, lease expiry, restart/recovery and observation period on
its exact artifacts before promotion. See `DELIVERY_PLAN.md` for current gates.
