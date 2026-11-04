# Hosted preboot intent observer

`kata-node-intent` runs on a trusted Linux node alongside `kata-runtime-guard`.
It observes Kubernetes resources and the CNI network namespace, then publishes
one immutable intent before the runtime guard starts the official Kata shim.
It does not create or modify Kubernetes resources. Unsupported or incomplete
observations leave the launch without intent; the wrapper's bounded preboot
wait then fails closed.

Run `kata-node-intent` continuously, or use `kata-node-intent --once` for one
bounded reconciliation. The latter prints `published`, `rejected` and
`unmanaged` counts and exits unsuccessfully when any inspected bundle is
rejected. This is preparation evidence, not proof that a guest packet fence is
installed. The separate guard verification reads the actual pinned TCX links.

The observer reads `/etc/openshell-kata/node-intent.json`. Every configuration,
executable and bundle path must be absolute, canonical, root-owned and protected
against group or other writes. Projected configuration should be copied into
the trusted host directory rather than supplied through ConfigMap symlinks.

| Version 1 field | Meaning |
| --- | --- |
| `version` | Integer `1` |
| `node_name`, `node_uid`, `boot_id` | Exact live node and boot identities |
| `kubectl_path`, `kubectl_sha256` | Trusted read-only API client and its SHA-256 pin |
| `kubeconfig_path` | Root-owned JSON kubeconfig with one context |
| `bundle_root` | Containerd task bundle directory, mounted at the same path as the host |
| `nsenter_path`, `ip_path` | Trusted Linux namespace and network observation executables |
| `arping_path` | Optional trusted iputils-arping executable; enables bounded preboot gateway-neighbor initialization |
| `broker_namespace`, `broker_namespace_uid` | `openshell-network` and its exact Namespace UID |
| `broker_image`, `guest_image` | Qualified image references pinned by digest |
| `additional_guest_images` | Optional additional qualified guest image digests; defaults to an empty list |
| `operator_network_config_path` | Root-owned immutable `HostedNetworkConfig` JSON shared with the launcher |
| `controller_namespace`, `controller_namespace_uid` | Exact namespace of authorized SSH controller Pods |
| `controller_labels` | Nonempty exact label map selecting those Pods |
| `controller_container_images` | Exact regular container name-to-image-digest map |
| `controller_init_container_images` | Exact init container name-to-image-digest map; defaults to empty |
| `controller_restartable_init_containers` | Names of init containers using `restartPolicy: Always`; defaults to empty |

The guest and its storage initializer must use the same admitted image. Configure
the same default and additional guest pins as the adapter. Additional images keep
the hosted resource profile, network ceiling and generation checks; callers cannot
select an unlisted image or mix two admitted images in one Pod.

The kubeconfig must select one HTTPS cluster with an explicit CA file or CA
data and one user containing only an absolute `tokenFile`. TLS verification
cannot be disabled. Inline tokens, executable credential plugins, impersonation
and alternate contexts are rejected. Kubernetes permissions consist of exact
Pod, Node and Namespace reads, Pod lists in the configured broker/controller
namespaces, and ConfigMap reads in the broker namespace. The observer never
reads Secrets through the API or requests Pod exec access. Its projected
service-account credential belongs only to this trusted observer.

The observer independently checks the CRI Pod UID/name/namespace, source
Namespace UID, immutable original lease, broker Pod UID/IP, source owner
reference and immutable broker configuration digest. The broker capability must
fit the operator network configuration. Controller images and container names
must match exactly. Regular controllers must be running and ready; restartable
init sidecars must also be started and ready; ordinary init containers must
have completed successfully. Extra ephemeral containers and host namespaces
are rejected.

The preboot guest Pod may not yet have a `status.podIP`. The observer obtains
its IPv4 address and MAC from the pinned CNI `eth0` network namespace, then
checks the API address if one is available. A single default route and a known
gateway neighbor MAC must already exist. By default the observer sends no discovery traffic, and a missing neighbor
prevents launch. For a CNI that leaves the gateway unresolved, the operator may
explicitly configure `arping_path` as a protected absolute executable path. Only
while the guest is pending and no guest process has started, the observer sends
one bounded ARP request on the validated `eth0` to its observed default gateway.
It uses the pinned CNI network namespace and no IP probe or guessed MAC. It then
re-reads the interface, address, route and resolved neighbor; changed topology or
a failed/unresolved request produces no intent. The runtime guard still verifies
the established neighbor and installs the same packet fence before VM startup.

The host must create `/run/openshell-kata/intents` as a root-owned private
directory. Publication uses an atomic, non-overwriting `0600` file named by the
Pod UID. Once published, a different broker, lease, controller address or other
binding cannot replace that intent. Controller Pod address changes therefore
require a new sandbox launch generation.

The observer and runtime wrapper share a host-owned generation reservation
budget. A new UID must reserve capacity before any intent, per-UID lock, proof
or pinned object is created. The fixed budget is 512 retained generations per
node. Capacity exhaustion fails new launches; existing generations cannot be
used to acquire fresh authority. This bounds retention while qualified cleanup
is unavailable.

Original lease expiry alone is insufficient permission to unpin a fence: doing
so could reopen traffic from an expired VM that still exists. Pins and retained
proof must remain until qualified cleanup proves the matching VM and network
interface have been destroyed. The eBPF deadline independently denies traffic
while cleanup is pending.
