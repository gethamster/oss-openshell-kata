# Policy enforcement for Docker-capable Kata sandboxes

## Status and execution gate

The local `docker-vm` profile has passed the upload, execution, Docker/Compose,
preview, lifecycle, and external-boundary checks recorded in
[enforcement-qualification.json](../evidence/enforcement-qualification.json).
This document also tracks the larger production matrix. No hosted deployment
is qualified by a passing parser or an acknowledged configuration.

The current explicit prototype mode is for local qualification. It must remain
disabled by default and must not report native filesystem, process, or network
policy as enforced. Hardened admission requires host-observed evidence of its
supported VM controls before Ready.

The policy implementation includes native-policy validation in `src/policy.rs`,
operator-profile compilation in `src/profile.rs`, external network filtering and
brokering, validated transfers, and host-side runtime/resource controls. These
passed the local Rust Kata qualification. The earlier upload-only milestone is
retained separately; neither result qualifies an untested platform or hosted
deployment.

The implementation follows [ENFORCEMENT_CONTRACT.md](ENFORCEMENT_CONTRACT.md):
an explicit operator `docker-vm` policy protects host storage, bounds the whole
VM, and denies direct networking. Native guest filesystem/process restrictions
remain rejected. The contract identifies which controls require host-observed
evidence before hardened Ready and which guest-level guarantees are unsupported.

## Security contract

Treat the entire Docker-capable guest as hostile, including its kernel, Docker
daemon, containers, build steps, agent, and guest management helper. Access to
the guest Docker socket gives the caller effective guest administration even
when the initial agent runs as a non-root user. An immutable image is useful at
boot; it does not keep a running guest trustworthy after guest-root compromise.

Keep the gateway identity, supervisor credentials, SSH host identity, policy
authority, and final network authorization outside that guest. Bind every
control and relay operation to the tenant, workspace, sandbox, immutable runtime
identity, and current generation. Host root and cluster administrators remain
trusted; the adapter does not protect tenants from a compromised cluster
control plane or a hypervisor escape.

| Property | Native OpenShell contract | Docker-capable adapter contract |
| --- | --- | --- |
| Gateway authentication and tenant/workspace authorization | Owned by the unmodified gateway | Retain gateway checks and independently check the sandbox/generation on every adapter operation. |
| Guest filesystem paths | The native backend enforces admitted path restrictions | Guest-root Docker can bypass restrictions inside its guest. Do not claim selective guest-path enforcement. |
| Process UID, capabilities, and syscalls | The native backend qualifies a non-root, capability-free workload | Record the actual entrypoint identity; do not claim that it restricts Docker-created workloads or a compromised guest kernel. |
| Network executable identity | Native mediation can authorize measured workload executables | Authorize the entire sandbox at the external boundary. Reject narrower guest-executable requirements. |
| Resource limits | Depend on the selected runtime | Enforce CPU, memory, lifetime, and storage at the VM/host boundary. Do not advertise a guest process-count guarantee based on host process counts. |
| Provider credentials | Native supervisors keep provider material outside workloads | Real credentials stay on the host. The host broker terminates guest TLS for inspected REST destinations with a per-sandbox CA and substitutes OpenShell placeholders using OpenShell's endpoint-bound resolver; the guest receives placeholders and the public CA only. Other injection forms are rejected. |
| Preview ingress | Gateway routes authorized services | Expose only explicit gateway previews; never create direct application ingress to workload Pods. |

## Native and VM policy representation

The unmodified OpenShell 0.1.6 gateway rejects an unrestricted guest
`read_write: ["/"]` policy as unsafe. Its accepted selective paths, such as
`/sandbox` and `/tmp`, must not be reinterpreted as permission to write the whole
guest. The prototype previously accepted those paths without enforcing them;
that is not a hardened compatibility result.

The adapter must reject a native filesystem policy that it cannot honor.
Use an explicitly supplied native policy containing `version: 1`, optionally
with the supported L4 network subset, together with a separately validated
operator VM policy. Source inspection of the pinned parser and gateway resolver
shows that omitted filesystem/process/Landlock sections remain absent for an
explicit policy without provider/global layers. The final integration must
confirm this through the official CLI and effective snapshot; it must fail if
an additional layer introduces unsupported claims.

The VM policy does not reinterpret native fields. It declares host filesystem
and VM resource boundaries and whole-sandbox network access. Native network
rules must select all executables with `/**` and request destinations within
the operator `tcp_allow` ceiling. An endpoint is either L4 TCP with explicit
`tls: skip`, or, for provider credentials, enforced L7 REST with an access
preset and default TLS handling, which the host broker inspects. Empty native
network rules compile to deny-all even when that ceiling is nonempty.
Gateway-composed `_provider_*` rules name profile executables a VM cannot
attest, so they grant nothing. Narrow executable rules, audit mode, other L7
features, credential fields, and other unsupported endpoint options are
rejected. See the contract's provider credential section for the exact shape. No invented binary identity is sent
to the stock supervisor. This keeps the unmodified OpenShell gateway while
making the coarser VM policy explicit to its operator.

## Admission and capability checks

Implement `validate_policy(&SandboxPolicy) -> Result<ValidatedPolicy, PolicyError>`
as a pure validation step over the vendored OpenShell type. `ValidatedPolicy`
means that the adapter understands the requested intent; it does not mean the
runtime has installed or proved enforcement.

The general validator recognizes a version-1 policy with no requested guest
filesystem, process, Landlock, middleware, or network-access features. The
profile compiler validates native network intent separately and intersects it
with the operator ceiling. It rejects valid selective guest paths as unsupported
and rejects ambiguous paths before reporting capability limitations. Validation
never substitutes a broader policy or returns an enforcement flag. Typed errors
omit supplied paths, identities, and secret values.

Call validation before resource creation and again for the effective
`GetSandboxConfig` snapshot. Require gateway admission, pinned protocol support,
and an exact sandbox/generation match. Reject missing policy, unsupported
versions, selective guest filesystem guarantees, unimplemented process
selectors, narrow guest-binary rules, middleware, credential mechanisms, and endpoint
features. Diagnostics should identify the unsupported field without echoing
secrets. Keep the prototype bypass explicit and separate from hardened mode.

Before a hardened sandbox becomes Ready, independently verify the installed
outer fences and the effective profile. The supervisor polls the gateway every
five seconds, obtains fresh nonce-bound host-runtime evidence, and reports
Accepted/Loaded only after applying and verifying the result. Failed polling,
verification, or unsupported updates fail supervision and stop the hardened VM.
Changed broker policies revoke existing streams before acknowledgment; equal
policies preserve them. This has a polling propagation interval, not immediate
gateway-to-firewall revocation. Never treat the gateway's configuration-admitted
bit as runtime enforcement evidence.

## Filesystem and credentials outside the guest

Use sandbox-private disks and workspace storage. A guest may corrupt its own
disk; it must not gain access to another sandbox's disk or host directories.
Audit the actual Kata storage path, including any virtiofs daemon and its host
permissions. Prefer bounded block-backed guest storage where practical. Do not
claim that a shared host directory is safe merely because it is mounted through
a VM. Host filesystem paths and arbitrary host sockets are not caller inputs.

The import/export store retains validated, sealed USTAR archives under a private
directory capability and never extracts entries on the host. It accepts files
and directories only, bounds bytes and entries, and rejects traversal, links,
devices, sparse files, PAX/GNU extension records, and nonportable paths. It
normalizes ownership/timestamps and special mode bits, then atomically publishes
the archive. Uploads and downloads share two transfer slots; SFTP is rejected in
the hardened profile. See the contract for path limits and transfer deadlines.
Arbitrary exec stdout is not subject to archive quotas and must not be described
as a validated file export.

Keep gateway tokens, SSH private keys, provider material, and cloud credentials
out of guest mounts, environment, logs, images, and upload archives. Any
guest-facing authentication capability must be scoped to that sandbox and
generation and must not authorize a different sandbox. Provider credentials
are injected only by the external broker, which authorizes the destination
and REST operation before resolving a placeholder and revokes installed
material on withheld or invalid snapshots, stop, and delete. The adapter
fetches them with the sandbox's own supervisor JWT and passes snapshots to the
broker only over stdin and its root-only control socket. The per-sandbox proxy
CA key stays in a root-only node directory and the broker's memory.

## Network enforcement outside the guest

Install an independently enforced deny-all egress and ingress fence before any
untrusted guest instruction. The only external path is a sandbox-bound relay to
the trusted control/egress adapter. Guest iptables, proxy environment variables,
and guest process identity are not security boundaries.

The external adapter captures and validates the destination, resolves names,
checks policy, and opens approved upstream connections. Check resolved addresses
at connection time and on every redirect/re-resolution; deny metadata,
loopback, link-local, multicast, and unspecified destinations. Private services
require explicit operator-authorized destinations. Prevent DNS rebinding and
cross-sandbox relay reuse. DNS itself is an egress channel and must not offer
unrestricted external recursion from the guest.

The supported profile has no middleware, wildcard destinations, or guest
UDP/DNS. The external broker resolves exact hostname/port selectors to public
IPs and rejects non-global and mixed DNS results. Direct traffic remains
blocked. The TCP proxy does not enforce TLS SNI or virtual-host identity on a
shared public address for `tls: skip` destinations. TLS inspection, REST
access presets, and header/request-line credential substitution apply only to
inspected destinations; explicit method/path rules, body credential rewriting,
WebSocket and HTTP/2 inspection, and generic UDP remain unsupported.

Apply policy revisions atomically. Revoke or terminate existing connections
when a new policy removes their authorization. Losing policy/control service
must never open a direct route. Preview ports remain reachable only through the
authenticated gateway, with per-sandbox authorization and explicit port grants.

## Process and resource enforcement

The local profile uses Kata 4.3.1 runtime-rs/Dragonball with one vCPU, 2048 MiB
RAM, and a private 2048 MiB devmapper block-backed root image. Boot with this
configuration passed the local combined CLI and boundary qualification. Other
sizes and platforms must be rejected until implemented and
verified. A node-side watchdog enforces the configured VM lifetime independently
of the guest. Host process limits constrain the VMM and relay, not the number of
guest processes. Test fork bombs and memory/CPU/disk exhaustion at the guest
boundary. The hardened profile has no Go Kata fallback.

Implement stop/delete as authoritative destruction or termination of the VM
and its external relay. Guest cooperation can improve shutdown but cannot be
required for containment. Define command cancellation separately from stopping
the whole VM; a Docker-created detached process may survive a command's exit.
Do not expose arbitrary host devices, KVM handles, or runtime sockets to callers.

## Implementation sequence

1. **Pass the local upload gate.** Check repeated and concurrent binary transfers,
   hashes, executable permissions, failure cleanup, and command progress with the
   official unmodified CLI. Preserve reproducible evidence.
2. **Implement fail-closed policy validation.** The validator, operator-profile
   compiler, and effective-snapshot integration are implemented and passed the
   local CLI proof path. Extend qualification for each additional platform.
3. **Prove isolation of secrets and host storage.** Test the private block-backed
   storage and validated archive store against cross-sandbox and path attacks.
4. **Qualify the external deny-all fence.** Test it from the agent,
   rootful Docker daemon, build step, and Compose service, including after guest
   firewall changes and control-service failure.
5. **Qualify bounded external TCP authorization.** Test exact destinations,
   external DNS resolution, sandbox binding, policy revisions, revocation, and
   explicit previews together. The profile blocks guest UDP/DNS; clients use the
   broker for hostname-bearing requests. Validate every accepted effective-policy
   and operator-profile field before claiming hardened support.
6. **Add optional features independently.** Credential injection through the
   host broker is implemented with unit and broker-level tests (placeholder
   substitution against a local TLS upstream, endpoint scoping, revocation,
   peer binding, CA isolation, and no secret in guest files or logs); it needs
   qualification on each deployed node. Explicit L7 rules, middleware, resource
   extensions, and platform launchers each need positive and adversarial tests.
   Unimplemented features remain rejected.

The supported local profile is implemented and qualified as recorded in the
evidence. The broader adversarial matrix below remains a production gate:
multi-tenant load/exhaustion, crash recovery, launcher replacement, and every
deployment platform need separate qualification. A configuration flag is not proof.

## Required adversarial tests

- Reject accepted-by-gateway guest-path policies that the adapter cannot enforce,
  unsupported policy versions, narrow executable rules, and unimplemented
  provider/middleware settings before creating a VM.
- Try raw IPv4/IPv6, alternate DNS, metadata access, DNS rebinding, HTTP redirects,
  proxy-variable removal, guest firewall replacement, host networking in an
  inner container, and guest-root network changes. Verify external denial.
- Exercise approved and denied destinations from agent code, `docker pull`, a
  BuildKit build step, and a detached Compose service. Record external evidence.
- Attempt another sandbox's socket, relay, generation, preview, data disk, and
  imported files. Test stale credentials after stop/restart and deletion.
- Exercise upload/export traversal, symlink swaps, hard links, oversized archives,
  special files, partial transfer, concurrent transfer, and sandbox teardown.
- Rotate/revoke policy while a connection is active, disconnect the supervisor,
  restart the adapter, and replace the workload Pod. No case may gain access.
- Exhaust guest CPU, memory, disk, processes, and connections while checking that
  other sandboxes and trusted control services remain responsive.

## Upstream evidence and portability

Pin OpenShell 0.1.6 and qualify its private supervisor protocol on upgrades.
The external driver contract expressly permits policy enforcement outside the
stock supervisor. Native backend audit checks are not a universal guarantee for
external backends:

- [External driver policy contract](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/proto/compute_driver.proto#L191)
- [Native-only audit validation](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/crates/openshell-sandbox-backend/src/runtime.rs#L739)
- [Executable identity semantics](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/crates/openshell-isolation-interface/src/contract.rs#L418)
- [Kubernetes driver configuration limits](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/crates/openshell-driver-kubernetes/src/driver.rs#L508)

Share the policy/control contract and guest image profile across deployments;
qualify the launcher and external fences separately on each platform. Kata needs
bare metal or nested virtualization. A Linux VM on macOS or Windows does not
automatically expose nested virtualization. Local native OpenShell defaults stay
unchanged; this adapter must advertise only the launchers it has tested.
