# Docker VM enforcement contract

This contract describes the implemented policy schema and the enforcement
requirements of the `docker-vm` profile. Local qualification is recorded in
[enforcement-qualification.json](../evidence/enforcement-qualification.json);
the broader production matrix below remains open. A working Docker daemon or
a passing upload test does not establish every guarantee below. The runtime must install the controls and
return host-observed evidence before the adapter admits execution. Unsupported
platform capabilities cause a launch failure.

## Boundary and identity

The Kata guest, its kernel, Docker daemon, application containers, agent, and
guest helper are one untrusted workload. Docker administration intentionally
permits guest-root operations. The outer Linux host, hypervisor, runtime,
external control adapter, and policy file owner remain trusted.

Every operation binds to a gateway-authorized tenant/workspace and sandbox ID,
its concrete runtime instance, and one launch generation. Guest IPs, names,
process output, and guest-provided labels are not identity proofs. Reuse of an
IP or sandbox name must not authorize a retired generation.

The OpenShell supervisor-facing SSH host key, gateway JWTs, guest SSH client
private key, provider credentials, the per-sandbox proxy CA private key, and
policy authority remain outside the guest. The separate guest SSH server has a guest-local host key; that key proves
the pinned guest transport, not gateway authorization. Compromise of that guest
key must not authorize another sandbox or the OpenShell gateway.

## Two policy inputs

Keep the upstream OpenShell wire API unchanged. Each hardened launch requires:

1. An explicitly supplied native policy: `version: 1`, with no filesystem,
   process, Landlock, middleware, or narrow executable claims, and no
   credential mechanism other than gateway provider credentials injected by
   the host broker. The supported native network subset is described below.
2. A trusted operator VM policy selected by `--vm-policy /absolute/path.json`.

The native policy is not silently rewritten. The adapter checks both the
create-time policy and each effective policy snapshot. If a gateway-global
policy, provider, or update introduces unsupported native claims, reject it
before launch or stop the running sandbox. Missing native policy is not
equivalent to a minimal explicit policy.

The pinned upstream parser represents absent filesystem, process, and Landlock
sections as `None`. The gateway's captured-policy resolver preserves an explicit
policy and composes provider layers; it does not insert the restrictive default
filesystem in that path. Verify the complete path against the stock gateway
with `--policy` pointing to a file containing only `version: 1`, then inspect the
effective snapshot. Do not infer this from testing the adapter alone. A global
policy or provider can change the result. Omit the sections; an empty filesystem
section is not the requested representation.

The VM policy is operator configuration, never a sandbox environment variable
or a caller-selected host path. Load it before starting the driver, reject
unknown fields and invalid numbers, and retain an immutable parsed snapshot.
Require explicit process restart or a separately implemented atomic reload to
change it. Canonically encode and hash the validated profile; bind that hash
into each runtime generation and its enforcement evidence.

## Operator policy schema

The version-1 schema uses integer quantities and a single explicit profile:

```json
{
  "version": 1,
  "profile": "docker-vm",
  "resources": {
    "vcpus": 1,
    "memory_mib": 2048,
    "disk_mib": 2048,
    "lifetime_secs": 3600
  },
  "filesystem": {
    "host_mounts": "deny",
    "transfer_max_bytes": 268435456,
    "transfer_max_entries": 4096
  },
  "network": {
    "tcp_allow": []
  }
}
```

All resource limits must be positive, fit checked unit conversions, and stay
within the runtime's supported allocation range. The operator selects an exact
resource profile with the lifecycle helper's `--resource-profile` argument:

| Profile | vCPUs | Guest RAM (MiB) | Private disk (MiB) | Provisioning |
| --- | ---: | ---: | ---: | --- |
| `local` | 1 | 2048 | 2048 | Lima or native Linux |
| `build` | 16 | 49152 | 32768 | Lima |
| `foundry-build` | 32 | 131072 | 262144 | Native Linux |

The node's Kata configuration and devmapper snapshot size must match the selected
profile; mismatches fail before readiness. Lifetime is configurable within the validated
operator limit. The generic resource validator has broader ceilings, which do
not establish local runtime support. Caller resource overrides are currently
rejected. `disk_mib` describes the private guest disk, not just a Docker tmpfs.

`host_mounts` accepts only `deny` in version 1. The transfer limits bound a
single brokered import/export operation. A transfer has an opaque store ID and
an authorized relative path; it cannot name an arbitrary host directory.

Each `tcp_allow` entry contains one exact DNS hostname and one port:

```json
{"host": "example.com", "port": 443}
```

An empty list denies every upstream connection. Direct guest connections are
always denied, regardless of this list. Host globs, URLs, userinfo, non-global
IP literals, and ports outside 1 through 65535 are rejected. Exact ASCII DNS
names and globally routable IP literals are supported. DNS case and a terminal
dot are normalized; duplicate normalized endpoints collapse into one rule.
The external broker resolves names and rejects non-global or mixed
public/private results at connection time. Version 1 does not allow private
destinations, HTTP path restrictions, or arbitrary UDP. The operator ceiling
lists TCP destinations only; TLS inspection is compiled from native intent
(below) and never authored in the operator policy.

The optional `tcp_allow_public_ports` list (at most 16 nonzero ports, for
example `[443, 80]`) admits any public DNS name or global IP literal on those
ports. It is for build sandboxes only. The broker applies the same resolved
address checks, never inspects the traffic, and denies the same names. Omitting
the field keeps the exact behaviour and the existing policy encoding and digest.

### Native network policy can only narrow the operator ceiling

The operator `tcp_allow` list is a maximum, not automatic permission. A native
policy with no network rules compiles to deny-all even when the operator ceiling
contains destinations. To permit one endpoint, the native policy must explicitly
request it using the all-executables selector and opaque TCP transport:

```yaml
version: 1
network_policies:
  public_https:
    endpoints:
      - host: example.com
        port: 443
        protocol: tcp
        tls: skip
    binaries:
      - path: "/**"
```

Every native rule requires endpoints and only `/**` executable selectors.
Use an empty protocol or `tcp` and explicit `tls: skip`. Omit the L7-only
`enforcement` authoring field: the pinned gateway rejects it on TCP rules.
The runtime rejects audit mode. A single
port or a list of ports is supported; conflicting simultaneous forms are
rejected. Every resulting host/port must exist in the operator ceiling. A host
of `**` (or an empty host without `allowed_ips`) requests any public host on
its ports; each port must be in the ceiling's `tcp_allow_public_ports`. The
broker still refuses non-global, denied and protected destinations on those
ports and never inspects them (see [HOSTED.md](HOSTED.md)).

Other endpoint features are rejected on these TCP endpoints, including L7
rules, credentialed-provider markers, credential binding/signing/rewriting,
private-IP overrides, and inspection configuration. The gateway's well-formed
opaque `token_grant_owner` provenance is accepted; it never enables credential
access. Credentialed destinations use the inspected REST shape below.
This is whole-sandbox permission, with no assertion about which
guest binary opened a connection. It does not weaken a narrow binary rule into
an all-binary rule.

These rules authorize TCP transport to an address selected by the hostname.
The broker does not authenticate TLS SNI or the virtual HTTP service at a shared
public IP. TLS remains end-to-end between the guest and upstream, and guest
certificate verification is not a substitute for broker L7 enforcement.

### Provider credentials are injected by the host broker

Attached OpenShell providers (for example a member's `claude-subscription`, or
`github-user`/`github-repo` tokens) are supported only through host-side
injection. The real credential never enters the guest; the guest holds
OpenShell placeholders (`openshell:resolve:env:...`), exactly as a native
sandbox child does. A credentialed destination must be requested as inspected
L7 REST in an all-executable rule:

```yaml
version: 1
network_policies:
  model_and_subscriptions:
    binaries:
      - path: "/**"
    endpoints:
      - host: api.anthropic.com
        port: 443
        protocol: rest
        access: read-write      # read-only | read-write | full
        enforcement: enforce
      - host: github.com
        port: 443
        protocol: rest
        access: read-write
        enforcement: enforce
      - host: api.github.com
        port: 443
        protocol: rest
        access: read-write
        enforcement: enforce
      - host: chatgpt.com       # uncredentialed: unchanged opaque TCP
        port: 443
        tls: skip
```

Omit `tls` (OpenShell's default selects inspection); `tls: skip`, audit mode,
explicit `rules`/`deny_rules`, `path`, credential binding/signing, body or
WebSocket rewriting, `allow_uninspected_credentials`, private-IP overrides, and
IP-literal hosts are rejected. The gateway stamps `provider_credentialed` on
endpoints its attached providers bind, and requires a stamped endpoint to be
inspected; a stamped TCP endpoint is rejected here as well. One host/port is
either opaque or inspected, never both; matching REST rules union their
presets. Each destination must also exist in the operator `tcp_allow` ceiling.

The gateway also composes one reserved `_provider_<name>` rule per attached
provider from its profile, naming the profile's executables and L7 rules. A VM
cannot attest guest executables, so these rules grant nothing here: the
sandbox's own all-executable rule must authorize every destination. Dropping a
grant only narrows access. A user-authored narrow executable rule is still
rejected. Access is whole-sandbox: any guest process may use a credential at
its bound endpoints, with no claim about which executable sent a request.

The host broker enforces the following for an inspected destination:

- **TLS terminates on the host.** At creation the node generates a per-sandbox
  CA (`kata-network ca-generate`) in a root-only directory
  (`/var/lib/openshell-kata/jobs/<id>/tls`, key mode 0600). Its private key is
  delivered to the unprivileged broker only as a systemd credential and is
  removed with the sandbox. The public certificate, plus a bundle of the image's
  system roots and that certificate, is written beneath the mounted pristine
  operator image before first boot at `/etc/openshell-tls/openshell-ca.pem` and
  `/etc/openshell-tls/ca-bundle.pem`, without following links out of the guest
  root. Commands started by the adapter receive the native supervisor's trust
  variables (`NODE_EXTRA_CA_CERTS`, `DENO_CERT`, `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`). Sandboxes created
  before this support have no CA; their inspected destinations are refused.
- **Only the fenced guest is served.** Inspection requires `CONNECT` from the
  guest's own address; plain-HTTP forwarding and other peers are refused.
- **One request per tunnel, with OpenShell L7 handling.** The broker requires an
  origin-form HTTP/1.x request whose `Host` names the tunnel destination,
  rejects upgrades, HTTP/2, ambiguous framing and smuggling forms, applies the
  REST access preset (read-only: GET/HEAD/OPTIONS; read-write adds
  POST/PUT/PATCH; full admits all), and forwards with `Connection: close`.
- **OpenShell substitutes credentials.** Placeholders in the request line and
  headers (including Basic authorization) are resolved by OpenShell's
  `ProviderCredentialState` and `rewrite_http_header_block`, only for
  credentials whose gateway static binding covers the destination host, port,
  and path. An unresolvable or out-of-scope placeholder fails the request
  before anything is sent upstream.
- **Verified TLS upstream.** The broker originates TLS to the real host and
  verifies it against public roots plus the node's system bundle.

The adapter obtains credentials as a native supervisor does: it calls
`GetSandboxProviderEnvironment` with the sandbox's own renewed supervisor
JWT, declaring static endpoint bindings and stable placeholders, and requires
the snapshot to match the effective configuration's provider revision,
attachment epoch, and policy hash (re-reading both if a refresh lands between
them). A changed snapshot, including a gateway-refreshed `github-user` token,
is written to the lifecycle helper's stdin, then to `kata-network credentials`
on the node, then over the broker's root-only control socket. It is never in
arguments, files, the environment, or logs; the broker replies with
placeholders and the public certificate only. Gateway-withheld material,
dynamic token grants, provider-managed files, unbound credentials, and invalid
snapshots revoke every installed credential and are reported without values.
Stop and delete stop the broker, which holds credentials only in memory;
broker revocation and process exit discard them. OpenShell's retention of
recent placeholder generations within one provider identity applies unchanged.

## Runtime interface

The core driver validates both policies before invoking lifecycle operations.
The runtime receives a structured validated profile and trusted launch binding;
it never receives a shell fragment or a caller-controlled command prefix.
The recommended interface has these responsibilities:

| Operation | Required behavior |
| --- | --- |
| Create | Reserve bounded storage, allocate the isolated runtime, install external network rules, and retain a launch binding before starting untrusted code. |
| Verify | Answer a fresh nonce challenge after observing the actual runtime class, VM allocation, storage limits/mounts, interface identity, and installed rule set. Compare them with the requested profile and current launch. |
| Start | Refuse stale profile or generation state; reinstall and verify fences before resuming execution. |
| Stop | Revoke network and preview access, then stop the complete runtime without relying on guest cooperation. |
| Delete | Revoke access first, confirm the runtime is absent, then release storage, forwarding state, and credentials. |

Use distinct types for a validated profile and verified runtime state. A value
that merely records requested settings must never satisfy the verification
interface. Bind evidence to the sandbox ID, instance identity, generation,
profile hash, and observation time. A nonce can prevent stale association but
does not prove that a setting was installed; signatures do not replace actual
host observations either.

The adapter may publish Ready only after verifying the outer controls and
receiving an admitted effective native policy. It polls the effective gateway
configuration every five seconds and challenges the runtime with a fresh nonce.
Changed native rules compile under the original operator ceiling and trigger a
runtime update; unchanged rules trigger fresh verification. The adapter reports
configuration Accepted and policy Loaded only after application and checks.
An unsupported update or a failed poll/verification fails supervision and stops
the hardened VM. Polling has a propagation interval; it is not instantaneous
gateway-to-firewall revocation. The adapter must not translate
`configuration_admitted=true` or a successful SSH connection into enforcement
evidence. Guest commands, `/proc` output, and assertions from the guest helper
can supplement functional tests but cannot attest host controls.

## Filesystem enforcement

Give each guest a private writable storage budget. The host denies arbitrary
host mounts and node runtime sockets. Audit every host filesystem export used
by Kata, including its rootfs and virtiofs daemon: a declared mount list is not
proof that a compromised guest kernel cannot access additional host paths.

Bound all writable backing with a real per-sandbox quota or capacity. A Docker
tmpfs limit alone is insufficient when the guest root filesystem can still
grow in a shared containerd snapshot. A host-enforced read-only base with
bounded writable volumes is another valid implementation if it supports the
declared guest behavior. Reject the profile when neither storage arrangement
is available.

Host import/export uses a store owned by the external adapter. Resolve relative
paths beneath a pinned directory capability, reject escapes and special files,
and defend against symlink and rename races. Bound byte count and entry count;
publish imports atomically after validation. Never extract an untrusted archive
directly into an arbitrary host path. A read-only source cannot be modified by
export or cleanup operations.

The first store implementation retains canonical sealed USTAR archives and
does not unpack their entries on the host. It accepts regular files and
directories only, with UTF-8 paths of at most 255 bytes and 32 components.
Symlinks, hard links, sparse files, devices, PAX headers, and GNU extension
headers are rejected. It normalizes harmless `./` prefixes and executable bits,
strips ownership/timestamps/special mode bits, and bounds both content and wire
size. These format restrictions are part of the supported transfer interface;
callers must not interpret a rejected richer archive as a successful import.

Upload and download share a two-transfer limit per sandbox. The transfer paths
use bounded buffers, 30-second idle timeouts, and 600-second bounded transfer
stages. Upload receipt and guest extraction currently have separate deadline
budgets; download wraps its complete operation in a 600-second deadline. SFTP
is rejected in the hardened profile because it would bypass validated archive
transfers. Use the OpenShell upload/download operations.

These controls protect host and other-tenant files. They deliberately do not
restrict which private guest files Docker root may change. Arbitrary command
stdout is not classified as a file transfer or subject to archive quotas; VM
resource/lifetime limits still apply. An operator who permits arbitrary exec
must not claim that the file-transfer quota prevents all data export.

## Process and resource enforcement

Enforce the configured vCPU and memory allocation outside the guest. Account
for host VMM overhead separately from the guest's requested memory. The local
profile grants 2048 MiB of guest RAM and caps both the parent and shim cgroups
at 2304 MiB, including a 256 MiB host runtime allowance. Larger profiles reserve
the larger of 256 MiB and 1/64 of guest RAM (2048 MiB for the 128 GiB
`foundry-build` profile), since host page tables grow with touched guest RAM. The allowance
does not enlarge guest RAM; unlimited or mismatched host caps are rejected. The host
must reserve sufficient capacity for concurrent guests and trusted services;
per-guest limits do not justify unlimited aggregate admission.

Start the lifetime clock once for each launch generation. Persist its deadline
so an adapter restart does not extend it. When the deadline expires, revoke
network access and terminate the whole VM. Stop/delete must not depend on a
guest agent responding to a signal. Command cancellation and VM termination
remain separate operations; detached Docker services may outlive one command.

A host PID cgroup measures VMM threads, not guest processes. Version 1 makes no
guest PID-count, guest syscall, selective execution, or guest-executable identity
guarantee. A malicious guest can lie about its build result; successful command
output is not evidence that it honored a security policy.

## Network enforcement

Bind the outer rules to the actual host-side sandbox interface and runtime
identity. Source IP alone is insufficient because guest root can spoof it.
Use interface-scoped filtering to deny direct external traffic, sibling
traffic, node services, alternate protocols, and IPv6 bypasses. Ensure later
CNI changes cannot insert a permissive rule ahead of the enforcement point.

The guest can reach only its assigned external broker and established replies
for the authorized control path. The broker owns upstream DNS and TCP dialing,
checks the exact allowlist, and applies connection and byte limits. Require
unambiguous parsing of CONNECT authorities and absolute-form HTTP requests;
reject conflicting authorities, userinfo, unsupported framing, and invalid
ports. Validate the chosen IP after DNS resolution. Raw TCP and TLS to
`tls: skip` destinations remain opaque; do not claim per-request or TLS-content
enforcement there. Inspected REST destinations follow the provider credential
section above.

Changed broker policy revokes and drains the old generation's connections before
publishing the new rules. Reapplying identical policy keeps existing streams.
Broker failure must leave the external fence closed. Guest changes to
routes, iptables, DNS, proxy environment, or inner Docker networking cannot
disable the outer fence. Authorized preview traffic uses the gateway and an
explicit loopback port; workload Pods receive no direct application ingress.

## Qualification that proves the boundary

The local evidence covers the full stock-CLI flow, guest-root network attacks,
archive adversarial tests, host resource/storage bounds, and independent expiry.
The following is the broader production matrix, including unqualified crash,
multi-tenant exhaustion, and platform scenarios. Component tests and the earlier
prototype's CLI flows are not a substitute for these scenarios:

- Use the stock CLI to create, execute, transfer a binary with hash comparison,
  build an image, run Compose services, open an explicit preview, stop/start,
  and delete. The guest may use root through Docker during these tests.
- Read the effective native policy and show that its omitted sections remain
  omitted. A native restrictive-path, process, or binary policy must be rejected
  before VM creation; an incompatible update must revoke the running boundary.
- Attempt direct TCP, raw source spoofing, IPv6, UDP/DNS, metadata access, node
  access, and sibling access from the shell, Docker build, privileged inner
  container, and detached application. Observe denial from outside the guest.
- Demonstrate one allowed broker connection and one denied hostname/port, reject
  private/mixed DNS answers and authority confusion, and revoke a live stream.
- With a provider attached, show the guest environment and files hold only
  placeholders and the public CA, an inspected request reaches the upstream
  with the real credential, and the request fails after the provider is
  detached, at an unbound host, from another peer, and after stop.
- Try archive traversal, symlink swaps, hard links, special files, oversized
  transfers, and another sandbox's store ID. Verify host canaries are unchanged.
- Exhaust guest memory and every writable filesystem, and outlive the deadline.
  Verify host-observed bounds, VM termination, and another guest's health.
- Stop the broker, restart the adapter, replace the interface/runtime, replay
  old metadata, and reuse an IP. No stale binding may restore access.

Passing one local host profile does not qualify every cloud or operating system.
Use the same policy schema and guest contract across launchers, while testing
their actual VM, storage, and firewall implementations separately.

## Python and Go in the current implementation

The OpenShell adapter, policy compiler, network broker, transfer validation, and
hardened lifecycle implementation, setup orchestration, and CLI test harness
are Rust. The former Python helpers and prototype launcher have been removed.
Shell scripts provision the dedicated node and image; Docker, containerd,
nerdctl, and Lima remain upstream dependencies with their own implementation
languages. No Python or Go helper implements our policy boundary.

The selected upstream Kata runtime is `runtime-rs` with Dragonball from Kata
4.3.1. Its private block-backed root passed the local CLI and boundary tests.
There is no Go runtime fallback in the hardened profile. These local results
do not establish production, GKE, cross-cloud, or all-OS qualification.
