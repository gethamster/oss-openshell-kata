//! Native TCP intent compiled beneath an immutable operator ceiling.
use super::{Endpoint, InspectedEndpoint, Inspection, NetworkPolicy, RestAccess};
use crate::proto::openshell::sandbox::v1::{NetworkEndpoint, SandboxPolicy};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};

/// Gateway-reserved key prefix of rules composed from attached provider
/// profiles (OpenShell `PROVIDER_RULE_NAME_PREFIX`); users cannot author it.
const PROVIDER_RULE_PREFIX: &str = "_provider_";
/// `NetworkEndpoint.tls` values: unspecified selects inspection, 1 is `skip`.
const TLS_UNSPECIFIED: i32 = 0;
const TLS_SKIP: i32 = 1;
const ENFORCE: i32 = 1;

/// Compile supported native intent; omitted network rules grant no access.
///
/// # Errors
/// Rejects unsupported native guarantees and destinations outside the ceiling.
pub fn compile_native(native: &SandboxPolicy, ceiling: &NetworkPolicy) -> Result<NetworkPolicy> {
    compile(native, ceiling, false)
}

/// Compile native intent for a broker that terminates TLS for L7 REST
/// endpoints and injects provider credentials outside the guest.
///
/// Gateway-composed provider rules declare where a provider's credentials
/// may be used and which executables may use them. A VM cannot attest guest
/// executables, so those rules grant nothing here; the sandbox's own
/// all-executable rule must authorize every destination.
///
/// # Errors
/// Rejects unsupported native guarantees and destinations outside the ceiling.
pub fn compile_native_with_inspection(
    native: &SandboxPolicy,
    ceiling: &NetworkPolicy,
) -> Result<NetworkPolicy> {
    compile(native, ceiling, true)
}

fn compile(
    native: &SandboxPolicy,
    ceiling: &NetworkPolicy,
    inspection: bool,
) -> Result<NetworkPolicy> {
    let without_network = SandboxPolicy {
        network_policies: Default::default(),
        ..native.clone()
    };
    let _intent = crate::policy::validate_policy(&without_network)?;
    let ceiling = ceiling.validate()?;
    let mut allowed = BTreeSet::new();
    let mut inspected: BTreeMap<Endpoint, Inspection> = BTreeMap::new();
    let mut public_ports = BTreeSet::new();
    for (name, rule) in &native.network_policies {
        if inspection && name.starts_with(PROVIDER_RULE_PREFIX) {
            continue;
        }
        if rule.binaries.is_empty() || rule.endpoints.is_empty() {
            bail!("network rule requires endpoints and all-binary selector");
        }
        for binary in &rule.binaries {
            let all_binaries =
                crate::proto::openshell::sandbox::v1::NetworkBinary { path: "/**".into() };
            if binary.path != "/**" || binary != &all_binaries {
                bail!("guest executable identity enforcement is unsupported");
            }
        }
        for endpoint in &rule.endpoints {
            let requested = if inspection && endpoint.protocol == "rest" {
                Some(validate_rest_endpoint(endpoint)?)
            } else {
                validate_endpoint(endpoint)?;
                None
            };
            let ports = if endpoint.ports.is_empty() {
                vec![endpoint.port]
            } else {
                endpoint.ports.clone()
            };
            for port in ports {
                let port = u16::try_from(port).context("invalid TCP port")?;
                if is_public_host(&endpoint.host) {
                    if requested.is_some() {
                        bail!("public-host endpoints cannot be inspected; use tls skip");
                    }
                    if port == 0 {
                        bail!("TCP destination port must be nonzero");
                    }
                    if !ceiling.allows_public_port(port) {
                        bail!("native public port exceeds operator network ceiling");
                    }
                    public_ports.insert(port);
                    continue;
                }
                NetworkPolicy {
                    tcp_allow: vec![Endpoint {
                        host: endpoint.host.clone(),
                        port,
                    }],
                    ..Default::default()
                }
                .validate()?;
                // Inspection and credentials need an exact ceiling entry;
                // a public port only ever grants opaque TCP.
                let within = if requested.is_some() {
                    ceiling.allows_exact(&endpoint.host, port)
                } else {
                    ceiling.allows(&endpoint.host, port)
                };
                if !within {
                    bail!("native destination exceeds operator network ceiling");
                }
                // Policy validation canonicalizes DNS case and terminal dot.
                let host = endpoint.host.trim_end_matches('.').to_ascii_lowercase();
                let host = host
                    .parse::<std::net::IpAddr>()
                    .map_or(host, |ip| ip.to_string());
                let destination = Endpoint { host, port };
                // One destination has one transport: opaque or inspected.
                if allowed.contains(&destination)
                    && requested.is_some() != inspected.contains_key(&destination)
                {
                    bail!("destination mixes tls: skip and inspected REST rules");
                }
                if let Some(requested) = requested {
                    let entry = inspected.entry(destination.clone()).or_insert(requested);
                    // OpenShell unions matching rules; presets are nested.
                    entry.access = entry.access.max(requested.access);
                    // One destination has one behavior: as in OpenShell, the
                    // opt-out holds only when every rule for it agrees.
                    entry.allow_uninspected_credentials &= requested.allow_uninspected_credentials;
                }
                allowed.insert(destination);
            }
        }
    }

    let policy = NetworkPolicy {
        tcp_allow: allowed.into_iter().collect(),
        tls_inspect: inspected
            .into_iter()
            .map(|(endpoint, inspection)| InspectedEndpoint {
                host: endpoint.host,
                port: endpoint.port,
                access: inspection.access,
                allow_uninspected_credentials: inspection.allow_uninspected_credentials,
            })
            .collect(),
        tcp_allow_public_ports: public_ports.into_iter().collect(),
    };
    policy.validate()?;
    Ok(policy)
}

/// `**` (every name) selects any public DNS name on the endpoint's ports.
/// An empty host stays invalid, as in OpenShell without `allowed_ips`.
fn is_public_host(host: &str) -> bool {
    host == "**"
}

/// The supported credential-bearing shape: L7 REST with TLS terminated by the
/// host broker, enforced, with an access preset and no other L7 features.
/// `allow_uninspected_credentials` is OpenShell's opt-in to content the proxy
/// does not read; the broker then relays a WebSocket upgrade (see
/// `Mediation::relay`).
fn validate_rest_endpoint(endpoint: &NetworkEndpoint) -> Result<Inspection> {
    let supported = NetworkEndpoint {
        host: endpoint.host.clone(),
        port: endpoint.port,
        ports: endpoint.ports.clone(),
        protocol: endpoint.protocol.clone(),
        tls: endpoint.tls,
        enforcement: endpoint.enforcement,
        access: endpoint.access,
        allow_uninspected_credentials: endpoint.allow_uninspected_credentials,
        // The gateway stamps provider credential scope and grant provenance.
        provider_credentialed: endpoint.provider_credentialed,
        token_grant_owner: endpoint.token_grant_owner.clone(),
        ..Default::default()
    };
    if endpoint != &supported
        || endpoint.tls != TLS_UNSPECIFIED
        || endpoint.enforcement != ENFORCE
        || !valid_owner(&endpoint.token_grant_owner)
    {
        bail!(
            "REST endpoint requires unsupported fields [{}] or TLS/enforcement behavior (tls_mode={}, enforcement_mode={}); use protocol rest, an access preset and enforcement enforce without tls",
            unsupported_fields(endpoint, true),
            endpoint.tls,
            endpoint.enforcement
        );
    }
    if endpoint.port != 0 && !endpoint.ports.is_empty() && endpoint.ports != [endpoint.port] {
        bail!("ambiguous endpoint ports");
    }
    let access = match endpoint.access {
        1 => RestAccess::ReadOnly,
        2 => RestAccess::ReadWrite,
        3 => RestAccess::Full,
        _ => bail!("REST endpoint requires a read-only, read-write or full access preset"),
    };
    Ok(Inspection {
        access,
        allow_uninspected_credentials: endpoint.allow_uninspected_credentials,
    })
}

fn validate_endpoint(endpoint: &NetworkEndpoint) -> Result<()> {
    let supported = NetworkEndpoint {
        host: endpoint.host.clone(),
        port: endpoint.port,
        ports: endpoint.ports.clone(),
        protocol: endpoint.protocol.clone(),
        tls: endpoint.tls,
        enforcement: endpoint.enforcement,
        // The gateway stamps this opaque authority even on uncredentialed
        // global TCP policies. It conveys no credentials to this runtime.
        token_grant_owner: endpoint.token_grant_owner.clone(),
        ..Default::default()
    };
    if endpoint != &supported
        || !matches!(endpoint.protocol.as_str(), "" | "tcp")
        || endpoint.tls != TLS_SKIP
        || !matches!(endpoint.enforcement, 0 | 1)
        || !valid_owner(&endpoint.token_grant_owner)
    {
        bail!(
            "endpoint requires unsupported fields [{}], protocol or TLS behavior (tcp={}, tls_mode={}, enforcement_mode={}); use explicit tls skip and TCP",
            unsupported_fields(endpoint, false),
            matches!(endpoint.protocol.as_str(), "" | "tcp"),
            endpoint.tls,
            endpoint.enforcement
        );
    }
    if endpoint.port != 0 && !endpoint.ports.is_empty() && endpoint.ports != [endpoint.port] {
        bail!("ambiguous endpoint ports");
    }
    Ok(())
}

fn valid_owner(owner: &str) -> bool {
    owner.is_empty()
        || owner
            .strip_prefix("grant-owner:v1:")
            .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The set fields a refusal names. An inspected REST endpoint supports
/// `allow_uninspected_credentials`; an opaque TCP endpoint never does.
fn unsupported_fields(e: &NetworkEndpoint, inspected: bool) -> String {
    [
        ("access", e.access != 0),
        ("rules", !e.rules.is_empty()),
        ("allowed_ips", !e.allowed_ips.is_empty()),
        ("deny_rules", !e.deny_rules.is_empty()),
        ("allow_encoded_slash", e.allow_encoded_slash),
        ("persisted_queries", !e.persisted_queries.is_empty()),
        (
            "graphql_persisted_queries",
            !e.graphql_persisted_queries.is_empty(),
        ),
        ("graphql_max_body_bytes", e.graphql_max_body_bytes != 0),
        ("path", !e.path.is_empty()),
        (
            "websocket_credential_rewrite",
            e.websocket_credential_rewrite,
        ),
        (
            "request_body_credential_rewrite",
            e.request_body_credential_rewrite,
        ),
        ("advisor_proposed", e.advisor_proposed),
        ("credential_signing", !e.credential_signing.is_empty()),
        ("signing_service", !e.signing_service.is_empty()),
        ("signing_region", !e.signing_region.is_empty()),
        ("json_rpc_max_body_bytes", e.json_rpc_max_body_bytes != 0),
        ("mcp", e.mcp.is_some()),
        ("credential_binding", e.credential_binding.is_some()),
        (
            "allow_uninspected_credentials",
            e.allow_uninspected_credentials && !inspected,
        ),
        ("provider_credentialed", e.provider_credentialed),
        ("token_grant_owner", !e.token_grant_owner.is_empty()),
    ]
    .into_iter()
    .filter_map(|(name, present)| present.then_some(name))
    .collect::<Vec<_>>()
    .join(",")
}

#[cfg(test)]
mod tests;
