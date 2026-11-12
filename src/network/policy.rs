use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// An exact TCP destination selector. A hostname selects its public resolved IPs,
/// not TLS SNI or an application-level identity at a shared address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

/// The HTTP methods an inspected REST endpoint admits, as OpenShell's access
/// presets define them (`read-only`, `read-write`, `full`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestAccess {
    ReadOnly,
    ReadWrite,
    Full,
}
impl RestAccess {
    /// OpenShell's REST preset expansion: read-only is GET/HEAD/OPTIONS,
    /// read-write adds POST/PUT/PATCH, and full admits every method.
    pub fn allows(self, method: &str) -> bool {
        match self {
            Self::Full => true,
            Self::ReadWrite => matches!(
                method,
                "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH"
            ),
            Self::ReadOnly => matches!(method, "GET" | "HEAD" | "OPTIONS"),
        }
    }
}

/// A TCP destination whose TLS the host broker terminates for L7 REST handling
/// and provider credential placeholder substitution.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectedEndpoint {
    pub host: String,
    pub port: u16,
    pub access: RestAccess,
    /// OpenShell's `allow_uninspected_credentials`: the destination may carry
    /// content the broker does not read. Here it admits a WebSocket upgrade,
    /// whose messages the broker relays unread after the handshake. Omitted
    /// when false, so earlier policy encodings and digests are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_uninspected_credentials: bool,
}

/// How the broker handles one inspected destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub access: RestAccess,
    /// Whether a WebSocket upgrade is relayed instead of refused.
    pub allow_uninspected_credentials: bool,
}

/// Maximum distinct public TCP ports in one policy.
const MAX_PUBLIC_PORTS: usize = 16;

/// The only guest egress destinations; an empty policy permits none.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub tcp_allow: Vec<Endpoint>,
    /// Allowed destinations that the broker inspects instead of relaying
    /// opaquely. Each must also appear in `tcp_allow`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_inspect: Vec<InspectedEndpoint>,
    /// TCP ports on which any public DNS name is allowed; IP literals are not.
    /// The broker still refuses every non-global, denied or protected
    /// destination, and never inspects or injects credentials for them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_allow_public_ports: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedNetworkPolicy {
    allowed: BTreeSet<Endpoint>,
    inspected: BTreeMap<Endpoint, Inspection>,
    public_ports: BTreeSet<u16>,
}
impl NetworkPolicy {
    /// True when the policy grants no destination at all.
    pub fn is_deny_all(&self) -> bool {
        self.tcp_allow.is_empty() && self.tcp_allow_public_ports.is_empty()
    }

    /// Return the canonical exact endpoint set.
    pub fn normalized(&self) -> Result<Self> {
        Ok(self.validate()?.normalized())
    }

    /// Hash the canonical policy independently of runtime resource settings.
    pub fn digest(&self) -> Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&self.normalized()?)?)
        ))
    }

    /// Determine whether every permission is contained by the supplied ceiling.
    pub fn is_subset_of(&self, ceiling: &Self) -> Result<bool> {
        let normalized = self.normalized()?;
        let ceiling = ceiling.validate()?;
        Ok(normalized
            .tcp_allow
            .iter()
            .all(|entry| ceiling.allows(&entry.host, entry.port))
            // A public port never grants inspection or credential injection.
            && normalized
                .tls_inspect
                .iter()
                .all(|entry| ceiling.allows_exact(&entry.host, entry.port))
            && normalized
                .tcp_allow_public_ports
                .iter()
                .all(|port| ceiling.public_ports.contains(port)))
    }

    pub fn validate(&self) -> Result<ValidatedNetworkPolicy> {
        if self.tcp_allow.len() > 256 {
            bail!("too many TCP destination selectors");
        }
        let mut allowed = BTreeSet::new();
        for endpoint in &self.tcp_allow {
            if endpoint.port == 0 {
                bail!("TCP destination port must be nonzero");
            }
            let host = normalize_host(&endpoint.host)?;
            if let Ok(ip) = host.parse::<IpAddr>()
                && !globally_routable(ip)
            {
                bail!("non-global TCP destinations are forbidden");
            }
            allowed.insert(Endpoint {
                host,
                port: endpoint.port,
            });
        }
        let mut inspected = BTreeMap::new();
        for endpoint in &self.tls_inspect {
            let key = Endpoint {
                host: normalize_host(&endpoint.host)?,
                port: endpoint.port,
            };
            if !allowed.contains(&key) {
                bail!("inspected destinations must also be allowed TCP destinations");
            }
            if key.host.parse::<IpAddr>().is_ok() {
                bail!("inspected destinations require a DNS name for TLS verification");
            }
            let inspection = Inspection {
                access: endpoint.access,
                allow_uninspected_credentials: endpoint.allow_uninspected_credentials,
            };
            if inspected.insert(key, inspection).is_some() {
                bail!("duplicate inspected destination");
            }
        }
        let public_ports: BTreeSet<u16> = self.tcp_allow_public_ports.iter().copied().collect();
        if public_ports.len() > MAX_PUBLIC_PORTS {
            bail!("too many public TCP ports");
        }
        if public_ports.contains(&0) {
            bail!("public TCP port must be nonzero");
        }
        Ok(ValidatedNetworkPolicy {
            allowed,
            inspected,
            public_ports,
        })
    }
}
impl ValidatedNetworkPolicy {
    pub(crate) fn normalized(&self) -> NetworkPolicy {
        NetworkPolicy {
            tcp_allow: self.allowed.iter().cloned().collect(),
            tls_inspect: self
                .inspected
                .iter()
                .map(|(endpoint, inspection)| InspectedEndpoint {
                    host: endpoint.host.clone(),
                    port: endpoint.port,
                    access: inspection.access,
                    allow_uninspected_credentials: inspection.allow_uninspected_credentials,
                })
                .collect(),
            tcp_allow_public_ports: self.public_ports.iter().copied().collect(),
        }
    }
    /// Admit an exact destination, or any public DNS name on a public port.
    /// A public port never admits an IP literal: protected-suffix checks
    /// apply to names only. Callers must still require globally routable,
    /// non-denied resolved addresses.
    pub fn allows(&self, host: &str, port: u16) -> bool {
        let Ok(host) = normalize_host(host) else {
            return false;
        };
        (self.public_ports.contains(&port) && is_public_name(&host))
            || self.allowed.contains(&Endpoint { host, port })
    }
    /// Admit only an exact destination, never through a public port.
    pub fn allows_exact(&self, host: &str, port: u16) -> bool {
        normalize_host(host).is_ok_and(|host| self.allowed.contains(&Endpoint { host, port }))
    }
    /// Whether any host is admitted on this port.
    pub fn allows_public_port(&self, port: u16) -> bool {
        self.public_ports.contains(&port)
    }
    /// How the broker must inspect a destination, if it inspects it at all.
    pub fn inspection(&self, host: &str, port: u16) -> Option<Inspection> {
        let host = normalize_host(host).ok()?;
        self.inspected.get(&Endpoint { host, port }).copied()
    }
}

pub fn normalize_host(host: &str) -> Result<String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if name.len() > 253
        || !name.contains('.')
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        bail!("hostname must be an exact ASCII DNS name");
    }
    Ok(name)
}

/// A normalized DNS name that no resolver can read as an IPv4 address.
/// `inet_aton` accepts forms such as `8.8.2056` or `0x8.0x8.0x8.0x8`, so the
/// final label must start with a letter, as every real top-level domain does.
fn is_public_name(host: &str) -> bool {
    host.parse::<IpAddr>().is_err()
        && host
            .rsplit('.')
            .next()
            .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// Reject private, metadata, loopback, multicast and address-transition ranges.
pub fn globally_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => global_v4(ip),
        IpAddr::V6(ip) => global_v6(ip),
    }
}
fn global_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    let value = u32::from(ip);
    if octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || octets[0] >= 224
        || ip == Ipv4Addr::new(168, 63, 129, 16)
    {
        return false;
    }
    let blocked = [
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 0, 0, 0), 24),
        (Ipv4Addr::new(192, 0, 2, 0), 24),
        (Ipv4Addr::new(192, 88, 99, 0), 24),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(198, 18, 0, 0), 15),
        (Ipv4Addr::new(198, 51, 100, 0), 24),
        (Ipv4Addr::new(203, 0, 113, 0), 24),
    ];
    !blocked
        .iter()
        .any(|(base, bits)| value & (u32::MAX << (32 - bits)) == u32::from(*base))
}
fn global_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if s[0] & 0xe000 != 0x2000 {
        return false;
    }
    // Documentation, protocol-assignment/transition and 6to4 ranges.
    !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8)
        || s[0] == 0x2002
        || s[0] == 0x3fff && s[1] < 0x1000)
}
