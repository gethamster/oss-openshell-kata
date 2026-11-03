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
}

/// The only guest egress destinations; an empty list permits none.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub tcp_allow: Vec<Endpoint>,
    /// Allowed destinations that the broker inspects instead of relaying
    /// opaquely. Each must also appear in `tcp_allow`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_inspect: Vec<InspectedEndpoint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedNetworkPolicy {
    allowed: BTreeSet<Endpoint>,
    inspected: BTreeMap<Endpoint, RestAccess>,
}
impl NetworkPolicy {
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
            .all(|entry| ceiling.allows(&entry.host, entry.port)))
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
            if inspected.insert(key, endpoint.access).is_some() {
                bail!("duplicate inspected destination");
            }
        }
        Ok(ValidatedNetworkPolicy { allowed, inspected })
    }
}
impl ValidatedNetworkPolicy {
    pub(crate) fn normalized(&self) -> NetworkPolicy {
        NetworkPolicy {
            tcp_allow: self.allowed.iter().cloned().collect(),
            tls_inspect: self
                .inspected
                .iter()
                .map(|(endpoint, access)| InspectedEndpoint {
                    host: endpoint.host.clone(),
                    port: endpoint.port,
                    access: *access,
                })
                .collect(),
        }
    }
    pub fn allows(&self, host: &str, port: u16) -> bool {
        normalize_host(host).is_ok_and(|host| self.allowed.contains(&Endpoint { host, port }))
    }
    /// The REST access of a destination the broker must inspect, if any.
    pub fn inspection(&self, host: &str, port: u16) -> Option<RestAccess> {
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
