//! Explicit operator capability and retained identity for the hosted broker.
use crate::network::NetworkPolicy;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

pub(super) const PROFILE: &str = "brokered-public-tcp-v1";
pub(super) const UID_LABEL: &str = "openshell-kata.io/namespace-uid";
pub(super) const NONCE_LABEL: &str = "openshell-kata.io/launch-nonce";
pub(super) const COMPONENT: &str = "openshell-kata.io/component";
/// Immutable operator capability for public TCP brokering outside guest VMs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedNetworkConfig {
    pub version: u32,
    /// Use attached OpenShell providers as destination authority.
    #[serde(default)]
    pub provider_mediation: bool,
    #[serde(default)]
    pub gateway_endpoint: String,
    #[serde(default)]
    pub gateway_ca_file: PathBuf,
    #[serde(default)]
    pub gateway_addresses: Vec<std::net::Ipv4Addr>,
    pub broker_namespace: String,
    pub broker_namespace_uid: String,
    pub operator_ceiling: NetworkPolicy,
    pub baseline_denied_cidrs: Vec<String>,
    pub protected_hostname_suffixes: Vec<String>,
    pub authorization_lease_secs: u64,
    pub resolver_namespace_labels: BTreeMap<String, String>,
    pub resolver_pod_labels: BTreeMap<String, String>,
    pub resolver_nameservers: Vec<std::net::Ipv4Addr>,
    pub guard_namespace: String,
    pub guard_namespace_uid: String,
    pub guard_client_tls_config_file: PathBuf,
    pub inventory_file: PathBuf,
}
pub(super) type Config = HostedNetworkConfig;
impl HostedNetworkConfig {
    /// Read the bounded operator file; its parent must be outside tenant storage.
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = read_json(path)?;
        config.validate()?;
        Ok(config)
    }
    /// Reject broad selectors, unsupported versions and unbounded authorization.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.broker_namespace == "openshell-network",
            "unsupported hosted network profile"
        );
        canonical_uuid(&self.broker_namespace_uid)?;
        ensure!(
            self.guard_namespace == "kata-system",
            "guard must use separate trusted namespace"
        );
        canonical_uuid(&self.guard_namespace_uid)?;
        ensure!(
            self.guard_client_tls_config_file.is_absolute(),
            "guard client TLS config must be absolute"
        );
        self.operator_ceiling.validate()?;
        ensure!(
            !self.provider_mediation || self.operator_ceiling.tcp_allow.is_empty(),
            "provider mediation cannot carry a separate hostname ceiling"
        );
        if self.provider_mediation {
            let endpoint = tonic::transport::Endpoint::from_shared(self.gateway_endpoint.clone())?;
            ensure!(
                endpoint.uri().scheme_str() == Some("https")
                    && endpoint
                        .uri()
                        .authority()
                        .is_some_and(|authority| !authority.as_str().contains('@')),
                "provider gateway requires an exact HTTPS endpoint"
            );
            ensure!(
                self.gateway_ca_file.is_absolute()
                    && !self.gateway_addresses.is_empty()
                    && self.gateway_addresses.len() <= 8,
                "provider gateway requires a pinned CA and bounded control addresses"
            );
            ensure!(
                self.gateway_addresses
                    .iter()
                    .all(|ip| ip.is_private() && !ip.is_loopback() && !ip.is_link_local()),
                "gateway control addresses must be private infrastructure addresses"
            );
        }
        validate_nameservers(&self.resolver_nameservers)?;
        ensure!(
            (1..=30).contains(&self.authorization_lease_secs),
            "authorization lease must be 1..30 seconds"
        );
        ensure!(
            self.inventory_file.is_absolute(),
            "inventory file must be absolute"
        );
        for labels in [&self.resolver_namespace_labels, &self.resolver_pod_labels] {
            ensure!(
                !labels.is_empty() && labels.len() <= 16,
                "resolver selectors must be bounded and nonempty"
            );
            for (key, value) in labels {
                ensure!(
                    !key.is_empty()
                        && key.len() <= 253
                        && !value.is_empty()
                        && value.len() <= 63
                        && key
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"./_-".contains(&b))
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                    "invalid resolver label selector"
                );
            }
        }
        ensure!(
            self.baseline_denied_cidrs.len() <= 256
                && self.protected_hostname_suffixes.len() <= 128,
            "oversized operator destination inventory"
        );
        for value in &self.baseline_denied_cidrs {
            let _: ipnet::IpNet = value.parse()?;
        }
        for value in &self.protected_hostname_suffixes {
            crate::network::normalize_host(value)?;
            ensure!(
                value.parse::<std::net::IpAddr>().is_err(),
                "protected suffix cannot be an IP address"
            );
        }
        Ok(())
    }
    pub(super) fn digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}
pub(super) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    ensure!(path.is_absolute(), "operator file must be absolute");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "operator file exceeds size limit"
    );
    serde_json::from_slice(&bytes).context("invalid operator network file")
}
pub(super) fn configured() -> Result<Option<Config>> {
    std::env::var_os("OPENSHELL_KATA_HOSTED_NETWORK_CONFIG")
        .map(|p| Config::load(Path::new(&p)))
        .transpose()
}
pub(super) fn canonical_uuid(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value)?.to_string() == value
            && !uuid::Uuid::parse_str(value)?.is_nil(),
        "noncanonical resource UID"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub name: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub image: String,
    pub source_namespace_uid: String,
    pub sandbox_name: String,
    pub source_namespace: String,
    pub launch_nonce: String,
    pub config_sha256: String,
    pub operator_config_sha256: String,
    pub resolver_nameservers: Vec<std::net::Ipv4Addr>,
    pub broker_config: Option<crate::network::HostedBrokerConfig>,
    pub inventory: Option<crate::network::InfrastructureInventory>,
    pub initial_inventory: Option<crate::network::InfrastructureInventory>,
    pub response: Option<crate::network::HostedControlResponse>,
    pub uid: String,
    pub ip: String,
}
impl Binding {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.namespace == "openshell-network"
                && self.name.starts_with("broker-")
                && self.name.len() <= 63
                && self
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid broker resource name"
        );
        validate_nameservers(&self.resolver_nameservers)?;
        canonical_uuid(&self.namespace_uid)?;
        canonical_uuid(&self.source_namespace_uid)?;
        canonical_uuid(&self.launch_nonce)?;
        super::policy::validate_image(&self.image)?;
        ensure!(
            self.config_sha256.len() == 64
                && self.config_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid broker configuration digest"
        );
        ensure!(
            self.uid.is_empty() == self.ip.is_empty(),
            "partial broker identity"
        );
        if let Some(config) = &self.broker_config {
            config.validate()?;
            ensure!(
                config.digest()? == self.config_sha256
                    && config.binding.namespace_uid == self.source_namespace_uid
                    && config.binding.launch_nonce == self.launch_nonce
                    && super::policy::resource_id(&config.binding.sandbox_id)? == self.sandbox_name
                    && super::policy::namespace(&config.binding.workspace)?
                        == self.source_namespace,
                "retained broker authority differs"
            );
        }
        if !self.uid.is_empty() {
            canonical_uuid(&self.uid)?;
            let ip: std::net::Ipv4Addr = self.ip.parse()?;
            ensure!(ip.is_private(), "broker requires private IPv4");
        }
        Ok(())
    }
}

fn validate_nameservers(addresses: &[std::net::Ipv4Addr]) -> Result<()> {
    ensure!(
        (1..=3).contains(&addresses.len())
            && addresses.iter().all(std::net::Ipv4Addr::is_private)
            && addresses
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == addresses.len(),
        "one to three distinct private IPv4 resolvers required"
    );
    Ok(())
}
