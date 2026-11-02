//! Immutable hosted ceilings, launch identity and fresh infrastructure observations.

#[path = "guard_cli.rs"]
pub(super) mod cli;
#[path = "guard_runtime.rs"]
mod runtime;
pub use runtime::{HostedBrokerHandle, bind_hosted_broker};

use super::{NetworkPolicy, compile_native, normalize_host};
use crate::proto::openshell::sandbox::v1::SandboxPolicy;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(super) const MAX_DENIED: usize = 4096;

/// Immutable authority shared by exactly one sandbox launch and its broker.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerBinding {
    pub workspace: String,
    pub namespace_uid: String,
    pub sandbox_id: String,
    pub launch_nonce: String,
    pub expires_at_unix: u64,
}
impl BrokerBinding {
    pub fn validate(&self) -> Result<()> {
        let value = &self.workspace;
        ensure!(
            !value.is_empty()
                && value.len() <= 63
                && value.as_bytes()[0].is_ascii_alphanumeric()
                && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
                && value
                    .bytes()
                    .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'-'),
            "invalid broker workspace"
        );
        canonical_uuid(&self.namespace_uid)?;
        canonical_uuid(&self.launch_nonce)?;
        crate::config::SandboxId::parse(&self.sandbox_id)?;
        ensure!(self.expires_at_unix > 0, "absolute broker expiry required");
        Ok(())
    }
}

/// Trusted immutable network authority, independent of a VM resource profile.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostedBrokerConfig {
    pub version: u32,
    /// Provider policy supplies destination authority; only address fences are operator-owned.
    #[serde(default)]
    pub provider_mediation: bool,
    #[serde(default)]
    pub gateway_endpoint: String,
    #[serde(default)]
    pub gateway_ca_pem: String,
    pub operator_ceiling: NetworkPolicy,
    pub initial_ceiling: NetworkPolicy,
    pub binding: BrokerBinding,
    pub protected_hostname_suffixes: Vec<String>,
    pub baseline_denied_cidrs: Vec<String>,
    pub authorization_lease_secs: u64,
}
impl HostedBrokerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "hosted broker configuration exceeds limit"
        );
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported hosted broker configuration version"
        );
        self.binding.validate()?;
        ensure!(
            (1..=30).contains(&self.authorization_lease_secs),
            "broker authorization lease must be between one and thirty seconds"
        );
        self.operator_ceiling.validate()?;
        ensure!(
            serde_json::to_vec(&self.operator_ceiling.normalized()?)?.len() <= 48 * 1024,
            "operator network ceiling exceeds proof size bound"
        );
        ensure!(
            !self.provider_mediation
                || (self.operator_ceiling.tcp_allow.is_empty()
                    && self.initial_ceiling.tcp_allow.is_empty()),
            "provider mediation cannot carry a separate hostname ceiling"
        );
        ensure!(
            self.initial_ceiling.is_subset_of(&self.operator_ceiling)?,
            "initial network ceiling exceeds operator authority"
        );
        ensure!(
            self.protected_hostname_suffixes.len() <= 128,
            "too many protected hostname suffixes"
        );
        for suffix in &self.protected_hostname_suffixes {
            let normalized = normalize_host(suffix)?;
            ensure!(
                normalized.parse::<std::net::IpAddr>().is_err(),
                "protected hostname suffix cannot be an IP literal"
            );
        }
        canonical_cidrs(&self.baseline_denied_cidrs)?;
        for endpoint in &self.initial_ceiling.normalized()?.tcp_allow {
            self.check_host(&endpoint.host)?;
        }
        Ok(())
    }
    pub fn normalized(&self) -> Result<Self> {
        self.validate()?;
        Ok(Self {
            operator_ceiling: self.operator_ceiling.normalized()?,
            initial_ceiling: self.initial_ceiling.normalized()?,
            protected_hostname_suffixes: self
                .protected_hostname_suffixes
                .iter()
                .map(|h| normalize_host(h))
                .collect::<Result<BTreeSet<_>>>()?
                .into_iter()
                .collect(),
            baseline_denied_cidrs: canonical_cidrs(&self.baseline_denied_cidrs)?,
            ..self.clone()
        })
    }
    pub fn digest(&self) -> Result<String> {
        digest(&self.normalized()?)
    }
    pub fn compile(&self, native: &SandboxPolicy) -> Result<NetworkPolicy> {
        let result = compile_native(native, &self.operator_ceiling)?;
        self.validate_policy(&result)?;
        Ok(result)
    }
    pub(super) fn validate_policy(&self, policy: &NetworkPolicy) -> Result<()> {
        ensure!(
            policy.is_subset_of(&self.operator_ceiling)?
                && policy.is_subset_of(&self.initial_ceiling)?,
            "network authorization exceeds immutable ceiling"
        );
        for endpoint in &policy.normalized()?.tcp_allow {
            self.check_host(&endpoint.host)?;
        }
        Ok(())
    }
    pub(super) fn check_host(&self, host: &str) -> Result<()> {
        let host = normalize_host(host)?;
        for suffix in &self.protected_hostname_suffixes {
            let suffix = normalize_host(suffix)?;
            ensure!(
                host != suffix && !host.ends_with(&format!(".{suffix}")),
                "protected infrastructure hostname is forbidden"
            );
        }
        Ok(())
    }
}

/// A fresh trusted observation; expiry cannot be renewed at the same revision.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureInventory {
    pub version: u32,
    pub generation: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub denied_cidrs: Vec<String>,
}
impl InfrastructureInventory {
    pub fn validate_at(&self, now: u64) -> Result<()> {
        ensure!(
            self.version == 1 && self.generation > 0,
            "invalid infrastructure inventory version or generation"
        );
        ensure!(
            self.issued_at_unix > 0
                && self.issued_at_unix <= now
                && self.expires_at_unix > now
                && self
                    .expires_at_unix
                    .checked_sub(self.issued_at_unix)
                    .is_some_and(|seconds| (1..=60).contains(&seconds)),
            "infrastructure inventory is stale, future dated or outside its freshness bound"
        );
        canonical_cidrs(&self.denied_cidrs)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        digest(&Self {
            denied_cidrs: canonical_cidrs(&self.denied_cidrs)?,
            ..self.clone()
        })
    }
}

/// Matching authenticated gateway snapshots and a scoped, externally renewed JWT.
/// This message travels only over the private broker control channel and is never persisted.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAuthorization {
    pub config: Vec<u8>,
    pub environment: Vec<u8>,
    pub gateway_token: String,
}

/// Non-secret guest material returned only after the broker installs a snapshot.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderMaterial {
    pub environment: std::collections::HashMap<String, String>,
    pub files: std::collections::HashMap<String, String>,
    pub ca_certificate: String,
    pub mediation_generation: u64,
    pub config_revision: u64,
    pub provider_revision: u64,
    pub policy_hash: String,
    pub provider_attachment_epoch: String,
}
impl std::fmt::Debug for ProviderMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderMaterial")
            .field("config_revision", &self.config_revision)
            .field("provider_revision", &self.provider_revision)
            .finish_non_exhaustive()
    }
}

/// A read or mutation against an exact broker launch, process and CAS revision.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostedControlRequest {
    Ready {
        nonce: String,
    },
    AuthorizeProviders {
        binding: BrokerBinding,
        startup_epoch: String,
        expected_generation: u64,
        nonce: String,
        providers: ProviderAuthorization,
        inventory: InfrastructureInventory,
    },
    Authorize {
        binding: BrokerBinding,
        startup_epoch: String,
        expected_generation: u64,
        nonce: String,
        policy: NetworkPolicy,
        inventory: InfrastructureInventory,
    },
    Inspect {
        binding: BrokerBinding,
        startup_epoch: String,
        expected_generation: u64,
        nonce: String,
    },
    Stop {
        binding: BrokerBinding,
        startup_epoch: String,
        expected_generation: u64,
        nonce: String,
    },
}
impl HostedControlRequest {
    pub fn nonce(&self) -> &str {
        match self {
            Self::Ready { nonce }
            | Self::Authorize { nonce, .. }
            | Self::AuthorizeProviders { nonce, .. }
            | Self::Inspect { nonce, .. }
            | Self::Stop { nonce, .. } => nonce,
        }
    }
    pub(super) fn expected(&self) -> Option<(&BrokerBinding, &str, u64)> {
        match self {
            Self::Ready { .. } => None,
            Self::AuthorizeProviders {
                binding,
                startup_epoch,
                expected_generation,
                ..
            }
            | Self::Authorize {
                binding,
                startup_epoch,
                expected_generation,
                ..
            }
            | Self::Inspect {
                binding,
                startup_epoch,
                expected_generation,
                ..
            }
            | Self::Stop {
                binding,
                startup_epoch,
                expected_generation,
                ..
            } => Some((binding, startup_epoch, *expected_generation)),
        }
    }
}

/// Current enforced state; readiness is not authorization renewal.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedControlResponse {
    pub nonce: String,
    pub binding: BrokerBinding,
    pub startup_epoch: String,
    pub generation: u64,
    pub policy: NetworkPolicy,
    pub policy_sha256: String,
    pub config_sha256: String,
    pub inventory_generation: u64,
    pub inventory_sha256: String,
    pub effective_denied_sha256: String,
    pub authorization_expires_at_unix: u64,
    pub active_connections: usize,
    pub stopping: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_material: Option<ProviderMaterial>,
}

pub(super) fn canonical_uuid(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value)?.to_string() == value,
        "canonical UUID required"
    );
    Ok(())
}
pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock precedes epoch")?
        .as_secs())
}
pub(super) fn digest(value: &impl Serialize) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
pub(super) fn canonical_cidrs(values: &[String]) -> Result<Vec<String>> {
    ensure!(
        values.len() <= MAX_DENIED,
        "too many denied infrastructure networks"
    );
    values
        .iter()
        .map(|value| {
            ensure!(value.len() <= 64, "infrastructure CIDR exceeds limit");
            Ok(value.parse::<ipnet::IpNet>()?.trunc().to_string())
        })
        .collect::<Result<BTreeSet<_>>>()
        .map(|v| v.into_iter().collect())
}
