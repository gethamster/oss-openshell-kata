//! Explicit VM-scoped admission and live Kubernetes runtime evidence.

use crate::proto::openshell::compute::v1::DriverSandbox;
use anyhow::{Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Validate the operator-owned private network used for guest endpoints.
pub fn validate_network(cidr: &str) -> Result<ipnet::IpNet> {
    let network: ipnet::IpNet = cidr.parse()?;
    let private = match network {
        ipnet::IpNet::V4(net) => {
            net.network().is_private() && net.broadcast().is_private() && net.prefix_len() >= 8
        }
        ipnet::IpNet::V6(net) => net.network().is_unique_local() && net.prefix_len() >= 7,
    };
    ensure!(private, "guest network must be a bounded private CIDR");
    Ok(network)
}

/// Evidence produced by the trusted launcher after observing live Kubernetes resources.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProof {
    pub version: u32,
    pub sandbox_id: String,
    pub workspace: String,
    pub namespace: String,
    pub runtime_identity: String,
    pub runtime_class: String,
    pub image: String,
    pub network: String,
    pub cpu: String,
    pub memory: String,
    pub policy_sha256: String,
    pub expires_at_unix: u64,
    pub deadline_enforcement: String,
    #[serde(default)]
    pub proof_nonce: Option<String>,
    #[serde(default)]
    pub source_namespace_uid: Option<String>,
    #[serde(default)]
    pub broker_pod_uid: Option<String>,
    #[serde(default)]
    pub broker_ip: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    pub broker: Option<crate::network::HostedControlResponse>,
    #[serde(default)]
    pub fence: Option<crate::network::hosted_fence::HostedFenceProof>,
}

/// Derive the tenant namespace; live resource ownership is checked separately.
pub fn namespace(workspace: &str) -> Result<String> {
    ensure!(
        !workspace.is_empty()
            && workspace.len() <= 63
            && workspace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && workspace.as_bytes()[0].is_ascii_alphanumeric()
            && workspace.as_bytes()[workspace.len() - 1].is_ascii_alphanumeric()
            && !matches!(
                workspace,
                "default" | "kube-system" | "network" | "master" | "dashboard" | "platform"
            ),
        "unsupported hosted workspace"
    );
    let suffix = if workspace.len() <= 55 {
        workspace.to_owned()
    } else {
        format!("{:x}", Sha256::digest(workspace.as_bytes()))[..24].to_owned()
    };
    Ok(format!("sandbox-{suffix}"))
}

/// Require an immutable image in the configured operator profile.
pub fn validate_image(image: &str) -> Result<()> {
    let Some((repository, digest)) = image.split_once("@sha256:") else {
        bail!("hosted guest image must use a SHA-256 digest")
    };
    ensure!(
        !repository.is_empty()
            && !repository.chars().any(char::is_whitespace)
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid immutable guest image"
    );
    Ok(())
}

/// Admit only VM-wide isolation without native guest filesystem/process claims.
pub fn validate_request(sandbox: &DriverSandbox, image: &str) -> Result<()> {
    validate_resources(sandbox, image)?;
    let native = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.policy.as_ref())
        .ok_or_else(|| anyhow::anyhow!("explicit VM policy required"))?;
    let _validated_intent = crate::policy::validate_policy(native)?;
    Ok(())
}

/// Admit hosted TCP intent under an explicit immutable operator ceiling.
pub fn validate_brokered_request(
    sandbox: &DriverSandbox,
    image: &str,
    ceiling: &crate::network::NetworkPolicy,
) -> Result<crate::network::NetworkPolicy> {
    validate_resources(sandbox, image)?;
    let native = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.policy.as_ref())
        .ok_or_else(|| anyhow::anyhow!("explicit VM policy required"))?;
    crate::network::compile_native(native, ceiling)
}

fn validate_resources(sandbox: &DriverSandbox, image: &str) -> Result<()> {
    namespace(&sandbox.workspace)?;
    validate_image(image)?;
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox spec required"))?;
    let template = spec
        .template
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox template required"))?;
    ensure!(
        template.image == image,
        "guest image differs from qualified operator profile"
    );
    ensure!(
        spec.environment.is_empty() && template.environment.is_empty(),
        "guest environment overrides are unsupported"
    );
    ensure!(
        spec.isolation_backend.is_none(),
        "external isolation backend override unsupported"
    );
    ensure!(
        template
            .platform_config
            .as_ref()
            .is_none_or(|value| value.fields.is_empty())
            && template
                .driver_config
                .as_ref()
                .is_none_or(|value| value.fields.is_empty()),
        "platform overrides are unsupported"
    );
    ensure!(
        spec.resource_requirements
            .as_ref()
            .is_none_or(|value| value.gpu.is_none()),
        "GPU resources unsupported"
    );
    if let Some(resources) = &template.resources {
        ensure!(
            (resources.cpu_request.is_empty() || resources.cpu_request == "2")
                && (resources.cpu_limit.is_empty() || resources.cpu_limit == "2")
                && (resources.memory_request.is_empty() || resources.memory_request == "4Gi")
                && (resources.memory_limit.is_empty() || resources.memory_limit == "4Gi"),
            "resource override differs from qualified limits"
        );
    }
    ensure!(
        template.user_namespaces.is_none(),
        "user namespace override unsupported"
    );
    ensure!(
        spec.workload_identity
            .as_ref()
            .is_none_or(|identity| identity.user.is_empty() && identity.group.is_empty()),
        "guest identity selectors unsupported"
    );
    Ok(())
}

impl RuntimeProof {
    /// Verify explicit hosted capability and fresh broker/fence generation evidence.
    pub fn validate_for_profile(
        &self,
        sandbox: &DriverSandbox,
        image: &str,
        runtime_identity: &str,
        operator_path: Option<&std::path::Path>,
        nonce: &str,
        expected_policy: Option<&crate::network::NetworkPolicy>,
    ) -> Result<()> {
        let Some(path) = operator_path else {
            return self.validate(sandbox, image, runtime_identity);
        };
        let operator = crate::kubernetes::HostedNetworkConfig::load(path)?;
        let challenge = uuid::Uuid::parse_str(nonce)?;
        ensure!(
            !challenge.is_nil() && challenge.to_string() == nonce,
            "invalid runtime proof challenge"
        );
        let initial_ceiling =
            validate_brokered_request(sandbox, image, &operator.operator_ceiling)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        self.validate_identity(sandbox, image, runtime_identity, now, 2)?;
        ensure!(
            self.network == "brokered-public-tcp-v1" && self.proof_nonce.as_deref() == Some(nonce),
            "hosted network profile or proof challenge differs"
        );
        let broker = self
            .broker
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("broker proof missing"))?;
        let fence = self
            .fence
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("host packet fence proof missing"))?;
        fence.validate(now)?;
        let source_uid = self
            .source_namespace_uid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("source namespace UID missing"))?;
        let broker_uid = self
            .broker_pod_uid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("broker Pod UID missing"))?;
        ensure!(
            broker.nonce == nonce
                && !broker.stopping
                && broker.generation > 0
                && uuid::Uuid::parse_str(&broker.startup_epoch).is_ok()
                && broker.binding.workspace == sandbox.workspace
                && broker.binding.sandbox_id == sandbox.id
                && broker.binding.namespace_uid == source_uid
                && broker.binding.expires_at_unix == self.expires_at_unix,
            "broker proof belongs to another launch or namespace"
        );
        let expected_config = crate::network::HostedBrokerConfig {
            version: 1,
            operator_ceiling: operator.operator_ceiling,
            initial_ceiling,
            binding: broker.binding.clone(),
            protected_hostname_suffixes: operator.protected_hostname_suffixes,
            baseline_denied_cidrs: operator.baseline_denied_cidrs,
            authorization_lease_secs: operator.authorization_lease_secs,
        };
        ensure!(
            broker.config_sha256 == expected_config.digest()?
                && broker.policy_sha256 == broker.policy.digest()?
                && broker
                    .policy
                    .is_subset_of(&expected_config.initial_ceiling)?,
            "broker policy or immutable ceiling differs"
        );
        let binding = &fence.binding;
        ensure!(
            binding.workspace == sandbox.workspace
                && binding.namespace_uid == source_uid
                && binding.sandbox_id == sandbox.id
                && binding.pod_uid == runtime_identity
                && binding.launch_nonce == broker.binding.launch_nonce
                && binding.expires_at_unix == self.expires_at_unix
                && binding.broker_pod_uid == broker_uid
                && Some(binding.broker_ip) == self.broker_ip
                && binding.broker_config_sha256 == broker.config_sha256,
            "host packet fence belongs to another runtime or broker"
        );
        if let Some(expected) = expected_policy {
            ensure!(
                broker.policy.normalized()? == expected.normalized()?,
                "broker did not enforce requested policy"
            );
        }
        let startup = broker.generation == 1
            && broker.policy.tcp_allow.is_empty()
            && broker.authorization_expires_at_unix == 0
            && broker.active_connections == 0
            && expected_policy.is_none();
        ensure!(
            startup
                || (broker.authorization_expires_at_unix > now
                    && broker.authorization_expires_at_unix
                        <= now.saturating_add(expected_config.authorization_lease_secs)
                    && broker.authorization_expires_at_unix <= self.expires_at_unix),
            "broker authorization has expired or exceeds its immutable lease"
        );
        for digest in [&broker.inventory_sha256, &broker.effective_denied_sha256] {
            ensure!(
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid broker inventory digest"
            );
        }
        ensure!(
            broker.inventory_generation > 0,
            "broker inventory revision missing"
        );
        Ok(())
    }

    fn validate_identity(
        &self,
        sandbox: &DriverSandbox,
        image: &str,
        runtime_identity: &str,
        now: u64,
        version: u32,
    ) -> Result<()> {
        ensure!(
            self.version == version
                && self.sandbox_id == sandbox.id
                && self.workspace == sandbox.workspace
                && self.namespace == namespace(&sandbox.workspace)?
                && self.runtime_identity == runtime_identity
                && uuid::Uuid::parse_str(runtime_identity).is_ok(),
            "runtime proof identity differs from sandbox generation"
        );
        ensure!(
            self.expires_at_unix > now
                && self.expires_at_unix <= now.saturating_add(86400)
                && self.deadline_enforcement == "kubelet-active-deadline",
            "runtime proof has no bounded independent lifetime"
        );
        let runtime_class = if version == 2 {
            "kata-qemu-runtime-rs-guarded"
        } else {
            "kata-qemu-runtime-rs"
        };
        ensure!(
            self.runtime_class == runtime_class
                && self.image == image
                && self.cpu == "2"
                && self.memory == "4Gi"
                && self.policy_sha256.len() == 64
                && self.policy_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "runtime proof is missing qualified fences"
        );
        Ok(())
    }

    /// Bind observed fences to this exact sandbox, workspace, image, and Pod generation.
    pub fn validate(
        &self,
        sandbox: &DriverSandbox,
        image: &str,
        runtime_identity: &str,
    ) -> Result<()> {
        validate_request(sandbox, image)?;
        ensure!(
            self.proof_nonce.is_none()
                && self.source_namespace_uid.is_none()
                && self.broker_pod_uid.is_none()
                && self.broker_ip.is_none()
                && self.broker.is_none()
                && self.fence.is_none(),
            "legacy isolated profile cannot carry broker authority"
        );
        ensure!(
            self.version == 1
                && self.sandbox_id == sandbox.id
                && self.workspace == sandbox.workspace
                && self.namespace == namespace(&sandbox.workspace)?
                && self.runtime_identity == runtime_identity
                && uuid::Uuid::parse_str(runtime_identity).is_ok(),
            "runtime proof identity differs from sandbox generation"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        ensure!(
            self.expires_at_unix > now
                && self.expires_at_unix <= now.saturating_add(86400)
                && self.deadline_enforcement == "kubelet-active-deadline",
            "runtime proof has no bounded independent lifetime"
        );
        ensure!(
            self.runtime_class == "kata-qemu-runtime-rs"
                && self.image == image
                && self.network == "deny-all-egress"
                && self.cpu == "2"
                && self.memory == "4Gi"
                && self.policy_sha256.len() == 64
                && self.policy_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "runtime proof is missing qualified fences"
        );
        Ok(())
    }
}
