//! Immutable operator ceilings compiled with native OpenShell policy intent.
use crate::{
    boundary::{
        filesystem::FilesystemPolicy,
        process::{OperatorCeilings, VmLimits},
    },
    network::NetworkPolicy,
    proto::openshell::sandbox::v1::SandboxPolicy,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VmPolicy {
    pub version: u32,
    pub profile: String,
    pub resources: VmLimits,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
}
impl VmPolicy {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .context("reading operator VM policy")?
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 128 * 1024 {
            bail!("operator policy exceeds size limit");
        }
        let policy: Self = serde_json::from_slice(&bytes).context("decoding operator VM policy")?;
        policy.validate()?;
        Ok(Self {
            network: policy.network.validate()?.normalized(),
            ..policy
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.profile != "docker-vm" {
            bail!("unsupported VM policy version or profile");
        }
        self.resources.validate(&OperatorCeilings::default())?;
        self.filesystem.validate()?;
        self.network.validate()?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let canonical = Self {
            network: self.network.validate()?.normalized(),
            ..self.clone()
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&canonical)?)
        ))
    }
    /// Native intent can only narrow the trusted operator ceiling.
    pub fn compile(&self, native: &SandboxPolicy) -> Result<Self> {
        self.validate()?;
        Ok(Self {
            network: crate::network::compile_native_with_inspection(native, &self.network)?,
            ..self.clone()
        })
    }
}
/// Fresh host-runtime observation, never supplied by a sandbox or gateway user.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnforcementEvidence {
    pub sandbox_id: String,
    pub policy_sha256: String,
    pub nonce: String,
    pub runtime: String,
    pub hypervisor_pid: u32,
    pub resources: VmLimits,
    pub storage_id: String,
    pub network_fence: String,
    pub watchdog_pid: u32,
    pub expires_at_unix_secs: u64,
}
impl EnforcementEvidence {
    pub fn validate(&self, id: &str, nonce: &str, policy: &VmPolicy) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if self.sandbox_id != id
            || self.nonce != nonce
            || self.policy_sha256 != policy.digest()?
            || self.resources != policy.resources
            || self.runtime != "kata-runtime-rs"
            || self.hypervisor_pid == 0
            || self.watchdog_pid == 0
            || self.storage_id.is_empty()
            || self.network_fence.is_empty()
            || self.expires_at_unix_secs <= now
            || self.expires_at_unix_secs > now.saturating_add(policy.resources.lifetime_secs)
        {
            bail!("runtime enforcement evidence does not match this launch");
        }
        Ok(())
    }
}
