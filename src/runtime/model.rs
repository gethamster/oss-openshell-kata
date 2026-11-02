//! Persisted lifecycle identity and validation for one isolated guest.
use crate::{
    boundary::process::VmDeadline,
    guest::Guest,
    network::FenceSpec,
    profile::{EnforcementEvidence, VmPolicy},
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{net::Ipv4Addr, path::PathBuf, str::FromStr};

const MIB: u64 = 1024 * 1024;

/// Guest RAM for the admitted profile, as Kata sizes it from the OCI limit.
pub(super) fn guest_memory_bytes(resources: &crate::boundary::process::VmLimits) -> u64 {
    resources.memory_mib * MIB
}

/// Host shim budget for one guest. Dragonball maps guest RAM into the shim, so
/// reserve a bounded host-only margin for the runtime, page tables and device
/// state without enlarging guest RAM: 256 MiB, or 1/64 of guest RAM for large
/// guests (page tables alone approach 1/512 of fully touched RAM). This is a
/// per-guest cgroup ceiling, not a node admission check.
pub(super) fn host_memory_bytes(resources: &crate::boundary::process::VmLimits) -> u64 {
    let guest = guest_memory_bytes(resources);
    guest + (256 * MIB).max(guest / 64)
}

/// Existing lifecycle verbs plus explicit policy verification and replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Create,
    Start,
    Stop,
    Delete,
    Verify,
    Update,
    Abort,
}
impl FromStr for Action {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        Ok(match value {
            "create" => Self::Create,
            "start" => Self::Start,
            "stop" => Self::Stop,
            "delete" => Self::Delete,
            "verify" => Self::Verify,
            "update" => Self::Update,
            "abort" => Self::Abort,
            _ => bail!("unsupported lifecycle action"),
        })
    }
}

/// Serializable SSH route; the private key itself never enters the guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub sandbox_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub private_key_path: PathBuf,
    pub known_hosts_path: PathBuf,
}
impl Route {
    /// Return the adapter's transport contract with fresh enforcement evidence.
    pub fn guest(&self, enforcement: Option<EnforcementEvidence>) -> Guest {
        Guest {
            sandbox_id: self.sandbox_id.clone(),
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            private_key_path: self.private_key_path.clone(),
            known_hosts_path: self.known_hosts_path.clone(),
            enforcement,
            runtime_identity: None,
        }
    }
    /// Produce JSON without requiring the adapter's internal transport type to serialize.
    pub fn output(&self, enforcement: EnforcementEvidence) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        value["enforcement"] = serde_json::to_value(enforcement)?;
        Ok(value)
    }
}

/// Host-only records required to reverify and destroy one guest generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub creation_nonce: String,
    /// Linux boot identity binds volatile namespace and fence observations.
    #[serde(default)]
    pub node_boot_id: Option<String>,
    /// Trusted image reference retained across restarts, never selected by tenant input.
    #[serde(default = "default_image")]
    pub image: String,
    pub attachment: super::network::Attachment,
    pub route: Route,
    pub policy: VmPolicy,
    pub deadline: VmDeadline,
    pub network: Option<FenceSpec>,
    pub storage_id: String,
    pub hypervisor_pid: u32,
    pub watchdog_pid: u32,
    pub cgroup_path: String,
}

fn default_image() -> String {
    "docker.io/library/openshell-kata-enforced:local".to_owned()
}

/// Select the fixed local image or an explicit immutable operator image.
pub fn selected_image(image: Option<&str>) -> Result<String> {
    match image {
        Some(image) => {
            crate::hosted::validate_image(image)?;
            Ok(image.to_owned())
        }
        None => Ok(default_image()),
    }
}

/// Require the containerd observation to use the retained, admitted image reference.
pub fn verify_image(native: &Value, expected: &str) -> Result<()> {
    if native["Image"].as_str() != Some(expected) {
        bail!("observed guest image differs from admitted operator image");
    }
    Ok(())
}

/// Require an unpredictable, printable per-request proof challenge.
pub fn validate_nonce(value: &str) -> Result<()> {
    if !(16..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("invalid runtime proof nonce");
    }
    Ok(())
}

/// Fixed hardware contracts selected by the operator, never by workload input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ResourceProfile {
    /// Development profile with one CPU and 2 GiB RAM/disk.
    #[default]
    Local,
    /// Local builder with 16 CPUs, 48 GiB RAM and 32 GiB private disk.
    Build,
    /// Foundry builder with 32 CPUs, 128 GiB RAM and 256 GiB private disk.
    FoundryBuild,
}
impl ResourceProfile {
    /// Require exact admission and storage sizes for the selected node profile.
    pub fn validate(self, policy: &VmPolicy) -> Result<()> {
        policy.validate()?;
        let expected = match self {
            Self::Local => (1, 2048, 2048),
            Self::Build => (16, 49152, 32768),
            Self::FoundryBuild => (32, 131072, 262144),
        };
        if (
            policy.resources.vcpus,
            policy.resources.memory_mib,
            policy.resources.disk_mib,
        ) != expected
        {
            bail!("runtime resources differ from selected operator profile");
        }
        Ok(())
    }
}

/// Validate the original development contract.
pub fn validate_supported_profile(policy: &VmPolicy) -> Result<()> {
    ResourceProfile::Local.validate(policy)
}

/// Select the actual IPv4 NIC, ignoring Kata's addressless tap helper.
pub fn guest_address(inspection: &Value) -> Result<Ipv4Addr> {
    let networks = inspection
        .pointer("/NetworkSettings/Networks")
        .and_then(Value::as_object)
        .context("missing guest network observation")?;
    let mut addresses = networks
        .values()
        .filter_map(|v| v.get("IPAddress").and_then(Value::as_str))
        .filter(|v| !v.is_empty());
    let address = addresses
        .next()
        .context("guest has no IPv4 address")?
        .parse()?;
    if addresses.next().is_some() {
        bail!("guest has ambiguous network addresses");
    }
    Ok(address)
}

/// Recognize only the pinned nerdctl response for the requested missing object.
pub fn confirmed_absent(code: i32, stdout: &[u8], stderr: &[u8], id: &str) -> bool {
    let message = String::from_utf8_lossy(stderr);
    let message = message.trim();
    let expected = format!("level=fatal msg=\"1 errors: [no such object {id}]\"");
    let prefix = message.strip_suffix(&expected);
    code == 1
        && (stdout.is_empty() || stdout == b"[]\n" || stdout == b"[]")
        && prefix.is_some_and(|p| {
            p.is_empty() || (p.starts_with("time=\"") && p.ends_with("\" ") && !p.contains('\n'))
        })
}
