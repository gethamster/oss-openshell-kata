//! Host-owned TCX packet fencing before the Kata shim can boot a guest.

#[cfg(target_os = "linux")]
#[path = "hosted_fence_linux.rs"]
mod hosted_fence_linux;
#[cfg(target_os = "linux")]
#[path = "hosted_fence_probe.rs"]
mod hosted_fence_probe;
#[path = "hosted_fence_runtime.rs"]
mod hosted_fence_runtime;
#[path = "hosted_fence_packet.rs"]
pub mod packet;

#[cfg(any(target_os = "linux", test))]
use anyhow::Context;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

#[path = "hosted_fence_budget.rs"]
mod hosted_fence_budget;
pub use hosted_fence_budget::reserve_hosted_fence_generation;
pub use hosted_fence_runtime::run_runtime_guard;

pub(crate) use hosted_fence_runtime::proof_server_node_uid;
/// Read back the actual pinned host fence for an exact Pod generation.
pub(crate) use hosted_fence_runtime::verify_hosted_fence;

/// Immutable launch authority delivered by a trusted node controller.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedFenceIntent {
    pub version: u32,
    pub workspace: String,
    pub namespace_uid: String,
    pub sandbox_id: String,
    pub pod_uid: String,
    pub launch_nonce: String,
    pub expires_at_unix: u64,
    pub broker_pod_uid: String,
    pub broker_ip: Ipv4Addr,
    pub broker_port: u16,
    pub broker_config_sha256: String,
    pub controller_cidrs: Vec<String>,
    pub guest_ip: Ipv4Addr,
    pub guest_mac: String,
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: String,
    pub interface: String,
    pub node_uid: String,
    pub boot_id: String,
}
impl HostedFenceIntent {
    /// Reject selectors that could weaken the fixed TCP broker and SSH boundary.
    pub fn validate(&self, now_unix: u64) -> Result<()> {
        ensure!(self.version == 1, "unsupported host fence intent version");
        crate::hosted::namespace(&self.workspace)?;
        crate::config::SandboxId::parse(&self.sandbox_id)?;
        for value in [
            &self.namespace_uid,
            &self.pod_uid,
            &self.launch_nonce,
            &self.broker_pod_uid,
            &self.node_uid,
            &self.boot_id,
        ] {
            let parsed = uuid::Uuid::parse_str(value)?;
            ensure!(
                parsed.to_string() == *value && !parsed.is_nil(),
                "noncanonical fence identity"
            );
        }
        ensure!(
            self.interface == "eth0" && self.broker_port == 3128,
            "unsupported host network attachment"
        );
        ensure!(
            self.expires_at_unix > now_unix && self.expires_at_unix - now_unix <= 86400,
            "expired or excessive host fence lifetime"
        );
        ensure!(
            self.guest_ip.is_private()
                && self.broker_ip.is_private()
                && self.guest_ip != self.broker_ip,
            "host fence requires distinct private guest and broker IPv4 addresses"
        );
        ensure!(
            (self.gateway_ip.is_private() || self.gateway_ip.is_link_local())
                && self.gateway_ip != self.guest_ip
                && self.gateway_ip != self.broker_ip,
            "invalid host gateway address"
        );
        parse_mac(&self.guest_mac)?;
        parse_mac(&self.gateway_mac)?;
        ensure!(
            !self.guest_mac.eq_ignore_ascii_case(&self.gateway_mac),
            "guest and gateway MAC must differ"
        );
        digest_valid(&self.broker_config_sha256)?;
        ensure!(
            !self.controller_cidrs.is_empty()
                && self.controller_cidrs.len() <= packet::MAX_CONTROLLERS,
            "bounded controller network inventory required"
        );
        for cidr in &self.controller_cidrs {
            let network: ipnet::Ipv4Net = cidr.parse()?;
            ensure!(
                network.prefix_len() == 32
                    && network.network().is_private()
                    && network.broadcast().is_private()
                    && network.to_string() == *cidr,
                "controller network must be exact canonical private IPv4 /32"
            );
        }
        Ok(())
    }
    /// Bind every immutable launch selector to its canonical serialized digest.
    pub fn sha256(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn packet_config(
        &self,
        now_unix: u64,
        boottime_ns: u64,
    ) -> Result<packet::PacketConfig> {
        self.validate(now_unix)?;
        let mut controllers = [([0; 4], 0); packet::MAX_CONTROLLERS];
        for (slot, cidr) in controllers.iter_mut().zip(&self.controller_cidrs) {
            let cidr: ipnet::Ipv4Net = cidr.parse()?;
            *slot = (cidr.network().octets(), cidr.prefix_len());
        }
        // Conservative one-second allowance for the two clock reads; never extend TTL.
        let lifetime = self
            .expires_at_unix
            .saturating_sub(now_unix)
            .saturating_sub(1);
        let deadline = boottime_ns
            .checked_add(
                lifetime
                    .checked_mul(1_000_000_000)
                    .context("fence lifetime overflow")?,
            )
            .context("boottime deadline overflow")?;
        Ok(packet::PacketConfig {
            guest_ip: self.guest_ip.octets(),
            broker_ip: self.broker_ip.octets(),
            gateway_ip: self.gateway_ip.octets(),
            guest_mac: parse_mac(&self.guest_mac)?,
            gateway_mac: parse_mac(&self.gateway_mac)?,
            broker_port: self.broker_port,
            controllers,
            controller_count: self.controller_cidrs.len().try_into()?,
            expires_at_boottime_ns: deadline,
        })
    }
}

/// Read-back identity of pinned TCX links and their outer Pod network attachment.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedFenceProof {
    pub version: u32,
    pub binding: HostedFenceIntent,
    pub netns_device: u64,
    pub netns_inode: u64,
    pub ifindex: u32,
    pub ingress_link_id: u32,
    pub egress_link_id: u32,
    pub ingress_program_id: u32,
    pub egress_program_id: u32,
    pub object_sha256: String,
    pub intent_sha256: String,
    pub installed_at_unix: u64,
}
impl HostedFenceProof {
    /// Validate portable proof structure; the node verifier additionally reads live links.
    pub fn validate(&self, now_unix: u64) -> Result<()> {
        self.binding.validate(now_unix)?;
        ensure!(
            self.version == 1 && self.netns_device > 0 && self.netns_inode > 0 && self.ifindex > 0,
            "incomplete host fence network identity"
        );
        ensure!(
            self.ingress_link_id > 0
                && self.egress_link_id > 0
                && self.ingress_link_id != self.egress_link_id
                && self.ingress_program_id > 0
                && self.egress_program_id > 0
                && self.ingress_program_id != self.egress_program_id,
            "incomplete host fence link identity"
        );
        digest_valid(&self.object_sha256)?;
        ensure!(
            self.intent_sha256 == self.binding.sha256()?
                && self.installed_at_unix <= now_unix
                && self.installed_at_unix < self.binding.expires_at_unix,
            "host fence proof binding differs"
        );
        Ok(())
    }
}
/// Fresh node-local verification response; the challenge does not authorize changes.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedFenceResponse {
    pub nonce: String,
    pub proof: HostedFenceProof,
}

pub(crate) fn digest_valid(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid lowercase SHA-256 digest"
    );
    Ok(())
}
pub(crate) fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let octets = value
        .split(':')
        .map(|part| {
            ensure!(part.len() == 2, "invalid MAC octet");
            Ok(u8::from_str_radix(part, 16)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let octets: [u8; 6] = octets
        .try_into()
        .map_err(|_| anyhow::anyhow!("MAC requires six octets"))?;
    ensure!(
        octets[0] & 1 == 0 && octets != [0; 6],
        "MAC requires a nonzero unicast address"
    );
    Ok(octets)
}
#[cfg(test)]
#[path = "hosted_fence_tests.rs"]
mod tests;
