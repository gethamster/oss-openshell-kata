//! Credential-free retained Kubernetes intent and live-runtime evidence.

use super::policy;
use crate::resource_shape::ResourceShape;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub(super) sandbox_id: String,
    pub(super) workspace: String,
    pub(super) namespace: String,
    pub(super) name: String,
    pub(super) image: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) username: String,
    pub(super) runtime_identity: String,
    #[serde(default)]
    pub(super) broker: Option<super::broker_config::Binding>,
    #[serde(default)]
    pub(super) launch_nonce: Option<String>,
    #[serde(default)]
    pub(super) owns_volume_for_launch: bool,
    #[serde(default)]
    pub(super) expires_at: Option<u64>,
    /// The declared operator shape; absent means the default shape, so default
    /// state stays byte-identical to earlier releases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) resource_shape: Option<ResourceShape>,
    /// Docker data is on its own raw disk (overlay2). Absent for guests launched
    /// before the disk, which keep VFS on the shared volume until relaunch.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) docker_disk: bool,
    pub(super) private_key_path: PathBuf,
    pub(super) known_hosts_path: PathBuf,
}

impl State {
    /// The retained shape, or the default shape.
    pub(super) fn shape(&self) -> ResourceShape {
        self.resource_shape.clone().unwrap_or_default()
    }
    pub(super) fn validate(&self, sandbox: &str, folder: &std::path::Path) -> Result<()> {
        ensure!(
            self.sandbox_id == sandbox
                && self.name == policy::resource_id(sandbox)?
                && self.namespace == policy::namespace(&self.workspace)?
                && self.port == 22
                && self.username == "sandbox"
                && self.private_key_path == folder.join("client_key")
                && self.known_hosts_path == folder.join("known_hosts"),
            "retained sandbox identity differs"
        );
        policy::validate_image(&self.image)?;
        if let Some(shape) = &self.resource_shape {
            shape.validate()?;
            ensure!(
                !shape.is_default(),
                "retained default shape must be implicit"
            );
        }
        if let Some(broker) = &self.broker {
            broker.validate()?;
            ensure!(
                Some(broker.launch_nonce.as_str()) == self.launch_nonce.as_deref()
                    && broker.source_namespace == self.namespace,
                "retained broker generation differs"
            );
        }
        if let Some(nonce) = &self.launch_nonce {
            uuid::Uuid::parse_str(nonce)?;
        }
        if !self.runtime_identity.is_empty() {
            uuid::Uuid::parse_str(&self.runtime_identity)?;
        }
        if !self.host.is_empty() {
            let ip: IpAddr = self.host.parse()?;
            ensure!(
                !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast(),
                "invalid retained guest address"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(super) struct Route<'a> {
    pub(super) sandbox_id: &'a str,
    pub(super) host: &'a str,
    pub(super) port: u16,
    pub(super) username: &'a str,
    pub(super) private_key_path: &'a std::path::Path,
    pub(super) known_hosts_path: &'a std::path::Path,
    pub(super) runtime_identity: &'a str,
}

impl<'a> From<&'a State> for Route<'a> {
    fn from(state: &'a State) -> Self {
        Self {
            sandbox_id: &state.sandbox_id,
            host: &state.host,
            port: state.port,
            username: &state.username,
            private_key_path: &state.private_key_path,
            known_hosts_path: &state.known_hosts_path,
            runtime_identity: &state.runtime_identity,
        }
    }
}
