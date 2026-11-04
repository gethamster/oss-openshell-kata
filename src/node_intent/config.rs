//! Fixed operator configuration and canonical Kubernetes identities.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const CONFIG: &str = "/etc/openshell-kata/node-intent.json";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u32,
    pub node_name: String,
    pub node_uid: String,
    pub boot_id: String,
    pub kubectl_path: PathBuf,
    pub kubectl_sha256: String,
    pub kubeconfig_path: PathBuf,
    pub bundle_root: PathBuf,
    pub nsenter_path: PathBuf,
    pub ip_path: PathBuf,
    #[serde(default)]
    pub arping_path: Option<PathBuf>,
    pub broker_namespace: String,
    pub broker_namespace_uid: String,
    pub broker_image: String,
    pub guest_image: String,
    #[serde(default)]
    pub additional_guest_images: Vec<String>,
    pub operator_network_config_path: PathBuf,
    pub controller_namespace: String,
    pub controller_namespace_uid: String,
    pub controller_labels: BTreeMap<String, String>,
    pub controller_container_images: BTreeMap<String, String>,
    #[serde(default)]
    pub controller_init_container_images: BTreeMap<String, String>,
    #[serde(default)]
    pub controller_restartable_init_containers: BTreeSet<String>,
    #[serde(skip)]
    pub operator: Option<crate::kubernetes::HostedNetworkConfig>,
}
impl Config {
    pub(super) fn load() -> Result<Self> {
        let mut config: Self = super::host::read_trusted(Path::new(CONFIG))?;
        let operator: crate::kubernetes::HostedNetworkConfig =
            super::host::read_trusted(&config.operator_network_config_path)?;
        operator.validate()?;
        config.operator = Some(operator);
        config.validate()?;
        for path in [
            &config.kubectl_path,
            &config.kubeconfig_path,
            &config.bundle_root,
            &config.nsenter_path,
            &config.ip_path,
            &config.operator_network_config_path,
        ] {
            super::host::trusted_path(path)?;
        }
        if let Some(path) = &config.arping_path {
            super::host::trusted_path(path)?;
            ensure!(
                std::fs::metadata(path)?.is_file(),
                "ARP executable must be a regular file"
            );
        }
        ensure!(
            super::host::file_digest(&config.kubectl_path)? == config.kubectl_sha256,
            "kubectl digest differs from operator pin"
        );
        let kubeconfig = super::host::read_trusted::<serde_json::Value>(&config.kubeconfig_path)?;
        super::validate_kubeconfig(&kubeconfig)?;
        for path in [
            kubeconfig["clusters"][0]["cluster"]["certificate-authority"].as_str(),
            kubeconfig["users"][0]["user"]["tokenFile"].as_str(),
        ]
        .into_iter()
        .flatten()
        {
            // Kubelet rotates projected token/CA symlinks; validate the resolved
            // root-owned target without reading or recording credential bytes.
            super::host::trusted_path(&std::fs::canonicalize(path)?)?;
        }
        ensure!(
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == config.boot_id,
            "node boot changed"
        );
        Ok(config)
    }
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1,
            "unsupported node-intent configuration version"
        );
        for value in [
            &self.node_uid,
            &self.boot_id,
            &self.broker_namespace_uid,
            &self.controller_namespace_uid,
        ] {
            canonical_uuid(value)?;
        }
        for value in [
            &self.node_name,
            &self.broker_namespace,
            &self.controller_namespace,
        ] {
            dns_label(value)?;
        }
        ensure!(
            self.broker_namespace == "openshell-network",
            "unexpected broker namespace"
        );
        for image in [&self.broker_image, &self.guest_image]
            .into_iter()
            .chain(&self.additional_guest_images)
        {
            crate::hosted::validate_image(image)?;
        }
        ensure!(
            !self.controller_container_images.is_empty()
                && self.controller_container_images.len() <= 16
                && self.controller_init_container_images.len() <= 16,
            "bounded exact controller container inventory required"
        );
        for (name, image) in self
            .controller_container_images
            .iter()
            .chain(&self.controller_init_container_images)
        {
            dns_label(name)?;
            crate::hosted::validate_image(image)?;
        }
        ensure!(
            self.controller_restartable_init_containers
                .iter()
                .all(|name| self.controller_init_container_images.contains_key(name)),
            "restartable initializer must have an exact image pin"
        );
        for path in [
            &self.kubectl_path,
            &self.kubeconfig_path,
            &self.bundle_root,
            &self.nsenter_path,
            &self.ip_path,
            &self.operator_network_config_path,
        ] {
            ensure!(
                path.is_absolute(),
                "operator executable and state paths must be absolute"
            );
        }
        if let Some(path) = &self.arping_path {
            ensure!(path.is_absolute(), "ARP executable path must be absolute");
        }
        ensure!(
            self.kubectl_sha256.len() == 64
                && self
                    .kubectl_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid kubectl SHA256 pin"
        );
        ensure!(
            !self.controller_labels.is_empty() && self.controller_labels.len() <= 16,
            "bounded nonempty controller selectors required"
        );
        for (key, value) in &self.controller_labels {
            ensure!(
                !key.is_empty()
                    && key.len() <= 253
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"./_-".contains(&b)),
                "invalid controller selector key"
            );
            ensure!(
                !value.is_empty()
                    && value.len() <= 63
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid controller selector value"
            );
        }
        Ok(())
    }
}

pub(crate) fn validate_kubeconfig(value: &serde_json::Value) -> Result<()> {
    let clusters = value["clusters"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("explicit JSON kubeconfig cluster required"))?;
    let users = value["users"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("explicit service-account kubeconfig user required"))?;
    let contexts = value["contexts"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("explicit kubeconfig context required"))?;
    ensure!(
        clusters.len() == 1 && users.len() == 1 && contexts.len() == 1,
        "one exact Kubernetes authentication context required"
    );
    ensure!(
        value["current-context"] == contexts[0]["name"]
            && contexts[0]["context"]["cluster"] == clusters[0]["name"]
            && contexts[0]["context"]["user"] == users[0]["name"],
        "Kubernetes context identity differs"
    );
    let cluster = clusters[0]["cluster"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Kubernetes TLS cluster missing"))?;
    ensure!(
        cluster.keys().all(|key| matches!(
            key.as_str(),
            "server" | "certificate-authority" | "certificate-authority-data"
        )),
        "unsupported Kubernetes TLS configuration"
    );
    let server = cluster
        .get("server")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Kubernetes HTTPS server required"))?;
    let endpoint = tonic::transport::Endpoint::from_shared(server.to_owned())?;
    ensure!(
        endpoint.uri().scheme_str() == Some("https")
            && endpoint
                .uri()
                .authority()
                .is_some_and(|a| !a.as_str().contains('@')),
        "Kubernetes API must use authenticated HTTPS"
    );
    let ca_file = cluster
        .get("certificate-authority")
        .and_then(serde_json::Value::as_str);
    let ca_data = cluster
        .get("certificate-authority-data")
        .and_then(serde_json::Value::as_str);
    ensure!(
        ca_file.is_some() != ca_data.is_some()
            && ca_file.or(ca_data).is_some_and(|v| !v.is_empty()),
        "one explicit Kubernetes CA required"
    );
    if let Some(path) = ca_file {
        ensure!(
            Path::new(path).is_absolute(),
            "Kubernetes CA path must be absolute"
        );
    }
    let user = users[0]["user"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("service-account authentication missing"))?;
    ensure!(
        user.len() == 1
            && user
                .get("tokenFile")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|path| Path::new(path).is_absolute()),
        "only a projected service-account token file is supported"
    );
    Ok(())
}
pub(super) fn canonical_uuid(value: &str) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(value)?;
    ensure!(
        !uuid.is_nil() && uuid.to_string() == value,
        "noncanonical resource UID"
    );
    Ok(())
}
pub(super) fn dns_label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.')),
        "invalid Kubernetes object name"
    );
    Ok(())
}
