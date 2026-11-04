//! Publish node-owned preboot fence intent from independently observed launch identity.

mod admission;
mod client;
mod config;
mod host;
#[cfg(all(test, target_os = "linux"))]
mod linux_tests;
#[cfg(test)]
mod tests;

pub(crate) use config::validate_kubeconfig;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[derive(Debug, Parser)]
struct Arguments {
    /// Reconcile one bounded inventory rather than polling continuously.
    #[arg(long)]
    once: bool,
}

#[derive(Debug, Deserialize)]
struct Bundle {
    annotations: BTreeMap<String, String>,
    linux: Linux,
}
#[derive(Debug, Deserialize)]
struct Linux {
    namespaces: Vec<Namespace>,
}
#[derive(Debug, Deserialize)]
struct Namespace {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    path: PathBuf,
}

impl Bundle {
    fn annotation(&self, name: &str) -> Result<&str> {
        self.annotations
            .get(name)
            .map(String::as_str)
            .context("required CRI annotation missing")
    }
    fn netns(&self) -> Result<PathBuf> {
        let entries: Vec<_> = self
            .linux
            .namespaces
            .iter()
            .filter(|entry| entry.kind == "network")
            .collect();
        ensure!(
            entries.len() == 1,
            "explicit single CNI network namespace required"
        );
        let path = std::fs::canonicalize(&entries[0].path)?;
        ensure!(
            path.parent() == Some(std::path::Path::new("/run/netns")),
            "unsupported CNI namespace location"
        );
        Ok(path)
    }
}

/// Reconcile trusted node launch intent without writing Kubernetes resources.
///
/// # Errors
/// Rejects unsupported hosts, untrusted files, mismatched API identities and
/// unavailable preboot network observations. Failed launches receive no intent.
pub async fn run_node_intent() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "node intent reconciliation requires Linux"
    );
    let arguments = Arguments::parse();
    let config = config::Config::load()?;
    let client = client::Client::new(&config);
    loop {
        let result = reconcile(&config, &client).await?;
        if arguments.once {
            println!("{}", serde_json::to_string(&result)?);
            ensure!(
                result.rejected == 0,
                "preboot intent reconciliation rejected one or more bundles"
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[derive(Default, Serialize)]
struct Reconciled {
    published: usize,
    rejected: usize,
    unmanaged: usize,
}

async fn reconcile(config: &config::Config, client: &client::Client<'_>) -> Result<Reconciled> {
    let mut summary = Reconciled::default();
    for path in host::bundles(&config.bundle_root)? {
        let result = reconcile_bundle(config, client, &path).await;
        match result {
            Ok(true) => summary.published += 1,
            Ok(false) => summary.unmanaged += 1,
            Err(error) => {
                summary.rejected += 1;
                // No API or file contents are logged; they can contain credentials.
                tracing::warn!(bundle = %path.display(), %error, "preboot intent rejected");
            }
        }
    }
    Ok(summary)
}

async fn reconcile_bundle(
    config: &config::Config,
    client: &client::Client<'_>,
    path: &std::path::Path,
) -> Result<bool> {
    let bundle: Bundle = host::read_trusted(path)?;
    if bundle.annotation("io.kubernetes.cri.container-type")? != "sandbox" {
        return Ok(false);
    }
    let uid = bundle.annotation("io.kubernetes.cri.sandbox-uid")?;
    config::canonical_uuid(uid)?;
    let name = bundle.annotation("io.kubernetes.cri.sandbox-name")?;
    let namespace = bundle.annotation("io.kubernetes.cri.sandbox-namespace")?;
    config::dns_label(name)?;
    config::dns_label(namespace)?;
    if let Some(intent) = host::existing(uid)? {
        intent.validate(host::now()?)?;
        // Kata removes the outer interface's address after installing TC
        // redirects. Intent is deliberately immutable, so never re-derive a
        // running generation or acquire new authority through reconciliation.
        ensure!(
            intent.pod_uid == uid
                && crate::hosted::namespace(&intent.workspace)? == namespace
                && intent.node_uid == config.node_uid
                && intent.boot_id == config.boot_id,
            "retained intent belongs to another node launch"
        );
        return Ok(true);
    }
    let guest = client.get("pod", name, Some(namespace)).await?;
    if guest["metadata"]["labels"]["platform.tryhamster.dev/network-profile"] != admission::PROFILE
    {
        return Ok(false);
    }
    ensure!(
        guest["metadata"]["uid"] == uid,
        "CRI and live Pod UID differ"
    );
    let launch = fetch_launch(config, client, &guest, namespace).await?;
    let mut intent = admission::derive(config, &guest, &launch)?;
    if config.arping_path.is_some() {
        admission::require_preboot(&guest)?;
    }
    let network = host::network(config, &bundle.netns()?).await?;
    network.bind(&mut intent)?;
    if let Some(ip) = guest["status"]["podIP"]
        .as_str()
        .filter(|ip| !ip.is_empty())
    {
        ensure!(
            ip.parse::<std::net::Ipv4Addr>()? == network.ip,
            "CNI and API guest IP differ"
        );
    }
    intent.validate(host::now()?)?;
    let after = client.get("pod", name, Some(namespace)).await?;
    ensure!(
        admission::stable_guest(&guest, &after),
        "guest changed while resolving preboot intent"
    );
    if let Some(ip) = after["status"]["podIP"]
        .as_str()
        .filter(|ip| !ip.is_empty())
    {
        ensure!(
            ip.parse::<std::net::Ipv4Addr>()? == network.ip,
            "published API guest IP differs from CNI"
        );
    }
    let after_broker = client
        .get(
            "pod",
            admission::name(&launch.broker)?,
            Some(&config.broker_namespace),
        )
        .await?;
    ensure!(
        admission::stable_broker(&launch.broker, &after_broker),
        "broker changed while resolving preboot intent"
    );
    if config.arping_path.is_some() {
        admission::require_preboot(&after)?;
    }
    host::publish(&intent)?;
    Ok(true)
}

async fn fetch_launch(
    config: &config::Config,
    client: &client::Client<'_>,
    guest: &Value,
    namespace: &str,
) -> Result<admission::Launch> {
    let nonce = guest["metadata"]["annotations"]["openshell-kata.io/launch-nonce"]
        .as_str()
        .context("launch nonce missing")?;
    config::canonical_uuid(nonce)?;
    let (source_namespace, node, broker_namespace, controller_namespace, controllers) = tokio::try_join!(
        client.get("namespace", namespace, None),
        client.get("node", &config.node_name, None),
        client.get("namespace", &config.broker_namespace, None),
        client.get("namespace", &config.controller_namespace, None),
        client.list_pods(&config.controller_namespace, &config.controller_labels),
    )?;
    let source_uid = source_namespace["metadata"]["uid"]
        .as_str()
        .context("source namespace UID missing")?;
    config::canonical_uuid(source_uid)?;
    let labels = BTreeMap::from([
        ("openshell-kata.io/namespace-uid".into(), source_uid.into()),
        ("openshell-kata.io/launch-nonce".into(), nonce.into()),
        (
            "openshell-kata.io/component".into(),
            "network-broker".into(),
        ),
    ]);
    let brokers = client.list_pods(&config.broker_namespace, &labels).await?;
    let items = brokers["items"]
        .as_array()
        .context("broker inventory missing")?;
    ensure!(items.len() == 1, "unique broker generation required");
    let broker = items[0].clone();
    let configmap = client
        .get(
            "configmap",
            admission::name(&broker)?,
            Some(&config.broker_namespace),
        )
        .await?;
    Ok(admission::Launch {
        source_namespace,
        node,
        broker_namespace,
        controller_namespace,
        controllers,
        broker,
        configmap,
    })
}
