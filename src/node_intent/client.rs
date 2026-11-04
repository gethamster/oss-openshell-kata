//! Bounded read-only Kubernetes commands using operator-owned authentication.
use super::config::{Config, dns_label};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};

pub(super) const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;

pub(super) struct Client<'a> {
    config: &'a Config,
}
impl<'a> Client<'a> {
    pub(super) fn new(config: &'a Config) -> Self {
        Self { config }
    }
    pub(super) async fn get(
        &self,
        resource: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> Result<Value> {
        ensure!(
            matches!(resource, "pod" | "node" | "namespace" | "configmap"),
            "unsupported API resource"
        );
        dns_label(name)?;
        let mut arguments = vec![
            "get".into(),
            resource.into(),
            name.into(),
            "-o".into(),
            "json".into(),
        ];
        if let Some(namespace) = namespace {
            dns_label(namespace)?;
            arguments.extend(["-n".into(), namespace.into()]);
        }
        self.query(&arguments).await
    }
    pub(super) async fn list_pods(
        &self,
        namespace: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<Value> {
        dns_label(namespace)?;
        ensure!(
            !labels.is_empty() && labels.len() <= 16,
            "bounded API selector required"
        );
        let selector = labels
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(",");
        let result = self
            .query(&[
                "get".into(),
                "pods".into(),
                "-n".into(),
                namespace.into(),
                "-l".into(),
                selector,
                "--chunk-size=32".into(),
                "-o".into(),
                "json".into(),
            ])
            .await?;
        let items = result["items"]
            .as_array()
            .context("Pod inventory missing")?;
        ensure!(items.len() <= 32, "Pod inventory exceeds bounded selector");
        Ok(result)
    }
    async fn query(&self, arguments: &[String]) -> Result<Value> {
        let mut command = Command::new(&self.config.kubectl_path);
        command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .arg("--kubeconfig")
            .arg(&self.config.kubeconfig_path)
            .arg("--request-timeout=5s")
            .args(arguments);
        serde_json::from_slice(&bounded(command).await?).context("invalid bounded API response")
    }
}

pub(super) async fn bounded(command: Command) -> Result<Vec<u8>> {
    bounded_for(command, Duration::from_secs(8)).await
}

pub(super) async fn bounded_for(mut command: Command, deadline: Duration) -> Result<Vec<u8>> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("starting trusted observation command")?;
    let mut output = child.stdout.take().context("observation output missing")?;
    let work = async {
        let mut bytes = Vec::new();
        (&mut output)
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= OUTPUT_LIMIT,
            "observation output exceeds bound"
        );
        ensure!(
            child.wait().await?.success(),
            "trusted observation command failed"
        );
        Ok(bytes)
    };
    tokio::time::timeout(deadline, work)
        .await
        .context("trusted observation command timed out")?
}

pub(super) async fn ip(namespace: &Path, config: &Config, arguments: &[&str]) -> Result<Value> {
    let mut command = Command::new(&config.nsenter_path);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .arg(format!("--net={}", namespace.display()))
        .arg("--")
        .arg(&config.ip_path)
        .arg("-j");
    // iproute2's IPv4-only address output omits the link-layer MAC. Read the
    // full interface record; the observer separately selects its single inet IP.
    if arguments.first().copied() != Some("address") {
        command.arg("-4");
    }
    command.args(arguments);
    serde_json::from_slice(&bounded(command).await?).context("invalid bounded network observation")
}

/// Resolve only the already validated link-local/default gateway before VM startup.
pub(super) async fn resolve_gateway(
    namespace: &Path,
    config: &Config,
    gateway: std::net::Ipv4Addr,
) -> Result<()> {
    ensure!(
        gateway.is_private() || gateway.is_link_local(),
        "gateway neighbor initialization requires a private or link-local gateway"
    );
    let executable = config
        .arping_path
        .as_ref()
        .context("gateway neighbor initialization is disabled")?;
    let mut command = Command::new(&config.nsenter_path);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .arg(format!("--net={}", namespace.display()))
        .arg("--")
        .arg(executable)
        .args(["-I", "eth0", "-c", "1", "-w", "2"])
        .arg(gateway.to_string());
    bounded_for(command, Duration::from_secs(3)).await?;
    Ok(())
}
