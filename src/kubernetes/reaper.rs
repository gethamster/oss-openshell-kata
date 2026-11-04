//! Trusted, namespaced absolute-expiry reconciliation independent of the adapter.
//!
//! API deletion is a cleanup request. It does not prove a partitioned node has
//! stopped its VM; running guests also retain their Kubelet-relative deadline.

use super::{client::Client, lease, manifest, policy};
use anyhow::{Context, Result, ensure};
use futures::{StreamExt, stream};
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Duration;

const BATCH: usize = 16;
const PARALLEL: usize = 4;
const POLL: Duration = Duration::from_secs(2);
const PASS_TIMEOUT: Duration = Duration::from_secs(60);
const DELETE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Default, Serialize)]
pub(super) struct Summary {
    pub(super) observed: usize,
    pub(super) foreign: usize,
    pub(super) invalid: usize,
    pub(super) unexpired: usize,
    pub(super) requested: usize,
    pub(super) tightened: usize,
    pub(super) errors: usize,
}

pub(super) async fn run(client: &Client, workspace: &str, once: bool) -> Result<()> {
    policy::namespace(workspace)?;
    let mut cursor = 0usize;
    loop {
        let result = tokio::time::timeout(
            PASS_TIMEOUT,
            reconcile(client, workspace, lease::now()?, cursor),
        )
        .await;
        // Rotate even on timeout: persistent failures must not starve other VMs.
        cursor = cursor.wrapping_add(BATCH);
        match result {
            Ok(Ok(summary)) => {
                println!("{}", serde_json::to_string(&summary)?);
                ensure!(
                    !once || (summary.errors == 0 && summary.invalid == 0),
                    "lease reconciliation reported invalid leases or failed requests"
                );
            }
            Ok(Err(error)) if once => return Err(error),
            Err(error) if once => return Err(error).context("lease reconciliation timed out"),
            _ => eprintln!("lease reconciliation failed; retrying without broader privileges"),
        }
        if once {
            return Ok(());
        }
        tokio::time::sleep(POLL).await;
    }
}

pub(super) async fn reconcile(
    client: &Client,
    workspace: &str,
    now: u64,
    cursor: usize,
) -> Result<Summary> {
    let namespace = policy::namespace(workspace)?;
    policy::check_namespace(
        &client.required("namespace", Some(&namespace), None).await?,
        workspace,
    )?;
    let inventory = client.required("pods", None, Some(&namespace)).await?;
    let pods = inventory["items"]
        .as_array()
        .context("invalid Pod inventory")?;
    if super::billing::reconcile(client, workspace, pods)
        .await
        .is_err()
    {
        eprintln!("billing reconciliation needs retry");
    }
    let mut summary = Summary {
        observed: pods.len(),
        ..Default::default()
    };
    let mut operations = Vec::new();
    for pod in pods {
        if pod["metadata"]["labels"]["app.kubernetes.io/managed-by"] != manifest::OWNER {
            summary.foreign += 1;
            continue;
        }
        match operation(pod, &namespace, now) {
            Ok((true, _)) => operations.push((pod, None)),
            Ok((false, patch)) => {
                if super::billing::observe(workspace, pod).await.is_err() {
                    // Fail closed for paid compute; the normal reaper keeps its volume.
                    operations.push((pod, None));
                    continue;
                }
                summary.unexpired += 1;
                if let Some(patch) = patch {
                    operations.push((pod, Some(patch)));
                }
            }
            Err(_) => summary.invalid += 1,
        }
    }
    operations.sort_by_key(|(pod, _)| pod["metadata"]["name"].as_str().unwrap_or_default());
    let count = operations.len();
    let selected: Vec<_> = (0..count.min(BATCH))
        .map(|offset| &operations[(cursor % count + offset) % count])
        .collect();
    let results: Vec<_> = stream::iter(selected)
        .map(|(pod, patch)| async move {
            tokio::time::timeout(DELETE_TIMEOUT, reconcile_pod(client, pod, patch.as_ref())).await
        })
        .buffer_unordered(PARALLEL)
        .collect()
        .await;
    for result in results {
        match result {
            Ok(Ok(true)) => summary.requested += 1,
            Ok(Ok(false)) => summary.tightened += 1,
            _ => summary.errors += 1,
        }
    }
    Ok(summary)
}

fn operation(pod: &Value, namespace: &str, now: u64) -> Result<(bool, Option<Value>)> {
    ensure!(
        pod["metadata"]["namespace"] == namespace,
        "Pod namespace differs"
    );
    let annotations = &pod["metadata"]["annotations"];
    let sandbox = annotations[lease::SANDBOX]
        .as_str()
        .context("sandbox identity missing")?;
    let name = policy::resource_id(sandbox)?;
    ensure!(
        pod["metadata"]["name"] == name,
        "Pod name differs from sandbox"
    );
    policy::require_owned(pod, &name)?;
    let nonce = annotations[lease::NONCE]
        .as_str()
        .context("launch nonce missing")?;
    canonical_uuid(nonce)?;
    identity(pod)?;
    let value = annotations[lease::EXPIRES]
        .as_str()
        .context("absolute expiry missing")?;
    let expires: u64 = value.parse().context("invalid absolute expiry")?;
    ensure!(
        expires > 0 && expires.to_string() == value,
        "noncanonical absolute expiry"
    );
    ensure!(
        expires <= now.saturating_add(86400),
        "absolute expiry exceeds profile horizon"
    );
    if expires <= now {
        return Ok((true, None));
    }
    let patch = if pod["status"]["startTime"].is_null() {
        None
    } else {
        lease::patch(pod, nonce, expires)?
    };
    Ok((false, patch))
}

async fn reconcile_pod(client: &Client, pod: &Value, patch: Option<&Value>) -> Result<bool> {
    if let Some(patch) = patch {
        let name = pod["metadata"]["name"]
            .as_str()
            .context("Pod name missing")?;
        let namespace = pod["metadata"]["namespace"]
            .as_str()
            .context("Pod namespace missing")?;
        client
            .checked(
                &[
                    "patch",
                    "pod",
                    name,
                    "-n",
                    namespace,
                    "--type=json",
                    "-p",
                    &serde_json::to_string(patch)?,
                ],
                None,
            )
            .await?;
        Ok(false)
    } else {
        delete_observed(client, pod).await?;
        Ok(true)
    }
}

fn canonical_uuid(value: &str) -> Result<()> {
    ensure!(
        uuid::Uuid::parse_str(value)?.to_string() == value,
        "noncanonical runtime identity"
    );
    Ok(())
}

fn identity(pod: &Value) -> Result<(&str, &str)> {
    let uid = pod["metadata"]["uid"].as_str().context("Pod UID missing")?;
    canonical_uuid(uid)?;
    let revision = pod["metadata"]["resourceVersion"]
        .as_str()
        .context("Pod revision missing")?;
    ensure!(
        !revision.is_empty() && revision.len() <= 256 && !revision.chars().any(char::is_control),
        "invalid Pod revision"
    );
    Ok((uid, revision))
}

pub(super) async fn delete_observed(client: &Client, pod: &Value) -> Result<()> {
    let (uid, revision) = identity(pod)?;
    let namespace = pod["metadata"]["namespace"]
        .as_str()
        .context("Pod namespace missing")?;
    let sandbox = pod["metadata"]["annotations"][lease::SANDBOX]
        .as_str()
        .context("sandbox identity missing")?;
    let name = policy::resource_id(sandbox)?;
    ensure!(
        pod["metadata"]["name"] == name,
        "Pod name differs from sandbox"
    );
    // The namespace was derived from a validated workspace by each caller. Keep
    // this raw URI path safe even if this helper gains another trusted caller.
    ensure!(
        namespace.starts_with("sandbox-")
            && namespace.len() <= 63
            && namespace
                .bytes()
                .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'-'),
        "invalid sandbox namespace"
    );
    let path = format!("/api/v1/namespaces/{namespace}/pods/{name}");
    let options = json!({"apiVersion":"v1","kind":"DeleteOptions",
        "preconditions":{"uid":uid,"resourceVersion":revision}});
    client
        .checked(
            &["delete", "--raw", &path, "-f", "-"],
            Some(serde_json::to_vec(&options)?),
        )
        .await?;
    Ok(())
}
