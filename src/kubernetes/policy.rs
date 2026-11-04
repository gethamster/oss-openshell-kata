//! Validation of additive Kubernetes network allowances and tenant identities.

use super::manifest;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) const DEFAULT_CONTROL_NAMESPACE: &str = "openshell-system";

pub(super) fn configured_control_namespace() -> Result<String> {
    let configured = std::env::var("OPENSHELL_KATA_CONTROL_NAMESPACE");
    let value = match &configured {
        Ok(value) => value.as_str(),
        Err(std::env::VarError::NotPresent) => DEFAULT_CONTROL_NAMESPACE,
        Err(_) => anyhow::bail!("operator control namespace must be UTF-8"),
    };
    validate_control_namespace(value)?;
    Ok(value.to_owned())
}

pub(super) fn validate_control_namespace(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "invalid operator control namespace"
    );
    Ok(())
}

pub(super) fn namespace(workspace: &str) -> Result<String> {
    crate::hosted::namespace(workspace)
}

pub(super) fn resource_id(sandbox: &str) -> Result<String> {
    crate::config::SandboxId::parse(sandbox)?;
    Ok(format!(
        "kata-{}",
        &format!("{:x}", Sha256::digest(sandbox.as_bytes()))[..24]
    ))
}

pub(super) fn validate_image(image: &str) -> Result<()> {
    let (repository, digest) = image.rsplit_once("@sha256:").unwrap_or(("", ""));
    ensure!(
        !repository.is_empty()
            && repository.as_bytes()[0].is_ascii_alphanumeric()
            && repository
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"./:_-".contains(&b))
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "immutable guest image required"
    );
    Ok(())
}

pub(super) fn validate_storage_class(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && label
                        .bytes()
                        .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'-')
            }),
        "invalid operator storage class name"
    );
    Ok(())
}

pub(super) fn require_owned(resource: &Value, name: &str) -> Result<()> {
    let expected = manifest::labels(name);
    let observed = &resource["metadata"]["labels"];
    ensure!(
        expected.as_object().is_some_and(|labels| labels
            .iter()
            .filter(|(k, _)| k.as_str() != "platform.tryhamster.dev/network-profile")
            .all(|(k, v)| observed.get(k) == Some(v)))
            && matches!(
                observed["platform.tryhamster.dev/network-profile"].as_str(),
                Some("isolated" | "brokered-public-tcp-v1")
            ),
        "existing resource belongs to another owner"
    );
    Ok(())
}

/// Preserve every binding label while accepting the two topology labels that
/// Kubernetes admission adds to Pods. Callers still validate policies against
/// all observed labels, including topology-selected additive policies.
pub(super) fn pod_labels_match(observed: &Value, expected: &Value) -> bool {
    let (Some(observed), Some(expected)) = (observed.as_object(), expected.as_object()) else {
        return false;
    };
    expected
        .iter()
        .all(|(key, value)| observed.get(key) == Some(value))
        && observed.iter().all(|(key, value)| {
            expected.contains_key(key)
                || (matches!(
                    key.as_str(),
                    "topology.kubernetes.io/region" | "topology.kubernetes.io/zone"
                ) && value.as_str().is_some_and(|value| !value.is_empty()))
        })
}

pub(super) fn check_namespace(observed: &Value, workspace: &str) -> Result<()> {
    namespace(workspace)?;
    ensure!(
        observed["metadata"]["labels"]["platform.tryhamster.dev/tenant"] == workspace
            && observed["metadata"]["labels"]["platform.tryhamster.dev/role"] == "sandbox",
        "namespace ownership differs from workspace"
    );
    Ok(())
}

pub(super) fn selected(selector: &Value, labels: &Value) -> Result<bool> {
    ensure!(
        selector
            .get("matchExpressions")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "unsupported network policy selector expression"
    );
    Ok(selector.get("matchLabels").is_none_or(|value| {
        value.as_object().is_some_and(|map| {
            map.iter()
                .all(|(key, value)| labels.get(key) == Some(value))
        })
    }))
}

pub(super) fn validate_policies(
    policies: &[Value],
    labels: &Value,
    control_namespace: &str,
) -> Result<()> {
    validate_control_namespace(control_namespace)?;
    let mut found = false;
    for policy in policies {
        let spec = &policy["spec"];
        ensure!(spec.is_object(), "invalid network policy specification");
        if !selected(&spec["podSelector"], labels)? {
            continue;
        }
        let egress_type = spec
            .get("policyTypes")
            .map_or(spec.get("egress").is_some(), |types| {
                types
                    .as_array()
                    .is_some_and(|types| types.iter().any(|value| value == "Egress"))
            });
        if egress_type {
            found = true;
            ensure!(
                spec.get("egress")
                    .is_none_or(|rules| rules.as_array().is_some_and(Vec::is_empty)),
                "unexpected guest egress allowance"
            );
        }
        if let Some(rules) = spec.get("ingress") {
            for rule in rules
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("invalid ingress rules"))?
            {
                validate_ingress(rule, control_namespace)?;
            }
        }
    }
    ensure!(found, "guest egress isolation missing");
    Ok(())
}

fn validate_ingress(rule: &Value, control_namespace: &str) -> Result<()> {
    let ports = rule["ports"]
        .as_array()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("unbounded guest ingress"))?;
    for port in ports {
        ensure!(
            matches!(port["port"].as_u64(), Some(22 | 5501))
                && port.get("protocol").is_none_or(|v| v == "TCP")
                && port.get("endPort").is_none(),
            "unexpected guest ingress port"
        );
    }
    let sources = rule["from"]
        .as_array()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("unbounded guest ingress"))?;
    for source in sources {
        let namespace = &source["namespaceSelector"];
        let pod = &source["podSelector"];
        ensure!(
            namespace["matchLabels"] == json!({"kubernetes.io/metadata.name":control_namespace})
                && namespace
                    .get("matchExpressions")
                    .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
                && pod["matchLabels"] == json!({"platform.tryhamster.dev/role":"sandbox-control"})
                && pod
                    .get("matchExpressions")
                    .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
                && source.get("ipBlock").is_none(),
            "unexpected guest ingress principal"
        );
    }
    Ok(())
}
