//! Conservative validation of every policy selecting a brokered guest or broker.
use super::{
    broker_config::{Binding, Config},
    broker_manifest, policy,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
fn validate(policies: &[Value], labels: &Value, expected: &Value) -> Result<()> {
    let mut ingress = false;
    let mut egress = false;
    for observed in policies {
        let spec = &observed["spec"];
        ensure!(spec.is_object(), "invalid network policy");
        if !policy::selected(&spec["podSelector"], labels)? {
            continue;
        }
        let types = spec
            .get("policyTypes")
            .and_then(Value::as_array)
            .context("explicit network policy types required")?;
        ensure!(
            types.iter().all(|v| v == "Ingress" || v == "Egress"),
            "unsupported network policy type"
        );
        for (direction, found) in [("ingress", &mut ingress), ("egress", &mut egress)] {
            let title = if direction == "ingress" {
                "Ingress"
            } else {
                "Egress"
            };
            if types.iter().any(|v| v == title) {
                *found = true;
            }
            if let Some(rules) = spec.get(direction) {
                for rule in rules.as_array().context("invalid network rules")? {
                    ensure!(
                        expected["spec"][direction]
                            .as_array()
                            .is_some_and(|allowed| allowed.contains(rule)),
                        "unexpected additive network allowance"
                    );
                }
            }
        }
    }
    ensure!(ingress && egress, "bidirectional network isolation missing");
    Ok(())
}
pub(super) fn validate_guest(policies: &[Value], labels: &Value, binding: &Binding) -> Result<()> {
    ensure!(
        policy::pod_labels_match(
            labels,
            &broker_manifest::guest_labels(&binding.sandbox_name, binding)
        ),
        "guest generation labels differ"
    );
    validate(
        policies,
        labels,
        &broker_manifest::guest_policy(&binding.sandbox_name, "unused", binding),
    )
}
pub(super) fn validate_broker(
    policies: &[Value],
    labels: &Value,
    binding: &Binding,
    config: &Config,
    inventory: &crate::network::InfrastructureInventory,
) -> Result<()> {
    ensure!(
        policy::pod_labels_match(labels, &broker_manifest::labels(binding)),
        "broker generation labels differ"
    );
    validate(
        policies,
        labels,
        &broker_manifest::network_policy(binding, config, inventory)?,
    )
}
