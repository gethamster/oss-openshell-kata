//! Shared trusted broker projection for node-side preboot admission.
use super::{broker_config::Binding, broker_manifest, broker_spec, policy};
use crate::network::HostedBrokerConfig;
use anyhow::{Result, ensure};
use serde_json::Value;

/// Render the same immutable broker Pod expected by its Kubernetes lifecycle.
pub(crate) fn node_broker_manifest(
    image: &str,
    broker_namespace_uid: &str,
    config: &HostedBrokerConfig,
    operator: &super::HostedNetworkConfig,
) -> Result<Value> {
    config.validate()?;
    operator.validate()?;
    ensure!(
        operator.broker_namespace_uid == broker_namespace_uid,
        "node broker namespace differs from operator"
    );
    let binding = Binding {
        name: format!("broker-{}", config.binding.launch_nonce.replace('-', "")),
        namespace: "openshell-network".into(),
        namespace_uid: broker_namespace_uid.into(),
        image: image.into(),
        source_namespace_uid: config.binding.namespace_uid.clone(),
        sandbox_name: policy::resource_id(&config.binding.sandbox_id)?,
        source_namespace: policy::namespace(&config.binding.workspace)?,
        launch_nonce: config.binding.launch_nonce.clone(),
        config_sha256: config.digest()?,
        operator_config_sha256: operator.digest()?,
        resolver_nameservers: operator.resolver_nameservers.clone(),
        broker_config: Some(config.clone()),
        inventory: None,
        initial_inventory: None,
        response: None,
        uid: String::new(),
        ip: String::new(),
    };
    broker_manifest::pod(&binding, config.binding.expires_at_unix)
}

/// Reject any broker Pod outside the lifecycle's closed executable specification.
pub(crate) fn validate_node_broker_pod(
    actual: &Value,
    image: &str,
    broker_namespace_uid: &str,
    config: &HostedBrokerConfig,
    operator: &super::HostedNetworkConfig,
) -> Result<()> {
    let expected = node_broker_manifest(image, broker_namespace_uid, config, operator)?;
    broker_spec::validate(&actual["spec"], &expected["spec"])?;
    ensure!(
        ["name", "namespace", "ownerReferences"]
            .iter()
            .all(|field| actual["metadata"][field] == expected["metadata"][field])
            && policy::pod_labels_match(
                &actual["metadata"]["labels"],
                &expected["metadata"]["labels"]
            ),
        "node-observed broker ownership differs"
    );
    Ok(())
}
