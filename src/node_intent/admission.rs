//! Bind API observations to an immutable operator capability before host inspection.
use super::config::{Config, canonical_uuid};
use crate::network::{HostedBrokerConfig, hosted_fence::HostedFenceIntent};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) const PROFILE: &str = "brokered-public-tcp-v1";

pub(super) struct Launch {
    pub source_namespace: Value,
    pub node: Value,
    pub broker_namespace: Value,
    pub controller_namespace: Value,
    pub controllers: Value,
    pub broker: Value,
    pub configmap: Value,
}

pub(super) fn name(value: &Value) -> Result<&str> {
    value["metadata"]["name"]
        .as_str()
        .context("resource name missing")
}
fn text<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str> {
    let mut item = value;
    for segment in path {
        item = &item[*segment];
    }
    item.as_str().context("required resource field missing")
}
fn namespace(namespace: &Value, expected_name: &str, expected_uid: &str) -> Result<()> {
    canonical_uuid(expected_uid)?;
    ensure!(
        name(namespace)? == expected_name
            && namespace["metadata"]["uid"] == expected_uid
            && namespace["metadata"]
                .get("deletionTimestamp")
                .is_none_or(Value::is_null),
        "namespace generation differs"
    );
    Ok(())
}
fn no_host_namespaces(pod: &Value) -> Result<()> {
    ensure!(
        ["hostNetwork", "hostPID", "hostIPC"]
            .iter()
            .all(|key| pod["spec"].get(key).is_none_or(|v| v == false))
            && pod["spec"]
                .get("ephemeralContainers")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "host or ephemeral container authority prohibited"
    );
    ensure!(
        pod["metadata"]
            .get("deletionTimestamp")
            .is_none_or(Value::is_null),
        "terminating Pod cannot authorize intent"
    );
    Ok(())
}
fn owner(resource: &Value, source_name: &str, source_uid: &str) -> Result<()> {
    let owners = resource["metadata"]["ownerReferences"]
        .as_array()
        .context("source Namespace owner missing")?;
    ensure!(
        owners.len() == 1
            && owners[0]["apiVersion"] == "v1"
            && owners[0]["kind"] == "Namespace"
            && owners[0]["name"] == source_name
            && owners[0]["uid"] == source_uid
            && owners[0]["controller"] == false
            && owners[0]["blockOwnerDeletion"] == false,
        "resource owner is not exact source Namespace"
    );
    Ok(())
}
fn containers(pod: &Value, group: &str, expected: &BTreeMap<String, String>) -> Result<()> {
    let observed = pod["spec"]
        .get(group)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    ensure!(
        observed.len() == expected.len(),
        "controller container inventory differs"
    );
    let mut seen = BTreeSet::new();
    for container in observed {
        let name = text(container, &["name"])?;
        ensure!(
            seen.insert(name)
                && expected
                    .get(name)
                    .is_some_and(|image| container["image"] == *image),
            "controller image differs from pin"
        );
    }
    Ok(())
}
fn controller_addresses(config: &Config, pods: &Value) -> Result<Vec<String>> {
    let items = pods["items"]
        .as_array()
        .context("controller Pod inventory missing")?;
    ensure!(
        !items.is_empty() && items.len() <= 16,
        "bounded controller inventory required"
    );
    let mut addresses = BTreeSet::new();
    for pod in items {
        no_host_namespaces(pod)?;
        ensure!(
            pod["metadata"]["namespace"] == config.controller_namespace
                && pod["status"]["phase"] == "Running",
            "controller is not running in trusted namespace"
        );
        canonical_uuid(text(pod, &["metadata", "uid"])?)?;
        for (key, value) in &config.controller_labels {
            ensure!(
                pod["metadata"]["labels"][key] == *value,
                "controller selector differs"
            );
        }
        containers(pod, "containers", &config.controller_container_images)?;
        containers(
            pod,
            "initContainers",
            &config.controller_init_container_images,
        )?;
        controller_status(config, pod)?;
        let ip: std::net::Ipv4Addr = text(pod, &["status", "podIP"])?.parse()?;
        ensure!(ip.is_private(), "controller requires private IPv4");
        addresses.insert(format!("{ip}/32"));
    }
    Ok(addresses.into_iter().collect())
}
fn controller_status(config: &Config, pod: &Value) -> Result<()> {
    for (group, status_group, images) in [
        (
            "containers",
            "containerStatuses",
            &config.controller_container_images,
        ),
        (
            "initContainers",
            "initContainerStatuses",
            &config.controller_init_container_images,
        ),
    ] {
        let specs = pod["spec"]
            .get(group)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let states = pod["status"]
            .get(status_group)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        ensure!(
            states.len() == images.len(),
            "controller process inventory differs"
        );
        let mut seen = BTreeSet::new();
        for spec in specs {
            let name = text(spec, &["name"])?;
            let matches = states
                .iter()
                .filter(|s| s["name"] == name)
                .collect::<Vec<_>>();
            ensure!(
                matches.len() == 1 && seen.insert(name),
                "controller process identity differs"
            );
            let state = matches[0];
            if group == "containers" || config.controller_restartable_init_containers.contains(name)
            {
                ensure!(
                    state["ready"] == true && state["state"]["running"].is_object(),
                    "controller process is not running and ready"
                );
                if group == "initContainers" {
                    ensure!(
                        spec["restartPolicy"] == "Always" && state["started"] == true,
                        "restartable init sidecar has not started"
                    );
                }
            } else {
                ensure!(
                    spec.get("restartPolicy").is_none()
                        && state["state"]["terminated"]["exitCode"] == 0
                        && state["state"]["terminated"]["reason"] == "Completed",
                    "controller initializer did not complete successfully"
                );
            }
        }
    }
    Ok(())
}

pub(super) fn derive(config: &Config, guest: &Value, launch: &Launch) -> Result<HostedFenceIntent> {
    let operator = config
        .operator
        .as_ref()
        .context("operator network authority not loaded")?;
    let configmap = &launch.configmap;
    ensure!(
        configmap["immutable"] == true,
        "broker configuration must be immutable"
    );
    let data = configmap["data"]
        .as_object()
        .context("broker configuration data missing")?;
    ensure!(data.len() == 1, "unexpected broker configuration entries");
    let encoded = data
        .get("config.json")
        .and_then(Value::as_str)
        .context("broker config.json missing")?;
    ensure!(encoded.len() <= 128 * 1024, "broker config exceeds bound");
    let broker_config: HostedBrokerConfig =
        serde_json::from_str(encoded).context("invalid broker capability")?;
    broker_config.validate()?;
    let b = &broker_config.binding;
    let source_name = crate::hosted::namespace(&b.workspace)?;
    namespace(&launch.source_namespace, &source_name, &b.namespace_uid)?;
    namespace(
        &launch.broker_namespace,
        &config.broker_namespace,
        &config.broker_namespace_uid,
    )?;
    namespace(
        &launch.controller_namespace,
        &config.controller_namespace,
        &config.controller_namespace_uid,
    )?;
    ensure!(
        operator.broker_namespace == config.broker_namespace
            && operator.broker_namespace_uid == config.broker_namespace_uid,
        "operator broker namespace differs"
    );
    let expected = HostedBrokerConfig {
        provider_mediation: operator.provider_mediation,
        gateway_endpoint: operator.gateway_endpoint.clone(),
        gateway_ca_pem: if operator.provider_mediation {
            std::fs::read_to_string(&operator.gateway_ca_file)?
        } else {
            String::new()
        },
        operator_ceiling: operator.operator_ceiling.clone(),
        baseline_denied_cidrs: operator.baseline_denied_cidrs.clone(),
        protected_hostname_suffixes: operator.protected_hostname_suffixes.clone(),
        authorization_lease_secs: operator.authorization_lease_secs,
        ..broker_config.clone()
    };
    ensure!(
        expected.digest()? == broker_config.digest()?,
        "broker capability exceeds immutable operator authority"
    );
    let digest = broker_config.digest()?;
    validate_guest(config, guest, b, &digest)?;
    validate_broker(config, &launch.broker, configmap, &broker_config)?;
    ensure!(
        name(&launch.node)? == config.node_name
            && launch.node["metadata"]["uid"] == config.node_uid
            && launch.node["status"]["nodeInfo"]["bootID"] == config.boot_id
            && launch.node["metadata"]["labels"]["openshell-kata.io/guarded-runtime"] == "true",
        "live Node generation differs"
    );
    let broker_ip: std::net::Ipv4Addr = text(&launch.broker, &["status", "podIP"])?.parse()?;
    let broker_uid = text(&launch.broker, &["metadata", "uid"])?;
    ensure!(
        guest["metadata"]["annotations"]["openshell-kata.io/broker-pod-uid"] == broker_uid
            && guest["metadata"]["annotations"]["openshell-kata.io/broker-ip"]
                == broker_ip.to_string(),
        "guest references another broker"
    );
    Ok(HostedFenceIntent {
        version: 1,
        workspace: b.workspace.clone(),
        namespace_uid: b.namespace_uid.clone(),
        sandbox_id: b.sandbox_id.clone(),
        pod_uid: text(guest, &["metadata", "uid"])?.into(),
        launch_nonce: b.launch_nonce.clone(),
        expires_at_unix: b.expires_at_unix,
        broker_pod_uid: broker_uid.into(),
        broker_ip,
        broker_port: 3128,
        broker_config_sha256: digest,
        controller_cidrs: controller_addresses(config, &launch.controllers)?,
        guest_ip: std::net::Ipv4Addr::UNSPECIFIED,
        guest_mac: String::new(),
        gateway_ip: std::net::Ipv4Addr::UNSPECIFIED,
        gateway_mac: String::new(),
        interface: "eth0".into(),
        node_uid: config.node_uid.clone(),
        boot_id: config.boot_id.clone(),
    })
}

fn validate_guest(
    config: &Config,
    guest: &Value,
    binding: &crate::network::BrokerBinding,
    digest: &str,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    no_host_namespaces(guest)?;
    canonical_uuid(text(guest, &["metadata", "uid"])?)?;
    ensure!(
        guest["metadata"]["namespace"] == crate::hosted::namespace(&binding.workspace)?
            && guest["spec"]["nodeName"] == config.node_name
            && guest["spec"]["runtimeClassName"] == "kata-qemu-runtime-rs-guarded"
            && guest["spec"]["automountServiceAccountToken"] == false,
        "guest runtime placement differs"
    );
    let expected_name = format!(
        "kata-{}",
        &format!("{:x}", Sha256::digest(binding.sandbox_id.as_bytes()))[..24]
    );
    ensure!(
        name(guest)? == expected_name
            && guest["metadata"]["labels"]["sandbox-id"] == expected_name
            && guest["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "openshell-kata"
            && guest["metadata"]["labels"]["platform.tryhamster.dev/network-profile"] == PROFILE
            && guest["metadata"]["labels"]["openshell-kata.io/namespace-uid"]
                == binding.namespace_uid
            && guest["metadata"]["labels"]["openshell-kata.io/launch-nonce"]
                == binding.launch_nonce,
        "guest managed launch identity differs"
    );
    for (key, value) in [
        ("sandbox-id", binding.sandbox_id.clone()),
        ("launch-nonce", binding.launch_nonce.clone()),
        ("expires-at", binding.expires_at_unix.to_string()),
        ("source-namespace-uid", binding.namespace_uid.clone()),
        ("broker-port", "3128".into()),
        ("broker-config-sha256", digest.into()),
    ] {
        ensure!(
            guest["metadata"]["annotations"][format!("openshell-kata.io/{key}")] == value,
            "guest immutable launch annotation differs"
        );
    }
    let containers = guest["spec"]["containers"]
        .as_array()
        .context("guest container missing")?;
    let init = guest["spec"]["initContainers"]
        .as_array()
        .context("guest storage initializer missing")?;
    let image = containers
        .first()
        .and_then(|container| container["image"].as_str());
    ensure!(
        containers.len() == 1
            && init.len() == 1
            && image.is_some_and(|image| image == config.guest_image
                || config
                    .additional_guest_images
                    .iter()
                    .any(|allowed| allowed == image))
            && init[0]["image"] == containers[0]["image"],
        "guest image inventory differs"
    );
    let now = super::host::now()?;
    ensure!(
        binding.expires_at_unix > now && binding.expires_at_unix - now <= 86400,
        "guest original lease expired or excessive"
    );
    Ok(())
}

fn validate_broker(
    config: &Config,
    broker: &Value,
    configmap: &Value,
    broker_config: &HostedBrokerConfig,
) -> Result<()> {
    let binding = &broker_config.binding;
    no_host_namespaces(broker)?;
    canonical_uuid(text(broker, &["metadata", "uid"])?)?;
    let source = crate::hosted::namespace(&binding.workspace)?;
    owner(broker, &source, &binding.namespace_uid)?;
    owner(configmap, &source, &binding.namespace_uid)?;
    let expected_name = format!("broker-{}", binding.launch_nonce.replace('-', ""));
    ensure!(
        name(broker)? == expected_name
            && name(configmap)? == expected_name
            && broker["metadata"]["namespace"] == config.broker_namespace
            && configmap["metadata"]["namespace"] == config.broker_namespace,
        "broker resource route differs"
    );
    for resource in [broker, configmap] {
        for (key, value) in [
            ("app.kubernetes.io/managed-by", "openshell-kata"),
            ("openshell-kata.io/component", "network-broker"),
            (
                "openshell-kata.io/namespace-uid",
                binding.namespace_uid.as_str(),
            ),
            (
                "openshell-kata.io/launch-nonce",
                binding.launch_nonce.as_str(),
            ),
        ] {
            ensure!(
                resource["metadata"]["labels"][key] == value,
                "broker label identity differs"
            );
        }
    }
    let containers = broker["spec"]["containers"]
        .as_array()
        .context("broker container missing")?;
    let states = broker["status"]["containerStatuses"]
        .as_array()
        .context("broker process status missing")?;
    ensure!(
        containers.len() == 1
            && containers[0]["image"] == config.broker_image
            && broker["spec"]["automountServiceAccountToken"] == false
            && broker["spec"]["restartPolicy"] == "Never"
            && broker["status"]["phase"] == "Running"
            && states.len() == 1
            && states[0]["ready"] == true
            && states[0]["restartCount"] == 0,
        "broker process generation differs"
    );
    crate::kubernetes::validate_node_broker_pod(
        broker,
        &config.broker_image,
        &config.broker_namespace_uid,
        broker_config,
        config
            .operator
            .as_ref()
            .context("operator network authority missing")?,
    )
}

pub(super) fn stable_guest(before: &Value, after: &Value) -> bool {
    before["metadata"]["uid"] == after["metadata"]["uid"]
        && before["metadata"]["labels"] == after["metadata"]["labels"]
        && before["metadata"]["annotations"] == after["metadata"]["annotations"]
        && before["spec"] == after["spec"]
        && after["metadata"]
            .get("deletionTimestamp")
            .is_none_or(Value::is_null)
}
pub(super) fn stable_broker(before: &Value, after: &Value) -> bool {
    stable_guest(before, after)
        && before["status"]["podIP"] == after["status"]["podIP"]
        && before["status"]["containerStatuses"] == after["status"]["containerStatuses"]
}
