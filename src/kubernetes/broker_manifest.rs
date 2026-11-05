//! Generation-specific broker resources and exact cross-namespace principals.
use super::{
    broker_config::{Binding, COMPONENT, Config, NONCE_LABEL, PROFILE, UID_LABEL},
    manifest,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
pub(super) fn labels(binding: &Binding) -> Value {
    json!({"app.kubernetes.io/managed-by":manifest::OWNER,COMPONENT:"network-broker",NONCE_LABEL:binding.launch_nonce,UID_LABEL:binding.source_namespace_uid,"sandbox-id":binding.sandbox_name,"platform.tryhamster.dev/network-profile":PROFILE})
}
pub(super) fn guest_labels(name: &str, binding: &Binding) -> Value {
    let mut labels = manifest::labels(name);
    labels["platform.tryhamster.dev/network-profile"] = json!(PROFILE);
    labels[NONCE_LABEL] = json!(binding.launch_nonce);
    labels[UID_LABEL] = json!(binding.source_namespace_uid);
    labels
}
fn metadata(binding: &Binding) -> Value {
    json!({"name":binding.name,"namespace":binding.namespace,"labels":labels(binding),"ownerReferences":[{"apiVersion":"v1","kind":"Namespace","name":binding.source_namespace,"uid":binding.source_namespace_uid,"controller":false,"blockOwnerDeletion":false}]})
}
pub(super) fn pod(binding: &Binding, expires: u64) -> Result<Value> {
    binding.validate()?;
    let remaining = expires
        .checked_sub(super::lease::now()?)
        .filter(|n| *n > 0)
        .ok_or_else(|| anyhow::anyhow!("broker lease expired"))?;
    Ok(
        json!({"apiVersion":"v1","kind":"Pod","metadata":metadata(binding),"spec":{
        "automountServiceAccountToken":false,"enableServiceLinks":false,"restartPolicy":"Never","nodeSelector":{"pool":"trusted-services"},"dnsPolicy":"None","dnsConfig":{"nameservers":binding.resolver_nameservers,"searches":[],"options":[{"name":"ndots","value":"1"}]},"activeDeadlineSeconds":remaining,"terminationGracePeriodSeconds":5,
        "securityContext":{"runAsNonRoot":true,"runAsUser":10001,"runAsGroup":10001,"fsGroup":10001,"seccompProfile":{"type":"RuntimeDefault"}},
        "initContainers":[{"name":"control-permissions","image":binding.image,"command":["sh","-ec","umask 077; mkdir /run/broker/private"],"resources":{"requests":{"cpu":"10m","memory":"16Mi","ephemeral-storage":"128Mi"},"limits":{"cpu":"100m","memory":"32Mi","ephemeral-storage":"128Mi"}},"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"control","mountPath":"/run/broker"}]}],
        "containers":[{"name":"broker","image":binding.image,"command":["kata-network"],"args":["broker-hosted","--bind","$(POD_IP):3128","--config","/broker-config/config.json","--inventory","/broker-inventory/inventory.json","--control","/run/broker/private/control.sock"],
        "env":[{"name":"POD_IP","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"status.podIP"}}}],
        "securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},
        "resources":{"requests":{"cpu":"100m","memory":"64Mi","ephemeral-storage":"128Mi"},"limits":{"cpu":"1","memory":"128Mi","ephemeral-storage":"128Mi"}},
        "volumeMounts":[{"name":"control","mountPath":"/run/broker"},{"name":"config","mountPath":"/broker-config","readOnly":true},{"name":"inventory","mountPath":"/broker-inventory","readOnly":true}]}],
        "volumes":[{"name":"control","emptyDir":{"medium":"Memory","sizeLimit":"1Mi"}},{"name":"config","configMap":{"name":binding.name,"defaultMode":292}},{"name":"inventory","configMap":{"name":format!("{}-inventory",binding.name),"defaultMode":292}}]}}),
    )
}
pub(super) fn configmap(
    binding: &Binding,
    name: &str,
    key: &str,
    value: &impl serde::Serialize,
) -> Result<Value> {
    let mut meta = metadata(binding);
    meta["name"] = json!(name);
    Ok(
        json!({"apiVersion":"v1","kind":"ConfigMap","metadata":meta,"immutable":true,"data":{key:serde_json::to_string(value)?}}),
    )
}
pub(super) fn guest_policy(
    name: &str,
    namespace: &str,
    binding: &Binding,
    control_namespace: &str,
) -> Value {
    let mut p = manifest::network_policy(name, namespace, control_namespace);
    p["metadata"]["labels"] = guest_labels(name, binding);
    p["spec"]["egress"] = json!([{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":binding.namespace}},"podSelector":{"matchLabels":labels(binding)}}],"ports":[{"protocol":"TCP","port":3128}]}]);
    p
}
pub(super) fn denied(
    config: &Config,
    inventory: &crate::network::InfrastructureInventory,
) -> Vec<String> {
    let mut values: Vec<String> = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/3",
        "168.63.129.16/32",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    values.extend(
        config
            .baseline_denied_cidrs
            .iter()
            .chain(&inventory.denied_cidrs)
            .filter(|s| s.parse::<ipnet::Ipv4Net>().is_ok())
            .cloned(),
    );
    values.sort();
    values.dedup();
    values
}
pub(super) fn network_policy(
    binding: &Binding,
    config: &Config,
    inventory: &crate::network::InfrastructureInventory,
) -> Result<Value> {
    config.validate()?;
    ensure!(
        binding.namespace == config.broker_namespace,
        "broker namespace differs"
    );
    // Public ports get the same private, baseline and inventory exclusions.
    let ports: std::collections::BTreeSet<_> = config
        .operator_ceiling
        .tcp_allow
        .iter()
        .map(|e| e.port)
        .chain(
            config
                .operator_ceiling
                .tcp_allow_public_ports
                .iter()
                .copied(),
        )
        .collect();
    let mut egress = vec![
        json!({"to":[{"namespaceSelector":{"matchLabels":config.resolver_namespace_labels},"podSelector":{"matchLabels":config.resolver_pod_labels}}],"ports":[{"protocol":"UDP","port":53},{"protocol":"TCP","port":53}]}),
    ];
    if !ports.is_empty() {
        egress.push(json!({"to":[{"ipBlock":{"cidr":"0.0.0.0/0","except":denied(config,inventory)}}],"ports":ports.into_iter().map(|port|json!({"protocol":"TCP","port":port})).collect::<Vec<_>>()}));
    }
    Ok(
        json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":metadata(binding),"spec":{
      "podSelector":{"matchLabels":labels(binding)},"policyTypes":["Ingress","Egress"],
      "ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":binding.source_namespace}},"podSelector":{"matchLabels":guest_labels(&binding.sandbox_name,binding)}}],"ports":[{"protocol":"TCP","port":3128}]}],
      "egress":egress}}),
    )
}

pub(super) fn guest_pod(state: &super::model::State) -> Value {
    let mut pod = manifest::pod(
        &state.name,
        &state.namespace,
        &state.image,
        &state.shape(),
        state.docker_disk,
    );
    if let Some(binding) = &state.broker {
        pod["spec"]["runtimeClassName"] = json!(manifest::GUARDED_RUNTIME);
        pod["metadata"]["labels"] = guest_labels(&state.name, binding);
        let url = format!("http://{}:3128", binding.ip);
        let env = pod["spec"]["containers"][0]["env"]
            .as_array_mut()
            .expect("static guest environment");
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            env.push(json!({"name":key,"value":url}));
        }
        for key in ["NO_PROXY", "no_proxy"] {
            env.push(json!({"name":key,"value":"localhost,127.0.0.1,::1"}));
        }
    }
    pod
}
