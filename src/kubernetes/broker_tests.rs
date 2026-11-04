//! Adversarial manifest and additive-policy tests for the opt-in hosted broker.
use super::{
    broker_config::{self, Config},
    broker_manifest, broker_policy, manifest,
};
use serde_json::{Value, json};

fn image() -> String {
    format!("registry.example/adapter@sha256:{}", "b".repeat(64))
}
fn config() -> Config {
    serde_json::from_value(json!({
        "version":1,"broker_namespace":"openshell-network",
        "broker_namespace_uid":"68f2d388-4196-40d1-ae46-9676f578f74d",
        "resolver_namespace_labels":{"kubernetes.io/metadata.name":"trusted-dns"},
        "resolver_pod_labels":{"app":"dns"},"resolver_nameservers":["10.20.0.10"],
        "guard_namespace":"kata-system","guard_namespace_uid":"a964da5c-45bd-4d5d-bd6e-d855c9f7b35a","guard_client_tls_config_file":"/operator/guard-client.json",
        "operator_ceiling":{"tcp_allow":[]},"baseline_denied_cidrs":["10.0.0.0/8"],
        "protected_hostname_suffixes":["internal.example"],"authorization_lease_secs":20,
        "inventory_file":"/operator/inventory.json"
    }))
    .expect("operator config")
}
fn binding() -> broker_config::Binding {
    broker_config::Binding {
        name: "broker-69348810c91b4beb".into(),
        image: image(),
        source_namespace_uid: "789f2ce2-2e81-4942-b20f-75ca3ace4683".into(),
        sandbox_name: super::policy::resource_id("sandbox").expect("sandbox name"),
        launch_nonce: "69348810-c91b-4beb-b9e8-e4c79a771bb2".into(),
        source_namespace: "sandbox-tenant".into(),
        operator_config_sha256: "a".repeat(64),
        resolver_nameservers: config().resolver_nameservers,
        broker_config: None,
        inventory: None,
        initial_inventory: None,
        response: None,
        config_sha256: "a".repeat(64),
        namespace: "openshell-network".into(),
        namespace_uid: config().broker_namespace_uid,
        uid: String::new(),
        ip: String::new(),
    }
}
#[test]
fn broker_is_trusted_tokenless_and_generation_bound() {
    let b = binding();
    let pod = broker_manifest::pod(&b, 4_000_000_000).expect("broker pod");
    assert!(pod["spec"].get("runtimeClassName").is_none());
    assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
    assert_eq!(pod["spec"]["restartPolicy"], "Never");
    assert_eq!(pod["spec"]["securityContext"]["runAsUser"], 10001);
    assert_eq!(
        pod["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"],
        true
    );
    assert_eq!(pod["metadata"]["ownerReferences"][0]["kind"], "Namespace");
    assert_eq!(
        pod["metadata"]["ownerReferences"][0]["uid"],
        b.source_namespace_uid
    );
    assert!(!pod.to_string().contains("hostPath"));
}
#[test]
fn brokered_guest_has_only_combined_exact_broker_principal() {
    let config = config();
    let binding = binding();
    let p = broker_manifest::guest_policy(
        &binding.sandbox_name,
        "sandbox-tenant",
        &binding,
        super::policy::DEFAULT_CONTROL_NAMESPACE,
    );
    let labels = broker_manifest::guest_labels(&binding.sandbox_name, &binding);
    broker_policy::validate_guest(
        std::slice::from_ref(&p),
        &labels,
        &binding,
        super::policy::DEFAULT_CONTROL_NAMESPACE,
    )
    .expect("exact fence");
    let mut broaden = p.clone();
    broaden["spec"]["egress"][0]["to"][0]
        .as_object_mut()
        .expect("peer")
        .remove("podSelector");
    assert!(
        broker_policy::validate_guest(
            &[p.clone(), broaden],
            &labels,
            &binding,
            super::policy::DEFAULT_CONTROL_NAMESPACE
        )
        .is_err()
    );
    let mut broaden = p.clone();
    broaden["spec"]["egress"][0]["ports"][0]["endPort"] = json!(65535);
    assert!(
        broker_policy::validate_guest(
            &[p, broaden],
            &labels,
            &binding,
            super::policy::DEFAULT_CONTROL_NAMESPACE
        )
        .is_err()
    );
    assert_eq!(config.broker_namespace, "openshell-network");
}

#[test]
fn pod_topology_labels_preserve_every_owned_binding_label() {
    let b = binding();
    for expected in [
        broker_manifest::labels(&b),
        broker_manifest::guest_labels(&b.sandbox_name, &b),
    ] {
        let mut observed = expected.clone();
        observed["topology.kubernetes.io/region"] = json!("us-central1");
        observed["topology.kubernetes.io/zone"] = json!("us-central1-a");
        assert!(super::policy::pod_labels_match(&observed, &expected));
        for key in expected.as_object().expect("labels").keys() {
            let mut changed = observed.clone();
            changed[key] = json!("other");
            assert!(
                !super::policy::pod_labels_match(&changed, &expected),
                "changed {key}"
            );
            let mut missing = observed.clone();
            missing.as_object_mut().expect("labels").remove(key);
            assert!(
                !super::policy::pod_labels_match(&missing, &expected),
                "missing {key}"
            );
        }
        observed["untrusted.example/extra"] = json!("true");
        assert!(!super::policy::pod_labels_match(&observed, &expected));
    }
}

#[test]
fn topology_selected_additive_network_policy_is_rejected() {
    let b = binding();
    let mut labels = broker_manifest::labels(&b);
    labels["topology.kubernetes.io/zone"] = json!("us-central1-a");
    let expected = broker_manifest::network_policy(&b, &config(), &inventory()).expect("policy");
    let extra = json!({"spec":{"podSelector":{"matchLabels":{"topology.kubernetes.io/zone":"us-central1-a"}},"policyTypes":["Egress"],"egress":[{}]}});
    assert!(
        broker_policy::validate_broker(&[expected, extra], &labels, &b, &config(), &inventory())
            .is_err()
    );
}
#[test]
fn broker_additive_policy_cannot_allow_nodes_or_extra_resolvers() {
    let cfg = config();
    let b = binding();
    let p = broker_manifest::network_policy(&b, &cfg, &inventory()).expect("broker fence");
    let labels = broker_manifest::labels(&b);
    broker_policy::validate_broker(std::slice::from_ref(&p), &labels, &b, &cfg, &inventory())
        .expect("exact broker fence");
    let extra = json!({"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{}]}});
    assert!(broker_policy::validate_broker(&[p, extra], &labels, &b, &cfg, &inventory()).is_err());
}
#[test]
fn isolated_guest_profile_remains_deny_all() {
    let p = manifest::network_policy(
        "sandbox",
        "sandbox-tenant",
        super::policy::DEFAULT_CONTROL_NAMESPACE,
    );
    assert_eq!(p["spec"]["egress"], json!([]));
    assert_eq!(
        manifest::labels("sandbox")["platform.tryhamster.dev/network-profile"],
        "isolated"
    );
}
#[test]
fn invalid_operator_selectors_and_partial_broker_identities_fail_closed() {
    let mut cfg = config();
    cfg.resolver_pod_labels.clear();
    assert!(cfg.validate().is_err());
    let mut b = binding();
    b.uid = uuid::Uuid::new_v4().to_string();
    assert!(b.validate().is_err());
    let mut value: Value = serde_json::to_value(config()).expect("config");
    value["version"] = json!(2);
    assert!(
        serde_json::from_value::<Config>(value)
            .expect("schema")
            .validate()
            .is_err()
    );
}

fn inventory() -> crate::network::InfrastructureInventory {
    serde_json::from_value(json!({"version":1,"generation":1,"issued_at_unix":1,"expires_at_unix":60,"denied_cidrs":["10.0.0.0/8"]})).expect("inventory")
}

fn bound() -> broker_config::Binding {
    use crate::network::{BrokerBinding, HostedBrokerConfig, NetworkPolicy};
    let mut b = binding();
    let c = HostedBrokerConfig {
        version: 1,
        operator_ceiling: NetworkPolicy::default(),
        initial_ceiling: NetworkPolicy::default(),
        binding: BrokerBinding {
            workspace: "tenant".into(),
            namespace_uid: b.source_namespace_uid.clone(),
            sandbox_id: "sandbox".into(),
            launch_nonce: b.launch_nonce.clone(),
            expires_at_unix: super::lease::now().expect("now") + 3600,
        },
        protected_hostname_suffixes: vec![],
        baseline_denied_cidrs: vec![],
        authorization_lease_secs: 20,
    };
    b.config_sha256 = c.digest().expect("digest");
    b.broker_config = Some(c);
    b.inventory = Some(inventory());
    b.initial_inventory = Some(inventory());
    b.uid = uuid::Uuid::new_v4().to_string();
    b.ip = "10.20.1.3".into();
    b
}
fn response(b: &broker_config::Binding) -> crate::network::HostedControlResponse {
    use crate::network::{HostedControlResponse, NetworkPolicy};
    HostedControlResponse {
        nonce: uuid::Uuid::new_v4().to_string(),
        binding: b.broker_config.as_ref().expect("config").binding.clone(),
        startup_epoch: uuid::Uuid::new_v4().to_string(),
        generation: 1,
        policy: NetworkPolicy::default(),
        policy_sha256: NetworkPolicy::default().digest().expect("digest"),
        config_sha256: b.config_sha256.clone(),
        inventory_generation: 1,
        inventory_sha256: inventory().digest().expect("digest"),
        effective_denied_sha256: "c".repeat(64),
        authorization_expires_at_unix: 0,
        active_connections: 0,
        stopping: false,
    }
}
#[test]
fn control_proof_rejects_replayed_nonce_epoch_binding_and_policy() {
    let mut b = bound();
    let original = response(&b);
    b.response = Some(original.clone());
    super::broker::validate_response(&b, &original, &original.nonce).expect("bound response");
    for change in 0..5 {
        let mut r = original.clone();
        match change {
            0 => r.nonce = uuid::Uuid::new_v4().to_string(),
            1 => r.binding.namespace_uid = uuid::Uuid::new_v4().to_string(),
            2 => r.startup_epoch = uuid::Uuid::new_v4().to_string(),
            3 => r.config_sha256 = "f".repeat(64),
            _ => r.policy_sha256 = "f".repeat(64),
        }
        assert!(
            super::broker::validate_response(&b, &r, &original.nonce).is_err(),
            "change {change}"
        );
    }
}
#[test]
fn public_tcp_ports_and_infrastructure_exclusions_follow_operator_ceiling() {
    let mut cfg = config();
    cfg.operator_ceiling.tcp_allow = vec![
        crate::network::Endpoint {
            host: "example.com".into(),
            port: 443,
        },
        crate::network::Endpoint {
            host: "example.org".into(),
            port: 443,
        },
    ];
    let mut i = inventory();
    i.denied_cidrs.push("8.8.8.8/32".into());
    let p = broker_manifest::network_policy(&binding(), &cfg, &i).expect("policy");
    assert_eq!(
        p["spec"]["egress"][1]["ports"],
        json!([{"protocol":"TCP","port":443}])
    );
    assert!(
        p["spec"]["egress"][1]["to"][0]["ipBlock"]["except"]
            .as_array()
            .expect("except")
            .contains(&json!("8.8.8.8/32"))
    );
    assert_eq!(broker_manifest::network_policy(&binding(),&config(),&i).expect("no public ports")["spec"]["egress"].as_array().expect("egress").len(),1);
}

struct Mock {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    client: super::client::Client,
    binding: broker_config::Binding,
}
impl Mock {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("mock");
        let root = dir.path().canonicalize().expect("path");
        let mut b = bound();
        let r = response(&b);
        b.response = Some(r.clone());
        let mut pod =
            broker_manifest::pod(&b, super::lease::now().expect("now") + 3600).expect("pod");
        pod["metadata"]["uid"] = json!(b.uid);
        pod["status"] = json!({"phase":"Running","podIP":b.ip,"containerStatuses":[{"ready":true,"restartCount":0}]});
        for (name, value) in [
            ("pod.json", pod),
            (
                "source.json",
                json!({"metadata":{"name":b.source_namespace,"uid":b.source_namespace_uid,"labels":{"platform.tryhamster.dev/tenant":"tenant","platform.tryhamster.dev/role":"sandbox"}}}),
            ),
            (
                "namespace.json",
                json!({"metadata":{"name":b.namespace,"uid":b.namespace_uid,"labels":{}}}),
            ),
        ] {
            std::fs::write(root.join(name), serde_json::to_vec(&value).expect("value"))
                .expect("fixture");
        }
        std::fs::write(
            root.join("response.json"),
            serde_json::to_string(&r)
                .expect("response")
                .replace(&r.nonce, "CHALLENGE"),
        )
        .expect("response fixture");
        let mut stop = r.clone();
        stop.stopping = true;
        std::fs::write(
            root.join("stop.json"),
            serde_json::to_string(&stop)
                .expect("stop")
                .replace(&r.nonce, "CHALLENGE"),
        )
        .expect("stop fixture");
        let program = root.join("kubectl");
        let script = format!(
            r#"#!/bin/sh
set -eu
root='{}'
printf '%s\n' "$*" >> "$root/calls"
case "$*" in
*"get namespace kata-system "*) cat "$root/guard-namespace.json";;
*"get namespace sandbox-tenant "*) cat "$root/source.json";;
*"get namespace "*) cat "$root/namespace.json";;
*"get pods "*) cat "$root/guards.json";;
*"get node "*) cat "$root/node.json";;
*"get pod kata-"*) cat "$root/guest.json";;
*"get pvc "*) cat "$root/pvc.json";;
*"get runtimeclass "*) cat "$root/runtime.json";;
*"get networkpolicies -n sandbox-tenant"*) cat "$root/guest-policies.json";;
*"get networkpolicies "*) cat "$root/broker-policies.json";;
*"get configmap "*"-inventory -n"*) if test -f "$root/inventory-map.json"; then cat "$root/inventory-map.json"; fi;;
*"get configmap "*) if test -f "$root/config-map.json"; then cat "$root/config-map.json"; fi;;
*"get pod guard-pod "*) cat "$root/guard-pod.json";;
*"get pod "*) if test -f "$root/pod.json"; then cat "$root/pod.json"; fi;;
*"hosted-ready"*) for arg do last="$arg"; done; sed "s/CHALLENGE/$last/g" "$root/response.json";;
*"hosted-inspect"*|*"hosted-stop"*|*"hosted-authorize"*) cat > "$root/request.json"; nonce=$(sed -n 's/.*"nonce":"\([^"]*\)".*/\1/p' "$root/request.json"); response=response; case "$*" in *hosted-stop*) response=stop;; *hosted-authorize*) response=authorize;; esac; sed "s/CHALLENGE/$nonce/g" "$root/$response.json"; if test -f "$root/replacement.json"; then cp "$root/replacement.json" "$root/pod.json"; fi;;
*"delete --raw "*) cat > "$root/delete.json"; rm "$root/pod.json";;
*"get networkpolicy "*|*"get configmap "*) :;;
*"apply "*) cat > "$root/applied.json"; case "$(cat "$root/applied.json")" in *'"kind":"Pod"'*) cp "$root/bootpod.json" "$root/pod.json";; esac;;
*) exit 1;;
esac
"#,
            root.display()
        );
        std::fs::write(&program, script).expect("script");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).expect("mode");
        Self {
            _dir: dir,
            root,
            client: super::client::Client {
                program,
                context: None,
            },
            binding: b,
        }
    }
}
#[tokio::test]
async fn private_control_roundtrip_does_not_renew_and_binds_request_generation() {
    let f = Mock::new();
    let nonce = uuid::Uuid::new_v4().to_string();
    let r = super::broker::inspect(&f.client, &f.binding, &nonce)
        .await
        .expect("inspect");
    assert_eq!(r.nonce, nonce);
    assert_eq!(r.authorization_expires_at_unix, 0);
    let request: Value =
        serde_json::from_slice(&std::fs::read(f.root.join("request.json")).expect("request"))
            .expect("json");
    assert_eq!(request["expected_generation"], 1);
    assert_eq!(request["startup_epoch"], r.startup_epoch);
    let calls = std::fs::read_to_string(f.root.join("calls")).expect("calls");
    assert!(calls.contains("--control /run/broker/private/control.sock --request -"));
    assert!(!calls.contains("example.com"));
}
#[tokio::test]
async fn control_exec_rejects_pod_replacement_after_successful_rpc() {
    let f = Mock::new();
    let mut pod: Value =
        serde_json::from_slice(&std::fs::read(f.root.join("pod.json")).expect("pod"))
            .expect("json");
    pod["metadata"]["uid"] = json!(uuid::Uuid::new_v4().to_string());
    std::fs::write(
        f.root.join("replacement.json"),
        serde_json::to_vec(&pod).expect("json"),
    )
    .expect("replacement");
    assert!(
        super::broker::inspect(&f.client, &f.binding, &uuid::Uuid::new_v4().to_string())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn broker_stop_drains_before_uid_preconditioned_delete() {
    let f = Mock::new();
    super::broker::delete(&f.client, &f.binding)
        .await
        .expect("stop and delete");
    let deletion: Value =
        serde_json::from_slice(&std::fs::read(f.root.join("delete.json")).expect("delete"))
            .expect("options");
    assert_eq!(deletion["preconditions"]["uid"], f.binding.uid);
    let calls = std::fs::read_to_string(f.root.join("calls")).expect("calls");
    assert!(calls.find("hosted-stop").expect("stop") < calls.find("delete --raw").expect("delete"));
}

fn state_for(f: &Mock, folder: &std::path::Path) -> super::model::State {
    super::model::State {
        sandbox_id: "sandbox".into(),
        workspace: "tenant".into(),
        namespace: "sandbox-tenant".into(),
        name: super::policy::resource_id("sandbox").expect("name"),
        image: image(),
        host: String::new(),
        port: 22,
        username: "sandbox".into(),
        runtime_identity: String::new(),
        launch_nonce: Some(f.binding.launch_nonce.clone()),
        owns_volume_for_launch: false,
        expires_at: Some(
            f.binding
                .broker_config
                .as_ref()
                .expect("config")
                .binding
                .expires_at_unix,
        ),
        private_key_path: folder.join("client_key"),
        known_hosts_path: folder.join("known_hosts"),
        broker: Some(f.binding.clone()),
    }
}
#[tokio::test]
async fn broker_creation_persists_uid_and_starts_without_network_authority() {
    let f = Mock::new();
    let store = super::store::Store::new(&f.root.join("state")).expect("store");
    let folder = store.folder("sandbox").expect("folder");
    let mut state = state_for(&f, &folder);
    let b = state.broker.as_mut().expect("broker");
    b.uid.clear();
    b.ip.clear();
    b.response = None;
    std::fs::rename(f.root.join("pod.json"), f.root.join("bootpod.json")).expect("pending mock");
    let created = super::broker::create_with_config(&f.client, &store, &state, &config())
        .await
        .expect("create broker");
    let b = created.broker.expect("binding");
    assert_eq!(b.uid, f.binding.uid);
    assert_eq!(b.ip, f.binding.ip);
    assert_eq!(
        b.response.expect("readiness").authorization_expires_at_unix,
        0
    );
    let retained = store.read("sandbox").expect("read").expect("state");
    assert_eq!(retained.broker.expect("broker").uid, f.binding.uid);
    let calls = std::fs::read_to_string(f.root.join("calls")).expect("calls");
    assert!(calls.contains("hosted-ready"));
    assert!(!calls.contains("hosted-authorize"));
}
#[tokio::test]
async fn authorization_refreshes_inventory_and_binds_the_cas_acknowledgement() {
    let f = Mock::new();
    let now = super::lease::now().expect("now");
    let mut cfg = config();
    cfg.inventory_file = f.root.join("fresh.json");
    let fresh = crate::network::InfrastructureInventory {
        version: 1,
        generation: 2,
        issued_at_unix: now,
        expires_at_unix: now + 60,
        denied_cidrs: vec!["8.8.8.8/32".into()],
    };
    std::fs::write(
        &cfg.inventory_file,
        serde_json::to_vec(&fresh).expect("inventory"),
    )
    .expect("file");
    let mut ack = f.binding.response.clone().expect("response");
    ack.generation = 2;
    ack.inventory_generation = 2;
    ack.inventory_sha256 = fresh.digest().expect("digest");
    ack.authorization_expires_at_unix = now + 20;
    std::fs::write(
        f.root.join("authorize.json"),
        serde_json::to_string(&ack)
            .expect("response")
            .replace(&ack.nonce, "CHALLENGE"),
    )
    .expect("response");
    let state = state_for(&f, &f.root);
    let nonce = uuid::Uuid::new_v4().to_string();
    let next = super::broker::authorize_with_config(
        &f.client,
        &state,
        crate::network::NetworkPolicy::default(),
        &nonce,
        &cfg,
    )
    .await
    .expect("authorize");
    assert_eq!(
        next.broker
            .expect("binding")
            .inventory
            .expect("inventory")
            .generation,
        2
    );
    let request: Value =
        serde_json::from_slice(&std::fs::read(f.root.join("request.json")).expect("request"))
            .expect("json");
    assert_eq!(request["action"], "authorize");
    assert_eq!(request["expected_generation"], 1);
    assert_eq!(request["inventory"]["generation"], 2);
    let calls = std::fs::read_to_string(f.root.join("calls")).expect("calls");
    assert!(calls.find("apply ").expect("NP") < calls.find("hosted-authorize").expect("authorize"));
}
#[tokio::test]
async fn expired_inventory_cannot_reach_mutation_or_broaden_network() {
    let f = Mock::new();
    let mut cfg = config();
    cfg.inventory_file = f.root.join("stale.json");
    std::fs::write(
        &cfg.inventory_file,
        serde_json::to_vec(&inventory()).expect("inventory"),
    )
    .expect("file");
    assert!(
        super::broker::authorize_with_config(
            &f.client,
            &state_for(&f, &f.root),
            crate::network::NetworkPolicy::default(),
            &uuid::Uuid::new_v4().to_string(),
            &cfg
        )
        .await
        .is_err()
    );
    assert!(!f.root.join("calls").exists());
}

fn fence_fixture(f: &Mock) -> (super::model::State, Value) {
    use crate::network::hosted_fence::{HostedFenceIntent, HostedFenceProof, HostedFenceResponse};
    let now = super::lease::now().expect("now");
    let pod_uid = uuid::Uuid::new_v4().to_string();
    let node_uid = uuid::Uuid::new_v4().to_string();
    let boot = uuid::Uuid::new_v4().to_string();
    let mut state = state_for(f, &f.root);
    state.runtime_identity = pod_uid.clone();
    let intent = HostedFenceIntent {
        version: 1,
        workspace: state.workspace.clone(),
        namespace_uid: f.binding.source_namespace_uid.clone(),
        sandbox_id: state.sandbox_id.clone(),
        pod_uid: pod_uid.clone(),
        launch_nonce: f.binding.launch_nonce.clone(),
        expires_at_unix: state.expires_at.expect("expiry"),
        broker_pod_uid: f.binding.uid.clone(),
        broker_ip: f.binding.ip.parse().expect("IP"),
        broker_port: 3128,
        broker_config_sha256: f.binding.config_sha256.clone(),
        controller_cidrs: vec!["10.20.0.4/32".into()],
        guest_ip: "10.176.0.5".parse().expect("guest IP"),
        guest_mac: "02:00:00:00:00:01".into(),
        gateway_ip: "10.176.0.1".parse().expect("gateway"),
        gateway_mac: "02:00:00:00:00:02".into(),
        interface: "eth0".into(),
        node_uid: node_uid.clone(),
        boot_id: boot.clone(),
    };
    let digest = intent.sha256().expect("digest");
    let proof = HostedFenceProof {
        version: 1,
        binding: intent,
        netns_device: 1,
        netns_inode: 42,
        ifindex: 2,
        ingress_link_id: 3,
        egress_link_id: 4,
        ingress_program_id: 5,
        egress_program_id: 6,
        object_sha256: "a".repeat(64),
        intent_sha256: digest,
        installed_at_unix: now,
    };
    let response = HostedFenceResponse {
        nonce: "CHALLENGE".into(),
        proof,
    };
    let guard = json!({"metadata":{"name":"guard-pod","namespace":"kata-system","uid":uuid::Uuid::new_v4().to_string(),"labels":{broker_config::COMPONENT:"runtime-guard"}},"spec":{"nodeName":"worker","automountServiceAccountToken":false,"containers":[{"name":"node-intent","image":image()},{"name":"proof-server","image":image()}]},"status":{"phase":"Running","podIP":"10.20.1.4","containerStatuses":[{"name":"node-intent","ready":true,"state":{"running":{}}},{"name":"proof-server","ready":true,"state":{"running":{}}}]}});
    for (name, value) in [
        ("guard-pod.json", guard.clone()),
        (
            "guard-namespace.json",
            json!({"metadata":{"name":"kata-system","uid":config().guard_namespace_uid,"labels":{}}}),
        ),
        ("guards.json", json!({"items":[guard]})),
        (
            "guard-response.json",
            serde_json::to_value(response).expect("response"),
        ),
        (
            "node.json",
            json!({"metadata":{"uid":node_uid},"status":{"nodeInfo":{"bootID":boot}}}),
        ),
    ] {
        std::fs::write(
            f.root.join(name),
            serde_json::to_vec(&value).expect("value"),
        )
        .expect("fixture");
    }
    (
        state,
        json!({"metadata":{"uid":pod_uid},"spec":{"nodeName":"worker"},"status":{"podIP":"10.176.0.5"}}),
    )
}
#[tokio::test]
async fn fresh_node_fence_proof_is_queried_outside_guest_and_binds_every_runtime() {
    let f = Mock::new();
    let (state, guest) = fence_fixture(&f);
    let nonce = uuid::Uuid::new_v4().to_string();
    let proof =
        super::fence::verify_with_image(&f.client, &state, &guest, &nonce, &image(), &config())
            .await
            .expect("fence proof");
    assert_eq!(proof.binding.pod_uid, state.runtime_identity);
    let calls = std::fs::read_to_string(f.root.join("calls")).expect("calls");
    assert!(calls.contains("guard-rpc 10.20.1.4:9443"));
    let original = std::fs::read(f.root.join("guard-response.json")).expect("original proof");
    for key in [
        "broker_pod_uid",
        "namespace_uid",
        "broker_config_sha256",
        "pod_uid",
    ] {
        let mut response: Value = serde_json::from_slice(&original).expect("json");
        response["proof"]["binding"][key] = if key == "broker_config_sha256" {
            json!("f".repeat(64))
        } else {
            json!(uuid::Uuid::new_v4().to_string())
        };
        let intent: crate::network::hosted_fence::HostedFenceIntent =
            serde_json::from_value(response["proof"]["binding"].clone()).expect("intent");
        response["proof"]["intent_sha256"] = json!(intent.sha256().expect("digest"));
        std::fs::write(
            f.root.join("guard-response.json"),
            serde_json::to_vec(&response).expect("json"),
        )
        .expect("file");
        assert!(
            super::fence::verify_with_image(
                &f.client,
                &state,
                &guest,
                &uuid::Uuid::new_v4().to_string(),
                &image(),
                &config()
            )
            .await
            .is_err(),
            "changed {key}"
        );
    }
}
#[tokio::test]
async fn guard_on_wrong_node_or_wrong_image_cannot_supply_proof() {
    for field in ["nodeName", "image"] {
        let f = Mock::new();
        let (state, guest) = fence_fixture(&f);
        let mut guards: Value =
            serde_json::from_slice(&std::fs::read(f.root.join("guards.json")).expect("file"))
                .expect("json");
        if field == "nodeName" {
            guards["items"][0]["spec"][field] = json!("other-node");
        } else {
            guards["items"][0]["spec"]["containers"][0][field] =
                json!(format!("other@sha256:{}", "f".repeat(64)));
        }
        std::fs::write(
            f.root.join("guards.json"),
            serde_json::to_vec(&guards).expect("json"),
        )
        .expect("file");
        assert!(
            super::fence::verify_with_image(
                &f.client,
                &state,
                &guest,
                &uuid::Uuid::new_v4().to_string(),
                &image(),
                &config()
            )
            .await
            .is_err()
        );
        assert!(
            !std::fs::read_to_string(f.root.join("calls"))
                .expect("calls")
                .contains("guard-rpc")
        );
    }
}
#[test]
fn operator_config_loading_is_explicit_bounded_and_rejects_unknown_fields() {
    let dir = tempfile::tempdir().expect("directory");
    let path = dir.path().join("network.json");
    let cfg = config();
    std::fs::write(&path, serde_json::to_vec(&cfg).expect("json")).expect("file");
    assert_eq!(
        Config::load(&path)
            .expect("config")
            .digest()
            .expect("digest"),
        cfg.digest().expect("digest")
    );
    assert!(Config::load(std::path::Path::new("relative.json")).is_err());
    let mut value = serde_json::to_value(cfg).expect("value");
    value["unexpected"] = json!(true);
    std::fs::write(&path, serde_json::to_vec(&value).expect("value")).expect("file");
    assert!(Config::load(&path).is_err());
    std::fs::write(&path, vec![b' '; 1024 * 1024 + 1]).expect("large file");
    assert!(Config::load(&path).is_err());
}

#[path = "broker_flow_tests.rs"]
mod flow;

#[tokio::test]
async fn trusted_broker_proof_rejects_unrendered_executable_and_credential_fields() {
    for (pointer, value) in [
        (
            "/spec/ephemeralContainers",
            json!([{"name":"injected","image":image()}]),
        ),
        (
            "/spec/containers/0/lifecycle",
            json!({"postStart":{"exec":{"command":["sh","-c","touch /run/broker/private/injected"]}}}),
        ),
        (
            "/spec/containers/0/envFrom",
            json!([{"configMapRef":{"name":"untrusted"}}]),
        ),
        (
            "/spec/containers/0/startupProbe",
            json!({"exec":{"command":["sh","-c","true"]}}),
        ),
        (
            "/spec/containers/0/readinessProbe",
            json!({"exec":{"command":["sh","-c","true"]}}),
        ),
        (
            "/spec/containers/0/livenessProbe",
            json!({"exec":{"command":["sh","-c","true"]}}),
        ),
        (
            "/spec/initContainers/0/lifecycle",
            json!({"postStart":{"exec":{"command":["sh","-c","true"]}}}),
        ),
        (
            "/spec/initContainers/0/envFrom",
            json!([{"secretRef":{"name":"injected"}}]),
        ),
        (
            "/spec/initContainers/0/readinessProbe",
            json!({"exec":{"command":["sh","-c","true"]}}),
        ),
    ] {
        let f = Mock::new();
        let mut pod: Value =
            serde_json::from_slice(&std::fs::read(f.root.join("pod.json")).expect("pod"))
                .expect("json");
        let parent = pointer.rsplit_once('/').expect("pointer");
        pod.pointer_mut(parent.0)
            .expect("object")
            .as_object_mut()
            .expect("object")
            .insert(parent.1.into(), value);
        std::fs::write(
            f.root.join("pod.json"),
            serde_json::to_vec(&pod).expect("pod"),
        )
        .expect("file");
        assert!(
            super::broker::observe(&f.client, &f.binding).await.is_err(),
            "accepted {pointer}"
        );
        assert!(
            !std::fs::read_to_string(f.root.join("calls"))
                .expect("calls")
                .contains("hosted-")
        );
    }
}

#[test]
fn trusted_broker_spec_accepts_only_known_harmless_api_defaults() {
    let expected = broker_manifest::pod(&binding(), super::lease::now().expect("now") + 3600)
        .expect("manifest");
    let mut actual = expected["spec"].clone();
    for (key, value) in [
        ("dnsPolicy", json!("None")),
        ("schedulerName", json!("default-scheduler")),
        ("serviceAccountName", json!("default")),
        ("serviceAccount", json!("default")),
        ("priority", json!(0)),
        ("preemptionPolicy", json!("PreemptLowerPriority")),
        ("nodeName", json!("trusted-node")),
        ("hostNetwork", json!(false)),
        ("hostPID", json!(false)),
        ("hostIPC", json!(false)),
        ("hostUsers", json!(true)),
        ("imagePullSecrets", json!([])),
        ("os", json!({"name":"linux"})),
        (
            "tolerations",
            json!([{"key":"node.kubernetes.io/not-ready","operator":"Exists","effect":"NoExecute","tolerationSeconds":300}]),
        ),
    ] {
        actual[key] = value;
    }
    actual["securityContext"]["supplementalGroupsPolicy"] = json!("Merge");
    for group in ["containers", "initContainers"] {
        for (key, value) in [
            ("imagePullPolicy", json!("IfNotPresent")),
            ("terminationMessagePath", json!("/dev/termination-log")),
            ("terminationMessagePolicy", json!("File")),
            ("stdin", json!(false)),
            ("stdinOnce", json!(false)),
            ("tty", json!(false)),
        ] {
            actual[group][0][key] = value;
        }
    }
    super::broker_spec::validate(&actual, &expected["spec"]).expect("known API defaults");
    actual["serviceAccountName"] = json!("privileged-identity");
    assert!(super::broker_spec::validate(&actual, &expected["spec"]).is_err());
}

#[test]
fn brokered_guest_control_ingress_uses_the_operator_namespace() {
    let binding = binding();
    let control = "release-control";
    let p =
        broker_manifest::guest_policy(&binding.sandbox_name, "sandbox-tenant", &binding, control);
    let labels = broker_manifest::guest_labels(&binding.sandbox_name, &binding);
    assert_eq!(
        p["spec"]["ingress"][0]["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        control
    );
    broker_policy::validate_guest(std::slice::from_ref(&p), &labels, &binding, control)
        .expect("configured controller allowed");
    assert!(broker_policy::validate_guest(&[p], &labels, &binding, "other-control").is_err());
}
