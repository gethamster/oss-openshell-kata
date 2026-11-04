//! Complete hosted proof fixture using a separate process for operator environment.
use super::{Mock, binding, config, fence_fixture, image, inventory};
use crate::kubernetes::{
    self as kube,
    broker_config::{self, Config},
    broker_manifest,
};
use serde_json::{Value, json};

#[tokio::test]
async fn subprocess_profile_verifies_complete_broker_and_fence_path() {
    let Some(root) = std::env::var_os("OPENSHELL_KATA_TEST_PROFILE_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let state: kube::model::State =
        broker_config::read_json(&root.join("state.json")).expect("state");
    let client = kube::client::Client {
        program: root.join("kubectl"),
        context: None,
    };
    let nonce = uuid::Uuid::new_v4().to_string();
    let (_, proof) = kube::proof::verify_with_nonce(
        &client,
        &state,
        "portable-rwo",
        &"10.176.0.0/16".parse().expect("network"),
        &nonce,
    )
    .await
    .expect("complete v2 proof");
    assert_eq!(proof["version"], 2);
    assert_eq!(proof["proof_nonce"], nonce);
    assert_eq!(proof["broker"]["nonce"], nonce);
    assert_eq!(proof["fence"]["binding"]["pod_uid"], state.runtime_identity);
    let cfg = Config::load(&root.join("operator.json")).expect("operator config");
    let source: Value = broker_config::read_json(&root.join("source.json")).expect("source");
    let intent = kube::broker::intent(&state, &source, &cfg).expect("bounded broker intent");
    assert_eq!(
        intent.source_namespace_uid,
        state.broker.expect("broker").source_namespace_uid
    );
    assert!(intent.uid.is_empty());
}
#[test]
fn complete_v2_proof_fixture_runs_with_explicit_child_environment() {
    let f = Mock::new();
    let (mut state, guest) = fence_fixture(&f);
    let mut cfg = config();
    cfg.inventory_file = f.root.join("live-inventory.json");
    state
        .broker
        .as_mut()
        .expect("broker")
        .operator_config_sha256 = cfg.digest().expect("digest");
    let b = state.broker.as_ref().expect("broker");
    let now = kube::lease::now().expect("now");
    let mut pod = broker_manifest::guest_pod(&state);
    pod["metadata"]["labels"]["topology.kubernetes.io/region"] = json!("us-central1");
    pod["metadata"]["labels"]["topology.kubernetes.io/zone"] = json!("us-central1-a");
    let broker_path = f.root.join("pod.json");
    let mut broker: Value =
        serde_json::from_slice(&std::fs::read(&broker_path).expect("broker")).expect("broker JSON");
    broker["metadata"]["labels"]["topology.kubernetes.io/region"] = json!("us-central1");
    broker["metadata"]["labels"]["topology.kubernetes.io/zone"] = json!("us-central1-a");
    std::fs::write(
        broker_path,
        serde_json::to_vec(&broker).expect("broker JSON"),
    )
    .expect("broker fixture");
    pod["metadata"]["uid"] = guest["metadata"]["uid"].clone();
    pod["metadata"]["annotations"] = kube::lease::annotations(
        &state.sandbox_id,
        &b.launch_nonce,
        state.expires_at.expect("expiry"),
    );
    pod["spec"]["nodeName"] = json!("worker");
    pod["spec"]["activeDeadlineSeconds"] = json!(300);
    pod["status"] = json!({"phase":"Running","podIP":"10.176.0.5","startTime":chrono::DateTime::from_timestamp(now as i64,0).expect("time").to_rfc3339(),"containerStatuses":[{"ready":true}]});
    let mut node: Value =
        serde_json::from_slice(&std::fs::read(f.root.join("node.json")).expect("node"))
            .expect("node json");
    node["metadata"]["labels"] = json!({"pool":"kata-workers","katacontainers.io/kata-runtime":"true","openshell-kata.io/guarded-runtime":"true"});
    let source = json!({"metadata":{"name":state.namespace,"uid":b.source_namespace_uid,"labels":{"platform.tryhamster.dev/tenant":"tenant","platform.tryhamster.dev/role":"sandbox"}}});
    let fresh = crate::network::InfrastructureInventory {
        version: 1,
        generation: 2,
        issued_at_unix: now,
        expires_at_unix: now + 60,
        denied_cidrs: vec![],
    };
    let network = b.broker_config.as_ref().expect("config");
    for (name, value) in [
        ("state.json", serde_json::to_value(&state).expect("state")),
        (
            "operator.json",
            serde_json::to_value(&cfg).expect("operator"),
        ),
        ("initial.json", json!({"tcp_allow":[]})),
        (
            "live-inventory.json",
            serde_json::to_value(fresh).expect("inventory"),
        ),
        ("guest.json", pod),
        ("source.json", source),
        ("node.json", node),
        (
            "pvc.json",
            kube::manifest::pvc(&state.name, &state.namespace, "portable-rwo"),
        ),
        (
            "runtime.json",
            json!({"handler":kube::manifest::GUARDED_RUNTIME,"metadata":{"annotations":{"katacontainers.io/kata-version":"4.3.1"}}}),
        ),
        (
            "guest-policies.json",
            json!({"items":[broker_manifest::guest_policy(&state.name,&state.namespace,b, super::policy::DEFAULT_CONTROL_NAMESPACE)]}),
        ),
        (
            "broker-policies.json",
            json!({"items":[broker_manifest::network_policy(b,&cfg,&inventory()).expect("policy")]}),
        ),
        (
            "config-map.json",
            broker_manifest::configmap(b, &b.name, "config.json", network).expect("map"),
        ),
        (
            "inventory-map.json",
            broker_manifest::configmap(
                b,
                &format!("{}-inventory", b.name),
                "inventory.json",
                &inventory(),
            )
            .expect("map"),
        ),
    ] {
        std::fs::write(
            f.root.join(name),
            serde_json::to_vec(&value).expect("value"),
        )
        .expect("fixture");
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "kubernetes::broker_tests::flow::subprocess_profile_verifies_complete_broker_and_fence_path",
            "--nocapture",
        ])
        .env("OPENSHELL_KATA_TEST_PROFILE_ROOT", &f.root)
        .env(
            "OPENSHELL_KATA_HOSTED_NETWORK_CONFIG",
            f.root.join("operator.json"),
        )
        .env("OPENSHELL_KATA_GUARD_IMAGE", image())
        .env("OPENSHELL_KATA_BROKER_IMAGE", image())
        .env(
            "OPENSHELL_KATA_INITIAL_NETWORK_POLICY_FILE",
            f.root.join("initial.json"),
        )
        .output()
        .expect("child fixture");
    assert!(
        output.status.success(),
        "child failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn broker_dns_is_explicit_and_rejects_ambient_or_unbounded_resolvers() {
    let cfg = config();
    let b = binding();
    let pod = broker_manifest::pod(&b, kube::lease::now().expect("now") + 3600).expect("broker");
    assert_eq!(pod["spec"]["dnsPolicy"], "None");
    assert_eq!(
        pod["spec"]["dnsConfig"],
        json!({"nameservers":["10.20.0.10"],"searches":[],"options":[{"name":"ndots","value":"1"}]})
    );
    for nameservers in [
        json!([]),
        json!(["10.20.0.10", "10.20.0.10"]),
        json!(["8.8.8.8"]),
        json!(["127.0.0.1"]),
        json!(["169.254.20.10"]),
        json!(["10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4"]),
    ] {
        let mut value = serde_json::to_value(&cfg).expect("config");
        value["resolver_nameservers"] = nameservers;
        assert!(
            serde_json::from_value::<Config>(value)
                .expect("schema")
                .validate()
                .is_err()
        );
    }
}

#[test]
fn broker_runs_on_trusted_services_pool_with_bounded_init_and_storage() {
    let pod =
        broker_manifest::pod(&binding(), kube::lease::now().expect("now") + 3600).expect("broker");
    assert_eq!(
        pod["spec"]["nodeSelector"],
        json!({"pool":"trusted-services"})
    );
    assert!(pod["spec"].get("runtimeClassName").is_none());
    assert_eq!(
        pod["spec"]["containers"][0]["resources"],
        json!({"requests":{"cpu":"100m","memory":"64Mi","ephemeral-storage":"128Mi"},"limits":{"cpu":"1","memory":"128Mi","ephemeral-storage":"128Mi"}})
    );
    assert_eq!(
        pod["spec"]["initContainers"][0]["resources"],
        json!({"requests":{"cpu":"10m","memory":"16Mi","ephemeral-storage":"128Mi"},"limits":{"cpu":"100m","memory":"32Mi","ephemeral-storage":"128Mi"}})
    );
    let mut changed = pod.clone();
    changed["spec"]["nodeSelector"]["pool"] = json!("kata-workers");
    assert!(kube::broker_spec::validate(&changed["spec"], &pod["spec"]).is_err());
    let mut changed = pod.clone();
    changed["spec"]["initContainers"][0]["resources"]["limits"]["ephemeral-storage"] = json!("1Gi");
    assert!(kube::broker_spec::validate(&changed["spec"], &pod["spec"]).is_err());
}

#[test]
fn brokered_guests_require_a_distinct_preboot_guarded_runtime() {
    let f = Mock::new();
    let (state, _) = fence_fixture(&f);
    let guest = broker_manifest::guest_pod(&state);
    assert_eq!(
        guest["spec"]["runtimeClassName"],
        "kata-qemu-runtime-rs-guarded"
    );
    assert_eq!(
        guest["spec"]["nodeSelector"],
        json!({"pool":"kata-workers"})
    );
    assert_eq!(
        kube::manifest::pod("id", "sandbox-tenant", &image())["spec"]["runtimeClassName"],
        "kata-qemu-runtime-rs"
    );
}

#[tokio::test]
async fn guard_rpc_rejects_namespace_replay_and_post_rpc_pod_replacement_without_exec() {
    for change in ["namespace", "nonce", "replacement"] {
        let f = Mock::new();
        let (state, guest) = fence_fixture(&f);
        let operator = config();
        match change {
            "namespace" => {
                let mut ns: Value = serde_json::from_slice(
                    &std::fs::read(f.root.join("guard-namespace.json")).expect("namespace"),
                )
                .expect("json");
                ns["metadata"]["uid"] = json!(uuid::Uuid::new_v4().to_string());
                std::fs::write(
                    f.root.join("guard-namespace.json"),
                    serde_json::to_vec(&ns).expect("json"),
                )
                .expect("file");
            }
            "nonce" => {
                let mut response: Value = serde_json::from_slice(
                    &std::fs::read(f.root.join("guard-response.json")).expect("response"),
                )
                .expect("json");
                response["nonce"] = json!(uuid::Uuid::new_v4().to_string());
                std::fs::write(
                    f.root.join("guard-response.json"),
                    serde_json::to_vec(&response).expect("json"),
                )
                .expect("file");
            }
            _ => {
                let mut pod: Value = serde_json::from_slice(
                    &std::fs::read(f.root.join("guard-pod.json")).expect("pod"),
                )
                .expect("json");
                pod["metadata"]["uid"] = json!(uuid::Uuid::new_v4().to_string());
                std::fs::write(
                    f.root.join("guard-replacement.json"),
                    serde_json::to_vec(&pod).expect("json"),
                )
                .expect("file");
            }
        }
        assert!(
            kube::fence::verify_with_image(
                &f.client,
                &state,
                &guest,
                &uuid::Uuid::new_v4().to_string(),
                &image(),
                &operator
            )
            .await
            .is_err(),
            "accepted {change}"
        );
        let calls = std::fs::read_to_string(f.root.join("calls")).expect("calls");
        assert!(!calls.contains(" exec "));
        assert!(!calls.contains("kata-runtime-guard"));
        if change == "namespace" {
            assert!(!calls.contains("guard-rpc"));
        } else {
            assert!(calls.contains("guard-rpc 10.20.1.4:9443"));
        }
    }
}
#[test]
fn privileged_guard_namespace_and_tls_paths_are_operator_owned_syntax() {
    for (field, value) in [
        ("guard_namespace", json!("openshell-network")),
        ("guard_namespace_uid", json!("not-uid")),
        (
            "guard_client_tls_config_file",
            json!("relative-client.json"),
        ),
    ] {
        let mut c = serde_json::to_value(config()).expect("config");
        c[field] = value;
        assert!(
            serde_json::from_value::<Config>(c)
                .expect("schema")
                .validate()
                .is_err(),
            "accepted {field}"
        );
    }
    let mut c = config();
    c.guard_client_tls_config_file = "/not-mounted-in-node/client.json".into();
    c.validate()
        .expect("node only validates syntax, not Gateway key access");
}

#[test]
fn guard_composition_requires_both_exact_ready_containers_and_no_host_namespaces() {
    let f = Mock::new();
    fence_fixture(&f);
    let good: Value =
        serde_json::from_slice(&std::fs::read(f.root.join("guard-pod.json")).expect("guard"))
            .expect("json");
    kube::fence::validate_guard(&good, &image(), "kata-system", "worker")
        .expect("two trusted ready containers");
    for change in [
        "extra",
        "duplicate",
        "unready",
        "not-running",
        "hostNetwork",
        "hostPID",
        "hostIPC",
        "ephemeral",
        "init",
        "token",
    ] {
        let mut pod = good.clone();
        match change {
            "extra" => pod["spec"]["containers"]
                .as_array_mut()
                .expect("containers")
                .push(json!({"name":"extra","image":image()})),
            "duplicate" => pod["spec"]["containers"][1]["name"] = json!("node-intent"),
            "unready" => pod["status"]["containerStatuses"][1]["ready"] = json!(false),
            "not-running" => {
                pod["status"]["containerStatuses"][1]["state"] = json!({"terminated":{}})
            }
            "ephemeral" => {
                pod["spec"]["ephemeralContainers"] = json!([{"name":"extra","image":image()}])
            }
            "init" => pod["spec"]["initContainers"] = json!([{"name":"installer","image":image()}]),
            "token" => pod["spec"]["automountServiceAccountToken"] = json!(true),
            field => pod["spec"][field] = json!(true),
        }
        assert!(
            kube::fence::validate_guard(&pod, &image(), "kata-system", "worker").is_err(),
            "accepted {change}"
        );
    }
}

#[test]
fn network_peers_bind_full_generation_labels_and_exact_namespace_names() {
    let b = binding();
    let labels = broker_manifest::guest_labels(&b.sandbox_name, &b);
    let p = broker_manifest::guest_policy(
        &b.sandbox_name,
        &b.source_namespace,
        &b,
        super::policy::DEFAULT_CONTROL_NAMESPACE,
    );
    assert_eq!(
        p["spec"]["egress"][0]["to"][0]["namespaceSelector"]["matchLabels"],
        json!({"kubernetes.io/metadata.name":"openshell-network"})
    );
    for key in [
        broker_config::UID_LABEL,
        broker_config::NONCE_LABEL,
        "sandbox-id",
    ] {
        let mut missing = labels.clone();
        missing.as_object_mut().expect("labels").remove(key);
        assert!(
            kube::broker_policy::validate_guest(
                std::slice::from_ref(&p),
                &missing,
                &b,
                super::policy::DEFAULT_CONTROL_NAMESPACE
            )
            .is_err(),
            "accepted missing {key}"
        );
    }
    let bp = broker_manifest::network_policy(&b, &config(), &inventory()).expect("broker policy");
    assert_eq!(
        bp["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"],
        labels
    );
    let mut copied = bp.clone();
    copied["spec"]["ingress"][0]["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] =
        json!("sandbox-other");
    assert!(
        kube::broker_policy::validate_broker(
            &[copied],
            &broker_manifest::labels(&b),
            &b,
            &config(),
            &inventory()
        )
        .is_err()
    );
}
#[tokio::test]
async fn copied_namespace_uid_mirror_cannot_authorize_after_actual_namespace_replacement() {
    let f = Mock::new();
    let mut cfg = config();
    cfg.inventory_file = f.root.join("fresh.json");
    let now = kube::lease::now().expect("now");
    std::fs::write(
        &cfg.inventory_file,
        serde_json::to_vec(&crate::network::InfrastructureInventory {
            version: 1,
            generation: 2,
            issued_at_unix: now,
            expires_at_unix: now + 60,
            denied_cidrs: vec![],
        })
        .expect("inventory"),
    )
    .expect("file");
    let mut namespace: Value =
        serde_json::from_slice(&std::fs::read(f.root.join("source.json")).expect("namespace"))
            .expect("json");
    namespace["metadata"]["uid"] = json!(uuid::Uuid::new_v4().to_string());
    namespace["metadata"]["labels"][broker_config::UID_LABEL] =
        json!(f.binding.source_namespace_uid);
    std::fs::write(
        f.root.join("source.json"),
        serde_json::to_vec(&namespace).expect("json"),
    )
    .expect("file");
    assert!(
        kube::broker::authorize_with_config(
            &f.client,
            &super::state_for(&f, &f.root),
            crate::network::NetworkPolicy::default(),
            &uuid::Uuid::new_v4().to_string(),
            &cfg
        )
        .await
        .is_err()
    );
    let calls = std::fs::read_to_string(f.root.join("calls")).expect("calls");
    assert!(!calls.contains(" exec ") && !calls.contains("hosted-") && !calls.contains(" apply "));
}
