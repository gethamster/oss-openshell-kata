use super::*;
use serde_json::json;
fn network() -> ipnet::IpNet {
    "10.176.0.0/16".parse().expect("network")
}

fn image() -> String {
    format!("registry.example/guest@sha256:{}", "a".repeat(64))
}
fn state() -> model::State {
    let name = policy::resource_id("id").expect("id");
    model::State {
        sandbox_id: "id".into(),
        workspace: "1h31c".into(),
        namespace: "sandbox-1h31c".into(),
        name,
        image: image(),
        host: "".into(),
        port: 22,
        username: "sandbox".into(),
        runtime_identity: "93f296f5-c3b3-4599-bede-aaeb88db87b1".into(),
        broker: None,
        private_key_path: "/state/key".into(),
        known_hosts_path: "/state/known".into(),
        launch_nonce: Some(uuid::Uuid::new_v4().to_string()),
        owns_volume_for_launch: false,
        expires_at: Some(lease::now().expect("now") + 3600),
        resource_shape: None,
    }
}
fn build_shape() -> crate::resource_shape::ResourceShape {
    crate::resource_shape::ResourceShape::parse("build=4,8Gi,100Gi").expect("build shape")
}
fn observations(state: &model::State) -> proof::Observations {
    let mut pod = manifest::pod(&state.name, &state.namespace, &state.image, &state.shape());
    pod["metadata"]["uid"] = json!(state.runtime_identity);
    pod["metadata"]["resourceVersion"] = json!("1");
    pod["metadata"]["annotations"] = lease::annotations(
        &state.sandbox_id,
        state.launch_nonce.as_deref().expect("launch nonce"),
        state.expires_at.expect("lease"),
    );
    pod["spec"]["activeDeadlineSeconds"] = json!(300);
    pod["spec"]["nodeName"] = json!("worker");
    pod["status"] = json!({"phase":"Running","startTime":chrono::DateTime::from_timestamp(lease::now().expect("now") as i64,0).expect("time").to_rfc3339(),"podIP":"10.176.0.5","containerStatuses":[{"ready":true}]});
    proof::Observations {
        pod,
        pvc: manifest::pvc(
            &state.name,
            &state.namespace,
            "standard-rwo",
            &state.shape(),
        ),
        node: json!({"metadata":{"labels":{"pool":"kata-workers","katacontainers.io/kata-runtime":"true"}}}),
        runtime: json!({"handler":manifest::RUNTIME,"metadata":{"annotations":{"katacontainers.io/kata-version":"4.3.1"}}}),
        policies: vec![manifest::network_policy(
            &state.name,
            &state.namespace,
            policy::DEFAULT_CONTROL_NAMESPACE,
        )],
    }
}
#[test]
fn workspace_names_cannot_escape_tenant_mapping() {
    assert_eq!(
        policy::namespace("1h31c").expect("workspace"),
        "sandbox-1h31c"
    );
    assert!(policy::namespace(&"a".repeat(63)).expect("long").len() <= 63);
    for name in [
        "",
        "../other",
        "default",
        "kube-system",
        "UPPER",
        "-tenant",
        "tenant-",
    ] {
        assert!(policy::namespace(name).is_err(), "accepted {name}");
    }
}
#[test]
fn only_exact_pinned_guest_images_are_accepted() {
    for value in [
        "docker:latest",
        "docker:29-dind",
        "repo@sha256:xyz",
        "-repo@sha256:aaaa",
    ] {
        assert!(policy::validate_image(value).is_err(), "accepted {value}");
    }
    policy::validate_image(&image()).expect("pinned");
}
#[test]
fn storage_profile_is_operator_selected_and_verified() {
    for name in [
        "aws-ebs-gp3",
        "azure-managed-csi",
        "tenant.fast",
        "kata-regional-rwo",
    ] {
        policy::validate_storage_class(name).expect("operator-selected storage profile");
    }
    for name in [
        "", "Upper", "a/b", "a b", ".bad", "bad.", "a..b", "-bad", "bad-",
    ] {
        assert!(
            policy::validate_storage_class(name).is_err(),
            "accepted {name:?}"
        );
    }
    assert!(policy::validate_storage_class(&"a".repeat(254)).is_err());
    assert!(policy::validate_storage_class(&"a".repeat(64)).is_err());
    let state = state();
    let observed = observations(&state);
    assert!(
        proof::validate(
            &state,
            "kata-regional-rwo",
            &observed,
            &network(),
            policy::DEFAULT_CONTROL_NAMESPACE
        )
        .is_err()
    );
}
#[test]
fn additive_egress_and_unbounded_ingress_are_rejected() {
    let labels = json!({"sandbox-id":"test"});
    let deny = json!({"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"]}});
    policy::validate_policies(
        std::slice::from_ref(&deny),
        &labels,
        policy::DEFAULT_CONTROL_NAMESPACE,
    )
    .expect("deny all");
    let allow = json!({"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{}]}});
    assert!(
        policy::validate_policies(&[deny, allow], &labels, policy::DEFAULT_CONTROL_NAMESPACE)
            .is_err()
    );
    for rule in [
        json!({}),
        json!({"ports":[{"port":22}]}),
        json!({"from":[{}]}),
    ] {
        let policy =
            json!({"spec":{"podSelector":{},"policyTypes":["Egress","Ingress"],"ingress":[rule]}});
        assert!(
            policy::validate_policies(&[policy], &labels, policy::DEFAULT_CONTROL_NAMESPACE)
                .is_err()
        );
    }
}
#[test]
fn ssh_ingress_is_limited_to_exact_trusted_principal_and_ports() {
    let policy = manifest::network_policy("id", "sandbox-1h31c", policy::DEFAULT_CONTROL_NAMESPACE);
    policy::validate_policies(
        std::slice::from_ref(&policy),
        &manifest::labels("id"),
        policy::DEFAULT_CONTROL_NAMESPACE,
    )
    .expect("trusted");
    for pointer in [
        "/spec/ingress/0/from/0/namespaceSelector/matchLabels/kubernetes.io~1metadata.name",
        "/spec/ingress/0/from/0/podSelector/matchLabels/platform.tryhamster.dev~1role",
        "/spec/ingress/0/ports/0/port",
    ] {
        let mut changed = policy.clone();
        *changed.pointer_mut(pointer).expect("field") = json!("foreign");
        assert!(
            policy::validate_policies(
                &[changed],
                &manifest::labels("id"),
                policy::DEFAULT_CONTROL_NAMESPACE
            )
            .is_err()
        );
    }
    let mut changed = policy;
    changed["spec"]["ingress"][0]["ports"][0]["endPort"] = json!(65535);
    assert!(
        policy::validate_policies(
            &[changed],
            &manifest::labels("id"),
            policy::DEFAULT_CONTROL_NAMESPACE
        )
        .is_err()
    );
}
#[test]
fn ingress_only_policy_is_not_egress_isolation() {
    assert!(
        policy::validate_policies(
            &[json!({"spec":{"podSelector":{},"policyTypes":["Ingress"],"egress":[]}})],
            &json!({}),
            policy::DEFAULT_CONTROL_NAMESPACE,
        )
        .is_err()
    );
}
#[test]
fn pod_has_private_storage_no_token_fixed_vm_and_no_python_probe() {
    let default = crate::resource_shape::ResourceShape::default();
    let pod = manifest::pod("id", "sandbox-1h31c", &image(), &default);
    assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
    assert_eq!(pod["spec"]["runtimeClassName"], manifest::RUNTIME);
    assert_eq!(
        pod["spec"]["containers"][0]["readinessProbe"]["exec"]["command"][2],
        r#"test -n "$(ss -H -lnt 'sport = :22')""#
    );
    // Node-origin TCP probes are intentionally outside the guest packet policy.
    assert!(pod["spec"]["containers"][0]["readinessProbe"]["exec"].is_object());
    assert!(pod["spec"]["containers"][0]["readinessProbe"]["tcpSocket"].is_null());
    assert_eq!(
        pod["spec"]["containers"][0]["readinessProbe"]["exec"]["command"][2],
        r#"test -n "$(ss -H -lnt 'sport = :22')""#
    );
    assert_eq!(
        pod["spec"]["containers"][0]["resources"]["limits"],
        manifest::limits(&default)
    );
    assert!(!pod.to_string().contains("python"));
}
#[test]
fn default_shape_manifests_are_unchanged() {
    let default = crate::resource_shape::ResourceShape::default();
    let resources = json!({"cpu":"2","memory":"4Gi","ephemeral-storage":"1Gi"});
    let pod = manifest::pod("id", "sandbox-1h31c", &image(), &default);
    for container in ["containers", "initContainers"] {
        assert_eq!(
            pod["spec"][container][0]["resources"],
            json!({"requests":resources,"limits":resources})
        );
    }
    assert_eq!(
        manifest::pvc("id", "sandbox-1h31c", "standard-rwo", &default)["spec"]["resources"],
        json!({"requests":{"storage":"19Gi"}})
    );
    // Default retained state serializes without the new field, as before.
    assert!(
        !serde_json::to_string(&state())
            .expect("state")
            .contains("resource_shape")
    );
}
#[test]
fn declared_shape_sizes_pod_volume_and_proof() {
    let shape = build_shape();
    let shaped = model::State {
        resource_shape: Some(shape.clone()),
        ..state()
    };
    let observed = observations(&shaped);
    let resources = json!({"cpu":"4","memory":"8Gi","ephemeral-storage":"1Gi"});
    assert_eq!(
        observed.pod["spec"]["containers"][0]["resources"],
        json!({"requests":resources,"limits":resources})
    );
    assert_eq!(
        observed.pvc["spec"]["resources"]["requests"]["storage"],
        "100Gi"
    );
    let (_, proof) = proof::validate(
        &shaped,
        "standard-rwo",
        &observed,
        &network(),
        policy::DEFAULT_CONTROL_NAMESPACE,
    )
    .expect("shaped proof");
    assert_eq!(
        (proof["cpu"].as_str(), proof["memory"].as_str()),
        (Some("4"), Some("8Gi"))
    );
    assert_eq!(
        proof["resource_shape"],
        serde_json::to_value(&shape).expect("shape")
    );
    // A default-sized Pod or volume cannot stand in for the retained shape,
    // and a shaped Pod or volume cannot stand in for the default shape.
    let default_state = state();
    let default_resources = json!({"cpu":"2","memory":"4Gi","ephemeral-storage":"1Gi"});
    for (retained, sizes, storage) in [
        (&shaped, default_resources.clone(), "100Gi"),
        (&shaped, resources.clone(), "19Gi"),
        (&default_state, resources.clone(), "19Gi"),
        (&default_state, default_resources, "100Gi"),
    ] {
        let mut changed = observations(retained);
        changed.pod["spec"]["containers"][0]["resources"] =
            json!({"requests":sizes,"limits":sizes});
        changed.pvc["spec"]["resources"]["requests"]["storage"] = json!(storage);
        assert!(
            proof::validate(
                retained,
                "standard-rwo",
                &changed,
                &network(),
                policy::DEFAULT_CONTROL_NAMESPACE
            )
            .is_err()
        );
    }
}
#[test]
fn retained_state_rejects_an_explicit_default_shape() {
    let folder = std::path::Path::new("/state");
    let mut state = model::State {
        private_key_path: folder.join("client_key"),
        known_hosts_path: folder.join("known_hosts"),
        resource_shape: Some(build_shape()),
        ..state()
    };
    state.validate("id", folder).expect("declared shape");
    state.resource_shape = Some(crate::resource_shape::ResourceShape::default());
    assert!(state.validate("id", folder).is_err());
}
#[test]
fn live_proof_binds_uid_image_storage_boot_and_network() {
    let state = state();
    let observed = observations(&state);
    let (actual, proof) = proof::validate(
        &state,
        "standard-rwo",
        &observed,
        &network(),
        policy::DEFAULT_CONTROL_NAMESPACE,
    )
    .expect("live proof");
    assert_eq!(actual.host, "10.176.0.5");
    assert_eq!(proof["network"], "deny-all-egress");
    for (pointer, value) in [
        ("/metadata/uid", json!(uuid::Uuid::new_v4().to_string())),
        (
            "/spec/volumes/0/persistentVolumeClaim/claimName",
            json!("foreign"),
        ),
        ("/spec/containers/0/command", json!(["sh", "-c", "unsafe"])),
        ("/spec/initContainers/0/image", json!("foreign:latest")),
        ("/spec/automountServiceAccountToken", json!(true)),
        ("/spec/containers/0/resources/limits/cpu", json!("99")),
    ] {
        let mut changed = observations(&state);
        *changed.pod.pointer_mut(pointer).expect("field") = value;
        assert!(
            proof::validate(
                &state,
                "standard-rwo",
                &changed,
                &network(),
                policy::DEFAULT_CONTROL_NAMESPACE
            )
            .is_err(),
            "accepted {pointer}"
        );
    }
}
#[test]
fn resources_require_exact_owner_and_namespace_tenant() {
    policy::require_owned(
        &json!({"metadata":{"labels":manifest::labels("kata-id")}}),
        "kata-id",
    )
    .expect("owned");
    assert!(policy::require_owned(&json!({"metadata":{}}), "kata-id").is_err());
    assert!(
        policy::require_owned(
            &json!({"metadata":{"labels":manifest::labels("other")}}),
            "kata-id"
        )
        .is_err()
    );
    let namespace = json!({"metadata":{"labels":{"platform.tryhamster.dev/tenant":"1h31c","platform.tryhamster.dev/role":"sandbox"}}});
    policy::check_namespace(&namespace, "1h31c").expect("namespace");
    assert!(policy::check_namespace(&namespace, "other").is_err());
    // Instance names do not authorize access: every namespace must be enrolled
    // for this exact tenant and carry the sandbox role.
    let platform_namespace = json!({"metadata":{"labels":{
        "platform.tryhamster.dev/tenant":"self-hosted",
        "platform.tryhamster.dev/role":"control-plane"
    }}});
    assert!(policy::check_namespace(&platform_namespace, "self-hosted").is_err());
    assert!(policy::check_namespace(&json!({"metadata":{}}), "self-hosted").is_err());
}
#[test]
fn per_sandbox_locks_do_not_serialize_other_tenants() {
    let temp = tempfile::tempdir().expect("state");
    let path = temp.path().canonicalize().expect("canonical");
    let store = store::Store::new(&path).expect("store");
    let _first = store.lock("first").expect("first");
    let _second = store.lock("second").expect("second");
}
#[test]
fn generation_cleanup_refuses_replaced_uid_or_nonce() {
    let mut state = state();
    let nonce = uuid::Uuid::new_v4().to_string();
    state.launch_nonce = Some(nonce.clone());
    let mut observed = observations(&state);
    observed.pod["metadata"]["annotations"] = json!({"openshell-kata.io/launch-nonce":nonce});
    lifecycle::require_generation(&observed.pod, &state).expect("owned generation");
    observed.pod["metadata"]["annotations"]["openshell-kata.io/launch-nonce"] =
        json!(uuid::Uuid::new_v4().to_string());
    assert!(lifecycle::require_generation(&observed.pod, &state).is_err());
    observed.pod["metadata"]["annotations"]["openshell-kata.io/launch-nonce"] = json!(nonce);
    observed.pod["metadata"]["uid"] = json!(uuid::Uuid::new_v4().to_string());
    assert!(lifecycle::require_generation(&observed.pod, &state).is_err());
}
#[test]
fn live_proof_rejects_guest_address_outside_operator_range() {
    let state = state();
    let mut observed = observations(&state);
    observed.pod["status"]["podIP"] = json!("10.177.0.5");
    assert!(
        proof::validate(
            &state,
            "standard-rwo",
            &observed,
            &network(),
            policy::DEFAULT_CONTROL_NAMESPACE
        )
        .is_err()
    );
}
#[test]
fn retained_state_round_trips_privately_and_deletion_erases_ssh_files() {
    use std::os::unix::fs::PermissionsExt as _;
    let temp = tempfile::tempdir().expect("state");
    let path = temp.path().canonicalize().expect("canonical");
    let store = store::Store::new(&path).expect("store");
    let folder = store.folder("id").expect("folder");
    let mut state = state();
    state.private_key_path = folder.join("client_key");
    state.known_hosts_path = folder.join("known_hosts");
    store.save(&state).expect("durable save");
    assert_eq!(
        store
            .read("id")
            .expect("read")
            .expect("present")
            .runtime_identity,
        state.runtime_identity
    );
    assert_eq!(
        std::fs::metadata(folder.join("metadata.json"))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o077,
        0
    );
    for file in [
        "client_key",
        "client_key.pub",
        "host_key",
        "host_key.pub",
        "known_hosts",
    ] {
        std::fs::write(folder.join(file), "fixture").expect("fixture SSH material");
    }
    store.erase("id").expect("delete retained state");
    assert!(!folder.exists());
}
#[test]
fn retained_metadata_and_locks_cannot_follow_symlinks() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().expect("state");
    let path = temp.path().canonicalize().expect("canonical");
    let store = store::Store::new(&path).expect("store");
    let folder = store.folder("id").expect("folder");
    let outside = path.join("outside");
    std::fs::write(&outside, b"canary").expect("canary");
    symlink(&outside, folder.join("metadata.json")).expect("metadata link");
    assert!(store.read("id").is_err());
    let lock = path.join(format!("{}.lock", policy::resource_id("id").expect("name")));
    symlink(&outside, lock).expect("lock link");
    assert!(store.lock("id").is_err());
    assert_eq!(std::fs::read(&outside).expect("canary"), b"canary");
}
#[tokio::test]
async fn prelaunch_rejects_additive_egress_before_any_pod_creation() {
    use std::os::unix::fs::PermissionsExt as _;
    let temp = tempfile::tempdir().expect("fixture");
    let root = temp.path().canonicalize().expect("canonical");
    let program = root.join("kubectl");
    let applied = root.join("applied.jsonl");
    let source = format!(
        r#"#!/bin/sh
case "$*" in
  *"get namespace sandbox-1h31c "*) printf '%s' '{{"metadata":{{"labels":{{"platform.tryhamster.dev/tenant":"1h31c","platform.tryhamster.dev/role":"sandbox"}}}}}}' ;;
  *"get networkpolicies "*) printf '%s' '{{"items":[{{"spec":{{"podSelector":{{}},"policyTypes":["Egress"],"egress":[{{}}]}}}}]}}' ;;
  *"apply "*) cat >> '{}' ;;
  *) exit 0 ;;
esac
"#,
        applied.display()
    );
    std::fs::write(&program, source).expect("mock client");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).expect("executable");
    let client = client::Client {
        context: None,
        program,
    };
    let store = store::Store::new(&root.join("state")).expect("state");
    let folder = store.folder("id").expect("folder");
    let nonce = uuid::Uuid::new_v4().to_string();
    let image = image();
    let network = network();
    let error = lifecycle::create(
        &client,
        &store,
        &folder,
        &lifecycle::Launch {
            sandbox: "id",
            workspace: "1h31c",
            image: &image,
            nonce: &nonce,
            storage_class: "standard-rwo",
            network: &network,
            resource_shape: None,
            lifetime_secs: 3600,
        },
    )
    .await
    .expect_err("reject additive egress");
    assert!(error.to_string().contains("egress"), "{error:#}");
    let applied = std::fs::read_to_string(&applied).expect("applied control objects");
    assert!(applied.contains("PersistentVolumeClaim"));
    assert!(
        !applied.contains("\"kind\":\"Pod\""),
        "guest started before network gate"
    );
    let retained = store.read("id").expect("read").expect("retained");
    assert_eq!(retained.launch_nonce.as_deref(), Some(nonce.as_str()));
}
#[tokio::test]
async fn wrong_nonce_abort_has_no_kubernetes_or_storage_effect() {
    let temp = tempfile::tempdir().expect("fixture");
    let root = temp.path().canonicalize().expect("canonical");
    let store = store::Store::new(&root).expect("store");
    let folder = store.folder("id").expect("folder");
    let mut state = state();
    state.private_key_path = folder.join("client_key");
    state.known_hosts_path = folder.join("known_hosts");
    state.launch_nonce = Some(uuid::Uuid::new_v4().to_string());
    store.save(&state).expect("save");
    let client = client::Client {
        context: None,
        program: root.join("must-not-execute"),
    };
    lifecycle::abort(&client, &store, &state, &uuid::Uuid::new_v4().to_string())
        .await
        .expect("no-op");
    assert!(store.read("id").expect("read").is_some());
}

struct ClusterFixture {
    _temporary: tempfile::TempDir,
    root: std::path::PathBuf,
    client: client::Client,
    store: store::Store,
}
impl ClusterFixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let temporary = tempfile::tempdir().expect("cluster fixture");
        let root = temporary.path().canonicalize().expect("canonical");
        let client = client::Client {
            context: None,
            program: root.join("kubectl"),
        };
        let source = format!(
            r#"#!/bin/sh
set -eu
root='{}'
case "$*" in
  *"get namespace "*) cat "$root/namespace.json" ;;
  *"get networkpolicies "*) cat "$root/policies.json" ;;
  *"get runtimeclass "*) cat "$root/runtime.json" ;;
  *"get node "*) cat "$root/node.json" ;;
  *"get pod "*) if test -f "$root/pod.json"; then cat "$root/pod.json"; fi ;;
  *"get pvc "*) if test -f "$root/pvc.json"; then cat "$root/pvc.json"; fi ;;
  *"get secret "*) if test -f "$root/secret.json"; then cat "$root/secret.json"; fi ;;
  *"get networkpolicy "*) if test -f "$root/networkpolicy.json"; then cat "$root/networkpolicy.json"; fi ;;
  *"delete pod "*) rm -f "$root/pod.json" ;;
  *"delete pvc "*) rm -f "$root/pvc.json" ;;
  *"delete secret "*) rm -f "$root/secret.json" ;;
  *"delete networkpolicy "*) rm -f "$root/networkpolicy.json" ;;
  *"apply "*)
    cat > "$root/request.json"
    if grep -q '"kind":"Pod"' "$root/request.json"; then
      annotations=$(sed -n 's/.*"annotations":\({{[^}}]*}}\).*/\1/p' "$root/request.json")
      sed "s|\"annotations\":{{[^}}]*}}|\"annotations\":$annotations|" "$root/ready-pod.json" > "$root/pod.json"
    elif grep -q '"kind":"PersistentVolumeClaim"' "$root/request.json"; then
      cp "$root/request.json" "$root/pvc.json"
    elif grep -q '"kind":"Secret"' "$root/request.json"; then
      cp "$root/request.json" "$root/secret.json"
    elif grep -q '"kind":"NetworkPolicy"' "$root/request.json"; then
      cp "$root/request.json" "$root/networkpolicy.json"
    else exit 1; fi ;;
  *) exit 1 ;;
esac
"#,
            root.display()
        );
        std::fs::write(&client.program, source).expect("mock kubectl");
        std::fs::set_permissions(&client.program, std::fs::Permissions::from_mode(0o700))
            .expect("executable");
        let state = state();
        let observed = observations(&state);
        for (name, value) in [
            (
                "namespace",
                json!({"metadata":{"labels":{"platform.tryhamster.dev/tenant":"1h31c","platform.tryhamster.dev/role":"sandbox"}}}),
            ),
            ("policies", json!({"items":observed.policies})),
            ("runtime", observed.runtime),
            ("node", observed.node),
        ] {
            std::fs::write(
                root.join(format!("{name}.json")),
                serde_json::to_vec(&value).expect("json"),
            )
            .expect("fixture resource");
        }
        let store = store::Store::new(&root.join("state")).expect("state");
        Self {
            _temporary: temporary,
            root,
            client,
            store,
        }
    }
    fn ready_pod(&self, nonce: &str) {
        let state = state();
        let mut pod = observations(&state).pod;
        pod["metadata"]["uid"] = json!(uuid::Uuid::new_v4().to_string());
        pod["metadata"]["annotations"] =
            lease::annotations(&state.sandbox_id, nonce, state.expires_at.expect("lease"));
        std::fs::write(
            self.root.join("ready-pod.json"),
            serde_json::to_vec(&pod).expect("pod json"),
        )
        .expect("ready pod");
    }
    async fn launch(&self, nonce: &str) -> serde_json::Value {
        self.ready_pod(nonce);
        let folder = self.store.folder("id").expect("folder");
        let image = image();
        let network = network();
        lifecycle::create(
            &self.client,
            &self.store,
            &folder,
            &lifecycle::Launch {
                sandbox: "id",
                workspace: "1h31c",
                image: &image,
                nonce,
                storage_class: "standard-rwo",
                network: &network,
                resource_shape: None,
                lifetime_secs: 3600,
            },
        )
        .await
        .expect("create")
    }
}
#[tokio::test]
async fn create_retry_recovers_verified_ssh_host_without_rotating_keys() {
    let cluster = ClusterFixture::new();
    let original = cluster.launch(&uuid::Uuid::new_v4().to_string()).await;
    let host_key = cluster.store.key("id", "host_key.pub").expect("host key");
    let mut interrupted = cluster.store.read("id").expect("read").expect("state");
    interrupted.host.clear();
    interrupted.runtime_identity.clear();
    cluster
        .store
        .save(&interrupted)
        .expect("interrupted intent");
    cluster
        .store
        .known_hosts("id", "placeholder", &host_key)
        .expect("initial host key");

    let recovered = cluster.launch(&uuid::Uuid::new_v4().to_string()).await;
    assert_eq!(recovered["runtime_identity"], original["runtime_identity"]);
    assert_eq!(recovered["host"], original["host"]);
    let known = std::fs::read_to_string(
        cluster
            .store
            .folder("id")
            .expect("folder")
            .join("known_hosts"),
    )
    .expect("recovered host key");
    assert_eq!(known.split_whitespace().next(), Some("10.176.0.5"));
    assert_eq!(
        cluster.store.key("id", "host_key.pub").expect("host key"),
        host_key
    );
}

#[tokio::test]
async fn lifecycle_create_verify_stop_restart_delete_retains_only_the_private_volume() {
    let cluster = ClusterFixture::new();
    let first = uuid::Uuid::new_v4().to_string();
    let route = cluster.launch(&first).await;
    assert_eq!(route["host"], "10.176.0.5");
    let state = cluster.store.read("id").expect("state").expect("present");
    let (_, proof) = proof::verify(&cluster.client, &state, "standard-rwo", &network())
        .await
        .expect("live verify");
    assert_eq!(proof["runtime_identity"], route["runtime_identity"]);
    assert!(state.owns_volume_for_launch);
    // Retrying create must preserve the original generation. A duplicate
    // request's compensation cannot delete this already-running sandbox.
    let duplicate = uuid::Uuid::new_v4().to_string();
    cluster.launch(&duplicate).await;
    let retained = cluster.store.read("id").expect("read").expect("retained");
    assert_eq!(retained.launch_nonce.as_deref(), Some(first.as_str()));
    lifecycle::abort(&cluster.client, &cluster.store, &retained, &duplicate)
        .await
        .expect("duplicate no-op");
    assert!(cluster.root.join("pod.json").exists());
    lifecycle::stop(&cluster.client, &cluster.store, &retained, false)
        .await
        .expect("stop");
    assert!(!cluster.root.join("pod.json").exists());
    assert!(cluster.root.join("pvc.json").exists());
    let second = uuid::Uuid::new_v4().to_string();
    let restarted = cluster.launch(&second).await;
    assert_ne!(route["runtime_identity"], restarted["runtime_identity"]);
    let state = cluster.store.read("id").expect("read").expect("retained");
    assert!(!state.owns_volume_for_launch);
    lifecycle::stop(&cluster.client, &cluster.store, &state, true)
        .await
        .expect("delete");
    for name in ["pod", "pvc", "secret", "networkpolicy"] {
        assert!(
            !cluster.root.join(format!("{name}.json")).exists(),
            "{name} survived"
        );
    }
    assert!(
        !cluster
            .store
            .folder("id")
            .expect("new empty directory")
            .join("metadata.json")
            .exists()
    );
}
#[tokio::test]
async fn nonce_bound_abort_removes_new_storage_but_preserves_a_restarted_volume() {
    let cluster = ClusterFixture::new();
    let nonce = uuid::Uuid::new_v4().to_string();
    cluster.launch(&nonce).await;
    let state = cluster.store.read("id").expect("read").expect("state");
    lifecycle::abort(&cluster.client, &cluster.store, &state, &nonce)
        .await
        .expect("new launch abort");
    assert!(!cluster.root.join("pvc.json").exists());
    let nonce = uuid::Uuid::new_v4().to_string();
    cluster.launch(&nonce).await;
    let state = cluster.store.read("id").expect("read").expect("state");
    lifecycle::stop(&cluster.client, &cluster.store, &state, false)
        .await
        .expect("stop");
    let restarted_nonce = uuid::Uuid::new_v4().to_string();
    cluster.launch(&restarted_nonce).await;
    let restarted = cluster.store.read("id").expect("read").expect("state");
    lifecycle::abort(
        &cluster.client,
        &cluster.store,
        &restarted,
        &restarted_nonce,
    )
    .await
    .expect("restart abort");
    assert!(!cluster.root.join("pod.json").exists());
    assert!(cluster.root.join("pvc.json").exists());
    assert!(cluster.store.read("id").expect("read").is_some());
}
#[test]
fn lease_is_original_bounded_and_legacy_restart_fails_closed() {
    assert_eq!(
        lease::expires_at(None, 3600, 1000).expect("new lease"),
        4600
    );
    assert_eq!(
        lease::expires_at(Some(Some(4600)), 3600, 2000).expect("retained lease"),
        4600
    );
    assert!(lease::expires_at(Some(None), 3600, 1000).is_err());
    assert!(lease::expires_at(Some(Some(4600)), 3600, 4600).is_err());
    for lifetime in [0, 1, 59, 86401, u64::MAX] {
        assert!(lease::expires_at(None, lifetime, 1000).is_err());
    }
    assert!(lease::expires_at(None, 3600, u64::MAX).is_err());
}
#[test]
fn lease_deadline_rounds_start_up_and_never_extends_original_expiry() {
    assert_eq!(
        lease::allowed_seconds(200, "1970-01-01T00:01:40Z").expect("whole start"),
        100
    );
    assert_eq!(
        lease::allowed_seconds(200, "1970-01-01T00:01:40.2Z").expect("fraction start"),
        99
    );
    assert!(lease::allowed_seconds(100, "1970-01-01T00:01:40Z").is_err());
    assert!(lease::allowed_seconds(200, "bad date").is_err());
}
#[test]
fn lease_patch_tests_uid_resource_version_and_nonce_and_only_decreases() {
    let nonce = uuid::Uuid::new_v4().to_string();
    let wrong_nonce = uuid::Uuid::new_v4().to_string();
    let pod = json!({"metadata":{"uid":"uid","resourceVersion":"123","annotations":{"openshell-kata.io/launch-nonce":nonce}},
        "spec":{"activeDeadlineSeconds":3600},"status":{"startTime":"1970-01-01T00:01:40Z"}});
    let patch = lease::patch(&pod, &nonce, 200)
        .expect("decrease")
        .expect("patch");
    assert_eq!(
        patch[0],
        json!({"op":"test","path":"/metadata/uid","value":"uid"})
    );
    assert_eq!(
        patch[1],
        json!({"op":"test","path":"/metadata/resourceVersion","value":"123"})
    );
    assert_eq!(
        patch[2],
        json!({"op":"test","path":"/metadata/annotations/openshell-kata.io~1launch-nonce","value":nonce})
    );
    assert_eq!(
        patch[3],
        json!({"op":"replace","path":"/spec/activeDeadlineSeconds","value":100})
    );
    let mut already_shorter = pod.clone();
    already_shorter["spec"]["activeDeadlineSeconds"] = json!(50);
    assert!(
        lease::patch(&already_shorter, &nonce, 200)
            .expect("shorter")
            .is_none()
    );
    assert!(lease::patch(&pod, &wrong_nonce, 200).is_err());
    let mut missing_identity = pod.clone();
    missing_identity["metadata"]["resourceVersion"] = json!(null);
    assert!(lease::patch(&missing_identity, &nonce, 200).is_err());
}
#[tokio::test]
async fn expired_or_legacy_stopped_lease_cannot_restart_and_cleanup_remains_allowed() {
    for expires in [None, Some(lease::now().expect("now") - 1)] {
        let cluster = ClusterFixture::new();
        let nonce = uuid::Uuid::new_v4().to_string();
        cluster.launch(&nonce).await;
        let mut state = cluster.store.read("id").expect("read").expect("state");
        lifecycle::stop(&cluster.client, &cluster.store, &state, false)
            .await
            .expect("stop");
        state.expires_at = expires;
        cluster.store.save(&state).expect("persist old lease");
        let image = image();
        let network = network();
        let folder = cluster.store.folder("id").expect("folder");
        let nonce = uuid::Uuid::new_v4().to_string();
        let error = lifecycle::create(
            &cluster.client,
            &cluster.store,
            &folder,
            &lifecycle::Launch {
                sandbox: "id",
                workspace: "1h31c",
                image: &image,
                nonce: &nonce,
                storage_class: "standard-rwo",
                network: &network,
                resource_shape: None,
                lifetime_secs: 3600,
            },
        )
        .await
        .expect_err("no fresh lease on restart");
        assert!(error.to_string().contains("lease"), "{error:#}");
        assert!(!cluster.root.join("pod.json").exists());
        assert!(cluster.root.join("pvc.json").exists());
        lifecycle::stop(&cluster.client, &cluster.store, &state, true)
            .await
            .expect("explicit cleanup");
        assert!(!cluster.root.join("pvc.json").exists());
    }
}
#[test]
fn live_proof_refuses_deadline_removal_extension_expiry_and_legacy_metadata() {
    let state = state();
    for seconds in [json!(null), json!(0), json!(86400)] {
        let mut observed = observations(&state);
        observed.pod["spec"]["activeDeadlineSeconds"] = seconds;
        assert!(
            proof::validate(
                &state,
                "standard-rwo",
                &observed,
                &network(),
                policy::DEFAULT_CONTROL_NAMESPACE
            )
            .is_err()
        );
    }
    for expires in [None, Some(lease::now().expect("now") - 1)] {
        let mut expired = state.clone();
        expired.expires_at = expires;
        assert!(
            proof::validate(
                &expired,
                "standard-rwo",
                &observations(&state),
                &network(),
                policy::DEFAULT_CONTROL_NAMESPACE
            )
            .is_err()
        );
    }
}

#[test]
fn configured_control_namespace_is_exact_for_isolated_policy_and_proof() {
    let control = "release-39bd86447bde-gateway";
    let policy = manifest::network_policy("id", "sandbox-tenant", control);
    policy::validate_policies(
        std::slice::from_ref(&policy),
        &manifest::labels("id"),
        control,
    )
    .expect("configured operator principal");
    for other in [policy::DEFAULT_CONTROL_NAMESPACE, "release-other-gateway"] {
        assert!(
            policy::validate_policies(
                std::slice::from_ref(&policy),
                &manifest::labels("id"),
                other
            )
            .is_err()
        );
    }
    let mut additional = policy.clone();
    additional["spec"]["ingress"][0]["from"]
        .as_array_mut()
        .expect("sources")
        .push(json!({
            "namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"foreign"}},
            "podSelector":{"matchLabels":{"platform.tryhamster.dev/role":"sandbox-control"}}
        }));
    assert!(policy::validate_policies(&[additional], &manifest::labels("id"), control).is_err());
    let mut wrong_role = policy;
    wrong_role["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"]["platform.tryhamster.dev/role"] =
        json!("other");
    assert!(policy::validate_policies(&[wrong_role], &manifest::labels("id"), control).is_err());
    let state = state();
    let mut observed = observations(&state);
    observed.policies = vec![manifest::network_policy(
        &state.name,
        &state.namespace,
        control,
    )];
    proof::validate(&state, "standard-rwo", &observed, &network(), control)
        .expect("configured revalidation");
    assert!(
        proof::validate(
            &state,
            "standard-rwo",
            &observed,
            &network(),
            policy::DEFAULT_CONTROL_NAMESPACE
        )
        .is_err()
    );
}

#[test]
fn control_namespace_rejects_non_dns_labels() {
    for invalid in [
        "",
        "UPPER",
        "a.b",
        "a_b",
        "-first",
        "last-",
        "é",
        "a/b",
        " ",
        &"a".repeat(64),
    ] {
        assert!(
            policy::validate_control_namespace(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
    for valid in [
        policy::DEFAULT_CONTROL_NAMESPACE,
        "release-39bd86447bde-gateway",
        "a",
        "0",
    ] {
        policy::validate_control_namespace(valid).expect("valid namespace");
    }
}
