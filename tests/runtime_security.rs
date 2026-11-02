use openshell_kata::{
    boundary::process::{OperatorCeilings, VmLimits},
    profile::VmPolicy,
    runtime::{
        lifecycle::{self, Settings},
        model::{Action, Record, Route, validate_supported_profile},
        network::Attachment,
        spec::guest_spec,
        state::StateDirectory,
    },
};
use serde_json::json;
use std::path::PathBuf;

fn policy() -> VmPolicy {
    serde_json::from_value(json!({"version":1,"profile":"docker-vm","resources":{"vcpus":1,"memory_mib":2048,"disk_mib":2048,"lifetime_secs":3600},"filesystem":{"host_mounts":"deny","transfer_max_bytes":268435456,"transfer_max_entries":4096},"network":{"tcp_allow":[]}})).expect("policy fixture")
}
#[test]
fn minimal_guest_spec_exposes_no_host_files_or_devices() {
    let spec = guest_spec("sample", "/run/netns/example", "http://10.205.0.1:38080");
    assert_eq!(spec["linux"]["devices"], json!([]));
    for mount in spec["mounts"].as_array().expect("mounts") {
        assert_ne!(mount["type"], "bind");
        assert!(!mount["source"].as_str().expect("source").starts_with('/'));
    }
    assert_eq!(spec["linux"]["cgroupsPath"], "/openshell-kata/sample/guest");
    assert_eq!(
        spec["linux"]["resources"]["memory"]["limit"],
        2_147_483_648_u64
    );
    assert!(
        spec["linux"]["namespaces"]
            .as_array()
            .expect("namespaces")
            .iter()
            .any(|n| n["path"] == "/run/netns/example")
    );
}
#[test]
fn interface_names_are_bound_to_the_creation_generation() {
    let id = uuid::Uuid::new_v4().to_string();
    let first_nonce = uuid::Uuid::new_v4().to_string();
    let second_nonce = uuid::Uuid::new_v4().to_string();
    let one = Attachment::for_id(&id, &first_nonce, 24);
    let two = Attachment::for_id(&id, &second_nonce, 24);
    assert_ne!(one.netns, two.netns);
    assert_ne!(one.host_veth, two.host_veth);
    assert_eq!(one.owner, first_nonce);
    assert!(one.host_veth.len() <= 15);
    assert!(one.guest_ip.is_private());
    assert_ne!(one.guest_ip, one.gateway_ip);
}
#[test]
fn unsupported_hardware_sizes_are_rejected_not_silently_clamped() {
    let mut p = policy();
    p.resources.vcpus = 2;
    assert!(validate_supported_profile(&p).is_err());
    p.resources.vcpus = 1;
    p.resources.disk_mib = 4096;
    assert!(validate_supported_profile(&p).is_err());
}
fn setup() -> (tempfile::TempDir, StateDirectory, Settings) {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = std::fs::canonicalize(temp.path()).expect("canonical");
    let state = StateDirectory::new(root.join("state")).expect("state");
    let settings = Settings {
        vm: "nonexistent-test-node".into(),
        node_transport: Default::default(),
        resource_profile: Default::default(),
        state_dir: state.root().into(),
        node_binary: PathBuf::from("/does/not/exist"),
        image: None,
        max_sandboxes: None,
    };
    (temp, state, settings)
}
fn record(id: &str, nonce: &str, root: &std::path::Path) -> Record {
    let p = policy();
    let deadline = VmLimits {
        vcpus: 1,
        memory_mib: 2048,
        disk_mib: 2048,
        lifetime_secs: 3600,
    }
    .validate(&OperatorCeilings::default())
    .expect("limits")
    .deadline_from(1)
    .expect("deadline");
    Record {
        creation_nonce: nonce.into(),
        node_boot_id: None,
        image: "docker.io/library/openshell-kata-enforced:local".into(),
        route: Route {
            sandbox_id: id.into(),
            host: "127.0.0.1".into(),
            port: 2222,
            username: "sandbox".into(),
            private_key_path: root.join("client"),
            known_hosts_path: root.join("known"),
        },
        policy: p,
        deadline,
        network: None,
        attachment: Attachment::for_id(id, nonce, 0),
        storage_id: String::new(),
        hypervisor_pid: 0,
        watchdog_pid: 0,
        cgroup_path: String::new(),
    }
}

#[tokio::test]
async fn unusable_socket_path_is_rejected_before_node_operations_or_state_record() {
    let temp = tempfile::tempdir().expect("private fixture");
    let root = std::fs::canonicalize(temp.path())
        .expect("canonical fixture")
        .join("x".repeat(100));
    let settings = Settings {
        vm: "unused-test-node".into(),
        node_transport: Default::default(),
        resource_profile: Default::default(),
        state_dir: root.clone(),
        node_binary: "/unused".into(),
        image: None,
        max_sandboxes: None,
    };
    let id = uuid::Uuid::new_v4().to_string();
    let policy_file = temp.path().join("policy.json");
    std::fs::write(
        &policy_file,
        serde_json::to_vec(&policy()).expect("policy JSON"),
    )
    .expect("operator policy");
    let nonce = uuid::Uuid::new_v4().to_string();
    let error = lifecycle::execute(
        &settings,
        Action::Create,
        &id,
        Some(&policy_file),
        Some(&nonce),
    )
    .await
    .expect_err("unusable operator state path");
    assert!(
        error
            .to_string()
            .contains("too long for an SSH control socket"),
        "path preflight must precede node operations: {error:#}"
    );
    assert!(!root.join(&id).exists(), "no guest intent may be created");
}

#[tokio::test]
async fn missing_tunnel_cleanup_remains_available_for_an_overlong_state_path() {
    let temp = tempfile::tempdir().expect("private fixture");
    let root = std::fs::canonicalize(temp.path())
        .expect("canonical fixture")
        .join("x".repeat(100));
    let state = StateDirectory::new(root).expect("owned state");
    let id = uuid::Uuid::new_v4().to_string();
    assert!(state.control_path(&id).is_err());
    let node =
        openshell_kata::runtime::command::Node::new("unused-test-node").expect("node identity");
    openshell_kata::runtime::transport::close_tunnel(&node, &state, &id)
        .await
        .expect("absent tunnel must not block cleanup of node resources");
}
#[tokio::test]
async fn mismatched_abort_never_deletes_an_existing_generation() {
    let (_temp, state, settings) = setup();
    let id = uuid::Uuid::new_v4().to_string();
    let original_nonce = uuid::Uuid::new_v4().to_string();
    let other_nonce = uuid::Uuid::new_v4().to_string();
    state.create(&id).expect("create");
    state
        .write(&id, &record(&id, &original_nonce, state.root()))
        .expect("write");
    let output = lifecycle::execute(&settings, Action::Abort, &id, None, Some(&other_nonce))
        .await
        .expect("no-op");
    assert_eq!(output, json!({}));
    assert!(state.path(&id).expect("path").exists());
    let kept: Record = state.read(&id).expect("original remains");
    assert_eq!(kept.creation_nonce, original_nonce);
}
#[tokio::test]
async fn abort_missing_state_is_a_noop_without_node_access() {
    let (_temp, _state, settings) = setup();
    let id = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        lifecycle::execute(&settings, Action::Abort, &id, None, Some(&nonce))
            .await
            .expect("no-op"),
        json!({})
    );
}
#[tokio::test]
async fn preexisting_state_refuses_create_before_contacting_the_node() {
    let (temp, state, settings) = setup();
    let id = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    state.create(&id).expect("create");
    let path = temp.path().join("policy.json");
    std::fs::write(&path, serde_json::to_vec(&policy()).expect("policy bytes")).expect("write");
    let error = lifecycle::execute(&settings, Action::Create, &id, Some(&path), Some(&nonce))
        .await
        .expect_err("reject");
    assert!(error.to_string().contains("already exists"), "{error}");
    assert!(state.path(&id).expect("path").exists());
}
#[tokio::test]
async fn invalid_nonce_refuses_create_before_policy_or_node_access() {
    let (_temp, _state, settings) = setup();
    let id = uuid::Uuid::new_v4().to_string();
    let invalid_nonce = uuid::Uuid::new_v4()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>();
    let error = lifecycle::execute(&settings, Action::Create, &id, None, Some(&invalid_nonce))
        .await
        .expect_err("reject");
    assert!(error.to_string().contains("nonce"));
}

#[test]
fn restart_removes_only_known_kata_taps_and_refuses_unknown_links() {
    use openshell_kata::runtime::network::stale_taps;
    let links = json!([{"ifname":"lo"},{"ifname":"eth0"},{"ifname":"tap0_kata","linkinfo":{"info_kind":"tun","info_data":{"type":"tap"}}}]);
    assert_eq!(stale_taps(&links).expect("known tap"), vec!["tap0_kata"]);
    assert!(stale_taps(&json!([{"ifname":"foreign"}])).is_err());
    assert!(stale_taps(&json!([{"ifname":"tap0_kata","linkinfo":{"info_kind":"veth"}}])).is_err());
}

#[test]
fn shim_reaping_requires_exact_id_and_containerd_namespace_tokens() {
    use openshell_kata::runtime::containerd::owned_shim_arguments;
    assert!(owned_shim_arguments(
        b"shim\0-namespace\0default\0-id\0one\0",
        "one"
    ));
    assert!(!owned_shim_arguments(
        b"shim\0-namespace\0default\0-id\0one-extra\0",
        "one"
    ));
    assert!(!owned_shim_arguments(
        b"shim\0-namespace\0other\0-id\0one\0",
        "one"
    ));
    assert!(!owned_shim_arguments(
        b"shim -namespace default -id one",
        "one"
    ));
}

#[test]
fn shim_socket_uses_pinned_kata_address_hash_and_rejects_paths() {
    use openshell_kata::runtime::containerd::shim_socket;
    assert_eq!(
        shim_socket("9f5dc553-9559-4ef7-b6b0-eac7a4e63200")
            .expect("known ID")
            .to_str(),
        Some("/run/containerd/s/4619A0CC99A2AB91E212F74127CC7AE9AF3D08D00864B44DFFF1AB5FCCD5F059")
    );
    assert!(shim_socket("../other").is_err());
}

#[test]
fn foundry_profile_is_explicit_and_drives_exact_guest_resources() {
    use openshell_kata::runtime::model::ResourceProfile;
    use openshell_kata::runtime::spec::guest_spec_for;
    let mut p = policy();
    p.resources.vcpus = 32;
    p.resources.memory_mib = 131072;
    p.resources.disk_mib = 262144;
    assert!(ResourceProfile::Local.validate(&p).is_err());
    ResourceProfile::FoundryBuild
        .validate(&p)
        .expect("explicit build profile");
    let spec = guest_spec_for(
        "sample",
        "/run/netns/sample",
        "http://10.205.0.1:38080",
        &p.resources,
    );
    assert_eq!(
        spec["linux"]["resources"]["memory"]["limit"],
        137438953472u64
    );
    assert_eq!(spec["linux"]["resources"]["cpu"]["quota"], 3200000);
    assert_eq!(
        spec["annotations"]["io.katacontainers.config.hypervisor.default_vcpus"],
        "32"
    );
    p.resources.disk_mib += 1;
    assert!(ResourceProfile::FoundryBuild.validate(&p).is_err());
}

fn foundry_policy(temp: &tempfile::TempDir) -> PathBuf {
    let mut p = policy();
    p.resources.vcpus = 32;
    p.resources.memory_mib = 131072;
    p.resources.disk_mib = 262144;
    let path = temp.path().join("policy.json");
    std::fs::write(&path, serde_json::to_vec(&p).expect("policy bytes")).expect("write");
    path
}

#[tokio::test]
async fn foundry_inventory_limit_rejects_a_disk_at_capacity_before_node_access() {
    let (temp, state, mut settings) = setup();
    settings.resource_profile = openshell_kata::runtime::model::ResourceProfile::FoundryBuild;
    settings.max_sandboxes = Some(3);
    for id in ["one", "two", "three"] {
        state.create(id).expect("retained guest");
    }
    let path = foundry_policy(&temp);
    let error = lifecycle::execute(
        &settings,
        Action::Create,
        "four",
        Some(&path),
        Some("creation-nonce-0123456789"),
    )
    .await
    .expect_err("bounded retained inventory");
    assert!(error.to_string().contains("capacity of 3"), "{error:#}");
}

#[tokio::test]
async fn foundry_inventory_below_capacity_passes_the_limit_check() {
    let (temp, state, mut settings) = setup();
    settings.resource_profile = openshell_kata::runtime::model::ResourceProfile::FoundryBuild;
    settings.max_sandboxes = Some(3);
    for id in ["one", "two"] {
        state.create(id).expect("retained guest");
    }
    let path = foundry_policy(&temp);
    let error = lifecycle::execute(
        &settings,
        Action::Create,
        "three",
        Some(&path),
        Some("creation-nonce-0123456789"),
    )
    .await
    .expect_err("the fixture node is unreachable");
    let message = format!("{error:#}");
    assert!(
        !message.contains("capacity") && message.contains("immutable operator image"),
        "{message}"
    );
}

#[tokio::test]
async fn foundry_requires_an_explicit_node_capacity() {
    let (temp, _state, mut settings) = setup();
    settings.resource_profile = openshell_kata::runtime::model::ResourceProfile::FoundryBuild;
    let path = foundry_policy(&temp);
    let error = lifecycle::execute(
        &settings,
        Action::Create,
        "one",
        Some(&path),
        Some("creation-nonce-0123456789"),
    )
    .await
    .expect_err("capacity is mandatory");
    assert!(error.to_string().contains("node capacity"), "{error:#}");
}
