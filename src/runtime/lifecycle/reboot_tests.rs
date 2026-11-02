use super::*;
use std::os::unix::fs::PermissionsExt;

fn fixture() -> (
    tempfile::TempDir,
    StateDirectory,
    Settings,
    Node,
    Record,
    PathBuf,
) {
    let files = tempfile::tempdir().expect("fixture directory");
    let root = files.path().canonicalize().expect("canonical fixture root");
    let state = StateDirectory::new(root.join("state")).expect("private state");
    state.create("one").expect("retained guest");
    let runner = root.join("node.py");
    std::fs::write(&runner, include_str!("node_fixture.py")).expect("fixture program");
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o700))
        .expect("private executable");
    let image = "registry.example/guest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let creation = "creation-nonce-0123456789";
    let native = json!({"Labels":{"openshell-kata.creation-nonce":creation},"Runtime":{"Name":"io.containerd.kata.v2"},"Image":image,"SnapshotKey":"retained-snapshot"});
    let document = runner.with_extension("json");
    std::fs::write(&document, serde_json::to_vec(&json!({"boot":"544f3954-0589-46a1-aa22-eb40ea010b21", "native":native,"running":false,"namespace":false,"link":false})).expect("fixture JSON")).expect("fixture state");
    let policy: VmPolicy = serde_json::from_value(json!({"version":1,"profile":"docker-vm","resources":{"vcpus":32,"memory_mib":131072,"disk_mib":262144,"lifetime_secs":3600},"filesystem":{"host_mounts":"deny","transfer_max_bytes":268435456,"transfer_max_entries":4096},"network":{"tcp_allow":[]}})).expect("policy");
    let record = Record {
        creation_nonce: creation.to_owned(),
        node_boot_id: Some("d145e083-ef26-4fe8-bbf4-d5ef104287ee".to_owned()),
        image: image.to_owned(),
        attachment: network::Attachment::for_id("one", creation, 42),
        route: Route {
            sandbox_id: "one".into(),
            host: "127.0.0.1".into(),
            port: 2222,
            username: "sandbox".into(),
            private_key_path: root.join("client"),
            known_hosts_path: root.join("hosts"),
        },
        deadline: policy
            .resources
            .validate(&OperatorCeilings::default())
            .expect("limits")
            .deadline_from(100)
            .expect("deadline"),
        policy,
        network: None,
        storage_id: "retained-snapshot".into(),
        hypervisor_pid: 44,
        watchdog_pid: 45,
        cgroup_path: "/sys/fs/cgroup/openshell-kata/one".into(),
    };
    let settings = Settings {
        vm: "native".into(),
        node_transport: NodeTransport::LinuxLocal,
        resource_profile: model::ResourceProfile::FoundryBuild,
        state_dir: state.root().to_owned(),
        node_binary: "/opt/openshell-kata/kata-runtime".into(),
        image: Some(image.into()),
        max_sandboxes: Some(48),
    };
    let node = Node::with_transport("native", NodeTransport::LinuxLocal)
        .expect("native node")
        .test_runner(runner);
    (files, state, settings, node, record, document)
}

#[tokio::test]
async fn new_node_boot_restores_only_stopped_storage_and_refreshes_network_identity() {
    let (_files, state, settings, node, record, document) = fixture();
    let restored = recover_boot_network(&node, &state, &settings, "one", &record)
        .await
        .expect("reconstruct stopped attachment");
    assert_ne!(restored.node_boot_id, record.node_boot_id);
    assert_eq!(restored.storage_id, record.storage_id);
    assert_eq!(restored.creation_nonce, record.creation_nonce);
    assert_eq!(
        restored.deadline.expires_at_unix_secs(),
        record.deadline.expires_at_unix_secs()
    );
    assert_eq!(restored.network.as_ref().expect("fresh proof").ifindex, 321);
    assert_eq!(restored.hypervisor_pid, 0);
    let saved: Record = state.read("one").expect("persisted reboot identity");
    assert_eq!(saved.node_boot_id, restored.node_boot_id);
    let observed: Value =
        serde_json::from_slice(&std::fs::read(&document).expect("fixture state")).expect("JSON");
    assert_eq!(observed["last_link_action"], "down");
    assert_eq!(observed["installed_spec"]["ifindex"], 321);
    let before = observed["calls"].as_array().expect("calls").len();
    recover_boot_network(&node, &state, &settings, "one", &restored)
        .await
        .expect("same boot no-op");
    let after: Value =
        serde_json::from_slice(&std::fs::read(&document).expect("fixture state")).expect("JSON");
    assert_eq!(
        after["calls"].as_array().expect("calls").len(),
        before + 1,
        "same boot only rereads boot ID"
    );
}

#[tokio::test]
async fn reboot_reconstruction_rejects_running_replaced_or_partially_present_objects() {
    for mutation in [
        json!({"running":true}),
        json!({"namespace":true}),
        json!({"namespace":true,"link":true}),
        json!({"native":{"Labels":{"openshell-kata.creation-nonce":"foreign"}}}),
    ] {
        let (_files, state, settings, node, record, document) = fixture();
        let mut fixture: Value =
            serde_json::from_slice(&std::fs::read(&document).expect("fixture state"))
                .expect("JSON");
        for (key, value) in mutation.as_object().expect("mutation") {
            fixture[key] = value.clone();
        }
        std::fs::write(
            &document,
            serde_json::to_vec(&fixture).expect("fixture JSON"),
        )
        .expect("write fixture");
        assert!(
            recover_boot_network(&node, &state, &settings, "one", &record)
                .await
                .is_err(),
            "unsafe boot mutation {mutation}"
        );
        let observed: Value =
            serde_json::from_slice(&std::fs::read(&document).expect("fixture state"))
                .expect("JSON");
        assert!(
            observed.get("installed_spec").is_none(),
            "no network publication after failed boundary"
        );
    }
}
