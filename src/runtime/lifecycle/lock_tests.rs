use super::*;
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Instant};

fn settings(state: &StateDirectory) -> Settings {
    Settings {
        vm: "native".into(),
        node_transport: NodeTransport::LinuxLocal,
        resource_profile: model::ResourceProfile::Local,
        state_dir: state.root().to_owned(),
        node_binary: "/opt/openshell-kata/kata-runtime".into(),
        image: None,
        max_sandboxes: Some(48),
    }
}

fn state() -> (tempfile::TempDir, StateDirectory) {
    let files = tempfile::tempdir().expect("fixture directory");
    let root = files.path().canonicalize().expect("canonical root");
    let state = StateDirectory::new(root.join("state")).expect("private state");
    (files, state)
}

async fn hold(root: &Path, name: String, work: Duration) {
    let _lock = LifecycleLock::acquire(root.join(name)).await.expect("lock");
    tokio::time::sleep(work).await;
}

#[tokio::test]
async fn distinct_sandboxes_run_in_parallel_and_one_sandbox_stays_ordered() {
    let (_files, state) = state();
    let root = Arc::new(state.root().to_owned());
    let work = Duration::from_millis(200);
    let started = Instant::now();
    let tasks: Vec<_> = (0..10)
        .map(|index| {
            let root = root.clone();
            tokio::spawn(async move { hold(&root, format!(".lock-guest-{index}"), work).await })
        })
        .collect();
    for task in tasks {
        task.await.expect("distinct sandbox");
    }
    assert!(
        started.elapsed() < work * 4,
        "ten distinct sandboxes must not serialize: {:?}",
        started.elapsed()
    );
    let started = Instant::now();
    let tasks: Vec<_> = (0..3)
        .map(|_| {
            let root = root.clone();
            tokio::spawn(async move { hold(&root, ".lock-guest-0".into(), work).await })
        })
        .collect();
    for task in tasks {
        task.await.expect("same sandbox");
    }
    assert!(
        started.elapsed() >= work * 3,
        "operations on one sandbox stay ordered"
    );
}

#[tokio::test]
async fn retired_lock_is_reopened_by_waiters_and_still_excludes() {
    let (_files, state) = state();
    let path = state.root().join(".lock-guest");
    let first = LifecycleLock::acquire(path.clone()).await.expect("first");
    let waiter = tokio::spawn({
        let path = path.clone();
        async move { LifecycleLock::acquire(path).await.expect("waiter") }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    first.retire().expect("retire");
    let second = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("waiter re-opens a retired lock")
        .expect("waiter task");
    let third = tokio::spawn({
        let path = path.clone();
        async move { LifecycleLock::acquire(path).await.expect("third") }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!third.is_finished(), "the re-opened lock still excludes");
    drop(second);
    tokio::time::timeout(Duration::from_secs(5), third)
        .await
        .expect("released")
        .expect("third task");
}

#[tokio::test]
async fn a_create_reservation_never_blocks_another_sandboxes_revalidation() {
    let (_files, state) = state();
    let settings = settings(&state);
    // A create holding the node reservation, as during a burst.
    let _reservation = LifecycleLock::acquire(state.root().join(".lock"))
        .await
        .expect("node reservation");
    let verify = tokio::time::timeout(
        Duration::from_secs(5),
        execute(&settings, Action::Verify, "running", None, None),
    )
    .await
    .expect("revalidation must not queue behind a node reservation");
    assert!(verify.is_err(), "absent fixture state is still refused");
    // The same sandbox remains ordered behind its own in-flight operation.
    let _busy = LifecycleLock::acquire(state.root().join(".lock-running"))
        .await
        .expect("sandbox lock");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            execute(&settings, Action::Verify, "running", None, None),
        )
        .await
        .is_err(),
        "one sandbox's operations stay serialized"
    );
}

#[tokio::test]
async fn reservations_exclude_retained_addresses_and_ports_from_new_plans() {
    let (files, state) = state();
    let creation = "creation-nonce-0123456789";
    state.create("stopped").expect("retained guest");
    let digest = Sha256::digest(b"new");
    let seed = u16::from_be_bytes([digest[0], digest[1]]) % 16384;
    let held = network::Attachment::for_id("new", creation, seed);
    let record: Record = serde_json::from_value(json!({
        "creation_nonce": creation,
        "image": "registry.example/guest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "route": {"sandbox_id":"stopped","host":"127.0.0.1","port":40001,"username":"sandbox",
                  "private_key_path":"/k","known_hosts_path":"/h"},
        "policy": {"version":1,"profile":"docker-vm","resources":{"vcpus":1,"memory_mib":2048,"disk_mib":2048,"lifetime_secs":3600},"filesystem":{"host_mounts":"deny","transfer_max_bytes":268435456,"transfer_max_entries":4096},"network":{"tcp_allow":[]}},
        "deadline": {"started_at_unix_secs":1,"expires_at_unix_secs":4000000000_u64},
        "network": null,
        "attachment": held,
        "storage_id": "", "hypervisor_pid": 0, "watchdog_pid": 0, "cgroup_path": ""
    }))
    .expect("record");
    state.write("stopped", &record).expect("record written");
    state.create("unwritten").expect("crashed create");
    let (addresses, ports) = reservations(&state).expect("reservations");
    assert_eq!(addresses, vec![held.gateway_ip]);
    assert_eq!(ports, vec![40001]);
    assert_ne!(unreserved_port(&ports).expect("port"), 40001);
    // The node shows no links: the stopped guest's address is reserved only by its record.
    let runner = files.path().join("node.sh");
    std::fs::write(&runner, "#!/bin/sh\necho '[]'\n").expect("runner");
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let node = Node::with_transport("native", NodeTransport::LinuxLocal)
        .expect("node")
        .test_runner(runner);
    let unrestricted = network::plan_attachment(&node, "new", creation, &[])
        .await
        .expect("plan");
    assert_eq!(unrestricted.gateway_ip, held.gateway_ip);
    let planned = network::plan_attachment(&node, "new", creation, &addresses)
        .await
        .expect("plan");
    assert_ne!(planned.gateway_ip, held.gateway_ip);
}

fn plain_record(id: &str, nonce: &str, reserved: Reserved) -> Record {
    serde_json::from_value(json!({
        "creation_nonce": nonce,
        "image": "registry.example/guest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "route": {"sandbox_id":id,"host":"127.0.0.1","port":reserved.port,"username":"sandbox",
                  "private_key_path":reserved.directory.join("client_key"),"known_hosts_path":reserved.directory.join("known_hosts")},
        "policy": {"version":1,"profile":"docker-vm","resources":{"vcpus":1,"memory_mib":2048,"disk_mib":2048,"lifetime_secs":3600},"filesystem":{"host_mounts":"deny","transfer_max_bytes":268435456,"transfer_max_entries":4096},"network":{"tcp_allow":[]}},
        "deadline": {"started_at_unix_secs":1,"expires_at_unix_secs":4000000000_u64},
        "network": null,
        "attachment": reserved.attachment,
        "storage_id": "", "hypervisor_pid": 0, "watchdog_pid": 0, "cgroup_path": ""
    }))
    .expect("record")
}

#[tokio::test]
async fn concurrent_creates_reserve_unique_node_resources_through_the_real_plan() {
    let (files, state) = state();
    let runner = files.path().join("node.py");
    std::fs::write(&runner, include_str!("fake_ip_node.py")).expect("fake node");
    std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o700)).expect("mode");
    // Same creation nonce everywhere and colliding address seeds stress the plan.
    let nonce = "creation-nonce-0123456789";
    let root = state.root().to_owned();
    // Another lifecycle process's transient ownership probe, seen mid-inventory.
    std::fs::write(root.join(".tmpProbe1"), b"").expect("concurrent probe");
    let creates: Vec<_> = (0..12)
        .map(|index| {
            let root = root.clone();
            let runner = runner.clone();
            tokio::spawn(async move {
                // Each create is its own process: its own state handle and ownership probe.
                let state = StateDirectory::new(&root)?;
                let node =
                    Node::with_transport("native", NodeTransport::LinuxLocal)?.test_runner(runner);
                let id = format!("burst-{index}");
                let record = reserve_create(
                    &node,
                    &state,
                    &id,
                    nonce,
                    || Ok(()),
                    |reserved| plain_record(&id, nonce, reserved),
                )
                .await?;
                let fence =
                    network::create_attachment(&node, &id, nonce, &record.attachment).await?;
                anyhow::Ok((record, fence))
            })
        })
        .collect();
    let mut created = Vec::new();
    for create in creates {
        created.push(
            create
                .await
                .expect("task")
                .expect("no spurious create failure"),
        );
    }
    let unique = |values: Vec<String>| {
        let count = values.len();
        let set: std::collections::BTreeSet<_> = values.into_iter().collect();
        set.len() == count
    };
    assert!(unique(
        created
            .iter()
            .map(|(r, _)| r.attachment.host_veth.clone())
            .collect()
    ));
    assert!(unique(
        created.iter().map(|(r, _)| r.attachment.peer()).collect()
    ));
    assert!(unique(
        created
            .iter()
            .map(|(r, _)| r.attachment.netns.clone())
            .collect()
    ));
    assert!(unique(
        created
            .iter()
            .map(|(r, _)| r.attachment.gateway_ip.to_string())
            .collect()
    ));
    assert!(unique(
        created
            .iter()
            .map(|(r, _)| r.route.port.to_string())
            .collect()
    ));
    assert!(unique(
        created.iter().map(|(_, f)| f.ifindex.to_string()).collect()
    ));
    let retained = state.retained_ids().expect("consistent inventory");
    assert_eq!(retained.len(), 12);
}
