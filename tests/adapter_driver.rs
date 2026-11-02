use openshell_kata::{
    config::Config,
    driver::Driver,
    proto::openshell::compute::v1::{self as c, compute_driver_server::ComputeDriver},
};
use std::{os::unix::fs::PermissionsExt, sync::Arc};
use tokio_stream::StreamExt;
use tonic::{Code, Request};

fn config(root: &std::path::Path) -> Arc<Config> {
    Arc::new(Config {
        socket: root.join("driver.sock"),
        gateway: "https://127.0.0.1:1".into(),
        gateway_ca: root.join("missing-ca"),
        lifecycle: root.join("lifecycle"),
        lifecycle_arg: vec![],
        ssh: "/usr/bin/ssh".into(),
        prototype_policy_mode: true,
        vm_policy: None,
        runtime_profile: openshell_kata::config::RuntimeProfile::Local,
        guest_image: None,
        guest_network_cidr: None,
        additional_guest_images: Vec::new(),
        recovery_dir: None,
        hosted_network_config: None,
        max_sandboxes: None,
    })
}
fn sandbox(authentication: Vec<u8>) -> c::DriverSandbox {
    c::DriverSandbox {
        id: "test-sandbox".into(),
        name: "test-name".into(),
        spec: Some(c::DriverSandboxSpec {
            template: Some(c::DriverSandboxTemplate {
                image: "docker:29-dind".into(),
                ..Default::default()
            }),
            command: vec!["sleep".into(), "60".into()],
            launch_authentication: authentication,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn invalid_launch_authentication_never_calls_lifecycle() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let driver = Driver::new(config(root.path())).expect("valid test configuration");
    let error = driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(sandbox(b"{}".to_vec())),
        }))
        .await
        .expect_err("invalid auth rejected");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(
        driver
            .list_sandboxes(Request::new(c::ListSandboxesRequest {}))
            .await?
            .into_inner()
            .sandboxes
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn deletion_failure_keeps_record_for_retry() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let key = root.path().join("host-key");
    let status = std::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()?;
    anyhow::ensure!(status.success(), "fixture key generation failed");
    let metadata=serde_json::json!({"sandbox_id":"test-sandbox","host":"127.0.0.1","port":12345,"username":"sandbox","private_key_path":key,"known_hosts_path":root.path().join("known-hosts")}).to_string();
    let marker = root.path().join("failed-once");
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\ncreate) printf '%s' '{}' ;;\ndelete) if [ ! -f '{}' ]; then touch '{}'; exit 1; fi ;;\nesac\n",
        metadata,
        marker.display(),
        marker.display()
    );
    std::fs::write(root.path().join("lifecycle"), script)?;
    std::fs::set_permissions(
        root.path().join("lifecycle"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    let auth = serde_json::to_vec(
        &serde_json::json!({"supervisor":{"gateway_token":"test-placeholder","ssh_host_private_key":std::fs::read_to_string(&key)?}}),
    )?;
    let driver = Driver::new(config(root.path())).expect("valid test configuration");
    driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(sandbox(auth)),
        }))
        .await?;
    let mut watch = driver
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest::default()))
        .await?
        .into_inner();
    let first_snapshot = tokio::time::timeout(std::time::Duration::from_secs(2), watch.next())
        .await?
        .expect("initial event")?;
    assert!(matches!(
        first_snapshot.payload,
        Some(c::watch_sandboxes_event::Payload::Sandbox(_))
    ));
    let first = driver
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "test-sandbox".into(),
            ..Default::default()
        }))
        .await;
    assert!(first.is_err());
    // Observations are coalesced. A failed deletion may leave the same Failed
    // state, so no duplicate event is required; any event must retain the sandbox.
    if let Ok(Some(after_failure)) =
        tokio::time::timeout(std::time::Duration::from_millis(400), watch.next()).await
    {
        assert!(
            matches!(
                after_failure?.payload,
                Some(c::watch_sandboxes_event::Payload::Sandbox(_))
            ),
            "failed deletion must not emit a tombstone"
        );
    }
    assert!(
        driver
            .get_sandbox(Request::new(c::GetSandboxRequest {
                sandbox_id: "test-sandbox".into(),
                ..Default::default()
            }))
            .await
            .is_ok()
    );
    assert!(
        driver
            .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                sandbox_id: "test-sandbox".into(),
                ..Default::default()
            }))
            .await?
            .into_inner()
            .deleted
    );
    assert_eq!(
        driver
            .get_sandbox(Request::new(c::GetSandboxRequest {
                sandbox_id: "test-sandbox".into(),
                ..Default::default()
            }))
            .await
            .expect_err("deleted")
            .code(),
        Code::NotFound
    );
    let deleted = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let event = watch.next().await.expect("live watch")?;
            if let Some(c::watch_sandboxes_event::Payload::Deleted(event)) = event.payload {
                break Ok::<_, tonic::Status>(event);
            }
        }
    })
    .await??;
    assert_eq!(deleted.sandbox_id, "test-sandbox");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(700), watch.next())
            .await
            .is_err(),
        "a watcher must receive each retained deletion only once"
    );
    let mut reconnect = driver
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest::default()))
        .await?
        .into_inner();
    let replay = tokio::time::timeout(std::time::Duration::from_secs(2), reconnect.next())
        .await?
        .expect("retained tombstone")?;
    assert!(
        matches!(
            replay.payload,
            Some(c::watch_sandboxes_event::Payload::Deleted(_))
        ),
        "a reconnected watcher must recover missed deletion"
    );
    let restarted = Driver::new(config(root.path())).expect("valid test configuration");
    assert!(
        !restarted
            .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                sandbox_id: "test-sandbox".into(),
                ..Default::default()
            }))
            .await?
            .into_inner()
            .deleted
    );
    let mut after_restart = restarted
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest::default()))
        .await?
        .into_inner();
    let confirmed_absent =
        tokio::time::timeout(std::time::Duration::from_secs(2), after_restart.next())
            .await?
            .expect("confirmed absence tombstone")?;
    assert!(matches!(
        confirmed_absent.payload,
        Some(c::watch_sandboxes_event::Payload::Deleted(_))
    ));
    Ok(())
}

#[tokio::test]
async fn unsupported_contract_major_is_rejected() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let driver = Driver::new(config(root.path())).expect("valid test configuration");
    let request = c::GetCapabilitiesRequest {
        gateway: Some(
            openshell_kata::proto::openshell::extension::v1::PeerMetadata {
                protocol_version: Some(
                    openshell_kata::proto::openshell::extension::v1::ProtocolVersion {
                        major: 99,
                        minor: 0,
                    },
                ),
                ..Default::default()
            },
        ),
    };
    assert_eq!(
        driver
            .get_capabilities(Request::new(request))
            .await
            .expect_err("incompatible major")
            .code(),
        Code::FailedPrecondition
    );
    Ok(())
}

#[tokio::test]
async fn stopping_an_unknown_registry_entry_fails_without_claiming_backend_success()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let driver = Driver::new(config(root.path())).expect("valid test configuration");
    let error = driver
        .stop_sandbox(Request::new(c::StopSandboxRequest {
            sandbox_id: "unknown-sandbox".into(),
            ..Default::default()
        }))
        .await
        .expect_err("unknown backend state must not be called stopped");
    assert_eq!(error.code(), Code::NotFound);
    Ok(())
}

async fn failed_launch_fixture(
    root: &std::path::Path,
    abort_fails: bool,
) -> anyhow::Result<(Driver, Vec<u8>)> {
    let key = root.join("key");
    anyhow::ensure!(
        std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()?
            .success(),
        "key fixture"
    );
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\ncreate) touch '{}'; sleep 0.1; printf 'invalid metadata';;\nabort) touch '{}'; exit {};;\ndelete) touch '{}';;\nesac\n",
        root.join("started").display(),
        root.join("aborted").display(),
        u8::from(abort_fails),
        root.join("deleted").display()
    );
    std::fs::write(root.join("lifecycle"), script)?;
    std::fs::set_permissions(
        root.join("lifecycle"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    let auth = serde_json::to_vec(
        &serde_json::json!({"supervisor":{"gateway_token":"test-placeholder","ssh_host_private_key":std::fs::read_to_string(key)?}}),
    )?;
    Ok((Driver::new(config(root))?, auth))
}

#[tokio::test]
async fn malformed_launch_metadata_uses_owned_abort_and_retains_failed_cleanup()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (driver, auth) = failed_launch_fixture(root.path(), true).await?;
    assert!(
        driver
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(sandbox(auth))
            }))
            .await
            .is_err()
    );
    assert!(root.path().join("aborted").exists());
    assert!(
        !root.path().join("deleted").exists(),
        "failed create must not delete pre-existing same-ID state"
    );
    let observed = driver
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "test-sandbox".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("failed cleanup retained");
    let ready = &observed.status.expect("status").conditions[0];
    assert_eq!(ready.status, "False");
    assert_eq!(ready.reason, "CleanupRequired");
    Ok(())
}

#[tokio::test]
async fn cancelled_create_rpc_still_finishes_owned_cleanup() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (driver, auth) = failed_launch_fixture(root.path(), false).await?;
    let request = tokio::spawn(async move {
        driver
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(sandbox(auth)),
            }))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !root.path().join("started").exists() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    request.abort();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !root.path().join("aborted").exists() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(!root.path().join("deleted").exists());
    Ok(())
}

#[tokio::test]
async fn refused_create_with_noop_abort_does_not_publish_a_false_deletion() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let (driver, auth) = failed_launch_fixture(root.path(), false).await?;
    assert!(
        driver
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(sandbox(auth))
            }))
            .await
            .is_err()
    );
    let mut events = driver
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest::default()))
        .await?
        .into_inner();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.next())
            .await
            .is_err(),
        "abort does not prove an existing runtime is absent"
    );
    Ok(())
}

#[tokio::test]
async fn blocked_creation_does_not_delay_another_sandbox_stop() -> anyhow::Result<()> {
    use std::time::Duration;
    let root = tempfile::tempdir()?;
    let key = root.path().join("key");
    assert!(
        std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()?
            .success()
    );
    let route = serde_json::json!({"sandbox_id":"test-sandbox","host":"127.0.0.1","port":12345,"username":"sandbox","private_key_path":key,"known_hosts_path":root.path().join("known-hosts")}).to_string();
    std::fs::write(
        root.path().join("lifecycle"),
        format!(
            "#!/bin/sh\nif [ \"$1:$2\" = create:blocked ]; then touch '{0}/entered'; while [ ! -f '{0}/release' ]; do sleep 0.02; done; fi\nif [ \"$1\" = create ]; then printf '%s' '{1}' | sed \"s/test-sandbox/$2/\"; fi\n",
            root.path().display(),
            route
        ),
    )?;
    std::fs::set_permissions(
        root.path().join("lifecycle"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    let auth = serde_json::to_vec(
        &serde_json::json!({"supervisor":{"gateway_token":"test-placeholder","ssh_host_private_key":std::fs::read_to_string(&key)?}}),
    )?;
    let driver = Driver::new(config(root.path()))?;
    driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(sandbox(auth.clone())),
        }))
        .await?;
    let mut blocked = sandbox(auth);
    blocked.id = "blocked".into();
    let creating_driver = driver.clone();
    let creating = tokio::spawn(async move {
        creating_driver
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(blocked),
            }))
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !root.path().join("entered").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let stopping_driver = driver.clone();
    let same_id = tokio::spawn(async move {
        stopping_driver
            .stop_sandbox(Request::new(c::StopSandboxRequest {
                sandbox_id: "blocked".into(),
                ..Default::default()
            }))
            .await
    });
    let other = tokio::time::timeout(
        Duration::from_millis(300),
        driver.stop_sandbox(Request::new(c::StopSandboxRequest {
            sandbox_id: "test-sandbox".into(),
            ..Default::default()
        })),
    )
    .await;
    assert!(
        !same_id.is_finished(),
        "same-ID operations must remain exclusive"
    );
    std::fs::write(root.path().join("release"), b"release")?;
    creating.await??;
    same_id.await??;
    assert!(
        other.is_ok(),
        "another sandbox's startup blocked access cancellation"
    );
    other??;
    driver.close().await;
    Ok(())
}
