use super::*;

#[tokio::test]
async fn failed_stop_or_delete_never_keeps_a_closed_runtime_ready() -> anyhow::Result<()> {
    for action in ["stop", "delete"] {
        let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
        let driver =
            Driver::new(fixture.runtime.config.clone()).expect("valid fixture configuration");
        driver
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(fixture.intent()?),
            }))
            .await?;
        driver_ready(&driver).await?;
        let original = fixture.files.path().join("original-lifecycle");
        fs::copy(&fixture.runtime.config.lifecycle, &original)?;
        let marker = fixture.files.path().join("cleanup-failed-once");
        executable(
            &fixture.runtime.config.lifecycle,
            &format!(
                "#!/bin/sh\nif [ \"$1\" = {action} ] && [ ! -f '{}' ]; then touch '{}'; exit 24; fi\nexec /bin/sh '{}' \"$@\"\n",
                marker.display(),
                marker.display(),
                original.display()
            ),
        )?;
        if action == "stop" {
            assert!(
                driver
                    .stop_sandbox(Request::new(c::StopSandboxRequest {
                        sandbox_id: "fixture-id".into(),
                        ..Default::default()
                    }))
                    .await
                    .is_err()
            );
        } else {
            assert!(
                driver
                    .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                        sandbox_id: "fixture-id".into(),
                        ..Default::default()
                    }))
                    .await
                    .is_err()
            );
        }
        let current = driver
            .get_sandbox(Request::new(c::GetSandboxRequest {
                sandbox_id: "fixture-id".into(),
                ..Default::default()
            }))
            .await?
            .into_inner()
            .sandbox
            .expect("retained after failure");
        assert!(
            current
                .status
                .expect("status")
                .conditions
                .iter()
                .all(|condition| condition.r#type != "Ready" || condition.status != "True")
        );
        if action == "stop" {
            driver
                .stop_sandbox(Request::new(c::StopSandboxRequest {
                    sandbox_id: "fixture-id".into(),
                    ..Default::default()
                }))
                .await?;
        }
        driver
            .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                sandbox_id: "fixture-id".into(),
                ..Default::default()
            }))
            .await?;
        fixture.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn transient_start_failure_is_failed_and_can_retry_the_same_transition() -> anyhow::Result<()>
{
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let driver = Driver::new(fixture.runtime.config.clone()).expect("valid fixture configuration");
    driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(fixture.intent()?),
        }))
        .await?;
    driver_ready(&driver).await?;
    driver
        .stop_sandbox(Request::new(c::StopSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    let lifecycle = fixture.runtime.config.lifecycle.clone();
    let original = fixture.files.path().join("original-lifecycle");
    fs::copy(&lifecycle, &original)?;
    executable(
        &lifecycle,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = start ] && [ ! -f '{}' ]; then touch '{}'; exit 24; fi\nexec /bin/sh '{}' \"$@\"\n",
            fixture.files.path().join("failed-once").display(),
            fixture.files.path().join("failed-once").display(),
            original.display()
        ),
    )?;
    let authentication = fixture.authentication()?;
    let start = || {
        Request::new(c::StartSandboxRequest {
            sandbox_id: "fixture-id".into(),
            generation_id: "retry-transition".into(),
            expected_runtime_identity: INSTANCE.into(),
            launch_authentication: authentication.clone(),
            ..Default::default()
        })
    };
    assert!(driver.start_sandbox(start()).await.is_err());
    let failed = driver
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("failed record");
    assert!(
        failed
            .status
            .expect("failed status")
            .conditions
            .iter()
            .any(|condition| condition.reason == "RuntimeError")
    );
    driver.start_sandbox(start()).await?;
    driver_ready(&driver).await?;
    assert_eq!(
        driver
            .start_sandbox(start())
            .await?
            .into_inner()
            .runtime_identity,
        INSTANCE,
        "successful transition retries are idempotent"
    );
    driver
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn restart_recovers_stopped_without_credentials_and_requires_fresh_start()
-> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let mut config = (*fixture.runtime.config).clone();
    config.recovery_dir = Some(fixture.files.path().join("registry"));
    let config = Arc::new(config);
    let driver = Driver::new(config.clone()).expect("valid fixture configuration");
    driver
        .create_sandbox(Request::new(c::CreateSandboxRequest {
            sandbox: Some(fixture.intent()?),
        }))
        .await?;
    driver_ready(&driver).await?;
    driver.close().await;
    drop(driver);
    let recovered = Driver::new(config.clone()).expect("valid fixture configuration");
    recovered.recover().await?;
    assert!(
        fixture.files.path().join("stopped").exists(),
        "startup must stop the retained Pod"
    );
    let record = recovered
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("retained record");
    assert!(
        record
            .spec
            .as_ref()
            .expect("retained spec")
            .launch_authentication
            .is_empty(),
        "credentials cannot survive recovery"
    );
    let status = record.status.as_ref().expect("stopped status");
    assert!(
        status
            .conditions
            .iter()
            .any(|c| c.r#type == "Suspended" && c.status == "True")
    );
    assert!(
        !status
            .conditions
            .iter()
            .any(|c| c.r#type == "Ready" && c.status == "True")
    );
    assert_eq!(
        recovered
            .start_sandbox(Request::new(c::StartSandboxRequest {
                sandbox_id: "fixture-id".into(),
                ..Default::default()
            }))
            .await
            .expect_err("fresh gateway authentication required")
            .code(),
        tonic::Code::InvalidArgument
    );
    let next = "db4c1779-8b56-44d7-b3ac-b75c5b34bb27";
    for name in ["route.json", "proof.json"] {
        let path = fixture.files.path().join(name);
        fs::write(&path, fs::read_to_string(&path)?.replace(INSTANCE, next))?;
    }
    let mut authentication: serde_json::Value = serde_json::from_slice(&fixture.authentication()?)?;
    authentication["supervisor"]["gateway_token"] = serde_json::json!("fresh-start-credential");
    let started = recovered
        .start_sandbox(Request::new(c::StartSandboxRequest {
            sandbox_id: "fixture-id".into(),
            expected_runtime_identity: INSTANCE.into(),
            generation_id: "restart-generation".into(),
            launch_authentication: serde_json::to_vec(&authentication)?,
            ..Default::default()
        }))
        .await?
        .into_inner();
    assert_eq!(started.runtime_identity, next);
    driver_ready(&recovered).await?;
    assert!(
        fixture
            .state
            .headers
            .lock()
            .expect("headers")
            .iter()
            .any(|h| h == "Bearer fresh-start-credential")
    );
    let files = fs::read_dir(config.recovery_dir.as_ref().expect("recovery directory"))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(files.len(), 1);
    let value: serde_json::Value = serde_json::from_slice(&fs::read(files[0].path())?)?;
    let bytes: Vec<u8> = serde_json::from_value(value["sandbox"].clone())?;
    let persisted: c::DriverSandbox = prost::Message::decode(bytes.as_slice())?;
    assert!(
        persisted
            .spec
            .expect("persisted spec")
            .launch_authentication
            .is_empty()
    );
    assert_eq!(
        fs::metadata(files[0].path())?.permissions().mode() & 0o777,
        0o600
    );
    recovered
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    assert_eq!(
        fs::read_dir(config.recovery_dir.as_ref().expect("registry"))?.count(),
        0
    );
    recovered.close().await;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn interrupted_provisioning_and_failed_recovery_never_publish_ready() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let mut config = (*fixture.runtime.config).clone();
    config.recovery_dir = Some(fixture.files.path().join("registry"));
    executable(&config.lifecycle, "#!/bin/sh\nexit 23\n")?;
    let config = Arc::new(config);
    let driver = Driver::new(config.clone()).expect("valid fixture configuration");
    assert!(
        driver
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(fixture.intent()?)
            }))
            .await
            .is_err()
    );
    assert_eq!(
        fs::read_dir(config.recovery_dir.as_ref().expect("registry"))?.count(),
        1,
        "intent must precede backend mutation"
    );
    drop(driver);
    let recovered = Driver::new(config.clone()).expect("valid fixture configuration");
    assert!(
        recovered.recover().await.is_err(),
        "failed backend cleanup prevents startup"
    );
    assert!(
        recovered
            .list_sandboxes(Request::new(c::ListSandboxesRequest {}))
            .await?
            .into_inner()
            .sandboxes
            .is_empty()
    );
    executable(&config.lifecycle, "#!/bin/sh\nprintf '{}'\n")?;
    recovered.recover().await?;
    let observed = recovered
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("interrupted intent recovered");
    assert!(
        observed
            .status
            .expect("stopped status")
            .conditions
            .iter()
            .all(|c| c.r#type != "Ready" || c.status == "False")
    );
    assert_eq!(
        recovered
            .create_sandbox(Request::new(c::CreateSandboxRequest {
                sandbox: Some(fixture.intent()?)
            }))
            .await
            .expect_err("retained resources require fresh Start")
            .code(),
        tonic::Code::FailedPrecondition
    );
    recovered
        .stop_sandbox(Request::new(c::StopSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    recovered
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn native_recovery_stops_before_inventory_and_requires_new_authenticated_start()
-> anyhow::Result<()> {
    use openshell_kata::{
        profile::VmPolicy,
        recovery::{Retained, Store},
    };
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let root = fixture.files.path();
    let policy: VmPolicy = serde_json::from_value(
        serde_json::json!({"version":1,"profile":"docker-vm","resources":{"vcpus":32,"memory_mib":131072,"disk_mib":262144,"lifetime_secs":3600},"filesystem":{"host_mounts":"deny","transfer_max_bytes":268435456,"transfer_max_entries":4096},"network":{"tcp_allow":[]}}),
    )?;
    let path = root.join("native-policy.json");
    fs::write(&path, serde_json::to_vec(&policy)?)?;
    let config = Arc::new(Config {
        runtime_profile: RuntimeProfile::Local,
        vm_policy: Some(path),
        guest_network_cidr: None,
        additional_guest_images: Vec::new(),
        recovery_dir: Some(root.join("native-registry")),
        max_sandboxes: Some(4),
        workspace_capacities: Vec::new(),
        ..(*fixture.runtime.config).clone()
    });
    let mut route: serde_json::Value = serde_json::from_slice(&fs::read(root.join("route.json"))?)?;
    route["host"] = serde_json::json!("127.0.0.1");
    route["port"] = serde_json::json!(2222);
    route["enforcement"] = serde_json::json!({"sandbox_id":"fixture-id","policy_sha256":policy.digest()?,"nonce":"RUNTIME_NONCE","runtime":"kata-runtime-rs","hypervisor_pid":101,"resources":policy.resources,"storage_id":"private-block-snapshot","network_fence":"generation-proof","watchdog_pid":102,"expires_at_unix_secs":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()+3600});
    fs::write(root.join("native-route.json"), serde_json::to_vec(&route)?)?;
    let lifecycle = format!(
        "#!/bin/sh\naction=$1\nshift 2\nnonce=\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --proof-nonce ]; then nonce=$2; shift; fi; shift; done\ncase \"$action\" in\nstop) touch '{}'; printf '{{}}' ;;\nstart|create|verify|update) sed \"s/RUNTIME_NONCE/$nonce/g\" '{}' ;;\n*) printf '{{}}' ;;\nesac\n",
        root.join("native-stopped").display(),
        root.join("native-route.json").display()
    );
    executable(&config.lifecycle, "#!/bin/sh\nexit 23\n")?;
    let store = Store::for_config(&config)?;
    store.save(&Retained::new(
        fixture.intent()?,
        INSTANCE.into(),
        "old-generation".into(),
    ))?;
    let driver = Driver::new(config.clone())?;
    assert!(
        driver.recover().await.is_err(),
        "unconfirmed cleanup prevents publishing inventory"
    );
    assert!(
        driver
            .list_sandboxes(Request::new(c::ListSandboxesRequest {}))
            .await?
            .into_inner()
            .sandboxes
            .is_empty()
    );
    executable(&config.lifecycle, &lifecycle)?;
    driver.recover().await?;
    assert!(
        root.join("native-stopped").exists(),
        "native lifecycle stop precedes exposure"
    );
    let record = driver
        .get_sandbox(Request::new(c::GetSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .sandbox
        .expect("native retained record");
    assert!(record.spec.expect("spec").launch_authentication.is_empty());
    assert!(
        record
            .status
            .expect("status")
            .conditions
            .iter()
            .any(|condition| condition.r#type == "Suspended" && condition.status == "True")
    );
    assert_eq!(
        driver
            .start_sandbox(Request::new(c::StartSandboxRequest {
                sandbox_id: "fixture-id".into(),
                ..Default::default()
            }))
            .await
            .expect_err("fresh authorization required")
            .code(),
        tonic::Code::InvalidArgument
    );
    let mut authentication: serde_json::Value = serde_json::from_slice(&fixture.authentication()?)?;
    authentication["supervisor"]["gateway_token"] = serde_json::json!("fresh-start-credential");
    driver
        .start_sandbox(Request::new(c::StartSandboxRequest {
            sandbox_id: "fixture-id".into(),
            generation_id: "native-restart".into(),
            launch_authentication: serde_json::to_vec(&authentication)?,
            ..Default::default()
        }))
        .await?;
    driver_ready(&driver).await?;
    assert!(
        fixture
            .state
            .headers
            .lock()
            .expect("headers")
            .iter()
            .any(|header| header == "Bearer fresh-start-credential")
    );
    driver
        .delete_sandbox(Request::new(c::DeleteSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    assert!(store.load(&config)?.admitted.is_empty());
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn recovery_retires_sandboxes_the_new_operator_profile_no_longer_admits() -> anyhow::Result<()>
{
    use openshell_kata::{
        profile::VmPolicy,
        recovery::{Retained, Store},
    };
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let root = fixture.files.path();
    let policy: VmPolicy = serde_json::from_value(
        serde_json::json!({"version":1,"profile":"docker-vm","resources":{"vcpus":32,"memory_mib":131072,"disk_mib":262144,"lifetime_secs":3600},"filesystem":{"host_mounts":"deny","transfer_max_bytes":268435456,"transfer_max_entries":4096},"network":{"tcp_allow":[]}}),
    )?;
    let path = root.join("native-policy.json");
    fs::write(&path, serde_json::to_vec(&policy)?)?;
    let retired_image = IMAGE.replace("aaaa", "cccc");
    let previous = Config {
        runtime_profile: RuntimeProfile::Local,
        vm_policy: Some(path),
        guest_network_cidr: None,
        additional_guest_images: vec![retired_image.clone()],
        recovery_dir: Some(root.join("native-registry")),
        max_sandboxes: Some(4),
        workspace_capacities: Vec::new(),
        ..(*fixture.runtime.config).clone()
    };
    let store = Store::for_config(&previous)?;
    store.save(&Retained::new(
        fixture.intent()?,
        INSTANCE.into(),
        "kept-generation".into(),
    ))?;
    let mut old = fixture.intent()?;
    old.id = "retired-id".into();
    old.spec
        .as_mut()
        .expect("spec")
        .template
        .as_mut()
        .expect("template")
        .resources = Some(c::DriverResourceRequirements {
        cpu_request: "16".into(),
        ..Default::default()
    });
    store.save(&Retained::new(
        old,
        INSTANCE.into(),
        "old-generation".into(),
    ))?;
    let mut dropped = fixture.intent()?;
    dropped.id = "dropped-id".into();
    dropped.workspace = "workspace-dropped".into();
    dropped
        .spec
        .as_mut()
        .expect("spec")
        .template
        .as_mut()
        .expect("template")
        .image = retired_image.clone();
    store.save(&Retained::new(
        dropped,
        INSTANCE.into(),
        "dropped-generation".into(),
    ))?;
    // The next release no longer admits the previous image, and the old record's
    // resources leave the operator profile.
    let config = Arc::new(Config {
        additional_guest_images: Vec::new(),
        ..previous
    });
    let log = root.join("lifecycle.log");
    executable(
        &config.lifecycle,
        &format!(
            "#!/bin/sh\necho \"$1 $2 $OPENSHELL_KATA_GUEST_IMAGE\" >> '{}'\ncase \"$1\" in delete) exit 7 ;; esac\nprintf '{{}}'\n",
            log.display()
        ),
    )?;
    let failing = Driver::new(config.clone())?;
    failing.recover().await?;
    assert!(
        Store::for_config(&config)?.load(&config)?.retired.len() == 1,
        "a failed retirement keeps its record for the next recovery"
    );
    let ids = |driver: Driver| async move {
        anyhow::Ok(
            driver
                .list_sandboxes(Request::new(c::ListSandboxesRequest {}))
                .await?
                .into_inner()
                .sandboxes
                .into_iter()
                .map(|sandbox| sandbox.id)
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(
        ids(failing).await?,
        vec!["dropped-id".to_owned(), "fixture-id".to_owned()]
    );

    fs::remove_file(&log)?;
    executable(
        &config.lifecycle,
        &format!(
            "#!/bin/sh\necho \"$1 $2 $OPENSHELL_KATA_GUEST_IMAGE\" >> '{}'\nprintf '{{}}'\n",
            log.display()
        ),
    )?;
    let driver = Driver::new(config.clone())?;
    driver.recover().await?;
    let calls = fs::read_to_string(&log)?;
    assert!(calls.contains("delete retired-id"), "{calls}");
    assert!(calls.contains("stop fixture-id"), "{calls}");
    assert!(!calls.contains("stop retired-id"), "{calls}");
    // A dropped image alone keeps the sandbox, stopped on its own image.
    assert!(
        calls.contains(&format!("stop dropped-id {retired_image}")),
        "{calls}"
    );
    assert!(!calls.contains("delete dropped-id"), "{calls}");
    assert_eq!(
        driver
            .get_sandbox(Request::new(c::GetSandboxRequest {
                sandbox_id: "retired-id".into(),
                ..Default::default()
            }))
            .await
            .expect_err("retired sandbox is gone")
            .code(),
        tonic::Code::NotFound
    );
    let recovered = Store::for_config(&config)?.load(&config)?;
    assert!(recovered.retired.is_empty(), "retired record removed");
    assert_eq!(recovered.admitted.len(), 2);
    let mut watch = driver
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest {}))
        .await?
        .into_inner();
    let mut deleted = false;
    for _ in 0..4 {
        let Ok(Some(event)) =
            tokio::time::timeout(std::time::Duration::from_secs(2), watch.next()).await
        else {
            break;
        };
        let event = event?;
        if let Some(c::watch_sandboxes_event::Payload::Deleted(gone)) = event.payload {
            deleted |= gone.sandbox_id == "retired-id";
        }
    }
    assert!(
        deleted,
        "the gateway observes the retired sandbox as deleted"
    );
    assert_eq!(
        ids(driver).await?,
        vec!["dropped-id".to_owned(), "fixture-id".to_owned()]
    );
    fixture.close().await;
    Ok(())
}
