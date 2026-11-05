#[path = "support/gateway.rs"]
mod gateway;

use gateway::{Gateway, State};
use openshell_kata::{
    config::{Config, RuntimeProfile},
    guest::Guest,
    proto::openshell::{compute::v1 as c, sandbox::v1 as s, v1 as o},
    supervisor::{Output, Phase, Runtime},
};
use openshell_kata::{
    driver::Driver, proto::openshell::compute::v1::compute_driver_server::ComputeDriver,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::Request;
use tonic::transport::{Identity, Server, ServerTlsConfig};

const INSTANCE: &str = "8e7c7bb5-4ac0-46a2-afd3-4a426209a168";
const IMAGE: &str = "registry.example/guest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    files: tempfile::TempDir,
    state: Arc<State>,
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
    server: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

fn command(directory: &Path, args: &[&str]) -> anyhow::Result<()> {
    let result = Command::new("openssl")
        .args(args)
        .current_dir(directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    anyhow::ensure!(result.success(), "test certificate generation failed");
    Ok(())
}

fn executable(path: &Path, contents: &str) -> anyhow::Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

impl Fixture {
    async fn new(command_args: Vec<String>) -> anyhow::Result<Self> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("openshell_kata=debug")
            .with_test_writer()
            .try_init();
        let files = tempfile::tempdir()?;
        let root = files.path();
        fs::write(
            root.join("tls.cnf"),
            "[v3]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n",
        )?;
        command(
            root,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.crt",
                "-days",
                "1",
                "-subj",
                "/CN=Test CA",
            ],
        )?;
        command(
            root,
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
                "-subj",
                "/CN=localhost",
            ],
        )?;
        command(
            root,
            &[
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "server.crt",
                "-days",
                "1",
                "-extfile",
                "tls.cnf",
                "-extensions",
                "v3",
            ],
        )?;
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(root.join("ssh-key"))
            .status()?;
        anyhow::ensure!(status.success(), "test SSH key generation failed");
        let proof = serde_json::json!({"version":1,"sandbox_id":"fixture-id","workspace":"tenant-a","namespace":"sandbox-tenant-a","runtime_identity":INSTANCE,"runtime_class":"kata-qemu-runtime-rs","image":IMAGE,"network":"deny-all-egress","cpu":"2","memory":"4Gi","policy_sha256":"b".repeat(64),"expires_at_unix":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()+3600,"deadline_enforcement":"kubelet-active-deadline"});
        fs::write(root.join("proof.json"), serde_json::to_vec(&proof)?)?;
        executable(
            &root.join("lifecycle"),
            &format!(
                "#!/bin/sh\ncase \"$1\" in\nverify) cat '{}' ;;\ncreate|start) cat '{}' ;;\nstop) touch '{}'; printf '{{}}' ;;\n*) printf '{{}}' ;;\nesac\n",
                root.join("proof.json").display(),
                root.join("route.json").display(),
                root.join("stopped").display()
            ),
        )?;
        executable(
            &root.join("guest-ssh"),
            &format!(
                "#!/bin/sh\ncase \" $* \" in\n*' -W '*) exec cat ;;\n*) touch '{}'; head -c 3145728 /dev/zero | tr '\\000' x; printf 'fixture stderr' >&2; exit 7 ;;\nesac\n",
                root.join("main-ran").display()
            ),
        )?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let state = Arc::new(State::default());
        *state.snapshot.lock().expect("fixture snapshot") = s::GetSandboxConfigResponse {
            policy: Some(s::SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            configuration_admitted: true,
            version: 1,
            policy_hash: "hash".into(),
            config_revision: 1,
            provider_env_revision: 1,
            ..Default::default()
        };
        *state.providers.lock().expect("fixture providers") =
            o::GetSandboxProviderEnvironmentResponse {
                provider_env_revision: 1,
                policy_hash: "hash".into(),
                ..Default::default()
            };
        let shutdown = CancellationToken::new();
        let future = Server::builder()
            .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(
                fs::read(root.join("server.crt"))?,
                fs::read(root.join("server.key"))?,
            )))?
            .add_service(Gateway(state.clone()))
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                shutdown.clone().cancelled_owned(),
            );
        let server = tokio::spawn(future);
        let config = Arc::new(Config {
            socket: root.join("unused.sock"),
            gateway: format!("https://{address}"),
            gateway_ca: root.join("ca.crt"),
            lifecycle: root.join("lifecycle"),
            lifecycle_arg: vec![],
            ssh: root.join("guest-ssh"),
            prototype_policy_mode: false,
            vm_policy: None,
            runtime_profile: RuntimeProfile::Kubernetes,
            guest_image: Some(IMAGE.into()),
            guest_network_cidr: Some("10.176.0.0/16".into()),
            additional_guest_images: Vec::new(),
            recovery_dir: None,
            hosted_network_config: None,
            max_sandboxes: None,
            workspace_capacities: Vec::new(),
        });
        let authentication = serde_json::to_vec(
            &serde_json::json!({"supervisor":{"gateway_token":"initial-credential","ssh_host_private_key":fs::read_to_string(root.join("ssh-key"))?}}),
        )?;
        let guest = Guest {
            sandbox_id: "fixture-id".into(),
            host: "10.176.0.10".into(),
            port: 22,
            username: "sandbox".into(),
            private_key_path: root.join("ssh-key"),
            known_hosts_path: root.join("known-hosts"),
            runtime_identity: Some(INSTANCE.into()),
            enforcement: None,
        };
        fs::write(
            root.join("route.json"),
            serde_json::to_vec(
                &serde_json::json!({"sandbox_id":guest.sandbox_id,"host":guest.host,"port":guest.port,"username":guest.username,"private_key_path":guest.private_key_path,"known_hosts_path":guest.known_hosts_path,"runtime_identity":guest.runtime_identity}),
            )?,
        )?;
        let runtime = Runtime::new(
            c::DriverSandbox {
                id: "fixture-id".into(),
                name: "fixture".into(),
                workspace: "tenant-a".into(),
                spec: Some(c::DriverSandboxSpec {
                    command: command_args,
                    policy: Some(s::SandboxPolicy {
                        version: 1,
                        ..Default::default()
                    }),
                    template: Some(c::DriverSandboxTemplate {
                        image: IMAGE.into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            config,
            guest,
            authentication,
        )?;
        Ok(Self {
            files,
            state,
            runtime,
            shutdown,
            server,
        })
    }

    async fn phase(&self, expected: Phase) -> anyhow::Result<()> {
        let mut phases = self.runtime.phase.subscribe();
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if *phases.borrow_and_update() == expected {
                    return Ok::<_, anyhow::Error>(());
                }
                phases.changed().await?;
            }
        })
        .await??;
        Ok(())
    }

    fn authentication(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &serde_json::json!({"supervisor":{"gateway_token":"initial-credential","ssh_host_private_key":fs::read_to_string(self.files.path().join("ssh-key"))?}}),
        )?)
    }
    fn intent(&self) -> anyhow::Result<c::DriverSandbox> {
        let mut intent = self.runtime.spec.clone();
        intent
            .spec
            .as_mut()
            .expect("fixture spec")
            .launch_authentication = self.authentication()?;
        Ok(intent)
    }
    async fn close(self) {
        self.runtime.close().await;
        self.shutdown.cancel();
        self.server.abort();
        let _ = self.server.await;
    }
}

#[tokio::test]
async fn bootstrap_refresh_capture_relay_and_gateway_outage() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    fixture.state.retry_configs.store(1, Ordering::SeqCst);
    fixture.runtime.start().await?;
    fixture.phase(Phase::Ready).await?;
    let mut exits = fixture.runtime.main_exit.subscribe();
    tokio::time::timeout(Duration::from_secs(3), async {
        while exits.borrow_and_update().is_none() {
            exits.changed().await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    assert_eq!(
        *exits.borrow(),
        Some(7),
        "canonical process exit must survive capture"
    );
    let history = fixture.runtime.history.lock().await;
    assert!(history.len() <= 64, "history is bounded under large output");
    assert!(
        history
            .iter()
            .any(|entry| matches!(entry, Output::Stderr(_))),
        "stderr must be retained separately"
    );
    drop(history);
    {
        let reports = fixture.state.reports.lock().expect("fixture reports");
        assert_eq!(
            reports
                .iter()
                .filter_map(|r| r.admission.as_ref().map(|a| a.state))
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(
            reports[1]
                .admission
                .as_ref()
                .expect("accepted report")
                .instance_id,
            INSTANCE
        );
    }
    let control = fixture
        .state
        .control
        .lock()
        .expect("fixture control")
        .as_ref()
        .expect("connected supervisor")
        .clone();
    control
        .send(Ok(o::GatewayMessage {
            payload: Some(o::gateway_message::Payload::RelayOpen(o::RelayOpen {
                channel_id: "fixture-channel".into(),
                target: Some(o::relay_open::Target::Tcp(o::TcpRelayTarget {
                    host: "127.0.0.1".into(),
                    port: 8080,
                })),
                ..Default::default()
            })),
        }))
        .await?;
    tokio::time::timeout(Duration::from_secs(3), fixture.state.relayed.notified()).await?;
    assert_eq!(
        *fixture.state.relay_data.lock().expect("relay data"),
        b"through-the-relay"
    );
    assert!(
        fixture
            .state
            .headers
            .lock()
            .expect("headers")
            .iter()
            .any(|value| value == "Bearer refreshed-credential"),
        "startup relay must use the replacement credential"
    );
    control
        .send(Err(tonic::Status::unavailable("fixture gateway outage")))
        .await?;
    fixture.phase(Phase::Failed).await?;
    tokio::time::timeout(Duration::from_secs(2), fixture.runtime.cancel.cancelled()).await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn unadmitted_configuration_never_starts_the_guest_command() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    fixture
        .state
        .snapshot
        .lock()
        .expect("snapshot")
        .configuration_admitted = false;
    fixture.runtime.start().await?;
    fixture.phase(Phase::Failed).await?;
    assert!(!fixture.files.path().join("main-ran").exists());
    assert!(fixture.state.reports.lock().expect("reports").is_empty());
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn provider_credentials_are_rejected_before_guest_execution() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    fixture
        .state
        .providers
        .lock()
        .expect("providers")
        .environment
        .insert("SECRET".into(), "fixture-only".into());
    fixture.runtime.start().await?;
    fixture.phase(Phase::Failed).await?;
    assert!(!fixture.files.path().join("main-ran").exists());
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn changed_effective_policy_revokes_a_live_runtime() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    fixture.runtime.start().await?;
    fixture.phase(Phase::Ready).await?;
    fixture
        .state
        .snapshot
        .lock()
        .expect("snapshot")
        .config_revision = 2;
    fixture.phase(Phase::Failed).await?;
    assert!(
        fixture.runtime.cancel.is_cancelled(),
        "policy changes revoke active streams"
    );
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn empty_canonical_command_cannot_be_admitted() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec![]).await?;
    fixture.runtime.start().await?;
    fixture.phase(Phase::Failed).await?;
    assert!(!fixture.files.path().join("main-ran").exists());
    fixture.close().await;
    Ok(())
}

async fn driver_ready(driver: &Driver) -> anyhow::Result<c::DriverSandbox> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let value = driver
                .get_sandbox(Request::new(c::GetSandboxRequest {
                    sandbox_id: "fixture-id".into(),
                    ..Default::default()
                }))
                .await?
                .into_inner()
                .sandbox
                .expect("driver record");
            if value
                .status
                .as_ref()
                .expect("driver status")
                .conditions
                .iter()
                .any(|c| c.r#type == "Ready" && c.status == "True")
            {
                return Ok::<_, anyhow::Error>(value);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?
}

#[tokio::test]
async fn hosted_driver_round_trip_replaces_runtime_identity_and_deletes_record()
-> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    let driver = Driver::new(fixture.runtime.config.clone()).expect("valid fixture configuration");
    let caps = driver
        .get_capabilities(Request::new(c::GetCapabilitiesRequest::default()))
        .await?
        .into_inner();
    assert_eq!(caps.default_image, IMAGE);
    assert!(caps.driver_reports_runtime_readiness);
    driver
        .ensure_workspace(Request::new(c::EnsureWorkspaceRequest {
            workspace: "tenant-a".into(),
        }))
        .await?;
    driver
        .validate_sandbox_create(Request::new(c::ValidateSandboxCreateRequest {
            sandbox: Some(fixture.intent()?),
        }))
        .await?;
    let create = || {
        Request::new(c::CreateSandboxRequest {
            sandbox: Some(fixture.intent().expect("fixture launch intent")),
        })
    };
    assert_eq!(
        driver
            .create_sandbox(create())
            .await?
            .into_inner()
            .runtime_identity,
        INSTANCE
    );
    driver_ready(&driver).await?;
    let mut watch = driver
        .watch_sandboxes(Request::new(c::WatchSandboxesRequest {}))
        .await?
        .into_inner();
    let initial = tokio::time::timeout(Duration::from_secs(2), watch.next())
        .await?
        .expect("initial watch snapshot")?;
    assert!(matches!(
        initial.payload,
        Some(c::watch_sandboxes_event::Payload::Sandbox(_))
    ));
    assert_eq!(
        driver
            .create_sandbox(create())
            .await?
            .into_inner()
            .runtime_identity,
        INSTANCE,
        "duplicate create preserves the same VM generation"
    );
    assert_eq!(
        driver
            .list_sandboxes(Request::new(c::ListSandboxesRequest {}))
            .await?
            .into_inner()
            .sandboxes
            .len(),
        1
    );
    assert_eq!(
        driver
            .authenticate_sandbox(Request::new(c::AuthenticateSandboxRequest::default()))
            .await
            .expect_err("driver cannot mint sandbox identity")
            .code(),
        tonic::Code::Unimplemented
    );
    assert_eq!(
        driver
            .suspend_sandbox(Request::new(c::SuspendSandboxRequest::default()))
            .await
            .expect_err("unsupported memory suspension")
            .code(),
        tonic::Code::Unimplemented
    );
    driver
        .stop_sandbox(Request::new(c::StopSandboxRequest {
            sandbox_id: "fixture-id".into(),
            ..Default::default()
        }))
        .await?;
    assert!(fixture.files.path().join("stopped").exists());
    // Leave the consumer stalled across stop/start, as a gateway can be while
    // waiting on a lifecycle RPC. An old observation must not supersede Ready.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let next = "0b1f678c-929b-4212-a28e-8f6b7cfdbf60";
    for name in ["route.json", "proof.json"] {
        let path = fixture.files.path().join(name);
        fs::write(&path, fs::read_to_string(&path)?.replace(INSTANCE, next))?;
    }
    let auth = fixture.authentication()?;
    assert_eq!(
        driver
            .start_sandbox(Request::new(c::StartSandboxRequest {
                sandbox_id: "fixture-id".into(),
                launch_authentication: auth,
                ..Default::default()
            }))
            .await?
            .into_inner()
            .runtime_identity,
        next
    );
    driver_ready(&driver).await?;
    let fresh = tokio::time::timeout(Duration::from_secs(2), watch.next())
        .await?
        .expect("fresh watch generation")?;
    let Some(c::watch_sandboxes_event::Payload::Sandbox(fresh)) = fresh.payload else {
        anyhow::bail!("unexpected deletion during restart");
    };
    let status = fresh
        .sandbox
        .expect("fresh sandbox")
        .status
        .expect("fresh status");
    assert_eq!(
        status.instance_id, next,
        "slow consumer must observe the current generation"
    );
    assert!(
        !status
            .conditions
            .iter()
            .any(|condition| condition.r#type == "Suspended"),
        "old Stopped cannot close the restarted supervisor"
    );
    assert!(
        driver
            .delete_sandbox(Request::new(c::DeleteSandboxRequest {
                sandbox_id: "fixture-id".into(),
                ..Default::default()
            }))
            .await?
            .into_inner()
            .deleted
    );
    assert!(
        driver
            .list_sandboxes(Request::new(c::ListSandboxesRequest {}))
            .await?
            .into_inner()
            .sandboxes
            .is_empty()
    );
    driver
        .delete_workspace(Request::new(c::DeleteWorkspaceRequest {
            workspace: "tenant-a".into(),
        }))
        .await?;
    driver.close().await;
    fixture.close().await;
    Ok(())
}

#[path = "support/recovery_cases.rs"]
mod recovery_cases;

#[tokio::test]
async fn runtime_observation_never_retains_launch_credentials() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    assert!(
        fixture
            .runtime
            .spec
            .spec
            .as_ref()
            .expect("fixture spec")
            .launch_authentication
            .is_empty(),
        "gateway bootstrap credentials must remain private to the supervisor"
    );
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn slow_boot_renews_nearly_expired_launch_credentials_before_ready() -> anyhow::Result<()> {
    let fixture = Fixture::new(vec!["fixture-main".into()]).await?;
    *fixture
        .state
        .initial_expires
        .lock()
        .expect("fixture expiry") = Some(std::time::Instant::now() + Duration::from_secs(5));
    fixture.runtime.start().await?;
    fixture.phase(Phase::Ready).await?;
    assert!(
        fixture.state.refresh_calls.load(Ordering::SeqCst) > 0,
        "Ready must follow renewal even when boot consumed most of the launch TTL"
    );
    tokio::time::sleep(Duration::from_millis(5100)).await;
    let control = fixture
        .state
        .control
        .lock()
        .expect("fixture control")
        .as_ref()
        .expect("supervisor")
        .clone();
    control
        .send(Ok(o::GatewayMessage {
            payload: Some(o::gateway_message::Payload::RelayOpen(o::RelayOpen {
                channel_id: "after-launch-expiry".into(),
                target: Some(o::relay_open::Target::Tcp(o::TcpRelayTarget {
                    host: "127.0.0.1".into(),
                    port: 8080,
                })),
                ..Default::default()
            })),
        }))
        .await?;
    tokio::time::timeout(Duration::from_secs(3), fixture.state.relayed.notified()).await?;
    assert!(
        fixture
            .state
            .headers
            .lock()
            .expect("fixture headers")
            .iter()
            .any(|value| value == "Bearer refreshed-credential")
    );
    fixture.close().await;
    Ok(())
}
