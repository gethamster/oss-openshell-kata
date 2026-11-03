use super::*;
use crate::network::{Endpoint, guard::BrokerBinding};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

fn policy() -> NetworkPolicy {
    NetworkPolicy {
        tcp_allow: vec![Endpoint {
            host: "example.com".into(),
            port: 443,
        }],
        ..Default::default()
    }
}
fn config() -> HostedBrokerConfig {
    HostedBrokerConfig {
        version: 1,
        operator_ceiling: policy(),
        initial_ceiling: policy(),
        binding: BrokerBinding {
            workspace: "tenant".into(),
            namespace_uid: uuid::Uuid::new_v4().to_string(),
            sandbox_id: uuid::Uuid::new_v4().to_string(),
            launch_nonce: uuid::Uuid::new_v4().to_string(),
            expires_at_unix: now().expect("clock") + 3600,
        },
        protected_hostname_suffixes: vec!["internal.example.com".into()],
        baseline_denied_cidrs: vec!["10.0.0.0/8".into()],
        authorization_lease_secs: 30,
    }
}
fn inventory(generation: u64) -> InfrastructureInventory {
    let now = now().expect("clock");
    InfrastructureInventory {
        version: 1,
        generation,
        issued_at_unix: now,
        expires_at_unix: now + 60,
        denied_cidrs: vec![],
    }
}
struct FakeConnector {
    answers: Vec<SocketAddr>,
    connects: Arc<AtomicUsize>,
}
impl Connector for FakeConnector {
    fn resolve<'a>(&'a self, _: &'a str, _: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async { Ok(self.answers.clone()) })
    }
    fn connect(&self, _: SocketAddr) -> BoxFuture<'_, Result<Stream>> {
        Box::pin(async {
            self.connects.fetch_add(1, Ordering::SeqCst);
            let (a, mut b) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(&mut b);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            Ok(Box::new(a) as Stream)
        })
    }
}
async fn fixture(
    config: HostedBrokerConfig,
    inventory: InfrastructureInventory,
    answers: Vec<SocketAddr>,
) -> Result<(HostedBrokerHandle, Arc<AtomicUsize>)> {
    let connects = Arc::new(AtomicUsize::new(0));
    let broker = bind_hosted_with_connector(
        "127.0.0.1:0".parse()?,
        config,
        inventory,
        Arc::new(FakeConnector {
            answers,
            connects: connects.clone(),
        }),
    )
    .await?;
    Ok((broker, connects))
}
fn request(
    broker: &HostedBrokerHandle,
    generation: u64,
    policy: NetworkPolicy,
    inventory: InfrastructureInventory,
) -> HostedControlRequest {
    HostedControlRequest::Authorize {
        binding: broker.config.binding.clone(),
        startup_epoch: broker.startup_epoch.clone(),
        expected_generation: generation,
        nonce: uuid::Uuid::new_v4().to_string(),
        policy,
        inventory,
    }
}
async fn inspect(broker: &HostedBrokerHandle) -> Result<HostedControlResponse> {
    broker.snapshot(&uuid::Uuid::new_v4().to_string()).await
}
async fn tunnel(broker: &HostedBrokerHandle) -> Result<BufReader<TcpStream>> {
    let mut socket = TcpStream::connect(broker.local_addr()).await?;
    socket
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        .await?;
    let mut reader = BufReader::new(socket);
    let mut head = String::new();
    reader.read_line(&mut head).await?;
    ensure!(head.contains("200"), "unexpected tunnel status: {head}");
    head.clear();
    reader.read_line(&mut head).await?;
    Ok(reader)
}
async fn echoed(stream: &mut BufReader<TcpStream>) -> Result<()> {
    stream.get_mut().write_all(b"echo").await?;
    let mut bytes = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes)).await??;
    assert_eq!(&bytes, b"echo");
    Ok(())
}
async fn closed(stream: &mut BufReader<TcpStream>) -> Result<()> {
    let mut b = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut b)).await??,
        0
    );
    Ok(())
}

#[tokio::test]
async fn startup_and_stale_initial_inventory_grant_no_authority() -> Result<()> {
    let mut inv = inventory(1);
    inv.issued_at_unix -= 120;
    inv.expires_at_unix -= 120;
    let (broker, connects) = fixture(config(), inv, vec!["8.8.4.4:443".parse()?]).await?;
    let snapshot = inspect(&broker).await?;
    assert!(snapshot.policy.tcp_allow.is_empty());
    assert_eq!(snapshot.authorization_expires_at_unix, 0);
    let mut socket = TcpStream::connect(broker.local_addr()).await?;
    let _ = socket
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        .await;
    let mut b = [0; 64];
    let _ = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut b)).await;
    assert_eq!(connects.load(Ordering::SeqCst), 0);
    broker
        .request(request(&broker, 1, policy(), inventory(2)))
        .await?;
    echoed(&mut tunnel(&broker).await?).await?;
    broker.shutdown().await
}

#[tokio::test]
async fn fresh_same_policy_renewal_keeps_tunnels_and_rejects_stale_cas_or_epoch() -> Result<()> {
    let inv = inventory(1);
    let (broker, _) = fixture(config(), inv.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    let first = broker
        .request(request(&broker, 1, policy(), inv.clone()))
        .await?;
    assert_eq!(first.generation, 2);
    let mut stream = tunnel(&broker).await?;
    echoed(&mut stream).await?;
    let renewed = broker
        .request(request(&broker, 2, policy(), inv.clone()))
        .await?;
    assert_eq!(renewed.generation, 3);
    echoed(&mut stream).await?;
    assert!(
        broker
            .request(request(&broker, 2, NetworkPolicy::default(), inv.clone()))
            .await
            .is_err()
    );
    let mut wrong = request(&broker, 3, NetworkPolicy::default(), inv);
    if let HostedControlRequest::Authorize { startup_epoch, .. } = &mut wrong {
        *startup_epoch = uuid::Uuid::new_v4().to_string();
    }
    assert!(broker.request(wrong).await.is_err());
    echoed(&mut stream).await?;
    let current = inspect(&broker).await?;
    assert_eq!(current.generation, 3);
    assert_eq!(current.policy, policy());
    broker.shutdown().await
}

#[tokio::test]
async fn monotonic_authorization_expires_and_inspection_never_renews() -> Result<()> {
    let inv = inventory(1);
    let (broker, _) = fixture(config(), inv.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    let response = broker.request(request(&broker, 1, policy(), inv)).await?;
    let mut stream = tunnel(&broker).await?;
    tokio::time::pause();
    for _ in 0..4 {
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(
            inspect(&broker).await?.authorization_expires_at_unix,
            response.authorization_expires_at_unix
        );
    }
    tokio::time::advance(Duration::from_secs(11)).await;
    tokio::task::yield_now().await;
    tokio::time::resume();
    let expired = inspect(&broker).await?;
    assert_eq!(expired.authorization_expires_at_unix, 0);
    assert!(expired.policy.tcp_allow.is_empty());
    closed(&mut stream).await?;
    broker.shutdown().await
}

#[tokio::test]
async fn inventory_monotonic_expiry_rejects_same_revision_after_clock_stall() -> Result<()> {
    let mut inv = inventory(1);
    inv.expires_at_unix = inv.issued_at_unix + 2;
    let (broker, _) = fixture(config(), inv.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    broker
        .request(request(&broker, 1, policy(), inv.clone()))
        .await?;
    let mut stream = tunnel(&broker).await?;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
    assert!(
        broker
            .request(request(&broker, 2, policy(), inv))
            .await
            .is_err()
    );
    tokio::time::resume();
    closed(&mut stream).await?;
    broker.shutdown().await
}

#[tokio::test]
async fn original_monotonic_expiry_cannot_be_extended_by_fresh_renewals() -> Result<()> {
    let mut c = config();
    c.binding.expires_at_unix = now()? + 60;
    let initial = inventory(1);
    let (broker, _) = fixture(c, initial.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    broker
        .request(request(&broker, 1, policy(), initial))
        .await?;
    let mut stream = tunnel(&broker).await?;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(20)).await;
    broker
        .request(request(&broker, 2, policy(), inventory(2)))
        .await?;
    tokio::time::advance(Duration::from_secs(20)).await;
    broker
        .request(request(&broker, 3, policy(), inventory(3)))
        .await?;
    tokio::time::advance(Duration::from_secs(21)).await;
    assert!(
        broker
            .request(request(&broker, 4, policy(), inventory(4)))
            .await
            .is_err()
    );
    tokio::task::yield_now().await;
    tokio::time::resume();
    closed(&mut stream).await?;
    assert_eq!(inspect(&broker).await?.authorization_expires_at_unix, 0);
    broker.shutdown().await
}

#[tokio::test]
async fn inventory_can_only_add_denials_and_checks_every_dns_answer() -> Result<()> {
    let initial = inventory(1);
    let (broker, connects) =
        fixture(config(), initial.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    broker
        .request(request(&broker, 1, policy(), initial))
        .await?;
    let mut stream = tunnel(&broker).await?;
    let mut denied = inventory(2);
    denied.denied_cidrs.push("8.8.4.4/32".into());
    let blocked = broker
        .request(request(&broker, 2, policy(), denied))
        .await?;
    closed(&mut stream).await?;
    let retained = broker
        .request(request(&broker, 3, policy(), inventory(3)))
        .await?;
    assert_eq!(
        retained.effective_denied_sha256,
        blocked.effective_denied_sha256
    );
    let mut socket = TcpStream::connect(broker.local_addr()).await?;
    socket
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        .await?;
    let mut output = String::new();
    socket.read_to_string(&mut output).await?;
    assert!(!output.contains("200"));
    assert_eq!(connects.load(Ordering::SeqCst), 1);
    broker.shutdown().await?;
    let initial = inventory(1);
    let (broker, connects) = fixture(
        config(),
        initial.clone(),
        vec!["8.8.4.4:443".parse()?, "10.0.0.1:443".parse()?],
    )
    .await?;
    broker
        .request(request(&broker, 1, policy(), initial))
        .await?;
    let mut socket = TcpStream::connect(broker.local_addr()).await?;
    socket
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        .await?;
    let mut output = String::new();
    socket.read_to_string(&mut output).await?;
    assert!(!output.contains("200"));
    assert_eq!(connects.load(Ordering::SeqCst), 0);
    broker.shutdown().await
}

#[tokio::test]
async fn stale_or_changed_inventory_and_widening_leave_current_authority_unchanged() -> Result<()> {
    let mut inv = inventory(1);
    inv.expires_at_unix = inv.issued_at_unix + 30;
    let (broker, _) = fixture(config(), inv.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    broker
        .request(request(&broker, 1, policy(), inv.clone()))
        .await?;
    let mut altered = inv.clone();
    altered.expires_at_unix += 1;
    assert!(
        broker
            .request(request(&broker, 2, policy(), altered))
            .await
            .is_err()
    );
    let mut stale = inv.clone();
    stale.generation = 0;
    assert!(
        broker
            .request(request(&broker, 2, policy(), stale))
            .await
            .is_err()
    );
    let wider = NetworkPolicy {
        tcp_allow: vec![Endpoint {
            host: "foreign.example.com".into(),
            port: 443,
        }],
        ..Default::default()
    };
    assert!(
        broker
            .request(request(&broker, 2, wider, inv))
            .await
            .is_err()
    );
    assert_eq!(inspect(&broker).await?.generation, 2);
    echoed(&mut tunnel(&broker).await?).await?;
    broker.shutdown().await
}

#[tokio::test]
async fn stop_ack_and_cancellation_drain_before_any_fresh_authority() -> Result<()> {
    let initial = inventory(1);
    let (broker, _) = fixture(config(), initial.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    broker
        .request(request(&broker, 1, policy(), initial.clone()))
        .await?;
    let mut stream = tunnel(&broker).await?;
    let mut update =
        Box::pin(broker.request(request(&broker, 2, NetworkPolicy::default(), initial)));
    assert!(matches!(
        futures::poll!(&mut update),
        std::task::Poll::Pending
    ));
    drop(update);
    closed(&mut stream).await?;
    assert_eq!(inspect(&broker).await?.authorization_expires_at_unix, 0);
    broker
        .request(request(&broker, 2, policy(), inventory(2)))
        .await?;
    let mut stream = tunnel(&broker).await?;
    let response = broker
        .request(HostedControlRequest::Stop {
            binding: broker.config.binding.clone(),
            startup_epoch: broker.startup_epoch.clone(),
            expected_generation: 3,
            nonce: uuid::Uuid::new_v4().to_string(),
        })
        .await?;
    assert!(response.stopping);
    assert_eq!(response.active_connections, 0);
    closed(&mut stream).await?;
    assert!(
        broker
            .request(request(&broker, 4, policy(), inventory(3)))
            .await
            .is_err()
    );
    broker.shutdown().await
}

#[tokio::test]
async fn caller_disconnect_or_cancel_after_apply_before_ack_revokes() -> Result<()> {
    for abort in [false, true] {
        let initial = inventory(1);
        let (broker, _) = fixture(config(), initial.clone(), vec!["8.8.4.4:443".parse()?]).await?;
        let broker = Arc::new(broker);
        let (mut client, server) = tokio::io::duplex(1);
        let requested = request(&broker, 1, policy(), initial);
        let mut bytes = serde_json::to_vec(&requested)?;
        bytes.push(b'\n');
        let cloned = broker.clone();
        let task =
            tokio::spawn(
                async move { crate::network::guard::cli::connection(server, &cloned).await },
            );
        client.write_all(&bytes).await?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !broker.guard.active_at(now()?) {
                tokio::task::yield_now().await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        if abort {
            task.abort();
            let _ = task.await;
        } else {
            drop(client);
            assert!(task.await?.is_err());
        }
        assert!(!broker.guard.active_at(now()?));
        assert_eq!(inspect(&broker).await?.authorization_expires_at_unix, 0);
        Arc::try_unwrap(broker)
            .ok()
            .expect("no remaining control tasks")
            .shutdown()
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn invalid_identity_and_nonce_cannot_change_authorization() -> Result<()> {
    let initial = inventory(1);
    let (broker, _) = fixture(config(), initial.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    let mut wrong = request(&broker, 1, policy(), initial.clone());
    if let HostedControlRequest::Authorize { binding, .. } = &mut wrong {
        binding.launch_nonce = uuid::Uuid::new_v4().to_string();
    }
    assert!(broker.request(wrong).await.is_err());
    assert!(
        broker
            .snapshot(&format!("invalid-{}", uuid::Uuid::new_v4()))
            .await
            .is_err()
    );
    assert!(
        broker
            .request(HostedControlRequest::Ready {
                nonce: "bad".into()
            })
            .await
            .is_err()
    );
    let ready = broker
        .request(HostedControlRequest::Ready {
            nonce: uuid::Uuid::new_v4().to_string(),
        })
        .await?;
    assert_eq!(ready.generation, 1);
    broker
        .request(request(&broker, 1, policy(), initial))
        .await?;
    let mut wrong = HostedControlRequest::Inspect {
        binding: broker.config.binding.clone(),
        startup_epoch: broker.startup_epoch.clone(),
        expected_generation: 2,
        nonce: uuid::Uuid::new_v4().to_string(),
    };
    let valid = broker.request(wrong.clone()).await?;
    assert_eq!(valid.generation, 2);
    if let HostedControlRequest::Inspect {
        expected_generation,
        ..
    } = &mut wrong
    {
        *expected_generation = 1;
    }
    assert!(broker.request(wrong).await.is_err());
    echoed(&mut tunnel(&broker).await?).await?;
    broker.shutdown().await
}

#[tokio::test]
async fn guarded_dns_rejects_empty_excessive_wrong_port_and_protected_suffix() -> Result<()> {
    for answers in [
        vec![],
        vec!["8.8.4.4:443".parse()?; 257],
        vec!["8.8.4.4:444".parse()?],
    ] {
        let initial = inventory(1);
        let (broker, connects) = fixture(config(), initial.clone(), answers).await?;
        broker
            .request(request(&broker, 1, policy(), initial))
            .await?;
        let connector = HostedConnector {
            guard: broker.guard.clone(),
            inner: Arc::new(FakeConnector {
                answers: vec!["8.8.4.4:443".parse()?],
                connects: connects.clone(),
            }),
        };
        assert!(
            connector
                .resolve("service.internal.example.com", 443)
                .await
                .is_err()
        );
        let mut socket = TcpStream::connect(broker.local_addr()).await?;
        socket
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await?;
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await?;
        assert_eq!(connects.load(Ordering::SeqCst), 0);
        broker.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn poisoned_guard_revokes_authority_without_panicking_control() -> Result<()> {
    let initial = inventory(1);
    let (broker, _) = fixture(config(), initial.clone(), vec!["8.8.4.4:443".parse()?]).await?;
    broker
        .request(request(&broker, 1, policy(), initial))
        .await?;
    let cloned = broker.guard.clone();
    let _ = std::thread::spawn(move || {
        let _locked = cloned.access.write().expect("not poisoned");
        panic!("fixture lock poison");
    })
    .join();
    assert!(!broker.guard.active_at(now()?));
    assert!(broker.guard.check(Some("8.8.4.4".parse()?)).is_err());
    broker.guard.revoke();
    assert_eq!(inspect(&broker).await?.authorization_expires_at_unix, 0);
    broker.shutdown().await
}
