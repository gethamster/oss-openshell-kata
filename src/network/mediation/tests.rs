use super::*;
use crate::network::{
    Endpoint, InspectedEndpoint, NetworkPolicy,
    broker::{BrokerHandle, Connector, Stream, bind_with_connector},
};
use crate::proto::openshell::v1::{
    GetSandboxProviderEnvironmentResponse as AdapterSnapshot, StaticCredentialBinding,
    StaticCredentialEndpointBinding,
};
use futures::future::BoxFuture;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const SANDBOX: &str = "sandbox-credential-fixture";
const HOST: &str = "api.anthropic.test";
const OTHER: &str = "api.github.test";
const SECRET: &str = "sk-ant-oat01-REAL-CREDENTIAL-NEVER-IN-GUEST";

/// The adapter encodes its own generated snapshot type; the broker decodes it
/// with OpenShell's, so this also proves wire compatibility.
fn snapshot(revision: u64, secret: Option<&str>) -> Vec<u8> {
    let mut response = AdapterSnapshot {
        provider_env_revision: revision,
        supports_stable_placeholder_environment_keys: true,
        ..Default::default()
    };
    if let Some(secret) = secret {
        response
            .environment
            .insert("CLAUDE_CODE_OAUTH_TOKEN".into(), secret.into());
        response.static_credential_bindings.insert(
            "CLAUDE_CODE_OAUTH_TOKEN".into(),
            StaticCredentialBinding {
                endpoints: vec![StaticCredentialEndpointBinding {
                    host: HOST.into(),
                    port: 443,
                    path: "/**".into(),
                }],
                credential_identity: "claude-sub-0123456789ab:oauth_token".into(),
                workload_credential_handle: String::new(),
            },
        );
    }
    response.encode_to_vec()
}

/// A local TLS origin that records every request head it receives.
struct Origin {
    address: SocketAddr,
    ca: String,
    heads: Arc<Mutex<Vec<String>>>,
}
async fn origin() -> Result<Origin> {
    let ca = SandboxCa::generate().map_err(|_| anyhow!("origin CA"))?;
    let pem = ca.cert_pem().to_owned();
    let tls = Arc::new(ProxyTlsState::new(
        CertCache::new(ca),
        build_upstream_client_config("").map_err(|_| anyhow!("roots"))?,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let heads = Arc::new(Mutex::new(Vec::new()));
    let recorded = heads.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let tls = tls.clone();
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = tls_terminate_client(stream, &tls, HOST).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let mut body = vec![0; length];
                let _ = stream.read_exact(&mut body).await;
                recorded.lock().expect("origin lock").push(head);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok(Origin {
        address,
        ca: pem,
        heads,
    })
}

/// Resolves every name to a public address and dials the local origin.
struct OriginConnector {
    route: SocketAddr,
    dials: AtomicUsize,
}
impl Connector for OriginConnector {
    fn resolve<'a>(&'a self, _host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move { Ok(vec![SocketAddr::new("93.184.216.34".parse()?, port)]) })
    }
    fn connect(&self, _address: SocketAddr) -> BoxFuture<'_, Result<Stream>> {
        Box::pin(async move {
            self.dials.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(TcpStream::connect(self.route).await?) as Stream)
        })
    }
}

struct Fixture {
    broker: BrokerHandle,
    origin: Origin,
    connector: Arc<OriginConnector>,
    guest_ca: String,
}
async fn fixture(guest: IpAddr, access: RestAccess) -> Result<Fixture> {
    let origin = origin().await?;
    let ca = SandboxCa::generate().map_err(|_| anyhow!("sandbox CA"))?;
    let guest_ca = ca.cert_pem().to_owned();
    let upstream = build_upstream_client_config(&origin.ca).map_err(|_| anyhow!("roots"))?;
    let mediation = Mediation::with_upstream(SANDBOX.into(), guest, Some(ca), upstream)?;
    let connector = Arc::new(OriginConnector {
        route: origin.address,
        dials: AtomicUsize::new(0),
    });
    let policy = NetworkPolicy {
        tcp_allow: [HOST, OTHER]
            .into_iter()
            .map(|host| Endpoint {
                host: host.into(),
                port: 443,
            })
            .collect(),
        tls_inspect: [HOST, OTHER]
            .into_iter()
            .map(|host| InspectedEndpoint {
                host: host.into(),
                port: 443,
                access,
            })
            .collect(),
        ..Default::default()
    };
    let broker = bind_with_connector(
        "127.0.0.1:0".parse()?,
        policy,
        connector.clone(),
        Some(mediation),
    )
    .await?;
    Ok(Fixture {
        broker,
        origin,
        connector,
        guest_ca,
    })
}

/// Act as a guest process: CONNECT, trust the sandbox CA, send one request.
async fn guest_request(fixture: &Fixture, host: &str, request: &str) -> Result<String> {
    let mut stream = TcpStream::connect(fixture.broker.local_addr()).await?;
    stream
        .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await?;
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    if !head.starts_with("HTTP/1.1 200") {
        return Ok(head);
    }
    let trust = build_upstream_client_config(&fixture.guest_ca).map_err(|_| anyhow!("roots"))?;
    let mut tls = tls_connect_upstream(stream, host, &trust)
        .await
        .map_err(|error| anyhow!("guest TLS: {error}"))?;
    tls.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

fn placeholder(material: &GuestMaterial) -> String {
    material.environment["CLAUDE_CODE_OAUTH_TOKEN"].clone()
}

#[test]
fn guest_material_holds_placeholders_and_public_trust_only() -> Result<()> {
    let ca = SandboxCa::generate().map_err(|_| anyhow!("CA"))?;
    let mediation = Mediation::new(SANDBOX.into(), "10.0.0.2".parse()?, Some(ca))?;
    let material = mediation.install(&snapshot(7, Some(SECRET)));
    assert_eq!(material.withheld, None);
    assert_eq!(material.provider_env_revision, 7);
    let token = placeholder(&material);
    assert!(token.starts_with("openshell:resolve:env:"), "{token}");
    let rendered = serde_json::to_string(&material)?;
    assert!(!rendered.contains(SECRET) && !rendered.contains("PRIVATE KEY"));
    let environment = material.guest_environment();
    assert!(environment.iter().all(|(_, value)| !value.contains(SECRET)));
    assert!(environment.contains(&("NODE_EXTRA_CA_CERTS".into(), GUEST_CA_PATH.into())));
    assert!(environment.contains(&("GIT_SSL_CAINFO".into(), GUEST_BUNDLE_PATH.into())));
    // The resolver stays scoped to the provider's bound endpoint.
    assert_eq!(
        mediation
            .credentials
            .resolver_for_endpoint(HOST, 443, "/v1/messages")
            .and_then(|resolver| resolver.resolve_placeholder(&token).map(str::to_owned))
            .as_deref(),
        Some(SECRET)
    );
    assert!(
        mediation
            .credentials
            .resolver_for_endpoint(OTHER, 443, "/")
            .and_then(|resolver| resolver.resolve_placeholder(&token).map(str::to_owned))
            .is_none()
    );
    Ok(())
}

#[test]
fn unusable_snapshots_revoke_installed_credentials() -> Result<()> {
    let mediation = Mediation::new(SANDBOX.into(), "10.0.0.2".parse()?, None)?;
    let token = placeholder(&mediation.install(&snapshot(1, Some(SECRET))));
    let resolves = |mediation: &Mediation| {
        mediation
            .credentials
            .resolver_for_endpoint(HOST, 443, "/")
            .and_then(|resolver| resolver.resolve_placeholder(&token).map(str::to_owned))
            .is_some()
    };
    assert!(resolves(&mediation));
    let mut withheld = AdapterSnapshot::decode(snapshot(2, Some(SECRET)).as_slice())?;
    withheld.readiness_reason = 1;
    let material = mediation.install(&withheld.encode_to_vec());
    assert!(material.withheld.is_some() && material.environment.is_empty());
    assert!(
        !resolves(&mediation),
        "withheld snapshot revokes old placeholders"
    );

    mediation.install(&snapshot(3, Some(SECRET)));
    let mut unbound = AdapterSnapshot::decode(snapshot(4, Some(SECRET)).as_slice())?;
    unbound.static_credential_bindings.clear();
    let material = mediation.install(&unbound.encode_to_vec());
    assert!(
        material.withheld.is_some(),
        "unbound credentials are refused"
    );
    assert!(!format!("{material:?}").contains(SECRET));

    mediation.install(&snapshot(5, Some(SECRET)));
    let material = mediation.install(b"\xffnot a snapshot");
    assert!(material.withheld.is_some());
    assert!(material.ca_certificate.is_none(), "no CA, no inspection");

    mediation.install(&snapshot(6, Some(SECRET)));
    mediation.revoke();
    assert!(!resolves(&mediation));
    Ok(())
}

#[test]
fn every_sandbox_gets_its_own_ca_and_the_key_never_reaches_the_guest() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let node = tempfile::tempdir()?;
    let first = generate_ca(&node.path().join("first/tls"))?;
    let second = generate_ca(&node.path().join("second/tls"))?;
    assert_ne!(first, second);
    let key = node
        .path()
        .join(format!("first/tls/{CA_KEY_CREDENTIAL}.pem"));
    assert_eq!(std::fs::metadata(&key)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(node.path().join("first/tls"))?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let loaded = Mediation::load_ca(Some(&credentials(&node.path().join("first/tls"))?))?
        .context("CA credentials")?;
    assert_eq!(loaded.cert_pem(), first);

    let guest = tempfile::tempdir()?;
    std::fs::create_dir_all(guest.path().join("etc/ssl/certs"))?;
    std::fs::write(
        guest.path().join("etc/ssl/certs/ca-certificates.crt"),
        "-----BEGIN CERTIFICATE-----\nSYSTEM\n-----END CERTIFICATE-----",
    )?;
    install_guest_trust(guest.path(), &first)?;
    let ca = std::fs::read_to_string(guest.path().join("etc/openshell-tls/openshell-ca.pem"))?;
    let bundle = std::fs::read_to_string(guest.path().join("etc/openshell-tls/ca-bundle.pem"))?;
    assert_eq!(ca, first);
    assert!(bundle.starts_with("-----BEGIN CERTIFICATE-----\nSYSTEM") && bundle.ends_with(&first));
    for entry in walk(guest.path())? {
        let contents = std::fs::read(&entry)?;
        assert!(
            !String::from_utf8_lossy(&contents).contains("PRIVATE KEY"),
            "{} holds key material",
            entry.display()
        );
    }
    assert!(install_guest_trust(guest.path(), "not a certificate").is_err());
    Ok(())
}

#[test]
fn guest_trust_never_follows_links_out_of_the_guest_root() -> Result<()> {
    let host = tempfile::tempdir()?;
    let host_secret = host.path().join("host-secret");
    std::fs::write(&host_secret, "HOST-ONLY-CONTENT")?;
    let guest = tempfile::tempdir()?;
    std::fs::create_dir_all(guest.path().join("etc/ssl/certs"))?;
    std::os::unix::fs::symlink(
        &host_secret,
        guest.path().join("etc/ssl/certs/ca-certificates.crt"),
    )?;
    let certificate = SandboxCa::generate()
        .map_err(|_| anyhow!("CA"))?
        .cert_pem()
        .to_owned();
    install_guest_trust(guest.path(), &certificate)?;
    let bundle = std::fs::read_to_string(guest.path().join("etc/openshell-tls/ca-bundle.pem"))?;
    assert!(!bundle.contains("HOST-ONLY-CONTENT"));
    std::fs::remove_dir_all(guest.path().join("etc"))?;
    std::os::unix::fs::symlink(host.path(), guest.path().join("etc"))?;
    assert!(install_guest_trust(guest.path(), &certificate).is_err());
    assert!(!host.path().join("openshell-tls").exists());
    Ok(())
}

fn credentials(directory: &Path) -> Result<PathBuf> {
    // systemd LoadCredential names files by credential name, not by path.
    let loaded = directory.parent().context("parent")?.join("credentials");
    std::fs::create_dir_all(&loaded)?;
    for name in [CA_KEY_CREDENTIAL, CA_CERT_CREDENTIAL] {
        std::fs::copy(directory.join(format!("{name}.pem")), loaded.join(name))?;
    }
    Ok(loaded)
}

fn walk(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            files.extend(walk(&path)?);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

use std::path::PathBuf;

/// Logs written while the broker handled credentials.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn broker_substitutes_placeholders_only_on_the_verified_upstream() -> Result<()> {
    let logs = Captured::default();
    let writer = logs.clone();
    let _logging = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish(),
    );
    let fixture = fixture("127.0.0.1".parse()?, RestAccess::ReadWrite).await?;
    let mediation = fixture.broker.mediation().context("mediation")?;
    let token = placeholder(&mediation.install(&snapshot(1, Some(SECRET))));

    let response = guest_request(
        &fixture,
        HOST,
        &format!(
            "POST /v1/messages HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\nContent-Length: 4\r\n\r\nping"
        ),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("ok"));
    assert!(
        !response.contains(SECRET),
        "the guest never sees the credential"
    );
    let heads = fixture.origin.heads.lock().expect("origin lock").clone();
    assert_eq!(heads.len(), 1);
    assert!(
        heads[0].contains(&format!("Authorization: Bearer {SECRET}")),
        "{}",
        heads[0]
    );
    assert!(heads[0].contains("Connection: close") && !heads[0].contains(&token));

    // A placeholder sent to an endpoint its credential is not bound to.
    let response = guest_request(
        &fixture,
        OTHER,
        &format!("GET / HTTP/1.1\r\nHost: {OTHER}\r\nAuthorization: Bearer {token}\r\n\r\n"),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");

    // The access preset applies before any credential is resolved.
    let response = guest_request(
        &fixture,
        HOST,
        &format!(
            "DELETE /v1/files/1 HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\n\r\n"
        ),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");

    // Host must name the tunnel destination.
    let response = guest_request(
        &fixture,
        HOST,
        &format!("GET / HTTP/1.1\r\nHost: {OTHER}\r\nAuthorization: Bearer {token}\r\n\r\n"),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");

    // Revoked or absent credentials fail closed instead of leaking placeholders.
    mediation.install(&snapshot(2, None));
    let response = guest_request(
        &fixture,
        HOST,
        &format!(
            "GET /v1/models HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\n\r\n"
        ),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    mediation.install(&snapshot(3, Some(SECRET)));
    let token = placeholder(&mediation.install(&snapshot(3, Some(SECRET))));
    fixture.broker.deny_and_drain().await?;
    let response = guest_request(
        &fixture,
        HOST,
        &format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\n\r\n"),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert_eq!(fixture.origin.heads.lock().expect("origin lock").len(), 1);
    assert!(fixture.connector.dials.load(Ordering::Relaxed) >= 1);

    let logs = String::from_utf8(logs.0.lock().expect("log lock").clone())?;
    assert!(!logs.contains(SECRET), "credentials never reach logs");
    Ok(())
}

#[tokio::test]
async fn inspected_destinations_admit_only_the_fenced_guest() -> Result<()> {
    let fixture = fixture("10.200.0.2".parse()?, RestAccess::Full).await?;
    let mediation = fixture.broker.mediation().context("mediation")?;
    let token = placeholder(&mediation.install(&snapshot(1, Some(SECRET))));
    let response = guest_request(
        &fixture,
        HOST,
        &format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {token}\r\n\r\n"),
    )
    .await?;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert_eq!(fixture.connector.dials.load(Ordering::Relaxed), 0);
    Ok(())
}
