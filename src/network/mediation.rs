//! Host-side provider credential injection for inspected REST destinations.
//!
//! The guest receives only OpenShell placeholders and the public certificate of
//! a per-sandbox CA. This broker terminates the guest's TLS with that CA,
//! applies the endpoint's REST access preset, substitutes placeholders with
//! OpenShell's endpoint-bound resolver, and originates verified TLS upstream.
//! Real credentials and the CA private key never leave this host process.
use super::{Inspection, proxy};
use anyhow::{Context, Result, anyhow, bail};
use openshell_core::{
    proto::v1::GetSandboxProviderEnvironmentResponse,
    provider_credentials::ProviderCredentialState, secrets::rewrite_http_header_block,
};
use openshell_supervisor_network::l7::tls::{
    CertCache, ProxyTlsState, SandboxCa, build_upstream_client_config, read_system_ca_bundle,
    tls_connect_upstream, tls_terminate_client,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

/// Upper bound of one serialized provider snapshot.
pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;
/// Guest trust files, in the native supervisor's layout and file names.
pub const GUEST_CA_PATH: &str = "/etc/openshell-tls/openshell-ca.pem";
pub const GUEST_BUNDLE_PATH: &str = "/etc/openshell-tls/ca-bundle.pem";
/// systemd credential names that carry the CA into the broker unit.
pub const CA_KEY_CREDENTIAL: &str = "proxy-ca-key";
pub const CA_CERT_CREDENTIAL: &str = "proxy-ca-cert";

/// The complete workload-facing result of one provider snapshot.
///
/// `environment` holds OpenShell placeholders and non-secret provider
/// configuration only; `ca_certificate` is public.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestMaterial {
    pub sandbox_id: String,
    pub provider_env_revision: u64,
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub ca_certificate: Option<String>,
    /// Why credentials were revoked instead of installed, if they were.
    #[serde(default)]
    pub withheld: Option<String>,
}

impl GuestMaterial {
    /// Environment for guest commands: placeholders plus TLS trust variables
    /// matching the native supervisor's child environment.
    pub fn guest_environment(&self) -> Vec<(String, String)> {
        let mut environment: Vec<_> = self
            .environment
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if self.ca_certificate.is_some() {
            for (key, value) in [
                ("NODE_EXTRA_CA_CERTS", GUEST_CA_PATH),
                ("DENO_CERT", GUEST_CA_PATH),
                ("SSL_CERT_FILE", GUEST_BUNDLE_PATH),
                ("REQUESTS_CA_BUNDLE", GUEST_BUNDLE_PATH),
                ("CURL_CA_BUNDLE", GUEST_BUNDLE_PATH),
                ("GIT_SSL_CAINFO", GUEST_BUNDLE_PATH),
            ] {
                environment.retain(|(name, _)| name != key);
                environment.push((key.into(), value.into()));
            }
        }
        environment
    }
}

/// Provider credentials and TLS identity for exactly one sandbox broker.
pub struct Mediation {
    sandbox_id: String,
    guest_ip: IpAddr,
    tls: Option<(ProxyTlsState, String)>,
    credentials: ProviderCredentialState,
    revision: Mutex<u64>,
    /// Ends every relayed WebSocket when credentials are revoked.
    upgraded: Mutex<CancellationToken>,
}

impl Mediation {
    /// Bind mediation to one sandbox and its fenced guest address. Without a
    /// CA, credentials can be installed but no destination is inspected.
    pub fn new(sandbox_id: String, guest_ip: IpAddr, ca: Option<SandboxCa>) -> Result<Self> {
        let upstream = build_upstream_client_config(&read_system_ca_bundle())
            .map_err(|error| anyhow!("upstream TLS roots unavailable: {error}"))?;
        Self::with_upstream(sandbox_id, guest_ip, ca, upstream)
    }

    pub(crate) fn with_upstream(
        sandbox_id: String,
        guest_ip: IpAddr,
        ca: Option<SandboxCa>,
        upstream: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        crate::config::SandboxId::parse(&sandbox_id)?;
        let tls = ca.map(|ca| {
            let certificate = ca.cert_pem().to_owned();
            (
                ProxyTlsState::new(CertCache::new(ca), upstream),
                certificate,
            )
        });
        Ok(Self {
            sandbox_id,
            guest_ip,
            tls,
            credentials: ProviderCredentialState::from_environment(
                0,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ),
            revision: Mutex::new(0),
            upgraded: Mutex::new(CancellationToken::new()),
        })
    }

    /// Load the CA delivered as systemd credentials, if this unit has them.
    pub fn load_ca(directory: Option<&Path>) -> Result<Option<SandboxCa>> {
        let Some(directory) = directory else {
            return Ok(None);
        };
        let key = directory.join(CA_KEY_CREDENTIAL);
        let certificate = directory.join(CA_CERT_CREDENTIAL);
        if !key.exists() && !certificate.exists() {
            return Ok(None);
        }
        let key = std::fs::read_to_string(key).context("reading proxy CA key credential")?;
        let certificate =
            std::fs::read_to_string(certificate).context("reading proxy CA certificate")?;
        SandboxCa::from_pem(&certificate, &key)
            .map(Some)
            .map_err(|_| anyhow!("invalid proxy CA credentials"))
    }

    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    /// Whether a connection originates from this sandbox's fenced guest.
    pub fn admits_peer(&self, peer: IpAddr) -> bool {
        peer == self.guest_ip
    }

    pub fn inspects(&self) -> bool {
        self.tls.is_some()
    }

    /// Install one gateway provider snapshot (protobuf
    /// `GetSandboxProviderEnvironmentResponse`). An unusable snapshot revokes
    /// every installed credential and reports why, without echoing values.
    pub fn install(&self, snapshot: &[u8]) -> GuestMaterial {
        let mut revision = self
            .revision
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = self.credential_names();
        match self.prepare(snapshot) {
            Ok(installed) => {
                *revision = installed;
                // A refreshed credential keeps its sockets; a removed one does not.
                if !before.is_subset(&self.credential_names()) {
                    self.close_upgraded();
                }
                self.material(installed, None)
            }
            Err(error) => {
                self.credentials
                    .revoke_static_provider_environment(self.credentials.revision());
                *revision = 0;
                self.close_upgraded();
                self.material(0, Some(error.to_string()))
            }
        }
    }

    /// Remove every installed credential; later requests fail closed.
    pub fn revoke(&self) {
        let mut revision = self
            .revision
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.credentials
            .revoke_static_provider_environment(self.credentials.revision());
        *revision = 0;
        self.close_upgraded();
    }

    fn credential_names(&self) -> BTreeSet<String> {
        self.environment()
            .map(|environment| environment.into_keys().collect())
            .unwrap_or_default()
    }

    /// A relayed WebSocket was authorized by a credential in its handshake,
    /// so none outlives a revocation or the removal of a credential.
    fn close_upgraded(&self) {
        let mut upgraded = self
            .upgraded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *upgraded).cancel();
    }

    fn prepare(&self, snapshot: &[u8]) -> Result<u64> {
        if snapshot.len() > MAX_SNAPSHOT_BYTES {
            bail!("provider snapshot exceeds its size limit");
        }
        // Decoding errors never include field values.
        let response = GetSandboxProviderEnvironmentResponse::decode(snapshot)
            .map_err(|_| anyhow!("invalid provider snapshot"))?;
        if response.readiness_reason != 0 {
            bail!("gateway withheld provider credentials");
        }
        if !response.dynamic_credentials.is_empty() {
            bail!("dynamic provider credentials are unsupported in a VM");
        }
        if !response.files.is_empty() {
            bail!("provider-managed guest files are unsupported in a VM");
        }
        if !response.supports_stable_placeholder_environment_keys
            && (self.credentials.requires_stable_placeholders()
                || !response.stable_placeholder_environment_keys.is_empty())
        {
            bail!("gateway does not support the required stable credential placeholders");
        }
        let mut expirations = HashMap::new();
        for (name, time) in &response.credential_expiration_times {
            if !(0..1_000_000_000).contains(&time.nanos) {
                bail!("invalid credential expiration time");
            }
            let millis = time
                .seconds
                .checked_mul(1000)
                .and_then(|value| value.checked_add(i64::from(time.nanos / 1_000_000)))
                .context("invalid credential expiration time")?;
            expirations.insert(name.clone(), millis);
        }
        let secrets: Vec<String> = response
            .environment
            .iter()
            .filter(|(key, _)| !response.non_secret_environment_keys.contains(key))
            .map(|(_, value)| value.clone())
            .collect();
        let revision = response.provider_env_revision;
        self.credentials
            .install_bound_environment_with_stable_placeholders(
                revision,
                response.environment,
                expirations,
                HashMap::new(),
                response.static_credential_bindings,
                response.non_secret_environment_keys,
                response.stable_placeholder_environment_keys,
            )
            .map_err(|_| anyhow!("invalid provider credential bindings"))?;
        let environment = self.environment()?;
        // Defense in depth: no credential value may reach the guest.
        if environment.values().any(|value| {
            secrets
                .iter()
                .any(|secret| !secret.is_empty() && value.contains(secret.as_str()))
        }) {
            bail!("provider snapshot would expose a credential to the guest");
        }
        Ok(revision)
    }

    fn environment(&self) -> Result<BTreeMap<String, String>> {
        let snapshot = self
            .credentials
            .child_environment_snapshot()
            .map_err(|_| anyhow!("provider credential state unavailable"))?;
        for key in snapshot.environment.keys() {
            if !valid_environment_name(key) {
                bail!("provider environment name is not a portable variable name");
            }
        }
        Ok(snapshot.environment.into_iter().collect())
    }

    fn material(&self, revision: u64, withheld: Option<String>) -> GuestMaterial {
        let environment = if withheld.is_some() {
            BTreeMap::new()
        } else {
            self.environment().unwrap_or_default()
        };
        GuestMaterial {
            sandbox_id: self.sandbox_id.clone(),
            provider_env_revision: revision,
            environment,
            ca_certificate: self.tls.as_ref().map(|(_, pem)| pem.clone()),
            withheld,
        }
    }

    /// Serve one inspected HTTPS request on an established CONNECT tunnel.
    ///
    /// The broker reads and rewrites the request head only; a request body is
    /// relayed unread. A WebSocket upgrade is admitted only where the policy
    /// sets `allow_uninspected_credentials`: after the origin answers `101`
    /// the tunnel carries frames in both directions, unread, until either
    /// side closes or the credentials are revoked.
    pub(super) async fn relay<C, U>(
        &self,
        client: C,
        upstream: U,
        host: &str,
        port: u16,
        inspection: Inspection,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let (tls, _) = self
            .tls
            .as_ref()
            .context("TLS inspection is not configured")?;
        let client = tokio::time::timeout(
            Duration::from_secs(15),
            tls_terminate_client(client, tls, host),
        )
        .await
        .context("guest TLS handshake timed out")?
        .map_err(|_| anyhow!("guest TLS handshake failed"))?;
        let mut client = BufReader::new(client);
        let request = match tokio::time::timeout(
            Duration::from_secs(30),
            proxy::read_inspected_head(
                &mut client,
                host,
                port,
                inspection.allow_uninspected_credentials,
            ),
        )
        .await
        {
            Ok(Ok(request)) => request,
            _ => return respond(&mut client, "400 Bad Request").await,
        };
        // A WebSocket carries client messages, so it needs a preset that
        // admits a request body.
        if !inspection.access.allows(&request.method)
            || (request.upgrade && !inspection.access.allows("POST"))
        {
            tracing::info!(%host, port, method=%request.method, "inspected request denied by access preset");
            return respond(&mut client, "403 Forbidden").await;
        }
        // Taken before the credential is resolved, so a revocation at any
        // later point ends the WebSocket this request may open.
        let revoked = self
            .upgraded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let resolver = self
            .credentials
            .resolver_for_endpoint(host, port, &request.target);
        let Ok(rewritten) = rewrite_http_header_block(&request.forward, resolver.as_deref()) else {
            tracing::info!(%host, port, "request carries a credential placeholder unavailable at this endpoint");
            return respond(&mut client, "403 Forbidden").await;
        };
        // An origin echoes the subprotocol it selects in its `101`, which the
        // guest reads: a credential must never be substituted into it.
        if request.upgrade
            && websocket_fields(&request.forward) != websocket_fields(&rewritten.rewritten)
        {
            tracing::info!(%host, port, "upgrade carries a credential placeholder in a WebSocket field");
            return respond(&mut client, "403 Forbidden").await;
        }
        let upstream = match tokio::time::timeout(
            Duration::from_secs(15),
            tls_connect_upstream(upstream, host, tls.upstream_config()),
        )
        .await
        {
            Ok(Ok(upstream)) => upstream,
            _ => return respond(&mut client, "502 Bad Gateway").await,
        };
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
        upstream_write.write_all(&rewritten.rewritten).await?;
        drop(rewritten);
        let (client_read, mut client_write) = tokio::io::split(client);
        // The inner reader still serves bytes it buffered while reading the head.
        let mut client_read = BufReader::new(client_read);
        if request.upgrade {
            let mut upstream_read = BufReader::new(upstream_read);
            let response = match tokio::time::timeout(
                Duration::from_secs(30),
                proxy::read_upgrade_response(&mut upstream_read),
            )
            .await
            {
                Ok(Ok(response)) => response,
                _ => return respond(&mut client_write, "502 Bad Gateway").await,
            };
            client_write.write_all(&response.head).await?;
            match response.answer {
                proxy::UpgradeAnswer::Switched => {
                    tracing::info!(%host, port, "inspected destination upgraded to WebSocket");
                    // A WebSocket ends for both sides when either one closes.
                    tokio::select! {
                        biased;
                        () = revoked.cancelled() => {}
                        result = tokio::io::copy(&mut client_read, &mut upstream_write) => { result?; }
                        result = tokio::io::copy(&mut upstream_read, &mut client_write) => { result?; }
                    }
                    let _ = upstream_write.shutdown().await;
                }
                // The origin kept HTTP: the guest gets this one response and no
                // further request reaches the origin on this tunnel.
                proxy::UpgradeAnswer::Refused(body) => {
                    let forward = async {
                        match body {
                            Some(body) => {
                                proxy::forward_body(&mut upstream_read, &mut client_write, body)
                                    .await
                            }
                            None => tokio::io::copy(&mut upstream_read, &mut client_write)
                                .await
                                .map(drop)
                                .map_err(Into::into),
                        }
                    };
                    tokio::time::timeout(Duration::from_secs(30), forward)
                        .await
                        .context("origin response timed out")??;
                }
            }
            client_write.shutdown().await?;
            return Ok(());
        }
        {
            let body = proxy::forward_body(&mut client_read, &mut upstream_write, request.body);
            // The forwarded request asks the origin to close after its response.
            let response = tokio::io::copy(&mut upstream_read, &mut client_write);
            tokio::pin!(body, response);
            tokio::select! {
                result = &mut response => { result?; }
                result = &mut body => { result?; response.await?; }
            }
        }
        client_write.shutdown().await?;
        Ok(())
    }
}

/// The `Sec-WebSocket-*` lines of a request head.
fn websocket_fields(head: &[u8]) -> Vec<&[u8]> {
    const PREFIX: &[u8] = b"sec-websocket-";
    head.split(|byte| *byte == b'\n')
        .filter(|line| {
            line.len() >= PREFIX.len() && line[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
        })
        .collect()
}

async fn respond(client: &mut (impl AsyncWrite + Unpin), status: &str) -> Result<()> {
    client
        .write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    client.shutdown().await?;
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Generate a per-sandbox CA into a root-only directory on the node.
///
/// # Errors
/// Fails when the directory cannot be made private or the files written.
pub fn generate_ca(directory: &Path) -> Result<String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    let ca = SandboxCa::generate().map_err(|_| anyhow!("proxy CA generation failed"))?;
    let key = ca
        .private_key_pem()
        .map_err(|_| anyhow!("proxy CA key serialization failed"))?;
    for (name, contents, mode) in [
        (CA_KEY_CREDENTIAL, key.as_str(), 0o600),
        (CA_CERT_CREDENTIAL, ca.cert_pem(), 0o644),
    ] {
        let path = directory.join(format!("{name}.pem"));
        let temporary = directory.join(format!(".{name}.tmp"));
        let _ = std::fs::remove_file(&temporary);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, contents.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)?;
    }
    Ok(ca.cert_pem().to_owned())
}

/// Install the public CA and a combined bundle into a mounted guest root.
///
/// The root is untrusted content: every access stays beneath it.
///
/// # Errors
/// Fails on an invalid certificate or a path that escapes the guest root.
pub fn install_guest_trust(root: &Path, certificate: &str) -> Result<()> {
    use cap_std::fs::{Dir, DirBuilder, OpenOptions, Permissions};
    use cap_std::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::io::{Read as _, Write as _};
    if !certificate.starts_with("-----BEGIN CERTIFICATE-----")
        || certificate.matches("BEGIN CERTIFICATE").count() != 1
    {
        bail!("guest trust requires exactly one PEM certificate");
    }
    let root = Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    let mut system = String::new();
    for path in [
        "etc/ssl/certs/ca-certificates.crt",
        "etc/pki/tls/certs/ca-bundle.crt",
        "etc/ssl/ca-bundle.pem",
        "etc/ssl/cert.pem",
    ] {
        let Ok(file) = root.open(path) else {
            continue;
        };
        let mut contents = String::new();
        file.take(16 * 1024 * 1024).read_to_string(&mut contents)?;
        if !contents.trim().is_empty() {
            system = contents;
            break;
        }
    }
    if !system.is_empty() && !system.ends_with('\n') {
        system.push('\n');
    }
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o755);
    root.create_dir_with("etc/openshell-tls", &builder)?;
    for (path, contents) in [
        ("etc/openshell-tls/openshell-ca.pem", certificate.to_owned()),
        (
            "etc/openshell-tls/ca-bundle.pem",
            format!("{system}{certificate}"),
        ),
    ] {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o644);
        let mut file = root.open_with(path, &options)?;
        file.write_all(contents.as_bytes())?;
        file.set_permissions(Permissions::from_mode(0o644))?;
        file.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
