mod credentials;

use crate::network::mediation::GuestMaterial;
use crate::{
    admission,
    config::{Config, RuntimeProfile, SandboxId, shell_quote},
    guest::Guest,
    proto::openshell::{compute::v1 as c, sandbox::v1 as s, v1 as o},
    ssh,
};
use anyhow::{Context, Result, bail};
use prost::Message as _;
use serde::Deserialize;
use sha2::Digest as _;
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    sync::{Mutex, broadcast, mpsc, watch},
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Closing,
    Ready,
    Stopped,
    Stopping,
    Deleting,
    Failed,
}
#[derive(Clone, Debug)]
pub enum Output {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(u32),
}

async fn cancel_before_cleanup(cancel: &CancellationToken, cleanup: impl Future<Output = ()>) {
    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), cleanup).await;
}

async fn bounded_send<T: Send>(
    sender: &mpsc::Sender<T>,
    message: T,
    cancel: &CancellationToken,
) -> Result<()> {
    tokio::select! {
        () = cancel.cancelled() => bail!("runtime access cancelled"),
        result = tokio::time::timeout(Duration::from_secs(1), sender.send(message)) => {
            result.context("supervisor heartbeat queue deadline exceeded")?.map_err(|_| anyhow::anyhow!("supervisor heartbeat queue closed"))
        }
    }
}

fn mark_failed(phase: &watch::Sender<Phase>) -> bool {
    phase.send_if_modified(|current| {
        if matches!(current, Phase::Starting | Phase::Ready) {
            *current = Phase::Failed;
            true
        } else {
            false
        }
    })
}

/// A buffer holding credential material, cleared when dropped.
struct Zeroizing(Vec<u8>);
impl Drop for Zeroizing {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|byte| *byte = 0);
        std::hint::black_box(&self.0);
    }
}

struct GatewayCredential {
    token: String,
    session_id: Option<String>,
}

fn refreshed_token(
    response: o::RefreshSandboxTokenResponse,
    expected_session: Option<&str>,
) -> Result<GatewayCredential> {
    anyhow::ensure!(
        !response.token.is_empty()
            && !response.session_id.is_empty()
            && expected_session.is_none_or(|expected| response.session_id == expected),
        "invalid refreshed runtime credential"
    );
    anyhow::ensure!(
        response.extension_credentials.is_empty(),
        "unrequested extension credentials"
    );
    Ok(GatewayCredential {
        token: response.token,
        session_id: Some(response.session_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_reports_installed_only_when_material_is_held() {
        assert_eq!(super::readiness_reason(0, false), 0);
        assert_eq!(
            super::readiness_reason(0, true),
            o::ProviderReadinessReason::CredentialsWithheld as i32
        );
        let expired = o::ProviderReadinessReason::SupervisorLeaseExpired as i32;
        assert_eq!(super::readiness_reason(expired, true), expired);
    }

    #[test]
    fn intentional_close_cannot_be_replaced_by_supervisor_error() {
        for current in [
            Phase::Closing,
            Phase::Stopping,
            Phase::Deleting,
            Phase::Stopped,
            Phase::Failed,
        ] {
            let (phase, _) = watch::channel(current);
            assert!(!mark_failed(&phase));
            assert_eq!(*phase.borrow(), current);
        }
        for current in [Phase::Starting, Phase::Ready] {
            let (phase, _) = watch::channel(current);
            assert!(mark_failed(&phase));
            assert_eq!(*phase.borrow(), Phase::Failed);
        }
    }

    #[tokio::test]
    async fn hanging_cleanup_cannot_delay_access_revocation() {
        let cancel = CancellationToken::new();
        let cleanup = async {
            assert!(cancel.is_cancelled());
            std::future::pending::<()>().await;
        };
        let result = tokio::time::timeout(
            Duration::from_millis(20),
            cancel_before_cleanup(&cancel, cleanup),
        )
        .await;
        assert!(result.is_err());
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn full_heartbeat_queue_is_bounded_and_cancellable() {
        let (sender, _receiver) = mpsc::channel(1);
        sender.send(1).await.expect("empty fixture queue");
        let cancel = CancellationToken::new();
        assert!(bounded_send(&sender, 2, &cancel).await.is_err());
        cancel.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), bounded_send(&sender, 2, &cancel))
                .await
                .expect("cancellation is immediate")
                .is_err()
        );
    }

    #[test]
    fn refreshed_credentials_preserve_the_authenticated_session() {
        let response = o::RefreshSandboxTokenResponse {
            token: "fixture-token".into(),
            session_id: "generation".into(),
            ..Default::default()
        };
        assert!(refreshed_token(response.clone(), Some("other")).is_err());
        let initial = refreshed_token(response.clone(), None).expect("first authenticated refresh");
        assert_eq!(initial.session_id.as_deref(), Some("generation"));
        assert_eq!(
            refreshed_token(response, Some("generation"))
                .expect("matching refresh")
                .token,
            "fixture-token"
        );
    }
}
#[derive(Deserialize)]
struct Authentication {
    supervisor: SupervisorAuthentication,
}
#[derive(Deserialize)]
struct SupervisorAuthentication {
    gateway_token: String,
    ssh_host_private_key: String,
}

pub fn validate_authentication(bytes: &[u8]) -> Result<()> {
    let auth: Authentication =
        serde_json::from_slice(bytes).context("invalid gateway launch authentication")?;
    if auth.supervisor.gateway_token.is_empty() {
        bail!("gateway token required");
    }
    russh::keys::decode_secret_key(&auth.supervisor.ssh_host_private_key, None)
        .context("invalid gateway SSH host key")?;
    Ok(())
}

/// The readiness reason for a provider snapshot: the gateway's own reason when it
/// withheld material, credentials withheld by the host broker, otherwise ready.
fn readiness_reason(snapshot_reason: i32, withheld: bool) -> i32 {
    if snapshot_reason != 0 {
        snapshot_reason
    } else if withheld {
        o::ProviderReadinessReason::CredentialsWithheld as i32
    } else {
        0
    }
}

/// One runtime generation; credentials never enter guest commands or logs.
pub struct Runtime {
    pub spec: c::DriverSandbox,
    pub id: SandboxId,
    pub instance: String,
    pub config: Arc<Config>,
    pub guest: Guest,
    pub vm_policy: Option<crate::profile::VmPolicy>,
    pub transfer_slots: Arc<tokio::sync::Semaphore>,
    pub operation_slots: Arc<tokio::sync::Semaphore>,
    operator_policy: Option<crate::profile::VmPolicy>,
    hosted_network: Option<crate::hosted_network::RuntimeNetwork>,
    pub cancel: CancellationToken,
    pub phase: watch::Sender<Phase>,
    pub output: broadcast::Sender<Output>,
    pub history: Mutex<VecDeque<Output>>,
    pub main_exit: watch::Sender<Option<u32>>,
    authentication: Authentication,
    gateway_token: RwLock<GatewayCredential>,
    credential_handshakes: tokio::sync::RwLock<()>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    endpoint: Mutex<Option<tempfile::TempDir>>,
    /// Workload-facing provider material from the host broker: placeholders
    /// and the public proxy CA, never credential values.
    guest_material: RwLock<Option<Arc<GuestMaterial>>>,
    /// Digest of the provider snapshot last installed in the host broker.
    provider_digest: Mutex<Option<[u8; 32]>>,
}

/// How many times a provider snapshot that changed between the configuration
/// and environment reads is fetched again before supervision fails.
const PROVIDER_SNAPSHOT_ATTEMPTS: usize = 3;
/// Bound on one revalidation round, so heartbeats keep flowing under host load.
const REVALIDATION_DEADLINE: Duration = Duration::from_secs(20);
/// Cadence of full native runtime proofs while the effective policy is unchanged.
pub const NATIVE_REVALIDATION_INTERVAL: Duration = Duration::from_secs(30);
/// Longest a running guest may go without a successful proof before missed
/// deadlines stop it like a violation.
pub const REVALIDATION_GRACE: Duration = Duration::from_secs(300);

/// Missed deadlines are deferred within the grace; verified failures never are.
pub fn revalidation_deferrable(error: &anyhow::Error, since_verified: Duration) -> bool {
    crate::guest::is_deadline(error) && since_verified < REVALIDATION_GRACE
}

impl Runtime {
    pub fn new(
        spec: c::DriverSandbox,
        config: Arc<Config>,
        guest: Guest,
        authentication: Vec<u8>,
    ) -> Result<Arc<Self>> {
        Self::new_with_policy(spec, config, guest, authentication, None, None)
    }
    pub fn new_with_policy(
        mut spec: c::DriverSandbox,
        config: Arc<Config>,
        guest: Guest,
        authentication: Vec<u8>,
        operator_policy: Option<crate::profile::VmPolicy>,
        vm_policy: Option<crate::profile::VmPolicy>,
    ) -> Result<Arc<Self>> {
        let auth: Authentication = serde_json::from_slice(&authentication)
            .context("invalid gateway launch authentication")?;
        // Keep bootstrap credentials only in the private supervisor state;
        // observations and restarted specifications must never echo them.
        spec.spec
            .as_mut()
            .context("missing sandbox spec")?
            .launch_authentication
            .clear();
        let id = SandboxId::parse(&spec.id)?;
        let (phase, _) = watch::channel(Phase::Starting);
        let (output, _) = broadcast::channel(128);
        let (main_exit, _) = watch::channel(None);
        let instance = guest
            .runtime_identity
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let hosted_network = config
            .hosted_network_config
            .as_deref()
            .map(|path| {
                crate::hosted_network::RuntimeNetwork::new(
                    path,
                    &spec,
                    config.guest_image.as_deref().unwrap_or(""),
                )
            })
            .transpose()?;
        Ok(Arc::new(Self {
            spec,
            id,
            instance,
            config,
            guest,
            vm_policy,
            operator_policy,
            hosted_network,
            transfer_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            operation_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            cancel: CancellationToken::new(),
            phase,
            output,
            history: Mutex::new(VecDeque::new()),
            main_exit,
            credential_handshakes: tokio::sync::RwLock::new(()),
            gateway_token: RwLock::new(GatewayCredential {
                token: auth.supervisor.gateway_token.clone(),
                session_id: None,
            }),
            authentication: auth,
            tasks: Mutex::new(Vec::new()),
            endpoint: Mutex::new(None),
            guest_material: RwLock::new(None),
            provider_digest: Mutex::new(None),
        }))
    }
    /// Whether attached provider credentials are injected by the host broker.
    fn mediates_providers(&self) -> bool {
        self.operator_policy.is_some() && self.hosted_network.is_none()
    }
    /// Environment for guest commands: provider placeholders and the proxy
    /// CA trust settings, as the native supervisor gives its children.
    pub fn guest_environment(&self) -> Vec<(String, String)> {
        self.guest_material
            .read()
            .ok()
            .and_then(|material| material.clone())
            .map(|material| material.guest_environment())
            .unwrap_or_default()
    }
    /// Whether execution requires the verified VM boundary to be Ready.
    pub fn is_enforced(&self) -> bool {
        self.vm_policy.is_some() || self.config.runtime_profile == RuntimeProfile::Kubernetes
    }
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        let (directory, task) = ssh::listen(
            self.clone(),
            &self.authentication.supervisor.ssh_host_private_key,
        )
        .await?;
        let path = directory.path().join("ssh.sock");
        *self.endpoint.lock().await = Some(directory);
        self.tasks.lock().await.push(task);
        let runtime = self.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = runtime.supervise(path).await {
                if !mark_failed(&runtime.phase) {
                    return;
                }
                tracing::error!(sandbox = %runtime.id, error = %error, "supervisor stopped");
                runtime.cancel.cancel();
                if runtime.vm_policy.is_some()
                    || runtime.config.runtime_profile == RuntimeProfile::Kubernetes
                {
                    cancel_before_cleanup(&runtime.cancel, async {
                        if let Err(error) = crate::guest::lifecycle(&runtime.config, "stop", &runtime.id).await {
                            tracing::error!(sandbox=%runtime.id,%error,"failed to stop rejected VM");
                        }
                    }).await;
                }
            }
        });
        self.tasks.lock().await.push(task);
        Ok(())
    }
    pub async fn close(&self) {
        self.phase.send_if_modified(|phase| {
            if matches!(phase, Phase::Starting | Phase::Ready) {
                *phase = Phase::Closing;
                true
            } else {
                false
            }
        });
        self.cancel.cancel();
        for task in self.tasks.lock().await.drain(..) {
            task.abort();
            let _ = task.await;
        }
        self.endpoint.lock().await.take();
    }
    fn request<T>(&self, message: T) -> Result<Request<T>> {
        let mut request = Request::new(message);
        request.metadata_mut().insert(
            "authorization",
            format!(
                "Bearer {}",
                self.gateway_token
                    .read()
                    .map_err(|_| anyhow::anyhow!("runtime credential lock unavailable"))?
                    .token
            )
            .parse()?,
        );
        Ok(request)
    }
    async fn client(&self) -> Result<o::open_shell_client::OpenShellClient<Channel>> {
        let ca = tokio::fs::read(&self.config.gateway_ca).await?;
        let channel = Endpoint::from_shared(self.config.gateway.clone())?
            .connect_timeout(Duration::from_secs(10))
            .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)))?
            .connect()
            .await?;
        Ok(o::open_shell_client::OpenShellClient::new(channel))
    }
    async fn refresh_credential(
        &self,
        client: &mut o::open_shell_client::OpenShellClient<Channel>,
    ) -> Result<()> {
        credentials::rotate(&self.credential_handshakes,async {
            let mut request=self.request(o::RefreshSandboxTokenRequest::default())?;
            request.set_timeout(Duration::from_secs(10));
            let response=tokio::select! {
                ()=self.cancel.cancelled()=>bail!("runtime credential renewal cancelled"),
                response=tokio::time::timeout(Duration::from_secs(10),client.refresh_sandbox_token(request))=>response.context("runtime credential refresh deadline exceeded")??.into_inner(),
            };
            let mut credential=self.gateway_token.write().map_err(|_|anyhow::anyhow!("runtime credential lock unavailable"))?;
            *credential=refreshed_token(response,credential.session_id.as_deref())?;
            Ok(())
        }).await
    }
    async fn supervise(self: &Arc<Self>, ssh_path: PathBuf) -> Result<()> {
        let mut client = self.client().await?;
        let mut attempts = 0;
        let snapshot = loop {
            let request = self.request(s::GetSandboxConfigRequest {
                name: self.spec.name.clone(),
                ..Default::default()
            })?;
            match client.get_sandbox_config(request).await {
                Ok(response) => break response.into_inner(),
                Err(error)
                    if attempts < 60
                        && matches!(
                            error.code(),
                            tonic::Code::NotFound | tonic::Code::Unavailable
                        ) =>
                {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let mut applied = self.vm_policy.clone();
        let (snapshot, providers) = self.paired_snapshots(&mut client, snapshot).await?;
        let mut attempt = 0;
        // A boot burst can delay the first proof; a missed deadline is retried, a
        // verified mismatch is not.
        loop {
            match self.enforce_snapshot(&snapshot, &mut applied).await {
                Err(error) if crate::guest::is_deadline(&error) && attempt < 2 => {
                    attempt += 1;
                    tracing::warn!(sandbox=%self.id, error=%error, attempt, "initial runtime verification deferred");
                }
                result => break result?,
            }
        }
        // Placeholders and trust must exist before the workload starts.
        self.sync_providers(&providers, applied.as_ref()).await?;
        if self.config.runtime_profile == RuntimeProfile::Kubernetes
            && self.hosted_network.is_none()
        {
            let _validated = crate::policy::validate_policy(
                snapshot
                    .policy
                    .as_ref()
                    .context("effective hosted policy required")?,
            )?;
            crate::guest::verify_runtime(&self.config, &self.spec, &self.instance).await?;
        }
        let pending = o::ReportSandboxConfigurationRequest {
            sandbox_id: self.id.to_string(),
            expected_instance_id: snapshot.configuration_instance_id.clone(),
            admission: Some(o::SandboxConfigurationAdmission {
                instance_id: self.instance.clone(),
                state: 1,
                ..Default::default()
            }),
        };
        client
            .report_sandbox_configuration(self.request(pending)?)
            .await?;
        self.start_main().await?;
        self.report_accepted(&mut client, &snapshot).await?;
        let mut last_snapshot = snapshot;
        let (sender, receiver) = mpsc::channel(32);
        sender
            .send(o::SupervisorMessage {
                payload: Some(o::supervisor_message::Payload::Hello(o::SupervisorHello {
                    sandbox_id: self.id.to_string(),
                    instance_id: self.instance.clone(),
                    connection_epoch: 1,
                    // The gateway accepts readiness evidence only from a supervisor
                    // that advertises it; mediated sandboxes report each heartbeat.
                    supports_provider_readiness: self.mediates_providers(),
                    ..Default::default()
                })),
            })
            .await?;
        let mut stream = client
            .connect_supervisor(self.request(ReceiverStream::new(receiver))?)
            .await?
            .into_inner();
        // VM boot may consume most of the launch JWT's lifetime. Renew only
        // after the supervisor handshake is authenticated and before processing
        // SessionAccepted or opening relays, then use the normal periodic cadence.
        if self.is_enforced() {
            self.refresh_credential(&mut client).await?;
        }
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(5),
            Duration::from_secs(5),
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Provider readiness evidence belongs to the accepted session and renews
        // its lease each heartbeat; sequences only increase within the session.
        let mut session: Option<String> = None;
        let mut readiness_sequence: u64 = 0;
        let mut refresh = credentials::refresh_timer();
        let mut verified_at = tokio::time::Instant::now();
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return Ok(()),
                _ = refresh.tick(), if self.is_enforced() => { self.refresh_credential(&mut client).await?; },
                _ = heartbeat.tick(), if session.is_some() => {
                    if self.vm_policy.is_some() || self.config.runtime_profile == RuntimeProfile::Kubernetes {
                        let last_verified = verified_at;
                        let revalidation = tokio::time::timeout(REVALIDATION_DEADLINE, async {
                                let mut request = self.request(s::GetSandboxConfigRequest { name:self.spec.name.clone(), ..Default::default() })?;
                                request.set_timeout(Duration::from_secs(10));
                                let effective = client.get_sandbox_config(request).await?.into_inner();
                                let (effective, providers) = self.paired_snapshots(&mut client, effective).await?;
                                // Policy changes apply at once; unchanged native guests are
                                // re-proven on a slower cadence to bound host load at fleet scale.
                                let proven = self.operator_policy.is_none()
                                    || effective != last_snapshot
                                    || last_verified.elapsed() >= NATIVE_REVALIDATION_INTERVAL;
                                if proven {
                                    self.enforce_snapshot(&effective,&mut applied).await?;
                                }
                                self.sync_providers(&providers, applied.as_ref()).await?;
                                if let Some(session) = session.as_deref() {
                                    readiness_sequence += 1;
                                    if let Err(error) = self
                                        .report_readiness(&mut client, session, readiness_sequence, &effective, &providers)
                                        .await
                                    {
                                        tracing::warn!(sandbox=%self.id, error=%error, "provider readiness report failed");
                                    }
                                }
                                if self.config.runtime_profile == RuntimeProfile::Kubernetes && self.hosted_network.is_none() {
                                        if effective.version!=last_snapshot.version || effective.config_revision!=last_snapshot.config_revision { bail!("effective policy changed; hosted runtime must be reprovisioned"); }
                                        let _validated = crate::policy::validate_policy(effective.policy.as_ref().context("effective hosted policy required")?)?;
                                        crate::guest::verify_runtime(&self.config,&self.spec,&self.instance).await?;
                                }
                                if effective != last_snapshot {
                                    self.report_accepted(&mut client,&effective).await?;
                                    last_snapshot = effective;
                                }
                                Ok::<_,anyhow::Error>(proven)
                            });
                        tokio::pin!(revalidation);
                        loop {
                            tokio::select! {
                                () = self.cancel.cancelled() => return Ok(()),
                                message = stream.message() => match message?.and_then(|m| m.payload) {
                                    Some(o::gateway_message::Payload::RelayOpen(open)) => {
                                        let runtime = self.clone();
                                        let sender = sender.clone();
                                        let path = ssh_path.clone();
                                        self.tasks.lock().await.push(tokio::spawn(async move {
                                            if let Err(error) = runtime.relay(open, path, sender).await {
                                                tracing::warn!(sandbox=%runtime.id, error=%error, "relay failed");
                                            }
                                        }));
                                    }
                                    Some(o::gateway_message::Payload::SessionRejected(_)) => bail!("gateway rejected supervisor session"),
                                    None => bail!("gateway closed supervisor session"),
                                    _ => {}
                                },
                                result = &mut revalidation => {
                                match result.context("runtime revalidation deadline exceeded").and_then(|outcome| outcome) {
                                    Ok(true) => verified_at = tokio::time::Instant::now(),
                                    Ok(false) => {}
                                    // Contention is not a violation: defer within a bounded grace.
                                    Err(error) if revalidation_deferrable(&error, verified_at.elapsed()) => {
                                        tracing::warn!(sandbox=%self.id, error=%error, "runtime revalidation deferred");
                                    }
                                    Err(error) => return Err(error),
                                }
                                break;
                            }
                        }
                        }
                    }
                    bounded_send(&sender,o::SupervisorMessage {payload:Some(o::supervisor_message::Payload::Heartbeat(o::SupervisorHeartbeat {}))},&self.cancel).await?;
                },
                message = stream.message() => match message?.and_then(|m|m.payload) {
                    Some(o::gateway_message::Payload::SessionAccepted(accepted)) => {
                        session = Some(accepted.session_id);
                        readiness_sequence = 0;
                        if self.vm_policy.is_some() { self.enforce_snapshot(&last_snapshot,&mut applied).await?; }
                        if self.config.runtime_profile == RuntimeProfile::Kubernetes { crate::guest::verify_runtime(&self.config,&self.spec,&self.instance).await?; }
                        self.phase.send_if_modified(|phase| { if *phase == Phase::Starting { *phase=Phase::Ready;true }else{false} });
                        tracing::info!(sandbox=%self.id,"supervisor connected");
                    },
                    Some(o::gateway_message::Payload::RelayOpen(open)) => {
                        let runtime = self.clone(); let sender = sender.clone(); let path = ssh_path.clone();
                        self.tasks.lock().await.push(tokio::spawn(async move { if let Err(error) = runtime.relay(open, path, sender).await { tracing::warn!(sandbox=%runtime.id,error=%error,"relay failed"); } }));
                    }
                    Some(o::gateway_message::Payload::SessionRejected(_)) => bail!("gateway rejected supervisor session"),
                    None => bail!("gateway closed supervisor session"),
                    _ => {}
                }
            }
        }
    }
    async fn enforce_snapshot(
        &self,
        snapshot: &s::GetSandboxConfigResponse,
        applied: &mut Option<crate::profile::VmPolicy>,
    ) -> Result<()> {
        if let Some(network) = &self.hosted_network {
            let policy = network.compile(snapshot)?;
            return crate::guest::enforce_hosted_network(
                &self.config,
                &self.spec,
                &self.instance,
                &policy,
            )
            .await;
        }
        let Some(operator) = &self.operator_policy else {
            return admission::validate_snapshot(snapshot);
        };
        if !snapshot.configuration_admitted || !snapshot.supervisor_middleware_services.is_empty() {
            bail!("effective configuration is not supported or admitted");
        }
        let native = snapshot
            .policy
            .as_ref()
            .context("effective native policy missing")?;
        let next = operator.compile(native)?;
        let nonce = Uuid::new_v4().to_string();
        let action = if applied.as_ref() == Some(&next) {
            "verify"
        } else {
            "update"
        };
        let verified = crate::guest::lifecycle_with_policy(
            &self.config,
            action,
            &self.id,
            Some(&next),
            Some(&nonce),
        )
        .await?
        .context("missing fresh runtime evidence")?;
        if verified.host != self.guest.host
            || verified.port != self.guest.port
            || verified.username != self.guest.username
            || verified.private_key_path != self.guest.private_key_path
            || verified.known_hosts_path != self.guest.known_hosts_path
        {
            bail!("runtime route changed during verification");
        }
        *applied = Some(next);
        Ok(())
    }
    /// Read the provider environment that belongs to `config`, re-reading
    /// both when a provider refresh lands between the two requests.
    async fn paired_snapshots(
        &self,
        client: &mut o::open_shell_client::OpenShellClient<Channel>,
        mut config: s::GetSandboxConfigResponse,
    ) -> Result<(
        s::GetSandboxConfigResponse,
        o::GetSandboxProviderEnvironmentResponse,
    )> {
        let mediated = self.mediates_providers();
        for attempt in 1..=PROVIDER_SNAPSHOT_ATTEMPTS {
            let mut request = self.request(o::GetSandboxProviderEnvironmentRequest {
                sandbox_id: self.id.to_string(),
                // The host broker scopes static credentials to their bound
                // endpoints and keeps stable placeholders across refreshes.
                supports_static_credential_bindings: mediated,
                supports_stable_placeholder_environment_keys: mediated,
            })?;
            request.set_timeout(Duration::from_secs(10));
            let providers = client
                .get_sandbox_provider_environment(request)
                .await?
                .into_inner();
            if providers.provider_env_revision == config.provider_env_revision
                && providers.provider_attachment_epoch == config.provider_attachment_epoch
                && providers.policy_hash == config.policy_hash
            {
                return Ok((config, providers));
            }
            if attempt == PROVIDER_SNAPSHOT_ATTEMPTS {
                break;
            }
            let mut request = self.request(s::GetSandboxConfigRequest {
                name: self.spec.name.clone(),
                ..Default::default()
            })?;
            request.set_timeout(Duration::from_secs(10));
            config = client.get_sandbox_config(request).await?.into_inner();
        }
        bail!("provider snapshot is unsupported or does not match effective configuration");
    }
    /// Install changed provider snapshots in the host broker and publish the
    /// resulting placeholders; other profiles admit no provider material.
    async fn sync_providers(
        &self,
        providers: &o::GetSandboxProviderEnvironmentResponse,
        applied: Option<&crate::profile::VmPolicy>,
    ) -> Result<()> {
        if !self.mediates_providers() {
            if !providers.environment.is_empty()
                || !providers.dynamic_credentials.is_empty()
                || !providers.static_credential_bindings.is_empty()
                || !providers.files.is_empty()
                || providers.readiness_reason != 0
            {
                bail!("provider snapshot is unsupported or does not match effective configuration");
            }
            return Ok(());
        }
        let inspected = applied.is_some_and(|policy| !policy.network.tls_inspect.is_empty());
        let mut installed = self.provider_digest.lock().await;
        if installed.is_none() && providers.environment.is_empty() && !inspected {
            return Ok(());
        }
        let snapshot = Zeroizing(providers.encode_to_vec());
        let digest: [u8; 32] = sha2::Sha256::digest(&snapshot.0).into();
        if *installed == Some(digest) {
            return Ok(());
        }
        let material =
            crate::guest::install_provider_credentials(&self.config, &self.id, &snapshot.0).await?;
        drop(snapshot);
        if let Some(reason) = &material.withheld {
            tracing::warn!(sandbox=%self.id, %reason, "provider credentials revoked in the host broker");
        }
        if inspected && material.ca_certificate.is_none() {
            tracing::warn!(sandbox=%self.id, "guest predates host TLS inspection; inspected destinations are refused");
        }
        *self
            .guest_material
            .write()
            .map_err(|_| anyhow::anyhow!("provider material lock unavailable"))? =
            Some(Arc::new(material));
        *installed = Some(digest);
        Ok(())
    }
    /// Report the installed provider state for this session. Credentials and the
    /// launch environment count as installed only when the host broker holds the
    /// snapshot's material; the gateway marks provider changes ready from this.
    async fn report_readiness(
        &self,
        client: &mut o::open_shell_client::OpenShellClient<Channel>,
        session: &str,
        sequence: u64,
        config: &s::GetSandboxConfigResponse,
        providers: &o::GetSandboxProviderEnvironmentResponse,
    ) -> Result<()> {
        if !self.mediates_providers() {
            return Ok(());
        }
        let withheld = self
            .guest_material
            .read()
            .map_err(|_| anyhow::anyhow!("provider material lock unavailable"))?
            .as_ref()
            .is_some_and(|material| material.withheld.is_some());
        let reason = readiness_reason(providers.readiness_reason, withheld);
        client
            .report_provider_readiness(self.request(o::ReportProviderReadinessRequest {
                sandbox_id: self.id.to_string(),
                observation: Some(o::ProviderReadinessObservation {
                    session_id: session.to_owned(),
                    sequence,
                    attachment_epoch: providers.provider_attachment_epoch.clone(),
                    provider_env_revision: providers.provider_env_revision,
                    config_revision: config.config_revision,
                    policy_hash: config.policy_hash.clone(),
                    credentials_installed: reason == 0,
                    policy_active: true,
                    launch_environment_installed: reason == 0,
                    process_instance_id: self.instance.clone(),
                    reason,
                }),
            })?)
            .await?;
        Ok(())
    }
    async fn report_accepted(
        &self,
        client: &mut o::open_shell_client::OpenShellClient<Channel>,
        snapshot: &s::GetSandboxConfigResponse,
    ) -> Result<()> {
        client
            .report_sandbox_configuration(self.request(o::ReportSandboxConfigurationRequest {
                sandbox_id: self.id.to_string(),
                admission: Some(o::SandboxConfigurationAdmission {
                    instance_id: self.instance.clone(),
                    state: 2,
                    policy_version: snapshot.version,
                    policy_hash: snapshot.policy_hash.clone(),
                    config_revision: snapshot.config_revision,
                    provider_env_revision: snapshot.provider_env_revision,
                    ..Default::default()
                }),
                ..Default::default()
            })?)
            .await?;
        if snapshot.policy_source == s::PolicySource::Sandbox as i32 {
            client
                .report_policy_status(self.request(o::ReportPolicyStatusRequest {
                    sandbox_id: self.id.to_string(),
                    version: snapshot.version,
                    status: 2,
                    load_error: String::new(),
                })?)
                .await?;
        }
        Ok(())
    }
    async fn start_main(self: &Arc<Self>) -> Result<()> {
        let command = self
            .spec
            .spec
            .as_ref()
            .context("missing sandbox spec")?
            .command
            .iter()
            .map(|arg| shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        if command.is_empty() {
            bail!("canonical main command required");
        }
        let assignments = crate::guest::environment_assignments(&self.guest_environment())?;
        let command = if assignments.is_empty() {
            command
        } else {
            format!("exec /usr/bin/env{assignments} {command}")
        };
        let mut child = self.guest.exec(&self.config, &command)?;
        // The canonical main process is noninteractive in this bounded adapter.
        child.stdin.take();
        let stdout = child.stdout.take().context("main stdout unavailable")?;
        let stderr = child.stderr.take().context("main stderr unavailable")?;
        let runtime = self.clone();
        let task = tokio::spawn(async move {
            let out = runtime.capture(stdout, false);
            let err = runtime.capture(stderr, true);
            let wait = async {
                tokio::try_join!(out, err)?;
                child.wait().await.map_err(anyhow::Error::from)
            };
            let code = tokio::select! { () = runtime.cancel.cancelled() => { let _ = child.kill().await; return; }, result = wait => result.ok().and_then(|s|s.code()).and_then(|c|u32::try_from(c).ok()).unwrap_or(1) };
            runtime.main_exit.send_replace(Some(code));
            let _ = runtime.output.send(Output::Exit(code));
        });
        self.tasks.lock().await.push(task);
        Ok(())
    }
    async fn capture<R: AsyncRead + Unpin>(&self, mut reader: R, stderr: bool) -> Result<()> {
        let mut data = vec![0; 32768];
        loop {
            let size = reader.read(&mut data).await?;
            if size == 0 {
                return Ok(());
            }
            let message = if stderr {
                Output::Stderr(data[..size].to_vec())
            } else {
                Output::Stdout(data[..size].to_vec())
            };
            let mut history = self.history.lock().await;
            if history.len() == 64 {
                history.pop_front();
            }
            history.push_back(message.clone());
            let _ = self.output.send(message);
        }
    }
    async fn relay(
        &self,
        open: o::RelayOpen,
        path: PathBuf,
        control: mpsc::Sender<o::SupervisorMessage>,
    ) -> Result<()> {
        let mut child = None;
        let (mut reader, writer): (
            Box<dyn AsyncRead + Send + Unpin>,
            Box<dyn AsyncWrite + Send + Unpin>,
        ) = match open.target {
            Some(o::relay_open::Target::Tcp(target)) => {
                let mut process = self.guest.tcp(&self.config, &target.host, target.port)?;
                let out = process.stdout.take().context("TCP stdout unavailable")?;
                let input = process.stdin.take().context("TCP stdin unavailable")?;
                if let Some(mut errors) = process.stderr.take() {
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut errors, &mut tokio::io::sink()).await;
                    });
                }
                child = Some(process);
                (Box::new(out), Box::new(input))
            }
            _ => {
                let (reader, writer) = UnixStream::connect(path).await?.into_split();
                (Box::new(reader), Box::new(writer))
            }
        };
        let (sender, receiver) = mpsc::channel(32);
        sender
            .send(o::RelayFrame {
                payload: Some(o::relay_frame::Payload::Init(o::RelayInit {
                    channel_id: open.channel_id.clone(),
                })),
            })
            .await?;
        let mut client = self.client().await?;
        let incoming = credentials::handshake(&self.credential_handshakes, async {
            // Token refresh consumes the old bearer on the gateway before its
            // response arrives. Build the request only after this guard is held.
            let request=self.request(ReceiverStream::new(receiver))?;
            let response=tokio::select! {
                ()=self.cancel.cancelled()=>bail!("relay cancelled before authentication"),
                result=tokio::time::timeout(Duration::from_secs(10),client.relay_stream(request))=>result.context("relay authentication deadline exceeded")??,
            };
            Ok(response.into_inner())
        }).await?;
        control
            .send(o::SupervisorMessage {
                payload: Some(o::supervisor_message::Payload::RelayOpenResult(
                    o::RelayOpenResult {
                        channel_id: open.channel_id,
                        success: true,
                        ..Default::default()
                    },
                )),
            })
            .await?;
        let outgoing = async move {
            let mut data = vec![0; 32768];
            loop {
                let count = reader.read(&mut data).await?;
                if count == 0 {
                    break;
                }
                sender
                    .send(o::RelayFrame {
                        payload: Some(o::relay_frame::Payload::Data(data[..count].to_vec())),
                    })
                    .await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let inbound = relay_to_guest(incoming, writer);
        tokio::select! { () = self.cancel.cancelled() => {}, result = async { tokio::try_join!(outgoing, inbound) } => { result?; } }
        if let Some(mut child) = child {
            let _ = child.kill().await;
        }
        Ok(())
    }
}

/// Own the input handle so EOF also closes subprocess stdin. ChildStdin's
/// shutdown only flushes; retaining it would keep SSH and its gateway slot live.
async fn relay_to_guest<S, W>(mut incoming: S, mut writer: W) -> Result<()>
where
    S: futures::Stream<Item = Result<o::RelayFrame, tonic::Status>> + Unpin,
    W: AsyncWrite + Unpin,
{
    use futures::TryStreamExt;
    while let Some(frame) = incoming.try_next().await? {
        if let Some(o::relay_frame::Payload::Data(data)) = frame.payload {
            writer.write_all(&data).await?;
        }
    }
    writer.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use std::process::Stdio;

    #[tokio::test]
    async fn relay_eof_closes_child_stdin_and_preserves_output() -> Result<()> {
        let mut child = tokio::process::Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().context("child stdin")?;
        let mut output = child.stdout.take().context("child stdout")?;
        let frames = futures::stream::iter([Ok(o::RelayFrame {
            payload: Some(o::relay_frame::Payload::Data(b"relay EOF".to_vec())),
        })]);
        relay_to_guest(frames, input).await?;
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), output.read_to_end(&mut received)).await??;
        assert_eq!(received, b"relay EOF");
        assert!(child.wait().await?.success());
        Ok(())
    }
}
