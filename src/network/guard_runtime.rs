//! The external broker's independent authorization and infrastructure lease.

use super::{
    HostedBrokerConfig, HostedControlRequest, HostedControlResponse, InfrastructureInventory,
    MAX_DENIED, ProviderMaterial, canonical_cidrs, canonical_uuid, digest, now,
};
use crate::network::{
    BrokerHandle, NetworkPolicy,
    broker::{Connector, Stream, SystemConnector, bind_with_connector},
    globally_routable,
};
use anyhow::{Context, Result, ensure};
use futures::future::BoxFuture;
use openshell_supervisor_network::provider_proxy::{
    DestinationGuard, GatewayCredentials, GatewayEndpoint, ProviderProxy, ProxyOptions,
};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex, RwLock},
    time::Duration,
};
use tokio::{sync::Mutex, task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;

struct Access {
    denied: Vec<ipnet::IpNet>,
    authorization_expires: u64,
    inventory_expires: u64,
    authorization_deadline: Instant,
    inventory_deadline: Instant,
    cancel: CancellationToken,
}
struct AddressGuard {
    config: Arc<HostedBrokerConfig>,
    absolute_deadline: Instant,
    access: RwLock<Access>,
}
impl AddressGuard {
    fn active_at(&self, time: u64) -> bool {
        let Ok(access) = self.access.read() else {
            return false;
        };
        let monotonic = Instant::now();
        !access.cancel.is_cancelled()
            && time < access.authorization_expires
            && time < access.inventory_expires
            && time < self.config.binding.expires_at_unix
            && monotonic < access.authorization_deadline
            && monotonic < access.inventory_deadline
            && monotonic < self.absolute_deadline
    }
    fn revoke(&self) {
        match self.access.read() {
            Ok(access) => access.cancel.cancel(),
            Err(poisoned) => poisoned.into_inner().cancel.cancel(),
        }
    }
    fn expire_at(&self, time: u64) {
        if !self.active_at(time) {
            self.revoke();
        }
    }
    fn check(&self, address: Option<IpAddr>) -> Result<()> {
        let time = now()?;
        ensure!(
            self.active_at(time),
            "broker authorization or infrastructure inventory expired"
        );
        if let Some(ip) = address {
            ensure!(
                globally_routable(ip),
                "non-global broker destination forbidden"
            );
            ensure!(
                !self
                    .access
                    .read()
                    .map_err(|_| anyhow::anyhow!("broker address guard unavailable"))?
                    .denied
                    .iter()
                    .any(|range| range.contains(&ip)),
                "infrastructure broker destination forbidden"
            );
        }
        Ok(())
    }
    fn authorize(
        &self,
        denied: &[String],
        authorization_expires: u64,
        inventory_expires: u64,
        inventory_deadline: Instant,
    ) -> Result<()> {
        let denied = denied
            .iter()
            .map(|s| s.parse())
            .collect::<std::result::Result<_, _>>()?;
        let mut access = self
            .access
            .write()
            .map_err(|_| anyhow::anyhow!("broker address guard unavailable"))?;
        let cancel = if access.cancel.is_cancelled() {
            CancellationToken::new()
        } else {
            access.cancel.clone()
        };
        let authorization_deadline = deadline(authorization_expires)?
            .min(inventory_deadline)
            .min(self.absolute_deadline);
        *access = Access {
            denied,
            authorization_expires,
            inventory_expires,
            authorization_deadline,
            inventory_deadline,
            cancel,
        };
        Ok(())
    }
}
impl DestinationGuard for AddressGuard {
    fn check_host(&self, host: &str) -> std::result::Result<(), String> {
        self.config
            .check_host(host)
            .map_err(|_| "protected infrastructure hostname forbidden".to_owned())
    }
    fn check(&self, addresses: &[SocketAddr]) -> std::result::Result<(), String> {
        self.check(None)
            .map_err(|_| "broker lease is inactive".to_owned())?;
        for address in addresses {
            self.check(Some(address.ip()))
                .map_err(|_| "destination is outside public egress".to_owned())?;
            if if_addrs::get_if_addrs()
                .map_err(|_| "host address inventory unavailable".to_owned())?
                .iter()
                .any(|interface| interface.ip() == address.ip())
            {
                return Err("node-local destination forbidden".to_owned());
            }
        }
        Ok(())
    }
}
struct HostedConnector {
    guard: Arc<AddressGuard>,
    inner: Arc<dyn Connector>,
}
impl Connector for HostedConnector {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            self.guard.check(None)?;
            self.guard.config.check_host(host)?;
            let addresses = self.inner.resolve(host, port).await?;
            ensure!(
                !addresses.is_empty() && addresses.len() <= 256,
                "invalid broker DNS answer count"
            );
            for address in &addresses {
                ensure!(address.port() == port, "DNS destination port changed");
                self.guard.check(Some(address.ip()))?;
            }
            Ok(addresses)
        })
    }
    fn connect(&self, address: SocketAddr) -> BoxFuture<'_, Result<Stream>> {
        Box::pin(async move {
            self.guard.check(Some(address.ip()))?;
            let stream = self.inner.connect(address).await?;
            self.guard.check(Some(address.ip()))?;
            Ok(stream)
        })
    }
    fn cancellation(&self) -> CancellationToken {
        match self.guard.access.read() {
            Ok(access) => access.cancel.clone(),
            Err(_) => {
                let token = CancellationToken::new();
                token.cancel();
                token
            }
        }
    }
}
struct ControlState {
    generation: u64,
    policy: NetworkPolicy,
    inventory: InfrastructureInventory,
    inventory_deadline: Instant,
    denied: Vec<String>,
    authorization_expires: u64,
    stopping: bool,
    provider_material: Option<ProviderMaterial>,
}

/// Trusted control handle. Every new process begins with no network authority.
pub struct HostedBrokerHandle {
    broker: Option<BrokerHandle>,
    provider: Arc<StdMutex<Option<Arc<ProviderProxy>>>>,
    bind: SocketAddr,
    tls_directory: tempfile::TempDir,
    config: Arc<HostedBrokerConfig>,
    config_sha256: String,
    startup_epoch: String,
    guard: Arc<AddressGuard>,
    state: Mutex<ControlState>,
    stop_watch: CancellationToken,
    watch: Option<JoinHandle<()>>,
}
impl HostedBrokerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.broker
            .as_ref()
            .map_or(self.bind, BrokerHandle::local_addr)
    }
    pub fn startup_epoch(&self) -> &str {
        &self.startup_epoch
    }
    pub async fn snapshot(&self, nonce: &str) -> Result<HostedControlResponse> {
        canonical_uuid(nonce)?;
        let state = self.state.lock().await;
        self.response(&state, nonce).await
    }
    async fn response(&self, state: &ControlState, nonce: &str) -> Result<HostedControlResponse> {
        let active = self.guard.active_at(now()?) && !state.stopping;
        let policy = if active {
            state.policy.clone()
        } else {
            NetworkPolicy::default()
        };
        Ok(HostedControlResponse {
            nonce: nonce.into(),
            binding: self.config.binding.clone(),
            startup_epoch: self.startup_epoch.clone(),
            generation: state.generation,
            policy_sha256: policy.digest()?,
            policy,
            config_sha256: self.config_sha256.clone(),
            inventory_generation: state.inventory.generation,
            inventory_sha256: state.inventory.digest()?,
            effective_denied_sha256: digest(&state.denied)?,
            authorization_expires_at_unix: if active {
                state.authorization_expires
            } else {
                0
            },
            active_connections: self.active_connections().await,
            stopping: state.stopping,
            provider_material: if active {
                state.provider_material.clone()
            } else {
                None
            },
        })
    }
    async fn active_connections(&self) -> usize {
        if let Some(broker) = &self.broker {
            return broker.active_connections().await;
        }
        self.provider
            .lock()
            .expect("provider proxy lock poisoned")
            .as_ref()
            .map_or(0, |proxy| proxy.active_connections())
    }
    async fn deny_and_drain(&self) -> Result<()> {
        if let Some(broker) = &self.broker {
            return broker.deny_and_drain().await.map(|_| ());
        }
        if let Some(proxy) = self
            .provider
            .lock()
            .expect("provider proxy lock poisoned")
            .clone()
        {
            proxy
                .revoke("provider authority revoked")
                .map_err(|_| anyhow::anyhow!("provider revocation failed"))?;
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.active_connections().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("provider connections did not drain")?;
        Ok(())
    }
    async fn apply_providers(
        &self,
        generation: u64,
        providers: &super::ProviderAuthorization,
    ) -> Result<ProviderMaterial> {
        ensure!(
            self.config.provider_mediation,
            "provider mediation is not configured"
        );
        let existing = self
            .provider
            .lock()
            .expect("provider proxy lock poisoned")
            .clone();
        let proxy = if let Some(proxy) = existing {
            proxy
        } else {
            let credentials = GatewayCredentials::externally_managed(&providers.gateway_token)
                .map_err(|_| anyhow::anyhow!("invalid gateway credential"))?;
            let endpoint = GatewayEndpoint::new(self.config.gateway_endpoint.clone(), credentials)
                .with_ca_certificate(self.config.gateway_ca_pem.as_bytes().to_vec());
            let proxy = ProviderProxy::start(ProxyOptions {
                sandbox_id: self.config.binding.sandbox_id.clone(),
                bind: self.bind,
                tls_directory: self.tls_directory.path().to_owned(),
                gateway: Some(endpoint),
                destination_guard: self.guard.clone(),
            })
            .await
            .map_err(|_| anyhow::anyhow!("provider mediator failed to start"))?;
            let proxy = Arc::new(proxy);
            *self.provider.lock().expect("provider proxy lock poisoned") = Some(proxy.clone());
            proxy
        };
        proxy
            .update_gateway_credentials(&providers.gateway_token)
            .map_err(|_| anyhow::anyhow!("gateway credential update failed"))?;
        let material = proxy
            .apply(generation, &providers.config, &providers.environment)
            .map_err(|_| anyhow::anyhow!("provider snapshot rejected"))?;
        Ok(ProviderMaterial {
            environment: material.environment,
            files: material.files,
            ca_certificate: material.ca_certificate,
            mediation_generation: material.mediation_generation,
            config_revision: material.config_revision,
            provider_revision: material.provider_revision,
            policy_hash: material.policy_hash,
            provider_attachment_epoch: material.provider_attachment_epoch,
        })
    }
    /// Process an exact-binding, process-epoch and generation-checked request.
    pub async fn request(&self, request: HostedControlRequest) -> Result<HostedControlResponse> {
        canonical_uuid(request.nonce())?;
        let mut state = self.state.lock().await;
        if let Some((binding, epoch, generation)) = request.expected() {
            ensure!(
                binding == &self.config.binding && epoch == self.startup_epoch,
                "broker launch binding or process epoch differs"
            );
            ensure!(
                generation == state.generation,
                "broker authorization generation changed"
            );
        }
        ensure!(!state.stopping, "broker has stopped");
        match &request {
            HostedControlRequest::Ready { .. } | HostedControlRequest::Inspect { .. } => {}
            HostedControlRequest::AuthorizeProviders {
                providers,
                inventory,
                ..
            } => {
                ensure!(
                    self.config.provider_mediation,
                    "provider mediation is not configured"
                );
                let mut rollback = self
                    .authorize(&mut state, &NetworkPolicy::default(), inventory)
                    .await?;
                state.provider_material =
                    Some(self.apply_providers(state.generation, providers).await?);
                let result = self.response(&state, request.nonce()).await;
                if result.is_ok() {
                    rollback.disarm();
                }
                return result;
            }
            HostedControlRequest::Authorize {
                policy, inventory, ..
            } => {
                ensure!(
                    !self.config.provider_mediation,
                    "provider snapshots are required"
                );
                let mut rollback = self.authorize(&mut state, policy, inventory).await?;
                let result = self.response(&state, request.nonce()).await;
                if result.is_ok() {
                    rollback.disarm();
                }
                return result;
            }
            HostedControlRequest::Stop { .. } => {
                self.guard.revoke();
                self.deny_and_drain().await?;
                ensure!(
                    self.active_connections().await == 0,
                    "broker stop has not drained active connections"
                );
                state.generation = state
                    .generation
                    .checked_add(1)
                    .context("broker generation overflow")?;
                state.policy = NetworkPolicy::default();
                state.authorization_expires = 0;
                state.stopping = true;
            }
        }
        self.response(&state, request.nonce()).await
    }
    async fn authorize(
        &self,
        state: &mut ControlState,
        policy: &NetworkPolicy,
        inventory: &InfrastructureInventory,
    ) -> Result<RevokeOnDrop> {
        let time = now()?;
        ensure!(
            time < self.config.binding.expires_at_unix
                && Instant::now() < self.guard.absolute_deadline,
            "broker absolute lease expired"
        );
        inventory.validate_at(time)?;
        ensure!(
            inventory.generation >= state.inventory.generation,
            "infrastructure inventory revision regressed"
        );
        ensure!(
            inventory.generation != state.inventory.generation
                || inventory.digest()? == state.inventory.digest()?,
            "infrastructure inventory changed within its revision"
        );
        let inventory_deadline = if inventory.generation == state.inventory.generation {
            ensure!(
                Instant::now() < state.inventory_deadline,
                "infrastructure monotonic freshness expired"
            );
            state.inventory_deadline
        } else {
            deadline(inventory.expires_at_unix)?
        };
        self.config.validate_policy(policy)?;
        let policy = policy.normalized()?;
        let denied = canonical_cidrs(
            &state
                .denied
                .iter()
                .chain(inventory.denied_cidrs.iter())
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>(),
        )?;
        ensure!(
            denied.len() <= MAX_DENIED,
            "monotonic denied inventory exceeds limit"
        );

        let rollback = RevokeOnDrop {
            guard: self.guard.clone(),
            provider: self.provider.clone(),
            armed: true,
        };
        let changes =
            state.policy != policy || state.denied != denied || !self.guard.active_at(time);
        if changes {
            self.guard.revoke();
            self.deny_and_drain().await?;
        }
        let time = now()?;
        inventory.validate_at(time)?;
        let expires = time
            .checked_add(self.config.authorization_lease_secs)
            .context("authorization expiry overflow")?
            .min(self.config.binding.expires_at_unix)
            .min(inventory.expires_at_unix);
        ensure!(expires > time, "broker lease expired during authorization");
        let next_generation = state
            .generation
            .checked_add(1)
            .context("broker generation overflow")?;
        // The new policy is never usable while the guard remains revoked. A
        // cancelled update can only leave deny-all, never a partial permission.
        if changes && let Some(broker) = &self.broker {
            broker.replace_policy(policy.clone()).await?;
        }
        self.guard.authorize(
            &denied,
            expires,
            inventory.expires_at_unix,
            inventory_deadline,
        )?;
        *state = ControlState {
            generation: next_generation,
            policy,
            inventory: inventory.clone(),
            inventory_deadline,
            denied,
            authorization_expires: expires,
            stopping: false,
            provider_material: state.provider_material.clone(),
        };
        Ok(rollback)
    }
    pub async fn shutdown(mut self) -> Result<()> {
        self.guard.revoke();
        self.deny_and_drain().await?;
        self.stop_watch.cancel();
        if let Some(watch) = self.watch.take() {
            watch.await?;
        }
        if let Some(broker) = self.broker.take() {
            broker.shutdown().await?;
        }
        Ok(())
    }
}
impl Drop for HostedBrokerHandle {
    fn drop(&mut self) {
        self.guard.revoke();
        if let Ok(slot) = self.provider.lock()
            && let Some(proxy) = slot.as_ref()
        {
            let _ = proxy.revoke("provider broker stopped");
        }
        self.stop_watch.cancel();
    }
}

pub(crate) struct RevokeOnDrop {
    guard: Arc<AddressGuard>,
    provider: Arc<StdMutex<Option<Arc<ProviderProxy>>>>,
    armed: bool,
}
impl RevokeOnDrop {
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for RevokeOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.guard.revoke();
            if let Ok(slot) = self.provider.lock()
                && let Some(proxy) = slot.as_ref()
            {
                let _ = proxy.revoke("provider control operation cancelled");
            }
        }
    }
}
impl HostedBrokerHandle {
    pub(crate) fn mutation_guard(&self) -> RevokeOnDrop {
        RevokeOnDrop {
            guard: self.guard.clone(),
            provider: self.provider.clone(),
            armed: true,
        }
    }
}
fn deadline(expires: u64) -> Result<Instant> {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let remaining = Duration::from_secs(expires)
        .checked_sub(elapsed)
        .context("wall clock deadline expired")?;
    Ok(Instant::now() + remaining)
}

/// Start the same TCP broker with additional external-hosted authority guards.
pub async fn bind_hosted_broker(
    address: SocketAddr,
    config: HostedBrokerConfig,
    inventory: InfrastructureInventory,
) -> Result<HostedBrokerHandle> {
    bind_hosted_with_connector(address, config, inventory, Arc::new(SystemConnector)).await
}
async fn bind_hosted_with_connector(
    address: SocketAddr,
    config: HostedBrokerConfig,
    inventory: InfrastructureInventory,
    inner: Arc<dyn Connector>,
) -> Result<HostedBrokerHandle> {
    crate::initialize_tls();
    let config = Arc::new(config.normalized()?);
    let time = now()?;
    ensure!(
        config.binding.expires_at_unix > time && config.binding.expires_at_unix - time <= 86400,
        "broker absolute expiry is expired or unbounded"
    );
    inventory.validate_at(inventory.issued_at_unix)?;
    ensure!(
        inventory.issued_at_unix <= time,
        "initial inventory is future dated"
    );
    let inventory_deadline = deadline(inventory.expires_at_unix).unwrap_or_else(|_| Instant::now());
    let denied = canonical_cidrs(
        &config
            .baseline_denied_cidrs
            .iter()
            .chain(inventory.denied_cidrs.iter())
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>(),
    )?;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let guard = Arc::new(AddressGuard {
        config: config.clone(),
        absolute_deadline: deadline(config.binding.expires_at_unix)?,
        access: RwLock::new(Access {
            denied: denied
                .iter()
                .map(|v| v.parse())
                .collect::<std::result::Result<_, _>>()?,
            authorization_expires: 0,
            inventory_expires: inventory.expires_at_unix,
            authorization_deadline: Instant::now(),
            inventory_deadline,
            cancel,
        }),
    });
    let broker = if config.provider_mediation {
        None
    } else {
        Some(
            bind_with_connector(
                address,
                NetworkPolicy::default(),
                Arc::new(HostedConnector {
                    guard: guard.clone(),
                    inner,
                }),
            )
            .await?,
        )
    };
    let provider: Arc<StdMutex<Option<Arc<ProviderProxy>>>> = Arc::new(StdMutex::new(None));
    let observed_provider = provider.clone();
    let stop_watch = CancellationToken::new();
    let stopped = stop_watch.clone();
    let watched = guard.clone();
    let watch = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        loop {
            tokio::select! {biased;()=stopped.cancelled()=>break,_=tick.tick()=>{
                match now(){Ok(time)=>watched.expire_at(time),Err(_)=>watched.revoke()}
                let next = now().is_ok_and(|time| watched.active_at(time));
                if !next && let Some(proxy) = observed_provider.lock().expect("provider proxy lock poisoned").as_ref() {
                    let _ = proxy.revoke("infrastructure lease expired");
                }
            }}
        }
    });
    Ok(HostedBrokerHandle {
        config_sha256: config.digest()?,
        broker,
        provider,
        bind: address,
        tls_directory: tempfile::tempdir()?,
        config,
        startup_epoch: uuid::Uuid::new_v4().to_string(),
        guard,
        state: Mutex::new(ControlState {
            generation: 1,
            policy: NetworkPolicy::default(),
            inventory,
            inventory_deadline,
            denied,
            authorization_expires: 0,
            stopping: false,
            provider_material: None,
        }),
        stop_watch,
        watch: Some(watch),
    })
}

#[cfg(test)]
#[path = "guard_deep_tests.rs"]
mod tests;
