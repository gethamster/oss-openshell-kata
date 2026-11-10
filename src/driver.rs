mod lifecycle;
mod settlement;

use crate::{
    admission,
    config::{Config, RuntimeProfile, SandboxId},
    guest,
    proto::openshell::{compute::v1 as c, extension::v1 as e},
    recovery::{Retained, Store},
    supervisor::{Phase, Runtime},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};

/// The local compute extension and its owned runtime generations.
#[derive(Clone)]
pub struct Driver {
    config: Arc<Config>,
    registry: Arc<RwLock<Registry>>,
    lifecycle: Arc<LifecycleLocks>,
    recovery_gate: Arc<RwLock<()>>,
    in_flight: Arc<settlement::InFlight>,
    recovery: Option<Store>,
    operator_policy: Option<crate::profile::VmPolicy>,
    /// Ends long-lived watch streams so a graceful server shutdown can drain.
    shutdown: CancellationToken,
}

#[derive(Default)]
struct LifecycleLocks(Mutex<BTreeMap<String, Weak<Mutex<()>>>>);

impl LifecycleLocks {
    async fn lock(&self, id: &str) -> Result<tokio::sync::OwnedMutexGuard<()>, Status> {
        let lock = {
            let mut locks = self.0.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(id).and_then(Weak::upgrade) {
                lock
            } else {
                if locks.len() >= 256 {
                    return Err(Status::resource_exhausted(
                        "too many concurrent lifecycle identities",
                    ));
                }
                let lock = Arc::new(Mutex::new(()));
                locks.insert(id.to_owned(), Arc::downgrade(&lock));
                lock
            }
        };
        Ok(lock.lock_owned().await)
    }
}

#[derive(Default)]
struct Registry {
    active: BTreeMap<String, Arc<Runtime>>,
    retained: BTreeMap<String, Retained>,
    failed_cleanup: BTreeMap<String, PendingCleanup>,
    // Retained until this adapter exits so reconnecting watchers cannot miss
    // successful deletion. A new generation of the same ID replaces its tombstone.
    deleted: BTreeSet<String>,
}

#[derive(Default)]
struct WatchState {
    seen: BTreeMap<String, c::DriverSandbox>,
    deleted: BTreeSet<String>,
}

impl WatchState {
    fn accept(&mut self, event: &c::WatchSandboxesEvent, initial: bool) -> bool {
        match &event.payload {
            Some(c::watch_sandboxes_event::Payload::Deleted(value)) => {
                self.seen.remove(&value.sandbox_id);
                self.deleted.insert(value.sandbox_id.clone())
            }
            Some(c::watch_sandboxes_event::Payload::Sandbox(value)) => {
                let Some(sandbox) = &value.sandbox else {
                    return false;
                };
                // Stop/start RPCs own these transitions. Replaying a queued old
                // generation's transition can close a newly accepted supervisor.
                if !initial
                    && sandbox.status.as_ref().is_some_and(|status| {
                        status.conditions.iter().any(|condition| {
                            matches!(condition.r#type.as_str(), "Suspended" | "Bootstrapping")
                        })
                    })
                {
                    return false;
                }
                if self.seen.get(&sandbox.id) == Some(sandbox) {
                    return false;
                }
                self.deleted.remove(&sandbox.id);
                self.seen.insert(sandbox.id.clone(), sandbox.clone());
                true
            }
            Some(c::watch_sandboxes_event::Payload::PlatformEvent(_)) | None => false,
        }
    }
}
#[derive(Clone)]
struct PendingCleanup {
    sandbox: c::DriverSandbox,
    nonce: String,
}
impl Driver {
    pub fn new(config: Arc<Config>) -> anyhow::Result<Self> {
        let operator_policy = config
            .vm_policy
            .as_deref()
            .map(crate::profile::VmPolicy::load)
            .transpose()?;
        let recovery = config
            .recovery_dir
            .as_ref()
            .map(|_| Store::for_config(&config))
            .transpose()?;
        Ok(Self {
            config,
            registry: Arc::default(),
            lifecycle: Arc::default(),
            recovery_gate: Arc::default(),
            in_flight: Arc::default(),
            recovery,
            operator_policy,
            shutdown: CancellationToken::new(),
        })
    }
    fn runtime_identity(&self, runtime: &Runtime) -> String {
        if self.config.runtime_profile == RuntimeProfile::Kubernetes {
            runtime.instance.clone()
        } else {
            runtime.id.to_string()
        }
    }
    /// Admit `sandbox` under `config`: the adapter's own for a new sandbox, or
    /// [`Config::retaining`] for one it already retains.
    fn policy_for(
        &self,
        config: &Config,
        sandbox: &c::DriverSandbox,
    ) -> anyhow::Result<Option<crate::profile::VmPolicy>> {
        if let Some(policy) = &self.operator_policy {
            return admission::compile_request_for_images(
                sandbox,
                policy,
                &config
                    .admitted_images()
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
            .map(Some);
        }
        config.validate_request(sandbox)?;
        Ok(None)
    }
    fn hosted_network_for(
        &self,
        config: &Config,
        sandbox: &c::DriverSandbox,
    ) -> anyhow::Result<Option<crate::network::NetworkPolicy>> {
        config
            .hosted_network_config
            .as_deref()
            .map(|path| {
                let operator = crate::kubernetes::HostedNetworkConfig::load(path)?;
                let selected = config.for_sandbox(sandbox);
                crate::hosted::validate_brokered_request(
                    sandbox,
                    selected.guest_image.as_deref().unwrap_or(""),
                    &selected.resource_shape,
                    &operator.operator_ceiling,
                )
            })
            .transpose()
    }
    /// Stop retained compute before exposing credential-free stopped records.
    pub async fn recover(&self) -> anyhow::Result<()> {
        let _guard = self.recovery_gate.write().await;
        let Some(store) = &self.recovery else {
            return Ok(());
        };
        let recovered = store.load(&self.config)?;
        {
            let registry = self.registry.read().await;
            anyhow::ensure!(
                registry.active.is_empty() && registry.retained.is_empty(),
                "recovery requires a fresh adapter"
            );
        }
        let mut retired = Vec::new();
        for record in &recovered.retired {
            let id = SandboxId::parse(&record.retained.sandbox.id)?;
            if self.retire(store, &id, &record.reason).await {
                retired.push(id.to_string());
            }
        }
        for retained in &recovered.admitted {
            let id = SandboxId::parse(&retained.sandbox.id)?;
            let config = self.config.retaining(&retained.sandbox);
            let config = config.for_sandbox(&retained.sandbox);
            guest::lifecycle(&config, "stop", &id).await?;
        }
        let mut registry = self.registry.write().await;
        for retained in recovered.admitted {
            registry
                .retained
                .insert(retained.sandbox.id.clone(), retained);
        }
        // Reported as deleted so the lifecycle owner re-places them.
        registry.deleted.extend(retired);
        Ok(())
    }
    /// Delete one retained sandbox the operator profile no longer admits: guest,
    /// network fence, snapshot and recovery record. A failed cleanup keeps the
    /// record for the next recovery and never blocks the rest of the adapter.
    async fn retire(&self, store: &Store, id: &SandboxId, reason: &str) -> bool {
        tracing::warn!(sandbox=%id, reason, "retiring retained sandbox the operator profile no longer admits");
        let cleanup = async {
            guest::lifecycle(&self.config, "delete", id).await?;
            store.remove(id.as_str())
        }
        .await;
        match cleanup {
            Ok(()) => {
                tracing::info!(sandbox=%id, "retired sandbox deleted");
                true
            }
            Err(error) => {
                tracing::error!(sandbox=%id, error=%format!("{error:#}"), "retired sandbox cleanup failed; record kept for the next recovery");
                false
            }
        }
    }
    fn persist(&self, retained: &Retained) -> Result<(), Status> {
        if let Some(store) = &self.recovery {
            store.save(retained).map_err(internal)?;
        }
        Ok(())
    }
    /// Ends every open `WatchSandboxes` stream. The gateway reconnects to the
    /// next adapter and takes a fresh snapshot, so nothing is lost; without
    /// this a graceful stop waits on the endless stream until it is killed.
    pub fn begin_shutdown(&self) {
        self.shutdown.cancel();
    }
    pub async fn close(&self) {
        let records: Vec<_> = self
            .registry
            .read()
            .await
            .active
            .values()
            .cloned()
            .collect();
        for runtime in records {
            runtime.close().await;
        }
    }
    async fn register(
        &self,
        id: String,
        runtime: Arc<Runtime>,
        generation: String,
    ) -> Result<(), Status> {
        let retained = Retained::new(runtime.spec.clone(), runtime.instance.clone(), generation);
        self.persist(&retained)?;
        let mut registry = self.registry.write().await;
        registry.failed_cleanup.remove(&id);
        registry.deleted.remove(&id);
        registry.retained.insert(id.clone(), retained);
        registry.active.insert(id, runtime);
        Ok(())
    }
    async fn deleted(&self, id: String) -> Result<(), Status> {
        if let Some(store) = &self.recovery {
            store.remove(&id).map_err(internal)?;
        }
        let mut registry = self.registry.write().await;
        registry.failed_cleanup.remove(&id);
        registry.active.remove(&id);
        registry.retained.remove(&id);
        registry.deleted.insert(id);
        Ok(())
    }
    async fn observation_ids(&self) -> Vec<String> {
        let registry = self.registry.read().await;
        registry
            .retained
            .keys()
            .chain(registry.failed_cleanup.keys())
            .chain(&registry.deleted)
            .cloned()
            .collect()
    }
    async fn current_observation(&self, id: &str) -> Option<c::WatchSandboxesEvent> {
        let registry = self.registry.read().await;
        let payload = if let Some(record) = registry.active.get(id) {
            c::watch_sandboxes_event::Payload::Sandbox(c::WatchSandboxesSandboxEvent {
                sandbox: Some(Self::observation(record)),
            })
        } else if let Some(record) = registry.retained.get(id) {
            c::watch_sandboxes_event::Payload::Sandbox(c::WatchSandboxesSandboxEvent {
                sandbox: Some(record.observation()),
            })
        } else if let Some(record) = registry.failed_cleanup.get(id) {
            c::watch_sandboxes_event::Payload::Sandbox(c::WatchSandboxesSandboxEvent {
                sandbox: Some(record.sandbox.clone()),
            })
        } else if registry.deleted.contains(id) {
            c::watch_sandboxes_event::Payload::Deleted(c::WatchSandboxesDeletedEvent {
                sandbox_id: id.into(),
            })
        } else {
            return None;
        };
        Some(c::WatchSandboxesEvent {
            payload: Some(payload),
        })
    }
    async fn compensate_create(&self, mut sandbox: c::DriverSandbox, id: &SandboxId, nonce: &str) {
        match guest::lifecycle_with_policy(&self.config, "abort", id, None, Some(nonce)).await {
            // An abort may leave a pre-existing, differently owned VM intact.
            // Only an explicit, verified delete may publish an absence event.
            Ok(_) => {
                self.registry
                    .write()
                    .await
                    .failed_cleanup
                    .remove(id.as_str());
            }
            Err(error) => {
                tracing::error!(sandbox=%id,%error,"unverified VM cleanup failed; retained for retry");
                if let Some(spec) = sandbox.spec.as_mut() {
                    spec.launch_authentication.clear();
                }
                sandbox.status = Some(c::DriverSandboxStatus {
                    conditions: vec![c::DriverCondition {
                        r#type: "Ready".into(),
                        status: "False".into(),
                        reason: "CleanupRequired".into(),
                        message: "Runtime cleanup must succeed before retry".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                });
                self.registry.write().await.failed_cleanup.insert(
                    id.to_string(),
                    PendingCleanup {
                        sandbox,
                        nonce: nonce.to_owned(),
                    },
                );
            }
        }
    }
    fn observation(runtime: &Runtime) -> c::DriverSandbox {
        let mut sandbox = runtime.spec.clone();
        let phase = *runtime.phase.borrow();
        let mut conditions = vec![c::DriverCondition {
            r#type: "Ready".into(),
            status: if phase == Phase::Ready {
                "True"
            } else {
                "False"
            }
            .into(),
            reason: match phase {
                Phase::Ready if runtime.vm_policy.is_some() => "EnforcedVmReady",
                Phase::Ready if runtime.config.runtime_profile == RuntimeProfile::Kubernetes => {
                    "EnforcedVmReady"
                }
                Phase::Ready => "PrototypeControlReady",
                Phase::Failed => "RuntimeError",
                Phase::Stopping => "DependenciesNotReady",
                Phase::Deleting => "Deleting",
                _ => "Starting",
            }
            .into(),
            message: if runtime.vm_policy.is_some() {
                "Host-enforced Docker VM profile"
            } else {
                "Kata guest control; policy qualification is separate"
            }
            .into(),
            ..Default::default()
        }];
        if phase == Phase::Starting {
            conditions.push(c::DriverCondition {
                r#type: "Bootstrapping".into(),
                status: "True".into(),
                reason: "Starting".into(),
                ..Default::default()
            });
        }
        if phase == Phase::Stopped {
            conditions.push(c::DriverCondition {
                r#type: "Suspended".into(),
                status: "True".into(),
                reason: "Stopped".into(),
                ..Default::default()
            });
        }
        if phase == Phase::Stopping {
            conditions.push(c::DriverCondition {
                r#type: "Suspended".into(),
                status: "False".into(),
                reason: "PodTerminating".into(),
                message: "Runtime stop in progress".into(),
                ..Default::default()
            });
        }
        sandbox.status = Some(c::DriverSandboxStatus {
            deleting: phase == Phase::Deleting,
            name: sandbox.name.clone(),
            instance_id: runtime.instance.clone(),
            conditions,
            ..Default::default()
        });
        sandbox
    }
}
fn internal(error: impl std::fmt::Display) -> Status {
    tracing::error!(%error,"adapter operation failed");
    Status::internal("isolated guest operation failed; inspect adapter logs")
}

#[tonic::async_trait]
impl c::compute_driver_server::ComputeDriver for Driver {
    async fn get_capabilities(
        &self,
        request: Request<c::GetCapabilitiesRequest>,
    ) -> Result<Response<c::GetCapabilitiesResponse>, Status> {
        if request
            .get_ref()
            .gateway
            .as_ref()
            .and_then(|m| m.protocol_version.as_ref())
            .is_some_and(|v| v.major != 1)
        {
            return Err(Status::failed_precondition(
                "compute contract major version must be 1",
            ));
        }
        Ok(Response::new(c::GetCapabilitiesResponse {
            driver_name:"openshell-kata".into(), driver_version:env!("CARGO_PKG_VERSION").into(), default_image:self.config.guest_image.clone().unwrap_or_else(|| "docker:29-dind".into()), driver_reports_runtime_readiness:true,
            resource_admission_policy:r#"v1:{"allow_driver_config":false,"resource_admission":{"enabled":true,"required_labels":{"openshell.ai/sandbox-attachable":"true","openshell.ai/sandbox-attachable-workspace":"${workspace}"}}}"#.into(),
            extension:Some(e::PeerMetadata { protocol_version:Some(e::ProtocolVersion { major:1,minor:0 }),implementation_name:"openshell-kata".into(),implementation_version:env!("CARGO_PKG_VERSION").into(),supported_capabilities:vec!["openshell.compute.contract".into(), "openshell.compute.operation-settlement".into()],..Default::default() }),..Default::default()
        }))
    }
    async fn authenticate_sandbox(
        &self,
        _: Request<c::AuthenticateSandboxRequest>,
    ) -> Result<Response<c::AuthenticateSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "gateway supplies launch authentication",
        ))
    }
    async fn validate_sandbox_create(
        &self,
        request: Request<c::ValidateSandboxCreateRequest>,
    ) -> Result<Response<c::ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .get_ref()
            .sandbox
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox required"))?;
        SandboxId::parse(&sandbox.id).map_err(|e| Status::invalid_argument(e.to_string()))?;
        self.policy_for(&self.config, sandbox)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(c::ValidateSandboxCreateResponse {}))
    }
    async fn create_sandbox(
        &self,
        request: Request<c::CreateSandboxRequest>,
    ) -> Result<Response<c::CreateSandboxResponse>, Status> {
        let driver = self.clone();
        // Accepted from here: settlement waits for this ticket.
        let ticket = self.in_flight.enter(
            request
                .get_ref()
                .sandbox
                .as_ref()
                .map_or("", |sandbox| sandbox.id.as_str()),
        );
        tokio::spawn(async move {
            let _ticket = ticket;
            driver.create_sandbox_owned(request).await
        })
        .await
        .map_err(internal)?
    }
    async fn get_sandbox(
        &self,
        request: Request<c::GetSandboxRequest>,
    ) -> Result<Response<c::GetSandboxResponse>, Status> {
        let event = self
            .current_observation(&request.get_ref().sandbox_id)
            .await;
        let Some(c::WatchSandboxesEvent {
            payload: Some(c::watch_sandboxes_event::Payload::Sandbox(observation)),
        }) = event
        else {
            return Err(Status::not_found("sandbox not found"));
        };
        Ok(Response::new(c::GetSandboxResponse {
            sandbox: observation.sandbox,
        }))
    }
    async fn list_sandboxes(
        &self,
        _: Request<c::ListSandboxesRequest>,
    ) -> Result<Response<c::ListSandboxesResponse>, Status> {
        let registry = self.registry.read().await;
        Ok(Response::new(c::ListSandboxesResponse {
            sandboxes: registry
                .retained
                .iter()
                .map(|(id, retained)| {
                    registry.active.get(id).map_or_else(
                        || retained.observation(),
                        |runtime| Self::observation(runtime),
                    )
                })
                .chain(
                    registry
                        .failed_cleanup
                        .values()
                        .map(|pending| pending.sandbox.clone()),
                )
                .collect(),
        }))
    }
    async fn stop_sandbox(
        &self,
        request: Request<c::StopSandboxRequest>,
    ) -> Result<Response<c::StopSandboxResponse>, Status> {
        let driver = self.clone();
        // Accepted from here: settlement waits for this ticket.
        let ticket = self.in_flight.enter(&request.get_ref().sandbox_id);
        tokio::spawn(async move {
            let _ticket = ticket;
            driver.stop_sandbox_owned(request).await
        })
        .await
        .map_err(internal)?
    }
    async fn start_sandbox(
        &self,
        request: Request<c::StartSandboxRequest>,
    ) -> Result<Response<c::StartSandboxResponse>, Status> {
        let driver = self.clone();
        // Accepted from here: settlement waits for this ticket.
        let ticket = self.in_flight.enter(&request.get_ref().sandbox_id);
        tokio::spawn(async move {
            let _ticket = ticket;
            driver.start_sandbox_owned(request).await
        })
        .await
        .map_err(internal)?
    }
    async fn suspend_sandbox(
        &self,
        _: Request<c::SuspendSandboxRequest>,
    ) -> Result<Response<c::SuspendSandboxResponse>, Status> {
        Err(Status::unimplemented(
            "memory suspension is not implemented",
        ))
    }
    async fn delete_sandbox(
        &self,
        request: Request<c::DeleteSandboxRequest>,
    ) -> Result<Response<c::DeleteSandboxResponse>, Status> {
        let driver = self.clone();
        // Accepted from here: settlement waits for this ticket.
        let ticket = self.in_flight.enter(&request.get_ref().sandbox_id);
        tokio::spawn(async move {
            let _ticket = ticket;
            driver.delete_sandbox_owned(request).await
        })
        .await
        .map_err(internal)?
    }
    type WatchSandboxesStream = ReceiverStream<Result<c::WatchSandboxesEvent, Status>>;
    async fn watch_sandboxes(
        &self,
        _: Request<c::WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let (sender, receiver) = mpsc::channel(1);
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(300));
            let mut state = WatchState::default();
            let mut initial = true;
            loop {
                tokio::select! {
                    _ = driver.shutdown.cancelled() => return,
                    _ = interval.tick() => {}
                }
                for id in driver.observation_ids().await {
                    let permit = tokio::select! {
                        _ = driver.shutdown.cancelled() => return,
                        permit = sender.reserve() => permit,
                    };
                    let Ok(permit) = permit else {
                        return;
                    };
                    // Read after backpressure clears, not before waiting in a
                    // producer queue with an obsolete runtime generation.
                    if let Some(event) = driver.current_observation(&id).await
                        && state.accept(&event, initial)
                    {
                        permit.send(Ok(event));
                    }
                }
                initial = false;
                if sender.is_closed() {
                    return;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
    async fn ensure_workspace(
        &self,
        request: Request<c::EnsureWorkspaceRequest>,
    ) -> Result<Response<c::EnsureWorkspaceResponse>, Status> {
        if self.config.runtime_profile == crate::config::RuntimeProfile::Kubernetes {
            let workspace = request.into_inner().workspace;
            crate::hosted::namespace(&workspace).map_err(internal)?;
            let id = SandboxId::parse(&workspace).map_err(internal)?;
            guest::lifecycle(&self.config, "ensure-workspace", &id)
                .await
                .map_err(internal)?;
        }
        Ok(Response::new(c::EnsureWorkspaceResponse {}))
    }
    async fn delete_workspace(
        &self,
        request: Request<c::DeleteWorkspaceRequest>,
    ) -> Result<Response<c::DeleteWorkspaceResponse>, Status> {
        if self.config.runtime_profile == crate::config::RuntimeProfile::Kubernetes {
            let workspace = request.into_inner().workspace;
            crate::hosted::namespace(&workspace).map_err(internal)?;
            let id = SandboxId::parse(&workspace).map_err(internal)?;
            guest::lifecycle(&self.config, "delete-workspace", &id)
                .await
                .map_err(internal)?;
        }
        Ok(Response::new(c::DeleteWorkspaceResponse {}))
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    #[test]
    fn hosted_network_uses_the_selected_owner_image_and_keeps_the_operator_ceiling()
    -> anyhow::Result<()> {
        use clap::Parser;
        let root = tempfile::tempdir()?;
        let network_path = root.path().join("network.json");
        let ceiling = crate::network::NetworkPolicy {
            tcp_allow: vec![crate::network::Endpoint {
                host: "registry.npmjs.org".into(),
                port: 443,
            }],
            ..Default::default()
        };
        let operator = serde_json::json!({
            "version":1,"broker_namespace":"openshell-network",
            "broker_namespace_uid":"ea3293cf-4e1c-49a1-b558-ceba087503e6",
            "operator_ceiling":ceiling,"baseline_denied_cidrs":[],
            "protected_hostname_suffixes":[],"authorization_lease_secs":30,
            "resolver_namespace_labels":{"kubernetes.io/metadata.name":"kube-system"},
            "resolver_pod_labels":{"k8s-app":"kube-dns"},
            "resolver_nameservers":["10.96.0.10"],
            "guard_namespace":"kata-system",
            "guard_namespace_uid":"6d62883f-fcb5-4b5e-a250-aaea50eeaf41",
            "guard_client_tls_config_file":"/private/guard.json",
            "inventory_file":"/private/inventory.json"
        });
        std::fs::write(&network_path, serde_json::to_vec(&operator)?)?;
        let mut config = Config::parse_from([
            "openshell-kata",
            "--socket",
            "/private/adapter.sock",
            "--gateway-ca",
            "/private/ca",
            "--lifecycle",
            "/private/lifecycle",
            "--runtime-profile",
            "kubernetes",
            "--guest-network-cidr",
            "10.176.0.0/16",
            "--recovery-dir",
            "/private/registry",
        ]);
        config.guest_image = Some(format!("registry.example/guest@sha256:{}", "a".repeat(64)));
        let owner = format!("registry.example/team-workspace@sha256:{}", "b".repeat(64));
        config.additional_guest_images = vec![owner.clone()];
        config.recovery_dir = Some(root.path().join("registry"));
        config.hosted_network_config = Some(network_path);
        config.validate()?;
        let driver = Driver::new(Arc::new(config))?;
        let mut sandbox = c::DriverSandbox {
            id: "owner-sandbox".into(),
            workspace: "tenant-a".into(),
            spec: Some(c::DriverSandboxSpec {
                template: Some(c::DriverSandboxTemplate {
                    image: owner,
                    ..Default::default()
                }),
                policy: Some(crate::proto::openshell::sandbox::v1::SandboxPolicy {
                    version: 1,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            driver.hosted_network_for(&driver.config, &sandbox)?,
            Some(crate::network::NetworkPolicy::default())
        );
        let native = sandbox
            .spec
            .as_mut()
            .expect("spec")
            .policy
            .as_mut()
            .expect("policy");
        native.network_policies.insert(
            "npm".into(),
            crate::proto::openshell::sandbox::v1::NetworkPolicyRule {
                binaries: vec![crate::proto::openshell::sandbox::v1::NetworkBinary {
                    path: "/**".into(),
                }],
                endpoints: vec![crate::proto::openshell::sandbox::v1::NetworkEndpoint {
                    host: "registry.npmjs.org".into(),
                    port: 443,
                    protocol: "tcp".into(),
                    tls: 1,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        driver.config.validate_request(&sandbox)?;
        assert_eq!(
            driver.hosted_network_for(&driver.config, &sandbox)?,
            Some(ceiling)
        );
        sandbox
            .spec
            .as_mut()
            .expect("spec")
            .policy
            .as_mut()
            .expect("policy")
            .network_policies
            .get_mut("npm")
            .expect("rule")
            .endpoints[0]
            .host = "github.com".into();
        assert!(
            driver.hosted_network_for(&driver.config, &sandbox).is_err(),
            "owner cannot widen network authority"
        );
        sandbox
            .spec
            .as_mut()
            .expect("spec")
            .template
            .as_mut()
            .expect("template")
            .image = format!("registry.example/foreign@sha256:{}", "c".repeat(64));
        assert!(
            driver.hosted_network_for(&driver.config, &sandbox).is_err(),
            "foreign images remain rejected"
        );
        Ok(())
    }

    fn observation(instance: &str, condition: &str) -> c::WatchSandboxesEvent {
        c::WatchSandboxesEvent {
            payload: Some(c::watch_sandboxes_event::Payload::Sandbox(
                c::WatchSandboxesSandboxEvent {
                    sandbox: Some(c::DriverSandbox {
                        id: "id".into(),
                        status: Some(c::DriverSandboxStatus {
                            instance_id: instance.into(),
                            conditions: vec![c::DriverCondition {
                                r#type: condition.into(),
                                status: "True".into(),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                },
            )),
        }
    }

    #[tokio::test]
    async fn lifecycle_lock_inventory_is_bounded_and_reclaims_finished_ids() {
        let locks = LifecycleLocks::default();
        let mut held = Vec::new();
        for index in 0..256 {
            held.push(
                locks
                    .lock(&format!("id-{index}"))
                    .await
                    .expect("bounded key"),
            );
        }
        assert_eq!(
            locks
                .lock("overflow")
                .await
                .expect_err("live key bound")
                .code(),
            tonic::Code::ResourceExhausted
        );
        drop(held);
        let _guard = locks.lock("new-id").await.expect("reclaim dead weak keys");
        assert_eq!(locks.0.lock().await.len(), 1);
    }

    #[test]
    fn old_rpc_owned_transitions_cannot_supersede_a_restarted_session() {
        let mut state = WatchState::default();
        assert!(state.accept(&observation("old", "Ready"), false));
        assert!(!state.accept(&observation("old", "Ready"), false));
        assert!(!state.accept(&observation("old", "Suspended"), false));
        assert!(!state.accept(&observation("old", "Bootstrapping"), false));
        assert!(state.accept(&observation("new", "Ready"), false));
    }
}
