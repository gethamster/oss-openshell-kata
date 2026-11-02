use super::*;

// Own lifecycle work until its cleanup completes, even after RPC cancellation.
impl Driver {
    pub(super) async fn create_sandbox_owned(
        &self,
        request: Request<c::CreateSandboxRequest>,
    ) -> Result<Response<c::CreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox required"))?;
        let policy = self
            .policy_for(&sandbox)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        let id =
            SandboxId::parse(&sandbox.id).map_err(|e| Status::invalid_argument(e.to_string()))?;
        // Lifecycle and proof steps run with this sandbox's admitted guest image.
        let config = std::sync::Arc::new(self.config.for_sandbox(&sandbox));
        let _recovery = self.recovery_gate.read().await;
        let _guard = self.lifecycle.lock(id.as_str()).await?;
        if let Some(existing) = self.registry.read().await.active.get(id.as_str()) {
            if existing.spec.workspace != sandbox.workspace {
                return Err(Status::failed_precondition(
                    "existing sandbox belongs to another workspace",
                ));
            }
            return Ok(Response::new(c::CreateSandboxResponse {
                runtime_identity: self.runtime_identity(existing),
            }));
        }
        if self
            .registry
            .read()
            .await
            .retained
            .contains_key(id.as_str())
        {
            return Err(Status::failed_precondition(
                "retained sandbox requires fresh Start authentication",
            ));
        }
        let previous = self
            .registry
            .read()
            .await
            .failed_cleanup
            .get(id.as_str())
            .cloned();
        if let Some(previous) = previous {
            guest::lifecycle_with_policy(&self.config, "abort", &id, None, Some(&previous.nonce))
                .await
                .map_err(internal)?;
            self.registry
                .write()
                .await
                .failed_cleanup
                .remove(id.as_str());
        }
        let authentication = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("spec required"))?
            .launch_authentication
            .clone();
        crate::supervisor::validate_authentication(&authentication)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        self.persist(&Retained::new(
            sandbox.clone(),
            String::new(),
            String::new(),
        ))?;
        let nonce = uuid::Uuid::new_v4().to_string();
        let network = self.hosted_network_for(&sandbox).map_err(internal)?;
        let guest_result = guest::lifecycle_for_network(
            &config,
            "create",
            &id,
            Some(&sandbox.workspace),
            policy.as_ref(),
            Some(&nonce),
            network.as_ref(),
        )
        .await;
        let guest = match guest_result {
            Ok(Some(guest)) => guest,
            result => {
                self.compensate_create(sandbox, &id, &nonce).await;
                return Err(internal(
                    result
                        .err()
                        .unwrap_or_else(|| anyhow::anyhow!("missing guest route")),
                ));
            }
        };
        let runtime = match Runtime::new_with_policy(
            sandbox.clone(),
            config.clone(),
            guest,
            authentication,
            self.operator_policy.clone(),
            policy,
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                self.compensate_create(sandbox, &id, &nonce).await;
                return Err(internal(error));
            }
        };
        if let Err(error) = guest::verify_runtime(&config, &runtime.spec, &runtime.instance).await {
            self.compensate_create(sandbox, &id, &nonce).await;
            return Err(internal(error));
        }
        self.register(id.to_string(), runtime.clone(), String::new())
            .await?;
        if let Err(error) = runtime.start().await {
            runtime.phase.send_replace(Phase::Failed);
            runtime.close().await;
            if guest::lifecycle(&self.config, "delete", &id).await.is_ok() {
                self.deleted(id.to_string()).await?;
            }
            return Err(internal(error));
        }
        Ok(Response::new(c::CreateSandboxResponse {
            runtime_identity: self.runtime_identity(&runtime),
        }))
    }
    pub(super) async fn start_sandbox_owned(
        &self,
        request: Request<c::StartSandboxRequest>,
    ) -> Result<Response<c::StartSandboxResponse>, Status> {
        let request = request.into_inner();
        crate::supervisor::validate_authentication(&request.launch_authentication)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let id = SandboxId::parse(&request.sandbox_id).map_err(internal)?;
        let _recovery = self.recovery_gate.read().await;
        let _guard = self.lifecycle.lock(id.as_str()).await?;
        let (old, retained) = {
            let registry = self.registry.read().await;
            (
                registry.active.get(id.as_str()).cloned(),
                registry
                    .retained
                    .get(id.as_str())
                    .cloned()
                    .ok_or_else(|| Status::not_found("sandbox not found"))?,
            )
        };
        if let Some(old) = &old {
            if !request.generation_id.is_empty()
                && request.generation_id == retained.generation
                && *old.phase.borrow() == Phase::Ready
            {
                return Ok(Response::new(c::StartSandboxResponse {
                    runtime_identity: old.instance.clone(),
                }));
            }
            if !matches!(*old.phase.borrow(), Phase::Stopped | Phase::Failed) {
                return Err(Status::failed_precondition(
                    "sandbox must be stopped before start",
                ));
            }
        }
        if self.config.runtime_profile == RuntimeProfile::Kubernetes
            && !request.expected_runtime_identity.is_empty()
            && request.expected_runtime_identity != retained.runtime_identity
            && (request.generation_id.is_empty() || request.generation_id != retained.generation)
        {
            return Err(Status::failed_precondition(
                "retained runtime identity differs",
            ));
        }
        let config = std::sync::Arc::new(self.config.for_sandbox(&retained.sandbox));
        let policy = self
            .policy_for(&retained.sandbox)
            .map_err(internal)?
            .map(|policy| crate::profile::VmPolicy {
                network: crate::network::NetworkPolicy::default(),
                ..policy
            });
        self.persist(&Retained::new(
            retained.sandbox.clone(),
            retained.runtime_identity.clone(),
            request.generation_id.clone(),
        ))?;
        if let Some(old) = &old {
            old.phase.send_replace(Phase::Stopping);
            old.close().await;
        }
        let nonce = uuid::Uuid::new_v4().to_string();
        let network = self
            .hosted_network_for(&retained.sandbox)
            .map_err(internal)?;
        let result = async {
            guest::lifecycle(&self.config, "stop", &id)
                .await
                .map_err(internal)?;
            let guest = guest::lifecycle_for_network(
                &config,
                "start",
                &id,
                Some(&retained.sandbox.workspace),
                policy.as_ref(),
                Some(&nonce),
                network.as_ref(),
            )
            .await
            .map_err(internal)?
            .ok_or_else(|| Status::internal("missing guest route"))?;
            let runtime = Runtime::new_with_policy(
                retained.sandbox,
                config.clone(),
                guest,
                request.launch_authentication,
                self.operator_policy.clone(),
                policy,
            )
            .map_err(internal)?;
            guest::verify_runtime(&config, &runtime.spec, &runtime.instance)
                .await
                .map_err(internal)?;
            self.register(id.to_string(), runtime.clone(), request.generation_id)
                .await?;
            runtime.start().await.map_err(internal)?;
            Ok(Response::new(c::StartSandboxResponse {
                runtime_identity: if self.config.runtime_profile
                    == crate::config::RuntimeProfile::Kubernetes
                {
                    runtime.instance.clone()
                } else {
                    id.to_string()
                },
            }))
        }
        .await;
        if result.is_err() {
            let current = self.registry.read().await.active.get(id.as_str()).cloned();
            if let Some(current) = current {
                current.cancel.cancel();
                current.phase.send_replace(Phase::Failed);
                current.close().await;
            }
            let _ = guest::lifecycle(&self.config, "stop", &id).await;
        }
        result
    }

    pub(super) async fn stop_sandbox_owned(
        &self,
        request: Request<c::StopSandboxRequest>,
    ) -> Result<Response<c::StopSandboxResponse>, Status> {
        let id = SandboxId::parse(&request.get_ref().sandbox_id).map_err(internal)?;
        let _recovery = self.recovery_gate.read().await;
        let _guard = self.lifecycle.lock(id.as_str()).await?;
        let (runtime, exists) = {
            let registry = self.registry.read().await;
            (
                registry.active.get(id.as_str()).cloned(),
                registry.retained.contains_key(id.as_str()),
            )
        };
        if !exists {
            return Err(Status::not_found("sandbox not found"));
        }
        if let Some(runtime) = &runtime {
            runtime.phase.send_replace(Phase::Stopping);
            runtime.close().await;
        }
        if let Err(error) = guest::lifecycle(&self.config, "stop", &id).await {
            if let Some(runtime) = &runtime {
                runtime.phase.send_replace(Phase::Failed);
            }
            return Err(internal(error));
        }
        if let Some(runtime) = runtime {
            runtime.phase.send_replace(Phase::Stopped);
        }
        Ok(Response::new(c::StopSandboxResponse {}))
    }
    pub(super) async fn delete_sandbox_owned(
        &self,
        request: Request<c::DeleteSandboxRequest>,
    ) -> Result<Response<c::DeleteSandboxResponse>, Status> {
        let id = request.into_inner().sandbox_id;
        let validated_id =
            SandboxId::parse(&id).map_err(|error| Status::invalid_argument(error.to_string()))?;
        let _recovery = self.recovery_gate.read().await;
        let _guard = self.lifecycle.lock(validated_id.as_str()).await?;
        let (record, retained) = {
            let registry = self.registry.read().await;
            (
                registry.active.get(&id).cloned(),
                registry.retained.contains_key(&id),
            )
        };
        if let Some(runtime) = &record {
            runtime.phase.send_replace(Phase::Deleting);
            runtime.close().await;
        }
        // The runtime helper can recover retained state after adapter restart.
        // Its idempotent deletion must confirm absence before we publish it.
        if let Err(error) = guest::lifecycle(&self.config, "delete", &validated_id).await {
            if let Some(runtime) = &record {
                runtime.phase.send_replace(Phase::Failed);
            }
            return Err(internal(error));
        }
        if let Err(error) = self.deleted(id).await {
            if let Some(runtime) = &record {
                runtime.phase.send_replace(Phase::Failed);
            }
            return Err(error);
        }
        Ok(Response::new(c::DeleteSandboxResponse {
            deleted: record.is_some() || retained,
        }))
    }
}
