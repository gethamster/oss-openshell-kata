//! Trusted broker creation, guarded control and generation-safe cleanup.
use super::{
    broker_config::{self, Binding, Config},
    broker_manifest, broker_policy,
    client::Client,
    lease,
    model::State,
    policy,
    store::Store,
};
use crate::network::{
    BrokerBinding, HostedBrokerConfig, HostedControlRequest, HostedControlResponse,
    InfrastructureInventory, NetworkPolicy,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::time::Duration;

pub(super) fn intent(state: &State, namespace: &Value, config: &Config) -> Result<Binding> {
    let uid = namespace["metadata"]["uid"]
        .as_str()
        .context("source namespace UID missing")?;
    broker_config::canonical_uuid(uid)?;
    ensure!(
        namespace["metadata"]["name"] == state.namespace
            && namespace["metadata"]["deletionTimestamp"].is_null(),
        "source namespace identity differs or is deleting"
    );
    let nonce = state
        .launch_nonce
        .as_ref()
        .context("launch nonce missing")?;
    let image =
        std::env::var("OPENSHELL_KATA_BROKER_IMAGE").context("immutable broker image required")?;
    policy::validate_image(&image)?;
    let initial: NetworkPolicy = broker_config::read_json(std::path::Path::new(
        &std::env::var_os("OPENSHELL_KATA_INITIAL_NETWORK_POLICY_FILE")
            .context("initial network policy file required")?,
    ))?;
    ensure!(
        config.provider_mediation && initial.tcp_allow.is_empty()
            || initial.is_subset_of(&config.operator_ceiling)?,
        "initial network policy exceeds operator ceiling"
    );
    let network = HostedBrokerConfig {
        version: 1,
        provider_mediation: config.provider_mediation,
        gateway_endpoint: config.gateway_endpoint.clone(),
        gateway_ca_pem: if config.provider_mediation {
            std::fs::read_to_string(&config.gateway_ca_file)?
        } else {
            String::new()
        },
        operator_ceiling: config.operator_ceiling.clone(),
        initial_ceiling: initial,
        binding: BrokerBinding {
            workspace: state.workspace.clone(),
            namespace_uid: uid.into(),
            sandbox_id: state.sandbox_id.clone(),
            launch_nonce: nonce.clone(),
            expires_at_unix: state.expires_at.context("lease missing")?,
        },
        protected_hostname_suffixes: config.protected_hostname_suffixes.clone(),
        baseline_denied_cidrs: config.baseline_denied_cidrs.clone(),
        authorization_lease_secs: config.authorization_lease_secs,
    };
    network.validate()?;
    let inventory: InfrastructureInventory = broker_config::read_json(&config.inventory_file)?;
    inventory.validate_at(lease::now()?)?;
    let binding = Binding {
        name: format!("broker-{}", nonce.replace('-', "")),
        namespace: config.broker_namespace.clone(),
        namespace_uid: config.broker_namespace_uid.clone(),
        image,
        source_namespace_uid: uid.into(),
        sandbox_name: state.name.clone(),
        source_namespace: state.namespace.clone(),
        launch_nonce: nonce.clone(),
        config_sha256: network.digest()?,
        operator_config_sha256: config.digest()?,
        resolver_nameservers: config.resolver_nameservers.clone(),
        broker_config: Some(network),
        inventory: Some(inventory.clone()),
        initial_inventory: Some(inventory),
        response: None,
        uid: String::new(),
        ip: String::new(),
    };
    binding.validate()?;
    Ok(binding)
}
pub(super) fn config(binding: &Binding) -> Result<Config> {
    let config =
        broker_config::configured()?.context("retained broker requires operator capability")?;
    ensure!(
        config.digest()? == binding.operator_config_sha256,
        "operator network configuration changed; reprovision required"
    );
    Ok(config)
}
pub(super) async fn namespace(client: &Client, binding: &Binding) -> Result<()> {
    let (broker_namespace, source) = tokio::try_join!(
        client.required("namespace", Some(&binding.namespace), None),
        client.required("namespace", Some(&binding.source_namespace), None)
    )?;
    ensure!(
        broker_namespace["metadata"]["name"] == binding.namespace
            && broker_namespace["metadata"]["uid"] == binding.namespace_uid
            && broker_namespace["metadata"]["deletionTimestamp"].is_null(),
        "broker namespace generation differs"
    );
    let workspace = &binding
        .broker_config
        .as_ref()
        .context("broker configuration missing")?
        .binding
        .workspace;
    policy::check_namespace(&source, workspace)?;
    ensure!(
        source["metadata"]["name"] == binding.source_namespace
            && source["metadata"]["uid"] == binding.source_namespace_uid
            && source["metadata"]["deletionTimestamp"].is_null(),
        "source namespace generation differs"
    );
    Ok(())
}
pub(super) async fn create(client: &Client, store: &Store, state: &State) -> Result<State> {
    let Some(binding) = &state.broker else {
        return Ok(state.clone());
    };
    let config = config(binding)?;
    create_with_config(client, store, state, &config).await
}

pub(super) async fn create_with_config(
    client: &Client,
    store: &Store,
    state: &State,
    config: &Config,
) -> Result<State> {
    let binding = state.broker.as_ref().context("broker missing")?;
    config.validate()?;
    namespace(client, binding).await?;
    ensure!(
        client
            .get("pod", Some(&binding.name), Some(&binding.namespace))
            .await?
            .is_none(),
        "broker launch name already exists"
    );
    let inventory = binding
        .inventory
        .as_ref()
        .context("broker inventory missing")?;
    let network = binding
        .broker_config
        .as_ref()
        .context("broker configuration missing")?;
    client
        .apply(&broker_manifest::network_policy(
            binding, config, inventory,
        )?)
        .await?;
    client
        .apply(&broker_manifest::configmap(
            binding,
            &binding.name,
            "config.json",
            network,
        )?)
        .await?;
    client
        .apply(&broker_manifest::configmap(
            binding,
            &format!("{}-inventory", binding.name),
            "inventory.json",
            inventory,
        )?)
        .await?;
    client
        .apply(&broker_manifest::pod(
            binding,
            state.expires_at.context("lease missing")?,
        )?)
        .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        ensure!(
            lease::now()? < state.expires_at.context("lease missing")?,
            "sandbox expired during broker startup"
        );
        let pod = client
            .required("pod", Some(&binding.name), Some(&binding.namespace))
            .await?;
        ensure!(
            pod["status"]["phase"] != "Failed",
            "broker failed before readiness"
        );
        if pod["status"]["phase"] == "Running" && pod["status"]["podIP"].as_str().is_some() {
            let mut next = binding.clone();
            next.uid = pod["metadata"]["uid"]
                .as_str()
                .context("broker UID missing")?
                .into();
            next.ip = pod["status"]["podIP"]
                .as_str()
                .context("broker IP missing")?
                .into();
            next.validate()?;
            let candidate = State {
                broker: Some(next),
                ..state.clone()
            };
            // Persist observed UID before exec or any subsequent guest creation.
            store.save(&candidate)?;
            if let Ok(response) =
                ready(client, candidate.broker.as_ref().context("broker missing")?).await
            {
                ensure!(
                    response.generation == 1
                        && response.policy.tcp_allow.is_empty()
                        && response.authorization_expires_at_unix == 0,
                    "broker did not boot denied"
                );
                let mut next = candidate.broker.clone().context("broker missing")?;
                next.response = Some(response);
                let ready = State {
                    broker: Some(next),
                    ..candidate
                };
                store.save(&ready)?;
                return Ok(ready);
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "broker startup timed out"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
pub(super) fn validate_response(
    binding: &Binding,
    response: &HostedControlResponse,
    nonce: &str,
) -> Result<()> {
    ensure!(
        response.nonce == nonce
            && response.binding
                == binding
                    .broker_config
                    .as_ref()
                    .context("broker config missing")?
                    .binding
            && response.config_sha256 == binding.config_sha256,
        "broker response binding differs"
    );
    broker_config::canonical_uuid(&response.startup_epoch)?;
    if let Some(previous) = &binding.response {
        ensure!(
            response.startup_epoch == previous.startup_epoch
                && response.generation >= previous.generation,
            "broker epoch or generation changed"
        );
    }
    ensure!(
        response.policy.digest()? == response.policy_sha256,
        "broker policy digest differs"
    );
    Ok(())
}
pub(super) async fn observe(client: &Client, binding: &Binding) -> Result<Value> {
    namespace(client, binding).await?;
    let pod = client
        .required("pod", Some(&binding.name), Some(&binding.namespace))
        .await?;
    ensure!(
        pod["metadata"]["uid"] == binding.uid && pod["status"]["podIP"] == binding.ip,
        "broker Pod generation changed"
    );
    ensure!(
        pod["status"]["phase"] == "Running"
            && pod["status"]["containerStatuses"]
                .as_array()
                .is_some_and(|s| s.len() == 1
                    && s[0]["ready"] == true
                    && s[0]["restartCount"] == 0),
        "broker not running in original process generation"
    );
    let expected = broker_manifest::pod(
        binding,
        binding
            .broker_config
            .as_ref()
            .context("broker config missing")?
            .binding
            .expires_at_unix,
    )?;
    let spec = &pod["spec"];
    super::broker_spec::validate(spec, &expected["spec"])?;
    ensure!(
        spec.get("runtimeClassName").is_none()
            && ["hostNetwork", "hostPID", "hostIPC"]
                .iter()
                .all(|k| spec.get(k).is_none_or(|v| v == false)),
        "broker trust boundary changed"
    );
    ensure!(
        pod["metadata"]["labels"] == broker_manifest::labels(binding)
            && pod["metadata"]["ownerReferences"] == expected["metadata"]["ownerReferences"],
        "broker ownership changed"
    );
    Ok(pod)
}
async fn exec(
    client: &Client,
    binding: &Binding,
    command: &str,
    request: Option<&HostedControlRequest>,
    nonce: &str,
) -> Result<HostedControlResponse> {
    observe(client, binding).await?;
    let mut args = vec![
        "exec",
        "-i",
        "-n",
        &binding.namespace,
        &binding.name,
        "-c",
        "broker",
        "--",
        "kata-network",
        command,
        "--control",
        "/run/broker/private/control.sock",
    ];
    let data = if let Some(request) = request {
        args.extend(["--request", "-"]);
        Some(serde_json::to_vec(request)?)
    } else {
        args.extend(["--nonce", nonce]);
        None
    };
    let output = tokio::time::timeout(Duration::from_secs(15), client.checked(&args, data))
        .await
        .context("broker control timed out")??;
    if command == "hosted-stop" {
        let pod = client
            .required("pod", Some(&binding.name), Some(&binding.namespace))
            .await?;
        ensure!(
            pod["metadata"]["uid"] == binding.uid,
            "broker replaced during stop"
        );
    } else {
        observe(client, binding).await?;
    }
    let response: HostedControlResponse = serde_json::from_slice(&output.stdout)?;
    validate_response(binding, &response, nonce)?;
    if command == "hosted-stop" {
        ensure!(
            response.stopping && response.active_connections == 0,
            "broker did not drain before stop acknowledgement"
        );
    } else {
        ensure!(!response.stopping, "broker is stopping");
    }
    Ok(response)
}
pub(super) async fn ready(client: &Client, binding: &Binding) -> Result<HostedControlResponse> {
    let nonce = uuid::Uuid::new_v4().to_string();
    exec(client, binding, "hosted-ready", None, &nonce).await
}
pub(super) async fn inspect(
    client: &Client,
    binding: &Binding,
    nonce: &str,
) -> Result<HostedControlResponse> {
    let previous = ready(client, binding).await?;
    let request = HostedControlRequest::Inspect {
        binding: previous.binding,
        startup_epoch: previous.startup_epoch,
        expected_generation: previous.generation,
        nonce: nonce.into(),
    };
    exec(client, binding, "hosted-inspect", Some(&request), nonce).await
}
pub(super) async fn authorize(
    client: &Client,
    state: &State,
    policy: NetworkPolicy,
    nonce: &str,
) -> Result<State> {
    let binding = state
        .broker
        .as_ref()
        .context("sandbox has no network broker")?;
    let config = config(binding)?;
    authorize_with_config(client, state, policy, nonce, &config).await
}

pub(super) async fn authorize_with_config(
    client: &Client,
    state: &State,
    policy: NetworkPolicy,
    nonce: &str,
    config: &Config,
) -> Result<State> {
    let binding = state
        .broker
        .as_ref()
        .context("sandbox has no network broker")?;
    config.validate()?;
    let inventory: InfrastructureInventory = broker_config::read_json(&config.inventory_file)?;
    inventory.validate_at(lease::now()?)?;
    let previous = inspect(client, binding, &uuid::Uuid::new_v4().to_string()).await?;
    let previous_generation = previous.generation;
    let normalized = policy.normalized()?;
    let request = HostedControlRequest::Authorize {
        binding: previous.binding,
        startup_epoch: previous.startup_epoch,
        expected_generation: previous.generation,
        nonce: nonce.into(),
        policy,
        inventory: inventory.clone(),
    };
    client
        .apply(&broker_manifest::network_policy(
            binding, config, &inventory,
        )?)
        .await?;
    let response = exec(client, binding, "hosted-authorize", Some(&request), nonce).await?;
    ensure!(
        response.policy == normalized
            && response.generation
                == previous_generation
                    .checked_add(1)
                    .context("broker generation overflow")?
            && response.inventory_generation == inventory.generation
            && response.inventory_sha256 == inventory.digest()?
            && response.authorization_expires_at_unix > lease::now()?,
        "broker authorization proof differs"
    );
    let next = Binding {
        inventory: Some(inventory),
        response: Some(response),
        ..binding.clone()
    };
    Ok(State {
        broker: Some(next),
        ..state.clone()
    })
}
pub(super) async fn authorize_providers(
    client: &Client,
    state: &State,
    providers: crate::network::ProviderAuthorization,
    nonce: &str,
) -> Result<State> {
    let binding = state
        .broker
        .as_ref()
        .context("sandbox has no provider broker")?;
    let config = config(binding)?;
    ensure!(
        config.provider_mediation,
        "provider mediation is not configured"
    );
    let inventory: InfrastructureInventory = broker_config::read_json(&config.inventory_file)?;
    inventory.validate_at(lease::now()?)?;
    let previous = inspect(client, binding, &uuid::Uuid::new_v4().to_string()).await?;
    let request = HostedControlRequest::AuthorizeProviders {
        binding: previous.binding,
        startup_epoch: previous.startup_epoch,
        expected_generation: previous.generation,
        nonce: nonce.into(),
        providers,
        inventory: inventory.clone(),
    };
    client
        .apply(&broker_manifest::network_policy(
            binding, &config, &inventory,
        )?)
        .await?;
    let response = exec(client, binding, "hosted-authorize", Some(&request), nonce).await?;
    ensure!(
        response.provider_material.is_some()
            && response.policy.tcp_allow.is_empty()
            && response.generation
                == previous
                    .generation
                    .checked_add(1)
                    .context("broker generation overflow")?
            && response.inventory_generation == inventory.generation
            && response.inventory_sha256 == inventory.digest()?
            && response.authorization_expires_at_unix > lease::now()?,
        "provider authorization proof differs"
    );
    let next = Binding {
        inventory: Some(inventory),
        response: Some(response),
        ..binding.clone()
    };
    Ok(State {
        broker: Some(next),
        ..state.clone()
    })
}

pub(super) async fn validate_resources(client: &Client, binding: &Binding) -> Result<()> {
    observe(client, binding).await?;
    let config = config(binding)?;
    let inventory = binding
        .inventory
        .as_ref()
        .context("broker inventory missing")?;
    let policies = client
        .required("networkpolicies", None, Some(&binding.namespace))
        .await?;
    broker_policy::validate_broker(
        policies["items"]
            .as_array()
            .context("invalid broker policy inventory")?,
        &broker_manifest::labels(binding),
        binding,
        &config,
        inventory,
    )?;
    validate_map(
        client,
        binding,
        &binding.name,
        "config.json",
        binding
            .broker_config
            .as_ref()
            .context("broker config missing")?,
    )
    .await?;
    validate_map(
        client,
        binding,
        &format!("{}-inventory", binding.name),
        "inventory.json",
        binding
            .initial_inventory
            .as_ref()
            .context("initial broker inventory missing")?,
    )
    .await?;
    Ok(())
}
async fn validate_map(
    client: &Client,
    binding: &Binding,
    name: &str,
    key: &str,
    value: &impl serde::Serialize,
) -> Result<()> {
    let actual = client
        .required("configmap", Some(name), Some(&binding.namespace))
        .await?;
    let expected = broker_manifest::configmap(binding, name, key, value)?;
    ensure!(
        actual["immutable"] == true
            && actual["data"] == expected["data"]
            && ["labels", "ownerReferences", "name", "namespace"]
                .iter()
                .all(|key| actual["metadata"][key] == expected["metadata"][key]),
        "broker immutable configuration changed"
    );
    Ok(())
}

pub(super) async fn delete(client: &Client, binding: &Binding) -> Result<()> {
    namespace(client, binding).await?;
    let mut stop_error = None;
    if let Some(pod) = client
        .get("pod", Some(&binding.name), Some(&binding.namespace))
        .await?
    {
        ensure!(
            (binding.uid.is_empty() || pod["metadata"]["uid"] == binding.uid)
                && pod["metadata"]["labels"] == broker_manifest::labels(binding),
            "refusing to stop replaced broker"
        );
        if !binding.uid.is_empty() && binding.response.is_some() {
            let stop = async {
                let previous = inspect(client, binding, &uuid::Uuid::new_v4().to_string()).await?;
                let nonce = uuid::Uuid::new_v4().to_string();
                let request = HostedControlRequest::Stop {
                    binding: previous.binding,
                    startup_epoch: previous.startup_epoch,
                    expected_generation: previous.generation,
                    nonce: nonce.clone(),
                };
                exec(client, binding, "hosted-stop", Some(&request), &nonce).await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(error) = stop {
                stop_error = Some(error);
            }
        }
        let uid = pod["metadata"]["uid"]
            .as_str()
            .context("broker UID missing")?;
        broker_config::canonical_uuid(uid)?;
        client.checked(&["delete","--raw",&format!("/api/v1/namespaces/{}/pods/{}",binding.namespace,binding.name),"-f","-"],Some(serde_json::to_vec(&json!({"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":uid},"gracePeriodSeconds":0}))?)).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while client
            .get("pod", Some(&binding.name), Some(&binding.namespace))
            .await?
            .is_some()
        {
            ensure!(
                tokio::time::Instant::now() < deadline,
                "broker survived deletion"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    for (kind, name) in [
        ("networkpolicy", binding.name.clone()),
        ("configmap", binding.name.clone()),
        ("configmap", format!("{}-inventory", binding.name)),
    ] {
        if let Some(resource) = client
            .get(kind, Some(&name), Some(&binding.namespace))
            .await?
        {
            ensure!(
                resource["metadata"]["labels"] == broker_manifest::labels(binding),
                "refusing to delete foreign broker resource"
            );
            client.delete(kind, &name, &binding.namespace).await?;
        }
    }
    if let Some(error) = stop_error {
        return Err(error)
            .context("broker Pod deleted but shutdown could not be independently acknowledged");
    }
    Ok(())
}
