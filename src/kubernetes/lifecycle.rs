//! Nonce-bound Kubernetes VM creation, revalidation, and retained-volume recovery.

use super::{
    broker, broker_config, broker_manifest,
    client::{Client, command_output},
    lease, manifest,
    model::{Route, State},
    policy, proof, reaper,
    store::Store,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::process::Command;

pub(super) struct Launch<'a> {
    pub(super) sandbox: &'a str,
    pub(super) workspace: &'a str,
    pub(super) image: &'a str,
    pub(super) nonce: &'a str,
    pub(super) storage_class: &'a str,
    pub(super) network: &'a ipnet::IpNet,
    pub(super) resource_shape: Option<crate::resource_shape::ResourceShape>,
    pub(super) lifetime_secs: u64,
}

pub(super) async fn create(
    client: &Client,
    store: &Store,
    folder: &Path,
    launch: &Launch<'_>,
) -> Result<Value> {
    let control_namespace = policy::configured_control_namespace()?;
    policy::validate_image(launch.image)?;
    uuid::Uuid::parse_str(launch.nonce)?;
    let namespace = policy::namespace(launch.workspace)?;
    let source_namespace = client.required("namespace", Some(&namespace), None).await?;
    policy::check_namespace(&source_namespace, launch.workspace)?;
    let network_config = broker_config::configured()?;
    let name = policy::resource_id(launch.sandbox)?;
    let existing = store.read(launch.sandbox)?;
    let expires = lease::expires_at(
        existing.as_ref().map(|state| state.expires_at),
        launch.lifetime_secs,
        lease::now()?,
    )?;
    if let Some(existing) = &existing {
        ensure!(
            existing.workspace == launch.workspace && existing.image == launch.image,
            "existing runtime has different retained identity"
        );
        ensure!(
            existing.resource_shape == launch.resource_shape,
            "retained resource shape differs; explicit cleanup required"
        );
        ensure!(
            existing.broker.is_some() == network_config.is_some(),
            "retained network profile differs; explicit cleanup required"
        );
        if let Some(binding) = &existing.broker {
            broker::config(binding)?;
        }
    }
    if client
        .get("pod", Some(&name), Some(&namespace))
        .await?
        .is_some()
    {
        let retained = existing.context("existing runtime lacks matching retained identity")?;
        let (state, _) =
            proof::verify(client, &retained, launch.storage_class, launch.network).await?;
        let host_key = store.key(launch.sandbox, "host_key.pub")?;
        store.known_hosts(launch.sandbox, &state.host, &host_key)?;
        store.save(&state)?;
        return Ok(serde_json::to_value(Route::from(&state))?);
    }
    let volume = client.get("pvc", Some(&name), Some(&namespace)).await?;
    if let Some(volume) = &volume {
        policy::require_owned(volume, &name)?;
        let storage = launch.resource_shape.clone().unwrap_or_default().storage();
        ensure!(
            volume["spec"]["storageClassName"] == launch.storage_class
                && volume["spec"]["resources"]["requests"]["storage"] == storage,
            "existing storage profile differs"
        );
    }
    for kind in ["networkpolicy", "secret"] {
        if let Some(resource) = client.get(kind, Some(&name), Some(&namespace)).await? {
            policy::require_owned(&resource, &name)?;
        }
    }
    // The intent is durable before keys or Kubernetes objects are changed. A
    // failed-launch abort can identify exactly this generation, including preboot.
    if let Some(binding) = existing.as_ref().and_then(|s| s.broker.as_ref()) {
        broker::delete(client, binding).await?;
    }
    let base = State {
        sandbox_id: launch.sandbox.into(),
        workspace: launch.workspace.into(),
        namespace: namespace.clone(),
        name: name.clone(),
        image: launch.image.into(),
        host: String::new(),
        port: 22,
        username: "sandbox".into(),
        runtime_identity: String::new(),
        broker: None,
        launch_nonce: Some(launch.nonce.into()),
        owns_volume_for_launch: volume.is_none(),
        expires_at: Some(expires),
        resource_shape: launch.resource_shape.clone(),
        private_key_path: folder.join("client_key"),
        known_hosts_path: folder.join("known_hosts"),
    };
    let state = if let Some(config) = &network_config {
        State {
            broker: Some(broker::intent(&base, &source_namespace, config)?),
            ..base
        }
    } else {
        base
    };
    store.save(&state)?;
    generate_keys(store, launch.sandbox, folder).await?;
    let host_key = store.key(launch.sandbox, "host_key.pub")?;
    store.known_hosts(launch.sandbox, "placeholder", &host_key)?;
    let state = broker::create(client, store, &state).await?;
    let network_policy = state.broker.as_ref().map_or_else(
        || manifest::network_policy(&name, &namespace, &control_namespace),
        |binding| broker_manifest::guest_policy(&name, &namespace, binding, &control_namespace),
    );
    client.apply(&network_policy).await?;
    if volume.is_none() {
        client
            .apply(&manifest::pvc(
                &name,
                &namespace,
                launch.storage_class,
                &state.shape(),
            ))
            .await?;
    }
    client.apply(&json!({"apiVersion":"v1","kind":"Secret","metadata":manifest::metadata(&name,&namespace),
        "type":"Opaque","stringData":{"authorized_keys":store.key(launch.sandbox,"client_key.pub")?,
        "host_key":store.key(launch.sandbox,"host_key")?}})).await?;
    let policies = client
        .required("networkpolicies", None, Some(&namespace))
        .await?;
    let items = policies["items"]
        .as_array()
        .context("invalid policy inventory")?;
    if let Some(binding) = &state.broker {
        super::broker_policy::validate_guest(
            items,
            &broker_manifest::guest_labels(&name, binding),
            binding,
            &control_namespace,
        )?;
    } else {
        policy::validate_policies(items, &manifest::labels(&name), &control_namespace)?;
    }
    let mut pod = broker_manifest::guest_pod(&state);
    pod["metadata"]["annotations"] = lease::annotations(launch.sandbox, launch.nonce, expires);
    if let Some(binding) = &state.broker {
        for (key, value) in [
            ("source-namespace-uid", binding.source_namespace_uid.clone()),
            ("broker-pod-uid", binding.uid.clone()),
            ("broker-ip", binding.ip.clone()),
            ("broker-port", "3128".into()),
            ("broker-config-sha256", binding.config_sha256.clone()),
        ] {
            pod["metadata"]["annotations"][format!("openshell-kata.io/{key}")] = json!(value);
        }
    }
    pod["spec"]["activeDeadlineSeconds"] = json!(
        expires
            .checked_sub(lease::now()?)
            .filter(|v| *v > 0)
            .context("sandbox lease expired before boot")?
    );
    super::billing::reserve(&state.workspace, launch.nonce).await?;
    client.apply(&pod).await?;
    let ready = wait_ready(client, &state, launch.storage_class, launch.network).await?;
    store.known_hosts(launch.sandbox, &ready.host, &host_key)?;
    store.save(&ready)?;
    Ok(serde_json::to_value(Route::from(&ready))?)
}

async fn generate_keys(store: &Store, sandbox: &str, folder: &Path) -> Result<()> {
    for filename in ["client_key", "host_key"] {
        store.remove_key(sandbox, filename)?;
        store.remove_key(sandbox, &format!("{filename}.pub"))?;
        let mut command = Command::new("ssh-keygen");
        command
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(folder.join(filename));
        let output = command_output(command, None, Duration::from_secs(10)).await?;
        ensure!(output.status.success(), "SSH key generation failed");
    }
    Ok(())
}

async fn wait_ready(
    client: &Client,
    state: &State,
    storage_class: &str,
    network: &ipnet::IpNet,
) -> Result<State> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
    loop {
        let pod = client
            .required("pod", Some(&state.name), Some(&state.namespace))
            .await?;
        super::billing::observe(&state.workspace, &pod).await?;
        enforce_lease_at(client, state, &pod, lease::now()?).await?;
        ensure!(pod["status"]["phase"] != "Failed", "guest boot failed");
        if pod["status"]["phase"] == "Running"
            && pod["status"]["containerStatuses"]
                .as_array()
                .is_some_and(|v| !v.is_empty() && v.iter().all(|s| s["ready"] == true))
        {
            return Ok(proof::verify(client, state, storage_class, network)
                .await?
                .0);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "guest readiness deadline exceeded"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

pub(super) async fn stop(
    client: &Client,
    store: &Store,
    state: &State,
    delete: bool,
) -> Result<()> {
    let namespace = client
        .required("namespace", Some(&state.namespace), None)
        .await?;
    policy::check_namespace(&namespace, &state.workspace)?;
    if let Some(binding) = &state.broker {
        ensure!(
            namespace["metadata"]["uid"] == binding.source_namespace_uid,
            "source namespace replaced"
        );
        broker::delete(client, binding).await?;
    }
    if let Some(pod) = client
        .get("pod", Some(&state.name), Some(&state.namespace))
        .await?
    {
        require_generation(&pod, state)?;
    }
    if delete {
        for kind in ["secret", "pvc", "networkpolicy"] {
            if let Some(resource) = client
                .get(kind, Some(&state.name), Some(&state.namespace))
                .await?
            {
                policy::require_owned(&resource, &state.name)?;
            }
        }
    }
    client.delete("pod", &state.name, &state.namespace).await?;
    if let Some(generation) = &state.launch_nonce {
        super::billing::release(generation).await?;
    }
    if delete {
        for kind in ["secret", "pvc", "networkpolicy"] {
            client.delete(kind, &state.name, &state.namespace).await?;
        }
        store.erase(&state.sandbox_id)?;
    }
    Ok(())
}

pub(super) async fn abort(
    client: &Client,
    store: &Store,
    state: &State,
    nonce: &str,
) -> Result<()> {
    uuid::Uuid::parse_str(nonce)?;
    if state.launch_nonce.as_deref() != Some(nonce) {
        return Ok(());
    }
    stop(client, store, state, false).await?;
    for kind in ["secret", "networkpolicy"] {
        if let Some(resource) = client
            .get(kind, Some(&state.name), Some(&state.namespace))
            .await?
        {
            policy::require_owned(&resource, &state.name)?;
            client.delete(kind, &state.name, &state.namespace).await?;
        }
    }
    if state.owns_volume_for_launch {
        if let Some(resource) = client
            .get("pvc", Some(&state.name), Some(&state.namespace))
            .await?
        {
            policy::require_owned(&resource, &state.name)?;
            client.delete("pvc", &state.name, &state.namespace).await?;
        }
        store.erase(&state.sandbox_id)?;
    }
    Ok(())
}

pub(super) fn require_generation(pod: &Value, state: &State) -> Result<()> {
    policy::require_owned(pod, &state.name)?;
    if !state.runtime_identity.is_empty() {
        ensure!(
            pod["metadata"]["uid"] == state.runtime_identity,
            "refusing to delete a replaced runtime"
        );
    }
    if let Some(nonce) = &state.launch_nonce {
        ensure!(
            pod["metadata"]["annotations"]["openshell-kata.io/launch-nonce"] == *nonce,
            "refusing to delete a different launch"
        );
    }
    Ok(())
}

async fn tighten_deadline(client: &Client, state: &State, pod: &Value) -> Result<()> {
    require_generation(pod, state)?;
    let nonce = state
        .launch_nonce
        .as_deref()
        .context("runtime launch nonce missing")?;
    let expires = state.expires_at.context("runtime lease missing")?;
    if let Some(patch) = lease::patch(pod, nonce, expires)? {
        client
            .checked(
                &[
                    "patch",
                    "pod",
                    &state.name,
                    "-n",
                    &state.namespace,
                    "--type=json",
                    "-p",
                    &serde_json::to_string(&patch)?,
                ],
                None,
            )
            .await?;
    }
    Ok(())
}

pub(super) async fn enforce_lease_at(
    client: &Client,
    state: &State,
    pod: &Value,
    now: u64,
) -> Result<()> {
    require_generation(pod, state)?;
    let expires = lease::validate_binding(pod, state)?;
    if now >= expires {
        reaper::delete_observed(client, pod).await?;
        anyhow::bail!("sandbox lease expired; runtime deletion requested");
    }
    if pod["status"]["startTime"].as_str().is_some() {
        tighten_deadline(client, state, pod).await?;
    }
    Ok(())
}
