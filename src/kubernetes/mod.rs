//! Cloud-independent Kubernetes launcher for operator-qualified Rust Kata guests.

mod billing;
mod broker;
mod broker_config;
mod broker_manifest;
mod broker_policy;
mod broker_spec;
#[cfg(test)]
mod broker_tests;
mod client;
#[cfg(test)]
mod expiry_tests;
mod fence;
mod lease;
mod lifecycle;
mod manifest;
mod model;
mod node_broker;
mod policy;
mod proof;
mod reaper;
mod store;
#[cfg(test)]
mod test_program;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod workspace_tests;

pub use broker_config::HostedNetworkConfig;
#[cfg(test)]
pub(crate) use node_broker::node_broker_manifest;
pub(crate) use node_broker::validate_node_broker_pod;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, ValueEnum};
use std::{env, path::PathBuf};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Action {
    Create,
    Start,
    Verify,
    ApplyNetwork,
    Stop,
    Delete,
    Abort,
    EnsureWorkspace,
    DeleteWorkspace,
    ReapExpired,
}
#[derive(Debug, Parser)]
struct Arguments {
    #[arg(value_enum)]
    action: Action,
    sandbox: String,
    #[arg(long)]
    proof_nonce: Option<uuid::Uuid>,
    /// Reconcile one bounded batch instead of running the independent controller.
    #[arg(long)]
    once: bool,
}

/// Execute the trusted launcher's lifecycle contract using operator environment.
///
/// # Errors
/// Rejects malformed identifiers, unsafe state, unqualified resources, broadening
/// network policies, mismatched generations, and failed or timed-out operations.
pub async fn run() -> Result<()> {
    let arguments = Arguments::parse();
    let client = client::Client {
        program: "kubectl".into(),
        context: env::var("OPENSHELL_KATA_KUBE_CONTEXT")
            .ok()
            .filter(|s| !s.is_empty()),
    };
    if matches!(arguments.action, Action::ReapExpired) {
        return reaper::run(&client, &arguments.sandbox, arguments.once).await;
    }
    ensure!(!arguments.once, "--once is only valid for reap-expired");
    if matches!(
        arguments.action,
        Action::EnsureWorkspace | Action::DeleteWorkspace
    ) {
        workspace(&client, &arguments.sandbox, arguments.action).await?;
        println!("{{}}");
        return Ok(());
    }
    policy::resource_id(&arguments.sandbox)?;
    let root = env::var_os("OPENSHELL_KATA_STATE_DIR")
        .map_or_else(|| PathBuf::from("/var/lib/openshell-kata"), PathBuf::from);
    let store = store::Store::new(&root)?;
    let _lock = store.lock(&arguments.sandbox)?;
    let folder = store.folder(&arguments.sandbox)?;
    let state = store.read(&arguments.sandbox)?;
    let result = match arguments.action {
        Action::Create | Action::Start => {
            let workspace = env::var("OPENSHELL_KATA_WORKSPACE")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| state.as_ref().map(|s| s.workspace.clone()))
                .context("workspace required")?;
            let image = env::var("OPENSHELL_KATA_GUEST_IMAGE")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| state.as_ref().map(|s| s.image.clone()))
                .context("immutable guest image required")?;
            let storage_class = storage_class()?;
            let network = network()?;
            let resource_shape = resource_shape()?;
            let nonce = arguments
                .proof_nonce
                .unwrap_or_else(uuid::Uuid::new_v4)
                .to_string();
            lifecycle::create(
                &client,
                &store,
                &folder,
                &lifecycle::Launch {
                    sandbox: &arguments.sandbox,
                    workspace: &workspace,
                    image: &image,
                    nonce: &nonce,
                    storage_class: &storage_class,
                    network: &network,
                    resource_shape,
                    lifetime_secs: env::var("OPENSHELL_KATA_LIFETIME_SECS")
                        .unwrap_or_else(|_| "3600".into())
                        .parse()
                        .context("invalid VM lifetime")?,
                },
            )
            .await?
        }
        Action::Verify | Action::ApplyNetwork => {
            let state = state.context("missing retained runtime identity")?;
            let nonce = if state.broker.is_some() {
                arguments
                    .proof_nonce
                    .context("verification requires fresh proof nonce")?
            } else {
                arguments.proof_nonce.unwrap_or_else(uuid::Uuid::new_v4)
            }
            .to_string();
            if matches!(arguments.action, Action::ApplyNetwork) {
                ensure!(
                    state.broker.is_some(),
                    "network authorization requires broker profile"
                );
                ensure!(
                    env::var("OPENSHELL_KATA_RUNTIME_IDENTITY").ok().as_deref()
                        == Some(state.runtime_identity.as_str()),
                    "network authorization runtime identity differs"
                );
                proof::verify_with_nonce(&client, &state, &storage_class()?, &network()?, &nonce)
                    .await?;
                let path = env::var_os("OPENSHELL_KATA_NETWORK_POLICY_FILE")
                    .context("network policy file required")?;
                let policy = broker_config::read_json(std::path::Path::new(&path))?;
                let next = broker::authorize(&client, &state, policy, &nonce).await?;
                store.save(&next)?;
                proof::verify_with_nonce(&client, &next, &storage_class()?, &network()?, &nonce)
                    .await?
                    .1
            } else {
                proof::verify_with_nonce(&client, &state, &storage_class()?, &network()?, &nonce)
                    .await?
                    .1
            }
        }
        Action::Stop | Action::Delete => {
            if let Some(state) = state {
                lifecycle::stop(
                    &client,
                    &store,
                    &state,
                    matches!(arguments.action, Action::Delete),
                )
                .await?;
            }
            serde_json::json!({})
        }
        Action::Abort => {
            let nonce = arguments
                .proof_nonce
                .context("abort requires launch nonce")?
                .to_string();
            if let Some(state) = state {
                lifecycle::abort(&client, &store, &state, &nonce).await?;
            }
            serde_json::json!({})
        }
        Action::EnsureWorkspace | Action::DeleteWorkspace | Action::ReapExpired => {
            unreachable!("workspace action handled before state access")
        }
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn storage_class() -> Result<String> {
    let value = env::var("OPENSHELL_KATA_STORAGE_CLASS")
        .context("explicit operator storage class required")?;
    policy::validate_storage_class(&value)?;
    Ok(value)
}

/// The adapter-selected declared shape for create/start; absent means the default.
fn resource_shape() -> Result<Option<crate::resource_shape::ResourceShape>> {
    let Some(value) = env::var("OPENSHELL_KATA_RESOURCE_SHAPE")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let shape = crate::resource_shape::ResourceShape::parse(&value)?;
    ensure!(
        !shape.is_default(),
        "the default resource shape is implicit"
    );
    Ok(Some(shape))
}

fn network() -> Result<ipnet::IpNet> {
    let network: ipnet::IpNet = env::var("OPENSHELL_KATA_GUEST_NETWORK_CIDR")
        .context("explicit operator guest network CIDR required")?
        .parse()?;
    match network {
        ipnet::IpNet::V4(net) => ensure!(
            net.network().is_private() && net.broadcast().is_private(),
            "operator guest network must be private IPv4"
        ),
        ipnet::IpNet::V6(_) => bail!("IPv6 guest routing is not qualified"),
    }
    Ok(network)
}

async fn workspace(client: &client::Client, workspace: &str, action: Action) -> Result<()> {
    let namespace = policy::namespace(workspace)?;
    let observed = client.get("namespace", Some(&namespace), None).await?;
    let Some(observed) = observed else {
        ensure!(
            matches!(action, Action::DeleteWorkspace),
            "required Kubernetes resource is absent"
        );
        return Ok(());
    };
    policy::check_namespace(&observed, workspace)?;
    if matches!(action, Action::DeleteWorkspace) {
        let pods = client.required("pods", None, Some(&namespace)).await?;
        let items = pods["items"]
            .as_array()
            .context("invalid workspace pod inventory")?;
        ensure!(
            items.iter().all(
                |item| item["metadata"]["labels"]["app.kubernetes.io/managed-by"]
                    != manifest::OWNER
            ),
            "workspace still has active guests"
        );
    }
    Ok(())
}
