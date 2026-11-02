use anyhow::{Context, Result, bail};
use clap::Parser;
use openshell_kata::config::MAX_SANDBOXES_LIMIT;
use openshell_kata::runtime::{
    command::NodeTransport,
    lifecycle::{self, Settings, WatchJob},
    model::Action,
    model::ResourceProfile,
    watchdog,
};
use std::path::PathBuf;

/// Local or self-hosted Kata lifecycle with fresh external enforcement proofs.
#[derive(Debug, Parser)]
struct Arguments {
    action: String,
    id: String,
    #[arg(long)]
    policy_file: Option<PathBuf>,
    #[arg(long)]
    proof_nonce: Option<String>,
    #[arg(long, default_value = "openshell-kata-enforcement")]
    vm: String,
    #[arg(long, value_enum, default_value = "lima")]
    node_transport: NodeTransport,
    #[arg(long, value_enum, default_value = "local")]
    resource_profile: ResourceProfile,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long, default_value = "/opt/openshell-kata/kata-runtime")]
    node_binary: PathBuf,
    /// Operator-selected immutable guest image; never a workload override.
    #[arg(long)]
    image: Option<String>,
    /// Operator node capacity in retained guests; required by `foundry-build`.
    #[arg(
        long,
        env = "OPENSHELL_KATA_MAX_SANDBOXES",
        value_parser = clap::value_parser!(u8).range(1..=i64::from(MAX_SANDBOXES_LIMIT))
    )]
    max_sandboxes: Option<u8>,
}
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Arguments::parse();
    use clap::ValueEnum;
    if let Ok(value) = std::env::var("OPENSHELL_KATA_NODE_TRANSPORT") {
        args.node_transport = NodeTransport::from_str(&value, false).map_err(anyhow::Error::msg)?;
    }
    if let Ok(value) = std::env::var("OPENSHELL_KATA_RESOURCE_PROFILE") {
        args.resource_profile =
            ResourceProfile::from_str(&value, false).map_err(anyhow::Error::msg)?;
    }
    if args.action == "reap-shim" {
        let count = openshell_kata::runtime::containerd::reap_shim(
            &args.id,
            args.proof_nonce
                .as_deref()
                .context("reap-shim requires creation nonce")?,
        )
        .await?;
        println!("{}", serde_json::json!({"reaped":count}));
        return Ok(());
    }
    if args.action == "set-spec" {
        if !cfg!(target_os = "linux") {
            bail!("containerd update runs on the Linux node only");
        }
        openshell_kata::runtime::containerd::set_spec(
            &args.id,
            args.proof_nonce
                .as_deref()
                .context("set-spec requires creation nonce")?,
            std::fs::read(args.policy_file.context("set-spec requires a spec file")?)?,
        )
        .await?;
        println!("{{}}");
        return Ok(());
    }
    if args.action == "watchdog" {
        if !cfg!(target_os = "linux") {
            bail!("watchdog runs on the Linux node only");
        }
        let job: WatchJob = serde_json::from_slice(&std::fs::read(&args.id)?)?;
        watchdog::watch_cgroup_ready(&job.cgroup, job.deadline, Some(&job.ready)).await?;
        return Ok(());
    }
    let root = match args
        .state_dir
        .or_else(|| std::env::var_os("OPENSHELL_KATA_STATE_DIR").map(PathBuf::from))
    {
        Some(root) => root,
        None => std::env::current_dir()?.join(".local/runtime"),
    };
    let settings = Settings {
        vm: args.vm,
        node_transport: args.node_transport,
        resource_profile: args.resource_profile,
        state_dir: root,
        node_binary: args.node_binary,
        image: args
            .image
            .or_else(|| std::env::var("OPENSHELL_KATA_GUEST_IMAGE").ok()),
        max_sandboxes: args.max_sandboxes,
    };
    let action: Action = args.action.parse().context("invalid runtime action")?;
    let value = lifecycle::execute(
        &settings,
        action,
        &args.id,
        args.policy_file.as_deref(),
        args.proof_nonce.as_deref(),
    )
    .await?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}
