use super::{
    BrokerHandle, FenceProof, FenceSpec, NetworkPolicy, bind_broker, install_fence,
    mediation::{self, GuestMaterial, Mediation},
    remove_fence, verify_fence,
};
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

/// Standalone outer-host network broker and fence operations.
#[derive(Debug, Parser)]
pub struct NetworkCli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Debug, Subcommand)]
enum Command {
    BrokerHosted {
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        control: PathBuf,
    },
    HostedAuthorize {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    HostedInspect {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    HostedStop {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    HostedReady {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        nonce: String,
    },
    Broker {
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        control: PathBuf,
        /// Sandbox whose provider credentials this broker may hold.
        #[arg(long, requires = "guest_ip")]
        sandbox_id: Option<String>,
        /// The only peer address admitted to inspected destinations.
        #[arg(long, requires = "sandbox_id")]
        guest_ip: Option<std::net::IpAddr>,
    },
    /// Install a provider snapshot read from stdin into a running broker.
    Credentials {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        sandbox_id: String,
        #[arg(long)]
        nonce: String,
    },
    /// Generate a sandbox proxy CA into a private node directory.
    CaGenerate {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Install the public proxy CA into a mounted, not yet booted guest root.
    GuestTrust {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
    },
    Install {
        #[arg(long)]
        spec: PathBuf,
    },
    Verify {
        #[arg(long)]
        proof: PathBuf,
    },
    Remove {
        #[arg(long)]
        proof: PathBuf,
    },
    Plan {
        #[arg(long)]
        spec: PathBuf,
    },
    Update {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        nonce: String,
    },
    Inspect {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        nonce: String,
    },
    Stop {
        #[arg(long)]
        control: PathBuf,
        #[arg(long)]
        nonce: String,
    },
}
/// Base64 protobuf provider snapshot; it carries credentials, so it is never
/// formatted.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct Snapshot(String);
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Snapshot([REDACTED])")
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum ControlRequest {
    Update {
        nonce: String,
        policy: NetworkPolicy,
    },
    Inspect {
        nonce: String,
    },
    Stop {
        nonce: String,
    },
    Credentials {
        nonce: String,
        sandbox_id: String,
        snapshot: Snapshot,
    },
}
impl ControlRequest {
    fn nonce(&self) -> &str {
        match self {
            Self::Update { nonce, .. }
            | Self::Inspect { nonce }
            | Self::Stop { nonce }
            | Self::Credentials { nonce, .. } => nonce,
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
struct ControlResponse {
    nonce: String,
    generation: u64,
    policy: NetworkPolicy,
    stopping: bool,
    #[serde(default)]
    active_connections: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    material: Option<GuestMaterial>,
}

/// Control requests carry at most one bounded provider snapshot.
const MAX_CONTROL_REQUEST: usize = 2 * mediation::MAX_SNAPSHOT_BYTES;

async fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
    if bytes.len() > 1024 * 1024 {
        bail!("network configuration exceeds size limit");
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn nonce_valid(nonce: &str) -> bool {
    (16..=128).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
async fn request_control(path: &Path, request: ControlRequest) -> Result<ControlResponse> {
    let mut stream = UnixStream::connect(path).await?;
    let mut bytes = serde_json::to_vec(&request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    let mut result = Vec::new();
    let mut reader = BufReader::new(stream);
    (&mut reader)
        .take(65537)
        .read_until(b'\n', &mut result)
        .await?;
    if result.len() > 65536 {
        bail!("oversized broker response");
    }
    let response: ControlResponse =
        serde_json::from_slice(&result).context("broker control request failed")?;
    if response.nonce != request.nonce() {
        bail!("broker control nonce mismatch");
    }
    Ok(response)
}
async fn control_connection(stream: UnixStream, broker: &BrokerHandle) -> Result<bool> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        (&mut reader)
            .take(MAX_CONTROL_REQUEST as u64 + 1)
            .read_until(b'\n', &mut bytes),
    )
    .await??;
    if bytes.len() > MAX_CONTROL_REQUEST {
        bail!("oversized broker control request");
    }
    // Parse errors could quote a credential; report none of the input.
    let request: ControlRequest =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid control request"))?;
    drop(bytes);
    if !nonce_valid(request.nonce()) {
        bail!("invalid broker request nonce");
    }
    let stopping = matches!(request, ControlRequest::Stop { .. });
    if stopping {
        broker.deny_and_drain().await?;
    }
    if let ControlRequest::Update { policy, .. } = &request {
        broker.replace_policy(policy.clone()).await?;
    }
    let material = match &request {
        ControlRequest::Credentials {
            sandbox_id,
            snapshot,
            ..
        } => {
            let mediation = broker
                .mediation()
                .context("broker has no provider mediation")?;
            if mediation.sandbox_id() != sandbox_id {
                bail!("provider snapshot names another sandbox");
            }
            let snapshot = base64::engine::general_purpose::STANDARD
                .decode(&snapshot.0)
                .map_err(|_| anyhow::anyhow!("invalid provider snapshot encoding"))?;
            Some(mediation.install(&snapshot))
        }
        _ => None,
    };
    let (generation, policy) = broker.snapshot().await?;
    let response = ControlResponse {
        nonce: request.nonce().into(),
        generation,
        policy,
        stopping,
        active_connections: broker.active_connections().await,
        material,
    };
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.shutdown().await?;
    Ok(stopping)
}

struct SocketFile(PathBuf);
impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn run_broker(
    address: SocketAddr,
    policy_path: &Path,
    control: &Path,
    binding: Option<(String, std::net::IpAddr)>,
) -> Result<()> {
    let parent = control
        .parent()
        .context("broker control directory required")?;
    if !parent.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    if parent.metadata()?.permissions().mode() & 0o077 != 0 {
        bail!("broker control directory must be private (0700)");
    }
    let listener = UnixListener::bind(control).context("binding private broker control socket")?;
    std::fs::set_permissions(control, std::fs::Permissions::from_mode(0o600))?;
    let _socket = SocketFile(control.into());
    let mediation = binding
        .map(|(sandbox_id, guest_ip)| {
            let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
            Mediation::new(
                sandbox_id,
                guest_ip,
                Mediation::load_ca(credentials.as_deref())?,
            )
        })
        .transpose()?;
    let broker = bind_broker(address, read_json(policy_path).await?, mediation).await?;
    let (generation, policy) = broker.snapshot().await?;
    println!(
        "{}",
        serde_json::json!({"ready":true,"address":broker.local_addr(),"generation":generation,"policy":policy})
    );
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            accepted=listener.accept()=>{let(stream,_)=accepted?;match control_connection(stream,&broker).await{Ok(true)=>break,Ok(false)=>{},Err(error)=>tracing::warn!(%error,"broker control rejected")}}
        }
    }
    broker.shutdown().await
}

/// Execute one host-side operation; structured output goes to stdout.
pub async fn run_network(cli: NetworkCli) -> Result<()> {
    match cli.command {
        Command::BrokerHosted {
            bind,
            config,
            inventory,
            control,
        } => super::guard::cli::serve(bind, &config, &inventory, &control).await,
        Command::HostedAuthorize { control, request } => {
            super::guard::cli::from_path(&control, &request, "authorize").await
        }
        Command::HostedInspect { control, request } => {
            super::guard::cli::from_path(&control, &request, "inspect").await
        }
        Command::HostedStop { control, request } => {
            super::guard::cli::from_path(&control, &request, "stop").await
        }
        Command::HostedReady { control, nonce } => {
            super::guard::cli::send(
                &control,
                super::guard::HostedControlRequest::Ready { nonce },
            )
            .await
        }
        Command::Broker {
            bind,
            policy,
            control,
            sandbox_id,
            guest_ip,
        } => run_broker(bind, &policy, &control, sandbox_id.zip(guest_ip)).await,
        Command::Credentials {
            control,
            sandbox_id,
            nonce,
        } => {
            if !nonce_valid(&nonce) {
                bail!("invalid broker request nonce");
            }
            let mut snapshot = Vec::new();
            tokio::io::stdin()
                .take(mediation::MAX_SNAPSHOT_BYTES as u64 + 1)
                .read_to_end(&mut snapshot)
                .await?;
            if snapshot.len() > mediation::MAX_SNAPSHOT_BYTES {
                bail!("provider snapshot exceeds its size limit");
            }
            let snapshot = Snapshot(base64::engine::general_purpose::STANDARD.encode(&snapshot));
            let result = request_control(
                &control,
                ControlRequest::Credentials {
                    nonce,
                    sandbox_id: sandbox_id.clone(),
                    snapshot,
                },
            )
            .await?;
            let material = result
                .material
                .as_ref()
                .context("broker returned no provider material")?;
            if material.sandbox_id != sandbox_id {
                bail!("broker returned material for another sandbox");
            }
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
        Command::CaGenerate { directory } => {
            let certificate = mediation::generate_ca(&directory)?;
            println!("{}", serde_json::json!({ "certificate": certificate }));
            Ok(())
        }
        Command::GuestTrust { root, certificate } => {
            let certificate = std::fs::read_to_string(certificate)?;
            mediation::install_guest_trust(&root, &certificate)?;
            println!("{{\"installed\":true}}");
            Ok(())
        }
        Command::Install { spec } => {
            let proof = install_fence(read_json::<FenceSpec>(&spec).await?).await?;
            println!("{}", serde_json::to_string(&proof)?);
            Ok(())
        }
        Command::Verify { proof } => {
            verify_fence(&read_json::<FenceProof>(&proof).await?).await?;
            println!("{{\"verified\":true}}");
            Ok(())
        }
        Command::Remove { proof } => {
            remove_fence(&read_json::<FenceProof>(&proof).await?).await?;
            println!("{{\"removed\":true}}");
            Ok(())
        }
        Command::Plan { spec } => {
            print!("{}", read_json::<FenceSpec>(&spec).await?.rules()?);
            Ok(())
        }
        Command::Update {
            control,
            policy,
            nonce,
        } => {
            if !nonce_valid(&nonce) {
                bail!("invalid broker request nonce");
            }
            let result = request_control(
                &control,
                ControlRequest::Update {
                    nonce,
                    policy: read_json(&policy).await?,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
        Command::Inspect { control, nonce } => {
            if !nonce_valid(&nonce) {
                bail!("invalid broker request nonce");
            }
            let result = request_control(&control, ControlRequest::Inspect { nonce }).await?;
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
        Command::Stop { control, nonce } => {
            if !nonce_valid(&nonce) {
                bail!("invalid broker request nonce");
            }
            let result = request_control(&control, ControlRequest::Stop { nonce }).await?;
            println!("{}", serde_json::to_string(&result)?);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_control_requests_never_format_snapshots() {
        let request = ControlRequest::Credentials {
            nonce: "nonce-0123456789abcdef".into(),
            sandbox_id: "sandbox".into(),
            snapshot: Snapshot("c2stYW50LXNlY3JldA==".into()),
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("[REDACTED]") && !rendered.contains("c2stYW50"));
    }
}
