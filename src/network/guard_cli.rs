//! Bounded private control protocol for the hosted broker.

use super::{
    HostedBrokerConfig, HostedBrokerHandle, HostedControlRequest, HostedControlResponse,
    InfrastructureInventory, bind_hosted_broker,
};
use anyhow::{Context, Result, bail, ensure};
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

const LIMIT: usize = 1024 * 1024;

pub(crate) async fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        tokio::io::stdin()
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
    } else {
        tokio::fs::File::open(path)
            .await?
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
    }
    ensure!(
        bytes.len() <= LIMIT,
        "hosted broker input exceeds size limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

async fn exchange(control: &Path, request: &HostedControlRequest) -> Result<HostedControlResponse> {
    let mut stream = UnixStream::connect(control).await?;
    let mut bytes = serde_json::to_vec(request)?;
    ensure!(bytes.len() < LIMIT, "hosted control request exceeds limit");
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    let mut reader = BufReader::new(stream);
    let mut bytes = Vec::new();
    (&mut reader)
        .take(262145)
        .read_until(b'\n', &mut bytes)
        .await?;
    ensure!(
        bytes.len() <= 262144,
        "hosted control response exceeds limit"
    );
    let response: HostedControlResponse =
        serde_json::from_slice(&bytes).context("hosted broker rejected control request")?;
    ensure!(
        response.nonce == request.nonce(),
        "hosted broker challenge differs"
    );
    if let Some((binding, epoch, generation)) = request.expected() {
        ensure!(
            &response.binding == binding && response.startup_epoch == epoch,
            "hosted broker response launch binding changed"
        );
        let expected = if matches!(
            request,
            HostedControlRequest::Authorize { .. }
                | HostedControlRequest::AuthorizeProviders { .. }
                | HostedControlRequest::Stop { .. }
        ) {
            generation
                .checked_add(1)
                .context("expected generation overflow")?
        } else {
            generation
        };
        ensure!(
            response.generation == expected,
            "hosted broker response generation differs"
        );
    }
    ensure!(
        response.policy_sha256 == response.policy.digest()?,
        "hosted broker policy digest differs"
    );
    Ok(response)
}

pub(crate) async fn send(control: &Path, request: HostedControlRequest) -> Result<()> {
    let response = tokio::time::timeout(Duration::from_secs(10), exchange(control, &request))
        .await
        .context("hosted broker control deadline exceeded")??;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

pub(crate) async fn from_path(control: &Path, path: &Path, action: &str) -> Result<()> {
    let request: HostedControlRequest = read(path).await?;
    let matches = matches!(
        (&request, action),
        (HostedControlRequest::Authorize { .. }, "authorize")
            | (HostedControlRequest::AuthorizeProviders { .. }, "authorize")
            | (HostedControlRequest::Inspect { .. }, "inspect")
            | (HostedControlRequest::Stop { .. }, "stop")
    );
    ensure!(matches, "hosted control action differs from command");
    send(control, request).await
}

struct SocketFile(PathBuf);
impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub(super) async fn connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    broker: &HostedBrokerHandle,
) -> Result<bool> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut bytes = Vec::new();
    (&mut reader)
        .take((LIMIT + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .await?;
    ensure!(bytes.len() <= LIMIT, "oversized hosted control request");
    let request: HostedControlRequest = serde_json::from_slice(&bytes)?;
    let authorize = matches!(
        request,
        HostedControlRequest::Authorize { .. } | HostedControlRequest::AuthorizeProviders { .. }
    );
    let response = tokio::select! {
        biased;
        gone=reader.read_u8()=>{let _=gone;bail!("hosted control caller disconnected or sent extra data");}
        result=broker.request(request)=>result?,
    };
    // The core protects cancellation during mutation. Keep that protection
    // through the final acknowledgement write as well.
    let mut rollback = authorize.then(|| broker.mutation_guard());
    let mut bytes = serde_json::to_vec(&response)?;
    ensure!(
        bytes.len() < 262144,
        "hosted control response exceeds bound"
    );
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.shutdown().await?;
    if let Some(guard) = &mut rollback {
        guard.disarm();
    }
    Ok(response.stopping)
}

pub(crate) async fn serve(
    address: SocketAddr,
    config_path: &Path,
    inventory_path: &Path,
    control: &Path,
) -> Result<()> {
    let config: HostedBrokerConfig = read(config_path).await?;
    let inventory: InfrastructureInventory = read(inventory_path).await?;
    // Validate/start before binding control, so invalid authority leaves no socket.
    let broker = bind_hosted_broker(address, config, inventory).await?;
    let parent = control
        .parent()
        .context("hosted control directory required")?;
    if !parent.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0,
        "hosted control directory must be private (0700)"
    );
    let listener = UnixListener::bind(control)?;
    std::fs::set_permissions(control, std::fs::Permissions::from_mode(0o600))?;
    let _socket = SocketFile(control.into());
    let state = broker.snapshot(&uuid::Uuid::new_v4().to_string()).await?;
    println!(
        "{}",
        serde_json::json!({"ready":true,"address":broker.local_addr(),"state":state})
    );
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
            accepted=listener.accept()=>{
                let(stream,_)=accepted?;
                match tokio::time::timeout(Duration::from_secs(10),connection(stream,&broker)).await {
                    Ok(Ok(true))=>break,Ok(Ok(false))=>{},Ok(Err(error))=>tracing::warn!(%error,"hosted broker control rejected"),Err(_)=>tracing::warn!("hosted broker control timed out"),
                }
            }
        }
    }
    broker.shutdown().await
}
