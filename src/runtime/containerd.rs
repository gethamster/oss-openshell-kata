//! Narrow containerd metadata update used before a guest's first execution.
use anyhow::{Context, Result, bail};
use hyper_util::rt::TokioIo;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::net::UnixStream;
use tonic::{Request, transport::Endpoint};
use tower::service_fn;

/// Kata 4.3.1's pinned socket derivation (`crates/shim/src/shim.rs`).
pub fn shim_socket(id: &str) -> Result<std::path::PathBuf> {
    super::state::validate_id(id)?;
    Ok(format!(
        "/run/containerd/s/{:X}",
        Sha256::digest(format!("/run/containerd/containerd.sock/default/{id}").as_bytes())
    )
    .into())
}

#[derive(Clone, PartialEq, Message)]
struct Container {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(map = "string,string", tag = "2")]
    labels: HashMap<String, String>,
    #[prost(message, optional, tag = "5")]
    spec: Option<prost_types::Any>,
}
#[derive(Clone, PartialEq, Message)]
struct Get {
    #[prost(string, tag = "1")]
    id: String,
}
#[derive(Clone, PartialEq, Message)]
struct Response {
    #[prost(message, optional, tag = "1")]
    container: Option<Container>,
}
#[derive(Clone, PartialEq, Message)]
struct Update {
    #[prost(message, optional, tag = "1")]
    container: Option<Container>,
    #[prost(message, optional, tag = "2")]
    update_mask: Option<prost_types::FieldMask>,
}

#[derive(Clone, PartialEq, Message)]
struct TaskGet {
    #[prost(string, tag = "1")]
    container_id: String,
    #[prost(string, tag = "2")]
    exec_id: String,
}
#[derive(Clone, PartialEq, Message)]
struct TaskResponse {}
fn request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "containerd-namespace",
        tonic::metadata::MetadataValue::from_static("default"),
    );
    request
}

/// Identify a shim by complete argument tokens, never a substring or bare PID.
pub fn owned_shim_arguments(command: &[u8], id: &str) -> bool {
    let arguments: Vec<_> = command.split(|byte| *byte == 0).collect();
    arguments
        .windows(2)
        .any(|a| a[0] == b"-id" && a[1] == id.as_bytes())
        && arguments
            .windows(2)
            .any(|a| a[0] == b"-namespace" && a[1] == b"default")
}

/// Reap failed-start shims that have not yet joined the VM cgroup.
/// Linux pidfds prevent PID reuse from redirecting a cleanup signal.
pub async fn reap_shim(id: &str, nonce: &str) -> Result<u32> {
    super::state::validate_id(id)?;
    super::model::validate_nonce(nonce)?;
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(|_| async {
            UnixStream::connect("/run/containerd/containerd.sock")
                .await
                .map(TokioIo::new)
        }))
        .await?;
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.context("containerd is not ready")?;
    let response: tonic::Response<Response> = client
        .unary(
            request(Get { id: id.to_owned() }),
            tonic::codegen::http::uri::PathAndQuery::from_static(
                "/containerd.services.containers.v1.Containers/Get",
            ),
            tonic_prost::ProstCodec::default(),
        )
        .await?;
    let container = response
        .into_inner()
        .container
        .context("container ownership is missing")?;
    if container.id != id
        || container
            .labels
            .get("openshell-kata.creation-nonce")
            .is_none_or(|n| n != nonce)
    {
        bail!("refusing to reap a different creation generation");
    }
    let count = reap_processes(id)?;
    retire_socket(id).await?;
    if !task_exists(&mut client, id).await? {
        super::containerd_bundle::retire_abandoned(id).await?;
    }
    Ok(count)
}

async fn task_exists(
    client: &mut tonic::client::Grpc<tonic::transport::Channel>,
    id: &str,
) -> Result<bool> {
    client
        .ready()
        .await
        .context("containerd RPC is not ready")?;
    let task: Result<tonic::Response<TaskResponse>, tonic::Status> = client
        .unary(
            request(TaskGet {
                container_id: id.to_owned(),
                exec_id: String::new(),
            }),
            tonic::codegen::http::uri::PathAndQuery::from_static(
                "/containerd.services.tasks.v1.Tasks/Get",
            ),
            tonic_prost::ProstCodec::default(),
        )
        .await;
    match task {
        Ok(_) => Ok(true),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(false),
        Err(status) => Err(status.into()),
    }
}

async fn retire_socket(id: &str) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path = shim_socket(id)?;
    // A SIGKILLed shim exits only after the kernel unmaps all guest RAM, which
    // takes many seconds for a large guest. Stay within the node command bound.
    for _ in 0..600 {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(metadata) if !metadata.file_type().is_socket() || metadata.uid() != 0 => {
                bail!("refusing an unexpected shim socket artifact")
            }
            Ok(_) => {}
        }
        match UnixStream::connect(&path).await {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(&path)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(stream) => drop(stream),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    bail!("shim endpoint remains live after owned process cleanup")
}

#[cfg(target_os = "linux")]
fn reap_processes(id: &str) -> Result<u32> {
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    let mut reaped = 0;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .and_then(Pid::from_raw)
        else {
            continue;
        };
        let Ok(handle) = pidfd_open(pid, PidfdFlags::empty()) else {
            continue;
        };
        if std::fs::read_link(entry.path().join("exe")).ok().as_deref()
            != Some(std::path::Path::new(
                "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2",
            ))
        {
            continue;
        }
        let Ok(command) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if owned_shim_arguments(&command, id) {
            match pidfd_send_signal(&handle, Signal::KILL) {
                Ok(()) => reaped += 1,
                Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(reaped)
}
#[cfg(not(target_os = "linux"))]
fn reap_processes(_id: &str) -> Result<u32> {
    bail!("shim cleanup runs on the Linux node only")
}

/// Replace only the OCI spec on the already allocated private snapshot.
///
/// The caller runs on the trusted node before starting the container. The
/// existing creation label must match, and all snapshot/image metadata is kept.
pub async fn set_spec(id: &str, nonce: &str, spec_bytes: Vec<u8>) -> Result<()> {
    super::state::validate_id(id)?;
    super::model::validate_nonce(nonce)?;
    let parsed: serde_json::Value = serde_json::from_slice(&spec_bytes)?;
    if parsed
        .pointer("/linux/devices")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|v| !v.is_empty())
    {
        bail!("OCI spec exposes node devices");
    }
    let mounts = parsed
        .get("mounts")
        .and_then(serde_json::Value::as_array)
        .context("OCI mounts missing")?;
    if mounts
        .iter()
        .any(|m| m["type"] == "bind" || m["source"].as_str().is_some_and(|s| s.starts_with('/')))
    {
        bail!("OCI spec exposes host filesystem");
    }
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(|_| async {
            UnixStream::connect("/run/containerd/containerd.sock")
                .await
                .map(TokioIo::new)
        }))
        .await?;
    let mut client = tonic::client::Grpc::new(channel);
    client.ready().await.context("containerd is not ready")?;
    let task: Result<tonic::Response<TaskResponse>, tonic::Status> = client
        .unary(
            request(TaskGet {
                container_id: id.to_owned(),
                exec_id: String::new(),
            }),
            tonic::codegen::http::uri::PathAndQuery::from_static(
                "/containerd.services.tasks.v1.Tasks/Get",
            ),
            tonic_prost::ProstCodec::default(),
        )
        .await;
    match task {
        Err(status) if status.code() == tonic::Code::NotFound => {}
        Err(status) => return Err(status.into()),
        Ok(_) => bail!("refusing to modify an already-created guest task"),
    }
    client
        .ready()
        .await
        .context("containerd RPC is not ready")?;
    let response: tonic::Response<Response> = client
        .unary(
            request(Get { id: id.to_owned() }),
            tonic::codegen::http::uri::PathAndQuery::from_static(
                "/containerd.services.containers.v1.Containers/Get",
            ),
            tonic_prost::ProstCodec::default(),
        )
        .await?;
    let original = response
        .into_inner()
        .container
        .context("containerd returned no container")?;
    if original.id != id
        || original
            .labels
            .get("openshell-kata.creation-nonce")
            .is_none_or(|n| n != nonce)
    {
        bail!("container creation identity does not match");
    }
    let original_spec = original.spec.context("container has no OCI spec")?;
    let container = Container {
        id: id.to_owned(),
        labels: HashMap::new(),
        spec: Some(prost_types::Any {
            type_url: original_spec.type_url,
            value: spec_bytes.clone(),
        }),
    };
    client
        .ready()
        .await
        .context("containerd RPC is not ready")?;
    let response: tonic::Response<Response> = client
        .unary(
            request(Update {
                container: Some(container),
                update_mask: Some(prost_types::FieldMask {
                    paths: vec!["spec".into()],
                }),
            }),
            tonic::codegen::http::uri::PathAndQuery::from_static(
                "/containerd.services.containers.v1.Containers/Update",
            ),
            tonic_prost::ProstCodec::default(),
        )
        .await?;
    let stored = response
        .into_inner()
        .container
        .and_then(|c| c.spec)
        .context("containerd did not return stored spec")?;
    if stored.value != spec_bytes {
        bail!("stored OCI spec differs from requested spec");
    }
    Ok(())
}
