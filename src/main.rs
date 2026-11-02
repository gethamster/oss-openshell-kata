use clap::Parser;
use openshell_kata::{
    config::Config, driver::Driver,
    proto::openshell::compute::v1::compute_driver_server::ComputeDriverServer,
};
use std::{
    os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt},
    sync::Arc,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Arc::new(Config::parse());
    config.validate()?;
    if let Some(parent) = config.socket.parent() {
        if !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("driver socket parent must be a private directory");
        }
    }
    clear_stale_socket(&config).await?;
    let driver = Driver::new(config.clone())?;
    driver.recover().await?;
    let listener = UnixListener::bind(&config.socket)?;
    std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o600))?;
    let shutdown_driver = driver.clone();
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(driver))
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler installation");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
        })
        .await?;
    shutdown_driver.close().await;
    std::fs::remove_file(&config.socket)?;
    Ok(())
}

async fn clear_stale_socket(config: &Config) -> anyhow::Result<()> {
    if config.socket.exists() {
        let metadata = std::fs::symlink_metadata(&config.socket)?;
        use std::os::unix::fs::MetadataExt;
        if !(config.runtime_profile == openshell_kata::config::RuntimeProfile::Kubernetes
            || (config.runtime_profile == openshell_kata::config::RuntimeProfile::Local
                && config.vm_policy.is_some()
                && !config.prototype_policy_mode))
            || !metadata.file_type().is_socket()
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            anyhow::bail!("driver socket already exists or has an unexpected owner/type");
        }
        match tokio::net::UnixStream::connect(&config.socket).await {
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(&config.socket)?
            }
            _ => anyhow::bail!("driver socket is live or its state cannot be verified"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_kata::config::RuntimeProfile;
    use std::path::PathBuf;

    fn config(socket: PathBuf) -> Config {
        Config::parse_from([
            "openshell-kata",
            "--socket",
            socket.to_str().expect("UTF8 socket"),
            "--gateway-ca",
            "/tmp/ca",
            "--lifecycle",
            "/tmp/lifecycle",
            "--vm-policy",
            "/tmp/policy",
        ])
    }

    #[tokio::test]
    async fn native_restart_removes_only_an_owned_refused_socket() {
        let directory = tempfile::tempdir().expect("private directory");
        let socket = directory.path().join("driver.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        let config = config(socket.clone());
        assert!(
            clear_stale_socket(&config).await.is_err(),
            "live socket must survive"
        );
        assert!(socket.exists());
        drop(listener);
        clear_stale_socket(&config)
            .await
            .expect("remove owned stale native socket");
        assert!(!socket.exists());
        std::fs::write(&socket, "keep").expect("unexpected file");
        assert!(clear_stale_socket(&config).await.is_err());
        assert_eq!(
            std::fs::read_to_string(&socket).expect("retained file"),
            "keep"
        );
    }

    #[tokio::test]
    async fn prototype_cannot_claim_native_socket_recovery() {
        let directory = tempfile::tempdir().expect("private directory");
        let socket = directory.path().join("driver.sock");
        drop(UnixListener::bind(&socket).expect("listener"));
        let mut config = config(socket.clone());
        config.vm_policy = None;
        config.runtime_profile = RuntimeProfile::Local;
        config.prototype_policy_mode = true;
        assert!(clear_stale_socket(&config).await.is_err());
        assert!(socket.exists());
    }
}
