//! Pinned guest SSH transport independent of containerd execution streams.

use super::command::{Node, NodeTransport};
use super::state::StateDirectory;
use crate::guest::Guest;
use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::net::IpAddr;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

const SSH_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_START_TIMEOUT: Duration = Duration::from_secs(20);
const READINESS_DEADLINE: Duration = Duration::from_secs(180);
const PING_COMMAND: &str = "curl --fail --silent --show-error --max-time 2 --unix-socket /var/run/docker.sock http://localhost/_ping";

/// Generate a unique client identity and guest host key in one private state directory.
///
/// # Errors
/// Rejects existing key paths or reports key-generation failures without key material.
pub async fn generate_keys(
    node: &Node,
    state: &StateDirectory,
    id: &str,
) -> Result<(PathBuf, PathBuf)> {
    let directory = state.path(id)?;
    let metadata = directory
        .symlink_metadata()
        .context("opening identity directory")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("runtime identity directory is unsafe");
    }
    let client = directory.join("client_key");
    let host = directory.join("host_key");
    for key in [&client, &host] {
        for candidate in [key.to_path_buf(), key.with_extension("pub")] {
            if candidate.symlink_metadata().is_ok() {
                bail!("runtime identity path already exists");
            }
        }
    }
    for key in [&client, &host] {
        node.command(
            "ssh-keygen",
            &[
                "-q".into(),
                "-t".into(),
                "ed25519".into(),
                "-N".into(),
                "".into(),
                "-f".into(),
                key.as_os_str().to_owned(),
            ],
            SSH_COMMAND_TIMEOUT,
        )
        .await?;
    }
    Ok((client, host))
}

/// Open a loopback-only SSH forward to one authenticated guest.
///
/// An existing live tunnel is retained. Call [`close_tunnel`] first when the
/// guest IP changes, so a restart cannot retain a stale forwarding destination.
///
/// # Errors
/// Rejects invalid guest routes, unsafe socket entries, and transport startup failures.
pub async fn open_tunnel(
    node: &Node,
    state: &StateDirectory,
    id: &str,
    guest_ip: &str,
    guest: &Guest,
) -> Result<()> {
    validate_guest(guest)?;
    if guest.sandbox_id != id {
        bail!("guest identity does not match its tunnel");
    }
    let address: IpAddr = guest_ip.parse().context("invalid guest network address")?;
    let socket = state.control_path(id)?;
    check_socket_entry(&socket)?;
    let config = node_ssh_config(node)?;
    let check = tunnel_command(&config, &socket, "check", node);
    let result = node.raw_command("ssh", &check, SSH_COMMAND_TIMEOUT).await?;
    if result.status.success() {
        return Ok(());
    }
    close_tunnel(node, state, id).await?;
    let destination = match address {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let args = vec![
        "-F".into(),
        config.into_os_string(),
        "-M".into(),
        "-S".into(),
        socket.into_os_string(),
        "-fNT".into(),
        "-oExitOnForwardFailure=yes".into(),
        "-oServerAliveInterval=15".into(),
        "-oServerAliveCountMax=3".into(),
        "-L".into(),
        format!("127.0.0.1:{}:{destination}:22", guest.port).into(),
        node_destination(node).into(),
    ];
    node.command("ssh", &args, TUNNEL_START_TIMEOUT).await?;
    Ok(())
}

/// Close only the control socket belonging to one sandbox.
///
/// # Errors
/// Rejects non-socket entries and live tunnels that cannot be closed cleanly.
pub async fn close_tunnel(node: &Node, state: &StateDirectory, id: &str) -> Result<()> {
    let socket = state.control_path_for_cleanup(id)?;
    if !check_socket_entry(&socket)? {
        return Ok(());
    }
    state.control_path(id)?;
    let config = node_ssh_config(node)?;
    let output = node
        .raw_command(
            "ssh",
            &tunnel_command(&config, &socket, "exit", node),
            SSH_COMMAND_TIMEOUT,
        )
        .await?;
    if !output.status.success() {
        let check = node
            .raw_command(
                "ssh",
                &tunnel_command(&config, &socket, "check", node),
                SSH_COMMAND_TIMEOUT,
            )
            .await?;
        if check.status.success() {
            bail!("runtime tunnel remains active after close request");
        }
        let error = String::from_utf8_lossy(&check.stderr);
        if !error.contains("Connection refused") && !error.contains("No such file or directory") {
            bail!("unable to confirm runtime tunnel closure");
        }
    }
    for _ in 0..40 {
        if !check_socket_entry(&socket)? {
            return Ok(());
        }
        if !output.status.success() {
            std::fs::remove_file(&socket).context("removing stale tunnel socket")?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("runtime tunnel control socket did not close")
}

/// Execute a bounded command over pinned, noninteractive guest SSH.
///
/// # Errors
/// Rejects invalid routes and reports SSH launch, timeout, or exit failures.
pub async fn guest_command(
    node: &Node,
    guest: &Guest,
    command: &str,
    timeout: Duration,
) -> Result<Output> {
    let args = guest_arguments(guest, command)?;
    node.command("ssh", &args, timeout).await
}

/// Wait for the guest's private Docker API without requiring Python inside it.
///
/// # Errors
/// Reports invalid authentication metadata or a service that misses the readiness deadline.
pub async fn wait_ready(node: &Node, guest: &Guest) -> Result<()> {
    let args = guest_arguments(guest, PING_COMMAND)?;
    let started = Instant::now();
    while started.elapsed() < READINESS_DEADLINE {
        if let Ok(output) = node.raw_command("ssh", &args, SSH_COMMAND_TIMEOUT).await
            && output.status.success()
            && output.stdout.trim_ascii() == b"OK"
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("guest SSH or Docker did not become ready within 180 seconds")
}

fn node_ssh_config(node: &Node) -> Result<PathBuf> {
    if node.transport() == NodeTransport::LinuxLocal {
        return Ok(PathBuf::from("/etc/openshell-kata/node-ssh.config"));
    }
    let home = std::env::var_os("HOME").context("HOME is required for the local node transport")?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        bail!("HOME must be absolute for the local node transport");
    }
    Ok(home.join(".lima").join(node.vm()).join("ssh.config"))
}

fn node_destination(node: &Node) -> String {
    match node.transport() {
        NodeTransport::Lima => format!("lima-{}", node.vm()),
        NodeTransport::LinuxLocal => "openshell-kata-linux".to_owned(),
    }
}

fn tunnel_command(config: &Path, socket: &Path, operation: &str, node: &Node) -> Vec<OsString> {
    vec![
        "-F".into(),
        config.as_os_str().to_owned(),
        "-S".into(),
        socket.as_os_str().to_owned(),
        "-O".into(),
        operation.into(),
        node_destination(node).into(),
    ]
}

fn check_socket_entry(socket: &Path) -> Result<bool> {
    match socket.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(true),
        Ok(_) => bail!("runtime tunnel path is not a socket"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("checking runtime tunnel socket"),
    }
}

fn validate_guest(guest: &Guest) -> Result<()> {
    if !guest
        .host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
        || guest.port == 0
    {
        bail!("invalid local guest SSH route");
    }
    if guest.username.is_empty()
        || !guest
            .username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("invalid guest SSH user");
    }
    for path in [&guest.private_key_path, &guest.known_hosts_path] {
        if !path.is_absolute()
            || path
                .as_os_str()
                .to_string_lossy()
                .chars()
                .any(char::is_control)
        {
            bail!("invalid guest authentication path");
        }
    }
    Ok(())
}

pub(super) fn guest_arguments(guest: &Guest, command: &str) -> Result<Vec<OsString>> {
    validate_guest(guest)?;
    Ok(vec![
        "-F".into(),
        "/dev/null".into(),
        "-T".into(),
        "-oIdentitiesOnly=yes".into(),
        "-oBatchMode=yes".into(),
        "-oStrictHostKeyChecking=yes".into(),
        "-oGlobalKnownHostsFile=/dev/null".into(),
        "-oUpdateHostKeys=no".into(),
        "-oForwardAgent=no".into(),
        "-oControlMaster=no".into(),
        "-oConnectTimeout=5".into(),
        format!("-oUserKnownHostsFile={}", guest.known_hosts_path.display()).into(),
        "-i".into(),
        guest.private_key_path.as_os_str().to_owned(),
        "-p".into(),
        guest.port.to_string().into(),
        "--".into(),
        format!("{}@{}", guest.username, guest.host).into(),
        command.into(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn guest() -> Guest {
        Guest {
            sandbox_id: "one".into(),
            host: "127.0.0.1".into(),
            port: 2222,
            username: "sandbox".into(),
            private_key_path: "/private/key".into(),
            known_hosts_path: "/private/hosts".into(),
            enforcement: None,
            runtime_identity: None,
        }
    }

    #[test]
    fn native_node_tunnel_uses_fixed_operator_config_without_lima() {
        let node = Node::with_transport("native", NodeTransport::LinuxLocal).expect("node");
        let config = node_ssh_config(&node).expect("fixed config");
        assert_eq!(config, PathBuf::from("/etc/openshell-kata/node-ssh.config"));
        let args = tunnel_command(&config, Path::new("/tmp/control.sock"), "check", &node);
        assert_eq!(args.last(), Some(&OsString::from("openshell-kata-linux")));
        assert!(
            !args
                .iter()
                .any(|value| value.to_string_lossy().contains("lima-"))
        );
    }

    #[test]
    fn guest_commands_keep_pinning_and_one_remote_argument() {
        let command = "printf '%s' 'a; b'";
        let args = guest_arguments(&guest(), command).expect("valid guest");
        assert!(args.contains(&"-oStrictHostKeyChecking=yes".into()));
        assert!(args.contains(&"-oGlobalKnownHostsFile=/dev/null".into()));
        assert!(args.contains(&"-oUpdateHostKeys=no".into()));
        assert!(args.contains(&"-oForwardAgent=no".into()));
        assert_eq!(args.last(), Some(&OsString::from(command)));
        assert!(args.contains(&"-oUserKnownHostsFile=/private/hosts".into()));
    }

    #[test]
    fn invalid_ssh_routes_fail_before_starting_a_process() {
        let mut invalid = guest();
        invalid.host = "203.0.113.1".into();
        assert!(guest_arguments(&invalid, "true").is_err());
        invalid = guest();
        invalid.username = "sandbox;id".into();
        assert!(guest_arguments(&invalid, "true").is_err());
        invalid = guest();
        invalid.known_hosts_path = "/path\nProxyCommand bad".into();
        assert!(guest_arguments(&invalid, "true").is_err());
    }

    #[tokio::test]
    async fn key_generation_is_private_and_refuses_replacement() {
        let temporary = tempfile::tempdir_in("/tmp").expect("temporary directory");
        let root = temporary.path().canonicalize().expect("canonical root");
        let state = StateDirectory::new(root.join("state")).expect("private state");
        state.create("one").expect("one");
        let node = Node::new("test-node").expect("node");
        let (client, host) = generate_keys(&node, &state, "one")
            .await
            .expect("generate keys");
        assert_eq!(
            std::fs::metadata(&client)
                .expect("client metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(host.with_extension("pub").is_file());
        assert!(generate_keys(&node, &state, "one").await.is_err());
    }

    #[tokio::test]
    async fn missing_tunnel_is_idempotent_but_regular_files_are_rejected() {
        let temporary = tempfile::tempdir_in("/tmp").expect("temporary directory");
        let root = temporary.path().canonicalize().expect("canonical root");
        let state = StateDirectory::new(root.join("s")).expect("private state");
        let node = Node::new("test-node").expect("node");
        close_tunnel(&node, &state, "one")
            .await
            .expect("absent tunnel");
        let socket = state.control_path("one").expect("socket path");
        std::fs::write(socket, b"do not remove").expect("regular file");
        assert!(close_tunnel(&node, &state, "one").await.is_err());
    }
}
