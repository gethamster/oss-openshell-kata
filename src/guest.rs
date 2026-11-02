use crate::config::{Config, RuntimeProfile, SandboxId};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{net::IpAddr, path::PathBuf, process::Stdio, time::Duration};
use tokio::process::{Child, Command};

/// Startup behavior for a user command carried over the private SSH relay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShellMode {
    #[default]
    Login,
    NonLogin,
}

/// Trusted lifecycle output describing a pinned SSH route to one guest.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    pub sandbox_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub private_key_path: PathBuf,
    pub known_hosts_path: PathBuf,
    #[serde(default)]
    pub enforcement: Option<crate::profile::EnforcementEvidence>,
    #[serde(default)]
    pub runtime_identity: Option<String>,
}
impl Guest {
    pub fn validate(&self, id: &SandboxId) -> Result<()> {
        if self.sandbox_id != id.as_str()
            || !self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
            || self.port == 0
        {
            bail!("lifecycle returned an invalid guest route");
        }
        if self.username.is_empty()
            || !self
                .username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            bail!("invalid guest user");
        }
        if !self.private_key_path.is_absolute() || !self.known_hosts_path.is_absolute() {
            bail!("guest authentication paths must be absolute");
        }
        Ok(())
    }

    fn validate_for(&self, config: &Config, id: &SandboxId) -> Result<()> {
        if config.runtime_profile == RuntimeProfile::Local {
            return self.validate(id);
        }
        let network = crate::hosted::validate_network(
            config
                .guest_network_cidr
                .as_deref()
                .context("hosted guest network required")?,
        )?;
        let valid_ip = self
            .host
            .parse::<IpAddr>()
            .is_ok_and(|ip| network.contains(&ip));
        if self.sandbox_id != id.as_str()
            || !valid_ip
            || self.port != 22
            || self.username != "sandbox"
            || !self.private_key_path.is_absolute()
            || !self.known_hosts_path.is_absolute()
            || self
                .runtime_identity
                .as_deref()
                .is_none_or(|value| uuid::Uuid::parse_str(value).is_err())
        {
            bail!("invalid hosted guest endpoint or generation");
        }
        Ok(())
    }

    fn command(&self, config: &Config) -> Command {
        let mut command = Command::new(&config.ssh);
        command
            .args([
                "-F",
                "/dev/null",
                "-T",
                "-oBatchMode=yes",
                "-oIdentitiesOnly=yes",
                "-oStrictHostKeyChecking=yes",
                "-oGlobalKnownHostsFile=/dev/null",
                "-oUpdateHostKeys=no",
                "-oForwardAgent=no",
                "-oControlMaster=no",
                "-oServerAliveInterval=30",
                "-oServerAliveCountMax=3",
                "-oLogLevel=ERROR",
            ])
            .arg(format!(
                "-oUserKnownHostsFile={}",
                self.known_hosts_path.display()
            ))
            .arg("-i")
            .arg(&self.private_key_path)
            .arg("-p")
            .arg(self.port.to_string())
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_ASKPASS")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    pub fn exec(&self, config: &Config, command: &str) -> Result<Child> {
        self.command(config)
            .arg("--")
            .arg(format!("{}@{}", self.username, self.host))
            .arg(command)
            .spawn()
            .context("starting isolated guest SSH execution")
    }
    /// Execute the gateway's command as one literal Bash command argument.
    /// Non-login execution also clears shell startup-file environment hooks.
    pub fn exec_shell(
        &self,
        config: &Config,
        command: Option<&str>,
        mode: ShellMode,
    ) -> Result<Child> {
        let mut invocation = match mode {
            ShellMode::Login => "exec /bin/bash -l",
            ShellMode::NonLogin => {
                "exec /usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile --norc"
            }
        }
        .to_owned();
        if let Some(command) = command {
            invocation.push_str(" -c ");
            invocation.push_str(&crate::config::shell_quote(command));
        }
        self.exec(config, &invocation)
    }
    pub fn sftp(&self, config: &Config) -> Result<Child> {
        self.command(config)
            .arg("-s")
            .arg("--")
            .arg(format!("{}@{}", self.username, self.host))
            .arg("sftp")
            .spawn()
            .context("starting isolated guest SFTP")
    }
    pub fn tcp(&self, config: &Config, host: &str, port: u32) -> Result<Child> {
        if !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()) && host != "localhost" {
            bail!("preview target must be loopback");
        }
        if port == 0 || port > u16::MAX.into() {
            bail!("invalid preview port");
        }
        let target = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        self.command(config)
            .arg("-W")
            .arg(target)
            .arg("--")
            .arg(format!("{}@{}", self.username, self.host))
            .spawn()
            .context("starting guest TCP relay")
    }
}

/// Concurrent lifecycle processes that provision or tear down guests.
pub const PROVISIONING_SLOTS: usize = 16;
/// Concurrent lifecycle processes that revalidate running guests, budgeted apart
/// from provisioning so neither starves the other.
pub const OBSERVATION_SLOTS: usize = 16;

fn lifecycle_slots(action: &str) -> &'static tokio::sync::Semaphore {
    static PROVISIONING: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(PROVISIONING_SLOTS);
    static OBSERVATION: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(OBSERVATION_SLOTS);
    if matches!(action, "verify" | "update") {
        &OBSERVATION
    } else {
        &PROVISIONING
    }
}

/// Whether an error is a missed deadline (host or gateway contention) rather
/// than a verified result. Callers may retry these; verified failures stand.
pub fn is_deadline(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<tokio::time::error::Elapsed>()
            || cause
                .downcast_ref::<tonic::Status>()
                .is_some_and(|status| status.code() == tonic::Code::DeadlineExceeded)
    })
}

pub async fn lifecycle(config: &Config, action: &str, id: &SandboxId) -> Result<Option<Guest>> {
    lifecycle_with_policy(config, action, id, None, None).await
}

pub async fn lifecycle_with_policy(
    config: &Config,
    action: &str,
    id: &SandboxId,
    policy: Option<&crate::profile::VmPolicy>,
    nonce: Option<&str>,
) -> Result<Option<Guest>> {
    lifecycle_for_policy(config, action, id, None, policy, nonce).await
}

pub async fn lifecycle_for(
    config: &Config,
    action: &str,
    id: &SandboxId,
    workspace: Option<&str>,
) -> Result<Option<Guest>> {
    lifecycle_for_policy(config, action, id, workspace, None, None).await
}

pub async fn lifecycle_for_policy(
    config: &Config,
    action: &str,
    id: &SandboxId,
    workspace: Option<&str>,
    policy: Option<&crate::profile::VmPolicy>,
    nonce: Option<&str>,
) -> Result<Option<Guest>> {
    lifecycle_for_network(config, action, id, workspace, policy, nonce, None).await
}

/// Launch with a separate hosted capability, without local VM resource assumptions.
pub async fn lifecycle_for_network(
    config: &Config,
    action: &str,
    id: &SandboxId,
    workspace: Option<&str>,
    policy: Option<&crate::profile::VmPolicy>,
    nonce: Option<&str>,
    initial_network: Option<&crate::network::NetworkPolicy>,
) -> Result<Option<Guest>> {
    if policy.is_some() && nonce.is_none() {
        bail!("runtime enforcement requires a proof challenge");
    }
    if let Some(nonce) = nonce {
        crate::runtime::model::validate_nonce(nonce)?;
    }
    let policy_file = policy
        .map(|policy| -> Result<_> {
            let mut file = tempfile::NamedTempFile::new()?;
            serde_json::to_writer(&mut file, policy)?;
            file.as_file().sync_all()?;
            Ok(file)
        })
        .transpose()?;
    let network_file = initial_network.map(private_json).transpose()?;
    let mut command = Command::new(&config.lifecycle);
    command
        .args(&config.lifecycle_arg)
        .arg(action)
        .arg(id.as_str());
    hosted_environment(&mut command, config);
    if let Some(file) = &network_file {
        command.env("OPENSHELL_KATA_INITIAL_NETWORK_POLICY_FILE", file.path());
    } else {
        command.env_remove("OPENSHELL_KATA_INITIAL_NETWORK_POLICY_FILE");
    }
    for (name, value) in [
        ("OPENSHELL_KATA_GUEST_IMAGE", &config.guest_image),
        (
            "OPENSHELL_KATA_GUEST_NETWORK_CIDR",
            &config.guest_network_cidr,
        ),
    ] {
        if let Some(value) = value {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
    if let Some(workspace) = workspace {
        command.env("OPENSHELL_KATA_WORKSPACE", workspace);
    }
    if let Some(file) = &policy_file {
        command.arg("--policy-file").arg(file.path());
    }
    if let Some(nonce) = nonce {
        command.arg("--proof-nonce").arg(nonce);
    }
    let timeout = Duration::from_secs(match (config.runtime_profile, action) {
        (RuntimeProfile::Kubernetes, "create" | "start" | "stop" | "delete" | "abort") => 660,
        (_, "create" | "start") => 600,
        _ => 30,
    });
    // The deadline bounds execution only; waiting for a slot is not charged to it.
    let _slot = lifecycle_slots(action)
        .acquire()
        .await
        .context("lifecycle slots closed")?;
    let output = tokio::time::timeout(
        timeout,
        command
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("guest lifecycle timed out")?
    .context("running guest lifecycle")?;
    if !output.status.success() {
        let diagnostic: String = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(4096)
            .collect();
        tracing::error!(action, sandbox=%id, stderr=%diagnostic, "guest lifecycle failed");
        bail!(
            "guest lifecycle {action} failed with status {}",
            output.status
        );
    }
    if matches!(action, "create" | "start")
        || (config.runtime_profile == RuntimeProfile::Local
            && matches!(action, "verify" | "update"))
    {
        let guest: Guest =
            serde_json::from_slice(&output.stdout).context("decoding guest lifecycle metadata")?;
        guest.validate_for(config, id)?;
        if let Some(policy) = policy {
            guest
                .enforcement
                .as_ref()
                .context("runtime enforcement evidence missing")?
                .validate(
                    id.as_str(),
                    nonce.context("runtime enforcement requires a proof challenge")?,
                    policy,
                )?;
        }
        Ok(Some(guest))
    } else {
        Ok(None)
    }
}

pub async fn verify_runtime(
    config: &Config,
    sandbox: &crate::proto::openshell::compute::v1::DriverSandbox,
    identity: &str,
) -> Result<()> {
    if config.runtime_profile == RuntimeProfile::Local {
        return Ok(());
    }
    let mut command = Command::new(&config.lifecycle);
    let nonce = uuid::Uuid::new_v4().to_string();
    command
        .args(&config.lifecycle_arg)
        .arg("verify")
        .arg(&sandbox.id)
        .env(
            "OPENSHELL_KATA_GUEST_NETWORK_CIDR",
            config.guest_network_cidr.as_deref().unwrap_or(""),
        )
        .stdin(Stdio::null())
        .kill_on_drop(true);
    hosted_environment(&mut command, config);
    if config.hosted_network_config.is_some() {
        command.arg("--proof-nonce").arg(&nonce);
    }
    let output = bounded_output(command, Duration::from_secs(15)).await?;
    if !output.status.success() {
        bail!("live Kubernetes runtime verification failed");
    }
    let proof: crate::hosted::RuntimeProof = serde_json::from_slice(&output.stdout)?;
    proof.validate_for_profile(
        sandbox,
        config.guest_image.as_deref().unwrap_or(""),
        identity,
        config.hosted_network_config.as_deref(),
        &nonce,
        None,
    )
}

fn private_json(value: &impl serde::Serialize) -> Result<tempfile::NamedTempFile> {
    let mut file = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(&mut file, value)?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn hosted_environment(command: &mut Command, config: &Config) {
    for name in [
        "OPENSHELL_KATA_NETWORK_POLICY_FILE",
        "OPENSHELL_KATA_RUNTIME_IDENTITY",
    ] {
        command.env_remove(name);
    }
    if let Some(path) = &config.hosted_network_config {
        command.env("OPENSHELL_KATA_HOSTED_NETWORK_CONFIG", path);
    } else {
        command.env_remove("OPENSHELL_KATA_HOSTED_NETWORK_CONFIG");
    }
}

/// Renew authority only with a newly compiled fresh gateway snapshot.
pub async fn enforce_hosted_network(
    config: &Config,
    sandbox: &crate::proto::openshell::compute::v1::DriverSandbox,
    identity: &str,
    policy: &crate::network::NetworkPolicy,
) -> Result<()> {
    let nonce = uuid::Uuid::new_v4().to_string();
    let file = private_json(policy)?;
    let mut command = Command::new(&config.lifecycle);
    hosted_environment(&mut command, config);
    command
        .args(&config.lifecycle_arg)
        .arg("apply-network")
        .arg(&sandbox.id)
        .arg("--proof-nonce")
        .arg(&nonce)
        .env("OPENSHELL_KATA_NETWORK_POLICY_FILE", file.path())
        .env("OPENSHELL_KATA_RUNTIME_IDENTITY", identity)
        .env(
            "OPENSHELL_KATA_GUEST_NETWORK_CIDR",
            config.guest_network_cidr.as_deref().unwrap_or(""),
        )
        .stdin(Stdio::null());
    let output = bounded_output(command, Duration::from_secs(15)).await?;
    if !output.status.success() {
        bail!("hosted network authorization failed");
    }
    let proof: crate::hosted::RuntimeProof = serde_json::from_slice(&output.stdout)?;
    proof.validate_for_profile(
        sandbox,
        config.guest_image.as_deref().unwrap_or(""),
        identity,
        config.hosted_network_config.as_deref(),
        &nonce,
        Some(policy),
    )
}

async fn bounded_output(mut command: Command, duration: Duration) -> Result<std::process::Output> {
    tokio::time::timeout(duration, command.kill_on_drop(true).output())
        .await
        .context("runtime command deadline exceeded")?
        .context("running guest lifecycle")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hanging_runtime_command_has_a_deadline() {
        let mut command = Command::new("/bin/sleep");
        command.arg("10");
        let result = bounded_output(command, Duration::from_millis(20)).await;
        assert!(result.is_err());
    }
}
