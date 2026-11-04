use anyhow::{Result, bail};
use clap::{Parser, ValueEnum};
use std::{fmt, path::PathBuf};

/// Validated immutable target identifier used at runtime boundaries.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SandboxId(String);

impl SandboxId {
    /// Validate a gateway identifier before using it in lifecycle commands.
    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > 128
            || !value.as_bytes()[0].is_ascii_alphanumeric()
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            bail!("invalid sandbox identifier");
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Upper bound on the operator-selected native node capacity (`--max-sandboxes`).
pub const MAX_SANDBOXES_LIMIT: u8 = 64;

/// Operator configuration; no workload input can select host commands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum RuntimeProfile {
    #[default]
    Local,
    Kubernetes,
}

/// Operator configuration; no workload input can select host commands.
#[derive(Clone, Debug, Parser)]
pub struct Config {
    #[arg(long)]
    pub socket: PathBuf,
    #[arg(long, default_value = "https://127.0.0.1:28670")]
    pub gateway: String,
    #[arg(long)]
    pub gateway_ca: PathBuf,
    #[arg(long)]
    pub lifecycle: PathBuf,
    #[arg(long)]
    pub lifecycle_arg: Vec<String>,
    #[arg(long, default_value = "/usr/bin/ssh")]
    pub ssh: PathBuf,
    /// Explicit local experiment: policies are inspected but not fully enforced.
    #[arg(long)]
    pub prototype_policy_mode: bool,
    /// Trusted immutable VM policy for the local runtime.
    #[arg(long)]
    pub vm_policy: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "local")]
    pub runtime_profile: RuntimeProfile,
    #[arg(long)]
    pub guest_image: Option<String>,
    /// Further operator-pinned immutable guest images a sandbox template may select,
    /// each under the same enforced runtime profile as the default `--guest-image`.
    #[arg(long = "additional-guest-image")]
    pub additional_guest_images: Vec<String>,
    /// Trusted private Pod network; workload requests cannot select the route.
    #[arg(long)]
    pub guest_network_cidr: Option<String>,
    /// Private durable metadata directory; never stores launch credentials.
    #[arg(long)]
    pub recovery_dir: Option<PathBuf>,
    /// Explicit operator profile for brokered hosted TCP; absent means deny-all.
    #[arg(long)]
    pub hosted_network_config: Option<PathBuf>,
    /// Operator capacity of the native node: the most retained sandboxes, stopped
    /// guests included, it admits at once. Required with native recovery. The
    /// lifecycle reads the same `OPENSHELL_KATA_MAX_SANDBOXES` service setting.
    #[arg(long, env = "OPENSHELL_KATA_MAX_SANDBOXES", value_parser = clap::value_parser!(u8).range(1..=i64::from(MAX_SANDBOXES_LIMIT)))]
    pub max_sandboxes: Option<u8>,
}
impl Config {
    /// The operator-admitted guest images: the default image first, then any additional ones.
    pub fn admitted_images(&self) -> Vec<&str> {
        self.guest_image
            .iter()
            .chain(self.additional_guest_images.iter())
            .map(String::as_str)
            .collect()
    }

    /// The configuration for one sandbox: its admitted template image becomes the
    /// guest image every lifecycle and proof step for that sandbox uses.
    pub fn for_sandbox(
        &self,
        sandbox: &crate::proto::openshell::compute::v1::DriverSandbox,
    ) -> Self {
        let image = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.template.as_ref())
            .map(|template| template.image.as_str());
        match image {
            Some(image)
                if self
                    .additional_guest_images
                    .iter()
                    .any(|admitted| admitted == image) =>
            {
                Self {
                    guest_image: Some(image.to_owned()),
                    ..self.clone()
                }
            }
            _ => self.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(path) = &self.hosted_network_config {
            if self.runtime_profile != RuntimeProfile::Kubernetes || !path.is_absolute() {
                bail!("hosted network configuration requires Kubernetes and an absolute path");
            }
            crate::kubernetes::HostedNetworkConfig::load(path)?;
        }
        if !self.additional_guest_images.is_empty() {
            if self.guest_image.is_none()
                || self.prototype_policy_mode
                || (self.runtime_profile == RuntimeProfile::Local && self.vm_policy.is_none())
            {
                bail!(
                    "additional guest images require an enforced runtime profile and a default guest image"
                );
            }
            for image in &self.additional_guest_images {
                crate::hosted::validate_image(image)?;
            }
        }
        if let Some(path) = &self.vm_policy {
            if !path.is_absolute()
                || self.prototype_policy_mode
                || self.runtime_profile != RuntimeProfile::Local
            {
                bail!(
                    "VM policy requires the local runtime, an absolute path and no prototype mode"
                );
            }
            crate::profile::VmPolicy::load(path)?;
        }
        if self.runtime_profile == RuntimeProfile::Local
            && let Some(image) = &self.guest_image
        {
            if self.vm_policy.is_none() || self.prototype_policy_mode {
                bail!("operator image requires the enforced local VM profile");
            }
            crate::hosted::validate_image(image)?;
        }
        if self.runtime_profile == RuntimeProfile::Local
            && let Some(directory) = &self.recovery_dir
            && (!directory.is_absolute()
                || self.prototype_policy_mode
                || self.vm_policy.is_none()
                || self.guest_image.is_none())
        {
            bail!(
                "native recovery requires an absolute directory, enforced policy and pinned guest image"
            );
        }
        let native_recovery =
            self.runtime_profile == RuntimeProfile::Local && self.recovery_dir.is_some();
        match self.max_sandboxes {
            None if native_recovery => {
                bail!("native recovery requires an explicit --max-sandboxes node capacity")
            }
            Some(_) if !native_recovery => {
                bail!("--max-sandboxes applies only to the native local runtime with recovery")
            }
            Some(capacity) if !(1..=MAX_SANDBOXES_LIMIT).contains(&capacity) => {
                bail!("--max-sandboxes must be between 1 and {MAX_SANDBOXES_LIMIT}")
            }
            _ => {}
        }
        if self.runtime_profile == RuntimeProfile::Kubernetes {
            if self
                .recovery_dir
                .as_ref()
                .is_none_or(|path| !path.is_absolute())
            {
                bail!("hosted runtime requires an absolute recovery directory");
            }
            if self.prototype_policy_mode {
                bail!("prototype mode is prohibited for hosted runtime");
            }
            crate::hosted::validate_image(self.guest_image.as_deref().unwrap_or(""))?;
            crate::hosted::validate_network(
                self.guest_network_cidr.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("hosted runtime requires a guest network CIDR")
                })?,
            )?;
        }
        for path in [&self.socket, &self.gateway_ca, &self.lifecycle, &self.ssh] {
            if !path.is_absolute() {
                bail!("operator paths must be absolute");
            }
        }
        let endpoint = tonic::transport::Endpoint::from_shared(self.gateway.clone())?;
        let uri = endpoint.uri();
        if uri.scheme_str() != Some("https")
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
        {
            bail!("gateway requires TLS");
        }
        if self.prototype_policy_mode
            && !uri.host().is_some_and(|host| {
                host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            })
        {
            bail!("prototype policy mode is limited to a loopback gateway");
        }
        Ok(())
    }
    pub fn validate_request(
        &self,
        sandbox: &crate::proto::openshell::compute::v1::DriverSandbox,
    ) -> Result<()> {
        match self.runtime_profile {
            RuntimeProfile::Local => {
                if let Some(path) = &self.vm_policy {
                    let policy = crate::profile::VmPolicy::load(path)?;
                    crate::admission::compile_request_for_images(
                        sandbox,
                        &policy,
                        &self.admitted_images(),
                    )
                    .map(|_| ())
                } else {
                    crate::admission::validate_request(sandbox, self.prototype_policy_mode)
                }
            }
            RuntimeProfile::Kubernetes => {
                let selected = self.for_sandbox(sandbox);
                if let Some(path) = &self.hosted_network_config {
                    let operator = crate::kubernetes::HostedNetworkConfig::load(path)?;
                    crate::hosted::validate_brokered_request(
                        sandbox,
                        selected.guest_image.as_deref().unwrap_or(""),
                        &operator.operator_ceiling,
                    )
                    .map(|_| ())
                } else {
                    crate::hosted::validate_request(
                        sandbox,
                        selected.guest_image.as_deref().unwrap_or(""),
                    )
                }
            }
        }
    }
}

/// Quote one shell argument for the remote guest's POSIX shell.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
