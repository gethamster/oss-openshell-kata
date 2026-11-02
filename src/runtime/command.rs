//! Bounded operator-command execution for the dedicated Linux runtime node.

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

const NODE_COMMAND_TIMEOUT: Duration = Duration::from_secs(100);
const MAX_DIAGNOSTIC_CHARACTERS: usize = 4096;
const MAX_COMMAND_OUTPUT_BYTES: u64 = 1024 * 1024;

/// Operator-selected transport to the dedicated runtime node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeTransport {
    /// Apple Silicon development through the existing Lima node.
    #[default]
    Lima,
    /// Native Linux host commands with noninteractive privilege escalation.
    LinuxLocal,
}

/// A validated, dedicated node that executes only explicit operator commands.
#[derive(Clone, Debug)]
pub struct Node {
    vm: String,
    transport: NodeTransport,
    #[cfg(test)]
    test_runner: Option<std::path::PathBuf>,
}

impl Node {
    /// Construct a node identifier without allowing paths or command options.
    ///
    /// # Errors
    /// Rejects an empty, non-ASCII, overlong, or syntactically invalid node name.
    pub fn new(vm: impl Into<String>) -> Result<Self> {
        Self::with_transport(vm, NodeTransport::Lima)
    }

    /// Construct a node with an explicit trusted operator transport.
    pub fn with_transport(vm: impl Into<String>, transport: NodeTransport) -> Result<Self> {
        let vm = vm.into();
        if vm.is_empty()
            || vm.len() > 64
            || !vm.as_bytes()[0].is_ascii_alphanumeric()
            || !vm
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            bail!("invalid runtime node name");
        }
        Ok(Self {
            vm,
            transport,
            #[cfg(test)]
            test_runner: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_runner(self, path: std::path::PathBuf) -> Self {
        Self {
            test_runner: Some(path),
            ..self
        }
    }

    /// Return the validated node name used for local transport configuration.
    pub fn vm(&self) -> &str {
        &self.vm
    }

    /// Return the explicit node transport.
    pub fn transport(&self) -> NodeTransport {
        self.transport
    }

    /// Execute an operator command with a deadline, rejecting nonzero exit status.
    ///
    /// # Errors
    /// Reports process launch, timeout, or exit failure with bounded diagnostics.
    pub async fn command(
        &self,
        program: impl AsRef<OsStr>,
        args: &[OsString],
        timeout: Duration,
    ) -> Result<Output> {
        let program = program.as_ref();
        let output = self.raw_command(program, args, timeout).await?;
        if !output.status.success() {
            bail!(
                "{} failed with {}: {}",
                program.to_string_lossy(),
                output.status,
                bounded_diagnostic(&output.stderr)
            );
        }
        Ok(output)
    }

    /// Execute an operator command while preserving its exit status for inspection.
    ///
    /// Arguments are passed directly without a shell; workload credentials and SSH
    /// agent settings are not inherited by these host-side commands.
    ///
    /// # Errors
    /// Reports process launch failures or expiration of the supplied deadline.
    pub async fn raw_command(
        &self,
        program: impl AsRef<OsStr>,
        args: &[OsString],
        timeout: Duration,
    ) -> Result<Output> {
        let mut command = Command::new(program.as_ref());
        command
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for name in [
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "LANG",
            "LC_CTYPE",
            "LIMA_HOME",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        tokio::time::timeout(timeout, async {
            let mut child = command.spawn().context("launching runtime command")?;
            let stdout = child
                .stdout
                .take()
                .context("runtime stdout was not piped")?;
            let stderr = child
                .stderr
                .take()
                .context("runtime stderr was not piped")?;
            let (stdout, stderr, status) =
                tokio::try_join!(bounded_output(stdout), bounded_output(stderr), async {
                    child.wait().await.context("waiting for runtime command")
                })?;
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        })
        .await
        .context("runtime command timed out")?
    }

    /// Execute a checked command as root inside the dedicated Linux node.
    ///
    /// # Errors
    /// Reports transport, timeout, or command exit failures.
    pub async fn node(&self, args: &[OsString]) -> Result<Output> {
        let output = self.raw_node(args).await?;
        if !output.status.success() {
            bail!(
                "runtime node command failed with {}: {}",
                output.status,
                bounded_diagnostic(&output.stderr)
            );
        }
        Ok(output)
    }

    /// Execute a node command, retaining nonzero status for explicit interpretation.
    ///
    /// # Errors
    /// Reports transport launch failures and the outer command deadline.
    pub async fn raw_node(&self, args: &[OsString]) -> Result<Output> {
        #[cfg(test)]
        if let Some(runner) = &self.test_runner {
            return self.raw_command(runner, args, NODE_COMMAND_TIMEOUT).await;
        }
        let (program, arguments) = self.node_invocation(args);
        self.raw_command(program, &arguments, NODE_COMMAND_TIMEOUT)
            .await
    }

    fn node_invocation(&self, args: &[OsString]) -> (&'static str, Vec<OsString>) {
        let (program, mut arguments): (_, Vec<OsString>) = match self.transport {
            NodeTransport::Lima => (
                "limactl",
                vec![
                    "shell".into(),
                    self.vm.clone().into(),
                    "sudo".into(),
                    "-n".into(),
                    "--".into(),
                    "timeout".into(),
                    "--signal=KILL".into(),
                    "90".into(),
                ],
            ),
            NodeTransport::LinuxLocal => (
                "sudo",
                vec![
                    "-n".into(),
                    "--".into(),
                    "timeout".into(),
                    "--signal=KILL".into(),
                    "90".into(),
                ],
            ),
        };
        arguments.extend_from_slice(args);
        (program, arguments)
    }

    /// Stage a private local file on the selected node without invoking a shell.
    pub async fn stage(&self, source: &std::path::Path) -> Result<String> {
        if self.transport == NodeTransport::LinuxLocal {
            let path = source
                .canonicalize()
                .context("canonicalizing staged file")?;
            if !path.is_file() {
                bail!("staged source is not a regular file");
            }
            return Ok(path.to_str().context("non-UTF8 staged path")?.to_owned());
        }
        let stage = self
            .command(
                "limactl",
                &[
                    "shell".into(),
                    self.vm.clone().into(),
                    "mktemp".into(),
                    "/tmp/osk-transfer.XXXXXXXX".into(),
                ],
                Duration::from_secs(15),
            )
            .await?;
        let stage = String::from_utf8(stage.stdout)?.trim().to_owned();
        self.command(
            "limactl",
            &[
                "cp".into(),
                source.as_os_str().to_owned(),
                format!("{}:{stage}", self.vm).into(),
            ],
            Duration::from_secs(30),
        )
        .await?;
        Ok(stage)
    }

    /// Remove only a remote staging copy; local source ownership remains with the caller.
    pub async fn unstage(&self, stage: &str) -> Result<()> {
        if self.transport == NodeTransport::Lima {
            self.node(&["rm".into(), "--".into(), stage.into()]).await?;
        }
        Ok(())
    }

    /// Run a checked containerd command using the capped block-device snapshotter.
    ///
    /// # Errors
    /// Reports node transport and containerd command failures.
    pub async fn nerdctl(&self, args: &[OsString]) -> Result<Output> {
        let mut arguments = vec!["nerdctl".into(), "--snapshotter".into(), "devmapper".into()];
        arguments.extend_from_slice(args);
        self.node(&arguments).await
    }

    /// Run a containerd command while retaining its status for absence checks.
    ///
    /// # Errors
    /// Reports node transport launch failures and command deadlines.
    pub async fn raw_nerdctl(&self, args: &[OsString]) -> Result<Output> {
        let mut arguments = vec!["nerdctl".into(), "--snapshotter".into(), "devmapper".into()];
        arguments.extend_from_slice(args);
        self.raw_node(&arguments).await
    }
}

async fn bounded_output(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_COMMAND_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_COMMAND_OUTPUT_BYTES {
        bail!("runtime command exceeded its output limit");
    }
    Ok(bytes)
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(MAX_DIAGNOSTIC_CHARACTERS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::time::{Duration, Instant};

    #[test]
    fn linux_local_transport_has_noninteractive_privilege_and_bounded_timeout() {
        let node = Node::with_transport("native", NodeTransport::LinuxLocal).expect("native node");
        let (program, args) = node.node_invocation(&["printf".into(), "a b; $x".into()]);
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                OsString::from("-n"),
                "--".into(),
                "timeout".into(),
                "--signal=KILL".into(),
                "90".into(),
                "printf".into(),
                "a b; $x".into()
            ]
        );
    }

    #[test]
    fn node_names_reject_options_paths_and_non_ascii() {
        for name in ["", "-flag", "../node", "a/b", "node;id", "é"] {
            assert!(Node::new(name).is_err(), "accepted invalid node {name:?}");
        }
        assert!(Node::new("openshell-kata-enforcement").is_ok());
        assert!(Node::new("a".repeat(65)).is_err());
    }

    #[tokio::test]
    async fn checked_commands_preserve_argument_boundaries() {
        let node = Node::new("test-node").expect("valid node");
        let output = node
            .command(
                "/usr/bin/printf",
                &[OsString::from("%s"), OsString::from("a b; $not_a_shell")],
                Duration::from_secs(2),
            )
            .await
            .expect("printf");
        assert_eq!(output.stdout, b"a b; $not_a_shell");
    }

    #[tokio::test]
    async fn raw_commands_preserve_status_and_checked_commands_reject_it() {
        let node = Node::new("test-node").expect("valid node");
        let args = [
            OsString::from("-c"),
            OsString::from("printf denied >&2; exit 7"),
        ];
        let raw = node
            .raw_command("/bin/sh", &args, Duration::from_secs(2))
            .await
            .expect("raw process");
        assert_eq!(raw.status.code(), Some(7));
        let error = node
            .command("/bin/sh", &args, Duration::from_secs(2))
            .await
            .expect_err("reject failure");
        assert!(error.to_string().contains("denied"));
    }

    #[tokio::test]
    async fn commands_have_a_finite_deadline() {
        let node = Node::new("test-node").expect("valid node");
        let started = Instant::now();
        let error = node
            .command(
                "/bin/sleep",
                &[OsString::from("30")],
                Duration::from_millis(50),
            )
            .await
            .expect_err("timeout");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn oversized_control_output_fails_without_unbounded_capture() {
        let node = Node::new("test-node").expect("node");
        let error = node
            .command(
                "/bin/sh",
                &["-c".into(), "head -c 1100000 /dev/zero".into()],
                Duration::from_secs(2),
            )
            .await
            .expect_err("output cap");
        assert!(error.to_string().contains("output limit"));
    }

    #[tokio::test]
    async fn untrusted_environment_and_diagnostics_are_bounded() {
        let node = Node::new("test-node").expect("valid node");
        let output = node
            .command(
                "/bin/sh",
                &[
                    "-c".into(),
                    "printf '%s:%s' \"${SSH_AUTH_SOCK-unset}\" \"${SSH_ASKPASS-unset}\"".into(),
                ],
                Duration::from_secs(2),
            )
            .await
            .expect("environment check");
        assert_eq!(output.stdout, b"unset:unset");
        let message = bounded_diagnostic(&vec![b'x'; 5000]);
        assert_eq!(message.len(), 4096);
    }
}
