//! Bounded, argument-preserving access to the operator's Kubernetes client.

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    process::{Output, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};

const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub(super) struct Client {
    pub(super) context: Option<String>,
    pub(super) program: std::path::PathBuf,
}

impl Client {
    pub(super) async fn kube(&self, args: &[&str], data: Option<Vec<u8>>) -> Result<Output> {
        let mut command = Command::new(&self.program);
        command.arg("--request-timeout=10s");
        if let Some(context) = &self.context {
            command.arg(format!("--context={context}"));
        }
        command.args(args);
        command_output(command, data, Duration::from_secs(190)).await
    }

    pub(super) async fn checked(&self, args: &[&str], data: Option<Vec<u8>>) -> Result<Output> {
        let output = self.kube(args, data).await?;
        ensure!(
            output.status.success(),
            "kubectl operation failed; inspect trusted runtime events"
        );
        Ok(output)
    }

    pub(super) async fn get(
        &self,
        kind: &str,
        name: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<Option<Value>> {
        let mut args = vec!["get", kind];
        if let Some(name) = name {
            args.push(name);
        }
        if let Some(namespace) = namespace {
            args.extend(["-n", namespace]);
        }
        args.extend(["-o", "json"]);
        // kubectl suppresses JSON for an empty list with --ignore-not-found.
        // Only named lookups use absence as an optional resource observation.
        if name.is_some() {
            args.push("--ignore-not-found");
        }
        let output = self.checked(&args, None).await?;
        if output.stdout.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        Ok(Some(
            serde_json::from_slice(&output.stdout).context("decoding Kubernetes observation")?,
        ))
    }

    pub(super) async fn required(
        &self,
        kind: &str,
        name: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<Value> {
        self.get(kind, name, namespace)
            .await?
            .context("required Kubernetes resource is absent")
    }

    pub(super) async fn apply(&self, value: &Value) -> Result<()> {
        self.checked(
            &[
                "apply",
                "--server-side",
                "--field-manager=openshell-kata",
                "-f",
                "-",
            ],
            Some(serde_json::to_vec(value)?),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn delete(&self, kind: &str, name: &str, namespace: &str) -> Result<()> {
        self.checked(
            &[
                "delete",
                kind,
                name,
                "-n",
                namespace,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=180s",
            ],
            None,
        )
        .await?;
        ensure!(
            self.get(kind, Some(name), Some(namespace)).await?.is_none(),
            "resource survived deletion"
        );
        Ok(())
    }
}

pub(super) async fn command_output(
    mut command: Command,
    data: Option<Vec<u8>>,
    duration: Duration,
) -> Result<Output> {
    command
        .stdin(if data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_ASKPASS");
    tokio::time::timeout(duration, async {
        let mut child = command
            .spawn()
            .context("launching trusted operator command")?;
        let stdout = child.stdout.take().context("missing operator stdout")?;
        let stderr = child.stderr.take().context("missing operator stderr")?;
        let stdin = child.stdin.take();
        let writer = async move {
            if let (Some(mut stdin), Some(data)) = (stdin, data) {
                stdin.write_all(&data).await?;
                stdin.shutdown().await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let (stdout, stderr, status, ()) = tokio::try_join!(
            bounded(stdout),
            bounded(stderr),
            async { child.wait().await.context("waiting for operator command") },
            async { writer.await.context("writing operator request") }
        )?;
        Ok(Output {
            stdout,
            stderr,
            status,
        })
    })
    .await
    .context("operator command timed out")?
}

async fn bounded(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() as u64 <= OUTPUT_LIMIT,
        "operator output limit exceeded"
    );
    Ok(bytes)
}
