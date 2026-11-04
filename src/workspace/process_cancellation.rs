//! Cooperative cancellation with kernel-owned, unreaped child identities.
use super::{Record, Workspace, exit_code, frozen, identity};
use anyhow::{Context, Result, ensure};
use rustix::{
    io::Errno,
    process::{Pid, Signal, WaitOptions, getpid, kill_process, wait},
};
use std::{io::Read, process::Stdio, time::Duration};

pub(super) async fn run(
    workspace: &Workspace,
    id: &str,
    command: &[String],
    expected: &Record,
) -> Result<i32> {
    // Install a handler even when a launcher inherited SIGCHLD=SIG_IGN.
    // Otherwise Linux may auto-reap children and make numeric PIDs reusable.
    // Listening for SIGCHLD does not register any child with Tokio's reaper.
    let _child_notifications =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())?;
    // This dedicated controller never registers children with Tokio's reaper.
    // Until this function calls wait, each direct child PID remains reserved
    // by the kernel, including after exit. No other thread reaps these children.
    let mut child = std::process::Command::new(&command[0])
        .args(&command[1..])
        .env("OPENSHELL_WORKSPACE_COMMAND_ID", id)
        .env("OPENSHELL_WORKSPACE_ROOT", &workspace.root)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn workspace command")?;
    loop {
        let requested = match super::read_record(workspace, &format!("{id}.cancel")) {
            Ok(Some(record)) if &record != expected => {
                super::mark_drain_failed(workspace, id)?;
                anyhow::bail!("workspace cancellation request identity changed");
            }
            Ok(record) => record.is_some(),
            Err(error) => {
                super::mark_drain_failed(workspace, id)?;
                return Err(error.context("read workspace cancellation request"));
            }
        };
        if requested || frozen(workspace)? {
            if let Err(error) = stop_children().await {
                super::mark_drain_failed(workspace, id)?;
                return Err(error);
            }
            super::replace_record(workspace, &format!("{id}.cancel-ack"), expected)?;
            return Ok(137);
        }
        if let Some(status) = child.try_wait()? {
            return Ok(exit_code(status));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn stop_children() -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        // A descendant that detached or double-forked is adopted by this
        // subreaper after its parent dies. Re-scan after every reap cycle.
        for child in direct_children()? {
            match kill_process(child, Signal::KILL) {
                Ok(()) | Err(Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
        }
        loop {
            match wait(WaitOptions::NOHANG) {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(Errno::CHILD) => return Ok(()),
                Err(Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "workspace descendants did not stop"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn direct_children() -> Result<Vec<Pid>> {
    let parent = getpid().as_raw_nonzero().get() as u32;
    let mut children = Vec::new();
    for task in std::fs::read_dir("/proc/self/task")? {
        let path = task?.path().join("children");
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let mut list = String::new();
        file.take(128 * 1024 + 1).read_to_string(&mut list)?;
        ensure!(
            list.len() <= 128 * 1024,
            "workspace child listing limit exceeded"
        );
        for raw in list.split_whitespace() {
            ensure!(
                children.len() < 4096,
                "workspace child count limit exceeded"
            );
            let child = Pid::from_raw(raw.parse()?).context("invalid child PID")?;
            // Never signal a PID obtained from the workspace, command, or an
            // arbitrary /proc entry: only our own unreaped kernel children.
            ensure!(
                identity(child)?.parent == parent,
                "workspace child ownership changed"
            );
            children.push(child);
        }
    }
    Ok(children)
}
