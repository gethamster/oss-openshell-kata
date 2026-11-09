use super::Workspace;
use anyhow::{Context, Result, ensure};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::io::Write;
use std::{
    io::Read,
    process::{ExitStatus, Stdio},
};
use uuid::Uuid;

#[cfg(target_os = "linux")]
#[path = "process_cancellation.rs"]
mod cancellation;

const RECORD_DIRECTORY: &str = ".system-processes";
const MAX_COMMAND_BYTES: usize = 128 * 1024;
const MAX_RECORD_BYTES: u64 = 4096;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    pid: u32,
    start: u64,
}

/// Run a command beneath a session leader whose identity can be cancelled safely.
///
/// # Errors
/// Rejects invalid arguments, non-Linux hosts, or subprocess/filesystem errors.
pub async fn run(workspace: &Workspace, id: &str, command: &str) -> Result<i32> {
    validate_id(id)?;
    validate_command(command)?;
    ensure!(
        !frozen(workspace)?,
        "workspace is quiesced for a runtime move"
    );
    ensure!(
        cfg!(target_os = "linux"),
        "workspace process control requires Linux"
    );
    if super::capability::read(workspace, id)?.is_some() {
        return Ok(125);
    }
    if cancelled(workspace, id)? {
        return Ok(137);
    }
    let mut child = tokio::process::Command::new(std::env::current_exe()?)
        .arg("--root")
        .arg(&workspace.root)
        .arg("__run-child")
        .arg(id)
        .arg(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn workspace process controller")?;
    let pid = child.id().context("workspace controller has no PID")?;
    let result = child.wait().await;
    cleanup_record(workspace, id, pid)?;
    let status = result?;
    Ok(if super::capability::read(workspace, id)?.is_some() {
        125
    } else {
        exit_code(status)
    })
}

/// Run the private session controller, called only by this executable's `run` path.
///
/// # Errors
/// Rejects invalid identities, unsupported hosts, live or unresolved records, or launch errors.
pub async fn run_child(workspace: &Workspace, id: &str, command: &str) -> Result<i32> {
    validate_id(id)?;
    let command = validate_command(command)?;
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{getpid, set_child_subreaper, setsid};
        setsid().context("create workspace process session")?;
        // Orphaned descendants, including detached sessions, return to this
        // controller so cancellation can retain kernel child ownership.
        set_child_subreaper(Some(getpid())).context("retain workspace descendants")?;
        let pid = getpid();
        let record = Record {
            version: 1,
            pid: pid.as_raw_nonzero().get() as u32,
            start: identity(pid)?.start,
        };
        publish_record(workspace, id, &record)?;
        if cancelled(workspace, id)? || frozen(workspace)? {
            return Ok(137);
        }
        cancellation::run(workspace, id, &command, &record).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (workspace, command);
        anyhow::bail!("workspace process control requires Linux")
    }
}

/// Publish cancellation for the exact retained controller.
///
/// # Errors
/// Rejects forged/stale process identities, unsupported hosts and cancellation-record failures.
pub fn kill(workspace: &Workspace, id: &str) -> Result<()> {
    validate_id(id)?;
    let record = match read_record(workspace, id)? {
        Some(record) => record,
        None => {
            // Cancellation may race the launch before a controller exists.
            // Publish intent before checking again, so either the new controller
            // sees it or this caller signals the now-published identity.
            mark_cancelled(workspace, id)?;
            let Some(record) = read_record(workspace, id)? else {
                return Ok(());
            };
            record
        }
    };
    #[cfg(target_os = "linux")]
    {
        use rustix::process::Pid;
        let pid = Pid::from_raw(i32::try_from(record.pid)?)
            .context("invalid workspace controller PID")?;
        let observed = match identity(pid).context("read workspace controller identity") {
            Ok(value) => value,
            Err(error) if is_missing(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        ensure!(
            record.version == 1 && observed.start == record.start,
            "workspace process identity changed"
        );
        ensure!(
            observed.group == record.pid && observed.session == record.pid,
            "workspace process session changed"
        );
        // Cross-process exe/cmdline access is deliberately restricted by the
        // normal runtime. No PID is signalled here: the UUID-bound controller
        // validates this exact record against its own retained identity.
        replace_record(workspace, &format!("{id}.cancel"), &record)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
        loop {
            if let Some(acknowledged) = read_record(workspace, &format!("{id}.cancel-ack"))? {
                ensure!(
                    acknowledged == record,
                    "workspace cancellation acknowledgement changed"
                );
                return Ok(());
            }
            ensure!(
                !drain_failed(workspace, id)?,
                "workspace cancellation drain failed"
            );
            ensure!(
                std::time::Instant::now() < deadline,
                "workspace cancellation was not acknowledged"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = record;
        anyhow::bail!("workspace process control requires Linux")
    }
}

pub(super) fn validate_id(id: &str) -> Result<()> {
    ensure!(
        Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id),
        "canonical workspace process UUID required"
    );
    Ok(())
}

fn validate_command(encoded: &str) -> Result<Vec<String>> {
    ensure!(
        encoded.len() <= MAX_COMMAND_BYTES,
        "workspace command limit exceeded"
    );
    let command: Vec<String> =
        serde_json::from_str(encoded).context("invalid workspace command JSON")?;
    ensure!(
        !command.is_empty() && command.len() <= 4096 && !command[0].is_empty(),
        "invalid workspace command"
    );
    ensure!(
        command.iter().all(|arg| !arg.contains('\0')),
        "workspace command contains NUL"
    );
    Ok(command)
}

pub(super) fn process_directory(workspace: &Workspace) -> Result<Dir> {
    super::files::create_private_directory(&workspace.directory, RECORD_DIRECTORY)?;
    let directory = workspace.directory.open_dir_nofollow(RECORD_DIRECTORY)?;
    #[cfg(unix)]
    {
        use cap_std::fs::{MetadataExt, PermissionsExt};
        let metadata = directory.dir_metadata()?;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0
                && metadata.uid() == rustix::process::geteuid().as_raw(),
            "workspace process directory must be private and owned"
        );
    }
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn publish_record(workspace: &Workspace, id: &str, record: &Record) -> Result<()> {
    let directory = process_directory(workspace)?;
    // Serialize stale-record replacement with other launches and completion cleanup.
    let _lock = lock_records(&directory)?;
    let replace = stale_record(workspace, id)?;
    let staged = format!(".process-{}", Uuid::new_v4());
    let mut options = super::files::private_file_options();
    options.write(true).create_new(true);
    let result: Result<()> = (|| {
        let mut file = directory.open_with(&staged, &options)?;
        file.write_all(&serde_json::to_vec(record)?)?;
        file.sync_all()?;
        if replace {
            directory.rename(&staged, &directory, format!("{id}.json"))?;
        } else {
            directory.hard_link(&staged, &directory, format!("{id}.json"))?;
            directory.remove_file(&staged)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = directory.remove_file(&staged);
    }
    result?;
    super::files::sync_directory(&directory)
}

#[cfg(target_os = "linux")]
fn lock_records(directory: &Dir) -> Result<std::fs::File> {
    let lock = directory.open(".")?.into_std();
    lock.lock().context("lock workspace process records")?;
    Ok(lock)
}

#[cfg(target_os = "linux")]
fn stale_record(workspace: &Workspace, id: &str) -> Result<bool> {
    let Some(record) = read_record(workspace, id)? else {
        return Ok(false);
    };
    let command = id.strip_suffix(".hold").unwrap_or(id);
    let directory = process_directory(workspace)?;
    for suffix in [
        "capability.json",
        "cancel.json",
        "cancel-ack.json",
        "cancelled",
        "drain-failed",
    ] {
        match directory.symlink_metadata(format!("{command}.{suffix}")) {
            Ok(_) => anyhow::bail!("workspace process has retained {suffix} evidence"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if id.ends_with(".hold") {
        ensure!(
            read_record(workspace, &format!("{id}-exit"))?.is_none(),
            "workspace holder has a retained stop request"
        );
    }
    require_stale(&record)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn require_stale(record: &Record) -> Result<()> {
    ensure!(
        record.version == 1,
        "invalid workspace process record version"
    );
    let pid = rustix::process::Pid::from_raw(i32::try_from(record.pid)?)
        .context("invalid workspace controller PID")?;
    // Abrupt sandbox stops retain the record. Absence or PID reuse proves that
    // its controller is gone; an unreadable identity cannot establish that.
    match identity(pid) {
        Ok(observed) => ensure!(
            observed.start != record.start,
            "workspace process identity is still live"
        ),
        Err(error) if is_missing(&error) => {}
        Err(error) => return Err(error.context("read previous workspace process identity")),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn replace_record(workspace: &Workspace, id: &str, record: &Record) -> Result<()> {
    let directory = process_directory(workspace)?;
    let staged = format!(".identity-{}", Uuid::new_v4());
    let mut options = super::files::private_file_options();
    options.write(true).create_new(true);
    let result: Result<()> = (|| {
        let mut file = directory.open_with(&staged, &options)?;
        file.write_all(&serde_json::to_vec(record)?)?;
        file.sync_all()?;
        directory.rename(&staged, &directory, format!("{id}.json"))?;
        super::files::sync_directory(&directory)
    })();
    if result.is_err() {
        let _ = directory.remove_file(staged);
    }
    result
}

fn cancelled(workspace: &Workspace, id: &str) -> Result<bool> {
    let directory = process_directory(workspace)?;
    match directory.symlink_metadata(format!("{id}.cancelled")) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() == 0,
                "invalid workspace cancellation marker"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn mark_cancelled(workspace: &Workspace, id: &str) -> Result<()> {
    let directory = process_directory(workspace)?;
    let mut options = super::files::private_file_options();
    options.write(true).create_new(true);
    match directory.open_with(format!("{id}.cancelled"), &options) {
        Ok(file) => {
            file.sync_all()?;
            super::files::sync_directory(&directory)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                cancelled(workspace, id)?,
                "workspace cancellation marker disappeared"
            );
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

// Retain explicit failure evidence: an uncertain drain must never look like
// an idle source after the controller exits or the transport reconnects.
#[cfg(target_os = "linux")]
fn mark_drain_failed(workspace: &Workspace, id: &str) -> Result<()> {
    let directory = process_directory(workspace)?;
    let mut options = super::files::private_file_options();
    options.write(true).create_new(true);
    match directory.open_with(format!("{id}.drain-failed"), &options) {
        Ok(file) => file.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    super::files::sync_directory(&directory)
}

fn drain_failed(workspace: &Workspace, id: &str) -> Result<bool> {
    match process_directory(workspace)?.symlink_metadata(format!("{id}.drain-failed")) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn read_record(workspace: &Workspace, id: &str) -> Result<Option<Record>> {
    let directory = process_directory(workspace)?;
    let mut options = super::files::private_file_options();
    options.read(true).follow(FollowSymlinks::No);
    let file = match directory.open_with(format!("{id}.json"), &options) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_RECORD_BYTES,
        "invalid workspace process record"
    );
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_RECORD_BYTES,
        "workspace process record limit exceeded"
    );
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn cleanup_record(workspace: &Workspace, id: &str, pid: u32) -> Result<()> {
    let directory = process_directory(workspace)?;
    #[cfg(target_os = "linux")]
    let _lock = lock_records(&directory)?;
    if super::capability::read(workspace, id)?.is_some() || drain_failed(workspace, id)? {
        return Ok(());
    }
    if let Some(record) = read_record(workspace, id)? {
        ensure!(record.pid == pid, "workspace process record was replaced");
        #[cfg(target_os = "linux")]
        require_stale(&record)?;
        directory.remove_file(format!("{id}.json"))?;
        super::files::sync_directory(&directory)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct Identity {
    start: u64,
    group: u32,
    session: u32,
    parent: u32,
    state: String,
}

#[cfg(target_os = "linux")]
fn identity(pid: rustix::process::Pid) -> Result<Identity> {
    let contents = std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero()))?;
    let (_, fields) = contents
        .rsplit_once(')')
        .context("invalid workspace process stat")?;
    let parts = fields.split_whitespace().collect::<Vec<_>>();
    ensure!(parts.len() > 19, "incomplete workspace process stat");
    Ok(Identity {
        group: parts[2].parse()?,
        session: parts[3].parse()?,
        start: parts[19].parse()?,
        parent: parts[1].parse()?,
        state: parts[0].into(),
    })
}

#[cfg(target_os = "linux")]
fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

const FREEZE_MARKER: &str = ".system-quiesced";

fn frozen(workspace: &Workspace) -> Result<bool> {
    match workspace.directory.symlink_metadata(FREEZE_MARKER) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() == 0,
                "invalid workspace quiescence marker"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Stop helper-managed descendants and prevent subsequent helper launches.
pub async fn quiesce(workspace: &Workspace) -> Result<()> {
    let mut options = super::files::private_file_options();
    options.write(true).create_new(true);
    match workspace.directory.open_with(FREEZE_MARKER, &options) {
        Ok(file) => file.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            frozen(workspace)?;
        }
        Err(error) => return Err(error.into()),
    }
    super::files::sync_directory(&workspace.directory)?;
    let directory = process_directory(workspace)?;
    let mut ids = Vec::new();
    for entry in directory.entries()? {
        let name = entry?.file_name();
        if let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json"))
            && Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id)
        {
            ids.push(id.to_owned());
        }
    }
    for id in &ids {
        #[cfg(target_os = "linux")]
        if let Some(record) = read_record(workspace, id)? {
            let live = i32::try_from(record.pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .and_then(|pid| identity(pid).ok())
                .is_some_and(|current| current.start == record.start && current.state != "Z");
            if !live {
                continue;
            }
        }
        kill(workspace, id)?;
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let active = ids.iter().try_fold(false, |active, id| -> Result<bool> {
            let record = read_record(workspace, id)?;
            #[cfg(target_os = "linux")]
            if let Some(record) = record
                && let Some(pid) = i32::try_from(record.pid)
                    .ok()
                    .and_then(rustix::process::Pid::from_raw)
            {
                return Ok(active
                    || identity(pid).is_ok_and(|current| {
                        current.start == record.start && current.state != "Z"
                    }));
            }
            #[cfg(not(target_os = "linux"))]
            let _ = record;
            Ok(active)
        })?;
        if !active {
            stop_holders(workspace).await?;
            match reconcile_quiescent(workspace) {
                Ok(()) => return Ok(()),
                // An owner shell can enter hold just after its command drains.
                // Reconcile that late holder; never exempt an unknown process.
                Err(error) if tokio::time::Instant::now() >= deadline => return Err(error),
                Err(_) => {}
            }
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "workspace processes did not stop"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Resume new helper launches after an unsuccessful runtime move.
pub fn thaw(workspace: &Workspace) -> Result<()> {
    match workspace.directory.remove_file(FREEZE_MARKER) {
        Ok(()) => super::files::sync_directory(&workspace.directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize, Serialize)]
struct Ancestor {
    pid: u32,
    start: u64,
}

#[cfg(target_os = "linux")]
fn ancestors(mut pid: rustix::process::Pid) -> Result<Vec<Ancestor>> {
    let mut result = Vec::new();
    loop {
        let process = identity(pid)?;
        let Some(parent) = i32::try_from(process.parent)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        else {
            break;
        };
        pid = parent;
        let process = identity(pid)?;
        result.push(Ancestor {
            pid: pid.as_raw_nonzero().get() as u32,
            start: process.start,
        });
        ensure!(
            result.len() <= 128,
            "workspace process ancestry limit exceeded"
        );
    }
    Ok(result)
}

/// Holders are stopped through their own identity-bound requests. No live
/// process is exempted based on a writable workspace record.
async fn stop_holders(workspace: &Workspace) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let directory = process_directory(workspace)?;
        let mut holders = Vec::new();
        for entry in directory.entries()? {
            let name = entry?.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".hold.json"))
            else {
                continue;
            };
            validate_id(id)?;
            let Some(record) = read_record(workspace, &format!("{id}.hold"))? else {
                continue;
            };
            ensure!(record.version == 1, "unsupported holder identity");
            replace_record(workspace, &format!("{id}.hold-exit"), &record)?;
            holders.push(record);
            ensure!(holders.len() <= 4096, "workspace holder limit exceeded");
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let mut live = false;
            for record in &holders {
                let pid = i32::try_from(record.pid)
                    .ok()
                    .and_then(rustix::process::Pid::from_raw)
                    .context("invalid holder PID")?;
                match identity(pid) {
                    Ok(current) => live |= current.start == record.start && current.state != "Z",
                    Err(error) if is_missing(&error) => {}
                    Err(error) => return Err(error.context("verify holder exit")),
                }
            }
            if !live {
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "workspace holders did not exit"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = workspace;
        anyhow::bail!("workspace quiescence requires Linux")
    }
}

/// Recover a failed drain only after a fresh scan proves the whole process
/// namespace quiescent. Retain the failure evidence under a distinct name; a
/// reconnect, thaw, or plain export alone must never clear it.
fn reconcile_quiescent(workspace: &Workspace) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        ensure!(frozen(workspace)?, "workspace is not frozen");
        let allowed = ancestors(rustix::process::getpid())?;
        require_quiescent(&allowed)?;
        let directory = process_directory(workspace)?;
        let _lock = lock_records(&directory)?;
        let mut failures = Vec::new();
        for entry in directory.entries()? {
            let name = entry?.file_name();
            if let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".drain-failed"))
            {
                validate_id(id)?;
                let record = read_record(workspace, id)?;
                for suffix in ["cancel", "cancel-ack"] {
                    if let Some(request) = read_record(workspace, &format!("{id}.{suffix}"))? {
                        ensure!(
                            record.as_ref() == Some(&request),
                            "workspace cancellation identity changed"
                        );
                    }
                }
                failures.push(name);
            }
        }
        // Validate every retained identity before reconciling any failure.
        for name in failures {
            directory.rename(
                &name,
                &directory,
                format!("{}.reconciled-{}", name.to_string_lossy(), Uuid::new_v4()),
            )?;
        }
        super::files::sync_directory(&directory)?;
    }
    verify_quiescent(workspace)
}

/// Recheck the frozen source immediately before reading an export.
pub(super) fn verify_quiescent(_workspace: &Workspace) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let workspace = _workspace;
        let allowed = ancestors(rustix::process::getpid())?;
        for entry in process_directory(workspace)?.entries()? {
            let name = entry?.file_name();
            ensure!(
                !name
                    .to_str()
                    .is_some_and(|name| name.ends_with(".drain-failed")),
                "workspace descendant drain remains unverified"
            );
        }
        require_quiescent(&allowed)?;
    }
    Ok(())
}

pub(super) fn verify_frozen_export(workspace: &Workspace) -> Result<()> {
    if frozen(workspace)? {
        verify_quiescent(workspace)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_quiescent(allowed: &[Ancestor]) -> Result<()> {
    let own = rustix::process::getpid().as_raw_nonzero().get() as u32;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
        else {
            continue;
        };
        let raw = pid.as_raw_nonzero().get() as u32;
        if raw == own {
            continue;
        }
        let current = match identity(pid) {
            Ok(current) => current,
            Err(error) if is_missing(&error) => continue,
            Err(error) => return Err(error),
        };
        if current.state == "Z"
            || allowed
                .iter()
                .any(|allowed| allowed.pid == raw && allowed.start == current.start)
        {
            continue;
        }
        anyhow::bail!(
            "workspace still has an untracked live process ({raw}); refusing a non-quiescent export"
        );
    }
    Ok(())
}

/// Keep a completed owner workload alive without running more guest commands.
pub async fn hold(_workspace: &Workspace, id: &str) -> Result<()> {
    validate_id(id)?;
    #[cfg(target_os = "linux")]
    {
        let workspace = _workspace;
        let pid = rustix::process::getpid();
        let record = Record {
            version: 1,
            pid: pid.as_raw_nonzero().get() as u32,
            start: identity(pid)?.start,
        };
        publish_record(workspace, &format!("{id}.hold"), &record)?;
        loop {
            if let Some(request) = read_record(workspace, &format!("{id}.hold-exit"))? {
                ensure!(request == record, "workspace holder stop identity changed");
                ensure!(
                    read_record(workspace, &format!("{id}.hold"))? == Some(record),
                    "workspace holder identity was replaced"
                );
                let directory = process_directory(workspace)?;
                // Remove the consumed request before freeing the identity so
                // a verified source restart can reuse its canonical holder ID.
                directory.remove_file(format!("{id}.hold-exit.json"))?;
                directory.remove_file(format!("{id}.hold.json"))?;
                super::files::sync_directory(&directory)?;
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("workspace holding requires Linux")
}

#[cfg(all(test, target_os = "linux"))]
#[path = "process_restart_tests.rs"]
mod restart_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_drain_retains_record_and_blocks_export_after_thaw() {
        let directory = tempfile::tempdir().expect("workspace");
        let workspace = Workspace::open(directory.path()).expect("open workspace");
        let id = Uuid::new_v4().to_string();
        let pid = rustix::process::getpid();
        let record = Record {
            version: 1,
            pid: pid.as_raw_nonzero().get() as u32,
            start: identity(pid).expect("current process").start,
        };
        publish_record(&workspace, &id, &record).expect("publish identity");
        mark_drain_failed(&workspace, &id).expect("persist failed drain");
        cleanup_record(&workspace, &id, record.pid).expect("retain failed record");
        assert!(read_record(&workspace, &id).expect("read record").is_some());
        thaw(&workspace).expect("thaw does not erase failed drain");
        let error = verify_quiescent(&workspace).expect_err("failed drain is not quiescent");
        assert!(error.to_string().contains("drain remains unverified"));
    }

    #[test]
    fn process_argument_validation_rejects_ambiguous_identity_and_commands() {
        assert!(validate_id("../other").is_err());
        assert!(validate_id("550E8400-E29B-41D4-A716-446655440000").is_err());
        for command in ["null", "[]", "[\"\"]", "[\"x\\u0000y\"]"] {
            assert!(validate_command(command).is_err(), "accepted {command}");
        }
        assert_eq!(
            validate_command("[\"printf\",\"%s\",\"a b\"]").expect("command"),
            ["printf", "%s", "a b"]
        );
    }
}
