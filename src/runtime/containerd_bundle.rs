//! Retire a task bundle that containerd abandoned after a dead shim's cleanup.
//!
//! When a shim dies, containerd runs the shim's `delete` command and removes
//! the task bundle only if that command finishes within containerd's short
//! cleanup timeout. A large guest can outlast it; containerd then forgets the
//! task but keeps the bundle, and every later task create for the same id fails
//! with `mkdir ...: file exists`. This repeats containerd's own cleanup once the
//! caller has proven no task or owned shim remains.
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const BUNDLES: &str = "/run/containerd/io.containerd.runtime.v2.task/default";
const SHIM: &str = "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2";
const CLEANUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Remove an abandoned bundle for `id`; returns whether one existed.
pub(super) async fn retire_abandoned(id: &str) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    super::state::validate_id(id)?;
    let bundle = Path::new(BUNDLES).join(id);
    let metadata = match std::fs::symlink_metadata(&bundle) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        other => other?,
    };
    if !metadata.is_dir() || metadata.uid() != 0 {
        bail!("refusing an unexpected task bundle artifact");
    }
    let work = match std::fs::read_link(bundle.join("work")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        other => Some(owned_work_directory(&other?, id)?),
    };
    run_shim_cleanup(&bundle, id).await?;
    if mounted_below(&bundle.join("rootfs"))? {
        bail!("abandoned task bundle still has a mounted root filesystem");
    }
    std::fs::remove_dir_all(&bundle).context("remove abandoned task bundle")?;
    if let Some(work) = work {
        match std::fs::remove_dir_all(&work) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            other => other.context("remove abandoned task state")?,
        }
    }
    Ok(true)
}

/// The bundle's `work` link must name this id's containerd runtime state.
fn owned_work_directory(target: &Path, id: &str) -> Result<PathBuf> {
    let owned = target.is_absolute()
        && target.file_name().is_some_and(|name| name == id)
        && target
            .parent()
            .is_some_and(|parent| parent.ends_with("io.containerd.runtime.v2.task/default"))
        && target.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        });
    if !owned {
        bail!("task bundle work link leaves containerd runtime state");
    }
    Ok(target.to_owned())
}

/// Kata's own host teardown, invoked exactly as containerd invokes it.
async fn run_shim_cleanup(bundle: &Path, id: &str) -> Result<()> {
    let publisher = ["/usr/local/bin/containerd", "/usr/bin/containerd"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .context("containerd executable not found")?;
    let child = tokio::process::Command::new(SHIM)
        .current_dir(bundle)
        .args([
            "-namespace",
            "default",
            "-address",
            "/run/containerd/containerd.sock",
        ])
        .args(["-publish-binary", publisher, "-id", id, "-bundle"])
        .arg(bundle)
        .arg("delete")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .status();
    let status = tokio::time::timeout(CLEANUP_TIMEOUT, child)
        .await
        .context("shim cleanup of the abandoned task bundle timed out")??;
    if !status.success() {
        bail!("shim cleanup of the abandoned task bundle failed: {status}");
    }
    Ok(())
}

fn mounted_below(path: &Path) -> Result<bool> {
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(mounts
        .lines()
        .filter_map(|line| line.split(' ').nth(4))
        .any(|point| Path::new(point).starts_with(path)))
}

#[cfg(test)]
mod tests {
    use super::owned_work_directory;
    use std::path::Path;

    #[test]
    fn work_link_must_name_this_tasks_runtime_state() {
        let id = "c51854bf-5eb3-4aee-87a8-2b4997106d37";
        let state = format!("/var/lib/containerd/io.containerd.runtime.v2.task/default/{id}");
        assert!(owned_work_directory(Path::new(&state), id).is_ok());
        for unsafe_target in [
            "relative/io.containerd.runtime.v2.task/default/c51854bf-5eb3-4aee-87a8-2b4997106d37",
            "/var/lib/containerd/io.containerd.runtime.v2.task/default/other",
            "/var/lib/containerd/io.containerd.runtime.v2.task/k8s.io/c51854bf-5eb3-4aee-87a8-2b4997106d37",
            "/var/lib/containerd/io.containerd.runtime.v2.task/default/../default/c51854bf-5eb3-4aee-87a8-2b4997106d37",
            "/",
        ] {
            assert!(
                owned_work_directory(Path::new(unsafe_target), id).is_err(),
                "{unsafe_target}"
            );
        }
    }
}
