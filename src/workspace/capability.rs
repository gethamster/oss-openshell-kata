//! Docker requests are retained separately from untrusted command output.
use super::{Workspace, files, process};
use anyhow::{Context, Result, ensure};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    process::Command,
};
use uuid::Uuid;

const SUFFIX: &str = ".capability.json";

/// An invocation requiring a Docker-capable runtime, bound to one command UUID.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequest {
    pub version: u32,
    pub capability: String,
    pub command_id: String,
}

/// Read one bounded capability request without following filesystem links.
pub fn read(workspace: &Workspace, id: &str) -> Result<Option<CapabilityRequest>> {
    process::validate_id(id)?;
    let directory = process::process_directory(workspace)?;
    let mut options = files::private_file_options();
    options.read(true).follow(FollowSymlinks::No);
    let file = match directory.open_with(format!("{id}{SUFFIX}"), &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 1024,
        "invalid capability request"
    );
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024, "capability request too large");
    let request: CapabilityRequest = serde_json::from_slice(&bytes)?;
    ensure!(
        request.version == 1 && request.capability == "docker" && request.command_id == id,
        "invalid capability request"
    );
    Ok(Some(request))
}

/// List pending requests, including commands launched by a thread workload itself.
pub fn pending(workspace: &Workspace) -> Result<Vec<CapabilityRequest>> {
    let directory = process::process_directory(workspace)?;
    let mut ids = Vec::new();
    for entry in directory.entries()? {
        let name = entry?.file_name();
        if let Some(id) = name.to_str().and_then(|name| name.strip_suffix(SUFFIX)) {
            process::validate_id(id)?;
            ids.push(id.to_owned());
        }
        ensure!(ids.len() <= 4096, "too many capability requests");
    }
    ids.sort();
    ids.into_iter()
        .filter_map(|id| read(workspace, &id).transpose())
        .collect()
}

/// Acknowledge a successfully handled request; retries are harmless.
pub fn acknowledge(workspace: &Workspace, id: &str) -> Result<()> {
    process::validate_id(id)?;
    let directory = process::process_directory(workspace)?;
    match directory.remove_file(format!("{id}{SUFFIX}")) {
        Ok(()) => files::sync_directory(&directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Execute local CLI information requests or retain a Docker runtime request.
pub fn request_docker(workspace: &Workspace, args: &[String], compose: bool) -> Result<i32> {
    if local_information(args, compose) {
        let executable = if compose {
            "/usr/libexec/openshell/docker-compose"
        } else {
            "/usr/libexec/openshell/docker"
        };
        return Ok(Command::new(executable)
            .args(args)
            .status()
            .context("run Docker CLI information request")?
            .code()
            .unwrap_or(1));
    }
    let managed = std::env::var("OPENSHELL_WORKSPACE_COMMAND_ID").ok();
    let id = managed
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    process::validate_id(&id)?;
    let request = CapabilityRequest {
        version: 1,
        capability: "docker".into(),
        command_id: id.clone(),
    };
    let directory = process::process_directory(workspace)?;
    let staged = format!(".capability-{}", Uuid::new_v4());
    let mut options = files::private_file_options();
    options.write(true).create_new(true);
    let mut file = directory.open_with(&staged, &options)?;
    file.write_all(&serde_json::to_vec(&request)?)?;
    file.sync_all()?;
    directory.rename(&staged, &directory, format!("{id}{SUFFIX}"))?;
    files::sync_directory(&directory)?;
    eprintln!(
        "Docker requires moving this session to the Docker-capable sandbox; this command was interrupted and has not been replayed."
    );
    if managed.is_some() {
        process::kill(workspace, &id)?;
        // Do not return into a compound shell command while its controller is
        // handling cancellation. The verified controller terminates the group.
        loop {
            std::thread::park();
        }
    }
    Ok(125)
}

fn local_information(args: &[String], compose: bool) -> bool {
    args.is_empty()
        || matches!(args, [one] if one == "--help" || one == "-h" || one == "--version" || one == "-v" || (compose && one == "version"))
        || matches!(args, [command, ..] if matches!(command.as_str(), "help" | "version"))
        || matches!(args, [command, subcommand, ..] if !compose && command == "compose" && matches!(subcommand.as_str(), "help" | "version"))
        || matches!(args, [one, two] if !compose && one == "compose" && matches!(two.as_str(), "version" | "--help" | "-h"))
        || matches!(args, [_, help] if matches!(help.as_str(), "--help" | "-h"))
        || matches!(args, [group, _, help] if !compose
            && matches!(group.as_str(), "compose" | "buildx" | "container" | "image" | "network" | "volume" | "system" | "context" | "plugin" | "manifest" | "service" | "stack" | "swarm" | "node" | "secret" | "config" | "trust")
            && matches!(help.as_str(), "--help" | "-h"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_local_information_avoids_a_runtime_request() {
        for (args, compose, expected) in [
            (vec![], false, true),
            (vec!["--version"], false, true),
            (vec!["compose", "version"], false, true),
            (vec!["info"], false, false),
            (vec!["version"], false, true),
            (vec!["help"], false, true),
            (vec!["help", "build"], false, true),
            (vec!["compose", "help"], false, true),
            (vec!["compose", "help", "build"], false, true),
            (vec!["version"], true, true),
            (vec!["compose", "up"], false, false),
            (vec!["run", "--help"], false, true),
            (vec!["run", "alpine", "--help"], false, false),
            (vec!["compose", "up", "--help"], false, true),
        ] {
            let args = args.into_iter().map(String::from).collect::<Vec<_>>();
            assert_eq!(local_information(&args, compose), expected, "{args:?}");
        }
    }
}
