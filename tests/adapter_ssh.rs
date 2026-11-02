use anyhow::Context;
use openshell_kata::{
    config::Config,
    guest::Guest,
    proto::openshell::compute::v1 as c,
    ssh,
    supervisor::{Phase, Runtime},
};
use russh::{ChannelMsg, client};
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

struct Client {
    banner: Arc<std::sync::Mutex<Vec<u8>>>,
}
fn upload_tar(body: &[u8], path: &str) -> anyhow::Result<Vec<u8>> {
    upload_tar_kind(body, path, tar::EntryType::Regular)
}
fn upload_tar_kind(body: &[u8], path: &str, kind: tar::EntryType) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut builder = tar::Builder::new(&mut bytes);
    let mut header = tar::Header::new_ustar();
    header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
    header.set_size(body.len() as u64);
    header.set_mode(0o600);
    header.set_entry_type(kind);
    header.set_cksum();
    builder.append(&header, body)?;
    builder.finish()?;
    drop(builder);
    Ok(bytes)
}
impl client::Handler for Client {
    type Error = anyhow::Error;
    async fn kex_done(
        &mut self,
        _: Option<&[u8]>,
        _: &russh::Names,
        session: &mut client::Session,
    ) -> anyhow::Result<()> {
        *self.banner.lock().expect("fixture banner") = session.remote_sshid().to_vec();
        Ok(())
    }
    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }
}
struct Fixture {
    _files: tempfile::TempDir,
    _socket: tempfile::TempDir,
    runtime: Arc<Runtime>,
    listener: tokio::task::JoinHandle<()>,
    client: client::Handle<Client>,
    banner: Arc<std::sync::Mutex<Vec<u8>>>,
}
impl Fixture {
    async fn new() -> anyhow::Result<Self> {
        Self::with_user("sandbox").await
    }
    async fn with_user(user: &str) -> anyhow::Result<Self> {
        Self::with_profile(user, None, Phase::Starting).await
    }
    async fn hardened(phase: Phase) -> anyhow::Result<Self> {
        let profile = openshell_kata::profile::VmPolicy {
            version: 1,
            profile: "docker-vm".into(),
            resources: openshell_kata::boundary::process::VmLimits {
                vcpus: 1,
                memory_mib: 2048,
                disk_mib: 2048,
                lifetime_secs: 60,
            },
            filesystem: Default::default(),
            network: Default::default(),
        };
        Self::with_profile("sandbox", Some(profile), phase).await
    }
    async fn with_profile(
        user: &str,
        profile: Option<openshell_kata::profile::VmPolicy>,
        phase: Phase,
    ) -> anyhow::Result<Self> {
        let files = tempfile::tempdir()?;
        let key = files.path().join("host-key");
        let status = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()?;
        anyhow::ensure!(status.success(), "fixture key generation failed");
        let executable = files.path().join("guest-ssh");
        let safe = files.path().join("safe.tar");
        let hostile = files.path().join("hostile.tar");
        let link = files.path().join("link.tar");
        std::fs::write(&safe, upload_tar(b"exported source", "./source.txt")?)?;
        std::fs::write(&hostile, upload_tar(b"escape", "../escape")?)?;
        std::fs::write(
            &link,
            upload_tar_kind(b"", "link", tar::EntryType::Symlink)?,
        )?;
        let quote = openshell_kata::config::shell_quote;
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\nfor argument do command=$argument; done\ncase \"$command\" in\nfixture-eof-hold) cat >/dev/null; printf '%s' \"$$\" > {}; printf stdin-closed; exec sleep 120;;\n*hold-output*) cat >/dev/null; sleep 120 & printf '%s' \"$!\" > {}; exit 0;;\n*failure*) echo extractor-failed >&2; exit 23;;\n*'tar -xf'*) cat >/dev/null;;\nfixture-output) printf normal; printf error >&2; exit 7;;\n 'tar cf - -C /sandbox safe') cat {};;\n 'tar cf - -C /sandbox hostile') cat {};;\n 'tar cf - -C /sandbox link') cat {};;\n 'tar cf - -C /sandbox badexit') cat {}; exit 23;;\n*) cat;;\nesac\n",
                quote(&files.path().join("eof-process.pid").to_string_lossy()),
                quote(&files.path().join("held-output.pid").to_string_lossy()),
                quote(&safe.to_string_lossy()),
                quote(&hostile.to_string_lossy()),
                quote(&link.to_string_lossy()),
                quote(&safe.to_string_lossy())
            ),
        )?;
        let original = std::fs::read_to_string(&executable)?;
        let prelude = format!(
            "#!/bin/sh\nfor argument do command=$argument; done\nprintf '%s\\n' \"$command\" >> {}\ncase \"$command\" in\n\"exec /usr/bin/env -u BASH_ENV -u ENV /bin/bash --noprofile --norc\"*) BASH_ENV={} exec /bin/sh -c \"$command\";;\n\"exec /bin/bash -l -c '\"*) command=${{command#\"exec /bin/bash -l -c '\"}}; command=${{command%\"'\"}};;\nesac\n",
            quote(&files.path().join("shell-commands").to_string_lossy()),
            quote(&files.path().join("startup-profile").to_string_lossy())
        );
        std::fs::write(
            &executable,
            original.replacen(
                "#!/bin/sh\nfor argument do command=$argument; done\n",
                &prelude,
                1,
            ),
        )?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
        let config = Arc::new(Config {
            socket: files.path().join("driver.sock"),
            gateway: "https://127.0.0.1:1".into(),
            gateway_ca: files.path().join("unused-ca"),
            lifecycle: executable.clone(),
            lifecycle_arg: vec![],
            ssh: executable,
            prototype_policy_mode: true,
            vm_policy: None,
            runtime_profile: openshell_kata::config::RuntimeProfile::Local,
            guest_image: None,
            guest_network_cidr: None,
            additional_guest_images: Vec::new(),
            recovery_dir: None,
            hosted_network_config: None,
            hosted_resource_profile: Default::default(),
            max_sandboxes: None,
        });
        let guest = Guest {
            sandbox_id: "test-id".into(),
            host: "127.0.0.1".into(),
            port: 12345,
            username: "sandbox".into(),
            private_key_path: key.clone(),
            known_hosts_path: files.path().join("unused-hosts"),
            enforcement: None,
            runtime_identity: None,
        };
        let host_key = std::fs::read_to_string(key)?;
        let authentication = serde_json::to_vec(
            &serde_json::json!({"supervisor":{"gateway_token":"test-placeholder","ssh_host_private_key":host_key}}),
        )?;
        let runtime = Runtime::new_with_policy(
            c::DriverSandbox {
                id: "test-id".into(),
                name: "test-name".into(),
                spec: Some(c::DriverSandboxSpec::default()),
                ..Default::default()
            },
            config,
            guest,
            authentication,
            profile.clone(),
            profile,
        )?;
        runtime.phase.send_replace(phase);
        let (socket, listener) = ssh::listen(runtime.clone(), &host_key).await?;
        let stream = tokio::net::UnixStream::connect(socket.path().join("ssh.sock")).await?;
        let banner = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut client = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            Client {
                banner: banner.clone(),
            },
        )
        .await?;
        anyhow::ensure!(
            client.authenticate_none(user).await?.success(),
            "fixture authentication failed"
        );
        Ok(Self {
            _files: files,
            _socket: socket,
            runtime,
            listener,
            client,
            banner,
        })
    }
    async fn close(mut self) {
        self.runtime.close().await;
        self.listener.abort();
        let _ = (&mut self.listener).await;
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Fixture descendants intentionally retain pipes; never leave them on the host.
        for name in ["eof-process.pid", "held-output.pid"] {
            if let Ok(value) = std::fs::read_to_string(self._files.path().join(name))
                && let Ok(pid) = value.parse::<u32>()
            {
                let _ = std::process::Command::new("/bin/kill")
                    .args(["-KILL", &pid.to_string()])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
        }
    }
}

async fn wait_for_permits(
    semaphore: &tokio::sync::Semaphore,
    expected: usize,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while semaphore.available_permits() != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn gateway_relayed_system_ssh_username_does_not_select_guest_identity() -> anyhow::Result<()>
{
    let fixture = Fixture::with_user("local-desktop-user").await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel.exec(true, "fixture-output").await?;
    channel.eof().await?;
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit = Some(exit_status);
        }
    }
    assert_eq!(exit, Some(7));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn forwards_stdout_stderr_and_exit_status() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel.exec(true, "fixture-output").await?;
    channel.eof().await?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            _ => {}
        }
    }
    assert_eq!(stdout, b"normal");
    assert_eq!(stderr, b"error");
    assert_eq!(exit, Some(7));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn invalid_upload_plan_closes_channel_without_waiting_for_eof() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel.data(&b"{invalid}\n"[..]).await?;
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit = Some(exit_status);
        }
    }
    assert_eq!(exit, Some(1));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn failed_extractor_reports_failure_after_archive_validation() -> anyhow::Result<()> {
    assert_extractor_failure_without_final_ack(b"source").await
}

#[tokio::test]
async fn early_extractor_failure_preserves_status_without_a_final_ack() -> anyhow::Result<()> {
    assert_extractor_failure_without_final_ack(&vec![0x71; 2 * 1024 * 1024]).await
}

async fn assert_extractor_failure_without_final_ack(body: &[u8]) -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel
        .data(&b"{\"destination_directory\":\"/sandbox/failure\"}\n"[..])
        .await?;
    let bytes = upload_tar(body, "file")?;
    channel.data(bytes.as_slice()).await?;
    channel.eof().await?;
    let mut exit = None;
    let mut errors = Vec::new();
    let mut acknowledgments = Vec::new();
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        match message {
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            ChannelMsg::ExtendedData { data, .. } => errors.extend_from_slice(&data),
            ChannelMsg::Data { data } => acknowledgments.extend_from_slice(&data),
            _ => {}
        }
    }
    assert_eq!(exit, Some(23), "{}", String::from_utf8_lossy(&errors));
    assert!(
        acknowledgments
            .as_chunks::<8>()
            .0
            .iter()
            .all(|value| { u64::from_be_bytes(*value) != bytes.len() as u64 }),
        "failed extraction must not acknowledge the final archive total"
    );
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn ssh_upload_reports_final_total_for_multi_megabyte_input() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel
        .data(&b"{\"destination_directory\":\"/sandbox/project\"}\n"[..])
        .await?;
    let bytes = upload_tar(&vec![0x71; 2 * 1024 * 1024 + 19], "source.bin")?;
    channel.data(&bytes[..]).await?;
    channel.eof().await?;
    let mut acks = Vec::new();
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await? {
        match message {
            ChannelMsg::Data { data } => acks.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            _ => {}
        }
    }
    let totals = acks
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_be_bytes(*chunk))
        .collect::<Vec<_>>();
    assert_eq!(totals.first(), Some(&0));
    assert_eq!(totals.last(), Some(&(bytes.len() as u64)));
    assert_eq!(exit, Some(0));
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn cancellation_closes_an_upload_with_an_incomplete_plan() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel.data(&b"{\"destination_"[..]).await?;
    fixture.runtime.cancel.cancel();
    while tokio::time::timeout(Duration::from_secs(5), channel.wait())
        .await?
        .is_some()
    {}
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn invalid_archive_is_rejected_before_guest_extractor_can_start() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    // This destination makes the guest fixture exit 23 if it is ever started.
    channel
        .data(&b"{\"destination_directory\":\"/sandbox/failure\"}\n"[..])
        .await?;
    channel
        .data(upload_tar(b"hostile", "../escape")?.as_slice())
        .await?;
    channel.eof().await?;
    let mut exit = None;
    let mut acks = Vec::new();
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        match message {
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            ChannelMsg::Data { data } => acks.extend_from_slice(&data),
            _ => {}
        }
    }
    assert_eq!(exit, Some(1));
    assert_eq!(acks, 0u64.to_be_bytes(), "no final success acknowledgement");
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn cancellation_reclaims_an_unfinished_archive_transfer() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel
        .data(&b"{\"destination_directory\":\"/sandbox/failure\"}\n"[..])
        .await?;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        if matches!(message, ChannelMsg::Data { .. }) {
            break;
        }
    }
    assert_eq!(fixture.runtime.transfer_slots.available_permits(), 1);
    fixture.runtime.cancel.cancel();
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit = Some(exit_status);
        }
    }
    assert_eq!(exit, Some(1));
    assert_eq!(fixture.runtime.transfer_slots.available_permits(), 2);
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn simultaneous_uploads_are_limited_before_spooling() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut channel = fixture.client.channel_open_session().await?;
        channel
            .request_subsystem(true, "openshell-upload-v1")
            .await?;
        channel
            .data(&b"{\"destination_directory\":\"/sandbox/project\"}\n"[..])
            .await?;
        while let Some(message) =
            tokio::time::timeout(Duration::from_secs(5), channel.wait()).await?
        {
            if matches!(message, ChannelMsg::Data { .. }) {
                break;
            }
        }
        held.push(channel);
    }
    assert_eq!(fixture.runtime.transfer_slots.available_permits(), 0);
    let mut rejected = fixture.client.channel_open_session().await?;
    rejected
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    rejected
        .data(&b"{\"destination_directory\":\"/sandbox/project\"}\n"[..])
        .await?;
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), rejected.wait()).await? {
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit = Some(exit_status);
        }
    }
    assert_eq!(exit, Some(1));
    fixture.close().await;
    drop(held);
    Ok(())
}

#[tokio::test]
async fn ssh_download_validates_and_normalizes_before_publishing() -> anyhow::Result<()> {
    use std::io::Read;
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel.exec(true, "tar cf - -C /sandbox safe").await?;
    channel.eof().await?;
    let mut output = Vec::new();
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        match message {
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            _ => {}
        }
    }
    assert_eq!(exit, Some(0));
    let mut archive = tar::Archive::new(output.as_slice());
    let mut entry = archive.entries()?.next().expect("exported entry")?;
    assert_eq!(entry.path()?.to_str(), Some("source.txt"));
    assert_eq!(entry.header().uid()?, 0);
    assert_eq!(entry.header().mode()?, 0o600);
    let mut content = String::new();
    entry.read_to_string(&mut content)?;
    assert_eq!(content, "exported source");
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn ssh_download_rejects_hostile_or_failed_exports_without_publishing_bytes()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    for name in ["hostile", "link", "badexit"] {
        let mut channel = fixture.client.channel_open_session().await?;
        channel
            .exec(true, format!("tar cf - -C /sandbox {name}"))
            .await?;
        channel.eof().await?;
        let mut output = Vec::new();
        let mut exit = None;
        while let Some(message) =
            tokio::time::timeout(Duration::from_secs(5), channel.wait()).await?
        {
            match message {
                ChannelMsg::Data { data } => output.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }
        assert_eq!(exit, Some(1), "{name}");
        assert!(
            output.is_empty(),
            "{name} published bytes before validation"
        );
    }
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn cancellation_after_exec_stdin_eof_reclaims_operation_and_child() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel.exec(true, "fixture-eof-hold").await?;
    channel.eof().await?;
    let mut output = Vec::new();
    while output != b"stdin-closed" {
        let message = tokio::time::timeout(Duration::from_secs(5), channel.wait())
            .await
            .context("fixture did not consume stdin EOF")?
            .expect("exec remains open after consuming stdin");
        if let ChannelMsg::Data { data } = message {
            output.extend_from_slice(&data);
        }
    }
    assert_eq!(fixture.runtime.operation_slots.available_permits(), 31);
    let pid: u32 =
        std::fs::read_to_string(fixture._files.path().join("eof-process.pid"))?.parse()?;
    fixture.runtime.cancel.cancel();
    wait_for_permits(&fixture.runtime.operation_slots, 32)
        .await
        .context("exec operation permit was not reclaimed")?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while std::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("cancelled guest SSH child remained live")?;
    std::fs::remove_file(fixture._files.path().join("eof-process.pid"))?;
    fixture.close().await;
    Ok(())
}

enum EndHeldOutput {
    Cancel,
    Timeout,
}

async fn held_output_upload_reclaims_permits(end: EndHeldOutput) -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .request_subsystem(true, "openshell-upload-v1")
        .await?;
    channel
        .data(&b"{\"destination_directory\":\"/sandbox/hold-output\"}\n"[..])
        .await?;
    let archive = upload_tar(b"source", "file")?;
    channel.data(archive.as_slice()).await?;
    channel.eof().await?;
    let mut acks = Vec::new();
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), channel.wait())
            .await?
            .expect("upload remains open while descendant holds output");
        if let ChannelMsg::Data { data } = message {
            acks.extend_from_slice(&data);
            if acks
                .as_chunks::<8>()
                .0
                .iter()
                .any(|chunk| u64::from_be_bytes(*chunk) == archive.len() as u64)
            {
                break;
            }
        }
    }
    // The final ACK proves extraction exited successfully; only output draining remains.
    assert_eq!(fixture.runtime.transfer_slots.available_permits(), 1);
    assert_eq!(fixture.runtime.operation_slots.available_permits(), 31);
    match end {
        EndHeldOutput::Cancel => fixture.runtime.cancel.cancel(),
        EndHeldOutput::Timeout => {
            // Start the drain deadline before advancing only this test runtime's clock.
            for _ in 0..5 {
                tokio::task::yield_now().await;
            }
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(31)).await;
            tokio::time::resume();
        }
    }
    wait_for_permits(&fixture.runtime.transfer_slots, 2).await?;
    wait_for_permits(&fixture.runtime.operation_slots, 32).await?;
    if matches!(end, EndHeldOutput::Timeout) {
        let mut exit = None;
        while let Some(message) =
            tokio::time::timeout(Duration::from_secs(5), channel.wait()).await?
        {
            if let ChannelMsg::ExitStatus { exit_status } = message {
                exit = Some(exit_status);
            }
        }
        assert_eq!(exit, Some(1), "stuck output must fail instead of hanging");
    }
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn cancellation_reclaims_upload_after_extractor_exits_with_inherited_output()
-> anyhow::Result<()> {
    held_output_upload_reclaims_permits(EndHeldOutput::Cancel).await
}

#[tokio::test]
async fn output_drain_deadline_reclaims_upload_after_extractor_exits() -> anyhow::Result<()> {
    held_output_upload_reclaims_permits(EndHeldOutput::Timeout).await
}

#[tokio::test]
async fn hardened_runtime_rejects_sftp_without_starting_guest_process() -> anyhow::Result<()> {
    let fixture = Fixture::hardened(Phase::Ready).await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        assert!(!matches!(message, ChannelMsg::Data { .. }));
        if let ChannelMsg::ExitStatus { exit_status } = message {
            exit = Some(exit_status);
        }
    }
    assert_eq!(exit, Some(1));
    wait_for_permits(&fixture.runtime.operation_slots, 32).await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn hardened_runtime_rejects_exec_until_ready() -> anyhow::Result<()> {
    let fixture = Fixture::hardened(Phase::Starting).await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel.exec(true, "fixture-output").await?;
    loop {
        match tokio::time::timeout(Duration::from_secs(5), channel.wait())
            .await?
            .expect("request failure")
        {
            ChannelMsg::Failure => break,
            ChannelMsg::Data { .. } | ChannelMsg::ExtendedData { .. } => {
                panic!("guest executed before runtime readiness")
            }
            _ => {}
        }
    }
    assert_eq!(fixture.runtime.operation_slots.available_permits(), 32);
    channel.close().await?;
    fixture.close().await;
    Ok(())
}

#[path = "support/ssh_login_cases.rs"]
mod ssh_login_cases;
