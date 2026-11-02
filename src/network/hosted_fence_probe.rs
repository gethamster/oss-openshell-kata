//! Probe real TCX support without touching a host or workload interface.
use super::{
    hosted_fence_linux::attach,
    hosted_fence_runtime::{GuardConfig, validate_probe_namespace},
};
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    programs::{SchedClassifier, TcAttachType, links::LinkType},
};
use std::{
    os::unix::fs::MetadataExt,
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct ProbeDevice<'a> {
    config: &'a GuardConfig,
    name: String,
    removed: bool,
}
impl ProbeDevice<'_> {
    fn remove(&mut self) -> Result<()> {
        let status = run_status(command(self.config).args(["link", "delete", "dev", &self.name]))?;
        ensure!(
            status.success(),
            "could not remove the owned TCX probe interface"
        );
        self.removed = true;
        Ok(())
    }
}
impl Drop for ProbeDevice<'_> {
    fn drop(&mut self) {
        if !self.removed {
            let _ = run_status(
                command(self.config)
                    .args(["link", "delete", "dev", &self.name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null()),
            );
        }
    }
}
fn command(config: &GuardConfig) -> Command {
    let mut command = Command::new(&config.ip_path);
    command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    command
}

fn run_status(command: &mut Command) -> Result<ExitStatus> {
    let mut child = command.stdin(Stdio::null()).spawn()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("TCX probe interface operation timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn probe(config: &GuardConfig) -> Result<()> {
    let current = std::fs::metadata("/proc/self/ns/net")?;
    let host = std::fs::metadata("/proc/1/ns/net")?;
    let inventory = command(config).args(["-json", "link", "show"]).output()?;
    ensure!(
        inventory.status.success() && inventory.stdout.len() <= 131072,
        "cannot inspect the probe namespace"
    );
    validate_probe_namespace(
        (current.dev(), current.ino()),
        (host.dev(), host.ino()),
        &serde_json::from_slice(&inventory.stdout)?,
    )?;
    let name = format!("kg{:x}", std::process::id());
    let status = run_status(command(config).args(["link", "add", "name", &name, "type", "dummy"]))?;
    ensure!(
        status.success(),
        "cannot create the owned TCX probe interface"
    );
    let mut device = ProbeDevice {
        config,
        name,
        removed: false,
    };
    // No selectors or pins are installed. The zero-initialized map denies all
    // packets, and this fresh dummy interface has no workload or IP address.
    let mut ebpf =
        Ebpf::load_file(&config.object_path).context("loading the pinned TCX object for probe")?;
    let ingress = attach(
        &mut ebpf,
        "kata_ingress",
        &device.name,
        TcAttachType::Ingress,
    )?;
    let egress = attach(&mut ebpf, "kata_egress", &device.name, TcAttachType::Egress)?;
    let input = ingress.info()?;
    let output = egress.info()?;
    ensure!(
        input.link_type()? == LinkType::Tcx && output.link_type()? == LinkType::Tcx,
        "the probe requires actual TCX attachments"
    );
    for (direction, expected) in [
        (TcAttachType::Ingress, input.program_id()),
        (TcAttachType::Egress, output.program_id()),
    ] {
        let (_, programs) = SchedClassifier::query_tcx(&device.name, direction)?;
        ensure!(
            programs.len() == 1 && programs[0].id() == expected,
            "TCX probe attachment readback differs"
        );
    }
    drop((ingress, egress, ebpf));
    device.remove()?;
    println!(
        "{}",
        serde_json::json!({"version":1,"tcx":true,"object_sha256":config.object_sha256,"netns_device":current.dev(),"netns_inode":current.ino(),"ingress_program_id":input.program_id(),"egress_program_id":output.program_id()})
    );
    Ok(())
}
