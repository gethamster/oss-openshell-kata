//! Host observations of hypervisor identity, resource limits, and capped storage.
use super::command::Node;
use super::model::{guest_memory_bytes, host_memory_bytes};
use crate::profile::VmPolicy;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::ffi::OsString;
fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
pub(super) async fn host_process(
    node: &Node,
    id: &str,
    native: &Value,
    policy: &VmPolicy,
) -> Result<(u32, String)> {
    let internal = native["ID"].as_str().context("missing container ID")?;
    let output = node
        .node(&args(&["pgrep", "-f", "containerd-shim-kata-v2"]))
        .await?;
    for line in String::from_utf8(output.stdout)?.lines() {
        let pid: u32 = line.parse()?;
        let command = node
            .raw_node(&args(&["cat", &format!("/proc/{pid}/cmdline")]))
            .await?;
        let arguments = command.stdout.split(|b| *b == 0).collect::<Vec<_>>();
        if arguments
            .windows(2)
            .any(|pair| pair[0] == b"-id" && pair[1] == internal.as_bytes())
        {
            let output = node
                .node(&args(&["cat", &format!("/proc/{pid}/cgroup")]))
                .await?;
            let output = String::from_utf8(output.stdout)?;
            let path = output
                .lines()
                .find_map(|line| line.strip_prefix("0::"))
                .context("missing unified cgroup")?;
            if path != format!("/openshell-kata/{id}")
                && !path.starts_with(&format!("/openshell-kata/{id}/"))
            {
                bail!("hypervisor is outside its bounded cgroup");
            }
            let executable = node
                .node(&args(&["readlink", "-f", &format!("/proc/{pid}/exe")]))
                .await?;
            if String::from_utf8(executable.stdout)?.trim()
                != "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2"
            {
                bail!("hypervisor executable is not the official Rust runtime");
            }
            let cgroup = format!("/sys/fs/cgroup/openshell-kata/{id}");
            let memory = node
                .node(&args(&["cat", &format!("{cgroup}/memory.max")]))
                .await?;
            let guest_memory = node
                .node(&args(&["cat", &format!("{cgroup}/guest/memory.max")]))
                .await?;
            let cpu = node
                .node(&args(&["cat", &format!("{cgroup}/cpu.max")]))
                .await?;
            if !valid_memory_limits(
                &policy.resources,
                native
                    .pointer("/Spec/linux/resources/memory/limit")
                    .and_then(Value::as_u64),
                String::from_utf8(memory.stdout)?.trim(),
                String::from_utf8(guest_memory.stdout)?.trim(),
            ) || String::from_utf8(cpu.stdout)?.trim()
                != format!("{} 100000", u64::from(policy.resources.vcpus) * 100000)
            {
                bail!("host resource limits differ from admitted profile");
            }
            // Kata acknowledges task startup before Dragonball has necessarily
            // named every vCPU thread. Wait for the admitted count to appear;
            // transient startup state is not a resource-profile mismatch. The shim's
            // other threads come and go meanwhile; one that exits between listing
            // and reading is skipped, not a failed verification (a vanished
            // hypervisor still fails the count at the deadline).
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let threads = node
                    .node(&args(&[
                        "sh",
                        "-c",
                        "for comm in /proc/\"$1\"/task/*/comm; do cat \"$comm\" 2>/dev/null || :; done",
                        "sh",
                        &pid.to_string(),
                    ]))
                    .await?;
                let count = String::from_utf8(threads.stdout)?
                    .lines()
                    .filter(|name| name.starts_with("db_vcpu"))
                    .count();
                if count == policy.resources.vcpus as usize {
                    break;
                }
                if count > policy.resources.vcpus as usize
                    || tokio::time::Instant::now() >= deadline
                {
                    bail!(
                        "unexpected virtual CPU count: observed {count}, expected {}",
                        policy.resources.vcpus
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            return Ok((pid, cgroup));
        }
    }
    bail!("running official Rust Kata hypervisor was not found")
}

fn valid_memory_limits(
    resources: &crate::boundary::process::VmLimits,
    guest_bytes: Option<u64>,
    parent: &str,
    shim: &str,
) -> bool {
    let host = host_memory_bytes(resources);
    guest_bytes == Some(guest_memory_bytes(resources))
        && parent.parse::<u64>().ok() == Some(host)
        && shim.parse::<u64>().ok() == Some(host)
}

pub(super) async fn verify_storage(node: &Node, native: &Value, policy: &VmPolicy) -> Result<()> {
    if native["Snapshotter"] != "devmapper" {
        bail!("sandbox root is not on capped block storage");
    }
    let mounts = native
        .pointer("/Spec/mounts")
        .and_then(Value::as_array)
        .context("missing OCI mounts")?;
    for mount in mounts {
        let kind = mount["type"].as_str().context("missing mount type")?;
        let source = mount["source"].as_str().unwrap_or("");
        if ![
            "proc", "tmpfs", "devpts", "sysfs", "mqueue", "cgroup", "cgroup2",
        ]
        .contains(&kind)
            || source.starts_with('/')
        {
            bail!("host filesystem mounts are forbidden");
        }
    }
    if native
        .pointer("/Spec/linux/devices")
        .and_then(Value::as_array)
        .is_some_and(|devices| !devices.is_empty())
    {
        bail!("host device passthrough is forbidden");
    }
    let configuration = node
        .node(&args(&[
            "cat",
            "/opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml",
        ]))
        .await?;
    let configuration = String::from_utf8(configuration.stdout)?;
    if !configuration
        .lines()
        .any(|line| line.trim() == "shared_fs = \"none\"")
    {
        bail!("host shared filesystem export is not disabled");
    }
    let pool = node
        .node(&args(&["dmsetup", "table", "openshell-kata-pool"]))
        .await?;
    let pool = String::from_utf8(pool.stdout)?;
    if pool.contains("skip_block_zeroing") || !pool.contains("error_if_no_space") {
        bail!("thin pool does not enforce safe zeroing and exhaustion behavior");
    }
    let source = storage_device(node, native).await?;
    let output = node
        .node(&args(&["blockdev", "--getsize64", &source]))
        .await?;
    let bytes: String = String::from_utf8(output.stdout)?;
    if bytes.trim().parse::<u64>()? != policy.resources.disk_mib * 1024 * 1024 {
        bail!("private block device capacity differs from admitted disk limit");
    }
    Ok(())
}

pub(super) async fn storage_device(node: &Node, native: &Value) -> Result<String> {
    let key = native["SnapshotKey"]
        .as_str()
        .context("missing snapshot identity")?;
    let output = node
        .node(&args(&[
            "ctr",
            "snapshots",
            "--snapshotter",
            "devmapper",
            "mounts",
            "/run/openshell-kata-probe",
            key,
        ]))
        .await?;
    let mounts = String::from_utf8(output.stdout)?;
    mounts
        .split_whitespace()
        .find(|part| part.starts_with("/dev/mapper/openshell-kata-pool-"))
        .map(str::to_owned)
        .context("snapshot has no owned block device")
}

#[cfg(test)]
mod tests {
    use super::valid_memory_limits;
    use crate::boundary::process::VmLimits;

    fn limits(vcpus: u32, memory_mib: u64, disk_mib: u64) -> VmLimits {
        VmLimits {
            vcpus,
            memory_mib,
            disk_mib,
            lifetime_secs: 3600,
        }
    }

    #[test]
    fn guest_memory_and_both_host_limits_are_verified_separately() {
        let local = limits(1, 2048, 2048);
        let guest = Some(2_147_483_648);
        assert!(valid_memory_limits(
            &local,
            guest,
            "2415919104",
            "2415919104"
        ));
        for (parent, shim) in [
            ("2147483648", "2415919104"),
            ("2415919104", "2147483648"),
            ("max", "2415919104"),
            ("2415919104", "max"),
            ("2415919105", "2415919104"),
        ] {
            assert!(!valid_memory_limits(&local, guest, parent, shim));
        }
        assert!(!valid_memory_limits(
            &local,
            Some(2_415_919_104),
            "2415919104",
            "2415919104"
        ));
        assert!(!valid_memory_limits(
            &local,
            None,
            "2415919104",
            "2415919104"
        ));
    }

    #[test]
    fn large_build_guests_reserve_proportional_host_overhead() {
        // foundry-build: 128 GiB guest RAM plus a 4 GiB (1/32) host margin.
        let build = limits(32, 131_072, 262_144);
        let guest = Some(137_438_953_472);
        let host = (137_438_953_472_u64 + 4_294_967_296).to_string();
        assert!(valid_memory_limits(&build, guest, &host, &host));
        // The former 1/64 margin OOM-killed a fully faulted 128 GiB guest's shim.
        let narrow = (137_438_953_472_u64 + 2_147_483_648).to_string();
        assert!(!valid_memory_limits(&build, guest, &narrow, &narrow));
        let local_margin = (137_438_953_472_u64 + 268_435_456).to_string();
        assert!(!valid_memory_limits(
            &build,
            guest,
            &local_margin,
            &local_margin
        ));
        assert!(!valid_memory_limits(
            &build,
            Some(2_147_483_648),
            &host,
            &host
        ));
    }
}
