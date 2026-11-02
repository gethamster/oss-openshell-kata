//! Preboot host network attachment and external broker lifecycle.
use super::command::Node;
use crate::{network::FenceSpec, profile::VmPolicy};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

/// Plan cleanup only for the tap created by the pinned, single-NIC Kata profile.
pub fn stale_taps(links: &Value) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for link in links
        .as_array()
        .context("invalid network link observation")?
    {
        match link["ifname"].as_str().context("link name missing")? {
            "lo" | "eth0" => {}
            "tap0_kata"
                if link.pointer("/linkinfo/info_kind").and_then(Value::as_str) == Some("tun")
                    && link
                        .pointer("/linkinfo/info_data/type")
                        .and_then(Value::as_str)
                        == Some("tap") =>
            {
                result.push("tap0_kata".to_owned())
            }
            _ => bail!("refusing to remove an unfamiliar network interface"),
        }
    }
    Ok(result)
}

/// Retire stale Kata tap/filter state only in this generation's pinned namespace.
pub async fn reset_for_restart(node: &Node, id: &str, attachment: &Attachment) -> Result<()> {
    let owner: Value = serde_json::from_slice(
        &node
            .node(&args(&[
                "cat",
                &format!("{}/netns-owner.json", job_directory(id)),
            ]))
            .await?
            .stdout,
    )?;
    let inode = String::from_utf8(
        node.node(&args(&["stat", "-Lc", "%i", &attachment.namespace_path()]))
            .await?
            .stdout,
    )?;
    if owner["nonce"] != attachment.owner || owner["inode"] != inode.trim() {
        bail!("network namespace identity changed before restart");
    }
    let links: Value = serde_json::from_slice(
        &node
            .node(&args(&[
                "ip",
                "-j",
                "-d",
                "-n",
                &attachment.netns,
                "link",
                "show",
            ]))
            .await?
            .stdout,
    )?;
    for tap in stale_taps(&links)? {
        node.node(&args(&[
            "ip",
            "-n",
            &attachment.netns,
            "link",
            "delete",
            "dev",
            &tap,
        ]))
        .await?;
    }
    let qdiscs: Value = serde_json::from_slice(
        &node
            .node(&args(&[
                "ip",
                "netns",
                "exec",
                &attachment.netns,
                "tc",
                "-j",
                "qdisc",
                "show",
                "dev",
                "eth0",
            ]))
            .await?
            .stdout,
    )?;
    for qdisc in qdiscs.as_array().context("invalid qdisc observation")? {
        if let Some(kind @ ("ingress" | "clsact")) = qdisc["kind"].as_str() {
            node.node(&args(&[
                "ip",
                "netns",
                "exec",
                &attachment.netns,
                "tc",
                "qdisc",
                "del",
                "dev",
                "eth0",
                kind,
            ]))
            .await?;
        }
    }
    node.node(&args(&[
        "ip",
        "-n",
        &attachment.netns,
        "address",
        "replace",
        &format!("{}/30", attachment.guest_ip),
        "dev",
        "eth0",
    ]))
    .await?;
    node.node(&args(&[
        "ip",
        "-n",
        &attachment.netns,
        "link",
        "set",
        "eth0",
        "up",
    ]))
    .await?;
    node.node(&args(&[
        "ip",
        "-n",
        &attachment.netns,
        "route",
        "replace",
        "default",
        "via",
        &attachment.gateway_ip.to_string(),
    ]))
    .await?;
    Ok(())
}

/// A host-owned interface and network namespace created before any guest code.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attachment {
    pub owner: String,
    pub netns: String,
    pub host_veth: String,
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
}
impl Attachment {
    pub fn for_id(id: &str, nonce: &str, index: u16) -> Self {
        let hash = format!("{:x}", Sha256::digest(format!("{id}:{nonce}").as_bytes()));
        let host_veth = format!("okh{}", &hash[..10]);
        let netns = format!("okn{}", &hash[..20]);
        let third = (index / 64) as u8;
        let fourth = ((index % 64) * 4) as u8;
        Self {
            owner: nonce.to_owned(),
            netns,
            host_veth,
            guest_ip: Ipv4Addr::new(10, 205, third, fourth + 2),
            gateway_ip: Ipv4Addr::new(10, 205, third, fourth + 1),
        }
    }
    pub fn namespace_path(&self) -> String {
        format!("/run/netns/{}", self.netns)
    }
}

/// Plan the complete generation identity without changing node resources.
///
/// `reserved` holds gateway addresses retained by other guests whose links may be
/// absent (stopped across a reboot, or planned by a concurrent create).
pub async fn plan_attachment(
    node: &Node,
    id: &str,
    nonce: &str,
    reserved: &[Ipv4Addr],
) -> Result<Attachment> {
    let all = node.node(&args(&["ip", "-j", "address", "show"])).await?;
    let occupied = String::from_utf8(all.stdout)?;
    let digest = Sha256::digest(id.as_bytes());
    let seed = u16::from_be_bytes([digest[0], digest[1]]) % 16384;
    (0..16384)
        .map(|offset| Attachment::for_id(id, nonce, (seed + offset) % 16384))
        .find(|a| {
            !reserved.contains(&a.gateway_ip) && !occupied.contains(&a.gateway_ip.to_string())
        })
        .context("no private network allocation available")
}

/// Create only the previously persisted, generation-owned network plan.
pub async fn create_attachment(
    node: &Node,
    id: &str,
    nonce: &str,
    attachment: &Attachment,
) -> Result<FenceSpec> {
    node.node(&args(&["ip", "netns", "add", &attachment.netns]))
        .await?;
    let inode = node
        .node(&args(&["stat", "-Lc", "%i", &attachment.namespace_path()]))
        .await?;
    put_json(
        node,
        &serde_json::json!({"nonce":nonce,"inode":String::from_utf8(inode.stdout)?.trim()}),
        &format!("{}/netns-owner.json", job_directory(id)),
    )
    .await?;
    let peer = "okpeer0";
    node.node(&args(&[
        "ip",
        "link",
        "add",
        &attachment.host_veth,
        "type",
        "veth",
        "peer",
        "name",
        peer,
    ]))
    .await?;
    node.node(&args(&[
        "ip",
        "link",
        "set",
        "dev",
        &attachment.host_veth,
        "alias",
        &format!("openshell-kata:{id}:{nonce}"),
    ]))
    .await?;
    node.node(&args(&[
        "ip",
        "link",
        "set",
        peer,
        "netns",
        &attachment.netns,
    ]))
    .await?;
    node.node(&args(&[
        "ip",
        "address",
        "add",
        &format!("{}/30", attachment.gateway_ip),
        "dev",
        &attachment.host_veth,
    ]))
    .await?;
    for command in [
        args(&[
            "ip",
            "-n",
            &attachment.netns,
            "link",
            "set",
            peer,
            "name",
            "eth0",
        ]),
        args(&[
            "ip",
            "-n",
            &attachment.netns,
            "address",
            "add",
            &format!("{}/30", attachment.guest_ip),
            "dev",
            "eth0",
        ]),
        args(&["ip", "-n", &attachment.netns, "link", "set", "lo", "up"]),
        args(&["ip", "-n", &attachment.netns, "link", "set", "eth0", "up"]),
        args(&[
            "ip",
            "-n",
            &attachment.netns,
            "route",
            "add",
            "default",
            "via",
            &attachment.gateway_ip.to_string(),
        ]),
    ] {
        node.node(&command).await?;
    }
    let host: Value = serde_json::from_slice(
        &node
            .node(&args(&[
                "ip",
                "-j",
                "link",
                "show",
                "dev",
                &attachment.host_veth,
            ]))
            .await?
            .stdout,
    )?;
    let guest: Value = serde_json::from_slice(
        &node
            .node(&args(&[
                "ip",
                "-j",
                "-n",
                &attachment.netns,
                "link",
                "show",
                "eth0",
            ]))
            .await?
            .stdout,
    )?;
    let spec = FenceSpec {
        sandbox_id: id.to_owned(),
        host_veth: attachment.host_veth.clone(),
        ifindex: u32::try_from(
            host[0]["ifindex"]
                .as_u64()
                .context("missing host interface identity")?,
        )?,
        guest_ip: attachment.guest_ip,
        gateway_ip: attachment.gateway_ip,
        guest_mac: guest[0]["address"]
            .as_str()
            .context("missing guest MAC")?
            .to_owned(),
        gateway_mac: host[0]["address"]
            .as_str()
            .context("missing host MAC")?
            .to_owned(),
        broker_port: 38080,
        proof_nonce: nonce.to_owned(),
    };
    spec.validate()?;
    Ok(spec)
}

/// Write a bounded, non-secret JSON document into a root-owned node job directory.
pub async fn put_json<T: Serialize>(node: &Node, value: &T, destination: &str) -> Result<()> {
    let temporary = tempfile::NamedTempFile::new()?;
    std::fs::write(temporary.path(), serde_json::to_vec(value)?)?;
    let stage = node.stage(temporary.path()).await?;
    node.node(&args(&["install", "-D", "-m", "0644", &stage, destination]))
        .await?;
    node.unstage(&stage).await?;
    Ok(())
}

pub fn job_directory(id: &str) -> String {
    format!("/var/lib/openshell-kata/jobs/{id}")
}
pub fn broker_unit(id: &str) -> String {
    format!(
        "okata-b-{}",
        &format!("{:x}", Sha256::digest(id.as_bytes()))[..20]
    )
}
pub fn control_path(id: &str) -> String {
    format!("/run/{}/broker.sock", broker_unit(id))
}
pub fn network_binary(runtime_binary: &Path) -> PathBuf {
    runtime_binary.with_file_name("kata-network")
}

/// Install the host packet fence while the host veth is still down.
pub async fn install(node: &Node, runtime_binary: &Path, id: &str, spec: &FenceSpec) -> Result<()> {
    let directory = job_directory(id);
    let spec_path = format!("{directory}/fence-spec.json");
    put_json(node, spec, &spec_path).await?;
    let output = node
        .node(&args(&[
            network_binary(runtime_binary)
                .to_str()
                .context("invalid node binary path")?,
            "install",
            "--spec",
            &spec_path,
        ]))
        .await?;
    let proof: Value =
        serde_json::from_slice(&output.stdout).context("decoding host fence proof")?;
    put_json(node, &proof, &format!("{directory}/fence-proof.json")).await?;
    node.node(&args(&["ip", "link", "set", &spec.host_veth, "up"]))
        .await?;
    Ok(())
}

/// Launch the broker without root identity or networking capabilities.
pub async fn start_broker(
    node: &Node,
    runtime_binary: &Path,
    id: &str,
    policy: &VmPolicy,
    spec: &FenceSpec,
) -> Result<()> {
    let directory = job_directory(id);
    let policy_path = format!("{directory}/network.json");
    put_json(node, &policy.network, &policy_path).await?;
    let unit = broker_unit(id);
    let binary = network_binary(runtime_binary);
    node.node(&args(&[
        "systemd-run",
        "--quiet",
        "--collect",
        &format!("--unit={unit}"),
        "--property=DynamicUser=yes",
        "--setenv=RUST_LOG=info",
        &format!("--property=RuntimeDirectory={unit}"),
        "--property=RuntimeDirectoryMode=0700",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        binary.to_str().context("invalid broker path")?,
        "broker",
        "--bind",
        &format!("{}:{}", spec.gateway_ip, spec.broker_port),
        "--policy",
        &policy_path,
        "--control",
        &control_path(id),
    ]))
    .await?;
    Ok(())
}

/// Recheck the outside packet fence before releasing any guest execution.
pub async fn check_fence(node: &Node, runtime_binary: &Path, id: &str) -> Result<()> {
    node.node(&args(&[
        network_binary(runtime_binary)
            .to_str()
            .context("invalid fence binary")?,
        "verify",
        "--proof",
        &format!("{}/fence-proof.json", job_directory(id)),
    ]))
    .await?;
    Ok(())
}

/// Verify both the packet fence and the currently enforced broker generation.
pub async fn verify(
    node: &Node,
    runtime_binary: &Path,
    id: &str,
    policy: &VmPolicy,
    nonce: &str,
) -> Result<String> {
    let binary = network_binary(runtime_binary);
    let binary = binary.to_str().context("invalid network binary path")?;
    node.node(&args(&[
        binary,
        "verify",
        "--proof",
        &format!("{}/fence-proof.json", job_directory(id)),
    ]))
    .await?;
    let output = node
        .node(&args(&[
            binary,
            "inspect",
            "--control",
            &control_path(id),
            "--nonce",
            nonce,
        ]))
        .await?;
    let actual: Value = serde_json::from_slice(&output.stdout)?;
    if actual["nonce"] != nonce || actual["policy"] != serde_json::to_value(&policy.network)? {
        bail!("broker policy observation does not match requested generation");
    }
    let pid = node
        .node(&args(&[
            "systemctl",
            "show",
            "--value",
            "--property=MainPID",
            &broker_unit(id),
        ]))
        .await?;
    let pid = String::from_utf8(pid.stdout)?.trim().parse::<u32>()?;
    if pid == 0 {
        bail!("broker is not running");
    }
    let status = node
        .node(&args(&["cat", &format!("/proc/{pid}/status")]))
        .await?;
    let status = String::from_utf8(status.stdout)?;
    if status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .is_none_or(|line| line.split_whitespace().nth(1) == Some("0"))
        || !status
            .lines()
            .any(|line| line == "CapEff:\t0000000000000000")
    {
        bail!("broker has privileged process credentials");
    }
    Ok(format!("{}:{}", actual["generation"], policy.digest()?))
}

pub async fn update(
    node: &Node,
    runtime_binary: &Path,
    id: &str,
    policy: &VmPolicy,
    nonce: &str,
) -> Result<()> {
    let path = format!("{}/network.json", job_directory(id));
    put_json(node, &policy.network, &path).await?;
    node.node(&args(&[
        network_binary(runtime_binary)
            .to_str()
            .context("invalid broker binary")?,
        "update",
        "--control",
        &control_path(id),
        "--policy",
        &path,
        "--nonce",
        nonce,
    ]))
    .await?;
    Ok(())
}

/// Remove only recorded, generation-owned resources after execution has stopped.
pub async fn remove(
    node: &Node,
    runtime_binary: &Path,
    id: &str,
    attachment: &Attachment,
) -> Result<()> {
    let owner_path = format!("{}/netns-owner.json", job_directory(id));
    let namespace_exists = exists(node, &attachment.namespace_path()).await?;
    if !exists(node, &owner_path).await? {
        if namespace_exists
            || exists(node, &format!("/sys/class/net/{}", attachment.host_veth)).await?
        {
            bail!("network resource exists without this generation's ownership proof");
        }
        return Ok(());
    }
    let owner_output = node.node(&args(&["cat", &owner_path])).await?;
    let owner: Value = serde_json::from_slice(&owner_output.stdout)?;
    if owner["nonce"] != attachment.owner {
        bail!("network namespace ownership nonce changed");
    }
    if namespace_exists
        && owner["inode"]
            != String::from_utf8(
                node.node(&args(&["stat", "-Lc", "%i", &attachment.namespace_path()]))
                    .await?
                    .stdout,
            )?
            .trim()
    {
        bail!("network namespace identity changed");
    }
    stop_unit(node, &broker_unit(id)).await?;
    if exists(node, &format!("/sys/class/net/{}", attachment.host_veth)).await? {
        let link = node
            .node(&args(&[
                "ip",
                "-j",
                "link",
                "show",
                "dev",
                &attachment.host_veth,
            ]))
            .await?;
        let data: Value = serde_json::from_slice(&link.stdout)?;
        if data[0]["ifalias"] != format!("openshell-kata:{id}:{}", attachment.owner) {
            bail!("network interface ownership changed");
        }
        node.node(&args(&["ip", "link", "set", &attachment.host_veth, "down"]))
            .await?;
        let proof_path = format!("{}/fence-proof.json", job_directory(id));
        if exists(node, &proof_path).await? {
            node.node(&args(&[
                network_binary(runtime_binary)
                    .to_str()
                    .context("invalid network binary")?,
                "remove",
                "--proof",
                &proof_path,
            ]))
            .await?;
            node.node(&args(&["rm", "--", &proof_path])).await?;
        }
        node.node(&args(&["ip", "link", "delete", &attachment.host_veth]))
            .await?;
    }
    if namespace_exists {
        node.node(&args(&["ip", "netns", "delete", &attachment.netns]))
            .await?;
    }
    node.node(&args(&["rm", "--", &owner_path])).await?;
    Ok(())
}

pub async fn stop_unit(node: &Node, name: &str) -> Result<()> {
    let stopped = node.raw_node(&args(&["systemctl", "stop", name])).await?;
    if !stopped.status.success() {
        let load = node
            .node(&args(&[
                "systemctl",
                "show",
                "--value",
                "--property=LoadState",
                name,
            ]))
            .await?;
        if String::from_utf8(load.stdout)?.trim() != "not-found" {
            bail!("could not stop owned service");
        }
    }
    let active = node
        .node(&args(&[
            "systemctl",
            "show",
            "--value",
            "--property=ActiveState",
            name,
        ]))
        .await?;
    if !["inactive", "failed"].contains(&String::from_utf8(active.stdout)?.trim()) {
        bail!("owned service remains active");
    }
    let pid = node
        .node(&args(&[
            "systemctl",
            "show",
            "--value",
            "--property=MainPID",
            name,
        ]))
        .await?;
    if String::from_utf8(pid.stdout)?.trim() != "0" {
        bail!("owned service process remains");
    }
    Ok(())
}

/// Confirm both volatile attachment objects are absent; partial loss fails closed.
pub async fn attachment_absent(node: &Node, attachment: &Attachment) -> Result<bool> {
    let namespace = exists(node, &attachment.namespace_path()).await?;
    let link = exists(node, &format!("/sys/class/net/{}", attachment.host_veth)).await?;
    if namespace != link {
        bail!("runtime network attachment is partially missing");
    }
    Ok(!namespace)
}

async fn exists(node: &Node, path: &str) -> Result<bool> {
    let result = node.raw_node(&args(&["test", "-e", path])).await?;
    match result.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("could not verify node resource existence"),
    }
}
