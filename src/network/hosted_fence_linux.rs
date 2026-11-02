//! Linux-only TCX loader; unsupported kernels never fall back to legacy TC.
use super::{
    HostedFenceIntent, HostedFenceProof,
    hosted_fence_runtime::{GuardConfig, bpf_folder, create_root_directory, now, trusted_path},
    packet::{CONFIG_LEN, PacketConfig},
};
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{Array, Map, MapData},
    programs::{
        LinkOrder, SchedClassifier, TcAttachType,
        links::{FdLink, LinkType, PinnedLink},
        tc::TcAttachOptions,
    },
};
use serde_json::Value;
use std::{path::Path, process::Command};

pub(super) fn install(
    config: &GuardConfig,
    intent: &HostedFenceIntent,
    device: u64,
    inode: u64,
) -> Result<HostedFenceProof> {
    let ifindex = interface(config, intent, Phase::BeforeBoot)?;
    let folder = bpf_folder(&intent.pod_uid)?;
    create_root_directory(&folder)?;
    ensure!(
        !folder.join("ingress").exists()
            && !folder.join("egress").exists()
            && !folder.join("config").exists(),
        "retained BPF generation already exists"
    );
    let timestamp = now()?;
    let selectors = intent.packet_config(timestamp, boottime_ns()?)?;
    let mut ebpf =
        Ebpf::load_file(&config.object_path).context("loading the pinned Rust TCX object")?;
    let mut map = Array::<_, [u8; CONFIG_LEN]>::try_from(
        ebpf.map_mut("CONFIG").context("TCX CONFIG map absent")?,
    )?;
    map.set(0, selectors.encode(), 0)?;
    let ingress = attach(
        &mut ebpf,
        "kata_ingress",
        &intent.interface,
        TcAttachType::Ingress,
    )?;
    let egress = attach(
        &mut ebpf,
        "kata_egress",
        &intent.interface,
        TcAttachType::Egress,
    )?;
    let input = ingress.info()?;
    let output = egress.info()?;
    ensure!(
        input.link_type()? == LinkType::Tcx && output.link_type()? == LinkType::Tcx,
        "TCX links required"
    );
    let proof = HostedFenceProof {
        version: 1,
        binding: intent.clone(),
        netns_device: device,
        netns_inode: inode,
        ifindex,
        ingress_link_id: input.id(),
        egress_link_id: output.id(),
        ingress_program_id: input.program_id(),
        egress_program_id: output.program_id(),
        object_sha256: config.object_sha256.clone(),
        intent_sha256: intent.sha256()?,
        installed_at_unix: timestamp,
    };
    // Both live attachments exist before pinning. Dropping either unpinned FD
    // detaches only this invocation's program if a prior step failed.
    let ingress = ingress.pin(folder.join("ingress"))?;
    let egress = match egress.pin(folder.join("egress")) {
        Ok(link) => link,
        Err(error) => {
            drop(ingress.unpin()?);
            return Err(error.into());
        }
    };
    if let Err(error) = ebpf
        .map("CONFIG")
        .context("TCX CONFIG map disappeared")?
        .pin(folder.join("config"))
    {
        drop(ingress.unpin()?);
        drop(egress.unpin()?);
        return Err(error.into());
    }
    // Pins deliberately remain after this short-lived wrapper exits.
    drop((ingress, egress));
    verify(config, &proof)
}
pub(super) fn attach(
    ebpf: &mut Ebpf,
    name: &str,
    interface: &str,
    direction: TcAttachType,
) -> Result<FdLink> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .context("TCX program absent")?
        .try_into()?;
    program
        .load()
        .context("kernel rejected the Rust TCX classifier")?;
    let link = program
        .attach_with_options(
            interface,
            direction,
            TcAttachOptions::TcxOrder(LinkOrder::first()),
        )
        .context("kernel TCX attachment failed; no legacy fallback permitted")?;
    Ok(program.take_link(link)?.try_into()?)
}
pub(super) fn verify(config: &GuardConfig, proof: &HostedFenceProof) -> Result<HostedFenceProof> {
    let timestamp = now()?;
    proof.validate(timestamp)?;
    ensure!(
        proof.object_sha256 == config.object_sha256,
        "fence object differs from the qualified node object"
    );
    ensure!(
        interface(config, &proof.binding, Phase::AfterBoot)? == proof.ifindex,
        "fenced interface generation changed"
    );
    let actual = std::fs::metadata("/proc/self/ns/net")?;
    use std::os::unix::fs::MetadataExt;
    ensure!(
        actual.dev() == proof.netns_device && actual.ino() == proof.netns_inode,
        "fenced network namespace generation changed"
    );
    let folder = bpf_folder(&proof.binding.pod_uid)?;
    trusted_path(&folder)?;
    verify_link(
        &folder.join("ingress"),
        &proof.binding.interface,
        TcAttachType::Ingress,
        proof.ingress_link_id,
        proof.ingress_program_id,
    )?;
    verify_link(
        &folder.join("egress"),
        &proof.binding.interface,
        TcAttachType::Egress,
        proof.egress_link_id,
        proof.egress_program_id,
    )?;
    let map = Map::Array(MapData::from_pin(folder.join("config"))?);
    let array = Array::<_, [u8; CONFIG_LEN]>::try_from(&map)?;
    let selectors = PacketConfig::decode(&array.get(&0, 0)?);
    let clock = boottime_ns()?;
    let expected = PacketConfig {
        expires_at_boottime_ns: selectors.expires_at_boottime_ns,
        ..proof.binding.packet_config(timestamp, clock)?
    };
    ensure!(
        selectors == expected
            && clock < selectors.expires_at_boottime_ns
            && selectors.expires_at_boottime_ns
                <= clock + (proof.binding.expires_at_unix - timestamp + 1) * 1_000_000_000,
        "retained TCX selectors or immutable deadline differ"
    );
    Ok(proof.clone())
}
fn verify_link(
    path: &Path,
    interface: &str,
    direction: TcAttachType,
    link_id: u32,
    program_id: u32,
) -> Result<()> {
    trusted_path(path)?;
    let link: FdLink = PinnedLink::from_pin(path)?.into();
    let info = link.info()?;
    ensure!(
        info.link_type()? == LinkType::Tcx
            && info.id() == link_id
            && info.program_id() == program_id,
        "pinned TCX link generation differs"
    );
    let (_, programs) = SchedClassifier::query_tcx(interface, direction)?;
    ensure!(
        programs
            .first()
            .is_some_and(|program| program.id() == program_id),
        "the fence is not the first TCX program on the interface"
    );
    Ok(())
}
#[derive(Clone, Copy)]
enum Phase {
    BeforeBoot,
    AfterBoot,
}
fn interface(config: &GuardConfig, intent: &HostedFenceIntent, phase: Phase) -> Result<u32> {
    let value = ip(
        config,
        &["-json", "address", "show", "dev", &intent.interface],
    )?;
    let entries = value.as_array().context("invalid interface inventory")?;
    ensure!(entries.len() == 1, "fenced interface absent or ambiguous");
    let link = &entries[0];
    ensure!(
        link["ifname"] == intent.interface
            && link["address"]
                .as_str()
                .is_some_and(|mac| mac.eq_ignore_ascii_case(&intent.guest_mac)),
        "outer interface MAC differs from launch intent"
    );
    let index = link["ifindex"]
        .as_u64()
        .context("interface index absent")?
        .try_into()?;
    if matches!(phase, Phase::BeforeBoot) {
        ensure!(
            link["addr_info"]
                .as_array()
                .is_some_and(|addresses| addresses
                    .iter()
                    .any(|address| address["family"] == "inet"
                        && address["local"] == intent.guest_ip.to_string())),
            "preboot CNI guest address differs"
        );
        let routes = ip(config, &["-json", "route", "show", "default"])?;
        ensure!(
            routes.as_array().is_some_and(|routes| routes.len() == 1
                && routes[0]["dev"] == intent.interface
                && routes[0]["gateway"] == intent.gateway_ip.to_string()),
            "preboot CNI gateway differs"
        );
        let neighbors = ip(
            config,
            &[
                "-json",
                "neigh",
                "show",
                "to",
                &intent.gateway_ip.to_string(),
                "dev",
                &intent.interface,
            ],
        )?;
        ensure!(
            neighbors
                .as_array()
                .is_some_and(|neighbors| neighbors.len() == 1
                    && neighbors[0]["lladdr"]
                        .as_str()
                        .is_some_and(|mac| mac.eq_ignore_ascii_case(&intent.gateway_mac))),
            "preboot CNI gateway MAC not established"
        );
    }
    Ok(index)
}
fn ip(config: &GuardConfig, args: &[&str]) -> Result<Value> {
    let result = Command::new(&config.ip_path)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(args)
        .output()?;
    ensure!(
        result.status.success() && result.stdout.len() <= 131072,
        "bounded host interface inspection failed"
    );
    Ok(serde_json::from_slice(&result.stdout)?)
}
fn boottime_ns() -> Result<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime")?;
    let value = uptime
        .split_ascii_whitespace()
        .next()
        .context("uptime absent")?;
    let (seconds, fraction) = value.split_once('.').context("invalid uptime")?;
    ensure!(
        !fraction.is_empty() && fraction.len() <= 9 && fraction.bytes().all(|b| b.is_ascii_digit()),
        "invalid boottime fraction"
    );
    let precision = fraction.len() as u32;
    let seconds: u64 = seconds.parse()?;
    let fraction: u64 = fraction.parse()?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(fraction * 10u64.pow(9 - precision)))
        .context("boottime clock overflow")
}
