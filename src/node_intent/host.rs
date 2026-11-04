//! Capability-pinned network observation and immutable private intent publication.
use super::{client, config::Config};
use crate::network::hosted_fence::HostedFenceIntent;
use anyhow::{Context, Result, ensure};
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    net::Ipv4Addr,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const INTENTS: &str = "/run/openshell-kata/intents";
const LIMIT: u64 = 131072;

pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub(super) fn trusted_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "trusted host path must be absolute");
    let mut current = PathBuf::new();
    for part in path.components() {
        ensure!(
            matches!(part, Component::RootDir | Component::Normal(_)),
            "noncanonical trusted path"
        );
        current.push(part);
        let metadata = std::fs::symlink_metadata(&current)?;
        ensure!(
            !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.permissions().mode() & 0o022 == 0,
            "trusted path ownership, permissions or symlink differs"
        );
    }
    Ok(())
}
pub(super) fn read_trusted<T: DeserializeOwned>(path: &Path) -> Result<T> {
    trusted_path(path)?;
    let mut bytes = Vec::new();
    File::open(path)?.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= LIMIT,
        "trusted file exceeds size bound"
    );
    serde_json::from_slice(&bytes).context("invalid trusted JSON file")
}
pub(super) fn file_digest(path: &Path) -> Result<String> {
    let mut reader = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 32768];
    loop {
        let size = reader.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
pub(super) fn bundles(root: &Path) -> Result<Vec<PathBuf>> {
    trusted_path(root)?;
    let mut paths = Vec::new();
    let mut count = 0;
    for entry in std::fs::read_dir(root)? {
        count += 1;
        ensure!(count <= 512, "node OCI bundle inventory exceeds bound");
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path().join("config.json");
        if path.exists() {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

pub(super) struct Network {
    _namespace: File,
    pub ip: Ipv4Addr,
    mac: String,
    gateway_ip: Ipv4Addr,
    gateway_mac: String,
}
impl Network {
    pub(super) fn bind(&self, intent: &mut HostedFenceIntent) -> Result<()> {
        ensure!(
            self.ip != intent.broker_ip,
            "guest and broker addresses overlap"
        );
        intent.guest_ip = self.ip;
        intent.guest_mac = self.mac.clone();
        intent.gateway_ip = self.gateway_ip;
        intent.gateway_mac = self.gateway_mac.clone();
        Ok(())
    }
}
pub(super) async fn network(config: &Config, path: &Path) -> Result<Network> {
    trusted_path(path)?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let current = std::fs::metadata("/proc/self/ns/net")?;
    ensure!(
        metadata.dev() != current.dev() || metadata.ino() != current.ino(),
        "host network namespace is prohibited"
    );
    let pinned = PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        file.as_raw_fd()
    ));
    let observed = observe_network(config, &pinned).await?;
    let after = std::fs::metadata(path)?;
    ensure!(
        after.dev() == metadata.dev() && after.ino() == metadata.ino(),
        "CNI namespace changed during observation"
    );
    Ok(Network {
        _namespace: file,
        ip: observed.0,
        mac: observed.1,
        gateway_ip: observed.2,
        gateway_mac: observed.3,
    })
}
async fn network_snapshot(config: &Config, namespace: &Path) -> Result<(Value, Value, Value)> {
    tokio::try_join!(
        client::ip(namespace, config, &["address", "show", "dev", "eth0"]),
        client::ip(namespace, config, &["route", "show", "default"]),
        client::ip(namespace, config, &["neigh", "show"])
    )
}

pub(super) async fn observe_network(
    config: &Config,
    namespace: &Path,
) -> Result<(Ipv4Addr, String, Ipv4Addr, String)> {
    let (addresses, routes, neighbors) = network_snapshot(config, namespace).await?;
    let initial = parse_network(&addresses, &routes, &neighbors);
    if initial.is_ok() || config.arping_path.is_none() {
        return initial;
    }
    let before = parse_interface_route(&addresses, &routes)?;
    let matching = neighbors
        .as_array()
        .context("gateway neighbor inventory missing")?
        .iter()
        .filter(|entry| entry["dst"] == before.2.to_string() && entry["dev"] == "eth0")
        .collect::<Vec<_>>();
    let missing = matching.is_empty()
        || (matching.len() == 1
            && matching[0]["lladdr"].is_null()
            && matching[0]["state"].as_array().is_some_and(|states| {
                !states.is_empty()
                    && states
                        .iter()
                        .all(|state| matches!(state.as_str(), Some("INCOMPLETE" | "FAILED")))
            }));
    if !missing {
        return initial;
    }
    client::resolve_gateway(namespace, config, before.2).await?;
    let (after_addresses, after_routes, after_neighbors) =
        network_snapshot(config, namespace).await?;
    ensure!(
        parse_interface_route(&after_addresses, &after_routes)? == before
            && after_addresses[0]["ifindex"] == addresses[0]["ifindex"],
        "CNI interface or default route changed during gateway resolution"
    );
    parse_network(&after_addresses, &after_routes, &after_neighbors)
}

pub(super) fn parse_network(
    addresses: &Value,
    routes: &Value,
    neighbors: &Value,
) -> Result<(Ipv4Addr, String, Ipv4Addr, String)> {
    let (ip, mac, gateway) = parse_interface_route(addresses, routes)?;
    let neighbors = neighbors
        .as_array()
        .context("gateway neighbor inventory missing")?
        .iter()
        .filter(|n| {
            n["dst"].as_str().is_some_and(|v| v == gateway.to_string()) && n["dev"] == "eth0"
        })
        .collect::<Vec<_>>();
    ensure!(
        neighbors.len() == 1,
        "exact prepopulated gateway neighbor required"
    );
    let neighbor = neighbors[0];
    let states = neighbor["state"]
        .as_array()
        .context("gateway neighbor state missing")?;
    ensure!(
        !states.is_empty()
            && states.iter().all(|v| matches!(
                v.as_str(),
                Some("PERMANENT" | "REACHABLE" | "STALE" | "DELAY" | "PROBE" | "NOARP")
            )),
        "unresolved gateway neighbor prohibited"
    );
    let gateway_mac = neighbor["lladdr"]
        .as_str()
        .context("gateway MAC missing")?
        .to_owned();
    Ok((ip, mac, gateway, gateway_mac))
}

fn parse_interface_route(
    addresses: &Value,
    routes: &Value,
) -> Result<(Ipv4Addr, String, Ipv4Addr)> {
    let interfaces = addresses
        .as_array()
        .context("interface inventory missing")?;
    ensure!(
        interfaces.len() == 1
            && interfaces[0]["ifname"] == "eth0"
            && interfaces[0]["ifindex"].as_u64().is_some_and(|n| n > 0),
        "exact outer eth0 interface required"
    );
    let mac = interfaces[0]["address"]
        .as_str()
        .context("guest MAC missing")?
        .to_owned();
    let addresses = interfaces[0]["addr_info"]
        .as_array()
        .context("guest address inventory missing")?
        .iter()
        .filter(|a| a["family"] == "inet")
        .collect::<Vec<_>>();
    ensure!(addresses.len() == 1, "single guest IPv4 required");
    let ip: Ipv4Addr = addresses[0]["local"]
        .as_str()
        .context("guest IPv4 missing")?
        .parse()?;
    ensure!(ip.is_private(), "guest IPv4 must be private");
    let routes = routes
        .as_array()
        .context("default route inventory missing")?;
    ensure!(
        routes.len() == 1
            && routes[0]["dev"] == "eth0"
            && routes[0]["dst"] == "default"
            && routes[0].get("multipath").is_none(),
        "single outer default route required"
    );
    let gateway: Ipv4Addr = routes[0]["gateway"]
        .as_str()
        .context("default gateway missing")?
        .parse()?;
    Ok((ip, mac, gateway))
}

pub(super) fn publish(intent: &HostedFenceIntent) -> Result<()> {
    let root = Path::new(INTENTS);
    trusted_path(root)?;
    ensure!(
        std::fs::metadata(root)?.permissions().mode() & 0o077 == 0,
        "intent directory must be private"
    );
    crate::network::hosted_fence::reserve_hosted_fence_generation(&intent.pod_uid)?;
    publish_at(root, intent)
}
pub(super) fn existing(uid: &str) -> Result<Option<HostedFenceIntent>> {
    super::config::canonical_uuid(uid)?;
    let path = Path::new(INTENTS).join(format!("{uid}.json"));
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(read_trusted(&path)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn publish_at(root: &Path, intent: &HostedFenceIntent) -> Result<()> {
    super::config::canonical_uuid(&intent.pod_uid)?;
    let path = root.join(format!("{}.json", intent.pod_uid));
    let bytes = serde_json::to_vec(intent)?;
    if path.exists() {
        let existing = std::fs::symlink_metadata(&path)?;
        ensure!(
            existing.is_file()
                && !existing.file_type().is_symlink()
                && existing.permissions().mode() & 0o077 == 0,
            "existing intent is not a private regular file"
        );
        ensure!(
            std::fs::read(&path)? == bytes,
            "immutable intent generation changed"
        );
        return Ok(());
    }
    write_once(&path, &bytes)
}
fn write_once(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("intent parent missing")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|e| e.error)
        .context("intent publication raced an existing generation")?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
