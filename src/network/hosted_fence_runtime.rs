use super::{HostedFenceIntent, HostedFenceProof, HostedFenceResponse, digest_valid};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CONFIG_PATH: &str = "/etc/openshell-kata/runtime-guard.json";
const INTENT_ROOT: &str = "/run/openshell-kata/intents";
const PROOF_ROOT: &str = "/run/openshell-kata/fences";
#[cfg(target_os = "linux")]
const BPF_ROOT: &str = "/sys/fs/bpf/openshell-kata";
const LIMIT: u64 = 131072;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuardConfig {
    version: u32,
    pub(super) node_uid: String,
    pub(super) shim_path: PathBuf,
    shim_sha256: String,
    pub(super) object_path: PathBuf,
    pub(super) object_sha256: String,
    pub(super) nsenter_path: PathBuf,
    pub(super) ip_path: PathBuf,
    /// Exact wrapper path mounted identically in the host and trusted guard Pod.
    pub(super) guard_path: PathBuf,
}
impl GuardConfig {
    fn load() -> Result<Self> {
        let config: Self = read_trusted(Path::new(CONFIG_PATH))?;
        ensure!(
            config.version == 1,
            "unsupported runtime guard configuration"
        );
        uuid::Uuid::parse_str(&config.node_uid)?;
        digest_valid(&config.shim_sha256)?;
        digest_valid(&config.object_sha256)?;
        for path in [
            &config.shim_path,
            &config.object_path,
            &config.nsenter_path,
            &config.ip_path,
            &config.guard_path,
        ] {
            trusted_path(path)?;
        }
        ensure!(
            file_sha256(&config.shim_path)? == config.shim_sha256,
            "official Kata shim digest differs"
        );
        ensure!(
            file_sha256(&config.object_path)? == config.object_sha256,
            "TCX object digest differs"
        );
        Ok(config)
    }
}
#[derive(Debug, Deserialize)]
struct OciSpec {
    annotations: BTreeMap<String, String>,
    linux: OciLinux,
}
#[derive(Debug, Deserialize)]
struct OciLinux {
    namespaces: Vec<OciNamespace>,
}
#[derive(Debug, Deserialize)]
struct OciNamespace {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    path: PathBuf,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedFence {
    pub(super) proof: HostedFenceProof,
    pub(super) netns_path: PathBuf,
}

/// Run explicit node verification or wrap the exact upstream shim invocation.
pub fn run_runtime_guard() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "the Kata runtime guard requires Linux TCX"
    );
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|value| value == "serve") {
        ensure!(
            (arguments.len() == 3 || (arguments.len() == 5 && arguments[3] == "--bind"))
                && arguments[1] == "--config",
            "serve requires --config ABSOLUTE_PATH [--bind PRIVATE_IPV4:9443]"
        );
        let bind = if arguments.len() == 5 {
            Some(arguments[4].parse()?)
        } else {
            None
        };
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(crate::guard_rpc::serve(Path::new(&arguments[2]), bind));
    }
    let config = GuardConfig::load()?;
    match arguments.first().map(String::as_str) {
        Some("probe") => {
            ensure!(arguments.len() == 1, "probe accepts no arguments");
            #[cfg(target_os = "linux")]
            return super::hosted_fence_probe::probe(&config);
            #[cfg(not(target_os = "linux"))]
            bail!("the TCX probe requires Linux");
        }
        Some("verify") => verify_command(&config, &arguments[1..]),
        Some("internal-install") => internal(&config, &arguments[1..], Mode::Install),
        Some("internal-verify") => internal(&config, &arguments[1..], Mode::Verify),
        _ => wrap_shim(&config, &arguments),
    }
}
fn verify_command(config: &GuardConfig, args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 4 && args[0] == "--pod-uid" && args[2] == "--nonce",
        "verify requires --pod-uid UUID --nonce UUID"
    );
    canonical_uuid(&args[1])?;
    canonical_uuid(&args[3])?;
    let response = verify_with_config(config, &args[1], &args[3])?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}
pub(crate) fn proof_server_node_uid() -> Result<String> {
    ensure!(
        cfg!(target_os = "linux"),
        "the host proof server requires Linux TCX"
    );
    Ok(GuardConfig::load()?.node_uid)
}
pub(crate) fn verify_hosted_fence(pod_uid: &str, nonce: &str) -> Result<HostedFenceResponse> {
    canonical_uuid(pod_uid)?;
    canonical_uuid(nonce)?;
    let config = GuardConfig::load()?;
    verify_with_config(&config, pod_uid, nonce)
}
fn verify_with_config(
    config: &GuardConfig,
    pod_uid: &str,
    nonce: &str,
) -> Result<HostedFenceResponse> {
    canonical_uuid(pod_uid)?;
    canonical_uuid(nonce)?;
    let retained = read_retained(pod_uid)?;
    let proof = in_network_namespace(config, &retained.netns_path, pod_uid, Mode::Verify)?;
    Ok(HostedFenceResponse {
        nonce: nonce.into(),
        proof,
    })
}
#[derive(Clone, Copy)]
enum Mode {
    Install,
    Verify,
}
fn internal(config: &GuardConfig, args: &[String], mode: Mode) -> Result<()> {
    ensure!(args.len() == 5, "invalid internal fence operation");
    canonical_uuid(&args[0])?;
    if matches!(mode, Mode::Install) {
        super::reserve_hosted_fence_generation(&args[0])?;
    }
    let netns_path: PathBuf = args[1].clone().into();
    let expected_device: u64 = args[2].parse()?;
    let expected_inode: u64 = args[3].parse()?;
    ensure!(
        args[4] == "pinned",
        "unpinned namespace operation prohibited"
    );
    let actual = std::fs::metadata("/proc/self/ns/net")?;
    ensure!(
        actual.dev() == expected_device && actual.ino() == expected_inode,
        "entered namespace differs from pinned identity"
    );
    let intent: HostedFenceIntent = read_trusted(&intent_path(&args[0])?)?;
    validate_node(config, &intent)?;
    #[cfg(target_os = "linux")]
    let proof = match mode {
        Mode::Install => {
            super::hosted_fence_linux::install(config, &intent, expected_device, expected_inode)?
        }
        Mode::Verify => {
            let retained = read_retained(&args[0])?;
            ensure!(
                retained.proof.binding == intent && retained.netns_path == netns_path,
                "retained fence launch intent or namespace path differs"
            );
            super::hosted_fence_linux::verify(config, &retained.proof)?
        }
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (mode, netns_path);
        bail!("TCX requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        if matches!(mode, Mode::Install) {
            write_retained(&RetainedFence {
                proof: proof.clone(),
                netns_path,
            })?;
        }
        println!("{}", serde_json::to_string(&proof)?);
        Ok(())
    }
}
fn wrap_shim(config: &GuardConfig, args: &[String]) -> Result<()> {
    // These protocols do not create or boot a VM; preserve official shim behavior.
    let starts = args.iter().filter(|arg| arg.as_str() == "start").count();
    if starts > 0 {
        ensure!(
            starts == 1 && args.last().is_some_and(|arg| arg == "start"),
            "ambiguous shim start protocol"
        );
        let spec: OciSpec = read_trusted(&std::env::current_dir()?.join("config.json"))?;
        let uid = spec
            .annotations
            .get("io.kubernetes.cri.sandbox-uid")
            .context("CRI Pod UID required")?;
        canonical_uuid(uid)?;
        let _lock = lock_fence(uid)?;
        let intent = wait_intent(uid)?;
        validate_node(config, &intent)?;
        ensure!(
            spec.annotations.get("io.kubernetes.cri.sandbox-namespace")
                == Some(&crate::hosted::namespace(&intent.workspace)?),
            "OCI namespace differs from launch intent"
        );
        match spec
            .annotations
            .get("io.kubernetes.cri.container-type")
            .map(String::as_str)
        {
            Some("sandbox") => {
                let netns = oci_network(&spec)?;
                if proof_path(uid)?.exists() {
                    let retained = read_retained(uid)?;
                    ensure!(
                        retained.netns_path == netns,
                        "replacement network namespace rejected"
                    );
                    in_network_namespace(config, &netns, uid, Mode::Verify)?;
                } else {
                    in_network_namespace(config, &netns, uid, Mode::Install)?;
                }
            }
            Some("container") => {
                let retained = read_retained(uid)?;
                ensure!(
                    retained.proof.binding == intent,
                    "workload fence generation differs"
                );
                in_network_namespace(config, &retained.netns_path, uid, Mode::Verify)?;
            }
            _ => bail!("unsupported CRI container type"),
        }
    } else {
        ensure!(
            args.iter().any(|arg| matches!(
                arg.as_str(),
                "delete" | "-info" | "--info" | "-v" | "--version"
            )),
            "unsupported shim protocol"
        );
    }
    let error = Command::new(&config.shim_path).args(args).exec();
    Err(error).context("executing the exact official Kata shim")
}
fn oci_network(spec: &OciSpec) -> Result<PathBuf> {
    let namespaces = spec
        .linux
        .namespaces
        .iter()
        .filter(|entry| entry.kind == "network")
        .collect::<Vec<_>>();
    ensure!(
        namespaces.len() == 1,
        "exactly one explicit network namespace required"
    );
    let path = &namespaces[0].path;
    ensure!(path.is_absolute(), "host networking is prohibited");
    let path = std::fs::canonicalize(path)?;
    ensure!(
        path.parent() == Some(Path::new("/run/netns")),
        "unsupported CNI network namespace path"
    );
    Ok(path)
}
fn in_network_namespace(
    config: &GuardConfig,
    path: &Path,
    uid: &str,
    mode: Mode,
) -> Result<HostedFenceProof> {
    // The parent keeps this file open while nsenter opens /proc/PID/fd/N. CNI path
    // replacement cannot retarget the child to a different namespace.
    use std::os::fd::AsRawFd;
    trusted_path(path)?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let current = std::fs::metadata("/proc/self/ns/net")?;
    ensure!(
        metadata.dev() != current.dev() || metadata.ino() != current.ino(),
        "host network namespace is prohibited"
    );
    let target = format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd());
    let action = match mode {
        Mode::Install => "internal-install",
        Mode::Verify => "internal-verify",
    };
    let output = Command::new(&config.nsenter_path)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .arg(format!("--net={target}"))
        .arg("--")
        .arg(&config.guard_path)
        .args([action, uid])
        .arg(path)
        .arg(metadata.dev().to_string())
        .arg(metadata.ino().to_string())
        .arg("pinned")
        .output()?;
    ensure!(
        output.status.success(),
        "host fence namespace operation failed: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(2048)
            .collect::<String>()
    );
    ensure!(
        output.stdout.len() <= LIMIT as usize,
        "oversized fence proof"
    );
    let proof: HostedFenceProof = serde_json::from_slice(&output.stdout)?;
    proof.validate(now()?)?;
    ensure!(
        proof.netns_device == metadata.dev()
            && proof.netns_inode == metadata.ino()
            && proof.binding.pod_uid == uid,
        "host fence namespace response differs"
    );
    Ok(proof)
}
fn wait_intent(uid: &str) -> Result<HostedFenceIntent> {
    let path = intent_path(uid)?;
    for _ in 0..300 {
        match read_trusted(&path) {
            Ok(intent) => return Ok(intent),
            Err(error) if !path.exists() => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
    bail!("trusted launch intent did not arrive before the preboot deadline")
}
fn validate_node(config: &GuardConfig, intent: &HostedFenceIntent) -> Result<()> {
    intent.validate(now()?)?;
    ensure!(
        intent.node_uid == config.node_uid
            && std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == intent.boot_id,
        "host fence node or boot identity differs"
    );
    Ok(())
}
pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn canonical_uuid(value: &str) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(value)?;
    ensure!(
        !uuid.is_nil() && uuid.to_string() == value,
        "noncanonical Pod identity"
    );
    Ok(())
}
fn intent_path(uid: &str) -> Result<PathBuf> {
    canonical_uuid(uid)?;
    Ok(Path::new(INTENT_ROOT).join(format!("{uid}.json")))
}
fn proof_path(uid: &str) -> Result<PathBuf> {
    canonical_uuid(uid)?;
    Ok(Path::new(PROOF_ROOT).join(uid).join("state.json"))
}
#[cfg(target_os = "linux")]
pub(super) fn bpf_folder(uid: &str) -> Result<PathBuf> {
    canonical_uuid(uid)?;
    Ok(Path::new(BPF_ROOT).join(uid))
}
fn lock_fence(uid: &str) -> Result<File> {
    canonical_uuid(uid)?;
    super::reserve_hosted_fence_generation(uid)?;
    trusted_path(Path::new(PROOF_ROOT))?;
    let path = Path::new(PROOF_ROOT).join(format!("{uid}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0,
        "fence lock must be owned by root"
    );
    file.try_lock()
        .context("a fence generation operation is already active")?;
    Ok(file)
}
fn read_retained(uid: &str) -> Result<RetainedFence> {
    read_trusted(&proof_path(uid)?)
}
#[cfg(target_os = "linux")]
fn write_retained(state: &RetainedFence) -> Result<()> {
    use std::io::Write;
    let path = proof_path(&state.proof.binding.pod_uid)?;
    let parent = path.parent().context("fence proof parent required")?;
    create_root_directory(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)?;
    Ok(())
}
#[cfg(target_os = "linux")]
pub(super) fn create_root_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let parent = path.parent().context("root directory parent required")?;
    trusted_path(parent)?;
    if !path.exists() {
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    trusted_path(path)
}
pub(super) fn trusted_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir)),
        "trusted host path must be absolute and normalized"
    );
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current)?;
        ensure!(
            !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.permissions().mode() & 0o022 == 0,
            "host path must be root-owned, non-symlink and not writable by other users"
        );
    }
    Ok(())
}
fn read_trusted<T: DeserializeOwned>(path: &Path) -> Result<T> {
    trusted_path(path)?;
    read_bounded(path)
}
fn read_bounded<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= LIMIT as usize,
        "oversized host fence configuration"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn validate_probe_namespace(
    current: (u64, u64),
    host: (u64, u64),
    links: &serde_json::Value,
) -> Result<()> {
    ensure!(
        current != host,
        "TCX probe must run in a fresh non-host network namespace"
    );
    let links = links
        .as_array()
        .context("invalid probe interface inventory")?;
    ensure!(
        links.len() == 1 && links[0]["ifname"] == "lo",
        "TCX probe requires a fresh network namespace containing only loopback"
    );
    Ok(())
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn probe_rejects_host_and_existing_workload_namespaces() {
        assert!(validate_probe_namespace((1, 2), (1, 2), &json!([{"ifname":"lo"}])).is_err());
        assert!(
            validate_probe_namespace((1, 3), (1, 2), &json!([{"ifname":"lo"},{"ifname":"eth0"}]))
                .is_err()
        );
        assert!(validate_probe_namespace((1, 3), (1, 2), &json!([])).is_err());
        assert!(validate_probe_namespace((1, 3), (1, 2), &json!([{"ifname":"lo"}])).is_ok());
    }
}
