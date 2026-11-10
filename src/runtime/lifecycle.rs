//! Native lifecycle transactions, bound to host observations and one creation nonce.
mod boot;
use super::observation::{host_process, storage_device, verify_storage};
use super::{
    command::{Node, NodeTransport},
    model::{self, Action, Record, Route},
    network::{self},
    state::{StateDirectory, validate_id},
    transport,
};
use crate::{
    boundary::process::{OperatorCeilings, VmDeadline},
    profile::{EnforcementEvidence, VmPolicy},
};
use anyhow::{Context, Result, bail};
use boot::{node_boot_id, recover_boot_network};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    net::TcpListener,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn args(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn unit(id: &str) -> String {
    format!(
        "okata-w-{}",
        &format!("{:x}", Sha256::digest(id.as_bytes()))[..20]
    )
}

/// Explicit operator settings; workload arguments cannot select host binaries.
#[derive(Clone, Debug)]
pub struct Settings {
    pub vm: String,
    pub node_transport: NodeTransport,
    pub resource_profile: model::ResourceProfile,
    pub state_dir: PathBuf,
    pub node_binary: PathBuf,
    pub image: Option<String>,
    /// Operator node capacity in retained guests, stopped guests included.
    pub max_sandboxes: Option<u8>,
}

/// A persistent expiry job, run outside the guest and outside the adapter process.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchJob {
    pub cgroup: PathBuf,
    pub deadline: VmDeadline,
    pub ready: PathBuf,
}

/// Execute one lifecycle request, returning only public route and enforcement observations.
pub async fn execute(
    settings: &Settings,
    action: Action,
    id: &str,
    policy_path: Option<&Path>,
    nonce: Option<&str>,
) -> Result<Value> {
    validate_id(id)?;
    let state = StateDirectory::new(&settings.state_dir)?;
    // Operations on one sandbox stay ordered; distinct sandboxes proceed in parallel.
    let sandbox_lock = LifecycleLock::acquire(state.root().join(format!(".lock-{id}"))).await?;
    let result = execute_locked(settings, &state, action, id, policy_path, nonce).await;
    if !state.path(id)?.try_exists()? {
        // Retire the lock with its sandbox while still holding it; waiters re-open.
        sandbox_lock.retire()?;
    }
    result
}

/// An exclusive advisory lock file that waiters re-open if it is retired under them.
struct LifecycleLock {
    path: PathBuf,
    _file: File,
}

impl LifecycleLock {
    async fn acquire(path: PathBuf) -> Result<Self> {
        loop {
            if std::fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_file()) {
                bail!("invalid lifecycle lock");
            }
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .context("opening lifecycle lock")?;
            let file = tokio::task::spawn_blocking(move || -> Result<File> {
                file.lock()?;
                Ok(file)
            })
            .await??;
            use std::os::unix::fs::MetadataExt;
            let held = file.metadata()?;
            match std::fs::symlink_metadata(&path) {
                Ok(current) if current.ino() == held.ino() && current.dev() == held.dev() => {
                    return Ok(Self { path, _file: file });
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("checking lifecycle lock"),
            }
        }
    }

    fn retire(self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("retiring lifecycle lock"),
        }
    }
}

/// Gateway addresses and tunnel ports already held by retained guests.
fn reservations(state: &StateDirectory) -> Result<(Vec<std::net::Ipv4Addr>, Vec<u16>)> {
    let mut addresses = Vec::new();
    let mut ports = Vec::new();
    for retained in state.retained_ids()? {
        // A directory without metadata was never assigned an address or port.
        if let Ok(record) = state.read::<Record>(&retained) {
            addresses.push(record.attachment.gateway_ip);
            ports.push(record.route.port);
        }
    }
    Ok((addresses, ports))
}

/// Node resources claimed for one new guest under the node reservation lock.
struct Reserved {
    attachment: network::Attachment,
    port: u16,
    directory: PathBuf,
}

/// Claim capacity, a private address (with its link and namespace names) and a
/// tunnel port, and persist the record before releasing the node lock, so a
/// concurrent create always observes every earlier claim.
async fn reserve_create(
    node: &Node,
    state: &StateDirectory,
    id: &str,
    nonce: &str,
    check_capacity: impl FnOnce() -> Result<()>,
    record: impl FnOnce(Reserved) -> Record,
) -> Result<Record> {
    let _reservation = LifecycleLock::acquire(state.root().join(".lock")).await?;
    check_capacity()?;
    let (reserved_addresses, reserved_ports) = reservations(state)?;
    let attachment = network::plan_attachment(node, id, nonce, &reserved_addresses).await?;
    let port = unreserved_port(&reserved_ports)?;
    let directory = state.create(id)?;
    let record = record(Reserved {
        attachment,
        port,
        directory,
    });
    state.write(id, &record)?;
    Ok(record)
}

fn unreserved_port(reserved: &[u16]) -> Result<u16> {
    for _ in 0..64 {
        let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        if !reserved.contains(&port) {
            return Ok(port);
        }
    }
    bail!("no unreserved tunnel port available")
}

async fn execute_locked(
    settings: &Settings,
    state: &StateDirectory,
    action: Action,
    id: &str,
    policy_path: Option<&Path>,
    nonce: Option<&str>,
) -> Result<Value> {
    let node = Node::with_transport(&settings.vm, settings.node_transport)?;
    let exists = state.path(id)?.try_exists()?;
    if action == Action::Abort {
        if !exists {
            return Ok(json!({}));
        }
        let record: Record = state.read(id)?;
        if Some(record.creation_nonce.as_str()) != nonce {
            return Ok(json!({}));
        }
        return destroy(&node, state, settings, id, &record).await;
    }
    if action == Action::Create {
        let nonce = nonce.context("create requires proof nonce")?;
        model::validate_nonce(nonce)?;
        let policy = VmPolicy::load(policy_path.context("create requires a policy file")?)?;
        settings.resource_profile.validate(&policy)?;
        if exists {
            bail!("sandbox state already exists");
        }
        let capacity = match (settings.resource_profile, settings.max_sandboxes) {
            (model::ResourceProfile::Build, None) => {
                bail!("build profile requires an explicit operator node capacity")
            }
            (model::ResourceProfile::FoundryBuild, None) => {
                bail!("Foundry requires an explicit operator node capacity")
            }
            (_, capacity) => capacity,
        };
        let check_capacity = || -> Result<()> {
            if let Some(capacity) = capacity
                && state.retained_count()? >= usize::from(capacity)
            {
                bail!("node already retains its capacity of {capacity} guest disks");
            }
            Ok(())
        };
        // Refuse early without node access; re-checked under the reservation lock.
        check_capacity()?;
        if settings.resource_profile == model::ResourceProfile::FoundryBuild
            && settings.image.is_none()
        {
            bail!("Foundry requires an explicit immutable operator image");
        }
        // Validate the host transport before contacting or allocating the node.
        state.control_path(id)?;
        let raw = node
            .raw_nerdctl(&args(&["inspect", "--mode=native", id]))
            .await?;
        if !model::confirmed_absent(
            raw.status.code().unwrap_or(-1),
            &raw.stdout,
            &raw.stderr,
            id,
        ) {
            bail!("container absence could not be confirmed before creation");
        }
        let node_boot = node_boot_id(&node).await?;
        let deadline = policy
            .resources
            .validate(&OperatorCeilings::default())?
            .deadline_from(now()?)?;
        let image = model::selected_image(settings.image.as_deref())?;
        let mut record =
            reserve_create(&node, state, id, nonce, check_capacity, |reserved| Record {
                creation_nonce: nonce.to_owned(),
                node_boot_id: Some(node_boot),
                image,
                route: Route {
                    sandbox_id: id.to_owned(),
                    host: "127.0.0.1".into(),
                    port: reserved.port,
                    username: "sandbox".into(),
                    private_key_path: reserved.directory.join("client_key"),
                    known_hosts_path: reserved.directory.join("known_hosts"),
                },
                policy,
                deadline,
                network: None,
                attachment: reserved.attachment,
                storage_id: String::new(),
                hypervisor_pid: 0,
                watchdog_pid: 0,
                cgroup_path: String::new(),
            })
            .await?;
        let result = create(&node, state, settings, id, &record).await;
        match result {
            Ok(created) => {
                record = created;
                state.write(id, &record)?;
                return observe(&node, state, settings, id, &record, nonce).await;
            }
            Err(error) => {
                return Err(error.context("creation left nonce-bound state for safe abort"));
            }
        }
    }
    if !exists {
        if action == Action::Delete {
            let raw = node
                .raw_nerdctl(&args(&["inspect", "--mode=native", id]))
                .await?;
            if model::confirmed_absent(
                raw.status.code().unwrap_or(-1),
                &raw.stdout,
                &raw.stderr,
                id,
            ) {
                return Ok(json!({}));
            }
        }
        bail!("sandbox state is absent and runtime absence is unconfirmed");
    }
    let record: Record = state.read(id)?;
    if record.route.sandbox_id != id {
        bail!("sandbox state identity mismatch");
    }
    if action == Action::Delete {
        return destroy(&node, state, settings, id, &record).await;
    }
    if action == Action::Stop {
        return stop(&node, state, settings, id, &record).await;
    }
    if model::selected_image(settings.image.as_deref())? != record.image {
        bail!("operator image differs from retained sandbox intent");
    }
    let nonce = nonce.context("verification requires a proof nonce")?;
    model::validate_nonce(nonce)?;
    let policy = VmPolicy::load(policy_path.context("verification requires a policy file")?)?;
    settings.resource_profile.validate(&policy)?;
    if record.deadline.expired_at(now()?) {
        let _ = stop(&node, state, settings, id, &record).await;
        bail!("sandbox lease expired");
    }
    let record = match action {
        Action::Start => {
            if policy.resources != record.policy.resources
                || policy.filesystem != record.policy.filesystem
                || !policy.network.is_deny_all()
            {
                bail!(
                    "restart requires the same resource/filesystem policy with deny-all networking"
                );
            }
            state.control_path(id)?;
            let record = Record { policy, ..record };
            state.write(id, &record)?;
            start(&node, state, settings, id, &record).await?
        }
        Action::Update => {
            if policy.resources != record.policy.resources {
                bail!("live resource changes are unsupported");
            }
            network::update(&node, &settings.node_binary, id, &policy, nonce).await?;
            let updated = Record { policy, ..record };
            state.write(id, &updated)?;
            updated
        }
        Action::Verify => {
            if policy.digest()? != record.policy.digest()? {
                bail!("policy digest changed without applying an update");
            }
            record
        }
        _ => bail!("unsupported lifecycle transition"),
    };
    observe(&node, state, settings, id, &record, nonce).await
}

async fn create(
    node: &Node,
    state: &StateDirectory,
    settings: &Settings,
    id: &str,
    record: &Record,
) -> Result<Record> {
    transport::generate_keys(node, state, id).await?;
    let spec =
        network::create_attachment(node, id, &record.creation_nonce, &record.attachment).await?;
    let record = Record {
        network: Some(spec.clone()),
        ..record.clone()
    };
    state.write(id, &record)?;
    network::install(node, &settings.node_binary, id, &spec).await?;
    let proxy = format!("http://{}:{}", spec.gateway_ip, spec.broker_port);
    let config = super::spec::guest_spec_for(
        id,
        &record.attachment.namespace_path(),
        &proxy,
        &record.policy.resources,
    );
    let config_path = format!("{}/oci.json", network::job_directory(id));
    network::put_json(node, &config, &config_path).await?;
    node.node(&args(&[
        "ctr",
        "containers",
        "create",
        "--snapshotter",
        "devmapper",
        "--runtime",
        "io.containerd.kata.v2",
        "--label",
        "openshell-kata.managed=true",
        "--label",
        &format!("openshell-kata.creation-nonce={}", record.creation_nonce),
        &record.image,
        id,
    ]))
    .await?;
    node.node(&args(&[
        settings
            .node_binary
            .to_str()
            .context("invalid runtime binary")?,
        "set-spec",
        id,
        "--policy-file",
        &config_path,
        "--proof-nonce",
        &record.creation_nonce,
    ]))
    .await?;
    let directory = state.path(id)?;
    for (source, destination) in [
        (directory.join("client_key.pub"), "/etc/ssh/authorized_keys"),
        (directory.join("host_key"), "/etc/ssh/ssh_host_ed25519_key"),
    ] {
        copy_guest_file(node, id, &source, destination).await?;
    }
    install_proxy_trust(node, settings, id).await?;
    let key = std::fs::read_to_string(directory.join("host_key.pub"))?;
    let mut fields = key.split_whitespace();
    let algorithm = fields.next().context("missing host key algorithm")?;
    let value = fields.next().context("missing host key value")?;
    std::fs::write(
        &record.route.known_hosts_path,
        format!("[127.0.0.1]:{} {algorithm} {value}\n", record.route.port),
    )?;
    start(node, state, settings, id, &record).await
}

/// Generate the sandbox's proxy CA on the node and trust its public
/// certificate in the pristine operator image before any guest code runs.
async fn install_proxy_trust(node: &Node, settings: &Settings, id: &str) -> Result<()> {
    network::generate_proxy_ca(node, &settings.node_binary, id).await?;
    let native = inspect(node, id).await?;
    let device = storage_device(node, &native).await?;
    let root = format!("{}/trusted-root", network::job_directory(id));
    node.node(&args(&["mkdir", "-p", &root])).await?;
    let install = async {
        node.node(&args(&["mount", &device, &root])).await?;
        network::install_guest_trust(node, &settings.node_binary, id, &root).await
    }
    .await;
    let unmount = node.node(&args(&["umount", &root])).await;
    install?;
    unmount?;
    Ok(())
}

/// Install one provider snapshot into the sandbox's running broker. Returns
/// only workload-facing material: placeholders and the public CA.
///
/// # Errors
/// Fails for an unknown sandbox, a broker without mediation, or a mismatched
/// broker response.
pub async fn install_credentials(settings: &Settings, id: &str, snapshot: &[u8]) -> Result<Value> {
    validate_id(id)?;
    let state = StateDirectory::new(&settings.state_dir)?;
    let _lock = LifecycleLock::acquire(state.root().join(format!(".lock-{id}"))).await?;
    let record: Record = state.read(id)?;
    if record.route.sandbox_id != id {
        bail!("sandbox state identity mismatch");
    }
    record
        .network
        .as_ref()
        .context("sandbox has no installed network broker")?;
    let node = Node::with_transport(&settings.vm, settings.node_transport)?;
    let nonce = uuid::Uuid::new_v4().to_string();
    network::install_credentials(&node, &settings.node_binary, id, snapshot, &nonce).await
}

async fn copy_guest_file(node: &Node, id: &str, source: &Path, destination: &str) -> Result<()> {
    let native = inspect(node, id).await?;
    let device = storage_device(node, &native).await?;
    let root = format!("{}/trusted-root", network::job_directory(id));
    node.node(&args(&["mkdir", "-p", &root])).await?;
    let stage = node.stage(source).await?;
    let copy = async {
        node.node(&args(&["mount", &device, &root])).await?;
        let mode = if destination == "/etc/ssh/authorized_keys" {
            "0644"
        } else {
            "0600"
        };
        node.node(&args(&[
            "install",
            "-m",
            mode,
            &stage,
            &format!("{root}{destination}"),
        ]))
        .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let unmount = node.node(&args(&["umount", &root])).await;
    let _ = node.unstage(&stage).await;
    copy?;
    unmount?;
    Ok(())
}

async fn start(
    node: &Node,
    state: &StateDirectory,
    settings: &Settings,
    id: &str,
    record: &Record,
) -> Result<Record> {
    let native = inspect(node, id).await?;
    owned(&native, &record.creation_nonce)?;
    model::verify_image(&native, &record.image)?;
    let current = node.node(&args(&["ctr", "tasks", "list"])).await?;
    let running = String::from_utf8(current.stdout)?.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.first().copied() == Some(id) && fields.last().copied() == Some("RUNNING")
    });
    let restored = recover_boot_network(node, state, settings, id, record).await?;
    let record = &restored;
    let spec = record
        .network
        .as_ref()
        .context("sandbox has no installed network fence")?;
    network::check_fence(node, &settings.node_binary, id).await?;
    network::stop_unit(node, &network::broker_unit(id)).await?;
    network::start_broker(node, &settings.node_binary, id, &record.policy, spec).await?;
    let mut prepared = record.clone();
    if !running {
        // A shim that died (for example OOM-killed by its cgroup) leaves its
        // process group, socket and task bundle behind, and containerd then
        // refuses every new task for this id. Reap them exactly as stop does.
        stop_task(node, settings, id, record).await?;
        network::reset_for_restart(node, id, &record.attachment).await?;
        node.node(&args(&[
            "ip",
            "link",
            "set",
            &record.attachment.host_veth,
            "up",
        ]))
        .await?;
        prepare_cgroup(node, id, &record.policy).await?;
        prepared.cgroup_path = format!("/sys/fs/cgroup/openshell-kata/{id}");
        verify_storage(node, &native, &prepared.policy).await?;
        prepared.watchdog_pid = launch_watchdog(node, settings, id, &prepared).await?;
        state.write(id, &prepared)?;
        if prepared.deadline.expired_at(now()?) {
            bail!("sandbox lifetime expired before boot");
        }
        // Large guests initialize their page metadata before the agent can answer.
        // Bound that boot separately from short node operations; the independent
        // VM lifetime watchdog remains active throughout startup.
        let boot_timeout = match settings.resource_profile {
            model::ResourceProfile::Local => Duration::from_secs(90),
            _ => Duration::from_secs(300),
        };
        // No host process reads a detached task's stdio. Without --null-io the
        // guest's stdout/stderr pipe fills and every writer (sshd logs each
        // connection) blocks forever, so guest SSH stops answering.
        node.node_with_timeout(
            &args(&["ctr", "tasks", "start", "--null-io", "--detach", id]),
            boot_timeout,
        )
        .await?;
        // Kata uses the OCI memory limit to size guest RAM, then applies that
        // same limit to the host shim cgroup. Keep guest sizing unchanged and
        // allow the shim's bounded overhead under the enclosing host budget.
        write_control(
            node,
            &format!("/sys/fs/cgroup/openshell-kata/{id}/guest/memory.max"),
            &model::host_memory_bytes(&record.policy.resources).to_string(),
        )
        .await?;
    }
    let (pid, cgroup) = host_process(node, id, &native, &record.policy).await?;
    let record = Record {
        hypervisor_pid: pid,
        cgroup_path: cgroup,
        ..prepared
    };
    verify_storage(node, &native, &record.policy).await?;
    let record = Record {
        storage_id: native["SnapshotKey"]
            .as_str()
            .context("missing private snapshot")?
            .to_owned(),
        ..record
    };
    state.write(id, &record)?;
    let guest = record.route.guest(None);
    transport::open_tunnel(
        node,
        state,
        id,
        &record.attachment.guest_ip.to_string(),
        &guest,
    )
    .await?;
    transport::wait_ready(node, &guest).await?;
    Ok(record)
}

async fn inspect(node: &Node, id: &str) -> Result<Value> {
    let output = node.node(&args(&["ctr", "containers", "info", id])).await?;
    serde_json::from_slice(&output.stdout).context("decoding container observation")
}

async fn prepare_cgroup(node: &Node, id: &str, policy: &VmPolicy) -> Result<()> {
    let parent = "/sys/fs/cgroup/openshell-kata";
    node.node(&args(&["mkdir", "-p", parent])).await?;
    write_control(
        node,
        "/sys/fs/cgroup/cgroup.subtree_control",
        "+cpu +memory",
    )
    .await?;
    write_control(
        node,
        &format!("{parent}/cgroup.subtree_control"),
        "+cpu +memory",
    )
    .await?;
    let path = format!("{parent}/{id}");
    node.node(&args(&["mkdir", "-p", &path])).await?;
    write_control(
        node,
        &format!("{path}/cpu.max"),
        &format!("{} 100000", u64::from(policy.resources.vcpus) * 100000),
    )
    .await?;
    write_control(
        node,
        &format!("{path}/memory.max"),
        &model::host_memory_bytes(&policy.resources).to_string(),
    )
    .await?;
    write_control(node, &format!("{path}/memory.swap.max"), "0").await?;
    write_control(
        node,
        &format!("{path}/cgroup.subtree_control"),
        "+cpu +memory",
    )
    .await?;
    Ok(())
}
async fn write_control(node: &Node, path: &str, value: &str) -> Result<()> {
    node.node(&args(&[
        "sh",
        "-c",
        "printf '%s' \"$1\" > \"$2\"",
        "sh",
        value,
        path,
    ]))
    .await?;
    Ok(())
}

fn owned(native: &Value, nonce: &str) -> Result<()> {
    if native["Labels"]["openshell-kata.creation-nonce"] != nonce
        || native["Runtime"]["Name"] != "io.containerd.kata.v2"
    {
        bail!("container ownership or runtime does not match persisted creation");
    }
    Ok(())
}

async fn launch_watchdog(
    node: &Node,
    settings: &Settings,
    id: &str,
    record: &Record,
) -> Result<u32> {
    let job = WatchJob {
        cgroup: record.cgroup_path.clone().into(),
        deadline: record.deadline,
        ready: format!("{}/watch-ready", network::job_directory(id)).into(),
    };
    let path = format!("{}/watch.json", network::job_directory(id));
    let _ = node
        .raw_node(&args(&[
            "rm",
            "-f",
            job.ready.to_str().context("invalid watchdog ready path")?,
        ]))
        .await?;
    network::put_json(node, &job, &path).await?;
    network::stop_unit(node, &unit(id)).await?;
    node.node(&args(&[
        "systemd-run",
        "--quiet",
        "--collect",
        &format!("--unit={}", unit(id)),
        "--property=Restart=on-failure",
        "--property=RestartSec=1",
        "--property=StartLimitIntervalSec=0",
        settings
            .node_binary
            .to_str()
            .context("invalid runtime binary path")?,
        "watchdog",
        &path,
    ]))
    .await?;
    for _ in 0..30 {
        let output = node
            .node(&args(&[
                "systemctl",
                "show",
                "--value",
                "--property=MainPID",
                &unit(id),
            ]))
            .await?;
        if let Ok(pid) = String::from_utf8(output.stdout)?.trim().parse::<u32>()
            && pid != 0
        {
            let ready = node
                .raw_node(&args(&[
                    "cat",
                    job.ready.to_str().context("invalid watchdog ready path")?,
                ]))
                .await?;
            if ready.status.success() && String::from_utf8(ready.stdout)?.trim() == pid.to_string()
            {
                return Ok(pid);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("independent expiry watchdog failed to start")
}

async fn observe(
    node: &Node,
    _state: &StateDirectory,
    settings: &Settings,
    id: &str,
    record: &Record,
    nonce: &str,
) -> Result<Value> {
    if record.deadline.expired_at(now()?) {
        bail!("sandbox lifetime expired");
    }
    let native = inspect(node, id).await?;
    owned(&native, &record.creation_nonce)?;
    model::verify_image(&native, &record.image)?;
    if native["SnapshotKey"] != record.storage_id {
        bail!("private snapshot identity changed");
    }
    let (pid, _) = host_process(node, id, &native, &record.policy).await?;
    verify_storage(node, &native, &record.policy).await?;
    let fence = network::verify(node, &settings.node_binary, id, &record.policy, nonce).await?;
    let output = node
        .node(&args(&[
            "systemctl",
            "show",
            "--value",
            "--property=MainPID",
            &unit(id),
        ]))
        .await?;
    let watchdog = String::from_utf8(output.stdout)?.trim().parse::<u32>()?;
    if watchdog == 0 || watchdog != record.watchdog_pid {
        bail!("expiry watchdog is absent or changed");
    }
    let ready = node
        .node(&args(&[
            "cat",
            &format!("{}/watch-ready", network::job_directory(id)),
        ]))
        .await?;
    if String::from_utf8(ready.stdout)?.trim() != watchdog.to_string() {
        bail!("watchdog has not pinned its kill handle");
    }
    let evidence = EnforcementEvidence {
        sandbox_id: id.to_owned(),
        policy_sha256: record.policy.digest()?,
        nonce: nonce.to_owned(),
        runtime: "kata-runtime-rs".into(),
        hypervisor_pid: pid,
        resources: record.policy.resources,
        storage_id: record.storage_id.clone(),
        network_fence: fence,
        watchdog_pid: watchdog,
        expires_at_unix_secs: record.deadline.expires_at_unix_secs(),
    };
    evidence.validate(id, nonce, &record.policy)?;
    record.route.output(evidence)
}

async fn stop(
    node: &Node,
    state: &StateDirectory,
    settings: &Settings,
    id: &str,
    record: &Record,
) -> Result<Value> {
    network::stop_unit(node, &network::broker_unit(id)).await?;
    let guest = record.route.guest(None);
    let sync_args = transport::guest_arguments(&guest, "exec /bin/sync")?;
    match node
        .raw_command("ssh", &sync_args, Duration::from_secs(10))
        .await
    {
        Ok(output) if output.status.success() => {}
        _ => tracing::warn!(
            sandbox = id,
            "guest flush unavailable; proceeding with bounded forced stop"
        ),
    }
    if !network::attachment_absent(node, &record.attachment).await? {
        node.node(&args(&[
            "ip",
            "link",
            "set",
            &record.attachment.host_veth,
            "down",
        ]))
        .await?;
    }
    stop_task(node, settings, id, record).await?;
    // Recreate stopped attachments before accepting new allocations after reboot.
    recover_boot_network(node, state, settings, id, record).await?;
    network::stop_unit(node, &unit(id)).await?;
    transport::close_tunnel(node, state, id).await?;
    Ok(json!({}))
}
async fn destroy(
    node: &Node,
    state: &StateDirectory,
    settings: &Settings,
    id: &str,
    record: &Record,
) -> Result<Value> {
    let raw = node
        .raw_nerdctl(&args(&["inspect", "--mode=native", id]))
        .await?;
    if raw.status.success() {
        let values: Vec<Value> = serde_json::from_slice(&raw.stdout)?;
        owned(
            values.first().context("missing container")?,
            &record.creation_nonce,
        )?;
        stop_task(node, settings, id, record).await?;
        node.node(&args(&["ctr", "containers", "delete", id]))
            .await?;
    } else if !model::confirmed_absent(
        raw.status.code().unwrap_or(-1),
        &raw.stdout,
        &raw.stderr,
        id,
    ) {
        bail!("container absence could not be confirmed for deletion");
    }
    transport::close_tunnel(node, state, id).await?;
    network::stop_unit(node, &unit(id)).await?;
    network::remove(node, &settings.node_binary, id, &record.attachment).await?;
    network::remove_proxy_ca(node, id).await?;
    state.remove(id)?;
    Ok(json!({}))
}

async fn stop_task(node: &Node, settings: &Settings, id: &str, record: &Record) -> Result<()> {
    node.node(&args(&[
        settings
            .node_binary
            .to_str()
            .context("invalid node runtime path")?,
        "reap-shim",
        id,
        "--proof-nonce",
        &record.creation_nonce,
    ]))
    .await?;
    if !record.cgroup_path.is_empty() {
        let present = node
            .raw_node(&args(&["test", "-d", &record.cgroup_path]))
            .await?;
        if present.status.success() {
            if record.cgroup_path != format!("/sys/fs/cgroup/openshell-kata/{id}")
                && !record
                    .cgroup_path
                    .starts_with(&format!("/sys/fs/cgroup/openshell-kata/{id}/"))
            {
                bail!("untrusted cgroup cleanup path");
            }
            write_control(node, &format!("{}/cgroup.kill", record.cgroup_path), "1").await?;
        } else if present.status.code() != Some(1) {
            bail!("could not verify cgroup absence");
        }
    }
    let _ = node
        .raw_node(&args(&["ctr", "tasks", "kill", "--signal", "SIGKILL", id]))
        .await?;
    let _ = node
        .raw_node(&args(&["ctr", "tasks", "delete", "--force", id]))
        .await?;
    let output = node.node(&args(&["ctr", "tasks", "list"])).await?;
    if String::from_utf8(output.stdout)?
        .lines()
        .any(|line| line.split_whitespace().next() == Some(id))
    {
        bail!("task remains after stop");
    }
    Ok(())
}

#[cfg(test)]
mod lock_tests;
#[cfg(test)]
#[path = "lifecycle/reboot_tests.rs"]
mod reboot_tests;
