//! Credential-free durable intent for stopped sandbox recovery.

use crate::{
    config::{Config, RuntimeProfile, SandboxId},
    proto::openshell::compute::v1 as c,
};
use anyhow::{Context, Result, ensure};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};

const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 128;

/// Validated sandbox intent, separate from live supervisor authentication.
#[derive(Clone)]
pub struct Retained {
    pub sandbox: c::DriverSandbox,
    pub runtime_identity: String,
    pub generation: String,
}

impl Retained {
    pub fn new(
        mut sandbox: c::DriverSandbox,
        runtime_identity: String,
        generation: String,
    ) -> Self {
        sandbox.status = None;
        if let Some(spec) = &mut sandbox.spec {
            spec.launch_authentication.clear();
        }
        Self {
            sandbox,
            runtime_identity,
            generation,
        }
    }

    pub fn observation(&self) -> c::DriverSandbox {
        let mut sandbox = self.sandbox.clone();
        sandbox.status = Some(c::DriverSandboxStatus {
            name: sandbox.name.clone(),
            instance_id: self.runtime_identity.clone(),
            conditions: vec![
                c::DriverCondition {
                    r#type: "Ready".into(),
                    status: "False".into(),
                    reason: "FreshStartRequired".into(),
                    ..Default::default()
                },
                c::DriverCondition {
                    r#type: "Suspended".into(),
                    status: "True".into(),
                    reason: "Stopped".into(),
                    message: "Recovered intent; fresh gateway Start authentication required".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        sandbox
    }
}

/// A retained sandbox the current operator profile no longer admits, such as one
/// whose image left the allowlist in a release. It is retired, not restarted.
pub struct Retired {
    pub retained: Retained,
    pub reason: String,
}

/// Recovery inventory split by admission under the current operator profile.
///
/// Integrity failures (binding, identity, credentials, bounds) still fail the
/// whole load; only a per-record admission mismatch retires one record.
pub struct Recovered {
    pub admitted: Vec<Retained>,
    pub retired: Vec<Retired>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    sandbox: Vec<u8>,
    runtime_identity: String,
    generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operator_sha256: Option<String>,
    /// Binding format: absent for legacy records whose fingerprint also covered the
    /// VM policy and default guest image; [`BINDING`] binds node identity only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<u32>,
}

/// Current recovery binding: node identity (gateway authority and CA, lifecycle,
/// SSH, environment). Guest images and the VM policy are admission rules,
/// re-validated per retained sandbox on every recovery.
const BINDING: u32 = 2;

/// Private atomic snapshots of operator-validated intent, never bearer tokens.
#[derive(Clone)]
pub struct Store {
    root: PathBuf,
    mutation: Arc<Mutex<()>>,
    native_fingerprint: Option<String>,
    /// Native node capacity; `None` keeps the pilot per-workspace rule.
    native_capacity: Option<usize>,
}

impl Store {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            mutation: Arc::default(),
            native_fingerprint: None,
            native_capacity: None,
        }
    }

    /// Open recovery for a validated operator configuration.
    ///
    /// Native records bind to the pinned policy, gateway CA and lifecycle selection
    /// and are capped by the operator's `--max-sandboxes`. The capacity is not part
    /// of the binding, so raising it keeps retained intent. Legacy hosted records
    /// retain their existing two-per-workspace contract.
    ///
    /// # Errors
    /// Rejects missing or unsafe native configuration and unreadable public CA files.
    pub fn for_config(config: &Config) -> Result<Self> {
        let root = config
            .recovery_dir
            .clone()
            .context("recovery directory is required")?;
        if config.runtime_profile == RuntimeProfile::Local {
            config.validate()?;
            let capacity = config
                .max_sandboxes
                .context("native recovery requires --max-sandboxes")?;
            Ok(Self {
                native_fingerprint: Some(native_fingerprint(config)?),
                native_capacity: Some(usize::from(capacity)),
                ..Self::new(root)
            })
        } else {
            Ok(Self::new(root))
        }
    }

    fn directory(&self) -> Result<()> {
        ensure!(
            self.root.is_absolute(),
            "recovery directory must be absolute"
        );
        if self.root.exists() {
            ensure!(
                fs::symlink_metadata(&self.root)?.is_dir()
                    && !fs::symlink_metadata(&self.root)?.file_type().is_symlink(),
                "recovery directory must not be a symlink"
            );
        }
        fs::create_dir_all(&self.root)?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn path(&self, id: &str) -> Result<PathBuf> {
        SandboxId::parse(id)?;
        Ok(self
            .root
            .join(format!("{:x}.json", Sha256::digest(id.as_bytes()))))
    }

    fn inventory(&self) -> Result<Vec<(PathBuf, u64)>> {
        let mut entries = Vec::new();
        let mut total = 0;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            ensure!(
                entry.file_type()?.is_file(),
                "recovery snapshot must be a regular file"
            );
            let metadata = entry.metadata()?;
            ensure!(
                metadata.len() <= MAX_RECORD_BYTES && metadata.permissions().mode() & 0o077 == 0,
                "recovery snapshot size or permissions differ"
            );
            total += metadata.len();
            entries.push((entry.path(), metadata.len()));
            ensure!(
                entries.len() <= MAX_RECORDS && total <= MAX_STORE_BYTES,
                "recovery inventory exceeds bounds"
            );
        }
        Ok(entries)
    }

    pub fn save(&self, retained: &Retained) -> Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery store lock unavailable"))?;
        let target = self.path(&retained.sandbox.id)?;
        self.directory()?;
        let sanitized = Retained::new(
            retained.sandbox.clone(),
            retained.runtime_identity.clone(),
            retained.generation.clone(),
        );
        let snapshot = Snapshot {
            version: 1,
            sandbox: sanitized.sandbox.encode_to_vec(),
            runtime_identity: sanitized.runtime_identity,
            generation: sanitized.generation,
            operator_sha256: self.native_fingerprint.clone(),
            binding: self.native_fingerprint.as_ref().map(|_| BINDING),
        };
        let encoded = serde_json::to_vec(&snapshot)?;
        ensure!(
            encoded.len() as u64 <= MAX_RECORD_BYTES,
            "recovery snapshot exceeds size limit"
        );
        let inventory = self.inventory()?;
        let mut workspace_records = 0;
        let mut existing = false;
        for (path, _) in &inventory {
            let stored: Snapshot = serde_json::from_slice(&fs::read(path)?)?;
            ensure!(stored.version == 1, "unsupported recovery snapshot version");
            // A legacy native record awaits retirement by the next recovery.
            ensure!(
                stored.operator_sha256 == self.native_fingerprint
                    || (self.native_fingerprint.is_some()
                        && stored.binding.is_none()
                        && stored.operator_sha256.is_some()),
                "recovery operator binding differs"
            );
            let sandbox = c::DriverSandbox::decode(stored.sandbox.as_slice())?;
            ensure!(
                self.path(&sandbox.id)? == *path,
                "recovery snapshot identity differs from filename"
            );
            if path == &target {
                existing = true;
                ensure!(
                    sandbox.workspace == sanitized.sandbox.workspace,
                    "retained workspace differs"
                );
            }
            if sandbox.workspace == sanitized.sandbox.workspace {
                workspace_records += 1;
            }
        }
        if let Some(capacity) = self.native_capacity {
            ensure!(
                existing || inventory.len() < capacity,
                "native node already retains its capacity of {capacity} sandboxes"
            );
        } else {
            ensure!(
                existing || workspace_records < 2,
                "pilot workspace already has two retained sandboxes"
            );
        }
        let replaced = inventory
            .iter()
            .find(|(path, _)| path == &target)
            .map_or(0, |(_, size)| *size);
        let total: u64 = inventory.iter().map(|(_, size)| size).sum();
        ensure!(
            total - replaced + encoded.len() as u64 <= MAX_STORE_BYTES,
            "recovery inventory exceeds size limit"
        );
        ensure!(
            replaced != 0 || inventory.len() < MAX_RECORDS,
            "recovery inventory exceeds record limit"
        );
        let mut temporary = tempfile::NamedTempFile::new_in(&self.root)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temporary.write_all(&encoded)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(target)
            .map_err(|e| e.error)
            .context("persisting sandbox recovery intent")?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    pub fn load(&self, config: &Config) -> Result<Recovered> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery store lock unavailable"))?;
        self.directory()?;
        let (expected_binding, legacy_binding) = if config.runtime_profile == RuntimeProfile::Local
        {
            (
                Some(native_fingerprint(config)?),
                Some(legacy_native_fingerprint(config)?),
            )
        } else {
            (None, None)
        };
        ensure!(
            expected_binding == self.native_fingerprint,
            "recovery store operator configuration differs"
        );
        let inventory = self.inventory()?;
        if let Some(capacity) = self.native_capacity {
            ensure!(
                inventory.len() <= capacity,
                "native recovery inventory exceeds the node capacity of {capacity} sandboxes"
            );
        }
        let mut recovered = Recovered {
            admitted: Vec::new(),
            retired: Vec::new(),
        };
        for (path, _) in inventory {
            let snapshot: Snapshot = serde_json::from_slice(&fs::read(&path)?)
                .context("decoding sandbox recovery intent")?;
            ensure!(
                snapshot.version == 1,
                "unsupported recovery snapshot version"
            );
            // Records bound to node identity must match it. A legacy native record also
            // bound the VM policy and default image, so a mismatch cannot tell a policy
            // change from an identity change: it is retired and re-placed, never reattached.
            let legacy_mismatch = expected_binding.is_some()
                && snapshot.binding.is_none()
                && snapshot.operator_sha256.is_some()
                && snapshot.operator_sha256 != legacy_binding;
            ensure!(
                legacy_mismatch
                    || (snapshot.binding.is_none() && snapshot.operator_sha256 == legacy_binding)
                    || snapshot.operator_sha256 == expected_binding,
                "recovery operator binding differs"
            );
            let sandbox = c::DriverSandbox::decode(snapshot.sandbox.as_slice())?;
            ensure!(
                sandbox
                    .spec
                    .as_ref()
                    .is_some_and(|spec| spec.launch_authentication.is_empty()),
                "recovery snapshot contains forbidden launch authentication"
            );
            ensure!(
                self.path(&sandbox.id)? == path,
                "recovery snapshot identity differs from filename"
            );
            ensure!(
                snapshot.runtime_identity.is_empty()
                    || uuid::Uuid::parse_str(&snapshot.runtime_identity).is_ok(),
                "invalid retained runtime identity"
            );
            let admission = if legacy_mismatch {
                Err(anyhow::anyhow!(
                    "retained under an earlier operator binding"
                ))
            } else {
                config.validate_request(&sandbox)
            };
            let retained = Retained::new(sandbox, snapshot.runtime_identity, snapshot.generation);
            match admission {
                Ok(()) => recovered.admitted.push(retained),
                Err(error) => recovered.retired.push(Retired {
                    retained,
                    reason: format!("{error:#}"),
                }),
            }
        }
        Ok(recovered)
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("recovery store lock unavailable"))?;
        match fs::remove_file(self.path(id)?) {
            Ok(()) => {
                fs::File::open(&self.root)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Bind native recovery to the node's public operator identity.
fn native_fingerprint(config: &Config) -> Result<String> {
    let (identity, _) = native_binding(config)?;
    let mut binding = identity;
    binding["version"] = serde_json::json!(BINDING);
    Ok(format!(
        "{:x}",
        Sha256::digest(crate::canonical::to_vec(&binding)?)
    ))
}

/// The binding legacy records were written with: identity plus the VM policy
/// digest and default guest image.
fn legacy_native_fingerprint(config: &Config) -> Result<String> {
    let (identity, policy_sha256) = native_binding(config)?;
    let binding = serde_json::json!({"version":1,"profile":"native-enforced","policy_sha256":policy_sha256,"guest_image":config.guest_image,"gateway":identity["gateway"],"gateway_ca_sha256":identity["gateway_ca_sha256"],"lifecycle":identity["lifecycle"],"lifecycle_arg":identity["lifecycle_arg"],"ssh":identity["ssh"],"environment":identity["environment"]});
    Ok(format!(
        "{:x}",
        Sha256::digest(crate::canonical::to_vec(&binding)?)
    ))
}

/// Validated native configuration as its identity fields and VM policy digest.
fn native_binding(config: &Config) -> Result<(serde_json::Value, String)> {
    config.validate()?;
    ensure!(
        config.runtime_profile == RuntimeProfile::Local && config.recovery_dir.is_some(),
        "native recovery configuration is required"
    );
    let policy = crate::profile::VmPolicy::load(
        config
            .vm_policy
            .as_deref()
            .context("native recovery policy is required")?,
    )?;
    let mut ca = Vec::new();
    fs::File::open(&config.gateway_ca)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut ca)?;
    ensure!(
        !ca.is_empty() && ca.len() <= 1024 * 1024,
        "gateway CA bundle size differs"
    );
    let environment: std::collections::BTreeMap<_, _> = [
        "OPENSHELL_KATA_NODE_TRANSPORT",
        "OPENSHELL_KATA_RESOURCE_PROFILE",
        "OPENSHELL_KATA_STATE_DIR",
    ]
    .into_iter()
    .map(|name| {
        (
            name,
            std::env::var_os(name).map(|value| value.to_string_lossy().into_owned()),
        )
    })
    .collect();
    let identity = serde_json::json!({"profile":"native-enforced","gateway":config.gateway,"gateway_ca_sha256":format!("{:x}", Sha256::digest(&ca)),"lifecycle":config.lifecycle,"lifecycle_arg":config.lifecycle_arg,"ssh":config.ssh,"environment":environment});
    Ok((identity, policy.digest()?))
}
