//! Interlock provider runtime startup with boot-bound node qualification.
use super::hosted_fence_runtime::{GuardConfig, read_trusted, trusted_path};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs::{File, OpenOptions, TryLockError},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

const LOCK: &str = "/run/openshell-kata/provider-bootstrap.lock";
const READY: &str = "/run/openshell-kata/provider-bootstrap-ready.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    node_uid: String,
    boot_id: String,
    guard_config_sha256: String,
}
impl Receipt {
    fn validate(&self, node_uid: &str, boot_id: &str, config_sha256: &str) -> Result<()> {
        ensure!(
            self.version == 1
                && self.node_uid == node_uid
                && self.boot_id == boot_id
                && self.guard_config_sha256 == config_sha256,
            "provider node has no matching boot-bound qualification"
        );
        Ok(())
    }
}

fn wait_shared(lock: &File, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match lock.try_lock_shared() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {
                ensure!(
                    Instant::now() < deadline,
                    "provider node bootstrap did not finish before the startup deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(TryLockError::Error(error)) => {
                return Err(error).context("locking provider bootstrap");
            }
        }
    }
}

pub(super) fn enter(config: &GuardConfig) -> Result<Option<(File, GuardConfig)>> {
    if !config.provider_bootstrap {
        return Ok(None);
    }
    let path = Path::new(LOCK);
    trusted_path(path)?;
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    ensure!(
        lock.metadata()?.is_file(),
        "provider bootstrap lock is not a regular file"
    );
    wait_shared(&lock, Duration::from_secs(60))?;
    let descriptor = lock.metadata()?;
    trusted_path(path)?;
    let current = std::fs::symlink_metadata(path)?;
    ensure!(
        descriptor.dev() == current.dev() && descriptor.ino() == current.ino(),
        "provider bootstrap lock was replaced"
    );
    let current = GuardConfig::load()?;
    ensure!(
        current.provider_bootstrap,
        "provider bootstrap mode changed during startup"
    );
    let receipt: Receipt = read_trusted(Path::new(READY))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    receipt.validate(&current.node_uid, boot.trim(), &current.source_sha256)?;
    Ok(Some((lock, current)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_receipt_binds_node_boot_and_exact_guard_configuration() -> Result<()> {
        let receipt = Receipt {
            version: 1,
            node_uid: "node".into(),
            boot_id: "boot".into(),
            guard_config_sha256: "hash".into(),
        };
        receipt.validate("node", "boot", "hash")?;
        assert!(receipt.validate("other-node", "boot", "hash").is_err());
        assert!(receipt.validate("node", "previous-boot", "hash").is_err());
        assert!(receipt.validate("node", "boot", "previous-config").is_err());
        assert!(serde_json::from_str::<Receipt>(r#"{"version":1,"node_uid":"node","boot_id":"boot","guard_config_sha256":"hash","ready":true}"#).is_err());
        Ok(())
    }
    #[test]
    fn shared_startup_waits_for_bootstrap_and_blocks_reinstallation_until_released() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("bootstrap.lock");
        let exclusive = File::create(&path)?;
        exclusive.lock()?;
        let shared = File::open(&path)?;
        assert!(wait_shared(&shared, Duration::from_millis(20)).is_err());
        exclusive.unlock()?;
        wait_shared(&shared, Duration::from_millis(20))?;
        assert!(matches!(
            exclusive.try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        drop(shared);
        exclusive.try_lock()?;
        Ok(())
    }
}
