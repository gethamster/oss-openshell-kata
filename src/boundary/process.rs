//! Resource policy validation. The trusted runtime must apply these values to
//! the hypervisor and independently terminate the VM when its deadline expires.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

const MIB: u64 = 1024 * 1024;

/// VM-wide requested resources, never per-process limits inside a rootful guest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmLimits {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub lifetime_secs: u64,
}

/// Trusted operator maximums. Tenants cannot raise these through their policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorCeilings {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub lifetime_secs: u64,
}

impl Default for OperatorCeilings {
    fn default() -> Self {
        Self {
            vcpus: 64,
            memory_mib: 196_608,
            disk_mib: 1_048_576,
            lifetime_secs: 86_400,
        }
    }
}

/// Limits checked for zero, operator ceilings and byte conversion overflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedVmLimits(VmLimits);

impl VmLimits {
    /// Validate before allocating or starting any runtime resources.
    pub fn validate(self, ceiling: &OperatorCeilings) -> Result<ValidatedVmLimits> {
        for (name, requested, maximum) in [
            ("vcpus", u64::from(self.vcpus), u64::from(ceiling.vcpus)),
            ("memory_mib", self.memory_mib, ceiling.memory_mib),
            ("disk_mib", self.disk_mib, ceiling.disk_mib),
            ("lifetime_secs", self.lifetime_secs, ceiling.lifetime_secs),
        ] {
            if requested == 0 || requested > maximum {
                bail!("{name} must be positive and within the operator ceiling");
            }
        }
        if self.memory_mib.checked_mul(MIB).is_none() || self.disk_mib.checked_mul(MIB).is_none() {
            bail!("VM resource byte count overflows");
        }
        Ok(ValidatedVmLimits(self))
    }
}

impl ValidatedVmLimits {
    pub fn as_limits(&self) -> &VmLimits {
        &self.0
    }
    pub fn memory_bytes(&self) -> u64 {
        self.0.memory_mib * MIB
    }
    pub fn disk_bytes(&self) -> u64 {
        self.0.disk_mib * MIB
    }

    /// Persist this deadline in trusted runtime state and give it to a watchdog
    /// whose lifetime is independent of the adapter and guest processes.
    pub fn deadline_from(&self, started_at_unix_secs: u64) -> Result<VmDeadline> {
        let expires_at_unix_secs = started_at_unix_secs
            .checked_add(self.0.lifetime_secs)
            .ok_or_else(|| anyhow::anyhow!("VM expiration timestamp overflows"))?;
        Ok(VmDeadline {
            started_at_unix_secs,
            expires_at_unix_secs,
        })
    }
}

/// Durable wall-clock bound. A watchdog should additionally use a monotonic
/// timer during one run, so backwards wall-clock changes never extend a lease.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmDeadline {
    started_at_unix_secs: u64,
    expires_at_unix_secs: u64,
}

impl VmDeadline {
    pub fn expires_at_unix_secs(&self) -> u64 {
        self.expires_at_unix_secs
    }
    /// Invalid persisted intervals and clock rollback fail closed.
    pub fn expired_at(&self, now_unix_secs: u64) -> bool {
        self.expires_at_unix_secs <= self.started_at_unix_secs
            || now_unix_secs < self.started_at_unix_secs
            || now_unix_secs >= self.expires_at_unix_secs
    }
}
