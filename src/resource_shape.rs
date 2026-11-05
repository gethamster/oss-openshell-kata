//! Operator-declared resource shapes for hosted Kubernetes Kata guests.
//!
//! Every hosted sandbox uses the qualified default shape (two vCPU, 4 GiB
//! memory, a 19 GiB private volume) unless its operator-pinned template asks
//! for exactly the CPU and memory of a shape the operator declared with
//! `--resource-shape`. Native policy and guest input cannot select a shape.

use crate::proto::openshell::compute::v1::DriverResourceRequirements;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

/// Name of the built-in hosted shape.
pub const DEFAULT_NAME: &str = "default";
/// Most declared shapes one adapter accepts.
pub const MAX_SHAPES: usize = 8;
/// Ceiling for a declared shape's vCPU count: one `n2-standard-8` Kata worker.
pub const MAX_CPU: u32 = 8;
/// Ceiling for a declared shape's memory in GiB: one `n2-standard-8` Kata worker.
pub const MAX_MEMORY_GIB: u32 = 32;
/// Ceiling for a declared shape's private volume in GiB.
pub const MAX_STORAGE_GIB: u32 = 200;

/// CPU, memory and private-volume size for one hosted Kata guest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceShape {
    pub name: String,
    pub cpu: u32,
    pub memory_gib: u32,
    pub storage_gib: u32,
}

impl Default for ResourceShape {
    /// The qualified hosted shape: two vCPU, 4 GiB memory and a 19 GiB volume.
    fn default() -> Self {
        Self {
            name: DEFAULT_NAME.into(),
            cpu: 2,
            memory_gib: 4,
            storage_gib: 19,
        }
    }
}

impl ResourceShape {
    /// Parse one operator declaration, `NAME=CPU,MEMORYGi,STORAGEGi`,
    /// for example `build=4,8Gi,100Gi`.
    pub fn parse(value: &str) -> Result<Self> {
        let (name, sizes) = value
            .split_once('=')
            .context("resource shape must be NAME=CPU,MEMORY,STORAGE")?;
        let sizes: Vec<&str> = sizes.split(',').collect();
        let [cpu, memory, storage] = sizes[..] else {
            anyhow::bail!("resource shape must be NAME=CPU,MEMORY,STORAGE");
        };
        let shape = Self {
            name: name.into(),
            cpu: cpu.parse().context("invalid resource shape CPU")?,
            memory_gib: gibibytes(memory).context("invalid resource shape memory")?,
            storage_gib: gibibytes(storage).context("invalid resource shape storage")?,
        };
        shape.validate()?;
        Ok(shape)
    }

    /// The declaration `parse` accepts; the adapter passes it to the launcher.
    pub fn declaration(&self) -> String {
        format!(
            "{}={},{},{}",
            self.name,
            self.cpu,
            self.memory(),
            self.storage()
        )
    }

    /// Reject the reserved name, malformed names and sizes above the ceiling.
    pub fn validate(&self) -> Result<()> {
        if self.is_default() {
            return Ok(());
        }
        ensure!(
            self.name != DEFAULT_NAME
                && !self.name.is_empty()
                && self.name.len() <= 32
                && self.name.as_bytes()[0].is_ascii_lowercase()
                && self
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "resource shape name must be a short lowercase label other than default"
        );
        ensure!(
            (1..=MAX_CPU).contains(&self.cpu)
                && (1..=MAX_MEMORY_GIB).contains(&self.memory_gib)
                && (1..=MAX_STORAGE_GIB).contains(&self.storage_gib),
            "resource shape exceeds the hosted ceiling of {MAX_CPU} vCPU, {MAX_MEMORY_GIB}Gi memory and {MAX_STORAGE_GIB}Gi storage"
        );
        let default = Self::default();
        ensure!(
            (self.cpu, self.memory_gib) != (default.cpu, default.memory_gib),
            "resource shape must differ from the default CPU and memory"
        );
        Ok(())
    }

    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
    /// Kubernetes CPU quantity.
    pub fn cpu(&self) -> String {
        self.cpu.to_string()
    }
    /// Kubernetes memory quantity.
    pub fn memory(&self) -> String {
        format!("{}Gi", self.memory_gib)
    }
    /// Kubernetes private-volume request.
    pub fn storage(&self) -> String {
        format!("{}Gi", self.storage_gib)
    }

    /// Whether a template's resource requirements select exactly this shape.
    /// The default shape keeps its existing rule: each value is empty or equal.
    /// A declared shape needs explicit CPU and memory values.
    pub fn admits(&self, requested: Option<&DriverResourceRequirements>) -> bool {
        let Some(requested) = requested else {
            return self.is_default();
        };
        let (cpu, memory) = (self.cpu(), self.memory());
        let cpus = [&requested.cpu_request, &requested.cpu_limit];
        let memories = [&requested.memory_request, &requested.memory_limit];
        let matches = cpus.iter().all(|v| v.is_empty() || **v == cpu)
            && memories.iter().all(|v| v.is_empty() || **v == memory);
        matches
            && (self.is_default()
                || (cpus.iter().any(|v| !v.is_empty()) && memories.iter().any(|v| !v.is_empty())))
    }

    /// The declared shape a template selects, else the default shape. Admission
    /// then refuses requirements that the selected shape does not admit.
    pub fn select(declared: &[Self], requested: Option<&DriverResourceRequirements>) -> Self {
        declared
            .iter()
            .find(|shape| shape.admits(requested))
            .cloned()
            .unwrap_or_default()
    }
}

/// Validate a complete operator declaration list.
pub fn validate_declared(shapes: &[ResourceShape]) -> Result<()> {
    ensure!(
        shapes.len() <= MAX_SHAPES,
        "at most {MAX_SHAPES} resource shapes are allowed"
    );
    for (index, shape) in shapes.iter().enumerate() {
        shape.validate()?;
        ensure!(
            !shape.is_default(),
            "the default resource shape is built in"
        );
        ensure!(
            shapes[..index].iter().all(|other| other.name != shape.name
                && (other.cpu, other.memory_gib) != (shape.cpu, shape.memory_gib)),
            "resource shapes need distinct names and distinct CPU and memory"
        );
    }
    Ok(())
}

fn gibibytes(value: &str) -> Result<u32> {
    let digits = value.strip_suffix("Gi").context("size must use Gi")?;
    ensure!(
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
        "size must be whole Gi"
    );
    Ok(digits.parse()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requested(cpu: &str, memory: &str) -> DriverResourceRequirements {
        DriverResourceRequirements {
            cpu_request: cpu.into(),
            cpu_limit: cpu.into(),
            memory_request: memory.into(),
            memory_limit: memory.into(),
        }
    }

    #[test]
    fn declarations_round_trip_and_respect_the_ceiling() {
        let build = ResourceShape::parse("build=4,8Gi,100Gi").expect("build shape");
        assert_eq!(
            (build.cpu(), build.memory(), build.storage()),
            ("4".into(), "8Gi".into(), "100Gi".into())
        );
        assert_eq!(build.declaration(), "build=4,8Gi,100Gi");
        for invalid in [
            "build=9,8Gi,100Gi",
            "build=4,33Gi,100Gi",
            "build=4,8Gi,201Gi",
            "build=0,8Gi,100Gi",
            "build=4,8G,100Gi",
            "build=4,8Gi",
            "default=4,8Gi,100Gi",
            "Build=4,8Gi,100Gi",
            "same=2,4Gi,100Gi",
            "=4,8Gi,100Gi",
        ] {
            assert!(ResourceShape::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn declared_lists_reject_duplicates() {
        let build = ResourceShape::parse("build=4,8Gi,100Gi").expect("build");
        let other = ResourceShape::parse("other=4,8Gi,50Gi").expect("other");
        let renamed = ResourceShape::parse("build=6,12Gi,50Gi").expect("renamed");
        validate_declared(std::slice::from_ref(&build)).expect("one shape");
        assert!(validate_declared(&[build.clone(), other]).is_err());
        assert!(validate_declared(&[build, renamed]).is_err());
    }

    #[test]
    fn only_explicit_template_resources_select_a_declared_shape() {
        let build = ResourceShape::parse("build=4,8Gi,100Gi").expect("build");
        let declared = [build.clone()];
        assert_eq!(
            ResourceShape::select(&declared, Some(&requested("4", "8Gi"))),
            build
        );
        for template in [None, Some(requested("", "")), Some(requested("2", "4Gi"))] {
            let selected = ResourceShape::select(&declared, template.as_ref());
            assert!(selected.is_default());
            assert!(selected.admits(template.as_ref()));
        }
        // CPU alone never selects the larger shape, and the default refuses it.
        let partial = requested("4", "");
        let selected = ResourceShape::select(&declared, Some(&partial));
        assert!(selected.is_default() && !selected.admits(Some(&partial)));
        // Undeclared sizes fall back to the default shape, which refuses them.
        let unknown = requested("6", "12Gi");
        assert!(!ResourceShape::select(&declared, Some(&unknown)).admits(Some(&unknown)));
        assert!(
            !ResourceShape::select(&[], Some(&requested("4", "8Gi")))
                .admits(Some(&requested("4", "8Gi")))
        );
    }
}
