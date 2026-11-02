use crate::proto::openshell::{compute::v1::DriverSandbox, sandbox::v1::GetSandboxConfigResponse};
use anyhow::{Result, bail};

pub fn compile_request(
    sandbox: &DriverSandbox,
    operator: &crate::profile::VmPolicy,
) -> Result<crate::profile::VmPolicy> {
    compile_request_for_image(sandbox, operator, None)
}

/// Compile a request against an optional operator-pinned image and actual VM limits.
pub fn compile_request_for_image(
    sandbox: &DriverSandbox,
    operator: &crate::profile::VmPolicy,
    image: Option<&str>,
) -> Result<crate::profile::VmPolicy> {
    compile_request_for_images(sandbox, operator, image.as_slice())
}

/// Admit a request whose template selects one of the operator-pinned images; every
/// image runs under the same operator VM profile.
pub fn compile_request_for_images(
    sandbox: &DriverSandbox,
    operator: &crate::profile::VmPolicy,
    images: &[&str],
) -> Result<crate::profile::VmPolicy> {
    let native = sandbox
        .spec
        .as_ref()
        .and_then(|s| s.policy.as_ref())
        .ok_or_else(|| anyhow::anyhow!("hardened mode requires explicit native policy"))?;
    // Reuse the exact image/environment/resource boundary, then separately
    // compile native network intent without discarding its requirements.
    let mut shape = sandbox.clone();
    let spec = shape.spec.as_mut().expect("spec checked");
    spec.policy = None;
    let template = spec
        .template
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("sandbox template required"))?;
    if !images.is_empty() {
        for image in images {
            crate::hosted::validate_image(image)?;
        }
        anyhow::ensure!(
            images.contains(&template.image.as_str()),
            "guest image differs from operator profile"
        );
        template.image = "docker:29-dind".into();
    }
    if let Some(resources) = &template.resources {
        let cpu = operator.resources.vcpus.to_string();
        let memory_mi = format!("{}Mi", operator.resources.memory_mib);
        let memory_gi = format!("{}Gi", operator.resources.memory_mib / 1024);
        let cpu_ok = |value: &str| value.is_empty() || value == cpu;
        let memory_ok = |value: &str| {
            value.is_empty()
                || value == memory_mi
                || (operator.resources.memory_mib.is_multiple_of(1024) && value == memory_gi)
        };
        anyhow::ensure!(
            cpu_ok(&resources.cpu_request)
                && cpu_ok(&resources.cpu_limit)
                && memory_ok(&resources.memory_request)
                && memory_ok(&resources.memory_limit),
            "resource request differs from operator VM profile"
        );
        template.resources = None;
    }
    validate_request(&shape, true)?;
    operator.compile(native)
}

pub fn validate_request(sandbox: &DriverSandbox, prototype: bool) -> Result<()> {
    if !prototype {
        let policy = sandbox
            .spec
            .as_ref()
            .and_then(|spec| spec.policy.as_ref())
            .ok_or_else(|| anyhow::anyhow!("strict mode requires an explicit policy"))?;
        let _validated = crate::policy::validate_policy(policy)?;
        bail!(
            "runtime enforcement is not qualified: verified VM, storage and external network fences are required"
        );
    }
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox spec required"))?;
    let template = spec
        .template
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox template required"))?;
    if !matches!(
        template.image.as_str(),
        "docker:29-dind" | "docker.io/library/docker:29-dind"
    ) {
        bail!("prototype supports only docker:29-dind");
    }
    if !spec.environment.is_empty()
        || !template.environment.is_empty()
        || template
            .driver_config
            .as_ref()
            .is_some_and(|v| !v.fields.is_empty())
        || template
            .platform_config
            .as_ref()
            .is_some_and(|v| !v.fields.is_empty())
        || template.user_namespaces.is_some()
        || spec
            .workload_identity
            .as_ref()
            .is_some_and(|v| !v.user.is_empty() || !v.group.is_empty())
        || spec.isolation_backend.is_some()
    {
        bail!("unsupported runtime configuration");
    }
    if template.resources.as_ref().is_some_and(|v| {
        !v.cpu_request.is_empty()
            || !v.cpu_limit.is_empty()
            || !v.memory_request.is_empty()
            || !v.memory_limit.is_empty()
    }) || spec
        .resource_requirements
        .as_ref()
        .is_some_and(|v| v.gpu.is_some())
    {
        bail!("prototype rejects resource overrides");
    }
    if spec
        .policy
        .as_ref()
        .is_some_and(|p| !p.network_policies.is_empty())
    {
        bail!("prototype cannot enforce network policies");
    }
    Ok(())
}
pub fn validate_snapshot(config: &GetSandboxConfigResponse) -> Result<()> {
    if !config.configuration_admitted {
        bail!("gateway has not admitted the configuration");
    }
    if config
        .policy
        .as_ref()
        .is_some_and(|p| !p.network_policies.is_empty())
        || !config.supervisor_middleware_services.is_empty()
    {
        bail!("prototype cannot enforce effective network policy or middleware");
    }
    Ok(())
}
