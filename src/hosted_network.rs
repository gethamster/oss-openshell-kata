//! Compile each fresh hosted snapshot within its immutable original capability.

use crate::{
    hosted,
    kubernetes::HostedNetworkConfig,
    network::{NetworkPolicy, compile_native},
    proto::openshell::{compute::v1::DriverSandbox, sandbox::v1 as s},
};
use anyhow::{Context, Result, ensure};
use std::path::Path;

pub(crate) struct RuntimeNetwork {
    initial: NetworkPolicy,
}

impl RuntimeNetwork {
    pub(crate) fn new(
        path: &Path,
        sandbox: &DriverSandbox,
        image: &str,
        shape: &crate::resource_shape::ResourceShape,
    ) -> Result<Self> {
        let operator = HostedNetworkConfig::load(path)?;
        let initial =
            hosted::validate_brokered_request(sandbox, image, shape, &operator.operator_ceiling)?;
        Ok(Self { initial })
    }

    pub(crate) fn compile(&self, snapshot: &s::GetSandboxConfigResponse) -> Result<NetworkPolicy> {
        ensure!(
            snapshot.configuration_admitted
                && snapshot.supervisor_middleware_services.is_empty()
                && snapshot.policy_source == s::PolicySource::Sandbox as i32,
            "brokered networking requires an admitted sandbox policy without middleware"
        );
        compile_native(
            snapshot
                .policy
                .as_ref()
                .context("effective native policy missing")?,
            &self.initial,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Endpoint;

    fn snapshot(host: Option<&str>) -> s::GetSandboxConfigResponse {
        let mut native = s::SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        if let Some(host) = host {
            native.network_policies.insert(
                "tcp".into(),
                s::NetworkPolicyRule {
                    binaries: vec![s::NetworkBinary { path: "/**".into() }],
                    endpoints: vec![s::NetworkEndpoint {
                        host: host.into(),
                        port: 443,
                        protocol: "tcp".into(),
                        tls: 1,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
        }
        s::GetSandboxConfigResponse {
            policy: Some(native),
            policy_source: s::PolicySource::Sandbox as i32,
            configuration_admitted: true,
            ..Default::default()
        }
    }

    #[test]
    fn fresh_snapshots_may_revoke_but_cannot_expand_original_capability() -> Result<()> {
        let network = RuntimeNetwork {
            initial: NetworkPolicy {
                tcp_allow: vec![Endpoint {
                    host: "registry.npmjs.org".into(),
                    port: 443,
                }],
                ..Default::default()
            },
        };
        assert_eq!(
            network.compile(&snapshot(Some("registry.npmjs.org")))?,
            network.initial
        );
        assert_eq!(network.compile(&snapshot(None))?, NetworkPolicy::default());
        assert!(network.compile(&snapshot(Some("github.com"))).is_err());
        let denied = RuntimeNetwork {
            initial: NetworkPolicy::default(),
        };
        assert!(
            denied
                .compile(&snapshot(Some("registry.npmjs.org")))
                .is_err()
        );
        assert_eq!(denied.compile(&snapshot(None))?, NetworkPolicy::default());
        Ok(())
    }

    #[test]
    fn global_or_unadmitted_snapshots_never_authorize_a_lease() {
        let network = RuntimeNetwork {
            initial: NetworkPolicy::default(),
        };
        let mut effective = snapshot(None);
        effective.policy_source = s::PolicySource::Global as i32;
        assert!(network.compile(&effective).is_err());
        effective = snapshot(None);
        effective.configuration_admitted = false;
        assert!(network.compile(&effective).is_err());
        effective = snapshot(None);
        effective.policy = None;
        assert!(network.compile(&effective).is_err());
    }
}
