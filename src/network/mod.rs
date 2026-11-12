//! An external guest egress fence and an explicit TCP destination broker.
mod broker;
mod cli;
mod compiler;
mod fence;
pub mod guard;
pub mod hosted_fence;
pub mod mediation;
mod policy;
mod proxy;

/// Policy features of this broker that an older one refuses, declared for
/// release tooling. oss-sre reads this exact line from the `kata-network`
/// binary (`scripts/standalone_release.py`) and writes
/// `allow_uninspected_credentials` into a Kata placement policy only for a
/// driver that declares it. `kata-network --help` prints it. Never remove or
/// reword a line while the feature is supported; add one line per feature.
pub const POLICY_FEATURES: &str = "openshell-kata-policy-feature: allow_uninspected_credentials";

pub use broker::{BrokerHandle, bind_broker};
pub use cli::{NetworkCli, run_network};
pub use compiler::{compile_native, compile_native_with_inspection};
pub use fence::{FenceProof, FenceSpec, install_fence, remove_fence, verify_fence};
pub use guard::{
    BrokerBinding, HostedBrokerConfig, HostedBrokerHandle, HostedControlRequest,
    HostedControlResponse, InfrastructureInventory, bind_hosted_broker,
};
pub use policy::{
    Endpoint, InspectedEndpoint, Inspection, NetworkPolicy, RestAccess, ValidatedNetworkPolicy,
    globally_routable, normalize_host,
};
