//! An external guest egress fence and an explicit TCP destination broker.
mod broker;
mod cli;
mod compiler;
mod fence;
pub mod guard;
pub mod hosted_fence;
mod policy;
mod proxy;

pub use broker::{BrokerHandle, bind_broker};
pub use cli::{NetworkCli, run_network};
pub use compiler::compile_native;
pub use fence::{FenceProof, FenceSpec, install_fence, remove_fence, verify_fence};
pub use guard::{
    BrokerBinding, HostedBrokerConfig, HostedBrokerHandle, HostedControlRequest,
    HostedControlResponse, InfrastructureInventory, ProviderAuthorization, ProviderMaterial,
    bind_hosted_broker,
};
pub use policy::{
    Endpoint, NetworkPolicy, ValidatedNetworkPolicy, globally_routable, normalize_host,
};
