//! External OpenShell compute adapter for isolated Kata guests.
pub mod admission;
pub mod boundary;
pub mod canonical;
pub mod config;
pub mod download;
pub mod driver;
pub mod guard_rpc;
pub mod guest;
pub mod hosted;
mod hosted_network;
pub mod inventory;
pub mod kubernetes;
pub mod network;
pub mod node_intent;
pub mod operator;
pub mod policy;
pub mod profile;
pub mod recovery;
pub mod resource_shape;
pub mod runtime;
pub mod ssh;
pub mod supervisor;
pub mod upload;
pub mod workspace;
/// Pinned, unmodified OpenShell wire contracts.
#[allow(clippy::all, rustdoc::invalid_html_tags)]
pub mod proto {
    pub mod openshell {
        pub mod compute {
            pub mod v1 {
                tonic::include_proto!("openshell.compute.v1");
            }
        }
        pub mod datamodel {
            pub mod v1 {
                tonic::include_proto!("openshell.datamodel.v1");
            }
        }
        pub mod extension {
            pub mod v1 {
                tonic::include_proto!("openshell.extension.v1");
            }
        }
        pub mod options {
            pub mod v1 {
                tonic::include_proto!("openshell.options.v1");
            }
        }
        pub mod sandbox {
            pub mod v1 {
                tonic::include_proto!("openshell.sandbox.v1");
            }
        }
        pub mod v1 {
            tonic::include_proto!("openshell.v1");
        }
    }
}
