//! Native lifecycle and host-side enforcement for isolated Kata virtual machines.
pub mod command;
pub mod model;
pub mod state;

pub mod transport;

pub mod network;
pub mod watchdog;

pub mod lifecycle;

pub mod spec;

pub mod containerd;
mod containerd_bundle;

mod observation;
