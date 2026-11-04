//! Guest-side command and file conveniences, separate from the external VM boundary.

mod capability;
mod files;
mod process;
mod transfer;

pub use capability::{CapabilityRequest, acknowledge, pending, read as capability, request_docker};
pub use files::{RemoveOptions, Workspace};
pub use process::{hold, kill, quiesce, run, run_child, thaw};
pub use transfer::{export, import};

/// Maximum bytes in one System file operation.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
