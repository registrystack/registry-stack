// SPDX-License-Identifier: Apache-2.0
//! Registry Relay re-exports for the standalone Evidence Server crates.

mod registry_relay;

pub use evidence_core::*;
pub use evidence_server::*;

pub(crate) use registry_relay::{
    evidence_principal, require_evaluation_access, RegistryRelaySourceReader,
};
