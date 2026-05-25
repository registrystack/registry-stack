// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Witness runtime.

pub mod api;
pub mod openapi;
pub mod runtime;
pub mod self_attestation_rate_limit;
pub mod standalone;

pub(crate) const PROBLEM_TYPE_BASE_URL: &str = "https://docs.registry-witness.dev/problems";

pub use api::*;
pub use openapi::*;
pub use runtime::*;
pub use self_attestation_rate_limit::*;
pub use standalone::*;
