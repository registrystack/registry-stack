// SPDX-License-Identifier: Apache-2.0
//! Shared Registry Witness domain model and credential primitives.

pub mod config;
pub mod error;
pub mod model;
pub mod sd_jwt;

pub use config::*;
pub use error::EvidenceError;
pub use model::*;
