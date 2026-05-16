// SPDX-License-Identifier: Apache-2.0
//! Claim-type payload builders.
//!
//! Each submodule owns the `credentialSubject` shape for one claim
//! type. The shapes are public so the orchestrator can construct them
//! and the audit layer can label its events; the orchestrator itself
//! lives in [`super`].

pub mod aggregate_result;
pub mod entity_record;
pub mod verify_result;

pub use aggregate_result::{aggregate_result_subject, AggregateResultInput};
pub use entity_record::{entity_record_subject, EntityRecordInput};
pub use verify_result::{verify_result_subject, VerifyResultInput};
