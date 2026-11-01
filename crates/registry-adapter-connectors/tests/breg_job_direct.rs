// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "breg")]
//! The direct destination's admission rule: an ingestion job sends an
//! item straight to BReg only through an immediate Action or a Proposal
//! start and submit (`products/adapter/CONCEPT.md` sections 17.1 and
//! 17.3). Every other operation the connector implements stays out of a
//! job's direct path.

use registry_adapter_connectors::breg::{
    action, batch, ingestion, job_direct_admits, mutation, proposal,
};

#[test]
fn the_direct_destination_admits_action_and_proposal_only() {
    for admitted in [&*action::INVOKE, &*proposal::START, &*proposal::SUBMIT] {
        assert!(job_direct_admits(admitted), "{}", admitted.name);
    }
    for refused in [
        &*mutation::CREATE,
        &*mutation::PATCH,
        &*mutation::TOMBSTONE,
        &*batch::RECORDS,
        &*ingestion::CREATE_RUN,
        &*ingestion::SUBMIT_CHUNK,
    ] {
        assert!(!job_direct_admits(refused), "{}", refused.name);
    }
}
