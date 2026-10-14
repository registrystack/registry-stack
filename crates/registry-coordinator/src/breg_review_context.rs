// SPDX-License-Identifier: Apache-2.0
//! Exact, independently authorized Proposal context for machine assessment.
//!
//! This read uses the connection's explicit source profile. It never borrows
//! a human reviewer's credential or a field-free review-status grant.

use std::collections::BTreeMap;

use registry_breg_client::{BRegProposalReviewContextContract, BaseRegistryClient};
use registry_review_protocol::{ContentDigest, SubjectBinding};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{adapters::refused, breg_action::failure, protocol::CallOutcome};

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadReviewContext {
    pub action_id: String,
    pub contract: BRegProposalReviewContextContract,
    pub subject: SubjectBinding,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewContextObservation {
    pub subject: SubjectBinding,
    pub contract: BRegProposalReviewContextContract,
    pub reference: String,
    pub fields: BTreeMap<String, Value>,
}

impl ReadReviewContext {
    fn check(&self) -> bool {
        self.subject.check().is_ok()
            && self.subject.subject_type == "proposal"
            && uuid::Uuid::parse_str(&self.subject.id)
                .is_ok_and(|id| id.to_string() == self.subject.id)
            && self
                .subject
                .version
                .parse::<u32>()
                .is_ok_and(|version| version > 0 && version.to_string() == self.subject.version)
            && !self.action_id.is_empty()
            && self.action_id.len() <= 128
            && self
                .action_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && self
                .contract
                .id
                .starts_with("urn:registry:breg:review-context:")
            && self.contract.id.len() <= 2048
            && !self.contract.id.chars().any(char::is_control)
            && ContentDigest::parse(&self.contract.revision).is_ok()
            && ContentDigest::parse(&self.contract.schema_digest).is_ok()
    }
}

pub async fn read(client: &BaseRegistryClient, profile: &str, value: &Value) -> CallOutcome {
    let input: ReadReviewContext = match serde_json::from_value(value.clone()) {
        Ok(input) => input,
        Err(_) => return refused("invalid-command"),
    };
    if !input.check() {
        return refused("invalid-command");
    }
    let metadata = match client.registry_contract(Some(profile)).await {
        Ok(metadata) => metadata.value,
        Err(error) => return failure(error, false),
    };
    let binding = match metadata.select_proposal_review_context(profile, &input.action_id) {
        Ok(binding) => binding,
        Err(_) => return refused("product-forbidden"),
    };
    let document = match client
        .read_proposal_review_by_id(&binding, &input.subject.id)
        .await
    {
        Ok(document) => document.value,
        Err(error) => return failure(error, false),
    };
    if document.subject.source != input.subject.source
        || document.subject.subject_type != input.subject.subject_type
        || document.subject.id != input.subject.id
        || document.subject.version != input.subject.version
        || document.subject.digest != input.subject.digest.as_str()
    {
        return refused("proposal-binding-mismatch");
    }
    if !document.context.contract.as_ref().is_some_and(|contract| {
        contract.id == input.contract.id
            && contract.revision == input.contract.revision
            && contract.schema_digest == input.contract.schema_digest
    }) {
        return refused("proposal-contract-changed");
    }
    if !document.reviewable {
        return refused("proposal-blocked");
    }
    let current = match client.registry_contract(Some(profile)).await {
        Ok(metadata) => metadata.value,
        Err(error) => return failure(error, false),
    };
    if current
        .select_proposal_review_context(profile, &input.action_id)
        .is_err()
    {
        return refused("product-forbidden");
    }
    let Some(fields) = document.context.fields else {
        return refused("invalid-response");
    };
    let observation = ReviewContextObservation {
        subject: input.subject,
        contract: input.contract,
        reference: document.context.reference,
        fields,
    };
    match serde_json::to_value(observation) {
        Ok(value) => CallOutcome::Success(value),
        Err(_) => refused("invalid-response"),
    }
}
