// SPDX-License-Identifier: Apache-2.0

//! Everything the page reads from the registry, always under the person's
//! own token and the one configured access profile.
//!
//! The registry does not tie a Proposal's target to the person holding the
//! Proposal: a person may hold a draft naming someone else's record. So a
//! review reads the draft, then reads the record its target input names. A
//! page offers the submit form only when both reads succeed, and a submit
//! repeats both reads before it calls the registry.

use registry_breg_client::{
    BRegMetadata, BRegMetadataOperation, BRegOperationKind, BRegProposal, BRegRecordOptions,
    BaseRegistryClient, BaseRegistryClientError, RegistryRecordSingleResponse,
};
use serde_json::Value;

use crate::templates::Item;

/// The value shown for an empty or absent field.
pub(crate) const NOT_PROVIDED: &str = "Not provided";

/// Why a review could not be loaded.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// The registry refused or concealed a read, or the draft names no
    /// readable target. Rendered as the one neutral not-found page.
    NotFound,
    /// The registry no longer accepts the person's token.
    SignedOut,
    /// The registry definitely declined the request, so it had no effect.
    Refused(String),
    /// The registry failed, or answered outside the shape this page reads.
    Unavailable(String),
}

impl Refusal {
    pub(crate) fn from_client(error: &BaseRegistryClientError) -> Self {
        match error.status() {
            Some(403 | 404) => Self::NotFound,
            Some(401) => Self::SignedOut,
            // A rate limit is a refusal worth retrying later.
            Some(429) => Self::Unavailable(error.to_string()),
            Some(400..=499) => Self::Refused(error.to_string()),
            _ => Self::Unavailable(error.to_string()),
        }
    }
}

/// A draft and its target, both read under the person's token.
pub(crate) struct Review {
    pub action_label: String,
    pub target_label: String,
    pub current: Vec<Item>,
    pub proposed: Vec<Item>,
    /// The target record revision whose values `current` shows.
    pub target: RecordRevision,
    /// The submit action the registry advertises on the draft right now.
    pub submit: Option<BRegProposal>,
    pub proposal: BRegProposal,
}

/// One revision of one record, as the registry identified it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordRevision {
    pub record: String,
    pub revision: String,
}

pub(crate) struct Profile<'a> {
    pub action: &'a str,
    pub target_input: &'a str,
    pub access_profile: &'a str,
}

/// Read the draft `request_id` and the record its target input names.
pub(crate) async fn load(
    registry: &BaseRegistryClient,
    profile: &Profile<'_>,
    request_id: &str,
) -> Result<Review, Refusal> {
    let metadata = registry
        .registry_contract(Some(profile.access_profile))
        .await
        .map_err(|error| Refusal::from_client(&error))?
        .value;
    let get = metadata
        .select_proposal_get(profile.access_profile)
        .map_err(|_| Refusal::NotFound)?;
    let proposal = registry
        .get_proposal(&get, request_id)
        .await
        .map_err(|error| Refusal::from_client(&error))?
        .value;
    if proposal.action_id() != profile.action {
        return Err(Refusal::NotFound);
    }
    let action = metadata
        .actions()
        .iter()
        .find(|action| {
            action.identifier() == profile.action
                && action.access_profile() == profile.access_profile
        })
        .ok_or(Refusal::NotFound)?;
    let target_input = action
        .reference_inputs()
        .iter()
        .find(|input| input.input_identifier() == profile.target_input)
        .ok_or(Refusal::NotFound)?;
    let target_get = get_operation(
        &metadata,
        target_input.target_record_type(),
        profile.access_profile,
    )
    .ok_or(Refusal::NotFound)?;
    let input = proposal.input().ok_or(Refusal::NotFound)?;
    let target_id = input
        .get(target_input.api_name())
        .and_then(Value::as_str)
        .filter(|value| crate::canonical_uuid(value))
        .ok_or(Refusal::NotFound)?;
    let options = BRegRecordOptions::default()
        .access_profile(profile.access_profile)
        .map_err(|_| Refusal::NotFound)?;
    let target = registry
        .get_record(route(target_get)?, target_id, &options)
        .await
        .map_err(|error| Refusal::from_client(&error))?
        .value;
    let proposed = action
        .inputs()
        .iter()
        .filter(|field| field.identifier() != profile.target_input)
        .filter_map(|field| {
            input.get(field.api_name()).map(|value| Item {
                label: field.label().to_owned(),
                value: display_value(value),
            })
        })
        .collect();
    let action_label = action
        .display()
        .get("label")
        .and_then(Value::as_str)
        .unwrap_or(action.identifier())
        .to_owned();
    let submit = proposal
        .link("submit")
        .filter(|link| {
            link.availability()
                .is_none_or(|availability| availability.available)
        })
        .map(|_| proposal.clone());
    Ok(Review {
        action_label,
        target_label: target_get.record_type_label().to_owned(),
        current: items(target_get, &target),
        proposed,
        target: RecordRevision {
            record: target.data.record_identifier.clone(),
            revision: target.data.revision_identifier.clone(),
        },
        submit,
        proposal,
    })
}
fn display_value(value: &Value) -> String {
    match value {
        Value::Null => NOT_PROVIDED.to_owned(),
        Value::String(text) if text.is_empty() => NOT_PROVIDED.to_owned(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn get_operation<'a>(
    metadata: &'a BRegMetadata,
    entity: &str,
    access_profile: &str,
) -> Option<&'a BRegMetadataOperation> {
    metadata.operations().iter().find(|operation| {
        matches!(operation.kind(), BRegOperationKind::Get)
            && operation.source_record_type() == entity
            && operation.access_profile() == access_profile
    })
}

/// The entity route in a Get operation's `/v1/records/{route}/{record_id}`
/// path.
fn route(operation: &BRegMetadataOperation) -> Result<&str, Refusal> {
    operation
        .path()
        .strip_prefix("/v1/records/")
        .and_then(|rest| rest.strip_suffix("/{record_id}"))
        .filter(|route| !route.is_empty() && !route.contains('/'))
        .ok_or_else(|| {
            Refusal::Unavailable("a registry read path has an unexpected shape".to_owned())
        })
}

/// The readable fields of `record`, labelled from caller-filtered metadata,
/// with coded values shown by their labels.
fn items(operation: &BRegMetadataOperation, record: &RegistryRecordSingleResponse) -> Vec<Item> {
    operation
        .fields()
        .iter()
        .filter(|field| {
            operation
                .readable_fields()
                .iter()
                .any(|readable| readable == field.identifier())
        })
        .map(|field| {
            let value = match record.data.domain_data.get(field.api_name()) {
                None | Some(Value::Null) => NOT_PROVIDED.to_owned(),
                Some(Value::String(text)) if text.is_empty() => NOT_PROVIDED.to_owned(),
                Some(Value::String(text)) => field
                    .code_labels()
                    .get(text)
                    .cloned()
                    .unwrap_or_else(|| text.clone()),
                Some(other) => other.to_string(),
            };
            Item {
                label: field.label().to_owned(),
                value,
            }
        })
        .collect()
}
