// SPDX-License-Identifier: Apache-2.0

//! Everything the page reads from the registry, always under the person's
//! own token and the one configured access profile.
//!
//! The registry does not tie a request's target to the person holding the
//! request: a person may hold a draft naming someone else's record. So a
//! review reads the draft, then reads the record its target field names. A
//! page offers the submit form only when both reads succeed, and a submit
//! repeats both reads before it calls the registry.

use registry_breg_client::{
    BRegLifecycleAction, BRegLifecycleOperation, BRegMetadata, BRegMetadataOperation,
    BRegOperationKind, BRegRecordOptions, BaseRegistryClient, BaseRegistryClientError,
    RegistryRecordSingleResponse,
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
    /// The registry failed, or answered outside the shape this page reads.
    Unavailable(String),
}

impl Refusal {
    pub(crate) fn from_client(error: &BaseRegistryClientError) -> Self {
        match error.status() {
            Some(403 | 404) => Self::NotFound,
            Some(401) => Self::SignedOut,
            _ => Self::Unavailable(error.to_string()),
        }
    }
}

/// A draft and its target, both read under the person's token.
pub(crate) struct Review {
    pub entity_label: String,
    pub target_label: String,
    pub current: Vec<Item>,
    pub proposed: Vec<Item>,
    /// The submit action the registry advertises on the draft right now.
    pub submit: Option<BRegLifecycleAction>,
}

pub(crate) struct Profile<'a> {
    pub entity: &'a str,
    pub target_field: &'a str,
    pub access_profile: &'a str,
}

/// Read the draft `request_id` and the record its target field names.
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
    let request_get =
        get_operation(&metadata, profile.entity, profile.access_profile).ok_or_else(|| {
            Refusal::Unavailable(
                "the registry metadata describes no read of the configured request entity"
                    .to_owned(),
            )
        })?;
    let options = BRegRecordOptions::default()
        .access_profile(profile.access_profile)
        .map_err(|_| Refusal::Unavailable("the access profile is invalid".to_owned()))?;
    let draft = registry
        .get_record(route(request_get)?, request_id, &options)
        .await
        .map_err(|error| Refusal::from_client(&error))?
        .value;

    let target_field = request_get
        .fields()
        .iter()
        .find(|field| field.identifier() == profile.target_field)
        .ok_or_else(|| {
            Refusal::Unavailable(
                "the registry metadata does not describe the configured target field".to_owned(),
            )
        })?;
    let target_get = target_field
        .reference()
        .and_then(|reference| {
            reference
                .operations()
                .iter()
                .find(|operation| operation.access_profile() == profile.access_profile)
        })
        .and_then(|reference| metadata.operation(reference.operation_identifier()))
        .filter(|operation| {
            matches!(operation.kind(), BRegOperationKind::Get)
                && operation.access_profile() == profile.access_profile
        })
        .ok_or_else(|| {
            Refusal::Unavailable(
                "the registry metadata describes no read of the target field's record".to_owned(),
            )
        })?;
    // A draft that names no target, or a target this person may not read,
    // offers nothing to confirm.
    let target_id = draft
        .data
        .domain_data
        .get(target_field.api_name())
        .and_then(Value::as_str)
        .filter(|value| crate::canonical_uuid(value))
        .ok_or(Refusal::NotFound)?;
    let target = registry
        .get_record(route(target_get)?, target_id, &options)
        .await
        .map_err(|error| Refusal::from_client(&error))?
        .value;

    let authority = metadata
        .select_lifecycle(profile.entity, profile.access_profile)
        .map_err(|_| {
            Refusal::Unavailable(
                "the registry metadata describes no lifecycle for the request entity".to_owned(),
            )
        })?;
    let submit = registry
        .lifecycle_actions(&authority, &draft)
        .map_err(|_| {
            Refusal::Unavailable("the draft's lifecycle actions are not valid".to_owned())
        })?
        .into_iter()
        .find(|action| action.operation() == BRegLifecycleOperation::SubmitRequest);

    Ok(Review {
        entity_label: request_get.entity_label().to_owned(),
        target_label: target_get.entity_label().to_owned(),
        current: items(target_get, &target, None),
        proposed: items(request_get, &draft, Some(profile.target_field)),
        submit,
    })
}

fn get_operation<'a>(
    metadata: &'a BRegMetadata,
    entity: &str,
    access_profile: &str,
) -> Option<&'a BRegMetadataOperation> {
    metadata.operations().iter().find(|operation| {
        matches!(operation.kind(), BRegOperationKind::Get)
            && operation.source_entity() == entity
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
fn items(
    operation: &BRegMetadataOperation,
    record: &RegistryRecordSingleResponse,
    skip: Option<&str>,
) -> Vec<Item> {
    operation
        .fields()
        .iter()
        .filter(|field| Some(field.identifier()) != skip)
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
