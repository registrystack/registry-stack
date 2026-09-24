// SPDX-License-Identifier: Apache-2.0

//! The tool contract derived from caller-filtered Registry Metadata.
//!
//! The gateway never carries a schema of its own. Every tool call reads the
//! metadata the Base Registry Engine publishes for the agent profile under the
//! caller's delegated token and derives this contract from it, so a change of
//! identity or registry revision can never reuse a stale shape.

use std::collections::BTreeSet;

use registry_breg_client::{BRegMetadata, BRegMetadataOperation, BRegOperationKind};
use serde_json::Value;

/// The operator-declared names the contract is derived from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContractSpec {
    pub(crate) access_profile: String,
    pub(crate) details_entity: String,
    pub(crate) application_entity: String,
    /// The API name of the application field that references the citizen's
    /// own record.
    pub(crate) target_field: String,
    /// The API name of the application field that records the citizen.
    pub(crate) owner_field: String,
}

/// One readable field of the citizen's own record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LabelledField {
    pub(crate) api_name: String,
    pub(crate) label: String,
}

/// One application field the citizen may author.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EditableField {
    pub(crate) api_name: String,
    pub(crate) label: String,
    pub(crate) schema: Value,
    pub(crate) required: bool,
}

/// The complete contract one tool call works against.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Contract {
    pub(crate) registry_revision: String,
    pub(crate) details_route: String,
    pub(crate) details_fields: Vec<LabelledField>,
    pub(crate) application_route: String,
    pub(crate) create_operation: String,
    pub(crate) patch_operation: String,
    pub(crate) target_api_name: String,
    pub(crate) owner_api_name: String,
    pub(crate) editable: Vec<EditableField>,
    pub(crate) patch_editable: BTreeSet<String>,
}

/// A value-free reason the published metadata cannot carry the tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ContractError {
    #[error("the registry publishes no list operation for the citizen's own record")]
    DetailsListMissing,
    #[error("the registry publishes no {0} operation for the application")]
    ApplicationOperationMissing(&'static str),
    #[error(
        "the application target field is not a writable reference to the citizen's own record"
    )]
    TargetFieldInvalid,
    #[error("the application owner field is not writable on create")]
    OwnerFieldInvalid,
    #[error("the application offers no field the citizen may author")]
    NothingEditable,
}

impl Contract {
    pub(crate) fn derive(
        metadata: &BRegMetadata,
        spec: &ContractSpec,
    ) -> Result<Self, ContractError> {
        let details = metadata
            .operations()
            .iter()
            .find(|operation| {
                matches!(operation.kind(), BRegOperationKind::List)
                    && operation.source_entity() == spec.details_entity
                    && operation.access_profile() == spec.access_profile
            })
            .ok_or(ContractError::DetailsListMissing)?;
        let details_route = details
            .path()
            .strip_prefix("/v1/records/")
            .filter(|route| !route.is_empty() && !route.contains('/'))
            .ok_or(ContractError::DetailsListMissing)?
            .to_owned();
        let details_fields = details
            .readable_fields()
            .iter()
            .filter_map(|identifier| field_by_id(details, identifier))
            .map(|field| LabelledField {
                api_name: field.api_name().to_owned(),
                label: field.label().to_owned(),
            })
            .collect();

        let create = application_operation(metadata, spec, "create", &BRegOperationKind::Create)?;
        let patch = application_operation(metadata, spec, "patch", &BRegOperationKind::Patch)?;
        application_operation(metadata, spec, "get", &BRegOperationKind::Get)?;
        let application_route = create
            .path()
            .strip_prefix("/v1/records/")
            .filter(|route| !route.is_empty() && !route.contains('/'))
            .ok_or(ContractError::ApplicationOperationMissing("create"))?
            .to_owned();

        let target = field_by_api_name(create, &spec.target_field)
            .filter(|field| field.reference_target_entity() == Some(spec.details_entity.as_str()))
            .filter(|field| contains(create.create_writable_fields(), field.identifier()))
            .filter(|field| contains(patch.readable_fields(), field.identifier()))
            .ok_or(ContractError::TargetFieldInvalid)?;
        let owner = field_by_api_name(create, &spec.owner_field)
            .filter(|field| contains(create.create_writable_fields(), field.identifier()))
            .ok_or(ContractError::OwnerFieldInvalid)?;

        let controlled = [target.identifier(), owner.identifier()];
        let editable: Vec<EditableField> = create
            .create_writable_fields()
            .iter()
            .filter(|identifier| !controlled.contains(&identifier.as_str()))
            .filter_map(|identifier| field_by_id(create, identifier))
            .map(|field| EditableField {
                api_name: field.api_name().to_owned(),
                label: field.label().to_owned(),
                schema: field.schema().clone(),
                required: field.required(),
            })
            .collect();
        if editable.is_empty() {
            return Err(ContractError::NothingEditable);
        }
        let patch_editable = patch
            .patch_writable_fields()
            .iter()
            .filter(|identifier| !controlled.contains(&identifier.as_str()))
            .filter_map(|identifier| field_by_id(patch, identifier))
            .map(|field| field.api_name().to_owned())
            .filter(|api_name| editable.iter().any(|field| &field.api_name == api_name))
            .collect();

        Ok(Self {
            registry_revision: metadata.registry_revision().to_owned(),
            details_route,
            details_fields,
            application_route,
            create_operation: create.identifier().to_owned(),
            patch_operation: patch.identifier().to_owned(),
            target_api_name: target.api_name().to_owned(),
            owner_api_name: owner.api_name().to_owned(),
            editable,
            patch_editable,
        })
    }
}

fn application_operation<'a>(
    metadata: &'a BRegMetadata,
    spec: &ContractSpec,
    suffix: &'static str,
    kind: &BRegOperationKind,
) -> Result<&'a BRegMetadataOperation, ContractError> {
    let identifier = format!("records.{}.{suffix}", spec.application_entity);
    metadata
        .operation(&identifier)
        .filter(|operation| operation.kind() == kind)
        .filter(|operation| operation.source_entity() == spec.application_entity)
        .filter(|operation| operation.access_profile() == spec.access_profile)
        .ok_or(ContractError::ApplicationOperationMissing(suffix))
}

fn field_by_id<'a>(
    operation: &'a BRegMetadataOperation,
    identifier: &str,
) -> Option<&'a registry_breg_client::BRegMetadataField> {
    operation
        .fields()
        .iter()
        .find(|field| field.identifier() == identifier)
}

fn field_by_api_name<'a>(
    operation: &'a BRegMetadataOperation,
    api_name: &str,
) -> Option<&'a registry_breg_client::BRegMetadataField> {
    operation
        .fields()
        .iter()
        .find(|field| field.api_name() == api_name)
}

fn contains(values: &[String], wanted: &str) -> bool {
    values.iter().any(|value| value == wanted)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/citizen-agent-metadata.json");

    pub(crate) fn spec() -> ContractSpec {
        ContractSpec {
            access_profile: "citizen-agent".to_owned(),
            details_entity: "person-address".to_owned(),
            application_entity: "address-correction-request".to_owned(),
            target_field: "address".to_owned(),
            owner_field: "owner".to_owned(),
        }
    }

    pub(crate) fn fixture_contract() -> Contract {
        let metadata = BRegMetadata::from_slice(FIXTURE).expect("fixture metadata");
        Contract::derive(&metadata, &spec()).expect("fixture contract")
    }

    #[test]
    fn the_contract_comes_from_the_published_agent_metadata() {
        let contract = fixture_contract();
        assert_eq!(contract.details_route, "person-addresses");
        assert_eq!(
            contract
                .details_fields
                .iter()
                .map(|field| (field.api_name.as_str(), field.label.as_str()))
                .collect::<Vec<_>>(),
            [
                ("addressLine", "Address line"),
                ("locality", "Locality"),
                ("postalCode", "Postal code"),
            ]
        );
        assert_eq!(contract.application_route, "address-correction-requests");
        assert_eq!(
            contract.create_operation,
            "records.address-correction-request.create"
        );
        assert_eq!(
            contract.patch_operation,
            "records.address-correction-request.patch"
        );
        assert_eq!(contract.target_api_name, "address");
        assert_eq!(contract.owner_api_name, "owner");
    }

    #[test]
    fn the_target_and_owner_are_never_editable() {
        let contract = fixture_contract();
        let editable: Vec<&str> = contract
            .editable
            .iter()
            .map(|field| field.api_name.as_str())
            .collect();
        assert_eq!(editable, ["newAddressLine", "newLocality", "newPostalCode"]);
        assert!(!contract.patch_editable.contains("address"));
        assert!(!contract.patch_editable.contains("owner"));
        assert_eq!(contract.patch_editable.len(), 3);
    }

    #[test]
    fn a_target_that_does_not_reference_the_citizen_record_is_refused() {
        let mut spec = spec();
        spec.target_field = "newLocality".to_owned();
        let metadata = BRegMetadata::from_slice(FIXTURE).expect("fixture metadata");
        assert_eq!(
            Contract::derive(&metadata, &spec),
            Err(ContractError::TargetFieldInvalid)
        );
    }

    #[test]
    fn a_citizen_record_without_a_published_list_is_refused() {
        // The application entity has create, get, and patch for this profile
        // but no list, so naming it as the citizen's record finds no lookup.
        let mut spec = spec();
        spec.details_entity = "address-correction-request".to_owned();
        let metadata = BRegMetadata::from_slice(FIXTURE).expect("fixture metadata");
        assert_eq!(
            Contract::derive(&metadata, &spec),
            Err(ContractError::DetailsListMissing)
        );
    }

    #[test]
    fn metadata_for_another_profile_is_refused() {
        let mut spec = spec();
        spec.access_profile = "citizen-review".to_owned();
        let metadata = BRegMetadata::from_slice(FIXTURE).expect("fixture metadata");
        assert_eq!(
            Contract::derive(&metadata, &spec),
            Err(ContractError::DetailsListMissing)
        );
    }
}
