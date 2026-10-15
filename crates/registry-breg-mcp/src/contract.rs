// SPDX-License-Identifier: Apache-2.0

//! Tools derive their shape from the caller-filtered Action contract.

use registry_breg_client::{BRegActionMode, BRegMetadata, BRegOperationKind};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ContractSpec {
    pub(crate) access_profile: String,
    pub(crate) details_record_type: String,
    pub(crate) action: String,
    pub(crate) target_input: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LabelledField {
    pub(crate) api_name: String,
    pub(crate) label: String,
}
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EditableField {
    pub(crate) api_name: String,
    pub(crate) label: String,
    pub(crate) schema: Value,
    pub(crate) required: bool,
}
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Contract {
    pub(crate) action_revision: String,
    pub(crate) details_route: String,
    pub(crate) details_fields: Vec<LabelledField>,
    pub(crate) target_api_name: String,
    pub(crate) editable: Vec<EditableField>,
    pub(crate) patch_editable: BTreeSet<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ContractError {
    #[error("the registry publishes no list of the citizen's own record")]
    DetailsListMissing,
    #[error("the registry publishes no proposal-mode Action for the configured profile")]
    ActionMissing,
    #[error("the target input does not reference the citizen's own record type")]
    TargetInputInvalid,
    #[error("the Action offers no editable input")]
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
                    && operation.source_record_type() == spec.details_record_type
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
            .fields()
            .iter()
            .filter(|field| {
                details
                    .readable_fields()
                    .iter()
                    .any(|id| id == field.identifier())
            })
            .map(|field| LabelledField {
                api_name: field.api_name().to_owned(),
                label: field.label().to_owned(),
            })
            .collect();
        let action = metadata
            .actions()
            .iter()
            .find(|action| {
                action.identifier() == spec.action
                    && action.access_profile() == spec.access_profile
                    && action.mode() == BRegActionMode::Proposal
            })
            .ok_or(ContractError::ActionMissing)?;
        let target = action
            .inputs()
            .iter()
            .find(|input| input.identifier() == spec.target_input)
            .filter(|input| {
                input.required()
                    && action.reference_inputs().iter().any(|reference| {
                        reference.input_identifier() == input.identifier()
                            && reference.target_record_type() == spec.details_record_type
                    })
            })
            .ok_or(ContractError::TargetInputInvalid)?;
        let editable: Vec<_> = action
            .inputs()
            .iter()
            .filter(|input| input.identifier() != target.identifier())
            .map(|input| EditableField {
                api_name: input.api_name().to_owned(),
                label: input.label().to_owned(),
                schema: input.schema().clone(),
                required: input.required(),
            })
            .collect();
        if editable.is_empty() {
            return Err(ContractError::NothingEditable);
        }
        let patch_editable = editable
            .iter()
            .map(|input| input.api_name.clone())
            .collect();
        Ok(Self {
            action_revision: action.definition_revision().to_owned(),
            details_route,
            details_fields,
            target_api_name: target.api_name().to_owned(),
            editable,
            patch_editable,
        })
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    pub(crate) const FIXTURE: &[u8] =
        include_bytes!("../tests/fixtures/citizen-agent-metadata.json");
    pub(crate) fn spec() -> ContractSpec {
        ContractSpec {
            access_profile: "citizen-agent".into(),
            details_record_type: "person-address".into(),
            action: "correct-address".into(),
            target_input: "address".into(),
        }
    }
    pub(crate) fn fixture_contract() -> Contract {
        Contract::derive(&BRegMetadata::from_slice(FIXTURE).unwrap(), &spec()).unwrap()
    }
    pub(crate) fn divergent_fixture() -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(FIXTURE).unwrap();
        value["actions"][0]["inputs"][0]["id"] = json!("target-ref");
        value["actions"][0]["referenceInputs"][0]["input"] = json!("target-ref");
        serde_json::to_vec(&value).unwrap()
    }
    #[test]
    fn only_proposal_mode_for_the_selected_profile_is_offered() {
        let mut value: Value = serde_json::from_slice(FIXTURE).unwrap();
        value["actions"][0]["execution"]["mode"] = json!("immediate");
        let metadata = BRegMetadata::from_slice(&serde_json::to_vec(&value).unwrap());
        assert!(metadata.is_err() || Contract::derive(&metadata.unwrap(), &spec()).is_err());
        let mut other = spec();
        other.access_profile = "other".into();
        assert!(Contract::derive(&BRegMetadata::from_slice(FIXTURE).unwrap(), &other).is_err());
    }
    #[test]
    fn generated_schema_constraints_are_offered_without_reconstruction() {
        let mut value: Value = serde_json::from_slice(FIXTURE).unwrap();
        let schema = json!({"type":"object","required":["when"],
            "properties":{"when":{"type":"string","format":"date-time"}},
            "additionalProperties":false});
        value["actions"][0]["inputs"][1]["schema"] = schema.clone();
        let metadata = BRegMetadata::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        let contract = Contract::derive(&metadata, &spec()).unwrap();
        assert_eq!(contract.editable[0].schema, schema);
        value["actions"][0]["inputs"][1]
            .as_object_mut()
            .unwrap()
            .remove("schema");
        assert!(BRegMetadata::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn controlled_inputs_are_never_editable() {
        let contract = fixture_contract();
        assert!(!contract.patch_editable.contains("address"));
        assert!(!contract.patch_editable.contains("owner"));
        assert_eq!(contract.editable.len(), 3);
    }
    #[test]
    fn target_uses_identifier_and_exact_record_type() {
        let metadata = BRegMetadata::from_slice(&divergent_fixture()).unwrap();
        assert_eq!(
            Contract::derive(&metadata, &spec()),
            Err(ContractError::TargetInputInvalid)
        );
        let mut renamed = spec();
        renamed.target_input = "target-ref".into();
        assert_eq!(
            Contract::derive(&metadata, &renamed)
                .unwrap()
                .target_api_name,
            "address"
        );
    }
}
