//! The requester-scoped definitions document, as discovery returns it.
//!
//! Discovery answers one question: which complete request shapes may this
//! requester send. It is not a trust anchor and it grants no authority. The
//! values here are useful for authoring a relying procedure once, after which
//! the procedure itself, not a fresh discovery response, supplies the
//! verification expectations for every request.
//!
//! These types are owned here rather than imported from the runtime. The
//! integration suite proves they agree with a real deployment.

use registry_evidence_verifier::{
    model::SubjectBindingMode,
    verifier::{
        ExpectedFormDocument, ExpectedListDocument, ExpectedListFormDocument,
        ExpectedOutputDocument, ExpectedScalarFormDocument,
    },
    AssuranceProfile,
};
use serde::{Deserialize, Serialize};

pub const EVIDENCE_DEFINITIONS_SCHEMA_V1: &str = "registry.evidence-definitions/v1";

const fn default_holder_bound_batch_max_size() -> u16 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDefinitionsDocument {
    pub schema: String,
    pub assurance_profile: AssuranceProfile,
    pub issued_by: String,
    pub provided_by: String,
    /// Effective holder-bound batch ceiling published by the deployment.
    ///
    /// A missing member is read as one for compatibility with a deployment
    /// predating batch-ceiling discovery. One is the only safe inference: it
    /// never causes a caller or protocol adapter to advertise a wider batch
    /// than that deployment can honor.
    #[serde(default = "default_holder_bound_batch_max_size")]
    pub holder_bound_batch_max_size: u16,
    pub definitions: Vec<EvidenceDefinition>,
}

impl EvidenceDefinitionsDocument {
    /// The single definition for one requirement identifier, when the
    /// requester is entitled to exactly one shape of it.
    ///
    /// A deployment keys its authorized shapes on requirement, purpose, and
    /// selector profile together, so one requirement may carry several. This
    /// answers `None` for an ambiguous requirement rather than picking one,
    /// because `purpose` is policy bearing on both ends: it travels in the
    /// request and the verifier compares it. Read `definitions` directly to
    /// choose between the shapes.
    #[must_use]
    pub fn definition(&self, requirement: &str) -> Option<&EvidenceDefinition> {
        let mut matching = self
            .definitions
            .iter()
            .filter(|definition| definition.requirement == requirement);
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDefinition {
    pub requirement: String,
    /// The revision an assertion for this requirement carries. It covers this
    /// requirement's own configuration and artifact closure, so pinning it does
    /// not couple a relying procedure to the rest of the deployment.
    pub configuration_revision: String,
    pub kind: DefinitionKind,
    /// What the subject bindings in this requirement's assertions are derived
    /// under. Absent means audience-scoped, the mode every requirement already
    /// had, so a document served before binding modes existed still parses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_binding_mode: Option<SubjectBindingMode>,
    pub evidence_type: String,
    pub purpose: String,
    pub reference_frameworks: Vec<String>,
    pub subjects: Vec<DefinitionSubject>,
    pub concepts: Vec<DefinitionConcept>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefinitionKind {
    Criterion,
    InformationRequirement,
    Constraint,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionSubject {
    pub role: String,
    pub cardinality: DefinitionCardinality,
    pub selector: DefinitionSelector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefinitionCardinality {
    One,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefinitionSelector {
    pub profile: String,
    pub value_origin: SelectorValueOrigin,
    pub fields: Vec<SelectorField>,
}

/// Where a selector's values come from. Only `Request` values are carried in
/// the request body; the other two are resolved from the authenticated caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectorValueOrigin {
    Request,
    AuthenticatedContext,
    AuthenticatedGrant,
}

/// Public validation metadata for one selector field.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SelectorField {
    String {
        name: String,
        #[serde(rename = "minimumBytes")]
        minimum_bytes: u64,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: u64,
    },
    Date {
        name: String,
    },
    Integer {
        name: String,
        minimum: i64,
        maximum: i64,
    },
    Boolean {
        name: String,
    },
    ControlledCode {
        name: String,
        scheme: String,
        version: String,
        #[serde(rename = "maximumBytes")]
        maximum_bytes: u64,
    },
}

impl SelectorField {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::String { name, .. }
            | Self::Date { name }
            | Self::Integer { name, .. }
            | Self::Boolean { name }
            | Self::ControlledCode { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefinitionConcept {
    pub id: String,
    pub form: ConceptForm,
}

impl DefinitionConcept {
    /// The verification expectation for a concept whose declared form is a
    /// scalar. Returns `None` for the two collection forms, whose expectation
    /// needs the cardinality the relying procedure states.
    #[must_use]
    pub fn scalar_expected_output(&self) -> Option<ExpectedOutputDocument> {
        self.form.scalar_form().map(|form| ExpectedOutputDocument {
            concept: self.id.clone(),
            form: ExpectedFormDocument::Scalar(form),
        })
    }

    /// The verification expectation for a concept whose declared form is a
    /// collection. The bounds come from the relying procedure, not from
    /// discovery, which does not publish them.
    #[must_use]
    pub fn list_expected_output(
        &self,
        minimum_items: usize,
        maximum_items: usize,
    ) -> Option<ExpectedOutputDocument> {
        self.form.is_list().then(|| ExpectedOutputDocument {
            concept: self.id.clone(),
            form: ExpectedFormDocument::List(ExpectedListFormDocument {
                list: ExpectedListDocument {
                    minimum_items,
                    maximum_items,
                },
            }),
        })
    }
}

/// The declared public form of one concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConceptForm {
    Boolean,
    ControlledCode,
    ControlledCategory,
    BoundedInteger,
    BoundedDecimal,
    DateBucket,
    TimeBucket,
    AudienceScopedEntityReference,
    ControlledCodeList,
    EntityReferenceList,
    ReviewedStructuredValue,
}

impl ConceptForm {
    /// The published value form each declared concept form takes on the wire.
    ///
    /// The mapping is stated by `products/evidence/contracts/`
    /// `supported-value-forms.yaml`. A bounded decimal is a JSON string
    /// carrying canonical decimal text, so its expected form is a string.
    #[must_use]
    pub fn scalar_form(self) -> Option<ExpectedScalarFormDocument> {
        match self {
            Self::Boolean => Some(ExpectedScalarFormDocument::Boolean),
            Self::ControlledCode | Self::ControlledCategory | Self::BoundedDecimal => {
                Some(ExpectedScalarFormDocument::String)
            }
            Self::BoundedInteger => Some(ExpectedScalarFormDocument::Integer),
            Self::DateBucket => Some(ExpectedScalarFormDocument::DateBucket),
            Self::TimeBucket => Some(ExpectedScalarFormDocument::TimeBucket),
            Self::AudienceScopedEntityReference => {
                Some(ExpectedScalarFormDocument::EntityReference)
            }
            Self::ReviewedStructuredValue => Some(ExpectedScalarFormDocument::Structured),
            Self::ControlledCodeList | Self::EntityReferenceList => None,
        }
    }

    #[must_use]
    pub fn is_list(self) -> bool {
        matches!(self, Self::ControlledCodeList | Self::EntityReferenceList)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &str = r#"{
      "schema": "registry.evidence-definitions/v1",
      "assuranceProfile": "local",
      "issuedBy": "urn:example:client:issuer",
      "providedBy": "urn:example:client:provider",
      "holderBoundBatchMaxSize": 4,
      "definitions": [
        {
          "requirement": "urn:example:client:requirement:status:v1",
          "configurationRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
          "kind": "criterion",
          "evidenceType": "urn:example:client:evidence-type:status:v1",
          "purpose": "example-decision",
          "referenceFrameworks": ["urn:example:client:framework:status:v1"],
          "subjects": [
            {
              "role": "subject",
              "cardinality": "one",
              "selector": {
                "profile": "record-lookup-v1",
                "valueOrigin": "request",
                "fields": [
                  {"type": "string", "name": "record_reference", "minimumBytes": 1, "maximumBytes": 200},
                  {"type": "date", "name": "recorded_on"},
                  {"type": "integer", "name": "sequence", "minimum": 0, "maximum": 10},
                  {"type": "boolean", "name": "confirmed"},
                  {"type": "controlled-code", "name": "office", "scheme": "urn:example:client:scheme:office", "version": "1", "maximumBytes": 32}
                ]
              }
            }
          ],
          "concepts": [{"id": "urn:example:client:concept:status-holds", "form": "boolean"}]
        }
      ]
    }"#;

    fn document() -> EvidenceDefinitionsDocument {
        serde_json::from_str(DOCUMENT).expect("the discovery document parses")
    }

    #[test]
    fn the_discovery_document_parses_into_closed_types() {
        let document = document();
        assert_eq!(document.schema, EVIDENCE_DEFINITIONS_SCHEMA_V1);
        assert_eq!(document.assurance_profile, AssuranceProfile::Local);
        assert_eq!(document.holder_bound_batch_max_size, 4);
        let definition = document
            .definition("urn:example:client:requirement:status:v1")
            .expect("the requirement is present");
        assert_eq!(definition.kind, DefinitionKind::Criterion);
        assert_eq!(
            definition.subjects[0].cardinality,
            DefinitionCardinality::One
        );
        assert_eq!(
            definition.subjects[0].selector.value_origin,
            SelectorValueOrigin::Request
        );
        assert_eq!(
            definition.subjects[0]
                .selector
                .fields
                .iter()
                .map(SelectorField::name)
                .collect::<Vec<_>>(),
            [
                "record_reference",
                "recorded_on",
                "sequence",
                "confirmed",
                "office"
            ]
        );
        assert!(document
            .definition("urn:example:client:requirement:absent")
            .is_none());
    }

    #[test]
    fn a_requirement_with_two_authorized_shapes_yields_no_single_definition() {
        // A deployment keys its discovery candidates on requirement, purpose,
        // and selector profile together, so one requirement can carry several
        // authorized shapes. Answering with whichever happened to serialize
        // first would have the relying party author a request, and close a
        // verification policy, for a purpose it never chose, and verification
        // would pass because the deployment did issue for that purpose.
        let mut document = document();
        let mut other_purpose = document.definitions[0].clone();
        other_purpose.purpose = "other-decision".to_owned();
        document.definitions.push(other_purpose);
        // Two shapes of one requirement are distinct items, so the definitions
        // contract's `uniqueItems` does not stop a deployment sending this.
        let round_tripped: EvidenceDefinitionsDocument = serde_json::from_str(
            &serde_json::to_string(&document).expect("the two shape document serializes"),
        )
        .expect("the two shape document parses");
        assert_eq!(round_tripped.definitions.len(), 2);
        assert!(round_tripped
            .definition("urn:example:client:requirement:status:v1")
            .is_none());
        // The entries stay visible, so a caller that wants to disambiguate on
        // purpose or selector profile still can.
        assert!(round_tripped
            .definitions
            .iter()
            .any(|definition| definition.purpose == "other-decision"));
    }

    #[test]
    fn each_definition_carries_its_own_configuration_revision() {
        // A deployment serves several requirements from one bundle and each
        // publishes the revision its own assertions carry. A relying procedure
        // that pinned a document-level value would break whenever an unrelated
        // requirement's configuration changed, so the field lives here.
        let mut document = document();
        let mut other_requirement = document.definitions[0].clone();
        other_requirement.requirement = "urn:example:client:requirement:other:v1".to_owned();
        other_requirement.configuration_revision = format!("sha256:{}", "1".repeat(64));
        document.definitions.push(other_requirement);
        let round_tripped: EvidenceDefinitionsDocument = serde_json::from_str(
            &serde_json::to_string(&document).expect("the two requirement document serializes"),
        )
        .expect("the two requirement document parses");
        assert_eq!(
            round_tripped
                .definition("urn:example:client:requirement:status:v1")
                .expect("the first requirement is present")
                .configuration_revision,
            format!("sha256:{}", "0".repeat(64))
        );
        assert_eq!(
            round_tripped
                .definition("urn:example:client:requirement:other:v1")
                .expect("the second requirement is present")
                .configuration_revision,
            format!("sha256:{}", "1".repeat(64))
        );
    }

    #[test]
    fn a_document_level_configuration_revision_is_refused() {
        // The revision moved from the document to each definition. A deployment
        // still publishing it at the document level would have a relying party
        // pin a value no assertion carries, so the closed type refuses it
        // rather than ignoring it.
        let document_level = DOCUMENT.replace(
            r#""assuranceProfile": "local","#,
            r#""assuranceProfile": "local", "configurationRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000","#,
        );
        assert!(serde_json::from_str::<EvidenceDefinitionsDocument>(&document_level).is_err());
    }

    #[test]
    fn a_definition_without_the_binding_mode_key_deserializes_to_no_mode() {
        // Absence means audience-scoped, and a definitions document served
        // before binding modes existed carries no such key at all, so this
        // must parse rather than fail.
        let definition = &document().definitions[0];
        assert_eq!(definition.subject_binding_mode, None);
    }

    #[test]
    fn a_definition_with_the_holder_bound_key_deserializes_to_the_holder_bound_mode() {
        let holder_bound = DOCUMENT.replace(
            r#""kind": "criterion","#,
            r#""kind": "criterion", "subjectBindingMode": "holder-bound","#,
        );
        assert_ne!(holder_bound, DOCUMENT, "the binding mode rewrite applies");
        let document: EvidenceDefinitionsDocument =
            serde_json::from_str(&holder_bound).expect("the holder-bound document parses");
        assert_eq!(
            document.definitions[0].subject_binding_mode,
            Some(SubjectBindingMode::HolderBound)
        );
    }

    #[test]
    fn an_audience_scoped_definition_reserializes_without_the_binding_mode_key() {
        // Absence is the audience-scoped mode, so re-emitting the key as an
        // explicit null would publish a shape the definitions contract does not
        // describe, and would hand a relying party a value to resolve where the
        // deployment stated none.
        let value =
            serde_json::to_value(&document().definitions[0]).expect("the definition serializes");
        assert!(!value
            .as_object()
            .expect("a definition serializes as an object")
            .contains_key("subjectBindingMode"));
    }

    #[test]
    fn an_undeclared_member_is_refused() {
        let extended = DOCUMENT.replace(
            r#""schema": "registry.evidence-definitions/v1","#,
            r#""schema": "registry.evidence-definitions/v1", "sourcePlan": "leaked","#,
        );
        assert!(serde_json::from_str::<EvidenceDefinitionsDocument>(&extended).is_err());
    }

    #[test]
    fn every_scalar_concept_form_maps_to_one_expected_value_form() {
        let cases = [
            (ConceptForm::Boolean, ExpectedScalarFormDocument::Boolean),
            (
                ConceptForm::ControlledCode,
                ExpectedScalarFormDocument::String,
            ),
            (
                ConceptForm::ControlledCategory,
                ExpectedScalarFormDocument::String,
            ),
            (
                ConceptForm::BoundedDecimal,
                ExpectedScalarFormDocument::String,
            ),
            (
                ConceptForm::BoundedInteger,
                ExpectedScalarFormDocument::Integer,
            ),
            (
                ConceptForm::DateBucket,
                ExpectedScalarFormDocument::DateBucket,
            ),
            (
                ConceptForm::TimeBucket,
                ExpectedScalarFormDocument::TimeBucket,
            ),
            (
                ConceptForm::AudienceScopedEntityReference,
                ExpectedScalarFormDocument::EntityReference,
            ),
            (
                ConceptForm::ReviewedStructuredValue,
                ExpectedScalarFormDocument::Structured,
            ),
        ];
        for (form, expected) in cases {
            let concept = DefinitionConcept {
                id: "urn:example:client:concept:one".to_owned(),
                form,
            };
            let output = concept
                .scalar_expected_output()
                .expect("a scalar form has a scalar expectation");
            // The verification policy types carry no equality, so the wire
            // form they serialize to is what these tests compare.
            assert_eq!(
                serde_json::to_value(&output.form).expect("the form serializes"),
                serde_json::to_value(ExpectedFormDocument::Scalar(expected))
                    .expect("the form serializes")
            );
            assert!(concept.list_expected_output(1, 2).is_none());
        }
    }

    #[test]
    fn a_collection_concept_form_needs_caller_supplied_bounds() {
        for form in [
            ConceptForm::ControlledCodeList,
            ConceptForm::EntityReferenceList,
        ] {
            let concept = DefinitionConcept {
                id: "urn:example:client:concept:many".to_owned(),
                form,
            };
            assert!(concept.scalar_expected_output().is_none());
            let output = concept
                .list_expected_output(1, 4)
                .expect("a collection form has a collection expectation");
            assert_eq!(
                serde_json::to_value(&output.form).expect("the form serializes"),
                serde_json::json!({"list": {"minimumItems": 1, "maximumItems": 4}})
            );
        }
    }
}
