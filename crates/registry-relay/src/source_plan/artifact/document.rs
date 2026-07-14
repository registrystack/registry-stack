//! Closed artifact document schemas and validated artifact wrappers.

use super::*;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct ArtifactReferenceDocument {
    pub(in super::super) id: String,
    pub(in super::super) version: String,
    pub(in super::super) hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct UnhashedArtifactReferenceDocument {
    pub(in super::super) id: String,
    pub(in super::super) version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct IntegrationReferenceDocument {
    pub(in super::super) id: String,
    pub(in super::super) revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum SubjectModeDocument {
    SingleSubject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum SelectorProvenanceDocument {
    TrustedNotaryAssertion {
        assertion_contract: HashReferenceDocument,
    },
    WorkloadSelected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct HashReferenceDocument {
    pub(in super::super) id: String,
    pub(in super::super) hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct SubjectDocument {
    pub(in super::super) mode: SubjectModeDocument,
    pub(in super::super) selector_provenance: SelectorProvenanceDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum InputRoleDocument {
    Selector,
    Parameter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum InputScalarTypeDocument {
    String,
    Boolean,
    Integer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum InputTypeMemberDocument {
    String,
    Boolean,
    Integer,
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(in super::super) enum InputSchemaTypeDocument {
    Scalar(InputScalarTypeDocument),
    Nullable(Vec<InputTypeMemberDocument>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum InputStringFormatDocument {
    Date,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) enum InputTypeDocument {
    String,
    FullDate,
    Boolean,
    Integer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum CanonicalizationDocument {
    Identity,
    AsciiLowercase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct InputDocument {
    pub(in super::super) role: InputRoleDocument,
    #[serde(rename = "type")]
    pub(in super::super) schema_type: InputSchemaTypeDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) format: Option<InputStringFormatDocument>,
    #[serde(rename = "maxLength", default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_length: Option<u32>,
    #[serde(rename = "minLength", default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) min_length: Option<u32>,
    #[serde(
        rename = "x-registry-max-bytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(in super::super) max_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) pattern: Option<String>,
    #[serde(rename = "x-registry-canonicalization")]
    pub(in super::super) canonicalization: CanonicalizationDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) maximum: Option<i64>,
    #[serde(rename = "enum", default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) allowed_values: Vec<serde_json::Value>,
    #[serde(rename = "const", default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) constant: Option<serde_json::Value>,
}

impl InputDocument {
    pub(in crate::source_plan) fn resolved_type(&self) -> Option<(InputTypeDocument, bool)> {
        let (scalar, nullable) = match &self.schema_type {
            InputSchemaTypeDocument::Scalar(scalar) => (*scalar, false),
            InputSchemaTypeDocument::Nullable(members) => {
                if members.len() != 2
                    || members
                        .iter()
                        .filter(|member| **member == InputTypeMemberDocument::Null)
                        .count()
                        != 1
                {
                    return None;
                }
                let scalar = members.iter().find_map(|member| match member {
                    InputTypeMemberDocument::String => Some(InputScalarTypeDocument::String),
                    InputTypeMemberDocument::Boolean => Some(InputScalarTypeDocument::Boolean),
                    InputTypeMemberDocument::Integer => Some(InputScalarTypeDocument::Integer),
                    InputTypeMemberDocument::Null => None,
                })?;
                (scalar, true)
            }
        };
        let input_type = match (scalar, self.format) {
            (InputScalarTypeDocument::String, None) => InputTypeDocument::String,
            (InputScalarTypeDocument::String, Some(InputStringFormatDocument::Date)) => {
                InputTypeDocument::FullDate
            }
            (InputScalarTypeDocument::Boolean, None) => InputTypeDocument::Boolean,
            (InputScalarTypeDocument::Integer, None) => InputTypeDocument::Integer,
            (InputScalarTypeDocument::Boolean | InputScalarTypeDocument::Integer, Some(_)) => {
                return None;
            }
        };
        Some((input_type, nullable))
    }

    pub(in crate::source_plan) fn canonical_max_bytes(&self) -> Option<u32> {
        let (input_type, nullable) = self.resolved_type()?;
        let scalar = match input_type {
            InputTypeDocument::String | InputTypeDocument::FullDate => self.max_bytes?,
            InputTypeDocument::Boolean => 5,
            InputTypeDocument::Integer => self
                .minimum
                .into_iter()
                .chain(self.maximum)
                .map(|value| value.to_string().len())
                .max()
                .and_then(|bytes| u32::try_from(bytes).ok())?,
        };
        Some(if nullable { scalar.max(4) } else { scalar })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum AcquisitionClassDocument {
    SourceProjectedExact,
    BoundedFullRecord,
    MaterializedSnapshot,
}

impl From<AcquisitionClassDocument> for AcquisitionClass {
    fn from(value: AcquisitionClassDocument) -> Self {
        match value {
            AcquisitionClassDocument::SourceProjectedExact => Self::SourceProjectedExact,
            AcquisitionClassDocument::BoundedFullRecord => Self::BoundedFullRecord,
            AcquisitionClassDocument::MaterializedSnapshot => Self::MaterializedSnapshot,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PublicAcquisitionDocument {
    pub(in super::super) class: AcquisitionClassDocument,
    /// Complete worst-case Relay-visible source schema, including routing controls.
    pub(in super::super) fields: BTreeMap<String, ResponseSchemaDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum SourceObservedAtDocument {
    Absent,
    AcquiredRfc3339 { field: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum SourceRevisionDocument {
    Absent,
    AcquiredString { field: String, max_bytes: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct SourceProvenanceDocument {
    pub(in super::super) source_observed_at: SourceObservedAtDocument,
    pub(in super::super) source_revision: SourceRevisionDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum OutputTypeDocument {
    String,
    Boolean,
    Integer,
    Date,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct OutputFieldDocument {
    #[serde(rename = "type")]
    pub(in super::super) output_type: OutputTypeDocument,
    pub(in super::super) nullable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) maximum: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum ExactSelectorDocument {
    HttpExactAnd {
        operation: String,
        components: BTreeMap<String, RequestSelectorLocationDocument>,
    },
    SnapshotExactAnd {
        components: BTreeMap<String, SnapshotSelectorLocationDocument>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum SnapshotSelectorLocationDocument {
    SnapshotKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum CodecSelectorRoleDocument {
    DciIdtypeValue,
    DciExactPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum RequestSelectorLocationDocument {
    Query { parameter: String },
    Path { parameter: String },
    Body { pointer: String },
    Codec { role: CodecSelectorRoleDocument },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct RelationSelectorDocument {
    pub(in super::super) step: String,
    pub(in super::super) output: String,
    pub(in super::super) location: RequestSelectorLocationDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum ReviewedCardinalityDocument {
    SourceEnforcedSingleton,
    ProbeTwo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum ResponseSchemaDocument {
    /// A script-visible response body constrained by the response byte limit
    /// and the host's recursive JSON/text decoder limits, but not by a
    /// product-shaped closed schema.
    ScriptBody,
    Object {
        nullable: bool,
        reject_unknown_fields: bool,
        fields: BTreeMap<String, ResponseSchemaFieldDocument>,
    },
    Array {
        nullable: bool,
        max_items: u16,
        items: Box<ResponseSchemaDocument>,
    },
    String {
        nullable: bool,
        max_bytes: u32,
    },
    Boolean {
        nullable: bool,
    },
    Integer {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
    Number {
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
}

impl ResponseSchemaDocument {
    pub(super) fn validates_public_output(&self, output: &OutputFieldDocument) -> bool {
        match (self, &output.output_type) {
            (
                Self::String { nullable, .. },
                OutputTypeDocument::String | OutputTypeDocument::Date,
            )
            | (Self::Boolean { nullable }, OutputTypeDocument::Boolean)
            | (Self::Integer { nullable, .. }, OutputTypeDocument::Integer) => {
                *nullable == output.nullable
            }
            _ => false,
        }
    }

    pub(super) fn matches_response_schema(&self, schema: &Self) -> bool {
        self == schema
    }

    /// Compares the selected field shape while deliberately ignoring whether
    /// the raw source object permits additional, unselected members. Retained
    /// acquisition schemas are validated separately as closed objects.
    pub(super) fn matches_selected_shape(&self, selected: &Self) -> bool {
        match (self, selected) {
            (
                Self::Object {
                    nullable: raw_nullable,
                    fields: raw_fields,
                    ..
                },
                Self::Object {
                    nullable: selected_nullable,
                    fields: selected_fields,
                    ..
                },
            ) => {
                raw_nullable == selected_nullable
                    && raw_fields.len() == selected_fields.len()
                    && raw_fields.iter().all(|(name, raw)| {
                        selected_fields.get(name).is_some_and(|selected| {
                            raw.required == selected.required
                                && raw.schema.matches_selected_shape(&selected.schema)
                        })
                    })
            }
            (
                Self::Array {
                    nullable: raw_nullable,
                    max_items: raw_max_items,
                    items: raw_items,
                },
                Self::Array {
                    nullable: selected_nullable,
                    max_items: selected_max_items,
                    items: selected_items,
                },
            ) => {
                raw_nullable == selected_nullable
                    && raw_max_items == selected_max_items
                    && raw_items.matches_selected_shape(selected_items)
            }
            _ => self == selected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct ResponseSchemaFieldDocument {
    pub(in super::super) required: bool,
    pub(in super::super) schema: Box<ResponseSchemaDocument>,
}

impl ReviewedCardinalityDocument {
    pub(super) const fn cardinality(&self) -> SourceCardinality {
        match self {
            Self::SourceEnforcedSingleton => SourceCardinality::Singleton,
            Self::ProbeTwo => SourceCardinality::AmbiguityProbe,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PackAcquisitionDocument {
    pub(in super::super) class: AcquisitionClassDocument,
    pub(in super::super) fields: BTreeMap<String, ResponseSchemaDocument>,
    pub(in super::super) control_fields: BTreeMap<String, ResponseSchemaDocument>,
    pub(in super::super) selector: Option<ExactSelectorDocument>,
    pub(in super::super) cardinality: ReviewedCardinalityDocument,
    pub(in super::super) reject_unknown_fields: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct LimitsDocument {
    pub(in super::super) max_source_matches: u8,
    pub(in super::super) max_disclosed_records: u8,
    pub(in super::super) max_data_exchanges: u8,
    pub(in super::super) max_credential_exchanges: u8,
    pub(in super::super) max_data_destinations: u8,
    pub(in super::super) max_source_bytes: u64,
    pub(in super::super) timeout_ms: u32,
    pub(in super::super) max_in_flight: u16,
    pub(in super::super) quota_per_minute: u32,
    pub(in super::super) quota_burst: u16,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct BindingLimitsDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_source_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_in_flight: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) quota_per_minute: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) quota_burst: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_public_response_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_token_lifetime_ms: Option<u32>,
}

impl LimitsDocument {
    pub(in super::super) fn validate_for_acquisition(
        self,
        acquisition: AcquisitionClassDocument,
    ) -> Result<Self, SourcePlanArtifactError> {
        let transport_bounds_valid = match acquisition {
            AcquisitionClassDocument::SourceProjectedExact
            | AcquisitionClassDocument::BoundedFullRecord => {
                (1..=16).contains(&self.max_data_exchanges)
                    && self.max_credential_exchanges <= 1
                    && self.max_data_destinations == 1
            }
            AcquisitionClassDocument::MaterializedSnapshot => {
                self.max_data_exchanges == 0
                    && self.max_credential_exchanges == 0
                    && self.max_data_destinations == 0
            }
        };
        let valid = (1..=2).contains(&self.max_source_matches)
            && self.max_disclosed_records == 1
            && transport_bounds_valid
            && (1..=16 * 1024 * 1024).contains(&self.max_source_bytes)
            && (1..=60_000).contains(&self.timeout_ms)
            && (1..=MAX_IN_FLIGHT).contains(&self.max_in_flight)
            && (1..=MAX_QUOTA_PER_MINUTE).contains(&self.quota_per_minute)
            && (1..=MAX_QUOTA_BURST).contains(&self.quota_burst)
            && u32::from(self.quota_burst) <= self.quota_per_minute;
        valid
            .then_some(self)
            .ok_or(SourcePlanArtifactError::InvalidLimits)
    }

    pub(in super::super) const fn operation_bounds(self) -> OperationBounds {
        OperationBounds {
            max_source_matches: self.max_source_matches,
            max_disclosed_records: self.max_disclosed_records,
            max_data_exchanges: self.max_data_exchanges,
            max_credential_exchanges: self.max_credential_exchanges,
            max_data_destinations: self.max_data_destinations,
            max_source_bytes: self.max_source_bytes,
            timeout_ms: self.timeout_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum PolicyCacheDocument {
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum UnavailableDocument {
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PolicyDocument {
    pub(in super::super) id: String,
    pub(in super::super) hash: String,
    pub(in super::super) decision_cache: PolicyCacheDocument,
    pub(in super::super) max_decision_age_ms: u32,
    pub(in super::super) unavailable: UnavailableDocument,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum ConsentRevocationDocument {
    OnlineRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct ConsentDocument {
    pub(in super::super) required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) verifier: Option<HashReferenceDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_age_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) revocation: Option<ConsentRevocationDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) unavailable: Option<UnavailableDocument>,
}

/// V1 accepts no conditional policy obligations.
///
/// An uninhabited element type makes the required sequence structurally
/// capable of representing only `[]`. Any non-empty or unknown element fails
/// strict deserialization before the public contract can be compiled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum MandatoryObligationDocument {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct AuthorizationDocument {
    pub(in super::super) workload: String,
    pub(in super::super) required_scope: String,
    pub(in super::super) purposes: Vec<String>,
    pub(in super::super) legal_basis: String,
    pub(in super::super) policy: PolicyDocument,
    pub(in super::super) consent: ConsentDocument,
    pub(in super::super) mandatory_obligations: Vec<MandatoryObligationDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum OutcomeDocument {
    Match,
    NoMatch,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PublicBehaviorDocument {
    pub(in super::super) outcomes: Vec<OutcomeDocument>,
    pub(in super::super) denial_code: String,
    pub(in super::super) denial_timing_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum MaterializationStaleBehaviorDocument {
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum MaterializationRefreshClassDocument {
    OperatorTriggered,
    Scheduled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct MaterializationFootprintDocument {
    pub(in super::super) fields: Vec<String>,
    pub(in super::super) max_source_records: u64,
    pub(in super::super) max_source_bytes: u64,
    pub(in super::super) max_data_exchanges: u8,
    pub(in super::super) max_credential_exchanges: u8,
    pub(in super::super) max_data_destinations: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct MaterializationContractDocument {
    pub(in super::super) max_snapshot_age_ms: u64,
    pub(in super::super) stale_behavior: MaterializationStaleBehaviorDocument,
    pub(in super::super) footprint: MaterializationFootprintDocument,
    pub(in super::super) refresh_class: MaterializationRefreshClassDocument,
    pub(in super::super) snapshot_retention_generations: u16,
    pub(in super::super) immutable_generation: bool,
    pub(in super::super) digest_bound_active_pointer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum SourceCapabilityDocument {
    Http,
    Script,
    Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct RuntimeRequirementsDocument {
    pub(in super::super) platform_profile: String,
    pub(in super::super) source_capability: SourceCapabilityDocument,
    pub(in super::super) script_abi: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PublicContractSpecDocument {
    pub(in super::super) runtime: RuntimeRequirementsDocument,
    pub(in super::super) subject: SubjectDocument,
    pub(in super::super) inputs: BTreeMap<String, InputDocument>,
    pub(in super::super) integration: IntegrationReferenceDocument,
    pub(in super::super) acquisition: PublicAcquisitionDocument,
    pub(in super::super) source_provenance: SourceProvenanceDocument,
    pub(in super::super) output: BTreeMap<String, OutputFieldDocument>,
    pub(in super::super) authorization: AuthorizationDocument,
    pub(in super::super) bounds: LimitsDocument,
    pub(in super::super) public_behavior: PublicBehaviorDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) materialization: Option<MaterializationContractDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PublicContractDocument {
    pub(in super::super) schema: String,
    pub(in super::super) id: String,
    pub(in super::super) version: String,
    pub(in super::super) spec: PublicContractSpecDocument,
}

/// A validated typed public contract and its exact RFC 8785 identity.
pub struct PublicContractArtifact {
    pub(in super::super) document: PublicContractDocument,
    pub(super) identity: ProfileIdentity,
    pub(in super::super) integration_id: IntegrationPackId,
    pub(in super::super) integration_revision: ProfileVersion,
    pub(in super::super) acquisition_class: AcquisitionClass,
    pub(in super::super) acquired_fields: BTreeSet<AcquiredField>,
    pub(in super::super) cardinality: SourceCardinality,
    pub(in super::super) public_limits: LimitsDocument,
    pub(in super::super) workload_id: WorkloadId,
    pub(in super::super) required_scope: RequiredConsultationScope,
    pub(in super::super) policy_identity: PolicyIdentity,
    pub(in super::super) consent_verifier: Option<(OperationId, IntegrationPackHash)>,
    pub(in super::super) selector_provenance: SelectorProvenance,
    pub(in super::super) purposes: Box<[CanonicalPurpose]>,
    pub(in super::super) legal_basis: LegalBasisId,
    pub(super) canonical_json: Box<[u8]>,
}

impl fmt::Debug for PublicContractArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicContractArtifact")
            .field("identity", &self.identity)
            .field("integration_id", &self.integration_id)
            .field("integration_revision", &self.integration_revision)
            .finish_non_exhaustive()
    }
}

impl PublicContractArtifact {
    /// Return the id, version, and computed public contract hash.
    #[must_use]
    pub const fn identity(&self) -> &ProfileIdentity {
        &self.identity
    }

    /// Return the product-neutral integration id declared by the public contract.
    #[must_use]
    pub const fn integration_id(&self) -> &IntegrationPackId {
        &self.integration_id
    }

    /// Return the semantic integration revision declared by the public contract.
    #[must_use]
    pub const fn integration_revision(&self) -> ProfileVersion {
        self.integration_revision
    }

    /// Return exactly the canonical JSON form of the typed public contract.
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct ParameterDeclarationDocument {
    pub(in super::super) allowed_values: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum ValueExpressionDocument {
    Literal { value: String },
    ConsultationInput { name: String },
    DeploymentParameter { name: String },
    PriorStepOutput { step: String, output: String },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum BodyTemplateDocument {
    Null,
    Boolean {
        value: bool,
    },
    Integer {
        value: i64,
    },
    StringLiteral {
        value: String,
    },
    Expression {
        value: ValueExpressionDocument,
    },
    Array {
        items: Vec<BodyTemplateDocument>,
    },
    Object {
        fields: BTreeMap<String, BodyTemplateDocument>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum ResponseNormalizationDocument {
    ScriptBody,
    #[serde(rename = "json_object")]
    Object,
    #[serde(rename = "json_array_probe_two")]
    ArrayProbeTwo,
    #[serde(rename = "json_object_array_probe_two")]
    ObjectArrayProbeTwo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum RequestCodecDocument {
    None,
    Json,
    DciExactV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum ResponseVerifierDocument {
    DciJwsV1,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct DciExactDocument {
    pub(in super::super) protocol_version: String,
    pub(in super::super) sender_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) receiver_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) registry_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) registry_event_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) record_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) identifier_type: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in super::super) exact_and: BTreeMap<String, DciExactPredicateDocument>,
    pub(in super::super) locale: String,
    pub(in super::super) page_number: u16,
    pub(in super::super) jwks_operation: String,
    pub(in super::super) response_verifier: ResponseVerifierDocument,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct DciExactPredicateDocument {
    pub(in super::super) field: String,
    pub(in super::super) response_pointer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum VerificationPrimitiveDocument {
    JwksV1,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct VerificationOperationDocument {
    pub(in super::super) id: String,
    pub(in super::super) primitive: VerificationPrimitiveDocument,
    pub(in super::super) destination_slot: String,
    pub(in super::super) method: ReadMethod,
    pub(in super::super) path: String,
    pub(in super::super) step_limits: StepLimitsDocument,
    pub(in super::super) max_response_bytes: u32,
    pub(in super::super) accepted_statuses: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum RequestSignerDocument {
    DciJwsV1,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PriorOutputBindingDocument {
    pub(in super::super) pointer: String,
    #[serde(rename = "type")]
    pub(in super::super) output_type: OutputTypeDocument,
    pub(in super::super) nullable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_bytes: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) minimum: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) maximum: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct StepLimitsDocument {
    pub(in super::super) max_request_bytes: u32,
    pub(in super::super) timeout_ms: u32,
    pub(in super::super) max_in_flight: u16,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum SourceAuthDocument {
    None,
    Basic {
        max_value_bytes: u16,
    },
    StaticBearer {
        max_value_bytes: u16,
    },
    ApiKeyHeader {
        name: String,
        max_value_bytes: u16,
    },
    ApiKeyQuery {
        name: String,
        max_value_bytes: u16,
    },
    #[serde(rename = "oauth_client_credentials")]
    OAuthClientCredentials,
}

impl SourceAuthDocument {
    pub(super) const fn max_value_bytes(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Basic { max_value_bytes }
            | Self::StaticBearer { max_value_bytes }
            | Self::ApiKeyHeader {
                max_value_bytes, ..
            }
            | Self::ApiKeyQuery {
                max_value_bytes, ..
            } => *max_value_bytes as usize,
            Self::OAuthClientCredentials => 0,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mechanism", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum ProjectionMechanismDocument {
    QueryParameterExact {
        parameter: String,
        delimiter: String,
    },
    ReviewedRequestTemplate {
        request_hash: String,
        minimization_evidence: String,
    },
    BoundedFullRecord,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mechanism", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum CardinalityMechanismDocument {
    ScriptManaged,
    DciProbeTwo,
    ProbeQueryParameter {
        parameter: String,
    },
    ProbeBodyInteger {
        pointer: String,
    },
    ReviewedRequestTemplateProbe {
        request_hash: String,
        conformance_evidence: String,
    },
    SourceEnforcedSingleton {
        conformance_evidence: String,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct ResponseDocument {
    #[serde(default, skip_serializing_if = "ResponseFormatDocument::is_json")]
    pub(in super::super) format: ResponseFormatDocument,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) selected_headers: Vec<String>,
    pub(in super::super) max_bytes: u32,
    pub(in super::super) max_records: u8,
    pub(in super::super) normalization: ResponseNormalizationDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) records_field: Option<String>,
    pub(in super::super) cardinality: CardinalityMechanismDocument,
    pub(in super::super) schema: ResponseSchemaDocument,
    pub(in super::super) output_mapping: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in super::super) prior_outputs: BTreeMap<String, PriorOutputBindingDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) accepted_statuses: Vec<u16>,
    #[serde(default, skip_serializing_if = "StatusOutcomesDocument::is_empty")]
    pub(in super::super) status_outcomes: StatusOutcomesDocument,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum ResponseFormatDocument {
    #[default]
    Json,
    Text,
}

impl ResponseFormatDocument {
    const fn is_json(&self) -> bool {
        matches!(self, Self::Json)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct StatusOutcomesDocument {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) no_match: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) ambiguous: Vec<u16>,
}

impl StatusOutcomesDocument {
    fn is_empty(&self) -> bool {
        self.no_match.is_empty() && self.ambiguous.is_empty()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct HttpOperationDocument {
    pub(in super::super) id: String,
    pub(in super::super) method: ReadMethod,
    pub(in super::super) destination_slot: String,
    pub(in super::super) path: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in super::super) path_parameters: BTreeMap<String, ValueExpressionDocument>,
    pub(in super::super) query: BTreeMap<String, ValueExpressionDocument>,
    pub(in super::super) headers: BTreeMap<String, ValueExpressionDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) script_request_headers: Vec<String>,
    pub(in super::super) body: Option<BodyTemplateDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) input_selector: Option<RequestSelectorLocationDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) relation_selector: Option<RelationSelectorDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) request_codec: Option<RequestCodecDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) dci: Option<DciExactDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) request_signer: Option<RequestSignerDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) step_limits: Option<StepLimitsDocument>,
    pub(in super::super) auth: SourceAuthDocument,
    pub(in super::super) acquisition_fields: Vec<String>,
    pub(in super::super) control_fields: Vec<String>,
    pub(in super::super) projection: ProjectionMechanismDocument,
    pub(in super::super) response: ResponseDocument,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct CredentialOperationDocument {
    pub(in super::super) id: String,
    pub(in super::super) kind: CredentialOperationKindDocument,
    pub(in super::super) destination_slot: String,
    pub(in super::super) path: String,
    pub(in super::super) request: OAuth2ClientCredentialsRequestDocument,
    pub(in super::super) response: OAuth2ClientCredentialsResponseDocument,
    pub(in super::super) failure_policy: CredentialFailurePolicyDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum CredentialOperationKindDocument {
    #[serde(rename = "oauth2_client_credentials")]
    OAuth2ClientCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum OAuth2ClientCredentialsRequestFormatDocument {
    JsonClientSecretBody,
    FormClientSecretBody,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct OAuth2ClientCredentialsRequestDocument {
    pub(in super::super) format: OAuth2ClientCredentialsRequestFormatDocument,
    pub(in super::super) max_client_id_bytes: u16,
    pub(in super::super) max_client_secret_bytes: u16,
    pub(in super::super) max_body_bytes: u32,
    pub(in super::super) max_request_bytes: u32,
    pub(in super::super) timeout_ms: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) audience: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) resource: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct OAuth2ClientCredentialsResponseDocument {
    pub(in super::super) max_bytes: u32,
    pub(in super::super) accepted_statuses: Vec<u16>,
    pub(in super::super) schema: OAuth2TokenResponseSchemaDocument,
    pub(in super::super) access_token_max_bytes: u16,
    pub(in super::super) token_type: OAuth2TokenTypeDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) expires_in_min_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) expires_in_max_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_token_lifetime_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) expiry_safety_skew_ms: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "OAuth2TokenCacheModeDocument::is_expiry_bound"
    )]
    pub(in super::super) cache_mode: OAuth2TokenCacheModeDocument,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(in super::super) enum OAuth2TokenTypeDocument {
    Bearer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum OAuth2TokenResponseSchemaDocument {
    StrictAccessTokenBearerExpiresIn,
    StrictAccessTokenBearerNoExpiry,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum OAuth2TokenCacheModeDocument {
    #[default]
    ExpiryBound,
    Disabled,
}

impl OAuth2TokenCacheModeDocument {
    pub(super) const fn is_expiry_bound(&self) -> bool {
        matches!(self, Self::ExpiryBound)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum CredentialFailurePolicyDocument {
    FailClosedSourceUnavailableNoRetryNoStaleNoDataDispatch,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct SnapshotTemplateDocument {
    pub(in super::super) max_snapshot_age_ms: u64,
    pub(in super::super) unavailable: MaterializationStaleBehaviorDocument,
    pub(in super::super) immutable_generation: bool,
}

/// The only physical scalar type accepted by the SnapshotExact key lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum SnapshotPhysicalTypeDocument {
    Utf8,
}

/// The only comparison semantics accepted by the SnapshotExact key lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum SnapshotComparisonDocument {
    BinaryEquality,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct SnapshotExactKeyDocument {
    pub(in super::super) input: String,
    pub(in super::super) physical_field: String,
    pub(in super::super) physical_type: SnapshotPhysicalTypeDocument,
    pub(in super::super) comparison: SnapshotComparisonDocument,
}

/// Reviewed logical-to-physical mapping for one local exact snapshot read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct SnapshotExactMappingDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) key: Option<SnapshotExactKeyDocument>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in super::super) keys: BTreeMap<String, SnapshotExactKeyDocument>,
    pub(in super::super) projection: BTreeMap<String, String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct RhaiTemplateDocument {
    pub(in super::super) script: String,
    pub(in super::super) script_hash: String,
    pub(in super::super) abi: String,
    pub(in super::super) entrypoint: String,
    pub(in super::super) memory_bytes: u64,
    pub(in super::super) cpu_ms: u32,
    pub(in super::super) ipc_frame_bytes: u32,
    pub(in super::super) instructions: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) call_depth: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) string_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) array_items: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) map_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) output_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) concurrency: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum ScriptReadSemanticsDocument {
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct ScriptAllowRuleDocument {
    pub(in super::super) method: ReadMethod,
    pub(in super::super) path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) semantics: Option<ScriptReadSemanticsDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct ScriptResponseDocument {
    pub(in super::super) format: ResponseFormatDocument,
    pub(in super::super) max_bytes: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct ScriptAuthorityDocument {
    pub(in super::super) allow: Vec<ScriptAllowRuleDocument>,
    pub(in super::super) request_headers: Vec<String>,
    pub(in super::super) response_headers: Vec<String>,
    pub(in super::super) response: ScriptResponseDocument,
    pub(in super::super) auth: SourceAuthDocument,
    pub(in super::super) request_max_bytes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) signed_dci: Option<DciExactDocument>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "predicate", rename_all = "snake_case", deny_unknown_fields)]
pub(in super::super) enum StepConditionDocument {
    Exists {
        step: String,
        output: String,
    },
    StringEquals {
        step: String,
        output: String,
        value: String,
    },
    BooleanEquals {
        step: String,
        output: String,
        value: bool,
    },
    IntegerEquals {
        step: String,
        output: String,
        value: i64,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PlanTemplateDocument {
    pub(in super::super) kind: SourcePlanKind,
    pub(in super::super) data_destination_slot: Option<String>,
    pub(in super::super) credential_destination_slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) verification_destination_slot: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) operations: Vec<HttpOperationDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) verification_operations: Vec<VerificationOperationDocument>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) steps: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in super::super) step_conditions: BTreeMap<String, StepConditionDocument>,
    pub(in super::super) credential_operation: Option<CredentialOperationDocument>,
    pub(in super::super) snapshot: Option<SnapshotTemplateDocument>,
    pub(in super::super) rhai: Option<RhaiTemplateDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) script_authority: Option<ScriptAuthorityDocument>,
}

/// Closed evidence classes required for every reviewed integration pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceClass {
    /// Positive source-version and response-shape fixtures.
    Conformance,
    /// Negative cases proving unsafe or over-broad behavior is rejected.
    NegativeSecurity,
    /// Proof that acquisition and disclosure are field-minimized.
    Minimization,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct EvidenceManifestDocument {
    pub(in super::super) conformance: Vec<String>,
    pub(in super::super) negative_security: Vec<String>,
    pub(in super::super) minimization: Vec<String>,
}

impl EvidenceManifestDocument {
    pub(in super::super) fn class_hashes(&self, class: EvidenceClass) -> &[String] {
        match class {
            EvidenceClass::Conformance => &self.conformance,
            EvidenceClass::NegativeSecurity => &self.negative_security,
            EvidenceClass::Minimization => &self.minimization,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct IntegrationPackSpecDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) product_family: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(in super::super) supported_version_evidence: Vec<String>,
    pub(in super::super) logical_operation: String,
    pub(in super::super) input_slots: BTreeMap<String, InputDocument>,
    pub(in super::super) acquisition: PublicAcquisitionDocument,
    pub(in super::super) source_provenance: SourceProvenanceDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) reviewed_acquisition: Option<PackAcquisitionDocument>,
    pub(in super::super) output: BTreeMap<String, OutputFieldDocument>,
    pub(in super::super) plan: PlanTemplateDocument,
    pub(in super::super) bounds: LimitsDocument,
    pub(in super::super) deployment_parameters: BTreeMap<String, ParameterDeclarationDocument>,
    pub(in super::super) evidence: EvidenceManifestDocument,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct IntegrationPackDocument {
    pub(in super::super) schema: String,
    pub(in super::super) id: String,
    pub(in super::super) version: String,
    pub(in super::super) spec: IntegrationPackSpecDocument,
}

/// A validated reviewed integration pack and its exact RFC 8785 identity.
#[derive(Clone)]
pub struct IntegrationPackArtifact {
    pub(in super::super) document: IntegrationPackDocument,
    pub(super) identity: IntegrationPackIdentity,
    pub(in super::super) logical_operation: OperationId,
    pub(super) canonical_json: Box<[u8]>,
}

impl fmt::Debug for IntegrationPackArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IntegrationPackArtifact")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl IntegrationPackArtifact {
    /// Return the reviewed integration-pack identity.
    #[must_use]
    pub const fn identity(&self) -> &IntegrationPackIdentity {
        &self.identity
    }

    /// Return the canonical JSON form used in the pack hash preimage.
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct DestinationDocument {
    pub(in super::super) id: String,
    pub(in super::super) origin: String,
    #[serde(
        default = "root_application_base_path",
        skip_serializing_if = "is_root_application_base_path"
    )]
    pub(in super::super) application_base_path: String,
    #[serde(
        default,
        skip_serializing_if = "DestinationDnsFamilyDocument::is_dual_stack_strict"
    )]
    pub(in super::super) dns_family: DestinationDnsFamilyDocument,
    pub(in super::super) allowed_private_cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) ca: Option<DestinationCaDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) mtls: Option<DestinationMtlsDocument>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct DestinationCaDocument {
    pub(in super::super) file: PathBuf,
    pub(in super::super) generation: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct DestinationMtlsDocument {
    pub(in super::super) certificate_file: PathBuf,
    pub(in super::super) private_key: DestinationSecretReferenceDocument,
    pub(in super::super) generation: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct DestinationSecretReferenceDocument {
    pub(in super::super) secret: String,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum DestinationDnsFamilyDocument {
    #[default]
    DualStackStrict,
    Ipv4Only,
}

impl DestinationDnsFamilyDocument {
    const fn is_dual_stack_strict(&self) -> bool {
        matches!(self, Self::DualStackStrict)
    }
}

fn root_application_base_path() -> String {
    "/".to_owned()
}

fn is_root_application_base_path(path: &String) -> bool {
    path == "/"
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct CredentialBindingDocument {
    #[serde(rename = "ref")]
    pub(in super::super) reference: String,
    pub(in super::super) generation: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct CapabilitiesDocument {
    pub(in super::super) allow_script: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) script: Option<RhaiBindingDocument>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in super::super) enum RhaiIsolationDocument {
    OneShotWorkerV1,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct RhaiBindingDocument {
    pub(in super::super) max_calls: u8,
    pub(in super::super) memory_bytes: u64,
    pub(in super::super) cpu_ms: u32,
    pub(in super::super) ipc_frame_bytes: u32,
    pub(in super::super) instructions: u64,
    pub(in super::super) call_depth: u8,
    pub(in super::super) string_bytes: u32,
    pub(in super::super) array_items: u32,
    pub(in super::super) map_entries: u32,
    pub(in super::super) output_bytes: u32,
    pub(in super::super) concurrency: u16,
    pub(in super::super) isolation: RhaiIsolationDocument,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct PrivateBindingDocument {
    pub(in super::super) profile: UnhashedArtifactReferenceDocument,
    pub(in super::super) integration_pack: ArtifactReferenceDocument,
    pub(in super::super) tenant: String,
    pub(in super::super) registry_instance: String,
    pub(in super::super) source_instance: String,
    pub(in super::super) data_destination: Option<DestinationDocument>,
    pub(in super::super) credential_destination: Option<DestinationDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) verification_destination: Option<DestinationDocument>,
    pub(in super::super) credential: Option<CredentialBindingDocument>,
    pub(in super::super) deployment_parameters: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) limits: Option<BindingLimitsDocument>,
    pub(in super::super) capabilities: CapabilitiesDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) materialization: Option<MaterializationBindingDocument>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in super::super) struct MaterializationBindingDocument {
    pub(in super::super) table_provider: String,
    pub(in super::super) mapping: SnapshotExactMappingDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_snapshot_age_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_source_records: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_source_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_data_exchanges: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_credential_exchanges: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) max_data_destinations: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(in super::super) snapshot_retention_generations: Option<u16>,
}

/// A validated runtime-private binding.
///
/// This type intentionally implements neither `Debug`, `Clone`, nor
/// serialization. Its private fields prevent topology and credential-reference
/// values from becoming an accidental application-facing configuration API.
pub struct PrivateBindingArtifact {
    pub(in super::super) document: PrivateBindingDocument,
    pub(in super::super) profile_id: ProfileId,
    pub(in super::super) profile_version: ProfileVersion,
    pub(in super::super) pack_identity: IntegrationPackIdentity,
    pub(in super::super) tenant: TenantId,
    pub(in super::super) registry_instance: RegistryInstanceId,
    pub(in super::super) data_destination_id: Option<SourceDestinationId>,
    pub(in super::super) credential_destination_id: Option<SourceDestinationId>,
    pub(in super::super) verification_destination_id: Option<SourceDestinationId>,
    pub(in super::super) credential_reference: Option<CredentialReferenceId>,
    pub(super) hash: PrivateBindingHash,
}

impl PrivateBindingArtifact {
    /// Return the secret-free, domain-separated private binding hash.
    #[must_use]
    pub const fn hash(&self) -> &PrivateBindingHash {
        &self.hash
    }
}
