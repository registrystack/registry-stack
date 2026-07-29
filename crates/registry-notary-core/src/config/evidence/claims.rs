// SPDX-License-Identifier: Apache-2.0
//! Claim definitions, rules, and operation configuration.

use std::borrow::Cow;

use schemars::{Schema, SchemaGenerator};

use super::*;

pub const MAX_CLAIM_DEPENDENCY_NODES_V1: usize = 64;
pub const MAX_CLAIM_DEPENDENCY_EDGES_V1: usize = 256;
pub const MAX_CLAIM_VALUE_STRING_BYTES_V1: u32 = 64 * 1024;
pub const MAX_RELAY_OUTPUT_SCHEMA_DEPTH_V1: usize = 8;
pub const MAX_RELAY_OUTPUT_SCHEMA_NODES_V1: usize = 256;
pub const MAX_RELAY_OUTPUT_EXPANDED_NODES_V1: usize = 4_096;
pub const MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1: usize = 32;
pub const MAX_RELAY_OUTPUT_ARRAY_ITEMS_V1: u16 = 256;
pub const MAX_RELAY_OUTPUT_NAME_BYTES_V1: usize = 128;
pub const MAX_RELAY_OUTPUT_VALUE_BYTES_V1: u32 = 64 * 1024;

// The platform decoder wraps consultation outputs in the Relay result root and
// its closed `outputs` object. The remaining fixed result fields consume 18
// more nodes. Reserving all 20 fixed nodes here ensures an accepted authored
// contract cannot fail later when the complete result decoder is compiled.
const RELAY_OUTPUT_ROOT_DEPTH_V1: usize = 3;
const RELAY_RESULT_ENVELOPE_NODES_V1: usize = 20;

fn default_claim_formats() -> Vec<String> {
    vec![FORMAT_CLAIM_RESULT_JSON.to_string()]
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimDefinition {
    pub id: String,
    pub title: String,
    pub version: String,
    pub subject_type: String,
    /// Sealed provenance choice. This field is intentionally required so an
    /// omitted connection can never turn a registry-backed claim into a
    /// source-free claim.
    pub evidence_mode: ClaimEvidenceMode,
    #[serde(default)]
    pub value: ClaimValueConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<ClaimSemanticConfig>,
    #[serde(default)]
    pub inputs: Vec<ClaimInputConfig>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    /// Caller scopes checked before any registry consultation is dispatched.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    pub rule: RuleConfig,
    #[serde(default)]
    pub operations: ClaimOperationsConfig,
    #[serde(default)]
    pub disclosure: DisclosureConfig,
    /// Omitting this field keeps existing authored claims renderable using the
    /// canonical claim-result representation. An explicitly empty list is
    /// rejected during configuration validation.
    #[serde(default = "default_claim_formats")]
    pub formats: Vec<String>,
    #[serde(default)]
    pub credential_profiles: Vec<String>,
    #[serde(default)]
    pub cccev: Option<CccevConfig>,
    #[serde(default)]
    pub oots: Option<OotsConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimEvidenceMode {
    RegistryBacked {
        consultations: BTreeMap<String, RelayConsultationConfig>,
    },
    SelfAttested,
}

impl<'de> Deserialize<'de> for ClaimEvidenceMode {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        match SealedClaimEvidenceMode::deserialize(deserializer)? {
            SealedClaimEvidenceMode::RegistryBacked { consultations } => {
                Ok(Self::RegistryBacked { consultations })
            }
            SealedClaimEvidenceMode::SelfAttested {} => Ok(Self::SelfAttested),
        }
    }
}

/// The tagged configuration wire contract shared by deserialization and schema generation.
#[derive(Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SealedClaimEvidenceMode {
    RegistryBacked {
        consultations: BTreeMap<String, RelayConsultationConfig>,
    },
    SelfAttested {},
}

impl JsonSchema for ClaimEvidenceMode {
    fn schema_name() -> Cow<'static, str> {
        "ClaimEvidenceMode".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        generator.subschema_for::<SealedClaimEvidenceMode>()
    }
}

impl ClaimEvidenceMode {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::RegistryBacked { .. } => "registry_backed",
            Self::SelfAttested => "self_attested",
        }
    }

    #[must_use]
    pub const fn is_registry_backed(&self) -> bool {
        matches!(self, Self::RegistryBacked { .. })
    }

    #[must_use]
    pub const fn is_self_attested(&self) -> bool {
        matches!(self, Self::SelfAttested)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayConsultationConfig {
    pub profile: RelayConsultationProfileRef,
    #[schemars(with = "BTreeMap<String, schema::RelayConsultationInputSchema>")]
    pub inputs: BTreeMap<String, RelayConsultationInput>,
    /// Complete closed public output schema expected from the pinned profile.
    #[serde(default)]
    pub outputs: BTreeMap<String, RelayOutputContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayConsultationProfileRef {
    pub id: String,
    pub contract_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayOutputContract {
    Boolean {
        #[serde(default)]
        nullable: bool,
    },
    Integer {
        #[serde(default)]
        nullable: bool,
        minimum: i64,
        maximum: i64,
    },
    String {
        #[serde(default)]
        nullable: bool,
        max_bytes: u32,
    },
    Date {
        #[serde(default)]
        nullable: bool,
    },
    Object {
        #[serde(default)]
        nullable: bool,
        max_bytes: u32,
        fields: BTreeMap<String, RelayOutputObjectFieldContract>,
    },
    Array {
        #[serde(default)]
        nullable: bool,
        max_bytes: u32,
        max_items: u16,
        items: Box<RelayOutputContract>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayOutputObjectFieldContract {
    pub required: bool,
    pub schema: Box<RelayOutputContract>,
}

impl RelayOutputContract {
    #[must_use]
    pub const fn nullable(&self) -> bool {
        match self {
            Self::Boolean { nullable }
            | Self::Integer { nullable, .. }
            | Self::String { nullable, .. }
            | Self::Date { nullable }
            | Self::Object { nullable, .. }
            | Self::Array { nullable, .. } => *nullable,
        }
    }

    #[must_use]
    pub const fn value_type(&self) -> &'static str {
        match self {
            Self::Boolean { .. } => "boolean",
            Self::Integer { .. } => "integer",
            Self::String { .. } => "string",
            Self::Date { .. } => "date",
            Self::Object { .. } => "object",
            Self::Array { .. } => "array",
        }
    }

    #[must_use]
    pub const fn is_scalar(&self) -> bool {
        matches!(
            self,
            Self::Boolean { .. } | Self::Integer { .. } | Self::String { .. } | Self::Date { .. }
        )
    }

    /// Validate one exact public Relay value without retaining a serialized
    /// copy or exposing value-bearing error details.
    #[must_use]
    pub fn validates_value(&self, value: &serde_json::Value) -> bool {
        if value.is_null() {
            return self.nullable();
        }
        match (self, value) {
            (Self::Boolean { .. }, serde_json::Value::Bool(_)) => true,
            (
                Self::Integer {
                    minimum, maximum, ..
                },
                serde_json::Value::Number(value),
            ) => exact_json_i64(value).is_some_and(|value| value >= *minimum && value <= *maximum),
            (Self::String { max_bytes, .. }, serde_json::Value::String(value)) => {
                value.len() <= *max_bytes as usize
            }
            (Self::Date { .. }, serde_json::Value::String(value)) => {
                crate::is_rfc3339_full_date(value)
            }
            (
                Self::Object {
                    max_bytes, fields, ..
                },
                serde_json::Value::Object(value),
            ) => {
                serialized_value_fits(value, *max_bytes)
                    && value.keys().all(|name| fields.contains_key(name))
                    && fields.iter().all(|(name, field)| {
                        value
                            .get(name)
                            .is_some_and(|value| field.schema.validates_value(value))
                            || !field.required && !value.contains_key(name)
                    })
            }
            (
                Self::Array {
                    max_bytes,
                    max_items,
                    items,
                    ..
                },
                serde_json::Value::Array(value),
            ) => {
                value.len() <= usize::from(*max_items)
                    && serialized_value_fits(value, *max_bytes)
                    && value.iter().all(|value| items.validates_value(value))
            }
            _ => false,
        }
    }
}

fn exact_json_i64(value: &serde_json::Number) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
}

fn serialized_value_fits<T: ?Sized + Serialize>(value: &T, max_bytes: u32) -> bool {
    struct ByteLimitWriter {
        remaining: usize,
    }

    impl std::io::Write for ByteLimitWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.remaining {
                return Err(std::io::Error::other("serialized value exceeds its bound"));
            }
            self.remaining -= bytes.len();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    serde_json::to_writer(
        ByteLimitWriter {
            remaining: max_bytes as usize,
        },
        value,
    )
    .is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestVariableConfig {
    pub from: String,
    #[serde(rename = "type")]
    pub value_type: RequestVariableType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestVariableType {
    Date,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayConsultationInput {
    TargetId,
    TargetIdentifier(String),
    TargetAttribute(String),
    RequesterId,
    RequesterIdentifier(String),
}

impl RelayConsultationInput {
    #[must_use]
    pub fn request_path(&self) -> &str {
        match self {
            Self::TargetId => "target.id",
            Self::TargetIdentifier(path) => path,
            Self::TargetAttribute(path) => path,
            Self::RequesterId => "request.requester.id",
            Self::RequesterIdentifier(path) => path,
        }
    }

    #[must_use]
    pub fn request_context_path(&self) -> &str {
        self.request_path()
            .strip_prefix("request.")
            .unwrap_or(self.request_path())
    }

    #[must_use]
    pub const fn is_requester_derived(&self) -> bool {
        matches!(self, Self::RequesterId | Self::RequesterIdentifier(_))
    }

    #[must_use]
    pub const fn is_target_derived(&self) -> bool {
        matches!(
            self,
            Self::TargetId | Self::TargetIdentifier(_) | Self::TargetAttribute(_)
        )
    }

    #[must_use]
    pub const fn is_authenticated_target_identifier(&self) -> bool {
        matches!(self, Self::TargetId | Self::TargetIdentifier(_))
    }
}

impl Serialize for RelayConsultationInput {
    fn serialize<Serializer>(
        &self,
        serializer: Serializer,
    ) -> Result<Serializer::Ok, Serializer::Error>
    where
        Serializer: serde::Serializer,
    {
        serializer.serialize_str(self.request_path())
    }
}

impl<'de> Deserialize<'de> for RelayConsultationInput {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        let mapping = String::deserialize(deserializer)?;
        match mapping.as_str() {
            "target.id" => Ok(Self::TargetId),
            "request.requester.id" => Ok(Self::RequesterId),
            _ if mapping
                .strip_prefix("request.target.identifiers.")
                .is_some_and(is_request_identifier_name) =>
            {
                Ok(Self::TargetIdentifier(mapping))
            }
            _ if mapping
                .strip_prefix("request.target.attributes.")
                .is_some_and(is_target_attribute_name) =>
            {
                Ok(Self::TargetAttribute(mapping))
            }
            _ if mapping
                .strip_prefix("request.requester.identifiers.")
                .is_some_and(is_request_identifier_name) =>
            {
                Ok(Self::RequesterIdentifier(mapping))
            }
            _ => Err(serde::de::Error::custom(
                "unsupported consultation input mapping; v1 permits target.id, request.requester.id, request.target.identifiers.<stable-id>, request.target.attributes.<stable-name>, or request.requester.identifiers.<stable-id>",
            )),
        }
    }
}

pub(in crate::config) fn validate_claim_evidence_mode(
    claim: &ClaimDefinition,
    relay_configured: bool,
) -> Result<(), EvidenceConfigError> {
    validate_claim_required_scopes(claim)?;
    match &claim.evidence_mode {
        ClaimEvidenceMode::RegistryBacked { consultations } => {
            if !relay_configured {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed requires evidence.relay",
                );
            }
            if claim.purpose.as_deref().is_none_or(|purpose| {
                purpose.is_empty()
                    || purpose.len() > 256
                    || purpose.contains(',')
                    || purpose
                        .chars()
                        .any(|character| character.is_control() || character.is_whitespace())
            }) {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed requires one explicit bounded purpose token",
                );
            }
            if claim.required_scopes.is_empty() {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed requires required_scopes to contain at least one entry",
                );
            }
            if consultations.len() != 1 {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed requires exactly one named consultation in v1",
                );
            }
            let (consultation_name, consultation) = consultations
                .first_key_value()
                .expect("exactly one consultation was checked above");
            validate_consultation(claim, consultation_name, consultation)?;
            match &claim.rule {
                RuleConfig::ConsultationOutput {
                    consultation: rule_consultation,
                    output,
                } => {
                    if rule_consultation != consultation_name {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed consultation_output rule.consultation must match its consultation name",
                        );
                    }
                    if !is_input_name(output) {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed consultation_output rule.output must be one top-level Relay output name",
                        );
                    }
                    if let Some(output_config) = consultation.outputs.get(output) {
                        if claim.value.value_type != output_config.value_type()
                            || !claim.value.nullable
                        {
                            return invalid_claim_evidence_mode(
                                claim,
                                "registry_backed consultation_output claim value type must match its declared output and remain nullable for no_match",
                            );
                        }
                    } else if consultation.outputs.is_empty() {
                        if claim.value.value_type != "string" {
                            return invalid_claim_evidence_mode(
                                claim,
                                "registry_backed consultation_output claim value.type must be string in v1 unless typed outputs are declared",
                            );
                        }
                    } else {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed consultation_output rule.output must name a declared consultation output",
                        );
                    }
                }
                RuleConfig::ConsultationMatched {
                    consultation: rule_consultation,
                } => {
                    if rule_consultation != consultation_name {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed consultation_matched rule.consultation must match its consultation name",
                        );
                    }
                    if claim.value.value_type != "boolean" {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed consultation_matched claim value.type must be boolean",
                        );
                    }
                }
                RuleConfig::Cel { bindings, .. } => {
                    if consultation.outputs.is_empty() {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed supports only consultation_matched and consultation_output rules in v1 unless a complete typed consultation output schema is declared",
                        );
                    }
                    if !bindings.claims.is_empty() || !bindings.vars.is_empty() {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed CEL receives only its consultation outputs and declared service request variables",
                        );
                    }
                    if !matches!(
                        claim.value.value_type.as_str(),
                        "boolean" | "integer" | "string" | "date"
                    ) {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed CEL result type must be boolean, integer, string, or date; generic Number is not supported",
                        );
                    }
                }
            }
        }
        ClaimEvidenceMode::SelfAttested => match &claim.rule {
            RuleConfig::Cel { .. } => {}
            RuleConfig::ConsultationOutput { .. } | RuleConfig::ConsultationMatched { .. } => {
                return invalid_claim_evidence_mode(
                    claim,
                    "self_attested rules cannot name a Relay consultation",
                );
            }
        },
    }
    Ok(())
}

pub(in crate::config) fn validate_claim_value_config(
    claim: &ClaimDefinition,
) -> Result<(), EvidenceConfigError> {
    let Some(max_bytes) = claim.value.max_bytes else {
        return Ok(());
    };
    if claim.value.value_type != "string" {
        return Err(EvidenceConfigError::InvalidClaimValueConfig {
            claim: claim.id.clone(),
            reason: "value.max_bytes is allowed only when value.type is string".to_string(),
        });
    }
    if !(1..=MAX_CLAIM_VALUE_STRING_BYTES_V1).contains(&max_bytes) {
        return Err(EvidenceConfigError::InvalidClaimValueConfig {
            claim: claim.id.clone(),
            reason: format!(
                "value.max_bytes must be between 1 and {MAX_CLAIM_VALUE_STRING_BYTES_V1}"
            ),
        });
    }
    Ok(())
}

pub(in crate::config) fn validate_self_attested_dependency_modes(
    claims: &[ClaimDefinition],
    delegation: &SubjectAccessDelegationConfig,
) -> Result<(), EvidenceConfigError> {
    for claim in claims
        .iter()
        .filter(|claim| claim.evidence_mode.is_self_attested())
    {
        let mut pending: Vec<&str> = claim.depends_on.iter().map(String::as_str).collect();
        let mut visited = HashSet::new();
        while let Some(dependency_id) = pending.pop() {
            if !visited.insert(dependency_id) {
                continue;
            }
            let Some(dependency) = claims
                .iter()
                .find(|candidate| candidate.id == dependency_id)
            else {
                continue;
            };
            if !dependency.evidence_mode.is_self_attested() {
                let delegated_proof_edge = dependency.evidence_mode.is_registry_backed()
                    && delegation.allowed_relationships.iter().any(|relationship| {
                        relationship.proof_claim == dependency.id
                            && relationship
                                .allowed_claims
                                .iter()
                                .any(|allowed| allowed == &claim.id)
                            && claim
                                .depends_on
                                .iter()
                                .any(|direct| direct == dependency_id)
                    });
                if delegated_proof_edge {
                    continue;
                }
                return invalid_claim_evidence_mode(
                    claim,
                    "self_attested dependency closure may contain only self_attested claims except its configured direct delegated Relay proof",
                );
            }
            pending.extend(dependency.depends_on.iter().map(String::as_str));
        }
    }
    Ok(())
}

pub(in crate::config) fn validate_relay_activation_shape(
    claims: &[ClaimDefinition],
) -> Result<(), EvidenceConfigError> {
    let mut outputs_by_client = BTreeMap::new();
    for claim in claims
        .iter()
        .filter(|claim| claim.evidence_mode.is_registry_backed())
    {
        let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
            unreachable!("registry-backed claims were filtered above");
        };
        let (_, consultation) = consultations
            .first_key_value()
            .expect("individual mode validation requires one consultation");
        let input_name = consultation
            .inputs
            .first_key_value()
            .expect("individual mode validation requires one input")
            .0;
        let client_key = (
            consultation.profile.clone(),
            claim
                .purpose
                .clone()
                .expect("individual mode validation requires one purpose"),
            input_name.clone(),
        );
        let legacy_output = consultation
            .outputs
            .is_empty()
            .then(|| match &claim.rule {
                RuleConfig::ConsultationOutput { output, .. } => Some(output.clone()),
                RuleConfig::ConsultationMatched { .. } => None,
                RuleConfig::Cel { .. } => None,
            })
            .flatten();
        match outputs_by_client.get_mut(&client_key) {
            Some((expected_outputs, expected_legacy_output))
                if expected_outputs != &consultation.outputs =>
            {
                return invalid_claim_evidence_mode(
                    claim,
                    "claims sharing one Relay profile, purpose, and input name must declare one identical result contract",
                );
            }
            Some((_, Some(expected)))
                if legacy_output
                    .as_ref()
                    .is_some_and(|actual| actual != expected) =>
            {
                return invalid_claim_evidence_mode(
                    claim,
                    "legacy claims sharing one Relay profile, purpose, and input name must select one shared string output",
                );
            }
            Some((_, expected @ None)) if legacy_output.is_some() => {
                *expected = legacy_output;
            }
            None => {
                outputs_by_client.insert(client_key, (consultation.outputs.clone(), legacy_output));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

pub(in crate::config) fn validate_claim_dependency_bounds(
    claims: &[ClaimDefinition],
) -> Result<(), EvidenceConfigError> {
    if claims.len() > MAX_CLAIM_DEPENDENCY_NODES_V1 {
        return Err(EvidenceConfigError::ClaimDependencyGraphTooLarge {
            claim: "*".to_string(),
            nodes: claims.len(),
            edges: 0,
        });
    }
    for root in claims {
        let mut pending = vec![root.id.as_str()];
        let mut visited = HashSet::new();
        let mut edges = 0usize;
        while let Some(claim_id) = pending.pop() {
            if !visited.insert(claim_id) {
                continue;
            }
            let Some(claim) = claims.iter().find(|candidate| candidate.id == claim_id) else {
                continue;
            };
            edges = edges.saturating_add(claim.depends_on.len());
            if visited.len() > MAX_CLAIM_DEPENDENCY_NODES_V1
                || edges > MAX_CLAIM_DEPENDENCY_EDGES_V1
            {
                return Err(EvidenceConfigError::ClaimDependencyGraphTooLarge {
                    claim: root.id.clone(),
                    nodes: visited.len(),
                    edges,
                });
            }
            pending.extend(claim.depends_on.iter().map(String::as_str));
        }
    }
    Ok(())
}

fn validate_claim_required_scopes(claim: &ClaimDefinition) -> Result<(), EvidenceConfigError> {
    if claim.required_scopes.len() > 16 {
        return invalid_claim_evidence_mode(
            claim,
            "required_scopes cannot contain more than 16 entries",
        );
    }
    let mut seen = HashSet::new();
    for scope in &claim.required_scopes {
        if scope.is_empty()
            || scope.len() > 128
            || !scope
                .bytes()
                .all(|byte| matches!(byte, b'!' | b'#'..=b'[' | b']'..=b'~'))
        {
            return invalid_claim_evidence_mode(
                claim,
                "required_scopes entries must be bounded OAuth scope tokens",
            );
        }
        if !seen.insert(scope.as_str()) {
            return invalid_claim_evidence_mode(
                claim,
                "required_scopes must not contain duplicate entries",
            );
        }
    }
    Ok(())
}

fn validate_sha256_uri(value: &str) -> Result<(), &'static str> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("must start with sha256:");
    };
    if hex.len() != 64 {
        return Err("must contain 64 lowercase hex characters");
    }
    if !hex
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("must contain only lowercase hex characters");
    }
    Ok(())
}

fn validate_consultation(
    claim: &ClaimDefinition,
    name: &str,
    consultation: &RelayConsultationConfig,
) -> Result<(), EvidenceConfigError> {
    if !is_stable_id(name) {
        return invalid_claim_evidence_mode(
            claim,
            "consultation names must use the bounded Relay stable-id grammar",
        );
    }
    if !is_stable_id(&consultation.profile.id) {
        return invalid_claim_evidence_mode(
            claim,
            "consultation profile.id must match [a-z][a-z0-9._-]{0,95}",
        );
    }
    validate_sha256_uri(&consultation.profile.contract_hash).map_err(|reason| {
        EvidenceConfigError::InvalidClaimEvidenceMode {
            claim: claim.id.clone(),
            reason: format!("consultation profile.contract_hash {reason}"),
        }
    })?;
    if !(1..=16).contains(&consultation.inputs.len()) {
        return invalid_claim_evidence_mode(
            claim,
            "consultation inputs must contain one to sixteen typed request mappings in v1",
        );
    }
    let mut request_paths = BTreeSet::new();
    for (input_name, input) in &consultation.inputs {
        if !is_input_name(input_name) {
            return invalid_claim_evidence_mode(
                claim,
                "consultation input names must match [a-z][a-z0-9_]{0,95}",
            );
        }
        if !request_paths.insert(input.request_path()) {
            return invalid_claim_evidence_mode(
                claim,
                "consultation inputs must map injectively to request context paths",
            );
        }
    }
    if !(1..=MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1).contains(&consultation.outputs.len()) {
        return invalid_claim_evidence_mode(
            claim,
            "consultation outputs must contain one to 32 entries",
        );
    }
    let mut schema_nodes = RELAY_RESULT_ENVELOPE_NODES_V1;
    let mut expanded_nodes = RELAY_RESULT_ENVELOPE_NODES_V1;
    for (output_name, output) in &consultation.outputs {
        if !is_input_name(output_name) || matches!(output_name.as_str(), "matched" | "outcome") {
            return invalid_claim_evidence_mode(
                claim,
                "consultation output names must match [a-z][a-z0-9_]{0,95} and cannot be matched or outcome",
            );
        }
        let expanded = validate_relay_output_schema(
            output,
            RELAY_OUTPUT_ROOT_DEPTH_V1,
            &mut schema_nodes,
        )
        .ok_or_else(|| EvidenceConfigError::InvalidClaimEvidenceMode {
            claim: claim.id.clone(),
            reason: "consultation output schema must be closed and remain within platform depth, field, item, node, name, numeric, and byte bounds".to_string(),
        })?;
        expanded_nodes = expanded_nodes.checked_add(expanded).ok_or_else(|| {
            EvidenceConfigError::InvalidClaimEvidenceMode {
                claim: claim.id.clone(),
                reason: "consultation output schema exceeds the platform expanded-node bound"
                    .to_string(),
            }
        })?;
        if expanded_nodes > MAX_RELAY_OUTPUT_EXPANDED_NODES_V1 {
            return invalid_claim_evidence_mode(
                claim,
                "consultation output schema exceeds the platform expanded-node bound",
            );
        }
    }
    Ok(())
}

fn validate_relay_output_schema(
    schema: &RelayOutputContract,
    depth: usize,
    nodes: &mut usize,
) -> Option<usize> {
    *nodes = nodes.checked_add(1)?;
    if depth > MAX_RELAY_OUTPUT_SCHEMA_DEPTH_V1 || *nodes > MAX_RELAY_OUTPUT_SCHEMA_NODES_V1 {
        return None;
    }
    match schema {
        RelayOutputContract::Boolean { .. } | RelayOutputContract::Date { .. } => Some(1),
        RelayOutputContract::Integer {
            minimum, maximum, ..
        } if valid_json_integer_bounds(*minimum, *maximum) => Some(1),
        RelayOutputContract::String { max_bytes, .. }
            if (1..=MAX_RELAY_OUTPUT_VALUE_BYTES_V1).contains(max_bytes) =>
        {
            Some(1)
        }
        RelayOutputContract::Object {
            max_bytes, fields, ..
        } => {
            if !(1..=MAX_RELAY_OUTPUT_VALUE_BYTES_V1).contains(max_bytes)
                || !(1..=MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1).contains(&fields.len())
            {
                return None;
            }
            let mut expanded = 1_usize;
            for (name, field) in fields {
                if !valid_relay_output_name(name) {
                    return None;
                }
                expanded = expanded.checked_add(validate_relay_output_schema(
                    &field.schema,
                    depth + 1,
                    nodes,
                )?)?;
            }
            Some(expanded)
        }
        RelayOutputContract::Array {
            max_bytes,
            max_items,
            items,
            ..
        } => {
            if !(1..=MAX_RELAY_OUTPUT_VALUE_BYTES_V1).contains(max_bytes)
                || !(1..=MAX_RELAY_OUTPUT_ARRAY_ITEMS_V1).contains(max_items)
            {
                return None;
            }
            validate_relay_output_schema(items, depth + 1, nodes)?
                .checked_mul(usize::from(*max_items))
                .and_then(|expanded| expanded.checked_add(1))
        }
        RelayOutputContract::Integer { .. } | RelayOutputContract::String { .. } => None,
    }
}

fn valid_json_integer_bounds(minimum: i64, maximum: i64) -> bool {
    const MAX_SAFE_INTEGER: i64 = (1_i64 << 53) - 1;
    minimum <= maximum && minimum >= -MAX_SAFE_INTEGER && maximum <= MAX_SAFE_INTEGER
}

fn valid_relay_output_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RELAY_OUTPUT_NAME_BYTES_V1
        && !value.chars().any(char::is_control)
}

fn is_request_identifier_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        && value.len() <= 96
        && bytes.all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'
            )
        })
}

fn is_target_attribute_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 64
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn is_stable_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 96
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
}

fn is_input_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 96
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn invalid_claim_evidence_mode<T>(
    claim: &ClaimDefinition,
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidClaimEvidenceMode {
        claim: claim.id.clone(),
        reason: reason.into(),
    })
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimSemanticConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concept: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_mapping: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimValueConfig {
    #[serde(rename = "type", default)]
    pub value_type: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub nullable: bool,
    /// Optional evaluated UTF-8 string byte ceiling. Absence preserves the
    /// direct-configuration behavior that predates per-claim byte bounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 65536))]
    pub max_bytes: Option<u32>,
    #[serde(default)]
    pub unit: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimInputConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleConfig {
    ConsultationOutput {
        consultation: String,
        output: String,
    },
    ConsultationMatched {
        consultation: String,
    },
    Cel {
        expression: String,
        #[serde(default)]
        bindings: CelBindingsConfig,
    },
}

pub(in crate::config) fn validate_claim_semantics(
    claim: &ClaimDefinition,
) -> Result<(), EvidenceConfigError> {
    let Some(semantics) = &claim.semantics else {
        return Ok(());
    };
    let mut has_term = false;
    for (field, value) in [
        ("concept", semantics.concept.as_deref()),
        ("property", semantics.property.as_deref()),
        ("vocabulary", semantics.vocabulary.as_deref()),
        ("predicate", semantics.predicate.as_deref()),
    ] {
        let Some(value) = value else {
            continue;
        };
        has_term = true;
        validate_semantic_reference(&claim.id, field, value)?;
    }
    for value in &semantics.derived_from {
        has_term = true;
        validate_semantic_reference(&claim.id, "derived_from", value)?;
    }
    if let Some(value_mapping) = semantics.value_mapping.as_deref() {
        if value_mapping.trim().is_empty() {
            return invalid_claim_semantics(&claim.id, "value_mapping must not be empty");
        }
    }
    if !has_term {
        return invalid_claim_semantics(
            &claim.id,
            "at least one of concept, property, vocabulary, predicate, or derived_from must be set",
        );
    }
    if semantics.property.is_some() && semantics.predicate.is_some() {
        return invalid_claim_semantics(
            &claim.id,
            "property and predicate are mutually exclusive; use derived_from for predicate inputs",
        );
    }
    Ok(())
}

pub(in crate::config) fn validate_semantic_reference(
    claim_id: &str,
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return invalid_claim_semantics(claim_id, format!("{field} must not be empty"));
    }
    if value.starts_with("https://") || value.starts_with("http://") || value.starts_with("urn:") {
        return Ok(());
    }
    invalid_claim_semantics(
        claim_id,
        format!("{field} must be an absolute http(s) URI or urn"),
    )
}

pub(in crate::config) fn invalid_claim_semantics<T>(
    claim: &str,
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidClaimSemantics {
        claim: claim.to_string(),
        reason: reason.into(),
    })
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CelBindingsConfig {
    #[serde(default)]
    pub claims: BTreeMap<String, ClaimBindingConfig>,
    #[serde(default)]
    pub vars: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimBindingConfig {
    pub claim: String,
    #[serde(default)]
    pub binding_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimOperationsConfig {
    #[serde(default = "default_enabled_operation")]
    pub evaluate: OperationConfig,
    #[serde(default)]
    pub batch_evaluate: BatchOperationConfig,
}

impl Default for ClaimOperationsConfig {
    fn default() -> Self {
        Self {
            evaluate: OperationConfig { enabled: true },
            batch_evaluate: BatchOperationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationConfig {
    #[serde(default)]
    pub enabled: bool,
}

pub(in crate::config) fn default_enabled_operation() -> OperationConfig {
    OperationConfig { enabled: true }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchOperationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_inline_batch_limit")]
    #[schemars(range(min = 1, max = 100))]
    pub max_subjects: usize,
}

impl Default for BatchOperationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_subjects: default_inline_batch_limit(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CccevConfig {
    #[serde(default)]
    pub requirement_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_type_iri: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OotsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub requirement: Option<String>,
    #[serde(default)]
    pub reference_framework: Option<String>,
    #[serde(default)]
    pub evidence_type_classification: Option<String>,
    #[serde(default)]
    pub evidence_type_list: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub authentication_level_of_assurance: Option<String>,
}
