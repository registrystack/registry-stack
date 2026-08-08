//! The authored question document, as an adopter writes it.
//!
//! Every type here is closed: an unknown field is a rejection rather than
//! something quietly carried along, so a document that parses is a document
//! whose every key the form knows. The checks in [`crate::validate`] then
//! decide whether the values are usable.

use std::collections::BTreeMap;

use serde::Deserialize;

/// One authored question: what is asked, of which subjects, from which source,
/// and which governed concepts the answer carries.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Question {
    pub id: String,
    pub question: String,
    pub purpose: String,
    #[serde(default)]
    pub subject: Option<QuestionSubject>,
    #[serde(default)]
    pub subjects: Vec<QuestionSubject>,
    pub source: QuestionSource,
    pub answers: Vec<QuestionAnswer>,
    pub derivation: String,
    pub disclosure: QuestionDisclosure,
    #[serde(rename = "responseFormats", default = "default_response_formats")]
    pub response_formats: Vec<QuestionResponseFormat>,
    #[serde(default)]
    pub governance: Option<QuestionGovernance>,
}

/// A serialization an answer may be returned in.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum QuestionResponseFormat {
    SignedJws,
    SdJwtVc,
}

impl QuestionResponseFormat {
    /// The name this format is written under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignedJws => "signed-jws",
            Self::SdJwtVc => "sd-jwt-vc",
        }
    }
}

/// The response formats a question offers when it names none.
#[must_use]
pub fn default_response_formats() -> Vec<QuestionResponseFormat> {
    vec![QuestionResponseFormat::SignedJws]
}

/// The published description of what a question decides and under what rules.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestionGovernance {
    pub requirement: String,
    pub kind: RequirementKind,
    pub reference_frameworks: Vec<String>,
    pub evidence_type: String,
    pub validity_seconds: u64,
    pub observation_timezone: String,
    pub fixtures: String,
    pub disclosure_families: Vec<String>,
}

/// What kind of rule a question's requirement is.
#[derive(Clone, Copy, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RequirementKind {
    Criterion,
    InformationRequirement,
    Constraint,
}

impl RequirementKind {
    /// The name this kind is written under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Criterion => "criterion",
            Self::InformationRequirement => "information-requirement",
            Self::Constraint => "constraint",
        }
    }
}

/// One party a question is asked about.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct QuestionSubject {
    pub role: String,
    pub selector: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub derivation: bool,
}

/// Where a question reads from: a named source, or an operation of the
/// project's own OpenAPI description together with the facts it projects.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct QuestionSource {
    #[serde(rename = "ref")]
    pub source_ref: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub facts: Vec<QuestionFact>,
    #[serde(rename = "collectionBounds", default)]
    pub collection_bounds: BTreeMap<String, u64>,
}

/// One value projected out of a source response and handed to the derivation.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct QuestionFact {
    pub name: String,
    pub path: String,
    pub combine: FactCombination,
}

/// How many values a fact's path is expected to reach.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum FactCombination {
    ExactlyOne,
    Collect,
}

/// One governed concept a question answers, and the shape of that answer.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct QuestionAnswer {
    pub concept: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub answer_type: AnswerType,
    #[serde(default)]
    pub values: Vec<String>,
    pub minimum: Option<i64>,
    pub maximum: Option<i64>,
    pub schema: Option<String>,
    #[serde(rename = "maximumSerializedBytes")]
    pub maximum_serialized_bytes: Option<u64>,
    #[serde(rename = "sdJwtVc")]
    pub sd_jwt_vc: Option<QuestionSdJwtVc>,
}

/// The shape of one answer.
#[derive(Clone, Copy, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AnswerType {
    Boolean,
    ControlledCategory,
    BoundedInteger,
    ReviewedStructuredValue,
}

/// How an answer appears in the SD-JWT VC serialization of a response.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestionSdJwtVc {
    pub claim: String,
    pub disclosure: QuestionSdJwtVcDisclosure,
}

/// Where a projected claim sits in the disclosure structure.
#[derive(Clone, Copy, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum QuestionSdJwtVcDisclosure {
    TopLevel,
}

/// Which of a question's concepts a response may carry.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct QuestionDisclosure {
    pub allow: Vec<String>,
}
