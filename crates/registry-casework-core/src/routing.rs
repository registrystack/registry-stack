// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use jsonschema::{Draft, JSONSchema};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAXIMUM_ROUTING_RULES: usize = 64;
pub const MAXIMUM_ROUTING_PROJECTION_FIELDS: usize = 32;
pub const MAXIMUM_ROUTING_PREDICATES: usize = 16;
pub const MAXIMUM_ROUTING_VALUES: usize = 32;
pub const MAXIMUM_ROUTING_SOURCE_FIELDS: usize = 128;
pub const MAXIMUM_ROUTING_SOURCE_STAGES: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RoutingActivity {
    Review,
    Apply,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingRule {
    #[serde(deserialize_with = "crate::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub id: String,
    pub because: String,
    pub when: RoutingCondition,
    pub queue: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingCondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<RoutingActivity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "crate::typed::local_id_keys"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::LocalId, RoutingPredicate>")
    )]
    pub fields: BTreeMap<String, RoutingPredicate>,
}

/// One field predicate, written as a mapping with exactly one key that names
/// it: `{equals: value}` or `{oneOf: [values]}` (CFG-ID-7).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "RoutingPredicateDocument", into = "RoutingPredicateDocument")]
pub enum RoutingPredicate {
    Equals(EqualsPredicate),
    OneOf(OneOfPredicate),
}

/// The written form of [`RoutingPredicate`], an externally tagged union the
/// shared reader decodes with positions.
#[derive(Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum RoutingPredicateDocument {
    /// The projected field equals this value.
    Equals(Value),
    /// The projected field equals one of these values.
    OneOf(Vec<Value>),
}

impl From<RoutingPredicateDocument> for RoutingPredicate {
    fn from(document: RoutingPredicateDocument) -> Self {
        match document {
            RoutingPredicateDocument::Equals(equals) => Self::Equals(EqualsPredicate { equals }),
            RoutingPredicateDocument::OneOf(one_of) => Self::OneOf(OneOfPredicate { one_of }),
        }
    }
}

impl From<RoutingPredicate> for RoutingPredicateDocument {
    fn from(predicate: RoutingPredicate) -> Self {
        match predicate {
            RoutingPredicate::Equals(predicate) => Self::Equals(predicate.equals),
            RoutingPredicate::OneOf(predicate) => Self::OneOf(predicate.one_of),
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for RoutingPredicate {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "RoutingPredicate".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        RoutingPredicateDocument::json_schema(generator)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EqualsPredicate {
    pub equals: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneOfPredicate {
    pub one_of: Vec<Value>,
}

/// Source-owned routing metadata imported by the source's own authoring tool.
/// `schema` is the exact generated JSON Schema property for the API field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingFieldDescriptor {
    pub field: String,
    pub api_name: String,
    pub schema: Value,
}

/// Check that an imported source descriptor carries a compilable generated
/// JSON Schema before an adapter becomes active.
pub fn check_source_field_descriptor(descriptor: &RoutingFieldDescriptor) -> bool {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&descriptor.schema)
        .is_ok()
}

/// Validate one current source value against the exact generated descriptor
/// imported for that source field. Adapters use this before releasing a
/// caller-authorized review-context projection.
pub fn validate_source_field_value(
    descriptor: &RoutingFieldDescriptor,
    value: &Value,
) -> Result<(), RoutingDiagnostic> {
    let schema = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&descriptor.schema)
        .map_err(|_| {
            RoutingDiagnostic::new(
                format!(
                    "/source/fields/{}",
                    registry_platform_yaml::escape_pointer_segment(&descriptor.field)
                ),
                RoutingDiagnosticReason::UnknownField,
            )
        })?;
    schema.validate(value).map_err(|_| {
        RoutingDiagnostic::new(
            format!(
                "/source/fields/{}",
                registry_platform_yaml::escape_pointer_segment(&descriptor.field)
            ),
            RoutingDiagnosticReason::InvalidSourceValue,
        )
    })
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingSourceMetadata {
    pub stages: Vec<String>,
    pub fields: Vec<RoutingFieldDescriptor>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RoutingContext {
    pub activity: RoutingActivity,
    pub stage: Option<String>,
    /// Values are keyed by the imported logical field id used in `projection`.
    pub fields: BTreeMap<String, Value>,
}

impl fmt::Debug for RoutingContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutingContext")
            .field("activity", &self.activity)
            .field("has_stage", &self.stage.is_some())
            .field("field_count", &self.fields.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingDecision {
    pub queue: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub because: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingDiagnosticReason {
    TooManyRules,
    TooManyProjectionFields,
    DuplicateProjectionField,
    InvalidSourceMetadata,
    InvalidIdentifier,
    DuplicateRuleId,
    InvalidReason,
    UnknownQueue,
    UnknownStage,
    UnknownField,
    FieldNotProjected,
    TooManyPredicates,
    PredicateValueCount,
    DuplicatePredicateValue,
    InvalidPredicateValue,
    EmptyCondition,
    StageWithoutReview,
    UnreachableRule,
    InvalidSourceValue,
    UnexpectedSourceState,
}

impl RoutingDiagnosticReason {
    /// The stable diagnostic code (CFG-DIAG-3).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TooManyRules => "casework.routing.too-many-rules",
            Self::TooManyProjectionFields => "casework.routing.too-many-projection-fields",
            Self::DuplicateProjectionField => "casework.routing.duplicate-projection-field",
            Self::InvalidSourceMetadata => "casework.routing.invalid-source-description",
            Self::InvalidIdentifier => "casework.routing.invalid-rule-id",
            Self::DuplicateRuleId => "casework.routing.duplicate-rule-id",
            Self::InvalidReason => "casework.routing.invalid-because",
            Self::UnknownQueue => "casework.routing.unknown-queue",
            Self::UnknownStage => "casework.routing.unknown-stage",
            Self::UnknownField => "casework.routing.unknown-field",
            Self::FieldNotProjected => "casework.routing.field-not-projected",
            Self::TooManyPredicates => "casework.routing.too-many-predicates",
            Self::PredicateValueCount => "casework.routing.predicate-value-count",
            Self::DuplicatePredicateValue => "casework.routing.duplicate-predicate-value",
            Self::InvalidPredicateValue => "casework.routing.invalid-predicate-value",
            Self::EmptyCondition => "casework.routing.empty-condition",
            Self::StageWithoutReview => "casework.routing.stage-without-review",
            Self::UnreachableRule => "casework.routing.unreachable-rule",
            Self::InvalidSourceValue => "casework.routing.invalid-source-value",
            Self::UnexpectedSourceState => "casework.routing.unexpected-source-state",
        }
    }

    /// What is wrong, without repeating a value (CFG-SEC-3).
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::TooManyRules => "a request declares more than 64 routing rules",
            Self::TooManyProjectionFields => "a request projects more than 32 fields",
            Self::DuplicateProjectionField => "this field is already projected",
            Self::InvalidSourceMetadata => {
                "the source description's stages or fields are repeated, malformed, or over their bounds"
            }
            Self::InvalidIdentifier => {
                "a rule id is 1 to 64 lowercase letters, digits, or hyphens, starting with a letter"
            }
            Self::DuplicateRuleId => "another rule of this request already uses this id",
            Self::InvalidReason => "`because` is empty or longer than 256 bytes",
            Self::UnknownQueue => "the queue is not declared under `queues`",
            Self::UnknownStage => "the stage is not one the source description declares",
            Self::UnknownField => "the field is not one the source description declares",
            Self::FieldNotProjected => "the field is not listed in the request's `projection`",
            Self::TooManyPredicates => "a rule tests more than 16 fields",
            Self::PredicateValueCount => "a predicate names 1 to 32 values",
            Self::DuplicatePredicateValue => "a predicate names the same value twice",
            Self::InvalidPredicateValue => {
                "a predicate value does not match the field's schema in the source description"
            }
            Self::EmptyCondition => "`when` names no activity, stage, or field",
            Self::StageWithoutReview => "a stage is tested only by a review rule",
            Self::UnreachableRule => "an earlier rule matches every input this rule matches",
            Self::InvalidSourceValue => "the source returned a value its description does not allow",
            Self::UnexpectedSourceState => {
                "the source returned a stage the activity does not allow"
            }
        }
    }

    /// The edit that fixes it (CFG-DIAG-6).
    #[must_use]
    pub const fn suggested_action(self) -> &'static str {
        match self {
            Self::TooManyRules => "Merge rules, or route fewer cases explicitly and let the request's queue take the rest.",
            Self::TooManyProjectionFields => "Project only the fields routing tests.",
            Self::DuplicateProjectionField => "Remove the repeated entry.",
            Self::InvalidSourceMetadata => {
                "Regenerate the source description with the source's own tool and import it again."
            }
            Self::InvalidIdentifier => "Rename the rule with a valid id.",
            Self::DuplicateRuleId => "Give each rule of the request its own id.",
            Self::InvalidReason => "Write one sentence of at most 256 bytes saying why the rule routes here.",
            Self::UnknownQueue => "Declare the queue under `queues`, or route to a declared queue.",
            Self::UnknownStage => {
                "Use a stage the source description lists, or import a description that declares it."
            }
            Self::UnknownField => {
                "Use a field the source description lists, or import a description that declares it."
            }
            Self::FieldNotProjected => "Add the field to the request's `projection`, or stop testing it.",
            Self::TooManyPredicates => "Test at most 16 fields in one rule.",
            Self::PredicateValueCount => "Write `equals` with one value, or `oneOf` with 1 to 32 values.",
            Self::DuplicatePredicateValue => "Remove the repeated value.",
            Self::InvalidPredicateValue => "Write values the field's schema allows.",
            Self::EmptyCondition => "Name the activity, stage, or fields the rule matches.",
            Self::StageWithoutReview => "Set `activity: review`, or remove `stage`.",
            Self::UnreachableRule => "Move the rule above the broader rule, or remove it.",
            Self::InvalidSourceValue | Self::UnexpectedSourceState => {
                "Correct the record in the source, or import the source's current description."
            }
        }
    }
}

/// One routing finding. `path` is an RFC 6901 pointer relative to the source
/// request that declares the rule (`/routing/0/when/stage`), or, for a live
/// source value, to the observed subject (`/source/fields/region`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingDiagnostic {
    pub path: String,
    pub reason: RoutingDiagnosticReason,
}

impl RoutingDiagnostic {
    fn new(path: impl Into<String>, reason: RoutingDiagnosticReason) -> Self {
        Self {
            path: path.into(),
            reason,
        }
    }
}

impl fmt::Display for RoutingDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "routing policy refused at {}: {}",
            self.path,
            self.reason.message()
        )
    }
}

impl std::error::Error for RoutingDiagnostic {}

/// Check queue references and rule order, returning the first finding.
/// Passing source metadata also checks source stages and validates authored
/// predicate values against the source's generated field schemas.
pub fn check_routing_policy(
    default_queue: &str,
    projection: &[String],
    rules: &[RoutingRule],
    queues: &BTreeSet<String>,
    source: Option<&RoutingSourceMetadata>,
) -> Result<(), RoutingDiagnostic> {
    routing_policy_findings(default_queue, projection, rules, queues, source)
        .into_iter()
        .next()
        .map_or(Ok(()), Err)
}

/// Every finding [`check_routing_policy`] would report, in document order,
/// so a check command reports them all in one run (CFG-DIAG-5).
pub fn routing_policy_findings(
    default_queue: &str,
    projection: &[String],
    rules: &[RoutingRule],
    queues: &BTreeSet<String>,
    source: Option<&RoutingSourceMetadata>,
) -> Vec<RoutingDiagnostic> {
    let mut findings = Vec::new();
    if !queues.contains(default_queue) {
        findings.push(RoutingDiagnostic::new(
            "/queue",
            RoutingDiagnosticReason::UnknownQueue,
        ));
    }
    if projection.len() > MAXIMUM_ROUTING_PROJECTION_FIELDS {
        findings.push(RoutingDiagnostic::new(
            "/projection",
            RoutingDiagnosticReason::TooManyProjectionFields,
        ));
    }

    let source_fields = source.map(|metadata| {
        metadata
            .fields
            .iter()
            .map(|field| (field.field.as_str(), field))
            .collect::<BTreeMap<_, _>>()
    });
    let mut source_usable = true;
    if let Some(metadata) = source {
        if metadata.stages.len() > MAXIMUM_ROUTING_SOURCE_STAGES
            || metadata.stages.iter().collect::<BTreeSet<_>>().len() != metadata.stages.len()
            || metadata.stages.iter().any(|stage| !valid_identifier(stage))
            || metadata.fields.len() > MAXIMUM_ROUTING_SOURCE_FIELDS
            || source_fields
                .as_ref()
                .is_some_and(|fields| fields.len() != metadata.fields.len())
            || metadata.fields.iter().any(|field| {
                !valid_identifier(&field.field)
                    || field.api_name.is_empty()
                    || field.api_name.len() > 128
            })
        {
            source_usable = false;
            findings.push(RoutingDiagnostic::new(
                "",
                RoutingDiagnosticReason::InvalidSourceMetadata,
            ));
        }
    }
    let source = source.filter(|_| source_usable);
    let source_fields = source_fields.filter(|_| source_usable);

    let mut projected = BTreeSet::new();
    for (index, field) in projection.iter().enumerate() {
        if !projected.insert(field.as_str()) {
            findings.push(RoutingDiagnostic::new(
                format!("/projection/{index}"),
                RoutingDiagnosticReason::DuplicateProjectionField,
            ));
        } else if source_fields
            .as_ref()
            .is_some_and(|fields| !fields.contains_key(field.as_str()))
        {
            findings.push(RoutingDiagnostic::new(
                format!("/projection/{index}"),
                RoutingDiagnosticReason::UnknownField,
            ));
        }
    }

    if rules.len() > MAXIMUM_ROUTING_RULES {
        findings.push(RoutingDiagnostic::new(
            "/routing",
            RoutingDiagnosticReason::TooManyRules,
        ));
    }
    let mut ids = BTreeSet::new();
    for (index, rule) in rules.iter().enumerate() {
        let base = format!("/routing/{index}");
        if !valid_identifier(&rule.id) {
            findings.push(RoutingDiagnostic::new(
                format!("{base}/id"),
                RoutingDiagnosticReason::InvalidIdentifier,
            ));
        } else if !ids.insert(rule.id.as_str()) {
            findings.push(RoutingDiagnostic::new(
                format!("{base}/id"),
                RoutingDiagnosticReason::DuplicateRuleId,
            ));
        }
        if rule.because.trim().is_empty() || rule.because.len() > 256 {
            findings.push(RoutingDiagnostic::new(
                format!("{base}/because"),
                RoutingDiagnosticReason::InvalidReason,
            ));
        }
        if !queues.contains(&rule.queue) {
            findings.push(RoutingDiagnostic::new(
                format!("{base}/queue"),
                RoutingDiagnosticReason::UnknownQueue,
            ));
        }
        if rule.when.activity.is_none() && rule.when.stage.is_none() && rule.when.fields.is_empty()
        {
            findings.push(RoutingDiagnostic::new(
                format!("{base}/when"),
                RoutingDiagnosticReason::EmptyCondition,
            ));
        }
        if rule.when.fields.len() > MAXIMUM_ROUTING_PREDICATES {
            findings.push(RoutingDiagnostic::new(
                format!("{base}/when/fields"),
                RoutingDiagnosticReason::TooManyPredicates,
            ));
        }
        if rule.when.stage.is_some()
            && rule
                .when
                .activity
                .is_some_and(|activity| activity != RoutingActivity::Review)
        {
            findings.push(RoutingDiagnostic::new(
                format!("{base}/when/stage"),
                RoutingDiagnosticReason::StageWithoutReview,
            ));
        } else if let (Some(stage), Some(metadata)) = (&rule.when.stage, source) {
            if !metadata.stages.contains(stage) {
                findings.push(RoutingDiagnostic::new(
                    format!("{base}/when/stage"),
                    RoutingDiagnosticReason::UnknownStage,
                ));
            }
        }
        for (field, predicate) in &rule.when.fields {
            let path = format!(
                "{base}/when/fields/{}",
                registry_platform_yaml::escape_pointer_segment(field)
            );
            if !projection.contains(field) {
                findings.push(RoutingDiagnostic::new(
                    path,
                    RoutingDiagnosticReason::FieldNotProjected,
                ));
                continue;
            }
            let values = predicate_values(predicate);
            if values.is_empty() || values.len() > MAXIMUM_ROUTING_VALUES {
                findings.push(RoutingDiagnostic::new(
                    path,
                    RoutingDiagnosticReason::PredicateValueCount,
                ));
                continue;
            }
            if has_duplicates(values) {
                findings.push(RoutingDiagnostic::new(
                    path,
                    RoutingDiagnosticReason::DuplicatePredicateValue,
                ));
                continue;
            }
            if let Some(fields) = &source_fields {
                let Some(schema) = fields.get(field.as_str()).and_then(|descriptor| {
                    JSONSchema::options()
                        .with_draft(Draft::Draft202012)
                        .compile(&descriptor.schema)
                        .ok()
                }) else {
                    findings.push(RoutingDiagnostic::new(
                        path,
                        RoutingDiagnosticReason::UnknownField,
                    ));
                    continue;
                };
                if values.iter().any(|value| schema.validate(value).is_err()) {
                    findings.push(RoutingDiagnostic::new(
                        path,
                        RoutingDiagnosticReason::InvalidPredicateValue,
                    ));
                }
            }
        }
        if rules[..index]
            .iter()
            .any(|earlier| condition_subsumes(&earlier.when, &rule.when))
        {
            findings.push(RoutingDiagnostic::new(
                base,
                RoutingDiagnosticReason::UnreachableRule,
            ));
        }
    }
    findings
}

/// Evaluate the same first-match routing policy used by runtime reads and
/// offline explain/simulation. Missing projected fields simply fall through.
pub fn evaluate_routing(
    default_queue: &str,
    projection: &[String],
    rules: &[RoutingRule],
    source: &RoutingSourceMetadata,
    context: &RoutingContext,
) -> Result<RoutingDecision, RoutingDiagnostic> {
    let queues = rules
        .iter()
        .map(|rule| rule.queue.clone())
        .chain(std::iter::once(default_queue.to_owned()))
        .collect();
    check_routing_policy(default_queue, projection, rules, &queues, Some(source))?;

    match context.activity {
        RoutingActivity::Review => {
            let Some(stage) = context.stage.as_ref() else {
                return Err(RoutingDiagnostic::new(
                    "/source/stage",
                    RoutingDiagnosticReason::UnexpectedSourceState,
                ));
            };
            if stage.is_empty() || stage.len() > 64 {
                return Err(RoutingDiagnostic::new(
                    "/source/stage",
                    RoutingDiagnosticReason::UnexpectedSourceState,
                ));
            }
        }
        RoutingActivity::Apply if context.stage.is_some() => {
            return Err(RoutingDiagnostic::new(
                "/source/stage",
                RoutingDiagnosticReason::UnexpectedSourceState,
            ));
        }
        RoutingActivity::Apply => {}
    }

    let descriptors = source
        .fields
        .iter()
        .map(|field| (field.field.as_str(), field))
        .collect::<BTreeMap<_, _>>();
    for field in projection {
        if let Some(value) = context.fields.get(field) {
            let descriptor = descriptors.get(field.as_str()).ok_or_else(|| {
                RoutingDiagnostic::new(
                    format!(
                        "/source/fields/{}",
                        registry_platform_yaml::escape_pointer_segment(field)
                    ),
                    RoutingDiagnosticReason::UnknownField,
                )
            })?;
            let schema = JSONSchema::options()
                .with_draft(Draft::Draft202012)
                .compile(&descriptor.schema)
                .map_err(|_| {
                    RoutingDiagnostic::new(
                        format!(
                            "/source/fields/{}",
                            registry_platform_yaml::escape_pointer_segment(field)
                        ),
                        RoutingDiagnosticReason::UnknownField,
                    )
                })?;
            if schema.validate(value).is_err() {
                return Err(RoutingDiagnostic::new(
                    format!(
                        "/source/fields/{}",
                        registry_platform_yaml::escape_pointer_segment(field)
                    ),
                    RoutingDiagnosticReason::InvalidSourceValue,
                ));
            }
        }
    }

    if let Some(rule) = rules
        .iter()
        .find(|rule| matches_condition(&rule.when, context))
    {
        return Ok(RoutingDecision {
            queue: rule.queue.clone(),
            rule_id: Some(rule.id.clone()),
            because: Some(rule.because.clone()),
        });
    }
    Ok(RoutingDecision {
        queue: default_queue.to_owned(),
        rule_id: None,
        because: None,
    })
}

fn matches_condition(condition: &RoutingCondition, context: &RoutingContext) -> bool {
    condition
        .activity
        .is_none_or(|activity| activity == context.activity)
        && condition
            .stage
            .as_ref()
            .is_none_or(|stage| context.stage.as_ref() == Some(stage))
        && condition.fields.iter().all(|(field, predicate)| {
            context
                .fields
                .get(field)
                .is_some_and(|value| predicate_values(predicate).contains(value))
        })
}

fn condition_subsumes(earlier: &RoutingCondition, later: &RoutingCondition) -> bool {
    earlier
        .activity
        .is_none_or(|activity| later.activity == Some(activity))
        && earlier
            .stage
            .as_ref()
            .is_none_or(|stage| later.stage.as_ref() == Some(stage))
        && earlier.fields.iter().all(|(field, predicate)| {
            later.fields.get(field).is_some_and(|later_predicate| {
                predicate_values(later_predicate)
                    .iter()
                    .all(|value| predicate_values(predicate).contains(value))
            })
        })
}

fn predicate_values(predicate: &RoutingPredicate) -> &[Value] {
    match predicate {
        RoutingPredicate::Equals(predicate) => std::slice::from_ref(&predicate.equals),
        RoutingPredicate::OneOf(predicate) => &predicate.one_of,
    }
}

fn has_duplicates(values: &[Value]) -> bool {
    let mut canonical = BTreeSet::new();
    values.iter().any(|value| {
        registry_platform_canonical_json::canonicalize_json(value)
            .map_or(true, |value| !canonical.insert(value))
    })
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_id_1_an_identifier_follows_the_local_identifier_grammar() {
        assert!(valid_identifier("first_review-2"));
        assert!(valid_identifier(&format!("a{}", "b".repeat(63))));
        for refused in ["", "First", "1st", "_first", "first.review", "first review"] {
            assert!(!valid_identifier(refused));
        }
        assert!(!valid_identifier(&format!("a{}", "b".repeat(64))));
    }
    use serde_json::json;

    fn metadata() -> RoutingSourceMetadata {
        RoutingSourceMetadata {
            stages: vec!["technical".to_owned(), "authorization".to_owned()],
            fields: vec![RoutingFieldDescriptor {
                field: "region".to_owned(),
                api_name: "region".to_owned(),
                schema: json!({"type":"string", "enum":["north","south","islands"]}),
            }],
        }
    }

    fn rule(id: &str, condition: RoutingCondition, queue: &str) -> RoutingRule {
        RoutingRule {
            id: id.to_owned(),
            because: format!("Rule {id} matched."),
            when: condition,
            queue: queue.to_owned(),
        }
    }

    #[test]
    fn first_match_is_stable_and_missing_fields_fall_back() {
        let rules = vec![
            rule(
                "north-first",
                RoutingCondition {
                    fields: BTreeMap::from([(
                        "region".to_owned(),
                        RoutingPredicate::OneOf(OneOfPredicate {
                            one_of: vec![json!("north"), json!("south")],
                        }),
                    )]),
                    ..RoutingCondition::default()
                },
                "regional",
            ),
            rule(
                "southern-overlap",
                RoutingCondition {
                    fields: BTreeMap::from([(
                        "region".to_owned(),
                        RoutingPredicate::OneOf(OneOfPredicate {
                            one_of: vec![json!("south"), json!("islands")],
                        }),
                    )]),
                    ..RoutingCondition::default()
                },
                "special",
            ),
        ];
        let projection = vec!["region".to_owned()];
        let context = RoutingContext {
            activity: RoutingActivity::Review,
            stage: Some("technical".to_owned()),
            fields: BTreeMap::from([("region".to_owned(), json!("north"))]),
        };
        let decision = evaluate_routing("triage", &projection, &rules, &metadata(), &context)
            .expect("valid route");
        assert_eq!(decision.queue, "regional");
        assert_eq!(decision.rule_id.as_deref(), Some("north-first"));

        let fallback = evaluate_routing(
            "triage",
            &projection,
            &rules,
            &metadata(),
            &RoutingContext {
                fields: BTreeMap::new(),
                ..context
            },
        )
        .expect("missing field is a fallback");
        assert_eq!(fallback.queue, "triage");
        assert_eq!(fallback.rule_id, None);
    }

    #[test]
    fn unknown_stages_and_typed_values_are_field_addressed() {
        let mut rules = vec![rule(
            "review",
            RoutingCondition {
                activity: Some(RoutingActivity::Review),
                stage: Some("invented".to_owned()),
                ..RoutingCondition::default()
            },
            "reviewers",
        )];
        let queues = BTreeSet::from(["triage".to_owned(), "reviewers".to_owned()]);
        assert_eq!(
            check_routing_policy("triage", &[], &rules, &queues, Some(&metadata())),
            Err(RoutingDiagnostic::new(
                "/routing/0/when/stage",
                RoutingDiagnosticReason::UnknownStage,
            ))
        );

        rules[0].when.stage = Some("technical".to_owned());
        rules[0].when.fields.insert(
            "region".to_owned(),
            RoutingPredicate::Equals(EqualsPredicate { equals: json!(7) }),
        );
        assert_eq!(
            check_routing_policy(
                "triage",
                &["region".to_owned()],
                &rules,
                &queues,
                Some(&metadata()),
            ),
            Err(RoutingDiagnostic::new(
                "/routing/0/when/fields/region",
                RoutingDiagnosticReason::InvalidPredicateValue,
            ))
        );
    }

    #[test]
    fn every_routing_finding_is_reported_in_document_order() {
        let rules = vec![
            rule(
                "review",
                RoutingCondition {
                    activity: Some(RoutingActivity::Review),
                    stage: Some("invented".to_owned()),
                    ..RoutingCondition::default()
                },
                "missing",
            ),
            rule("review", RoutingCondition::default(), "triage"),
        ];
        let queues = BTreeSet::from(["triage".to_owned()]);
        let findings: Vec<_> =
            routing_policy_findings("absent", &[], &rules, &queues, Some(&metadata()))
                .into_iter()
                .map(|finding| (finding.path, finding.reason.code()))
                .collect();
        assert_eq!(
            findings,
            [
                ("/queue".to_owned(), "casework.routing.unknown-queue"),
                (
                    "/routing/0/queue".to_owned(),
                    "casework.routing.unknown-queue"
                ),
                (
                    "/routing/0/when/stage".to_owned(),
                    "casework.routing.unknown-stage"
                ),
                (
                    "/routing/1/id".to_owned(),
                    "casework.routing.duplicate-rule-id"
                ),
                (
                    "/routing/1/when".to_owned(),
                    "casework.routing.empty-condition"
                ),
            ]
        );
    }

    #[test]
    fn empty_source_stages_are_valid_without_authored_stage_predicates() {
        let queues = BTreeSet::from(["triage".to_owned(), "regional".to_owned()]);
        let metadata = RoutingSourceMetadata {
            stages: Vec::new(),
            fields: metadata().fields,
        };
        let field_rule = rule(
            "north",
            RoutingCondition {
                fields: BTreeMap::from([(
                    "region".to_owned(),
                    RoutingPredicate::Equals(EqualsPredicate {
                        equals: json!("north"),
                    }),
                )]),
                ..RoutingCondition::default()
            },
            "regional",
        );
        assert!(check_routing_policy(
            "triage",
            &["region".to_owned()],
            &[field_rule],
            &queues,
            Some(&metadata),
        )
        .is_ok());

        let stage_rule = rule(
            "staged",
            RoutingCondition {
                activity: Some(RoutingActivity::Review),
                stage: Some("technical".to_owned()),
                ..RoutingCondition::default()
            },
            "regional",
        );
        assert_eq!(
            check_routing_policy("triage", &[], &[stage_rule], &queues, Some(&metadata)),
            Err(RoutingDiagnostic::new(
                "/routing/0/when/stage",
                RoutingDiagnosticReason::UnknownStage,
            ))
        );
    }

    #[test]
    fn unreachable_rules_are_refused_but_intentional_overlap_is_ordered() {
        let queues = BTreeSet::from(["triage".to_owned(), "reviewers".to_owned()]);
        let wildcard_review = rule(
            "all-review",
            RoutingCondition {
                activity: Some(RoutingActivity::Review),
                ..RoutingCondition::default()
            },
            "reviewers",
        );
        let technical = rule(
            "technical",
            RoutingCondition {
                activity: Some(RoutingActivity::Review),
                stage: Some("technical".to_owned()),
                ..RoutingCondition::default()
            },
            "reviewers",
        );
        assert_eq!(
            check_routing_policy(
                "triage",
                &[],
                &[wildcard_review, technical],
                &queues,
                Some(&metadata()),
            ),
            Err(RoutingDiagnostic::new(
                "/routing/1",
                RoutingDiagnosticReason::UnreachableRule,
            ))
        );
    }

    #[test]
    fn invalid_live_values_and_states_are_visible_diagnostics() {
        let rules = vec![rule(
            "north",
            RoutingCondition {
                fields: BTreeMap::from([(
                    "region".to_owned(),
                    RoutingPredicate::Equals(EqualsPredicate {
                        equals: json!("north"),
                    }),
                )]),
                ..RoutingCondition::default()
            },
            "regional",
        )];
        let result = evaluate_routing(
            "triage",
            &["region".to_owned()],
            &rules,
            &metadata(),
            &RoutingContext {
                activity: RoutingActivity::Review,
                stage: Some("technical".to_owned()),
                fields: BTreeMap::from([("region".to_owned(), json!(false))]),
            },
        );
        assert_eq!(
            result,
            Err(RoutingDiagnostic::new(
                "/source/fields/region",
                RoutingDiagnosticReason::InvalidSourceValue,
            ))
        );
    }

    #[test]
    fn a_source_validated_frozen_stage_absent_from_current_policy_uses_the_default() {
        let decision = evaluate_routing(
            "triage",
            &[],
            &[rule(
                "current-stage",
                RoutingCondition {
                    activity: Some(RoutingActivity::Review),
                    stage: Some("technical".to_owned()),
                    ..RoutingCondition::default()
                },
                "current-review",
            )],
            &metadata(),
            &RoutingContext {
                activity: RoutingActivity::Review,
                stage: Some("legacy-review".to_owned()),
                fields: BTreeMap::new(),
            },
        )
        .expect("the adapter supplied a valid frozen stage");
        assert_eq!(decision.queue, "triage");
        assert_eq!(decision.rule_id, None);
    }
}
