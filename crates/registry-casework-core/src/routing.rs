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
#[serde(rename_all = "snake_case")]
pub enum RoutingActivity {
    Review,
    Apply,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingRule {
    pub id: String,
    pub because: String,
    pub when: RoutingCondition,
    pub queue: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingCondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<RoutingActivity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, RoutingPredicate>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RoutingPredicate {
    Equals(EqualsPredicate),
    OneOf(OneOfPredicate),
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
#[serde(rename_all = "snake_case")]
pub enum RoutingDiagnosticReason {
    Bounds,
    InvalidIdentifier,
    InvalidReason,
    UnknownQueue,
    UnknownStage,
    UnknownField,
    FieldNotProjected,
    InvalidPredicateValue,
    EmptyCondition,
    StageWithoutReview,
    UnreachableRule,
    InvalidSourceValue,
    UnexpectedSourceState,
}

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
        write!(formatter, "routing policy refused at {}", self.path)
    }
}

impl std::error::Error for RoutingDiagnostic {}

/// Check queue references and rule order. Passing source metadata also checks
/// source stages and validates authored predicate values against the source's
/// generated field schemas.
pub fn check_routing_policy(
    default_queue: &str,
    projection: &[String],
    rules: &[RoutingRule],
    queues: &BTreeSet<String>,
    source: Option<&RoutingSourceMetadata>,
) -> Result<(), RoutingDiagnostic> {
    if rules.len() > MAXIMUM_ROUTING_RULES
        || projection.len() > MAXIMUM_ROUTING_PROJECTION_FIELDS
        || projection.iter().collect::<BTreeSet<_>>().len() != projection.len()
    {
        return Err(RoutingDiagnostic::new(
            "routing",
            RoutingDiagnosticReason::Bounds,
        ));
    }
    if !queues.contains(default_queue) {
        return Err(RoutingDiagnostic::new(
            "queue",
            RoutingDiagnosticReason::UnknownQueue,
        ));
    }

    let source_fields = source.map(|metadata| {
        metadata
            .fields
            .iter()
            .map(|field| (field.field.as_str(), field))
            .collect::<BTreeMap<_, _>>()
    });
    if let Some(metadata) = source {
        if metadata.stages.is_empty()
            || metadata.stages.len() > MAXIMUM_ROUTING_SOURCE_STAGES
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
            return Err(RoutingDiagnostic::new(
                "source",
                RoutingDiagnosticReason::Bounds,
            ));
        }
    }
    if let Some(fields) = &source_fields {
        for (index, field) in projection.iter().enumerate() {
            if !fields.contains_key(field.as_str()) {
                return Err(RoutingDiagnostic::new(
                    format!("projection[{index}]"),
                    RoutingDiagnosticReason::UnknownField,
                ));
            }
        }
    }

    let mut ids = BTreeSet::new();
    for (index, rule) in rules.iter().enumerate() {
        let base = format!("routing[{index}]");
        if !valid_identifier(&rule.id) || !ids.insert(rule.id.as_str()) {
            return Err(RoutingDiagnostic::new(
                format!("{base}.id"),
                RoutingDiagnosticReason::InvalidIdentifier,
            ));
        }
        if rule.because.trim().is_empty() || rule.because.len() > 256 {
            return Err(RoutingDiagnostic::new(
                format!("{base}.because"),
                RoutingDiagnosticReason::InvalidReason,
            ));
        }
        if !queues.contains(&rule.queue) {
            return Err(RoutingDiagnostic::new(
                format!("{base}.queue"),
                RoutingDiagnosticReason::UnknownQueue,
            ));
        }
        if rule.when.activity.is_none() && rule.when.stage.is_none() && rule.when.fields.is_empty()
        {
            return Err(RoutingDiagnostic::new(
                format!("{base}.when"),
                RoutingDiagnosticReason::EmptyCondition,
            ));
        }
        if rule.when.fields.len() > MAXIMUM_ROUTING_PREDICATES {
            return Err(RoutingDiagnostic::new(
                format!("{base}.when.fields"),
                RoutingDiagnosticReason::Bounds,
            ));
        }
        if rule.when.stage.is_some()
            && rule
                .when
                .activity
                .is_some_and(|activity| activity != RoutingActivity::Review)
        {
            return Err(RoutingDiagnostic::new(
                format!("{base}.when.stage"),
                RoutingDiagnosticReason::StageWithoutReview,
            ));
        }
        if let (Some(stage), Some(metadata)) = (&rule.when.stage, source) {
            if !metadata.stages.contains(stage) {
                return Err(RoutingDiagnostic::new(
                    format!("{base}.when.stage"),
                    RoutingDiagnosticReason::UnknownStage,
                ));
            }
        }
        for (field, predicate) in &rule.when.fields {
            let path = format!("{base}.when.fields.{field}");
            if !projection.contains(field) {
                return Err(RoutingDiagnostic::new(
                    path,
                    RoutingDiagnosticReason::FieldNotProjected,
                ));
            }
            let values = predicate_values(predicate);
            if values.is_empty() || values.len() > MAXIMUM_ROUTING_VALUES || has_duplicates(values)
            {
                return Err(RoutingDiagnostic::new(
                    path,
                    RoutingDiagnosticReason::Bounds,
                ));
            }
            if let Some(fields) = &source_fields {
                let Some(descriptor) = fields.get(field.as_str()) else {
                    return Err(RoutingDiagnostic::new(
                        path,
                        RoutingDiagnosticReason::UnknownField,
                    ));
                };
                let schema = JSONSchema::options()
                    .with_draft(Draft::Draft202012)
                    .compile(&descriptor.schema)
                    .map_err(|_| {
                        RoutingDiagnostic::new(&path, RoutingDiagnosticReason::UnknownField)
                    })?;
                if values.iter().any(|value| schema.validate(value).is_err()) {
                    return Err(RoutingDiagnostic::new(
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
            return Err(RoutingDiagnostic::new(
                base,
                RoutingDiagnosticReason::UnreachableRule,
            ));
        }
    }
    Ok(())
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
                    "source.stage",
                    RoutingDiagnosticReason::UnexpectedSourceState,
                ));
            };
            if stage.is_empty() || stage.len() > 64 {
                return Err(RoutingDiagnostic::new(
                    "source.stage",
                    RoutingDiagnosticReason::UnexpectedSourceState,
                ));
            }
        }
        RoutingActivity::Apply if context.stage.is_some() => {
            return Err(RoutingDiagnostic::new(
                "source.stage",
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
                    format!("source.fields.{field}"),
                    RoutingDiagnosticReason::UnknownField,
                )
            })?;
            let schema = JSONSchema::options()
                .with_draft(Draft::Draft202012)
                .compile(&descriptor.schema)
                .map_err(|_| {
                    RoutingDiagnostic::new(
                        format!("source.fields.{field}"),
                        RoutingDiagnosticReason::UnknownField,
                    )
                })?;
            if schema.validate(value).is_err() {
                return Err(RoutingDiagnostic::new(
                    format!("source.fields.{field}"),
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
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
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
                "routing[0].when.stage",
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
                "routing[0].when.fields.region",
                RoutingDiagnosticReason::InvalidPredicateValue,
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
                "routing[1]",
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
                "source.fields.region",
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
