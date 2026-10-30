// SPDX-License-Identifier: Apache-2.0
//! `breg.read-in-force/v1`: the one record of a date-interval register that
//! is in force on a date, read with a single effective-time `:as-of` request.
//!
//! The author names the record type, the subject fields that identify the
//! thing the interval is about, and a calendar date. The adapter builds the
//! BReg `$filter` itself from the subject; no author text reaches the query
//! grammar except as a quoted literal or a validated number, so a subject value
//! cannot widen the filter. Asking for two rows is how the adapter tells one
//! record in force from an overlap without paging.

use std::collections::{BTreeMap, BTreeSet};

use chrono::NaiveDate;
use registry_breg_client::{BRegAsOfListRequest, BRegRecordOptions, BaseRegistryClient};
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};

use crate::{
    adapters::{read_failure, refused},
    definition::{Mapping, Member, Reference, Step, Workflow},
    protocol::{CallOutcome, DeclaredRefusal, HoldDetail, Operation},
};

/// The code a step receives on `onDeclaredRefusal` when no record is in force.
pub(crate) const NONE_IN_FORCE: &str = "none-in-force";
/// The failure code for two records in force on one date. The run is held, not
/// failed or retried: the register itself is wrong and needs a person.
pub(crate) const IN_FORCE_AMBIGUOUS: &str = "in-force-ambiguous";

/// A BReg `$filter` allows at most 32 predicates; the subject is capped well
/// below that so a mapping mistake fails at check time, not at the register.
pub(crate) const MAX_SUBJECT_FIELDS: usize = 16;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_LITERAL_BYTES: usize = 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct InForceRequest {
    /// The BReg record-type route, for example `assignments`.
    entity: String,
    /// The fields that identify the subject, each matched for equality.
    subject: BTreeMap<String, SubjectValue>,
    /// The calendar date, `YYYY-MM-DD`, sent to BReg as is.
    date: String,
}

/// A subject value the filter can carry as an equality literal.
#[derive(Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) enum SubjectValue {
    Text(String),
    Number(Number),
    Flag(bool),
}

/// The record in force on the date, with the Coordinator's own observation
/// time. `asOf` is the requested date, not a BReg echo.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct InForceRecord {
    record_identifier: String,
    revision_identifier: String,
    domain_data: BTreeMap<String, Value>,
    as_of: String,
    observed_at: String,
}

/// The single point that turns the step's calendar date into BReg's `asOf`.
/// BReg reads a date interval as of a calendar date, so the date goes as is.
fn as_of_parameter(date: &str) -> Option<String> {
    let parsed = NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    // Reject unpadded and otherwise lenient spellings the parser accepts.
    (parsed.format("%Y-%m-%d").to_string() == date).then(|| date.to_owned())
}

fn identifier_is_valid(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first == b'_')
        && name.len() <= MAX_IDENTIFIER_BYTES
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn literal(value: &SubjectValue) -> Option<String> {
    match value {
        SubjectValue::Text(text) => {
            if text.len() > MAX_LITERAL_BYTES || text.chars().any(char::is_control) {
                return None;
            }
            Some(format!("'{}'", text.replace('\'', "''")))
        }
        SubjectValue::Number(number) => {
            let text = number.to_string();
            // BReg accepts plain integers and decimals; exponent form is not
            // in its literal grammar.
            (!text.contains(['e', 'E'])).then_some(text)
        }
        SubjectValue::Flag(flag) => Some(flag.to_string()),
    }
}

/// `name eq literal and ...` in name order, or `None` when any name or value
/// falls outside what the filter grammar can carry as data.
fn subject_filter(subject: &BTreeMap<String, SubjectValue>) -> Option<String> {
    if subject.is_empty() || subject.len() > MAX_SUBJECT_FIELDS {
        return None;
    }
    let mut predicates = Vec::with_capacity(subject.len());
    for (name, value) in subject {
        if !identifier_is_valid(name) {
            return None;
        }
        predicates.push(format!("{name} eq {}", literal(value)?));
    }
    Some(predicates.join(" and "))
}

pub(crate) async fn read_in_force(
    client: &BaseRegistryClient,
    options: &BRegRecordOptions,
    input: &Value,
) -> CallOutcome {
    let Ok(input) = serde_json::from_value::<InForceRequest>(input.clone()) else {
        return refused("invalid-command");
    };
    let (Some(as_of), Some(filter)) =
        (as_of_parameter(&input.date), subject_filter(&input.subject))
    else {
        return refused("invalid-command");
    };
    // `top(2)` is the whole ambiguity check: one row is the answer, two rows
    // is an overlap, and a third is never needed to know that.
    let Ok(request) = BRegAsOfListRequest::new(as_of)
        .and_then(|request| request.options(options.clone()).filter(filter))
        .and_then(|request| request.top(2))
    else {
        return refused("invalid-command");
    };
    let answer = match client.list_records_as_of(&input.entity, &request).await {
        Ok(answer) => answer,
        Err(error) => return read_failure(error),
    };
    let observed_at = crate::record_read::observed_at_now();
    let mut items = answer.value.value.items;
    match items.len() {
        0 => DeclaredRefusal::new(NONE_IN_FORCE)
            .map(CallOutcome::DeclaredRefusal)
            .unwrap_or_else(|| refused("invalid-response")),
        1 => {
            let record = items.remove(0);
            match serde_json::to_value(InForceRecord {
                record_identifier: record.record_identifier,
                revision_identifier: record.revision_identifier,
                domain_data: record.domain_data,
                as_of: input.date,
                observed_at,
            }) {
                Ok(value) => CallOutcome::Success(value),
                Err(_) => refused("invalid-response"),
            }
        }
        2 => CallOutcome::InForceAmbiguous(HoldDetail {
            date: input.date,
            record_identifiers: items
                .into_iter()
                .map(|record| record.record_identifier)
                .collect(),
        }),
        _ => refused("invalid-response"),
    }
}

/// The subject fields a call names, when the mapping spells them out as a
/// literal or as nested fields. A subject built by a Function or read whole
/// from input is not known until the run.
fn literal_subject_fields(input: &Mapping) -> Option<BTreeSet<&str>> {
    let subject = match input {
        Mapping::Fields { fields } => match fields.get("subject")? {
            Member::Reference(Reference::Literal { value }) => value,
            Member::Fields(nested) => {
                return Some(nested.fields.keys().map(String::as_str).collect())
            }
            Member::Reference(_) => return None,
        },
        Mapping::Reference(Reference::Literal { value }) => value.get("subject")?,
        _ => return None,
    };
    Some(subject.as_object()?.keys().map(String::as_str).collect())
}

/// The scopes of the record type's non-overlap constraints, as the narrowed
/// subject schema carries them.
fn non_overlap_scopes(workflow: &Workflow, alias: &str) -> Vec<Vec<String>> {
    workflow
        .operations
        .get(alias)
        .and_then(|operation| {
            operation.input["properties"]["subject"]["x-registry-in-force-scopes"].as_array()
        })
        .map(|scopes| {
            scopes
                .iter()
                .map(|scope| {
                    scope
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|field| field.as_str().map(str::to_owned))
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The steps whose read could find two records in force for one subject on one
/// date. One record per subject is guaranteed only when a non-overlap
/// constraint's scope fields are all among the subject's fields; with no
/// constraint nothing prevents an overlap, and a subject built at run time
/// cannot be judged against a constraint that exists.
pub(crate) fn steps_that_may_be_ambiguous(workflow: &Workflow) -> Vec<&str> {
    workflow
        .steps
        .iter()
        .filter_map(|(name, step)| {
            let Step::Call { call, input, .. } = step else {
                return None;
            };
            if call.operation != Operation::ReadInForce {
                return None;
            }
            let scopes = non_overlap_scopes(workflow, &call.alias);
            let may_overlap = if scopes.is_empty() {
                true
            } else {
                literal_subject_fields(input).is_some_and(|fields| {
                    !scopes
                        .iter()
                        .any(|scope| scope.iter().all(|field| fields.contains(field.as_str())))
                })
            };
            may_overlap.then_some(name.as_str())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn subject(value: Value) -> BTreeMap<String, SubjectValue> {
        serde_json::from_value(value).expect("subject values are scalars")
    }

    #[test]
    fn the_filter_quotes_text_and_leaves_numbers_and_flags_bare() {
        assert_eq!(
            subject_filter(&subject(json!({
                "district": "O'Brien's", "grade": 7, "hours": 7.5, "lead": true, "debt": -3
            }))),
            Some("debt eq -3 and district eq 'O''Brien''s' and grade eq 7 and hours eq 7.5 and lead eq true".into())
        );
    }

    #[test]
    fn a_name_or_value_the_grammar_cannot_carry_has_no_filter() {
        let long_name = "a".repeat(129);
        let long_text = "x".repeat(1025);
        for (case, value) in [
            ("empty subject", json!({})),
            ("upper-case first letter", json!({"District": "x"})),
            ("leading digit", json!({"1st": "x"})),
            ("space in the name", json!({"a b": "x"})),
            ("filter fragment as a name", json!({"a eq 'x' or b": "x"})),
            ("name over the bound", json!({ long_name: "x" })),
            ("control character", json!({"a": "x\ny"})),
            ("text over the bound", json!({"a": long_text})),
            ("exponent number", json!({"a": 1e30})),
        ] {
            assert_eq!(subject_filter(&subject(value)), None, "{case}");
        }
    }

    #[test]
    fn a_subject_over_the_field_cap_has_no_filter() {
        let wide: serde_json::Map<String, Value> = (0..=MAX_SUBJECT_FIELDS)
            .map(|index| (format!("f{index}"), json!("x")))
            .collect();
        assert_eq!(subject_filter(&subject(Value::Object(wide))), None);
    }

    #[test]
    fn only_a_padded_calendar_date_is_sent_and_it_is_sent_as_the_date() {
        assert_eq!(as_of_parameter("2026-06-05").as_deref(), Some("2026-06-05"));
        for bad in [
            "2026-02-30",
            "2026-6-5",
            "26-06-05",
            "2026-06-05T00:00:00Z",
            " 2026-06-05",
            "",
        ] {
            assert_eq!(as_of_parameter(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn null_array_and_object_subject_values_do_not_decode() {
        for value in [json!(null), json!(["a"]), json!({"a": 1})] {
            assert!(
                serde_json::from_value::<BTreeMap<String, SubjectValue>>(json!({"k": value}))
                    .is_err()
            );
        }
    }
}
