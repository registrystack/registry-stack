// SPDX-License-Identifier: Apache-2.0

//! The per-operation result schema: one derivation shared by `adapterctl
//! check`, the fixture response check, and the runtime's final-exchange
//! body validation, so the three never diverge (`products/adapter/CONCEPT.md`
//! section 6). The schema vocabulary is closed: `object` with
//! `properties`, `required`, and `additionalProperties: false`; `array`
//! with `items`; and the scalars `string`, `integer`, `number`,
//! `boolean`, and `null`.

use crate::diagnostics::{finding, CheckCode};
use crate::envelope::{
    decode_slot, parse_envelope_template, SlotForm, ENVELOPE_GRAMMAR_RULE, SLOT_MARK,
};
use crate::profile::{AdapterProfile, ParameterizedPart};
use crate::project::{AdapterProject, Binding, RecordFieldType, RecordType};
use registry_platform_yaml::Diagnostic;
use serde_json::{json, Map, Value};

/// The derived schema of one facade operation's response body
/// (`products/adapter/CONCEPT.md` section 6): the operation's response
/// envelope with every slot replaced by the closed schema of what fills
/// it, and the `record` and `records` slots expanded from the record type
/// the deployment binds to the operation. An operation bound more than
/// once resolves through its first binding; a concrete derivation for a
/// named binding is [`derive_binding_result_schema`]. Errors are
/// value-free and name the configuration gap: an unknown operation, an
/// envelope that is not a JSON template, or a result slot with no binding
/// to a declared record type.
pub fn derive_operation_result_schema(
    profile: &AdapterProfile,
    project: &AdapterProject,
    operation_id: &str,
) -> Result<Value, String> {
    let operation = profile
        .operations
        .get(operation_id)
        .ok_or_else(|| format!("the profile declares no operation {operation_id}"))?;
    let template = parse_envelope_template(operation.response_envelope.text())?;
    let binding = project
        .bindings
        .iter()
        .find(|binding| binding.operation.as_str() == operation_id);
    derive_value(
        &template,
        binding,
        Some(project),
        &profile.parameterized_parts,
    )
}

/// The derived schema of one binding's response body: the bound
/// operation's response envelope with every slot replaced by the closed
/// schema of what fills it, and the `record` and `records` slots expanded
/// from the record type this binding names: the per-binding resolution
/// the compiled contract needs, where one operation serves several bound
/// record types (`products/adapter/CONCEPT.md` sections 6 and 7). A
/// parameterized part derives as a plain string, never as its stand-in
/// literal, because the contract cannot know the deployment's value.
pub fn derive_binding_result_schema(
    profile: &AdapterProfile,
    project: &AdapterProject,
    binding: &Binding,
) -> Result<Value, String> {
    let operation = profile
        .operations
        .get(binding.operation.as_str())
        .ok_or_else(|| {
            format!(
                "the binding names operation {}, which the profile does not declare",
                binding.operation.as_str()
            )
        })?;
    let template = parse_envelope_template(operation.response_envelope.text())?;
    derive_value(
        &template,
        Some(binding),
        Some(project),
        &profile.parameterized_parts,
    )
}

/// The derived schema of one binding's request body: the bound
/// operation's request envelope derived like
/// [`derive_binding_result_schema`], with the `record` slot expanded from
/// the binding's record type. An operation that declares no request
/// envelope is refused by name of the fault.
pub fn derive_operation_request_schema(
    profile: &AdapterProfile,
    project: &AdapterProject,
    binding: &Binding,
) -> Result<Value, String> {
    let operation = profile
        .operations
        .get(binding.operation.as_str())
        .ok_or_else(|| {
            format!(
                "the binding names operation {}, which the profile does not declare",
                binding.operation.as_str()
            )
        })?;
    let request_envelope = operation.request_envelope.as_ref().ok_or_else(|| {
        format!(
            "the operation {} declares no request envelope",
            binding.operation.as_str()
        )
    })?;
    let template = parse_envelope_template(request_envelope.text())?;
    derive_value(
        &template,
        Some(binding),
        Some(project),
        &profile.parameterized_parts,
    )
}

/// The derived schema of the profile's problem envelope
/// (`products/adapter/CONCEPT.md` section 7): the envelope template with
/// every slot replaced by the closed schema of what fills it. The same
/// single-source discipline as [`derive_operation_result_schema`]:
/// `adapterctl check`, the fixture error-path check, and the runtime's
/// problem-body validation all call this, so the three never diverge. A
/// problem envelope naming a record slot is refused: a problem carries
/// the problem slots, never a record.
pub fn derive_problem_envelope_schema(profile: &AdapterProfile) -> Result<Value, String> {
    let template = parse_envelope_template(profile.problem_envelope.text())?;
    derive_value(&template, None, None, &profile.parameterized_parts)
}

/// The derivation error an envelope carrying a record slot raises when the
/// operation has no binding: the one derivation failure a workspace may
/// carry, because binding completeness is the project check's concern.
pub(crate) const UNBOUND_RECORD_SLOT: &str =
    "the response envelope carries a record slot, but the operation has no binding to a record type";

/// The profile-level envelope derivation check: every operation's result
/// schema and the problem-envelope schema are derived once per workspace
/// check, independent of fixtures, so a malformed envelope is a finding
/// even where no fixture exercises the operation (addendum D). Findings
/// carry the derivation fault in the finding's message. An operation no
/// binding binds may leave its record slot unexpanded: that is the one
/// derivation failure a workspace may carry.
pub fn check_envelope_derivation(
    profile: &AdapterProfile,
    project: &AdapterProject,
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    for (index, operation) in profile.operations.iter().enumerate() {
        if let Err(reason) = derive_operation_result_schema(profile, project, operation.id.as_str())
        {
            let unbound = reason == UNBOUND_RECORD_SLOT
                && project
                    .bindings
                    .iter()
                    .all(|binding| binding.operation.as_str() != operation.id.as_str());
            if !unbound {
                findings.push(finding(
                    CheckCode::ProfileResponseEnvelopeUncompilable,
                    &format!("/operations/{index}/responseEnvelope"),
                    &reason,
                    "Repair the response envelope so the operation's result schema can be derived.",
                ));
            }
        }
    }
    if let Err(reason) = derive_problem_envelope_schema(profile) {
        findings.push(finding(
            CheckCode::ProfileProblemEnvelopeUncompilable,
            "/problemEnvelope",
            &reason,
            "Repair the problem envelope so the problem schema can be derived.",
        ));
    }
    findings
}

/// Derives the schema of one template value.
fn derive_value(
    template: &Value,
    binding: Option<&Binding>,
    project: Option<&AdapterProject>,
    parts: &[ParameterizedPart],
) -> Result<Value, String> {
    match template {
        Value::String(text) => Ok(derive_member(text, binding, project, parts)?.0),
        Value::Object(members) => {
            let mut properties = Map::new();
            let mut required = Vec::new();
            for (key, value) in members {
                if key.contains(SLOT_MARK) {
                    return Err(ENVELOPE_GRAMMAR_RULE.to_string());
                }
                let text = value.as_str();
                let (schema, optional) = match text.and_then(decode_slot) {
                    Some((name, form)) => (
                        form_schema(slot_schema(name, binding, project)?, form),
                        form == SlotForm::Optional,
                    ),
                    None => (derive_value(value, binding, project, parts)?, false),
                };
                properties.insert(key.clone(), schema);
                if !optional {
                    required.push(Value::String(key.clone()));
                }
            }
            // The required names sort explicitly, so the derived schema
            // never depends on the map's iteration order.
            required.sort_by(|left, right| {
                left.as_str()
                    .unwrap_or_default()
                    .cmp(right.as_str().unwrap_or_default())
            });
            Ok(json!({
                "type": "object",
                "properties": Value::Object(properties),
                "required": required,
                "additionalProperties": false,
            }))
        }
        Value::Array(items) => {
            let mut items_schema: Option<Value> = None;
            for item in items {
                if matches!(
                    item.as_str().and_then(decode_slot),
                    Some((_, SlotForm::Optional | SlotForm::Null))
                ) {
                    return Err(
                        "an optional or null slot fills an object member, never an array item"
                            .to_string(),
                    );
                }
                let schema = derive_value(item, binding, project, parts)?;
                match &items_schema {
                    Some(previous) if previous != &schema => {
                        return Err(
                            "the response envelope template carries array members of different shapes"
                                .to_string(),
                        );
                    }
                    _ => items_schema = Some(schema),
                }
            }
            Ok(json!({
                "type": "array",
                "items": items_schema.unwrap_or_else(|| json!({"type": "null"})),
            }))
        }
        Value::Number(number) => Ok(json!({"type": "number", "const": number})),
        Value::Bool(boolean) => Ok(json!({"type": "boolean", "const": boolean})),
        Value::Null => Ok(json!({"type": "null"})),
    }
}

/// One object member's schema and whether it may be absent: a whole-value
/// optional slot (`{{?slot}}`) is optional, everything else is required. A
/// literal standing for a declared parameterized part derives as a plain
/// string: the deployment declares the part's value, so the contract
/// cannot carry it as a constant.
fn derive_member(
    text: &str,
    binding: Option<&Binding>,
    project: Option<&AdapterProject>,
    parts: &[ParameterizedPart],
) -> Result<(Value, bool), String> {
    match decode_slot(text) {
        Some((name, form)) => Ok((
            form_schema(slot_schema(name, binding, project)?, form),
            form == SlotForm::Optional,
        )),
        None if text.contains(SLOT_MARK) => Err(ENVELOPE_GRAMMAR_RULE.to_string()),
        None if parts.iter().any(|part| part.name.as_str() == text) => {
            Ok((json!({"type": "string"}), false))
        }
        None => Ok((json!({"type": "string", "const": text}), false)),
    }
}

/// A null slot is present and may be `null`: its schema admits either.
fn form_schema(schema: Value, form: SlotForm) -> Value {
    match form {
        SlotForm::Null => json!({"anyOf": [schema, {"type": "null"}]}),
        SlotForm::Required | SlotForm::Optional => schema,
    }
}

/// The closed schema of what fills one envelope slot: the bound record
/// type for `record` and `records`, typed scalars for the engine-filled
/// slots.
fn slot_schema(
    name: &str,
    binding: Option<&Binding>,
    project: Option<&AdapterProject>,
) -> Result<Value, String> {
    match name {
        "record" => record_schema(binding, project),
        "records" => record_schema(binding, project)
            .map(|schema| json!({"type": "array", "items": schema})),
        "nextCursor" | "problemCode" | "problemDetail" | "problemTitle" | "recordId"
        | "recordType" | "requestId" => Ok(json!({"type": "string"})),
        "status" => Ok(json!({"type": "integer"})),
        other => Err(format!(
            "the response envelope names slot {other}, which the closed slot vocabulary does not declare"
        )),
    }
}

/// The closed schema of one record the bound record type declares: every
/// declared field typed, required where declared, and no other member. The
/// runtime checks each record a route produces against it before the
/// facade discloses the record.
pub fn binding_record_schema(project: &AdapterProject, binding: &Binding) -> Result<Value, String> {
    record_schema(Some(binding), Some(project))
}

fn record_schema(
    binding: Option<&Binding>,
    project: Option<&AdapterProject>,
) -> Result<Value, String> {
    let (Some(binding), Some(project)) = (binding, project) else {
        return Err(UNBOUND_RECORD_SLOT.to_string());
    };
    let record_type = project
        .record_types
        .get(binding.record_type.as_str())
        .ok_or_else(|| "the binding names no declared record type".to_string())?;
    Ok(record_object_schema(record_type))
}

fn record_object_schema(record_type: &RecordType) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in record_type.fields.iter() {
        properties.insert(field.name.as_str().to_string(), field_schema(field.r#type));
        if field.required {
            required.push(Value::String(field.name.as_str().to_string()));
        }
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required,
        "additionalProperties": false,
    })
}

fn field_schema(field_type: RecordFieldType) -> Value {
    match field_type {
        RecordFieldType::String => json!({"type": "string"}),
        RecordFieldType::Integer => json!({"type": "integer"}),
        RecordFieldType::Decimal => json!({"type": "number"}),
        RecordFieldType::Boolean => json!({"type": "boolean"}),
        RecordFieldType::Date => json!({"type": "string", "format": "date"}),
        RecordFieldType::DateTime => json!({"type": "string", "format": "date-time"}),
    }
}

/// Checks one value against a derived result schema, returning the JSON
/// pointer of every violation: a value of the wrong type, an object key
/// the schema does not declare, or a missing required key. Pointers are
/// value-free; the checked value is never echoed.
#[must_use]
pub fn validate_result_schema(value: &Value, schema: &Value) -> Vec<String> {
    let mut violations = Vec::new();
    validate_at(value, schema, "", &mut violations);
    violations
}

fn validate_at(value: &Value, schema: &Value, pointer: &str, violations: &mut Vec<String>) {
    if let Some(branches) = schema.get("anyOf").and_then(Value::as_array) {
        let admitted = branches.iter().any(|branch| {
            let mut branch_violations = Vec::new();
            validate_at(value, branch, pointer, &mut branch_violations);
            branch_violations.is_empty()
        });
        if !admitted {
            violations.push(pointer.to_string());
        }
        return;
    }
    if let Some(fixed) = schema.get("const") {
        if value != fixed {
            violations.push(pointer.to_string());
            return;
        }
    }
    let Some(expected) = schema.get("type").and_then(Value::as_str) else {
        return;
    };
    if !type_matches(value, expected) {
        violations.push(pointer.to_string());
        return;
    }
    match expected {
        "string" => {
            let well_formed = match (schema.get("format").and_then(Value::as_str), value.as_str()) {
                (Some("date"), Some(text)) => is_date(text),
                (Some("date-time"), Some(text)) => is_date_time(text),
                _ => true,
            };
            if !well_formed {
                violations.push(pointer.to_string());
            }
        }
        "object" => {
            let Some(members) = value.as_object() else {
                return;
            };
            let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
                return;
            };
            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                for key in members.keys() {
                    if !properties.contains_key(key) {
                        violations.push(format!("{}/{}", pointer, escape_token(key)));
                    }
                }
            }
            let required = schema.get("required").and_then(Value::as_array);
            for (key, member_schema) in properties {
                match members.get(key) {
                    Some(member) => validate_at(
                        member,
                        member_schema,
                        &format!("{}/{}", pointer, escape_token(key)),
                        violations,
                    ),
                    None => {
                        let required_member = required.is_some_and(|names| {
                            names.iter().any(|name| name.as_str() == Some(key.as_str()))
                        });
                        if required_member {
                            violations.push(format!("{}/{}", pointer, escape_token(key)));
                        }
                    }
                }
            }
        }
        "array" => {
            if let (Some(items), Some(members)) = (schema.get("items"), value.as_array()) {
                for (index, member) in members.iter().enumerate() {
                    validate_at(member, items, &format!("{pointer}/{index}"), violations);
                }
            }
        }
        _ => {}
    }
}

/// A calendar date in `YYYY-MM-DD` form that exists.
pub fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = &text[range];
        if part.bytes().all(|byte| byte.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let longest = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=longest).contains(&day)
}

/// An RFC 3339 date-time: a date, `T`, a time with optional fraction, and
/// `Z` or a numeric offset.
pub fn is_date_time(text: &str) -> bool {
    let Some((date, rest)) = text.split_once(['T', 't']) else {
        return false;
    };
    if !is_date(date) {
        return false;
    }
    let (time, offset) = match rest.find(['Z', 'z', '+', '-']) {
        Some(index) => rest.split_at(index),
        None => return false,
    };
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (time, None),
    };
    if fraction
        .is_some_and(|digits| digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let field = |text: &str, limit: u32| {
        text.len() == 2
            && text.bytes().all(|byte| byte.is_ascii_digit())
            && text.parse::<u32>().is_ok_and(|value| value <= limit)
    };
    let parts: Vec<&str> = clock.split(':').collect();
    let clock_ok =
        parts.len() == 3 && field(parts[0], 23) && field(parts[1], 59) && field(parts[2], 60);
    let offset_ok = match offset {
        "Z" | "z" => true,
        _ => {
            let numeric = &offset[1..];
            numeric
                .split_once(':')
                .is_some_and(|(hours, minutes)| field(hours, 23) && field(minutes, 59))
        }
    };
    clock_ok && offset_ok
}

fn type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
}

/// Escapes one object key for a JSON pointer (`~` to `~0`, `/` to `~1`).
fn escape_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Checks one fixture entry's expected facade response body against the
/// schema the entry's expected status selects, refusing every violation,
/// and a missing body, under `adapter.fixture.response-schema` at the
/// fixture path it concerns. A 2xx expected status validates against the
/// operation's result schema; any other expected status validates
/// against the profile's problem envelope (CONCEPT section 6), so an
/// honest error-path suite is not refused as if it promised a record.
/// A problem expectation carries no body to validate: the class-and-code
/// resolution is the fixture checks' concern. Both schemas come
/// pre-derived: the caller derives each once per workspace check and
/// reuses it (addendum ruling). The caller pairs entries with
/// operations; core stays no-I/O.
#[must_use]
pub fn check_fixture_expected_response(
    entry_index: usize,
    expected: &crate::fixture::ExpectedFacade,
    result_schema: &Value,
    problem_schema: &Value,
) -> Vec<Diagnostic> {
    let crate::fixture::ExpectedFacade::Response { status, body, .. } = expected else {
        return Vec::new();
    };
    let two_hundred = registry_platform_yaml::BoundedU32::<200, 299>::new(status.get());
    let is_result = two_hundred.is_ok();
    let kind = if is_result {
        "the operation's result schema"
    } else {
        "the profile's problem envelope"
    };
    let Some(body) = body.as_ref() else {
        return vec![finding(
            CheckCode::FixtureResponseSchema,
            &format!("/entries/{entry_index}/expected"),
            &format!("the fixture expects no facade response body where {kind} requires one"),
            if is_result {
                "Give the entry the facade body the profile envelope and the bound record type produce."
            } else {
                "Give the entry the problem body the profile's problem envelope produces."
            },
        )];
    };
    // An explicit JSON `null` body is a body (G-FIXTURES): it validates
    // as the null value, never as an absent one.
    let body = body.as_value();
    let schema = if is_result {
        result_schema
    } else {
        problem_schema
    };
    validate_result_schema(body, schema)
        .into_iter()
        .map(|violation| {
            finding(
                CheckCode::FixtureResponseSchema,
                &format!("/entries/{entry_index}/expected/body{violation}"),
                &format!("the fixture's expected facade response body does not match {kind}"),
                if is_result {
                    "Bring the expected body in line with the profile envelope and the bound record type."
                } else {
                    "Bring the expected body in line with the profile's problem envelope."
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn dates_and_date_times_are_checked_for_shape_and_calendar() {
        assert!(is_date("2024-02-29"));
        assert!(!is_date("2023-02-29"));
        assert!(!is_date("2023-13-01"));
        assert!(!is_date("23-01-01"));
        assert!(!is_date("2023-1-001"));
        assert!(is_date_time("2024-05-01T10:20:30Z"));
        assert!(is_date_time("2024-05-01T10:20:30.123+02:00"));
        assert!(is_date_time("2024-05-01T10:20:30-05:30"));
        assert!(!is_date_time("2024-05-01T10:20:30"));
        assert!(!is_date_time("2024-05-01 10:20:30Z"));
        assert!(!is_date_time("2024-05-01T25:20:30Z"));
        assert!(!is_date_time("2024-05-01T10:20:30.Z"));
        assert!(!is_date_time("2024-05-01T10:20:30+0200"));
    }

    #[test]
    fn a_record_with_a_malformed_date_is_a_violation() {
        let schema = json!({"type":"object","properties":{"born":{"type":"string","format":"date"}},"required":["born"],"additionalProperties":false});
        let mut found = Vec::new();
        validate_at(&json!({"born":"2024-02-30"}), &schema, "", &mut found);
        assert_eq!(found, vec!["/born".to_owned()]);
        let mut found = Vec::new();
        validate_at(&json!({"born":"2024-02-28"}), &schema, "", &mut found);
        assert!(found.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{ExpectedFacade, RecordedHeaders};
    use crate::profile::{EnvelopeTemplate, ParameterizedPart, ProfileOperation};
    use crate::project::{Binding, PinnedRef, ProjectIdentity, RecordField};
    use crate::route::TemplatedRoute;
    use registry_platform_yaml::{
        BoundedU64, Digest, ExternalId, LocalId, UniqueIdList, UniqueList,
    };

    fn external(text: &str) -> ExternalId {
        ExternalId::new(text).expect("id")
    }

    fn local(text: &str) -> LocalId {
        LocalId::new(text).expect("id")
    }

    fn pin(id: &str) -> PinnedRef {
        PinnedRef {
            id: local(id),
            version: "1.0.0".to_string(),
            digest: Digest::new(
                "sha256:678260a56715cba21db1f0687e5a2c5e5efb2ea0b8eea687b5f3ee8723c5f6c9",
            )
            .expect("digest"),
        }
    }

    fn operation(envelope: &str) -> ProfileOperation {
        ProfileOperation {
            id: local("cases-find"),
            method: crate::model::HttpMethod::Get,
            path: "/v2/cases".to_string(),
            path_parameters: UniqueList::new(Vec::new()).expect("empty"),
            record_type_parameter: local("type"),
            record_id_parameter: None,
            success_status: registry_platform_yaml::BoundedU32::new(200).expect("status"),
            request_envelope: None,
            response_envelope: EnvelopeTemplate(envelope.to_string()),
            pagination: None,
        }
    }

    fn profile(envelope: &str) -> AdapterProfile {
        AdapterProfile {
            version: "1.0.0".to_string(),
            id: local("case-api"),
            operations: UniqueIdList::new(vec![operation(envelope)]).expect("unique"),
            problems: UniqueIdList::new(vec![crate::profile::Problem {
                code: external("cases.conflict"),
                status: registry_platform_yaml::BoundedU32::<400, 599>::new(409).expect("status"),
                title: "the record was already there".to_string(),
                classes: UniqueList::new(vec![crate::model::ErrorClass::OutcomeConflict])
                    .expect("unique"),
            }])
            .expect("unique"),
            problem_envelope: EnvelopeTemplate(r#"{"code": "{{problemCode}}"}"#.to_string()),
            parameterized_parts: UniqueList::new(Vec::new()).expect("empty"),
        }
    }

    fn record_type() -> RecordType {
        RecordType {
            name: local("case"),
            fields: UniqueList::new(vec![
                RecordField {
                    name: local("id"),
                    r#type: RecordFieldType::String,
                    required: true,
                },
                RecordField {
                    name: local("region"),
                    r#type: RecordFieldType::String,
                    required: false,
                },
                RecordField {
                    name: local("opened-on"),
                    r#type: RecordFieldType::Date,
                    required: false,
                },
            ])
            .expect("unique"),
        }
    }

    fn project(bound: bool) -> AdapterProject {
        AdapterProject {
            project: ProjectIdentity {
                id: local("case-deployment"),
                version: "1.0.0".to_string(),
            },
            profile: pin("case-api"),
            pack: pin("case-api-pack"),
            record_types: UniqueIdList::new(vec![record_type()]).expect("unique"),
            templated_routes: UniqueIdList::<TemplatedRoute>::new(Vec::new()).expect("empty"),
            bindings: UniqueIdList::new(if bound {
                vec![Binding {
                    id: local("find-cases"),
                    operation: external("cases-find"),
                    record_type: local("case"),
                    route: external("fetch-cases"),
                    filters: UniqueList::new(Vec::new()).expect("unique"),
                    maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
                }]
            } else {
                Vec::new()
            })
            .expect("unique"),
            access_profiles: UniqueIdList::new(Vec::new()).expect("empty"),
            parameterized_parts: Default::default(),
        }
    }

    /// An envelope literal derives as a const: a body carrying a
    /// different literal refuses at its pointer, the fixed literal
    /// passes (`products/adapter/CONCEPT.md` section 7).
    #[test]
    fn envelope_literals_derive_as_const() {
        let profile = profile(r#"{"resourceType": "Bundle", "entry": {{records}}}"#);
        let schema =
            derive_operation_result_schema(&profile, &project(true), "cases-find").expect("derive");
        assert_eq!(
            schema["properties"]["resourceType"],
            json!({"type": "string", "const": "Bundle"})
        );
        let good = json!({"resourceType": "Bundle", "entry": [{"id": "c-1"}]});
        assert!(validate_result_schema(&good, &schema).is_empty());
        let other = json!({"resourceType": "Patient", "entry": []});
        assert_eq!(
            validate_result_schema(&other, &schema),
            vec!["/resourceType"]
        );
    }

    /// A null slot is a required member that admits `null`: the derived
    /// schema accepts a string or `null`, refuses a missing member, and
    /// refuses a null slot standing as an array item.
    #[test]
    fn a_null_slot_derives_as_a_required_nullable_member() {
        let nullable = profile(r#"{"items": {{records}}, "next": {{??nextCursor}}}"#);
        let schema = derive_operation_result_schema(&nullable, &project(true), "cases-find")
            .expect("derive");
        let required = schema["required"].as_array().expect("required");
        assert!(required.iter().any(|name| name == "next"));
        for body in [
            json!({"items": [], "next": null}),
            json!({"items": [], "next": "abc"}),
        ] {
            assert!(validate_result_schema(&body, &schema).is_empty(), "{body}");
        }
        assert_eq!(
            validate_result_schema(&json!({"items": [], "next": 3}), &schema),
            vec!["/next"]
        );
        assert_eq!(
            validate_result_schema(&json!({"items": []}), &schema),
            vec!["/next"]
        );
        let in_array = profile(r#"{"items": ["{{??nextCursor}}"]}"#);
        assert!(derive_operation_result_schema(&in_array, &project(true), "cases-find").is_err());
    }

    /// A placeholder inside a longer string never binds: the derivation
    /// refuses with the envelope grammar rule, for the response envelope
    /// and the problem envelope alike.
    #[test]
    fn a_mid_string_slot_refuses_with_the_envelope_grammar_rule() {
        let response_profile = profile(r#"{"code": "CASE-{{recordId}}"}"#);
        assert_eq!(
            derive_operation_result_schema(&response_profile, &project(true), "cases-find")
                .expect_err("mid-string slot"),
            ENVELOPE_GRAMMAR_RULE
        );
        let mut problem_profile = profile(r#"{{record}}"#);
        problem_profile.problem_envelope =
            EnvelopeTemplate(r#"{"code": "CASE-{{problemCode}}"}"#.to_string());
        assert_eq!(
            derive_problem_envelope_schema(&problem_profile).expect_err("mid-string slot"),
            ENVELOPE_GRAMMAR_RULE
        );
    }

    /// The derivation expands the `record` and `records` slots from the
    /// bound record type, keeps the profile's own envelope shape closed,
    /// and carries the profile's literal slots as typed scalars.
    #[test]
    fn derive_expands_the_bound_record_type_into_the_envelope() {
        let profile = profile(
            r#"{"record": {{record}}, "recordType": "{{recordType}}", "cases": {{records}}}"#,
        );
        let deployment = project(true);
        let schema =
            derive_operation_result_schema(&profile, &deployment, "cases-find").expect("derive");
        // The required names sort explicitly, whatever order the envelope
        // template declares its members in.
        assert_eq!(schema["required"], json!(["cases", "record", "recordType"]));
        assert_eq!(schema["additionalProperties"], json!(false));
        assert_eq!(schema["properties"]["record"]["required"], json!(["id"]));
        assert_eq!(
            schema["properties"]["record"]["additionalProperties"],
            json!(false)
        );
        assert_eq!(
            schema["properties"]["record"]["properties"]["opened-on"],
            json!({"type": "string", "format": "date"})
        );
        assert_eq!(
            schema["properties"]["cases"]["items"]["required"],
            json!(["id"])
        );
        assert_eq!(schema["properties"]["cases"]["type"], json!("array"));
        assert_eq!(
            schema["properties"]["recordType"],
            json!({"type": "string"})
        );
    }

    /// A whole-body record slot derives the record schema itself; an
    /// operation with no binding, and an unknown operation, are refused.
    #[test]
    fn derive_accepts_a_whole_body_record_slot_and_refuses_an_unbound_one() {
        let profile = profile(r#"{{record}}"#);
        let schema =
            derive_operation_result_schema(&profile, &project(true), "cases-find").expect("derive");
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["required"], json!(["id"]));
        assert!(
            derive_operation_result_schema(&profile, &project(false), "cases-find").is_err(),
            "a result slot without a binding is refused"
        );
        assert!(
            derive_operation_result_schema(&profile, &project(true), "cases-missing").is_err(),
            "an unknown operation is refused"
        );
    }

    /// Validation refuses extra members, members of the wrong type, and
    /// missing required members, each at its pointer; a conforming value,
    /// including one omitting optional members, passes.
    #[test]
    fn validate_refuses_extra_wrong_and_missing_members() {
        let profile = profile(r#"{"record": {{record}}}"#);
        let schema =
            derive_operation_result_schema(&profile, &project(true), "cases-find").expect("derive");

        let good = json!({"record": {"id": "c-1", "region": "north", "opened-on": "2026-01-01"}});
        assert!(validate_result_schema(&good, &schema).is_empty());

        let extra = json!({"record": {"id": "c-1", "ghost": true}});
        assert_eq!(
            validate_result_schema(&extra, &schema),
            vec!["/record/ghost"]
        );

        let wrong = json!({"record": {"id": 7}});
        assert_eq!(validate_result_schema(&wrong, &schema), vec!["/record/id"]);

        let missing = json!({"record": {"region": "north"}});
        assert_eq!(
            validate_result_schema(&missing, &schema),
            vec!["/record/id"]
        );

        let wrong_root = json!([1]);
        assert_eq!(validate_result_schema(&wrong_root, &schema), vec![""]);
    }

    /// The fixture check refuses extra, wrong-typed, and missing members
    /// and a missing body under the fixture response-schema code, each at
    /// the fixture path it concerns; a conforming body passes.
    #[test]
    fn fixture_check_refuses_with_the_response_schema_code() {
        let profile = profile(r#"{"record": {{record}}}"#);
        let schema =
            derive_operation_result_schema(&profile, &project(true), "cases-find").expect("derive");
        let problem = derive_problem_envelope_schema(&profile).expect("derive");
        let expected = |status: u32, body: Option<Value>| ExpectedFacade::Response {
            status: crate::fixture::HttpStatus::new(status).expect("a status"),
            headers: RecordedHeaders::new(),
            body: body.map(crate::fixture::RecordedBody),
        };
        let check = |index: usize, expected: &ExpectedFacade| {
            check_fixture_expected_response(index, expected, &schema, &problem)
        };

        let good = expected(200, Some(json!({"record": {"id": "c-1"}})));
        assert!(check(0, &good).is_empty());

        let findings = check(
            0,
            &expected(200, Some(json!({"record": {"id": "c-1", "ghost": true}}))),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckCode::FixtureResponseSchema.code());
        assert_eq!(findings[0].path, "/entries/0/expected/body/record/ghost");

        let findings = check(2, &expected(200, Some(json!({"record": {"id": 7}}))));
        assert_eq!(findings[0].path, "/entries/2/expected/body/record/id");

        let findings = check(0, &expected(200, Some(json!({"record": {}}))));
        assert_eq!(findings[0].path, "/entries/0/expected/body/record/id");

        // An absent body refuses at the expectation; an explicit JSON
        // `null` body is a body (G-FIXTURES) and validates as the null
        // value, refusing at the body root when the schema asks for an
        // object.
        let findings = check(0, &expected(200, None));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "/entries/0/expected");
        let findings = check(0, &expected(200, Some(Value::Null)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "/entries/0/expected/body");
    }

    /// The problem-envelope derivation closes the profile's problem
    /// template: the problem slots derive as strings, a record slot is
    /// refused, and a malformed template is refused by name of the fault.
    #[test]
    fn problem_envelope_derivation_closes_the_problem_template() {
        let problem_envelope = |text: &str| {
            let mut profile = profile(r#"{"record": {{record}}}"#);
            profile.problem_envelope = EnvelopeTemplate(text.to_string());
            profile
        };
        let with_detail = problem_envelope(
            r#"{"code": "{{problemCode}}", "title": "{{problemTitle}}", "detail": "{{?problemDetail}}"}"#,
        );
        let schema = derive_problem_envelope_schema(&with_detail).expect("derive");
        assert_eq!(schema["required"], json!(["code", "title"]));
        assert_eq!(schema["properties"]["code"], json!({"type": "string"}));
        assert_eq!(schema["properties"]["detail"], json!({"type": "string"}));

        let record_slot = problem_envelope(r#"{"code": "{{problemCode}}", "record": {{record}}}"#);
        assert!(
            derive_problem_envelope_schema(&record_slot).is_err(),
            "a problem envelope carries no record slot"
        );
        assert!(derive_problem_envelope_schema(&problem_envelope(r#"{"code": "#)).is_err());
    }

    /// The profile-level derivation check runs without fixtures: a
    /// well-formed profile passes, a response envelope that parses no
    /// JSON template refuses at the operation, a malformed problem
    /// envelope refuses once, and an unbound operation's record slot is
    /// the one derivation failure a workspace may carry.
    #[test]
    fn envelope_derivation_is_checked_independently_of_fixtures() {
        // Well-formed and bound: clean.
        let findings =
            check_envelope_derivation(&profile(r#"{"record": {{record}}}"#), &project(true));
        assert!(findings.is_empty());

        // An unbound operation's record slot does not refuse: binding
        // completeness is the project check's concern.
        let findings =
            check_envelope_derivation(&profile(r#"{"record": {{record}}}"#), &project(false));
        assert!(findings.is_empty());

        // A response envelope whose template is not closed JSON refuses
        // at the operation, though its placeholder grammar is fine.
        let unparseable = profile(r#"{"cases": {{records}}"#);
        let findings = check_envelope_derivation(&unparseable, &project(true));
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            CheckCode::ProfileResponseEnvelopeUncompilable.code()
        );
        assert_eq!(findings[0].path, "/operations/0/responseEnvelope");

        // A binding naming no declared record type refuses: the fault is
        // the binding, not the envelope.
        let mut ghost_binding = project(true);
        ghost_binding.bindings = UniqueIdList::new(vec![Binding {
            id: local("find-cases"),
            operation: external("cases-find"),
            record_type: local("ghost"),
            route: external("fetch-cases"),
            filters: UniqueList::new(Vec::new()).expect("unique"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
        }])
        .expect("unique");
        let findings =
            check_envelope_derivation(&profile(r#"{"record": {{record}}}"#), &ghost_binding);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            CheckCode::ProfileResponseEnvelopeUncompilable.code()
        );

        // A malformed problem envelope refuses once, at the envelope.
        let mut broken_problem = profile(r#"{"record": {{record}}}"#);
        broken_problem.problem_envelope =
            EnvelopeTemplate(r#"{"code": "{{problemCode}}""#.to_string());
        let findings = check_envelope_derivation(&broken_problem, &project(true));
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            CheckCode::ProfileProblemEnvelopeUncompilable.code()
        );
        assert_eq!(findings[0].path, "/problemEnvelope");
    }

    /// The entry's expected status selects the schema: a non-2xx entry
    /// with a well-formed problem body passes, a malformed one refuses at
    /// its pointer, and a 2xx entry carrying a problem body refuses
    /// against the result schema (addendum A).
    #[test]
    fn the_expected_status_selects_the_schema() {
        let with_record = profile(r#"{"record": {{record}}}"#);
        let schema = derive_operation_result_schema(&with_record, &project(true), "cases-find")
            .expect("derive");
        let problem_code_only = profile(r#"{"code": "{{problemCode}}"}"#);
        let problem = derive_problem_envelope_schema(&problem_code_only).expect("derive");
        let expected = |status: u32, body: Option<Value>| ExpectedFacade::Response {
            status: crate::fixture::HttpStatus::new(status).expect("a status"),
            headers: RecordedHeaders::new(),
            body: body.map(crate::fixture::RecordedBody),
        };
        let check = |expected: &ExpectedFacade| {
            check_fixture_expected_response(0, expected, &schema, &problem)
        };

        let good = expected(404, Some(json!({"code": "cases.conflict"})));
        assert!(check(&good).is_empty(), "an honest error-path entry passes");

        let findings = check(&expected(
            404,
            Some(json!({"code": "cases.conflict", "ghost": 1})),
        ));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "/entries/0/expected/body/ghost");
        assert!(
            findings[0].message.contains("problem envelope"),
            "the message names which envelope kind failed"
        );

        let findings = check(&expected(404, Some(json!({"code": 7}))));
        assert_eq!(findings[0].path, "/entries/0/expected/body/code");

        let findings = check(&expected(404, None));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "/entries/0/expected");

        // A 2xx entry carrying a problem body refuses against the result
        // schema.
        let findings = check(&expected(200, Some(json!({"code": "cases.conflict"}))));
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|finding| finding.message.contains("result schema")));
    }

    /// A case binding and a patient binding of one operation each expand
    /// their own record type: the per-binding derivation resolves the
    /// named binding, where the operation-level derivation keeps its
    /// first-binding rule (`products/adapter/CONCEPT.md` section 7).
    #[test]
    fn the_per_binding_derivation_resolves_the_named_binding() {
        let envelope = r#"{"record": {{record}}}"#;
        let profile = profile(envelope);
        let mut deployment = project(true);
        deployment.record_types = UniqueIdList::new(vec![
            record_type(),
            RecordType {
                name: local("patient"),
                fields: UniqueList::new(vec![RecordField {
                    name: local("wheelchair"),
                    r#type: RecordFieldType::Boolean,
                    required: true,
                }])
                .expect("unique"),
            },
        ])
        .expect("unique");
        deployment.bindings = UniqueIdList::new(vec![
            Binding {
                id: local("find-cases"),
                operation: external("cases-find"),
                record_type: local("case"),
                route: external("fetch-cases"),
                filters: UniqueList::new(Vec::new()).expect("unique"),
                maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
            },
            Binding {
                id: local("find-patients"),
                operation: external("cases-find"),
                record_type: local("patient"),
                route: external("fetch-patients"),
                filters: UniqueList::new(Vec::new()).expect("unique"),
                maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
            },
        ])
        .expect("unique");
        let bindings: Vec<Binding> = deployment.bindings.iter().cloned().collect();
        let cases =
            derive_binding_result_schema(&profile, &deployment, &bindings[0]).expect("derive");
        assert_eq!(cases["properties"]["record"]["required"], json!(["id"]));
        let patients =
            derive_binding_result_schema(&profile, &deployment, &bindings[1]).expect("derive");
        assert_eq!(
            patients["properties"]["record"]["required"],
            json!(["wheelchair"])
        );
        let first =
            derive_operation_result_schema(&profile, &deployment, "cases-find").expect("derive");
        assert_eq!(first["properties"]["record"]["required"], json!(["id"]));
        let ghost = Binding {
            id: local("find-ghosts"),
            operation: external("cases-missing"),
            record_type: local("case"),
            route: external("fetch-cases"),
            filters: UniqueList::new(Vec::new()).expect("unique"),
            maximum_upstream_calls: BoundedU64::<1, 100_000>::new(5).expect("budget"),
        };
        assert!(
            derive_binding_result_schema(&profile, &deployment, &ghost).is_err(),
            "a binding naming no declared operation is refused"
        );
    }

    /// The request derivation expands a write operation's request
    /// envelope against the binding's record type; an operation that
    /// declares no request envelope is refused by name of the fault.
    #[test]
    fn the_request_derivation_expands_the_request_envelope() {
        let write_profile = profile(r#"{"cases": {{records}}}"#);
        let mut operations: Vec<ProfileOperation> =
            write_profile.operations.iter().cloned().collect();
        operations[0].request_envelope =
            Some(EnvelopeTemplate(r#"{"input": {{record}}}"#.to_string()));
        let write_profile = AdapterProfile {
            operations: UniqueIdList::new(operations).expect("unique"),
            ..write_profile
        };
        let deployment = project(true);
        let binding: Binding = deployment.bindings.iter().next().expect("bound").clone();
        let schema =
            derive_operation_request_schema(&write_profile, &deployment, &binding).expect("derive");
        assert_eq!(schema["properties"]["input"]["required"], json!(["id"]));
        let read_profile = profile(r#"{"cases": {{records}}}"#);
        assert!(
            derive_operation_request_schema(&read_profile, &deployment, &binding).is_err(),
            "an operation with no request envelope is refused"
        );
    }

    /// A parameterized part derives as a plain string, never as the
    /// stand-in const literal: the contract cannot know the deployment's
    /// value (CONCEPT section 7). A non-part literal keeps its const, the
    /// per-binding and request derivations unpin the same way, and the
    /// problem envelope unpins like an operation's envelope.
    #[test]
    fn a_parameterized_part_derives_as_a_string_not_a_const() {
        let with_parts = |envelope: &str| {
            let mut profile = profile(envelope);
            profile.parameterized_parts = UniqueList::new(vec![ParameterizedPart {
                name: external("registryIdentifier"),
                description: "the deployment's registry identifier".to_string(),
            }])
            .expect("unique");
            profile
        };
        let parts_profile =
            with_parts(r#"{"meta": {"registryIdentifier": "registryIdentifier"}, "kind": "case"}"#);
        let deployment = project(true);
        let schema = derive_operation_result_schema(&parts_profile, &deployment, "cases-find")
            .expect("derive");
        assert_eq!(
            schema["properties"]["meta"]["properties"]["registryIdentifier"],
            json!({"type": "string"})
        );
        assert_eq!(
            schema["properties"]["kind"],
            json!({"type": "string", "const": "case"})
        );
        let binding: Binding = deployment.bindings.iter().next().expect("bound").clone();
        let per_binding =
            derive_binding_result_schema(&parts_profile, &deployment, &binding).expect("derive");
        assert_eq!(
            per_binding["properties"]["meta"]["properties"]["registryIdentifier"],
            json!({"type": "string"})
        );
        let mut request_profile = with_parts(r#"{"cases": {{records}}}"#);
        let operations: Vec<ProfileOperation> = request_profile
            .operations
            .iter()
            .cloned()
            .map(|mut operation| {
                operation.request_envelope = Some(EnvelopeTemplate(
                    r#"{"meta": {"registryIdentifier": "registryIdentifier"}}"#.to_string(),
                ));
                operation
            })
            .collect();
        request_profile.operations = UniqueIdList::new(operations).expect("unique");
        let request = derive_operation_request_schema(&request_profile, &deployment, &binding)
            .expect("derive");
        assert_eq!(
            request["properties"]["meta"]["properties"]["registryIdentifier"],
            json!({"type": "string"})
        );
        let mut problem_profile = with_parts(r#"{"cases": {{records}}}"#);
        problem_profile.problem_envelope = EnvelopeTemplate(
            r#"{"meta": {"registryIdentifier": "registryIdentifier"}}"#.to_string(),
        );
        let problem = derive_problem_envelope_schema(&problem_profile).expect("derive");
        assert_eq!(
            problem["properties"]["meta"]["properties"]["registryIdentifier"],
            json!({"type": "string"})
        );
    }
}
