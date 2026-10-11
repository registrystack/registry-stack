// SPDX-License-Identifier: Apache-2.0
//! Operation contracts: the JSON Schema of the input each catalog operation's
//! adapter decodes and of the output it returns. The committed generated files
//! are embedded, so the default build derives no schemas.

use std::{collections::BTreeMap, sync::OnceLock};

use jsonschema::{
    error::{TypeKind, ValidationErrorKind},
    JSONSchema,
};
use serde_json::Value;

use crate::protocol::Operation;

/// One operation's input and output schemas, as committed.
pub struct OperationContract {
    pub input: Value,
    pub output: Value,
    input_validator: JSONSchema,
    output_validator: JSONSchema,
}

/// Where a value leaves a contract. The path is an RFC 6901 pointer into the
/// checked value, empty for the value itself; neither member copies a value,
/// although the path names the checked value's own members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    pub path: String,
    pub expected: String,
}

/// What a violation expects of a member the contract does not declare.
const UNEXPECTED_MEMBER: &str = "no member of this name";

impl Violation {
    /// The path as far as the contract names it. An unexpected member's name
    /// comes from the checked value, so the path stops at the object that
    /// holds it.
    pub fn declared_path(&self) -> &str {
        if self.expected == UNEXPECTED_MEMBER {
            self.path.rsplit_once('/').map_or("", |(object, _)| object)
        } else {
            &self.path
        }
    }
}

impl OperationContract {
    /// Checks a value the operation's adapter would decode.
    pub fn check_input(&self, value: &Value) -> Result<(), Violation> {
        first_violation(&self.input_validator, value)
    }

    /// Checks a value offered as the operation's step output.
    pub fn check_output(&self, value: &Value) -> Result<(), Violation> {
        first_violation(&self.output_validator, value)
    }
}

pub(crate) fn first_violation(validator: &JSONSchema, value: &Value) -> Result<(), Violation> {
    let Err(mut errors) = validator.validate(value) else {
        return Ok(());
    };
    let Some(error) = errors.next() else {
        return Ok(());
    };
    let mut path = error.instance_path.to_string();
    let expected = match &error.kind {
        ValidationErrorKind::AdditionalProperties { unexpected }
        | ValidationErrorKind::UnevaluatedProperties { unexpected } => {
            if let Some(member) = unexpected.first() {
                path.push('/');
                path.push_str(&member.replace('~', "~0").replace('/', "~1"));
            }
            UNEXPECTED_MEMBER.to_owned()
        }
        kind => expected(kind),
    };
    Err(Violation { path, expected })
}

/// What a schema keyword expects, described from the schema alone.
fn expected(kind: &ValidationErrorKind) -> String {
    match kind {
        ValidationErrorKind::Type {
            kind: TypeKind::Single(kind),
        } => format!("a value of type {kind}"),
        ValidationErrorKind::Type {
            kind: TypeKind::Multiple(kinds),
        } => format!(
            "a value of type {}",
            kinds
                .into_iter()
                .map(|kind| kind.to_string())
                .collect::<Vec<_>>()
                .join(" or ")
        ),
        ValidationErrorKind::Required { property } => format!(
            "the required member {}",
            property.as_str().unwrap_or_default()
        ),
        ValidationErrorKind::Format { format } => format!("a {format} string"),
        ValidationErrorKind::Enum { options } => format!("one of {options}"),
        ValidationErrorKind::Constant { expected_value } => {
            format!("the constant {expected_value}")
        }
        ValidationErrorKind::Minimum { limit } => format!("a number no less than {limit}"),
        ValidationErrorKind::Maximum { limit } => format!("a number no greater than {limit}"),
        ValidationErrorKind::ExclusiveMinimum { limit } => format!("a number greater than {limit}"),
        ValidationErrorKind::ExclusiveMaximum { limit } => format!("a number less than {limit}"),
        ValidationErrorKind::MinLength { limit } => {
            format!("a string of at least {limit} characters")
        }
        ValidationErrorKind::MaxLength { limit } => {
            format!("a string of at most {limit} characters")
        }
        ValidationErrorKind::MinItems { limit } => format!("an array of at least {limit} items"),
        ValidationErrorKind::MaxItems { limit } => format!("an array of at most {limit} items"),
        ValidationErrorKind::MinProperties { limit } => {
            format!("an object of at least {limit} members")
        }
        ValidationErrorKind::MaxProperties { limit } => {
            format!("an object of at most {limit} members")
        }
        ValidationErrorKind::Pattern { pattern } => format!("a string matching {pattern}"),
        ValidationErrorKind::AnyOf | ValidationErrorKind::OneOfNotValid => {
            "a value matching one of the declared shapes".into()
        }
        ValidationErrorKind::OneOfMultipleValid => {
            "a value matching exactly one declared shape".into()
        }
        _ => "a value the contract accepts".into(),
    }
}

macro_rules! embedded {
    ($($id:literal),* $(,)?) => {
        &[$((
            $id,
            include_str!(concat!(
                "../../../products/coordinator/generated/operations/",
                $id,
                ".input.schema.json"
            )),
            include_str!(concat!(
                "../../../products/coordinator/generated/operations/",
                $id,
                ".output.schema.json"
            )),
        )),*]
    };
}

static EMBEDDED: &[(&str, &str, &str)] = embedded!(
    "cancel-review-request",
    "create-appointment",
    "evaluate-decision",
    "external-get",
    "invoke-breg-action",
    "read-availability",
    "read-record",
    "read-scheduling",
    "submit-message",
    "submit-review-request",
);

/// The committed contract of a wait event: the value a wait-for step that
/// continues with `next` holds as its output.
pub struct EventContract {
    pub output: Value,
    validator: JSONSchema,
}

impl EventContract {
    /// Checks a value offered as the event a wait receives.
    pub fn check(&self, value: &Value) -> Result<(), Violation> {
        first_violation(&self.validator, value)
    }
}

static EVENTS: &[(&str, &str)] = &[(
    "review-result",
    include_str!(
        "../../../products/coordinator/generated/operations/review-result.event.schema.json"
    ),
)];

/// The committed contract of the event a wait-for step waits for.
pub fn event_contract(event: &crate::definition::WaitEvent) -> &'static EventContract {
    static CONTRACTS: OnceLock<BTreeMap<&'static str, EventContract>> = OnceLock::new();
    let contracts = CONTRACTS.get_or_init(|| {
        EVENTS
            .iter()
            .map(|(id, text)| {
                let output: Value =
                    serde_json::from_str(text).expect("committed event contract is JSON");
                let validator = crate::definition::compile_schema(&output)
                    .expect("committed event contract compiles");
                (*id, EventContract { output, validator })
            })
            .collect()
    });
    contracts
        .get(event.id())
        .expect("every wait event has a committed contract")
}

/// The committed contract of a catalog operation.
pub fn contract(operation: Operation) -> &'static OperationContract {
    static CONTRACTS: OnceLock<BTreeMap<&'static str, OperationContract>> = OnceLock::new();
    let contracts = CONTRACTS.get_or_init(|| {
        EMBEDDED
            .iter()
            .map(|(id, input, output)| {
                let parse = |text: &str| -> (Value, JSONSchema) {
                    let schema =
                        serde_json::from_str(text).expect("committed operation contract is JSON");
                    let validator = crate::definition::compile_schema(&schema)
                        .expect("committed operation contract compiles");
                    (schema, validator)
                };
                let (input, input_validator) = parse(input);
                let (output, output_validator) = parse(output);
                (
                    *id,
                    OperationContract {
                        input,
                        output,
                        input_validator,
                        output_validator,
                    },
                )
            })
            .collect()
    });
    contracts
        .get(operation.as_str())
        .expect("every catalog operation has a committed contract")
}

/// Generated contract files and their reference, keyed by file name.
#[cfg(feature = "schema")]
pub fn generate() -> Result<BTreeMap<String, String>, serde_json::Error> {
    use crate::{
        adapters::{AppointmentRequest, AvailabilityRequest, ReadRequest, SchedulingReadRequest},
        breg_action::ActionInput,
        decision::{DecisionResult, Evaluation},
        external_http::{ExternalResponse, GetRequest},
        review::CancelReviewInput,
    };
    use registry_breg_client::{BRegActionReceipt, RegistryRecordSingleResponse};
    use registry_casework_client::{
        ReviewCancelResponse, ReviewCreateRequest, ReviewRequestAccepted,
    };
    use registry_messaging_core::{MessageReceipt, SubmitMessageRequest};
    use registry_scheduling_core::{
        AppointmentDocument, AvailabilityEntry, PageDocument, SchedulingServiceDocument,
    };

    let mut contracts = BTreeMap::new();
    let mut add = |operation: Operation, input: Value, output: Value| {
        contracts.insert(operation.as_str(), (input, output));
    };
    add(
        Operation::ReadRecord,
        derived::input::<ReadRequest>(),
        derived::output::<RegistryRecordSingleResponse>(),
    );
    add(
        Operation::SubmitMessage,
        derived::input::<SubmitMessageRequest>(),
        derived::output::<MessageReceipt>(),
    );
    add(
        Operation::ReadScheduling,
        derived::input::<SchedulingReadRequest>(),
        derived::output::<SchedulingServiceDocument>(),
    );
    add(
        Operation::ReadAvailability,
        derived::input::<AvailabilityRequest>(),
        derived::output::<PageDocument<AvailabilityEntry>>(),
    );
    add(
        Operation::CreateAppointment,
        derived::input::<AppointmentRequest>(),
        derived::output::<AppointmentDocument>(),
    );
    add(
        Operation::InvokeBregAction,
        derived::input::<ActionInput>(),
        derived::output::<BRegActionReceipt>(),
    );
    add(
        Operation::ExternalGet,
        derived::input::<GetRequest>(),
        derived::output::<ExternalResponse>(),
    );
    add(
        Operation::EvaluateDecision,
        derived::input::<Evaluation>(),
        derived::output::<DecisionResult>(),
    );
    add(
        Operation::SubmitReviewRequest,
        derived::input::<ReviewCreateRequest>(),
        derived::output::<ReviewRequestAccepted>(),
    );
    add(
        Operation::CancelReviewRequest,
        derived::input::<CancelReviewInput>(),
        derived::output::<ReviewCancelResponse>(),
    );
    let mut files = BTreeMap::new();
    for descriptor in crate::operations::descriptors() {
        let (mut input, mut output) = contracts
            .remove(descriptor.id)
            .expect("every catalog operation derives a contract");
        derived::finish(&mut input, &format!("{} input", descriptor.id));
        derived::finish(&mut output, &format!("{} output", descriptor.id));
        if descriptor.id == Operation::ReadRecord.as_str() {
            output["$defs"]["RegistryRecord"]["properties"]["domainData"]["description"] =
                Value::from(
                    "Project-defined record data. The registry project's entity schema owns \
                     these members, so check accepts any path beneath domainData and test \
                     and the runtime decide.",
                );
        }
        for (role, schema) in [("input", input), ("output", output)] {
            let mut text = serde_json::to_string_pretty(&schema)?;
            text.push('\n');
            files.insert(format!("{}.{role}.schema.json", descriptor.id), text);
        }
    }
    assert!(
        contracts.is_empty(),
        "every contract names a catalog operation"
    );
    let mut event = derived::output::<registry_casework_client::ReviewResult>();
    derived::finish(&mut event, "review-result event");
    let mut text = serde_json::to_string_pretty(&event)?;
    text.push('\n');
    files.insert("review-result.event.schema.json".into(), text);
    files.insert("README.md".into(), derived::reference(&files)?);
    Ok(files)
}

#[cfg(feature = "schema")]
mod derived {
    use std::collections::BTreeMap;

    use schemars::{generate::SchemaSettings, JsonSchema};
    use serde_json::{json, Value};

    /// What the adapter accepts: the deserialization contract of its input type.
    pub(super) fn input<T: JsonSchema>() -> Value {
        let generator = SchemaSettings::draft2020_12()
            .for_deserialize()
            .into_generator();
        generator.into_root_schema_for::<T>().to_value()
    }

    /// What the adapter returns: the serialization contract of its output type.
    pub(super) fn output<T: JsonSchema>() -> Value {
        let generator = SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator();
        generator.into_root_schema_for::<T>().to_value()
    }

    /// Coordinator asserts formats and knows no numeric format names, so each
    /// width becomes explicit bounds. Canonical JSON carries integers only
    /// within the IEEE 754 safe range, which bounds the 64-bit widths.
    pub(super) fn finish(schema: &mut Value, title: &str) {
        bound_numbers(schema);
        schema["title"] = json!(title);
    }

    const SAFE_INTEGER: i64 = (1 << 53) - 1;

    fn bound_numbers(value: &mut Value) {
        match value {
            Value::Object(object) => {
                let bounds: Option<(Value, Value)> =
                    match object.get("format").and_then(Value::as_str) {
                        Some("uint8") => Some((json!(0), json!(u8::MAX))),
                        Some("uint16") => Some((json!(0), json!(u16::MAX))),
                        Some("uint32") => Some((json!(0), json!(u32::MAX))),
                        Some("uint64" | "uint") => Some((json!(0), json!(SAFE_INTEGER))),
                        Some("int8") => Some((json!(i8::MIN), json!(i8::MAX))),
                        Some("int16") => Some((json!(i16::MIN), json!(i16::MAX))),
                        Some("int32") => Some((json!(i32::MIN), json!(i32::MAX))),
                        Some("int64" | "int") => Some((json!(-SAFE_INTEGER), json!(SAFE_INTEGER))),
                        Some("double" | "float") => Some((Value::Null, Value::Null)),
                        _ => None,
                    };
                if let Some((minimum, maximum)) = bounds {
                    object.remove("format");
                    if !minimum.is_null() && !object.contains_key("minimum") {
                        object.insert("minimum".into(), minimum);
                    }
                    if !maximum.is_null() && !object.contains_key("maximum") {
                        object.insert("maximum".into(), maximum);
                    }
                }
                object.values_mut().for_each(bound_numbers);
            }
            Value::Array(items) => items.iter_mut().for_each(bound_numbers),
            _ => {}
        }
    }

    /// The operation reference, built from the descriptors and the contracts.
    pub(super) fn reference(files: &BTreeMap<String, String>) -> Result<String, serde_json::Error> {
        let mut text = String::from(
            "<!-- Generated by the operation-schemas example of registry-coordinator. Do not edit. -->\n\
             # Coordinator operation reference\n\n\
             Each catalog operation has an input contract, the type its adapter decodes, and an \
             output contract, the type its adapter returns as the step output. A mapping that \
             feeds a call must produce a value its input contract accepts; a reference into a \
             call step's output must name a path its output contract declares.\n\n\
             | Operation | Version | Product | Effect | Key | Preparation | Recovery | Receipt |\n\
             |---|---|---|---|---|---|---|---|\n",
        );
        for descriptor in crate::operations::descriptors() {
            text.push_str(&format!(
                "| [`{id}`](#{id}) | {version} | `{product}` | {effect} | {key} | {preparation} | {recovery} | {receipt} |\n",
                id = descriptor.id,
                version = descriptor.version,
                product = descriptor.product,
                effect = word(&descriptor.effect)?,
                key = word(&descriptor.key_requirement)?,
                preparation = if descriptor.requires_preparation { "required" } else { "none" },
                recovery = word(&descriptor.recovery)?,
                receipt = if descriptor.read_receipt { "read" } else { "none" },
            ));
        }
        for descriptor in crate::operations::descriptors() {
            text.push_str(&format!("\n## {}\n", descriptor.id));
            for role in ["input", "output"] {
                let file = format!("{}.{role}.schema.json", descriptor.id);
                let schema: Value = serde_json::from_str(&files[&file])?;
                text.push_str(&format!(
                    "\n{} ([`{file}`]({file})):\n\n",
                    if role == "input" { "Input" } else { "Output" }
                ));
                text.push_str(&members(&schema));
            }
        }
        text.push_str(
            "\n## Wait events\n\n\
             A wait-for step waits for one event. When the event arrives, the step continues \
             with `next` and holds the event as its output, so a reference into a wait-for \
             step's output must name a path the event contract declares. A step reached by \
             `onTimeout` reads no event.\n",
        );
        let file = "review-result.event.schema.json";
        let schema: Value = serde_json::from_str(&files[file])?;
        text.push_str(&format!(
            "\n### review-result\n\nThe result of a review request a `submit-review-request` \
             step submitted, once the reviewing product reports it complete \
             ([`{file}`]({file})):\n\n"
        ));
        text.push_str(&members(&schema));
        Ok(text)
    }

    fn word<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
        Ok(serde_json::to_value(value)?
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
        match schema.get("$ref").and_then(Value::as_str) {
            Some(reference) => reference
                .strip_prefix('#')
                .and_then(|pointer| root.pointer(pointer))
                .unwrap_or(schema),
            None => schema,
        }
    }

    fn members(root: &Value) -> String {
        let schema = resolve(root, root);
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            let variants = schema
                .get("oneOf")
                .or_else(|| schema.get("anyOf"))
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            return if variants > 0 {
                format!("One of {variants} shapes; see the schema.\n")
            } else {
                "Any JSON value.\n".into()
            };
        };
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut text = String::from("| Member | Type | Required |\n|---|---|---|\n");
        for (name, member) in properties {
            text.push_str(&format!(
                "| `{name}` | {} | {} |\n",
                kind(member),
                if required.contains(&json!(name)) {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            text.push_str("\nNo other members are accepted.\n");
        } else {
            text.push_str("\nOther members are tolerated.\n");
        }
        text
    }

    fn kind(schema: &Value) -> String {
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let name = reference.rsplit('/').next().unwrap_or(reference);
            return format!("`{name}`");
        }
        if let Some(branches) = schema.get("anyOf").and_then(Value::as_array) {
            return branches.iter().map(kind).collect::<Vec<_>>().join(" or ");
        }
        let types = match schema.get("type") {
            Some(Value::String(kind)) => vec![kind.clone()],
            Some(Value::Array(kinds)) => kinds
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => return "any".into(),
        };
        let mut text = types.join(" or ");
        if let Some(format) = schema.get("format").and_then(Value::as_str) {
            text.push_str(&format!(" ({format})"));
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_catalog_operation_has_a_compilable_contract() {
        assert_eq!(EMBEDDED.len(), crate::operations::descriptors().len());
        for descriptor in crate::operations::descriptors() {
            let operation = Operation::parse(descriptor.id).unwrap();
            let contract = contract(operation);
            for schema in [&contract.input, &contract.output] {
                assert!(schema.get("$id").is_none());
                crate::definition::compile_schema(schema).unwrap_or_else(|error| {
                    panic!("{} contract does not compile: {error}", descriptor.id)
                });
            }
        }
    }

    #[test]
    fn a_violation_names_the_member_and_expectation_without_the_value() {
        let read = contract(Operation::ReadRecord);
        assert_eq!(
            read.check_input(&json!({"collection": "people", "recordId": "r-1"})),
            Ok(())
        );
        assert_eq!(
            read.check_input(&json!({"collection": "people"})),
            Err(Violation {
                path: String::new(),
                expected: "the required member recordId".into(),
            })
        );
        assert_eq!(
            read.check_input(&json!({"collection": 7, "recordId": "private-canary"})),
            Err(Violation {
                path: "/collection".into(),
                expected: "a value of type string".into(),
            })
        );
        assert_eq!(
            read.check_input(&json!({"collection": "c", "recordId": "r", "a/b": 1})),
            Err(Violation {
                path: "/a~1b".into(),
                expected: "no member of this name".into(),
            })
        );
        let availability = contract(Operation::ReadAvailability);
        let mut request = json!({
            "offering": "intake",
            "start": "2026-10-11T09:00:00Z",
            "end": "2026-10-11T17:00:00Z",
            "limit": 0,
            "grant": {"id": "00000000-0000-4000-8000-000000000000", "expiresAt": 1},
        });
        assert_eq!(
            availability.check_input(&request),
            Err(Violation {
                path: "/limit".into(),
                expected: "a number no less than 1".into(),
            })
        );
        request["limit"] = json!(10);
        request["start"] = json!("private-canary");
        let violation = availability.check_input(&request).unwrap_err();
        assert_eq!(violation.path, "/start");
        assert_eq!(violation.expected, "a date-time string");
        assert!(!format!("{violation:?}").contains("private-canary"));
        let external = contract(Operation::ExternalGet);
        assert_eq!(
            external.check_output(&json!({"status": 200, "body": null})),
            Ok(())
        );
        assert_eq!(
            external.check_output(&json!({"status": 70000, "body": {}})),
            Err(Violation {
                path: "/status".into(),
                expected: "a number no greater than 65535".into(),
            })
        );
    }

    #[test]
    fn the_declared_path_leaves_out_an_unexpected_member_name() {
        let read = contract(Operation::ReadRecord);
        let unexpected = read
            .check_input(&json!({"collection": "c", "recordId": "r", "private-canary": 1}))
            .unwrap_err();
        assert_eq!(unexpected.path, "/private-canary");
        assert_eq!(unexpected.declared_path(), "");
        let appointment = contract(Operation::CreateAppointment);
        let nested = appointment
            .check_input(&json!({
                "appointment": {"hold": "h-1"},
                "grant": {"id": "00000000-0000-4000-8000-000000000000", "expiresAt": 1,
                    "private-canary": 1},
            }))
            .unwrap_err();
        assert_eq!(nested.path, "/grant/private-canary");
        assert_eq!(nested.declared_path(), "/grant");
        let typed = read
            .check_input(&json!({"collection": 7, "recordId": "r"}))
            .unwrap_err();
        assert_eq!(typed.declared_path(), "/collection");
    }

    #[cfg(feature = "schema")]
    #[test]
    fn committed_contracts_match_their_generator() {
        let generated = generate().unwrap();
        for (id, input, output) in EMBEDDED {
            assert_eq!(generated[&format!("{id}.input.schema.json")], *input);
            assert_eq!(generated[&format!("{id}.output.schema.json")], *output);
        }
        for (id, event) in EVENTS {
            assert_eq!(generated[&format!("{id}.event.schema.json")], *event);
        }
    }
}
