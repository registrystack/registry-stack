// SPDX-License-Identifier: Apache-2.0
//! Operation contracts: the JSON Schema of the input each catalog operation's
//! adapter decodes, the success output it returns, and any declared-refusal
//! output it exposes to an authored branch. The committed generated files are
//! embedded, so the default build derives no schemas.

use std::{collections::BTreeMap, sync::OnceLock};

use jsonschema::{
    error::{TypeKind, ValidationErrorKind},
    JSONSchema,
};
use serde_json::{json, Value};

use crate::protocol::Operation;

/// One operation's input and route-specific output schemas, as committed.
pub struct OperationContract {
    pub input: Value,
    pub output: Value,
    /// Output made available only on an authored `onDeclaredRefusal` route.
    pub declared_refusal: Option<Value>,
    pub action: Option<crate::breg_action::ActionContract>,
    input_validator: JSONSchema,
    output_validator: JSONSchema,
    refusal_validator: Option<JSONSchema>,
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
    pub fn new(
        input: Value,
        output: Value,
        declared_refusal: Option<Value>,
        action: Option<crate::breg_action::ActionContract>,
    ) -> crate::Result<Self> {
        let input_validator = crate::definition::compile_schema(&input)?;
        let output_validator = crate::definition::compile_schema(&output)?;
        let refusal_validator = declared_refusal
            .as_ref()
            .map(crate::definition::compile_schema)
            .transpose()?;
        Ok(Self {
            input,
            output,
            declared_refusal,
            action,
            input_validator,
            output_validator,
            refusal_validator,
        })
    }
    /// Checks a value the operation's adapter would decode.
    pub fn check_input(&self, value: &Value) -> Result<(), Violation> {
        first_violation(&self.input_validator, value)
    }

    /// Checks a value offered as the operation's step output.
    pub fn check_output(&self, value: &Value) -> Result<(), Violation> {
        first_violation(&self.output_validator, value)
    }

    pub fn check_refusal(&self, value: &Value) -> Result<(), Violation> {
        match &self.refusal_validator {
            Some(validator) => first_violation(validator, value),
            None => Err(Violation {
                path: String::new(),
                expected: "an Operation declaring this business refusal".into(),
            }),
        }
    }
}

const SAFE_INTEGER: i64 = (1 << 53) - 1;

fn bound_numbers(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let bounds: Option<(Value, Value)> = match object.get("format").and_then(Value::as_str)
            {
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
            // Only descend into schema positions. Values in const, enum,
            // default and examples are authored data, even when they contain
            // keys such as format or properties.
            for keyword in [
                "$defs",
                "definitions",
                "properties",
                "patternProperties",
                "dependentSchemas",
            ] {
                if let Some(schemas) = object.get_mut(keyword).and_then(Value::as_object_mut) {
                    schemas.values_mut().for_each(bound_numbers);
                }
            }
            for keyword in [
                "additionalProperties",
                "unevaluatedProperties",
                "propertyNames",
                "items",
                "additionalItems",
                "unevaluatedItems",
                "contains",
                "not",
                "if",
                "then",
                "else",
            ] {
                if let Some(schema) = object.get_mut(keyword) {
                    bound_numbers(schema);
                }
            }
            for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
                if let Some(schemas) = object.get_mut(keyword).and_then(Value::as_array_mut) {
                    schemas.iter_mut().for_each(bound_numbers);
                }
            }
            if let Some(dependencies) = object
                .get_mut("dependencies")
                .and_then(Value::as_object_mut)
            {
                for schema in dependencies.values_mut().filter(|value| value.is_object()) {
                    bound_numbers(schema);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(bound_numbers),
        _ => {}
    }
}

/// Resolve one specialization from a local, owner-generated public export.
/// Live metadata still establishes the caller's authority at preparation time.
pub fn resolve_operation(
    operation: Operation,
    action: Option<&Value>,
    imported: &BTreeMap<String, Value>,
) -> crate::Result<OperationContract> {
    let invalid = || {
        crate::CoordinatorError::new(
            "coordinator.operation.contract-invalid",
            "select one Action from a generated BReg Action contract export",
        )
    };
    let Some(reference) = action else {
        if operation == Operation::InvokeBregAction {
            return Err(invalid());
        }
        let base = contract(operation);
        return OperationContract::new(
            base.input.clone(),
            base.output.clone(),
            base.declared_refusal.clone(),
            None,
        );
    };
    if operation != Operation::InvokeBregAction {
        return Err(invalid());
    }
    let object = reference
        .as_object()
        .filter(|value| value.len() == 2)
        .ok_or_else(invalid)?;
    let source = object
        .get("contract")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let export = imported
        .get(source)
        .filter(|value| {
            value.get("apiVersion").and_then(Value::as_str)
                == Some("id.registrystack.org/formats/breg/action-contracts/v1")
                && value.get("kind").and_then(Value::as_str) == Some("BRegActionContracts")
        })
        .ok_or_else(invalid)?;
    let entries = export
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let mut matching = entries
        .iter()
        .filter(|entry| entry.get("id").and_then(Value::as_str) == Some(id));
    let entry = matching.next().ok_or_else(invalid)?;
    if matching.next().is_some() {
        return Err(invalid());
    }
    let revision = entry
        .get("revision")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if !revision.strip_prefix("sha256:").is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }) {
        return Err(invalid());
    }
    let mode = serde_json::from_value(entry.get("mode").cloned().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let mut input = entry.get("input").cloned().ok_or_else(invalid)?;
    let mut output = entry.get("output").cloned().ok_or_else(invalid)?;
    // Local embedding changes the schema's base URI, never its validation rules.
    if let Some(schema) = input.as_object_mut() {
        schema.remove("$id");
    }
    if let Some(schema) = output.as_object_mut() {
        schema.remove("$id");
        schema.remove("$schema");
    }
    bound_numbers(&mut input);
    bound_numbers(&mut output);
    let output = if mode == registry_breg_client::BRegActionMode::Proposal {
        let definitions = output
            .as_object_mut()
            .and_then(|schema| schema.remove("$defs"));
        let mut wrapper = serde_json::json!({"type":"object","additionalProperties":false,"required":["proposal"],"properties":{"proposal":output}});
        if let Some(definitions) = definitions {
            wrapper["$defs"] = definitions;
        }
        wrapper
    } else {
        // Preparation obtains current target conditions using the maintained
        // client. An author may provide expected conditions, but cannot mint them.
        if let Some(required) = input.get_mut("required").and_then(Value::as_array_mut) {
            required.retain(|field| field != "preconditions");
        }
        output
    };
    OperationContract::new(
        input,
        output,
        entry.get("declaredRefusal").cloned(),
        Some(crate::breg_action::ActionContract {
            action_id: id.to_owned(),
            action_revision: revision.to_owned(),
            mode,
        }),
    )
}

pub fn breg_application_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let proposal = contract(Operation::SubmitBregProposal).output.clone();
        // Keep local references local after embedding the owner schema.
        let mut schema = serde_json::json!({
            "type":"object", "additionalProperties":false,
            "required":["outcome","proposal"],
            "properties": {"outcome":{"type":"string","enum":["applied","closed"]}, "proposal":proposal}
        });
        if let Some(defs) = schema["properties"]["proposal"].as_object_mut().and_then(|value| value.remove("$defs")) {
            schema["$defs"] = defs;
        }
        schema
    })
}

pub(crate) fn first_violation(validator: &JSONSchema, value: &Value) -> Result<(), Violation> {
    if crate::functions::check_value(value).is_err() {
        return Err(Violation {
            path: String::new(),
            expected: "a value within the host's bounded JSON contract".into(),
        });
    }
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

/// The committed completion contract: the value a wait-for step that
/// continues with `next` holds as its output.
pub struct CompletionContract {
    pub output: Value,
    validator: JSONSchema,
}

impl CompletionContract {
    /// Checks a value offered as the terminal result a wait receives.
    pub fn check(&self, value: &Value) -> Result<(), Violation> {
        first_violation(&self.validator, value)
    }
}

/// Casework's owning result schema. Signals never carry this result.
pub fn casework_completion_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        #[cfg(feature="schema")]
        { let mut schema=derived::output::<registry_casework_client::ReviewResult>(); derived::finish(&mut schema,"Casework result completion"); schema }
        #[cfg(not(feature="schema"))]
        { serde_json::from_str(include_str!("../../../products/coordinator/generated/operations/casework.submit-review-request.v1.result.completion.schema.json")).expect("generated result schema") }
    })
}

/// A compiled completion's result contract, irrespective of its adapter.
pub fn completion_contract(event: &crate::definition::CompletionDefinition) -> CompletionContract {
    CompletionContract {
        output: event.output.clone(),
        validator: crate::definition::compile_schema(&event.output)
            .expect("compiled completion schema"),
    }
}

/// The committed contract of a catalog operation.
pub fn contract(operation: Operation) -> &'static OperationContract {
    static CONTRACTS: OnceLock<BTreeMap<String, OperationContract>> = OnceLock::new();
    let contracts = CONTRACTS.get_or_init(|| {
        #[cfg(feature = "schema")]
        {
            derived_contracts()
                .into_iter()
                .map(|(id, (mut input, mut output))| {
                    derived::finish(&mut input, &format!("{id} input"));
                    derived::finish(&mut output, &format!("{id} output"));
                    let declared_refusal = (id == Operation::InvokeBregAction.as_str())
                        .then(derived::output::<crate::protocol::DeclaredRefusal>);
                    (
                        id.to_owned(),
                        OperationContract::new(input, output, declared_refusal, None)
                            .expect("owning schemas compile"),
                    )
                })
                .collect()
        }
        #[cfg(not(feature = "schema"))]
        {
            let schemas: BTreeMap<String, Value> = serde_json::from_str(include_str!(
                "../../../products/coordinator/generated/operations/catalog.json"
            ))
            .expect("generated catalog is JSON");
            assert_eq!(
                schemas.len(),
                crate::operations::descriptors().len(),
                "generated catalog covers every registered operation"
            );
            schemas
                .into_iter()
                .map(|(id, value)| {
                    assert!(
                        crate::operations::descriptor(&id).is_some(),
                        "generated schema belongs to a registered operation"
                    );
                    let contract = OperationContract::new(
                        value["input"].clone(),
                        value["output"].clone(),
                        value.get("declaredRefusal").cloned(),
                        None,
                    )
                    .expect("generated owning schemas compile");
                    (id, contract)
                })
                .collect()
        }
    });
    contracts
        .get(operation.as_str())
        .expect("every catalog operation has a committed contract")
}

/// Schemas derived from the owning wire models and adapter inputs.
#[cfg(feature = "schema")]
fn derived_contracts() -> BTreeMap<&'static str, (Value, Value)> {
    use crate::{
        adapters::{AvailabilityRequest, ReadRequest, SchedulingReadRequest},
        breg_action::ActionInput,
        decision::DecisionResult,
        external_http::{ExternalResponse, GetRequest},
        review::CancelReviewInput,
    };
    use registry_breg_client::{BRegActionReceipt, BRegProposal, RegistryRecordSingleResponse};
    use registry_casework_client::{
        ReviewCancelResponse, ReviewCreateRequest, ReviewRequestAccepted,
    };
    use registry_messaging_core::MessageReceipt;
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
        derived::submit_message_input(),
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
        derived::create_appointment_input(),
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
        derived::evaluation_input(),
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
    for operation in [
        Operation::SubmitBregProposal,
        Operation::ApplyBregProposal,
        Operation::RetryBregProposal,
        Operation::CancelBregProposal,
    ] {
        add(
            operation,
            derived::input::<BRegProposal>(),
            derived::output::<BRegProposal>(),
        );
    }
    contracts
}

/// Generated contract files and their reference, keyed by file name.
#[cfg(feature = "schema")]
pub fn generate() -> Result<BTreeMap<String, String>, serde_json::Error> {
    let mut contracts = derived_contracts();
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
            files.insert(
                format!("{}.{role}.schema.json", descriptor.id.replace('/', ".")),
                text,
            );
        }
    }
    assert!(
        contracts.is_empty(),
        "every contract names a catalog operation"
    );
    let mut event = derived::output::<registry_casework_client::ReviewResult>();
    derived::finish(&mut event, "Casework result completion");
    let mut text = serde_json::to_string_pretty(&event)?;
    text.push('\n');
    files.insert(
        "casework.submit-review-request.v1.result.completion.schema.json".into(),
        text,
    );
    let mut refusal = derived::output::<crate::protocol::DeclaredRefusal>();
    derived::finish(&mut refusal, "invoke-breg-action declared-refusal output");
    let mut text = serde_json::to_string_pretty(&refusal)?;
    text.push('\n');
    files.insert(
        "breg.invoke-action.v1.declared-refusal.schema.json".into(),
        text,
    );
    let mut catalog = serde_json::Map::new();
    for descriptor in crate::operations::descriptors() {
        let prefix = descriptor.id.replace('/', ".");
        let mut operation = serde_json::json!({
            "host":descriptor.host_contract(),
            "input":serde_json::from_str::<Value>(&files[&format!("{prefix}.input.schema.json")])?,
            "output":serde_json::from_str::<Value>(&files[&format!("{prefix}.output.schema.json")])?,
        });
        if descriptor.declared_refusal {
            operation["declaredRefusal"] = serde_json::from_str::<Value>(
                &files[&format!("{prefix}.declared-refusal.schema.json")],
            )?;
        }
        catalog.insert(descriptor.id.into(), operation);
    }
    files.insert(
        "catalog.json".into(),
        format!("{}\n", serde_json::to_string_pretty(&catalog)?),
    );
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

    /// Coordinator books directly under reviewed task authority. Scheduling's
    /// shared wire type also represents hold confirmation, which this adapter
    /// deliberately does not offer.
    pub(super) fn create_appointment_input() -> Value {
        let mut schema = input::<crate::adapters::AppointmentRequest>();
        let request = schema
            .pointer_mut("/$defs/CreateAppointmentRequest")
            .expect("the appointment input contains its maintained wire request");
        let required = request
            .as_object_mut()
            .expect("the maintained appointment request is an object")
            .entry("required")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("the maintained appointment requirements are an array");
        if !required.iter().any(|member| member == "admission") {
            required.push(json!("admission"));
        }
        request["properties"]["admission"] = json!({
            "$ref": "#/$defs/AdmissionRequest",
            "description": "The direct-create admission request."
        });
        request["properties"]["hold"] = json!({
            "description": "Hold confirmation is not offered by Coordinator.",
            "type": "null"
        });
        schema
    }

    /// Evaluation has value-level bounds in `Evaluation::parse` that the
    /// maintained DTO's derived schema cannot express on its own.
    pub(super) fn evaluation_input() -> Value {
        let mut schema = input::<crate::decision::Evaluation>();
        schema["properties"]["state"]["type"] = json!(["object", "string", "array"]);
        let questions = &mut schema["properties"]["questions"];
        questions["minProperties"] = json!(1);
        questions["maxProperties"] = json!(32);

        let variants = schema["$defs"]["Question"]["oneOf"]
            .as_array_mut()
            .expect("the maintained question type is a tagged union");
        for variant in variants {
            let properties = variant["properties"]
                .as_object_mut()
                .expect("each question variant is an object");
            properties
                .get_mut("instructions")
                .expect("each question has instructions")["pattern"] = json!(r"\S");
            match properties["type"]["const"].as_str() {
                Some("predicate") => {}
                Some("choice") => {
                    let criteria = properties
                        .get_mut("criteria")
                        .expect("a choice question has criteria");
                    criteria["minProperties"] = json!(2);
                    criteria["maxProperties"] = json!(32);
                    let values = criteria["patternProperties"]
                        .as_object_mut()
                        .and_then(|patterns| patterns.values_mut().next())
                        .expect("choice criteria use the maintained local-id pattern");
                    values["pattern"] = json!(r"\S");
                }
                Some("score") => {
                    let criteria = properties
                        .get_mut("criteria")
                        .expect("a score question has criteria");
                    criteria["minItems"] = json!(2);
                    criteria["maxItems"] = json!(10);
                    criteria["items"]["pattern"] = json!(r"\S");
                }
                _ => panic!("the maintained question type has an unknown variant"),
            }
        }
        schema
    }

    /// Messaging's request DTO represents optional wire members; its
    /// `content` method owns which combinations form one submission.
    pub(super) fn submit_message_input() -> Value {
        let mut schema = input::<registry_messaging_core::SubmitMessageRequest>();
        schema["oneOf"] = json!([
            {
                "required": ["template", "locale", "data"],
                "properties": {
                    "template": {"$ref": "#/$defs/TemplateReference"},
                    "locale": {"type": "string"},
                    "data": {"not": {"type": "null"}},
                    "content": {"type": "null"}
                }
            },
            {
                "required": ["content"],
                "properties": {
                    "template": {"type": "null"},
                    "locale": {"type": "null"},
                    "data": {"type": "null"},
                    "content": {"$ref": "#/$defs/DirectContent"}
                }
            }
        ]);
        schema
    }

    /// Coordinator asserts formats and knows no numeric format names, so each
    /// width becomes explicit bounds. Canonical JSON carries integers only
    /// within the IEEE 754 safe range, which bounds the 64-bit widths.
    pub(super) fn finish(schema: &mut Value, title: &str) {
        super::bound_numbers(schema);
        schema["title"] = json!(title);
    }

    /// The operation reference, built from the descriptors and the contracts.
    pub(super) fn reference(files: &BTreeMap<String, String>) -> Result<String, serde_json::Error> {
        let mut text = String::from(
            "<!-- Generated by the operation-schemas example of registry-coordinator. Do not edit. -->\n\
             # Coordinator operation reference\n\n\
             Each catalog operation has an input contract, the type its adapter decodes, and a \
             success output contract, the type its adapter returns on `next`. A mapping that \
             feeds a call must produce a value its input contract accepts; a reference into a \
             call step's output must name a path the contract for that route declares. Only the \
             operations marked below accept `onDeclaredRefusal`; that route receives the closed \
             declared-refusal output and no product detail or call input.\n\n\
             | Operation | Version | Product | Effect | Key | Preparation | Recovery | Receipt | Declared refusal |\n\
             |---|---|---|---|---|---|---|---|---|\n",
        );
        for descriptor in crate::operations::descriptors() {
            text.push_str(&format!(
                "| [`{id}`](#{id}) | {version} | `{product}` | {effect} | {key} | {preparation} | {recovery} | {receipt} | {declared_refusal} |\n",
                id = descriptor.id,
                version = descriptor.version,
                product = descriptor.product,
                effect = word(&descriptor.effect)?,
                key = word(&descriptor.key_requirement)?,
                preparation = if descriptor.requires_preparation { "required" } else { "none" },
                recovery = word(&descriptor.recovery)?,
                receipt = if descriptor.read_receipt { "read" } else { "none" },
                declared_refusal = if descriptor.declared_refusal {
                    format!(
                        "[`onDeclaredRefusal`]({}.declared-refusal.schema.json)",
                        descriptor.id.replace('/', ".")
                    )
                } else {
                    "none".into()
                },
            ));
        }
        for descriptor in crate::operations::descriptors() {
            text.push_str(&format!("\n## {}\n", descriptor.id));
            text.push_str("\nHost execution and completion contract:\n\n```json\n");
            text.push_str(&serde_json::to_string_pretty(&descriptor.host_contract())?);
            text.push_str("\n```\n");
            for role in ["input", "output"] {
                let file = format!("{}.{role}.schema.json", descriptor.id.replace('/', "."));
                let schema: Value = serde_json::from_str(&files[&file])?;
                text.push_str(&format!(
                    "\n{} ([`{file}`]({file})):\n\n",
                    if role == "input" { "Input" } else { "Output" }
                ));
                text.push_str(&members(&schema));
            }
            if descriptor.declared_refusal {
                let file = format!(
                    "{}.declared-refusal.schema.json",
                    descriptor.id.replace('/', ".")
                );
                let schema: Value = serde_json::from_str(&files[&file])?;
                text.push_str(&format!(
                    "\nDeclared-refusal output ([`{file}`]({file})):\n\n"
                ));
                text.push_str(&members(&schema));
            }
        }
        text.push_str(
            "\n## Completions\n\n\
             A `wait-for` step observes a named completion on an accepted Operation. The host \
             reads the authoritative result under current connection authority, using the \
             saved command and exact correlation. A terminal result continues through `next` \
             as the step output. A step reached by `onTimeout` has no completion output. \
             Authenticated signals only wake an eligible read and never carry the result. \
             Durable read spacing, the observation budget and the original deadline survive \
             retries and restarts.\n",
        );
        let file = "casework.submit-review-request.v1.result.completion.schema.json";
        let schema: Value = serde_json::from_str(&files[file])?;
        text.push_str(&format!(
            "\n### casework.submit-review-request/v1.result\n\nThe result of a review request a `casework.submit-review-request/v1` \
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
    fn numeric_format_projection_preserves_literal_schema_shaped_data() {
        let literal = json!({"format":"uint8","properties":{"x":{"format":"int64"}}});
        let mut schema = json!({
            "type":"object", "const":literal, "enum":[literal],
            "default":literal, "examples":[literal],
            "properties":{"number":{"type":"integer","format":"uint8"}},
            "$defs":{"Number":{"allOf":[{"type":"integer","format":"int64"}]}},
            "additionalProperties":{"type":"integer","format":"uint16"},
            "dependentSchemas":{"number":{"properties":{"other":{"type":"integer","format":"int8"}}}}
        });
        bound_numbers(&mut schema);
        for key in ["const", "default"] {
            assert_eq!(schema[key], literal);
        }
        for key in ["enum", "examples"] {
            assert_eq!(schema[key][0], literal);
        }
        assert_eq!(
            schema["properties"]["number"],
            json!({"type":"integer","minimum":0,"maximum":255})
        );
        assert_eq!(
            schema["$defs"]["Number"]["allOf"][0]["maximum"],
            SAFE_INTEGER
        );
        assert_eq!(schema["additionalProperties"]["maximum"], u16::MAX);
        assert_eq!(
            schema["dependentSchemas"]["number"]["properties"]["other"]["minimum"],
            i8::MIN
        );
    }

    #[test]
    fn operation_values_obey_host_bounds_before_schema_validation() {
        let contract =
            OperationContract::new(json!(true), json!(true), Some(json!(true)), None).unwrap();
        let oversized =
            json!({"private-canary":"x".repeat(crate::functions::MAXIMUM_VALUE_STRING_BYTES + 1)});
        for violation in [
            contract.check_input(&oversized),
            contract.check_output(&oversized),
            contract.check_refusal(&oversized),
        ] {
            let violation = violation.unwrap_err();
            assert_eq!(violation.path, "");
            assert_eq!(
                violation.expected,
                "a value within the host's bounded JSON contract"
            );
            assert!(!format!("{violation:?}").contains("private-canary"));
        }
    }

    #[cfg(feature = "schema")]
    fn generated_input(operation: Operation) -> JSONSchema {
        let files = generate().unwrap();
        let schema = serde_json::from_str(
            &files[&format!("{}.input.schema.json", operation.as_str().replace('/', "."))],
        )
        .unwrap();
        crate::definition::compile_schema(&schema).unwrap()
    }

    #[cfg(feature = "schema")]
    fn decision_runtime_accepts(input: &Value) -> bool {
        use registry_platform_config::{SecretProvider, SecretResolver};

        let config = serde_json::from_value(json!({
            "protocol": "system-one",
            "baseUrl": "http://127.0.0.1:9",
            "model": "contract-parity",
            "authorization": {"local": {}},
        }))
        .unwrap();
        crate::decision::DecisionConnection::new(
            &config,
            std::sync::Arc::new(SecretResolver::new([SecretProvider::Environment], "").unwrap()),
        )
        .unwrap()
        .prepare(input)
        .is_ok()
    }

    #[cfg(feature = "schema")]
    fn message_content_runtime_accepts(input: &Value) -> bool {
        serde_json::from_value::<registry_messaging_core::SubmitMessageRequest>(input.clone())
            .is_ok_and(|request| request.content().is_ok())
    }

    #[cfg(feature = "schema")]
    fn availability_selector_accepts(input: &Value) -> bool {
        input
            .get("offering")
            .and_then(Value::as_str)
            .is_some_and(registry_scheduling_core::valid_identifier)
    }

    #[cfg(feature = "schema")]
    fn assert_parity(
        schema: &JSONSchema,
        input: &Value,
        expected: bool,
        runtime_accepts: fn(&Value) -> bool,
    ) {
        assert_eq!(schema.is_valid(input), expected, "generated schema");
        assert_eq!(runtime_accepts(input), expected, "owning runtime validator");
    }

    #[test]
    fn every_catalog_operation_has_a_compilable_contract() {
        assert_eq!(
            serde_json::from_str::<BTreeMap<String, Value>>(include_str!(
                "../../../products/coordinator/generated/operations/catalog.json"
            ))
            .unwrap()
            .len(),
            crate::operations::descriptors().len()
        );
        for descriptor in crate::operations::descriptors() {
            let operation = Operation::parse(descriptor.id).unwrap();
            let contract = contract(operation);
            for schema in [&contract.input, &contract.output]
                .into_iter()
                .chain(contract.declared_refusal.iter())
            {
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
    fn only_the_breg_action_contract_exposes_a_closed_declared_refusal() {
        for descriptor in crate::operations::descriptors() {
            let operation = Operation::parse(descriptor.id).unwrap();
            let contract = contract(operation);
            assert_eq!(
                contract.declared_refusal.is_some(),
                descriptor.declared_refusal,
                "{}",
                descriptor.id
            );
        }
        let refusal = contract(Operation::InvokeBregAction)
            .declared_refusal
            .as_ref()
            .unwrap();
        let validator = crate::definition::compile_schema(refusal)
            .unwrap_or_else(|error| panic!("declared-refusal contract does not compile: {error}"));
        assert_eq!(
            first_violation(&validator, &json!({"refusalCode":"not-eligible"})),
            Ok(())
        );
        assert!(first_violation(
            &validator,
            &json!({"refusalCode":"not-eligible", "detail":"private-canary"})
        )
        .is_err());
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
                "appointment": {"admission": {
                    "offering": "intake",
                    "start": "2026-10-11T09:00:00Z",
                    "party": {"recipients": 1, "attendees": 1},
                    "policyRevision": 1,
                    "capabilities": [],
                    "prerequisites": [],
                }},
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
    fn appointment_contract_offers_direct_admission_only() {
        let schema = generated_input(Operation::CreateAppointment);
        let grant = json!({
            "id": "00000000-0000-4000-8000-000000000000",
            "expiresAt": 1,
        });
        let admission = json!({
            "offering": "intake",
            "start": "2026-10-11T09:00:00Z",
            "party": {"recipients": 1, "attendees": 1},
            "policyRevision": 1,
            "capabilities": [],
            "prerequisites": [],
        });
        assert!(schema.is_valid(&json!({
            "grant": grant,
            "appointment": {"admission": admission},
        })));
        assert!(schema.is_valid(&json!({
            "grant": grant,
            "appointment": {"admission": admission, "hold": null},
        })));
        assert!(!schema.is_valid(&json!({
            "grant": grant,
            "appointment": {"hold": "held-allocation"},
        })));
        assert!(!schema.is_valid(&json!({
            "grant": grant,
            "appointment": {},
        })));
        assert!(!schema.is_valid(&json!({
            "grant": grant,
            "appointment": {"admission": admission, "hold": "held-allocation"},
        })));
    }

    #[cfg(feature = "schema")]
    #[tokio::test]
    async fn availability_offering_matches_the_maintained_scheduling_selector() {
        use registry_scheduling_client::{
            BearerToken, SchedulingAuth, SchedulingClient, SchedulingClientConfig,
            SchedulingClientError,
        };

        let schema = generated_input(Operation::ReadAvailability);
        let request = |offering: &str| {
            json!({
                "offering": offering,
                "start": "2026-10-11T09:00:00Z",
                "end": "2026-10-11T17:00:00Z",
                "limit": 10,
            })
        };

        for offering in ["intake", "registry-update-30", "registry_update"] {
            let input = request(offering);
            assert_parity(&schema, &input, true, availability_selector_accepts);
        }
        let client = SchedulingClient::new(SchedulingClientConfig::new(
            "https://scheduling.example.invalid/"
                .parse()
                .expect("fixture service URL"),
        ))
        .expect("fixture client");
        let token = BearerToken::new("fixture-token").expect("fixture token");
        for offering in [
            "",
            "Intake",
            "30-minute-update",
            "registry.update",
            "registry/update",
            "registry update",
            &"x".repeat(65),
        ] {
            let input = request(offering);
            assert_parity(&schema, &input, false, availability_selector_accepts);
            assert!(matches!(
                client
                    .availability(
                        SchedulingAuth::new(&token),
                        offering,
                        None,
                        None,
                        None,
                        Some(10),
                    )
                    .await,
                Err(SchedulingClientError::InvalidRequest { .. })
            ));
        }
    }

    #[cfg(feature = "schema")]
    #[test]
    fn evaluation_contract_matches_the_runtime_state_and_question_bounds() {
        let schema = generated_input(Operation::EvaluateDecision);
        let predicate = json!({"type": "predicate", "instructions": "Decide eligibility"});
        for state in [json!({}), json!("summary"), json!([])] {
            assert_parity(
                &schema,
                &json!({
                "state": state,
                "questions": {"eligible": predicate},
                }),
                true,
                decision_runtime_accepts,
            );
        }
        for state in [Value::Null, json!(true), json!(1)] {
            assert_parity(
                &schema,
                &json!({
                "state": state,
                "questions": {"eligible": predicate},
                }),
                false,
                decision_runtime_accepts,
            );
        }
        for (input, expected) in [
            (json!({"state": {}, "questions": {}}), false),
            (
                json!({
                    "state": {},
                    "questions": {"eligible": {
                        "type": "predicate",
                        "instructions": "  ",
                    }},
                }),
                false,
            ),
            (
                json!({
                    "state": {},
                    "questions": {"route": {
                        "type": "choice",
                        "instructions": "Choose a route",
                        "criteria": {"accept": "Accept"},
                    }},
                }),
                false,
            ),
            (
                json!({
                    "state": {},
                    "questions": {"route": {
                        "type": "choice",
                        "instructions": "Choose a route",
                        "criteria": {"accept": "Accept", "review": "Review"},
                    }},
                }),
                true,
            ),
            (
                json!({
                    "state": {},
                    "questions": {"route": {
                        "type": "choice",
                        "instructions": "Choose a route",
                        "criteria": {"accept": "Accept", "review": "  "},
                    }},
                }),
                false,
            ),
            (
                json!({
                    "state": {},
                    "questions": {"score": {
                        "type": "score",
                        "instructions": "Score the request",
                        "criteria": ["Only one"],
                    }},
                }),
                false,
            ),
            (
                json!({
                    "state": {},
                    "questions": {"score": {
                        "type": "score",
                        "instructions": "Score the request",
                        "criteria": ["Complete", "Consistent"],
                    }},
                }),
                true,
            ),
            (
                json!({
                    "state": {},
                    "questions": {"score": {
                        "type": "score",
                        "instructions": "Score the request",
                        "criteria": ["Complete", "  "],
                    }},
                }),
                false,
            ),
        ] {
            assert_parity(&schema, &input, expected, decision_runtime_accepts);
        }

        let choice_criteria = (0..33)
            .map(|index| (format!("criterion_{index}"), json!("Criterion")))
            .collect::<serde_json::Map<_, _>>();
        assert_parity(
            &schema,
            &json!({
                "state": {},
                "questions": {"route": {
                    "type": "choice",
                    "instructions": "Choose a route",
                    "criteria": choice_criteria,
                }},
            }),
            false,
            decision_runtime_accepts,
        );
        assert_parity(
            &schema,
            &json!({
                "state": {},
                "questions": {"score": {
                    "type": "score",
                    "instructions": "Score the request",
                    "criteria": vec!["Criterion"; 11],
                }},
            }),
            false,
            decision_runtime_accepts,
        );

        let questions = (0..33)
            .map(|index| {
                (
                    format!("question_{index}"),
                    json!({"type": "predicate", "instructions": "Decide"}),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        assert_parity(
            &schema,
            &json!({"state": {}, "questions": questions}),
            false,
            decision_runtime_accepts,
        );
    }

    #[cfg(feature = "schema")]
    #[test]
    fn message_contract_requires_one_complete_content_selection() {
        let schema = generated_input(Operation::SubmitMessage);
        let base = json!({
            "senderProfile": "notices",
            "to": {"email": "person@example.org"},
        });
        let mut template = base.clone();
        template["template"] = json!({"id": "approved", "version": "v1"});
        template["locale"] = json!("en");
        template["data"] = json!({"firstName": "Ada"});
        assert_parity(&schema, &template, true, message_content_runtime_accepts);
        let mut template_with_null_content = template.clone();
        template_with_null_content["content"] = Value::Null;
        assert_parity(
            &schema,
            &template_with_null_content,
            true,
            message_content_runtime_accepts,
        );

        let mut template_with_null_data = template.clone();
        template_with_null_data["data"] = Value::Null;
        assert_parity(
            &schema,
            &template_with_null_data,
            false,
            message_content_runtime_accepts,
        );

        let mut direct = base.clone();
        direct["content"] = json!({"subject": "Decision", "text": "Approved"});
        assert_parity(&schema, &direct, true, message_content_runtime_accepts);
        let mut direct_with_null_template_members = direct.clone();
        direct_with_null_template_members["template"] = Value::Null;
        direct_with_null_template_members["locale"] = Value::Null;
        direct_with_null_template_members["data"] = Value::Null;
        assert_parity(
            &schema,
            &direct_with_null_template_members,
            true,
            message_content_runtime_accepts,
        );
        assert_parity(&schema, &base, false, message_content_runtime_accepts);

        let mut both = template.clone();
        both["content"] = json!({"text": "Approved"});
        assert_parity(&schema, &both, false, message_content_runtime_accepts);

        let mut incomplete_template = base.clone();
        incomplete_template["template"] = json!({"id": "approved", "version": "v1"});
        assert_parity(
            &schema,
            &incomplete_template,
            false,
            message_content_runtime_accepts,
        );

        let mut decorated_direct = direct.clone();
        decorated_direct["locale"] = json!("en");
        assert_parity(
            &schema,
            &decorated_direct,
            false,
            message_content_runtime_accepts,
        );
    }

    #[cfg(feature = "schema")]
    #[test]
    fn committed_contracts_match_their_generator() {
        let generated = generate().unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/coordinator/generated/operations");
        for (file, text) in generated {
            assert_eq!(
                std::fs::read_to_string(root.join(&file)).unwrap(),
                text,
                "{file}"
            );
        }
    }
}
