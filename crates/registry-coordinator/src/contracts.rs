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
    /// The host-owned completion a `wait-for` on this operation observes,
    /// when the operation's resolution fixes one.
    pub completion: Option<Value>,
    input_validator: JSONSchema,
    output_validator: JSONSchema,
    refusal_validator: Option<JSONSchema>,
    /// The complete provider response an `external.command/v1` interpretation
    /// Function reads, before it becomes an accepted result or a refusal.
    response_validator: Option<JSONSchema>,
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
    /// The prefix consisting only of explicitly declared property names.
    /// Dictionary and pattern members come from the checked value, even when
    /// their values violate a type constraint rather than an extra-member rule.
    /// Array positions and unsupported schema locations stop the projection.
    pub fn declared_path(&self, schema: &Value, value: &Value) -> String {
        let Some(path) = self.path.strip_prefix('/') else {
            return String::new();
        };
        let mut schemas = vec![schema];
        let mut current = value;
        let mut safe = String::new();
        let mut budget = 1024;
        for token in path.split('/') {
            if !current.is_object() {
                break;
            }
            let mut name = String::new();
            let mut chars = token.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    match chars.next() {
                        Some('0') => name.push('~'),
                        Some('1') => name.push('/'),
                        _ => return safe,
                    }
                } else {
                    name.push(ch);
                }
            }
            let mut children = Vec::new();
            for candidate in &schemas {
                if !declared_property(schema, candidate, &name, &mut children, &mut budget, 0) {
                    return safe;
                }
            }
            if children.is_empty() {
                break;
            }
            safe.push('/');
            safe.push_str(token);
            schemas = children;
            let Some(child) = current.get(&name) else {
                break;
            };
            current = child;
        }
        safe
    }
}

/// Collect declarations at the same instance location. Every emitted name is
/// authored in the owning schema, including declarations behind local refs or
/// union branches. Exhaustion fails closed instead of using a partial search.
fn declared_property<'a>(
    root: &'a Value,
    schema: &'a Value,
    name: &str,
    children: &mut Vec<&'a Value>,
    budget: &mut usize,
    depth: usize,
) -> bool {
    if *budget == 0 || depth >= 64 {
        return false;
    }
    *budget -= 1;
    if let Some(child) = schema
        .get("properties")
        .and_then(|properties| properties.get(name))
    {
        children.push(child);
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(target) = reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer))
        {
            if !declared_property(root, target, name, children, budget, depth + 1) {
                return false;
            }
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                if !declared_property(root, branch, name, children, budget, depth + 1) {
                    return false;
                }
            }
        }
    }
    true
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
            completion: None,
            input_validator,
            output_validator,
            refusal_validator,
            response_validator: None,
        })
    }

    /// Adds the bounded provider response schema an interpreted command reads.
    pub(crate) fn with_response(mut self, response: Option<&Value>) -> crate::Result<Self> {
        self.response_validator = response
            .map(crate::definition::compile_schema)
            .transpose()?;
        Ok(self)
    }

    /// Checks a provider response before an interpretation Function reads it.
    /// An operation without a declared response accepts none.
    pub fn check_response(&self, value: &Value) -> Result<(), Violation> {
        match &self.response_validator {
            Some(validator) => first_violation(validator, value),
            None => Err(Violation {
                path: String::new(),
                expected: "an Operation declaring an interpreted provider response".into(),
            }),
        }
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

/// Normalize supported numeric width annotations at schema positions only.
/// Callers compiling imported schemas apply this to a validation copy so the
/// governed source and its revision remain unchanged.
pub(crate) fn bound_numbers(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let has_type = |expected: &str| match object.get("type") {
                Some(Value::String(kind)) => kind == expected,
                Some(Value::Array(kinds)) => {
                    kinds.iter().any(|kind| kind == expected)
                        && kinds.iter().all(|kind| kind == expected || kind == "null")
                }
                _ => false,
            };
            let integer = has_type("integer");
            let number = has_type("number");
            let bounds: Option<(Value, Value)> = match object.get("format").and_then(Value::as_str)
            {
                Some("uint8") if integer => Some((json!(0), json!(u8::MAX))),
                Some("uint16") if integer => Some((json!(0), json!(u16::MAX))),
                Some("uint32") if integer => Some((json!(0), json!(u32::MAX))),
                Some("uint64" | "uint") if integer => Some((json!(0), json!(SAFE_INTEGER))),
                Some("int8") if integer => Some((json!(i8::MIN), json!(i8::MAX))),
                Some("int16") if integer => Some((json!(i16::MIN), json!(i16::MAX))),
                Some("int32") if integer => Some((json!(i32::MIN), json!(i32::MAX))),
                Some("int64" | "int") if integer => {
                    Some((json!(-SAFE_INTEGER), json!(SAFE_INTEGER)))
                }
                Some("double" | "float") if number => Some((Value::Null, Value::Null)),
                _ => None,
            };
            if let Some((minimum, maximum)) = bounds {
                object.remove("format");
                for (keyword, bound, lower) in
                    [("minimum", minimum, true), ("maximum", maximum, false)]
                {
                    if bound.is_null() {
                        continue;
                    }
                    let replace = match object.get(keyword) {
                        None => true,
                        Some(existing) => existing.as_f64().zip(bound.as_f64()).is_some_and(
                            |(existing, bound)| {
                                if lower {
                                    existing < bound
                                } else {
                                    existing > bound
                                }
                            },
                        ),
                    };
                    if replace {
                        object.insert(keyword.into(), bound);
                    }
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
    record: Option<&Value>,
    template: Option<&Value>,
    imported: &BTreeMap<String, Value>,
) -> crate::Result<OperationContract> {
    if operation == Operation::ReadInForce {
        if action.is_some() || template.is_some() {
            return Err(in_force_contract_invalid());
        }
        return resolve_in_force(record.ok_or_else(in_force_contract_invalid)?, imported);
    }
    if let Some(record) = record {
        if operation != Operation::ReadRecord || action.is_some() || template.is_some() {
            return Err(record_contract_invalid());
        }
        return resolve_record(record, imported);
    }
    if let Some(template) = template {
        if operation != Operation::SubmitMessage || action.is_some() {
            return Err(template_contract_invalid());
        }
        return resolve_template(template, imported);
    }
    let invalid = || {
        crate::CoordinatorError::new(
            "coordinator.operation.contract-invalid",
            "select one Action from a generated BReg Action contract export",
        )
    };
    let Some(reference) = action else {
        if operation == Operation::InvokeBregAction || operation.takes_proposal_action() {
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
    if operation != Operation::InvokeBregAction && !operation.takes_proposal_action() {
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
    let pinned = crate::breg_action::ActionContract {
        action_id: id.to_owned(),
        action_revision: revision.to_owned(),
        mode,
    };
    if operation.takes_proposal_action() {
        return resolve_proposal(operation, pinned, input);
    }
    if mode == registry_breg_client::BRegActionMode::Proposal {
        return Err(crate::CoordinatorError::new(
            "coordinator.operation.proposal-action",
            format!("Action {id} is a Proposal Action; breg.invoke-action/v1 invokes only immediate Actions"),
        )
        .suggest("Select an immediate Action. The applicant starts and submits a Proposal in the Base Registry Engine; follow it from an event trigger or a read."));
    }
    // Preparation obtains current target conditions using the maintained
    // client. An author may provide expected conditions, but cannot mint them.
    if let Some(required) = input.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|field| field != "preconditions");
    }
    OperationContract::new(
        input,
        output,
        entry.get("declaredRefusal").cloned(),
        Some(pinned),
    )
}

/// A Proposal operation of one pinned Proposal Action. Start and submit send
/// the Action's own input; read and cancel name a Proposal by id. Every
/// call returns the same receipt, and a follow settles to the completion
/// fixed by the Action's input members.
fn resolve_proposal(
    operation: Operation,
    pinned: crate::breg_action::ActionContract,
    mut action_input: Value,
) -> crate::Result<OperationContract> {
    if pinned.mode != registry_breg_client::BRegActionMode::Proposal {
        return Err(crate::CoordinatorError::new(
            "coordinator.operation.contract-invalid",
            format!(
                "Action {} is an immediate Action; {} takes only Proposal Actions",
                pinned.action_id,
                operation.as_str()
            ),
        )
        .suggest("Select a Proposal Action, or invoke this Action with breg.invoke-action/v1."));
    }
    let base = contract(operation);
    let input = if matches!(
        operation,
        Operation::StartProposal | Operation::SubmitProposal
    ) {
        // Start reads current target conditions like an immediate invocation.
        if let Some(required) = action_input
            .get_mut("required")
            .and_then(Value::as_array_mut)
        {
            required.retain(|field| field != "preconditions");
        }
        action_input.clone()
    } else {
        base.input.clone()
    };
    let completion = operation.follows_proposal().then(|| {
        crate::breg_proposal::completion_schema(
            operation,
            crate::breg_proposal::settled_input(&action_input),
        )
    });
    let mut resolved = OperationContract::new(input, base.output.clone(), None, Some(pinned))?;
    resolved.completion = completion;
    Ok(resolved)
}

pub(crate) fn is_breg_record_schema(value: &Value) -> bool {
    value.get("$id").and_then(Value::as_str).is_some_and(|id| {
        id.strip_prefix("urn:breg:record-type:")
            .is_some_and(|id| !id.is_empty())
    }) && value.get("type").and_then(Value::as_str) == Some("object")
        && value.get("properties").is_some_and(Value::is_object)
}

pub(crate) fn is_messaging_template_export(value: &Value) -> bool {
    value.get("apiVersion").and_then(Value::as_str)
        == Some("id.registrystack.org/formats/messaging/template-contracts/v1")
        && value.get("kind").and_then(Value::as_str) == Some("MessagingTemplateContracts")
}

fn record_contract_invalid() -> crate::CoordinatorError {
    crate::CoordinatorError::new(
        "coordinator.operation.contract-invalid",
        "select a generated BReg record schema for breg.read-record/v1 with record: {contract: <import>}",
    )
}

fn resolve_record(
    reference: &Value,
    imported: &BTreeMap<String, Value>,
) -> crate::Result<OperationContract> {
    let source = reference
        .get("contract")
        .and_then(Value::as_str)
        .ok_or_else(record_contract_invalid)?;
    let schema = imported
        .get(source)
        .filter(|value| is_breg_record_schema(value))
        .ok_or_else(record_contract_invalid)?;
    let properties = schema["properties"]
        .as_object()
        .ok_or_else(record_contract_invalid)?;
    let base = contract(Operation::ReadRecord);
    let mut output = base.output.clone();
    // Reads retain current disclosure: required fields may be hidden, and
    // this specialization promises API names rather than value validation.
    output["$defs"]["RegistryRecord"]["properties"]["domainData"] = record_domain_data(properties);
    OperationContract::new(
        base.input.clone(),
        output,
        base.declared_refusal.clone(),
        None,
    )
}

/// The `domainData` schema of a record read: only the record type's API names.
fn record_domain_data(properties: &serde_json::Map<String, Value>) -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "properties": properties.keys().map(|name| (name.clone(), Value::Bool(true))).collect::<serde_json::Map<_, _>>()
    })
}

fn in_force_contract_invalid() -> crate::CoordinatorError {
    crate::CoordinatorError::new(
        "coordinator.operation.contract-invalid",
        "select a generated BReg record schema for breg.read-in-force/v1 with record: {contract: <import>}",
    )
}

/// The `x-registry-temporal` marker of a generated record schema, when its
/// validity interval is a calendar-date range.
pub(crate) fn date_validity_interval(schema: &Value) -> Option<&Value> {
    schema
        .get("x-registry-temporal")
        .filter(|marker| marker.get("valueKind").and_then(Value::as_str) == Some("date"))
}

/// Narrow `breg.read-in-force/v1` to one record type: `entity` must be that
/// type's route, the subject may name only that type's fields, and the output
/// carries only those fields.
fn resolve_in_force(
    reference: &Value,
    imported: &BTreeMap<String, Value>,
) -> crate::Result<OperationContract> {
    let source = reference
        .get("contract")
        .and_then(Value::as_str)
        .ok_or_else(in_force_contract_invalid)?;
    let schema = imported
        .get(source)
        .filter(|value| is_breg_record_schema(value))
        .ok_or_else(in_force_contract_invalid)?;
    if date_validity_interval(schema).is_none() {
        return Err(crate::CoordinatorError::new(
            "definition.read-in-force-entity",
            "This record type has no date validity interval, so no record can be in force on a date.",
        )
        .suggest("Select a record type whose validity interval is a date range, or read it with breg.read-record/v1."));
    }
    let properties = schema["properties"]
        .as_object()
        .ok_or_else(in_force_contract_invalid)?;
    // The route names the record type the subject is read from; binding
    // `entity` to it keeps the check and the read on the same record type.
    let route = schema["x-registry-temporal"]["route"]
        .as_str()
        .ok_or_else(in_force_contract_invalid)?;
    let base = contract(Operation::ReadInForce);
    let mut input = base.input.clone();
    input["properties"]["entity"] = json!({"const": route});
    input["properties"]["subject"] = json!({
        "type": "object", "additionalProperties": false,
        "minProperties": 1, "maxProperties": crate::read_in_force::MAX_SUBJECT_FIELDS,
        "description": base.input["properties"]["subject"]["description"].clone(),
        "x-registry-in-force-scopes": schema["x-registry-temporal"]["nonOverlapScopeProperties"].clone(),
        "properties": properties.keys().map(|name| (name.clone(), json!({"$ref": "#/$defs/SubjectValue"}))).collect::<serde_json::Map<_, _>>()
    });
    let mut output = base.output.clone();
    // Reads retain current disclosure: required fields may be hidden, so the
    // output promises API names rather than value validation.
    output["properties"]["domainData"] = record_domain_data(properties);
    let mut refusal = base.declared_refusal.clone();
    if let Some(refusal) = refusal.as_mut() {
        refusal["properties"]["refusalCode"] =
            json!({"const": crate::read_in_force::NONE_IN_FORCE});
    }
    OperationContract::new(input, output, refusal, None)
}

fn template_contract_invalid() -> crate::CoordinatorError {
    crate::CoordinatorError::new(
        "coordinator.operation.contract-invalid",
        "select exactly one template ID and version from a generated Messaging template contract export",
    )
}

fn resolve_template(
    reference: &Value,
    imported: &BTreeMap<String, Value>,
) -> crate::Result<OperationContract> {
    let source = reference
        .get("contract")
        .and_then(Value::as_str)
        .ok_or_else(template_contract_invalid)?;
    let id = reference
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(template_contract_invalid)?;
    let version = reference
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(template_contract_invalid)?;
    let export = imported
        .get(source)
        .filter(|value| is_messaging_template_export(value))
        .ok_or_else(template_contract_invalid)?;
    let mut entries = export
        .get("templates")
        .and_then(Value::as_array)
        .ok_or_else(template_contract_invalid)?
        .iter()
        .filter(|entry| {
            entry.get("id").and_then(Value::as_str) == Some(id)
                && entry.get("version").and_then(Value::as_str) == Some(version)
        });
    let entry = entries.next().ok_or_else(template_contract_invalid)?;
    if entries.next().is_some() {
        return Err(template_contract_invalid());
    }
    let locales = entry
        .get("locales")
        .and_then(Value::as_array)
        .filter(|locales| {
            !locales.is_empty()
                && locales
                    .iter()
                    .all(|locale| locale.as_str().is_some_and(|locale| !locale.is_empty()))
        })
        .ok_or_else(template_contract_invalid)?;
    let mut data = entry
        .get("dataSchema")
        .cloned()
        .ok_or_else(template_contract_invalid)?;
    if let Some(object) = data.as_object_mut() {
        object.remove("$id");
        object.remove("$schema");
    }
    bound_numbers(&mut data);
    let data = crate::authoring::embed_schema(&data, "/$defs/templateData")?;
    let base = contract(Operation::SubmitMessage);
    let mut input = base.input.clone();
    input
        .as_object_mut()
        .expect("operation input is an object")
        .remove("oneOf");
    input["$defs"]["templateData"] = data;
    input["properties"]["template"] = json!({"type": "object", "additionalProperties": false,
        "required": ["id", "version"], "properties": {"id": {"const": id}, "version": {"const": version}}});
    input["properties"]["locale"] = json!({"type": "string", "enum": locales});
    input["properties"]["data"] = json!({"$ref": "#/$defs/templateData", "not": {"type": "null"}});
    input["properties"]["content"] = json!({"type": "null"});
    input["required"] = json!(["senderProfile", "to", "template", "locale", "data"]);
    OperationContract::new(
        input,
        base.output.clone(),
        base.declared_refusal.clone(),
        None,
    )
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
    validator: JSONSchema,
}

impl CompletionContract {
    pub(crate) fn new(output: &Value) -> crate::Result<Self> {
        Ok(Self {
            validator: crate::definition::compile_schema(output)?,
        })
    }

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

/// Shared Review and event wire schemas, generated from their owning types.
pub fn admission_schemas() -> &'static Value {
    static SCHEMAS: OnceLock<Value> = OnceLock::new();
    SCHEMAS.get_or_init(|| {
        #[cfg(feature = "schema")]
        {
            derived::admission_schemas()
        }
        #[cfg(not(feature = "schema"))]
        {
            serde_json::from_str(include_str!(
                "../../../products/coordinator/generated/operations/admission.schemas.json"
            ))
            .expect("generated admission wire schemas")
        }
    })
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
                    let declared_refusal = crate::operations::descriptor(id)
                        .expect("every derived contract names a catalog operation")
                        .declared_refusal
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
    macro_rules! schema_catalog {
        ($($name:ident => $id:literal, $metadata:expr, $factory:ident;)+) => {
            BTreeMap::from([$(($id, derived::$factory())),+])
        };
    }
    crate::operations::operation_catalog!(schema_catalog)
}

/// Generated contract files and their reference, keyed by file name.
#[cfg(feature = "schema")]
pub fn generate() -> Result<BTreeMap<String, String>, serde_json::Error> {
    let mut contracts = derived_contracts();
    let mut files = BTreeMap::new();
    files.insert(
        "admission.schemas.json".into(),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&derived::admission_schemas())?
        ),
    );
    for descriptor in crate::operations::descriptors() {
        let (mut input, mut output) = contracts
            .remove(descriptor.id)
            .expect("every catalog operation derives a contract");
        derived::finish(&mut input, &format!("{} input", descriptor.id));
        derived::finish(&mut output, &format!("{} output", descriptor.id));
        if descriptor.id == Operation::ReadRecord.as_str()
            || descriptor.id == Operation::ReadRecordV2.as_str()
        {
            output["$defs"]["RegistryRecord"]["properties"]["domainData"]["description"] =
                Value::from(
                    "Project-defined record data. An imported BReg record schema limits member \
                     names to the record type's API names. Fields may be hidden by access policy; \
                     value types remain open. Without a record import, any member name is accepted.",
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
    for descriptor in crate::operations::descriptors() {
        if !descriptor.declared_refusal {
            continue;
        }
        let mut refusal = derived::output::<crate::protocol::DeclaredRefusal>();
        let title = if descriptor.id == Operation::InvokeBregAction.as_str() {
            "invoke-breg-action declared-refusal output".to_owned()
        } else {
            format!("{} declared-refusal output", descriptor.id)
        };
        if descriptor.id == Operation::LookupRecord.as_str() {
            refusal["properties"]["refusalCode"] = serde_json::json!({
                "type": "string",
                "const": crate::record_read::UNRESOLVED
            });
        }
        derived::finish(&mut refusal, &title);
        let mut text = serde_json::to_string_pretty(&refusal)?;
        text.push('\n');
        files.insert(
            format!(
                "{}.declared-refusal.schema.json",
                descriptor.id.replace('/', ".")
            ),
            text,
        );
    }
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

    use crate::{
        adapters::{
            AppointmentReadRequest, AvailabilityRequest, CancellationRequest,
            CapacityPreviewRequest, HoldRequest, ReadRequest, ReleaseHoldRequest,
            RescheduleRequest, SchedulingReadRequest,
        },
        breg_action::ActionInput,
        breg_proposal::{ProposalReceipt, ProposalReference},
        decision::DecisionResult,
        external_http::{ExternalResponse, GetRequest},
        read_in_force::{InForceRecord, InForceRequest, MAX_SUBJECT_FIELDS},
        record_read::{LookedUpRecord, LookupRequest, MAX_LOOKUP_VALUES},
        review::CancelReviewInput,
    };
    use registry_breg_client::{BRegActionReceipt, RegistryRecordSingleResponse};
    use registry_casework_client::{
        ReviewCancelResponse, ReviewCreateRequest, ReviewRequestAccepted,
    };
    use registry_messaging_core::MessageReceipt;
    use registry_scheduling_client::HoldDocument;
    use registry_scheduling_core::{
        AppointmentDocument, AvailabilityEntry, AvailabilityPreviewDocument, PageDocument,
        SchedulingServiceDocument,
    };
    use schemars::{generate::SchemaSettings, JsonSchema};
    use serde_json::{json, Value};

    pub(super) fn admission_schemas() -> Value {
        let mut schemas = json!({
            "ReviewCompletion": input::<registry_review_protocol::ReviewCompletion>(),
            "HookEnvelope": input::<registry_platform_hooks::HookEnvelope>()
        });
        for (name, schema) in schemas.as_object_mut().expect("wire schema map") {
            finish(schema, name);
        }
        schemas
    }

    pub(super) fn read_record() -> (Value, Value) {
        (
            input::<ReadRequest>(),
            output::<RegistryRecordSingleResponse>(),
        )
    }

    pub(super) fn submit_message() -> (Value, Value) {
        (submit_message_input(), output::<MessageReceipt>())
    }

    pub(super) fn read_scheduling() -> (Value, Value) {
        (
            input::<SchedulingReadRequest>(),
            output::<SchedulingServiceDocument>(),
        )
    }

    pub(super) fn read_availability() -> (Value, Value) {
        (
            input::<AvailabilityRequest>(),
            output::<PageDocument<AvailabilityEntry>>(),
        )
    }

    pub(super) fn preview_availability() -> (Value, Value) {
        (
            input::<CapacityPreviewRequest>(),
            output::<AvailabilityPreviewDocument>(),
        )
    }

    pub(super) fn create_appointment() -> (Value, Value) {
        (create_appointment_input(), output::<AppointmentDocument>())
    }

    pub(super) fn read_appointment() -> (Value, Value) {
        (
            input::<AppointmentReadRequest>(),
            output::<AppointmentDocument>(),
        )
    }

    pub(super) fn create_hold() -> (Value, Value) {
        (input::<HoldRequest>(), output::<HoldDocument>())
    }

    pub(super) fn release_hold() -> (Value, Value) {
        (input::<ReleaseHoldRequest>(), output::<()>())
    }

    pub(super) fn confirm_hold() -> (Value, Value) {
        (confirm_hold_input(), output::<AppointmentDocument>())
    }

    pub(super) fn reschedule_appointment() -> (Value, Value) {
        (
            input::<RescheduleRequest>(),
            output::<AppointmentDocument>(),
        )
    }

    pub(super) fn cancel_appointment() -> (Value, Value) {
        (
            input::<CancellationRequest>(),
            output::<AppointmentDocument>(),
        )
    }

    pub(super) fn invoke_breg_action() -> (Value, Value) {
        (input::<ActionInput>(), output::<BRegActionReceipt>())
    }

    pub(super) fn read_in_force() -> (Value, Value) {
        let mut request = input::<InForceRequest>();
        request["properties"]["subject"]["minProperties"] = json!(1);
        request["properties"]["subject"]["maxProperties"] = json!(MAX_SUBJECT_FIELDS);
        request["properties"]["date"]["pattern"] = json!(r"^\d{4}-\d{2}-\d{2}$");
        request["properties"]["date"]["format"] = json!("date");
        let mut record = output::<InForceRecord>();
        record["properties"]["asOf"]["format"] = json!("date");
        record["properties"]["observedAt"]["format"] = json!("date-time");
        (request, record)
    }

    pub(super) fn lookup_record() -> (Value, Value) {
        let mut request = input::<LookupRequest>();
        request["properties"]["values"]["minProperties"] = json!(1);
        request["properties"]["values"]["maxProperties"] = json!(MAX_LOOKUP_VALUES);
        let mut record = output::<LookedUpRecord>();
        set_observed_at_format(&mut record);
        // BReg sends no ETag on a lookup, so the lookup contract does not offer one.
        record["$defs"]["Provenance"]["properties"]
            .as_object_mut()
            .expect("the provenance lists its members")
            .remove("etag");
        (request, record)
    }

    /// The v1 record envelope with the provenance of the read added.
    pub(super) fn read_record_v2() -> (Value, Value) {
        let mut envelope = output::<RegistryRecordSingleResponse>();
        let mut provenance = output::<LookedUpRecord>();
        set_observed_at_format(&mut provenance);
        envelope["description"] = json!(
            "One Registry Record v1 single-response envelope with the provenance of this read."
        );
        envelope["$defs"]["Provenance"] = provenance["$defs"]["Provenance"].clone();
        envelope["properties"]["provenance"] = json!({"$ref": "#/$defs/Provenance"});
        envelope["required"]
            .as_array_mut()
            .expect("the record envelope lists its required members")
            .push(json!("provenance"));
        (input::<ReadRequest>(), envelope)
    }

    fn set_observed_at_format(record: &mut Value) {
        record["$defs"]["Provenance"]["properties"]["observedAt"]["format"] = json!("date-time");
    }

    pub(super) fn read_proposal() -> (Value, Value) {
        (input::<ProposalReference>(), output::<ProposalReceipt>())
    }

    pub(super) fn start_proposal() -> (Value, Value) {
        (input::<ActionInput>(), output::<ProposalReceipt>())
    }

    pub(super) fn submit_proposal() -> (Value, Value) {
        (input::<ActionInput>(), output::<ProposalReceipt>())
    }

    pub(super) fn cancel_proposal() -> (Value, Value) {
        (input::<ProposalReference>(), output::<ProposalReceipt>())
    }

    pub(super) fn external_get() -> (Value, Value) {
        (input::<GetRequest>(), output::<ExternalResponse>())
    }

    /// The command body is a JSON object a pinned pure Function builds; the
    /// output is the bounded provider response the pinned interpretation
    /// Function receives, never the step result itself.
    pub(super) fn external_command() -> (Value, Value) {
        let mut response = output::<ExternalResponse>();
        response["description"] = json!(
            "The bounded provider response. The operation's interpret Function \
             receives it with the command and returns the step result, a declared \
             refusal, or an uncertain outcome."
        );
        (
            json!({
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "type":"object",
                "description":"The command body, sent as the exact JSON object to the \
                    connection's configured command path.",
                "additionalProperties":true
            }),
            response,
        )
    }

    pub(super) fn evaluate() -> (Value, Value) {
        (evaluation_input(), output::<DecisionResult>())
    }

    pub(super) fn submit_review_request() -> (Value, Value) {
        (
            input::<ReviewCreateRequest>(),
            output::<ReviewRequestAccepted>(),
        )
    }

    pub(super) fn cancel_review_request() -> (Value, Value) {
        (
            input::<CancelReviewInput>(),
            output::<ReviewCancelResponse>(),
        )
    }

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

    /// Direct booking and hold confirmation are separate catalog operations,
    /// although Scheduling carries both through one maintained wire type.
    pub(super) fn create_appointment_input() -> Value {
        appointment_input(false)
    }

    /// Hold confirmation uses the same maintained Scheduling wire request as
    /// direct creation, while accepting only its other mutually exclusive arm.
    pub(super) fn confirm_hold_input() -> Value {
        appointment_input(true)
    }

    fn appointment_input(confirm: bool) -> Value {
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
        let required_member = if confirm { "hold" } else { "admission" };
        if !required.iter().any(|member| member == required_member) {
            required.push(json!(required_member));
        }
        if confirm {
            request["properties"]["hold"] = json!({
                "description": "The Scheduling hold UUID to confirm.",
                "format": "uuid",
                "type": "string"
            });
            request["properties"]["admission"] = json!({
                "description": "Direct admission is not accepted by this operation.",
                "type": "null"
            });
        } else {
            request["properties"]["admission"] = json!({
                "$ref": "#/$defs/AdmissionRequest",
                "description": "The direct-create admission request."
            });
            request["properties"]["hold"] = json!({
                "description": "Hold confirmation is not accepted by this operation.",
                "type": "null"
            });
        }
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

    /// Publish the same explicit numeric width bounds the runtime compiler
    /// applies on its validation copy. Canonical JSON's IEEE 754 safe integer
    /// range also bounds the 64-bit widths.
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
    fn numeric_widths_intersect_explicit_limits_and_require_matching_types() {
        for (schema, accepted, refused) in [
            (
                json!({"type":"integer","format":"uint8","minimum":-5,"maximum":1000}),
                json!([0, 255]),
                json!([-1, 256]),
            ),
            (
                json!({"type":"integer","format":"uint8","minimum":10,"maximum":20}),
                json!([10, 20]),
                json!([9, 21]),
            ),
            (
                json!({"type":["integer","null"],"format":"int64","minimum":1}),
                json!([null, 1, SAFE_INTEGER]),
                json!([0, 1.5, "1", SAFE_INTEGER + 1]),
            ),
            (
                json!({"type":"number","format":"double","minimum":1,"maximum":2}),
                json!([1, 1.5, 2]),
                json!([0, 2.5, "1"]),
            ),
        ] {
            let original = schema.clone();
            let validator = crate::definition::compile_schema(&schema).unwrap();
            for value in accepted.as_array().unwrap() {
                assert!(validator.is_valid(value));
            }
            for value in refused.as_array().unwrap() {
                assert!(!validator.is_valid(value));
            }
            assert_eq!(
                schema, original,
                "compiler normalization never changes source"
            );
        }
        for schema in [
            json!({"type":"string","format":"int64"}),
            json!({"type":["integer","string"],"format":"int64"}),
            json!({"type":"integer","format":"double"}),
            json!({"format":"int64"}),
            json!({"type":"integer","format":"unknown-numeric-format"}),
            json!({"$ref":"https://example.invalid/private-schema"}),
        ] {
            assert!(crate::definition::compile_schema(&schema).is_err());
        }
    }

    #[test]
    fn compiler_preserves_schema_shaped_literal_data() {
        let literal = json!({"format":"int64","properties":{"secret":{"$ref":"https://example.invalid/literal"}}});
        let schema = json!({"type":"object","const":literal,"enum":[literal],
            "default":literal,"examples":[literal]});
        let original = schema.clone();
        let validator = crate::definition::compile_schema(&schema).unwrap();
        assert!(validator.is_valid(&literal));
        assert_eq!(schema, original);
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
    fn a_proposal_mode_action_is_refused_with_the_applicant_path() {
        let mut export: Value = serde_json::from_str(include_str!(
            "../../../products/coordinator/examples/governed-action-follow-up/generated/applications.contract.json"
        ))
        .unwrap();
        let reference = json!({"contract":"applications","id":"request-information"});
        let imported = BTreeMap::from([("applications".to_owned(), export.clone())]);
        assert!(resolve_operation(
            Operation::InvokeBregAction,
            Some(&reference),
            None,
            None,
            &imported
        )
        .is_ok());
        export["actions"][0]["mode"] = json!("proposal");
        let imported = BTreeMap::from([("applications".to_owned(), export)]);
        let Err(error) = resolve_operation(
            Operation::InvokeBregAction,
            Some(&reference),
            None,
            None,
            &imported,
        ) else {
            panic!("a Proposal-mode Action resolved");
        };
        assert_eq!(error.code, "coordinator.operation.proposal-action");
        assert!(error.message.contains("immediate"), "{}", error.message);
        assert!(
            error
                .suggested_action
                .as_deref()
                .is_some_and(|fix| fix.contains("applicant")),
            "{error:?}"
        );
    }

    #[test]
    fn declared_refusal_operations_expose_a_closed_declared_refusal() {
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
        assert!(Operation::ExternalCommand.descriptor().declared_refusal);
        for operation in [Operation::InvokeBregAction, Operation::ExternalCommand] {
            let refusal = contract(operation).declared_refusal.as_ref().unwrap();
            let validator = crate::definition::compile_schema(refusal).unwrap_or_else(|error| {
                panic!("declared-refusal contract does not compile: {error}")
            });
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
        let command = contract(Operation::ExternalCommand);
        assert_eq!(command.check_input(&json!({"amount":"25.00"})), Ok(()));
        assert!(command.check_input(&json!(["not-an-object"])).is_err());
        assert_eq!(
            command.check_output(&json!({"status":201,"body":{"id":"bill-1"}})),
            Ok(())
        );
    }

    #[test]
    fn the_declared_path_leaves_out_an_unexpected_member_name() {
        let read = contract(Operation::ReadRecord);
        let value = json!({"collection": "c", "recordId": "r", "private-canary": 1});
        let unexpected = read.check_input(&value).unwrap_err();
        assert_eq!(unexpected.path, "/private-canary");
        assert_eq!(unexpected.declared_path(&read.input, &value), "");
        let appointment = contract(Operation::CreateAppointment);
        let value = json!({
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
        });
        let nested = appointment.check_input(&value).unwrap_err();
        assert_eq!(nested.path, "/grant/private-canary");
        assert_eq!(nested.declared_path(&appointment.input, &value), "/grant");
        let value = json!({"collection": 7, "recordId": "r"});
        let typed = read.check_input(&value).unwrap_err();
        assert_eq!(typed.declared_path(&read.input, &value), "/collection");
    }

    #[test]
    fn declared_paths_hide_dictionary_and_pattern_keys_for_typed_violations() {
        let external = contract(Operation::ExternalGet);
        let value = json!({"path":"jobs/status", "query":{"private-person-id":7}});
        let violation = external.check_input(&value).unwrap_err();
        assert_eq!(violation.path, "/query/private-person-id");
        assert_eq!(violation.declared_path(&external.input, &value), "/query");

        let schema = json!({"properties":{"payload":{
            "patternProperties":{"^private-":{"type":"string"}}
        }}});
        let value = json!({"payload":{"private-person-id":7}});
        let violation = Violation {
            path: "/payload/private-person-id".into(),
            expected: "a string".into(),
        };
        assert_eq!(violation.declared_path(&schema, &value), "/payload");
    }

    #[test]
    fn declared_paths_follow_local_refs_and_union_declarations_only() {
        for keyword in ["allOf", "anyOf", "oneOf"] {
            let schema = json!({
                "$defs":{"payload":{"properties":{
                    "known/name":{"properties":{"value":{"type":"string"}}},
                    "dictionary":{"additionalProperties":{"type":"string"}}
                }}},
                (keyword):[{"properties":{"payload":{"$ref":"#/$defs/payload"}}}]
            });
            let value = json!({"payload":{
                "known/name":{"value":7}, "dictionary":{"private-person-id":7}
            }});
            for (path, expected) in [
                ("/payload/known~1name/value", "/payload/known~1name/value"),
                (
                    "/payload/dictionary/private-person-id",
                    "/payload/dictionary",
                ),
            ] {
                let violation = Violation {
                    path: path.into(),
                    expected: "a string".into(),
                };
                assert_eq!(
                    violation.declared_path(&schema, &value),
                    expected,
                    "{keyword}"
                );
            }
        }
    }

    #[test]
    fn declared_paths_fail_closed_at_dynamic_or_unsupported_positions() {
        let value = json!({"items":[{"private-person-id":7}], "payload":{"private-person-id":7}});
        for (schema, path, expected) in [
            (
                json!({"properties":{"items":{"items":{"properties":{"private-person-id":{}}}}}}),
                "/items/0/private-person-id",
                "/items",
            ),
            (
                json!({"properties":{"payload":{"$ref":"https://example.invalid/schema"}}}),
                "/payload/private-person-id",
                "/payload",
            ),
            (
                json!({"properties":{"payload":{"if":{},"then":{"properties":{"private-person-id":{}}}}}}),
                "/payload/private-person-id",
                "/payload",
            ),
            (json!({"$ref":"#"}), "/payload/private-person-id", ""),
            (
                json!({"properties":{"payload":{}}}),
                "/payload/private~2person-id",
                "/payload",
            ),
        ] {
            let violation = Violation {
                path: path.into(),
                expected: "a string".into(),
            };
            assert_eq!(violation.declared_path(&schema, &value), expected);
        }
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

        let confirmation = generated_input(Operation::ConfirmHold);
        assert!(confirmation.is_valid(&json!({
            "grant": grant,
            "appointment": {"hold": "00000000-0000-4000-8000-000000000001"},
        })));
        assert!(confirmation.is_valid(&json!({
            "grant": grant,
            "appointment": {
                "hold": "00000000-0000-4000-8000-000000000001",
                "admission": null
            },
        })));
        assert!(!confirmation.is_valid(&json!({
            "grant": grant,
            "appointment": {"hold": "held-allocation"},
        })));
        assert!(!confirmation.is_valid(&json!({
            "grant": grant,
            "appointment": {"admission": admission},
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
