// SPDX-License-Identifier: Apache-2.0
//! Static mapping checks. Before any run, each reference path must resolve in
//! the schema of the value it reads, and each mapping must fit what it feeds:
//! the operation input contract, the outcome schema, a date-time for
//! waitUntil, or a declared case for choose.
//!
//! Only mismatches the schemas decide are refused. A member a schema leaves
//! open, a string without a format, a nullable source, and every value a
//! function computes are left to scenarios and the runtime.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{
    contracts::{first_violation, Violation},
    definition::{
        authored, compile_schema, output_routes, parse_timestamp, AvailableOutputs, Mapping,
        OutputRoute, Reference, Step, Workflow,
    },
    CoordinatorError, Result,
};

/// Schema nodes one navigation or description may visit, so a recursive or
/// deeply composed schema ends as undecidable rather than looping.
const BUDGET: usize = 256;

fn budget() -> usize {
    BUDGET
}

/// Check every step's mapping, in step-name order, and report the first
/// mismatch in each step.
pub(crate) fn check(workflow: &Workflow) -> Vec<CoordinatorError> {
    let routes = output_routes(workflow);
    workflow
        .steps
        .iter()
        .filter_map(|(name, step)| {
            check_step(
                workflow,
                name,
                step,
                routes
                    .get(name)
                    .expect("a checked workflow reaches every step"),
            )
            .err()
        })
        .collect()
}

fn check_step(
    workflow: &Workflow,
    name: &str,
    step: &Step,
    available: &AvailableOutputs,
) -> Result<()> {
    let Some(mapping) = step.mapping() else {
        return Ok(());
    };
    let base = format!("steps.{name}.{}", step.role());
    let mut read = BTreeMap::new();
    for (member, reference) in mapping.references() {
        if let Some(schema) = source(workflow, available, reference, &format!("{base}{member}"))? {
            read.insert(member, schema);
        }
    }
    if let Mapping::Function { function, inputs } = mapping {
        let signature = workflow.functions.get(function).ok_or_else(|| {
            authored(
                "mapping.function",
                &format!("{base}.function"),
                "the named Function is not declared",
                "Name one of the project's declared Functions.",
            )
        })?;
        if inputs.keys().ne(signature.inputs.keys()) {
            return Err(authored(
                "mapping.function",
                &format!("{base}.inputs"),
                "the named Function inputs must match its declared signature exactly",
                "Supply every declared input name once and remove undeclared names.",
            ));
        }
        for (name, reference) in inputs {
            reference_fits(
                &signature.inputs[name],
                reference,
                read.get(&format!(".inputs.{name}")),
                &format!("{base}.inputs.{name}"),
            )?;
        }
        let result = Read {
            root: &signature.output,
            schema: signature.output.clone(),
        };
        match step {
            Step::Call { call, .. } => {
                schema_fits(&workflow.operation(call).input, &result, &base)?
            }
            Step::Finish { finish, .. } => schema_fits(&workflow.outcomes[finish], &result, &base)?,
            Step::WaitUntil { .. } => {
                instant_fits(&Reference::Input { path: None }, Some(&result), &base)?
            }
            Step::Choose { cases, .. } => label_fits(
                &Reference::Input { path: None },
                Some(&result),
                cases,
                &base,
            )?,
            _ => {}
        }
    }
    match (step, mapping) {
        (Step::Call { call, .. }, Mapping::Reference(reference)) => reference_fits(
            &workflow.operation(call).input,
            reference,
            read.get(""),
            &base,
        )?,
        (Step::Finish { finish, .. }, Mapping::Reference(reference)) => {
            reference_fits(&workflow.outcomes[finish], reference, read.get(""), &base)?
        }
        (Step::Call { call, .. }, Mapping::Fields { fields }) => fields_fit(
            &workflow.operation(call).input,
            &format!("the {} input", call.operation.as_str()),
            &base,
            fields,
            &read,
        )?,
        (Step::Finish { finish, .. }, Mapping::Fields { fields }) => fields_fit(
            &workflow.outcomes[finish],
            &format!("the {finish} outcome"),
            &base,
            fields,
            &read,
        )?,
        (Step::WaitUntil { .. }, Mapping::Reference(reference)) => {
            instant_fits(reference, read.get(""), &base)?
        }
        (Step::Choose { cases, .. }, Mapping::Reference(reference)) => {
            label_fits(reference, read.get(""), cases, &base)?
        }
        _ => {}
    }
    Ok(())
}

/// What a schema says a value holds: the root it was read from, for local
/// references, and the subschema at the referenced path.
struct Read<'a> {
    root: &'a Value,
    schema: Value,
}

fn reference_fits(
    target: &Value,
    reference: &Reference,
    read: Option<&Read<'_>>,
    field: &str,
) -> Result<()> {
    if let Reference::Literal { value } = reference {
        if let Some(violation) = literal_violation(target, target, value) {
            return Err(authored(
                "mapping.literal",
                &format!("{field}.value"),
                &format!(
                    "the literal does not fit its target schema: expected {}",
                    violation.expected
                ),
                "Correct the literal to satisfy the target schema.",
            ));
        }
    } else if let Some(read) = read {
        schema_fits(target, read, field)?;
    }
    Ok(())
}

fn schema_fits(target: &Value, read: &Read<'_>, field: &str) -> Result<()> {
    let wanted = facts(target, target, &mut budget());
    let offered = facts(read.root, &read.schema, &mut budget());
    if !wanted.accepts(&offered) {
        return Err(authored(
            "mapping.type",
            field,
            &format!(
                "expected {}; the producer supplies {}",
                wanted.describe(),
                offered.describe()
            ),
            "Select a value of the target type, or convert it with a typed Function.",
        ));
    }
    Ok(())
}

/// Resolve an input or step reference's path in its producer's schema.
fn source<'a>(
    workflow: &'a Workflow,
    available: &AvailableOutputs,
    reference: &Reference,
    field: &str,
) -> Result<Option<Read<'a>>> {
    let (root, producer, path) = match reference {
        Reference::Input { path } => (
            &workflow.input,
            "the workflow input schema".to_owned(),
            path,
        ),
        Reference::Step { step, path } => match workflow.steps.get(step) {
            Some(Step::Call { call, .. }) => match available.get(step) {
                Some(OutputRoute::CallSuccess) => (
                    &workflow.operation(call).output,
                    format!("the {} output of step {step}", call.operation.as_str()),
                    path,
                ),
                Some(OutputRoute::DeclaredRefusal) => (
                    workflow
                        .operation(call)
                        .refusal
                        .as_ref()
                        .expect("a declared-refusal route has a committed contract"),
                    format!(
                        "the {} declared-refusal output of step {step}",
                        call.operation.as_str()
                    ),
                    path,
                ),
                _ => return Ok(None),
            },
            Some(Step::WaitFor { wait_for, .. }) => (
                &workflow
                    .completion(wait_for)
                    .expect("the completion was resolved")
                    .output,
                format!("the {} completion of step {step}", wait_for.name),
                path,
            ),
            _ => return Ok(None),
        },
        Reference::Literal { .. } => return Ok(None),
    };
    let mut schema = root.clone();
    let mut walked = String::new();
    for token in path.as_deref().unwrap_or("").split('/').skip(1) {
        walked.push('/');
        walked.push_str(token);
        let name = token.replace("~1", "/").replace("~0", "~");
        schema = match member(root, &schema, &name, &mut budget()) {
            Reach::Schema(next) => next,
            Reach::Silent => Value::Bool(true),
            Reach::Forbidden | Reach::Undeclared => {
                return Err(authored(
                    "mapping.path",
                    &format!("{field}.path"),
                    &format!("expected a path that {producer} declares; it declares nothing at {walked}"),
                    &format!("Correct the path to a member {producer} declares, or omit path to use the whole value."),
                ))
            }
        };
    }
    Ok(Some(Read { root, schema }))
}

/// Check a fields mapping against the object it builds: every member it
/// sets is declared, every required member is set, and each literal or
/// reference fits its member.
fn fields_fit(
    target: &Value,
    name: &str,
    base: &str,
    fields: &BTreeMap<String, Reference>,
    read: &BTreeMap<String, Read<'_>>,
) -> Result<()> {
    let whole = facts(target, target, &mut budget());
    if !whole.allows(&Kind::Object) {
        return Err(authored(
            "mapping.type",
            base,
            &format!(
                "expected {}, as {name} declares; fields builds an object",
                whole.describe()
            ),
            "Build the output with a function, or declare an object outcome.",
        ));
    }
    for (field, reference) in fields {
        let path = format!("{base}.fields.{field}");
        let declared = match member(target, target, field, &mut budget()) {
            Reach::Schema(schema) => schema,
            Reach::Silent => Value::Bool(true),
            Reach::Forbidden | Reach::Undeclared => {
                return Err(authored(
                    "mapping.field",
                    &path,
                    &format!("expected a member {name} declares; it declares no {field}"),
                    &format!("Remove {field}, or rename it to a member {name} declares."),
                ))
            }
        };
        if let Reference::Literal { value } = reference {
            if let Some(violation) = literal_violation(target, &declared, value) {
                let at = if violation.path.is_empty() {
                    format!("for {field}")
                } else {
                    format!("at {} inside {field}", violation.path)
                };
                return Err(authored(
                    "mapping.literal",
                    &format!("{path}.value"),
                    &format!(
                        "expected {} {at}, as {name} declares; the literal does not match",
                        violation.expected
                    ),
                    &format!("Correct the literal to match what {name} declares, or select the value with a reference."),
                ));
            }
        } else if let Some(read) = read.get(&format!(".fields.{field}")) {
            let wanted = facts(target, &declared, &mut budget());
            let offered = facts(read.root, &read.schema, &mut budget());
            if !wanted.accepts(&offered) {
                return Err(authored(
                    "mapping.type",
                    &path,
                    &format!(
                        "expected {} for {field}, as {name} declares; the reference reads {}",
                        wanted.describe(),
                        offered.describe()
                    ),
                    "Select a member of the declared type, or convert the value in a function.",
                ));
            }
        }
    }
    if let Some(missing) = required(target, target, &mut budget())
        .into_iter()
        .find(|member| !fields.contains_key(member))
    {
        return Err(authored(
            "mapping.field",
            &format!("{base}.fields"),
            &format!("expected every member {name} requires; fields does not set {missing}"),
            &format!("Add a {missing} field with a reference or a literal."),
        ));
    }
    Ok(())
}

/// A waitUntil reference reads a date-time string.
fn instant_fits(reference: &Reference, read: Option<&Read<'_>>, base: &str) -> Result<()> {
    if let Reference::Literal { value } = reference {
        if parse_timestamp(value).is_err() {
            return Err(authored(
                "mapping.literal",
                &format!("{base}.value"),
                "expected a date-time string for waitUntil; the literal does not match",
                "Write the literal as an RFC 3339 date-time, such as 2026-10-10T09:00:00Z, or select the instant with a reference.",
            ));
        }
        return Ok(());
    }
    let Some(read) = read else {
        return Ok(());
    };
    let offered = facts(read.root, &read.schema, &mut budget());
    let instant = Facts::kinds([Kind::String(Some("date-time".into()))]);
    if !instant.accepts(&offered) {
        return Err(authored(
            "mapping.type",
            base,
            &format!(
                "expected a date-time string for waitUntil; the reference reads {}",
                offered.describe()
            ),
            "Select a date-time member, or compute the instant in a function.",
        ));
    }
    Ok(())
}

/// A choose reference reads a string, and when its schema lists the strings
/// it may hold, the cases name exactly those.
fn label_fits(
    reference: &Reference,
    read: Option<&Read<'_>>,
    cases: &BTreeMap<String, String>,
    base: &str,
) -> Result<()> {
    let field = base.rsplit_once('.').map_or(base, |(step, _)| step);
    if let Reference::Literal { value } = reference {
        if !value
            .as_str()
            .is_some_and(|label| cases.contains_key(label))
        {
            return Err(authored(
                "mapping.literal",
                &format!("{base}.value"),
                "expected a string naming a case; the literal names none",
                "Write the label of a declared case, or select the label with a reference.",
            ));
        }
        return Ok(());
    }
    let Some(read) = read else {
        return Ok(());
    };
    let offered = facts(read.root, &read.schema, &mut budget());
    if !Facts::kinds([Kind::String(None)]).accepts(&offered) {
        return Err(authored(
            "mapping.type",
            base,
            &format!(
                "expected a string naming a case; the reference reads {}",
                offered.describe()
            ),
            "Select a string member, or compute the label in a function.",
        ));
    }
    let Some(values) = offered.values else {
        return Ok(());
    };
    let labels = values
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if let Some(missing) = labels.iter().find(|label| !cases.contains_key(**label)) {
        return Err(authored(
            "mapping.cases",
            &format!("{field}.cases"),
            &format!("expected a case for every value the reference can read; there is no case for {missing}"),
            &format!("Add a case for {missing}."),
        ));
    }
    if let Some(extra) = cases.keys().find(|case| !labels.contains(case.as_str())) {
        return Err(authored(
            "mapping.cases",
            &format!("{field}.cases.{extra}"),
            &format!("expected only cases the reference can read; it never reads {extra}"),
            &format!("Remove the {extra} case."),
        ));
    }
    Ok(())
}

/// Validate a literal against its member's schema. The member is checked
/// with the target's definitions beside it; a member that refers elsewhere
/// in its target is left to scenarios and the runtime.
fn literal_violation(target: &Value, declared: &Value, value: &Value) -> Option<Violation> {
    let mut schema = declared.clone();
    if let Value::Object(object) = &mut schema {
        for definitions in ["$defs", "definitions"] {
            if let Some(shared) = target.get(definitions) {
                object.entry(definitions).or_insert_with(|| shared.clone());
            }
        }
    }
    if !references_definitions_only(&schema) {
        return None;
    }
    let validator = compile_schema(&schema).ok()?;
    first_violation(&validator, value).err()
}

fn references_definitions_only(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "$ref" {
                value.as_str().is_some_and(|reference| {
                    reference.starts_with("#/$defs/") || reference.starts_with("#/definitions/")
                })
            } else {
                references_definitions_only(value)
            }
        }),
        Value::Array(items) => items.iter().all(references_definitions_only),
        _ => true,
    }
}

/// What a schema says about one member of the values it accepts.
enum Reach {
    /// No accepted value has this member.
    Forbidden,
    /// The schema lists its members, and this is not one of them.
    Undeclared,
    /// The schema says nothing about members, so the member is open.
    Silent,
    /// The schema the member satisfies; `true` when it is declared open.
    Schema(Value),
}

fn reach(schema: &Value) -> Reach {
    match schema {
        Value::Bool(false) => Reach::Forbidden,
        schema => Reach::Schema(schema.clone()),
    }
}

/// Every part holds: a part that forbids the member forbids it, and a part
/// that declares it outweighs a part that lists other members.
fn all_of(parts: Vec<Reach>) -> Reach {
    let mut schemas = Vec::new();
    let mut undeclared = false;
    for part in parts {
        match part {
            Reach::Forbidden => return Reach::Forbidden,
            Reach::Undeclared => undeclared = true,
            Reach::Silent => {}
            Reach::Schema(schema) => schemas.push(schema),
        }
    }
    if !schemas.is_empty() {
        return Reach::Schema(combine("allOf", schemas));
    }
    if undeclared {
        Reach::Undeclared
    } else {
        Reach::Silent
    }
}

/// One part holds: a member any part declares is declared, and it is open
/// when another part says nothing about members.
fn any_of(parts: Vec<Reach>) -> Reach {
    let mut schemas = Vec::new();
    let (mut undeclared, mut silent) = (false, false);
    for part in parts {
        match part {
            Reach::Forbidden => {}
            Reach::Undeclared => undeclared = true,
            Reach::Silent => silent = true,
            Reach::Schema(schema) => schemas.push(schema),
        }
    }
    if !schemas.is_empty() {
        return Reach::Schema(if silent {
            Value::Bool(true)
        } else {
            combine("anyOf", schemas)
        });
    }
    if undeclared {
        Reach::Undeclared
    } else if silent {
        Reach::Silent
    } else {
        Reach::Forbidden
    }
}

fn combine(keyword: &str, schemas: Vec<Value>) -> Value {
    let mut schemas = schemas
        .into_iter()
        .filter(|schema| !(keyword == "allOf" && *schema == Value::Bool(true)))
        .collect::<Vec<_>>();
    if keyword == "anyOf" && schemas.contains(&Value::Bool(true)) {
        return Value::Bool(true);
    }
    match schemas.len() {
        0 => Value::Bool(true),
        1 => schemas.remove(0),
        _ => Value::Object(Map::from_iter([(
            keyword.to_owned(),
            Value::Array(schemas),
        )])),
    }
}

/// A local reference, or `None` when it leaves the document or names nothing.
fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    root.pointer(reference.strip_prefix('#')?)
}

/// What a schema says about the member a token names.
fn member(root: &Value, schema: &Value, token: &str, budget: &mut usize) -> Reach {
    if *budget == 0 {
        return Reach::Silent;
    }
    *budget -= 1;
    let object = match schema {
        Value::Object(object) => object,
        Value::Bool(false) => return Reach::Forbidden,
        _ => return Reach::Silent,
    };
    let mut parts = Vec::new();
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        parts.push(match resolve(root, reference) {
            Some(target) => member(root, target, token, budget),
            None => Reach::Schema(Value::Bool(true)),
        });
    }
    if object.contains_key("$dynamicRef") || object.contains_key("$recursiveRef") {
        parts.push(Reach::Schema(Value::Bool(true)));
    }
    if let Some(Value::Array(schemas)) = object.get("allOf") {
        let reached = schemas
            .iter()
            .map(|schema| member(root, schema, token, budget))
            .collect();
        parts.push(all_of(reached));
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(Value::Array(schemas)) = object.get(keyword) {
            let reached = schemas
                .iter()
                .map(|schema| member(root, schema, token, budget))
                .collect();
            parts.push(any_of(reached));
        }
    }
    parts.push(own_member(object, token));
    all_of(parts)
}

/// The member as this schema object's own keywords describe it.
fn own_member(object: &Map<String, Value>, token: &str) -> Reach {
    let types = declared_types(object);
    let allows = |kind: &str| {
        types
            .as_ref()
            .is_none_or(|types| types.iter().any(|declared| declared == kind))
    };
    let keywords = [
        "properties",
        "patternProperties",
        "additionalProperties",
        "items",
        "prefixItems",
        "maxItems",
    ];
    if types.is_none() && !keywords.iter().any(|keyword| object.contains_key(*keyword)) {
        return Reach::Silent;
    }
    let mut options = vec![Reach::Forbidden];
    if allows("object") {
        options.push(object_member(object, token));
    }
    if allows("array") {
        options.push(array_member(object, token));
    }
    any_of(options)
}

fn object_member(object: &Map<String, Value>, token: &str) -> Reach {
    if let Some(schema) = object
        .get("properties")
        .and_then(|properties| properties.get(token))
    {
        return reach(schema);
    }
    // Pattern names are not matched here, so a member a pattern may name
    // stays open.
    if object
        .get("patternProperties")
        .and_then(Value::as_object)
        .is_some_and(|patterns| !patterns.is_empty())
    {
        return Reach::Schema(Value::Bool(true));
    }
    match object.get("additionalProperties") {
        Some(schema) => reach(schema),
        None if object.contains_key("properties") => Reach::Undeclared,
        None => Reach::Silent,
    }
}

fn array_member(object: &Map<String, Value>, token: &str) -> Reach {
    let canonical = token == "0" || (!token.starts_with('0') && !token.is_empty());
    let Some(index) = token
        .parse::<usize>()
        .ok()
        .filter(|_| canonical && token.bytes().all(|byte| byte.is_ascii_digit()))
    else {
        return Reach::Forbidden;
    };
    if object
        .get("maxItems")
        .and_then(Value::as_u64)
        .is_some_and(|maximum| index as u64 >= maximum)
    {
        return Reach::Forbidden;
    }
    if let Some(schema) = object
        .get("prefixItems")
        .and_then(Value::as_array)
        .and_then(|prefix| prefix.get(index))
    {
        return reach(schema);
    }
    match object.get("items") {
        Some(schema) => reach(schema),
        None => Reach::Silent,
    }
}

fn declared_types(object: &Map<String, Value>) -> Option<Vec<String>> {
    match object.get("type")? {
        Value::String(kind) => Some(vec![kind.clone()]),
        Value::Array(kinds) => Some(
            kinds
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        ),
        _ => None,
    }
}

/// The members every value a schema accepts must hold: its own, its
/// reference's and every allOf part's, and those every alternative requires.
fn required(root: &Value, schema: &Value, budget: &mut usize) -> BTreeSet<String> {
    let mut members = BTreeSet::new();
    if *budget == 0 {
        return members;
    }
    *budget -= 1;
    let Value::Object(object) = schema else {
        return members;
    };
    if let Some(Value::Array(names)) = object.get("required") {
        members.extend(names.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    if let Some(target) = object
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| resolve(root, reference))
    {
        members.extend(required(root, target, budget));
    }
    if let Some(Value::Array(schemas)) = object.get("allOf") {
        for schema in schemas {
            members.extend(required(root, schema, budget));
        }
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(Value::Array(schemas)) = object.get(keyword) {
            let mut alternatives = schemas.iter().map(|schema| required(root, schema, budget));
            if let Some(first) = alternatives.next() {
                members.extend(alternatives.fold(first, |common, next| {
                    common.intersection(&next).cloned().collect()
                }));
            }
        }
    }
    members
}

/// A JSON type, with a string's declared format.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Object,
    Array,
    String(Option<String>),
    Integer,
    Number,
    Boolean,
    Null,
}

impl Kind {
    fn of(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(_) => Self::Boolean,
            Value::Number(number) if number.is_i64() || number.is_u64() => Self::Integer,
            Value::Number(number) if number.as_f64().is_some_and(|n| n.fract() == 0.0) => {
                Self::Integer
            }
            Value::Number(_) => Self::Number,
            Value::String(_) => Self::String(None),
            Value::Array(_) => Self::Array,
            Value::Object(_) => Self::Object,
        }
    }

    fn named(name: &str, format: Option<&str>) -> Option<Self> {
        Some(match name {
            "object" => Self::Object,
            "array" => Self::Array,
            "string" => Self::String(format.map(str::to_owned)),
            "integer" => Self::Integer,
            "number" => Self::Number,
            "boolean" => Self::Boolean,
            "null" => Self::Null,
            _ => return None,
        })
    }

    /// The kind both declarations admit, if any.
    fn meet(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::String(None), Self::String(format))
            | (Self::String(format), Self::String(None)) => Some(Self::String(format.clone())),
            (Self::Integer, Self::Number) | (Self::Number, Self::Integer) => Some(Self::Integer),
            (a, b) if a == b => Some(a.clone()),
            _ => None,
        }
    }

    /// Whether a value read as `offered` may satisfy `self`. A string
    /// without a format may hold any format, and an integer is a number.
    fn accepts(&self, offered: &Self) -> bool {
        match (self, offered) {
            (Self::String(wanted), Self::String(offered)) => {
                wanted.is_none() || offered.is_none() || wanted == offered
            }
            (Self::Integer | Self::Number, Self::Integer | Self::Number) => true,
            (a, b) => a == b,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Object => "an object".into(),
            Self::Array => "an array".into(),
            Self::String(None) => "a string".into(),
            Self::String(Some(format)) => {
                let article = if format.starts_with(['a', 'e', 'i', 'o']) {
                    "an"
                } else {
                    "a"
                };
                format!("{article} {format} string")
            }
            Self::Integer => "an integer".into(),
            Self::Number => "a number".into(),
            Self::Boolean => "a boolean".into(),
            Self::Null => "null".into(),
        }
    }
}

/// The kinds and, when the schema lists them, the values a schema admits.
/// `None` means the schema does not decide.
#[derive(Clone, Debug)]
struct Facts {
    kinds: Option<BTreeSet<Kind>>,
    values: Option<Vec<Value>>,
}

impl Facts {
    const ANY: Self = Self {
        kinds: None,
        values: None,
    };

    fn kinds(kinds: impl IntoIterator<Item = Kind>) -> Self {
        Self {
            kinds: Some(kinds.into_iter().collect()),
            values: None,
        }
    }

    fn allows(&self, kind: &Kind) -> bool {
        self.kinds
            .as_ref()
            .is_none_or(|kinds| kinds.is_empty() || kinds.iter().any(|own| own.accepts(kind)))
    }

    /// Whether some value the offered schema admits may satisfy this one.
    /// A schema that admits nothing is not decided here.
    fn accepts(&self, offered: &Self) -> bool {
        match (&self.kinds, &offered.kinds) {
            (Some(wanted), Some(offered)) if !wanted.is_empty() && !offered.is_empty() => wanted
                .iter()
                .any(|wanted| offered.iter().any(|offered| wanted.accepts(offered))),
            _ => true,
        }
    }

    fn both(self, other: Self) -> Self {
        let kinds = match (self.kinds, other.kinds) {
            (None, kinds) | (kinds, None) => kinds,
            (Some(a), Some(b)) => Some(
                a.iter()
                    .flat_map(|a| b.iter().filter_map(move |b| a.meet(b)))
                    .collect(),
            ),
        };
        let values = match (self.values, other.values) {
            (None, values) | (values, None) => values,
            (Some(a), Some(b)) => Some(a.into_iter().filter(|value| b.contains(value)).collect()),
        };
        Self { kinds, values }
    }

    fn either(self, other: Self) -> Self {
        let kinds = match (self.kinds, other.kinds) {
            (Some(mut a), Some(b)) => {
                a.extend(b);
                Some(a)
            }
            _ => None,
        };
        let values = match (self.values, other.values) {
            (Some(mut a), Some(b)) => {
                for value in b {
                    if !a.contains(&value) {
                        a.push(value);
                    }
                }
                Some(a)
            }
            _ => None,
        };
        Self { kinds, values }
    }

    fn describe(&self) -> String {
        match &self.kinds {
            None => "any value".into(),
            Some(kinds) if kinds.is_empty() => "no value".into(),
            Some(kinds) => kinds
                .iter()
                .map(Kind::describe)
                .collect::<Vec<_>>()
                .join(" or "),
        }
    }
}

/// What a schema decides about the values it admits.
fn facts(root: &Value, schema: &Value, budget: &mut usize) -> Facts {
    if *budget == 0 {
        return Facts::ANY;
    }
    *budget -= 1;
    let object = match schema {
        Value::Object(object) => object,
        Value::Bool(false) => {
            return Facts {
                kinds: Some(BTreeSet::new()),
                values: Some(Vec::new()),
            }
        }
        _ => return Facts::ANY,
    };
    let mut result = own_facts(object);
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        if let Some(target) = resolve(root, reference) {
            result = result.both(facts(root, target, budget));
        }
    }
    if let Some(Value::Array(schemas)) = object.get("allOf") {
        for schema in schemas {
            result = result.both(facts(root, schema, budget));
        }
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(Value::Array(schemas)) = object.get(keyword) {
            let mut alternatives = schemas.iter().map(|schema| facts(root, schema, budget));
            if let Some(first) = alternatives.next() {
                result = result.both(alternatives.fold(first, Facts::either));
            }
        }
    }
    result
}

fn own_facts(object: &Map<String, Value>) -> Facts {
    let format = object.get("format").and_then(Value::as_str);
    let values = match (object.get("enum"), object.get("const")) {
        (Some(Value::Array(values)), _) => Some(values.clone()),
        (_, Some(value)) => Some(vec![value.clone()]),
        _ => None,
    };
    let kinds = match declared_types(object) {
        Some(types) => Some(
            types
                .iter()
                .filter_map(|name| Kind::named(name, format))
                .collect(),
        ),
        None => values
            .as_ref()
            .map(|values| values.iter().map(Kind::of).collect()),
    };
    let values = values.or_else(|| {
        (kinds.as_ref() == Some(&BTreeSet::from([Kind::Null]))).then(|| vec![Value::Null])
    });
    Facts { kinds, values }
}
