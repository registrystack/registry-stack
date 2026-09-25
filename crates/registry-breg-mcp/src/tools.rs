// SPDX-License-Identifier: Apache-2.0

//! Tool names, input schemas, and argument parsing.
//!
//! Every argument is parsed here, before any registry call. The application's
//! target and owner fields are absent from every input schema and refused by
//! every parser: the gateway resolves the citizen's own record and names it
//! itself, so a chat host can never choose what an application points at.

use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::contract::Contract;

pub(crate) const DESCRIBE_SERVICE: &str = "describe_service";
pub(crate) const GET_MY_DETAILS: &str = "get_my_details";
pub(crate) const START_APPLICATION: &str = "start_application";
pub(crate) const UPDATE_APPLICATION: &str = "update_application";
pub(crate) const PREPARE_REVIEW: &str = "prepare_review";
pub(crate) const GET_APPLICATION_STATUS: &str = "get_application_status";

pub(crate) const TOOL_NAMES: [&str; 6] = [
    DESCRIBE_SERVICE,
    GET_MY_DETAILS,
    START_APPLICATION,
    UPDATE_APPLICATION,
    PREPARE_REVIEW,
    GET_APPLICATION_STATUS,
];

/// The most edits one `update_application` call may carry. The registry's own
/// patch limit is higher; the gateway reserves one operation for the target
/// precondition it adds itself.
pub(crate) const MAXIMUM_EDITS: usize = 64;

/// A value-free reason an argument set was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ArgumentError {
    #[error("the tool accepts no argument by that name")]
    UnknownArgument,
    #[error("a required argument is missing")]
    MissingArgument,
    #[error("an argument has the wrong type")]
    WrongType,
    #[error("the application identifier is not a UUID")]
    InvalidApplicationIdentifier,
    #[error("an edit names a field the citizen may not change")]
    FieldNotEditable,
    #[error("an edit uses an operation the tool does not offer")]
    UnsupportedEdit,
    #[error("an update carries no edit or too many edits")]
    EditCount,
}

/// One citizen edit to an application draft, by field API name.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Edit {
    Add(String, Value),
    Replace(String, Value),
    Remove(String),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct UpdateArguments {
    pub(crate) application: Uuid,
    pub(crate) expected_revision: String,
    pub(crate) edits: Vec<Edit>,
}

/// Input schema for tools that take no argument.
pub(crate) fn empty_input_schema() -> Map<String, Value> {
    object_schema(Map::new(), &[])
}

/// Input schema for tools that name one application.
pub(crate) fn application_input_schema() -> Map<String, Value> {
    let mut properties = Map::new();
    properties.insert("applicationId".to_owned(), application_id_schema());
    object_schema(properties, &["applicationId"])
}

/// Input schema for `start_application`: the editable fields only.
pub(crate) fn start_input_schema(contract: &Contract) -> Map<String, Value> {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &contract.editable {
        let mut schema = field.schema.as_object().cloned().unwrap_or_default();
        schema.insert("title".to_owned(), Value::String(field.label.clone()));
        properties.insert(field.api_name.clone(), Value::Object(schema));
        if field.required {
            required.push(field.api_name.as_str());
        }
    }
    object_schema(properties, &required)
}

/// Input schema for `update_application`: edits whose paths are the editable
/// fields only.
pub(crate) fn update_input_schema(contract: &Contract) -> Map<String, Value> {
    let paths: Vec<Value> = contract
        .patch_editable
        .iter()
        .map(|api_name| Value::String(format!("/{api_name}")))
        .collect();
    let mut properties = Map::new();
    properties.insert("applicationId".to_owned(), application_id_schema());
    properties.insert(
        "expectedRevision".to_owned(),
        json!({"type": "string", "minLength": 1, "maxLength": 64}),
    );
    properties.insert(
        "patch".to_owned(),
        json!({
            "type": "array",
            "minItems": 1,
            "maxItems": MAXIMUM_EDITS,
            "items": {
                "type": "object",
                "properties": {
                    "op": {"type": "string", "enum": ["add", "replace", "remove"]},
                    "path": {"type": "string", "enum": paths},
                    "value": {}
                },
                "required": ["op", "path"],
                "additionalProperties": false
            }
        }),
    );
    object_schema(properties, &["applicationId", "expectedRevision", "patch"])
}

fn application_id_schema() -> Value {
    json!({"type": "string", "format": "uuid"})
}

fn object_schema(properties: Map<String, Value>, required: &[&str]) -> Map<String, Value> {
    let mut schema = Map::new();
    schema.insert("type".to_owned(), Value::String("object".to_owned()));
    schema.insert("properties".to_owned(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_owned(), json!(required));
    }
    schema.insert("additionalProperties".to_owned(), Value::Bool(false));
    schema
}

/// Refuse, before any registry call, an argument or edit that names a field
/// the gateway writes itself. The full parse against the published contract
/// follows; this screen needs only the operator-configured field names, so a
/// smuggled target never reaches the registry, not even as a metadata read.
pub(crate) fn screen_controlled(
    tool: &str,
    arguments: Option<&Map<String, Value>>,
    controlled: [&str; 2],
) -> Result<(), ArgumentError> {
    let Some(arguments) = arguments else {
        return Ok(());
    };
    let names_controlled = |path: &Value| {
        path.as_str()
            .is_some_and(|path| path.split('/').any(|segment| controlled.contains(&segment)))
    };
    match tool {
        START_APPLICATION
            if arguments
                .keys()
                .any(|key| controlled.contains(&key.as_str())) =>
        {
            Err(ArgumentError::FieldNotEditable)
        }
        UPDATE_APPLICATION => {
            let edits = arguments.get("patch").and_then(Value::as_array);
            let smuggled = edits.into_iter().flatten().any(|edit| {
                ["path", "from"]
                    .iter()
                    .any(|member| edit.get(*member).is_some_and(names_controlled))
            });
            if smuggled {
                Err(ArgumentError::FieldNotEditable)
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

/// Refuse any argument to a tool that takes none.
pub(crate) fn parse_no_arguments(
    arguments: Option<&Map<String, Value>>,
) -> Result<(), ArgumentError> {
    match arguments {
        Some(arguments) if !arguments.is_empty() => Err(ArgumentError::UnknownArgument),
        _ => Ok(()),
    }
}

/// Parse the one application identifier a tool takes.
pub(crate) fn parse_application(
    arguments: Option<&Map<String, Value>>,
) -> Result<Uuid, ArgumentError> {
    let arguments = arguments.ok_or(ArgumentError::MissingArgument)?;
    only_keys(arguments, &["applicationId"])?;
    application_identifier(arguments)
}

/// Parse `start_application`: every key must be an editable field.
pub(crate) fn parse_start(
    arguments: Option<&Map<String, Value>>,
    contract: &Contract,
) -> Result<Map<String, Value>, ArgumentError> {
    let arguments = arguments.cloned().unwrap_or_default();
    for key in arguments.keys() {
        if !contract.editable.iter().any(|field| &field.api_name == key) {
            return Err(ArgumentError::UnknownArgument);
        }
    }
    Ok(arguments)
}

/// Parse `update_application`: every edit path must be exactly one editable
/// field, and only add, replace, and remove are offered.
pub(crate) fn parse_update(
    arguments: Option<&Map<String, Value>>,
    contract: &Contract,
) -> Result<UpdateArguments, ArgumentError> {
    let arguments = arguments.ok_or(ArgumentError::MissingArgument)?;
    only_keys(arguments, &["applicationId", "expectedRevision", "patch"])?;
    let application = application_identifier(arguments)?;
    let expected_revision = match arguments.get("expectedRevision") {
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 64 => value.clone(),
        Some(_) => return Err(ArgumentError::WrongType),
        None => return Err(ArgumentError::MissingArgument),
    };
    let patch = match arguments.get("patch") {
        Some(Value::Array(patch)) => patch,
        Some(_) => return Err(ArgumentError::WrongType),
        None => return Err(ArgumentError::MissingArgument),
    };
    if patch.is_empty() || patch.len() > MAXIMUM_EDITS {
        return Err(ArgumentError::EditCount);
    }
    let edits = patch
        .iter()
        .map(|edit| parse_edit(edit, contract))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UpdateArguments {
        application,
        expected_revision,
        edits,
    })
}

fn parse_edit(edit: &Value, contract: &Contract) -> Result<Edit, ArgumentError> {
    let edit = edit.as_object().ok_or(ArgumentError::WrongType)?;
    only_keys(edit, &["op", "path", "value"])?;
    let path = match edit.get("path") {
        Some(Value::String(path)) => path,
        Some(_) => return Err(ArgumentError::WrongType),
        None => return Err(ArgumentError::MissingArgument),
    };
    let field = path
        .strip_prefix('/')
        .filter(|field| contract.patch_editable.contains(*field))
        .ok_or(ArgumentError::FieldNotEditable)?
        .to_owned();
    let value = edit.get("value").cloned();
    match (edit.get("op").and_then(Value::as_str), value) {
        (Some("add"), Some(value)) => Ok(Edit::Add(field, value)),
        (Some("replace"), Some(value)) => Ok(Edit::Replace(field, value)),
        (Some("remove"), None) => Ok(Edit::Remove(field)),
        (Some("add" | "replace"), None) => Err(ArgumentError::MissingArgument),
        (Some("remove"), Some(_)) => Err(ArgumentError::UnknownArgument),
        (Some(_), _) => Err(ArgumentError::UnsupportedEdit),
        (None, _) => Err(ArgumentError::MissingArgument),
    }
}

fn application_identifier(arguments: &Map<String, Value>) -> Result<Uuid, ArgumentError> {
    match arguments.get("applicationId") {
        Some(Value::String(value)) => {
            Uuid::parse_str(value).map_err(|_| ArgumentError::InvalidApplicationIdentifier)
        }
        Some(_) => Err(ArgumentError::WrongType),
        None => Err(ArgumentError::MissingArgument),
    }
}

fn only_keys(arguments: &Map<String, Value>, allowed: &[&str]) -> Result<(), ArgumentError> {
    if arguments.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(ArgumentError::UnknownArgument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::tests::fixture_contract;

    const OTHER_ADDRESS: &str = "0f0e0d0c-0b0a-4908-8706-050403020100";
    const APPLICATION: &str = "25e4ef6d-80bd-4e88-8e83-59b17cd26a4f";

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().expect("object").clone()
    }

    fn property_names(schema: &Map<String, Value>) -> Vec<String> {
        schema["properties"]
            .as_object()
            .expect("properties")
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn the_start_schema_never_exposes_the_target_or_owner() {
        let schema = start_input_schema(&fixture_contract());
        assert_eq!(
            property_names(&schema),
            ["newAddressLine", "newLocality", "newPostalCode"]
        );
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        assert_eq!(schema["properties"]["newAddressLine"]["maxLength"], 200);
        assert_eq!(
            schema["properties"]["newAddressLine"]["title"],
            "New address line"
        );
    }

    #[test]
    fn the_update_schema_offers_only_editable_paths() {
        let schema = update_input_schema(&fixture_contract());
        let paths = &schema["properties"]["patch"]["items"]["properties"]["path"]["enum"];
        assert_eq!(
            paths,
            &json!(["/newAddressLine", "/newLocality", "/newPostalCode"])
        );
        assert_eq!(
            schema["properties"]["patch"]["items"]["properties"]["op"]["enum"],
            json!(["add", "replace", "remove"])
        );
    }

    #[test]
    fn a_smuggled_target_argument_is_refused_before_any_call() {
        let contract = fixture_contract();
        for key in ["address", "owner", "recordIdentifier"] {
            let arguments = object(json!({
                "newAddressLine": "2 Quay",
                "newLocality": "Port Selene",
                "newPostalCode": "PS-200",
                key: OTHER_ADDRESS,
            }));
            assert_eq!(
                parse_start(Some(&arguments), &contract),
                Err(ArgumentError::UnknownArgument),
                "{key}"
            );
        }
    }

    #[test]
    fn start_accepts_the_editable_fields() {
        let arguments = object(json!({
            "newAddressLine": "2 Quay",
            "newLocality": "Port Selene",
            "newPostalCode": "PS-200",
        }));
        assert_eq!(
            parse_start(Some(&arguments), &fixture_contract()),
            Ok(arguments.clone())
        );
    }

    #[test]
    fn a_patch_path_aimed_at_the_target_or_owner_is_refused() {
        let contract = fixture_contract();
        for path in [
            "/address",
            "/data/address",
            "/owner",
            "/data/owner",
            "/newLocality/0",
            "/newLocality/",
            "newLocality",
            "",
            "/",
            "/data/newLocality",
        ] {
            let arguments = object(json!({
                "applicationId": APPLICATION,
                "expectedRevision": "1",
                "patch": [{"op": "replace", "path": path, "value": OTHER_ADDRESS}],
            }));
            assert_eq!(
                parse_update(Some(&arguments), &contract),
                Err(ArgumentError::FieldNotEditable),
                "{path}"
            );
        }
    }

    #[test]
    fn a_controlled_field_is_refused_before_the_contract_is_known() {
        let controlled = ["address", "owner"];
        for (tool, arguments) in [
            (
                START_APPLICATION,
                json!({"newLocality": "x", "address": OTHER_ADDRESS}),
            ),
            (START_APPLICATION, json!({"owner": "synthetic-citizen-b"})),
            (
                UPDATE_APPLICATION,
                json!({"applicationId": APPLICATION, "expectedRevision": "1",
                    "patch": [{"op": "replace", "path": "/address", "value": OTHER_ADDRESS}]}),
            ),
            (
                UPDATE_APPLICATION,
                json!({"applicationId": APPLICATION, "expectedRevision": "1",
                    "patch": [{"op": "replace", "path": "/data/address", "value": OTHER_ADDRESS}]}),
            ),
            (
                UPDATE_APPLICATION,
                json!({"applicationId": APPLICATION, "expectedRevision": "1",
                    "patch": [{"op": "move", "from": "/newLocality", "path": "/owner"}]}),
            ),
        ] {
            assert_eq!(
                screen_controlled(tool, Some(&object(arguments.clone())), controlled),
                Err(ArgumentError::FieldNotEditable),
                "{arguments}"
            );
        }
        let ordinary = object(
            json!({"applicationId": APPLICATION, "expectedRevision": "1",
            "patch": [{"op": "replace", "path": "/newLocality", "value": "address"}]}),
        );
        assert_eq!(
            screen_controlled(UPDATE_APPLICATION, Some(&ordinary), controlled),
            Ok(())
        );
        assert_eq!(
            screen_controlled(
                GET_MY_DETAILS,
                Some(&object(json!({"address": 1}))),
                controlled
            ),
            Ok(())
        );
    }

    #[test]
    fn a_test_or_move_edit_is_refused() {
        let contract = fixture_contract();
        for op in ["test", "move", "copy"] {
            let arguments = object(json!({
                "applicationId": APPLICATION,
                "expectedRevision": "1",
                "patch": [{"op": op, "path": "/newLocality", "value": "x"}],
            }));
            assert_eq!(
                parse_update(Some(&arguments), &contract),
                Err(ArgumentError::UnsupportedEdit),
                "{op}"
            );
        }
        let with_from = object(json!({
            "applicationId": APPLICATION,
            "expectedRevision": "1",
            "patch": [{"op": "move", "from": "/address", "path": "/newLocality"}],
        }));
        assert_eq!(
            parse_update(Some(&with_from), &contract),
            Err(ArgumentError::UnknownArgument)
        );
    }

    #[test]
    fn an_update_parses_its_edits() {
        let arguments = object(json!({
            "applicationId": APPLICATION,
            "expectedRevision": "1",
            "patch": [
                {"op": "replace", "path": "/newLocality", "value": "Old Town"},
                {"op": "add", "path": "/newPostalCode", "value": "PS-300"},
                {"op": "remove", "path": "/newAddressLine"},
            ],
        }));
        assert_eq!(
            parse_update(Some(&arguments), &fixture_contract()),
            Ok(UpdateArguments {
                application: Uuid::parse_str(APPLICATION).unwrap(),
                expected_revision: "1".to_owned(),
                edits: vec![
                    Edit::Replace("newLocality".to_owned(), json!("Old Town")),
                    Edit::Add("newPostalCode".to_owned(), json!("PS-300")),
                    Edit::Remove("newAddressLine".to_owned()),
                ],
            })
        );
    }

    #[test]
    fn an_update_with_no_edit_or_an_extra_argument_is_refused() {
        let contract = fixture_contract();
        let empty =
            object(json!({"applicationId": APPLICATION, "expectedRevision": "1", "patch": []}));
        assert_eq!(
            parse_update(Some(&empty), &contract),
            Err(ArgumentError::EditCount)
        );
        let extra = object(json!({
            "applicationId": APPLICATION,
            "expectedRevision": "1",
            "patch": [{"op": "replace", "path": "/newLocality", "value": "x"}],
            "address": OTHER_ADDRESS,
        }));
        assert_eq!(
            parse_update(Some(&extra), &contract),
            Err(ArgumentError::UnknownArgument)
        );
    }

    #[test]
    fn application_arguments_are_strict() {
        let good = object(json!({"applicationId": APPLICATION}));
        assert_eq!(
            parse_application(Some(&good)),
            Ok(Uuid::parse_str(APPLICATION).unwrap())
        );
        let bad = object(json!({"applicationId": "not-a-uuid"}));
        assert_eq!(
            parse_application(Some(&bad)),
            Err(ArgumentError::InvalidApplicationIdentifier)
        );
        let extra = object(json!({"applicationId": APPLICATION, "address": OTHER_ADDRESS}));
        assert_eq!(
            parse_application(Some(&extra)),
            Err(ArgumentError::UnknownArgument)
        );
        assert_eq!(parse_application(None), Err(ArgumentError::MissingArgument));
    }

    #[test]
    fn a_tool_without_arguments_refuses_any() {
        assert_eq!(parse_no_arguments(None), Ok(()));
        assert_eq!(parse_no_arguments(Some(&Map::new())), Ok(()));
        let smuggled = object(json!({"subject": "synthetic-citizen-b"}));
        assert_eq!(
            parse_no_arguments(Some(&smuggled)),
            Err(ArgumentError::UnknownArgument)
        );
    }
}
