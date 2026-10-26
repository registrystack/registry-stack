// SPDX-License-Identifier: Apache-2.0
//! Project-owned acceptance of specific advisory warnings.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    escape_pointer_segment, ApiVersion, Decoded, DisplayText, EnvelopeRule, Expect, FormatSpec,
    LocalId, Reader, Report, Severity,
};

pub const CHECK_ACCEPTANCES_FILE: &str = "check-acceptances.yaml";
pub const CHECK_ACCEPTANCES_API_VERSION: &str =
    "id.registrystack.org/formats/platform/check-acceptances/v1alpha1";
pub const CHECK_ACCEPTANCES_KIND: &str = "PlatformCheckAcceptances";
pub const CHECK_ACCEPTANCES_SCHEMA_ID: &str = "https://id.registrystack.org/schemas/platform/check-acceptances/check-acceptances.v1alpha1.schema.json";
pub const CHECK_ACCEPTANCES_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: CHECK_ACCEPTANCES_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(CHECK_ACCEPTANCES_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// A source file relative to the project and the resource path a check reports.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckScope {
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub file: String,
    /// A pointer whose list positions use existing unique identifiers when available.
    pub path: String,
}

/// One warning accepted for one exact scope, with the project's explanation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckAcceptance {
    #[cfg_attr(
        feature = "schema",
        schemars(regex(pattern = "^[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)+$"))
    )]
    pub code: String,
    pub scope: CheckScope,
    pub reason: DisplayText,
}

/// The optional project file shared by Registry Stack checking commands.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CheckAcceptances {
    pub acceptances: Vec<CheckAcceptance>,
}

/// The authored document's schema, including its shared reader envelope.
#[cfg(feature = "schema")]
pub fn check_acceptances_schema() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(CheckAcceptances))
        .expect("the acceptance schema is JSON");
    schema["$id"] = Value::String(CHECK_ACCEPTANCES_SCHEMA_ID.to_owned());
    schema["properties"]["apiVersion"] = serde_json::json!({
        "type": "string", "const": CHECK_ACCEPTANCES_API_VERSION
    });
    schema["properties"]["kind"] = serde_json::json!({
        "type": "string", "const": CHECK_ACCEPTANCES_KIND
    });
    schema["required"] = serde_json::json!(["apiVersion", "kind", "acceptances"]);
    schema["$defs"]["CheckAcceptance"]["properties"]["reason"] = serde_json::json!({
        "allOf": [{"$ref":"#/$defs/DisplayText"}, {"type":"string", "pattern":"\\S"}]
    });
    schema["$defs"]["CheckScope"]["properties"]["file"] = serde_json::json!({
        "type":"string", "minLength":1,
        "pattern":r"^[^/\\:\x00-\x1f\x7f-\x9f]+(/[^/\\:\x00-\x1f\x7f-\x9f]+)*$",
        "not":{"pattern":r"(^|/)\.{1,2}(/|$)"}
    });
    schema["$defs"]["CheckScope"]["properties"]["path"] = serde_json::json!({
        "type":"string", "pattern":r"^(?:/(?:[^~\x00-\x1f\x7f-\x9f]|~[01])*)?$"
    });
    schema
}

impl CheckAcceptances {
    /// Keep every finding and its severity. Only warnings may be accepted.
    /// Unmatched entries are harmless, including after a finding is fixed.
    pub fn apply(&self, report: &mut Report) {
        for diagnostic in report.diagnostics_mut() {
            if diagnostic.severity != Severity::Warning {
                continue;
            }
            if let Some(acceptance) = self.acceptances.iter().find(|acceptance| {
                acceptance.code == diagnostic.code
                    && diagnostic.scope.as_ref() == Some(&acceptance.scope)
            }) {
                diagnostic.accepted_reason = Some(acceptance.reason.as_str().to_owned());
            }
        }
    }
}

/// Read the shared closed format and validate its exact-match keys.
pub fn read_check_acceptances(
    file: &str,
    bytes: &[u8],
) -> Result<Decoded<CheckAcceptances>, Report> {
    let decoded = Reader::new(file)
        .decode::<CheckAcceptances>(bytes, &Expect::one(&CHECK_ACCEPTANCES_FORMAT))?;
    let mut diagnostics = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, acceptance) in decoded.value.acceptances.iter().enumerate() {
        let base = format!("/acceptances/{index}");
        let code_valid = acceptance.code.contains('.')
            && acceptance.code.split('.').all(|part| {
                part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                    && part.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            });
        let file_valid = !acceptance.scope.file.contains('\\')
            && !acceptance.scope.file.contains(':')
            && !acceptance.scope.file.chars().any(char::is_control)
            && acceptance
                .scope
                .file
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..");
        let path_valid = (acceptance.scope.path.is_empty()
            || acceptance.scope.path.starts_with('/'))
            && !acceptance.scope.path.chars().any(char::is_control)
            && acceptance.scope.path.match_indices('~').all(|(index, _)| {
                matches!(
                    acceptance.scope.path.as_bytes().get(index + 1),
                    Some(b'0' | b'1')
                )
            });
        for (valid, member, message, action) in [
            (
                code_valid,
                "code",
                "the check code must be dotted lowercase segments",
                "Copy the warning's code from its check report.",
            ),
            (
                file_valid,
                "scope/file",
                "the scope file must be a path inside the project",
                "Copy the warning's project-relative scope.file from its check report.",
            ),
            (
                path_valid,
                "scope/path",
                "the scope path must be empty or start with '/' and use valid pointer escapes",
                "Copy the warning's scope.path from its check report.",
            ),
            (
                !acceptance.reason.as_str().trim().is_empty(),
                "reason",
                "an accepted warning requires a nonblank reason",
                "Explain why the project accepts this warning.",
            ),
        ] {
            if !valid {
                diagnostics.push(decoded.document.diagnostic_at_value(
                    Severity::Error,
                    "config.check-acceptance-invalid",
                    &format!("{base}/{member}"),
                    message,
                    action,
                ));
            }
        }
        if !seen.insert((&acceptance.code, &acceptance.scope)) {
            diagnostics.push(decoded.document.diagnostic_at_value(
                Severity::Error,
                "config.check-acceptance-duplicate",
                &base,
                "a check code and scope may have only one acceptance",
                "Keep one entry for this warning and scope, with its reason.",
            ));
        }
    }
    if diagnostics.is_empty() {
        Ok(decoded)
    } else {
        Err(decoded.document.report_with(diagnostics))
    }
}

/// Address resource lists by their existing identifiers, without inspecting
/// behavior or recording a configuration fingerprint. Other positions stay numeric.
pub fn check_scope_path(document: &Value, pointer: &str) -> String {
    let Some(tail) = pointer.strip_prefix('/') else {
        return pointer.to_owned();
    };
    let mut node = Some(document);
    let mut scope = String::new();
    for encoded in tail.split('/') {
        let segment = encoded.replace("~1", "/").replace("~0", "~");
        let mut selector = None;
        node = match node {
            Some(Value::Array(items)) => {
                let item = segment
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| items.get(index));
                if let Some(item) = item {
                    for key in ["id", "action", "recordType"] {
                        if let Some(id) = item.get(key).and_then(Value::as_str) {
                            if LocalId::new(id).is_ok()
                                && items
                                    .iter()
                                    .filter(|item| {
                                        item.get(key).and_then(Value::as_str) == Some(id)
                                    })
                                    .count()
                                    == 1
                            {
                                selector = Some(format!("@{key}={id}"));
                                break;
                            }
                        }
                    }
                }
                item
            }
            Some(Value::Object(object)) => object.get(&segment),
            _ => None,
        };
        scope.push('/');
        scope.push_str(&escape_pointer_segment(
            selector.as_deref().unwrap_or(&segment),
        ));
    }
    scope
}
