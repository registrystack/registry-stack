// SPDX-License-Identifier: Apache-2.0
use anyhow::Result;
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, path::Path};
fn name(id: &str) -> String {
    id.split(['-', '_', ':', '.'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            format!(
                "{}{}",
                chars.next().unwrap().to_ascii_uppercase(),
                chars.as_str()
            )
        })
        .collect()
}
fn ts(schema: &Value, depth: usize) -> Result<String> {
    if depth > 16 {
        return Err(crate::project::ProjectRefusal::ContextSchemaTooDeep.into());
    }
    if let Some(values) = schema["enum"].as_array() {
        return Ok(values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(" | "));
    }
    if let Some(value) = schema.get("const") {
        return Ok(value.to_string());
    }
    if let Some(types) = schema["type"].as_array() {
        return types
            .iter()
            .map(|kind| {
                let mut child = schema.clone();
                child["type"] = kind.clone();
                ts(&child, depth + 1)
            })
            .collect::<Result<Vec<_>>>()
            .map(|v| v.join(" | "));
    }
    Ok(match schema["type"].as_str() {
        Some("string") => "string".into(),
        Some("integer" | "number") => "number".into(),
        Some("boolean") => "boolean".into(),
        Some("null") => "null".into(),
        Some("array") => format!("ReadonlyArray<{}>", ts(&schema["items"], depth + 1)?),
        Some("object") => {
            let required = schema["required"]
                .as_array()
                .map(|v| v.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>())
                .unwrap_or_default();
            let fields = schema["properties"]
                .as_object()
                .map(|p| {
                    p.iter()
                        .map(|(key, value)| {
                            Ok(format!(
                                "readonly {}{}: {}",
                                serde_json::to_string(key)?,
                                if required.contains(key.as_str()) {
                                    ""
                                } else {
                                    "?"
                                },
                                ts(value, depth + 1)?
                            ))
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();
            format!("{{ {} }}", fields.join("; "))
        }
        _ => "unknown".into(),
    })
}
fn py(schema: &Value, depth: usize) -> Result<String> {
    if depth > 16 {
        return Err(crate::project::ProjectRefusal::ContextSchemaTooDeep.into());
    }
    if let Some(values) = schema["enum"].as_array() {
        return Ok(format!(
            "Literal[{}]",
            values
                .iter()
                .map(python_literal)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(match schema["type"].as_str() {
        Some("string") => "str".into(),
        Some("integer") => "int".into(),
        Some("number") => "float".into(),
        Some("boolean") => "bool".into(),
        Some("null") => "None".into(),
        Some("array") => format!("list[{}]", py(&schema["items"], depth + 1)?),
        Some("object") => "dict[str, object]".into(),
        _ => "object".into(),
    })
}
fn python_literal(value: &Value) -> String {
    match value {
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(python_literal)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!(
                    "{}: {}",
                    serde_json::to_string(key).unwrap(),
                    python_literal(value)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => value.to_string(),
    }
}
pub(super) fn generate(project: &Path, output: &Path) -> Result<Value> {
    crate::project::check(project, false, false)?;
    let project = crate::project::load_and_check_policy(project)?;
    let mut typescript=String::from("// Generated from the compiled ReviewPolicy closure.\nimport type { casework } from '@registrystack/client';\n");
    let mut python=String::from("# Generated from the compiled ReviewPolicy closure.\nfrom __future__ import annotations\nfrom typing import Literal, TypedDict, NotRequired\nfrom registry_client.casework import PolicyBinding, SubjectBinding, ReviewCreateRequest, ReviewTask, ReviewResult\n\n");
    let mut schemas = serde_json::Map::new();
    for policy in &project.review_policies {
        let closure = policy.compile(&project)?;
        let policy_name = name(&policy.id);
        let binding = json!({"id":closure.identity.id,"version":closure.identity.version,"digest":closure.identity.digest});
        typescript.push_str(&format!("export const {policy_name}Policy = {} as const satisfies casework.PolicyBinding;\nexport type {policy_name}Context = {};\nexport type {policy_name}Request = Omit<casework.ReviewCreateRequest, 'policy' | 'context'> & {{readonly policy: casework.PolicySelection & {{readonly id: typeof {policy_name}Policy.id}}; readonly context: {{readonly mode: 'submitted'; readonly snapshot: {policy_name}Context}} | {{readonly mode: 'current-source'; readonly binding: {{readonly reference: string}}}} }};\nexport type {policy_name}Task = casework.ReviewTask;\nexport type {policy_name}Result = casework.ReviewResult;\n",binding,ts(&policy.display_schema,0)?));
        python.push_str(&format!(
            "{policy_name}Policy = {}\n{policy_name}Context = TypedDict({:?}, {{",
            python_literal(&binding),
            format!("{policy_name}Context")
        ));
        let required = policy.display_schema["required"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let mut fields = Vec::new();
        if let Some(properties) = policy.display_schema["properties"].as_object() {
            for (field, schema) in properties {
                let value = py(schema, 0)?;
                fields.push(format!(
                    "{}: {}",
                    serde_json::to_string(field)?,
                    if required.contains(field.as_str()) {
                        value
                    } else {
                        format!("NotRequired[{value}]")
                    }
                ));
            }
        }
        python.push_str(&fields.join(", "));
        python.push_str("})\n\n");
        schemas.insert(policy.id.clone(), policy.display_schema.clone());
    }
    fs::create_dir_all(output)?;
    fs::write(output.join("casework.ts"), typescript)?;
    fs::write(output.join("casework.py"), python)?;
    fs::write(
        output.join("contexts.schema.json"),
        serde_json::to_vec_pretty(&schemas)?,
    )?;
    Ok(
        json!({"ok":true,"command":"types","output":output,"files":["casework.ts","casework.py","contexts.schema.json"]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn too_deep() -> Value {
        let mut schema = json!({"type":"string"});
        for _ in 0..18 {
            schema = json!({"type":"array","items":schema});
        }
        schema
    }

    #[test]
    fn bounded_type_generation_is_a_typed_authoring_refusal() {
        for error in [
            ts(&too_deep(), 0).unwrap_err(),
            py(&too_deep(), 0).unwrap_err(),
        ] {
            let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Authoring, &error);
            assert_eq!(exit, crate::DOMAIN_REFUSAL_EXIT);
            assert_eq!(diagnostic["code"], "caseworkctl.refused");
            assert!(!diagnostic.to_string().contains("nesting"));
        }
    }
}
