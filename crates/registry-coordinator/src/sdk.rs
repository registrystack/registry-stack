// SPDX-License-Identifier: Apache-2.0
//! Typed, revision-pinned wrappers over the maintained Coordinator clients.
use crate::{definition::Definition, CoordinatorError, Result};
use serde_json::Value;

#[derive(Clone, Copy)]
pub enum Language {
    Typescript,
    Python,
}

pub fn generate(definition: &Definition, language: Language) -> Result<String> {
    let workflow = serde_json::to_string(&definition.workflow.id).map_err(|_| refused())?;
    let revision = serde_json::to_string(&definition.digest).map_err(|_| refused())?;
    let mut renderer = Renderer {
        language,
        declarations: Vec::new(),
        serial: 0,
    };
    let input = renderer.render(
        &definition.workflow.input,
        &definition.workflow.input,
        "Input",
        0,
    )?;
    let mut outcomes = Vec::new();
    for (name, schema) in &definition.workflow.outcomes {
        let output = renderer.render(schema, schema, "Output", 0)?;
        let name = serde_json::to_string(name).map_err(|_| refused())?;
        outcomes.push(match language {
            Language::Typescript => format!("{{ outcome: {name}; output: {output} | null }}"),
            Language::Python => {
                let alias = renderer.name("Outcome");
                let output = if output == "None" { output } else { format!("{output} | None") };
                renderer.declarations.push(format!("{alias} = TypedDict({alias:?}, {{\"outcome\": Literal[{name}], \"output\": {output}}})"));
                alias
            }
        });
    }
    let outcome = outcomes.join(" | ");
    let declarations = renderer.declarations.join("\n\n");
    Ok(match language {
        Language::Typescript => format!(
            r#"// Generated from the compiled Coordinator workflow. Regenerate with coordinatorctl types.
import type * as coordinator from '@registrystack/coordinator-client-native';
export const workflow = {workflow} as const;
export const workflowRevision = {revision} as const;
{declarations}
export type Input = {input};
export type Outcome = {outcome};
export interface Run {{ status: coordinator.RunStatus; result: Outcome | null }}
function checked(status: coordinator.RunStatus): Run {{
  if (status.workflow !== workflow || status.workflowRevision !== workflowRevision) throw new Error('Workflow contract mismatch');
  const names: readonly string[] = [{names}];
  if (status.outcome != null && !names.includes(status.outcome)) throw new Error('Workflow outcome mismatch');
  return {{ status, result: status.outcome == null ? null : {{ outcome: status.outcome, output: status.output ?? null }} as Outcome }};
}}
export class WorkflowClient {{
  constructor(private readonly client: coordinator.CoordinatorClient) {{}}
  async start(token: string, idempotencyKey: string, input: Input): Promise<Run> {{
    const answer = await this.client.start(token, idempotencyKey, {{ workflow, workflowRevision, input: input as coordinator.JsonValue }});
    return checked(answer.value);
  }}
  async get(token: string, runId: coordinator.RunId): Promise<Run> {{
    return checked((await this.client.status(token, runId)).value);
  }}
  async cancel(token: string, run: Run, reason: string): Promise<Run> {{
    checked(run.status);
    return checked((await this.client.cancel(token, run.status.runId, reason)).value);
  }}
}}
"#,
            names = definition
                .workflow
                .outcomes
                .keys()
                .map(|n| serde_json::to_string(n).expect("string"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Language::Python => format!(
            r#"# Generated from the compiled Coordinator workflow. Regenerate with coordinatorctl types.
from __future__ import annotations
from typing import Any, Literal, Never, NotRequired, Required, TYPE_CHECKING, TypedDict, TypeAlias, cast
if TYPE_CHECKING:
    from registry_coordinator_client import CoordinatorClient, RunStatus, StartRunRequest
WORKFLOW = {workflow}
WORKFLOW_REVISION = {revision}
{declarations}
Input: TypeAlias = {input}
Outcome: TypeAlias = {outcome}
class Run(TypedDict):
    status: RunStatus
    result: Outcome | None

def _checked(status: RunStatus) -> Run:
    if status["workflow"] != WORKFLOW or status["workflowRevision"] != WORKFLOW_REVISION:
        raise ValueError("Workflow contract mismatch")
    if status.get("outcome") is not None and status["outcome"] not in ({names},):
        raise ValueError("Workflow outcome mismatch")
    result = None if status.get("outcome") is None else cast(Outcome, {{"outcome": status["outcome"], "output": status.get("output")}})
    return {{"status": status, "result": result}}

class WorkflowClient:
    def __init__(self, client: CoordinatorClient) -> None:
        self.client = client

    def start(self, token: str, idempotency_key: str, input: Input) -> Run:
        return _checked(self.client.start(token, idempotency_key, cast("StartRunRequest", {{"workflow": WORKFLOW, "workflowRevision": WORKFLOW_REVISION, "input": input}}))["value"])

    def get(self, token: str, run_id: str) -> Run:
        return _checked(self.client.status(token, run_id)["value"])

    def cancel(self, token: str, run: Run, reason: str) -> Run:
        _checked(run["status"])
        return _checked(self.client.cancel(token, run["status"]["runId"], reason)["value"])
"#,
            names = definition
                .workflow
                .outcomes
                .keys()
                .map(|n| serde_json::to_string(n).expect("string"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

struct Renderer {
    language: Language,
    declarations: Vec<String>,
    serial: usize,
}
impl Renderer {
    fn name(&mut self, hint: &str) -> String {
        self.serial += 1;
        format!("{hint}{}", self.serial)
    }
    fn render(&mut self, schema: &Value, root: &Value, hint: &str, depth: usize) -> Result<String> {
        if depth > 64 {
            return Err(refused());
        }
        if schema == &Value::Bool(false) {
            return Ok(match self.language {
                Language::Typescript => "never",
                Language::Python => "Never",
            }
            .into());
        }
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let pointer = reference.strip_prefix('#').ok_or_else(refused)?;
            return self.render(
                root.pointer(pointer).ok_or_else(refused)?,
                root,
                hint,
                depth + 1,
            );
        }
        for union in ["oneOf", "anyOf"] {
            if let Some(variants) = schema.get(union).and_then(Value::as_array) {
                return variants
                    .iter()
                    .map(|variant| self.render(variant, root, hint, depth + 1))
                    .collect::<Result<Vec<_>>>()
                    .map(join_union);
            }
        }
        if let Some(variants) = schema.get("allOf").and_then(Value::as_array) {
            if matches!(self.language, Language::Typescript) {
                return variants
                    .iter()
                    .map(|variant| self.render(variant, root, hint, depth + 1))
                    .collect::<Result<Vec<_>>>()
                    .map(|types| {
                        types
                            .into_iter()
                            .map(|ty| format!("({ty})"))
                            .collect::<Vec<_>>()
                            .join(" & ")
                    });
            }
            return Err(CoordinatorError::new(
                "workflow.types-refused",
                "Python TypedDict cannot represent this schema intersection",
            ).suggest("Use a schema without allOf for Python export, or export TypeScript for the intersection."));
        }
        let values = schema
            .get("enum")
            .and_then(Value::as_array)
            .cloned()
            .or_else(|| schema.get("const").map(|value| vec![value.clone()]));
        if let Some(values) = values {
            if values.iter().all(|value| {
                value.is_string()
                    || value.is_boolean()
                    || value.is_null()
                    || value.is_i64()
                    || value.is_u64()
            }) {
                return Ok(match self.language {
                    Language::Typescript => values
                        .iter()
                        .map(Value::to_string)
                        .collect::<Vec<_>>()
                        .join(" | "),
                    Language::Python => {
                        let values = values
                            .iter()
                            .map(|value| match value {
                                Value::Bool(true) => "True".into(),
                                Value::Bool(false) => "False".into(),
                                Value::Null => "None".into(),
                                _ => value.to_string(),
                            })
                            .collect::<Vec<_>>();
                        format!("Literal[{}]", values.join(", "))
                    }
                });
            }
        }
        if let Some(types) = schema.get("type").and_then(Value::as_array) {
            return types
                .iter()
                .map(|kind| {
                    let mut variant = schema.clone();
                    variant["type"] = kind.clone();
                    self.render(&variant, root, hint, depth + 1)
                })
                .collect::<Result<Vec<_>>>()
                .map(join_union);
        }
        let kind = schema.get("type").and_then(Value::as_str).unwrap_or("");
        Ok(match kind {
            "string" => match self.language {
                Language::Typescript => "string",
                Language::Python => "str",
            }
            .into(),
            "integer" | "number" => match self.language {
                Language::Typescript => "number",
                Language::Python if kind == "integer" => "int",
                Language::Python => "int | float",
            }
            .into(),
            "boolean" => match self.language {
                Language::Typescript => "boolean",
                Language::Python => "bool",
            }
            .into(),
            "null" => match self.language {
                Language::Typescript => "null",
                Language::Python => "None",
            }
            .into(),
            "array" => {
                let item = self.render(
                    schema.get("items").unwrap_or(&Value::Bool(true)),
                    root,
                    hint,
                    depth + 1,
                )?;
                match self.language {
                    Language::Typescript => format!("Array<{item}>"),
                    Language::Python => format!("list[{item}]"),
                }
            }
            "object" => {
                if schema
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(|fields| !fields.is_empty())
                    && schema.get("additionalProperties") != Some(&Value::Bool(false))
                {
                    return Err(CoordinatorError::new(
                        "workflow.types-refused",
                        "a typed client cannot faithfully represent an open object with named members",
                    ).suggest("Export a closed object or a dictionary schema, or use the generic client with the complete runtime schema."));
                }

                let required = schema.get("required").and_then(Value::as_array);
                let mut properties = Vec::new();
                if let Some(fields) = schema.get("properties").and_then(Value::as_object) {
                    for (name, value) in fields {
                        let ty = self.render(value, root, hint, depth + 1)?;
                        let mandatory = required.is_some_and(|required| {
                            required.iter().any(|value| value.as_str() == Some(name))
                        });
                        properties.push(match self.language {
                            Language::Typescript => format!(
                                "{}{}: {ty}",
                                serde_json::to_string(name).expect("string"),
                                if mandatory { "" } else { "?" }
                            ),
                            Language::Python => format!(
                                "{}: {}[{ty}]",
                                serde_json::to_string(name).expect("string"),
                                if mandatory { "Required" } else { "NotRequired" }
                            ),
                        });
                    }
                }
                if properties.is_empty()
                    && schema.get("additionalProperties") != Some(&Value::Bool(false))
                {
                    let value = self.render(
                        schema
                            .get("additionalProperties")
                            .unwrap_or(&Value::Bool(true)),
                        root,
                        hint,
                        depth + 1,
                    )?;
                    match self.language {
                        Language::Typescript => format!("Record<string, {value}>"),
                        Language::Python => format!("dict[str, {value}]"),
                    }
                } else {
                    match self.language {
                        Language::Typescript if properties.is_empty() => {
                            "Record<string, never>".into()
                        }
                        Language::Typescript => format!("{{ {} }}", properties.join("; ")),
                        Language::Python => {
                            let name = self.name(hint);
                            self.declarations.push(format!(
                                "{name} = TypedDict({name:?}, {{{}}})",
                                properties.join(", ")
                            ));
                            name
                        }
                    }
                }
            }
            _ => match self.language {
                Language::Typescript => "unknown",
                Language::Python => "Any",
            }
            .into(),
        })
    }
}
fn join_union(types: Vec<String>) -> String {
    let mut distinct = Vec::new();
    for ty in types {
        if !distinct.contains(&ty) {
            distinct.push(ty);
        }
    }
    distinct.join(" | ")
}

fn refused() -> CoordinatorError {
    CoordinatorError::new(
        "workflow.types-refused",
        "the compiled schema cannot be represented as a bounded typed client",
    )
    .suggest("Use finite local input and outcome schemas, then export the checked workflow again.")
}
