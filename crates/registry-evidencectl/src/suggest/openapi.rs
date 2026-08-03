//! Loads a local OpenAPI 3.0.x or 3.1.x document and resolves the pieces the
//! `source suggest` pipeline needs: operation listings and one operation's
//! response schema with every local `$ref` inlined.
//!
//! Only local files are read and only local `#/components/...` refs are
//! followed. An external or remote `$ref` (anything not starting with `#/`)
//! and a `$ref` cycle are both rejected with a clear error rather than
//! silently truncated or ignored, because a partially-resolved schema would
//! let the closed-subset narrowing stage draft against data the runtime
//! cannot actually see.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

use super::types::{OperationKey, OperationSummary, ResolvedSchema};

/// Path Item Object keys this pipeline can draft a source from.
///
/// OpenAPI allows eight methods, but an Evidence fixed request declares one of
/// two: the runtime's method enumeration is `GET` and `POST`. Offering any
/// other method would only produce a source the runtime rejects, so the
/// listing is filtered here rather than at the far end of the pipeline.
const OPERATION_METHODS: [&str; 2] = ["get", "post"];

/// OpenAPI documents larger than this are rejected before they are read, the
/// way `sample::load_sample` rejects an oversized sample. The largest published
/// registry API descriptions are a few megabytes; a document past this ceiling
/// is a mistaken path rather than a specification to draft from.
const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

/// Query parameter names that bound how many items one response carries,
/// compared against the parameter's name lowercased with `_`, `-` and `.`
/// removed.
///
/// The list is deliberately closed. A name outside it yields no page-size
/// value at all, so the bound it would have set stays an unresolved
/// `TODO(evidencectl)` for the operator to answer, which is the outcome this
/// tool prefers over a bound it cannot justify. `page`, `pageNumber`,
/// `pageIndex`, `offset` and `start` are absent on purpose: they count pages
/// or positions, not items.
const PAGE_SIZE_NAMES: [&str; 8] = [
    "pagesize",
    "perpage",
    "size",
    "limit",
    "pagelimit",
    "count",
    "maxresults",
    "maxrecords",
];

/// Whether `name` names a page-size query parameter, comparing the whole
/// normalized name against [`PAGE_SIZE_NAMES`].
fn is_page_size_name(name: &str) -> bool {
    let normalized: String = name
        .chars()
        .filter(|character| !matches!(character, '_' | '-' | '.'))
        .flat_map(char::to_lowercase)
        .collect();
    PAGE_SIZE_NAMES.contains(&normalized.as_str())
}

/// A loaded, dialect-checked OpenAPI document.
///
/// `load` accepts OpenAPI 3.0.x and 3.1.x, in YAML or JSON, from a local
/// file. It does not otherwise validate the document against the OpenAPI
/// meta-schema; malformed structure surfaces as an error from whichever
/// accessor first needs the missing or mistyped piece.
#[derive(Debug, Clone)]
pub struct Spec {
    document: Value,
}

impl Spec {
    /// Reads and parses the OpenAPI document at `path`. Accepts YAML or
    /// JSON (YAML is a superset for this purpose, so both are parsed the
    /// same way) and requires a top-level `openapi: 3.0.x` or `3.1.x`
    /// version string. No network access is performed; `path` must name a
    /// local file.
    pub fn load(path: &Path) -> Result<Spec> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("reading OpenAPI document metadata at {}", path.display()))?;
        if metadata.len() > MAX_DOCUMENT_BYTES {
            bail!(
                "OpenAPI document at {} is {} bytes, exceeding the {} byte limit",
                path.display(),
                metadata.len(),
                MAX_DOCUMENT_BYTES
            );
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading OpenAPI document at {}", path.display()))?;
        let document: Value = serde_norway::from_str(&text)
            .with_context(|| format!("parsing {} as YAML or JSON", path.display()))?;
        let version = document
            .get("openapi")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "{} has no top-level `openapi` version string",
                    path.display()
                )
            })?;
        if !(version.starts_with("3.0.") || version.starts_with("3.1.")) {
            bail!(
                "{} declares `openapi: {version}`; only OpenAPI 3.0.x and 3.1.x are supported",
                path.display()
            );
        }
        Ok(Spec { document })
    }

    /// Every path-and-method operation that carries at least one JSON
    /// response schema (a response whose media type contains `json`, e.g.
    /// `application/json` or `application/problem+json`, and that declares
    /// a `schema`). Operations with no JSON response are omitted because
    /// they have nothing this pipeline can draft from.
    pub fn operations(&self) -> Vec<OperationSummary> {
        let mut out = Vec::new();
        let Some(paths) = self.document.get("paths").and_then(Value::as_object) else {
            return out;
        };
        for (path, path_item_raw) in paths {
            let Ok(path_item) = self.resolve_top_ref(path_item_raw, &mut Vec::new()) else {
                continue;
            };
            let Some(path_item) = path_item.as_object() else {
                continue;
            };
            for method in OPERATION_METHODS {
                let Some(operation) = path_item.get(method) else {
                    continue;
                };
                let json_responses = self.json_responses(operation);
                if json_responses.is_empty() {
                    continue;
                }
                out.push(OperationSummary {
                    key: OperationKey {
                        method: method.to_ascii_uppercase(),
                        path: path.clone(),
                    },
                    summary: operation
                        .get("summary")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    json_responses,
                });
            }
        }
        out
    }

    /// The `(status, media type)` pairs on `operation` whose media type
    /// looks like JSON and which declare a response `schema`.
    fn json_responses(&self, operation: &Value) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
            return out;
        };
        for (status, response_raw) in responses {
            let Ok(response) = self.resolve_top_ref(response_raw, &mut Vec::new()) else {
                continue;
            };
            let Some(content) = response.get("content").and_then(Value::as_object) else {
                continue;
            };
            for (media_type, media_object) in content {
                if media_type.to_ascii_lowercase().contains("json")
                    && media_object.get("schema").is_some()
                {
                    out.push((status.clone(), media_type.clone()));
                }
            }
        }
        out
    }

    /// The response schema for `key`'s `status`/`media_type` response, with
    /// every local `$ref` inlined and OpenAPI 3.0 `nullable: true` rewritten
    /// to the 3.1 type pair `[T, "null"]`.
    pub fn response_schema(
        &self,
        key: &OperationKey,
        status: &str,
        media_type: &str,
    ) -> Result<ResolvedSchema> {
        let operation = self.find_operation(key)?;
        let responses = operation
            .get("responses")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("{} {} declares no `responses`", key.method, key.path))?;
        let response_raw = responses
            .get(status)
            .ok_or_else(|| anyhow!("{} {} has no `{status}` response", key.method, key.path))?;
        let response = self
            .resolve_top_ref(response_raw, &mut Vec::new())
            .with_context(|| {
                format!(
                    "resolving the `{status}` response of {} {}",
                    key.method, key.path
                )
            })?;
        let content = response
            .get("content")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                anyhow!(
                    "{} {} `{status}` response declares no `content`",
                    key.method,
                    key.path
                )
            })?;
        let media_object = content.get(media_type).ok_or_else(|| {
            anyhow!(
                "{} {} `{status}` response has no `{media_type}` content",
                key.method,
                key.path
            )
        })?;
        let schema = media_object.get("schema").ok_or_else(|| {
            anyhow!(
                "{} {} `{status}` `{media_type}` response declares no `schema`",
                key.method,
                key.path
            )
        })?;
        let resolved = self
            .inline_schema(schema, &mut Vec::new())
            .with_context(|| {
                format!(
                    "resolving the `{status}` `{media_type}` response schema of {} {}",
                    key.method, key.path
                )
            })?;
        Ok(ResolvedSchema(resolved))
    }

    /// Base URLs from the document's top-level `servers` array, in document
    /// order. Empty when the document declares none.
    pub fn servers(&self) -> Vec<String> {
        self.document
            .get("servers")
            .and_then(Value::as_array)
            .map(|servers| {
                servers
                    .iter()
                    .filter_map(|server| server.get("url").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Integer `maximum` values found on `key`'s query parameters (path-item
    /// level and operation level) whose name is one of [`PAGE_SIZE_NAMES`].
    ///
    /// This is a naming heuristic, not a semantic one: it does not attempt
    /// to determine whether a matching parameter actually bounds page size,
    /// and it looks only at the parameter's own `schema.maximum`. Later
    /// pipeline stages decide whether and how to use the values as
    /// `Provenance::PageSize`.
    ///
    /// The match is on the whole normalized name rather than a substring,
    /// because a substring match cannot tell a page size from a page index:
    /// `page` and `pageSize` both contain `page`, but only one of them bounds
    /// how many items a response carries, and reading the other as an item
    /// count would suggest a bound orders of magnitude too generous.
    pub fn page_size_maximums(&self, key: &OperationKey) -> Result<Vec<i64>> {
        let paths = self
            .document
            .get("paths")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("document has no `paths`"))?;
        let path_item_raw = paths
            .get(&key.path)
            .ok_or_else(|| anyhow!("no path `{}` in the document", key.path))?;
        let path_item = self.resolve_top_ref(path_item_raw, &mut Vec::new())?;

        let mut maximums = Vec::new();
        if let Some(parameters) = path_item.get("parameters").and_then(Value::as_array) {
            self.collect_page_size_maximums(parameters, &mut maximums)?;
        }
        let operation = self.find_operation(key)?;
        if let Some(parameters) = operation.get("parameters").and_then(Value::as_array) {
            self.collect_page_size_maximums(parameters, &mut maximums)?;
        }
        Ok(maximums)
    }

    fn collect_page_size_maximums(&self, parameters: &[Value], out: &mut Vec<i64>) -> Result<()> {
        for parameter_raw in parameters {
            let parameter = self.resolve_top_ref(parameter_raw, &mut Vec::new())?;
            let Some(name) = parameter.get("name").and_then(Value::as_str) else {
                continue;
            };
            if parameter.get("in").and_then(Value::as_str) != Some("query") {
                continue;
            }
            if !is_page_size_name(name) {
                continue;
            }
            let Some(schema) = parameter.get("schema") else {
                continue;
            };
            let resolved = self
                .inline_schema(schema, &mut Vec::new())
                .with_context(|| format!("resolving the schema of query parameter `{name}`"))?;
            if let Some(maximum) = resolved.get("maximum").and_then(Value::as_i64) {
                out.push(maximum);
            }
        }
        Ok(())
    }

    /// Finds `key`'s Operation Object, resolving a path-item-level `$ref` if
    /// present.
    fn find_operation(&self, key: &OperationKey) -> Result<&Value> {
        let paths = self
            .document
            .get("paths")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("document has no `paths`"))?;
        let path_item_raw = paths
            .get(&key.path)
            .ok_or_else(|| anyhow!("no path `{}` in the document", key.path))?;
        let path_item = self.resolve_top_ref(path_item_raw, &mut Vec::new())?;
        let method = key.method.to_ascii_lowercase();
        path_item
            .get(&method)
            .ok_or_else(|| anyhow!("path `{}` has no `{}` operation", key.path, key.method))
    }

    /// Follows a chain of `$ref` at the top level of `node` (a Response,
    /// Parameter, or Path Item Object, none of which nest further schema
    /// keywords the way a Schema Object does) until a non-`$ref` object is
    /// reached. Returns `node` unchanged when it carries no `$ref`.
    fn resolve_top_ref<'a>(
        &'a self,
        node: &'a Value,
        stack: &mut Vec<String>,
    ) -> Result<&'a Value> {
        let Some(object) = node.as_object() else {
            return Ok(node);
        };
        let Some(reference) = object.get("$ref").and_then(Value::as_str) else {
            return Ok(node);
        };
        let pointer = local_ref_pointer(reference)?;
        if stack.iter().any(|seen| seen == reference) {
            bail!("$ref cycle detected at `{reference}`");
        }
        let target = resolve_pointer(&self.document, pointer)
            .with_context(|| format!("resolving $ref `{reference}`"))?;
        stack.push(reference.to_string());
        let resolved = self.resolve_top_ref(target, stack)?;
        stack.pop();
        Ok(resolved)
    }

    /// Recursively inlines every local `$ref` inside a Schema Object and
    /// normalizes OpenAPI 3.0 `nullable: true` to the 3.1 type pair. Per
    /// OpenAPI 3.0 semantics, a schema node carrying `$ref` has any sibling
    /// keywords ignored; this function does the same, uniformly, for
    /// simplicity.
    fn inline_schema(&self, node: &Value, stack: &mut Vec<String>) -> Result<Value> {
        let Value::Object(object) = node else {
            return Ok(node.clone());
        };
        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let pointer = local_ref_pointer(reference)?;
            if stack.iter().any(|seen| seen == reference) {
                bail!("$ref cycle detected at `{reference}`");
            }
            let target = resolve_pointer(&self.document, pointer)
                .with_context(|| format!("resolving $ref `{reference}`"))?
                .clone();
            stack.push(reference.to_string());
            let inlined = self.inline_schema(&target, stack);
            stack.pop();
            return inlined;
        }

        let mut result = serde_json::Map::with_capacity(object.len());
        for (key, value) in object {
            let inlined_value = match key.as_str() {
                "properties" => match value.as_object() {
                    Some(members) => {
                        let mut properties = serde_json::Map::with_capacity(members.len());
                        for (member_name, member_schema) in members {
                            properties.insert(
                                member_name.clone(),
                                self.inline_schema(member_schema, stack)?,
                            );
                        }
                        Value::Object(properties)
                    }
                    None => value.clone(),
                },
                "items" | "not" | "additionalProperties" if value.is_object() => {
                    self.inline_schema(value, stack)?
                }
                "allOf" | "oneOf" | "anyOf" => {
                    if let Some(members) = value.as_array() {
                        let mut inlined_members = Vec::with_capacity(members.len());
                        for member in members {
                            inlined_members.push(self.inline_schema(member, stack)?);
                        }
                        Value::Array(inlined_members)
                    } else {
                        value.clone()
                    }
                }
                _ => value.clone(),
            };
            result.insert(key.clone(), inlined_value);
        }
        normalize_nullable(&mut result);
        Ok(Value::Object(result))
    }
}

/// Rewrites OpenAPI 3.0's `nullable: true` in place to the 3.1-style type
/// pair `[T, "null"]`, removing the `nullable` keyword. A `nullable: true`
/// with no `type` keyword to pair against is left unrepresented (the
/// `nullable` key is still removed): the closed subset this pipeline drafts
/// toward always requires an explicit type, so a later stage rejects the
/// node as untyped rather than this function guessing one.
fn normalize_nullable(object: &mut serde_json::Map<String, Value>) {
    let Some(Value::Bool(true)) = object.remove("nullable") else {
        return;
    };
    match object.get_mut("type") {
        Some(Value::String(type_name)) => {
            let pair = Value::Array(vec![
                Value::String(type_name.clone()),
                Value::String("null".to_string()),
            ]);
            object.insert("type".to_string(), pair);
        }
        Some(Value::Array(type_names))
            if !type_names
                .iter()
                .any(|entry| entry.as_str() == Some("null")) =>
        {
            type_names.push(Value::String("null".to_string()));
        }
        _ => {}
    }
}

/// Validates that `reference` is a local same-document ref (`#/...` or the
/// whole-document `#`) and returns its JSON Pointer (without the leading
/// `#`). Rejects anything else — a relative or absolute document reference,
/// a URL, or a bare non-pointer fragment — as external or remote.
fn local_ref_pointer(reference: &str) -> Result<&str> {
    if reference == "#" {
        return Ok("");
    }
    if reference.starts_with("#/") {
        // Strip only the leading `#`, keeping the `/` that `resolve_pointer` expects.
        Ok(&reference[1..])
    } else {
        Err(anyhow!(
            "external or remote $ref `{reference}` is not supported; only local `#/...` refs are"
        ))
    }
}

/// Resolves an RFC 6901 JSON Pointer (without its leading `#`, e.g.
/// `/components/schemas/Record`) against `document`.
fn resolve_pointer<'a>(document: &'a Value, pointer: &str) -> Result<&'a Value> {
    let mut current = document;
    if pointer.is_empty() {
        return Ok(current);
    }
    for raw_segment in pointer.split('/').skip(1) {
        let segment = raw_segment.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => map
                .get(&segment)
                .ok_or_else(|| anyhow!("no member `{segment}` at this point in the document"))?,
            Value::Array(items) => {
                let index: usize = segment
                    .parse()
                    .map_err(|_| anyhow!("`{segment}` is not a valid array index"))?;
                items
                    .get(index)
                    .ok_or_else(|| anyhow!("index {index} is out of bounds"))?
            }
            _ => bail!("cannot descend into a scalar value at `{segment}`"),
        };
    }
    Ok(current)
}
