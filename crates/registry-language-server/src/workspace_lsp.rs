// SPDX-License-Identifier: Apache-2.0
//! Stateless LSP adapter for exact, authorized workspace-analysis snapshots.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Semaphore;
use tower_lsp_server::{
    jsonrpc::{Error, ErrorCode, Result},
    ls_types::{
        ExecuteCommandOptions, GotoDefinitionParams, GotoDefinitionResponse, InitializeParams,
        InitializeResult, Location, OneOf, Position, PositionEncodingKind, ReferenceParams,
        ServerCapabilities, ServerInfo,
    },
    LanguageServer,
};

use crate::{execute_workspace_analysis, yaml::YamlPointerResolver};

const MAX_AUTHORIZED_QUERY_BYTES: usize = 32 * 1024 * 1024;
const MAX_AUTHORIZED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_LSP_FRAME_BYTES: usize = MAX_AUTHORIZED_QUERY_BYTES + 1024 * 1024;
const MAX_LSP_HEADER_BYTES: usize = 8 * 1024;
const MAX_URI_BINDINGS: usize = 10_000;
const MAX_NAVIGATION_RESULTS: usize = 1_000;
const MAX_CONCURRENT_ANALYSES: usize = 2;
const MAX_ERROR_MESSAGE_CHARS: usize = 512;
const AUTHORIZED_QUERY_METHOD: &str = "registryStudio/authorizedQuery";
const SNAPSHOT_COMMAND: &str = "registryStudio.workspaceV1.snapshot";
const IMPACT_COMMAND: &str = "registryStudio.workspaceV1.impact";

#[derive(Debug)]
pub struct AuthorizedWorkspaceBackend {
    analysis_slots: Arc<Semaphore>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizedQueryParams {
    authorization: Authorization,
    request: OriginalRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
enum Authorization {
    Ready {
        after: Value,
        #[serde(default)]
        before: Option<Value>,
        #[serde(rename = "uriBindings")]
        uri_bindings: Vec<UriBinding>,
    },
    Unavailable {
        code: String,
        message: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UriBinding {
    path: String,
    uri: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalRequest {
    method: String,
    params: Value,
}

#[derive(Debug)]
struct BoundSnapshot {
    request: Value,
    analysis: Value,
    by_path: HashMap<String, BoundDocument>,
    by_uri: HashMap<String, String>,
}

#[derive(Debug)]
struct BoundDocument {
    uri: String,
    yaml: YamlPointerResolver,
}

#[derive(Debug)]
enum FrameBoundary {
    Header(Vec<u8>),
    Body(usize),
}

#[derive(Debug)]
struct BoundedLspInput<R> {
    inner: R,
    boundary: FrameBoundary,
}

impl<R> BoundedLspInput<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            boundary: FrameBoundary::Header(Vec::new()),
        }
    }

    fn observe(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            match &mut self.boundary {
                FrameBoundary::Header(header) => {
                    let byte = bytes[0];
                    bytes = &bytes[1..];
                    header.push(byte);
                    if header.len() > MAX_LSP_HEADER_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "the LSP header exceeds its byte limit",
                        ));
                    }
                    if header.ends_with(b"\r\n\r\n") {
                        let length = bounded_content_length(header)?;
                        header.clear();
                        self.boundary = if length == 0 {
                            FrameBoundary::Header(Vec::new())
                        } else {
                            FrameBoundary::Body(length)
                        };
                    }
                }
                FrameBoundary::Body(remaining) => {
                    let consumed = (*remaining).min(bytes.len());
                    *remaining -= consumed;
                    bytes = &bytes[consumed..];
                    if *remaining == 0 {
                        self.boundary = FrameBoundary::Header(Vec::new());
                    }
                }
            }
        }
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoundedLspInput<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                let received = &buffer.filled()[before..];
                Poll::Ready(this.observe(received))
            }
            other => other,
        }
    }
}

fn bounded_content_length(header: &[u8]) -> io::Result<usize> {
    let header = std::str::from_utf8(header)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the LSP header is not ASCII"))?;
    if !header.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the LSP header is not ASCII",
        ));
    }
    let mut lengths = header.lines().filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then_some(value.trim())
    });
    let length = lengths
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Content-Length"))?
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Content-Length"))?;
    if lengths.next().is_some() || length > MAX_LSP_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the LSP frame exceeds its byte limit",
        ));
    }
    Ok(length)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecuteCommandParams {
    command: String,
    #[serde(default)]
    arguments: Option<Vec<Value>>,
}

impl AuthorizedWorkspaceBackend {
    pub fn new(_: tower_lsp_server::Client) -> Self {
        Self {
            analysis_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_ANALYSES)),
        }
    }

    pub async fn authorized_query(&self, params: AuthorizedQueryParams) -> Result<Value> {
        let permit = self
            .analysis_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::internal_error())?;
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            Self::execute_authorized_query(params)
        })
        .await
        .map_err(|_| Error::internal_error())??;
        if serde_json::to_vec(&result)
            .map_err(|_| Error::internal_error())?
            .len()
            > MAX_AUTHORIZED_RESPONSE_BYTES
        {
            return Err(unavailable(
                "response-limit",
                "The authorized query response exceeds its byte limit.",
            ));
        }
        Ok(result)
    }

    fn execute_authorized_query(params: AuthorizedQueryParams) -> Result<Value> {
        if serde_json::to_vec(&params)
            .map_err(|_| Error::internal_error())?
            .len()
            > MAX_AUTHORIZED_QUERY_BYTES
        {
            return Err(invalid_params(
                "The authorized query exceeds its byte limit.",
            ));
        }
        let Authorization::Ready {
            after,
            before,
            uri_bindings,
        } = params.authorization
        else {
            let Authorization::Unavailable { code, message } = params.authorization else {
                unreachable!();
            };
            validate_public_error(&code, &message)?;
            return unavailable_result(
                &params.request.method,
                &params.request.params,
                code,
                message,
            );
        };

        match params.request.method.as_str() {
            "textDocument/definition" => {
                if before.is_some() {
                    return Err(invalid_params(
                        "A before snapshot is accepted only for impact comparison.",
                    ));
                }
                let bound = bind_snapshot(after, uri_bindings)?;
                definition(&bound, params.request.params)
            }
            "textDocument/references" => {
                if before.is_some() {
                    return Err(invalid_params(
                        "A before snapshot is accepted only for impact comparison.",
                    ));
                }
                let bound = bind_snapshot(after, uri_bindings)?;
                references(&bound, params.request.params)
            }
            "workspace/executeCommand" => {
                execute_command(after, before, uri_bindings, params.request.params)
            }
            _ => Err(Error::method_not_found()),
        }
    }
}

impl LanguageServer for AuthorizedWorkspaceBackend {
    async fn initialize(&self, _params: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                position_encoding: Some(PositionEncodingKind::UTF16),
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                execute_command_provider: Some(ExecuteCommandOptions {
                    commands: vec![SNAPSHOT_COMMAND.to_owned(), IMPACT_COMMAND.to_owned()],
                    ..ExecuteCommandOptions::default()
                }),
                experimental: Some(json!({"registryStudioAuthorizedQuery": true})),
                ..ServerCapabilities::default()
            },
            server_info: Some(ServerInfo {
                name: "Registry Studio Authorized Workspace Language Server".to_owned(),
                version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            }),
            offset_encoding: None,
        })
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn goto_definition(
        &self,
        _params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        Err(Error::content_modified())
    }

    async fn references(&self, _params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        Err(Error::content_modified())
    }
}

fn bind_snapshot(request: Value, bindings: Vec<UriBinding>) -> Result<BoundSnapshot> {
    if bindings.len() > MAX_URI_BINDINGS {
        return Err(invalid_params(
            "The authorized query has too many URI bindings.",
        ));
    }
    let analysis_response = analyze_request(&request)?;
    let analysis = analysis_response
        .get("analysis")
        .cloned()
        .ok_or_else(Error::internal_error)?;
    let authorized_files = analysis["files"]
        .as_array()
        .ok_or_else(Error::internal_error)?
        .iter()
        .filter_map(|file| Some((file["path"].as_str()?, file["state"].as_str()?)))
        .collect::<HashMap<_, _>>();
    let encoded_files = request["files"]
        .as_array()
        .ok_or_else(|| invalid_params("The after snapshot files are required."))?;
    let inputs = encoded_files
        .iter()
        .filter_map(|file| Some((file["path"].as_str()?, file["bytesBase64"].as_str()?)))
        .collect::<HashMap<_, _>>();
    let mut by_path = HashMap::new();
    let mut by_uri = HashMap::new();
    for binding in bindings {
        let state = authorized_files.get(binding.path.as_str()).copied();
        if binding.path.is_empty()
            || binding.uri.is_empty()
            || !matches!(state, Some("document" | "native"))
        {
            return Err(invalid_params(
                "A URI binding is not part of the authorized snapshot.",
            ));
        }
        let encoded = inputs
            .get(binding.path.as_str())
            .ok_or_else(|| invalid_params("A URI binding has no exact authorized bytes."))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid_params("A URI binding has invalid base64 bytes."))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| unavailable("source-unreadable", "A bound LSP document is not UTF-8."))?;
        let yaml = YamlPointerResolver::parse(text).ok_or_else(|| {
            unavailable(
                "location-unavailable",
                "A bound LSP document could not be parsed for navigation.",
            )
        })?;
        if by_uri
            .insert(binding.uri.clone(), binding.path.clone())
            .is_some()
            || by_path
                .insert(
                    binding.path,
                    BoundDocument {
                        uri: binding.uri,
                        yaml,
                    },
                )
                .is_some()
        {
            return Err(invalid_params("URI binding paths and URIs must be unique."));
        }
    }
    Ok(BoundSnapshot {
        request,
        analysis,
        by_path,
        by_uri,
    })
}

fn analyze_request(request: &Value) -> Result<Value> {
    let mut request = request.clone();
    let object = request
        .as_object_mut()
        .ok_or_else(|| invalid_params("An authorized snapshot must be an object."))?;
    object.insert("operation".to_owned(), Value::String("analyze".to_owned()));
    object.remove("before");
    object.remove("target");
    object.remove("targets");
    object.remove("maxResults");
    execute_workspace_analysis(request).map_err(analysis_error)
}

fn definition(bound: &BoundSnapshot, params: Value) -> Result<Value> {
    let params: GotoDefinitionParams =
        serde_json::from_value(params).map_err(|error| invalid_params(error.to_string()))?;
    let document = params.text_document_position_params;
    let uri = document.text_document.uri.as_str();
    let identity = identity_at(bound, uri, document.position)?;
    let Some(identity) = identity else {
        return Ok(Value::Null);
    };
    let result = query_analysis(&bound.request, "definition", identity)?;
    let definitions = result["definition"]["definitions"]
        .as_array()
        .ok_or_else(Error::internal_error)?;
    if result["definition"]["truncated"].as_bool() != Some(false) {
        return Err(unavailable(
            "result-limit",
            "The definition query was truncated before every location could be returned.",
        ));
    }
    let mut locations = Vec::with_capacity(definitions.len());
    for definition in definitions {
        let location = location_of(bound, &definition["location"])?;
        locations.push(location);
    }
    serde_json::to_value(locations).map_err(|_| Error::internal_error())
}

fn references(bound: &BoundSnapshot, params: Value) -> Result<Value> {
    let params: ReferenceParams =
        serde_json::from_value(params).map_err(|error| invalid_params(error.to_string()))?;
    let document = params.text_document_position;
    let uri = document.text_document.uri.as_str();
    let identity = identity_at(bound, uri, document.position)?;
    let Some(identity) = identity else {
        return Ok(json!([]));
    };
    let result = query_analysis(&bound.request, "references", identity.clone())?;
    let mut locations = Vec::new();
    if result["references"]["truncated"].as_bool() != Some(false) {
        return Err(unavailable(
            "result-limit",
            "The reference query was truncated before every location could be returned.",
        ));
    }
    for reference in result["references"]["incoming"]
        .as_array()
        .ok_or_else(Error::internal_error)?
    {
        locations.push(location_of(bound, &reference["location"])?);
    }
    if params.context.include_declaration {
        let definitions = query_analysis(&bound.request, "definition", identity)?;
        if definitions["definition"]["truncated"].as_bool() != Some(false) {
            return Err(unavailable(
                "result-limit",
                "The declaration query was truncated before every location could be returned.",
            ));
        }
        for definition in definitions["definition"]["definitions"]
            .as_array()
            .ok_or_else(Error::internal_error)?
        {
            locations.push(location_of(bound, &definition["location"])?);
        }
    }
    locations.sort_by(|left, right| {
        left["uri"]
            .as_str()
            .cmp(&right["uri"].as_str())
            .then_with(|| left["range"].to_string().cmp(&right["range"].to_string()))
    });
    locations.dedup();
    Ok(Value::Array(locations))
}

fn query_analysis(request: &Value, operation: &str, target: Value) -> Result<Value> {
    let mut query = request.clone();
    let object = query
        .as_object_mut()
        .ok_or_else(|| invalid_params("An authorized snapshot must be an object."))?;
    object.insert("operation".to_owned(), Value::String(operation.to_owned()));
    object.insert("target".to_owned(), target);
    object.insert("maxResults".to_owned(), json!(MAX_NAVIGATION_RESULTS));
    object.remove("before");
    object.remove("targets");
    execute_workspace_analysis(query).map_err(analysis_error)
}

fn identity_at(bound: &BoundSnapshot, uri: &str, position: Position) -> Result<Option<Value>> {
    let path = bound.by_uri.get(uri).ok_or_else(|| {
        unavailable(
            "document-unavailable",
            "The request URI is not in the authorized binding.",
        )
    })?;
    let document = bound.by_path.get(path).ok_or_else(Error::internal_error)?;
    if !position_in_document(document.yaml.source(), position) {
        return Err(invalid_params(
            "The UTF-16 position is outside the bound snapshot document.",
        ));
    }
    let mut candidates = Vec::<(u64, u8, String, Value)>::new();
    for reference in bound.analysis["references"]
        .as_array()
        .ok_or_else(Error::internal_error)?
    {
        if reference["location"]["file"].as_str() == Some(path.as_str()) {
            add_candidate(
                &mut candidates,
                &document.yaml,
                &reference["location"],
                &reference["target"],
                position,
                0,
            );
        }
    }
    for definition in bound.analysis["definitions"]
        .as_array()
        .ok_or_else(Error::internal_error)?
    {
        if definition["location"]["file"].as_str() == Some(path.as_str()) {
            let priority = if definition["identity"]["kind"] == "object" {
                1
            } else {
                2
            };
            add_candidate(
                &mut candidates,
                &document.yaml,
                &definition["location"],
                &definition["identity"],
                position,
                priority,
            );
        }
    }
    candidates.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    Ok(candidates.into_iter().next().map(|candidate| candidate.3))
}

fn add_candidate(
    candidates: &mut Vec<(u64, u8, String, Value)>,
    yaml: &YamlPointerResolver,
    location: &Value,
    identity: &Value,
    position: Position,
    priority: u8,
) {
    let Some(pointer) = location["pointer"].as_str() else {
        return;
    };
    let Some(range) = yaml.range_at_pointer(pointer) else {
        return;
    };
    if contains(range.start, range.end, position) {
        let width = (u64::from(range.end.line.saturating_sub(range.start.line)) << 32)
            + u64::from(range.end.character.saturating_sub(range.start.character));
        candidates.push((width, priority, identity_key(identity), identity.clone()));
    }
}

fn location_of(bound: &BoundSnapshot, location: &Value) -> Result<Value> {
    let path = location["file"]
        .as_str()
        .ok_or_else(Error::internal_error)?;
    let pointer = location["pointer"]
        .as_str()
        .ok_or_else(Error::internal_error)?;
    let document = bound.by_path.get(path).ok_or_else(|| {
        unavailable(
            "definition-source-unavailable",
            "A navigation result is not in the authorized URI binding.",
        )
    })?;
    let range = document.yaml.range_at_pointer(pointer).ok_or_else(|| {
        unavailable(
            "location-unavailable",
            "A navigation pointer has no precise YAML range.",
        )
    })?;
    Ok(json!({"uri":document.uri,"range":range}))
}

fn execute_command(
    after: Value,
    before: Option<Value>,
    bindings: Vec<UriBinding>,
    params: Value,
) -> Result<Value> {
    let params: ExecuteCommandParams =
        serde_json::from_value(params).map_err(|error| invalid_params(error.to_string()))?;
    match params.command.as_str() {
        SNAPSHOT_COMMAND => {
            if before.is_some() {
                return Err(invalid_params(
                    "A before snapshot is accepted only for impact comparison.",
                ));
            }
            if params
                .arguments
                .as_ref()
                .is_some_and(|arguments| !arguments.is_empty())
            {
                return Err(invalid_params("The snapshot command takes no arguments."));
            }
            let bound = bind_snapshot(after, bindings)?;
            Ok(json!({
                "status":"available",
                "snapshot":bound.analysis["snapshot"],
                "coverage":bound.analysis["coverage"]
            }))
        }
        IMPACT_COMMAND => impact_command(after, before, bindings, params.arguments),
        _ => Err(invalid_params("The workspace command is not implemented.")),
    }
}

fn impact_command(
    after: Value,
    before: Option<Value>,
    bindings: Vec<UriBinding>,
    arguments: Option<Vec<Value>>,
) -> Result<Value> {
    let arguments =
        arguments.ok_or_else(|| invalid_params("The impact command takes one argument."))?;
    if arguments.len() != 1 {
        return Err(invalid_params("The impact command takes one argument."));
    }
    let input = arguments.into_iter().next().expect("one argument");
    let requested = input
        .get("snapshot")
        .cloned()
        .ok_or_else(|| invalid_params("The impact command requires an exact snapshot."))?;
    let compare = input
        .get("compareWithBase")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if input
        .get("compareWithBase")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid_params("compareWithBase must be a boolean."));
    }
    if before.is_some() && !compare {
        return Err(invalid_params(
            "A before snapshot is accepted only for impact comparison.",
        ));
    }
    let bound = bind_snapshot(after.clone(), bindings)?;
    let current = bound.analysis["snapshot"].clone();
    validate_snapshot(&requested)?;
    if !same_snapshot(&requested, &current) {
        return Ok(json!({"status":"stale","requested":requested,"current":current}));
    }
    if compare && before.is_none() {
        return Ok(json!({
            "status":"unsupported",
            "code":"comparison-base-unavailable",
            "message":"This authorized query did not provide a captured base for comparison."
        }));
    }
    let before_analysis = before.as_ref().map(analyze_request).transpose()?;
    if before_analysis.as_ref().is_some_and(|analysis| {
        analysis["analysis"]["snapshot"]["workspaceBinding"]
            != bound.analysis["snapshot"]["workspaceBinding"]
    }) {
        return Err(invalid_params(
            "Before and after snapshots must have the same workspace binding.",
        ));
    }
    validate_impact_limits(input.get("limits"))?;
    validate_impact_targets(
        input.get("targets"),
        &bound.analysis,
        before_analysis
            .as_ref()
            .map(|analysis| &analysis["analysis"]),
    )?;
    let mut query = after;
    let object = query
        .as_object_mut()
        .ok_or_else(|| invalid_params("An authorized snapshot must be an object."))?;
    object.insert("operation".to_owned(), Value::String("impact".to_owned()));
    if let Some(before) = before {
        let before = snapshot_input(before)?;
        object.insert("before".to_owned(), before);
    } else {
        object.remove("before");
    }
    object.insert(
        "targets".to_owned(),
        input.get("targets").cloned().unwrap_or_else(|| json!([])),
    );
    object.insert(
        "limits".to_owned(),
        input.get("limits").cloned().unwrap_or_else(|| json!({})),
    );
    match execute_workspace_analysis(query) {
        Ok(result) => Ok(json!({"status":"available","impact":result["impact"]})),
        Err(error) => Ok(json!({
            "status":"unavailable",
            "code":error.code(),
            "message":error.to_string()
        })),
    }
}

fn snapshot_input(snapshot: Value) -> Result<Value> {
    let object = snapshot
        .as_object()
        .ok_or_else(|| invalid_params("A before snapshot must be an object."))?;
    let mut result = Map::new();
    for key in ["workspaceBinding", "revision", "files", "facts"] {
        result.insert(
            key.to_owned(),
            object
                .get(key)
                .cloned()
                .ok_or_else(|| invalid_params("The before snapshot is incomplete."))?,
        );
    }
    Ok(Value::Object(result))
}

fn validate_snapshot(snapshot: &Value) -> Result<()> {
    for key in ["workspaceBinding", "revision", "contentHash"] {
        if snapshot
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(invalid_params("The impact snapshot is incomplete."));
        }
    }
    Ok(())
}

fn same_snapshot(left: &Value, right: &Value) -> bool {
    ["workspaceBinding", "revision", "contentHash"]
        .into_iter()
        .all(|key| left.get(key) == right.get(key))
}

fn validate_impact_limits(limits: Option<&Value>) -> Result<()> {
    let Some(limits) = limits else {
        return Ok(());
    };
    let limits = limits
        .as_object()
        .ok_or_else(|| invalid_params("Impact limits must be an object."))?;
    for (key, value) in limits {
        if !matches!(key.as_str(), "maxDepth" | "maxResults" | "maxPaths")
            || value.as_u64().is_none_or(|value| value > usize::MAX as u64)
        {
            return Err(invalid_params(
                "Impact limits accept only non-negative integer maxDepth, maxResults and maxPaths fields.",
            ));
        }
    }
    Ok(())
}

fn validate_impact_targets(
    targets: Option<&Value>,
    after: &Value,
    before: Option<&Value>,
) -> Result<()> {
    let Some(targets) = targets else {
        return Ok(());
    };
    let targets = targets
        .as_array()
        .ok_or_else(|| invalid_params("Impact targets must be an array."))?;
    for target in targets {
        let kind = target["kind"]
            .as_str()
            .ok_or_else(|| invalid_params("An impact target identity is invalid."))?;
        if kind == "object" {
            continue;
        }
        if !matches!(kind, "authored-file" | "generated-file")
            || !identity_is_defined(after, target)
                && !before.is_some_and(|analysis| identity_is_defined(analysis, target))
        {
            return Err(invalid_params(
                "An impact file target is not part of the authorized snapshot or its captured base.",
            ));
        }
    }
    Ok(())
}

fn identity_is_defined(analysis: &Value, target: &Value) -> bool {
    let key = identity_key(target);
    analysis["definitions"]
        .as_array()
        .is_some_and(|definitions| {
            definitions
                .iter()
                .any(|definition| identity_key(&definition["identity"]) == key)
        })
}

fn unavailable_result(
    method: &str,
    params: &Value,
    code: String,
    message: String,
) -> Result<Value> {
    if method == "workspace/executeCommand" {
        let command = params.get("command").and_then(Value::as_str);
        if matches!(command, Some(SNAPSHOT_COMMAND | IMPACT_COMMAND)) {
            return Ok(json!({"status":"unavailable","code":code,"message":message}));
        }
    }
    Err(unavailable(&code, &message))
}

fn validate_public_error(code: &str, message: &str) -> Result<()> {
    let valid_code = !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid_code
        || message.is_empty()
        || message.len() > 512
        || message.chars().any(char::is_control)
    {
        return Err(invalid_params(
            "Unavailable authorization codes and messages must be bounded public text.",
        ));
    }
    Ok(())
}

fn position_in_document(text: &str, position: Position) -> bool {
    text.split('\n')
        .nth(position.line as usize)
        .map(|line| {
            line.trim_end_matches('\r').encode_utf16().count() >= position.character as usize
        })
        .unwrap_or(false)
}

fn contains(start: Position, end: Position, position: Position) -> bool {
    (position.line, position.character) >= (start.line, start.character)
        && (position.line, position.character) < (end.line, end.character)
}

fn identity_key(identity: &Value) -> String {
    match identity["kind"].as_str() {
        Some("object") => format!(
            "object:{}:{}",
            identity["scope"].as_str().unwrap_or_default(),
            identity["name"].as_str().unwrap_or_default()
        ),
        Some(kind) => format!("{kind}:{}", identity["path"].as_str().unwrap_or_default()),
        None => String::new(),
    }
}

fn analysis_error(error: crate::WorkspaceAnalysisError) -> Error {
    unavailable(error.code(), &error.to_string())
}

fn invalid_params(message: impl Into<Cow<'static, str>>) -> Error {
    Error::invalid_params(bounded_error_message(&message.into()))
}

fn unavailable(code: &str, message: &str) -> Error {
    Error {
        code: ErrorCode::ServerError(-32001),
        message: bounded_error_message(message),
        data: Some(json!({"code":code})),
    }
}

fn bounded_error_message(message: &str) -> Cow<'static, str> {
    let bounded = message
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_ERROR_MESSAGE_CHARS)
        .collect::<String>();
    Cow::Owned(if bounded.is_empty() {
        "The authorized query was refused.".to_owned()
    } else {
        bounded
    })
}

pub async fn run_workspace_lsp_stdio() {
    let stdin = BoundedLspInput::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();
    let (service, socket) = tower_lsp_server::LspService::build(AuthorizedWorkspaceBackend::new)
        .custom_method(
            AUTHORIZED_QUERY_METHOD,
            AuthorizedWorkspaceBackend::authorized_query,
        )
        .finish();
    tower_lsp_server::Server::new(stdin, stdout, socket)
        .serve(service)
        .await;
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn lsp_frame_ceiling_is_enforced_before_the_body() {
        let mut input = BoundedLspInput::new(());
        let header = format!("Content-Length: {}\r\n\r\n", MAX_LSP_FRAME_BYTES + 1);
        let error = input
            .observe(header.as_bytes())
            .expect_err("oversized frame is refused from its header");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut input = BoundedLspInput::new(());
        input
            .observe(b"Content-Length: 2\r\n\r\n{}Content-Length: 0\r\n\r\n")
            .expect("bounded adjacent frames are accepted");
        assert!(matches!(input.boundary, FrameBoundary::Header(_)));
    }

    #[test]
    fn identity_lookup_uses_pointer_range_at_utf16_position() {
        let action = "kind: PlatformAction\nname: apply\n";
        let service = "kind: PlatformService\nname: nursing\nmap:\n  steps:\n    - { label: \"🩺\", action: apply }\n";
        let native =
            "kind: BRegProject\nproject: {id: nursing}\nrecordTypes:\n  - id: practitioner\n";
        let file = |path: &str, text: &str| {
            let sha256 = Sha256::digest(text.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            json!({"path":path,"state":"document","sha256":sha256,"bytesBase64":BASE64.encode(text)})
        };
        let request = json!({
            "apiVersion":"id.registrystack.org/formats/platform/workspace-analysis/v1alpha1",
            "operation":"analyze","workspaceBinding":"workspace:test","revision":"r1",
            "files":[file("actions/apply.yaml", action),file("services/nursing.yaml", service),file("native/breg/nursing.yaml", native)],
            "facts":{
                "definitions":[
                    {"scope":"actions","name":"apply","file":"actions/apply.yaml","pointer":"/name"},
                    {"scope":"services","name":"nursing","file":"services/nursing.yaml","pointer":"/name"}
                ],
                "mentions":[{"source":{"scope":"services","name":"nursing"},"target":{"scope":"actions","name":"apply"},"kind":"service-action","file":"services/nursing.yaml","pointer":"/map/steps/0/action"}],
                "mappings":[],"nativeParts":["native/breg/nursing.yaml"],"coverageGaps":[],"checkGroups":[]
            }
        });
        let bound = bind_snapshot(
            request,
            vec![
                UriBinding {
                    path: "actions/apply.yaml".to_owned(),
                    uri: "registry-studio://authorized/actions/apply.yaml".to_owned(),
                },
                UriBinding {
                    path: "services/nursing.yaml".to_owned(),
                    uri: "registry-studio://authorized/services/nursing.yaml".to_owned(),
                },
                UriBinding {
                    path: "native/breg/nursing.yaml".to_owned(),
                    uri: "file:///definitely-not-present/native/breg/nursing.yaml".to_owned(),
                },
            ],
        )
        .expect("snapshot binds");
        let params: GotoDefinitionParams = serde_json::from_value(json!({
            "textDocument":{"uri":"registry-studio://authorized/services/nursing.yaml"},
            "position":{"line":4,"character":29}
        }))
        .expect("LSP params parse");
        let position = params.text_document_position_params;
        let identity = identity_at(
            &bound,
            position.text_document.uri.as_str(),
            position.position,
        )
        .expect("position is valid")
        .expect("identity resolves");
        assert_eq!(
            identity,
            json!({"kind":"object","scope":"actions","name":"apply"})
        );
        let at_end = identity_at(
            &bound,
            "registry-studio://authorized/services/nursing.yaml",
            Position::new(4, 34),
        )
        .expect("range-end position is valid")
        .expect("the containing document remains selectable");
        assert_eq!(
            at_end,
            json!({"kind":"authored-file","path":"services/nursing.yaml"})
        );
        let answer = definition(
            &bound,
            json!({
                "textDocument":{"uri":"registry-studio://authorized/services/nursing.yaml"},
                "position":{"line":4,"character":29}
            }),
        )
        .expect("definition succeeds");
        assert_eq!(
            answer[0]["uri"],
            "registry-studio://authorized/actions/apply.yaml"
        );
    }

    #[test]
    fn references_reject_truncated_declaration_locations() {
        let text = "name: apply\n";
        let sha256 = Sha256::digest(text.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let definitions = (0..=MAX_NAVIGATION_RESULTS)
            .map(|index| {
                json!({"scope":"actions","name":"apply","file":format!("actions/{index}.yaml"),"pointer":"/name"})
            })
            .collect::<Vec<_>>();
        let files = (0..=MAX_NAVIGATION_RESULTS)
            .map(|index| {
                json!({
                    "path":format!("actions/{index}.yaml"),"state":"document","sha256":sha256,
                    "bytesBase64":BASE64.encode(text)
                })
            })
            .collect::<Vec<_>>();
        let bindings = (0..=MAX_NAVIGATION_RESULTS)
            .map(|index| UriBinding {
                path: format!("actions/{index}.yaml"),
                uri: format!("registry-studio://authorized/actions/{index}.yaml"),
            })
            .collect::<Vec<_>>();
        let request = json!({
            "apiVersion":"id.registrystack.org/formats/platform/workspace-analysis/v1alpha1",
            "operation":"analyze","workspaceBinding":"workspace:test","revision":"r1",
            "files":files,
            "facts":{"definitions":definitions,"mentions":[],"mappings":[],"nativeParts":[],"coverageGaps":[],"checkGroups":[]}
        });
        let bound = bind_snapshot(request, bindings).expect("snapshot binds");
        let error = references(
            &bound,
            json!({
                "textDocument":{"uri":"registry-studio://authorized/actions/0.yaml"},
                "position":{"line":0,"character":7},
                "context":{"includeDeclaration":true}
            }),
        )
        .expect_err("truncated declarations fail closed");
        assert_eq!(error.code, ErrorCode::ServerError(-32001));
        assert_eq!(error.data, Some(json!({"code":"result-limit"})));
    }
}
