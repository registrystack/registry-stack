//! Draft Evidence source artifacts from a narrowed response schema, write
//! them into a deployment project, and verify them against the `evidence`
//! binary.
//!
//! This stage never re-derives anything the earlier pipeline stages already
//! decided: it renders `NarrowOutcome` and the confirmed selection into
//! files, a pasteable source block, and a report. A bound the pipeline could
//! not resolve is never invented here either — it stays an explicit
//! `# TODO(evidencectl):` comment, so `evidence check` keeps rejecting the
//! draft until a human resolves it.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::types::{
    BoundKind, BoundNeed, BoundValues, DraftArtifacts, DraftFile, NarrowOutcome, OperationKey,
    Provenance, SpecSource, SuggestedBound,
};

/// Everything the emit stage needs to draft artifacts for one source. Built
/// from the outputs of the earlier pipeline stages (`openapi`, `flatten`,
/// `sample`, `narrow`); this stage does not consult the OpenAPI document, the
/// sample, or the narrowing heuristics again.
#[derive(Debug, Clone)]
pub struct EmitInputs {
    /// Source identifier the caller chose. Names every emitted file and
    /// becomes the `sources.<id>` key.
    pub source_id: String,
    pub operation: OperationKey,
    /// Response status code the schema was read from.
    pub status: String,
    /// Response media type the schema was read from; also the `Accept`
    /// header value in the drafted source block.
    pub media_type: String,
    /// An origin and path prefix derived from the OpenAPI `servers` list, when
    /// one could be. The origin is emitted only as a commented review
    /// suggestion. See [`split_server_url`].
    pub base_url_suggestion: Option<ServerSuggestion>,
    /// Explicit reviewed source origin supplied by the author. Unlike the
    /// OpenAPI-derived suggestion, this is rendered as active source policy.
    pub base_url: Option<String>,
    /// Selected projection pointers (extended form), in presentation order.
    pub selection: Vec<String>,
    pub narrowed: NarrowOutcome,
    /// Every bound the closed subset required for this selection, each
    /// carrying its suggestion and provenance when the pipeline could derive
    /// one. Used to annotate resolved bounds with a `# derived from ...`
    /// comment; a need still unresolved is already covered by
    /// `narrowed.unresolved` and gets a TODO comment instead.
    pub needs: Vec<BoundNeed>,
    /// Where the OpenAPI document was read from, echoed back in
    /// `equivalent_command`.
    pub openapi: SpecSource,
    /// The sample file path, if one was used, echoed back in
    /// `equivalent_command`.
    pub sample_path: Option<PathBuf>,
    /// The deployment project the draft was (or would be) written into,
    /// echoed back in `equivalent_command`.
    pub project: Option<PathBuf>,
}

/// The outcome of running `evidence check` against a written draft.
///
/// Bundle-stage failures and secret/runtime-stage failures are distinguished
/// by the runtime's own fixed stderr messages: bundle rejection prints
/// "deployment ..." text, while secret/runtime initialization failure prints
/// "runtime ... initialization failed" — which means the bundle itself was
/// already accepted, only local secret material is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CheckClassification {
    /// `evidence check` passed outright.
    BundleAccepted,
    /// The bundle was rejected; `stderr` is the runtime's captured message.
    BundleRejected { stderr: String },
    /// The bundle was accepted, but local secret material has not been
    /// provisioned yet (expected for a freshly drafted project).
    SecretsUnprovisioned,
}

/// An OpenAPI server URL split into the two places the runtime keeps its
/// parts: `baseUrl` is validated as an origin, so any path the server URL
/// carried belongs on the request path instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSuggestion {
    /// Scheme, host and optional port, with no trailing slash.
    pub base_url: String,
    /// The path the server URL carried, without a trailing slash, or the
    /// empty string when it carried none.
    pub path_prefix: String,
}

/// Splits an OpenAPI server URL into an origin and a path prefix.
///
/// Returns `None` for anything that does not name one fixed origin: a URL with
/// `{variables}`, a relative URL, or one carrying a query or fragment. The
/// caller leaves the origin absent in that case. The origin is not otherwise
/// validated here because it remains a review suggestion, not source policy.
pub fn split_server_url(url: &str) -> Option<ServerSuggestion> {
    if url.contains(['{', '}', '?', '#', ' ']) {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(position) => (&rest[..position], &rest[position..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let path_prefix = path.trim_end_matches('/');
    Some(ServerSuggestion {
        base_url: format!("{scheme}://{authority}"),
        path_prefix: path_prefix.to_owned(),
    })
}

/// The get_path pointer byte-length ceiling the runtime enforces.
const GET_PATH_MAX_BYTES: usize = 256;
/// The get_path pointer segment-count ceiling the runtime enforces.
const GET_PATH_MAX_SEGMENTS: usize = 16;

/// The two methods an Evidence fixed request admits.
const ADMITTED_METHODS: [&str; 2] = ["GET", "POST"];

/// Draft the response schema, extract-script skeleton, facts-schema stub,
/// pasteable source block, human report, and equivalent command for one
/// source, from already-decided inputs.
pub fn draft(inputs: &EmitInputs) -> Result<DraftArtifacts> {
    let method = request_method(&inputs.operation.method)?;

    let mut get_paths = Vec::with_capacity(inputs.selection.len());
    for pointer in &inputs.selection {
        let derived = get_path_pointer(pointer).with_context(|| {
            format!(
                "preparing the extract script for source `{}`",
                inputs.source_id
            )
        })?;
        get_paths.push((pointer.clone(), derived));
    }

    let files = vec![
        DraftFile {
            bundle_relative_path: format!("adapters/{}-prepare.rhai", inputs.source_id),
            contents: render_prepare_script(),
        },
        DraftFile {
            bundle_relative_path: format!("schemas/{}-parameters.schema.yaml", inputs.source_id),
            contents: render_parameters_schema(),
        },
        DraftFile {
            bundle_relative_path: format!("schemas/{}-response.schema.yaml", inputs.source_id),
            contents: render_response_schema(inputs),
        },
        DraftFile {
            bundle_relative_path: format!("adapters/{}-extract.rhai", inputs.source_id),
            contents: render_extract_script(inputs, &get_paths),
        },
        DraftFile {
            bundle_relative_path: format!("schemas/{}-facts.schema.yaml", inputs.source_id),
            contents: render_facts_schema(&inputs.source_id),
        },
    ];

    Ok(DraftArtifacts {
        source_id: inputs.source_id.clone(),
        files,
        authoring_source: render_authoring_source(inputs),
        source_block: render_source_block(inputs, method),
        report: render_report(inputs),
        equivalent_command: render_equivalent_command(inputs),
    })
}

fn render_prepare_script() -> String {
    r#"fn prepare(selectors, context) {
    let parameters = context["parameters"];
    // TODO(evidencectl): bind only reviewed selector fields and fixed parameters.
    #{query: [], body: ()}
}
"#
    .to_owned()
}

fn render_parameters_schema() -> String {
    r#"# TODO(evidencectl): replace with the closed schema for this source's own
# reviewed adapter parameters. A transport: http-json source must declare at
# least one; the closed Version 1 schema subset has no empty-object schema.
type: object
additionalProperties: false
required: []
properties: {}
"#
    .to_owned()
}

/// Checks the operation's method against the runtime's fixed-request method
/// enumeration, which holds two members. Anything else is refused by name
/// rather than drafted into a source the runtime would reject.
pub fn request_method(method: &str) -> Result<&'static str> {
    let upper = method.to_ascii_uppercase();
    ADMITTED_METHODS
        .into_iter()
        .find(|admitted| *admitted == upper)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "an Evidence fixed request declares method GET or POST; `{method}` is outside \
                 that enumeration, so no source can call this operation"
            )
        })
}

/// The request path the source declares: the OpenAPI operation path with the
/// server URL's path prefix, if any, in front of it.
fn request_path(inputs: &EmitInputs) -> String {
    let prefix = inputs
        .base_url_suggestion
        .as_ref()
        .map(|server| server.path_prefix.as_str())
        .unwrap_or_default();
    format!("{prefix}{}", inputs.operation.path)
}

/// Write every draft file under `<project>/bundle/`, creating parent
/// directories as needed. Refuses to overwrite any existing file: if any
/// target already exists, nothing is written and the error lists every
/// collision so the caller can resolve them all at once.
#[allow(dead_code)]
pub fn write_into_project(project: &Path, files: &[DraftFile]) -> Result<Vec<PathBuf>> {
    let bundle_directory = project.join("bundle");
    let targets: Vec<PathBuf> = files
        .iter()
        .map(|file| bundle_directory.join(&file.bundle_relative_path))
        .collect();

    let collisions: Vec<String> = targets
        .iter()
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
        .collect();
    if !collisions.is_empty() {
        bail!(
            "refusing to overwrite existing file(s): {}",
            collisions.join(", ")
        );
    }

    for (file, target) in files.iter().zip(&targets) {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating the directory {}", parent.display()))?;
        }
        fs::write(target, &file.contents)
            .with_context(|| format!("writing {}", target.display()))?;
    }
    Ok(targets)
}

/// Write one complete editable source draft into an authoring project.
///
/// The authoring project owns this layout. The deployment-shaped print-only
/// draft remains available without `--project`, but local `dev` consumes this
/// source directory directly after its explicit review fields are completed.
pub fn write_into_authoring_project(
    project: &Path,
    artifacts: &DraftArtifacts,
) -> Result<Vec<PathBuf>> {
    for directory in ["sources", "adapters", "schemas"] {
        let path = project.join(directory);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspecting authoring directory {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "authoring directory {} must be a plain directory created by `evidencectl new`",
                path.display()
            );
        }
    }
    let source_path = project
        .join("sources")
        .join(format!("{}.yaml", artifacts.source_id));
    let mut targets = vec![source_path];
    targets.extend(
        artifacts
            .files
            .iter()
            .map(|file| project.join(&file.bundle_relative_path)),
    );

    let collisions = targets
        .iter()
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    if !collisions.is_empty() {
        bail!(
            "refusing to overwrite existing file(s): {}",
            collisions.join(", ")
        );
    }
    let mut contents = vec![artifacts.authoring_source.as_bytes()];
    contents.extend(artifacts.files.iter().map(|file| file.contents.as_bytes()));
    let mut written = Vec::new();
    for (target, contents) in targets.iter().zip(contents) {
        if let Err(error) = write_new_authoring_file(target, contents) {
            for path in &written {
                let _ = fs::remove_file(path);
            }
            return Err(error);
        }
        written.push(target.clone());
    }
    Ok(targets)
}

fn write_new_authoring_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::{fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("persisting {}", path.display()))
}

/// Run `evidence --runtime <project>/runtime.yaml check` and classify the
/// result. `evidence_bin` resolves the same way as the other `evidencectl`
/// subcommands that shell out to the runtime binary: an explicit path, else
/// `EVIDENCE_BIN`, else the first `evidence` found on `PATH`, and the
/// resolved binary identifies itself as this build's runtime before any
/// classification is made.
#[allow(dead_code)]
pub fn verify(project: &Path, evidence_bin: Option<&Path>) -> Result<CheckClassification> {
    let evidence_bin = crate::evidence_binary::resolve_matching(evidence_bin)
        .context("resolving the evidence binary")?;
    let runtime_path = project.join("runtime.yaml");

    let output = Command::new(&evidence_bin)
        .arg("--runtime")
        .arg(&runtime_path)
        .arg("check")
        .output()
        .with_context(|| format!("failed to run {}", evidence_bin.display()))?;

    if output.status.success() {
        return Ok(CheckClassification::BundleAccepted);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if is_secrets_unprovisioned(&stderr) {
        return Ok(CheckClassification::SecretsUnprovisioned);
    }
    Ok(CheckClassification::BundleRejected { stderr })
}

/// The runtime initialization stages that fail only because local secret or
/// key material has not been provisioned yet. Reaching any of them means the
/// bundle itself was already accepted.
///
/// The list is exact rather than a `runtime ... initialization failed` shape,
/// because the runtime reports bundle, source and rate-limit failures through
/// the same shape. Matching the shape would report a draft the runtime refused
/// as a success.
#[allow(dead_code)]
const SECRET_STAGE_MESSAGES: [&str; 3] = [
    "evidence: runtime secret initialization failed",
    "evidence: runtime audit initialization failed",
    "evidence: runtime signing initialization failed",
];

/// True when `stderr` names one of [`SECRET_STAGE_MESSAGES`].
///
/// The comparison is a prefix so a stage message that grows a trailing reason
/// still classifies; the stage name itself is still matched in full.
#[allow(dead_code)]
fn is_secrets_unprovisioned(stderr: &str) -> bool {
    let trimmed = stderr.trim();
    SECRET_STAGE_MESSAGES
        .iter()
        .any(|message| trimmed.starts_with(message))
}

/// Derive a plain RFC 6901 `get_path` pointer from an extended projection
/// pointer by substituting `0` for every `*` wildcard segment, then enforce
/// the runtime's byte-length and segment-count ceilings.
fn get_path_pointer(extended_pointer: &str) -> Result<String> {
    let derived = extended_pointer
        .split('/')
        .map(|segment| if segment == "*" { "0" } else { segment })
        .collect::<Vec<_>>()
        .join("/");

    if derived.len() > GET_PATH_MAX_BYTES {
        bail!(
            "selection pointer {extended_pointer} produces a get_path pointer of {} bytes, exceeding the {GET_PATH_MAX_BYTES}-byte ceiling",
            derived.len()
        );
    }
    let segment_count = derived.split('/').filter(|s| !s.is_empty()).count();
    if segment_count > GET_PATH_MAX_SEGMENTS {
        bail!(
            "selection pointer {extended_pointer} produces a get_path pointer of {segment_count} segments, exceeding the {GET_PATH_MAX_SEGMENTS}-segment ceiling"
        );
    }
    Ok(derived)
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

/// How a derived bound is described wherever it is reported: in a schema
/// comment, in the report, and in the auto-acceptance notes a flag-driven run
/// prints. One phrasing keeps those three consistent.
///
/// [`Provenance::Operator`] has no label here, because a value the operator
/// typed was not derived from anything: it is reported separately, and calling
/// it a derivation would misattribute a human decision to the tool.
pub(super) fn provenance_label(provenance: &Provenance) -> Option<&'static str> {
    match provenance {
        Provenance::Spec => Some("the OpenAPI schema"),
        Provenance::Format => Some("its declared format"),
        Provenance::Sample => Some("the sample response (widened)"),
        Provenance::PageSize => Some("a page-size parameter in the spec"),
        Provenance::SubsetCeiling => {
            Some("the subset ceiling, because the document states a larger bound")
        }
        Provenance::Operator => None,
    }
}

/// The comment written above a bound the operator chose themselves.
const OPERATOR_CHOICE_COMMENT: &str = "# chosen at the prompt";

/// The caution shown wherever a bound the tool guessed is announced.
///
/// Only a sampled integer earns one. A page of results says how long that page
/// was, but an integer field is usually a counter, and the highest value one
/// response happened to carry is no statement about how high it can climb;
/// under-sizing that ceiling rejects real responses later. Every other
/// derivation reads a stated bound rather than guessing at one.
pub(super) fn review_note(kind: &BoundKind, provenance: &Provenance) -> Option<&'static str> {
    match (kind, provenance) {
        (BoundKind::IntegerRange, Provenance::Sample) => {
            Some("a counter usually needs a more generous ceiling than one response shows")
        }
        _ => None,
    }
}

/// Re-attributes to the operator every bound whose accepted value differs from
/// what the pipeline suggested, so the draft's comments and the report describe
/// what actually happened.
///
/// A suggestion adopted unchanged keeps its real provenance: the operator
/// confirming a derivation does not make the derivation theirs. A need the
/// operator answered where nothing was suggested, and one whose suggestion they
/// edited, both become [`Provenance::Operator`] carrying the accepted value.
pub fn attribute_operator_edits(
    needs: &mut [BoundNeed],
    resolutions: &BTreeMap<(String, BoundKind), BoundValues>,
) {
    for need in needs.iter_mut() {
        let key = (need.pointer.clone(), need.kind.clone());
        let Some(accepted) = resolutions.get(&key) else {
            continue;
        };
        if need
            .suggestion
            .as_ref()
            .is_some_and(|suggestion| &suggestion.values == accepted)
        {
            continue;
        }
        need.suggestion = Some(SuggestedBound {
            values: accepted.clone(),
            provenance: Provenance::Operator,
        });
    }
}

/// Tracks which (pointer, kind) bound needs are still unresolved (get a TODO
/// comment) versus resolved with known provenance (get a "derived from"
/// comment), so the schema renderer can annotate each node as it recurses.
struct SchemaAnnotations {
    unresolved: BTreeSet<(String, BoundKind)>,
    provenance: BTreeMap<(String, BoundKind), Provenance>,
}

impl SchemaAnnotations {
    fn new(narrowed: &NarrowOutcome, needs: &[BoundNeed]) -> Self {
        let unresolved: BTreeSet<(String, BoundKind)> = narrowed
            .unresolved
            .iter()
            .map(|need| (need.pointer.clone(), need.kind.clone()))
            .collect();

        let mut provenance = BTreeMap::new();
        for need in needs {
            let key = (need.pointer.clone(), need.kind.clone());
            if unresolved.contains(&key) {
                continue;
            }
            if let Some(suggestion) = &need.suggestion {
                provenance.insert(key, suggestion.provenance.clone());
            }
        }

        Self {
            unresolved,
            provenance,
        }
    }

    fn comment_for(&self, pointer: &str, kind: BoundKind) -> Option<String> {
        let key = (pointer.to_owned(), kind.clone());
        if self.unresolved.contains(&key) {
            return Some(format!(
                "# TODO(evidencectl): {} needs {}",
                display_pointer(pointer),
                kind.label()
            ));
        }
        self.provenance.get(&key).map(|provenance| {
            provenance_label(provenance).map_or_else(
                || OPERATOR_CHOICE_COMMENT.to_owned(),
                |label| format!("# derived from {label}"),
            )
        })
    }
}

/// Renders a pointer for a message, naming the root rather than printing an
/// empty string. Matches the wording `narrow` and `flatten` already use.
fn display_pointer(pointer: &str) -> &str {
    if pointer.is_empty() {
        "(response root)"
    } else {
        pointer
    }
}

fn push_line(out: &mut String, indent: usize, text: &str) {
    for _ in 0..indent {
        out.push_str("  ");
    }
    out.push_str(text);
    out.push('\n');
}

fn yaml_scalar_string(value: &str) -> String {
    quote_if(value, needs_yaml_quoting(value))
}

/// A scalar written inside a flow sequence. There `,`, `[`, `]`, `{` and `}`
/// are significant wherever they appear, not only at the start of the scalar:
/// an unquoted `pending, review` would read as two members.
fn yaml_flow_scalar_string(value: &str) -> String {
    let quoted = needs_yaml_quoting(value) || value.contains([',', '[', ']', '{', '}']);
    quote_if(value, quoted)
}

fn quote_if(value: &str, quoted: bool) -> String {
    if quoted {
        format!("\"{}\"", escape_double_quoted(value))
    } else {
        value.to_owned()
    }
}

/// Escapes `value` for the interior of a double-quoted YAML or Rhai string.
///
/// One function serves both because the two grammars agree on every escape
/// used here: `\\`, `\"`, `\n`, `\r`, `\t`, and `\xNN` for the remaining
/// control characters, all of which are below `U+00A0` and so fit two hex
/// digits.
///
/// Every value passed here originates in the OpenAPI document: property names,
/// media types, enum members. A property name may legally contain a quote, a
/// backslash or a control character, and none of those may reach the output
/// raw. A raw newline folds a YAML scalar (turning the rest of the value into
/// a sibling mapping entry) and terminates a Rhai literal; a raw quote ends
/// either one early.
fn escape_double_quoted(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str(r"\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str(r"\n"),
            '\r' => escaped.push_str(r"\r"),
            '\t' => escaped.push_str(r"\t"),
            control if control.is_control() => {
                escaped.push_str(&format!(r"\x{:02x}", control as u32));
            }
            other => escaped.push(other),
        }
    }
    escaped
}

/// Renders `value` as a complete double-quoted Rhai string literal.
fn rhai_string_literal(value: &str) -> String {
    format!("\"{}\"", escape_double_quoted(value))
}

fn needs_yaml_quoting(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if matches!(
        value,
        "true" | "false" | "null" | "~" | "yes" | "no" | "Yes" | "No" | "TRUE" | "FALSE" | "NULL"
    ) {
        return true;
    }
    if value.trim() != value {
        return true;
    }
    if value.parse::<f64>().is_ok() {
        return true;
    }
    let first = value.chars().next().expect("checked non-empty above");
    if matches!(
        first,
        '-' | '?'
            | ':'
            | ','
            | '['
            | ']'
            | '{'
            | '}'
            | '#'
            | '&'
            | '*'
            | '!'
            | '|'
            | '>'
            | '\''
            | '"'
            | '%'
            | '@'
            | '`'
    ) {
        return true;
    }
    // A bare colon or hash is fine in a plain scalar (e.g. `https://...`); it
    // is only ambiguous with a mapping key or a comment when followed by
    // whitespace, or when a colon ends the scalar entirely.
    if value.contains(": ") || value.ends_with(':') || value.contains(" #") {
        return true;
    }
    // Any control character, not just a newline: a plain scalar carrying one
    // either folds or is rejected outright, and the quoted form escapes it.
    value.chars().any(char::is_control)
}

fn render_key(key: &str) -> String {
    yaml_scalar_string(key)
}

fn render_scalar(value: &Value) -> String {
    render_scalar_with(value, yaml_scalar_string)
}

fn render_flow_scalar(value: &Value) -> String {
    render_scalar_with(value, yaml_flow_scalar_string)
}

fn render_scalar_with(value: &Value, quote: fn(&str) -> String) -> String {
    match value {
        Value::String(s) => quote(s),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}

fn render_flow_list(items: &[Value]) -> String {
    let rendered: Vec<String> = items.iter().map(render_flow_scalar).collect();
    format!("[{}]", rendered.join(", "))
}

/// A `const` value, which the closed subset admits as a scalar or as a
/// sequence (an array node may be pinned to one exact list).
fn render_const_value(value: &Value) -> String {
    match value {
        Value::Array(items) => render_flow_list(items),
        other => render_scalar(other),
    }
}

fn render_type(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => render_flow_list(items),
        other => render_scalar(other),
    }
}

fn primary_type_name(object: &serde_json::Map<String, Value>) -> Option<&str> {
    match object.get("type") {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .find(|s| *s != "null"),
        _ => None,
    }
}

fn bound_kind_of(object: &serde_json::Map<String, Value>) -> Option<BoundKind> {
    match primary_type_name(object) {
        Some("array") => Some(BoundKind::ArrayMaxItems),
        Some("integer") => Some(BoundKind::IntegerRange),
        Some("string") => Some(BoundKind::StringLength),
        _ => None,
    }
}

fn render_response_schema(inputs: &EmitInputs) -> String {
    let annotations = SchemaAnnotations::new(&inputs.narrowed, &inputs.needs);
    let mut out = String::new();
    push_line(
        &mut out,
        0,
        &format!(
            "# Closed schema for the projected response of {}. The runtime checks it",
            inputs.source_id
        ),
    );
    push_line(
        &mut out,
        0,
        "# before the extract script runs, so the script maps a response whose shape",
    );
    push_line(
        &mut out,
        0,
        "# it can rely on and never re-checks presence or type by hand.",
    );
    push_line(&mut out, 0, "#");
    push_line(
        &mut out,
        0,
        "# Generated by `evidencectl source suggest`. Every TODO below blocks",
    );
    push_line(
        &mut out,
        0,
        "# `evidence check` until it is resolved by hand; every \"derived from\" comment",
    );
    push_line(
        &mut out,
        0,
        "# states where a bound came from so it can be reviewed rather than trusted",
    );
    push_line(&mut out, 0, "# blindly.");
    // A response body that is itself an array needs a `maxItems` like any other
    // array, but the root node has no property line to hang the comment on:
    // `render_schema_node` annotates children only. It is annotated here or
    // nowhere.
    if let Some(kind) = inputs.narrowed.schema.as_object().and_then(bound_kind_of) {
        if let Some(comment) = annotations.comment_for("", kind) {
            push_line(&mut out, 0, &comment);
        }
    }
    render_schema_node(&inputs.narrowed.schema, "", 0, &annotations, &mut out);
    out
}

fn render_schema_node(
    node: &Value,
    pointer: &str,
    indent: usize,
    annotations: &SchemaAnnotations,
    out: &mut String,
) {
    let Some(object) = node.as_object() else {
        return;
    };
    if let Some(type_value) = object.get("type") {
        push_line(out, indent, &format!("type: {}", render_type(type_value)));
    }
    match primary_type_name(object) {
        Some("object") => {
            if let Some(additional) = object.get("additionalProperties") {
                push_line(
                    out,
                    indent,
                    &format!("additionalProperties: {}", render_scalar(additional)),
                );
            }
            if let Some(required) = object.get("required").and_then(Value::as_array) {
                push_line(
                    out,
                    indent,
                    &format!("required: {}", render_flow_list(required)),
                );
            }
            if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                push_line(out, indent, "properties:");
                for (key, child) in properties {
                    let child_pointer = format!("{pointer}/{}", escape_pointer_segment(key));
                    if let Some(kind) = child.as_object().and_then(bound_kind_of) {
                        if let Some(comment) = annotations.comment_for(&child_pointer, kind) {
                            push_line(out, indent + 1, &comment);
                        }
                    }
                    push_line(out, indent + 1, &format!("{}:", render_key(key)));
                    render_schema_node(child, &child_pointer, indent + 2, annotations, out);
                }
            }
        }
        Some("array") => {
            if let Some(min_items) = object.get("minItems") {
                push_line(
                    out,
                    indent,
                    &format!("minItems: {}", render_scalar(min_items)),
                );
            }
            if let Some(max_items) = object.get("maxItems") {
                push_line(
                    out,
                    indent,
                    &format!("maxItems: {}", render_scalar(max_items)),
                );
            }
            if object.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
                push_line(out, indent, "uniqueItems: true");
            }
            if let Some(const_value) = object.get("const") {
                push_line(
                    out,
                    indent,
                    &format!("const: {}", render_const_value(const_value)),
                );
            }
            if let Some(items) = object.get("items") {
                // An array of scalars never reaches the object-properties loop
                // below, so a bound demanded of the items node is annotated
                // here or nowhere.
                let child_pointer = format!("{pointer}/*");
                if let Some(kind) = items.as_object().and_then(bound_kind_of) {
                    if let Some(comment) = annotations.comment_for(&child_pointer, kind) {
                        push_line(out, indent, &comment);
                    }
                }
                push_line(out, indent, "items:");
                render_schema_node(items, &child_pointer, indent + 1, annotations, out);
            }
        }
        _ => {
            for key in ["minimum", "maximum", "minLength", "maxLength"] {
                if let Some(value) = object.get(key) {
                    push_line(out, indent, &format!("{key}: {}", render_scalar(value)));
                }
            }
            if let Some(format_value) = object.get("format") {
                push_line(
                    out,
                    indent,
                    &format!("format: {}", render_scalar(format_value)),
                );
            }
            if let Some(enum_values) = object.get("enum").and_then(Value::as_array) {
                push_line(
                    out,
                    indent,
                    &format!("enum: {}", render_flow_list(enum_values)),
                );
            }
            if let Some(const_value) = object.get("const") {
                push_line(
                    out,
                    indent,
                    &format!("const: {}", render_const_value(const_value)),
                );
            }
        }
    }
}

fn render_facts_schema(source_id: &str) -> String {
    let mut out = String::new();
    push_line(
        &mut out,
        0,
        "# Closed schema for the facts extraction may hand to the derivation for",
    );
    push_line(
        &mut out,
        0,
        &format!("# {source_id}. Extraction output that does not match exactly is"),
    );
    push_line(&mut out, 0, "# rejected before any derivation runs.");
    push_line(&mut out, 0, "#");
    push_line(
        &mut out,
        0,
        "# TODO(evidencectl): replace placeholder_fact with the real fact(s) this",
    );
    push_line(
        &mut out,
        0,
        "# source's extract script produces, and give each one real bounds.",
    );
    push_line(&mut out, 0, "type: object");
    push_line(&mut out, 0, "additionalProperties: false");
    push_line(&mut out, 0, "required: [placeholder_fact]");
    push_line(&mut out, 0, "properties:");
    push_line(
        &mut out,
        1,
        "# TODO(evidencectl): rename and bound this placeholder fact.",
    );
    push_line(&mut out, 1, "placeholder_fact:");
    push_line(&mut out, 2, "type: string");
    push_line(&mut out, 2, "minLength: 1");
    push_line(&mut out, 2, "maxLength: 256");
    out
}

/// The commented loop sketch shown beside a selection that crosses an array,
/// as `(indentation, code)` pairs.
///
/// Every construct in it is one the runtime's Rhai engine actually registers:
/// an array is reached by its own pointer with `get_path`, guarded with
/// `is_missing`, and iterated with `for`. The engine disables ranges, exposes
/// `len` as a property rather than a method, and defines no `string + integer`
/// operator, so a sketch built from any of those would not run if pasted.
///
/// Each array the pointer crosses is named by its own pointer relative to the
/// element that contains it, so a nested array is reached from the outer
/// element rather than from the response root.
fn loop_sketch(extended_pointer: &str) -> Vec<(usize, String)> {
    let parts: Vec<&str> = extended_pointer.split("/*").collect();
    let Some((remainder, arrays)) = parts.split_last() else {
        return Vec::new();
    };
    if arrays.is_empty() {
        return Vec::new();
    }

    let mut lines = Vec::new();
    let mut indent = 4;
    for (depth, array_pointer) in arrays.iter().enumerate() {
        let level = depth + 1;
        let container = if depth == 0 {
            "source_response".to_owned()
        } else {
            format!("element_{depth}")
        };
        lines.push((
            indent,
            format!("let items_{level} = get_path({container}, \"{array_pointer}\");"),
        ));
        lines.push((indent, format!("if !is_missing(items_{level}) {{")));
        indent += 4;
        lines.push((indent, format!("for element_{level} in items_{level} {{")));
        indent += 4;
    }

    let innermost = arrays.len();
    if remainder.is_empty() {
        lines.push((
            indent,
            format!("// element_{innermost} is the value at {extended_pointer}"),
        ));
    } else {
        lines.push((
            indent,
            format!("let value = get_path(element_{innermost}, \"{remainder}\");"),
        ));
        lines.push((indent, "// ...".to_owned()));
    }
    for _ in arrays {
        indent -= 4;
        lines.push((indent, "}".to_owned()));
        indent -= 4;
        lines.push((indent, "}".to_owned()));
    }
    lines
}

fn render_extract_script(inputs: &EmitInputs, get_paths: &[(String, String)]) -> String {
    let mut out = String::new();
    push_line(
        &mut out,
        0,
        "// Fact extraction skeleton generated by `evidencectl source suggest` for",
    );
    push_line(
        &mut out,
        0,
        &format!("// {} {}.", inputs.operation.method, inputs.operation.path),
    );
    push_line(
        &mut out,
        0,
        "// The response schema has already rejected anything outside its declared",
    );
    push_line(
        &mut out,
        0,
        "// shape, so get_path below never needs a presence or type check beyond",
    );
    push_line(
        &mut out,
        0,
        "// is_missing. What remains is deciding how the selected leaves relate, which",
    );
    push_line(
        &mut out,
        0,
        "// cardinality outcome they mean, and which facts the derivation needs.",
    );
    push_line(&mut out, 0, "//");
    push_line(
        &mut out,
        0,
        "// TODO(evidencectl): decide how this response distinguishes zero, one, and",
    );
    push_line(
        &mut out,
        0,
        "// multiple matches, and return the matching outcome instead of the",
    );
    push_line(&mut out, 0, "// unconditional match below.");
    push_line(&mut out, 0, "fn extract(source_response, context) {");

    for (index, (extended_pointer, get_path_pointer)) in get_paths.iter().enumerate() {
        let variable = format!("leaf_{}", index + 1);
        push_line(
            &mut out,
            1,
            &format!(
                "let {variable} = get_path(source_response, {});",
                rhai_string_literal(get_path_pointer)
            ),
        );
        push_line(&mut out, 1, &format!("if is_missing({variable}) {{"));
        push_line(
            &mut out,
            2,
            &format!("// TODO(evidencectl): decide what an absent {extended_pointer} means here."),
        );
        push_line(&mut out, 1, "}");
        if extended_pointer.contains('*') {
            push_line(
                &mut out,
                1,
                &format!("// TODO(evidencectl): {extended_pointer} is under an array; the index 0"),
            );
            push_line(
                &mut out,
                1,
                "// pointer above only reaches the first element. Iterate every element once",
            );
            push_line(
                &mut out,
                1,
                "// the cardinality check above is written, for example:",
            );
            for (sketch_indent, code) in loop_sketch(extended_pointer) {
                let padding = " ".repeat(sketch_indent);
                push_line(&mut out, 1, &format!("// {padding}{code}"));
            }
        }
        out.push('\n');
    }

    push_line(&mut out, 1, "#{outcome: \"match\", facts: #{}}");
    out.push_str("}\n");
    out
}

/// Render only facts established mechanically by the selected OpenAPI
/// operation. Governed source policy remains absent rather than receiving a
/// plausible-looking default.
fn render_source_block(inputs: &EmitInputs, method: &str) -> String {
    let mut out = String::new();
    push_line(&mut out, 0, "sources:");
    push_line(&mut out, 1, &format!("{}:", render_key(&inputs.source_id)));
    push_line(&mut out, 2, "transport: http-json");
    if let Some(base_url) = &inputs.base_url {
        push_line(
            &mut out,
            2,
            &format!("baseUrl: {}", yaml_scalar_string(base_url)),
        );
    } else {
        match &inputs.base_url_suggestion {
            Some(server) => {
                push_line(
                    &mut out,
                    2,
                    "# Review the OpenAPI server origin before adding it to source policy:",
                );
                push_line(
                    &mut out,
                    2,
                    &format!("# baseUrl: {}", yaml_scalar_string(&server.base_url)),
                );
            }
            None => push_line(
                &mut out,
                2,
                "# Add a reviewed fixed baseUrl; the OpenAPI document gives no fixed origin.",
            ),
        }
    }
    push_line(&mut out, 2, "request:");
    push_line(&mut out, 3, &format!("method: {method}"));
    let path = request_path(inputs);
    if path.contains(['{', '}']) {
        push_line(
            &mut out,
            3,
            &format!("pathTemplate: {}", yaml_scalar_string(&path)),
        );
    } else {
        push_line(&mut out, 3, &format!("path: {}", yaml_scalar_string(&path)));
    }
    push_line(&mut out, 3, "fixedHeaders:");
    push_line(&mut out, 4, "- name: Accept");
    push_line(
        &mut out,
        5,
        &format!("value: {}", yaml_scalar_string(&inputs.media_type)),
    );
    let selection_values: Vec<Value> = inputs
        .selection
        .iter()
        .cloned()
        .map(Value::String)
        .collect();
    push_line(
        &mut out,
        3,
        &format!("projection: {}", render_flow_list(&selection_values)),
    );
    push_line(
        &mut out,
        2,
        &format!(
            "responseSchema: schemas/{}-response.schema.yaml",
            inputs.source_id
        ),
    );
    push_line(
        &mut out,
        2,
        &format!("extractScript: adapters/{}-extract.rhai", inputs.source_id),
    );
    push_line(
        &mut out,
        2,
        &format!("factSchema: schemas/{}-facts.schema.yaml", inputs.source_id),
    );
    out
}

/// Render the existing V1 source object without a surrounding `sources` map.
/// This keeps the authoring artifact identical to the runtime contract.
fn render_authoring_source(inputs: &EmitInputs) -> String {
    let mechanical = render_source_block(
        inputs,
        request_method(&inputs.operation.method).expect("validated method"),
    );
    let mut out = String::new();
    for line in mechanical
        .lines()
        .skip(2)
        .map(|line| line.strip_prefix("    ").unwrap_or(line))
    {
        if line == "request:" {
            push_line(
                &mut out,
                0,
                "# Replace review-required with source-derived, field-projected, or record-transformed.",
            );
            push_line(&mut out, 0, "posture: review-required");
            push_line(
                &mut out,
                0,
                "# Choose an authentication kind and logical secret:file references.",
            );
            push_line(&mut out, 0, "authentication: {kind: review-required}");
        }
        push_line(&mut out, 0, line);
        if line.starts_with("  projection:") {
            push_line(
                &mut out,
                1,
                "# Declare selectorInputs and any complete-segment pathBindings before running dev.",
            );
            push_line(&mut out, 1, "selectorInputs: []");
            push_line(
                &mut out,
                1,
                &format!("prepareScript: adapters/{}-prepare.rhai", inputs.source_id),
            );
            push_line(&mut out, 1, "adapterParameters: {}");
            push_line(
                &mut out,
                1,
                &format!(
                    "adapterParametersSchema: schemas/{}-parameters.schema.yaml",
                    inputs.source_id
                ),
            );
            push_line(&mut out, 1, "preparationLimits:");
            push_line(&mut out, 2, "query: allowed");
            push_line(&mut out, 2, "jsonBody: forbidden");
            push_line(&mut out, 2, "maximumNormalizedBytes: 4096");
            push_line(&mut out, 1, "redirects: deny");
            push_line(&mut out, 1, "timeoutMilliseconds: 3000");
            push_line(&mut out, 1, "maximumResponseBytes: 65536");
            push_line(&mut out, 1, "concurrencyLimit: 8");
        }
    }
    out
}

fn render_report(inputs: &EmitInputs) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "evidencectl source suggest: draft for source `{}` ({} {})\n\n",
        inputs.source_id, inputs.operation.method, inputs.operation.path
    ));

    let unresolved_keys: BTreeSet<(String, BoundKind)> = inputs
        .narrowed
        .unresolved
        .iter()
        .map(|need| (need.pointer.clone(), need.kind.clone()))
        .collect();

    let mut derived_lines = Vec::new();
    let mut chosen_lines = Vec::new();
    for need in &inputs.needs {
        let key = (need.pointer.clone(), need.kind.clone());
        if unresolved_keys.contains(&key) {
            continue;
        }
        let Some(suggestion) = &need.suggestion else {
            continue;
        };
        let note = review_note(&need.kind, &suggestion.provenance)
            .map_or_else(String::new, |note| format!(" ({note})"));
        match provenance_label(&suggestion.provenance) {
            Some(label) => derived_lines.push(format!(
                "  - {} ({}): derived from {label}{note}",
                need.pointer,
                need.kind.label()
            )),
            None => chosen_lines.push(format!("  - {} ({})", need.pointer, need.kind.label())),
        }
    }
    if derived_lines.is_empty() {
        out.push_str("Derived automatically: none.\n\n");
    } else {
        out.push_str("Derived automatically:\n");
        for line in &derived_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    if !chosen_lines.is_empty() {
        out.push_str("Chosen at the prompt:\n");
        for line in &chosen_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "Still needs your input ({}):\n",
        match inputs.narrowed.unresolved.len() {
            0 => "the source block below".to_owned(),
            1 => "1 schema bound, plus the source block below".to_owned(),
            count => format!("{count} schema bounds, plus the source block below"),
        }
    ));
    for need in &inputs.narrowed.unresolved {
        out.push_str(&format!(
            "  - TODO(evidencectl): {} needs {}\n",
            display_pointer(&need.pointer),
            need.kind.label()
        ));
    }
    if inputs.base_url.is_none() {
        out.push_str("  - source origin, ");
    } else {
        out.push_str("  - ");
    }
    out.push_str("posture, authentication, selector bindings, preparation,\n");
    out.push_str("    and request limits are intentionally absent from the mechanical draft.\n\n");

    out.push_str("Next steps:\n");
    out.push_str(&format!(
        "  1. Resolve every TODO(evidencectl) comment in schemas/{}-response.schema.yaml,\n     adapters/{}-extract.rhai, and schemas/{}-facts.schema.yaml.\n",
        inputs.source_id, inputs.source_id, inputs.source_id
    ));
    out.push_str("  2. Review the source block and add the governed source decisions it omits.\n");
    out.push_str("  3. Merge it into a separately authored Evidence project.\n");
    out
}

fn path_display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Quotes one argument of the reproduce command for a POSIX shell.
///
/// The reproduce line is meant to be pasted, and a projection pointer carries
/// `*`: an interactive zsh expands it, and aborts the whole command when it
/// matches nothing. Single quotes are used because they suppress every
/// expansion; the only character they cannot carry is the single quote itself,
/// which is spliced in as `'\''`.
///
/// The decision to quote is an allowlist rather than a list of characters
/// known to be special. A denylist has to be complete to be correct, and the
/// cost of an omission is not a cosmetic one: an unquoted `$` expands a
/// parameter and an unquoted backtick runs a command, so a pointer through a
/// property named `$id` would silently reproduce a different run.
fn shell_quote(value: &str) -> String {
    const SHELL_SAFE: [char; 6] = ['_', '.', '/', ':', '@', '-'];
    let safe = !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || SHELL_SAFE.contains(&character));
    if safe {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn render_equivalent_command(inputs: &EmitInputs) -> String {
    let mut parts: Vec<String> = vec![
        "evidencectl".to_owned(),
        "source".to_owned(),
        "suggest".to_owned(),
    ];

    if inputs.project.is_none() {
        parts.push("--openapi".to_owned());
        parts.push(shell_quote(&inputs.openapi.display()));
    }
    parts.push("--operation".to_owned());
    parts.push(shell_quote(&format!(
        "{} {}",
        inputs.operation.method, inputs.operation.path
    )));
    parts.push("--status".to_owned());
    parts.push(shell_quote(&inputs.status));
    parts.push("--media-type".to_owned());
    parts.push(shell_quote(&inputs.media_type));
    if let Some(sample) = &inputs.sample_path {
        parts.push("--sample".to_owned());
        parts.push(shell_quote(&path_display(sample)));
    }
    parts.push("--source-id".to_owned());
    parts.push(inputs.source_id.clone());
    if let Some(base_url) = &inputs.base_url {
        parts.push("--base-url".to_owned());
        parts.push(shell_quote(base_url));
    }
    if let Some(project) = &inputs.project {
        parts.push("--project".to_owned());
        parts.push(shell_quote(&path_display(project)));
    }
    for pointer in &inputs.selection {
        parts.push("--select".to_owned());
        parts.push(shell_quote(pointer));
    }

    parts.join(" ")
}
