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
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use registry_evidence_authoring::project::{self, Source};
use registry_platform_yaml::LocalId;
use serde_json::{json, Value};

use super::types::{
    BoundKind, BoundNeed, BoundValues, DraftArtifacts, DraftFile, NarrowOutcome, OperationKey,
    Provenance, RequestMapping, RequestTarget, SelectorScalarType, SpecSource, SuggestedBound,
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
    /// Exact UTF-8 bytes of the OpenAPI document that was interpreted. The
    /// generated pack pins these bytes so later tooling never re-fetches or
    /// silently substitutes a different provider contract.
    pub openapi_document: String,
    /// The sample file path, if one was used, echoed back in
    /// `equivalent_command`.
    pub sample_path: Option<PathBuf>,
    /// The deployment project the draft was (or would be) written into,
    /// echoed back in `equivalent_command`.
    pub project: Option<PathBuf>,
    /// Author-validated selector assignments. Empty preserves the incomplete
    /// review draft emitted by earlier releases.
    pub request_mappings: Vec<RequestMapping>,
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

/// Draft one complete pack closure, its thin Source binding, a human report,
/// and the equivalent command from already-decided inputs.
pub fn draft(inputs: &EmitInputs) -> Result<DraftArtifacts> {
    let method = request_method(&inputs.operation.method)?;
    if !inputs.request_mappings.is_empty() {
        validate_mapped_request_path(inputs)
            .context("generated request path is outside the Evidence fixed-request contract")?;
    }

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

    let files = render_pack_files(inputs, method, &get_paths)?;

    Ok(DraftArtifacts {
        source_id: inputs.source_id.clone(),
        files,
        authoring_source: render_authoring_source(inputs),
        source_block: render_source_block(inputs, method),
        report: render_report(inputs),
        equivalent_command: render_equivalent_command(inputs),
    })
}

fn render_pack_files(
    inputs: &EmitInputs,
    method: &str,
    get_paths: &[(String, String)],
) -> Result<Vec<DraftFile>> {
    let pack_root = format!("adapter-packs/{}", inputs.source_id);
    let prepare_path = format!("scripts/{}-prepare.rhai", inputs.source_id);
    let extract_path = format!("scripts/{}-extract.rhai", inputs.source_id);
    let inputs_schema_path = format!("schemas/{}-inputs.schema.json", inputs.source_id);
    let facts_schema_path = format!("schemas/{}-facts.schema.json", inputs.source_id);
    let openapi_path = "openapi/source.openapi.yaml";

    let prepare = render_prepare_script(inputs)?;
    let extract = render_extract_script(inputs, get_paths);
    let inputs_schema = render_inputs_schema(inputs)?;
    let facts_schema = format!(
        "{}\n",
        serde_json::to_string_pretty(&inputs.narrowed.schema)
            .context("rendering the generated facts schema")?
    );
    let pin = |path: &str, contents: &str| {
        json!({
            "path": path,
            "digest": registry_platform_config::sha256_uri(contents.as_bytes())
        })
    };

    let path_parameters = inputs
        .request_mappings
        .iter()
        .enumerate()
        .filter_map(|(index, mapping)| {
            let RequestTarget::Path(name) = &mapping.target else {
                return None;
            };
            Some((
                name.clone(),
                json!({"jsonpath":format!("$.{}", input_name(index))}),
            ))
        })
        .collect::<serde_json::Map<_, _>>();
    let query = inputs
        .request_mappings
        .iter()
        .enumerate()
        .filter_map(|(index, mapping)| {
            let RequestTarget::Query(name) = &mapping.target else {
                return None;
            };
            Some((
                name.clone(),
                json!({"jsonpath":format!("$.{}", input_name(index))}),
            ))
        })
        .collect::<serde_json::Map<_, _>>();
    let mut parameters = json!({
        "httpMethod": method,
        "path": pack_request_path(inputs),
        "operation": "lookup"
    });
    if !path_parameters.is_empty() {
        parameters["pathParameters"] = Value::Object(path_parameters);
    }
    if !query.is_empty() {
        parameters["query"] = Value::Object(query);
    }
    if method == "POST" {
        parameters["body"] = json!({
            "rhai": {"file":prepare_path,"entrypoint":"prepare"}
        });
    }
    let scripts = [pin(&prepare_path, &prepare), pin(&extract_path, &extract)];
    let pack = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/pack/v1alpha1",
        "kind": "AdapterPack",
        "id": inputs.source_id,
        "version": "0.1.0",
        "testedVersions": [],
        "endpoints": [{
            "id": inputs.source_id,
            "component": "http",
            "authentication": {"type":"none"},
            "attemptTimeoutMilliseconds": 3000,
            "maximumResponseBytes": 65536,
            "requestHeaders": ["accept"],
            "responseHeaders": [],
            "operations": [{
                "id":"lookup",
                "safeUpstream": method == "POST"
            }],
            "testedVersions": []
        }],
        "sourceRoutes": [{
            "id": inputs.source_id,
            "scan": "finite",
            "nextRecovery": "exact-replay",
            "edits": "ordered",
            "evidence": {
                "inputsSchema": pin(&inputs_schema_path, &inputs_schema),
                "factsSchema": pin(&facts_schema_path, &facts_schema),
                "acquisitionPosture": "record-transformed"
            },
            "steps": [
                {"setHeader":{"name":"Accept","value":{"constant":inputs.media_type}}},
                {"to":{"uri":format!("http:{}", inputs.source_id),"parameters":parameters}},
                {"setBody":{"rhai":{"file":extract_path,"entrypoint":"extract"}}}
            ]
        }],
        "scripts": scripts,
        "openApi": pin(openapi_path, &inputs.openapi_document),
        "capabilities": {
            "components": ["http"],
            "languages": ["constant", "rhai"],
            "eips": ["setHeader", "to", "setBody"]
        }
    });
    let pack_document = serde_norway::to_string(&pack).context("rendering Adapter pack YAML")?;
    Ok(vec![
        DraftFile {
            bundle_relative_path: format!("{pack_root}/pack.yaml"),
            contents: pack_document,
        },
        DraftFile {
            bundle_relative_path: format!("{pack_root}/{prepare_path}"),
            contents: prepare,
        },
        DraftFile {
            bundle_relative_path: format!("{pack_root}/{extract_path}"),
            contents: extract,
        },
        DraftFile {
            bundle_relative_path: format!("{pack_root}/{inputs_schema_path}"),
            contents: inputs_schema,
        },
        DraftFile {
            bundle_relative_path: format!("{pack_root}/{facts_schema_path}"),
            contents: facts_schema,
        },
        DraftFile {
            bundle_relative_path: format!("{pack_root}/{openapi_path}"),
            contents: inputs.openapi_document.clone(),
        },
    ])
}

fn render_inputs_schema(inputs: &EmitInputs) -> Result<String> {
    let properties = inputs
        .request_mappings
        .iter()
        .enumerate()
        .map(|(index, mapping)| {
            let value_type = match mapping.selector.scalar_type {
                SelectorScalarType::String => "string",
                SelectorScalarType::Integer => "integer",
                SelectorScalarType::Boolean => "boolean",
            };
            (input_name(index), json!({"type":value_type}))
        })
        .collect::<serde_json::Map<_, _>>();
    let required = properties.keys().cloned().collect::<Vec<_>>();
    Ok(format!(
        "{}\n",
        serde_json::to_string_pretty(&json!({
            "$schema":"https://json-schema.org/draft/2020-12/schema",
            "type":"object",
            "additionalProperties":false,
            "properties":properties,
            "required":required
        }))?
    ))
}

fn pack_request_path(inputs: &EmitInputs) -> String {
    request_path(inputs).replace('{', "{{").replace('}', "}}")
}

fn render_prepare_script(inputs: &EmitInputs) -> Result<String> {
    if inputs.request_mappings.is_empty() {
        return Ok(r#"fn prepare(exchange) {
    // TODO(evidencectl): bind only reviewed selector fields and fixed parameters.
    #{}
}
"#
        .to_owned());
    }

    let mut out = String::from("fn prepare(exchange) {\n");
    out.push_str("    let inputs = exchange[\"body\"];\n");
    let body = render_body(inputs)?;
    out.push_str(&format!("    {body}\n"));
    out.push_str("}\n");
    Ok(out)
}

fn input_name(index: usize) -> String {
    format!("input{}", index + 1)
}

fn input_access(inputs: &EmitInputs, mapping: &RequestMapping) -> String {
    let index = inputs
        .request_mappings
        .iter()
        .position(|candidate| std::ptr::eq(candidate, mapping))
        .expect("a rendered mapping belongs to the input list");
    format!("inputs[{}]", rhai_string_literal(&input_name(index)))
}

#[derive(Default)]
struct BodyNode {
    value: Option<String>,
    children: BTreeMap<String, BodyNode>,
}

fn render_body(inputs: &EmitInputs) -> Result<String> {
    let body_mappings = inputs
        .request_mappings
        .iter()
        .filter(|mapping| matches!(mapping.target, RequestTarget::Body(_)))
        .collect::<Vec<_>>();
    if body_mappings.is_empty() {
        return Ok("()".to_owned());
    }
    let mut root = BodyNode::default();
    for mapping in body_mappings {
        let RequestTarget::Body(pointer) = &mapping.target else {
            continue;
        };
        let mut node = &mut root;
        for segment in decode_body_pointer(pointer)? {
            node = node.children.entry(segment).or_default();
        }
        node.value = Some(input_access(inputs, mapping));
    }
    Ok(render_body_node(&root))
}

fn decode_body_pointer(pointer: &str) -> Result<Vec<String>> {
    pointer[1..]
        .split('/')
        .map(|encoded| {
            let mut decoded = String::new();
            let mut chars = encoded.chars();
            while let Some(character) = chars.next() {
                if character != '~' {
                    decoded.push(character);
                } else {
                    match chars.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        _ => bail!("invalid body pointer `{pointer}`"),
                    }
                }
            }
            Ok(decoded)
        })
        .collect()
}

fn render_body_node(node: &BodyNode) -> String {
    if let Some(value) = &node.value {
        return value.clone();
    }
    let entries = node
        .children
        .iter()
        .map(|(key, child)| format!("{}: {}", rhai_string_literal(key), render_body_node(child)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("#{{{entries}}}")
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

/// Mirror the pure FixedRequest path rules without linking the runtime into
/// authoring. The runtime-admission parity test covers the complete rendered
/// path, including its server prefix, bounds, escapes and binding names.
fn validate_mapped_request_path(inputs: &EmitInputs) -> Result<()> {
    let path = request_path(inputs);
    if !(2..=2048).contains(&path.len()) || !path.starts_with('/') || !path.is_ascii() {
        bail!("request paths must be absolute ASCII paths between 2 and 2048 bytes");
    }
    let bindings = inputs
        .request_mappings
        .iter()
        .filter_map(|mapping| {
            if let RequestTarget::Path(name) = &mapping.target {
                Some(name.as_str())
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>();
    let mut placeholders = BTreeSet::new();
    let mut normalized = String::with_capacity(path.len());
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || matches!(segment, "." | "..") {
            bail!("request paths must not contain empty or dot segments");
        }
        normalized.push('/');
        if segment.contains(['{', '}']) {
            let name = segment
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
                .ok_or_else(|| {
                    anyhow::anyhow!("a path placeholder must occupy one complete segment")
                })?;
            LocalId::new(name).with_context(|| {
                format!(
                    "path parameter `{name}` must be a Registry Stack LocalId for a path binding"
                )
            })?;
            if !placeholders.insert(name) {
                bail!("path placeholders must be unique: `{name}` is repeated");
            }
            if !bindings.contains(name) {
                bail!("required request input `path:{name}` has no --map-selector assignment");
            }
            normalized.push('x');
        } else {
            normalized.push_str(segment);
        }
    }
    if placeholders != bindings {
        bail!("path bindings must exactly match the generated path placeholders");
    }
    let bytes = normalized.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
                || bytes[index + 1].is_ascii_lowercase()
                || bytes[index + 2].is_ascii_lowercase()
            {
                bail!("request path contains a non-canonical escape");
            }
            let decoded = u8::from_str_radix(&normalized[index + 1..index + 3], 16)?;
            if decoded.is_ascii_alphanumeric()
                || matches!(decoded, b'-' | b'.' | b'_' | b'~' | b'/' | b'\\')
            {
                bail!("request path contains an ambiguous escape");
            }
            index += 3;
        } else if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'-'
            )
        {
            index += 1;
        } else {
            bail!("request path contains a prohibited character");
        }
    }
    Ok(())
}

/// Write every named Function asset under `<project>/`, creating parent
/// directories as needed. Refuses to overwrite any existing file: if any
/// target already exists, nothing is written and the error lists every
/// collision so the caller can resolve them all at once.
#[allow(dead_code)]
pub fn write_into_project(project: &Path, files: &[DraftFile]) -> Result<Vec<PathBuf>> {
    let targets: Vec<PathBuf> = files
        .iter()
        .map(|file| project.join(&file.bundle_relative_path))
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
    let project_metadata = fs::symlink_metadata(project)
        .with_context(|| format!("inspecting authoring project {}", project.display()))?;
    if project_metadata.file_type().is_symlink() || !project_metadata.is_dir() {
        bail!(
            "authoring project {} must be an existing plain directory",
            project.display()
        );
    }
    let project_path = project.join(project::PROJECT_FILE);
    let project_bytes =
        fs::read(&project_path).with_context(|| format!("reading {}", project_path.display()))?;
    let mut document = project::read_project(project::PROJECT_FILE, &project_bytes)?.value;
    let source_id = LocalId::new(artifacts.source_id.clone())?;
    if document.sources.contains_key(&source_id) {
        bail!(
            "EvidenceProject already defines Source `{}`",
            artifacts.source_id
        );
    }
    let source: Source = serde_json::from_str(&artifacts.authoring_source)
        .context("decoding the generated normalized Source")?;
    document.sources.insert(source_id, source);
    let mut value = serde_json::to_value(&document)?;
    let object = value
        .as_object_mut()
        .expect("EvidenceProject serializes as an object");
    object.insert("apiVersion".to_owned(), json!(project::PROJECT_API_VERSION));
    object.insert("kind".to_owned(), json!(project::PROJECT_KIND));
    let project_text = serde_norway::to_string(&value).context("encoding evidence.yaml")?;
    project::read_project(project::PROJECT_FILE, project_text.as_bytes())
        .context("validating the updated normalized EvidenceProject")?;
    let targets = artifacts
        .files
        .iter()
        .map(|file| {
            let relative = Path::new(&file.bundle_relative_path);
            if relative.as_os_str().is_empty()
                || !relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_)))
            {
                bail!(
                    "draft asset path `{}` must be a non-empty project-relative path",
                    file.bundle_relative_path
                );
            }
            Ok(project.join(relative))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut collisions = Vec::new();
    for path in &targets {
        match fs::symlink_metadata(path) {
            Ok(_) => collisions.push(path.display().to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", path.display()));
            }
        }
    }
    if !collisions.is_empty() {
        bail!(
            "refusing to overwrite existing file(s): {}",
            collisions.join(", ")
        );
    }
    let mut transaction = AuthoringWriteTransaction::default();
    let result = (|| -> Result<Vec<PathBuf>> {
        let mut written = Vec::new();
        for (target, file) in targets.iter().zip(&artifacts.files) {
            transaction.create_missing_parents(project, Path::new(&file.bundle_relative_path))?;
            transaction.write_new_file(target, file.contents.as_bytes())?;
            written.push(target.clone());
        }
        let permissions = fs::metadata(&project_path)?.permissions();
        let mut staged = tempfile::NamedTempFile::new_in(project)
            .context("staging the updated normalized EvidenceProject")?;
        use std::io::Write as _;
        let stage_result = staged.as_file().set_permissions(permissions).and_then(|_| {
            staged
                .write_all(project_text.as_bytes())
                .and_then(|_| staged.as_file().sync_all())
        });
        if let Err(error) = stage_result {
            let error = anyhow::Error::from(error)
                .context("staging the updated normalized EvidenceProject");
            return Err(error_with_staged_file_close(staged, error));
        }
        if let Err(tempfile::PersistError { error, file }) = staged.persist(&project_path) {
            let error = anyhow::Error::from(error)
                .context("publishing the updated normalized EvidenceProject");
            return Err(error_with_staged_file_close(file, error));
        }
        written.push(project_path);
        Ok(written)
    })();
    match result {
        Ok(written) => Ok(written),
        Err(error) => Err(transaction.error_with_rollback(error)),
    }
}

fn error_with_staged_file_close(
    staged: tempfile::NamedTempFile,
    error: anyhow::Error,
) -> anyhow::Error {
    let path = staged.path().to_path_buf();
    match staged.close() {
        Ok(()) => error,
        Err(cleanup) => error.context(format!(
            "removing staged file {} also failed: {cleanup}",
            path.display()
        )),
    }
}

#[derive(Debug)]
enum CreatedAuthoringPath {
    File(PathBuf),
    Directory(PathBuf),
}

#[derive(Debug, Default)]
struct AuthoringWriteTransaction {
    created: Vec<CreatedAuthoringPath>,
}

impl AuthoringWriteTransaction {
    fn create_missing_parents(&mut self, project: &Path, relative: &Path) -> Result<()> {
        let mut current = project.to_path_buf();
        for component in relative.parent().into_iter().flat_map(Path::components) {
            let Component::Normal(name) = component else {
                unreachable!("authoring paths were validated before writing");
            };
            current.push(name);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        bail!(
                            "asset parent {} must be a plain directory",
                            current.display()
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current)
                        .with_context(|| format!("creating directory {}", current.display()))?;
                    self.created
                        .push(CreatedAuthoringPath::Directory(current.clone()));
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspecting asset parent {}", current.display()));
                }
            }
        }
        Ok(())
    }

    fn write_new_file(&mut self, path: &Path, contents: &[u8]) -> Result<()> {
        use std::{fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _};

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        self.created
            .push(CreatedAuthoringPath::File(path.to_path_buf()));
        file.write_all(contents)
            .with_context(|| format!("writing {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("persisting {}", path.display()))
    }

    fn error_with_rollback(self, error: anyhow::Error) -> anyhow::Error {
        let mut failures = Vec::new();
        for created in self.created.into_iter().rev() {
            let (kind, path, result) = match created {
                CreatedAuthoringPath::File(path) => {
                    let result = fs::remove_file(&path);
                    ("file", path, result)
                }
                CreatedAuthoringPath::Directory(path) => {
                    let result = fs::remove_dir(&path);
                    ("directory", path, result)
                }
            };
            if let Err(cleanup) = result {
                if cleanup.kind() != std::io::ErrorKind::NotFound {
                    failures.push(format!("removing {kind} {}: {cleanup}", path.display()));
                }
            }
        }
        if failures.is_empty() {
            error
        } else {
            error.context(format!("rollback also failed: {}", failures.join("; ")))
        }
    }
}

/// Run `evidence check --runtime-config <project>/runtime.yaml` and classify the
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
        .arg("check")
        .arg("--runtime-config")
        .arg(&runtime_path)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
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
        Provenance::Sample => Some("the sample response (widened)"),
        Provenance::PageSize => Some("a page-size parameter in the spec"),
        Provenance::SubsetCeiling => {
            Some("the subset ceiling, because the document states a larger bound")
        }
        Provenance::Operator => None,
    }
}

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

fn render_extract_script(inputs: &EmitInputs, _get_paths: &[(String, String)]) -> String {
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
        "// shape, so the generated closed projection below can retain only the",
    );
    push_line(
        &mut out,
        0,
        "// selected fields. What remains is deciding how those fields relate, which",
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
    let mut projectors = String::new();
    let mut next_projector = 0;
    let root_projector = render_projector(
        &inputs.narrowed.schema,
        &mut next_projector,
        &mut projectors,
    )
    .expect("the narrowed facts schema has a closed object root");
    out.push_str(&projectors);
    push_line(&mut out, 0, "fn extract(exchange) {");
    push_line(&mut out, 1, "let source_response = exchange[\"body\"];");
    push_line(
        &mut out,
        1,
        &format!("#{{lookup: \"matched\", facts: {root_projector}(source_response)}}"),
    );
    out.push_str("}\n");
    out
}

fn render_projector(schema: &Value, next: &mut usize, definitions: &mut String) -> Option<String> {
    let value_type = schema.get("type");
    let is_type = |expected: &str| {
        value_type
            .and_then(Value::as_str)
            .is_some_and(|value| value == expected)
            || value_type
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value == expected))
    };
    if is_type("object") || schema.get("properties").is_some() {
        let name = format!("project_{}", *next);
        *next += 1;
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("a narrowed object schema carries properties");
        let children = properties
            .iter()
            .map(|(key, child)| (key, render_projector(child, next, definitions)))
            .collect::<Vec<_>>();
        definitions.push_str(&format!("fn {name}(value) {{\n    let out = #{{}};\n"));
        for (key, child) in children {
            let key = rhai_string_literal(key);
            definitions.push_str(&format!("    if {key} in value {{\n"));
            match child {
                Some(projector) => definitions.push_str(&format!(
                    "        out[{key}] = {projector}(value[{key}]);\n"
                )),
                None => definitions.push_str(&format!("        out[{key}] = value[{key}];\n")),
            }
            definitions.push_str("    }\n");
        }
        definitions.push_str("    out\n}\n\n");
        return Some(name);
    }
    if is_type("array") {
        let name = format!("project_{}", *next);
        *next += 1;
        let child = schema
            .get("items")
            .and_then(|items| render_projector(items, next, definitions));
        definitions.push_str(&format!("fn {name}(value) {{\n    let out = [];\n"));
        definitions.push_str("    for item in value {\n");
        match child {
            Some(projector) => {
                definitions.push_str(&format!("        out.push({projector}(item));\n"));
            }
            None => definitions.push_str("        out.push(item);\n"),
        }
        definitions.push_str("    }\n    out\n}\n\n");
        return Some(name);
    }
    None
}

/// Render the normalized Source draft, including generated request bindings
/// and the explicit defaults named for review in the report.
fn render_source_block(inputs: &EmitInputs, _method: &str) -> String {
    let source: Value = serde_json::from_str(&render_authoring_source(inputs))
        .expect("generated Source serializes as JSON");
    serde_norway::to_string(&json!({
        "sources":{inputs.source_id.clone():source}
    }))
    .expect("generated Source block renders")
}

/// Render the pack-backed Source binding without a surrounding `sources` map.
fn render_authoring_source(inputs: &EmitInputs) -> String {
    let input_bindings = inputs
        .request_mappings
        .iter()
        .enumerate()
        .map(|(index, mapping)| {
            (
                input_name(index),
                json!({"selector":{
                    "role":mapping.selector.role,
                    "profile":mapping.selector.profile,
                    "field":mapping.selector.field
                }}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let source = json!({
        "pack":{"id":inputs.source_id,"version":"0.1.0"},
        "route":inputs.source_id,
        "connection":inputs.source_id,
        "acquisitionPosture":"record-transformed",
        "inputs":input_bindings
    });
    serde_json::to_string(&source).expect("normalized Source serializes")
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
        out.push_str("  - Set the source origin.\n");
    }
    out.push_str("  - Review the generated Source posture and default source limits.\n");
    out.push_str("  - Configure target-owned authentication.\n");
    if inputs.request_mappings.is_empty() {
        out.push_str("  - Complete selector bindings and the pack request mapping.\n\n");
    } else {
        out.push_str("  - Review the generated selector bindings and pack request mapping.\n\n");
    }

    out.push_str("Next steps:\n");
    out.push_str(&format!(
        "  1. Resolve every TODO(evidencectl) comment in evidence.yaml and\n     adapter-packs/{}/scripts/{}-extract.rhai.\n",
        inputs.source_id,
        inputs.source_id
    ));
    out.push_str(
        "  2. Review the named Source, target connection, target authority, selector bindings, and private facts.\n",
    );
    out.push_str("  3. Complete or update the AssertionDefinitions that acquire this Source.\n");
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

    match &inputs.project {
        Some(project) => parts.push(shell_quote(&path_display(project))),
        None => {
            parts.push("--openapi".to_owned());
            parts.push(shell_quote(&inputs.openapi.display()));
        }
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
    for pointer in &inputs.selection {
        parts.push("--select".to_owned());
        parts.push(shell_quote(pointer));
    }
    for mapping in &inputs.request_mappings {
        parts.push("--map-selector".to_owned());
        parts.push(shell_quote(&format!(
            "{}.{}.{}={}",
            mapping.selector.role,
            mapping.selector.profile,
            mapping.selector.field,
            match &mapping.target {
                RequestTarget::Path(name) => format!("path:{name}"),
                RequestTarget::Query(name) => format!("query:{name}"),
                RequestTarget::Body(pointer) => format!("body:{pointer}"),
            }
        )));
    }

    parts.join(" ")
}
