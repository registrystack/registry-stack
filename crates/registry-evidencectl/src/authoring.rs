//! Compile the deliberately narrow local authoring shape used by the first
//! Evidence tutorial into the runtime's canonical deployment inputs.
//!
//! This module is an internal seam for `dev`. It does not expose another CLI
//! surface and it delegates the final semantic decision to `evidence check`.

#![allow(dead_code)] // Wired by the local runner in the next vertical slice.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read as _,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context as _, Result};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use url::{Host, Url};

const OPENAPI_FILE: &str = "source.openapi.yaml";
const QUESTIONS_DIRECTORY: &str = "questions";
const DERIVATIONS_DIRECTORY: &str = "derivations";
const SECRETS_DIRECTORY: &str = "secrets";
const LOCAL_URI_PREFIX: &str = "urn:registrystack:evidence:local:";
const LOCAL_MINT_ORIGIN: &str = "http://127.0.0.1:8081";
const LOCAL_EVIDENCE_PORT: u16 = 8080;
const LOCAL_AUDIENCE: &str = "registry-evidence-local";
const SIGNING_KEY_ID: &str = "local-signing-key-1";
const SOURCE_ID: &str = "local-source";
const SELECTOR_PROFILE_ID: &str = "local-subject-v1";
const AUTHORITY_PROFILE_ID: &str = "local-caller";
const MAX_OPENAPI_BYTES: u64 = 16 * 1024 * 1024;
const MAX_QUESTION_BYTES: u64 = 64 * 1024;
const MAX_DERIVATION_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompiledConceptForm {
    Boolean,
}

/// Closed metadata consumed later by `dev` and request preparation. It stays
/// in memory here; this compiler does not create a second public artifact.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledQuestion {
    pub(crate) question_alias: String,
    pub(crate) runtime_path: PathBuf,
    pub(crate) requirement_uri: String,
    pub(crate) purpose: String,
    pub(crate) subject_role: String,
    pub(crate) selector_profile: String,
    pub(crate) selector_field: String,
    pub(crate) concept_alias: String,
    pub(crate) concept_uri: String,
    pub(crate) concept_form: CompiledConceptForm,
    pub(crate) local_audience: String,
}

/// Compile one retained OpenAPI operation and one authored question into an
/// unpublished local generation, then ask the real Evidence binary to check
/// the complete result.
///
/// `staging_root` must be an existing, empty, owner-only directory. The caller
/// owns generation publication and process supervision.
pub(crate) fn compile_local_project(
    project_root: &Path,
    staging_root: &Path,
    evidence_bin: &Path,
) -> Result<CompiledQuestion> {
    let project_root = validate_project_root(project_root)?;
    validate_private_empty_staging(staging_root)?;
    validate_evidence_binary(evidence_bin)?;

    // Resolve the complete plan before writing anything. Unsupported or
    // ambiguous authoring inputs therefore leave the staging root empty.
    let inputs = read_inputs(&project_root)?;
    let plan = compile_plan(inputs)?;
    let compilation = write_plan(&project_root, staging_root, &plan)?;

    if let Err(error) = check_with_evidence(evidence_bin, &compilation.runtime_path) {
        // A rejected unpublished generation should remain removable by its
        // owner. No path outside the caller-supplied staging root is changed.
        let _ = set_bundle_modes(&staging_root.join("bundle"), 0o700, 0o600);
        let _ = fs::set_permissions(&compilation.runtime_path, fs::Permissions::from_mode(0o600));
        return Err(error);
    }

    Ok(compilation)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Question {
    id: String,
    question: String,
    purpose: String,
    subject: QuestionSubject,
    source: QuestionSource,
    answer: QuestionAnswer,
    disclosure: QuestionDisclosure,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionSubject {
    role: String,
    selector: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionSource {
    operation: String,
    facts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionAnswer {
    concept: String,
    #[serde(rename = "type")]
    answer_type: AnswerType,
    derivation: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AnswerType {
    Boolean,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionDisclosure {
    allow: Vec<String>,
}

struct Inputs {
    openapi: Value,
    question: Question,
    derivation: String,
}

struct CompilePlan {
    question_id: String,
    derivation_artifact: String,
    purpose: String,
    subject_role: String,
    selector_field: String,
    concept_alias: String,
    requirement_uri: String,
    concept_uri: String,
    bundle: Value,
    response_schema: Value,
    fact_schema: Value,
    adapter_parameters_schema: Value,
    prepare_script: String,
    extract_script: String,
    derivation_script: String,
}

struct Operation<'a> {
    method: &'a str,
    path: &'a str,
    path_item: &'a Map<String, Value>,
    operation: &'a Map<String, Value>,
}

fn validate_project_root(project_root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(project_root)
        .with_context(|| format!("inspecting project root {}", project_root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "project root {} must be a plain directory",
            project_root.display()
        );
    }
    fs::canonicalize(project_root)
        .with_context(|| format!("resolving project root {}", project_root.display()))
}

fn validate_private_empty_staging(staging_root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(staging_root)
        .with_context(|| format!("inspecting staging root {}", staging_root.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        bail!(
            "local compilation staging root {} must be a plain owner-only directory (mode 0700)",
            staging_root.display()
        );
    }
    let mut entries = fs::read_dir(staging_root)
        .with_context(|| format!("reading staging root {}", staging_root.display()))?;
    if entries.next().transpose()?.is_some() {
        bail!("local compilation staging root must be empty");
    }
    Ok(())
}

fn validate_evidence_binary(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspecting evidence binary {}", path.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!(
            "evidence binary {} is not an executable file",
            path.display()
        );
    }
    Ok(())
}

fn read_inputs(project_root: &Path) -> Result<Inputs> {
    let openapi_text = read_regular_file(
        &project_root.join(OPENAPI_FILE),
        MAX_OPENAPI_BYTES,
        "retained OpenAPI document",
    )?;
    let openapi: Value = serde_norway::from_slice(&openapi_text)
        .context("parsing retained OpenAPI document as YAML or JSON")?;
    validate_openapi_version(&openapi)?;

    let question_path = one_question_path(project_root)?;
    let question_bytes = read_regular_file(&question_path, MAX_QUESTION_BYTES, "question")?;
    let question: Question = serde_norway::from_slice(&question_bytes)
        .with_context(|| format!("parsing question {}", question_path.display()))?;
    validate_question(&question)?;

    let derivation_path = project_relative_derivation(project_root, &question.answer.derivation)?;
    let derivation_bytes = read_regular_file(
        &derivation_path,
        MAX_DERIVATION_BYTES,
        "authored derivation",
    )?;
    let derivation =
        String::from_utf8(derivation_bytes).context("authored derivation must be UTF-8")?;
    validate_authored_answer(&derivation)?;

    let secrets = project_root.join(SECRETS_DIRECTORY);
    let secrets_metadata = fs::symlink_metadata(&secrets)
        .with_context(|| format!("inspecting local secret directory {}", secrets.display()))?;
    if secrets_metadata.file_type().is_symlink()
        || !secrets_metadata.is_dir()
        || secrets_metadata.uid() != rustix::process::geteuid().as_raw()
        || secrets_metadata.permissions().mode() & 0o7777 != 0o700
    {
        bail!("local secret directory must be a plain owner-only directory (mode 0700)");
    }

    Ok(Inputs {
        openapi,
        question,
        derivation,
    })
}

/// Parse the authored program as Rhai and reserve `derive` exclusively for
/// the generated binding wrapper. Function discovery comes from the AST, so
/// strings, comments, and whitespace cannot masquerade as entry points.
fn validate_authored_answer(source: &str) -> Result<()> {
    let ast = rhai::Engine::new()
        .compile(source)
        .map_err(|_| anyhow!("authored derivation does not compile as Rhai"))?;
    let mut names = BTreeSet::new();
    let mut answers = 0;
    for function in ast.iter_functions() {
        if !names.insert(function.name) {
            bail!("authored derivation function names must be unique");
        }
        if function.name == "derive" {
            bail!("the `derive` entry point is reserved for the generated concept binding");
        }
        if function.name == "answer" {
            if function.params.len() != 3 {
                bail!("authored derivation must declare answer(facts, selectors, context)");
            }
            answers += 1;
        }
    }
    if answers != 1 {
        bail!("authored derivation must declare exactly one answer(facts, selectors, context)");
    }
    Ok(())
}

fn read_regular_file(path: &Path, maximum_bytes: u64, description: &str) -> Result<Vec<u8>> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening {description} {}", path.display()))?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {description} {}", path.display()))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum_bytes {
        bail!(
            "{description} {} is not a bounded plain file",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {description} {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
        bail!("{description} exceeds its byte limit");
    }
    Ok(bytes)
}

fn one_question_path(project_root: &Path) -> Result<PathBuf> {
    let directory = project_root.join(QUESTIONS_DIRECTORY);
    let metadata = fs::symlink_metadata(&directory)
        .with_context(|| format!("inspecting question directory {}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("questions must be held in a plain directory");
    }
    let entries = fs::read_dir(&directory)
        .with_context(|| format!("reading question directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    if entries.len() != 1 {
        bail!("local authoring requires exactly one questions/*.yaml file");
    }
    let path = entries[0].path();
    if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
        bail!("local authoring requires exactly one questions/*.yaml file");
    }
    Ok(path)
}

fn project_relative_derivation(project_root: &Path, value: &str) -> Result<PathBuf> {
    let relative = Path::new(value);
    let components = relative.components().collect::<Vec<_>>();
    if components.len() != 2
        || components.first() != Some(&Component::Normal(DERIVATIONS_DIRECTORY.as_ref()))
        || !matches!(components.get(1), Some(Component::Normal(_)))
        || relative
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("rhai")
    {
        bail!("answer.derivation must be a project-relative derivations/<name>.rhai file");
    }
    let directory = project_root.join(DERIVATIONS_DIRECTORY);
    let metadata = fs::symlink_metadata(&directory)
        .with_context(|| format!("inspecting derivation directory {}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("derivations must be held in a plain directory");
    }
    Ok(project_root.join(relative))
}

fn validate_question(question: &Question) -> Result<()> {
    for (label, value) in [
        ("id", question.id.as_str()),
        ("purpose", question.purpose.as_str()),
        ("subject.role", question.subject.role.as_str()),
        ("subject.selector", question.subject.selector.as_str()),
        ("answer.concept", question.answer.concept.as_str()),
    ] {
        if !valid_local_identifier(value) {
            bail!("question {label} must be a lowercase local identifier");
        }
    }
    if question.question.is_empty()
        || question.question.len() > 512
        || question.question.chars().any(char::is_control)
    {
        bail!("question text must be a non-empty bounded line of text");
    }
    let _answer_type = question.answer.answer_type;
    if question.source.facts.is_empty()
        || question.source.facts.len() > 16
        || question
            .source
            .facts
            .iter()
            .any(|fact| !valid_field_name(fact))
        || question.source.facts.iter().collect::<BTreeSet<_>>().len()
            != question.source.facts.len()
    {
        bail!("source.facts must contain unique top-level field names");
    }
    if question.disclosure.allow.as_slice() != [question.answer.concept.as_str()] {
        bail!("disclosure.allow must contain exactly the one answer concept");
    }
    if question.source.operation.is_empty()
        || question.source.operation.len() > 256
        || question.source.operation.chars().any(char::is_control)
    {
        bail!("source.operation must name one bounded OpenAPI operationId");
    }
    Ok(())
}

fn valid_local_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 64
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_field_name(value: &str) -> bool {
    valid_local_identifier(value)
}

fn validate_openapi_version(document: &Value) -> Result<()> {
    let version = document
        .get("openapi")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("retained document has no OpenAPI version"))?;
    if !(version.starts_with("3.0.") || version.starts_with("3.1.")) {
        bail!("only OpenAPI 3.0.x and 3.1.x are supported");
    }
    Ok(())
}

fn compile_plan(inputs: Inputs) -> Result<CompilePlan> {
    let question = &inputs.question;
    reject_unsupported_keys(
        inputs
            .openapi
            .as_object()
            .ok_or_else(|| anyhow!("retained OpenAPI document must be an object"))?,
        &["openapi", "info", "servers", "paths"],
        "OpenAPI document",
    )?;
    if inputs.openapi.get("security").is_some() {
        bail!("the local tutorial source must omit top-level OpenAPI security");
    }
    let base_url = exact_loopback_server(&inputs.openapi)?;
    let operation = unique_operation(&inputs.openapi, &question.source.operation)?;
    if operation.operation.get("security").is_some() {
        bail!("the local tutorial operation must omit OpenAPI security");
    }
    if operation.operation.get("requestBody").is_some() {
        bail!("the local tutorial GET operation must not declare a request body");
    }
    if operation.operation.get("servers").is_some() || operation.path_item.get("servers").is_some()
    {
        bail!("the local tutorial operation must use the document's one server");
    }
    reject_unsupported_keys(
        operation.path_item,
        &["get", "parameters"],
        "selected OpenAPI path item",
    )?;
    reject_unsupported_keys(
        operation.operation,
        &["operationId", "parameters", "responses"],
        "selected OpenAPI operation",
    )?;

    exact_path_selector(&operation, &question.subject.selector)?;
    let fact_properties = selected_fact_schemas(&operation, &question.source.facts)?;
    let requirement_uri = local_uri(&format!("requirement:{}", question.id));
    let concept_uri = local_uri(&format!(
        "concept:{}:{}",
        question.id, question.answer.concept
    ));

    let response_schema = closed_object_schema(&question.source.facts, &fact_properties);
    let fact_schema = response_schema.clone();
    let adapter_parameters_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["operationId"],
        "properties": {
            "operationId": {"type": "string", "const": question.source.operation}
        }
    });

    let prepare_script =
        "fn prepare(selectors, parameters) {\n    #{query: [], body: ()}\n}\n".to_owned();
    let extract_script = render_extract_script(&question.source.facts);
    let derivation_script = render_derivation(&inputs.derivation, &concept_uri);
    let bundle = render_bundle(
        question,
        &base_url,
        operation.path,
        &question.subject.selector,
        &requirement_uri,
        &concept_uri,
    );

    Ok(CompilePlan {
        question_id: question.id.clone(),
        derivation_artifact: question.answer.derivation.clone(),
        purpose: question.purpose.clone(),
        subject_role: question.subject.role.clone(),
        selector_field: question.subject.selector.clone(),
        concept_alias: question.answer.concept.clone(),
        requirement_uri,
        concept_uri,
        bundle,
        response_schema,
        fact_schema,
        adapter_parameters_schema,
        prepare_script,
        extract_script,
        derivation_script,
    })
}

fn exact_loopback_server(document: &Value) -> Result<String> {
    let servers = document
        .get("servers")
        .and_then(Value::as_array)
        .filter(|servers| servers.len() == 1)
        .ok_or_else(|| anyhow!("OpenAPI must declare exactly one local server"))?;
    let server = servers[0]
        .as_object()
        .filter(|server| server.len() == 1)
        .ok_or_else(|| anyhow!("the local OpenAPI server must contain only its fixed URL"))?;
    let value = server
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the local OpenAPI server URL is missing"))?;
    let url = Url::parse(value).context("parsing the local OpenAPI server URL")?;
    let port = url
        .port()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow!("the local OpenAPI server needs an explicit non-zero port"))?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("the local OpenAPI server must be one canonical HTTP loopback origin");
    }
    let canonical = match url.host() {
        Some(Host::Ipv4(address)) if address.is_loopback() => {
            format!("http://{address}:{port}")
        }
        Some(Host::Ipv6(address)) if address == std::net::Ipv6Addr::LOCALHOST => {
            format!("http://[{address}]:{port}")
        }
        _ => bail!("the local OpenAPI server must use a numeric loopback address"),
    };
    if canonical != value {
        bail!("the local OpenAPI server must use its exact canonical origin spelling");
    }
    Ok(canonical)
}

fn unique_operation<'a>(document: &'a Value, operation_id: &str) -> Result<Operation<'a>> {
    const METHODS: [&str; 8] = [
        "get", "put", "post", "delete", "options", "head", "patch", "trace",
    ];
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("OpenAPI paths must be an object"))?;
    let mut matches = Vec::new();
    for (path, item) in paths {
        let item = item
            .as_object()
            .ok_or_else(|| anyhow!("OpenAPI path item `{path}` must be an object"))?;
        if item.contains_key("$ref") {
            bail!("OpenAPI path-item references are outside the local tutorial subset");
        }
        for method in METHODS {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let operation = operation
                .as_object()
                .ok_or_else(|| anyhow!("OpenAPI operation `{method} {path}` must be an object"))?;
            if operation.get("operationId").and_then(Value::as_str) == Some(operation_id) {
                matches.push(Operation {
                    method,
                    path,
                    path_item: item,
                    operation,
                });
            }
        }
    }
    if matches.len() != 1 {
        bail!("source.operation must resolve to exactly one OpenAPI operationId");
    }
    let operation = matches.pop().expect("one operation");
    if operation.method != "get" {
        bail!("the local tutorial source supports only one resolved GET operationId");
    }
    Ok(operation)
}

fn exact_path_selector(operation: &Operation<'_>, expected: &str) -> Result<()> {
    let mut parameters = Vec::new();
    for owner in [operation.path_item, operation.operation] {
        if let Some(values) = owner.get("parameters") {
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("OpenAPI parameters must be an array"))?;
            parameters.extend(values);
        }
    }
    if parameters.len() != 1 {
        bail!("the local tutorial operation must declare exactly one path selector");
    }
    let parameter = parameters[0]
        .as_object()
        .ok_or_else(|| anyhow!("the path selector must be an object"))?;
    reject_unsupported_keys(
        parameter,
        &["name", "in", "required", "schema"],
        "path selector",
    )?;
    let parameter_schema = parameter
        .get("schema")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the path selector schema must be an object"))?;
    reject_unsupported_keys(parameter_schema, &["type"], "path selector schema")?;
    if parameter.contains_key("$ref")
        || parameter.get("name").and_then(Value::as_str) != Some(expected)
        || parameter.get("in").and_then(Value::as_str) != Some("path")
        || parameter.get("required").and_then(Value::as_bool) != Some(true)
        || parameter_schema.get("type").and_then(Value::as_str) != Some("string")
    {
        bail!(
            "the question selector must equal the operation's one required string path parameter"
        );
    }
    let placeholder = format!("{{{expected}}}");
    if !operation.path.starts_with('/')
        || operation.path.starts_with("//")
        || operation.path.contains(['?', '#', '\\'])
        || operation
            .path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        || operation
            .path
            .split('/')
            .filter(|segment| *segment == placeholder)
            .count()
            != 1
        || operation.path.matches('{').count() != 1
        || operation.path.matches('}').count() != 1
    {
        bail!("the path selector must occupy exactly one complete path segment");
    }
    Ok(())
}

fn selected_fact_schemas(
    operation: &Operation<'_>,
    selected: &[String],
) -> Result<BTreeMap<String, Value>> {
    let responses = operation
        .operation
        .get("responses")
        .and_then(Value::as_object)
        .filter(|responses| responses.len() == 1)
        .ok_or_else(|| anyhow!("the local tutorial operation must declare exactly one response"))?;
    let response = responses
        .get("200")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            anyhow!("the local tutorial operation must declare an exact 200 response")
        })?;
    if response.contains_key("$ref") {
        bail!("response references are outside the local tutorial subset");
    }
    reject_unsupported_keys(response, &["description", "content"], "200 response")?;
    let content = response
        .get("content")
        .and_then(Value::as_object)
        .filter(|content| content.len() == 1)
        .ok_or_else(|| anyhow!("the 200 response must declare exactly one JSON media type"))?;
    let media = content
        .get("application/json")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the 200 response must declare an application/json media type"))?;
    reject_unsupported_keys(media, &["schema"], "application/json media type")?;
    let schema = media
        .get("schema")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            anyhow!("the 200 response must declare an application/json object schema")
        })?;
    reject_unsupported_keys(
        schema,
        &["type", "required", "properties", "additionalProperties"],
        "200 JSON response schema",
    )?;
    if schema.get("type").and_then(Value::as_str) != Some("object")
        || !matches!(
            schema.get("additionalProperties"),
            None | Some(Value::Bool(false))
        )
    {
        bail!("the 200 JSON response schema must be an exact object");
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the 200 JSON object must declare properties"))?;
    let required_values = schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("the 200 JSON object must declare required properties"))?;
    let required = required_values
        .iter()
        .map(Value::as_str)
        .collect::<Option<BTreeSet<_>>>()
        .ok_or_else(|| anyhow!("the 200 JSON object required list is invalid"))?;
    if required.len() != required_values.len() {
        bail!("the 200 JSON object required list contains duplicates");
    }

    let mut facts = BTreeMap::new();
    for name in selected {
        if !required.contains(name.as_str()) {
            bail!("selected fact `{name}` is not required by the 200 response schema");
        }
        let property = properties
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("selected fact `{name}` is not a top-level scalar"))?;
        facts.insert(name.clone(), local_scalar_schema(name, property)?);
    }
    Ok(facts)
}

fn local_scalar_schema(name: &str, property: &Map<String, Value>) -> Result<Value> {
    let value_type = property.get("type").and_then(Value::as_str);
    match value_type {
        Some("boolean") => {
            reject_unsupported_keys(property, &["type"], &format!("selected fact `{name}`"))?;
            Ok(json!({"type": "boolean"}))
        }
        Some("integer") => {
            reject_unsupported_keys(
                property,
                &["type", "minimum", "maximum"],
                &format!("selected fact `{name}`"),
            )?;
            let minimum =
                optional_i64(property, "minimum", name)?.unwrap_or(-9_007_199_254_740_991);
            let maximum = optional_i64(property, "maximum", name)?.unwrap_or(9_007_199_254_740_991);
            if minimum > maximum {
                bail!("selected integer fact `{name}` has inconsistent bounds");
            }
            Ok(json!({"type": "integer", "minimum": minimum, "maximum": maximum}))
        }
        Some("string") => {
            reject_unsupported_keys(
                property,
                &["type", "format", "minLength", "maxLength"],
                &format!("selected fact `{name}`"),
            )?;
            let format = match property.get("format") {
                Some(Value::String(format)) => Some(format.as_str()),
                Some(_) => bail!("selected string fact `{name}` has an invalid format"),
                None => None,
            };
            if format.is_some_and(|format| !matches!(format, "date" | "date-time")) {
                bail!("selected string fact `{name}` uses an unsupported format");
            }
            let maximum = optional_u64(property, "maxLength", name)?.unwrap_or(16_384);
            let minimum = optional_u64(property, "minLength", name)?.unwrap_or(0);
            if maximum == 0 || maximum > 65_536 || minimum > maximum {
                bail!("selected string fact `{name}` has inconsistent bounds");
            }
            let mut schema = Map::from_iter([
                ("type".to_owned(), Value::String("string".to_owned())),
                ("minLength".to_owned(), Value::from(minimum)),
                ("maxLength".to_owned(), Value::from(maximum)),
            ]);
            if let Some(format) = format {
                schema.insert("format".to_owned(), Value::String(format.to_owned()));
            }
            Ok(Value::Object(schema))
        }
        _ => bail!("selected fact `{name}` must be a string, integer, or boolean scalar"),
    }
}

fn reject_unsupported_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    description: &str,
) -> Result<()> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        bail!("{description} contains unsupported key `{key}`");
    }
    Ok(())
}

fn optional_i64(object: &Map<String, Value>, key: &str, fact: &str) -> Result<Option<i64>> {
    match object.get(key) {
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| anyhow!("selected integer fact `{fact}` has an invalid `{key}`")),
        None => Ok(None),
    }
}

fn optional_u64(object: &Map<String, Value>, key: &str, fact: &str) -> Result<Option<u64>> {
    match object.get(key) {
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("selected string fact `{fact}` has an invalid `{key}`")),
        None => Ok(None),
    }
}

fn closed_object_schema(selected: &[String], properties: &BTreeMap<String, Value>) -> Value {
    let properties = properties
        .iter()
        .map(|(name, schema)| (name.clone(), schema.clone()))
        .collect::<Map<_, _>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": selected,
        "properties": properties,
    })
}

fn render_extract_script(facts: &[String]) -> String {
    let assignments = facts
        .iter()
        .map(|fact| {
            let key = json_string(fact);
            format!("    facts[{key}] = source_response[{key}];")
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "fn extract(source_response, parameters) {{\n    let facts = #{{}};\n{assignments}\n    #{{outcome: \"match\", facts: facts}}\n}}\n"
    )
}

fn render_derivation(authored: &str, concept_uri: &str) -> String {
    let mut rendered = authored.trim_end().to_owned();
    rendered.push_str("\n\n");
    rendered.push_str("fn derive(facts, selectors, evaluation_context) {\n");
    rendered.push_str("    [#{\n");
    rendered.push_str(&format!(
        "        concept_id: {},\n",
        json_string(concept_uri)
    ));
    // The equality is also the closed boolean gate: the runtime exposes only
    // bool-to-bool equality here, so any other authored return shape fails
    // derivation instead of becoming a disclosed value.
    rendered.push_str("        value: answer(facts, selectors, evaluation_context) == true\n");
    rendered.push_str("    }]\n}\n");
    rendered
}

fn render_bundle(
    question: &Question,
    base_url: &str,
    path_template: &str,
    selector: &str,
    requirement_uri: &str,
    concept_uri: &str,
) -> Value {
    let framework_id = local_uri(&format!("framework:{}", question.id));
    let evidence_type = local_uri(&format!("evidence-type:{}", question.id));
    let disclosure_family = local_uri(&format!("disclosure-family:{}", question.id));
    let path_bindings = Value::Object(Map::from_iter([(
        selector.to_owned(),
        json!({
            "role": question.subject.role,
            "profile": SELECTOR_PROFILE_ID,
            "field": selector,
        }),
    )]));
    let selector_fields = Value::Object(Map::from_iter([(
        selector.to_owned(),
        json!({"type": "string", "minimumBytes": 1, "maximumBytes": 200}),
    )]));
    let projection = question
        .source
        .facts
        .iter()
        .map(|fact| Value::String(format!("/{}", escape_pointer_segment(fact))))
        .collect::<Vec<_>>();

    json!({
        "version": 1,
        "assuranceProfile": "local",
        "service": {
            "providerId": local_uri("provider"),
            "trustDomain": local_uri("trust-domain"),
        },
        "issuer": {"id": local_uri("issuer")},
        "authentication": {
            "kind": "oidc-access-token",
            "issuer": LOCAL_MINT_ORIGIN,
            "audiences": [LOCAL_AUDIENCE],
            "tokenTypes": ["at+jwt"],
            "algorithms": ["EdDSA"],
            "jwksUri": format!("{LOCAL_MINT_ORIGIN}/.well-known/jwks.json"),
            "principalClaim": "sub",
            "requesterTagsClaim": "evidence_tags",
            "evidenceAudienceClaim": "evidence_audience",
            "grantIdClaim": "evidence_grant_id",
            "grantAuthorityClaim": "evidence_authority",
        },
        "audit": {
            "format": "keyed-jsonl",
            "hashSecretRef": "secret:file/audit-hmac-key",
            "hashKeyVersion": 1,
            "failClosed": true,
        },
        "subjectBinding": {
            "secretRef": "secret:file/subject-binding-hmac-key",
            "keyVersion": 1,
        },
        "rateLimits": {
            "requestsPerPrincipalPerMinute": 60,
            "burstPerPrincipal": 10,
            "failedSelectorAttemptsPerPrincipalAuthorityPerMinute": 10,
        },
        "signing": {
            "format": "flattened-jws-json",
            "algorithm": "EdDSA",
            "activeKeyId": SIGNING_KEY_ID,
            "activeKeyRef": "secret:file/signing-ed25519-private-jwk",
            "retiredPublicJwkFiles": [],
            "jwksPath": "/.well-known/evidence/jwks.json",
            "maximumAssertionValiditySeconds": 300,
            "verifierClockSkewSeconds": 30,
        },
        "responseFormats": ["signed-jws"],
        "selectorProfiles": {
            SELECTOR_PROFILE_ID: {
                "maximumAggregateBytes": 200,
                "fields": selector_fields,
            }
        },
        "sources": {
            SOURCE_ID: {
                "transport": "http-json",
                "baseUrl": base_url,
                "posture": "field-projected",
                "authentication": {"kind": "none"},
                "request": {
                    "method": "GET",
                    "pathTemplate": path_template,
                    "pathBindings": path_bindings,
                    "fixedHeaders": [{"name": "Accept", "value": "application/json"}],
                    "selectorInputs": [{
                        "role": question.subject.role,
                        "alternatives": [{
                            "profile": SELECTOR_PROFILE_ID,
                            "fields": [selector],
                        }],
                    }],
                    "prepareScript": "adapters/local-source-prepare.rhai",
                    "adapterParameters": {"operationId": question.source.operation},
                    "adapterParametersSchema": "schemas/local-source-adapter-parameters.schema.yaml",
                    "preparationLimits": {
                        "query": "allowed",
                        "jsonBody": "forbidden",
                        "maximumNormalizedBytes": 4096,
                    },
                    "projection": projection,
                    "redirects": "deny",
                    "timeoutMilliseconds": 3000,
                    "maximumResponseBytes": 65536,
                    "concurrencyLimit": 8,
                },
                "responseSchema": "schemas/local-source-response.schema.yaml",
                "extractScript": "adapters/local-source-extract.rhai",
                "factSchema": "schemas/local-source-facts.schema.yaml",
            }
        },
        "authorityProfiles": {
            AUTHORITY_PROFILE_ID: {
                "kind": "explicit-request",
                "requesterTags": [AUTHORITY_PROFILE_ID],
                "grants": [{
                    "requirement": requirement_uri,
                    "purpose": question.purpose,
                    "audienceFrom": "authenticated-requester",
                    "responseFormats": ["signed-jws"],
                    "subjects": [{
                        "role": question.subject.role,
                        "selectorProfile": SELECTOR_PROFILE_ID,
                        "valueOrigin": "request",
                    }],
                }],
            }
        },
        "requirements": [{
            "id": requirement_uri,
            "kind": "criterion",
            "source": SOURCE_ID,
            "purposes": [question.purpose],
            "subjectRoles": [{
                "role": question.subject.role,
                "cardinality": "one",
                "selectorProfiles": [SELECTOR_PROFILE_ID],
            }],
            "referenceFrameworks": [framework_id],
            "evidenceType": evidence_type,
            "observationTimezone": "UTC",
            "validitySeconds": 300,
            "derivation": {
                "script": question.answer.derivation,
                "parameters": {},
            },
            "concepts": [{
                "id": concept_uri,
                "form": "boolean",
                "required": true,
                "constraints": {},
            }],
            "disclosureGuard": {"families": [disclosure_family]},
            "existenceDisclosure": "collapse-unresolved",
        }],
    })
}

fn write_plan(
    project_root: &Path,
    staging_root: &Path,
    plan: &CompilePlan,
) -> Result<CompiledQuestion> {
    let bundle = staging_root.join("bundle");
    create_private_directory(&bundle)?;
    for directory in ["adapters", "derivations", "schemas"] {
        create_private_directory(&bundle.join(directory))?;
    }
    create_private_directory(&staging_root.join("audit"))?;

    write_private_file(&bundle.join("evidence.yaml"), &yaml_bytes(&plan.bundle)?)?;
    write_private_file(
        &bundle.join("adapters/local-source-prepare.rhai"),
        plan.prepare_script.as_bytes(),
    )?;
    write_private_file(
        &bundle.join("adapters/local-source-extract.rhai"),
        plan.extract_script.as_bytes(),
    )?;
    write_private_file(
        &bundle.join(&plan.derivation_artifact),
        plan.derivation_script.as_bytes(),
    )?;
    write_private_file(
        &bundle.join("schemas/local-source-response.schema.yaml"),
        &yaml_bytes(&plan.response_schema)?,
    )?;
    write_private_file(
        &bundle.join("schemas/local-source-facts.schema.yaml"),
        &yaml_bytes(&plan.fact_schema)?,
    )?;
    write_private_file(
        &bundle.join("schemas/local-source-adapter-parameters.schema.yaml"),
        &yaml_bytes(&plan.adapter_parameters_schema)?,
    )?;

    let canonical_staging = fs::canonicalize(staging_root)
        .with_context(|| format!("resolving staging root {}", staging_root.display()))?;
    let secret_root = fs::canonicalize(project_root.join(SECRETS_DIRECTORY))
        .context("resolving local secret directory")?;
    let runtime = json!({
        "version": 1,
        "bundleDirectory": canonical_staging.join("bundle").to_string_lossy(),
        "listener": {
            "bindHost": "127.0.0.1",
            "port": LOCAL_EVIDENCE_PORT,
            "tlsTermination": "operator-controlled-upstream",
            "trustProxyIdentityHeaders": false,
            "maximumRequestBytes": 65536,
            "maximumConcurrentRequests": 64,
            "requestTimeoutMilliseconds": 10000,
            "shutdownGraceMilliseconds": 30000,
        },
        "secretProviders": {"file": {"root": secret_root.to_string_lossy()}},
        "auditStorage": {
            "path": canonical_staging.join("audit/evidence.jsonl").to_string_lossy(),
            "maximumFileBytes": 1073741824_u64,
        },
        "outboundTls": {"systemRoots": true, "trustProfiles": {}},
    });
    let runtime_path = staging_root.join("runtime.yaml");
    write_private_file(&runtime_path, &yaml_bytes(&runtime)?)?;

    set_bundle_modes(&bundle, 0o500, 0o400)?;
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o400))
        .with_context(|| format!("sealing {}", runtime_path.display()))?;

    Ok(CompiledQuestion {
        question_alias: plan.question_id.clone(),
        runtime_path,
        requirement_uri: plan.requirement_uri.clone(),
        purpose: plan.purpose.clone(),
        subject_role: plan.subject_role.clone(),
        selector_profile: SELECTOR_PROFILE_ID.to_owned(),
        selector_field: plan.selector_field.clone(),
        concept_alias: plan.concept_alias.clone(),
        concept_uri: plan.concept_uri.clone(),
        concept_form: CompiledConceptForm::Boolean,
        local_audience: LOCAL_AUDIENCE.to_owned(),
    })
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("creating private directory {}", path.display()))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{fs::OpenOptions, io::Write as _, os::unix::fs::OpenOptionsExt as _};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("persisting {}", path.display()))
}

fn set_bundle_modes(root: &Path, directory_mode: u32, file_mode: u32) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            set_bundle_modes(&path, directory_mode, file_mode)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(directory_mode))?;
        } else if metadata.is_file() {
            fs::set_permissions(&path, fs::Permissions::from_mode(file_mode))?;
        } else {
            bail!("unexpected generated bundle entry");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(directory_mode))?;
    Ok(())
}

fn check_with_evidence(evidence_bin: &Path, runtime_path: &Path) -> Result<()> {
    let output = Command::new(evidence_bin)
        .arg("--runtime")
        .arg(runtime_path)
        .arg("check")
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .with_context(|| format!("running {} check", evidence_bin.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let diagnostic = stderr.trim();
    if diagnostic.is_empty() {
        bail!("Evidence rejected the compiled local generation");
    }
    bail!("Evidence rejected the compiled local generation: {diagnostic}")
}

fn yaml_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut text = serde_norway::to_string(value).context("serializing generated YAML")?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text.into_bytes())
}

fn local_uri(suffix: &str) -> String {
    format!("{LOCAL_URI_PREFIX}{suffix}")
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).expect("strings serialize")
}

fn escape_pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};

    const OPENAPI: &str = r#"openapi: 3.1.0
info: {title: Tutorial registry, version: 1.0.0}
servers: [{url: 'http://127.0.0.1:8000'}]
paths:
  /people/{person_id}:
    get:
      operationId: getPerson
      parameters:
        - name: person_id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200':
          description: A person
          content:
            application/json:
              schema:
                type: object
                required: [person_id, name, date_of_birth]
                properties:
                  person_id: {type: string}
                  name: {type: string}
                  date_of_birth: {type: string}
"#;

    const QUESTION: &str = r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts: [date_of_birth]
answer:
  concept: is_adult
  type: boolean
  derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#;

    const ANSWER: &str = r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    let adult_on = add_calendar_years(born, 18);
    compare_dates(context.legal_local_date, adult_on) >= 0
}
"#;

    #[test]
    fn compiles_only_the_canonical_private_local_generation() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("local compilation succeeds");

        assert_eq!(compiled.runtime_path, fixture.staging.join("runtime.yaml"));
        assert_eq!(compiled.question_alias, "adult-status");
        assert_eq!(
            compiled.requirement_uri,
            "urn:registrystack:evidence:local:requirement:adult-status"
        );
        assert_eq!(
            compiled.concept_uri,
            "urn:registrystack:evidence:local:concept:adult-status:is_adult"
        );
        assert_eq!(compiled.purpose, "age-check");
        assert_eq!(compiled.subject_role, "person");
        assert_eq!(compiled.selector_profile, SELECTOR_PROFILE_ID);
        assert_eq!(compiled.selector_field, "person_id");
        assert_eq!(compiled.concept_alias, "is_adult");
        assert_eq!(compiled.concept_form, CompiledConceptForm::Boolean);
        assert_eq!(compiled.local_audience, LOCAL_AUDIENCE);
        assert_eq!(
            tree(&fixture.staging),
            vec![
                "audit/",
                "bundle/",
                "bundle/adapters/",
                "bundle/adapters/local-source-extract.rhai",
                "bundle/adapters/local-source-prepare.rhai",
                "bundle/derivations/",
                "bundle/derivations/adult-status.rhai",
                "bundle/evidence.yaml",
                "bundle/schemas/",
                "bundle/schemas/local-source-adapter-parameters.schema.yaml",
                "bundle/schemas/local-source-facts.schema.yaml",
                "bundle/schemas/local-source-response.schema.yaml",
                "runtime.yaml",
            ]
        );
        assert_mode(&fixture.staging, 0o700);
        assert_mode(&fixture.staging.join("audit"), 0o700);
        assert_mode(&fixture.staging.join("bundle"), 0o500);
        assert_mode(&compiled.runtime_path, 0o400);

        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        assert_eq!(bundle["assuranceProfile"], "local");
        assert_eq!(
            bundle["sources"][SOURCE_ID]["authentication"],
            json!({"kind": "none"})
        );
        assert_eq!(
            bundle["sources"][SOURCE_ID]["request"]["pathBindings"]["person_id"],
            json!({"role": "person", "profile": SELECTOR_PROFILE_ID, "field": "person_id"})
        );
        assert!(bundle["requirements"][0].get("fixtures").is_none());
        assert_eq!(
            bundle["requirements"][0]["concepts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        let derivation =
            fs::read_to_string(fixture.staging.join("bundle/derivations/adult-status.rhai"))
                .expect("derivation reads");
        assert!(derivation.contains("fn answer(facts, selectors, context)"));
        assert!(derivation.contains(
            "concept_id: \"urn:registrystack:evidence:local:concept:adult-status:is_adult\""
        ));
        assert!(derivation.contains("value: answer(facts, selectors, evaluation_context) == true"));
        assert!(!derivation.contains("concept_id: \"is_adult\""));
    }

    #[test]
    fn question_is_closed_and_one_concept_cannot_be_widened() {
        for mutation in [
            QUESTION.replace("  allow: [is_adult]", "  allow: []"),
            QUESTION.replace("  allow: [is_adult]", "  allow: [is_adult, another_answer]"),
            QUESTION.replace("  allow: [is_adult]", "  allow: [is_adult, is_adult]"),
            QUESTION.replace(
                "  facts: [date_of_birth]",
                "  facts: [date_of_birth, date_of_birth]",
            ),
            format!("{QUESTION}unknown: true\n"),
        ] {
            let fixture = Fixture::new(OPENAPI, &mutation, ANSWER, true);
            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("widened question is rejected");
            assert!(fixture.staging_is_empty(), "{error:#}");
        }
    }

    #[test]
    fn authored_code_cannot_replace_or_bypass_the_generated_concept_binding() {
        let authored = r#"fn answer(facts, selectors, context) {
    [#{concept_id: "urn:attacker:extra", value: true}]
}
"#;
        let fixture = Fixture::new(OPENAPI, QUESTION, authored, true);
        compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("authored function stays behind the generated binding");

        let derivation =
            fs::read_to_string(fixture.staging.join("bundle/derivations/adult-status.rhai"))
                .expect("rejected generated derivation remains inspectable");
        let wrapper = derivation.rsplit_once("fn derive").unwrap().1;
        assert!(wrapper.contains("urn:registrystack:evidence:local:concept:adult-status:is_adult"));
        assert!(!wrapper.contains("urn:attacker"));
        assert!(wrapper.contains("answer(facts, selectors, evaluation_context) == true"));

        for rejected in [
            "fn helper(facts, selectors, context) { true }",
            "fn answer(facts) { true }",
            "fn answer(facts, selectors, context) { true } fn derive(facts, selectors, context) { [] }",
            "fn answer(facts, selectors, context) { true } fn answer(facts) { false }",
        ] {
            let fixture = Fixture::new(OPENAPI, QUESTION, rejected, true);
            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("authored entry-point bypass is rejected");
            assert!(fixture.staging_is_empty(), "{error:#}");
        }
    }

    #[test]
    fn ambiguous_or_nonlocal_openapi_fails_before_staging() {
        let cases = [
            OPENAPI.replace("127.0.0.1", "example.test"),
            OPENAPI.replace(
                "servers: [{url: 'http://127.0.0.1:8000'}]",
                "servers: [{url: 'http://127.0.0.1:8000'}, {url: 'http://127.0.0.1:8001'}]",
            ),
            OPENAPI.replace("paths:", "security: []\npaths:"),
            OPENAPI.replace("    get:", "    post:"),
            OPENAPI.replace("      responses:", "      security: []\n      responses:"),
            OPENAPI.replace("        '200':", "        default:"),
            OPENAPI.replace(
                "                  date_of_birth: {type: string}",
                "                  date_of_birth: {type: object}",
            ),
        ];
        for openapi in cases {
            let fixture = Fixture::new(&openapi, QUESTION, ANSWER, true);
            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("unsupported OpenAPI is rejected");
            assert!(fixture.staging_is_empty(), "{error:#}");
        }
    }

    #[test]
    fn unsupported_openapi_constraints_fail_before_staging() {
        let cases = [
            OPENAPI.replace(
                "date_of_birth: {type: string}",
                "date_of_birth: {type: string, enum: ['2000-01-01']}",
            ),
            OPENAPI.replace(
                "date_of_birth: {type: string}",
                "date_of_birth: {type: string, pattern: '^2000-'}",
            ),
            OPENAPI.replace(
                "date_of_birth: {type: string}",
                "date_of_birth: {type: integer, exclusiveMinimum: 0}",
            ),
            OPENAPI.replace(
                "date_of_birth: {type: string}",
                "date_of_birth: {type: string, x-extra: true}",
            ),
            OPENAPI.replace(
                "          required: true\n          schema:",
                "          required: true\n          style: simple\n          schema:",
            ),
            OPENAPI.replacen(
                "schema: {type: string}",
                "schema: {type: string, pattern: '^person-'}",
                1,
            ),
            OPENAPI.replace(
                "      operationId: getPerson",
                "      operationId: getPerson\n      summary: Unsupported metadata",
            ),
            OPENAPI.replace(
                "          description: A person",
                "          description: A person\n          headers: {}",
            ),
            OPENAPI.replace(
                "            application/json:\n              schema:",
                "            application/json:\n              example: {}\n              schema:",
            ),
            OPENAPI.replace(
                "                type: object\n                required:",
                "                type: object\n                minProperties: 1\n                required:",
            ),
        ];
        for openapi in cases {
            let fixture = Fixture::new(&openapi, QUESTION, ANSWER, true);
            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("unpreserved OpenAPI constraint is rejected");
            assert!(error.to_string().contains("unsupported key"), "{error:#}");
            assert!(fixture.staging_is_empty(), "{error:#}");
        }
    }

    #[test]
    fn punctuated_selector_and_fact_names_are_safely_quoted() {
        let (openapi, question, answer) = punctuated_inputs();
        let fixture = Fixture::new(&openapi, &question, &answer, true);
        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("punctuated names compile");

        assert_eq!(compiled.selector_field, "person-id.v1");
        let extract = fs::read_to_string(
            fixture
                .staging
                .join("bundle/adapters/local-source-extract.rhai"),
        )
        .expect("extract script reads");
        assert!(extract.contains("facts[\"date-of.birth\"] = source_response[\"date-of.birth\"];"));
    }

    #[test]
    fn input_files_and_private_staging_are_fail_closed() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fs::set_permissions(&fixture.staging, fs::Permissions::from_mode(0o755))
            .expect("change staging mode");
        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("public staging rejected");
        assert!(error.to_string().contains("0700"));

        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fs::write(fixture.project.join("questions/extra.yaml"), QUESTION)
            .expect("write extra question");
        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("ambiguous questions rejected");
        assert!(error.to_string().contains("exactly one"));
        assert!(fixture.staging_is_empty());
    }

    #[test]
    #[ignore = "run after building the sibling evidence binary with local source authentication"]
    fn real_evidence_loader_accepts_the_compiled_tutorial_generation() {
        let evidence = std::env::var_os("EVIDENCE_BIN")
            .map(PathBuf::from)
            .expect("set EVIDENCE_BIN to the built evidence binary");
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        crate::keygen::generate_scaffold_key_material(
            &fixture.project.join("secrets"),
            SIGNING_KEY_ID,
        )
        .expect("generate local keys");
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts generated inputs");

        let (openapi, question, answer) = punctuated_inputs();
        let fixture = Fixture::new(&openapi, &question, &answer, true);
        crate::keygen::generate_scaffold_key_material(
            &fixture.project.join("secrets"),
            SIGNING_KEY_ID,
        )
        .expect("generate local keys");
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts safely quoted punctuated names");
    }

    fn punctuated_inputs() -> (String, String, String) {
        let openapi = OPENAPI
            .replace("person_id", "person-id.v1")
            .replace("date_of_birth", "date-of.birth");
        let question = QUESTION
            .replace("person_id", "person-id.v1")
            .replace("date_of_birth", "date-of.birth");
        let answer = ANSWER.replace("facts.date_of_birth", "facts[\"date-of.birth\"]");
        (openapi, question, answer)
    }

    struct Fixture {
        _root: tempfile::TempDir,
        project: PathBuf,
        staging: PathBuf,
        evidence: PathBuf,
    }

    impl Fixture {
        fn new(openapi: &str, question: &str, derivation: &str, check_succeeds: bool) -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            let project = root.path().join("project");
            fs::create_dir(&project).expect("project");
            fs::create_dir(project.join("questions")).expect("questions");
            fs::create_dir(project.join("derivations")).expect("derivations");
            let mut secrets = fs::DirBuilder::new();
            secrets.mode(0o700);
            secrets.create(project.join("secrets")).expect("secrets");
            fs::write(project.join(OPENAPI_FILE), openapi).expect("OpenAPI");
            fs::write(project.join("questions/adult-status.yaml"), question).expect("question");
            fs::write(project.join("derivations/adult-status.rhai"), derivation)
                .expect("derivation");

            let staging = root.path().join("staging");
            let mut private = fs::DirBuilder::new();
            private.mode(0o700);
            private.create(&staging).expect("staging");

            let evidence = root.path().join("evidence-stub");
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&evidence)
                .expect("stub");
            let script = if check_succeeds {
                "#!/bin/sh\ntest \"$1\" = --runtime && test \"$3\" = check\n"
            } else {
                "#!/bin/sh\necho 'script rejected' >&2\nexit 1\n"
            };
            file.write_all(script.as_bytes()).expect("write stub");

            Self {
                _root: root,
                project,
                staging,
                evidence,
            }
        }

        fn staging_is_empty(&self) -> bool {
            fs::read_dir(&self.staging)
                .expect("read staging")
                .next()
                .is_none()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.staging.join("bundle").is_dir() {
                let _ = set_bundle_modes(&self.staging.join("bundle"), 0o700, 0o600);
            }
            if self.staging.join("runtime.yaml").is_file() {
                let _ = fs::set_permissions(
                    self.staging.join("runtime.yaml"),
                    fs::Permissions::from_mode(0o600),
                );
            }
        }
    }

    fn tree(root: &Path) -> Vec<String> {
        fn visit(root: &Path, current: &Path, output: &mut Vec<String>) {
            let mut entries = fs::read_dir(current)
                .expect("read directory")
                .collect::<std::io::Result<Vec<_>>>()
                .expect("entries");
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_string_lossy();
                if path.is_dir() {
                    output.push(format!("{relative}/"));
                    visit(root, &path, output);
                } else {
                    output.push(relative.into_owned());
                }
            }
        }
        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    fn assert_mode(path: &Path, expected: u32) {
        let actual = fs::metadata(path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(actual, expected, "mode of {}", path.display());
    }
}
