//! Compile the deliberately narrow local tutorial authoring shape into the
//! runtime's canonical deployment inputs.
//!
//! This module is an internal seam for `dev`. It does not expose another CLI
//! surface and it delegates the final semantic decision to `evidence check`.

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

use crate::suggest::{
    narrow,
    openapi::Spec,
    types::{BoundKind, BoundValues, OperationKey},
};

const OPENAPI_FILE: &str = "source.openapi.yaml";
const QUESTIONS_DIRECTORY: &str = "questions";
const SOURCES_DIRECTORY: &str = "sources";
const SELECTORS_DIRECTORY: &str = "selectors";
const DERIVATIONS_DIRECTORY: &str = "derivations";
const SECRETS_DIRECTORY: &str = "secrets";
const LOCAL_URI_PREFIX: &str = "urn:registrystack:evidence:local:";
const LOCAL_AUDIENCE: &str = "registry-evidence-local";
const SIGNING_KEY_ID: &str = "local-signing-key-1";
const AUTHORITY_PROFILE_ID: &str = "local-caller";
const LOCAL_CALLER_EVIDENCE_AUDIENCE: &str = "urn:registrystack:evidence:local:caller";
const MAX_OPENAPI_BYTES: u64 = 16 * 1024 * 1024;
const MAX_QUESTION_BYTES: u64 = 64 * 1024;
const MAX_DERIVATION_BYTES: u64 = 64 * 1024;
const MAX_SOURCE_ARTIFACT_BYTES: u64 = 1024 * 1024;
const MAX_QUESTIONS: usize = 128;
const MAX_CONCEPTS: usize = 16;
const MAX_CATEGORIES: usize = 32;
const MAX_CATEGORY_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompiledConceptForm {
    Boolean,
    ControlledCategory,
    BoundedInteger,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledConcept {
    pub(crate) concept_alias: String,
    pub(crate) concept_uri: String,
    pub(crate) concept_form: CompiledConceptForm,
}

/// Closed metadata consumed later by `dev` and request preparation. It stays
/// in memory here; this compiler does not create a second public artifact.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledQuestion {
    pub(crate) question_alias: String,
    pub(crate) requirement_uri: String,
    pub(crate) purpose: String,
    pub(crate) subjects: Vec<CompiledSubject>,
    pub(crate) concepts: Vec<CompiledConcept>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledSubject {
    pub(crate) role: String,
    pub(crate) selector_profile: String,
    pub(crate) selector_field: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledProject {
    pub(crate) runtime_path: PathBuf,
    pub(crate) questions: Vec<CompiledQuestion>,
    pub(crate) local_audience: String,
    pub(crate) requester_tag: String,
    pub(crate) caller_evidence_audience: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalServicePorts {
    pub(crate) evidence: u16,
    pub(crate) mint: u16,
}

impl LocalServicePorts {
    pub(crate) fn new(evidence: u16, mint: u16) -> Result<Self> {
        if evidence == 0 || mint == 0 {
            bail!("local service ports must be non-zero");
        }
        if evidence == mint {
            bail!("Evidence and Mint must use different local ports");
        }
        Ok(Self { evidence, mint })
    }

    pub(crate) fn mint_origin(self) -> String {
        format!("http://127.0.0.1:{}", self.mint)
    }
}

impl Default for LocalServicePorts {
    fn default() -> Self {
        Self {
            evidence: 8080,
            mint: 8081,
        }
    }
}

/// Compile the authored questions into one unpublished local generation, then
/// ask the real Evidence binary to check the complete result.
///
/// `staging_root` must be an existing, empty, owner-only directory. The caller
/// owns generation publication and process supervision.
#[cfg(test)]
pub(crate) fn compile_local_project(
    project_root: &Path,
    staging_root: &Path,
    evidence_bin: &Path,
) -> Result<CompiledProject> {
    compile_local_project_with_ports(
        project_root,
        staging_root,
        evidence_bin,
        LocalServicePorts::default(),
    )
}

pub(crate) fn compile_local_project_with_ports(
    project_root: &Path,
    staging_root: &Path,
    evidence_bin: &Path,
    ports: LocalServicePorts,
) -> Result<CompiledProject> {
    LocalServicePorts::new(ports.evidence, ports.mint)?;
    let project_root = validate_project_root(project_root)?;
    validate_private_empty_staging(staging_root)?;
    validate_evidence_binary(evidence_bin)?;

    // Resolve the complete plan before writing anything. Unsupported or
    // ambiguous authoring inputs therefore leave the staging root empty.
    let inputs = read_inputs(&project_root)?;
    let plan = compile_plan(inputs, ports)?;
    let compilation = write_plan(&project_root, staging_root, &plan, ports)?;

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
    #[serde(default)]
    subject: Option<QuestionSubject>,
    #[serde(default)]
    subjects: Vec<QuestionSubject>,
    source: QuestionSource,
    answers: Vec<QuestionAnswer>,
    derivation: String,
    disclosure: QuestionDisclosure,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionSubject {
    role: String,
    selector: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    derivation: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionSource {
    #[serde(rename = "ref")]
    source_ref: Option<String>,
    #[serde(default)]
    operation: Option<String>,
    #[serde(default)]
    facts: Vec<QuestionFact>,
    #[serde(rename = "collectionBounds", default)]
    collection_bounds: BTreeMap<String, u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionFact {
    name: String,
    path: String,
    combine: FactCombination,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum FactCombination {
    ExactlyOne,
    Collect,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionAnswer {
    concept: String,
    #[serde(rename = "type")]
    answer_type: AnswerType,
    #[serde(default)]
    values: Vec<String>,
    minimum: Option<i64>,
    maximum: Option<i64>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AnswerType {
    Boolean,
    ControlledCategory,
    BoundedInteger,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuestionDisclosure {
    allow: Vec<String>,
}

struct Inputs {
    openapi: Value,
    selectors: BTreeMap<String, Value>,
    sources: BTreeMap<String, Value>,
    questions: Vec<AuthoredQuestion>,
}

struct AuthoredQuestion {
    question: Question,
    derivation: String,
}

struct CompilePlan {
    questions: Vec<QuestionPlan>,
    bundle: Value,
}

struct QuestionPlan {
    question_id: String,
    source_artifact_id: String,
    authored_source_artifacts: Option<Vec<String>>,
    derivation_artifact: String,
    purpose: String,
    requirement_uri: String,
    concepts: Vec<ConceptPlan>,
    subjects: Vec<SubjectPlan>,
    source_id: String,
    source_value: Value,
    grant: Value,
    requirement: Value,
    response_schema: Value,
    fact_schema: Value,
    adapter_parameters_schema: Value,
    prepare_script: String,
    extract_script: String,
    derivation_script: String,
}

struct SubjectPlan {
    role: String,
    selector_field: String,
    selector_profile: String,
    selector_profile_value: Value,
    derivation: bool,
}

struct ConceptPlan {
    concept_alias: String,
    concept_uri: String,
    concept_form: CompiledConceptForm,
    constraints: Value,
    codelist: Option<(String, Value)>,
}

struct CompiledFacts {
    response_schema: Value,
    fact_schema: Value,
    extract_script: String,
}

struct BundleRequirement<'a> {
    requirement_uri: String,
    kind: &'static str,
    concepts: &'a [ConceptPlan],
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

    let selectors = read_named_objects(project_root, SELECTORS_DIRECTORY, "selector profile")?;
    let sources = read_named_objects(project_root, SOURCES_DIRECTORY, "source")?;
    let mut questions = Vec::new();
    let mut question_ids = BTreeSet::new();
    let mut derivation_paths = BTreeSet::new();
    for question_path in question_paths(project_root)? {
        let question_bytes = read_regular_file(&question_path, MAX_QUESTION_BYTES, "question")?;
        let question: Question = serde_norway::from_slice(&question_bytes)
            .with_context(|| format!("parsing question {}", question_path.display()))?;
        validate_question(&question)?;
        if question_path.file_stem().and_then(|value| value.to_str()) != Some(&question.id) {
            bail!("question id must match its questions/<id>.yaml filename");
        }
        if !question_ids.insert(question.id.clone()) {
            bail!("question ids must be unique");
        }
        if !derivation_paths.insert(question.derivation.clone()) {
            bail!("each question must name its own derivation file");
        }

        let derivation_path = project_relative_derivation(project_root, &question.derivation)?;
        let derivation_bytes = read_regular_file(
            &derivation_path,
            MAX_DERIVATION_BYTES,
            "authored derivation",
        )?;
        let derivation =
            String::from_utf8(derivation_bytes).context("authored derivation must be UTF-8")?;
        validate_authored_answer(&derivation)?;
        questions.push(AuthoredQuestion {
            question,
            derivation,
        });
    }

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
        selectors,
        sources,
        questions,
    })
}

fn read_named_objects(
    project_root: &Path,
    directory_name: &str,
    description: &str,
) -> Result<BTreeMap<String, Value>> {
    let directory = project_root.join(directory_name);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("inspecting {description} directory {}", directory.display())
            })
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{directory_name} must be held in a plain directory");
    }
    let mut paths = fs::read_dir(&directory)
        .with_context(|| format!("reading {description} directory {}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();

    let mut objects = BTreeMap::new();
    for path in paths {
        if path.extension().and_then(|extension| extension.to_str()) != Some("yaml") {
            bail!("{directory_name} may contain only <id>.yaml files");
        }
        let bytes = read_regular_file(&path, MAX_SOURCE_ARTIFACT_BYTES, description)?;
        let value: Value = serde_norway::from_slice(&bytes)
            .with_context(|| format!("parsing {description} {}", path.display()))?;
        if !value.is_object() {
            bail!("{description} must be a YAML object");
        }
        let id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| anyhow!("{description} file name is not valid UTF-8"))?;
        if !valid_local_identifier(id) {
            bail!("{description} file name must be a lowercase local identifier");
        }
        objects.insert(id.to_owned(), value);
    }
    Ok(objects)
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

fn question_paths(project_root: &Path) -> Result<Vec<PathBuf>> {
    let directory = project_root.join(QUESTIONS_DIRECTORY);
    let metadata = fs::symlink_metadata(&directory)
        .with_context(|| format!("inspecting question directory {}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("questions must be held in a plain directory");
    }
    let mut paths = fs::read_dir(&directory)
        .with_context(|| format!("reading question directory {}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    if paths.is_empty() || paths.len() > MAX_QUESTIONS {
        bail!("local authoring requires 1..={MAX_QUESTIONS} questions/*.yaml files");
    }
    if paths
        .iter()
        .any(|path| path.extension().and_then(|value| value.to_str()) != Some("yaml"))
    {
        bail!("questions must contain only questions/*.yaml files");
    }
    Ok(paths)
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
        bail!("derivation must be a project-relative derivations/<name>.rhai file");
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
    ] {
        if !valid_local_identifier(value) {
            bail!("question {label} must be a lowercase local identifier");
        }
    }
    let subjects = question_subjects(question)?;
    let mut roles = BTreeSet::new();
    for subject in &subjects {
        if !valid_local_identifier(&subject.role)
            || !valid_local_identifier(&subject.selector)
            || subject
                .profile
                .as_deref()
                .is_some_and(|profile| !valid_local_identifier(profile))
        {
            bail!("question subjects must use lowercase local role, selector, and profile identifiers");
        }
        if !roles.insert(subject.role.as_str()) {
            bail!("question subject roles must be unique");
        }
    }
    if question.question.is_empty()
        || question.question.len() > 512
        || question.question.chars().any(char::is_control)
    {
        bail!("question text must be a non-empty bounded line of text");
    }
    if !(1..=MAX_CONCEPTS).contains(&question.answers.len()) {
        bail!("answers must contain 1..={MAX_CONCEPTS} governed concepts");
    }
    let mut concepts = BTreeSet::new();
    for answer in &question.answers {
        if !valid_local_identifier(&answer.concept) {
            bail!("answer concept must be a lowercase local identifier");
        }
        if !concepts.insert(answer.concept.as_str()) {
            bail!("answer concepts must be unique");
        }
        validate_answer(answer)?;
    }
    match (&question.source.source_ref, &question.source.operation) {
        (Some(source_ref), None) => {
            if !valid_local_identifier(source_ref)
                || !question.source.facts.is_empty()
                || !question.source.collection_bounds.is_empty()
            {
                bail!("a source reference must contain only one valid ref");
            }
        }
        (None, Some(operation)) => {
            if question.source.facts.is_empty() || question.source.facts.len() > 16 {
                bail!("source.facts must contain 1..=16 authored fact selections");
            }
            let mut names = BTreeSet::new();
            let mut paths = BTreeSet::new();
            for fact in &question.source.facts {
                if !valid_field_name(&fact.name) || !names.insert(fact.name.as_str()) {
                    bail!("source fact names must be unique lowercase local identifiers");
                }
                if fact.path.is_empty()
                    || fact.path.len() > 256
                    || !fact.path.starts_with('/')
                    || fact.path.chars().any(char::is_control)
                    || !paths.insert(fact.path.as_str())
                {
                    bail!("source fact paths must be unique bounded extended JSON Pointers");
                }
                let repeated = fact.path.split('/').any(|segment| segment == "*");
                match (repeated, fact.combine) {
                    (false, FactCombination::ExactlyOne) | (true, FactCombination::Collect) => {}
                    (false, FactCombination::Collect) => bail!(
                        "source fact `{}` uses `collect` but its path visits no collection",
                        fact.name
                    ),
                    (true, FactCombination::ExactlyOne) => bail!(
                        "source fact `{}` visits a collection and must explicitly use `combine: collect`",
                        fact.name
                    ),
                }
            }
            if question.source.collection_bounds.len() > 16
                || question
                    .source
                    .collection_bounds
                    .iter()
                    .any(|(pointer, maximum)| {
                        pointer.is_empty()
                            || pointer.len() > 256
                            || !pointer.starts_with('/')
                            || pointer.chars().any(char::is_control)
                            || !(1..=256).contains(maximum)
                    })
            {
                bail!("source.collectionBounds must contain bounded array pointers with values in 1..=256");
            }
            if operation.is_empty()
                || operation.len() > 256
                || operation.chars().any(char::is_control)
            {
                bail!("source.operation must name one bounded OpenAPI operationId");
            }
        }
        _ => bail!("source must declare either ref or operation with facts"),
    }
    let allowed = question
        .disclosure
        .allow
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if allowed != concepts || allowed.len() != question.disclosure.allow.len() {
        bail!("disclosure.allow must contain exactly the declared answer concepts");
    }
    Ok(())
}

fn question_subjects(question: &Question) -> Result<Vec<&QuestionSubject>> {
    match (&question.subject, question.subjects.as_slice()) {
        (Some(subject), []) => Ok(vec![subject]),
        (None, subjects) if (1..=8).contains(&subjects.len()) => Ok(subjects.iter().collect()),
        (Some(_), _) => bail!("question must declare either subject or subjects, not both"),
        (None, _) => bail!("question must declare 1..=8 subjects"),
    }
}

fn validate_answer(answer: &QuestionAnswer) -> Result<()> {
    match answer.answer_type {
        AnswerType::Boolean => {
            if !answer.values.is_empty() || answer.minimum.is_some() || answer.maximum.is_some() {
                bail!("a boolean answer must not declare values or numeric bounds");
            }
        }
        AnswerType::ControlledCategory => {
            if answer.minimum.is_some() || answer.maximum.is_some() {
                bail!("a controlled-category answer must not declare numeric bounds");
            }
            if !(2..=MAX_CATEGORIES).contains(&answer.values.len())
                || answer.values.iter().collect::<BTreeSet<_>>().len() != answer.values.len()
                || answer.values.iter().any(|value| {
                    value.is_empty()
                        || value.len() > MAX_CATEGORY_BYTES
                        || value.chars().any(char::is_control)
                })
            {
                bail!(
                    "a controlled-category answer needs 2..={MAX_CATEGORIES} unique bounded values"
                );
            }
        }
        AnswerType::BoundedInteger => {
            if !answer.values.is_empty() {
                bail!("a bounded-integer answer must not declare category values");
            }
            let (Some(minimum), Some(maximum)) = (answer.minimum, answer.maximum) else {
                bail!("a bounded-integer answer requires minimum and maximum");
            };
            const JSON_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
            if !(-JSON_SAFE_INTEGER..=JSON_SAFE_INTEGER).contains(&minimum)
                || !(-JSON_SAFE_INTEGER..=JSON_SAFE_INTEGER).contains(&maximum)
                || minimum > maximum
            {
                bail!("a bounded-integer answer needs consistent JSON-safe bounds");
            }
        }
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

fn compile_plan(inputs: Inputs, ports: LocalServicePorts) -> Result<CompilePlan> {
    let has_inline_source = inputs
        .questions
        .iter()
        .any(|authored| authored.question.source.source_ref.is_none());
    let (spec, base_url) = if has_inline_source {
        reject_unsupported_keys(
            inputs
                .openapi
                .as_object()
                .ok_or_else(|| anyhow!("retained OpenAPI document must be an object"))?,
            &["openapi", "info", "servers", "paths", "components"],
            "OpenAPI document",
        )?;
        if inputs.openapi.get("security").is_some() {
            bail!("the local tutorial source must omit top-level OpenAPI security");
        }
        (
            Some(Spec::from_value(
                inputs.openapi.clone(),
                "retained OpenAPI document",
            )?),
            Some(exact_loopback_server(&inputs.openapi)?),
        )
    } else {
        (None, None)
    };
    let mut questions = Vec::with_capacity(inputs.questions.len());
    for authored in inputs.questions {
        questions.push(compile_question_plan(
            &inputs.openapi,
            spec.as_ref(),
            base_url.as_deref(),
            &inputs.selectors,
            &inputs.sources,
            authored,
        )?);
    }
    let bundle = render_bundle(&questions, ports);
    Ok(CompilePlan { questions, bundle })
}

fn compile_question_plan(
    openapi: &Value,
    spec: Option<&Spec>,
    base_url: Option<&str>,
    selectors: &BTreeMap<String, Value>,
    sources: &BTreeMap<String, Value>,
    authored: AuthoredQuestion,
) -> Result<QuestionPlan> {
    let question = &authored.question;
    if question.source.source_ref.is_some() {
        return compile_referenced_question(selectors, sources, authored);
    }
    let authored_subjects = question_subjects(question)?;
    if authored_subjects
        .iter()
        .any(|subject| subject.profile.is_some())
    {
        bail!("an OpenAPI question derives its local selector profiles");
    }
    let operation_id = question
        .source
        .operation
        .as_deref()
        .expect("inline source was validated");
    let operation = unique_operation(openapi, operation_id)?;
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

    exact_path_selectors(
        &operation,
        &authored_subjects
            .iter()
            .map(|subject| subject.selector.as_str())
            .collect::<Vec<_>>(),
    )?;
    let compiled_facts = compile_facts(
        spec.expect("inline source needs parsed OpenAPI"),
        &operation,
        &question.source,
    )?;
    let requirement_uri = local_uri(&format!("requirement:{}", question.id));
    let concepts = question
        .answers
        .iter()
        .map(|answer| compile_concept(&question.id, answer))
        .collect::<Vec<_>>();
    let requirement_kind =
        if concepts.len() == 1 && concepts[0].concept_form == CompiledConceptForm::Boolean {
            "criterion"
        } else {
            "information-requirement"
        };

    let response_schema = compiled_facts.response_schema;
    let fact_schema = compiled_facts.fact_schema;
    let adapter_parameters_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["operationId"],
        "properties": {
            "operationId": {"type": "string", "const": operation_id}
        }
    });

    let prepare_script =
        "fn prepare(selectors, parameters) {\n    #{query: [], body: ()}\n}\n".to_owned();
    let extract_script = compiled_facts.extract_script;
    let derivation_script = render_derivation(&authored.derivation, &concepts);
    let subjects = authored_subjects
        .iter()
        .map(|authored_subject| {
            let selector_profile = local_subject_selector_profile_id(
                &question.id,
                &authored_subject.role,
                authored_subjects.len(),
            );
            SubjectPlan {
                role: authored_subject.role.clone(),
                selector_field: authored_subject.selector.clone(),
                selector_profile,
                selector_profile_value: json!({
                    "maximumAggregateBytes": 200,
                    "fields": {
                        authored_subject.selector.clone(): {
                            "type": "string",
                            "minimumBytes": 1,
                            "maximumBytes": 200,
                        }
                    },
                }),
                derivation: authored_subject.derivation,
            }
        })
        .collect::<Vec<_>>();
    let source_id = local_source_id(&question.id);
    let (source_value, grant, requirement) = render_question_bundle_parts(
        question,
        base_url.expect("inline source needs local base URL"),
        operation.path,
        &subjects,
        &source_id,
        &BundleRequirement {
            requirement_uri: requirement_uri.clone(),
            kind: requirement_kind,
            concepts: &concepts,
        },
    );
    Ok(QuestionPlan {
        question_id: question.id.clone(),
        source_artifact_id: question.id.clone(),
        authored_source_artifacts: None,
        derivation_artifact: question.derivation.clone(),
        purpose: question.purpose.clone(),
        requirement_uri,
        concepts,
        subjects,
        source_id,
        source_value,
        grant,
        requirement,
        response_schema,
        fact_schema,
        adapter_parameters_schema,
        prepare_script,
        extract_script,
        derivation_script,
    })
}

fn compile_referenced_question(
    selectors: &BTreeMap<String, Value>,
    sources: &BTreeMap<String, Value>,
    authored: AuthoredQuestion,
) -> Result<QuestionPlan> {
    let question = &authored.question;
    let source_id = question
        .source
        .source_ref
        .as_deref()
        .expect("referenced source was validated");
    let source_value = sources
        .get(source_id)
        .ok_or_else(|| {
            anyhow!("question source ref `{source_id}` has no sources/{source_id}.yaml")
        })?
        .clone();
    let subjects = compile_referenced_subjects(question, &source_value, selectors)?;

    let requirement_uri = local_uri(&format!("requirement:{}", question.id));
    let concepts = question
        .answers
        .iter()
        .map(|answer| compile_concept(&question.id, answer))
        .collect::<Vec<_>>();
    let requirement_kind =
        if concepts.len() == 1 && concepts[0].concept_form == CompiledConceptForm::Boolean {
            "criterion"
        } else {
            "information-requirement"
        };
    let (grant, requirement) = render_governance_parts(
        question,
        &subjects,
        source_id,
        &BundleRequirement {
            requirement_uri: requirement_uri.clone(),
            kind: requirement_kind,
            concepts: &concepts,
        },
    );
    let derivation_script = render_derivation(&authored.derivation, &concepts);

    Ok(QuestionPlan {
        question_id: question.id.clone(),
        source_artifact_id: source_id.to_owned(),
        authored_source_artifacts: Some(referenced_source_artifacts(&source_value)?),
        derivation_artifact: question.derivation.clone(),
        purpose: question.purpose.clone(),
        requirement_uri,
        concepts,
        subjects,
        source_id: source_id.to_owned(),
        source_value,
        grant,
        requirement,
        response_schema: Value::Null,
        fact_schema: Value::Null,
        adapter_parameters_schema: Value::Null,
        prepare_script: String::new(),
        extract_script: String::new(),
        derivation_script,
    })
}

fn compile_referenced_subjects(
    question: &Question,
    source: &Value,
    selectors: &BTreeMap<String, Value>,
) -> Result<Vec<SubjectPlan>> {
    let authored = question_subjects(question)?;
    let mut compiled = Vec::with_capacity(authored.len());
    for subject in authored {
        let selector_profile = match &subject.profile {
            Some(profile) => profile.clone(),
            None => referenced_selector_profile(source, &subject.role, &subject.selector)?,
        };
        let selector_profile_value = selectors
            .get(&selector_profile)
            .ok_or_else(|| {
                anyhow!("referenced source question uses missing selectors/{selector_profile}.yaml")
            })?
            .clone();
        let selector_fields = selector_profile_value
            .get("fields")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("selector profile `{selector_profile}` has no fields object"))?;
        if !selector_fields.contains_key(&subject.selector) {
            bail!(
                "selector profile `{selector_profile}` does not declare the question subject field"
            );
        }
        let used_by_source =
            source_uses_subject(source, &subject.role, &selector_profile, &subject.selector)?;
        if !used_by_source && !subject.derivation {
            bail!("every question subject must be used by the source or declared for derivation");
        }
        compiled.push(SubjectPlan {
            role: subject.role.clone(),
            selector_field: subject.selector.clone(),
            selector_profile,
            selector_profile_value,
            derivation: subject.derivation,
        });
    }

    let inputs = source
        .pointer("/request/selectorInputs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("referenced source request must declare selectorInputs"))?;
    for input in inputs {
        let role = input
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("source selector input has no role"))?;
        let matches = compiled
            .iter()
            .filter(|subject| {
                subject.role == role
                    && source_uses_subject(
                        source,
                        role,
                        &subject.selector_profile,
                        &subject.selector_field,
                    )
                    .unwrap_or(false)
            })
            .count();
        if matches != 1 {
            bail!("question subjects must select exactly one alternative for every source role");
        }
    }
    Ok(compiled)
}

fn source_uses_subject(source: &Value, role: &str, profile: &str, field: &str) -> Result<bool> {
    let inputs = source
        .pointer("/request/selectorInputs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("referenced source request must declare selectorInputs"))?;
    Ok(inputs.iter().any(|input| {
        input.get("role").and_then(Value::as_str) == Some(role)
            && input
                .get("alternatives")
                .and_then(Value::as_array)
                .is_some_and(|alternatives| {
                    alternatives.iter().any(|alternative| {
                        alternative.get("profile").and_then(Value::as_str) == Some(profile)
                            && alternative
                                .get("fields")
                                .and_then(Value::as_array)
                                .is_some_and(|fields| {
                                    fields.len() == 1 && fields[0].as_str() == Some(field)
                                })
                    })
                })
    }))
}

fn referenced_selector_profile(source: &Value, role: &str, field: &str) -> Result<String> {
    let inputs = source
        .pointer("/request/selectorInputs")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("referenced source request must declare selectorInputs"))?;
    let mut matches = Vec::new();
    for input in inputs {
        if input.get("role").and_then(Value::as_str) != Some(role) {
            continue;
        }
        let alternatives = input
            .get("alternatives")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("source selector alternatives must be an array"))?;
        for alternative in alternatives {
            let fields = alternative
                .get("fields")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("source selector fields must be an array"))?;
            if fields.iter().any(|value| value.as_str() == Some(field)) {
                matches.push(
                    alternative
                        .get("profile")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow!("source selector alternative has no profile"))?
                        .to_owned(),
                );
            }
        }
    }
    if matches.len() != 1 {
        bail!("question subject must match exactly one referenced source selector alternative");
    }
    Ok(matches.pop().expect("one selector profile"))
}

fn referenced_source_artifacts(source: &Value) -> Result<Vec<String>> {
    [
        "/request/prepareScript",
        "/request/adapterParametersSchema",
        "/responseSchema",
        "/extractScript",
        "/factSchema",
    ]
    .iter()
    .map(|pointer| {
        let path = source
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("referenced source is missing `{pointer}`"))?;
        validate_bundle_relative_artifact(path)?;
        Ok(path.to_owned())
    })
    .collect()
}

fn validate_bundle_relative_artifact(value: &str) -> Result<()> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.components().count() != 2
        || !matches!(
            path.components().next(),
            Some(Component::Normal(directory))
                if directory == "adapters" || directory == "schemas"
        )
    {
        bail!("referenced source artifacts must be adapters/<file> or schemas/<file>");
    }
    Ok(())
}

fn compile_concept(question_id: &str, answer: &QuestionAnswer) -> ConceptPlan {
    let concept_uri = local_uri(&format!("concept:{question_id}:{}", answer.concept));
    match answer.answer_type {
        AnswerType::Boolean => ConceptPlan {
            concept_alias: answer.concept.clone(),
            concept_uri,
            concept_form: CompiledConceptForm::Boolean,
            constraints: json!({}),
            codelist: None,
        },
        AnswerType::ControlledCategory => {
            let scheme = local_uri(&format!("category-scheme:{question_id}:{}", answer.concept));
            let path = format!("codelists/{question_id}-{}.yaml", answer.concept);
            let maximum_bytes = answer
                .values
                .iter()
                .map(String::len)
                .max()
                .expect("controlled categories were validated");
            ConceptPlan {
                concept_alias: answer.concept.clone(),
                concept_uri,
                concept_form: CompiledConceptForm::ControlledCategory,
                constraints: json!({
                    "categoryScheme": scheme,
                    "schemeVersion": "1",
                    "maximumBytes": maximum_bytes,
                    "codelist": path,
                }),
                codelist: Some((
                    path,
                    json!({
                        "id": scheme,
                        "version": "1",
                        "codes": answer.values,
                    }),
                )),
            }
        }
        AnswerType::BoundedInteger => ConceptPlan {
            concept_alias: answer.concept.clone(),
            concept_uri,
            concept_form: CompiledConceptForm::BoundedInteger,
            constraints: json!({
                "minimum": answer.minimum.expect("bounded integer was validated"),
                "maximum": answer.maximum.expect("bounded integer was validated"),
            }),
            codelist: None,
        },
    }
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

fn exact_path_selectors(operation: &Operation<'_>, expected: &[&str]) -> Result<()> {
    let mut parameters = Vec::new();
    for owner in [operation.path_item, operation.operation] {
        if let Some(values) = owner.get("parameters") {
            let values = values
                .as_array()
                .ok_or_else(|| anyhow!("OpenAPI parameters must be an array"))?;
            parameters.extend(values);
        }
    }
    if parameters.len() != expected.len() {
        bail!("the local tutorial operation must declare exactly one path selector per subject");
    }
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if expected.len() != parameters.len() {
        bail!("each OpenAPI question subject must use a distinct path selector");
    }
    let mut actual = BTreeSet::new();
    for parameter in parameters {
        let parameter = parameter
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
        let name = parameter
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("the path selector must have a name"))?;
        if parameter.contains_key("$ref")
            || parameter.get("in").and_then(Value::as_str) != Some("path")
            || parameter.get("required").and_then(Value::as_bool) != Some(true)
            || parameter_schema.get("type").and_then(Value::as_str) != Some("string")
            || !actual.insert(name)
        {
            bail!("question selectors must equal the operation's required string path parameters");
        }
    }
    if actual != expected {
        bail!("question selectors must equal the operation's required string path parameters");
    }
    if !operation.path.starts_with('/')
        || operation.path.starts_with("//")
        || operation.path.contains(['?', '#', '\\'])
        || operation
            .path
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        || expected.iter().any(|name| {
            let placeholder = format!("{{{name}}}");
            operation
                .path
                .split('/')
                .filter(|segment| *segment == placeholder)
                .count()
                != 1
        })
        || operation.path.matches('{').count() != expected.len()
        || operation.path.matches('}').count() != expected.len()
    {
        bail!("each path selector must occupy exactly one complete path segment");
    }
    Ok(())
}

fn compile_facts(
    spec: &Spec,
    operation: &Operation<'_>,
    source: &QuestionSource,
) -> Result<CompiledFacts> {
    let operation_key = OperationKey {
        method: operation.method.to_ascii_uppercase(),
        path: operation.path.to_owned(),
    };
    let resolved = spec.response_schema(&operation_key, "200", "application/json")?;
    for fact in &source.facts {
        validate_selected_schema_path(&resolved.schema.0, &fact.path)?;
    }
    let (candidate_leaves, _) = crate::suggest::flatten::candidate_leaves(&resolved.schema);
    let offered = candidate_leaves
        .iter()
        .map(|leaf| leaf.pointer.as_str())
        .collect::<BTreeSet<_>>();
    for fact in &source.facts {
        if !offered.contains(fact.path.as_str()) {
            bail!(
                "source fact `{}` path `{}` is not a selectable scalar leaf in the 200 application/json response",
                fact.name,
                fact.path
            );
        }
    }

    let projection = source
        .facts
        .iter()
        .map(|fact| fact.path.clone())
        .collect::<Vec<_>>();
    let used_collections = source
        .facts
        .iter()
        .flat_map(|fact| collection_pointers(&fact.path))
        .collect::<BTreeSet<_>>();
    let declared_collections = source
        .collection_bounds
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if used_collections != declared_collections {
        let missing = used_collections
            .difference(&declared_collections)
            .cloned()
            .collect::<Vec<_>>();
        let unused = declared_collections
            .difference(&used_collections)
            .cloned()
            .collect::<Vec<_>>();
        bail!(
            "source.collectionBounds must exactly name every selected collection (missing: {}; unused: {})",
            display_list(&missing),
            display_list(&unused)
        );
    }

    let plan = narrow::plan_advisories(
        &resolved.schema,
        &projection,
        &crate::suggest::types::Observations::default(),
    )?;
    if let Some(advisory) = plan.advisories.first() {
        bail!(
            "selected source schema needs adopter review: {}",
            advisory.message()
        );
    }
    let mut resolutions = BTreeMap::new();
    for need in &plan.needs {
        match need.kind {
            BoundKind::ArrayMaxItems => {
                let maximum = source.collection_bounds.get(&need.pointer).ok_or_else(|| {
                    anyhow!(
                        "selected collection `{}` is unbounded; declare it in source.collectionBounds",
                        need.pointer
                    )
                })?;
                resolutions.insert(
                    (need.pointer.clone(), BoundKind::ArrayMaxItems),
                    BoundValues::MaxItems(*maximum),
                );
            }
            BoundKind::IntegerRange | BoundKind::StringLength => bail!(
                "selected fact schema at `{}` is unbounded; add its closed bounds to the retained OpenAPI document",
                need.pointer
            ),
        }
    }
    let mut response_schema = narrow::apply(&resolved.schema, &projection, &resolutions)?.schema;
    close_selected_response(&mut response_schema, &projection, &source.collection_bounds)?;

    let mut fact_properties = Map::new();
    for fact in &source.facts {
        let leaf = schema_at_extended_pointer(&response_schema, &fact.path)?.clone();
        let property = match fact.combine {
            FactCombination::ExactlyOne => leaf,
            FactCombination::Collect => {
                let maximum = collection_pointers(&fact.path)
                    .iter()
                    .try_fold(1_u64, |product, pointer| {
                        product.checked_mul(source.collection_bounds[pointer])
                    })
                    .ok_or_else(|| {
                        anyhow!("source fact `{}` collection bound overflows", fact.name)
                    })?;
                if maximum > 256 {
                    bail!(
                        "source fact `{}` can collect {maximum} values; reduce collection bounds so the product is at most 256",
                        fact.name
                    );
                }
                json!({
                    "type": "array",
                    "minItems": 1,
                    "maxItems": maximum,
                    "items": leaf,
                })
            }
        };
        fact_properties.insert(fact.name.clone(), property);
    }
    let required = source
        .facts
        .iter()
        .map(|fact| Value::String(fact.name.clone()))
        .collect::<Vec<_>>();
    let fact_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": fact_properties,
    });

    Ok(CompiledFacts {
        response_schema,
        fact_schema,
        extract_script: render_fact_extraction(&source.facts),
    })
}

fn validate_selected_schema_path(schema: &Value, pointer: &str) -> Result<()> {
    let segments = parse_extended_pointer(pointer)?;
    validate_selected_schema_node(schema, &segments, "")
}

fn validate_selected_schema_node(
    node: &Value,
    segments: &[ExtendedSegment],
    pointer: &str,
) -> Result<()> {
    let object = node
        .as_object()
        .ok_or_else(|| anyhow!("selected OpenAPI schema node at `{pointer}` is not an object"))?;
    let primary_type = match object.get("type") {
        Some(Value::String(value)) => value.as_str(),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .find(|value| *value != "null")
            .ok_or_else(|| {
                anyhow!("selected OpenAPI schema node at `{pointer}` has no value type")
            })?,
        _ => bail!("selected OpenAPI schema node at `{pointer}` has no closed type"),
    };
    let mut allowed = vec![
        "type",
        "description",
        "title",
        "deprecated",
        "readOnly",
        "writeOnly",
        "example",
        "examples",
    ];
    allowed.extend(match primary_type {
        "object" => &["properties", "required", "additionalProperties"][..],
        "array" => &["items", "minItems", "maxItems", "uniqueItems", "const"][..],
        "string" => &["format", "minLength", "maxLength", "enum", "const"][..],
        "integer" => &["minimum", "maximum", "enum", "const"][..],
        "boolean" => &["enum", "const"][..],
        other => {
            bail!("selected OpenAPI schema node at `{pointer}` has unsupported type `{other}`")
        }
    });
    reject_unsupported_keys(
        object,
        &allowed,
        &format!("selected OpenAPI schema at `{pointer}`"),
    )?;

    let Some((segment, rest)) = segments.split_first() else {
        return Ok(());
    };
    match (primary_type, segment) {
        ("object", ExtendedSegment::Key(key)) => {
            let child = object
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(key))
                .ok_or_else(|| {
                    anyhow!("selected OpenAPI schema at `{pointer}` has no member `{key}`")
                })?;
            validate_selected_schema_node(
                child,
                rest,
                &format!("{pointer}/{}", escape_pointer_segment(key)),
            )
        }
        ("array", ExtendedSegment::Wildcard) => {
            let child = object
                .get("items")
                .ok_or_else(|| anyhow!("selected OpenAPI array at `{pointer}` has no items"))?;
            validate_selected_schema_node(child, rest, &format!("{pointer}/*"))
        }
        ("object", ExtendedSegment::Wildcard) => {
            bail!("selected fact path uses `*` at object `{pointer}`")
        }
        ("array", ExtendedSegment::Key(_)) => {
            bail!("selected fact path must use `*` at array `{pointer}`")
        }
        _ => bail!("selected fact path continues past scalar `{pointer}`"),
    }
}

fn collection_pointers(pointer: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut collections = Vec::new();
    for segment in pointer.split('/').skip(1) {
        if segment == "*" {
            collections.push(format!("/{}", parts.join("/")));
        }
        parts.push(segment);
    }
    collections
}

fn display_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    }
}

fn close_selected_response(
    schema: &mut Value,
    selections: &[String],
    collection_bounds: &BTreeMap<String, u64>,
) -> Result<()> {
    for selection in selections {
        let segments = parse_extended_pointer(selection)?;
        close_selected_path(schema, &segments, "", collection_bounds)?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum ExtendedSegment {
    Key(String),
    Wildcard,
}

fn parse_extended_pointer(pointer: &str) -> Result<Vec<ExtendedSegment>> {
    if pointer.is_empty() || !pointer.starts_with('/') {
        bail!("source fact path must be a non-empty extended JSON Pointer");
    }
    pointer
        .split('/')
        .skip(1)
        .map(|segment| {
            if segment == "*" {
                Ok(ExtendedSegment::Wildcard)
            } else {
                decode_pointer_segment(segment).map(ExtendedSegment::Key)
            }
        })
        .collect()
}

fn decode_pointer_segment(segment: &str) -> Result<String> {
    let mut decoded = String::new();
    let mut characters = segment.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => bail!("source fact path contains an invalid JSON Pointer escape"),
        }
    }
    Ok(decoded)
}

fn close_selected_path(
    node: &mut Value,
    segments: &[ExtendedSegment],
    pointer: &str,
    collection_bounds: &BTreeMap<String, u64>,
) -> Result<()> {
    make_non_nullable(node);
    let Some((segment, rest)) = segments.split_first() else {
        return Ok(());
    };
    let object = node.as_object_mut().ok_or_else(|| {
        anyhow!("selected response path crosses a non-schema node at `{pointer}`")
    })?;
    match segment {
        ExtendedSegment::Key(key) => {
            let required = object
                .get_mut("required")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    anyhow!("selected response object at `{pointer}` has no required list")
                })?;
            if !required.iter().any(|value| value.as_str() == Some(key)) {
                required.push(Value::String(key.clone()));
            }
            let properties = object
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    anyhow!("selected response path expects an object at `{pointer}`")
                })?;
            let child = properties
                .get_mut(key)
                .ok_or_else(|| anyhow!("selected response path does not declare `{key}`"))?;
            let child_pointer = format!("{pointer}/{}", escape_pointer_segment(key));
            close_selected_path(child, rest, &child_pointer, collection_bounds)
        }
        ExtendedSegment::Wildcard => {
            let maximum = collection_bounds.get(pointer).ok_or_else(|| {
                anyhow!("selected response collection `{pointer}` has no authored bound")
            })?;
            let minimum = object.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            if minimum > *maximum {
                bail!(
                    "source.collectionBounds sets `{pointer}` to {maximum}, below its declared minItems {minimum}"
                );
            }
            object.insert("minItems".to_owned(), Value::from(minimum.max(1)));
            object.insert("maxItems".to_owned(), Value::from(*maximum));
            let items = object.get_mut("items").ok_or_else(|| {
                anyhow!("selected response collection `{pointer}` has no items schema")
            })?;
            close_selected_path(items, rest, &format!("{pointer}/*"), collection_bounds)
        }
    }
}

fn make_non_nullable(node: &mut Value) {
    let Some(object) = node.as_object_mut() else {
        return;
    };
    let Some(Value::Array(types)) = object.get("type") else {
        return;
    };
    if types.len() == 2 && types.iter().any(|value| value.as_str() == Some("null")) {
        if let Some(value_type) = types.iter().find(|value| value.as_str() != Some("null")) {
            object.insert("type".to_owned(), value_type.clone());
        }
    }
}

fn schema_at_extended_pointer<'a>(schema: &'a Value, pointer: &str) -> Result<&'a Value> {
    let mut node = schema;
    for segment in parse_extended_pointer(pointer)? {
        node = match segment {
            ExtendedSegment::Key(key) => node
                .get("properties")
                .and_then(|properties| properties.get(&key))
                .ok_or_else(|| anyhow!("generated response schema lost selected member `{key}`"))?,
            ExtendedSegment::Wildcard => node.get("items").ok_or_else(|| {
                anyhow!("generated response schema lost selected collection items")
            })?,
        };
    }
    Ok(node)
}

fn render_fact_extraction(facts: &[QuestionFact]) -> String {
    let mut rendered =
        String::from("fn extract(source_response, parameters) {\n    let facts = #{};\n");
    for (index, fact) in facts.iter().enumerate() {
        let name = json_string(&fact.name);
        match fact.combine {
            FactCombination::ExactlyOne => rendered.push_str(&format!(
                "    facts[{name}] = required(get_path(source_response, {}), \"source_fact_missing\");\n",
                json_string(&fact.path)
            )),
            FactCombination::Collect => {
                rendered.push_str(&format!("    let collected_{index} = [];\n"));
                render_collection_walk(&mut rendered, index, &fact.path);
                rendered.push_str(&format!("    facts[{name}] = collected_{index};\n"));
            }
        }
    }
    rendered.push_str("    #{outcome: \"match\", facts: facts}\n}\n");
    rendered
}

fn render_collection_walk(rendered: &mut String, fact_index: usize, pointer: &str) {
    let segments = pointer.split('/').skip(1).collect::<Vec<_>>();
    let wildcard_count = segments.iter().filter(|segment| **segment == "*").count();
    let mut cursor = "source_response".to_owned();
    let mut start = 0;
    let mut depth = 0;
    for (position, segment) in segments.iter().enumerate() {
        if *segment != "*" {
            continue;
        }
        let relative = format!("/{}", segments[start..position].join("/"));
        let items = format!("items_{fact_index}_{depth}");
        let item = format!("item_{fact_index}_{depth}");
        let indent = "    ".repeat(depth + 1);
        let collection = if relative == "/" {
            cursor.clone()
        } else {
            format!("get_path({cursor}, {})", json_string(&relative))
        };
        rendered.push_str(&format!(
            "{indent}let {items} = required({collection}, \"source_collection_missing\");\n"
        ));
        rendered.push_str(&format!("{indent}for {item} in {items} {{\n"));
        cursor = item;
        start = position + 1;
        depth += 1;
    }
    debug_assert_eq!(depth, wildcard_count);
    let tail = segments[start..].join("/");
    let indent = "    ".repeat(depth + 1);
    let value = if tail.is_empty() {
        cursor
    } else {
        format!("get_path({cursor}, {})", json_string(&format!("/{tail}")))
    };
    rendered.push_str(&format!(
        "{indent}collected_{fact_index}.push(required({value}, \"source_fact_missing\"));\n"
    ));
    for closing_depth in (0..depth).rev() {
        rendered.push_str(&format!("{}}}\n", "    ".repeat(closing_depth + 1)));
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

fn render_derivation(authored: &str, concepts: &[ConceptPlan]) -> String {
    let mut rendered = authored.trim_end().to_owned();
    rendered.push_str("\n\n");
    rendered.push_str("fn derive(facts, selectors, evaluation_context) {\n");
    rendered.push_str("    let governed_answers = answer(facts, selectors, evaluation_context);\n");
    rendered.push_str("    [\n");
    for (index, concept) in concepts.iter().enumerate() {
        rendered.push_str("        #{\n");
        rendered.push_str(&format!(
            "            concept_id: {},\n",
            json_string(&concept.concept_uri)
        ));
        rendered.push_str(&format!(
            "            value: governed_answers[{}]\n",
            json_string(&concept.concept_alias)
        ));
        rendered.push_str("        }");
        if index + 1 != concepts.len() {
            rendered.push(',');
        }
        rendered.push('\n');
    }
    rendered.push_str("    ]\n}\n");
    rendered
}

fn render_question_bundle_parts(
    question: &Question,
    base_url: &str,
    path_template: &str,
    subjects: &[SubjectPlan],
    source_id: &str,
    requirement: &BundleRequirement,
) -> (Value, Value, Value) {
    let path_bindings = Value::Object(Map::from_iter(subjects.iter().map(|subject| {
        (
            subject.selector_field.clone(),
            json!({
                "role": subject.role,
                "profile": subject.selector_profile,
                "field": subject.selector_field,
            }),
        )
    })));
    let selector_inputs = subjects
        .iter()
        .map(|subject| {
            json!({
                "role": subject.role,
                "alternatives": [{
                    "profile": subject.selector_profile,
                    "fields": [subject.selector_field],
                }],
            })
        })
        .collect::<Vec<_>>();
    let projection = question
        .source
        .facts
        .iter()
        .map(|fact| Value::String(fact.path.clone()))
        .collect::<Vec<_>>();

    let source_value = json!({
        "transport": "http-json",
        "baseUrl": base_url,
        "posture": "field-projected",
        "authentication": {"kind": "none"},
        "request": {
            "method": "GET",
            "pathTemplate": path_template,
            "pathBindings": path_bindings,
            "fixedHeaders": [{"name": "Accept", "value": "application/json"}],
            "selectorInputs": selector_inputs,
            "prepareScript": format!("adapters/{}-source-prepare.rhai", question.id),
            "adapterParameters": {"operationId": question.source.operation.as_deref().expect("inline source")},
            "adapterParametersSchema": format!(
                "schemas/{}-source-adapter-parameters.schema.yaml",
                question.id
            ),
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
        "responseSchema": format!("schemas/{}-source-response.schema.yaml", question.id),
        "extractScript": format!("adapters/{}-source-extract.rhai", question.id),
        "factSchema": format!("schemas/{}-source-facts.schema.yaml", question.id),
    });
    let (grant, requirement_value) =
        render_governance_parts(question, subjects, source_id, requirement);
    (source_value, grant, requirement_value)
}

fn render_governance_parts(
    question: &Question,
    subjects: &[SubjectPlan],
    source_id: &str,
    requirement: &BundleRequirement<'_>,
) -> (Value, Value) {
    let framework_id = local_uri(&format!("framework:{}", question.id));
    let evidence_type = local_uri(&format!("evidence-type:{}", question.id));
    let disclosure_family = local_uri(&format!("disclosure-family:{}", question.id));
    let grant_subjects = subjects
        .iter()
        .map(|subject| {
            json!({
                "role": subject.role,
                "selectorProfile": subject.selector_profile,
                "valueOrigin": "request",
            })
        })
        .collect::<Vec<_>>();
    let grant = json!({
        "requirement": requirement.requirement_uri,
        "purpose": question.purpose,
        "audienceFrom": "authenticated-requester",
        "responseFormats": ["signed-jws"],
        "subjects": grant_subjects,
    });
    let concepts = requirement
        .concepts
        .iter()
        .map(|concept| {
            json!({
                "id": concept.concept_uri,
                "form": match concept.concept_form {
                    CompiledConceptForm::Boolean => "boolean",
                    CompiledConceptForm::ControlledCategory => "controlled-category",
                    CompiledConceptForm::BoundedInteger => "bounded-integer",
                },
                "required": true,
                "constraints": concept.constraints,
            })
        })
        .collect::<Vec<_>>();
    let subject_roles = subjects
        .iter()
        .map(|subject| {
            json!({
                "role": subject.role,
                "cardinality": "one",
                "selectorProfiles": [subject.selector_profile],
            })
        })
        .collect::<Vec<_>>();
    let selector_inputs = subjects
        .iter()
        .filter(|subject| subject.derivation)
        .map(|subject| {
            json!({
                "role": subject.role,
                "alternatives": [{
                    "profile": subject.selector_profile,
                    "fields": [subject.selector_field],
                }],
            })
        })
        .collect::<Vec<_>>();
    let mut derivation = Map::from_iter([
        ("script".to_owned(), json!(question.derivation)),
        ("parameters".to_owned(), json!({})),
    ]);
    if !selector_inputs.is_empty() {
        derivation.insert("selectorInputs".to_owned(), Value::Array(selector_inputs));
    }
    let requirement_value = json!({
            "id": requirement.requirement_uri,
            "kind": requirement.kind,
            "source": source_id,
            "purposes": [question.purpose],
            "subjectRoles": subject_roles,
            "referenceFrameworks": [framework_id],
            "evidenceType": evidence_type,
            "observationTimezone": "UTC",
            "validitySeconds": 300,
            "derivation": derivation,
            "concepts": concepts,
            "disclosureGuard": {"families": [disclosure_family]},
            "existenceDisclosure": "collapse-unresolved",
    });
    (grant, requirement_value)
}

fn render_bundle(questions: &[QuestionPlan], ports: LocalServicePorts) -> Value {
    let mint_origin = ports.mint_origin();
    let selector_profiles = questions
        .iter()
        .flat_map(|question| &question.subjects)
        .map(|subject| {
            (
                subject.selector_profile.clone(),
                subject.selector_profile_value.clone(),
            )
        })
        .collect::<Map<_, _>>();
    let sources = questions
        .iter()
        .map(|question| (question.source_id.clone(), question.source_value.clone()))
        .collect::<Map<_, _>>();
    let grants = questions
        .iter()
        .map(|question| question.grant.clone())
        .collect::<Vec<_>>();
    let requirements = questions
        .iter()
        .map(|question| question.requirement.clone())
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
            "issuer": mint_origin,
            "audiences": [LOCAL_AUDIENCE],
            "tokenTypes": ["at+jwt"],
            "algorithms": ["EdDSA"],
            "jwksUri": format!("{mint_origin}/.well-known/jwks.json"),
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
        "selectorProfiles": selector_profiles,
        "sources": sources,
        "authorityProfiles": {
            AUTHORITY_PROFILE_ID: {
                "kind": "explicit-request",
                "requesterTags": [AUTHORITY_PROFILE_ID],
                "grants": grants,
            }
        },
        "requirements": requirements,
    })
}

fn write_plan(
    project_root: &Path,
    staging_root: &Path,
    plan: &CompilePlan,
    ports: LocalServicePorts,
) -> Result<CompiledProject> {
    let bundle = staging_root.join("bundle");
    create_private_directory(&bundle)?;
    for directory in ["adapters", "derivations", "schemas"] {
        create_private_directory(&bundle.join(directory))?;
    }
    if plan
        .questions
        .iter()
        .flat_map(|question| &question.concepts)
        .any(|concept| concept.codelist.is_some())
    {
        create_private_directory(&bundle.join("codelists"))?;
    }
    create_private_directory(&staging_root.join("audit"))?;

    write_private_file(&bundle.join("evidence.yaml"), &yaml_bytes(&plan.bundle)?)?;
    let mut written_sources = BTreeSet::new();
    for question in &plan.questions {
        if written_sources.insert(question.source_artifact_id.clone()) {
            if let Some(artifacts) = &question.authored_source_artifacts {
                for artifact in artifacts {
                    let bytes = read_regular_file(
                        &project_root.join(artifact),
                        MAX_SOURCE_ARTIFACT_BYTES,
                        "referenced source artifact",
                    )?;
                    write_private_file(&bundle.join(artifact), &bytes)?;
                }
            } else {
                write_private_file(
                    &bundle.join(format!(
                        "adapters/{}-source-prepare.rhai",
                        question.question_id
                    )),
                    question.prepare_script.as_bytes(),
                )?;
                write_private_file(
                    &bundle.join(format!(
                        "adapters/{}-source-extract.rhai",
                        question.question_id
                    )),
                    question.extract_script.as_bytes(),
                )?;
                write_private_file(
                    &bundle.join(format!(
                        "schemas/{}-source-response.schema.yaml",
                        question.question_id
                    )),
                    &yaml_bytes(&question.response_schema)?,
                )?;
                write_private_file(
                    &bundle.join(format!(
                        "schemas/{}-source-facts.schema.yaml",
                        question.question_id
                    )),
                    &yaml_bytes(&question.fact_schema)?,
                )?;
                write_private_file(
                    &bundle.join(format!(
                        "schemas/{}-source-adapter-parameters.schema.yaml",
                        question.question_id
                    )),
                    &yaml_bytes(&question.adapter_parameters_schema)?,
                )?;
            }
        }
        write_private_file(
            &bundle.join(&question.derivation_artifact),
            question.derivation_script.as_bytes(),
        )?;
        for (path, codelist) in question
            .concepts
            .iter()
            .filter_map(|concept| concept.codelist.as_ref())
        {
            write_private_file(&bundle.join(path), &yaml_bytes(codelist)?)?;
        }
    }

    let canonical_staging = fs::canonicalize(staging_root)
        .with_context(|| format!("resolving staging root {}", staging_root.display()))?;
    let secret_root = fs::canonicalize(project_root.join(SECRETS_DIRECTORY))
        .context("resolving local secret directory")?;
    let runtime = json!({
        "version": 1,
        "bundleDirectory": canonical_staging.join("bundle").to_string_lossy(),
        "listener": {
            "bindHost": "127.0.0.1",
            "port": ports.evidence,
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

    let questions = plan
        .questions
        .iter()
        .map(|question| CompiledQuestion {
            question_alias: question.question_id.clone(),
            requirement_uri: question.requirement_uri.clone(),
            purpose: question.purpose.clone(),
            subjects: question
                .subjects
                .iter()
                .map(|subject| CompiledSubject {
                    role: subject.role.clone(),
                    selector_profile: subject.selector_profile.clone(),
                    selector_field: subject.selector_field.clone(),
                })
                .collect(),
            concepts: question
                .concepts
                .iter()
                .map(|concept| CompiledConcept {
                    concept_alias: concept.concept_alias.clone(),
                    concept_uri: concept.concept_uri.clone(),
                    concept_form: concept.concept_form,
                })
                .collect(),
        })
        .collect();
    Ok(CompiledProject {
        runtime_path,
        questions,
        local_audience: LOCAL_AUDIENCE.to_owned(),
        requester_tag: AUTHORITY_PROFILE_ID.to_owned(),
        caller_evidence_audience: LOCAL_CALLER_EVIDENCE_AUDIENCE.to_owned(),
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

fn local_selector_profile_id(question_id: &str) -> String {
    format!("local-subject-{question_id}-v1")
}

fn local_subject_selector_profile_id(
    question_id: &str,
    role: &str,
    subject_count: usize,
) -> String {
    if subject_count == 1 {
        local_selector_profile_id(question_id)
    } else {
        format!("local-subject-{question_id}-{role}-v1")
    }
}

fn local_source_id(question_id: &str) -> String {
    format!("local-source-{question_id}")
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
                  date_of_birth: {type: string, format: date}
"#;

    const QUESTION: &str = r#"id: adult-status
question: Is the person at least 18 years old?
purpose: age-check
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: is_adult
    type: boolean
derivation: derivations/adult-status.rhai
disclosure:
  allow: [is_adult]
"#;

    const RELATIONSHIP_OPENAPI: &str = r#"openapi: 3.1.0
info: {title: Tutorial family registry, version: 1.0.0}
servers: [{url: 'http://127.0.0.1:8000'}]
paths:
  /children/{child_id}/candidate-parents/{candidate_id}:
    get:
      operationId: getParentRelationship
      parameters:
        - name: child_id
          in: path
          required: true
          schema: {type: string}
        - name: candidate_id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200':
          description: A governed relationship decision
          content:
            application/json:
              schema:
                type: object
                required: [relationship_confirmed]
                properties:
                  relationship_confirmed: {type: boolean}
"#;

    const RELATIONSHIP_QUESTION: &str = r#"id: parent-relationship
question: Is the candidate registered as a parent of the child?
purpose: relationship-check
subjects:
  - role: child
    selector: child_id
  - role: candidate-parent
    selector: candidate_id
source:
  operation: getParentRelationship
  facts:
    - name: relationship_confirmed
      path: /relationship_confirmed
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: relationship_confirmed
    type: boolean
derivation: derivations/parent-relationship.rhai
disclosure:
  allow: [relationship_confirmed]
"#;

    const RELATIONSHIP_ANSWER: &str = r#"fn answer(facts, selectors, context) {
    #{relationship_confirmed: required(facts.relationship_confirmed, "relationship_missing")}
}
"#;

    const ANSWER: &str = r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    let adult_on = add_calendar_years(born, 18);
    #{is_adult: compare_dates(context.legal_local_date, adult_on) >= 0}
}
"#;

    const AGE_BRACKET_QUESTION: &str = r#"id: age-bracket
question: Which age bracket does this person belong to?
purpose: service-path-selection
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: age_bracket
    type: controlled-category
    values: [under-18, 18-to-24, 25-to-64, 65-or-older]
derivation: derivations/age-bracket.rhai
disclosure:
  allow: [age_bracket]
"#;

    const AGE_BRACKET_ANSWER: &str = r#"fn answer(facts, selectors, context) {
    let born = parse_date(required(facts.date_of_birth, "date_of_birth_missing"));
    if compare_dates(context.legal_local_date, add_calendar_years(born, 18)) < 0 {
        #{age_bracket: "under-18"}
    } else if compare_dates(context.legal_local_date, add_calendar_years(born, 25)) < 0 {
        #{age_bracket: "18-to-24"}
    } else if compare_dates(context.legal_local_date, add_calendar_years(born, 65)) < 0 {
        #{age_bracket: "25-to-64"}
    } else {
        #{age_bracket: "65-or-older"}
    }
}
"#;

    const IMMUNIZATION_QUESTION: &str = r#"id: immunization-summary
question: Is the immunization schedule complete, and how many doses are recorded?
purpose: care-coordination
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: dose_count
      path: /dose_count
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: schedule_complete
    type: boolean
  - concept: dose_count
    type: bounded-integer
    minimum: 0
    maximum: 20
derivation: derivations/immunization-summary.rhai
disclosure:
  allow: [schedule_complete, dose_count]
"#;

    const IMMUNIZATION_ANSWER: &str = r#"fn answer(facts, selectors, context) {
    let dose_count = required(facts.dose_count, "dose_count_missing");
    #{schedule_complete: dose_count >= 3, dose_count: dose_count}
}
"#;

    const MULTI_EVENT_OPENAPI: &str = r#"openapi: 3.1.0
info: {title: Sanitized tracker API, version: 1.0.0}
servers: [{url: 'http://127.0.0.1:8000'}]
paths:
  /records/{record_id}/events:
    get:
      operationId: listRecordEvents
      parameters:
        - name: record_id
          in: path
          required: true
          schema: {type: string}
      responses:
        '200':
          description: Bounded event history
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/EventPage'
components:
  schemas:
    EventPage:
      type: object
      additionalProperties: false
      properties:
        events:
          type: array
          items:
            $ref: '#/components/schemas/Event'
    Event:
      type: object
      additionalProperties: false
      properties:
        event: {type: string, minLength: 1, maxLength: 64}
        status: {type: string, minLength: 1, maxLength: 32}
        occurredAt: {type: string, format: date-time}
"#;

    const MULTI_EVENT_QUESTION: &str = r#"id: event-history
question: Did the bounded event history satisfy the reviewed rule?
purpose: history-review
subject:
  role: record
  selector: record_id
source:
  operation: listRecordEvents
  facts:
    - name: event_statuses
      path: /events/*/status
      combine: collect
    - name: event_times
      path: /events/*/occurredAt
      combine: collect
  collectionBounds:
    /events: 4
answers:
  - concept: history_satisfies_rule
    type: boolean
derivation: derivations/event-history.rhai
disclosure:
  allow: [history_satisfies_rule]
"#;

    const MULTI_EVENT_ANSWER: &str = r#"fn answer(facts, selectors, context) {
    #{history_satisfies_rule: len(required(facts.event_statuses, "event_statuses_missing")) > 0}
}
"#;

    const MULTI_EVENT_RESPONSE: &str = r#"{
  "events": [
    {"event": "evt-001", "status": "completed", "occurredAt": "2026-07-01T08:00:00Z"},
    {"event": "evt-002", "status": "cancelled", "occurredAt": "2026-07-02T09:00:00Z"}
  ]
}"#;

    #[test]
    fn compiles_only_the_canonical_private_local_generation() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("local compilation succeeds");

        assert_eq!(compiled.runtime_path, fixture.staging.join("runtime.yaml"));
        assert_eq!(compiled.questions.len(), 1);
        let question = &compiled.questions[0];
        assert_eq!(question.question_alias, "adult-status");
        assert_eq!(
            question.requirement_uri,
            "urn:registrystack:evidence:local:requirement:adult-status"
        );
        assert_eq!(
            question.concepts[0].concept_uri,
            "urn:registrystack:evidence:local:concept:adult-status:is_adult"
        );
        assert_eq!(question.purpose, "age-check");
        assert_eq!(question.subjects[0].role, "person");
        assert_eq!(
            question.subjects[0].selector_profile,
            local_selector_profile_id("adult-status")
        );
        assert_eq!(question.subjects[0].selector_field, "person_id");
        assert_eq!(question.concepts[0].concept_alias, "is_adult");
        assert_eq!(
            question.concepts[0].concept_form,
            CompiledConceptForm::Boolean
        );
        assert_eq!(compiled.local_audience, LOCAL_AUDIENCE);
        assert_eq!(compiled.requester_tag, AUTHORITY_PROFILE_ID);
        assert_eq!(
            compiled.caller_evidence_audience,
            LOCAL_CALLER_EVIDENCE_AUDIENCE
        );
        assert_eq!(
            tree(&fixture.staging),
            vec![
                "audit/",
                "bundle/",
                "bundle/adapters/",
                "bundle/adapters/adult-status-source-extract.rhai",
                "bundle/adapters/adult-status-source-prepare.rhai",
                "bundle/derivations/",
                "bundle/derivations/adult-status.rhai",
                "bundle/evidence.yaml",
                "bundle/schemas/",
                "bundle/schemas/adult-status-source-adapter-parameters.schema.yaml",
                "bundle/schemas/adult-status-source-facts.schema.yaml",
                "bundle/schemas/adult-status-source-response.schema.yaml",
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
        let source_id = local_source_id("adult-status");
        let selector_profile = local_selector_profile_id("adult-status");
        assert_eq!(
            bundle["sources"][&source_id]["authentication"],
            json!({"kind": "none"})
        );
        assert_eq!(
            bundle["sources"][&source_id]["request"]["pathBindings"]["person_id"],
            json!({"role": "person", "profile": selector_profile, "field": "person_id"})
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
        assert!(derivation
            .contains("let governed_answers = answer(facts, selectors, evaluation_context)"));
        assert!(derivation.contains("value: governed_answers[\"is_adult\"]"));
        assert!(!derivation.contains("concept_id: \"is_adult\""));
    }

    #[test]
    fn inline_openapi_question_compiles_multiple_role_bound_subjects() {
        let fixture = Fixture::new(
            RELATIONSHIP_OPENAPI,
            RELATIONSHIP_QUESTION,
            RELATIONSHIP_ANSWER,
            true,
        );
        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("multi-subject local compilation succeeds");

        let question = &compiled.questions[0];
        assert_eq!(question.subjects.len(), 2);
        assert_eq!(question.subjects[0].role, "child");
        assert_eq!(question.subjects[0].selector_field, "child_id");
        assert_eq!(question.subjects[1].role, "candidate-parent");
        assert_eq!(question.subjects[1].selector_field, "candidate_id");

        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        let source = &bundle["sources"][local_source_id("parent-relationship")];
        assert_eq!(
            source["request"]["pathBindings"]["child_id"]["role"],
            "child"
        );
        assert_eq!(
            source["request"]["pathBindings"]["candidate_id"]["role"],
            "candidate-parent"
        );
        assert_eq!(
            source["request"]["selectorInputs"]
                .as_array()
                .expect("selector inputs")
                .len(),
            2
        );
        assert_eq!(
            bundle["requirements"][0]["subjectRoles"]
                .as_array()
                .expect("subject roles")
                .len(),
            2
        );
        assert_eq!(
            bundle["authorityProfiles"][AUTHORITY_PROFILE_ID]["grants"][0]["subjects"]
                .as_array()
                .expect("grant subjects")
                .len(),
            2
        );

        for invalid_question in [
            RELATIONSHIP_QUESTION.replace(
                "  - role: candidate-parent\n    selector: candidate_id\n",
                "",
            ),
            RELATIONSHIP_QUESTION.replace("role: candidate-parent", "role: child"),
            RELATIONSHIP_QUESTION.replace("selector: candidate_id", "selector: person_id"),
        ] {
            let fixture = Fixture::new(
                RELATIONSHIP_OPENAPI,
                &invalid_question,
                RELATIONSHIP_ANSWER,
                true,
            );
            compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                .expect_err("incomplete or ambiguous role binding is rejected");
            assert!(fixture.staging_is_empty());
        }
    }

    #[test]
    fn compiles_one_closed_controlled_category() {
        let fixture = Fixture::new(OPENAPI, AGE_BRACKET_QUESTION, AGE_BRACKET_ANSWER, true);
        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("controlled category compiles");

        assert_eq!(
            compiled.questions[0].concepts[0].concept_form,
            CompiledConceptForm::ControlledCategory
        );
        let codelist: Value = serde_norway::from_slice(
            &fs::read(
                fixture
                    .staging
                    .join("bundle/codelists/age-bracket-age_bracket.yaml"),
            )
            .expect("codelist reads"),
        )
        .expect("codelist parses");
        assert_eq!(
            codelist["codes"],
            json!(["under-18", "18-to-24", "25-to-64", "65-or-older"])
        );
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        assert_eq!(bundle["requirements"][0]["kind"], "information-requirement");
        assert_eq!(
            bundle["requirements"][0]["concepts"][0]["form"],
            "controlled-category"
        );
    }

    #[test]
    fn compiles_boolean_and_bounded_integer_into_one_signed_assertion_bundle() {
        let openapi = OPENAPI
            .replace(
                "required: [person_id, name, date_of_birth]",
                "required: [person_id, name, date_of_birth, dose_count]",
            )
            .replace(
                "                  date_of_birth: {type: string, format: date}",
                "                  date_of_birth: {type: string, format: date}\n                  dose_count: {type: integer, minimum: 0, maximum: 20}",
            );
        let fixture = Fixture::new(&openapi, IMMUNIZATION_QUESTION, IMMUNIZATION_ANSWER, true);
        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("multiple governed answers compile");

        assert_eq!(
            compiled.questions[0]
                .concepts
                .iter()
                .map(|concept| (concept.concept_alias.as_str(), concept.concept_form))
                .collect::<Vec<_>>(),
            [
                ("schedule_complete", CompiledConceptForm::Boolean),
                ("dose_count", CompiledConceptForm::BoundedInteger),
            ]
        );
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        let requirement = &bundle["requirements"][0];
        assert_eq!(requirement["kind"], "information-requirement");
        assert_eq!(requirement["concepts"].as_array().unwrap().len(), 2);
        assert_eq!(requirement["concepts"][0]["form"], "boolean");
        assert_eq!(requirement["concepts"][1]["form"], "bounded-integer");
        assert_eq!(
            requirement["concepts"][1]["constraints"],
            json!({"minimum": 0, "maximum": 20})
        );
        let derivation = fs::read_to_string(
            fixture
                .staging
                .join("bundle/derivations/immunization-summary.rhai"),
        )
        .expect("derivation reads");
        assert!(derivation.contains("value: governed_answers[\"schedule_complete\"]"));
        assert!(derivation.contains("value: governed_answers[\"dose_count\"]"));
        assert!(derivation.contains(
            "urn:registrystack:evidence:local:concept:immunization-summary:schedule_complete"
        ));
        assert!(derivation
            .contains("urn:registrystack:evidence:local:concept:immunization-summary:dose_count"));
    }

    #[test]
    fn compiles_every_authored_question_into_one_generation() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fixture.add_question(AGE_BRACKET_QUESTION, AGE_BRACKET_ANSWER);

        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("multiple questions compile");

        assert_eq!(
            compiled
                .questions
                .iter()
                .map(|question| question.question_alias.as_str())
                .collect::<Vec<_>>(),
            ["adult-status", "age-bracket"]
        );
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        assert_eq!(bundle["selectorProfiles"].as_object().unwrap().len(), 2);
        assert_eq!(bundle["sources"].as_object().unwrap().len(), 2);
        assert_eq!(
            bundle["authorityProfiles"][AUTHORITY_PROFILE_ID]["grants"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(bundle["requirements"].as_array().unwrap().len(), 2);
        assert!(fixture
            .staging
            .join("bundle/derivations/adult-status.rhai")
            .is_file());
        assert!(fixture
            .staging
            .join("bundle/derivations/age-bracket.rhai")
            .is_file());
    }

    #[test]
    fn referenced_v1_source_and_selector_are_reused_by_questions() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        for directory in ["sources", "selectors", "adapters", "schemas"] {
            fs::create_dir(fixture.project.join(directory)).expect("authoring directory");
        }
        fs::write(
            fixture.project.join("selectors/person-reference-v1.yaml"),
            "maximumAggregateBytes: 200\nfields:\n  person_id:\n    type: string\n    minimumBytes: 1\n    maximumBytes: 200\n",
        )
        .expect("selector");
        fs::write(
            fixture.project.join("sources/people.yaml"),
            r#"transport: http-json
baseUrl: https://records.example.test
posture: field-projected
authentication:
  kind: basic
  usernameRef: secret:file/records-username
  passwordRef: secret:file/records-password
request:
  method: GET
  pathTemplate: /people/{person_id}
  pathBindings:
    person_id: {role: person, profile: person-reference-v1, field: person_id}
  fixedHeaders: [{name: Accept, value: application/json}]
  selectorInputs:
    - role: person
      alternatives:
        - {profile: person-reference-v1, fields: [person_id]}
  prepareScript: adapters/people-prepare.rhai
  adapterParameters: {}
  adapterParametersSchema: schemas/people-parameters.schema.yaml
  preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
  projection: [/date_of_birth]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: schemas/people-response.schema.yaml
extractScript: adapters/people-extract.rhai
factSchema: schemas/people-facts.schema.yaml
"#,
        )
        .expect("source");
        for (path, contents) in [
            (
                "adapters/people-prepare.rhai",
                "fn prepare(s, p) { #{query: [], body: ()} }\n",
            ),
            (
                "adapters/people-extract.rhai",
                "fn extract(r, p) { #{outcome: \"match\", facts: r} }\n",
            ),
            (
                "schemas/people-parameters.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: []\nproperties: {}\n",
            ),
            (
                "schemas/people-response.schema.yaml",
                "type: object\nadditionalProperties: false\nproperties: {}\n",
            ),
            (
                "schemas/people-facts.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: []\nproperties: {}\n",
            ),
        ] {
            fs::write(fixture.project.join(path), contents).expect("source artifact");
        }
        let inline = r#"source:
  operation: getPerson
  facts:
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
"#;
        let referenced = QUESTION.replace(inline, "source:\n  ref: people\n");
        fs::write(
            fixture.project.join("questions/adult-status.yaml"),
            &referenced,
        )
        .expect("referenced question");
        let copied = referenced
            .replace("id: adult-status", "id: adult-status-copy")
            .replace(
                "derivations/adult-status.rhai",
                "derivations/adult-status-copy.rhai",
            );
        fixture.add_question(&copied, ANSWER);

        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("referenced source compiles");
        assert_eq!(compiled.questions.len(), 2);
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle"),
        )
        .expect("bundle yaml");
        assert_eq!(bundle["sources"].as_object().expect("sources").len(), 1);
        assert_eq!(
            bundle["selectorProfiles"]
                .as_object()
                .expect("selectors")
                .len(),
            1
        );
        assert_eq!(
            bundle["sources"]["people"]["authentication"]["usernameRef"],
            "secret:file/records-username"
        );
        assert!(fixture
            .staging
            .join("bundle/adapters/people-extract.rhai")
            .is_file());
    }

    #[test]
    fn referenced_question_compiles_multiple_role_bound_subjects() {
        let question = r#"id: relationship-check
question: Does the governed relationship hold?
purpose: relationship-review
subjects:
  - role: child
    selector: child_reference
    profile: child-reference-v1
    derivation: true
  - role: candidate
    selector: person_reference
    profile: person-reference-v1
    derivation: true
source:
  ref: family-record
answers:
  - concept: relationship_confirmed
    type: boolean
derivation: derivations/relationship-check.rhai
disclosure:
  allow: [relationship_confirmed]
"#;
        let answer = r#"fn answer(facts, selectors, context) {
    let child = required(selectors["child"], "child_missing");
    let candidate = required(selectors["candidate"], "candidate_missing");
    #{relationship_confirmed: child["values"]["child_reference"] != candidate["values"]["person_reference"]}
}
"#;
        let fixture = Fixture::new(OPENAPI, question, answer, true);
        for directory in ["sources", "selectors", "adapters", "schemas"] {
            fs::create_dir(fixture.project.join(directory)).expect("authoring directory");
        }
        for (name, field) in [
            ("child-reference-v1", "child_reference"),
            ("person-reference-v1", "person_reference"),
        ] {
            fs::write(
                fixture.project.join(format!("selectors/{name}.yaml")),
                format!(
                    "maximumAggregateBytes: 200\nfields:\n  {field}:\n    type: string\n    minimumBytes: 1\n    maximumBytes: 200\n"
                ),
            )
            .expect("selector");
        }
        fs::write(
            fixture.project.join("sources/family-record.yaml"),
            r#"transport: http-json
baseUrl: https://records.example.test
posture: field-projected
authentication: {kind: static-bearer, tokenRef: 'secret:file/records-token'}
request:
  method: GET
  pathTemplate: /children/{child_reference}/relationships
  pathBindings:
    child_reference: {role: child, profile: child-reference-v1, field: child_reference}
  selectorInputs:
    - role: child
      alternatives:
        - {profile: child-reference-v1, fields: [child_reference]}
  prepareScript: adapters/family-prepare.rhai
  adapterParameters: {}
  adapterParametersSchema: schemas/family-parameters.schema.yaml
  preparationLimits: {query: forbidden, jsonBody: forbidden, maximumNormalizedBytes: 4096}
  projection: [/relationship_complete]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: schemas/family-response.schema.yaml
extractScript: adapters/family-extract.rhai
factSchema: schemas/family-facts.schema.yaml
"#,
        )
        .expect("source");
        for (path, contents) in [
            (
                "adapters/family-prepare.rhai",
                "fn prepare(s, p) { #{query: [], body: ()} }\n",
            ),
            (
                "adapters/family-extract.rhai",
                "fn extract(r, p) { #{outcome: \"match\", facts: r} }\n",
            ),
            (
                "schemas/family-parameters.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: []\nproperties: {}\n",
            ),
            (
                "schemas/family-response.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [relationship_complete]\nproperties:\n  relationship_complete: {type: boolean}\n",
            ),
            (
                "schemas/family-facts.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: [relationship_complete]\nproperties:\n  relationship_complete: {type: boolean}\n",
            ),
        ] {
            fs::write(fixture.project.join(path), contents).expect("source artifact");
        }

        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("multi-subject question compiles");
        assert_eq!(
            compiled.questions[0]
                .subjects
                .iter()
                .map(|subject| (subject.role.as_str(), subject.selector_profile.as_str()))
                .collect::<Vec<_>>(),
            [
                ("child", "child-reference-v1"),
                ("candidate", "person-reference-v1"),
            ]
        );
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle"),
        )
        .expect("bundle YAML");
        assert_eq!(bundle["selectorProfiles"].as_object().unwrap().len(), 2);
        let grant = &bundle["authorityProfiles"][AUTHORITY_PROFILE_ID]["grants"][0];
        assert_eq!(grant["subjects"].as_array().unwrap().len(), 2);
        let requirement = &bundle["requirements"][0];
        assert_eq!(requirement["subjectRoles"].as_array().unwrap().len(), 2);
        assert_eq!(
            requirement["derivation"]["selectorInputs"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            bundle["sources"]["family-record"]["request"]["selectorInputs"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "the derivation-only candidate never widens the provider request"
        );
    }

    #[test]
    fn compiles_nested_multi_event_leaves_without_reducing_to_the_first_event() {
        let fixture = Fixture::new(
            MULTI_EVENT_OPENAPI,
            MULTI_EVENT_QUESTION,
            MULTI_EVENT_ANSWER,
            true,
        );
        compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("nested repeated facts compile");

        let response: Value = serde_norway::from_slice(
            &fs::read(
                fixture
                    .staging
                    .join("bundle/schemas/event-history-source-response.schema.yaml"),
            )
            .expect("response schema"),
        )
        .expect("response schema parses");
        assert_eq!(response["additionalProperties"], false);
        assert_eq!(response["required"], json!(["events"]));
        assert_eq!(response["properties"]["events"]["minItems"], 1);
        assert_eq!(response["properties"]["events"]["maxItems"], 4);
        assert_eq!(
            response["properties"]["events"]["items"]["required"],
            json!(["status", "occurredAt"])
        );

        let facts: Value = serde_norway::from_slice(
            &fs::read(
                fixture
                    .staging
                    .join("bundle/schemas/event-history-source-facts.schema.yaml"),
            )
            .expect("fact schema"),
        )
        .expect("fact schema parses");
        assert_eq!(facts["additionalProperties"], false);
        assert_eq!(facts["properties"]["event_statuses"]["minItems"], 1);
        assert_eq!(facts["properties"]["event_statuses"]["maxItems"], 4);

        let extract = fs::read_to_string(
            fixture
                .staging
                .join("bundle/adapters/event-history-source-extract.rhai"),
        )
        .expect("extract script");
        assert!(extract.contains("for item_0_0 in items_0_0"), "{extract}");
        assert!(extract.contains("collected_0.push"), "{extract}");
        assert!(extract.contains("for item_1_0 in items_1_0"), "{extract}");
        assert!(!extract.contains("/events/0"), "{extract}");

        let sample: Value = serde_json::from_str(MULTI_EVENT_RESPONSE).expect("sanitized sample");
        assert_eq!(sample["events"].as_array().expect("events").len(), 2);
        assert_ne!(sample["events"][0]["status"], sample["events"][1]["status"]);
    }

    #[test]
    fn repeated_fact_selection_requires_an_explicit_closed_combination_rule_and_bounds() {
        let cases = [
            MULTI_EVENT_QUESTION.replace("combine: collect", "combine: exactly-one"),
            MULTI_EVENT_QUESTION.replace(
                "  collectionBounds:\n    /events: 4",
                "  collectionBounds: {}",
            ),
            MULTI_EVENT_QUESTION.replace("    /events: 4", "    /events: 257"),
            MULTI_EVENT_QUESTION.replace("    /events: 4", "    /events: 4\n    /unused: 2"),
        ];
        for question in cases {
            let fixture = Fixture::new(MULTI_EVENT_OPENAPI, &question, MULTI_EVENT_ANSWER, true);
            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("unsafe repeated fact selection is rejected");
            assert!(fixture.staging_is_empty(), "{error:#}");
        }
    }

    #[test]
    fn selected_scalar_leaf_must_have_a_reviewed_closed_bound() {
        let unbounded = MULTI_EVENT_OPENAPI.replace(
            "status: {type: string, minLength: 1, maxLength: 32}",
            "status: {type: string}",
        );
        let fixture = Fixture::new(&unbounded, MULTI_EVENT_QUESTION, MULTI_EVENT_ANSWER, true);
        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("unbounded selected leaf is rejected");
        assert!(error.to_string().contains("unbounded"), "{error:#}");
        assert!(fixture.staging_is_empty());
    }

    #[test]
    fn collection_extraction_visits_nested_arrays_and_scalar_array_items() {
        let extract = render_fact_extraction(&[QuestionFact {
            name: "observations".to_owned(),
            path: "/events/*/groups/*/*".to_owned(),
            combine: FactCombination::Collect,
        }]);
        assert!(extract.contains("get_path(source_response, \"/events\")"));
        assert!(extract.contains("get_path(item_0_0, \"/groups\")"));
        assert!(extract.contains("let items_0_2 = required(item_0_1"));
        assert!(extract.contains("collected_0.push(required(item_0_2"));
        assert!(!extract.contains("/0"));
    }

    #[test]
    fn question_is_closed_and_disclosure_cannot_be_widened() {
        for mutation in [
            QUESTION.replace("  allow: [is_adult]", "  allow: []"),
            QUESTION.replace("  allow: [is_adult]", "  allow: [is_adult, another_answer]"),
            QUESTION.replace("  allow: [is_adult]", "  allow: [is_adult, is_adult]"),
            QUESTION.replace("      path: /date_of_birth", "      path: /missing"),
            format!("{QUESTION}unknown: true\n"),
        ] {
            let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
            fs::write(
                fixture.project.join("questions/adult-status.yaml"),
                mutation,
            )
            .expect("mutated question");
            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("widened question is rejected");
            assert!(fixture.staging_is_empty(), "{error:#}");
        }
    }

    #[test]
    fn multi_answer_constraints_and_exact_disclosure_fail_closed() {
        let openapi = OPENAPI
            .replace(
                "required: [person_id, name, date_of_birth]",
                "required: [person_id, name, date_of_birth, dose_count]",
            )
            .replace(
                "                  date_of_birth: {type: string, format: date}",
                "                  date_of_birth: {type: string, format: date}\n                  dose_count: {type: integer, minimum: 0, maximum: 20}",
            );
        for question in [
            IMMUNIZATION_QUESTION.replace("    minimum: 0\n", ""),
            IMMUNIZATION_QUESTION.replace("    maximum: 20", "    maximum: -1"),
            IMMUNIZATION_QUESTION.replace(
                "  allow: [schedule_complete, dose_count]",
                "  allow: [schedule_complete, undeclared]",
            ),
            IMMUNIZATION_QUESTION
                .replace("  - concept: dose_count", "  - concept: schedule_complete"),
            IMMUNIZATION_QUESTION.replace(
                "    type: boolean\n  - concept: dose_count",
                "    type: boolean\n    minimum: 0\n  - concept: dose_count",
            ),
        ] {
            let fixture = Fixture::new(&openapi, &question, IMMUNIZATION_ANSWER, true);
            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("invalid governed answers are rejected");
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
        assert!(
            wrapper.contains("let governed_answers = answer(facts, selectors, evaluation_context)")
        );
        assert!(wrapper.contains("value: governed_answers[\"is_adult\"]"));

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
                "                  date_of_birth: {type: string, format: date}",
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
                "date_of_birth: {type: string, format: date}",
                "date_of_birth: {type: string, maxLength: 32, pattern: '^2000-'}",
            ),
            OPENAPI.replace(
                "date_of_birth: {type: string, format: date}",
                "date_of_birth: {type: integer, exclusiveMinimum: 0}",
            ),
            OPENAPI.replace(
                "date_of_birth: {type: string, format: date}",
                "date_of_birth: {type: string, format: date, x-extra: true}",
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

        assert_eq!(
            compiled.questions[0].subjects[0].selector_field,
            "person-id.v1"
        );
        let extract = fs::read_to_string(
            fixture
                .staging
                .join("bundle/adapters/adult-status-source-extract.rhai"),
        )
        .expect("extract script reads");
        assert!(extract.contains(
            "facts[\"date-of.birth\"] = required(get_path(source_response, \"/date-of.birth\")"
        ));
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
        fs::write(
            fixture.project.join("questions/notes.txt"),
            b"not a question",
        )
        .expect("write unexpected entry");
        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("unexpected question entry rejected");
        assert!(error.to_string().contains("only questions/*.yaml"));
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

        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fixture.add_question(AGE_BRACKET_QUESTION, AGE_BRACKET_ANSWER);
        crate::keygen::generate_scaffold_key_material(
            &fixture.project.join("secrets"),
            SIGNING_KEY_ID,
        )
        .expect("generate local keys");
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts multiple questions");

        let fixture = Fixture::new(OPENAPI, AGE_BRACKET_QUESTION, AGE_BRACKET_ANSWER, true);
        crate::keygen::generate_scaffold_key_material(
            &fixture.project.join("secrets"),
            SIGNING_KEY_ID,
        )
        .expect("generate local keys");
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts the controlled category");

        let openapi = OPENAPI
            .replace(
                "required: [person_id, name, date_of_birth]",
                "required: [person_id, name, date_of_birth, dose_count]",
            )
            .replace(
                "                  date_of_birth: {type: string, format: date}",
                "                  date_of_birth: {type: string, format: date}\n                  dose_count: {type: integer, minimum: 0, maximum: 20}",
            );
        let fixture = Fixture::new(&openapi, IMMUNIZATION_QUESTION, IMMUNIZATION_ANSWER, true);
        crate::keygen::generate_scaffold_key_material(
            &fixture.project.join("secrets"),
            SIGNING_KEY_ID,
        )
        .expect("generate local keys");
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts multiple governed answers");

        let (openapi, question, answer) = punctuated_inputs();
        let fixture = Fixture::new(&openapi, &question, &answer, true);
        crate::keygen::generate_scaffold_key_material(
            &fixture.project.join("secrets"),
            SIGNING_KEY_ID,
        )
        .expect("generate local keys");
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts safely quoted punctuated names");

        let fixture = Fixture::new(
            MULTI_EVENT_OPENAPI,
            MULTI_EVENT_QUESTION,
            MULTI_EVENT_ANSWER,
            true,
        );
        crate::keygen::generate_scaffold_key_material(
            &fixture.project.join("secrets"),
            SIGNING_KEY_ID,
        )
        .expect("generate local keys");
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts nested repeated fact extraction");

        let fixture = Fixture::new(
            RELATIONSHIP_OPENAPI,
            RELATIONSHIP_QUESTION,
            RELATIONSHIP_ANSWER,
            true,
        );
        crate::keygen::generate_scaffold_key_material(
            &fixture.project.join("secrets"),
            SIGNING_KEY_ID,
        )
        .expect("generate local keys");
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts multiple role-bound subjects");
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

            let fixture = Self {
                _root: root,
                project,
                staging,
                evidence,
            };
            fixture.add_question(question, derivation);
            fixture
        }

        fn add_question(&self, question: &str, derivation: &str) {
            let parsed: Question = serde_norway::from_str(question).expect("question parses");
            fs::write(
                self.project
                    .join("questions")
                    .join(format!("{}.yaml", parsed.id)),
                question,
            )
            .expect("question");
            fs::write(self.project.join(&parsed.derivation), derivation).expect("derivation");
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
