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
use registry_platform_crypto::{canonicalize_json, domain_separated_sha256};
use serde_json::{json, Map, Value};
use url::{Host, Url};

use crate::suggest::{
    narrow,
    openapi::Spec,
    types::{BoundKind, BoundValues, OperationKey},
};

// The authoring form itself: what an adopter may write, and the checks that
// shape must satisfy. It lives in a library so that this compiler and an editor
// reach the same verdict from the same code; the reading of files below stays
// here, because that library performs no input or output.
pub(crate) use registry_evidence_authoring::{
    layout::{
        ACCESS_DIRECTORY, ACCESS_POLICIES_DIRECTORY, DERIVATIONS_DIRECTORY, FIXTURES_DIRECTORY,
        MAX_ACCESS_POLICY_BYTES, MAX_DERIVATION_BYTES, MAX_OPENAPI_BYTES, MAX_PROJECT_MARKER_BYTES,
        MAX_QUESTIONS, MAX_QUESTION_BYTES, MAX_SOURCE_ARTIFACT_BYTES, OPENAPI_FILE,
        QUESTIONS_DIRECTORY, SCHEMAS_DIRECTORY, SECRETS_DIRECTORY, SELECTORS_DIRECTORY,
        SOURCES_DIRECTORY,
    },
    model::{
        AccessPolicy, AnswerType, FactCombination, Question, QuestionAnswer, QuestionFact,
        QuestionResponseFormat, QuestionSdJwtVcDisclosure, QuestionSource,
    },
    validate::{
        collection_pointers, question_subjects, valid_local_identifier, validate_access_policy,
        validate_question,
    },
    validate_authored_answer, Finding,
};

const LOCAL_URI_PREFIX: &str = "urn:registrystack:evidence:local:";
const LOCAL_AUDIENCE: &str = "registry-evidence-local";
const LOCAL_SIGNING_PRIVATE_FILENAME: &str = "signing-p256-private-jwk";
const LOCAL_SIGNING_PUBLIC_FILENAME: &str = "signing-p256-public.jwk.json";
const AUTHORITY_PROFILE_ID: &str = "local-caller";
const LOCAL_CALLER_EVIDENCE_AUDIENCE: &str = "urn:registrystack:evidence:local:caller";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompiledConceptForm {
    Boolean,
    ControlledCategory,
    BoundedInteger,
    Structured,
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
    pub(crate) access_policies: Vec<CompiledAccessPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompiledAccessPolicy {
    pub(crate) id: String,
    pub(crate) requester_tag: String,
    pub(crate) questions: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct CompiledProductionProject {
    pub(crate) bundle_path: PathBuf,
    pub(crate) fixture_paths: Vec<String>,
    pub(crate) bundle: Value,
}

/// One unpublished local bundle used only by the fixture driver.
///
/// Dropping it restores owner-write permission so the caller's temporary
/// staging directory can be removed without leaving sealed artifacts behind.
pub(crate) struct CompiledFixtureProject {
    pub(crate) bundle_path: PathBuf,
    pub(crate) fixture_paths: Vec<String>,
}

impl Drop for CompiledFixtureProject {
    fn drop(&mut self) {
        let _ = set_bundle_modes(&self.bundle_path, 0o700, 0o600);
    }
}

enum CompileProfile {
    Local {
        ports: LocalServicePorts,
        active_public_jwk_file: String,
        active_public_jwk: Vec<u8>,
    },
    Production(Value),
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

    pub(crate) fn evidence_origin(self) -> String {
        format!("http://127.0.0.1:{}", self.evidence)
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
    let inputs = read_inputs(&project_root, true)?;
    validate_local_dev_sources(&inputs.sources)?;
    let (active_public_jwk_file, active_public_jwk) = local_signing_public_jwk(&project_root)?;
    let plan = compile_plan(
        inputs,
        CompileProfile::Local {
            ports,
            active_public_jwk_file,
            active_public_jwk,
        },
    )?;
    let compilation = write_plan(&project_root, staging_root, &plan, ports, evidence_bin)?;

    if let Err(error) = check_with_evidence(evidence_bin, &compilation.runtime_path) {
        // A rejected unpublished generation should remain removable by its
        // owner. No path outside the caller-supplied staging root is changed.
        let _ = set_bundle_modes(&staging_root.join("bundle"), 0o700, 0o600);
        let _ = fs::set_permissions(&compilation.runtime_path, fs::Permissions::from_mode(0o600));
        return Err(error);
    }

    Ok(compilation)
}

fn validate_local_dev_sources(sources: &BTreeMap<String, Value>) -> Result<()> {
    if sources
        .values()
        .any(|source| source.get("transport").and_then(Value::as_str) == Some("sqlite-extract"))
    {
        bail!(
            "local serving does not bind SQLite extracts; prove this editable project with `evidencectl fixtures run --project <dir>`"
        );
    }
    Ok(())
}

/// Compile one complete non-local deployment bundle into an unpublished private
/// staging directory. The caller owns temporary runtime validation and publication.
pub(crate) fn compile_production_project(
    project_root: &Path,
    deployment_target_root: &Path,
    staging_root: &Path,
    governed_bundle: Value,
    evidence_bin: &Path,
) -> Result<CompiledProductionProject> {
    validate_plain_path_components(project_root, "authoring project")?;
    let project_root = validate_project_root(project_root)?;
    validate_plain_path_components(deployment_target_root, "deployment target")?;
    let deployment_target_root = fs::canonicalize(deployment_target_root)
        .context("resolving deployment target directory")?;
    validate_private_empty_staging(staging_root)?;
    let inputs = read_inputs(&project_root, false)?;
    validate_production_inputs(&project_root, &inputs)?;
    let plan = compile_plan(inputs, CompileProfile::Production(governed_bundle))?;
    reject_local_production_values(&plan.bundle)?;
    validate_production_sources(&plan.bundle)?;
    let bundle_path = write_bundle(
        &project_root,
        Some(&deployment_target_root),
        staging_root,
        &plan,
        evidence_bin,
    )?;
    let fixture_paths = plan
        .questions
        .iter()
        .map(|question| {
            question
                .fixture_artifact
                .clone()
                .expect("production questions were validated")
        })
        .collect();
    Ok(CompiledProductionProject {
        bundle_path,
        fixture_paths,
        bundle: plan.bundle,
    })
}

/// Compile an editable project into a local bundle for offline fixture runs.
///
/// This path writes no runtime file and binds no extract. The real `evidence`
/// binary remains responsible for bundle validation and for materializing a
/// fixture's synthetic SQLite seed during `bundle-evaluate`.
pub(crate) fn compile_fixture_project(
    project_root: &Path,
    staging_root: &Path,
    evidence_bin: &Path,
) -> Result<CompiledFixtureProject> {
    let project_root = validate_project_root(project_root)?;
    validate_private_empty_staging(staging_root)?;
    let inputs = read_inputs(&project_root, false)?;
    validate_production_inputs(&project_root, &inputs)?;
    let (active_public_jwk_file, active_public_jwk) = local_signing_public_jwk(&project_root)?;
    let plan = compile_plan(
        inputs,
        CompileProfile::Local {
            ports: LocalServicePorts::default(),
            active_public_jwk_file,
            active_public_jwk,
        },
    )?;
    let bundle_path = write_bundle(&project_root, None, staging_root, &plan, evidence_bin)?;
    let fixture_paths = plan
        .questions
        .iter()
        .map(|question| {
            question
                .fixture_artifact
                .clone()
                .expect("fixture inputs were validated")
        })
        .collect();
    Ok(CompiledFixtureProject {
        bundle_path,
        fixture_paths,
    })
}

struct Inputs {
    openapi: Value,
    selectors: BTreeMap<String, Value>,
    sources: BTreeMap<String, Value>,
    schemas: BTreeMap<String, Value>,
    questions: Vec<AuthoredQuestion>,
    access_policies: Vec<AuthoredAccessPolicy>,
}

#[derive(Clone)]
struct AuthoredAccessPolicy {
    id: String,
    requester_tag: String,
    questions: Vec<String>,
}

struct AuthoredQuestion {
    question: Question,
    derivation: String,
}

struct CompilePlan {
    questions: Vec<QuestionPlan>,
    access_policies: Vec<AuthoredAccessPolicy>,
    bundle: Value,
    local_public_jwk: Option<(String, Vec<u8>)>,
}

struct QuestionPlan {
    question_id: String,
    source_artifact_id: String,
    authored_source_artifacts: Option<Vec<String>>,
    derivation_artifact: String,
    fixture_artifact: Option<String>,
    purpose: String,
    requirement_uri: String,
    response_formats: Vec<QuestionResponseFormat>,
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
    source: bool,
    derivation: bool,
}

struct ConceptPlan {
    concept_alias: String,
    concept_uri: String,
    concept_form: CompiledConceptForm,
    constraints: Value,
    codelist: Option<(String, Value)>,
    schema: Option<(String, Value)>,
    sd_jwt_vc: Option<Value>,
}

struct CompiledFacts {
    response_schema: Value,
    fact_schema: Value,
    extract_script: String,
}

struct BundleRequirement<'a> {
    handle: String,
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
    let root = fs::canonicalize(project_root)
        .with_context(|| format!("resolving project root {}", project_root.display()))?;

    // The marker is optional: a root that carries none compiles exactly as it
    // always has. A root that carries one must parse, so a project an author
    // meant to anchor never compiles from a document that failed to.
    let marker_path = root.join(registry_evidence_authoring::PROJECT_MARKER_FILE);
    match fs::symlink_metadata(&marker_path) {
        Ok(marker_metadata)
            if marker_metadata.file_type().is_symlink() || !marker_metadata.is_file() =>
        {
            bail!(
                "project marker {} must be a plain file",
                marker_path.display()
            );
        }
        Ok(_) => {
            let bytes =
                read_regular_file(&marker_path, MAX_PROJECT_MARKER_BYTES, "project marker")?;
            registry_evidence_authoring::parse_project_marker(&bytes)
                .map_err(|finding| anyhow!("{}", finding.message))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspecting project marker {}", marker_path.display()))
        }
    }

    Ok(root)
}

fn validate_plain_path_components(path: &Path, description: &str) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components = absolute.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    for component in components {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(value) => current.push(value),
            Component::CurDir => continue,
            Component::ParentDir | Component::Prefix(_) => {
                bail!("{description} must not contain path traversal")
            }
        }
        let metadata =
            fs::symlink_metadata(&current).with_context(|| format!("inspecting {description}"))?;
        if metadata.file_type().is_symlink() {
            bail!("{description} must not traverse symbolic links");
        }
        if !metadata.is_dir() {
            bail!("{description} must be a plain directory");
        }
    }
    Ok(())
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

fn read_inputs(project_root: &Path, require_local_secrets: bool) -> Result<Inputs> {
    let openapi_path = project_root.join(OPENAPI_FILE);
    let openapi = match fs::symlink_metadata(&openapi_path) {
        Ok(_) => {
            let openapi_text = read_regular_file(
                &openapi_path,
                MAX_OPENAPI_BYTES,
                "retained OpenAPI document",
            )?;
            let openapi: Value = serde_norway::from_slice(&openapi_text)
                .context("parsing retained OpenAPI document as YAML or JSON")?;
            validate_openapi_version(&openapi)?;
            openapi
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Value::Null,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspecting retained OpenAPI document {}",
                    openapi_path.display()
                )
            })
        }
    };

    let selectors = read_named_objects(project_root, SELECTORS_DIRECTORY, "selector profile")?;
    let sources = read_named_objects(project_root, SOURCES_DIRECTORY, "source")?;
    let schemas = read_named_objects(project_root, SCHEMAS_DIRECTORY, "schema")?;
    let mut questions = Vec::new();
    let mut question_ids = BTreeSet::new();
    let mut derivation_paths = BTreeSet::new();
    for question_path in question_paths(project_root)? {
        let question_bytes = read_regular_file(&question_path, MAX_QUESTION_BYTES, "question")?;
        let question: Question = serde_norway::from_slice(&question_bytes)
            .with_context(|| format!("parsing question {}", question_path.display()))?;
        first_finding(validate_question(&question))?;
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
        first_finding(validate_authored_answer(&derivation))?;
        questions.push(AuthoredQuestion {
            question,
            derivation,
        });
    }
    let access_policies = if require_local_secrets {
        read_access_policies(project_root, &question_ids)?
    } else {
        Vec::new()
    };

    if require_local_secrets {
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
    }

    Ok(Inputs {
        openapi,
        selectors,
        sources,
        schemas,
        questions,
        access_policies,
    })
}

fn local_signing_public_jwk(project_root: &Path) -> Result<(String, Vec<u8>)> {
    let path = project_root
        .join(SECRETS_DIRECTORY)
        .join(LOCAL_SIGNING_PUBLIC_FILENAME);
    let bytes = read_regular_file(&path, MAX_SOURCE_ARTIFACT_BYTES, "local signing public JWK")?;
    let text = std::str::from_utf8(&bytes).context("local signing public JWK must be UTF-8")?;
    let public = registry_platform_crypto::PublicJwk::parse(text)
        .context("local signing public JWK must be a valid ES256 P-256 public JWK")?;
    if public.algorithm().ok() != Some(registry_platform_crypto::SigningAlgorithm::Es256) {
        bail!("local signing public JWK must use ES256 P-256");
    }
    let kid = public
        .jkt()
        .context("computing the local signing JWK thumbprint")?;
    if public.kid.as_deref() != Some(kid.as_str()) {
        bail!("local signing public JWK kid must equal its RFC 7638 thumbprint");
    }
    Ok((format!("public-keys/{kid}.jwk.json"), bytes))
}

fn validate_production_inputs(project_root: &Path, inputs: &Inputs) -> Result<()> {
    for authored in &inputs.questions {
        let question = &authored.question;
        let governance = question
            .governance
            .as_ref()
            .ok_or_else(|| anyhow!("every production question requires governance"))?;
        if question.answers.iter().any(|answer| answer.id.is_none()) {
            bail!("every production answer requires one stable concept id");
        }
        for uri in std::iter::once(governance.requirement.as_str())
            .chain(governance.reference_frameworks.iter().map(String::as_str))
            .chain(std::iter::once(governance.evidence_type.as_str()))
            .chain(governance.disclosure_families.iter().map(String::as_str))
            .chain(
                question
                    .answers
                    .iter()
                    .filter_map(|answer| answer.id.as_deref()),
            )
        {
            if uri.starts_with(LOCAL_URI_PREFIX) {
                bail!("deployment governance must not use disposable local identifiers");
            }
        }
        let fixture = project_relative_fixture(project_root, &governance.fixtures)?;
        let _ = read_regular_file(&fixture, MAX_SOURCE_ARTIFACT_BYTES, "deployment fixture")?;
    }
    Ok(())
}

fn project_relative_fixture(project_root: &Path, value: &str) -> Result<PathBuf> {
    let relative = Path::new(value);
    let components = relative.components().collect::<Vec<_>>();
    if components.len() != 2
        || components.first() != Some(&Component::Normal(FIXTURES_DIRECTORY.as_ref()))
        || !matches!(components.get(1), Some(Component::Normal(_)))
        || relative
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("yaml")
    {
        bail!("governance fixtures must be project-relative fixtures/<name>.yaml files");
    }
    let directory = project_root.join(FIXTURES_DIRECTORY);
    let metadata = fs::symlink_metadata(&directory)
        .with_context(|| format!("inspecting fixture directory {}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("fixtures must be held in a plain directory");
    }
    Ok(project_root.join(relative))
}

fn reject_local_production_values(bundle: &Value) -> Result<()> {
    match bundle {
        Value::String(value) if value.starts_with(LOCAL_URI_PREFIX) => {
            bail!("the deployment bundle contains a disposable local identifier")
        }
        Value::Array(values) => {
            for value in values {
                reject_local_production_values(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                reject_local_production_values(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Hold every production source to the conditions its own transport carries.
/// A transport that opens a network channel must reach the registry over an
/// encrypted, authenticated connection, so its origin and its authentication
/// kind are both read here. A transport carrying no network channel is judged
/// by neither, and a transport this gate has no stated conditions for is
/// refused rather than waved through under another transport's rules.
fn validate_production_sources(bundle: &Value) -> Result<()> {
    let sources = bundle
        .get("sources")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("the deployment bundle has no sources object"))?;
    for source in sources.values() {
        let transport = source
            .get("transport")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("every production source must declare its transport"))?;
        match transport {
            "http-json" => {
                let https = source
                    .get("baseUrl")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.starts_with("https://"));
                let authenticated = source
                    .pointer("/authentication/kind")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind != "none" && kind != "review-required");
                if !https || !authenticated {
                    bail!("every production source must use authenticated HTTPS");
                }
            }
            // A statement source reads one extract file the operator mounted
            // read-only. It names no origin, opens no connection, and holds no
            // credential, so there is no channel for a scheme or an
            // authentication kind to govern. The conditions it does carry, a
            // bound extract profile and a stated maximum extract age, are
            // closed bundle fields the Evidence loader settles for every
            // assurance profile, and the runtime binds the profile to a path.
            // Restating them here would duplicate `evidence bundle-check`
            // rather than add a production condition.
            "sqlite-extract" => {}
            other => {
                bail!("production source transport `{other}` has no stated production conditions")
            }
        }
    }
    Ok(())
}

fn read_access_policies(
    project_root: &Path,
    question_ids: &BTreeSet<String>,
) -> Result<Vec<AuthoredAccessPolicy>> {
    let access_root = project_root.join(ACCESS_DIRECTORY);
    let access_metadata = match fs::symlink_metadata(&access_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspecting access directory {}", access_root.display()))
        }
    };
    if access_metadata.file_type().is_symlink() || !access_metadata.is_dir() {
        bail!("access must be held in a plain project directory");
    }
    let directory = access_root.join(ACCESS_POLICIES_DIRECTORY);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if access_root.join("clients").exists() {
                bail!("client access configuration requires at least one access policy");
            }
            return Ok(Vec::new());
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("inspecting access policy directory {}", directory.display())
            })
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("access policies must be held in a plain access/policies directory");
    }
    let mut paths = fs::read_dir(&directory)
        .with_context(|| format!("reading access policy directory {}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    if !(1..=MAX_QUESTIONS).contains(&paths.len()) {
        bail!("explicit access configuration requires 1..={MAX_QUESTIONS} access policies");
    }

    let mut ids = BTreeSet::new();
    let mut policies = Vec::with_capacity(paths.len());
    for path in paths {
        if path.extension().and_then(|extension| extension.to_str()) != Some("yaml") {
            bail!("access-policies may contain only <id>.yaml files");
        }
        let bytes = read_regular_file(&path, MAX_ACCESS_POLICY_BYTES, "access policy")?;
        let policy: AccessPolicy = serde_norway::from_slice(&bytes)
            .with_context(|| format!("parsing access policy {}", path.display()))?;
        first_finding(validate_access_policy(&policy))?;
        if path.file_stem().and_then(|value| value.to_str()) != Some(&policy.id) {
            bail!("access policy id must match its access/policies/<id>.yaml filename");
        }
        if !ids.insert(policy.id.clone()) {
            bail!("access policy ids must be unique");
        }
        if policy
            .questions
            .iter()
            .any(|question| !question_ids.contains(question))
        {
            bail!("access policy names a question that does not exist in this project");
        }
        let questions = policy.questions;
        let requester_tag = access_policy_requester_tag(&policy.id, &questions)?;
        policies.push(AuthoredAccessPolicy {
            id: policy.id,
            requester_tag,
            questions,
        });
    }
    Ok(policies)
}

pub(crate) fn access_policy_requester_tag(id: &str, questions: &[String]) -> Result<String> {
    if !valid_local_identifier(id) || questions.is_empty() || questions.len() > MAX_QUESTIONS {
        bail!("access policy is outside the closed local profile");
    }
    if !questions.windows(2).all(|pair| pair[0] < pair[1])
        || questions
            .iter()
            .any(|question| !valid_local_identifier(question))
    {
        bail!("access policy questions must be unique lowercase local identifiers");
    }
    let canonical = canonicalize_json(&json!({
        "version": 1,
        "id": id,
        "questions": questions,
    }))
    .context("canonicalizing access policy")?;
    let digest = domain_separated_sha256(b"registry-evidencectl-access-policy-v1\0", &canonical);
    let mut tag = String::from("policy-v1-");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut tag, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(tag)
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

/// Raise the first way an authored document departs from the authoring form.
///
/// The checks report departures as values, so that a caller with a place to
/// show them can show all of them. A compiler has no such place: it stops at
/// the first one, with the sentence adopters have always read.
fn first_finding(findings: Vec<Finding>) -> Result<()> {
    if let Some(finding) = findings.into_iter().next() {
        bail!("{}", finding.message);
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

fn compile_plan(inputs: Inputs, profile: CompileProfile) -> Result<CompilePlan> {
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
            &inputs.schemas,
            authored,
        )?);
    }
    let access_policies = inputs.access_policies;
    match profile {
        CompileProfile::Local {
            ports,
            active_public_jwk_file,
            active_public_jwk,
        } => {
            let bundle =
                render_local_bundle(&questions, &access_policies, ports, &active_public_jwk_file);
            Ok(CompilePlan {
                questions,
                access_policies,
                bundle,
                local_public_jwk: Some((active_public_jwk_file, active_public_jwk)),
            })
        }
        CompileProfile::Production(governance) => {
            let bundle = render_production_bundle(&questions, governance)?;
            Ok(CompilePlan {
                questions,
                access_policies,
                bundle,
                local_public_jwk: None,
            })
        }
    }
}

fn compile_question_plan(
    openapi: &Value,
    spec: Option<&Spec>,
    base_url: Option<&str>,
    selectors: &BTreeMap<String, Value>,
    sources: &BTreeMap<String, Value>,
    schemas: &BTreeMap<String, Value>,
    authored: AuthoredQuestion,
) -> Result<QuestionPlan> {
    let question = &authored.question;
    if question.source.source_ref.is_some() {
        return compile_referenced_question(selectors, sources, schemas, authored);
    }
    let authored_subjects =
        question_subjects(question).map_err(|finding| anyhow!("{}", finding.message))?;
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

    let path_selector_fields = authored_subjects
        .iter()
        .filter(|subject| {
            let placeholder = format!("{{{}}}", subject.selector);
            operation
                .path
                .split('/')
                .any(|segment| segment == placeholder)
        })
        .map(|subject| subject.selector.as_str())
        .collect::<BTreeSet<_>>();
    let mut source_subjects = vec![false; authored_subjects.len()];
    for selector in &path_selector_fields {
        let candidates = authored_subjects
            .iter()
            .enumerate()
            .filter(|(_, subject)| subject.selector == *selector)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let explicit = candidates
            .iter()
            .copied()
            .filter(|index| authored_subjects[*index].source == Some(true))
            .collect::<Vec<_>>();
        let selected = match (explicit.as_slice(), candidates.as_slice()) {
            ([selected], _) => *selected,
            ([], [selected]) if authored_subjects[*selected].source != Some(false) => *selected,
            ([], [_]) => {
                bail!("an inline path selector cannot bind a subject with source: false")
            }
            ([], _) => {
                bail!("shared selector fields require exactly one subject with source: true")
            }
            _ => {
                bail!("an inline path selector must identify exactly one subject with source: true")
            }
        };
        source_subjects[selected] = true;
    }
    for (index, subject) in authored_subjects.iter().enumerate() {
        if subject.source == Some(true) && !source_subjects[index] {
            bail!("a subject with source: true must supply an inline operation path selector");
        }
        if !source_subjects[index] && !subject.derivation {
            bail!("every question subject must be used by the source or declared for derivation");
        }
    }
    if !source_subjects.iter().any(|source| *source) {
        bail!("an inline OpenAPI question must bind at least one subject to the source path");
    }
    let source_selector_fields = path_selector_fields.into_iter().collect::<Vec<_>>();
    exact_path_selectors(&operation, &source_selector_fields)?;
    let compiled_facts = compile_facts(
        spec.expect("inline source needs parsed OpenAPI"),
        &operation,
        &question.source,
    )?;
    let requirement_uri = question
        .governance
        .as_ref()
        .map(|governance| governance.requirement.clone())
        .unwrap_or_else(|| local_uri(&format!("requirement:{}", question.id)));
    let concepts = question
        .answers
        .iter()
        .map(|answer| compile_concept(&question.id, answer, schemas))
        .collect::<Result<Vec<_>>>()?;
    let requirement_kind = question
        .governance
        .as_ref()
        .map(|governance| governance.kind.as_str())
        .unwrap_or_else(|| {
            if concepts.len() == 1 && concepts[0].concept_form == CompiledConceptForm::Boolean {
                "criterion"
            } else {
                "information-requirement"
            }
        });

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
        "fn prepare(selectors, context) {\n    #{query: [], body: ()}\n}\n".to_owned();
    let extract_script = compiled_facts.extract_script;
    let derivation_script = render_derivation(&authored.derivation, &concepts);
    let subjects = authored_subjects
        .iter()
        .enumerate()
        .map(|(index, authored_subject)| {
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
                source: source_subjects[index],
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
            handle: question.id.clone(),
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
        fixture_artifact: question
            .governance
            .as_ref()
            .map(|governance| governance.fixtures.clone()),
        purpose: question.purpose.clone(),
        requirement_uri,
        response_formats: question.response_formats.clone(),
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
    schemas: &BTreeMap<String, Value>,
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
    validate_referenced_source_authentication(&question.id, source_id, &source_value)?;
    let subjects = compile_referenced_subjects(question, &source_value, selectors)?;

    let requirement_uri = question
        .governance
        .as_ref()
        .map(|governance| governance.requirement.clone())
        .unwrap_or_else(|| local_uri(&format!("requirement:{}", question.id)));
    let concepts = question
        .answers
        .iter()
        .map(|answer| compile_concept(&question.id, answer, schemas))
        .collect::<Result<Vec<_>>>()?;
    let requirement_kind = question
        .governance
        .as_ref()
        .map(|governance| governance.kind.as_str())
        .unwrap_or_else(|| {
            if concepts.len() == 1 && concepts[0].concept_form == CompiledConceptForm::Boolean {
                "criterion"
            } else {
                "information-requirement"
            }
        });
    let (grant, requirement) = render_governance_parts(
        question,
        &subjects,
        source_id,
        &BundleRequirement {
            handle: question.id.clone(),
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
        fixture_artifact: question
            .governance
            .as_ref()
            .map(|governance| governance.fixtures.clone()),
        purpose: question.purpose.clone(),
        requirement_uri,
        response_formats: question.response_formats.clone(),
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
    let authored = question_subjects(question).map_err(|finding| anyhow!("{}", finding.message))?;
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
            source: used_by_source,
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

/// Hold a referenced source to a credential posture it states itself. A
/// transport that opens a network channel carries a credential decision, and
/// neither an absent field nor a mapping that names no kind is that decision,
/// so the compile names the source file rather than emitting a bundle the
/// runtime rejects later. Which kind was stated is the runtime's closed
/// enumeration to settle, so an unrecognized kind passes this gate and is
/// judged there. A transport carrying no network channel holds no credential,
/// so it declares none.
fn validate_referenced_source_authentication(
    question_id: &str,
    source_id: &str,
    source: &Value,
) -> Result<()> {
    if source.get("transport").and_then(Value::as_str) != Some("http-json") {
        return Ok(());
    }
    let Some(authentication) = source
        .get("authentication")
        .filter(|value| !value.is_null())
    else {
        bail!(
            "the referenced source sends no credential, and an absent field does not decide that: \
question `{question_id}` must declare the posture itself by adding an `authentication:` mapping \
naming the `kind:` its channel uses, in sources/{source_id}.yaml"
        )
    };
    if authentication
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| !kind.trim().is_empty())
    {
        return Ok(());
    }
    bail!(
        "the referenced source states `authentication:` without naming a `kind`, and an undecided \
mapping is not a posture: question `{question_id}` must name the `kind:` its channel uses under \
`authentication:` in sources/{source_id}.yaml"
    )
}

fn referenced_source_artifacts(source: &Value) -> Result<Vec<String>> {
    fn required(source: &Value, pointer: &str, artifacts: &mut Vec<String>) -> Result<()> {
        let path = source
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("referenced source is missing `{pointer}`"))?;
        validate_bundle_relative_artifact(path)?;
        artifacts.push(path.to_owned());
        Ok(())
    }

    fn optional(source: &Value, pointer: &str, artifacts: &mut Vec<String>) -> Result<()> {
        if let Some(path) = source.pointer(pointer).and_then(Value::as_str) {
            validate_bundle_relative_artifact(path)?;
            artifacts.push(path.to_owned());
        }
        Ok(())
    }

    let mut artifacts = Vec::new();
    for pointer in ["/responseSchema", "/extractScript", "/factSchema"] {
        required(source, pointer, &mut artifacts)?;
    }
    match source.get("transport").and_then(Value::as_str) {
        Some("http-json") => {
            required(source, "/request/prepareScript", &mut artifacts)?;
            required(source, "/request/adapterParametersSchema", &mut artifacts)?;
        }
        Some("sqlite-extract") => {
            required(source, "/request/statement", &mut artifacts)?;
            optional(source, "/request/prepareScript", &mut artifacts)?;
            optional(source, "/request/adapterParametersSchema", &mut artifacts)?;
        }
        Some(other) => bail!("referenced source transport `{other}` is unsupported"),
        None => bail!("referenced source must declare its transport"),
    }
    Ok(artifacts)
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
                if directory == "adapters" || directory == "queries" || directory == "schemas"
        )
    {
        bail!(
            "referenced source artifacts must be adapters/<file>, queries/<file>, or schemas/<file>"
        );
    }
    Ok(())
}

fn compile_concept(
    question_id: &str,
    answer: &QuestionAnswer,
    schemas: &BTreeMap<String, Value>,
) -> Result<ConceptPlan> {
    let concept_uri = answer
        .id
        .clone()
        .unwrap_or_else(|| local_uri(&format!("concept:{question_id}:{}", answer.concept)));
    Ok(match answer.answer_type {
        AnswerType::Boolean => ConceptPlan {
            concept_alias: answer.concept.clone(),
            concept_uri,
            concept_form: CompiledConceptForm::Boolean,
            constraints: json!({}),
            codelist: None,
            schema: None,
            sd_jwt_vc: None,
        },
        AnswerType::ControlledCategory => {
            let scheme = answer.id.as_ref().map_or_else(
                || local_uri(&format!("category-scheme:{question_id}:{}", answer.concept)),
                // Version 1 requires a distinct category-scheme identifier,
                // while the compact production question contract authors
                // only the stable concept identifier. This deterministic
                // suffix does not invent a requirement, framework, Evidence
                // Type, concept, or disclosure-family URI.
                |identifier| format!("{identifier}:categories"),
            );
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
                schema: None,
                sd_jwt_vc: None,
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
            schema: None,
            sd_jwt_vc: None,
        },
        AnswerType::ReviewedStructuredValue => {
            let path = answer
                .schema
                .as_deref()
                .expect("structured answer was validated");
            let key = Path::new(path)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| anyhow!("answer schema filename is not valid UTF-8"))?;
            let schema = schemas
                .get(key)
                .cloned()
                .ok_or_else(|| anyhow!("answer schema `{path}` does not exist"))?;
            let schema_id = schema
                .get("$id")
                .and_then(Value::as_str)
                .filter(|value| url::Url::parse(value).is_ok())
                .ok_or_else(|| anyhow!("answer schema `{path}` requires an absolute `$id`"))?
                .to_owned();
            ConceptPlan {
                concept_alias: answer.concept.clone(),
                concept_uri,
                concept_form: CompiledConceptForm::Structured,
                constraints: json!({
                    "schema": schema_id,
                    "maximumSerializedBytes": answer
                        .maximum_serialized_bytes
                        .expect("structured answer was validated"),
                }),
                codelist: None,
                schema: Some((path.to_owned(), schema)),
                sd_jwt_vc: answer.sd_jwt_vc.as_ref().map(|projection| {
                    json!({
                        "claim": projection.claim,
                        "disclosure": match projection.disclosure {
                            QuestionSdJwtVcDisclosure::TopLevel => "top-level",
                        },
                    })
                }),
            }
        }
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
        bail!(
            "the local tutorial operation must declare exactly one path selector per source-bound subject"
        );
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
    let selectable = registry_evidence_authoring::openapi::selectable_leaves(spec, &operation_key)?;
    let offered = selectable
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
        // Local synthetic generation metadata is intentionally ignored by
        // the production narrowing step and never reaches compiled contracts.
        "x-evidencectl-mock",
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
        String::from("fn extract(source_response, context) {\n    let facts = #{};\n");
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
    let source_subjects = subjects.iter().filter(|subject| subject.source);
    let path_bindings = Value::Object(Map::from_iter(source_subjects.clone().map(|subject| {
        (
            subject.selector_field.clone(),
            json!({
                "from": "selector",
                "role": subject.role,
                "profile": subject.selector_profile,
                "field": subject.selector_field,
            }),
        )
    })));
    let selector_inputs = source_subjects
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
    let (reference_frameworks, evidence_type, observation_timezone, validity_seconds, families) =
        match &question.governance {
            Some(governance) => (
                governance.reference_frameworks.clone(),
                governance.evidence_type.clone(),
                governance.observation_timezone.clone(),
                governance.validity_seconds,
                governance.disclosure_families.clone(),
            ),
            None => (
                vec![local_uri(&format!("framework:{}", question.id))],
                local_uri(&format!("evidence-type:{}", question.id)),
                "UTC".to_owned(),
                300,
                vec![local_uri(&format!("disclosure-family:{}", question.id))],
            ),
        };
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
    let response_formats = question
        .response_formats
        .iter()
        .map(|format| format.as_str())
        .collect::<Vec<_>>();
    let grant = json!({
        "requirement": requirement.requirement_uri,
        "purpose": question.purpose,
        "audienceFrom": "authenticated-requester",
        "responseFormats": response_formats,
        "subjects": grant_subjects,
    });
    let concepts = requirement
        .concepts
        .iter()
        .map(|concept| {
            let mut rendered = json!({
                "handle": concept.concept_alias,
                "id": concept.concept_uri,
                "form": match concept.concept_form {
                    CompiledConceptForm::Boolean => "boolean",
                    CompiledConceptForm::ControlledCategory => "controlled-category",
                    CompiledConceptForm::BoundedInteger => "bounded-integer",
                    CompiledConceptForm::Structured => "reviewed-structured-value",
                },
                "required": true,
                "constraints": concept.constraints,
            });
            if let Some(projection) = &concept.sd_jwt_vc {
                rendered["sdJwtVc"] = projection.clone();
            }
            rendered
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
    let mut requirement_value = json!({
            "handle": requirement.handle,
            "id": requirement.requirement_uri,
            "kind": requirement.kind,
            "acquisition": {
                "kind": "single",
                "source": source_id,
            },
            "purposes": [question.purpose],
            "subjectRoles": subject_roles,
            "referenceFrameworks": reference_frameworks,
            "evidenceType": evidence_type,
            "observationTimezone": observation_timezone,
            "validitySeconds": validity_seconds,
            "derivation": derivation,
            "concepts": concepts,
            "disclosureGuard": {"families": families},
            "existenceDisclosure": "collapse-unresolved",
    });
    if let Some(governance) = &question.governance {
        requirement_value["fixtures"] = Value::String(governance.fixtures.clone());
    }
    (grant, requirement_value)
}

fn render_local_bundle(
    questions: &[QuestionPlan],
    access_policies: &[AuthoredAccessPolicy],
    ports: LocalServicePorts,
    active_public_jwk_file: &str,
) -> Value {
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
    let authority_profiles = if access_policies.is_empty() {
        let grants = questions
            .iter()
            .map(|question| question.grant.clone())
            .collect::<Vec<_>>();
        Map::from_iter([(
            AUTHORITY_PROFILE_ID.to_owned(),
            json!({
                "kind": "explicit-request",
                "requesterTags": [AUTHORITY_PROFILE_ID],
                "grants": grants,
            }),
        )])
    } else {
        access_policies
            .iter()
            .map(|policy| {
                let grants = policy
                    .questions
                    .iter()
                    .map(|question_id| {
                        questions
                            .iter()
                            .find(|question| question.question_id == *question_id)
                            .expect("access policy questions were validated")
                            .grant
                            .clone()
                    })
                    .collect::<Vec<_>>();
                (
                    policy.requester_tag.clone(),
                    json!({
                        "kind": "explicit-request",
                        "requesterTags": [policy.requester_tag],
                        "grants": grants,
                    }),
                )
            })
            .collect::<Map<_, _>>()
    };
    let requirements = questions
        .iter()
        .map(|question| question.requirement.clone())
        .collect::<Vec<_>>();
    let response_formats = questions
        .iter()
        .flat_map(|question| question.response_formats.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(QuestionResponseFormat::as_str)
        .collect::<Vec<_>>();
    json!({
        "version": 1,
        "assuranceProfile": "local",
        "service": {
            "providerId": local_uri("provider"),
            "trustDomain": local_uri("trust-domain"),
            "publicOrigin": format!("http://127.0.0.1:{}", ports.evidence),
        },
        "issuer": {"id": local_uri("issuer")},
        "publication": {
            "serviceId": local_uri("service"),
            "title": "Local Evidence service",
            "description": "Local minimum-disclosure Evidence authoring service",
            "endpointUrl": ports.evidence_origin(),
            "jurisdictions": [local_uri("jurisdiction")],
        },
        "authentication": {
            "kind": "oidc-access-token",
            "issuer": mint_origin,
            "audiences": [LOCAL_AUDIENCE],
            "tokenTypes": ["at+jwt"],
            "algorithms": ["ES256"],
            "jwksUri": format!("{mint_origin}/.well-known/jwks.json"),
            "principalClaim": "sub",
            "requesterTagsClaim": "evidence_tags",
            "evidenceAudienceClaim": "evidence_audience",
            "grantIdClaim": "evidence_grant_id",
            "grantAuthorityClaim": "evidence_authority",
            "maximumTokenLifetimeSeconds": 300,
            "revokedKeyIds": [],
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
            "algorithm": "ES256",
            "activePublicJwkFile": active_public_jwk_file,
            "publishedPublicJwkFiles": [],
            "revokedKeyIds": [],
            "jwksPath": "/.well-known/evidence/jwks.json",
            "maximumAssertionValiditySeconds": 300,
            "verifierClockSkewSeconds": 30,
        },
        "responseFormats": response_formats,
        "selectorProfiles": selector_profiles,
        "sources": sources,
        "authorityProfiles": authority_profiles,
        "requirements": requirements,
    })
}

fn render_production_bundle(questions: &[QuestionPlan], mut governance: Value) -> Result<Value> {
    let object = governance
        .as_object_mut()
        .ok_or_else(|| anyhow!("deployment governance must be an object"))?;
    object.insert(
        "selectorProfiles".to_owned(),
        Value::Object(Map::from_iter(
            questions
                .iter()
                .flat_map(|question| &question.subjects)
                .map(|subject| {
                    (
                        subject.selector_profile.clone(),
                        subject.selector_profile_value.clone(),
                    )
                }),
        )),
    );
    object.insert(
        "sources".to_owned(),
        Value::Object(Map::from_iter(questions.iter().map(|question| {
            (question.source_id.clone(), question.source_value.clone())
        }))),
    );
    object.insert(
        "requirements".to_owned(),
        Value::Array(
            questions
                .iter()
                .map(|question| question.requirement.clone())
                .collect(),
        ),
    );
    Ok(governance)
}

fn write_plan(
    project_root: &Path,
    staging_root: &Path,
    plan: &CompilePlan,
    ports: LocalServicePorts,
    evidence_bin: &Path,
) -> Result<CompiledProject> {
    write_bundle(project_root, None, staging_root, plan, evidence_bin)?;
    create_private_directory(&staging_root.join("audit"))?;

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
        "signer": {
            "kind": "local-jwk",
            "privateKeyRef": format!("secret:file/{LOCAL_SIGNING_PRIVATE_FILENAME}"),
        },
        "auditStorage": {
            "path": canonical_staging.join("audit/evidence.jsonl").to_string_lossy(),
            "maximumFileBytes": 1073741824_u64,
        },
        "outboundTls": {"systemRoots": true, "trustProfiles": {}},
    });
    let runtime_path = staging_root.join("runtime.yaml");
    write_private_file(&runtime_path, &yaml_bytes(&runtime)?)?;
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
        access_policies: plan
            .access_policies
            .iter()
            .map(|policy| CompiledAccessPolicy {
                id: policy.id.clone(),
                requester_tag: policy.requester_tag.clone(),
                questions: policy.questions.clone(),
            })
            .collect(),
    })
}

fn write_bundle(
    project_root: &Path,
    deployment_target_root: Option<&Path>,
    staging_root: &Path,
    plan: &CompilePlan,
    evidence_bin: &Path,
) -> Result<PathBuf> {
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
    if plan.local_public_jwk.is_some() {
        create_private_directory(&bundle.join("public-keys"))?;
    }
    let config_path = bundle.join("evidence.yaml");
    write_private_file(&config_path, &yaml_bytes(&plan.bundle)?)?;
    let description = render_discovery_description(evidence_bin, &config_path)?;
    if !description.is_empty() {
        write_private_file(&bundle.join("catalog.jsonld"), &description)?;
    }
    let mut written_sources = BTreeSet::new();
    let mut written_paths = BTreeSet::from(["evidence.yaml".to_owned()]);
    if let Some((path, bytes)) = &plan.local_public_jwk {
        write_private_file(&bundle.join(path), bytes)?;
        written_paths.insert(path.clone());
    }
    for question in &plan.questions {
        if written_sources.insert(question.source_artifact_id.clone()) {
            if let Some(artifacts) = &question.authored_source_artifacts {
                for artifact in artifacts {
                    let bytes = read_project_artifact(
                        project_root,
                        artifact,
                        MAX_SOURCE_ARTIFACT_BYTES,
                        "referenced source artifact",
                    )?;
                    if !written_paths.insert(artifact.clone()) {
                        continue;
                    }
                    ensure_generated_parent(&bundle, artifact)?;
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
        written_paths.insert(question.derivation_artifact.clone());
        for (path, codelist) in question
            .concepts
            .iter()
            .filter_map(|concept| concept.codelist.as_ref())
        {
            if !written_paths.insert(path.clone()) {
                continue;
            }
            write_private_file(&bundle.join(path), &yaml_bytes(codelist)?)?;
        }
        for (path, schema) in question
            .concepts
            .iter()
            .filter_map(|concept| concept.schema.as_ref())
        {
            if written_paths.insert(path.clone()) {
                write_private_file(&bundle.join(path), &yaml_bytes(schema)?)?;
            }
        }
        if let Some(path) = &question.fixture_artifact {
            if written_paths.insert(path.clone()) {
                let bytes = read_project_artifact(
                    project_root,
                    path,
                    MAX_SOURCE_ARTIFACT_BYTES,
                    "deployment fixture",
                )?;
                ensure_generated_parent(&bundle, path)?;
                write_private_file(&bundle.join(path), &bytes)?;
            }
        }
    }
    for path in auxiliary_artifacts(&plan.bundle)? {
        if written_paths.insert(path.clone()) {
            let artifact_root = if path.starts_with("public-keys/") {
                deployment_target_root.unwrap_or(project_root)
            } else {
                project_root
            };
            let bytes = read_project_artifact(
                artifact_root,
                &path,
                MAX_SOURCE_ARTIFACT_BYTES,
                if path.starts_with("public-keys/") {
                    "governed deployment public key"
                } else {
                    "referenced bundle artifact"
                },
            )?;
            ensure_generated_parent(&bundle, &path)?;
            write_private_file(&bundle.join(path), &bytes)?;
        }
    }
    set_bundle_modes(&bundle, 0o500, 0o400)?;
    Ok(bundle)
}

fn read_project_artifact(
    project_root: &Path,
    relative: &str,
    maximum_bytes: u64,
    description: &str,
) -> Result<Vec<u8>> {
    let parent = project_root
        .join(relative)
        .parent()
        .ok_or_else(|| anyhow!("{description} has no project directory"))?
        .to_path_buf();
    let metadata = fs::symlink_metadata(&parent)
        .with_context(|| format!("inspecting {description} directory"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{description} must be held in a plain project directory");
    }
    read_regular_file(&project_root.join(relative), maximum_bytes, description)
}

fn ensure_generated_parent(bundle: &Path, relative: &str) -> Result<()> {
    let parent = bundle
        .join(relative)
        .parent()
        .ok_or_else(|| anyhow!("generated artifact has no parent"))?
        .to_path_buf();
    if !parent.exists() {
        fs::create_dir_all(&parent)
            .with_context(|| format!("creating generated directory {}", parent.display()))?;
    }
    Ok(())
}

fn auxiliary_artifacts(bundle: &Value) -> Result<Vec<String>> {
    let mut paths = BTreeSet::new();
    if let Some(profiles) = bundle.get("selectorProfiles").and_then(Value::as_object) {
        for profile in profiles.values() {
            if let Some(fields) = profile.get("fields").and_then(Value::as_object) {
                for field in fields.values() {
                    if let Some(path) = field.get("codelist").and_then(Value::as_str) {
                        validate_auxiliary_artifact(path, "codelists", ".yaml")?;
                        paths.insert(path.to_owned());
                    }
                }
            }
        }
    }
    if let Some(active) = bundle
        .pointer("/signing/activePublicJwkFile")
        .and_then(Value::as_str)
    {
        validate_auxiliary_artifact(active, "public-keys", ".jwk.json")?;
        paths.insert(active.to_owned());
    }
    if let Some(public_keys) = bundle
        .pointer("/signing/publishedPublicJwkFiles")
        .and_then(Value::as_array)
    {
        for value in public_keys {
            let path = value
                .as_str()
                .ok_or_else(|| anyhow!("published public key paths must be strings"))?;
            validate_auxiliary_artifact(path, "public-keys", ".jwk.json")?;
            paths.insert(path.to_owned());
        }
    }
    Ok(paths.into_iter().collect())
}

fn validate_auxiliary_artifact(value: &str, directory: &str, suffix: &str) -> Result<()> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.components().next() != Some(Component::Normal(directory.as_ref()))
        || path.components().count() != 2
        || !value.ends_with(suffix)
    {
        bail!("referenced bundle artifacts must remain in their allowed project directory");
    }
    Ok(())
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

fn render_discovery_description(evidence_bin: &Path, config_path: &Path) -> Result<Vec<u8>> {
    let output = Command::new(evidence_bin)
        .arg("render-discovery-description")
        .arg("--config")
        .arg(config_path)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .with_context(|| {
            format!(
                "running {} provider publication compiler",
                evidence_bin.display()
            )
        })?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let diagnostic = stderr.trim();
    if diagnostic.is_empty() {
        bail!("Evidence rejected provider publication compilation");
    }
    bail!("Evidence rejected provider publication compilation: {diagnostic}")
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
    use std::{
        io::Write as _,
        os::unix::fs::{symlink, OpenOptionsExt as _},
    };

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

    const BIRTH_CERTIFICATE_QUESTION: &str = r#"id: birth-certificate
question: What birth details are recorded for this person?
purpose: birth-record-review
subject:
  role: person
  selector: person_id
source:
  operation: getPerson
  facts:
    - name: name
      path: /name
      combine: exactly-one
    - name: date_of_birth
      path: /date_of_birth
      combine: exactly-one
  collectionBounds: {}
answers:
  - concept: birth_certificate
    type: reviewed-structured-value
    schema: schemas/birth-certificate.yaml
    maximumSerializedBytes: 2048
    sdJwtVc:
      claim: birthCertificate
      disclosure: top-level
responseFormats: [signed-jws, sd-jwt-vc]
derivation: derivations/birth-certificate.rhai
disclosure:
  allow: [birth_certificate]
"#;

    const BIRTH_CERTIFICATE_ANSWER: &str = r#"fn answer(facts, selectors, context) {
    #{birth_certificate: #{
        form: "reviewed-structured-value",
        schema: "urn:example:schema:birth-certificate:v1",
        fields: #{
            givenName: required(facts.name, "name_missing"),
            dateOfBirth: required(facts.date_of_birth, "date_of_birth_missing")
        }
    }}
}
"#;

    const BIRTH_CERTIFICATE_SCHEMA: &str = r#"$schema: https://json-schema.org/draft/2020-12/schema
$id: urn:example:schema:birth-certificate:v1
type: object
additionalProperties: false
required: [givenName, dateOfBirth]
properties:
  givenName: {type: string, minLength: 1, maxLength: 200}
  dateOfBirth: {type: string, format: date}
"#;

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
        assert!(compiled.access_policies.is_empty());
        assert_eq!(
            compiled.caller_evidence_audience,
            LOCAL_CALLER_EVIDENCE_AUDIENCE
        );
        let mut generated = tree(&fixture.staging);
        let public_key_index = generated
            .iter()
            .position(|path| path.starts_with("bundle/public-keys/") && path.ends_with(".jwk.json"))
            .expect("one governed local public JWK");
        let public_key = generated.remove(public_key_index);
        assert!(public_key.starts_with("bundle/public-keys/"));
        assert!(public_key.ends_with(".jwk.json"));
        generated.retain(|path| path != "bundle/public-keys/");
        assert_eq!(
            generated,
            vec![
                "audit/",
                "bundle/",
                "bundle/adapters/",
                "bundle/adapters/adult-status-source-extract.rhai",
                "bundle/adapters/adult-status-source-prepare.rhai",
                "bundle/catalog.jsonld",
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
        assert_eq!(bundle["service"]["publicOrigin"], "http://127.0.0.1:8080");
        assert_eq!(bundle["responseFormats"], json!(["signed-jws"]));
        let source_id = local_source_id("adult-status");
        let selector_profile = local_selector_profile_id("adult-status");
        assert_eq!(
            bundle["sources"][&source_id]["authentication"],
            json!({"kind": "none"})
        );
        assert_eq!(
            bundle["sources"][&source_id]["request"]["pathBindings"]["person_id"],
            json!({"from": "selector", "role": "person", "profile": selector_profile, "field": "person_id"})
        );
        assert_eq!(
            bundle["requirements"][0]["acquisition"],
            json!({"kind": "single", "source": source_id})
        );
        assert_eq!(bundle["requirements"][0]["handle"], "adult-status");
        assert_eq!(
            bundle["requirements"][0]["concepts"][0]["handle"],
            "is_adult"
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
    fn mock_generation_hints_do_not_change_the_compiled_source_schema() {
        let baseline = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        compile_local_project(&baseline.project, &baseline.staging, &baseline.evidence)
            .expect("baseline compilation succeeds");
        let hinted_openapi = OPENAPI.replace(
            "date_of_birth: {type: string, format: date}",
            "date_of_birth:\n                    type: string\n                    format: date\n                    x-evidencectl-mock:\n                      distribution: {kind: age, min: 18, max: 90}",
        );
        let hinted = Fixture::new(&hinted_openapi, QUESTION, ANSWER, true);
        compile_local_project(&hinted.project, &hinted.staging, &hinted.evidence)
            .expect("hinted compilation succeeds");

        let relative = "bundle/schemas/adult-status-source-response.schema.yaml";
        assert_eq!(
            fs::read(baseline.staging.join(relative)).expect("baseline schema"),
            fs::read(hinted.staging.join(relative)).expect("hinted schema"),
        );
    }

    #[test]
    fn compiles_explicit_sd_jwt_vc_for_a_scalar_answer() {
        let question = QUESTION.replace(
            "derivation: derivations/adult-status.rhai",
            "responseFormats: [signed-jws, sd-jwt-vc]\nderivation: derivations/adult-status.rhai",
        );
        let fixture = Fixture::new(OPENAPI, &question, ANSWER, true);

        compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("scalar SD-JWT VC format compiles");
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");

        assert_eq!(
            bundle["responseFormats"],
            json!(["signed-jws", "sd-jwt-vc"])
        );
        assert_eq!(
            bundle["authorityProfiles"][AUTHORITY_PROFILE_ID]["grants"][0]["responseFormats"],
            json!(["signed-jws", "sd-jwt-vc"])
        );
        assert!(bundle["requirements"][0]["concepts"][0]
            .get("sdJwtVc")
            .is_none());
    }

    #[test]
    fn refuses_response_formats_without_signed_jws() {
        let question = QUESTION.replace(
            "derivation: derivations/adult-status.rhai",
            "responseFormats: [sd-jwt-vc]\nderivation: derivations/adult-status.rhai",
        );
        let fixture = Fixture::new(OPENAPI, &question, ANSWER, true);

        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("signed JWS remains mandatory");

        assert!(error
            .to_string()
            .contains("responseFormats must contain signed-jws exactly once"));
    }

    #[test]
    fn refuses_duplicate_or_unknown_response_formats() {
        let duplicate = QUESTION.replace(
            "derivation: derivations/adult-status.rhai",
            "responseFormats: [signed-jws, signed-jws]\nderivation: derivations/adult-status.rhai",
        );
        let fixture = Fixture::new(OPENAPI, &duplicate, ANSWER, true);
        assert!(
            compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence).is_err()
        );

        let unknown = QUESTION.replace(
            "derivation: derivations/adult-status.rhai",
            "responseFormats: [signed-jws, unsigned-json]\nderivation: derivations/adult-status.rhai",
        );
        assert!(serde_norway::from_str::<Question>(&unknown).is_err());
    }

    #[test]
    fn refuses_structured_projection_without_sd_jwt_vc_format() {
        let question =
            BIRTH_CERTIFICATE_QUESTION.replace("responseFormats: [signed-jws, sd-jwt-vc]\n", "");
        let fixture = Fixture::new(OPENAPI, &question, BIRTH_CERTIFICATE_ANSWER, true);

        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("a projection cannot silently enable SD-JWT VC");

        assert!(error
            .to_string()
            .contains("an sdJwtVc projection requires responseFormats to include sd-jwt-vc"));
    }

    #[test]
    fn compiles_a_structured_value_into_independent_sd_jwt_vc_fields() {
        let openapi = OPENAPI.replace(
            "                  name: {type: string}",
            "                  name: {type: string, minLength: 1, maxLength: 200}",
        );
        let fixture = Fixture::new(
            &openapi,
            BIRTH_CERTIFICATE_QUESTION,
            BIRTH_CERTIFICATE_ANSWER,
            true,
        );
        fs::create_dir(fixture.project.join("schemas")).expect("schemas");
        fs::write(
            fixture.project.join("schemas/birth-certificate.yaml"),
            BIRTH_CERTIFICATE_SCHEMA,
        )
        .expect("birth certificate schema");

        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("structured value compiles");

        assert_eq!(
            compiled.questions[0].concepts[0].concept_form,
            CompiledConceptForm::Structured
        );
        assert!(fixture
            .staging
            .join("bundle/schemas/birth-certificate.yaml")
            .is_file());
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        assert_eq!(
            bundle["responseFormats"],
            json!(["signed-jws", "sd-jwt-vc"])
        );
        assert_eq!(
            bundle["authorityProfiles"][AUTHORITY_PROFILE_ID]["grants"][0]["responseFormats"],
            json!(["signed-jws", "sd-jwt-vc"])
        );
        let concept = &bundle["requirements"][0]["concepts"][0];
        assert_eq!(concept["form"], "reviewed-structured-value");
        assert_eq!(
            concept["constraints"],
            json!({
                "schema": "urn:example:schema:birth-certificate:v1",
                "maximumSerializedBytes": 2048,
            })
        );
        assert_eq!(
            concept["sdJwtVc"],
            json!({"claim": "birthCertificate", "disclosure": "top-level"})
        );
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
    fn inline_openapi_derivation_only_subject_never_widens_the_source_request() {
        let question = QUESTION.replace(
            "subject:\n  role: person\n  selector: person_id",
            "subjects:\n  - role: person\n    selector: person_id\n    derivation: true\n  - role: expected-beneficiary\n    selector: beneficiary_id\n    derivation: true",
        );
        let fixture = Fixture::new(OPENAPI, &question, ANSWER, true);

        compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("derivation-only subject compiles");
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        let source = &bundle["sources"][local_source_id("adult-status")];
        assert_eq!(
            source["request"]["pathBindings"]
                .as_object()
                .expect("path bindings")
                .len(),
            1
        );
        assert!(source["request"]["pathBindings"]
            .get("beneficiary_id")
            .is_none());
        assert_eq!(
            source["request"]["selectorInputs"]
                .as_array()
                .expect("source selector inputs")
                .len(),
            1,
            "the derivation-only beneficiary never reaches the provider request"
        );
        assert_eq!(
            bundle["requirements"][0]["derivation"]["selectorInputs"]
                .as_array()
                .expect("derivation selector inputs")
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

        let shared_selector = question
            .replace(
                "    selector: person_id\n    derivation: true",
                "    selector: person_id\n    source: true\n    derivation: true",
            )
            .replace("    selector: beneficiary_id", "    selector: person_id");
        let fixture = Fixture::new(OPENAPI, &shared_selector, ANSWER, true);
        compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("an explicit role disambiguates a shared selector field");
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        assert_eq!(
            bundle["sources"][local_source_id("adult-status")]["request"]["selectorInputs"],
            json!([{
                "role": "person",
                "alternatives": [{
                    "profile": local_subject_selector_profile_id("adult-status", "person", 2),
                    "fields": ["person_id"]
                }]
            }])
        );

        let ambiguous = shared_selector.replace("    source: true\n", "");
        let fixture = Fixture::new(OPENAPI, &ambiguous, ANSWER, true);
        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("a shared selector field needs one explicit source role");
        assert!(error
            .to_string()
            .contains("shared selector fields require exactly one subject with source: true"));

        let without_derivation = question.replace(
            "  - role: expected-beneficiary\n    selector: beneficiary_id\n    derivation: true",
            "  - role: expected-beneficiary\n    selector: beneficiary_id",
        );
        let fixture = Fixture::new(OPENAPI, &without_derivation, ANSWER, true);
        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("an unused subject needs explicit derivation access");
        assert!(error.to_string().contains(
            "every question subject must be used by the source or declared for derivation"
        ));
    }

    #[test]
    fn inline_openapi_question_rejects_no_source_bound_subject() {
        let openapi = OPENAPI
            .replace("/people/{person_id}:", "/population-summary:")
            .replace(
                "      parameters:\n        - name: person_id\n          in: path\n          required: true\n          schema: {type: string}\n",
                "",
            );
        let question = QUESTION.replace(
            "  selector: person_id",
            "  selector: person_id\n  derivation: true",
        );
        let fixture = Fixture::new(&openapi, &question, ANSWER, true);

        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("a constant source path still needs one source-bound subject");
        assert!(error.to_string().contains(
            "an inline OpenAPI question must bind at least one subject to the source path"
        ));
        assert!(fixture.staging_is_empty());
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
    fn production_controlled_category_keeps_the_stable_concept_and_distinct_scheme_ids() {
        let answer: QuestionAnswer = serde_norway::from_str(
            r#"concept: age_bracket
id: urn:authority:concept:age-bracket:v1
type: controlled-category
values: [under-18, adult]
"#,
        )
        .expect("production answer parses");
        let concept = compile_concept("age-bracket", &answer, &BTreeMap::new())
            .expect("controlled category compiles");

        assert_eq!(concept.concept_uri, "urn:authority:concept:age-bracket:v1");
        assert_eq!(
            concept.constraints["categoryScheme"],
            "urn:authority:concept:age-bracket:v1:categories"
        );
        assert_ne!(
            concept.constraints["categoryScheme"],
            concept.concept_uri.as_str(),
            "the runtime-required category scheme remains distinct from the governed concept"
        );
        let (_, codelist) = concept.codelist.expect("controlled category codelist");
        assert_eq!(
            codelist["id"],
            "urn:authority:concept:age-bracket:v1:categories"
        );
    }

    #[test]
    fn production_compiler_ignores_local_access_and_handles_all_neutral_question_shapes() {
        fn referenced(question: &str, source: &str) -> String {
            let start = question.find("source:\n").expect("source section");
            let end = start
                + question[start..]
                    .find("answers:\n")
                    .expect("answers section");
            format!(
                "{}source:\n  ref: {source}\n{}",
                &question[..start],
                &question[end..]
            )
        }

        fn governed(mut question: String, question_id: &str, answers: &[(&str, &str)]) -> String {
            for (alias, identifier) in answers {
                question = question.replace(
                    &format!("  - concept: {alias}\n"),
                    &format!("  - concept: {alias}\n    id: {identifier}\n"),
                );
            }
            question.push_str(&format!(
                r#"governance:
  requirement: urn:authority:requirement:{question_id}:v1
  kind: information-requirement
  referenceFrameworks: [urn:authority:framework:neutral:v1]
  evidenceType: urn:authority:evidence-type:{question_id}:v1
  validitySeconds: 300
  observationTimezone: UTC
  fixtures: fixtures/{question_id}.yaml
  disclosureFamilies: [urn:authority:disclosure-family:{question_id}:v1]
"#,
            ));
            question
        }

        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        for directory in ["sources", "selectors", "adapters", "schemas", "fixtures"] {
            fs::create_dir(fixture.project.join(directory))
                .expect("production authoring directory");
        }
        for (profile, field) in [
            ("person-reference-v1", "person_id"),
            ("child-reference-v1", "child_id"),
            ("candidate-reference-v1", "candidate_id"),
        ] {
            fs::write(
                fixture.project.join(format!("selectors/{profile}.yaml")),
                format!(
                    "maximumAggregateBytes: 64\nfields:\n  {field}:\n    type: string\n    minimumBytes: 1\n    maximumBytes: 64\n"
                ),
            )
            .expect("selector profile");
        }
        fs::write(
            fixture.project.join("sources/people.yaml"),
            r#"transport: http-json
baseUrl: https://records.example.test
posture: field-projected
authentication: {kind: static-authorization, tokenRef: 'secret:file/records-token'}
request:
  method: GET
  pathTemplate: /people/{person_id}
  pathBindings:
    person_id: {from: selector, role: person, profile: person-reference-v1, field: person_id}
  fixedHeaders: [{name: Accept, value: application/json}]
  selectorInputs:
    - role: person
      alternatives:
        - {profile: person-reference-v1, fields: [person_id]}
  prepareScript: adapters/source-prepare.rhai
  adapterParameters: {}
  adapterParametersSchema: schemas/source-parameters.schema.yaml
  preparationLimits: {query: forbidden, jsonBody: forbidden, maximumNormalizedBytes: 4096}
  projection: [/value]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: schemas/source-response.schema.yaml
extractScript: adapters/source-extract.rhai
factSchema: schemas/source-facts.schema.yaml
"#,
        )
        .expect("people source");
        fs::write(
            fixture.project.join("sources/relationships.yaml"),
            r#"transport: http-json
baseUrl: https://relationships.example.test
posture: field-projected
authentication: {kind: static-authorization, tokenRef: 'secret:file/relationships-token'}
request:
  method: GET
  pathTemplate: /children/{child_id}/candidates/{candidate_id}
  pathBindings:
    child_id: {from: selector, role: child, profile: child-reference-v1, field: child_id}
    candidate_id: {from: selector, role: candidate-parent, profile: candidate-reference-v1, field: candidate_id}
  fixedHeaders: [{name: Accept, value: application/json}]
  selectorInputs:
    - role: child
      alternatives:
        - {profile: child-reference-v1, fields: [child_id]}
    - role: candidate-parent
      alternatives:
        - {profile: candidate-reference-v1, fields: [candidate_id]}
  prepareScript: adapters/source-prepare.rhai
  adapterParameters: {}
  adapterParametersSchema: schemas/source-parameters.schema.yaml
  preparationLimits: {query: forbidden, jsonBody: forbidden, maximumNormalizedBytes: 4096}
  projection: [/value]
  redirects: deny
  timeoutMilliseconds: 3000
  maximumResponseBytes: 65536
  concurrencyLimit: 8
responseSchema: schemas/source-response.schema.yaml
extractScript: adapters/source-extract.rhai
factSchema: schemas/source-facts.schema.yaml
"#,
        )
        .expect("relationship source");
        for (path, contents) in [
            (
                "adapters/source-prepare.rhai",
                "fn prepare(selectors, context) { #{query: [], body: ()} }\n",
            ),
            (
                "adapters/source-extract.rhai",
                "fn extract(response, context) { #{outcome: \"match\", facts: response} }\n",
            ),
            (
                "schemas/source-parameters.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: []\nproperties: {}\n",
            ),
            (
                "schemas/source-response.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: []\nproperties: {}\n",
            ),
            (
                "schemas/source-facts.schema.yaml",
                "type: object\nadditionalProperties: false\nrequired: []\nproperties: {}\n",
            ),
        ] {
            fs::write(fixture.project.join(path), contents).expect("source artifact");
        }

        let questions = [
            (
                governed(
                    referenced(QUESTION, "people"),
                    "adult-status",
                    &[("is_adult", "urn:authority:concept:is-adult:v1")],
                ),
                ANSWER,
            ),
            (
                governed(
                    referenced(AGE_BRACKET_QUESTION, "people"),
                    "age-bracket",
                    &[("age_bracket", "urn:authority:concept:age-bracket:v1")],
                ),
                AGE_BRACKET_ANSWER,
            ),
            (
                governed(
                    referenced(IMMUNIZATION_QUESTION, "people"),
                    "immunization-summary",
                    &[
                        (
                            "schedule_complete",
                            "urn:authority:concept:schedule-complete:v1",
                        ),
                        ("dose_count", "urn:authority:concept:dose-count:v1"),
                    ],
                ),
                IMMUNIZATION_ANSWER,
            ),
            (
                governed(
                    referenced(RELATIONSHIP_QUESTION, "relationships"),
                    "parent-relationship",
                    &[(
                        "relationship_confirmed",
                        "urn:authority:concept:relationship-confirmed:v1",
                    )],
                ),
                RELATIONSHIP_ANSWER,
            ),
        ];
        for (question, derivation) in questions {
            fixture.add_question(&question, derivation);
            let parsed: Question = serde_norway::from_str(&question).expect("governed question");
            fs::write(
                fixture.project.join(format!("fixtures/{}.yaml", parsed.id)),
                "version: 1\ncases: []\n",
            )
            .expect("governed fixture");
        }

        symlink(
            fixture.project.join("questions"),
            fixture.project.join(ACCESS_DIRECTORY),
        )
        .expect("malformed local access link");

        let target = json!({
            "version": 1,
            "assuranceProfile": "production",
            "service": {
                "providerId": "urn:authority:provider",
                "trustDomain": "urn:authority:trust",
                "publicOrigin": "https://evidence.example.test"
            },
            "issuer": {"id": "urn:authority:issuer"},
            "authentication": {},
            "audit": {},
            "subjectBinding": {},
            "rateLimits": {},
            "signing": {},
            "authorityProfiles": {"authority": {"kind": "explicit-request"}},
        });
        let project = fs::canonicalize(&fixture.project).expect("canonical authoring project");
        let compiled = compile_production_project(
            &project,
            &project,
            &fixture.staging,
            target,
            &fixture.evidence,
        )
        .expect("all neutral shapes compile through production");
        let bundle = compiled.bundle;
        let requirements = bundle["requirements"].as_array().expect("requirements");

        assert_eq!(requirements.len(), 4);
        assert_eq!(
            requirements
                .iter()
                .map(|requirement| requirement["id"].as_str().expect("requirement id"))
                .collect::<Vec<_>>(),
            [
                "urn:authority:requirement:adult-status:v1",
                "urn:authority:requirement:age-bracket:v1",
                "urn:authority:requirement:immunization-summary:v1",
                "urn:authority:requirement:parent-relationship:v1",
            ]
        );
        assert_eq!(requirements[0]["concepts"][0]["form"], "boolean");
        assert_eq!(requirements[0]["handle"], "adult-status");
        assert_eq!(requirements[0]["concepts"][0]["handle"], "is_adult");
        assert_eq!(
            requirements[1]["concepts"][0]["form"],
            "controlled-category"
        );
        assert_eq!(requirements[2]["concepts"].as_array().unwrap().len(), 2);
        assert_eq!(requirements[2]["concepts"][1]["form"], "bounded-integer");
        assert_eq!(requirements[3]["subjectRoles"].as_array().unwrap().len(), 2);
        assert_eq!(compiled.fixture_paths.len(), 4);
        assert!(!serde_json::to_string(&bundle)
            .expect("bundle JSON")
            .contains(LOCAL_URI_PREFIX));
    }

    fn production_http_source() -> Value {
        json!({
            "transport": "http-json",
            "baseUrl": "https://records.example.test",
            "authentication": {
                "kind": "static-authorization",
                "tokenRef": "secret:file/records-token",
            },
        })
    }

    fn production_statement_source() -> Value {
        json!({
            "transport": "sqlite-extract",
            "extractProfile": "licence-register-extract",
            "maximumExtractAgeSeconds": 604800,
        })
    }

    #[test]
    fn local_dev_refuses_an_unbound_statement_source_with_the_fixture_next_step() {
        let sources =
            BTreeMap::from([("records".to_owned(), json!({"transport": "sqlite-extract"}))]);
        let error = validate_local_dev_sources(&sources)
            .expect_err("local serving accepted an unbound statement source")
            .to_string();
        assert!(error.contains("evidencectl fixtures run --project <dir>"));

        validate_local_dev_sources(&BTreeMap::from([(
            "records".to_owned(),
            json!({"transport": "http-json"}),
        )]))
        .expect("HTTP local development remains supported");
    }

    #[test]
    fn production_statement_source_carries_no_channel_to_hold_conditions_over() {
        let bundle = json!({"sources": {"licence-register": production_statement_source()}});
        validate_production_sources(&bundle).expect("a statement source opens no channel");
    }

    #[test]
    fn production_statement_source_does_not_relax_a_transport_beside_it() {
        let mut plaintext = production_http_source();
        plaintext["baseUrl"] = json!("http://records.example.test");
        let mut unauthenticated = production_http_source();
        unauthenticated["authentication"] = json!({"kind": "none"});
        for broken in [plaintext, unauthenticated] {
            let bundle = json!({
                "sources": {
                    "licence-register": production_statement_source(),
                    "people": broken,
                },
            });
            assert_eq!(
                validate_production_sources(&bundle)
                    .expect_err("the HTTP source is still held to its own conditions")
                    .to_string(),
                "every production source must use authenticated HTTPS"
            );
        }
        let bundle = json!({
            "sources": {
                "licence-register": production_statement_source(),
                "people": production_http_source(),
            },
        });
        validate_production_sources(&bundle).expect("both transports meet their own conditions");
    }

    #[test]
    fn production_http_source_still_requires_an_authenticated_https_channel() {
        let mut plaintext = production_http_source();
        plaintext["baseUrl"] = json!("http://records.example.test");
        let mut unauthenticated = production_http_source();
        unauthenticated["authentication"] = json!({"kind": "none"});
        let mut unreviewed = production_http_source();
        unreviewed["authentication"] = json!({"kind": "review-required"});
        for broken in [plaintext, unauthenticated, unreviewed] {
            let bundle = json!({"sources": {"people": broken}});
            assert_eq!(
                validate_production_sources(&bundle)
                    .expect_err("an unauthenticated or plaintext channel is refused")
                    .to_string(),
                "every production source must use authenticated HTTPS"
            );
        }
    }

    #[test]
    fn production_source_transport_without_stated_conditions_is_refused() {
        let bundle = json!({"sources": {"people": {"transport": "carrier-pigeon"}}});
        assert_eq!(
            validate_production_sources(&bundle)
                .expect_err("an ungoverned transport is refused rather than waved through")
                .to_string(),
            "production source transport `carrier-pigeon` has no stated production conditions"
        );
        let bundle = json!({"sources": {"people": {"baseUrl": "https://records.example.test"}}});
        assert_eq!(
            validate_production_sources(&bundle)
                .expect_err("a source naming no transport is refused")
                .to_string(),
            "every production source must declare its transport"
        );
    }

    #[test]
    fn local_compiler_uses_exact_optional_governance_but_keeps_local_assurance() {
        let question = QUESTION.replace(
            "  - concept: is_adult\n",
            "  - concept: is_adult\n    id: urn:authority:concept:is-adult:v1\n",
        ) + r#"governance:
  requirement: urn:authority:requirement:adult-status:v1
  kind: criterion
  referenceFrameworks: [urn:authority:framework:adult-status:v1]
  evidenceType: urn:authority:evidence-type:adult-status:v1
  validitySeconds: 900
  observationTimezone: Asia/Bangkok
  fixtures: fixtures/adult-status.yaml
  disclosureFamilies: [urn:authority:disclosure-family:adult-status:v1]
"#;
        let fixture = Fixture::new(OPENAPI, &question, ANSWER, true);
        fs::create_dir(fixture.project.join("fixtures")).expect("fixtures");
        fs::write(
            fixture.project.join("fixtures/adult-status.yaml"),
            "version: 1\ncases: []\n",
        )
        .expect("fixture");

        compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("governed local compilation");
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("local bundle"),
        )
        .expect("local bundle YAML");
        let requirement = &bundle["requirements"][0];

        assert_eq!(bundle["assuranceProfile"], "local");
        assert_eq!(bundle["authentication"]["issuer"], "http://127.0.0.1:8081");
        assert_eq!(bundle["signing"]["algorithm"], "ES256");
        let public_key = bundle["signing"]["activePublicJwkFile"]
            .as_str()
            .expect("active public JWK file");
        assert!(fixture.staging.join("bundle").join(public_key).is_file());
        assert_eq!(
            requirement["id"],
            "urn:authority:requirement:adult-status:v1"
        );
        assert_eq!(requirement["validitySeconds"], 900);
        assert_eq!(requirement["observationTimezone"], "Asia/Bangkok");
        assert_eq!(
            requirement["concepts"][0]["id"],
            "urn:authority:concept:is-adult:v1"
        );
        assert!(fixture
            .staging
            .join("bundle/fixtures/adult-status.yaml")
            .is_file());
    }

    #[test]
    fn a_valid_project_marker_is_accepted() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fixture.write_marker(registry_evidence_authoring::default_project_marker_document());

        compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("a project root with a valid marker compiles exactly as one without it");
    }

    #[test]
    fn a_corrupt_project_marker_is_rejected() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fixture.write_marker("version: 1\nproject: [\n");

        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("a project root with a corrupt marker must not compile");
        assert!(
            error.to_string().contains("does not parse"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_project_marker_with_an_unsupported_version_is_rejected() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fixture.write_marker("version: 2\nproject: evidence-authoring\n");

        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("a project root with an unsupported marker version must not compile");
        assert!(
            error.to_string().contains("version must be 1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn copied_project_artifacts_reject_symlinked_parent_directories() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let project = temporary.path().join("project");
        let outside = temporary.path().join("outside");
        fs::create_dir(&project).expect("project");
        fs::create_dir(&outside).expect("outside");

        for (directory, file) in [
            ("adapters", "prepare.rhai"),
            ("schemas", "facts.schema.yaml"),
            ("codelists", "categories.yaml"),
            ("public-keys", "retired.jwk.json"),
        ] {
            fs::write(outside.join(file), b"outside\n").expect("outside artifact");
            symlink(&outside, project.join(directory)).expect("artifact directory symlink");
            assert!(
                read_project_artifact(
                    &project,
                    &format!("{directory}/{file}"),
                    1024,
                    "copied artifact",
                )
                .is_err(),
                "{directory} symlink must not be followed"
            );
            fs::remove_file(project.join(directory)).expect("remove test symlink");
            fs::remove_file(outside.join(file)).expect("remove outside artifact");
        }
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
    fn explicit_access_policies_replace_the_implicit_caller_profile() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fixture.add_question(AGE_BRACKET_QUESTION, AGE_BRACKET_ANSWER);
        fixture.add_access_policy("age-checks", &["adult-status", "age-bracket"]);
        fixture.add_access_policy("service-routing", &["age-bracket"]);

        let compiled = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect("explicit access policies compile");

        assert_eq!(
            compiled
                .access_policies
                .iter()
                .map(|policy| (policy.id.as_str(), policy.questions.as_slice()))
                .collect::<Vec<_>>(),
            [
                (
                    "age-checks",
                    ["adult-status".to_owned(), "age-bracket".to_owned()].as_slice()
                ),
                ("service-routing", ["age-bracket".to_owned()].as_slice()),
            ]
        );
        let bundle: Value = serde_norway::from_slice(
            &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle reads"),
        )
        .expect("bundle parses");
        let profiles = bundle["authorityProfiles"]
            .as_object()
            .expect("authority profiles");
        assert_eq!(profiles.len(), 2);
        assert!(!profiles.contains_key(AUTHORITY_PROFILE_ID));
        for policy in &compiled.access_policies {
            let profile = &profiles[&policy.requester_tag];
            assert_eq!(profile["kind"], "explicit-request");
            assert_eq!(profile["requesterTags"], json!([policy.requester_tag]));
            let grants = profile["grants"].as_array().unwrap();
            assert_eq!(grants.len(), policy.questions.len());
            for (grant, question) in grants.iter().zip(&policy.questions) {
                assert_eq!(
                    grant["requirement"],
                    local_uri(&format!("requirement:{question}"))
                );
            }
        }
    }

    #[test]
    fn access_policy_tags_are_stable_and_revision_bound() {
        let first = access_policy_requester_tag("age-checks", &["adult-status".to_owned()])
            .expect("first tag");
        let same = access_policy_requester_tag("age-checks", &["adult-status".to_owned()])
            .expect("same tag");
        let changed = access_policy_requester_tag(
            "age-checks",
            &["adult-status".to_owned(), "age-bracket".to_owned()],
        )
        .expect("changed tag");

        assert_eq!(first, same);
        assert_ne!(first, changed);
        assert!(first.starts_with("policy-v1-"));
        assert_eq!(first.len(), "policy-v1-".len() + 64);
    }

    #[test]
    fn explicit_access_policies_reject_unknown_questions_before_writing() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fixture.add_access_policy("unknown-access", &["missing-question"]);

        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("unknown question must fail");

        assert!(error.to_string().contains("does not exist"));
        assert!(fixture.staging_is_empty());
    }

    #[test]
    fn explicit_access_directory_cannot_escape_through_a_symlink() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        let outside = fixture.project.parent().unwrap().join("outside-access");
        fs::create_dir(&outside).expect("outside access");
        symlink(&outside, fixture.project.join("access")).expect("access symlink");

        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("access symlink must fail");

        assert!(error.to_string().contains("plain project directory"));
        assert!(fixture.staging_is_empty());
    }

    /// Everything a referenced `people` source declares after its credential
    /// posture. The posture itself is written by the caller, so one project
    /// shape covers every authentication declaration the referenced route has
    /// to settle.
    const REFERENCED_SOURCE_TAIL: &str = r#"request:
  method: GET
  pathTemplate: /people/{person_id}
  pathBindings:
    person_id: {from: selector, role: person, profile: person-reference-v1, field: person_id}
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
"#;

    /// Write a project whose one question reads `sources/people.yaml`, with
    /// the authentication block under test, and return the question text.
    fn write_referenced_people_project(fixture: &Fixture, authentication: &str) -> String {
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
            format!(
                "transport: http-json\nbaseUrl: https://records.example.test\nposture: field-projected\n{authentication}{REFERENCED_SOURCE_TAIL}"
            ),
        )
        .expect("source");
        for (path, contents) in [
            (
                "adapters/people-prepare.rhai",
                "fn prepare(s, context) { #{query: [], body: ()} }\n",
            ),
            (
                "adapters/people-extract.rhai",
                "fn extract(r, context) { #{outcome: \"match\", facts: r} }\n",
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
        referenced
    }

    #[test]
    fn referenced_v1_source_and_selector_are_reused_by_questions() {
        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        let referenced = write_referenced_people_project(
            &fixture,
            "authentication:\n  kind: basic\n  usernameRef: secret:file/records-username\n  passwordRef: secret:file/records-password\n",
        );
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
    fn referenced_http_source_without_an_authentication_declaration_is_refused() {
        for authentication in ["", "authentication:\n"] {
            let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
            write_referenced_people_project(&fixture, authentication);

            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("an undeclared credential posture must not compile")
                    .to_string();

            assert_eq!(
                error,
                "the referenced source sends no credential, and an absent field does not decide \
that: question `adult-status` must declare the posture itself by adding an `authentication:` \
mapping naming the `kind:` its channel uses, in sources/people.yaml",
                "{authentication:?} was not refused as an absent posture"
            );
            assert!(fixture.staging_is_empty());
        }
    }

    #[test]
    fn referenced_http_source_with_an_unnamed_authentication_kind_is_refused() {
        for authentication in [
            "authentication: {}\n",
            "authentication: {kind: null}\n",
            "authentication: {kind: 3}\n",
            "authentication: {kind: ' '}\n",
            "authentication: basic\n",
        ] {
            let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
            write_referenced_people_project(&fixture, authentication);

            let error =
                compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                    .expect_err("a posture the source never names must not compile")
                    .to_string();

            assert_eq!(
                error,
                "the referenced source states `authentication:` without naming a `kind`, and an \
undecided mapping is not a posture: question `adult-status` must name the `kind:` its channel \
uses under `authentication:` in sources/people.yaml",
                "{authentication:?} was not refused as an unnamed kind"
            );
            assert!(fixture.staging_is_empty());
        }
    }

    #[test]
    fn referenced_http_source_compiles_every_declared_authentication_posture() {
        for authentication in [
            "authentication: {kind: none}\n",
            "authentication: {kind: static-authorization, tokenRef: 'secret:file/records-token'}\n",
            // The runtime owns the closed set of kinds. evidencectl settles
            // only that the source named one, so an unrecognized kind reaches
            // the runtime rather than being judged twice.
            "authentication: {kind: kind-this-tool-does-not-enumerate}\n",
        ] {
            let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
            write_referenced_people_project(&fixture, authentication);

            compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
                .expect("a declared credential posture compiles");
            let bundle: Value = serde_norway::from_slice(
                &fs::read(fixture.staging.join("bundle/evidence.yaml")).expect("bundle"),
            )
            .expect("bundle yaml");
            assert_eq!(
                bundle["sources"]["people"]["authentication"],
                serde_norway::from_str::<Value>(authentication).expect("posture")["authentication"],
            );
        }
    }

    #[test]
    fn referenced_question_consumes_the_shared_subject_source_finding() {
        let question = QUESTION
            .replace(
                "  selector: person_id\n",
                "  selector: person_id\n  source: true\n",
            )
            .replace(
                "source:\n  operation: getPerson\n  facts:\n    - name: date_of_birth\n      path: /date_of_birth\n      combine: exactly-one\n  collectionBounds: {}",
                "source:\n  ref: people",
            );
        let fixture = Fixture::new(OPENAPI, &question, ANSWER, true);

        let error = compile_local_project(&fixture.project, &fixture.staging, &fixture.evidence)
            .expect_err("a referenced source cannot use the inline source marker");

        assert_eq!(
            error.to_string(),
            "subject.source is available only to an inline OpenAPI operation"
        );
        assert!(fixture.staging_is_empty());
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
authentication: {kind: static-authorization, tokenRef: 'secret:file/records-token'}
request:
  method: GET
  pathTemplate: /children/{child_reference}/relationships
  pathBindings:
    child_reference: {from: selector, role: child, profile: child-reference-v1, field: child_reference}
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
                "fn prepare(s, context) { #{query: [], body: ()} }\n",
            ),
            (
                "adapters/family-extract.rhai",
                "fn extract(r, context) { #{outcome: \"match\", facts: r} }\n",
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
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts generated inputs");

        let fixture = Fixture::new(OPENAPI, QUESTION, ANSWER, true);
        fixture.add_question(AGE_BRACKET_QUESTION, AGE_BRACKET_ANSWER);
        fixture.add_access_policy("age-checks", &["adult-status"]);
        fixture.add_access_policy("service-routing", &["age-bracket"]);
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts explicit access profiles");

        let fixture = Fixture::new(OPENAPI, AGE_BRACKET_QUESTION, AGE_BRACKET_ANSWER, true);
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
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts multiple governed answers");

        let (openapi, question, answer) = punctuated_inputs();
        let fixture = Fixture::new(&openapi, &question, &answer, true);
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts safely quoted punctuated names");

        let fixture = Fixture::new(
            MULTI_EVENT_OPENAPI,
            MULTI_EVENT_QUESTION,
            MULTI_EVENT_ANSWER,
            true,
        );
        compile_local_project(&fixture.project, &fixture.staging, &evidence)
            .expect("real Evidence loader accepts nested repeated fact extraction");

        let fixture = Fixture::new(
            RELATIONSHIP_OPENAPI,
            RELATIONSHIP_QUESTION,
            RELATIONSHIP_ANSWER,
            true,
        );
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
            crate::keygen::generate_scaffold_key_material(&project.join("secrets"))
                .expect("local key material");
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
                "#!/bin/sh\nif test \"$1\" = render-discovery-description; then printf '{}\\n'; exit 0; fi\ntest \"$1\" = --runtime && test \"$3\" = check\n"
            } else {
                "#!/bin/sh\nif test \"$1\" = render-discovery-description; then printf '{}\\n'; exit 0; fi\necho 'script rejected' >&2\nexit 1\n"
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

        fn add_access_policy(&self, id: &str, questions: &[&str]) {
            fs::create_dir_all(self.project.join("access/policies")).expect("policy directory");
            let policy = json!({"version": 1, "id": id, "questions": questions});
            fs::write(
                self.project
                    .join("access/policies")
                    .join(format!("{id}.yaml")),
                serde_norway::to_string(&policy).expect("policy YAML"),
            )
            .expect("policy");
        }

        fn staging_is_empty(&self) -> bool {
            fs::read_dir(&self.staging)
                .expect("read staging")
                .next()
                .is_none()
        }

        fn write_marker(&self, contents: &str) {
            fs::write(
                self.project
                    .join(registry_evidence_authoring::PROJECT_MARKER_FILE),
                contents,
            )
            .expect("project marker");
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

    fn write_stub_evidence(path: &Path, script: &str) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(path)
            .expect("stub");
        file.write_all(script.as_bytes()).expect("write stub");
    }

    #[test]
    fn render_discovery_description_surfaces_the_evidence_compiler_stderr() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(
            &evidence,
            "#!/bin/sh\necho 'catalog binding is missing a required field' >&2\nexit 1\n",
        );
        let config_path = root.path().join("evidence.yaml");
        fs::write(&config_path, "questions: []\n").expect("config");

        let error = render_discovery_description(&evidence, &config_path)
            .expect_err("a rejected compilation must fail");
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("catalog binding is missing a required field"),
            "{diagnostic}"
        );
    }

    #[test]
    fn render_discovery_description_keeps_the_bare_message_when_evidence_writes_nothing() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(&evidence, "#!/bin/sh\nexit 1\n");
        let config_path = root.path().join("evidence.yaml");
        fs::write(&config_path, "questions: []\n").expect("config");

        let error = render_discovery_description(&evidence, &config_path)
            .expect_err("a rejected compilation must fail");
        assert_eq!(
            format!("{error:#}"),
            "Evidence rejected provider publication compilation"
        );
    }
}
