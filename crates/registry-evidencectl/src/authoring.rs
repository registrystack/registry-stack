//! Compile the deliberately narrow local tutorial authoring shape into the
//! runtime's canonical deployment inputs.
//!
//! This module is an internal seam for `dev`. It does not expose another CLI
//! surface and it delegates the final semantic decision to `evidence check`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read as _},
    iter::Peekable,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    str::Chars,
    thread,
};

use anyhow::{anyhow, bail, Context as _, Result};
use serde_json::{json, Value};

use crate::authored;
use crate::evidence_binary::{
    EVIDENCE_BUNDLE_API_VERSION, EVIDENCE_BUNDLE_KIND, EVIDENCE_RUNTIME_API_VERSION,
    EVIDENCE_RUNTIME_KIND,
};

// The authoring form itself: what an adopter may write, and the checks that
// shape must satisfy. It lives in a library so that this compiler and an editor
// reach the same verdict from the same code; the reading of files below stays
// here, because that library performs no input or output.
pub(crate) use registry_evidence_authoring::{
    layout::{FIXTURES_DIRECTORY, MAX_SOURCE_ARTIFACT_BYTES, SECRETS_DIRECTORY},
    validate::valid_local_identifier,
};

const LOCAL_URI_PREFIX: &str = "urn:registrystack:evidence:local:";
const LOCAL_AUDIENCE: &str = "urn:registrystack:evidence:local:gateway";
const LOCAL_SIGNING_PRIVATE_FILENAME: &str = "signing-p256-private-jwk";
const LOCAL_SIGNING_PUBLIC_FILENAME: &str = "signing-p256-public.jwk.json";
#[cfg(test)]
const OFFLINE_CHECK_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
#[cfg(test)]
const OFFLINE_CHECK_PUBLIC_JWK_FILE: &str =
    "public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompiledConceptForm {
    Boolean,
    ControlledCode,
    ControlledCategory,
    BoundedDecimal,
    DateBucket,
    TimeBucket,
    AudienceScopedEntityReference,
    ControlledCodeList,
    EntityReferenceList,
    BoundedIdentifier,
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
pub(crate) struct CompiledDefinition {
    pub(crate) definition_alias: String,
    pub(crate) requirement_uri: String,
    pub(crate) purpose: String,
    pub(crate) subjects: Vec<CompiledSubject>,
    pub(crate) concepts: Vec<CompiledConcept>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledSubject {
    pub(crate) role: String,
    pub(crate) selectors: Vec<CompiledSelector>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompiledSelector {
    pub(crate) profile: String,
    pub(crate) fields: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CompiledProject {
    pub(crate) runtime_path: PathBuf,
    pub(crate) definitions: Vec<CompiledDefinition>,
    pub(crate) local_audience: String,
    pub(crate) requester_tag: String,
    pub(crate) caller_evidence_audience: String,
    pub(crate) required_scopes: Vec<String>,
    pub(crate) access_profiles: Vec<CompiledAccessProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompiledAccessProfile {
    pub(crate) id: String,
    pub(crate) digest: String,
    pub(crate) requester_tags: Vec<String>,
    pub(crate) definitions: Vec<String>,
    pub(crate) actor_kind: Option<String>,
    pub(crate) task_grant: Option<crate::access::TaskGrantBinding>,
}

/// A field-addressed refusal from a typed authored document.
#[derive(Debug)]
pub(crate) struct AuthoredDiagnostic {
    pub(crate) code: String,
    pub(crate) path: String,
    pub(crate) message: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TargetBoundSource {
    pub(crate) source_id: String,
}

impl std::fmt::Display for AuthoredDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AuthoredDiagnostic {}

#[derive(Debug)]
pub(crate) struct CompiledProductionProject {
    pub(crate) bundle_path: PathBuf,
    pub(crate) fixture_paths: Vec<String>,
    pub(crate) bundle: Value,
}

/// The single line a cleanup failure a `Drop` cannot return is reported on.
///
/// A sealed artifact left behind is the operator's to remove, so the path and
/// the cause both have to reach them.
pub(crate) fn cleanup_failure_line(path: &Path, error: &anyhow::Error) -> String {
    format!(
        "evidencectl: failed to restore owner write on {}: {error:#}",
        path.display()
    )
}

enum CompileProfile {
    Local {
        ports: LocalServicePorts,
        audience: String,
        active_public_jwk_file: String,
        active_public_jwk: Vec<u8>,
        admission: LocalAdmission,
    },
    Production(Value),
}

/// The client admission a local bundle states. The default lists none, so the
/// bundle states `unrestricted` and leaves admission to the issuer, which is
/// what a session owning its own issuer wants.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LocalAdmission {
    /// The machine clients the compiled bundle admits by name.
    pub(crate) allowed_clients: Vec<String>,
    /// The assertion authorities each admitted exchange client may present,
    /// as the issuer owner pairs them.
    pub(crate) assertion_issuers: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalServicePorts {
    pub(crate) evidence: u16,
    pub(crate) issuer: u16,
}

impl LocalServicePorts {
    pub(crate) fn new(evidence: u16, issuer: u16) -> Result<Self> {
        if evidence == 0 || issuer == 0 {
            bail!("local service ports must be non-zero");
        }
        if evidence == issuer {
            bail!("Evidence and the local issuer must use different local ports");
        }
        Ok(Self { evidence, issuer })
    }

    pub(crate) fn issuer_origin(self) -> String {
        format!("http://127.0.0.1:{}", self.issuer)
    }

    pub(crate) fn evidence_origin(self) -> String {
        format!("http://127.0.0.1:{}", self.evidence)
    }
}

impl Default for LocalServicePorts {
    fn default() -> Self {
        Self {
            evidence: 8080,
            issuer: 8081,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compile_normalized_local_project(
    project_root: &Path,
    staging_root: &Path,
    evidence_bin: &Path,
    ports: LocalServicePorts,
    target: &Path,
    audience: &str,
    admission: &LocalAdmission,
) -> Result<CompiledProject> {
    let (connections, outbound_tls) = crate::build::local_dev_target_inputs(target)?;
    compile_local_project_with_target_inputs_resource_and_authority(
        project_root,
        staging_root,
        evidence_bin,
        ports,
        connections,
        outbound_tls,
        audience,
        admission,
        Some(&json!({"authoredTargetPath":target})),
    )
}

#[allow(clippy::too_many_arguments)]
fn compile_local_project_with_target_inputs_resource_and_authority(
    project_root: &Path,
    staging_root: &Path,
    evidence_bin: &Path,
    ports: LocalServicePorts,
    source_connections: Value,
    outbound_tls: Value,
    audience: &str,
    admission: &LocalAdmission,
    compiled_target_bundle: Option<&Value>,
) -> Result<CompiledProject> {
    LocalServicePorts::new(ports.evidence, ports.issuer)?;
    if !valid_local_audience(audience) {
        bail!("local Evidence resource must be one exact bounded absolute URI");
    }
    let project_root = validate_project_root(project_root)?;
    validate_private_empty_staging(staging_root)?;
    validate_evidence_binary(evidence_bin)?;

    // Resolve the complete plan before writing anything. Unsupported or
    // ambiguous authoring inputs therefore leave the staging root empty.
    let inputs = read_inputs(&project_root, true)?;
    if inputs.project.sources.values().any(|source| {
        source.source_type == registry_evidence_authoring::project::SourceType::SqliteExtract
    }) {
        bail!("local dev requires HTTP sources; SQLite extracts remain available through fixture and deployed runtime paths");
    }
    ensure_local_project_key_material(&project_root)?;
    let (active_public_jwk_file, active_public_jwk) =
        ensure_local_signing_public_jwk(&project_root)?;
    let mut plan = compile_plan_with_connections(
        inputs,
        CompileProfile::Local {
            ports,
            audience: audience.to_owned(),
            active_public_jwk_file,
            active_public_jwk,
            admission: admission.clone(),
        },
        source_connections,
    )?;
    let target_path = compiled_target_bundle
        .and_then(|value| value.get("authoredTargetPath"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| project_root.join("local-target.yaml"));
    let target_bytes = authored::read_authored_file(&target_path, "local EvidenceTarget")?;
    let target = registry_evidence_authoring::target::read_target(
        &target_path.to_string_lossy(),
        &target_bytes,
    )?
    .value;
    let (project, _) = crate::normalized::read(&project_root)?;
    let authority_path = crate::normalized::safe_asset(
        crate::normalized::target_directory(&target_path),
        &target.authority,
    )?;
    let authority_bytes = authored::read_authored_file(&authority_path, "target authority")?;
    plan.authority_document = Some(crate::normalized::compiled_authority(
        &project,
        &target,
        &authority_path,
        &authority_bytes,
    )?);
    plan.bundle["authentication"]["oidc"]["requiredScopes"] =
        serde_json::to_value(&target.authentication.oidc.required_scopes)?;
    if let Some(signing) = &target.signing {
        plan.bundle["signing"]["maximumAssertionValiditySeconds"] =
            json!(signing.maximum_assertion_validity_seconds);
    }
    check_target_signing_validity(&plan)?;
    let compilation = write_plan(
        &project_root,
        staging_root,
        &plan,
        ports,
        evidence_bin,
        outbound_tls,
    )?;

    if let Err(error) = check_with_evidence(evidence_bin, &compilation.runtime_path) {
        // A rejected unpublished generation should remain removable by its
        // owner. No path outside the caller-supplied staging root is changed.
        set_bundle_modes(&staging_root.join("bundle"), 0o700, 0o600).with_context(|| {
            format!("restoring owner write on the rejected generation after {error:#}")
        })?;
        fs::set_permissions(&compilation.runtime_path, fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!("restoring owner write on the rejected runtime settings after {error:#}")
            })?;
        return Err(error);
    }

    Ok(compilation)
}

pub(crate) fn valid_local_audience(value: &str) -> bool {
    // `Url::parse` normalizes a host, so it accepts bytes the OAuth resource
    // parameter refuses. The audience selected here becomes that parameter, so
    // it is held to the same byte-level grammar the token request applies, and
    // to this command's own tighter length bound.
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_whitespace)
        && registry_evidence_client::private_key_jwt::valid_resource_uri(value)
        && url::Url::parse(value).is_ok_and(|url| {
            url.fragment().is_none() && url.username().is_empty() && url.password().is_none()
        })
}

/// Compile a target package with optional operator revision metadata.
pub(crate) fn compile_target_project_with_revision(
    project_root: &Path,
    deployment_target_root: &Path,
    staging_root: &Path,
    governed_bundle: Value,
    evidence_bin: &Path,
    revision: Option<&str>,
) -> Result<CompiledProductionProject> {
    validate_plain_path_components(project_root, "authoring project")?;
    let project_root = validate_project_root(project_root)?;
    validate_plain_path_components(deployment_target_root, "deployment target")?;
    let deployment_target_root = fs::canonicalize(deployment_target_root)
        .context("resolving deployment target directory")?;
    validate_private_empty_staging(staging_root)?;
    let inputs = read_inputs(&project_root, false)?;
    let production = match governed_bundle
        .get("assuranceProfile")
        .and_then(Value::as_str)
    {
        Some("production") | Some("evidence-grade") => true,
        Some("local") => false,
        _ => bail!(
            "deployment governance assuranceProfile must be local, production, or evidence-grade"
        ),
    };
    validate_deployment_inputs(&project_root, &inputs, production)?;
    let plan = compile_plan(inputs, CompileProfile::Production(governed_bundle))?;
    check_target_signing_validity(&plan)?;
    if production {
        reject_local_production_values(&plan.bundle)?;
        validate_production_sources(&plan.bundle)?;
    }
    let bundle_path = write_bundle(
        &project_root,
        Some(&deployment_target_root),
        staging_root,
        &plan,
        evidence_bin,
        revision,
    )?;
    let fixture_paths = plan
        .definitions
        .iter()
        .filter_map(|definition| definition.fixture_artifact.clone())
        .collect();
    Ok(CompiledProductionProject {
        bundle_path,
        fixture_paths,
        bundle: plan.bundle,
    })
}

/// Refuse a requirement validity the selected deployment target cannot sign.
///
/// The target's governance states `signing.maximumAssertionValiditySeconds`,
/// and the runtime refuses any requirement whose validity exceeds it.
/// Reporting it here, against the definition that declares it, names the field
/// to change before the bundle reaches the runtime, which reports it only as a
/// generic refusal of the whole configuration. A target that states no integer
/// maximum is left to the runtime's own validation of the target shape.
fn check_target_signing_validity(plan: &CompilePlan) -> Result<()> {
    let Some(maximum) = plan.bundle["signing"]["maximumAssertionValiditySeconds"].as_u64() else {
        return Ok(());
    };
    for definition in &plan.definitions {
        let Some(validity) = definition.requirement["validitySeconds"].as_u64() else {
            continue;
        };
        if validity > maximum {
            return Err(AuthoredDiagnostic {
                code: "evidence.definition.validity-exceeds-signing-maximum".to_owned(),
                path: format!(
                    "evidence.yaml:/assertionDefinitions/{}/validitySeconds",
                    definition.definition_id
                ),
                message: "the requirement validity exceeds the deployment target's signing maximum at target.yaml /signing/maximumAssertionValiditySeconds".to_owned(),
            }
            .into());
        }
    }
    Ok(())
}

/// Validated normalized project and its supplied reviewed assets.
struct Inputs {
    project: registry_evidence_authoring::project::EvidenceProject,
    scripts: BTreeMap<String, String>,
}

struct CompilePlan {
    definitions: Vec<DefinitionPlan>,
    bundle: Value,
    local_public_jwk: Option<(String, Vec<u8>)>,
    generated_artifacts: BTreeMap<String, Vec<u8>>,
    authority_document: Option<Value>,
}

struct DefinitionPlan {
    definition_id: String,
    fixture_artifact: Option<String>,
    purpose: String,
    requirement_uri: String,
    concepts: Vec<ConceptPlan>,
    subjects: Vec<SubjectPlan>,
    requirement: Value,
}

#[derive(Debug)]
struct SubjectPlan {
    role: String,
    selectors: Vec<SubjectSelectorPlan>,
}

#[derive(Debug)]
struct SubjectSelectorPlan {
    profile: String,
    fields: Vec<String>,
}

struct ConceptPlan {
    concept_alias: String,
    concept_uri: String,
    concept_form: CompiledConceptForm,
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
            return Err(AuthoredDiagnostic {
                code: "evidence.project.symbolic-link".to_owned(),
                path: String::new(),
                message: "project and target directory paths must use plain directories without symbolic links; use the canonical absolute path".to_owned(),
            }.into());
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

fn read_inputs(project_root: &Path, _require_local_secrets: bool) -> Result<Inputs> {
    let (project, scripts) = crate::normalized::read(project_root)?;
    Ok(Inputs { project, scripts })
}

fn local_signing_public_jwk(project_root: &Path) -> Result<(String, Vec<u8>)> {
    let path = crate::normalized::safe_asset(
        project_root,
        &format!("{SECRETS_DIRECTORY}/{LOCAL_SIGNING_PUBLIC_FILENAME}"),
    )?;
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

/// Fill disposable local material only after checking the generated ancestor.
/// Key generation validates the secret directory itself before any chmod/write.
pub(crate) fn ensure_local_project_key_material(project_root: &Path) -> Result<()> {
    let generated = project_root.join(".generated");
    match fs::symlink_metadata(&generated) {
        Ok(_) => {
            crate::normalized::safe_asset(project_root, ".generated").map_err(|_| {
                AuthoredDiagnostic {
                    code: "evidence.project.symbolic-link".to_owned(),
                    path: generated.display().to_string(),
                    message: "local signing material requires a plain .generated directory; replace the symbolic link with a directory inside this project".to_owned(),
                }
            })?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_private_directory(&generated)?;
        }
        Err(error) => return Err(error).context("inspecting local generated directory"),
    }
    crate::keygen::ensure_local_key_material(&project_root.join(SECRETS_DIRECTORY))
}

/// Read the project's local signing public JWK, creating the keypair once
/// when the project has none.
///
/// `init` scaffolds this key for every new project. A project that lost it,
/// or was authored without it, gets the same create-only generation here —
/// under the same names and modes `init` uses — so the governed key reference
/// this compiler renders and the key material on disk always agree. An
/// existing private key is never regenerated; its missing public half is restored.
pub(crate) fn ensure_local_signing_public_jwk(project_root: &Path) -> Result<(String, Vec<u8>)> {
    let public = project_root
        .join(SECRETS_DIRECTORY)
        .join(LOCAL_SIGNING_PUBLIC_FILENAME);
    match fs::symlink_metadata(&public) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_local_project_key_material(project_root)
                .context("generating the local project signing key")?;
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("inspecting local signing public JWK {}", public.display())
            });
        }
    }
    local_signing_public_jwk(project_root)
}

fn validate_deployment_inputs(
    project_root: &Path,
    inputs: &Inputs,
    production: bool,
) -> Result<()> {
    for definition in inputs.project.assertion_definitions.values() {
        if production
            && definition
                .semantics
                .requirement
                .starts_with(LOCAL_URI_PREFIX)
        {
            bail!("production definitions cannot use disposable local semantics");
        }
        if let Some(fixture) = &definition.fixtures {
            let path = project_relative_fixture(project_root, fixture)?;
            let _ = read_regular_file(&path, MAX_SOURCE_ARTIFACT_BYTES, "deployment fixture")?;
        }
    }
    Ok(())
}

fn project_relative_fixture(project_root: &Path, value: &str) -> Result<PathBuf> {
    if !valid_fixture_reference(value) {
        bail!("governance fixtures must be project-relative fixtures/<name>.yaml files");
    }
    let relative = Path::new(value);
    let directory = project_root.join(FIXTURES_DIRECTORY);
    let metadata = fs::symlink_metadata(&directory)
        .with_context(|| format!("inspecting fixture directory {}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("fixtures must be held in a plain directory");
    }
    Ok(project_root.join(relative))
}

pub(crate) fn valid_fixture_reference(value: &str) -> bool {
    valid_two_part_reference(value, FIXTURES_DIRECTORY, "yaml")
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
    for (source_id, source) in sources {
        let transport =
            source
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthoredDiagnostic {
                    code: "evidence.source.transport-missing".to_owned(),
                    path: format!("sources/{source_id}.yaml:/type"),
                    message: "every production source must declare its transport".to_owned(),
                })?;
        match transport {
            "http-json" => {
                let connection = source
                    .get("connection")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("production HTTP Source must name a target connection")
                    })?;
                let binding = bundle
                    .get("sourceConnections")
                    .and_then(Value::as_object)
                    .and_then(|connections| connections.get(connection))
                    .ok_or_else(|| {
                        anyhow!("production HTTP Source requires its named target connection")
                    })?;
                let https = binding
                    .get("baseUrl")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.starts_with("https://"));
                let authenticated = binding
                    .pointer("/authentication/type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind != "none" && kind != "review-required");
                if !https || !authenticated {
                    return Err(AuthoredDiagnostic {
                        code: "evidence.source.production-channel".to_owned(),
                        path: if !https {
                            format!("target.yaml:/connections/{connection}/origin")
                        } else {
                            format!("target.yaml:/connections/{connection}/authentication/type")
                        },
                        message: "every production source must use authenticated HTTPS".to_owned(),
                    }
                    .into());
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
            _ => {
                return Err(AuthoredDiagnostic {
                    code: "evidence.source.production-transport".to_owned(),
                    path: format!("sources/{source_id}.yaml:/type"),
                    message: "the production source transport has no stated production conditions"
                        .to_owned(),
                }
                .into())
            }
        }
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

fn valid_two_part_reference(value: &str, directory: &str, extension: &str) -> bool {
    let relative = Path::new(value);
    let components = relative.components().collect::<Vec<_>>();
    !relative.is_absolute()
        && components.len() == 2
        && components.first() == Some(&Component::Normal(directory.as_ref()))
        && matches!(components.get(1), Some(Component::Normal(_)))
        && relative.extension().and_then(|value| value.to_str()) == Some(extension)
}

fn compile_plan(inputs: Inputs, profile: CompileProfile) -> Result<CompilePlan> {
    let connections = match &profile {
        CompileProfile::Production(governance) => governance
            .get("sourceConnections")
            .cloned()
            .unwrap_or_else(|| json!({})),
        CompileProfile::Local { .. } => json!({}),
    };
    compile_plan_with_connections(inputs, profile, connections)
}

fn compile_plan_with_connections(
    inputs: Inputs,
    profile: CompileProfile,
    source_connections: Value,
) -> Result<CompilePlan> {
    let compiled = registry_evidence_authoring::compile::compile(&inputs.project, &inputs.scripts)
        .map_err(|findings| authored::file_findings_report("evidence.yaml", "project", findings))?;
    let (mut bundle, local_public_jwk) = match profile {
        CompileProfile::Production(governance) => (governance, None),
        CompileProfile::Local {
            ports,
            audience,
            active_public_jwk_file,
            active_public_jwk,
            admission,
        } => (
            render_local_bundle(ports, &active_public_jwk_file, &audience, &admission)?,
            Some((active_public_jwk_file, active_public_jwk)),
        ),
    };
    let object = bundle
        .as_object_mut()
        .ok_or_else(|| anyhow!("target governance must be an object"))?;
    object.insert("authorityProfiles".to_owned(), json!({}));
    for (key, value) in compiled
        .model
        .as_object()
        .expect("compiled project is object")
    {
        object.insert(key.clone(), value.clone());
    }
    object.insert("sourceConnections".to_owned(), source_connections.clone());
    let connections = source_connections
        .as_object()
        .ok_or_else(|| anyhow!("sourceConnections must be a mapping"))?;
    for source in object
        .get_mut("sources")
        .expect("compiled sources")
        .as_object_mut()
        .expect("sources is object")
        .values_mut()
    {
        if let Some(name) = source
            .get("connection")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            let connection = connections
                .get(&name)
                .ok_or_else(|| anyhow!("source connection `{name}` requires an explicit target"))?;
            source["baseUrl"] = connection["baseUrl"].clone();
            source["authentication"] = connection["authentication"].clone();
            if let Some(trust) = connection.get("tlsTrustProfile") {
                source["tlsTrustProfile"] = trust.clone();
            }
        }
    }
    let formats = inputs
        .project
        .assertion_definitions
        .values()
        .flat_map(|definition| definition.representations.iter())
        .map(|format| serde_json::to_value(format).expect("format serializes"))
        .collect::<Vec<_>>();
    let mut formats = formats
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    formats.insert("signed-jws".to_owned());
    object.insert("responseFormats".to_owned(), json!(formats));
    let definitions = inputs
        .project
        .assertion_definitions
        .iter()
        .map(|(id, definition)| {
            let requirement = compiled.model["requirements"]
                .as_array()
                .expect("requirements array")
                .iter()
                .find(|value| value["handle"] == id.as_str())
                .expect("compiled definition")
                .clone();
            let subjects = definition
                .subjects
                .iter()
                .map(|subject| SubjectPlan {
                    role: subject.role.to_string(),
                    selectors: subject
                        .selectors
                        .iter()
                        .map(|selector| SubjectSelectorPlan {
                            profile: selector.to_string(),
                            fields: inputs.project.selector_profiles[selector]
                                .fields
                                .keys()
                                .map(ToString::to_string)
                                .collect(),
                        })
                        .collect(),
                })
                .collect();
            let concepts = definition
                .outputs
                .iter()
                .map(|(name, output)| ConceptPlan {
                    concept_alias: name.to_string(),
                    concept_uri: output.concept.clone(),
                    concept_form: match output.value_type.as_str() {
                        "boolean" => CompiledConceptForm::Boolean,
                        "controlled-code" => CompiledConceptForm::ControlledCode,
                        "bounded-decimal" => CompiledConceptForm::BoundedDecimal,
                        "date-bucket" => CompiledConceptForm::DateBucket,
                        "time-bucket" => CompiledConceptForm::TimeBucket,
                        "audience-scoped-entity-reference" => {
                            CompiledConceptForm::AudienceScopedEntityReference
                        }
                        "controlled-code-list" => CompiledConceptForm::ControlledCodeList,
                        "entity-reference-list" => CompiledConceptForm::EntityReferenceList,
                        "controlled-category" => CompiledConceptForm::ControlledCategory,
                        "bounded-identifier" => CompiledConceptForm::BoundedIdentifier,
                        "bounded-integer" => CompiledConceptForm::BoundedInteger,
                        _ => CompiledConceptForm::Structured,
                    },
                })
                .collect();
            DefinitionPlan {
                definition_id: id.to_string(),
                fixture_artifact: definition.fixtures.clone(),
                purpose: definition.purpose.clone(),
                requirement_uri: definition.semantics.requirement.clone(),
                concepts,
                subjects,
                requirement,
            }
        })
        .collect();
    Ok(CompilePlan {
        definitions,
        bundle,
        local_public_jwk,
        generated_artifacts: compiled.artifacts,
        authority_document: None,
    })
}

/// Read authored connection references without requiring runtime credentials.
pub(crate) fn source_connection_users(
    project_root: &Path,
    connection: &str,
) -> Result<Vec<String>> {
    let (project, _) = crate::normalized::read(project_root)?;
    Ok(project
        .sources
        .iter()
        .filter(|(_, source)| source.connection.as_ref().map(|id| id.as_str()) == Some(connection))
        .map(|(id, _)| id.to_string())
        .collect())
}

/// Validate imported ordinary artifact references without synthesizing a
/// deployment, authority, connection, credential, or question. This is a
/// structural import check; the real Evidence bundle check remains mandatory
/// when an operator selects a target and builds the complete project.
pub(crate) fn validate_source_artifact_graph(project_root: &Path) -> Result<()> {
    validate_source_artifact_graph_with_target_bindings(project_root).map(drop)
}

fn validate_source_artifact_graph_with_target_bindings(
    project_root: &Path,
) -> Result<Vec<TargetBoundSource>> {
    let (project, _) = crate::normalized::compile(project_root)?;
    Ok(project
        .sources
        .iter()
        .filter(|(_, source)| source.connection.is_some())
        .map(|(id, _)| TargetBoundSource {
            source_id: id.to_string(),
        })
        .collect())
}

/// Local target baseline for source-first authoring. Actual local grants are
/// compiled from authored definitions and target access profiles by `dev`, and from
/// the authored definitions again wherever the baseline is compiled into a
/// bundle (`check`, `explain`, `fixtures run`, `build` with `--target`).
///
/// The signing key reference is supplied by the caller so the governance
/// content and the key file written beside it come from one read of one key.
pub(crate) fn local_target_governance(active_public_jwk_file: &str) -> Result<Value> {
    let mut governance = render_local_bundle(
        LocalServicePorts::new(8080, 8081)?,
        active_public_jwk_file,
        LOCAL_AUDIENCE,
        &LocalAdmission::default(),
    )?;
    let object = governance
        .as_object_mut()
        .expect("local bundle is a mapping");
    // The bundle's envelope is not a governance member: governance declares
    // its own.
    for name in [
        "apiVersion",
        "kind",
        "selectorProfiles",
        "sources",
        "requirements",
    ] {
        object.remove(name);
    }
    Ok(governance)
}

fn render_local_bundle(
    ports: LocalServicePorts,
    active_public_jwk_file: &str,
    audience: &str,
    admission: &LocalAdmission,
) -> Result<Value> {
    let issuer_origin = ports.issuer_origin();
    let provider_id = local_resource_identity(audience, "provider");
    let issuer_id = local_resource_identity(audience, "issuer");
    let service_id = local_resource_identity(audience, "service");
    let selector_profiles = json!({});
    let sources = json!({});
    let authority_profiles = json!({});
    let requirements = json!([]);
    let response_formats = json!(["signed-jws"]);
    let mut bundle = json!({
        "apiVersion": EVIDENCE_BUNDLE_API_VERSION,
        "kind": EVIDENCE_BUNDLE_KIND,
        "assuranceProfile": "local",
        "service": {
            "providerId": provider_id,
            "trustDomain": local_uri("trust-domain"),
            "publicOrigin": format!("http://127.0.0.1:{}", ports.evidence),
        },
        "issuer": {"uri": issuer_id},
        "publication": {
            "serviceId": service_id,
            "title": "Local Evidence service",
            "description": "Local minimum-disclosure Evidence authoring service",
            "endpointUrl": ports.evidence_origin(),
            "jurisdictions": [local_uri("jurisdiction")],
        },
        "authentication": {
            "oidc": {
                "issuer": issuer_origin,
                "audience": audience,
                "jwksSource": {"type": "uri", "uri": format!("{issuer_origin}/oauth2/jwks")},
                "tokenTypes": ["at+jwt"],
                "algorithms": ["RS256"],
                "principalClaim": "sub",
                "requesterTagsClaim": "evidence_tags",
                "evidenceAudienceClaim": "evidence_audience",
                "allowedClients": "unrestricted",
                "requiredScopes": ["evidence:invoke"],
                "maximumTokenLifetimeSeconds": 300,
                "revokedKeyIds": [],
            },
        },
        "audit": {
            "hashKeyRef": "secret:file/audit-hmac-key",
            "hashKeyVersion": 1,
        },
        "subjectBinding": {
            "secretRef": "secret:file/subject-binding-hmac-key",
            "keyVersion": 1,
        },
        "rateLimits": {
            "requestsPerPrincipalPerMinute": 60,
            "burstPerPrincipal": 16,
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
    });
    if !admission.allowed_clients.is_empty() {
        bundle["authentication"]["oidc"]["allowedClients"] = json!(admission.allowed_clients);
    }
    if !admission.assertion_issuers.is_empty() {
        bundle["authentication"]["oidc"]["assertionIssuers"] = json!(admission.assertion_issuers);
    }
    Ok(bundle)
}

fn local_resource_identity(audience: &str, role: &str) -> String {
    if audience == LOCAL_AUDIENCE {
        local_uri(role)
    } else if audience.starts_with("urn:") && !audience.contains('?') {
        format!("{audience}:{role}")
    } else {
        format!("{audience}#{role}")
    }
}

fn write_plan(
    project_root: &Path,
    staging_root: &Path,
    plan: &CompilePlan,
    ports: LocalServicePorts,
    evidence_bin: &Path,
    outbound_tls: Value,
) -> Result<CompiledProject> {
    write_bundle(project_root, None, staging_root, plan, evidence_bin, None)?;
    create_private_directory(&staging_root.join("audit"))?;

    let canonical_staging = fs::canonicalize(staging_root)
        .with_context(|| format!("resolving staging root {}", staging_root.display()))?;
    let secret_root = fs::canonicalize(project_root.join(SECRETS_DIRECTORY))
        .context("resolving local secret directory")?;
    let mut runtime = json!({
        "apiVersion": EVIDENCE_RUNTIME_API_VERSION,
        "kind": EVIDENCE_RUNTIME_KIND,
        "package": {"root": canonical_staging.join("bundle").to_string_lossy()},
        "listener": {
            "bind": format!("127.0.0.1:{}", ports.evidence),
            "tlsTermination": "operator-controlled-upstream",
            "trustProxyIdentityHeaders": false,
            "maximumRequestBytes": 65536,
            "maximumConcurrentRequests": 64,
            "requestTimeoutMilliseconds": 10000,
            "shutdownGraceMilliseconds": 30000,
        },
        "secretProviders": {"file": {"root": secret_root.to_string_lossy()}},
        "signer": {
            "type": "local-jwk",
            "privateKeyRef": format!("secret:file/{LOCAL_SIGNING_PRIVATE_FILENAME}"),
        },
        "audit": {
            "path": canonical_staging.join("audit/evidence.jsonl").to_string_lossy(),
        },
        "outboundTls": outbound_tls,
    });
    let authority = plan
        .authority_document
        .as_ref()
        .context("local target requires complete authored authority")?;
    let authority_root = canonical_staging.join("authority");
    create_private_directory(&authority_root)?;
    runtime["authority"] = json!({"root":authority_root,"target":authority["target"]});
    let authority_path = canonical_staging.join("compiled-authority.yaml");
    write_private_file(&authority_path, &yaml_bytes(authority)?)?;
    let runtime_path = staging_root.join("runtime.yaml");
    write_private_file(&runtime_path, &yaml_bytes(&runtime)?)?;
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o400))
        .with_context(|| format!("sealing {}", runtime_path.display()))?;

    let output = Command::new(evidence_bin)
        .arg("authority")
        .arg("activate")
        .arg("--runtime-config")
        .arg(&runtime_path)
        .arg("--document")
        .arg(&authority_path)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME")
        .output()
        .context("activating the complete local target authority")?;
    if !output.status.success() {
        bail!(
            "Evidence refused the complete local target authority: {}",
            child_diagnostic(&output.stderr)
        );
    }

    let definitions = plan
        .definitions
        .iter()
        .map(|definition| CompiledDefinition {
            definition_alias: definition.definition_id.clone(),
            requirement_uri: definition.requirement_uri.clone(),
            purpose: definition.purpose.clone(),
            subjects: definition
                .subjects
                .iter()
                .map(|subject| CompiledSubject {
                    role: subject.role.clone(),
                    selectors: subject
                        .selectors
                        .iter()
                        .map(|selector| CompiledSelector {
                            profile: selector.profile.clone(),
                            fields: selector.fields.clone(),
                        })
                        .collect(),
                })
                .collect(),
            concepts: definition
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
        definitions,
        local_audience: plan.bundle["authentication"]["oidc"]["audience"]
            .as_str()
            .context("local Evidence audience missing")?
            .to_owned(),
        requester_tag: authority["accessProfiles"]
            .as_object()
            .and_then(|profiles| profiles.values().next())
            .and_then(|profile| profile["requesterTags"].as_array())
            .and_then(|tags| tags.first())
            .and_then(Value::as_str)
            .context("local target authority needs an identity tag")?
            .to_owned(),
        caller_evidence_audience: plan.bundle["requirements"]
            .as_array()
            .and_then(|definitions| definitions.first())
            .and_then(|definition| definition["grantCeiling"]["audiences"].as_array())
            .and_then(|audiences| audiences.first())
            .and_then(Value::as_str)
            .context("local definition needs an audience ceiling")?
            .to_owned(),
        required_scopes: plan.bundle["authentication"]["oidc"]["requiredScopes"]
            .as_array()
            .map_or_else(
                || vec!["evidence:invoke".to_owned()],
                |scopes| {
                    scopes
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                },
            ),
        access_profiles: authority["accessProfiles"]
            .as_object()
            .context("compiled target profiles")?
            .iter()
            .map(|(id, profile)| {
                let grants = profile["grants"]
                    .as_array()
                    .context("complete profile grants")?;
                let definitions = grants
                    .iter()
                    .filter_map(|grant| {
                        plan.definitions
                            .iter()
                            .find(|definition| grant["requirement"] == definition.requirement_uri)
                            .map(|definition| definition.definition_id.clone())
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let has_task = grants
                    .iter()
                    .flat_map(|grant| grant["subjects"].as_array().into_iter().flatten())
                    .any(|subject| subject["valueOrigin"] == "authenticated-grant");
                let task_grant = if has_task {
                    Some(crate::access::TaskGrantBinding {
                        requester_clients: profile["requesterClients"]
                            .as_array()
                            .context("task profile requester clients")?
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect(),
                        source_issuer: registry_platform_yaml::Url::new(
                            profile["grantSourceIssuer"]
                                .as_str()
                                .context("task profile issuer")?,
                        )
                        .map_err(|_| anyhow!("task profile source issuer is invalid"))?,
                    })
                } else {
                    None
                };
                Ok(CompiledAccessProfile {
                    id: id.clone(),
                    digest: crate::access::profile_digest(profile)?,
                    requester_tags: profile["requesterTags"]
                        .as_array()
                        .context("profile tags")?
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect(),
                    definitions,
                    actor_kind: profile["actorKind"].as_str().map(str::to_owned),
                    task_grant,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn write_bundle(
    project_root: &Path,
    deployment_target_root: Option<&Path>,
    staging_root: &Path,
    plan: &CompilePlan,
    evidence_bin: &Path,
    revision: Option<&str>,
) -> Result<PathBuf> {
    let config = yaml_bytes(&plan.bundle)?;
    let mut artifacts = plan.generated_artifacts.clone();
    for reserved in [
        "evidence.yaml",
        "catalog.jsonld",
        registry_platform_config::SUM_FILE,
        registry_platform_config::REVISION_FILE,
    ] {
        reserve_bundle_path(&artifacts, reserved)?;
    }
    insert_bundle_artifact(
        &mut artifacts,
        "evidence.yaml",
        config,
        "compiled Evidence configuration",
    )?;
    if let Some((path, bytes)) = &plan.local_public_jwk {
        reserve_bundle_path(&artifacts, path)?;
        insert_bundle_artifact(
            &mut artifacts,
            path,
            bytes.clone(),
            "local public signing key",
        )?;
    }
    for definition in &plan.definitions {
        if let Some(path) = &definition.fixture_artifact {
            let bytes = read_project_artifact(
                project_root,
                path,
                MAX_SOURCE_ARTIFACT_BYTES,
                "deployment fixture",
            )?;
            insert_bundle_artifact(&mut artifacts, path, bytes, "deployment fixture")?;
        }
    }
    let active_public_jwk_file = plan
        .bundle
        .pointer("/signing/activePublicJwkFile")
        .and_then(Value::as_str)
        .map(str::to_owned);
    for path in auxiliary_artifacts(&plan.bundle)? {
        if artifacts.contains_key(&path) {
            continue;
        }
        let governed_public_key = path.starts_with("public-keys/");
        let artifact_root = if governed_public_key {
            deployment_target_root.unwrap_or(project_root)
        } else {
            project_root
        };
        let bytes = read_project_artifact(
            artifact_root,
            &path,
            MAX_SOURCE_ARTIFACT_BYTES,
            if governed_public_key {
                "governed deployment public key"
            } else {
                "referenced bundle artifact"
            },
        )
        .map_err(|error| {
            governed_public_key_fault(
                &path,
                active_public_jwk_file.as_deref(),
                &plan.bundle["signing"]["publishedPublicJwkFiles"],
                error,
            )
        })?;
        insert_bundle_artifact(&mut artifacts, &path, bytes, "referenced bundle artifact")?;
    }
    ensure_no_bundle_path_aliases(artifacts.keys().map(String::as_str).chain([
        "catalog.jsonld",
        registry_platform_config::SUM_FILE,
        registry_platform_config::REVISION_FILE,
    ]))?;

    let bundle = staging_root.join("bundle");
    create_private_directory(&bundle)?;
    for (path, bytes) in &artifacts {
        ensure_generated_parent(&bundle, path)?;
        write_private_file(&bundle.join(path), bytes)?;
    }
    let config_path = bundle.join("evidence.yaml");
    let description =
        render_discovery_description(evidence_bin, &config_path, deployment_target_root.is_some())?;
    // Evidence prints a description only for a bundle that declares a
    // publication, and prints nothing for one that does not. Which of the two
    // this is was decided by the bundle written just above, so nothing back
    // from a publishing bundle is a rendering that did not happen, not a
    // bundle without a publication, and a candidate published without its
    // catalog would advertise nothing while looking complete.
    if plan.bundle.get("publication").is_some() && description.is_empty() {
        bail!(
            "Evidence returned no provider publication description for a bundle that declares publication; the candidate would carry no catalog.jsonld"
        );
    }
    if !description.is_empty() {
        write_private_file(&bundle.join("catalog.jsonld"), &description)?;
    }
    registry_platform_config::write_sum_file(
        &bundle,
        revision,
        &package_limits(),
        "evidencectl package",
    )?;
    set_bundle_modes(&bundle, 0o500, 0o400)?;
    Ok(bundle)
}

fn reserve_bundle_path(artifacts: &BTreeMap<String, Vec<u8>>, reserved: &str) -> Result<()> {
    if artifacts.contains_key(reserved) {
        bail!("bundle artifact path {reserved} is reserved for generated deployment output");
    }
    Ok(())
}

fn insert_bundle_artifact(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    path: &str,
    bytes: Vec<u8>,
    description: &str,
) -> Result<()> {
    if artifacts
        .get(path)
        .is_some_and(|existing| existing != &bytes)
    {
        bail!("bundle artifact path {path} assigns different content to {description}");
    }
    artifacts.entry(path.to_owned()).or_insert(bytes);
    Ok(())
}

fn ensure_no_bundle_path_aliases<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let paths = paths.into_iter().collect::<BTreeSet<_>>();
    let mut folded = BTreeMap::new();
    for path in &paths {
        let mut prefix = String::new();
        for component in path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            let is_file = prefix.len() == path.len();
            if let Some((previous, previous_is_file)) =
                folded.insert(prefix.to_ascii_lowercase(), (prefix.clone(), is_file))
            {
                if previous != prefix || previous_is_file || is_file {
                    if previous == prefix {
                        bail!(
                            "bundle artifact path {previous} cannot also be a directory for {path}"
                        );
                    }
                    bail!(
                        "bundle artifact path {prefix} differs from {previous} only in letter case"
                    );
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn package_limits() -> registry_platform_config::PackageLimits {
    registry_platform_config::PackageLimits {
        max_files: 1_024,
        max_file_bytes: MAX_SOURCE_ARTIFACT_BYTES,
        max_total_bytes: 16 * 1024 * 1024,
        max_depth: 3,
        max_path_bytes: 128,
    }
}

/// Refuse a missing governed public key as a field-addressed diagnostic.
///
/// The compile copies the public key files governance names out of the
/// deployment target, so an absent key means the target is incomplete, not
/// that the project is unreadable. Naming the governance field that selected
/// the missing file lets `check` and `explain` refuse with the same shape they
/// use for every other authored defect; other read failures pass through.
fn governed_public_key_fault(
    path: &str,
    active: Option<&str>,
    published: &Value,
    error: anyhow::Error,
) -> anyhow::Error {
    let missing = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound)
    });
    if !missing {
        return error;
    }
    AuthoredDiagnostic {
        code: "evidence.target.signing-key-missing".to_owned(),
        path: if Some(path) == active {
            "target.yaml:/signing/activePublicJwkFile".to_owned()
        } else {
            let index = published
                .as_array()
                .and_then(|files| files.iter().position(|file| file.as_str() == Some(path)));
            match index {
                Some(index) => format!("target.yaml:/signing/publishedPublicJwkFiles/{index}"),
                None => "target.yaml:/signing/publishedPublicJwkFiles".to_owned(),
            }
        },
        message: "the deployment target does not provide the public key file this member names"
            .to_owned(),
    }
    .into()
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
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(&parent)
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
    let mut command = Command::new(evidence_bin);
    command
        .arg("check")
        .arg("--runtime-config")
        .arg(runtime_path)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME");
    let run = run_bounded_evidence(
        command,
        StandardOutput::Discarded,
        &format!("{} check", evidence_bin.display()),
    )?;
    if run.status.success() {
        return Ok(());
    }
    let diagnostic = child_diagnostic(&run.stderr);
    if diagnostic.is_empty() {
        bail!("Evidence rejected the compiled local generation");
    }
    bail!("Evidence rejected the compiled local generation: {diagnostic}")
}

fn render_discovery_description(
    evidence_bin: &Path,
    config_path: &Path,
    target_authored: bool,
) -> Result<Vec<u8>> {
    let mut command = Command::new(evidence_bin);
    command
        .arg("render-discovery-description")
        .arg("--config")
        .arg(config_path)
        .env_remove("REGISTRY_EVIDENCE_RUNTIME");
    let run = run_bounded_evidence(
        command,
        StandardOutput::Bounded(MAX_DISCOVERY_DESCRIPTION_BYTES),
        &format!("{} provider publication compiler", evidence_bin.display()),
    )?;
    if run.status.success() {
        if run.stdout_over_bound {
            bail!(
                "Evidence returned a provider publication description longer than {MAX_DISCOVERY_DESCRIPTION_BYTES} bytes, which no deployment bundle can carry"
            );
        }
        return Ok(run.stdout);
    }
    // Relay the Evidence binary's own message — its validation is closed and
    // value-free, and it names the publication field that refused — but carry
    // it as a field-addressed refusal so `check` and `explain` report the
    // governed document and field instead of a generic offline-check refusal.
    let diagnostic = child_diagnostic(&run.stderr);
    let message = if diagnostic.is_empty() {
        "Evidence rejected provider publication compilation".to_owned()
    } else {
        format!("Evidence rejected provider publication compilation: {diagnostic}")
    };
    Err(AuthoredDiagnostic {
        code: "evidence.target.publication-invalid".to_owned(),
        path: if target_authored {
            "target.yaml:/publication".to_owned()
        } else {
            "evidence.yaml:/publication".to_owned()
        },
        message,
    }
    .into())
}

/// The longest provider publication description evidencectl accepts from the
/// Evidence binary.
///
/// The description is written into the deployment bundle as `catalog.jsonld`,
/// and the runtime bounds every bundle artifact of that kind at the same size
/// when it loads one, so a longer description could never be deployed.
const MAX_DISCOVERY_DESCRIPTION_BYTES: usize = 1024 * 1024;

/// What a delegated `evidence` run does with its standard output.
enum StandardOutput {
    /// The caller reads nothing, so the child writes to the null device.
    Discarded,
    /// The caller reads at most this many bytes of it.
    Bounded(usize),
}

/// What a delegated `evidence` run reported back.
struct BoundedEvidenceRun {
    status: ExitStatus,
    /// The standard output that was kept, empty when it was discarded.
    stdout: Vec<u8>,
    /// Whether standard output ran past the caller's bound. What that means is
    /// the caller's decision, so the bytes are still returned.
    stdout_over_bound: bool,
    /// At most one diagnostic's worth of the child's standard error.
    stderr: Vec<u8>,
}

/// Run a delegated `evidence` command and keep only what the caller can use.
///
/// Both streams are read while the child runs and bounded as they are read, so
/// a child that writes without end cannot grow this process while it waits.
/// `child_diagnostic` stays the single place that sanitizes what an operator
/// is shown.
fn run_bounded_evidence(
    mut command: Command,
    stdout: StandardOutput,
    what: &str,
) -> Result<BoundedEvidenceRun> {
    command.stdin(Stdio::null());
    command.stdout(match stdout {
        StandardOutput::Discarded => Stdio::null(),
        StandardOutput::Bounded(_) => Stdio::piped(),
    });
    command.stderr(Stdio::piped());
    let mut child = command.spawn().with_context(|| format!("running {what}"))?;
    let mut stdout_pipe = child.stdout.take();
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("running {what} left no standard-error pipe to read"))?;

    // The two pipes are read at the same time: draining one to its end first
    // would leave the child blocked on the other once that one filled up.
    let (read_stdout, read_stderr) = thread::scope(|scope| {
        let reader = scope.spawn(|| read_bounded(stderr_pipe, MAX_CHILD_DIAGNOSTIC_BYTES));
        let read_stdout = match (stdout_pipe.as_mut(), &stdout) {
            (Some(pipe), StandardOutput::Bounded(bound)) => read_bounded(pipe, *bound),
            _ => Ok((Vec::new(), false)),
        };
        let read_stderr = match reader.join() {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        (read_stdout, read_stderr)
    });
    let read = read_stdout.and_then(|stdout| read_stderr.map(|stderr| (stdout, stderr)));
    let ((stdout, stdout_over_bound), (stderr, _)) = match read {
        Ok(read) => read,
        Err(error) => {
            // The child may still be writing into a pipe this process can no
            // longer read, so it is stopped rather than waited for.
            crate::evidence_binary::terminate_child(&mut child);
            return Err(error).with_context(|| format!("reading the output of {what}"));
        }
    };
    let status = child.wait().with_context(|| format!("running {what}"))?;
    Ok(BoundedEvidenceRun {
        status,
        stdout,
        stdout_over_bound,
        stderr,
    })
}

/// Read at most `bound` bytes from a child's pipe, then read the rest and
/// throw it away.
///
/// One byte past the bound is read, so a caller can tell a stream that stayed
/// inside its bound from one that ran past it. Reading the remainder away
/// costs nothing here and keeps a child that writes more from blocking on a
/// pipe this process stopped reading.
fn read_bounded(reader: impl io::Read, bound: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut reader = reader;
    let mut captured = Vec::new();
    reader
        .by_ref()
        .take(bound as u64 + 1)
        .read_to_end(&mut captured)?;
    let over_bound = captured.len() > bound;
    io::copy(&mut reader, &mut io::sink())?;
    Ok((captured, over_bound))
}

/// The longest child diagnostic an operator message carries.
///
/// Evidence reports one classified line per refusal, so this budget holds
/// every message the binary produces while bounding a child that says more.
const MAX_CHILD_DIAGNOSTIC_BYTES: usize = 512;

/// Reduce a child process's standard error to one bounded printable diagnostic.
///
/// The bytes reach an operator's terminal and their logs, so the control
/// characters that move a cursor and the escape sequences that repaint a
/// screen are removed before the text is spliced into a message. Newline and
/// tab survive, because a multi-line refusal stays readable. What is left is
/// cut to a fixed budget on a character boundary and marked when it was cut,
/// so a child that floods standard error cannot flood the operator.
fn child_diagnostic(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut printable = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            // Dropping an introducer alone would leave the parameters of a
            // colour or cursor sequence, or the target of a hyperlink,
            // standing as text, so each sequence is consumed through its own
            // terminator.
            '\u{1b}' => consume_escape_sequences(&mut characters),
            // The same introducers in their single-character form. A terminal
            // reading UTF-8 acts on these too, so their payload is consumed
            // rather than left behind by the control-character arm below.
            '\u{9b}' => consume_control_sequence(&mut characters),
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => {
                if consume_string_sequence(&mut characters) {
                    consume_escape_sequences(&mut characters);
                }
            }
            '\n' | '\t' => printable.push(character),
            _ if character.is_control() => {}
            _ => printable.push(character),
        }
    }
    let diagnostic = printable.trim();
    if diagnostic.len() <= MAX_CHILD_DIAGNOSTIC_BYTES {
        return diagnostic.to_owned();
    }
    let mut cut = MAX_CHILD_DIAGNOSTIC_BYTES;
    while !diagnostic.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{} [truncated]", diagnostic[..cut].trim_end())
}

/// The longest run one escape sequence may consume.
///
/// Every sequence a terminal acts on is far shorter than this. The cap is what
/// keeps an introducer whose terminator never arrives from swallowing the rest
/// of a diagnostic: past it the remaining characters are read as text again.
const MAX_ESCAPE_SEQUENCE_CHARS: usize = 128;

/// Consume the escape sequence whose `ESC` was just read, and any sequence
/// that ended it.
///
/// A string sequence may be closed by an `ESC` that starts the next sequence
/// rather than by `ST`, so consumption repeats until no introducer is left.
fn consume_escape_sequences(characters: &mut Peekable<Chars<'_>>) {
    while consume_escape_sequence(characters) {}
}

/// Consume one ECMA-48 escape sequence, its `ESC` already read, and report
/// whether it ended on an `ESC` the caller must still read a sequence for.
fn consume_escape_sequence(characters: &mut Peekable<Chars<'_>>) -> bool {
    match characters.peek() {
        Some('[') => {
            characters.next();
            consume_control_sequence(characters);
            false
        }
        // `OSC`, `DCS`, `SOS`, `PM` and `APC` all carry a payload closed by a
        // terminator rather than by a final byte.
        Some(']' | 'P' | 'X' | '^' | '_') => {
            characters.next();
            consume_string_sequence(characters)
        }
        _ => {
            consume_two_byte_escape(characters);
            false
        }
    }
}

/// Consume a control sequence's parameter and intermediate bytes and the final
/// byte that ends it.
///
/// A sequence whose final byte never arrives, or one holding a character no
/// control sequence may carry, ends where that is found: the text after it is
/// printed rather than swallowed.
fn consume_control_sequence(characters: &mut Peekable<Chars<'_>>) {
    let mut consumed = 0;
    while consumed < MAX_ESCAPE_SEQUENCE_CHARS
        && characters
            .next_if(|candidate| matches!(candidate, '\u{20}'..='\u{3f}'))
            .is_some()
    {
        consumed += 1;
    }
    characters.next_if(|candidate| matches!(candidate, '\u{40}'..='\u{7e}'));
}

/// Consume the intermediate bytes of a two-byte escape and the final byte that
/// ends it.
///
/// An `ESC` that ends the text, or one followed by a character no escape
/// sequence may carry, consumes nothing further.
fn consume_two_byte_escape(characters: &mut Peekable<Chars<'_>>) {
    let mut consumed = 0;
    while consumed < MAX_ESCAPE_SEQUENCE_CHARS
        && characters
            .next_if(|candidate| matches!(candidate, '\u{20}'..='\u{2f}'))
            .is_some()
    {
        consumed += 1;
    }
    characters.next_if(|candidate| matches!(candidate, '\u{30}'..='\u{7e}'));
}

/// Consume a string sequence's payload and the `ST` or `BEL` that ends it, and
/// report whether it ended on an `ESC` that starts another sequence instead.
///
/// The payload carries arbitrary text, a hyperlink target among it, so it is
/// consumed rather than printed. A terminator that never arrives ends the
/// sequence at the cap, so what follows is read as text.
fn consume_string_sequence(characters: &mut Peekable<Chars<'_>>) -> bool {
    let mut consumed = 0;
    while consumed < MAX_ESCAPE_SEQUENCE_CHARS {
        match characters.next() {
            None | Some('\u{7}') | Some('\u{9c}') => return false,
            // `ST` in its two-character form. Anything else after the `ESC`
            // begins a sequence of its own, which the caller reads.
            Some('\u{1b}') => return characters.next_if_eq(&'\\').is_none(),
            Some(_) => consumed += 1,
        }
    }
    false
}

fn yaml_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut text = crate::authored::to_indented_yaml(value)?;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text.into_bytes())
}

fn local_uri(suffix: &str) -> String {
    format!("{LOCAL_URI_PREFIX}{suffix}")
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "support regressions inspect synthetic generated artifacts and stub processes"
    )]
    use super::*;
    use crate::evidence_binary::retry_busy_stub;
    use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};

    #[test]
    fn local_target_compilation_refuses_a_symlinked_generated_parent_before_key_generation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let project = root.join("project");
        let stage = root.join("stage");
        let outside = root.join("outside");
        for path in [&project, &stage, &outside] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        fs::copy(example.join("evidence.yaml"), project.join("evidence.yaml")).unwrap();
        for (relative, bytes) in crate::normalized::read(&example).unwrap().1 {
            let path = project.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        std::os::unix::fs::symlink(&outside, project.join(".generated")).unwrap();
        let evidence = root.join("evidence");
        write_stub_evidence(&evidence, "#!/bin/sh\nexit 1\n");

        let result = compile_local_project_with_target_inputs_resource_and_authority(
            &project,
            &stage,
            &evidence,
            LocalServicePorts::default(),
            json!({}),
            json!({}),
            LOCAL_AUDIENCE,
            &LocalAdmission::default(),
            None,
        );

        assert!(result.is_err(), "linked generated parent must be refused");
        assert_eq!(
            fs::read_dir(&outside).unwrap().count(),
            0,
            "local compilation wrote outside the project"
        );
        assert_eq!(fs::read_dir(&stage).unwrap().count(), 0);
    }

    #[test]
    fn local_compilation_measures_definitions_against_the_target_signing_maximum() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let project = root.join("project");
        let stage = root.join("stage");
        for path in [&project, &stage] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        fs::copy(example.join("evidence.yaml"), project.join("evidence.yaml")).unwrap();
        fs::copy(
            example.join("dev-authority.yaml"),
            project.join("dev-authority.yaml"),
        )
        .unwrap();
        for (relative, bytes) in crate::normalized::read(&example).unwrap().1 {
            let path = project.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        let mut target = fs::read_to_string(example.join("local-target.yaml")).unwrap();
        target.push_str("signing:\n  maximumAssertionValiditySeconds: 100\n");
        let target_path = project.join("local-target.yaml");
        fs::write(&target_path, target).unwrap();
        let evidence = root.join("evidence");
        write_stub_evidence(&evidence, "#!/bin/sh\nexit 1\n");

        let error = compile_normalized_local_project(
            &project,
            &stage,
            &evidence,
            LocalServicePorts::default(),
            &target_path,
            LOCAL_AUDIENCE,
            &LocalAdmission::default(),
        )
        .expect_err("a 300 second definition exceeds the target's 100 second maximum");
        let diagnostic = error
            .downcast_ref::<AuthoredDiagnostic>()
            .expect("the refusal is the authored validity diagnostic");
        assert_eq!(
            diagnostic.code,
            "evidence.definition.validity-exceeds-signing-maximum"
        );
        assert_eq!(fs::read_dir(&stage).unwrap().count(), 0);
    }

    #[test]
    fn generated_yaml_indents_sequences_beneath_their_keys() {
        let bytes = yaml_bytes(&json!({"required": ["a", "b"]})).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "required:\n  - a\n  - b\n"
        );
    }

    #[test]
    fn a_cleanup_failure_line_names_the_path_and_the_cause() {
        let line = cleanup_failure_line(
            Path::new("/staging/bundle"),
            &anyhow!("reading /staging/bundle").context("sealed generation"),
        );
        assert_eq!(
            line,
            "evidencectl: failed to restore owner write on /staging/bundle: sealed generation: reading /staging/bundle"
        );
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

        let error = retry_busy_stub(|| render_discovery_description(&evidence, &config_path, true))
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

        let error = retry_busy_stub(|| render_discovery_description(&evidence, &config_path, true))
            .expect_err("a rejected compilation must fail");
        assert_eq!(
            format!("{error:#}"),
            "Evidence rejected provider publication compilation"
        );
    }

    #[test]
    fn a_long_child_diagnostic_is_cut_to_the_budget_on_a_character_boundary() {
        let overlong = "\u{20ac}".repeat(MAX_CHILD_DIAGNOSTIC_BYTES);

        let diagnostic = child_diagnostic(overlong.as_bytes());

        assert!(diagnostic.ends_with(" [truncated]"), "{diagnostic}");
        let kept = diagnostic
            .strip_suffix(" [truncated]")
            .expect("the marker is present");
        assert!(kept.len() <= MAX_CHILD_DIAGNOSTIC_BYTES, "{}", kept.len());
        assert_eq!(
            kept.len() % "\u{20ac}".len(),
            0,
            "the cut must land on a character boundary"
        );
        assert!(kept.chars().all(|character| character == '\u{20ac}'));
    }

    #[test]
    fn render_discovery_description_bounds_a_long_child_diagnostic() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        let flood = "publication rejected ".repeat(64);
        write_stub_evidence(
            &evidence,
            &format!("#!/bin/sh\nprintf '%s' '{flood}' >&2\nexit 1\n"),
        );
        let config_path = root.path().join("evidence.yaml");
        fs::write(&config_path, "questions: []\n").expect("config");

        let error = retry_busy_stub(|| render_discovery_description(&evidence, &config_path, true))
            .expect_err("a rejected compilation must fail");

        let diagnostic = format!("{error:#}");
        assert!(diagnostic.ends_with("[truncated]"), "{diagnostic}");
        assert!(
            diagnostic.len()
                < "Evidence rejected provider publication compilation: ".len()
                    + MAX_CHILD_DIAGNOSTIC_BYTES
                    + " [truncated]".len()
                    + 1,
            "{}",
            diagnostic.len()
        );
    }

    #[test]
    fn a_flooding_child_is_read_within_the_diagnostic_bound() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(
            &evidence,
            "#!/bin/sh\nyes 'evidence flooded standard error' | head -c 4194304 >&2\nexit 1\n",
        );

        let run = retry_busy_stub(|| {
            run_bounded_evidence(Command::new(&evidence), StandardOutput::Discarded, "a stub")
        })
        .expect("the stub runs to completion");

        assert!(!run.status.success());
        assert!(
            run.stderr.len() <= MAX_CHILD_DIAGNOSTIC_BYTES + 1,
            "held {} bytes of the child's standard error",
            run.stderr.len()
        );
    }

    #[test]
    fn render_discovery_description_completes_when_the_child_floods_standard_error() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(
            &evidence,
            "#!/bin/sh\nyes 'evidence flooded standard error' | head -c 4194304 >&2\nexit 1\n",
        );
        let config_path = root.path().join("evidence.yaml");
        fs::write(&config_path, "questions: []\n").expect("config");

        let error = retry_busy_stub(|| render_discovery_description(&evidence, &config_path, true))
            .expect_err("a rejected compilation must fail");

        let diagnostic = format!("{error:#}");
        assert!(diagnostic.ends_with("[truncated]"), "{diagnostic}");
        assert!(
            diagnostic.len()
                <= "Evidence rejected provider publication compilation: ".len()
                    + MAX_CHILD_DIAGNOSTIC_BYTES
                    + " [truncated]".len(),
            "{}",
            diagnostic.len()
        );
    }

    #[test]
    fn render_discovery_description_refuses_a_description_past_the_bundle_artifact_bound() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(
            &evidence,
            &format!(
                "#!/bin/sh\nyes 'catalog' | head -c {}\nexit 0\n",
                MAX_DISCOVERY_DESCRIPTION_BYTES + 1024
            ),
        );
        let config_path = root.path().join("evidence.yaml");
        fs::write(&config_path, "questions: []\n").expect("config");

        let error = retry_busy_stub(|| render_discovery_description(&evidence, &config_path, true))
            .expect_err("an oversized description must be refused");

        assert!(format!("{error:#}").contains("longer than"), "{error:#}");
    }

    #[test]
    fn render_discovery_description_strips_child_terminal_control_sequences() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(
            &evidence,
            "#!/bin/sh\nprintf '\\033[31mcatalog binding rejected\\033[0m\\rcompleted' >&2\nexit 1\n",
        );
        let config_path = root.path().join("evidence.yaml");
        fs::write(&config_path, "questions: []\n").expect("config");

        let error = retry_busy_stub(|| render_discovery_description(&evidence, &config_path, true))
            .expect_err("a rejected compilation must fail");

        let diagnostic = format!("{error:#}");
        assert_eq!(
            diagnostic,
            "Evidence rejected provider publication compilation: \
             catalog binding rejectedcompleted"
        );
        assert!(!diagnostic.contains('\u{1b}'), "{diagnostic:?}");
        assert!(!diagnostic.contains('\r'), "{diagnostic:?}");
        assert!(!diagnostic.contains("[31m"), "{diagnostic:?}");
    }

    #[test]
    fn render_discovery_description_strips_a_child_operating_system_command() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(
            &evidence,
            "#!/bin/sh\nprintf '\\033]8;;https://example.invalid\\033\\\\click here\\033]8;;\\033\\\\ rejected' >&2\nexit 1\n",
        );
        let config_path = root.path().join("evidence.yaml");
        fs::write(&config_path, "questions: []\n").expect("config");

        let error = retry_busy_stub(|| render_discovery_description(&evidence, &config_path, true))
            .expect_err("a rejected compilation must fail");

        let diagnostic = format!("{error:#}");
        assert_eq!(
            diagnostic,
            "Evidence rejected provider publication compilation: click here rejected"
        );
        assert!(!diagnostic.contains("example.invalid"), "{diagnostic:?}");
    }

    #[test]
    fn a_two_byte_escape_leaves_neither_its_introducer_nor_its_final_byte() {
        assert_eq!(child_diagnostic(b"\x1b7saved\x1b8"), "saved");
        assert_eq!(child_diagnostic(b"\x1b(Bdesignated"), "designated");
    }

    #[test]
    fn a_control_sequence_without_a_final_byte_swallows_no_message() {
        assert_eq!(
            child_diagnostic(b"\x1b[1;2;3\nbundle rejected"),
            "bundle rejected"
        );
    }

    #[test]
    fn a_string_sequence_without_a_terminator_is_consumed_only_to_its_cap() {
        let mut stderr = b"\x1b]".to_vec();
        stderr.extend(std::iter::repeat_n(b'a', MAX_ESCAPE_SEQUENCE_CHARS));
        stderr.extend_from_slice(b"bundle rejected");

        assert_eq!(child_diagnostic(&stderr), "bundle rejected");
    }

    #[test]
    fn check_with_evidence_strips_child_terminal_control_sequences() {
        let root = tempfile::tempdir().expect("tempdir");
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(
            &evidence,
            "#!/bin/sh\nprintf '\\033[1;31mbundle compilation failed\\033[0m' >&2\nexit 1\n",
        );
        let runtime_path = root.path().join("runtime.yaml");
        fs::write(&runtime_path, "version: 1\n").expect("runtime");

        let error = retry_busy_stub(|| check_with_evidence(&evidence, &runtime_path))
            .expect_err("a rejected generation must fail");

        assert_eq!(
            format!("{error:#}"),
            "Evidence rejected the compiled local generation: bundle compilation failed"
        );
    }

    fn minimal_definition_plan(definition_id: &str, validity_seconds: u64) -> DefinitionPlan {
        DefinitionPlan {
            definition_id: definition_id.to_owned(),
            fixture_artifact: None,
            purpose: String::new(),
            requirement_uri: String::new(),
            concepts: Vec::new(),
            subjects: Vec::new(),
            requirement: json!({"validitySeconds": validity_seconds}),
        }
    }

    fn plan_with_validity(validity_seconds: u64, signing: Value) -> CompilePlan {
        CompilePlan {
            definitions: vec![minimal_definition_plan("record-status", validity_seconds)],
            bundle: json!({ "signing": signing }),
            local_public_jwk: None,
            generated_artifacts: BTreeMap::new(),
            authority_document: None,
        }
    }

    #[test]
    fn target_signing_validity_passes_a_requirement_at_the_target_signing_maximum() {
        check_target_signing_validity(&plan_with_validity(
            900,
            json!({"maximumAssertionValiditySeconds": 900}),
        ))
        .expect("a requirement at the target's own maximum is covered");
    }

    #[test]
    fn target_signing_validity_refuses_a_requirement_past_the_target_signing_maximum() {
        let error = check_target_signing_validity(&plan_with_validity(
            900,
            json!({"maximumAssertionValiditySeconds": 300}),
        ))
        .expect_err("900 seconds exceeds a target signing maximum of 300 seconds");
        let diagnostic = error
            .downcast_ref::<AuthoredDiagnostic>()
            .expect("a signing validity refusal is an authored diagnostic");
        assert_eq!(
            diagnostic.code,
            "evidence.definition.validity-exceeds-signing-maximum"
        );
        assert_eq!(
            diagnostic.path,
            "evidence.yaml:/assertionDefinitions/record-status/validitySeconds"
        );
        assert_eq!(
            diagnostic.message,
            "the requirement validity exceeds the deployment target's signing maximum at target.yaml /signing/maximumAssertionValiditySeconds"
        );
        assert!(!diagnostic.message.contains("900") && !diagnostic.message.contains("300"));
    }

    #[test]
    fn target_signing_validity_leaves_an_unstated_target_maximum_to_the_runtime() {
        check_target_signing_validity(&plan_with_validity(900, json!({})))
            .expect("a target stating no maximum is validated by the runtime, not assumed");
    }

    /// The governance a normalized target compiles to, from the standalone
    /// example's target document with `signing` appended when given.
    fn standalone_target_governance(signing: Option<&str>) -> Value {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        let root = tempfile::tempdir().expect("tempdir");
        let mut target = fs::read_to_string(example.join("local-target.yaml")).expect("target");
        if let Some(signing) = signing {
            target.push_str(signing);
        }
        fs::write(root.path().join("local-target.yaml"), target).expect("write target");
        fs::copy(
            example.join("dev-authority.yaml"),
            root.path().join("dev-authority.yaml"),
        )
        .expect("copy authority");
        crate::normalized::read_target_documents(&root.path().join("local-target.yaml"))
            .expect("the standalone target compiles to governance")
            .governed_bundle
    }

    #[test]
    fn a_target_stating_no_signing_maximum_compiles_to_the_local_baseline() {
        let governance = standalone_target_governance(None);
        assert_eq!(
            governance["signing"]["maximumAssertionValiditySeconds"],
            300
        );
        let key = governance["signing"]["activePublicJwkFile"]
            .as_str()
            .expect("the active key file");
        let baseline = local_target_governance(key).expect("baseline");
        assert_eq!(governance["signing"], baseline["signing"]);
    }

    #[test]
    fn a_target_signing_maximum_is_carried_into_governance_and_measured() {
        let signing = "signing:\n  maximumAssertionValiditySeconds: 604800\n";
        let governance = standalone_target_governance(Some(signing));
        assert_eq!(
            governance["signing"]["maximumAssertionValiditySeconds"],
            604_800
        );
        // Only the stated member changes.
        let baseline = local_target_governance("unused.jwk.json").expect("baseline");
        for member in [
            "format",
            "algorithm",
            "jwksPath",
            "verifierClockSkewSeconds",
        ] {
            assert_eq!(governance["signing"][member], baseline["signing"][member]);
        }
        let plan = |validity_seconds, governance: &Value| CompilePlan {
            bundle: governance.clone(),
            ..plan_with_validity(validity_seconds, json!({}))
        };
        check_target_signing_validity(&plan(604_800, &governance))
            .expect("a definition at the stated maximum is covered");
        let error = check_target_signing_validity(&plan(604_801, &governance))
            .expect_err("a definition past the stated maximum is refused");
        assert_eq!(
            error
                .downcast_ref::<AuthoredDiagnostic>()
                .expect("an authored diagnostic")
                .code,
            "evidence.definition.validity-exceeds-signing-maximum"
        );
    }

    #[test]
    fn a_seven_day_definition_is_refused_by_a_smaller_or_unstated_target_maximum() {
        let smaller = "signing:\n  maximumAssertionValiditySeconds: 604799\n";
        for governance in [
            standalone_target_governance(Some(smaller)),
            standalone_target_governance(None),
        ] {
            let plan = CompilePlan {
                bundle: governance,
                ..plan_with_validity(604_800, json!({}))
            };
            let error = check_target_signing_validity(&plan)
                .expect_err("seven days exceeds the target's maximum");
            let diagnostic = error
                .downcast_ref::<AuthoredDiagnostic>()
                .expect("an authored diagnostic");
            assert_eq!(
                diagnostic.code,
                "evidence.definition.validity-exceeds-signing-maximum"
            );
            assert_eq!(
                diagnostic.path,
                "evidence.yaml:/assertionDefinitions/record-status/validitySeconds"
            );
        }
    }

    #[test]
    fn normalized_plan_preserves_sources_definitions_and_ceiling_enforcement() {
        let project_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        let inputs = read_inputs(&project_root, false).unwrap();
        let expected =
            registry_evidence_authoring::compile::compile(&inputs.project, &inputs.scripts)
                .unwrap();
        let (connections, _) =
            crate::build::local_dev_target_inputs(&project_root.join("local-target.yaml")).unwrap();
        let plan = compile_plan_with_connections(
            inputs,
            CompileProfile::Local {
                ports: LocalServicePorts::default(),
                audience: LOCAL_AUDIENCE.to_owned(),
                active_public_jwk_file: OFFLINE_CHECK_PUBLIC_JWK_FILE.to_owned(),
                active_public_jwk: OFFLINE_CHECK_PUBLIC_JWK.as_bytes().to_vec(),
                admission: LocalAdmission::default(),
            },
            connections,
        )
        .unwrap();
        assert_eq!(plan.bundle["requirements"], expected.model["requirements"]);
        assert_eq!(
            plan.bundle["selectorProfiles"],
            expected.model["selectorProfiles"]
        );
        assert_eq!(plan.bundle["sources"].as_object().unwrap().len(), 3);
        assert_eq!(plan.bundle["requirements"].as_array().unwrap().len(), 4);
        assert_eq!(plan.bundle["authorityProfiles"], json!({}));
        assert!(plan.bundle["sources"]
            .as_object()
            .unwrap()
            .values()
            .all(|source| {
                source
                    .get("connection")
                    .and_then(Value::as_str)
                    .is_some_and(|id| plan.bundle["sourceConnections"].get(id).is_some())
            }));
        assert!(plan.bundle["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .all(|definition| {
                definition["grantCeiling"]["authorities"]
                    .as_array()
                    .is_some_and(|values| !values.is_empty())
                    && definition["representations"]
                        .as_array()
                        .is_some_and(|values| !values.is_empty())
                    && !definition["concepts"].as_array().unwrap().is_empty()
            }));
        assert!(plan
            .generated_artifacts
            .contains_key("derivations/adult-status.rhai"));
    }
    #[test]
    fn package_writer_creates_only_referenced_artifact_directories() {
        let root = tempfile::tempdir().unwrap();
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(&evidence, "#!/bin/sh\nexit 0\n");
        let stage = root.path().join("candidate");
        create_private_directory(&stage).unwrap();
        let plan = CompilePlan {
            definitions: Vec::new(),
            bundle: json!({}),
            local_public_jwk: None,
            generated_artifacts: BTreeMap::from([(
                "derivations/check.rhai".to_owned(),
                b"fn derive(a,b,c){[]}\n".to_vec(),
            )]),
            authority_document: None,
        };
        let bundle = write_bundle(root.path(), None, &stage, &plan, &evidence, None).unwrap();
        assert!(bundle.join("derivations/check.rhai").is_file());
        for absent in ["codelists", "adapters", "schemas", "public-keys"] {
            assert!(
                !bundle.join(absent).exists(),
                "unreferenced package directory created"
            );
        }
        set_bundle_modes(&bundle, 0o700, 0o600).unwrap();
    }

    #[test]
    fn package_writer_refuses_reserved_and_directory_aliases_before_writing() {
        let root = tempfile::tempdir().unwrap();
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(&evidence, "#!/bin/sh\nexit 0\n");
        for (index, reserved) in [
            "evidence.yaml",
            "catalog.jsonld",
            registry_platform_config::SUM_FILE,
            registry_platform_config::REVISION_FILE,
        ]
        .into_iter()
        .enumerate()
        {
            let stage = root.path().join(format!("reserved-{index}"));
            create_private_directory(&stage).unwrap();
            let plan = CompilePlan {
                definitions: Vec::new(),
                bundle: json!({}),
                local_public_jwk: None,
                generated_artifacts: BTreeMap::from([(
                    reserved.to_owned(),
                    b"authored overwrite".to_vec(),
                )]),
                authority_document: None,
            };
            let error = write_bundle(root.path(), None, &stage, &plan, &evidence, None)
                .expect_err("reserved output must be refused");
            assert!(format!("{error:#}").contains("is reserved"));
            assert!(!stage.join("bundle").exists());
        }
        let error = ensure_no_bundle_path_aliases([
            "schemas/source-response",
            "schemas/source-response/person.schema.json",
        ])
        .expect_err("one artifact cannot also be a directory");
        assert!(format!("{error:#}").contains("cannot also be a directory"));
        let error =
            ensure_no_bundle_path_aliases([registry_platform_config::SUM_FILE, "sha256sums"])
                .expect_err("case-folded names must be refused before writing");
        assert!(format!("{error:#}").contains("only in letter case"));
    }

    #[test]
    fn package_writer_compares_colliding_fixture_bytes_and_reuses_identical_assets() {
        let root = tempfile::tempdir().unwrap();
        let fixture_path = root.path().join("fixtures/shared.yaml");
        fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
        fs::write(&fixture_path, b"fixture: authored\n").unwrap();
        let evidence = root.path().join("evidence-stub");
        write_stub_evidence(&evidence, "#!/bin/sh\nexit 0\n");

        let different_stage = root.path().join("different");
        create_private_directory(&different_stage).unwrap();
        let mut definition = minimal_definition_plan("record-status", 60);
        definition.fixture_artifact = Some("fixtures/shared.yaml".to_owned());
        let different = CompilePlan {
            definitions: vec![definition],
            bundle: json!({}),
            local_public_jwk: None,
            generated_artifacts: BTreeMap::from([(
                "fixtures/shared.yaml".to_owned(),
                b"fixture: generated\n".to_vec(),
            )]),
            authority_document: None,
        };
        let error = write_bundle(
            root.path(),
            None,
            &different_stage,
            &different,
            &evidence,
            None,
        )
        .expect_err("different bytes at one path must be refused");
        assert!(format!("{error:#}").contains("assigns different content"));
        assert!(!different_stage.join("bundle").exists());

        let shared_stage = root.path().join("shared");
        create_private_directory(&shared_stage).unwrap();
        let mut first = minimal_definition_plan("first", 60);
        first.fixture_artifact = Some("fixtures/shared.yaml".to_owned());
        let mut second = minimal_definition_plan("second", 60);
        second.fixture_artifact = Some("fixtures/shared.yaml".to_owned());
        let shared = CompilePlan {
            definitions: vec![first, second],
            bundle: json!({}),
            local_public_jwk: None,
            generated_artifacts: BTreeMap::new(),
            authority_document: None,
        };
        let bundle =
            write_bundle(root.path(), None, &shared_stage, &shared, &evidence, None).unwrap();
        assert_eq!(
            fs::read(bundle.join("fixtures/shared.yaml")).unwrap(),
            b"fixture: authored\n"
        );
        set_bundle_modes(&bundle, 0o700, 0o600).unwrap();
    }
}
