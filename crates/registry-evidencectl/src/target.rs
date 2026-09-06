//! Deployment target authoring for `evidencectl`.
//!
//! A target is a native pair of reviewed `governance.yaml` and `runtime.yaml`
//! plus public signing keys. This module packages those files create-only
//! from an explicit settings document; it does not invent production
//! authority, generate keys, copy secrets, or relax the runtime schema.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{build, evidence_binary, source_import::ProjectLock};
use registry_platform_crypto::{PublicJwk, SigningAlgorithm};

const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;
const MAX_PUBLIC_KEY_BYTES: u64 = 256 * 1024;
const SECRET_PREFIX: &str = "secret:file/";

#[derive(Debug, Subcommand)]
pub(crate) enum TargetCommand {
    /// Create deployment target files from an explicit settings file.
    New(NewArgs),
    /// Inspect the public files and logical secret references in a target.
    Explain(ExplainArgs),
}

#[derive(Debug, Args)]
pub(crate) struct NewArgs {
    /// New target directory to create.
    pub directory: PathBuf,

    /// Closed settings document with native governance, runtime, and public keys.
    ///
    /// This command checks target-file shape, logical secret references, and
    /// public-key identity. Project-specific bundle and runtime semantics are
    /// checked by `target explain`, `fixtures run --target`, `build --target`,
    /// and `doctor`.
    #[arg(long)]
    pub settings: PathBuf,

    /// Public signing JWK whose RFC 7638 thumbprint names activePublicJwkFile.
    #[arg(long)]
    pub signing_public_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct ExplainArgs {
    /// Complete deployment target containing governance.yaml and runtime.yaml.
    pub target: PathBuf,

    /// Evidence project directory; defaults to the current directory.
    ///
    /// This command needs an editable project: one holding questions/ and
    /// sources/ beside evidence-project.yaml.
    #[arg(long, default_value = ".")]
    pub project: PathBuf,

    /// Emit one machine-readable JSON report on standard output.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetSettings {
    format_version: u32,
    governance: Value,
    runtime: Value,
    #[serde(default)]
    public_keys: BTreeMap<String, PathBuf>,
}

/// The closed Version 1 runtime settings shape, mirroring
/// `products/evidence/contracts/runtime.schema.yaml`.
///
/// evidencectl deliberately does not link the runtime crate, so it cannot
/// deserialize the document through the runtime's own type. The runtime denies
/// unknown fields and refuses a misspelled or unpublished key at startup; this
/// mirror moves that refusal into `target new`, before a target directory the
/// deployment cannot load exists. Each section stays untyped here because the
/// runtime, not evidencectl, owns what is inside it. The mirror is held in step
/// with the published contract by
/// `the_closed_runtime_mirror_matches_the_published_runtime_contract`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
// The fields state which keys the document may carry and which it must carry;
// deserializing is the whole check, so nothing reads them afterwards.
#[allow(dead_code)]
struct TargetRuntime {
    version: u32,
    bundle_directory: String,
    listener: Value,
    #[serde(default)]
    metrics_listener: Option<Value>,
    secret_providers: Value,
    signer: Value,
    audit_storage: Value,
    outbound_tls: Value,
    #[serde(default)]
    source_extracts: Option<Value>,
    #[serde(default)]
    acquisition_capabilities: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetReport {
    format_version: u32,
    target: String,
    fixture_paths: Vec<String>,
    public_key_files: Vec<String>,
    missing_public_key_files: Vec<String>,
    secret_references: Vec<String>,
}

pub(crate) fn run(command: TargetCommand) -> Result<ExitCode> {
    match command {
        TargetCommand::New(args) => new(args),
        TargetCommand::Explain(args) => explain(args),
    }
}

fn new(args: NewArgs) -> Result<ExitCode> {
    reject_existing(&args.directory)?;
    let parent = plain_parent(&args.directory, "target parent")?;
    let settings_parent = plain_parent(&args.settings, "settings parent")?;
    let settings_name = args
        .settings
        .file_name()
        .ok_or_else(|| anyhow!("settings file must name one file"))?;
    let settings_path = settings_parent.join(settings_name);
    let mut settings: TargetSettings = serde_norway::from_slice(&read_plain_file(
        &settings_path,
        MAX_SETTINGS_BYTES,
        "target settings",
    )?)
    .context("target settings are not the closed Version 1 shape")?;
    if settings.format_version != 1 {
        bail!("target settings formatVersion must be 1");
    }
    validate_settings_documents(&settings.governance, &settings.runtime)?;
    let derived_signing_public_key = args
        .signing_public_key
        .as_deref()
        .map(|path| signing_public_key_reference(path, "signing public key"))
        .transpose()?;
    if let Some((relative, _)) = &derived_signing_public_key {
        set_or_validate_active_public_key(&mut settings.governance, relative)?;
    }
    let expected_public_keys = expected_public_key_files(&settings.governance)?;
    let mut supplied_public_keys =
        normalize_supplied_public_keys(settings.public_keys, &settings_parent)?;
    if let Some((relative, source)) = derived_signing_public_key {
        if supplied_public_keys.insert(relative, source).is_some() {
            bail!("target settings must not also list the public key supplied by --signing-public-key");
        }
    }
    let supplied_names: BTreeSet<_> = supplied_public_keys.keys().cloned().collect();
    let expected_names: BTreeSet<_> = expected_public_keys.iter().cloned().collect();
    let missing: Vec<_> = expected_names
        .difference(&supplied_names)
        .cloned()
        .collect();
    let extra: Vec<_> = supplied_names
        .difference(&expected_names)
        .cloned()
        .collect();
    if !missing.is_empty() {
        bail!("target settings do not supply every public signing key referenced by governance");
    }
    if !extra.is_empty() {
        bail!("target settings name public keys not referenced by governance");
    }

    let staging = tempfile::Builder::new()
        .prefix(".evidencectl-target-")
        .tempdir_in(&parent)
        .with_context(|| format!("staging the target in {}", parent.display()))?;
    let staged = staging.path();
    fs::DirBuilder::new()
        .mode(0o755)
        .create(staged.join("public-keys"))
        .context("creating public-keys directory")?;
    write_new_file(
        &staged.join("governance.yaml"),
        serde_norway::to_string(&settings.governance)
            .context("encoding governance.yaml")?
            .as_bytes(),
        0o644,
    )?;
    write_new_file(
        &staged.join("runtime.yaml"),
        serde_norway::to_string(&settings.runtime)
            .context("encoding runtime.yaml")?
            .as_bytes(),
        0o644,
    )?;
    for (relative, source) in supplied_public_keys {
        write_new_file(&staged.join(relative), &source.bytes, 0o644)?;
    }
    publish(staging, &args.directory)?;
    println!(
        "Created deployment target files {}",
        args.directory.display()
    );
    println!(
        "Next: run `evidencectl fixtures run --project <editable-project> --target {}` before `evidencectl build`.",
        args.directory.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn validate_settings_documents(governance: &Value, runtime: &Value) -> Result<()> {
    let governance = governance
        .as_object()
        .ok_or_else(|| anyhow!("target settings governance must be a mapping"))?;
    let runtime = runtime
        .as_object()
        .ok_or_else(|| anyhow!("target settings runtime must be a mapping"))?;
    // Validate governance through the same closed type the consumers deserialize
    // it with (build::TargetGovernance), so `target new` refuses exactly what
    // `target explain`, `build --target`, and `fixtures run --target` refuse and
    // never leaves behind a create-only directory those commands cannot open.
    serde_json::from_value::<build::TargetGovernance>(Value::Object(governance.clone()))
        .context("target settings governance is not the closed deployment governance shape")?
        .into_bundle()
        .context("target settings governance is not the closed deployment governance shape")?;
    if runtime.get("version").and_then(Value::as_u64) != Some(1) {
        bail!("target settings runtime.version must be 1");
    }
    for section in [
        "service",
        "issuer",
        "authentication",
        "audit",
        "subjectBinding",
        "rateLimits",
        "signing",
        "authorityProfiles",
    ] {
        require_nonempty_mapping(governance, section, "target settings governance")?;
    }
    if runtime
        .get("bundleDirectory")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        bail!("target settings runtime.bundleDirectory must be a string");
    }
    for section in [
        "listener",
        "secretProviders",
        "signer",
        "auditStorage",
        "outboundTls",
    ] {
        require_nonempty_mapping(runtime, section, "target settings runtime")?;
    }
    // Validate the runtime document through the closed mirror of the shape the
    // runtime loads, so `target new` refuses an unknown or misspelled key here
    // rather than writing a runtime.yaml the deployment refuses at startup.
    serde_json::from_value::<TargetRuntime>(Value::Object(runtime.clone()))
        .context("target settings runtime is not the closed Version 1 runtime shape")?;
    let mut secret_references = BTreeSet::new();
    collect_secret_references(&Value::Object(governance.clone()), &mut secret_references)?;
    collect_secret_references(&Value::Object(runtime.clone()), &mut secret_references)?;
    Ok(())
}

fn require_nonempty_mapping(
    object: &serde_json::Map<String, Value>,
    section: &str,
    label: &str,
) -> Result<()> {
    if object
        .get(section)
        .and_then(Value::as_object)
        .is_some_and(|section| !section.is_empty())
    {
        return Ok(());
    }
    bail!("{label}.{section} must be a mapping");
}

fn explain(args: ExplainArgs) -> Result<ExitCode> {
    let target = fs::canonicalize(&args.target).context("resolving deployment target")?;
    let _project_lock = ProjectLock::acquire(&args.project)
        .with_context(|| format!("locking editable project {}", args.project.display()))?;
    let evidence_bin = evidence_binary::resolve_matching(None)?;
    let governance: Value = serde_norway::from_slice(&read_plain_file(
        &target.join("governance.yaml"),
        MAX_SETTINGS_BYTES,
        "deployment governance",
    )?)
    .context("parsing deployment governance")?;
    let runtime: Value = serde_norway::from_slice(&read_plain_file(
        &target.join("runtime.yaml"),
        MAX_SETTINGS_BYTES,
        "deployment runtime",
    )?)
    .context("parsing deployment runtime")?;
    let public_key_files = expected_public_key_files(&governance)?;
    let missing_public_key_files = public_key_files
        .iter()
        .filter(|path| {
            read_plain_file(
                &target.join(path),
                MAX_PUBLIC_KEY_BYTES,
                "public signing key",
            )
            .is_err()
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut secret_references = BTreeSet::new();
    collect_secret_references(&governance, &mut secret_references)?;
    collect_secret_references(&runtime, &mut secret_references)?;
    // The compile below copies every public key file this governance
    // references from the deployment target and fails when one is missing, so
    // the inventory above must run first: a missing key is reported here
    // instead of surfacing as an unrelated compile failure.
    let fixture_paths = if missing_public_key_files.is_empty() {
        let compiled = build::compile_target_fixture_project(&args.project, &target, &evidence_bin)
            .context("compiling editable project with deployment target")?;
        compiled.fixture_paths.clone()
    } else {
        Vec::new()
    };
    let report = TargetReport {
        format_version: 1,
        target: target.display().to_string(),
        fixture_paths,
        public_key_files,
        missing_public_key_files,
        secret_references: secret_references.into_iter().collect(),
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).context("encoding target explanation")?
        );
    } else {
        println!("Target: {}", report.target);
        for fixture in &report.fixture_paths {
            println!("Fixture: {fixture}");
        }
        for public_key in &report.public_key_files {
            println!("Public key: {public_key}");
        }
        for missing in &report.missing_public_key_files {
            println!("Missing public key: {missing}");
        }
        for reference in &report.secret_references {
            println!("Provision {SECRET_PREFIX}{reference}");
        }
    }
    Ok(if report.missing_public_key_files.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn expected_public_key_files(governance: &Value) -> Result<Vec<String>> {
    let signing = governance
        .get("signing")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("target governance must contain native signing configuration"))?;
    let mut files = BTreeSet::new();
    let active = signing
        .get("activePublicJwkFile")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("target governance signing.activePublicJwkFile is required"))?;
    files.insert(public_key_path(active)?);
    if let Some(published) = signing.get("publishedPublicJwkFiles") {
        let published = published.as_array().ok_or_else(|| {
            anyhow!("target governance signing.publishedPublicJwkFiles must be a list")
        })?;
        for value in published {
            let path = value.as_str().ok_or_else(|| {
                anyhow!("target governance published public key paths must be strings")
            })?;
            files.insert(public_key_path(path)?);
        }
    }
    Ok(files.into_iter().collect())
}

fn set_or_validate_active_public_key(governance: &mut Value, relative: &str) -> Result<()> {
    let signing = governance
        .get_mut("signing")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("target governance must contain native signing configuration"))?;
    match signing.get("activePublicJwkFile") {
        Some(Value::String(current)) => {
            let current = public_key_path(current)?;
            if current != relative {
                bail!("target governance signing.activePublicJwkFile does not match the --signing-public-key thumbprint");
            }
        }
        Some(_) => bail!("target governance signing.activePublicJwkFile must be a string"),
        None => {
            signing.insert(
                "activePublicJwkFile".to_owned(),
                Value::String(relative.to_owned()),
            );
        }
    }
    Ok(())
}

struct PublicKeySource {
    bytes: Vec<u8>,
}

fn signing_public_key_reference(
    path: &Path,
    description: &str,
) -> Result<(String, PublicKeySource)> {
    let source = resolve_plain_file(path, description)?;
    let bytes = read_plain_file(&source, MAX_PUBLIC_KEY_BYTES, description)?;
    let text =
        std::str::from_utf8(&bytes).with_context(|| format!("{description} must be UTF-8"))?;
    let public = PublicJwk::parse(text)
        .with_context(|| format!("{description} must be a valid public JWK"))?;
    if public.algorithm().ok() != Some(SigningAlgorithm::Es256) {
        bail!("{description} must use ES256 P-256");
    }
    let kid = public
        .jkt()
        .with_context(|| format!("computing the {description} thumbprint"))?;
    if public.kid.as_deref() != Some(kid.as_str()) {
        bail!("{description} kid must equal its RFC 7638 thumbprint");
    }
    Ok((
        format!("public-keys/{kid}.jwk.json"),
        PublicKeySource { bytes },
    ))
}

fn normalize_supplied_public_keys(
    public_keys: BTreeMap<String, PathBuf>,
    settings_parent: &Path,
) -> Result<BTreeMap<String, PublicKeySource>> {
    let mut normalized = BTreeMap::new();
    for (name, source) in public_keys {
        let relative = if name.starts_with("public-keys/") {
            public_key_path(&name)?
        } else {
            public_key_path(&format!("public-keys/{name}"))?
        };
        let source = if source.is_absolute() {
            source
        } else {
            settings_parent.join(source)
        };
        let (actual_relative, source) =
            signing_public_key_reference(&source, "target settings public key")?;
        if actual_relative != relative {
            bail!("target settings public key name must match the JWK RFC 7638 thumbprint");
        }
        if normalized.insert(relative, source).is_some() {
            bail!("target settings name the same public key more than once");
        }
    }
    Ok(normalized)
}

fn public_key_path(value: &str) -> Result<String> {
    let name = value
        .strip_prefix("public-keys/")
        .ok_or_else(|| anyhow!("public signing key paths must live under public-keys/"))?;
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.len() > 160
        || Path::new(name)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("public signing key names must be plain file names under public-keys/");
    }
    Ok(format!("public-keys/{name}"))
}

fn collect_secret_references(value: &Value, references: &mut BTreeSet<String>) -> Result<()> {
    match value {
        Value::String(value) => {
            if let Some(reference) = value.strip_prefix(SECRET_PREFIX) {
                if !valid_secret_name(reference) {
                    bail!("target secret reference has invalid syntax");
                }
                references.insert(reference.to_owned());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_secret_references(value, references)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_secret_references(value, references)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn valid_secret_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn reject_existing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("target output already exists; choose a new directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspecting target output"),
    }
}

fn resolve_plain_file(path: &Path, description: &str) -> Result<PathBuf> {
    let parent = plain_parent(path, description)?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("{description} must name one file"))?;
    Ok(parent.join(name))
}

fn plain_parent(path: &Path, description: &str) -> Result<PathBuf> {
    if !matches!(path.components().next_back(), Some(Component::Normal(_))) {
        bail!("{description} must name one file or directory");
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata =
        fs::symlink_metadata(parent).with_context(|| format!("inspecting {description}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("{description} must be an existing plain directory");
    }
    fs::canonicalize(parent).with_context(|| format!("resolving {description}"))
}

fn read_plain_file(path: &Path, maximum: u64, description: &str) -> Result<Vec<u8>> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("opening {description}"))?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("{description} must be a bounded regular file");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("{description} exceeds its byte limit");
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::DirBuilder::new()
            .mode(0o755)
            .recursive(true)
            .create(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn publish(staging: tempfile::TempDir, destination: &Path) -> Result<()> {
    let staged = staging.keep();
    if let Err(error) = rename_noreplace(&staged, destination) {
        let _ = fs::remove_dir_all(&staged);
        return Err(error).context("publishing the target without replacement");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn rename_noreplace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace target publication is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ES256_PUBLIC_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
    const ES256_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;

    fn target_settings(signing: &str, public_keys: &str) -> String {
        format!(
            r#"formatVersion: 1
governance:
  version: 1
  assuranceProfile: local
  service:
    publicOrigin: http://127.0.0.1:8080
  issuer:
    id: urn:example:issuer
  authentication:
    kind: oidc-access-token
  audit:
    format: keyed-jsonl
  subjectBinding:
    secretRef: secret:file/subject-binding-hmac-key
  rateLimits:
    requestsPerPrincipalPerMinute: 60
  signing:
{signing}
  authorityProfiles:
    local:
      kind: explicit-request
runtime:
  version: 1
  bundleDirectory: /tmp/evidence/bundle
  listener:
    bindHost: 127.0.0.1
  secretProviders:
    file:
      root: /tmp/evidence/secrets
  signer:
    kind: transit
  auditStorage:
    path: /tmp/evidence/audit.jsonl
  outboundTls:
    systemRoots: true
{public_keys}"#
        )
    }

    #[test]
    fn signing_public_key_reference_names_active_key_by_thumbprint() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let key_path = temporary.path().join("signing-public.jwk.json");
        fs::write(&key_path, ES256_PUBLIC_JWK).expect("public key");

        let (relative, source) = signing_public_key_reference(&key_path, "signing public key")
            .expect("public key reference");
        assert_eq!(
            relative,
            "public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json"
        );
        assert_eq!(source.bytes, ES256_PUBLIC_JWK.as_bytes());

        let mut governance = serde_json::json!({
            "signing": {
                "publishedPublicJwkFiles": []
            }
        });
        set_or_validate_active_public_key(&mut governance, &relative).expect("active key set");
        assert_eq!(governance["signing"]["activePublicJwkFile"], relative);
        set_or_validate_active_public_key(&mut governance, &relative).expect("matching active key");

        governance["signing"]["activePublicJwkFile"] =
            serde_json::json!("public-keys/other.jwk.json");
        assert!(set_or_validate_active_public_key(&mut governance, &relative).is_err());
    }

    #[test]
    fn target_new_fills_active_public_key_from_signing_key_argument() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let key_path = temporary.path().join("signing-public.jwk.json");
        let settings_path = temporary.path().join("settings.yaml");
        let target = temporary.path().join("target");
        fs::write(&key_path, ES256_PUBLIC_JWK).expect("public key");
        fs::write(
            &settings_path,
            target_settings("    publishedPublicJwkFiles: []", ""),
        )
        .expect("settings");

        new(NewArgs {
            directory: target.clone(),
            settings: settings_path,
            signing_public_key: Some(key_path),
        })
        .expect("target created");

        let governance: Value = serde_norway::from_slice(
            &fs::read(target.join("governance.yaml")).expect("governance"),
        )
        .expect("governance parses");
        assert_eq!(
            governance["signing"]["activePublicJwkFile"],
            "public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json"
        );
        assert!(target
            .join("public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json")
            .is_file());
    }

    #[test]
    fn public_key_inputs_must_match_governance_references() {
        let governance = serde_json::json!({
            "signing": {
                "activePublicJwkFile": "public-keys/active.jwk.json",
                "publishedPublicJwkFiles": ["public-keys/old.jwk.json"]
            }
        });
        assert_eq!(
            expected_public_key_files(&governance).expect("expected keys"),
            ["public-keys/active.jwk.json", "public-keys/old.jwk.json"]
        );

        let mut supplied = BTreeMap::new();
        let settings = tempfile::tempdir().expect("settings directory");
        let active = settings.path().join("active.jwk.json");
        fs::write(&active, ES256_PUBLIC_JWK).expect("active key");
        supplied.insert(
            "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json".to_owned(),
            PathBuf::from("active.jwk.json"),
        );
        assert_eq!(
            normalize_supplied_public_keys(supplied, settings.path())
                .expect("normalized")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json"]
        );
    }

    #[test]
    fn target_new_rejects_private_jwk_in_public_keys_without_publishing() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let key_path = temporary.path().join("private.jwk");
        let settings_path = temporary.path().join("settings.yaml");
        let target = temporary.path().join("target");
        fs::write(&key_path, ES256_PRIVATE_JWK).expect("private key");
        fs::write(
            &settings_path,
            target_settings(
                "    activePublicJwkFile: public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json\n    publishedPublicJwkFiles: []",
                "publicKeys:\n  _QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json: private.jwk\n",
            ),
        )
        .expect("settings");

        assert!(new(NewArgs {
            directory: target.clone(),
            settings: settings_path,
            signing_public_key: None,
        })
        .is_err());
        assert!(
            !target.exists(),
            "failed target creation must be create-only"
        );
    }

    #[test]
    fn target_new_rejects_public_key_filename_that_does_not_match_thumbprint() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let key_path = temporary.path().join("active.jwk.json");
        let settings_path = temporary.path().join("settings.yaml");
        let target = temporary.path().join("target");
        fs::write(&key_path, ES256_PUBLIC_JWK).expect("public key");
        fs::write(
            &settings_path,
            target_settings(
                "    activePublicJwkFile: public-keys/mismatched.jwk.json\n    publishedPublicJwkFiles: []",
                "publicKeys:\n  mismatched.jwk.json: active.jwk.json\n",
            ),
        )
        .expect("settings");

        assert!(new(NewArgs {
            directory: target.clone(),
            settings: settings_path,
            signing_public_key: None,
        })
        .is_err());
        assert!(
            !target.exists(),
            "failed target creation must be create-only"
        );
    }

    #[test]
    fn target_new_rejects_placeholder_runtime_shape() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let key_path = temporary.path().join("active.jwk.json");
        let settings_path = temporary.path().join("settings.yaml");
        let target = temporary.path().join("target");
        fs::write(&key_path, ES256_PUBLIC_JWK).expect("public key");
        fs::write(
            &settings_path,
            r#"formatVersion: 1
governance:
  version: 1
  assuranceProfile: local
  service:
    publicOrigin: http://127.0.0.1:8080
  issuer:
    id: urn:example:issuer
  authentication:
    kind: oidc-access-token
  audit:
    format: keyed-jsonl
  subjectBinding:
    secretRef: secret:file/subject-binding-hmac-key
  rateLimits:
    requestsPerPrincipalPerMinute: 60
  signing:
    activePublicJwkFile: public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json
    publishedPublicJwkFiles: []
  authorityProfiles:
    local:
      kind: explicit-request
runtime:
  version: 1
publicKeys:
  _QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json: active.jwk.json
"#,
        )
        .expect("settings");

        assert!(new(NewArgs {
            directory: target.clone(),
            settings: settings_path,
            signing_public_key: None,
        })
        .is_err());
        assert!(
            !target.exists(),
            "failed target creation must be create-only"
        );
    }

    #[test]
    fn target_new_rejects_unknown_governance_field() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let settings_path = temporary.path().join("settings.yaml");
        let target = temporary.path().join("target");
        fs::write(
            &settings_path,
            r#"formatVersion: 1
governance:
  version: 1
  assuranceProfile: local
  service:
    publicOrigin: http://127.0.0.1:8080
  issuer:
    id: urn:example:issuer
  authentication:
    kind: oidc-access-token
  audit:
    format: keyed-jsonl
  subjectBinding:
    secretRef: secret:file/subject-binding-hmac-key
  rateLimits:
    requestsPerPrincipalPerMinute: 60
  signing:
    activePublicJwkFile: public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json
    publishedPublicJwkFiles: []
  authorityProfiles:
    local:
      kind: explicit-request
  unexpectedField: true
runtime:
  version: 1
"#,
        )
        .expect("settings");

        // The consumers (target explain, build --target, fixtures run --target)
        // deserialize governance.yaml through the same closed TargetGovernance
        // type, which denies unknown fields. `target new` must refuse this file
        // too instead of creating a target those commands then refuse to open.
        assert!(new(NewArgs {
            directory: target.clone(),
            settings: settings_path,
            signing_public_key: None,
        })
        .is_err());
        assert!(
            !target.exists(),
            "failed target creation must be create-only"
        );
    }
    #[test]
    fn target_new_rejects_unknown_runtime_field() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let key_path = temporary.path().join("active.jwk.json");
        let settings_path = temporary.path().join("settings.yaml");
        let target = temporary.path().join("target");
        fs::write(&key_path, ES256_PUBLIC_JWK).expect("public key");
        let settings = target_settings(
            "    activePublicJwkFile: public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json\n    publishedPublicJwkFiles: []",
            "publicKeys:\n  _QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json: active.jwk.json\n",
        )
        .replace(
            "  outboundTls:\n",
            "  unexpectedField: true\n  outboundTls:\n",
        );
        fs::write(&settings_path, settings).expect("settings");

        // The runtime denies unknown fields and names this key when it refuses
        // the document at startup. `target new` must refuse it here instead of
        // writing a runtime.yaml the deployment cannot load.
        let Err(error) = new(NewArgs {
            directory: target.clone(),
            settings: settings_path,
            signing_public_key: None,
        }) else {
            panic!("an unknown runtime field is refused");
        };
        let reported = format!("{error:#}");
        assert!(reported.contains("unexpectedField"), "{reported}");
        assert!(
            !target.exists(),
            "failed target creation must be create-only"
        );
    }
    /// The Evidence runtime owns the settings shape and this crate does not link
    /// it, so `TargetRuntime` is a restatement nothing but a test can hold in
    /// step: a key the runtime adds would be refused here, and a key it drops
    /// would still be accepted. The published runtime contract is the document
    /// the runtime loader answers to, so it is what the mirror is held against.
    #[test]
    fn the_closed_runtime_mirror_matches_the_published_runtime_contract() {
        let contract = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../products/evidence/contracts/runtime.schema.yaml"
        );
        let schema: Value = serde_norway::from_slice(
            &fs::read(contract).expect("the published runtime contract is readable"),
        )
        .expect("the published runtime contract parses");
        assert_eq!(
            schema["additionalProperties"],
            Value::Bool(false),
            "the published runtime contract must stay closed"
        );
        let published = schema["properties"]
            .as_object()
            .expect("the runtime contract publishes properties");
        let required: BTreeSet<&str> = schema["required"]
            .as_array()
            .expect("the runtime contract names its required properties")
            .iter()
            .map(|name| name.as_str().expect("each required property is a name"))
            .collect();

        let complete: serde_json::Map<String, Value> = published
            .keys()
            .map(|name| (name.clone(), sample_runtime_value(name)))
            .collect();
        serde_json::from_value::<TargetRuntime>(Value::Object(complete.clone()))
            .expect("the mirror accepts every key the contract publishes");

        for name in published.keys() {
            let mut document = complete.clone();
            document.remove(name);
            let accepted = serde_json::from_value::<TargetRuntime>(Value::Object(document)).is_ok();
            assert_eq!(
                accepted,
                !required.contains(name.as_str()),
                "`{name}` is required by the mirror exactly when the contract requires it"
            );
        }

        let mut unpublished = complete;
        unpublished.insert("unpublishedField".to_owned(), Value::Bool(true));
        assert!(
            serde_json::from_value::<TargetRuntime>(Value::Object(unpublished)).is_err(),
            "the mirror must refuse a key the contract does not publish"
        );
    }

    /// A value the mirror can deserialize for the contract property `name`. The
    /// mirror leaves the interior of each section to the runtime, so only
    /// `version` and `bundleDirectory` need a shape of their own.
    fn sample_runtime_value(name: &str) -> Value {
        match name {
            "version" => serde_json::json!(1),
            "bundleDirectory" => serde_json::json!("/tmp/evidence/bundle"),
            _ => serde_json::json!({}),
        }
    }

    #[test]
    fn target_new_rejects_assurance_profile_outside_enum() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let settings_path = temporary.path().join("settings.yaml");
        let target = temporary.path().join("target");
        fs::write(
            &settings_path,
            r#"formatVersion: 1
governance:
  version: 1
  assuranceProfile: enterprise
  service:
    publicOrigin: http://127.0.0.1:8080
  issuer:
    id: urn:example:issuer
  authentication:
    kind: oidc-access-token
  audit:
    format: keyed-jsonl
  subjectBinding:
    secretRef: secret:file/subject-binding-hmac-key
  rateLimits:
    requestsPerPrincipalPerMinute: 60
  signing:
    activePublicJwkFile: public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json
    publishedPublicJwkFiles: []
  authorityProfiles:
    local:
      kind: explicit-request
runtime:
  version: 1
"#,
        )
        .expect("settings");

        // "enterprise" is a nonempty string, which the previous hand-rolled
        // check accepted; only the closed TargetGovernance type restricts
        // assuranceProfile to local, production, or evidence-grade.
        assert!(new(NewArgs {
            directory: target.clone(),
            settings: settings_path,
            signing_public_key: None,
        })
        .is_err());
        assert!(
            !target.exists(),
            "failed target creation must be create-only"
        );
    }

    #[test]
    fn target_new_accepts_a_valid_settings_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let key_path = temporary.path().join("active.jwk.json");
        let settings_path = temporary.path().join("settings.yaml");
        let target = temporary.path().join("target");
        fs::write(&key_path, ES256_PUBLIC_JWK).expect("public key");
        fs::write(
            &settings_path,
            target_settings(
                "    activePublicJwkFile: public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json\n    publishedPublicJwkFiles: []",
                "publicKeys:\n  _QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json: active.jwk.json\n",
            ),
        )
        .expect("settings");

        new(NewArgs {
            directory: target.clone(),
            settings: settings_path,
            signing_public_key: None,
        })
        .expect("a settings file matching the closed governance shape is accepted");

        assert!(target.join("governance.yaml").is_file());
        assert!(target.join("runtime.yaml").is_file());
        let governance: Value = serde_norway::from_slice(
            &fs::read(target.join("governance.yaml")).expect("governance"),
        )
        .expect("governance parses");
        assert_eq!(governance["assuranceProfile"], "local");
    }

    #[test]
    fn public_key_paths_stay_inside_public_keys_directory() {
        for value in [
            "active.jwk.json",
            "public-keys/../active.jwk.json",
            "public-keys/nested/active.jwk.json",
            "secrets/active.jwk.json",
        ] {
            assert!(public_key_path(value).is_err(), "{value} must be refused");
        }
        assert!(public_key_path("public-keys/active.jwk.json").is_ok());
    }

    #[test]
    fn target_explanation_reports_only_logical_secret_references() {
        let mut references = BTreeSet::new();
        collect_secret_references(
            &serde_json::json!({
                "audit": "secret:file/audit-key",
                "nested": ["secret:file/source-token", "not-secret"]
            }),
            &mut references,
        )
        .expect("references");
        assert_eq!(
            references.into_iter().collect::<Vec<_>>(),
            ["audit-key", "source-token"]
        );
    }
}
