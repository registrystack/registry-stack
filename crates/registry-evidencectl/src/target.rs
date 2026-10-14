//! Create and inspect the single normalized Evidence target model.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use registry_evidence_authoring::{
    project::{self, EvidenceProject},
    target::{self, EvidenceTarget},
};
use serde_json::{json, Value};

use crate::{authored, OutputFormat};

const MAX_TARGET_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum TargetCommand {
    /// Create a normalized target and its complete authority file.
    New(NewArgs),
    /// Inspect one normalized target and its complete grants.
    Explain(ExplainArgs),
}

#[derive(Debug, Args)]
pub(crate) struct NewArgs {
    /// New target directory to create.
    pub directory: PathBuf,
    /// Existing normalized target.yaml to copy with its referenced authority and public key.
    #[arg(long, required_unless_present = "local")]
    pub settings: Option<PathBuf>,
    /// Evidence project directory; defaults to the current directory with --local.
    #[arg(long, requires = "local")]
    pub project: Option<PathBuf>,
    /// Generate a complete disposable local target from the EvidenceProject ceilings.
    #[arg(long)]
    pub local: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ExplainArgs {
    /// Normalized target.yaml, or a directory containing target.yaml.
    pub target: PathBuf,
    /// Evidence project directory.
    ///
    /// This command needs an editable project holding evidence.yaml.
    #[arg(value_name = "PROJECT", default_value = ".")]
    pub project: PathBuf,
    /// Emit one machine-readable JSON report.
    #[arg(long)]
    pub json: bool,
}

pub(crate) fn run(command: TargetCommand, format: OutputFormat) -> Result<ExitCode> {
    match command {
        TargetCommand::New(args) => new(args),
        TargetCommand::Explain(args) => explain(args, format),
    }
}

fn new(args: NewArgs) -> Result<ExitCode> {
    if args.local {
        if args.settings.is_some() {
            bail!("target new accepts either --local or --settings, not both");
        }
        let project = args.project.as_deref().unwrap_or_else(|| Path::new("."));
        create_local_target(project, &args.directory, json!({}))?;
    } else {
        let source = args
            .settings
            .as_deref()
            .context("target new requires --settings or --local")?;
        copy_explicit_target(source, &args.directory)?;
    }
    println!("Created Evidence target {}", args.directory.display());
    Ok(ExitCode::SUCCESS)
}

fn target_path(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join("target.yaml")
    } else {
        path.to_path_buf()
    }
}

fn read_target(path: &Path) -> Result<EvidenceTarget> {
    let path = target_path(path);
    let bytes = read_plain_file(&path, MAX_TARGET_BYTES, "Evidence target")?;
    Ok(target::read_target(&path.to_string_lossy(), &bytes)?.value)
}

fn read_project(root: &Path) -> Result<EvidenceProject> {
    let root = fs::canonicalize(root).context("resolving Evidence project")?;
    let path = root.join(project::PROJECT_FILE);
    let bytes = read_plain_file(&path, MAX_TARGET_BYTES, "Evidence project")?;
    Ok(project::read_project(&path.to_string_lossy(), &bytes)?.value)
}

fn copy_explicit_target(source: &Path, destination: &Path) -> Result<()> {
    reject_existing(destination)?;
    let source_path = target_path(source);
    let source_root = plain_parent(&source_path, "target parent")?;
    let target = read_target(&source_path)?;
    let authority = safe_relative(&source_root, &target.authority, "target authority")?;
    let key = target
        .signer
        .get("publicJwkFile")
        .and_then(Value::as_str)
        .context("target signer requires publicJwkFile")?;
    let public_key = safe_relative(&source_root, key, "target public key")?;

    let parent = created_plain_parent(destination, "target destination parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".evidencectl-target-")
        .tempdir_in(parent)?;
    copy_new(
        &source_path,
        &staging.path().join("target.yaml"),
        MAX_TARGET_BYTES,
    )?;
    copy_new(
        &authority,
        &staging.path().join(&target.authority),
        MAX_TARGET_BYTES,
    )?;
    copy_new(&public_key, &staging.path().join(key), MAX_TARGET_BYTES)?;
    publish(staging, destination)
}

/// Preflight a local Source connection without changing the target.
pub(crate) fn check_local_connection(directory: &Path, name: &str, binding: &Value) -> Result<()> {
    if !crate::authoring::valid_local_identifier(name) || !binding.is_object() {
        bail!("local source connection requires a valid name and a mapping");
    }
    if !directory.try_exists()? {
        return reject_existing(directory);
    }
    let name = name.parse()?;
    let target = read_target(directory)?;
    if let Some(existing) = target.connections.get(&name) {
        if existing != binding {
            bail!("local source connection already has different authored settings; review it or choose another connection name");
        }
    }
    Ok(())
}

/// Add one Source connection by atomically replacing target.yaml.
pub(crate) fn ensure_local_connection(
    project: &Path,
    directory: &Path,
    name: &str,
    binding: Value,
) -> Result<()> {
    check_local_connection(directory, name, &binding)?;
    if !directory.exists() {
        if directory
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("yaml")
        {
            bail!("local target file is absent; run `evidencectl init` or pass --target with an existing normalized EvidenceTarget");
        }
        return create_local_target(project, directory, json!({name: binding}));
    }
    let path = target_path(directory);
    let mut target = read_target(&path)?;
    let id = name.parse()?;
    if target.connections.contains_key(&id) {
        return Ok(());
    }
    target.connections.insert(id, binding);
    let bytes = render_target(&target)?;
    replace_plain_file(&path, bytes.as_bytes())
}

/// Create a local target with a complete grant for every AssertionDefinition.
/// An identical retry is harmless and a different existing target is refused.
pub(crate) fn create_local_target(
    project_root: &Path,
    directory: &Path,
    source_connections: Value,
) -> Result<()> {
    let connections = source_connections
        .as_object()
        .context("local source connections must be a mapping")?;
    let project_root =
        fs::canonicalize(project_root).context("resolving local Evidence project")?;
    let project = read_project(&project_root)?;
    let parent = if directory.exists() {
        let metadata = fs::symlink_metadata(directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("existing local target must be a plain directory");
        }
        None
    } else {
        reject_existing(directory)?;
        Some(created_plain_parent(
            directory,
            "target destination parent",
        )?)
    };
    let (public_key, _) = crate::authoring::ensure_local_signing_public_jwk(&project_root)?;
    let target_value = json!({
        "apiVersion": target::TARGET_API_VERSION,
        "kind": target::TARGET_KIND,
        "id": "local",
        "project": project.id,
        "package": {"root": ".generated/package"},
        "authority": "authority.yaml",
        "service": {
            "providerId": "urn:example:provider:local-evidence",
            "issuer": "urn:example:issuer:local-evidence",
            "publicOrigin": "http://127.0.0.1:8080",
            "trustDomain": "urn:example:trust:local-evidence"
        },
        "listener": {"bind": "127.0.0.1:8080", "trustProxyIdentityHeaders": false},
        "authentication": {"oidc": {
            "issuer": "http://127.0.0.1:8081",
            "audience": "urn:example:audience:local-evidence",
            "tokenTypes": ["at+jwt"], "algorithms": ["ES256"],
            "jwksSource": {"type": "uri", "uri": "http://127.0.0.1:8081/oauth2/jwks"},
            "principalClaim": "sub", "requesterTagsClaim": "evidence_tags",
            "evidenceAudienceClaim": "evidence_audience", "requiredScopes": ["evidence:request"],
            "maximumTokenLifetimeSeconds": 300
        }},
        "connections": connections,
        "secretProviders": {"file": {"root": ".generated/secrets"}},
        "signer": {"type": "local-jwk", "algorithm": "ES256", "privateKeyRef": "secret:file/signing-p256-private-jwk", "publicJwkFile": public_key},
        "subjectBinding": {"secretRef": "secret:file/subject-binding-hmac-key", "keyVersion": 1},
        "audit": {"path": ".generated/audit/evidence.jsonl", "hashKeyRef": "secret:file/audit-hmac-key", "hashKeyVersion": 1},
        "rateLimits": {"requestsPerPrincipalPerMinute": 60, "burstPerPrincipal": 16, "failedSelectorAttemptsPerPrincipalAuthorityPerMinute": 10},
        "assuranceProfile": "local",
        "outboundTls": {"systemRoots": true, "trustProfiles": {}}
    });
    let target = target::read_target(
        "target.yaml",
        authored::to_indented_yaml(&target_value)?.as_bytes(),
    )?
    .value;
    let authority_value = local_authority(&project, &target)?;
    let authority_yaml = authored::to_indented_yaml(&authority_value)?;
    target::read_authority("authority.yaml", authority_yaml.as_bytes(), &project)?;
    let target_yaml = render_target(&target)?;

    let expected = [
        ("target.yaml", target_yaml.as_bytes()),
        ("authority.yaml", authority_yaml.as_bytes()),
    ];
    let Some(parent) = parent else {
        for (name, bytes) in expected {
            if read_plain_file(
                &directory.join(name),
                MAX_TARGET_BYTES,
                "existing target file",
            )? != bytes
            {
                bail!("local target already contains different authored settings; choose a new target directory or review it explicitly");
            }
        }
        return Ok(());
    };
    let staging = tempfile::Builder::new()
        .prefix(".evidencectl-target-")
        .tempdir_in(parent)?;
    write_new_file(&staging.path().join("target.yaml"), target_yaml.as_bytes())?;
    write_new_file(
        &staging.path().join("authority.yaml"),
        authority_yaml.as_bytes(),
    )?;
    publish(staging, directory)
}

fn local_authority(project: &EvidenceProject, target: &EvidenceTarget) -> Result<Value> {
    let grants = project
        .assertion_definitions
        .iter()
        .map(|(id, definition)| {
            let authority = definition
                .grant_ceiling
                .authorities
                .first()
                .context("a local grant needs an authority ceiling")?;
            let actor = definition
                .grant_ceiling
                .actor_kinds
                .first()
                .context("a local grant needs an actor-kind ceiling")?;
            let origin = definition
                .grant_ceiling
                .value_origins
                .first()
                .context("a local grant needs a value-origin ceiling")?;
            let representation = definition
                .representations
                .first()
                .context("a local grant needs a representation")?;
            let subjects = definition
                .subjects
                .iter()
                .map(|subject| {
                    Ok(json!({
                        "role": subject.role,
                        "selectorProfile": subject.selectors.first().context("a local grant subject needs a selector profile")?,
                        "valueOrigin": origin
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((authority.to_owned(), actor.to_owned(), json!({
                "definition": id,
                "purpose": definition.purpose,
                "audienceFrom": "authenticated-requester",
                "representations": [representation],
                "subjectBinding": definition.subject_binding,
                "subjects": subjects
            })))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut profiles = serde_json::Map::new();
    for (index, (authority, actor_kind, grant)) in grants.into_iter().enumerate() {
        profiles.insert(
            format!("local-service-{}", index + 1),
            json!({"authority": authority, "actorKind": actor_kind, "requesterTags": ["local-service"], "grants": [grant]}),
        );
    }
    Ok(json!({
        "apiVersion": target::AUTHORITY_API_VERSION,
        "kind": target::AUTHORITY_KIND,
        "target": target.id,
        "project": project.id,
        "accessProfiles": profiles
    }))
}

fn explain(args: ExplainArgs, format: OutputFormat) -> Result<ExitCode> {
    let project = read_project(&args.project)?;
    let path = target_path(&args.target);
    let target = read_target(&path)?;
    if target.project != project.id {
        bail!("target must name this EvidenceProject");
    }
    let root = plain_parent(&path, "target parent")?;
    let authority_path = safe_relative(&root, &target.authority, "target authority")?;
    let authority_bytes = read_plain_file(&authority_path, MAX_TARGET_BYTES, "target authority")?;
    let authority = target::read_authority(
        &authority_path.to_string_lossy(),
        &authority_bytes,
        &project,
    )?
    .value;
    if authority.target != target.id {
        bail!("target authority must name this EvidenceTarget");
    }
    let compiled = target::compile_authority(&authority, &project).map_err(|findings| {
        authored::file_findings_report(&authority_path.to_string_lossy(), "authority", findings)
    })?;
    let report = json!({
        "target": target.id,
        "project": target.project,
        "authority": target.authority,
        "accessProfiles": compiled["accessProfiles"],
        "connections": target.connections.keys().collect::<Vec<_>>(),
        "offline": true,
        "secretResolution": false
    });
    if args.json || format == OutputFormat::Json {
        crate::report::print(&crate::report::success(
            "target explain",
            "complete",
            report,
        ))?;
    } else {
        println!("Target: {}", target.id);
        println!("Project: {}", target.project);
        println!("Authority: {}", target.authority);
        println!("Access profiles: {}", authority.access_profiles.len());
    }
    Ok(ExitCode::SUCCESS)
}

fn render_target(target: &EvidenceTarget) -> Result<String> {
    let mut value = serde_json::to_value(target)?;
    let object = value.as_object_mut().expect("EvidenceTarget is an object");
    object.insert("apiVersion".to_owned(), json!(target::TARGET_API_VERSION));
    object.insert("kind".to_owned(), json!(target::TARGET_KIND));
    authored::to_indented_yaml(&value)
}

fn safe_relative(root: &Path, relative: &str, label: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        bail!("{label} must be a plain target-relative path without traversal");
    }
    let mut candidate = root.to_path_buf();
    for part in path.components() {
        candidate.push(part);
        let metadata = fs::symlink_metadata(&candidate)
            .with_context(|| format!("inspecting {label} {}", candidate.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("{label} cannot traverse symbolic links");
        }
    }
    Ok(candidate)
}

fn plain_parent(path: &Path, label: &str) -> Result<PathBuf> {
    let parent = path.parent().context("path requires a parent directory")?;
    let parent = fs::canonicalize(parent).with_context(|| format!("resolving {label}"))?;
    if !fs::symlink_metadata(&parent)?.is_dir() {
        bail!("{label} must be a plain directory");
    }
    Ok(parent)
}

fn created_plain_parent(path: &Path, label: &str) -> Result<PathBuf> {
    let parent = path.parent().context("path requires a parent directory")?;
    let mut cursor = PathBuf::new();
    for component in parent.components() {
        cursor.push(component);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                bail!("{label} cannot traverse symbolic links or non-directories");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o755).create(&cursor)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    fs::canonicalize(parent).with_context(|| format!("resolving {label}"))
}

fn reject_existing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("target destination already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_plain_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspecting {label}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        bail!("{label} must be a bounded plain file");
    }
    fs::read(path).with_context(|| format!("reading {label}"))
}

fn copy_new(source: &Path, destination: &Path, maximum: u64) -> Result<()> {
    let bytes = read_plain_file(source, maximum, "target input")?;
    write_new_file(destination, &bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("creating {} without replacement", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn replace_plain_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("target.yaml must remain a plain file");
    }
    let parent = path.parent().context("target.yaml requires a parent")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.as_file().set_permissions(metadata.permissions())?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged.persist(path).context("publishing target.yaml")?;
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

    #[test]
    fn target_relative_paths_reject_traversal() {
        let root = tempfile::tempdir().unwrap();
        assert!(safe_relative(root.path(), "../authority.yaml", "authority").is_err());
        assert!(safe_relative(root.path(), "/authority.yaml", "authority").is_err());
    }

    #[test]
    fn existing_destinations_are_never_replaced() {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("target");
        fs::create_dir(&destination).unwrap();
        assert!(reject_existing(&destination).is_err());
    }

    #[test]
    fn connection_names_and_shapes_are_bounded_before_io() {
        let root = tempfile::tempdir().unwrap();
        assert!(check_local_connection(
            root.path().join("missing").as_path(),
            "../bad",
            &json!({})
        )
        .is_err());
        assert!(check_local_connection(
            root.path().join("missing").as_path(),
            "source",
            &json!(true)
        )
        .is_err());
    }

    #[test]
    fn rendered_targets_use_the_normalized_envelope() {
        let value = json!({
            "apiVersion": target::TARGET_API_VERSION, "kind": target::TARGET_KIND,
            "id":"local", "project":"project", "package":{}, "authority":"authority.yaml",
            "service":{}, "listener":{},
            "authentication":{"oidc":{"jwksSource":{"type":"uri","uri":"https://issuer.example.test/jwks"}}},
            "connections":{}, "secretProviders":{}, "signer":{}, "subjectBinding":{}, "audit":{}, "rateLimits":{}
        });
        let decoded = target::read_target(
            "target.yaml",
            authored::to_indented_yaml(&value).unwrap().as_bytes(),
        )
        .unwrap();
        let rendered = render_target(&decoded.value).unwrap();
        assert!(rendered.contains("kind: EvidenceTarget"));
        assert!(!rendered.contains("EvidenceTargetSettings"));
    }
}
