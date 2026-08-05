//! Immutable Evidence Version 1 deployment bundle loading.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonschema::{Draft, JSONSchema};
use rhai::{Engine, AST};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_norway::Value as YamlValue;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::config::{
    ArtifactPath, ConceptForm, EvidenceConfig, OrderedMap, RuntimeConfig, SchemaFault,
    SelectorField,
};

pub const MAX_BUNDLE_FILES: usize = 1_024;
pub const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024;
pub const MAX_SCRIPT_BYTES: u64 = 64 * 1024;
pub const MAX_PUBLIC_JWK_BYTES: u64 = 64 * 1024;

const CONFIG_FILE: &str = "evidence.yaml";
const RUNTIME_FILE: &str = "runtime.yaml";
const REVISION_DOMAIN: &[u8] = b"registry.evidence.bundle-revision/v1\0";
const RUNTIME_REVISION_DOMAIN: &[u8] = b"registry.evidence.runtime-revision/v1\0";
const MAX_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
const ALLOWED_DIRECTORIES: [&str; 6] = [
    "adapters",
    "derivations",
    "schemas",
    "codelists",
    "fixtures",
    "public-keys",
];

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum BundleError {
    #[error("the Evidence deployment bundle is unavailable")]
    Unavailable,
    #[error("an Evidence deployment input is not immutable: {0}")]
    NotImmutable(ArtifactFault),
    #[error("the Evidence deployment bundle contains an unsupported filesystem entry")]
    UnsupportedEntry,
    #[error("the Evidence deployment bundle contains a prohibited path")]
    InvalidPath,
    #[error("the Evidence deployment bundle artifact closure is invalid: {0}")]
    UnknownFile(ArtifactFault),
    #[error("the Evidence deployment bundle exceeds a Version 1 size bound")]
    TooLarge,
    #[error("the Evidence deployment configuration is invalid: {0}")]
    Config(ArtifactFault),
    #[error("an Evidence bundle artifact is invalid: {0}")]
    InvalidArtifact(ArtifactFault),
    #[error("an Evidence Rhai script is invalid: {0}")]
    InvalidScript(ArtifactFault),
}

impl BundleError {
    /// The value-free diagnostic, when this failure identifies one artifact.
    ///
    /// The remaining variants describe the deployment directory itself and are
    /// already specific enough to act on without naming a file.
    pub fn artifact_fault(&self) -> Option<&ArtifactFault> {
        match self {
            Self::Config(fault)
            | Self::InvalidArtifact(fault)
            | Self::InvalidScript(fault)
            | Self::NotImmutable(fault)
            | Self::UnknownFile(fault) => Some(fault),
            _ => None,
        }
    }

    /// Name the artifact being loaded when the failure did not already know it.
    ///
    /// Loaders raise their causes where the cause is known and the artifact is
    /// not, so the enclosing per-artifact loop binds the name on the way out.
    fn in_artifact(self, artifact: &str) -> Self {
        match self {
            Self::Config(fault) => Self::Config(fault.bind(artifact)),
            Self::InvalidArtifact(fault) => Self::InvalidArtifact(fault.bind(artifact)),
            Self::InvalidScript(fault) => Self::InvalidScript(fault.bind(artifact)),
            Self::NotImmutable(fault) => Self::NotImmutable(fault.bind(artifact)),
            other => other,
        }
    }
}

/// A value-free deployment diagnostic bound to one bundle-relative artifact.
///
/// The artifact name comes from the reviewed bundle layout or from the
/// operator's runtime file name. It is never taken from document content, and
/// the fault it carries is value-free by construction.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArtifactFault {
    artifact: String,
    fault: SchemaFault,
}

impl ArtifactFault {
    /// A diagnostic whose artifact is already known.
    pub fn new(artifact: impl Into<String>, fault: SchemaFault) -> Self {
        Self {
            artifact: artifact.into(),
            fault,
        }
    }

    /// A cause raised before the artifact being loaded is in scope.
    fn unbound(cause: &'static str) -> Self {
        Self {
            artifact: String::new(),
            fault: SchemaFault::because(cause),
        }
    }

    /// The bundle-relative artifact, empty when no loader claimed the failure.
    pub fn artifact(&self) -> &str {
        &self.artifact
    }

    pub fn fault(&self) -> &SchemaFault {
        &self.fault
    }

    fn bind(mut self, artifact: &str) -> Self {
        if self.artifact.is_empty() {
            self.artifact = artifact.to_owned();
        }
        self
    }
}

impl fmt::Display for ArtifactFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.artifact.is_empty() {
            return fmt::Display::fmt(&self.fault, formatter);
        }
        write!(formatter, "artifact {}: {}", self.artifact, self.fault)
    }
}

/// An artifact fault whose artifact the caller binds later.
fn invalid_artifact(cause: &'static str) -> BundleError {
    BundleError::InvalidArtifact(ArtifactFault::unbound(cause))
}

/// An immutability fault whose artifact the caller binds when it knows one.
fn not_immutable(cause: &'static str) -> BundleError {
    BundleError::NotImmutable(ArtifactFault::unbound(cause))
}

/// A script fault whose artifact the caller binds later.
fn invalid_script(cause: &'static str) -> BundleError {
    BundleError::InvalidScript(ArtifactFault::unbound(cause))
}

/// A closure fault naming the artifact when the name is safe to print.
///
/// Closure names come from the reviewed configuration or from the bundle
/// directory listing. A directory listing is operator input, so a name is
/// quoted only when it matches the reviewed artifact grammar; anything else is
/// reported without a name rather than echoed.
fn unknown_file(candidate: &str, cause: &'static str) -> BundleError {
    if safe_artifact_name(candidate) {
        BundleError::UnknownFile(ArtifactFault::new(candidate, SchemaFault::because(cause)))
    } else {
        BundleError::UnknownFile(ArtifactFault::unbound(cause))
    }
}

/// The reviewed bundle-relative artifact grammar, as a printable-name test.
fn safe_artifact_name(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 128
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

#[derive(Debug, Clone)]
pub struct CompiledScript {
    pub source: String,
    pub ast: AST,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Codelist {
    Codes {
        id: String,
        version: String,
        codes: Vec<String>,
    },
    Mapping {
        id: String,
        version: String,
        entries: BTreeMap<String, String>,
        allowed_outputs: Vec<String>,
    },
}

impl Codelist {
    pub fn id(&self) -> &str {
        match self {
            Self::Codes { id, .. } | Self::Mapping { id, .. } => id,
        }
    }

    pub fn version(&self) -> &str {
        match self {
            Self::Codes { version, .. } | Self::Mapping { version, .. } => version,
        }
    }

    pub fn contains_output(&self, value: &str) -> bool {
        match self {
            Self::Codes { codes, .. } => codes.iter().any(|code| code == value),
            Self::Mapping {
                allowed_outputs, ..
            } => allowed_outputs.iter().any(|code| code == value),
        }
    }
}

/// One fully captured, validated bundle revision.
///
/// Runtime consumers use these captured bytes and compiled artifacts. They do
/// not reopen the deployment directory, which prevents a later filesystem
/// change from partially replacing the revision used by a serving process.
#[derive(Debug, Clone)]
pub struct Bundle {
    root: PathBuf,
    pub config: EvidenceConfig,
    revision: String,
    files: BTreeMap<String, Vec<u8>>,
    pub scripts: BTreeMap<String, CompiledScript>,
    pub fact_schemas: BTreeMap<String, JsonValue>,
    pub codelists: BTreeMap<String, Codelist>,
    pub fixtures: BTreeMap<String, YamlValue>,
    pub retired_public_jwks: BTreeMap<String, JsonValue>,
}

/// One captured operator runtime configuration and its bound trust anchors.
///
/// Secret values and audit contents are deliberately not captured. The
/// runtime digest covers only the reviewed runtime YAML and private-CA bytes.
#[derive(Debug, Clone)]
pub struct RuntimeDocument {
    path: PathBuf,
    pub config: RuntimeConfig,
    revision: String,
    bytes: Vec<u8>,
    pub ca_bundles: BTreeMap<String, Vec<u8>>,
}

impl RuntimeDocument {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let path = path.as_ref();
        if path.file_name().and_then(|name| name.to_str()) != Some(RUNTIME_FILE) {
            return Err(BundleError::InvalidPath);
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::Unavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(BundleError::InvalidPath);
        }
        let filesystem_read_only = filesystem_is_read_only(path)?;
        let writable_runtime = "the runtime file is writable";
        validate_read_only(&metadata, filesystem_read_only, writable_runtime)
            .map_err(|error| error.in_artifact(RUNTIME_FILE))?;
        let bytes = read_stable_file(
            path,
            &metadata,
            crate::config::MAX_CONFIG_BYTES as u64,
            filesystem_read_only,
            writable_runtime,
        )
        .map_err(|error| error.in_artifact(RUNTIME_FILE))?;
        let config = RuntimeConfig::parse_yaml(&bytes).map_err(|error| {
            BundleError::Config(ArtifactFault::new(RUNTIME_FILE, error.fault()))
        })?;
        validate_secret_root(Path::new(&config.secret_providers.file.root))?;

        let mut ca_bundles = BTreeMap::new();
        for (profile, binding) in config.outbound_tls.trust_profiles.iter() {
            let ca_path = Path::new(&binding.ca_bundle_file);
            let ca_metadata =
                fs::symlink_metadata(ca_path).map_err(|_| BundleError::Unavailable)?;
            if ca_metadata.file_type().is_symlink() || !ca_metadata.is_file() {
                return Err(BundleError::InvalidPath);
            }
            let ca_filesystem_read_only = filesystem_is_read_only(ca_path)?;
            let writable_ca = "the TLS CA bundle the runtime file names is writable";
            validate_read_only(&ca_metadata, ca_filesystem_read_only, writable_ca)?;
            let ca_bytes = read_stable_file(
                ca_path,
                &ca_metadata,
                MAX_CA_BUNDLE_BYTES,
                ca_filesystem_read_only,
                writable_ca,
            )?;
            validate_ca_bundle(&ca_bytes).map_err(|error| error.in_artifact(RUNTIME_FILE))?;
            ca_bundles.insert(profile.to_owned(), ca_bytes);
        }
        let revision = compute_runtime_revision(&bytes, &ca_bundles)?;
        Ok(Self {
            path: path.to_path_buf(),
            config,
            revision,
            bytes,
            ca_bundles,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The two independently captured, closed startup inputs.
#[derive(Debug, Clone)]
pub struct DeploymentInputs {
    pub bundle: Bundle,
    pub runtime: RuntimeDocument,
}

impl DeploymentInputs {
    pub fn load(runtime_path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let runtime = RuntimeDocument::load(runtime_path)?;
        let bundle = Bundle::load(&runtime.config.bundle_directory)?;
        validate_runtime_bindings(&bundle.config, &runtime.config)?;
        Ok(Self { bundle, runtime })
    }
}

pub type EvidenceBundle = Bundle;

impl Bundle {
    pub fn load(root: impl AsRef<Path>) -> Result<Self, BundleError> {
        let root = root.as_ref();
        let files = capture_bundle_files(root)?;
        let config_bytes = files.get(CONFIG_FILE).ok_or(BundleError::Unavailable)?;
        let config = EvidenceConfig::parse_yaml(config_bytes)
            .map_err(|error| BundleError::Config(ArtifactFault::new(CONFIG_FILE, error.fault())))?;
        validate_file_closure(&config, &files)?;

        let scripts = load_scripts(&config, &files)?;
        let fact_schemas = load_fact_schemas(&config, &files)?;
        let codelists = load_codelists(&config, &files)?;
        validate_codelist_references(&config, &codelists)?;
        let fixtures = load_fixtures(&config, &files)?;
        let retired_public_jwks = load_retired_public_jwks(&config, &files)?;
        let revision = compute_revision(&files)?;

        Ok(Self {
            root: root.to_path_buf(),
            config,
            revision,
            files,
            scripts,
            fact_schemas,
            codelists,
            fixtures,
            retired_public_jwks,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn configuration_revision(&self) -> &str {
        &self.revision
    }

    pub fn revision(&self) -> &str {
        self.configuration_revision()
    }

    pub fn artifact(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    pub fn script(&self, path: &ArtifactPath) -> Option<&CompiledScript> {
        self.scripts.get(path.as_str())
    }

    pub fn fact_schema(&self, path: &ArtifactPath) -> Option<&JsonValue> {
        self.fact_schemas.get(path.as_str())
    }

    pub fn codelist(&self, path: &ArtifactPath) -> Option<&Codelist> {
        self.codelists.get(path.as_str())
    }

    pub fn fixture(&self, path: &ArtifactPath) -> Option<&YamlValue> {
        self.fixtures.get(path.as_str())
    }
}

pub fn load_bundle(root: impl AsRef<Path>) -> Result<Bundle, BundleError> {
    Bundle::load(root)
}

fn capture_bundle_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, BundleError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| BundleError::Unavailable)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(BundleError::InvalidPath);
    }
    let filesystem_read_only = filesystem_is_read_only(root)?;
    validate_read_only(
        &root_metadata,
        filesystem_read_only,
        "the bundle directory is writable",
    )?;
    let canonical_root = fs::canonicalize(root).map_err(|_| BundleError::Unavailable)?;
    let mut paths = Vec::new();
    collect_paths(
        root,
        root,
        &canonical_root,
        filesystem_read_only,
        &mut paths,
    )?;
    paths.sort_by(|left, right| left.0.cmp(&right.0));
    if paths.len() > MAX_BUNDLE_FILES {
        return Err(BundleError::TooLarge);
    }

    let mut files = BTreeMap::new();
    let mut total = 0_u64;
    for (relative, path, scanned_metadata) in paths {
        let cap = file_size_cap(&relative);
        let bytes = read_stable_file(
            &path,
            &scanned_metadata,
            cap,
            filesystem_read_only,
            "the bundle artifact is writable",
        )
        .map_err(|error| error.in_artifact(&relative))?;
        total = total
            .checked_add(u64::try_from(bytes.len()).map_err(|_| BundleError::TooLarge)?)
            .ok_or(BundleError::TooLarge)?;
        if total > MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge);
        }
        files.insert(relative, bytes);
    }
    if !files.contains_key(CONFIG_FILE) {
        return Err(BundleError::Unavailable);
    }
    Ok(files)
}

fn collect_paths(
    root: &Path,
    directory: &Path,
    canonical_root: &Path,
    filesystem_read_only: bool,
    files: &mut Vec<(String, PathBuf, Metadata)>,
) -> Result<(), BundleError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| BundleError::Unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BundleError::Unavailable)?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| BundleError::Unavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(BundleError::InvalidPath);
        }
        let relative_path = path
            .strip_prefix(root)
            .map_err(|_| BundleError::InvalidPath)?;
        let relative = path_to_bundle_string(relative_path)?;
        // Named after the relative path is known, so a writable artifact says
        // which one it is. A path the bundle grammar refuses is refused as a
        // path first; both fail closed, and neither reaches the caller unread.
        validate_read_only(
            &metadata,
            filesystem_read_only,
            if metadata.is_dir() {
                "the bundle directory is writable"
            } else {
                "the bundle artifact is writable"
            },
        )
        .map_err(|error| error.in_artifact(&relative))?;
        let top = relative.split('/').next().ok_or(BundleError::InvalidPath)?;
        if directory == root {
            if metadata.is_dir() {
                if !ALLOWED_DIRECTORIES.contains(&top) {
                    return Err(BundleError::InvalidPath);
                }
            } else if relative != CONFIG_FILE {
                return Err(unknown_file(
                    &relative,
                    "bundle root contains a file other than the configuration",
                ));
            }
        } else if !ALLOWED_DIRECTORIES.contains(&top) {
            return Err(BundleError::InvalidPath);
        }

        let canonical = fs::canonicalize(&path).map_err(|_| BundleError::Unavailable)?;
        if !canonical.starts_with(canonical_root) {
            return Err(BundleError::InvalidPath);
        }
        if metadata.is_dir() {
            collect_paths(root, &path, canonical_root, filesystem_read_only, files)?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.nlink() != 1 {
                    return Err(BundleError::InvalidPath);
                }
            }
            files.push((relative, path, metadata));
        } else {
            return Err(BundleError::UnsupportedEntry);
        }
    }
    Ok(())
}

fn path_to_bundle_string(path: &Path) -> Result<String, BundleError> {
    let value = path.to_str().ok_or(BundleError::InvalidPath)?;
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(BundleError::InvalidPath);
    }
    Ok(value.to_owned())
}

/// Refuse a writable deployment input, naming which input it was.
///
/// Every caller passes its own cause because the classes are not
/// interchangeable to whoever has to fix one: a writable bundle artifact is
/// re-frozen with the documented `chmod`, while a writable runtime file or CA
/// bundle sits outside the bundle entirely and re-freezing changes nothing.
#[cfg(unix)]
fn validate_read_only(
    metadata: &Metadata,
    filesystem_read_only: bool,
    cause: &'static str,
) -> Result<(), BundleError> {
    use std::os::unix::fs::PermissionsExt as _;
    if !filesystem_read_only && metadata.permissions().mode() & 0o222 != 0 {
        Err(not_immutable(cause))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn validate_read_only(
    metadata: &Metadata,
    filesystem_read_only: bool,
    cause: &'static str,
) -> Result<(), BundleError> {
    if filesystem_read_only || metadata.permissions().readonly() {
        Ok(())
    } else {
        Err(not_immutable(cause))
    }
}

#[cfg(unix)]
fn filesystem_is_read_only(path: &Path) -> Result<bool, BundleError> {
    let status = rustix::fs::statvfs(path).map_err(|_| BundleError::Unavailable)?;
    Ok(status
        .f_flag
        .contains(rustix::fs::StatVfsMountFlags::RDONLY))
}

#[cfg(not(unix))]
fn filesystem_is_read_only(_path: &Path) -> Result<bool, BundleError> {
    Ok(false)
}

fn file_size_cap(path: &str) -> u64 {
    if path.starts_with("adapters/") || path.starts_with("derivations/") {
        MAX_SCRIPT_BYTES
    } else if path.starts_with("public-keys/") {
        MAX_PUBLIC_JWK_BYTES
    } else {
        MAX_ARTIFACT_BYTES
    }
}

fn read_stable_file(
    path: &Path,
    scanned: &Metadata,
    cap: u64,
    filesystem_read_only: bool,
    writable_cause: &'static str,
) -> Result<Vec<u8>, BundleError> {
    if scanned.len() > cap {
        return Err(BundleError::TooLarge);
    }
    let mut file = open_no_follow(path)?;
    let opened = file.metadata().map_err(|_| BundleError::Unavailable)?;
    validate_read_only(&opened, filesystem_read_only, writable_cause)?;
    if !opened.is_file() || !same_file(scanned, &opened) || opened.len() > cap {
        return Err(not_immutable(
            "the file was replaced between the directory scan and opening it",
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BundleError::Unavailable)?;
    if u64::try_from(bytes.len()).map_err(|_| BundleError::TooLarge)? > cap {
        return Err(BundleError::TooLarge);
    }
    let after = file.metadata().map_err(|_| BundleError::Unavailable)?;
    if !same_file(&opened, &after)
        || after.len() != u64::try_from(bytes.len()).map_err(|_| BundleError::TooLarge)?
    {
        return Err(not_immutable("the file changed while it was being read"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, BundleError> {
    use rustix::fs::{Mode, OFlags};
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| BundleError::Unavailable)?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File, BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::Unavailable)?;
    if metadata.file_type().is_symlink() {
        return Err(BundleError::InvalidPath);
    }
    File::open(path).map_err(|_| BundleError::Unavailable)
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.permissions().mode() == right.permissions().mode()
}

#[cfg(not(unix))]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len()
        && left.permissions().readonly() == right.permissions().readonly()
        && left.modified().ok() == right.modified().ok()
}

fn validate_file_closure(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), BundleError> {
    let mut expected = BTreeSet::from([CONFIG_FILE.to_owned()]);
    for (_, source) in config.sources.iter() {
        expected.insert(source.request.prepare_script.as_str().to_owned());
        expected.insert(source.extract_script.as_str().to_owned());
        expected.insert(source.request.adapter_parameters_schema.as_str().to_owned());
        expected.insert(source.response_schema.as_str().to_owned());
        expected.insert(source.fact_schema.as_str().to_owned());
    }
    for requirement in &config.requirements {
        expected.insert(requirement.derivation.script.as_str().to_owned());
        if let Some(fixtures) = &requirement.fixtures {
            expected.insert(fixtures.as_str().to_owned());
        }
        for concept in &requirement.concepts {
            if matches!(
                concept.form,
                ConceptForm::ControlledCode
                    | ConceptForm::ControlledCategory
                    | ConceptForm::ControlledCodeList
            ) {
                expected.insert(concept_codelist_path(&concept.constraints)?.to_owned());
            }
        }
    }
    for (_, profile) in config.selector_profiles.iter() {
        for (_, field) in profile.fields.iter() {
            if let SelectorField::ControlledCode { codelist, .. } = field {
                expected.insert(codelist.as_str().to_owned());
            }
        }
    }
    for path in &config.signing.retired_public_jwk_files {
        expected.insert(path.as_str().to_owned());
    }
    expected.extend(reviewed_schema_paths(config, files)?);
    expected.extend(reviewed_bucket_codelist_paths(config, files)?);
    let present: BTreeSet<&str> = files.keys().map(String::as_str).collect();
    let referenced: BTreeSet<&str> = expected.iter().map(String::as_str).collect();
    if let Some(missing) = referenced.difference(&present).next() {
        return Err(unknown_file(
            missing,
            "the configuration references an artifact the bundle does not contain",
        ));
    }
    if let Some(unreferenced) = present.difference(&referenced).next() {
        return Err(unknown_file(
            unreferenced,
            "the bundle contains an artifact the configuration does not reference",
        ));
    }
    Ok(())
}

fn reviewed_bucket_codelist_paths(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeSet<String>, BundleError> {
    let declarations = config
        .requirements
        .iter()
        .flat_map(|requirement| &requirement.concepts)
        .filter(|concept| {
            matches!(
                concept.form,
                ConceptForm::DateBucket | ConceptForm::TimeBucket
            )
        })
        .map(|concept| {
            Ok((
                concept_constraint_string(&concept.constraints, "bucketScheme")?,
                concept_constraint_string(&concept.constraints, "schemeVersion")?,
            ))
        })
        .collect::<Result<BTreeSet<_>, BundleError>>()?;
    let mut paths = BTreeSet::new();
    for (identifier, version) in declarations {
        let matches = files
            .iter()
            .filter(|(path, _)| path.starts_with("codelists/"))
            .filter_map(|(path, bytes)| {
                let document = std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|text| serde_norway::from_str::<YamlValue>(text).ok())?;
                let mapping = document.as_mapping()?;
                (mapping.get("id").and_then(YamlValue::as_str) == Some(identifier)
                    && mapping.get("version").and_then(YamlValue::as_str) == Some(version))
                .then(|| path.clone())
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(invalid_artifact(
                "bucket scheme codelist is missing or ambiguous",
            ));
        }
        paths.insert(matches[0].clone());
    }
    Ok(paths)
}

fn reviewed_schema_paths(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeSet<String>, BundleError> {
    let identifiers = config
        .requirements
        .iter()
        .flat_map(|requirement| &requirement.concepts)
        .filter(|concept| concept.form == ConceptForm::ReviewedStructuredValue)
        .map(|concept| concept_constraint_string(&concept.constraints, "schema"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut paths = BTreeSet::new();
    for identifier in identifiers {
        let matches = files
            .iter()
            .filter(|(path, _)| path.starts_with("schemas/"))
            .filter_map(|(path, bytes)| {
                let document = std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|text| serde_norway::from_str::<JsonValue>(text).ok())?;
                (document.get("$id").and_then(JsonValue::as_str) == Some(identifier))
                    .then(|| path.clone())
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(invalid_artifact(
                "reviewed structured schema identifier is missing or ambiguous",
            ));
        }
        paths.insert(matches[0].clone());
    }
    Ok(paths)
}

fn load_scripts(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, CompiledScript>, BundleError> {
    let mut expected = BTreeMap::new();
    for (_, source) in config.sources.iter() {
        insert_script_contract(
            &mut expected,
            source.request.prepare_script.as_str(),
            ("prepare", 2),
        )?;
        insert_script_contract(
            &mut expected,
            source.extract_script.as_str(),
            ("extract", 2),
        )?;
    }
    for requirement in &config.requirements {
        insert_script_contract(
            &mut expected,
            requirement.derivation.script.as_str(),
            ("derive", 3),
        )?;
    }
    let mut scripts = BTreeMap::new();
    for (path, (entrypoint, arity)) in expected {
        let script = compile_script(path, entrypoint, arity, files)
            .map_err(|error| error.in_artifact(path))?;
        scripts.insert(path.to_owned(), script);
    }
    Ok(scripts)
}

fn compile_script(
    path: &str,
    entrypoint: &'static str,
    arity: usize,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<CompiledScript, BundleError> {
    let bytes = files.get(path).ok_or(invalid_artifact("missing script"))?;
    let source = std::str::from_utf8(bytes)
        .map_err(|_| invalid_artifact("script is not UTF-8"))?
        .to_owned();
    reject_prohibited_script_capabilities(&source)?;
    let mut engine = Engine::new();
    engine.set_max_expr_depths(64, 64);
    engine.set_max_call_levels(32);
    engine.set_max_operations(100_000);
    engine.set_max_array_size(256);
    engine.set_max_map_size(256);
    engine.set_max_string_size(16_384);
    engine.set_max_modules(0);
    let ast = engine
        .compile(&source)
        .map_err(|_| invalid_script("script does not compile"))?;
    let entrypoint_functions = ast
        .iter_functions()
        .filter(|function| function.name == entrypoint)
        .map(|function| function.params.len())
        .collect::<Vec<_>>();
    if entrypoint_functions != [arity] {
        return Err(invalid_script(
            "script does not declare exactly one entrypoint with the required arity",
        ));
    }
    Ok(CompiledScript { source, ast })
}

fn insert_script_contract<'a>(
    scripts: &mut BTreeMap<&'a str, (&'static str, usize)>,
    path: &'a str,
    contract: (&'static str, usize),
) -> Result<(), BundleError> {
    if scripts
        .insert(path, contract)
        .is_some_and(|existing| existing != contract)
    {
        return Err(invalid_artifact(
            "one script path is assigned incompatible entry points",
        ));
    }
    Ok(())
}

fn reject_prohibited_script_capabilities(source: &str) -> Result<(), BundleError> {
    const PROHIBITED: [&str; 14] = [
        "import",
        "eval",
        "print",
        "debug",
        "get_env",
        "environment",
        "filesystem",
        "network",
        "process",
        "random",
        "Fn",
        "call",
        "curry",
        "is_def_fn",
    ];
    let mut identifier = String::new();
    let mut chars = source.chars().peekable();
    let mut quote = None;
    while let Some(character) = chars.next() {
        if let Some(delimiter) = quote {
            if character == '\\' {
                chars.next();
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
            continue;
        }
        if character == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
            continue;
        }
        if character.is_ascii_alphanumeric() || character == '_' {
            identifier.push(character);
        } else if !identifier.is_empty() {
            if PROHIBITED.contains(&identifier.as_str()) {
                return Err(invalid_script("script uses a prohibited capability"));
            }
            identifier.clear();
        }
    }
    if PROHIBITED.contains(&identifier.as_str()) {
        return Err(invalid_script("script uses a prohibited capability"));
    }
    Ok(())
}

/// Which contract one bundle schema artifact carries. Configuration keeps the
/// three roles disjoint, so every path resolves to exactly one of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaRole {
    /// Closed startup parameters; the empty parameter set is legitimate.
    AdapterParameters,
    /// Shape of one projected source response. Projection drops a missing
    /// selected leaf, so a declared property may legitimately be absent.
    Response,
    /// Closed fact set handed to derivation, and the reviewed concept schemas held
    /// to the same rule; every declared property is required.
    Facts,
}

fn load_fact_schemas(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, JsonValue>, BundleError> {
    let parameter_paths = config
        .sources
        .iter()
        .map(|(_, source)| source.request.adapter_parameters_schema.as_str())
        .collect::<BTreeSet<_>>();
    let response_paths = config
        .sources
        .iter()
        .map(|(_, source)| source.response_schema.as_str())
        .collect::<BTreeSet<_>>();
    let mut paths = config
        .sources
        .iter()
        .flat_map(|(_, source)| {
            [
                source.fact_schema.as_str(),
                source.response_schema.as_str(),
                source.request.adapter_parameters_schema.as_str(),
            ]
        })
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    paths.extend(reviewed_schema_paths(config, files)?);
    let mut schemas = BTreeMap::new();
    for path in paths {
        let role = if parameter_paths.contains(path.as_str()) {
            SchemaRole::AdapterParameters
        } else if response_paths.contains(path.as_str()) {
            SchemaRole::Response
        } else {
            SchemaRole::Facts
        };
        let schema =
            load_fact_schema(&path, role, files).map_err(|error| error.in_artifact(&path))?;
        schemas.insert(path, schema);
    }
    for (_, source) in config.sources.iter() {
        let schema_path = source.request.adapter_parameters_schema.as_str();
        validate_adapter_parameters(source, &schemas)
            .map_err(|error| error.in_artifact(schema_path))?;
    }
    Ok(schemas)
}

fn load_fact_schema(
    path: &str,
    role: SchemaRole,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<JsonValue, BundleError> {
    let bytes = files
        .get(path)
        .ok_or(invalid_artifact("missing fact schema"))?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid_artifact("fact schema is not UTF-8"))?;
    let schema: JsonValue = serde_norway::from_str(text)
        .map_err(|_| invalid_artifact("fact schema YAML is invalid"))?;
    validate_closed_schema(&schema, role)?;
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .map_err(|_| invalid_artifact("fact schema is not valid JSON Schema"))?;
    Ok(schema)
}

fn validate_adapter_parameters(
    source: &crate::config::SourceConfig,
    schemas: &BTreeMap<String, JsonValue>,
) -> Result<(), BundleError> {
    let schema = schemas
        .get(source.request.adapter_parameters_schema.as_str())
        .ok_or(invalid_artifact("missing adapter-parameter schema"))?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(schema)
        .map_err(|_| invalid_artifact("adapter-parameter schema is not valid JSON Schema"))?;
    let parameters = serde_json::to_value(&source.request.adapter_parameters)
        .map_err(|_| invalid_artifact("adapter parameters are not JSON-compatible"))?;
    if !compiled.is_valid(&parameters) {
        return Err(invalid_artifact(
            "adapter parameters do not satisfy their closed schema",
        ));
    }
    Ok(())
}

fn validate_closed_schema(schema: &JsonValue, role: SchemaRole) -> Result<(), BundleError> {
    let allow_empty_root = role == SchemaRole::AdapterParameters;
    let root = schema
        .as_object()
        .ok_or(invalid_artifact("fact schema must be an object"))?;
    if root.get("type").and_then(JsonValue::as_str) != Some("object")
        || root
            .get("additionalProperties")
            .and_then(JsonValue::as_bool)
            != Some(false)
    {
        return Err(invalid_artifact("fact schema must close the root object"));
    }
    let properties = root
        .get("properties")
        .and_then(JsonValue::as_object)
        .ok_or(invalid_artifact("fact schema must declare properties"))?;
    if (!allow_empty_root && properties.is_empty()) || properties.len() > 64 {
        return Err(invalid_artifact("fact schema property count is invalid"));
    }
    let required = root
        .get("required")
        .and_then(JsonValue::as_array)
        .ok_or(invalid_artifact("fact schema must declare required fields"))?;
    let required = required
        .iter()
        .map(JsonValue::as_str)
        .collect::<Option<BTreeSet<_>>>()
        .ok_or(invalid_artifact("fact schema required fields are invalid"))?;
    if required
        .iter()
        .any(|field| !properties.contains_key(*field))
        || (role != SchemaRole::Response
            && properties
                .keys()
                .any(|property| !required.contains(property.as_str())))
    {
        return Err(invalid_artifact(
            "fact schema must require its exact closed field set",
        ));
    }
    validate_schema_node(schema, role)
}

/// Reads the one type a schema node declares, and returns `None` for a node that
/// declares a bounded const instead.
///
/// A response schema may write that type as the pair `[T, "null"]`. Sources do
/// report an explicit null where they hold no value, and the projection carries
/// that null through verbatim, so a response shape has to be able to say so. The
/// pair is the only union the subset admits, and only in the response role: a
/// fact or an adapter parameter is never null. `null` reaches the script as the
/// same unit marker `is_missing` already reads, so one script test covers both an
/// absent leaf and an explicitly null one.
fn schema_node_type(
    object: &JsonMap<String, JsonValue>,
    role: SchemaRole,
) -> Result<Option<&str>, BundleError> {
    match object.get("type") {
        Some(JsonValue::String(name)) => Ok(Some(name.as_str())),
        Some(JsonValue::Array(members)) => {
            let [JsonValue::String(name), JsonValue::String(null_member)] = members.as_slice()
            else {
                return Err(invalid_artifact(
                    "schema node type is outside the closed Version 1 subset",
                ));
            };
            if role != SchemaRole::Response || null_member != "null" || name == "null" {
                return Err(invalid_artifact(
                    "schema node type is outside the closed Version 1 subset",
                ));
            }
            Ok(Some(name.as_str()))
        }
        Some(_) => Err(invalid_artifact(
            "schema node type is outside the closed Version 1 subset",
        )),
        None => Ok(None),
    }
}

fn validate_schema_node(node: &JsonValue, role: SchemaRole) -> Result<(), BundleError> {
    let object = node
        .as_object()
        .ok_or(invalid_artifact("every schema node must be a typed object"))?;
    let Some(value_type) = schema_node_type(object, role)? else {
        if object
            .keys()
            .all(|key| matches!(key.as_str(), "$schema" | "$id" | "const"))
            && object.get("const").is_some_and(schema_const_is_bounded)
        {
            return Ok(());
        }
        return Err(invalid_artifact(
            "every schema node must declare one type or one bounded const",
        ));
    };
    let allowed = match value_type {
        "object" => &[
            "$schema",
            "$id",
            "type",
            "additionalProperties",
            "required",
            "properties",
        ][..],
        "array" => &[
            "$schema",
            "$id",
            "type",
            "minItems",
            "maxItems",
            "uniqueItems",
            "items",
            "const",
        ][..],
        "string" => &[
            "$schema",
            "$id",
            "type",
            "minLength",
            "maxLength",
            "format",
            "enum",
            "const",
        ][..],
        "integer" => &[
            "$schema", "$id", "type", "minimum", "maximum", "enum", "const",
        ][..],
        "boolean" => &["$schema", "$id", "type", "enum", "const"][..],
        _ => {
            return Err(invalid_artifact(
                "schema node type is outside the closed Version 1 subset",
            ));
        }
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid_artifact(
            "schema node uses a keyword outside the closed Version 1 subset",
        ));
    }

    match value_type {
        "object" => {
            if object
                .get("additionalProperties")
                .and_then(JsonValue::as_bool)
                != Some(false)
            {
                return Err(invalid_artifact("nested schema objects must be closed"));
            }
            let properties = object
                .get("properties")
                .and_then(JsonValue::as_object)
                .filter(|properties| !properties.is_empty() && properties.len() <= 64)
                .ok_or(invalid_artifact(
                    "schema objects must declare bounded properties",
                ))?;
            let required = object
                .get("required")
                .and_then(JsonValue::as_array)
                .and_then(|required| {
                    required
                        .iter()
                        .map(JsonValue::as_str)
                        .collect::<Option<BTreeSet<_>>>()
                })
                .ok_or(invalid_artifact(
                    "schema objects must declare required properties",
                ))?;
            if required
                .iter()
                .any(|field| !properties.contains_key(*field))
                || (role != SchemaRole::Response
                    && properties
                        .keys()
                        .any(|property| !required.contains(property.as_str())))
            {
                return Err(invalid_artifact(
                    "schema objects must require their exact property set",
                ));
            }
            for property in properties.values() {
                validate_schema_node(property, role)?;
            }
        }
        "array" => {
            if object
                .get("uniqueItems")
                .is_some_and(|value| value.as_bool() != Some(true))
            {
                return Err(invalid_artifact("schema array uniqueness flag is invalid"));
            }
            if let Some(value) = object.get("const") {
                if !value.is_array() || !schema_const_is_bounded(value) {
                    return Err(invalid_artifact("schema array const is invalid"));
                }
            }
            let maximum = object
                .get("maxItems")
                .and_then(JsonValue::as_u64)
                .ok_or(invalid_artifact("schema arrays must be bounded"))?;
            if maximum == 0 || maximum > 256 {
                return Err(invalid_artifact("schema array bound is invalid"));
            }
            if object
                .get("minItems")
                .and_then(JsonValue::as_u64)
                .is_some_and(|minimum| minimum > maximum)
            {
                return Err(invalid_artifact("schema array bounds are invalid"));
            }
            validate_schema_node(
                object
                    .get("items")
                    .ok_or(invalid_artifact("schema arrays must close their item type"))?,
                role,
            )?;
        }
        "string" => {
            if object
                .get("format")
                .and_then(JsonValue::as_str)
                .is_some_and(|format| !matches!(format, "date" | "date-time"))
            {
                return Err(invalid_artifact(
                    "schema string format is outside the closed Version 1 subset",
                ));
            }
            let bounded = object
                .get("maxLength")
                .and_then(JsonValue::as_u64)
                .is_some_and(|maximum| maximum > 0 && maximum <= 65_536);
            let formatted = matches!(
                object.get("format").and_then(JsonValue::as_str),
                Some("date" | "date-time")
            );
            let enumerated = object
                .get("enum")
                .and_then(JsonValue::as_array)
                .is_some_and(|values| {
                    !values.is_empty()
                        && values.len() <= 256
                        && values.iter().all(|value| value.as_str().is_some())
                });
            let constant = object
                .get("const")
                .and_then(JsonValue::as_str)
                .is_some_and(|value| value.len() <= 65_536);
            if !bounded && !formatted && !enumerated && !constant {
                return Err(invalid_artifact(
                    "schema strings must be bounded, formatted, or enumerated",
                ));
            }
        }
        "integer" => {
            let bounded = object
                .get("minimum")
                .and_then(JsonValue::as_i64)
                .zip(object.get("maximum").and_then(JsonValue::as_i64));
            let enumerated = object
                .get("enum")
                .and_then(JsonValue::as_array)
                .is_some_and(|values| {
                    !values.is_empty()
                        && values.len() <= 256
                        && values.iter().all(|value| value.as_i64().is_some())
                });
            let constant = object.get("const").and_then(JsonValue::as_i64).is_some();
            if bounded.is_none_or(|(minimum, maximum)| minimum > maximum)
                && !enumerated
                && !constant
            {
                return Err(invalid_artifact(
                    "schema integers need both a minimum and a maximum, or an enum, or a const",
                ));
            }
        }
        "boolean" => {
            if object.get("const").is_some_and(|value| !value.is_boolean()) {
                return Err(invalid_artifact("schema boolean const is invalid"));
            }
            if object.get("enum").is_some_and(|value| {
                value.as_array().is_none_or(|values| {
                    values.is_empty()
                        || values.len() > 2
                        || values.iter().any(|value| !value.is_boolean())
                })
            }) {
                return Err(invalid_artifact("schema boolean enumeration is invalid"));
            }
        }
        _ => unreachable!("type was closed above"),
    }
    Ok(())
}

fn schema_const_is_bounded(value: &JsonValue) -> bool {
    match value {
        JsonValue::Bool(_) => true,
        JsonValue::Number(value) => value.as_i64().is_some(),
        JsonValue::String(value) => value.len() <= 65_536,
        JsonValue::Array(values) => {
            values.len() <= 256 && values.iter().all(schema_const_is_bounded)
        }
        JsonValue::Object(values) => {
            values.len() <= 256
                && values
                    .iter()
                    .all(|(name, value)| name.len() <= 1_024 && schema_const_is_bounded(value))
        }
        JsonValue::Null => false,
    }
}

fn load_codelists(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Codelist>, BundleError> {
    let mut paths = BTreeSet::new();
    for (_, profile) in config.selector_profiles.iter() {
        for (_, field) in profile.fields.iter() {
            if let SelectorField::ControlledCode { codelist, .. } = field {
                paths.insert(codelist.as_str().to_owned());
            }
        }
    }
    for requirement in &config.requirements {
        for concept in &requirement.concepts {
            if matches!(
                concept.form,
                ConceptForm::ControlledCode
                    | ConceptForm::ControlledCategory
                    | ConceptForm::ControlledCodeList
            ) {
                paths.insert(concept_codelist_path(&concept.constraints)?.to_owned());
            }
        }
    }
    paths.extend(reviewed_bucket_codelist_paths(config, files)?);
    let mut codelists = BTreeMap::new();
    for path in paths {
        let codelist = load_codelist(&path, files).map_err(|error| error.in_artifact(&path))?;
        codelists.insert(path, codelist);
    }
    Ok(codelists)
}

fn load_codelist(path: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<Codelist, BundleError> {
    let bytes = files
        .get(path)
        .ok_or(invalid_artifact("missing codelist"))?;
    let text = std::str::from_utf8(bytes).map_err(|_| invalid_artifact("codelist is not UTF-8"))?;
    let document: CodelistDocument =
        serde_norway::from_str(text).map_err(|_| invalid_artifact("codelist YAML is invalid"))?;
    document.validate()
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CodelistDocument {
    Codes(CodeCodelistDocument),
    Mapping(MappingCodelistDocument),
}

impl CodelistDocument {
    fn validate(self) -> Result<Codelist, BundleError> {
        match self {
            Self::Codes(document) => document.validate(),
            Self::Mapping(document) => document.validate(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeCodelistDocument {
    id: String,
    version: String,
    codes: Vec<String>,
}

impl CodeCodelistDocument {
    fn validate(self) -> Result<Codelist, BundleError> {
        validate_codelist_header(&self.id, &self.version)?;
        validate_code_collection(&self.codes)?;
        Ok(Codelist::Codes {
            id: self.id,
            version: self.version,
            codes: self.codes,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingCodelistDocument {
    id: String,
    version: String,
    entries: BTreeMap<String, String>,
    allowed_outputs: Vec<String>,
}

impl MappingCodelistDocument {
    fn validate(self) -> Result<Codelist, BundleError> {
        validate_codelist_header(&self.id, &self.version)?;
        if self.entries.is_empty() || self.entries.len() > 4_096 {
            return Err(invalid_artifact("codelist entry count is invalid"));
        }
        validate_code_collection(&self.allowed_outputs)?;
        for (input, output) in &self.entries {
            validate_code(input)?;
            validate_code(output)?;
            if !self.allowed_outputs.contains(output) {
                return Err(invalid_artifact("codelist mapping output is not allowed"));
            }
        }
        Ok(Codelist::Mapping {
            id: self.id,
            version: self.version,
            entries: self.entries,
            allowed_outputs: self.allowed_outputs,
        })
    }
}

fn validate_codelist_header(id: &str, version: &str) -> Result<(), BundleError> {
    if id.len() > 512
        || Url::parse(id).is_err()
        || version.is_empty()
        || version.len() > 128
        || version.contains('\0')
    {
        return Err(invalid_artifact("codelist identity is invalid"));
    }
    Ok(())
}

fn validate_code_collection(codes: &[String]) -> Result<(), BundleError> {
    if codes.is_empty() || codes.len() > 4_096 {
        return Err(invalid_artifact("codelist code count is invalid"));
    }
    let mut seen = BTreeSet::new();
    for code in codes {
        validate_code(code)?;
        if !seen.insert(code.as_str()) {
            return Err(invalid_artifact("codelist code is duplicated"));
        }
    }
    Ok(())
}

fn validate_code(code: &str) -> Result<(), BundleError> {
    let bytes = code.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(invalid_artifact("codelist code is invalid"));
    }
    Ok(())
}

fn validate_codelist_references(
    config: &EvidenceConfig,
    codelists: &BTreeMap<String, Codelist>,
) -> Result<(), BundleError> {
    for (_, profile) in config.selector_profiles.iter() {
        for (_, field) in profile.fields.iter() {
            if let SelectorField::ControlledCode {
                codelist,
                codelist_version,
                ..
            } = field
            {
                let loaded = codelists
                    .get(codelist.as_str())
                    .ok_or(invalid_artifact("selector codelist is missing"))?;
                if loaded.version() != codelist_version {
                    return Err(invalid_artifact("selector codelist version mismatch"));
                }
            }
        }
    }
    for requirement in &config.requirements {
        for concept in &requirement.concepts {
            if matches!(
                concept.form,
                ConceptForm::DateBucket | ConceptForm::TimeBucket
            ) {
                let identifier = concept_constraint_string(&concept.constraints, "bucketScheme")?;
                let version = concept_constraint_string(&concept.constraints, "schemeVersion")?;
                let matches = codelists
                    .values()
                    .filter(|codelist| codelist.id() == identifier && codelist.version() == version)
                    .count();
                if matches != 1 {
                    return Err(invalid_artifact("bucket scheme codelist identity mismatch"));
                }
                continue;
            }
            let version_key = match concept.form {
                ConceptForm::ControlledCode | ConceptForm::ControlledCodeList => "codelistVersion",
                ConceptForm::ControlledCategory => "schemeVersion",
                _ => continue,
            };
            let path = concept_codelist_path(&concept.constraints)?;
            let version = concept_constraint_string(&concept.constraints, version_key)?;
            let loaded = codelists
                .get(path)
                .ok_or(invalid_artifact("concept codelist is missing"))?;
            if loaded.version() != version {
                return Err(invalid_artifact("concept codelist version mismatch"));
            }
        }
    }
    Ok(())
}

fn load_fixtures(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, YamlValue>, BundleError> {
    let mut fixtures = BTreeMap::new();
    for requirement in &config.requirements {
        let Some(fixture_path) = &requirement.fixtures else {
            continue;
        };
        let path = fixture_path.as_str();
        if fixtures.contains_key(path) {
            continue;
        }
        let fixture = load_fixture(path, files).map_err(|error| error.in_artifact(path))?;
        fixtures.insert(path.to_owned(), fixture);
    }
    Ok(fixtures)
}

fn load_fixture(path: &str, files: &BTreeMap<String, Vec<u8>>) -> Result<YamlValue, BundleError> {
    let bytes = files
        .get(path)
        .ok_or(invalid_artifact("fixture file is missing"))?;
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid_artifact("fixture file is not UTF-8"))?;
    let fixture: YamlValue =
        serde_norway::from_str(text).map_err(|_| invalid_artifact("fixture YAML is invalid"))?;
    validate_fixture_coverage(&fixture)?;
    Ok(fixture)
}

fn validate_fixture_coverage(fixture: &YamlValue) -> Result<(), BundleError> {
    let root = fixture
        .as_mapping()
        .ok_or(invalid_artifact("fixture root must be a mapping"))?;
    if root.get("synthetic_only").and_then(YamlValue::as_bool) != Some(true) {
        return Err(invalid_artifact("fixtures must be synthetic-only"));
    }
    let cases = root
        .get("cases")
        .and_then(YamlValue::as_sequence)
        .ok_or(invalid_artifact("fixture cases are missing"))?;
    if cases.is_empty() || cases.len() > 256 {
        return Err(invalid_artifact("fixture case count is invalid"));
    }
    let mut ids = BTreeSet::new();
    let mut categories = FixtureCategories::default();
    for case in cases {
        let id = case
            .as_mapping()
            .and_then(|mapping| mapping.get("id"))
            .and_then(YamlValue::as_str)
            .ok_or(invalid_artifact("fixture case id is missing"))?;
        if id.is_empty() || id.len() > 128 || !ids.insert(id) {
            return Err(invalid_artifact("fixture case id is invalid or duplicated"));
        }
        categories.observe(id);
    }
    if !categories.complete() {
        return Err(invalid_artifact("fixture category coverage is incomplete"));
    }
    Ok(())
}

#[derive(Default)]
struct FixtureCategories {
    positive: bool,
    negative: bool,
    boundary: bool,
    missing: bool,
    no_match: bool,
    ambiguous: bool,
    source_failure: bool,
    anti_reconstruction: bool,
}

impl FixtureCategories {
    fn observe(&mut self, id: &str) {
        self.positive |= id == "positive";
        self.negative |= id.starts_with("negative");
        self.boundary |= id.starts_with("boundary");
        self.missing |= id.starts_with("missing");
        self.no_match |= id == "no-match";
        self.ambiguous |= id.starts_with("ambiguous");
        self.source_failure |= id == "source-failure";
        self.anti_reconstruction |= id == "anti-reconstruction";
    }

    fn complete(&self) -> bool {
        self.positive
            && self.negative
            && self.boundary
            && self.missing
            && self.no_match
            && self.ambiguous
            && self.source_failure
            && self.anti_reconstruction
    }
}

fn load_retired_public_jwks(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, JsonValue>, BundleError> {
    let mut keys = BTreeMap::new();
    for path in &config.signing.retired_public_jwk_files {
        let path = path.as_str();
        let load = || -> Result<(String, JsonMap<String, JsonValue>), BundleError> {
            let bytes = files
                .get(path)
                .ok_or(invalid_artifact("retired public JWK is missing"))?;
            let object = parse_strict_json_object(bytes)?;
            let kid = validate_public_jwk(&object, &config.signing.active_key_id)?;
            Ok((kid, object))
        };
        let (kid, object) = load().map_err(|error| error.in_artifact(path))?;
        if keys.insert(kid, JsonValue::Object(object)).is_some() {
            return Err(invalid_artifact("retired public JWK kid is duplicated").in_artifact(path));
        }
    }
    Ok(keys)
}

fn parse_strict_json_object(bytes: &[u8]) -> Result<JsonMap<String, JsonValue>, BundleError> {
    struct StrictObject(JsonMap<String, JsonValue>);
    impl<'de> Deserialize<'de> for StrictObject {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct ObjectVisitor;
            impl<'de> Visitor<'de> for ObjectVisitor {
                type Value = StrictObject;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("a JSON object with unique members")
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut object = JsonMap::new();
                    while let Some((key, value)) = map.next_entry::<String, JsonValue>()? {
                        if object.insert(key, value).is_some() {
                            return Err(de::Error::custom("duplicate JSON member"));
                        }
                    }
                    Ok(StrictObject(object))
                }
            }
            deserializer.deserialize_map(ObjectVisitor)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let object = StrictObject::deserialize(&mut deserializer)
        .map_err(|_| invalid_artifact("public JWK JSON is invalid"))?;
    deserializer
        .end()
        .map_err(|_| invalid_artifact("public JWK has trailing data"))?;
    Ok(object.0)
}

fn validate_public_jwk(
    object: &JsonMap<String, JsonValue>,
    active_key_id: &str,
) -> Result<String, BundleError> {
    const ALLOWED: [&str; 7] = ["kty", "crv", "x", "kid", "alg", "use", "key_ops"];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str()))
        || object.get("kty").and_then(JsonValue::as_str) != Some("OKP")
        || object.get("crv").and_then(JsonValue::as_str) != Some("Ed25519")
        || object.get("alg").and_then(JsonValue::as_str) != Some("EdDSA")
        || object
            .get("use")
            .is_some_and(|value| value.as_str() != Some("sig"))
    {
        return Err(invalid_artifact(
            "retired JWK is not an allowed public EdDSA key",
        ));
    }
    let kid = object
        .get("kid")
        .and_then(JsonValue::as_str)
        .filter(|kid| {
            !kid.is_empty()
                && kid.len() <= 256
                && !kid.chars().any(char::is_control)
                && *kid != active_key_id
        })
        .ok_or(invalid_artifact("retired JWK kid is invalid"))?;
    let x = object
        .get("x")
        .and_then(JsonValue::as_str)
        .ok_or(invalid_artifact("retired JWK public coordinate is missing"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| invalid_artifact("retired JWK public coordinate is invalid"))?;
    if decoded.len() != 32 {
        return Err(invalid_artifact(
            "retired JWK public coordinate has the wrong size",
        ));
    }
    if let Some(operations) = object.get("key_ops") {
        let operations = operations
            .as_array()
            .ok_or(invalid_artifact("retired JWK key_ops is invalid"))?;
        if operations.len() != 1 || operations[0].as_str() != Some("verify") {
            return Err(invalid_artifact("retired JWK key_ops is not verify-only"));
        }
    }
    Ok(kid.to_owned())
}

fn concept_codelist_path(constraints: &OrderedMap<YamlValue>) -> Result<&str, BundleError> {
    concept_constraint_string(constraints, "codelist")
}

fn concept_constraint_string<'a>(
    constraints: &'a OrderedMap<YamlValue>,
    key: &str,
) -> Result<&'a str, BundleError> {
    constraints
        .get(key)
        .and_then(YamlValue::as_str)
        .ok_or(invalid_artifact("concept codelist constraint is invalid"))
}

fn validate_runtime_bindings(
    bundle: &EvidenceConfig,
    runtime: &RuntimeConfig,
) -> Result<(), BundleError> {
    let required = bundle
        .sources
        .iter()
        .filter_map(|(_, source)| source.tls_trust_profile.as_deref())
        .collect::<BTreeSet<_>>();
    let configured = runtime
        .outbound_tls
        .trust_profiles
        .keys()
        .collect::<BTreeSet<_>>();
    if required != configured {
        return Err(invalid_artifact(
            "runtime TLS trust profiles must exactly bind bundle source profiles",
        ));
    }
    Ok(())
}

/// The secret root is the one immutability check whose subject is outside the
/// bundle, so its cause says so. Re-freezing the bundle does not touch it, and
/// an operator told only that a deployment input is not immutable audits the
/// bundle first and finds nothing wrong with it.
fn validate_secret_root(path: &Path) -> Result<(), BundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(BundleError::InvalidPath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(not_immutable(
                "the secret root directory the runtime file names is reachable by group or other",
            ));
        }
    }
    #[cfg(not(unix))]
    if !metadata.permissions().readonly() {
        return Err(not_immutable(
            "the secret root directory the runtime file names is writable",
        ));
    }
    Ok(())
}

fn validate_ca_bundle(bytes: &[u8]) -> Result<(), BundleError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid_artifact("TLS CA bundle is not UTF-8 PEM"))?;
    let mut in_certificate = false;
    let mut encoded = String::new();
    let mut certificates = 0_usize;
    for line in text.lines() {
        match line {
            "-----BEGIN CERTIFICATE-----" if !in_certificate => {
                in_certificate = true;
                encoded.clear();
            }
            "-----END CERTIFICATE-----" if in_certificate => {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|_| invalid_artifact("TLS CA bundle PEM is invalid"))?;
                if der.len() < 4 || der.first() != Some(&0x30) {
                    return Err(invalid_artifact("TLS CA bundle certificate is invalid"));
                }
                certificates = certificates.checked_add(1).ok_or(BundleError::TooLarge)?;
                if certificates > 64 {
                    return Err(BundleError::TooLarge);
                }
                in_certificate = false;
            }
            "" if !in_certificate => {}
            _ if in_certificate
                && !line.is_empty()
                && line.len() <= 76
                && line.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
                }) =>
            {
                encoded.push_str(line);
            }
            _ => {
                return Err(invalid_artifact(
                    "TLS CA bundle contains non-certificate PEM data",
                ));
            }
        }
    }
    if in_certificate || certificates == 0 {
        return Err(invalid_artifact(
            "TLS CA bundle contains no complete certificate",
        ));
    }
    Ok(())
}

fn compute_runtime_revision(
    runtime_bytes: &[u8],
    ca_bundles: &BTreeMap<String, Vec<u8>>,
) -> Result<String, BundleError> {
    let mut files = BTreeMap::from([("runtime.yaml".to_owned(), runtime_bytes.to_vec())]);
    for (profile, bytes) in ca_bundles {
        files.insert(format!("trust-profile/{profile}.pem"), bytes.clone());
    }
    compute_named_revision(RUNTIME_REVISION_DOMAIN, &files)
}

fn compute_revision(files: &BTreeMap<String, Vec<u8>>) -> Result<String, BundleError> {
    compute_named_revision(REVISION_DOMAIN, files)
}

fn compute_named_revision(
    domain: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<String, BundleError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(files.len())
            .map_err(|_| BundleError::TooLarge)?
            .to_be_bytes(),
    );
    for (path, bytes) in files {
        let path_bytes = path.as_bytes();
        hasher.update(
            u64::try_from(path_bytes.len())
                .map_err(|_| BundleError::TooLarge)?
                .to_be_bytes(),
        );
        hasher.update(path_bytes);
        hasher.update(
            u64::try_from(bytes.len())
                .map_err(|_| BundleError::TooLarge)?
                .to_be_bytes(),
        );
        hasher.update(bytes);
    }
    let digest = hasher.finalize();
    let mut revision = String::with_capacity("sha256:".len() + 64);
    revision.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut revision, "{byte:02x}").map_err(|_| BundleError::TooLarge)?;
    }
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AssuranceProfile;
    use crate::kernel::OfflineKernel;

    #[cfg(unix)]
    fn copy_acceptance_bundle(case: &str, destination: &Path) {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance")
            .join(case);
        copy_tree(&source, destination);
    }

    #[cfg(unix)]
    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("create destination");
        for entry in fs::read_dir(source).expect("read source tree") {
            let entry = entry.expect("source entry");
            let target = destination.join(entry.file_name());
            if entry.file_type().expect("source file type").is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("copy fixture artifact");
            }
        }
    }

    #[cfg(unix)]
    fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = fs::symlink_metadata(path).expect("tree metadata");
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("read tree") {
                set_tree_mode(
                    &entry.expect("tree entry").path(),
                    directory_mode,
                    file_mode,
                );
            }
            fs::set_permissions(path, fs::Permissions::from_mode(directory_mode))
                .expect("set directory mode");
        } else if metadata.is_file() {
            fs::set_permissions(path, fs::Permissions::from_mode(file_mode))
                .expect("set file mode");
        }
    }

    #[test]
    fn revision_binds_paths_and_exact_bytes_deterministically() {
        let first = BTreeMap::from([
            ("evidence.yaml".to_owned(), b"version: 1\n".to_vec()),
            ("schemas/facts.yaml".to_owned(), b"type: object\n".to_vec()),
        ]);
        let same = BTreeMap::from([
            ("schemas/facts.yaml".to_owned(), b"type: object\n".to_vec()),
            ("evidence.yaml".to_owned(), b"version: 1\n".to_vec()),
        ]);
        assert_eq!(compute_revision(&first), compute_revision(&same));

        let renamed = BTreeMap::from([
            ("evidence.yaml".to_owned(), b"version: 1\n".to_vec()),
            ("schemas/other.yaml".to_owned(), b"type: object\n".to_vec()),
        ]);
        assert_ne!(compute_revision(&first), compute_revision(&renamed));
    }

    #[test]
    fn fixture_coverage_is_case_neutral_but_complete() {
        let fixture: YamlValue = serde_norway::from_str(
            "synthetic_only: true\ncases:\n  - {id: positive}\n  - {id: negative-a}\n  - {id: boundary-a}\n  - {id: missing-a}\n  - {id: no-match}\n  - {id: ambiguous}\n  - {id: source-failure}\n  - {id: anti-reconstruction}\n",
        )
        .expect("fixture parses");
        assert!(validate_fixture_coverage(&fixture).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn local_bundle_may_omit_fixtures_but_strict_bundles_remain_complete() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        let config_path = directory.path().join(CONFIG_FILE);
        let strict = fs::read_to_string(&config_path).expect("configuration reads");
        let local = strict
            .replace(
                "assuranceProfile: evidence-grade",
                "assuranceProfile: local",
            )
            .lines()
            .filter(|line| !line.trim_start().starts_with("fixtures:"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&config_path, local).expect("local configuration writes");
        fs::remove_file(directory.path().join("fixtures/cases.yaml"))
            .expect("unreferenced fixture is removed");
        set_tree_mode(directory.path(), 0o555, 0o444);

        let bundle = Bundle::load(directory.path()).expect("local bundle loads without fixtures");
        assert_eq!(bundle.config.assurance_profile, AssuranceProfile::Local);
        assert!(bundle.fixtures.is_empty());

        set_tree_mode(directory.path(), 0o755, 0o644);
        for profile in ["production", "evidence-grade"] {
            let candidate = fs::read_to_string(&config_path)
                .expect("local configuration reads")
                .replace(
                    "assuranceProfile: local",
                    &format!("assuranceProfile: {profile}"),
                );
            fs::write(&config_path, candidate).expect("strict configuration writes");
            set_tree_mode(directory.path(), 0o555, 0o444);
            assert!(
                Bundle::load(directory.path()).is_err(),
                "{profile} bundle loaded without fixtures"
            );
            set_tree_mode(directory.path(), 0o755, 0o644);
            let reset = fs::read_to_string(&config_path)
                .expect("strict configuration reads")
                .replace(
                    &format!("assuranceProfile: {profile}"),
                    "assuranceProfile: local",
                );
            fs::write(&config_path, reset).expect("local configuration restores");
        }
    }

    #[cfg(unix)]
    #[test]
    fn strict_assurance_rejects_partial_fixture_suites() {
        for profile in ["production", "evidence-grade"] {
            let directory = tempfile::tempdir().expect("temporary bundle");
            copy_acceptance_bundle("adult-status", directory.path());

            let config_path = directory.path().join(CONFIG_FILE);
            let configuration = fs::read_to_string(&config_path)
                .expect("configuration reads")
                .replace(
                    "assuranceProfile: evidence-grade",
                    &format!("assuranceProfile: {profile}"),
                );
            fs::write(&config_path, configuration).expect("configuration writes");

            let fixtures_path = directory.path().join("fixtures/cases.yaml");
            let fixtures = fs::read_to_string(&fixtures_path)
                .expect("fixtures read")
                .lines()
                .filter(|line| !line.contains("id: anti-reconstruction"))
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(&fixtures_path, fixtures).expect("partial fixtures write");
            set_tree_mode(directory.path(), 0o555, 0o444);

            let error = Bundle::load(directory.path()).expect_err(&format!(
                "{profile} bundle loaded with incomplete fixture coverage"
            ));
            assert!(
                error
                    .to_string()
                    .contains("fixture category coverage is incomplete"),
                "{profile} failed for an unexpected reason: {error}"
            );
        }
    }

    #[test]
    fn strict_public_jwk_rejects_private_material_and_duplicate_members() {
        let private = br#"{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"old","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","d":"secret"}"#;
        let object = parse_strict_json_object(private).expect("JSON parses");
        assert!(validate_public_jwk(&object, "active").is_err());

        let duplicate = br#"{"kty":"OKP","kty":"OKP"}"#;
        assert!(parse_strict_json_object(duplicate).is_err());

        let control_kid = br#"{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"old\u000aidentifier","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let object = parse_strict_json_object(control_kid).expect("JSON parses");
        assert!(validate_public_jwk(&object, "active").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn all_coequal_immutable_acceptance_bundles_load_through_one_kernel() {
        for case in [
            "adult-status",
            "residence-region",
            "professional-licence",
            "legal-parent-relationship",
        ] {
            let directory = tempfile::tempdir().expect("temporary bundle");
            copy_acceptance_bundle(case, directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);

            let bundle = Bundle::load(directory.path()).expect("bundle loads");
            assert!(bundle.configuration_revision().starts_with("sha256:"));
            assert_eq!(bundle.configuration_revision().len(), 71);
            assert_eq!(bundle.scripts.len(), 3);
            assert_eq!(bundle.fact_schemas.len(), 3);
            assert_eq!(bundle.fixtures.len(), 1);

            set_tree_mode(directory.path(), 0o755, 0o444);
        }
    }

    #[cfg(unix)]
    #[test]
    fn combined_acceptance_bundle_loads_as_one_atomic_revision() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("all-definitions", directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);

        let bundle = Bundle::load(directory.path()).expect("combined bundle loads");
        assert_eq!(bundle.config.requirements.len(), 4);
        assert_eq!(bundle.config.sources.len(), 4);
        assert_eq!(bundle.scripts.len(), 12);
        assert_eq!(bundle.fact_schemas.len(), 12);
        assert_eq!(bundle.fixtures.len(), 4);
        assert_eq!(bundle.codelists.len(), 3);

        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[test]
    fn deployment_reference_projects_are_complete_compilable_bundles() {
        let projects_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/reference/request-adapter/deployment-projects");
        for project in [
            "dhis2-tracker-evidence",
            "opencrvs-family-evidence",
            "relay-protected-read-evidence",
        ] {
            let project_root = projects_root.join(project);
            RuntimeConfig::parse_yaml(
                &fs::read(project_root.join("runtime.yaml")).expect("read reference runtime"),
            )
            .expect("reference runtime is closed and valid");

            let directory = tempfile::tempdir().expect("temporary bundle");
            copy_tree(&project_root.join("bundle"), directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);

            let bundle = std::sync::Arc::new(
                Bundle::load(directory.path()).expect("reference bundle loads atomically"),
            );
            OfflineKernel::compile(bundle).expect("reference scripts compile through the ABI");

            set_tree_mode(directory.path(), 0o755, 0o444);
        }
    }

    #[cfg(unix)]
    #[test]
    fn reviewed_structured_schema_uri_resolves_exactly_one_bundle_artifact() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        let config_path = directory.path().join("evidence.yaml");
        let config = fs::read_to_string(&config_path).expect("read configuration");
        let original = "    concepts: [{id: urn:example:fixture:concept:adult-status, form: boolean, required: true, constraints: {}}]\n";
        let replacement = "    concepts: [{id: urn:example:fixture:concept:adult-status, form: boolean, required: true, constraints: {}}, {id: urn:example:fixture:concept:structured, form: reviewed-structured-value, required: false, constraints: {schema: urn:example:fixture:schema:structured:v1, maximumSerializedBytes: 512}}]\n";
        let config = config.replacen(original, replacement, 1);
        assert_ne!(
            config,
            fs::read_to_string(&config_path).expect("read configuration")
        );
        fs::write(&config_path, config).expect("write configuration");
        let schema = concat!(
            "$schema: https://json-schema.org/draft/2020-12/schema\n",
            "$id: urn:example:fixture:schema:structured:v1\n",
            "type: object\n",
            "additionalProperties: false\n",
            "required: [status]\n",
            "properties:\n",
            "  status: {type: string, enum: [A]}\n"
        );
        fs::write(directory.path().join("schemas/structured.yaml"), schema)
            .expect("write reviewed schema");
        set_tree_mode(directory.path(), 0o555, 0o444);
        let bundle = Bundle::load(directory.path()).expect("reviewed schema resolves");
        assert!(bundle.fact_schemas.contains_key("schemas/structured.yaml"));

        let schema_path = directory.path().join("schemas/structured.yaml");
        for invalid_property in [
            "{}",
            "{type: object, additionalProperties: true, required: [nested], properties: {nested: {type: string, maxLength: 8}}}",
            "{type: object, additionalProperties: false, required: [nested], properties: {nested: {}}}",
            "{type: array, maxItems: 2, items: {}}",
            "{type: array, items: {type: string, maxLength: 8}}",
            "{type: string, maxLength: 8, format: custom-id}",
        ] {
            set_tree_mode(directory.path(), 0o755, 0o644);
            fs::write(
                &schema_path,
                format!(
                    "$schema: https://json-schema.org/draft/2020-12/schema\n$id: urn:example:fixture:schema:structured:v1\ntype: object\nadditionalProperties: false\nrequired: [status]\nproperties:\n  status: {invalid_property}\n"
                ),
            )
            .expect("write invalid reviewed schema");
            set_tree_mode(directory.path(), 0o555, 0o444);
            assert!(
                matches!(
                    Bundle::load(directory.path()),
                    Err(BundleError::InvalidArtifact(_))
                ),
                "open nested schema must fail: {invalid_property}"
            );
        }

        set_tree_mode(directory.path(), 0o755, 0o644);
        fs::write(&schema_path, schema).expect("restore reviewed schema");
        fs::write(directory.path().join("schemas/duplicate.yaml"), schema)
            .expect("write duplicate schema");
        set_tree_mode(directory.path(), 0o555, 0o444);
        let ambiguous = Bundle::load(directory.path()).expect_err("duplicate schema is rejected");
        assert!(matches!(ambiguous, BundleError::InvalidArtifact(_)));
        assert_eq!(
            ambiguous.artifact_fault().map(ArtifactFault::fault),
            Some(&SchemaFault::because(
                "reviewed structured schema identifier is missing or ambiguous"
            ))
        );
    }

    /// The closed subset is learnable, but only if each rule states itself
    /// whole. A lower bound alone is what JSON Schema habit supplies, and it is
    /// refused, so the refusal has to say that an upper bound is the missing
    /// half rather than leave the author to guess which of three admitted forms
    /// was meant.
    #[test]
    fn an_integer_bounded_on_one_side_is_refused_by_the_whole_rule() {
        let admitted = [
            "{type: integer, minimum: 0, maximum: 64}",
            "{type: integer, enum: [1, 2]}",
            "{type: integer, const: 1}",
        ];
        for node in admitted {
            let node: JsonValue = serde_norway::from_str(node).expect("admitted integer node");
            assert!(
                validate_schema_node(&node, SchemaRole::Facts).is_ok(),
                "the subset admits this integer: {node}"
            );
        }

        for node in [
            "{type: integer, minimum: 0}",
            "{type: integer, maximum: 64}",
            "{type: integer}",
        ] {
            let node: JsonValue = serde_norway::from_str(node).expect("unbounded integer node");
            let refused = validate_schema_node(&node, SchemaRole::Facts)
                .expect_err("an integer bounded on one side is refused");
            assert_eq!(
                refused.artifact_fault().map(ArtifactFault::fault),
                Some(&SchemaFault::because(
                    "schema integers need both a minimum and a maximum, or an enum, or a const"
                )),
                "the refusal must name the whole rule: {node}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn writable_bundle_and_unknown_files_fail_closed() {
        let writable = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", writable.path());
        let writable_error = Bundle::load(writable.path()).expect_err("a writable bundle fails");
        let fault = writable_error
            .artifact_fault()
            .expect("the refusal names what is writable");
        assert_eq!(fault.artifact(), "");
        assert_eq!(fault.fault().cause(), "the bundle directory is writable");

        let unknown = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", unknown.path());
        fs::write(
            unknown.path().join("fixtures/unreferenced.yaml"),
            b"synthetic_only: true\n",
        )
        .expect("write unknown artifact");
        set_tree_mode(unknown.path(), 0o555, 0o444);
        let unreferenced = Bundle::load(unknown.path()).expect_err("unknown artifact is rejected");
        assert!(matches!(unreferenced, BundleError::UnknownFile(_)));
        let fault = unreferenced.artifact_fault().expect("closure names a file");
        assert_eq!(fault.artifact(), "fixtures/unreferenced.yaml");
        assert_eq!(
            fault.fault().cause(),
            "the bundle contains an artifact the configuration does not reference"
        );
        set_tree_mode(unknown.path(), 0o755, 0o444);

        let missing = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", missing.path());
        fs::remove_file(missing.path().join("derivations/adult-status.rhai"))
            .expect("remove referenced derivation");
        set_tree_mode(missing.path(), 0o555, 0o444);
        let absent = Bundle::load(missing.path()).expect_err("missing artifact is rejected");
        let fault = absent.artifact_fault().expect("closure names a file");
        assert_eq!(fault.artifact(), "derivations/adult-status.rhai");
        assert_eq!(
            fault.fault().cause(),
            "the configuration references an artifact the bundle does not contain"
        );
        set_tree_mode(missing.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_artifact_fails_before_file_access() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        let outside = tempfile::NamedTempFile::new().expect("outside script");
        let adapter = directory.path().join("adapters/source-a.rhai");
        fs::remove_file(&adapter).expect("remove copied adapter");
        symlink(outside.path(), adapter).expect("create symlink");
        set_tree_mode(directory.path(), 0o555, 0o444);
        assert!(matches!(
            Bundle::load(directory.path()),
            Err(BundleError::InvalidPath)
        ));
        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    #[test]
    fn runtime_and_ca_bytes_are_captured_under_an_independent_read_only_revision() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary runtime root");
        let secret_root = directory.path().join("secrets");
        fs::create_dir(&secret_root).expect("create secret root");
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("lock secret root");
        let ca_path = directory.path().join("internal.pem");
        fs::write(
            &ca_path,
            b"-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n",
        )
        .expect("write CA bundle");
        fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o444)).expect("lock CA bundle");
        let runtime_path = directory.path().join("runtime.yaml");
        fs::write(
            &runtime_path,
            format!(
                "version: 1\nbundleDirectory: /etc/registry-evidence/bundle\nlistener:\n  bindHost: 127.0.0.1\n  port: 8080\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 65536\n  maximumConcurrentRequests: 64\n  requestTimeoutMilliseconds: 10000\n  shutdownGraceMilliseconds: 30000\nsecretProviders:\n  file: {{root: {}}}\nauditStorage:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\n  maximumFileBytes: 1073741824\noutboundTls:\n  systemRoots: true\n  trustProfiles:\n    internal-pki: {{caBundleFile: {}}}\n",
                secret_root.display(),
                ca_path.display()
            ),
        )
        .expect("write runtime document");

        let writable = RuntimeDocument::load(&runtime_path).expect_err("a writable runtime fails");
        let fault = writable
            .artifact_fault()
            .expect("the refusal names what is writable");
        assert_eq!(fault.artifact(), RUNTIME_FILE);
        assert_eq!(fault.fault().cause(), "the runtime file is writable");
        fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
            .expect("lock runtime document");
        let runtime = RuntimeDocument::load(&runtime_path).expect("runtime loads");
        assert!(runtime.revision().starts_with("sha256:"));
        assert_eq!(runtime.revision().len(), 71);
        assert_eq!(runtime.ca_bundles.len(), 1);
        assert_eq!(
            runtime.bytes(),
            fs::read(&runtime_path).expect("read runtime")
        );

        // Everything the operator can re-freeze is already frozen here, so the
        // refusal has to name the one input outside the bundle. Re-freezing the
        // bundle in answer to it changes nothing, which is what makes an
        // unnamed immutability failure cost a mode audit of the whole tree.
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o750))
            .expect("loosen secret root");
        let loose = RuntimeDocument::load(&runtime_path).expect_err("a group-readable root fails");
        let fault = loose
            .artifact_fault()
            .expect("the refusal names what is loose");
        assert_eq!(
            fault.fault().cause(),
            "the secret root directory the runtime file names is reachable by group or other"
        );
    }
}
