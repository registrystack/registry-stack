//! Immutable Evidence Version 1 deployment bundle loading.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use jsonschema::{Draft, JSONSchema};
use registry_platform_crypto::{
    canonicalize_json, PublicJwk, SigningAlgorithm as ProviderSigningAlgorithm,
};
use rhai::{Engine, AST};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_norway::Value as YamlValue;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::config::{
    ArtifactPath, ConceptConfig, ConceptForm, EvidenceConfig, OrderedMap, RequirementConfig,
    RuntimeConfig, SchemaFault, SelectorField, TextLocation,
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
const REQUIREMENT_REVISION_DOMAIN: &[u8] = b"registry.evidence.requirement-revision/v1\0";
/// Path the canonical configuration projection takes inside a requirement's
/// closure. An artifact path can hold no `#`, so this can never collide with a
/// bundle file.
const PROJECTION_PATH: &str = "evidence.yaml#requirement";
/// Projected member holding the bundle's declared acquisition capabilities.
const ACQUISITION_CAPABILITIES: &str = "acquisitionCapabilities";
const MAX_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
/// Bytes folded into an extract's digest per read. An extract is sized by the
/// register it holds rather than by a byte cap, so it is digested in chunks of
/// this size and never held whole.
const EXTRACT_DIGEST_CHUNK_BYTES: usize = 64 * 1024;
const ALLOWED_DIRECTORIES: [&str; 7] = [
    "adapters",
    "derivations",
    "schemas",
    "codelists",
    "fixtures",
    "public-keys",
    "queries",
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

/// A value-free deployment diagnostic bound to one governed artifact.
///
/// The artifact name comes from the reviewed bundle layout or from a logical
/// runtime binding such as an extract profile. It is never taken from source
/// content or an operator filesystem path, and the fault it carries is
/// value-free by construction.
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

    /// A diagnostic that also says where inside the artifact the fault is.
    ///
    /// Only the position travels. The line an adopter is sent to is theirs to
    /// open; its text is content, and this type carries none.
    pub fn at(artifact: impl Into<String>, fault: SchemaFault, location: TextLocation) -> Self {
        Self::new(artifact, fault.at(location))
    }

    /// A cause raised before the artifact being loaded is in scope.
    fn unbound(cause: &'static str) -> Self {
        Self {
            artifact: String::new(),
            fault: SchemaFault::because(cause),
        }
    }

    /// The governed artifact, empty when no loader claimed the failure.
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

/// A trust-profile binding fault, named by the profile the two files disagree
/// on.
///
/// Both grammars validate a trust profile name as a local identifier before
/// this runs, so the name is reviewed configuration rather than document
/// content and printing it stays value-free.
fn trust_profile_fault(profile: &str, cause: &'static str) -> BundleError {
    BundleError::InvalidArtifact(ArtifactFault::new(
        format!("trustProfiles/{profile}"),
        SchemaFault::because(cause),
    ))
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
    requirement_revisions: BTreeMap<String, String>,
    files: BTreeMap<String, Vec<u8>>,
    pub scripts: BTreeMap<String, CompiledScript>,
    pub fact_schemas: BTreeMap<String, JsonValue>,
    pub codelists: BTreeMap<String, Codelist>,
    pub fixtures: BTreeMap<String, YamlValue>,
    pub active_public_jwk: PublicJwk,
    pub published_public_jwks: BTreeMap<String, PublicJwk>,
}

/// One captured operator runtime configuration and its bound trust anchors.
///
/// Secret values and audit contents are deliberately not captured. The
/// runtime digest covers the reviewed runtime YAML, the private-CA bytes, and
/// the digest of every process-local extract the document binds.
#[derive(Debug, Clone)]
pub struct RuntimeDocument {
    path: PathBuf,
    pub config: RuntimeConfig,
    revision: String,
    bytes: Vec<u8>,
    pub ca_bundles: BTreeMap<String, Vec<u8>>,
    pub source_extracts: BTreeMap<String, SourceExtract>,
}

/// One validated process-local extract file, bound to a logical name.
///
/// The bytes stay on disk. A CA bundle is kilobytes and is captured whole; an
/// extract is sized for a register, so what travels is the path this validated,
/// the digest taken over it while that validation still held, and the file
/// identity both were taken over.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SourceExtract {
    path: PathBuf,
    digest: String,
    identity: FileIdentity,
}

/// The identity a capture was taken over, kept so a later opener can prove it
/// opened the file that was validated.
///
/// It holds the metadata rather than a copy of the fields [`same_file`]
/// compares, so the two cannot drift apart: whatever identity a read brackets
/// itself with is the identity a reopen is held to.
#[derive(Debug, Clone)]
struct FileIdentity(Metadata);

impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        same_file(&self.0, &other.0)
    }
}

impl Eq for FileIdentity {}

impl SourceExtract {
    /// The validated file the statement executor opens.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `sha256:` and lowercase hex over the extract's bytes, as they were read.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Prove the bound path still names the file this validated and digested.
    ///
    /// The statement executor opens the extract by path, and it opens it after
    /// the bundle is read, the kernel is compiled, and the audit log is
    /// initialized. A publisher refreshing the bound path inside that window
    /// would hand SQLite a file that passed none of the checks above: not the
    /// symlink refusal, not the regular-file refusal, and not the writability
    /// refusal that is what makes `immutable=1` a checked fact. Checking here
    /// keeps a refresh landing mid-startup a startup failure rather than a
    /// deployment answering from bytes its runtime revision does not name.
    ///
    /// Narrowing rather than proof: a path renamed away and back inside the
    /// window still passes, and anyone who can write the containing directory
    /// can do worse than this. The case it settles is the one that happens.
    pub fn confirm_still_bound(&self) -> Result<(), BundleError> {
        let current = fs::symlink_metadata(&self.path).map_err(|_| {
            invalid_artifact("the source extract the runtime file names is unavailable")
        })?;
        if current.file_type().is_symlink()
            || !current.is_file()
            || FileIdentity(current) != self.identity
        {
            return Err(not_immutable(
                "the source extract was replaced between digesting it and opening it",
            ));
        }
        Ok(())
    }
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

        let mut source_extracts = BTreeMap::new();
        for (profile, binding) in config.source_extracts.iter() {
            let extract = capture_source_extract(Path::new(&binding.path))
                .map_err(|error| error.in_artifact(&source_extract_artifact(profile)))?;
            source_extracts.insert(profile.to_owned(), extract);
        }
        let revision = compute_runtime_revision(&bytes, &ca_bundles, &source_extracts)?;
        Ok(Self {
            path: path.to_path_buf(),
            config,
            revision,
            bytes,
            ca_bundles,
            source_extracts,
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
        validate_prior_fact_bindings(&config, &fact_schemas)?;
        let codelists = load_codelists(&config, &files)?;
        validate_codelist_references(&config, &codelists)?;
        let fixtures = load_fixtures(&config, &files)?;
        let (active_public_jwk, published_public_jwks) = load_public_jwks(&config, &files)?;
        let revision = compute_revision(&files)?;
        let requirement_revisions = compute_requirement_revisions(&config, &files)?;

        Ok(Self {
            root: root.to_path_buf(),
            config,
            revision,
            requirement_revisions,
            files,
            scripts,
            fact_schemas,
            codelists,
            fixtures,
            active_public_jwk,
            published_public_jwks,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The configuration revision an assertion for one requirement carries.
    ///
    /// It covers this requirement's own closure: the canonical projection of the
    /// configuration it depends on, and the exact bytes of every artifact it
    /// reaches. An edit that cannot change this requirement's assertions leaves
    /// it alone, so a relying party pinning it is not broken by a deployment's
    /// unrelated work. `None` names a requirement the bundle does not configure.
    pub fn configuration_revision(&self, requirement_id: &str) -> Option<&str> {
        self.requirement_revisions
            .get(requirement_id)
            .map(String::as_str)
    }

    /// The digest of every file in the deployment bundle.
    ///
    /// This is the deployment's own identity, for audit, status, and operator
    /// diagnostics. It is not what an assertion carries: see
    /// [`Bundle::configuration_revision`].
    pub fn revision(&self) -> &str {
        &self.revision
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
    // A statement is reviewed, bounded, executable text, so it is bounded like
    // the other executable artifacts rather than like a data file.
    if path.starts_with("adapters/")
        || path.starts_with("derivations/")
        || path.starts_with("queries/")
    {
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
    confirm_unchanged(
        &opened,
        &after,
        u64::try_from(bytes.len()).map_err(|_| BundleError::TooLarge)?,
        "the file changed while it was being read",
    )?;
    Ok(bytes)
}

/// The diagnostic name for one extract the runtime document binds.
///
/// The profile is a closed local identifier that both the bundle grammar and
/// the runtime grammar validate before anything here runs, so it is a
/// structural name rather than a document value and is safe to print. The file
/// bound to it is an operator path and never appears.
fn source_extract_artifact(profile: &str) -> String {
    format!("sourceExtracts/{profile}")
}

/// Validate and digest one process-local extract the runtime document names.
///
/// This is the capture [`RuntimeDocument::load`] performs for a CA bundle with
/// the bytes left on disk, and each way the file can be unusable carries its
/// own cause: an operator holding a deployment that will not start needs to
/// know whether the file is absent, indirect, of the wrong kind, or writable,
/// and those are four different pieces of work.
fn capture_source_extract(path: &Path) -> Result<SourceExtract, BundleError> {
    let unavailable = invalid_artifact("the source extract the runtime file names is unavailable");
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable.clone())?;
    if metadata.file_type().is_symlink() {
        return Err(invalid_artifact(
            "the source extract the runtime file names is a symbolic link",
        ));
    }
    if !metadata.is_file() {
        return Err(invalid_artifact(
            "the source extract the runtime file names is not a regular file",
        ));
    }
    let filesystem_read_only = filesystem_is_read_only(path).map_err(|_| unavailable)?;
    // Not hygiene. The statement executor opens this file `mode=ro` with
    // `immutable=1`, which promises SQLite that no other connection can change
    // it. A file that is still writable makes that promise false, and an
    // immutable connection over a file that changes is undefined behaviour
    // rather than a stale read. Dropping this check would move that undefined
    // behaviour into every assertion the deployment answers.
    validate_read_only(
        &metadata,
        filesystem_read_only,
        "the source extract the runtime file names is writable",
    )?;
    refuse_uncheckpointed_sidecars(path)?;
    let (digest, identity) = digest_stable_file(path, &metadata, filesystem_read_only)?;
    Ok(SourceExtract {
        path: path.to_path_buf(),
        digest,
        identity,
    })
}

/// The files SQLite writes beside a database and reads back to complete it.
///
/// A `-shm` is deliberately absent. It is shared memory rather than content,
/// and one can survive a clean checkpoint and close, so its presence says
/// nothing about whether the snapshot is whole.
const EXTRACT_SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-journal"];

/// Refuse an extract published with the sidecar that completes it.
///
/// `immutable=1` tells SQLite to skip change detection, and skipping change
/// detection also skips these files. A `-wal` holding committed frames is read
/// straight past, so the deployment answers from the last checkpoint while
/// every other reader of the same file sees newer rows. A `-journal` left by a
/// writer that died mid-transaction is worse: an ordinary read-only opener
/// refuses such a file because it cannot perform the rollback, while an
/// immutable opener reads the rows that transaction never committed as though
/// they were authoritative.
///
/// An extract is a published snapshot, so a sidecar is a publishing mistake
/// rather than a state to interpret, and this makes it a startup refusal
/// instead of a silent one. It detects that mistake rather than preventing it:
/// a sidecar appearing after this check belongs to the deployment's own
/// guarantee that nothing else changes the mounted file, and a publisher who
/// copies only the main file out of a live database leaves no sidecar to find.
fn refuse_uncheckpointed_sidecars(path: &Path) -> Result<(), BundleError> {
    for suffix in EXTRACT_SIDECAR_SUFFIXES {
        let mut sidecar = path.to_path_buf().into_os_string();
        sidecar.push(suffix);
        if fs::symlink_metadata(PathBuf::from(sidecar)).is_ok() {
            return Err(invalid_artifact(
                "the source extract the runtime file names has an uncheckpointed sidecar",
            ));
        }
    }
    Ok(())
}

/// Digest one file without holding it in memory.
///
/// [`read_stable_file`]'s identity discipline over a file too large to
/// capture: the bytes are folded into the digest in bounded chunks, and the
/// same before-and-after identity checks bracket the read, so the file
/// identity that was validated is the file identity that was hashed. There is
/// no byte cap, because an extract is a register rather than an artifact.
fn digest_stable_file(
    path: &Path,
    scanned: &Metadata,
    filesystem_read_only: bool,
) -> Result<(String, FileIdentity), BundleError> {
    let mut file = open_no_follow(path)?;
    let opened = file.metadata().map_err(|_| BundleError::Unavailable)?;
    validate_read_only(
        &opened,
        filesystem_read_only,
        "the source extract the runtime file names is writable",
    )?;
    if !opened.is_file() || !same_file(scanned, &opened) {
        return Err(not_immutable(
            "the source extract was replaced between naming it and opening it",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; EXTRACT_DIGEST_CHUNK_BYTES];
    let mut folded = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| BundleError::Unavailable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        folded = folded
            .checked_add(u64::try_from(read).map_err(|_| BundleError::TooLarge)?)
            .ok_or(BundleError::TooLarge)?;
    }
    let after = file.metadata().map_err(|_| BundleError::Unavailable)?;
    confirm_unchanged(
        &opened,
        &after,
        folded,
        "the source extract changed while it was being read",
    )?;
    // The identity that travels out is the one the read bracketed itself with,
    // not the one the caller scanned, so a later reopen is held to the file
    // these bytes actually came from.
    Ok((sha256_label(hasher)?, FileIdentity(opened)))
}

/// The closing half of a read's identity bracket.
///
/// The file that was open when the read started must still be the file that is
/// open now, and the byte count folded in must be the byte count the file
/// still reports. Both readers close their bracket here, so neither can drift
/// from the other on the property that makes a capture trustworthy.
fn confirm_unchanged(
    opened: &Metadata,
    after: &Metadata,
    folded: u64,
    cause: &'static str,
) -> Result<(), BundleError> {
    if same_file(opened, after) && after.len() == folded {
        Ok(())
    } else {
        Err(not_immutable(cause))
    }
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
        expected.extend(source_artifact_paths(source));
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
    expected.insert(config.signing.active_public_jwk_file.as_str().to_owned());
    for path in &config.signing.published_public_jwk_files {
        expected.insert(path.as_str().to_owned());
    }
    expected.extend(reviewed_schema_paths(all_concepts(config), files)?);
    expected.extend(reviewed_bucket_codelist_paths(all_concepts(config), files)?);
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

/// Every bundle artifact one source references, whatever its transport.
///
/// A transport that declares no request preparation, no adapter parameters, or
/// no statement contributes nothing for that role rather than a placeholder,
/// so bundle closure stays exact in both directions.
fn source_artifact_paths(source: &crate::config::SourceConfig) -> Vec<String> {
    [
        source.statement(),
        source.prepare_script(),
        Some(source.extract_script()),
        source.adapter_parameters_schema(),
        Some(source.response_schema()),
        Some(source.fact_schema()),
    ]
    .into_iter()
    .flatten()
    .map(|path| path.as_str().to_owned())
    .collect()
}

/// Every concept the configuration declares, in configuration order.
fn all_concepts(config: &EvidenceConfig) -> impl Iterator<Item = &ConceptConfig> {
    config
        .requirements
        .iter()
        .flat_map(|requirement| &requirement.concepts)
}

fn reviewed_bucket_codelist_paths<'a>(
    concepts: impl Iterator<Item = &'a ConceptConfig>,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeSet<String>, BundleError> {
    let declarations = concepts
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

fn reviewed_schema_paths<'a>(
    concepts: impl Iterator<Item = &'a ConceptConfig>,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeSet<String>, BundleError> {
    let identifiers = concepts
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
        if let Some(prepare_script) = source.prepare_script() {
            insert_script_contract(&mut expected, prepare_script.as_str(), ("prepare", 2))?;
        }
        insert_script_contract(
            &mut expected,
            source.extract_script().as_str(),
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
        .filter_map(|(_, source)| source.adapter_parameters_schema())
        .map(|schema| schema.as_str())
        .collect::<BTreeSet<_>>();
    let response_paths = config
        .sources
        .iter()
        .map(|(_, source)| source.response_schema().as_str())
        .collect::<BTreeSet<_>>();
    let mut paths = config
        .sources
        .iter()
        .flat_map(|(_, source)| {
            [
                Some(source.fact_schema()),
                Some(source.response_schema()),
                source.adapter_parameters_schema(),
            ]
        })
        .flatten()
        .map(|schema| schema.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    paths.extend(reviewed_schema_paths(all_concepts(config), files)?);
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
        let schema_path = source
            .adapter_parameters_schema()
            .map_or(CONFIG_FILE, |schema| schema.as_str());
        validate_adapter_parameters(source, &schemas)
            .map_err(|error| error.in_artifact(schema_path))?;
    }
    Ok(schemas)
}

/// Prove at startup that every Rust-owned fetch path binding can be filled by
/// the exact search fact schema that precedes it. Fact schemas require their
/// complete closed property set, so a declared scalar property exists on every
/// validated search match.
fn validate_prior_fact_bindings(
    config: &EvidenceConfig,
    schemas: &BTreeMap<String, JsonValue>,
) -> Result<(), BundleError> {
    for requirement in &config.requirements {
        // Exhaustive on purpose: a new acquisition form must state how its
        // prior-fact bindings are proven, and refusing the bundle is the only
        // safe answer until it does.
        match &requirement.acquisition {
            crate::config::AcquisitionConfig::Single { .. } => {}
            crate::config::AcquisitionConfig::SearchThenFetch { search, fetch } => {
                let search_source = config
                    .sources
                    .get(search)
                    .ok_or(invalid_artifact("search source is unavailable"))?;
                let fetch_source = config
                    .sources
                    .get(fetch)
                    .ok_or(invalid_artifact("fetch source is unavailable"))?;
                let search_schema = schemas
                    .get(search_source.fact_schema().as_str())
                    .and_then(JsonValue::as_object)
                    .and_then(|schema| schema.get("properties"))
                    .and_then(JsonValue::as_object)
                    .ok_or(invalid_artifact("search fact schema is unavailable"))?;
                // Version 1 froze this form on the single fetch receiving the
                // whole search FactSet, so every declared search fact is
                // bindable and there is no allowlist to narrow it.
                validate_bound_prior_facts(fetch_source, search_schema, None)?;
            }
            crate::config::AcquisitionConfig::SearchThenFetchSet { search, fetch, .. } => {
                validate_fetch_set_fact_schemas(config, schemas, search, fetch)?;
            }
        }
    }
    Ok(())
}

/// Prove every prior-fact path binding one source declares names a search fact
/// it may read, and one the search carries as a scalar.
///
/// `declared` is the member's own allowlist, and `None` is the frozen
/// `search-then-fetch` reading where the single fetch receives every search
/// fact. A path binding is one of two channels a prior fact can leave through:
/// the other is the JSON body the source's own `prepare` script builds, which
/// no static check reads and which the allowlist projection bounds instead.
fn validate_bound_prior_facts(
    fetch_source: &crate::config::SourceConfig,
    search_properties: &JsonMap<String, JsonValue>,
    declared: Option<&BTreeSet<&str>>,
) -> Result<(), BundleError> {
    for field in fetch_source.prior_fact_bindings() {
        if declared.is_some_and(|allowlist| !allowlist.contains(field)) {
            return Err(invalid_artifact(
                "fetch path binding references a fact the member did not declare",
            ));
        }
        let property = search_properties
            .get(field)
            .and_then(JsonValue::as_object)
            .ok_or(invalid_artifact(
                "fetch path binding references an unknown search fact",
            ))?;
        let scalar_type = property
            .get("type")
            .and_then(JsonValue::as_str)
            .is_some_and(|value| matches!(value, "string" | "integer" | "boolean"));
        let scalar_const = property
            .get("const")
            .is_some_and(|value| value.is_string() || value.is_i64() || value.is_boolean());
        if !scalar_type && !scalar_const {
            return Err(invalid_artifact(
                "fetch path binding requires a scalar search fact",
            ));
        }
    }
    Ok(())
}

/// The fact names one acquisition stage contributes to the derivation.
struct StageFacts<'a> {
    /// Every name the stage may contribute, which is what a merge collides on.
    properties: &'a JsonMap<String, JsonValue>,
    /// The subset a validated match always fills, which is what a later stage
    /// may read and what the merged set actually counts.
    required: BTreeSet<&'a str>,
}

fn stage_facts<'a>(
    schemas: &'a BTreeMap<String, JsonValue>,
    source: &crate::config::SourceConfig,
    unavailable: &'static str,
) -> Result<StageFacts<'a>, BundleError> {
    let schema = schemas
        .get(source.fact_schema().as_str())
        .and_then(JsonValue::as_object)
        .ok_or(invalid_artifact(unavailable))?;
    let properties = schema
        .get("properties")
        .and_then(JsonValue::as_object)
        .ok_or(invalid_artifact(unavailable))?;
    let required = schema
        .get("required")
        .and_then(JsonValue::as_array)
        .map(|fields| fields.iter().filter_map(JsonValue::as_str).collect())
        .ok_or(invalid_artifact(unavailable))?;
    Ok(StageFacts {
        properties,
        required,
    })
}

/// Prove one fetch set hands its derivation a well-formed merged fact set.
///
/// Each member reads a closed allowlist of the search FactSet and produces a
/// FactSet of its own, and the derivation receives all of them merged. That
/// leaves three things the runtime could not recover once acquisition has
/// started, so the bundle proves them here: every allowlisted name is a fact
/// the search always fills, no two stages claim one fact name, and the merged
/// set stays inside the bound a derivation accepts.
fn validate_fetch_set_fact_schemas(
    config: &EvidenceConfig,
    schemas: &BTreeMap<String, JsonValue>,
    search: &str,
    members: &[crate::config::FetchSetMember],
) -> Result<(), BundleError> {
    let search_source = config
        .sources
        .get(search)
        .ok_or(invalid_artifact("search source is unavailable"))?;
    let search_facts = stage_facts(schemas, search_source, "search fact schema is unavailable")?;
    let mut merged = search_facts
        .properties
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut required_facts = search_facts.required.len();

    for member in members {
        let member_source = config
            .sources
            .get(&member.source)
            .ok_or(invalid_artifact("fetch source is unavailable"))?;
        let member_facts = stage_facts(
            schemas,
            member_source,
            "fetch member fact schema is unavailable",
        )?;

        // An allowlisted name a validated search match might not carry would
        // reach the member as an absent input rather than as a refusal.
        for input in &member.fact_inputs {
            if !search_facts.required.contains(input.as_str()) {
                return Err(invalid_artifact(
                    "fetch member fact input is not a required search fact",
                ));
            }
        }
        // Two stages naming one fact would overwrite silently in the merge, so
        // the collision is refused rather than resolved by declaration order.
        for name in member_facts.properties.keys() {
            if !merged.insert(name.as_str()) {
                return Err(invalid_artifact(
                    "fetch set stages must declare disjoint fact names",
                ));
            }
        }
        required_facts = required_facts.saturating_add(member_facts.required.len());

        let allowlist = member
            .fact_inputs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        validate_bound_prior_facts(member_source, search_facts.properties, Some(&allowlist))?;
    }

    // Disjoint names make this sum the exact size of the merged fact set, so
    // reading it here is what keeps the derivation's own input bound from
    // refusing an otherwise valid request at acquisition time.
    if required_facts > crate::rhai_runtime::MAXIMUM_FACT_ENTRIES {
        return Err(invalid_artifact(
            "fetch set declares more facts than one derivation accepts",
        ));
    }
    Ok(())
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
    let Some(schema_path) = source.adapter_parameters_schema() else {
        // A source that declares no schema for adapter parameters may declare
        // no adapter parameters either, which the configuration has proven.
        return source
            .adapter_parameters()
            .is_empty()
            .then_some(())
            .ok_or(invalid_artifact("missing adapter-parameter schema"));
    };
    let schema = schemas
        .get(schema_path.as_str())
        .ok_or(invalid_artifact("missing adapter-parameter schema"))?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .should_validate_formats(true)
        .compile(schema)
        .map_err(|_| invalid_artifact("adapter-parameter schema is not valid JSON Schema"))?;
    let parameters = serde_json::to_value(source.adapter_parameters())
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
    paths.extend(reviewed_bucket_codelist_paths(all_concepts(config), files)?);
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

fn load_public_jwks(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(PublicJwk, BTreeMap<String, PublicJwk>), BundleError> {
    let active_path = config.signing.active_public_jwk_file.as_str();
    let active = files
        .get(active_path)
        .ok_or(invalid_artifact("active public JWK is missing"))
        .and_then(|bytes| parse_service_public_jwk(bytes))
        .map_err(|error| error.in_artifact(active_path))?;
    let active_kid = active
        .kid
        .as_deref()
        .ok_or(invalid_artifact("active public JWK kid is missing"))?;
    validate_public_jwk_path(active_path, active_kid)
        .map_err(|error| error.in_artifact(active_path))?;
    if config
        .signing
        .revoked_key_ids
        .iter()
        .any(|kid| kid == active_kid)
    {
        return Err(invalid_artifact("active public JWK is revoked").in_artifact(active_path));
    }

    let mut keys = BTreeMap::new();
    for path in &config.signing.published_public_jwk_files {
        let path = path.as_str();
        let load = || -> Result<(String, PublicJwk), BundleError> {
            let bytes = files
                .get(path)
                .ok_or(invalid_artifact("published public JWK is missing"))?;
            let jwk = parse_service_public_jwk(bytes)?;
            let kid = jwk
                .kid
                .as_deref()
                .ok_or(invalid_artifact("published public JWK kid is missing"))?
                .to_owned();
            validate_public_jwk_path(path, &kid)?;
            if kid == active_kid {
                return Err(invalid_artifact(
                    "published public JWK duplicates the active key",
                ));
            }
            if config
                .signing
                .revoked_key_ids
                .iter()
                .any(|revoked| revoked == &kid)
            {
                return Err(invalid_artifact("published public JWK is revoked"));
            }
            Ok((kid, jwk))
        };
        let (kid, jwk) = load().map_err(|error| error.in_artifact(path))?;
        if keys.insert(kid, jwk).is_some() {
            return Err(
                invalid_artifact("published public JWK kid is duplicated").in_artifact(path)
            );
        }
    }
    Ok((active, keys))
}

fn validate_public_jwk_path(path: &str, kid: &str) -> Result<(), BundleError> {
    let expected = format!("public-keys/{kid}.jwk.json");
    if path != expected {
        return Err(invalid_artifact(
            "public JWK filename does not match its RFC 7638 thumbprint",
        ));
    }
    Ok(())
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

fn parse_service_public_jwk(bytes: &[u8]) -> Result<PublicJwk, BundleError> {
    const EXACT_MEMBERS: [&str; 6] = ["kty", "crv", "x", "y", "alg", "kid"];
    let object = parse_strict_json_object(bytes)?;
    if object.len() != EXACT_MEMBERS.len()
        || object
            .keys()
            .any(|member| !EXACT_MEMBERS.contains(&member.as_str()))
    {
        return Err(invalid_artifact("service public JWK members are not exact"));
    }
    let json = serde_json::to_string(&object)
        .map_err(|_| invalid_artifact("service public JWK JSON is invalid"))?;
    let jwk =
        PublicJwk::parse(&json).map_err(|_| invalid_artifact("service public JWK is invalid"))?;
    if jwk.algorithm().ok() != Some(ProviderSigningAlgorithm::Es256)
        || jwk.kty != "EC"
        || jwk.crv.as_deref() != Some("P-256")
        || jwk.alg.as_deref() != Some("ES256")
    {
        return Err(invalid_artifact("service public JWK must be ES256 P-256"));
    }
    let thumbprint = jwk
        .jkt()
        .map_err(|_| invalid_artifact("service public JWK thumbprint is invalid"))?;
    if thumbprint.len() != 43 || jwk.kid.as_deref() != Some(thumbprint.as_str()) {
        return Err(invalid_artifact(
            "service public JWK kid must equal its RFC 7638 thumbprint",
        ));
    }
    Ok(jwk)
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
    let signer_matches_assurance = match bundle.assurance_profile {
        crate::config::AssuranceProfile::Local => runtime.signer.is_local_jwk(),
        crate::config::AssuranceProfile::Production
        | crate::config::AssuranceProfile::EvidenceGrade => runtime.signer.is_transit(),
    };
    if !signer_matches_assurance {
        return Err(invalid_artifact(
            "runtime signer kind does not match the bundle assurance profile",
        ));
    }
    let audit_ref = &bundle.audit.hash_secret_ref;
    let subject_ref = &bundle.subject_binding.secret_ref;
    if let Some(signing_ref) = runtime.signer.private_key_ref() {
        if signing_ref == audit_ref || signing_ref == subject_ref {
            return Err(invalid_artifact(
                "the local signing key reference must be distinct from audit and subject-binding references",
            ));
        }
    }
    let secret_root = Path::new(&runtime.secret_providers.file.root);
    let audit_path = Path::new(&runtime.audit_storage.path);
    let configured_secret_paths = [
        Some(audit_ref),
        Some(subject_ref),
        runtime.signer.private_key_ref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|reference| reference.as_str().strip_prefix("secret:file/"))
    .map(|name| secret_root.join(name));
    if configured_secret_paths
        .into_iter()
        .any(|path| path == audit_path)
    {
        return Err(invalid_artifact(
            "the audit storage path must not resolve to configured secret material",
        ));
    }
    // The binding is exact in both directions, but the two directions are
    // different repairs in different files: a profile the bundle names and the
    // runtime does not bind is missing trust material the deployment must add,
    // while a profile the runtime binds that no source names is trust the
    // deployment grants nobody asked for. One cause covering both leaves the
    // operator to diff the two files by hand to learn which way round it went.
    let required = bundle
        .sources
        .iter()
        .filter_map(|(_, source)| source.tls_trust_profile())
        .collect::<BTreeSet<_>>();
    let configured = runtime
        .outbound_tls
        .trust_profiles
        .keys()
        .collect::<BTreeSet<_>>();
    if let Some(unbound) = required.difference(&configured).next() {
        return Err(trust_profile_fault(
            unbound,
            "the runtime configuration does not bind a TLS trust profile a bundle source names",
        ));
    }
    if let Some(unused) = configured.difference(&required).next() {
        return Err(trust_profile_fault(
            unused,
            "the runtime configuration binds a TLS trust profile no bundle source names",
        ));
    }
    // Extracts bind exactly, in both directions, and each direction says which
    // profile is at fault. An unbound profile is a deployment that cannot
    // answer; a profile nothing names is a file the operator believes is in
    // use and is not. The remedies differ, so the diagnostics do too.
    let named_extracts = bundle
        .sources
        .iter()
        .filter_map(|(_, source)| source.extract_profile())
        .collect::<BTreeSet<_>>();
    let bound_extracts = runtime.source_extracts.keys().collect::<BTreeSet<_>>();
    if let Some(unbound) = named_extracts.difference(&bound_extracts).next() {
        return Err(invalid_artifact(
            "the runtime configuration binds no file for a source extract profile the bundle names",
        )
        .in_artifact(&source_extract_artifact(unbound)));
    }
    if let Some(unused) = bound_extracts.difference(&named_extracts).next() {
        return Err(invalid_artifact(
            "the runtime configuration binds a source extract profile no bundle source names",
        )
        .in_artifact(&source_extract_artifact(unused)));
    }
    // The operator half of the acquisition gate, and the half that gates.
    // A bundle declaring the kinds it needs states an intent beside the
    // requirement that uses it; the deployment decides separately whether it
    // may serve them. Silence means no, so a deployment that never heard of a
    // gated form refuses the bundle here, before it serves anything, rather
    // than acquiring from sources nobody enabled it to reach.
    for requirement in &bundle.requirements {
        if requirement
            .acquisition
            .required_capability()
            .is_some_and(|capability| !runtime.enables_acquisition_capability(capability))
        {
            return Err(invalid_artifact(
                "the runtime configuration does not enable an acquisition capability the bundle requires",
            ));
        }
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
    source_extracts: &BTreeMap<String, SourceExtract>,
) -> Result<String, BundleError> {
    let mut files = BTreeMap::from([("runtime.yaml".to_owned(), runtime_bytes.to_vec())]);
    for (profile, bytes) in ca_bundles {
        files.insert(format!("trust-profile/{profile}.pem"), bytes.clone());
    }
    // An extract enters the revision as its digest rather than its bytes. The
    // revision still covers every byte that was read, because a digest changes
    // whenever the file it was taken over changes.
    for (profile, extract) in source_extracts {
        files.insert(
            format!("source-extract/{profile}"),
            extract.digest().as_bytes().to_vec(),
        );
    }
    compute_named_revision(RUNTIME_REVISION_DOMAIN, &files)
}

fn compute_revision(files: &BTreeMap<String, Vec<u8>>) -> Result<String, BundleError> {
    compute_named_revision(REVISION_DOMAIN, files)
}

/// One configuration revision per configured requirement.
///
/// Each digest covers exactly what can change that requirement's assertions:
/// the canonical projection of the configuration it depends on, and the exact
/// bytes of every artifact it reaches. Requirements in one bundle therefore no
/// longer share a revision, so an edit that serves one of them does not
/// invalidate the revision a relying party pinned for another.
fn compute_requirement_revisions(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, String>, BundleError> {
    let mut revisions = BTreeMap::new();
    for requirement in &config.requirements {
        let mut closure = BTreeMap::from([(
            PROJECTION_PATH.to_owned(),
            canonical_projection(config, requirement)?,
        )]);
        for path in requirement_artifact_paths(config, requirement, files)? {
            // The bundle-wide closure check ran first, so a referenced artifact
            // is present. A miss here would silently shrink the digest, so it
            // fails instead.
            let bytes = files.get(&path).ok_or_else(|| {
                unknown_file(
                    &path,
                    "the requirement references an artifact the bundle does not contain",
                )
            })?;
            closure.insert(path, bytes.clone());
        }
        revisions.insert(
            requirement.id.clone(),
            compute_named_revision(REQUIREMENT_REVISION_DOMAIN, &closure)?,
        );
    }
    Ok(revisions)
}

/// Every bundle artifact one requirement reaches.
///
/// This is the bundle-wide closure of [`validate_file_closure`] restricted to
/// one requirement: its own derivation script, fixtures, concept codelists,
/// reviewed schemas and bucket codelists, the artifacts of every source its
/// bounded acquisition names, and the codelists of the selector profiles its subject roles and
/// grants use. The active and published public signing keys are deployment-wide
/// and stay in every requirement's closure, so this narrows nothing beyond
/// separating one requirement from another.
fn requirement_artifact_paths(
    config: &EvidenceConfig,
    requirement: &RequirementConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeSet<String>, BundleError> {
    let mut paths = BTreeSet::new();
    for source_id in requirement.acquisition.source_ids() {
        let source = config.sources.get(source_id).ok_or_else(|| {
            invalid_artifact("the requirement names a source the configuration does not define")
        })?;
        paths.extend(source_artifact_paths(source));
    }
    paths.insert(requirement.derivation.script.as_str().to_owned());
    if let Some(fixtures) = &requirement.fixtures {
        paths.insert(fixtures.as_str().to_owned());
    }
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
    for name in requirement_selector_profiles(config, requirement) {
        let profile = config.selector_profiles.get(&name).ok_or_else(|| {
            invalid_artifact(
                "the requirement names a selector profile the configuration does not define",
            )
        })?;
        for (_, field) in profile.fields.iter() {
            if let SelectorField::ControlledCode { codelist, .. } = field {
                paths.insert(codelist.as_str().to_owned());
            }
        }
    }
    paths.insert(config.signing.active_public_jwk_file.as_str().to_owned());
    for path in &config.signing.published_public_jwk_files {
        paths.insert(path.as_str().to_owned());
    }
    paths.extend(reviewed_schema_paths(requirement.concepts.iter(), files)?);
    paths.extend(reviewed_bucket_codelist_paths(
        requirement.concepts.iter(),
        files,
    )?);
    Ok(paths)
}

/// The selector profiles one requirement can be served through: those its
/// subject roles declare, and those a grant for it names.
fn requirement_selector_profiles(
    config: &EvidenceConfig,
    requirement: &RequirementConfig,
) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = requirement
        .subject_roles
        .iter()
        .flat_map(|role| role.selector_profiles.iter().cloned())
        .collect();
    for (_, profile) in config.authority_profiles.iter() {
        for grant in &profile.grants {
            if grant.requirement == requirement.id {
                names.extend(
                    grant
                        .subjects
                        .iter()
                        .map(|subject| subject.selector_profile.clone()),
                );
            }
        }
    }
    names
}

/// The configuration one requirement depends on, in the canonical form its
/// revision digest covers.
///
/// The projection starts from the complete parsed configuration and replaces
/// only the four members that hold per-requirement configuration, keeping this
/// requirement's own entries: the requirement itself, every source its bounded
/// acquisition names, the selector profiles it can be served through, and the authority
/// grants that offer it. Every other member is kept exactly as configured, so a
/// configuration member added later is covered without revisiting this
/// projection.
///
/// Starting from the parsed configuration rather than the file bytes is what
/// makes the projection possible at all, and it is faithful because the
/// configuration types reject an unknown member: nothing in the reviewed file
/// can be dropped by parsing it. Comments and formatting are not covered,
/// because neither can change an assertion.
fn canonical_projection(
    config: &EvidenceConfig,
    requirement: &RequirementConfig,
) -> Result<Vec<u8>, BundleError> {
    let mut document = serde_json::to_value(config)
        .map_err(|_| invalid_artifact("the configuration does not project"))?;
    let members = document
        .as_object_mut()
        .ok_or_else(|| invalid_artifact("the configuration does not project as a mapping"))?;
    let requirement_value = serde_json::to_value(requirement)
        .map_err(|_| invalid_artifact("the requirement does not project"))?;
    members.insert(
        "requirements".to_owned(),
        JsonValue::Array(vec![requirement_value]),
    );
    let profiles = requirement_selector_profiles(config, requirement);
    let acquisition_sources = requirement
        .acquisition
        .source_ids()
        .into_iter()
        .collect::<BTreeSet<_>>();
    retain_members(members, "sources", |name| {
        acquisition_sources.contains(name)
    })?;
    retain_members(members, "selectorProfiles", |name| profiles.contains(name))?;
    retain_acquisition_capability(members, requirement)?;
    preserve_selector_field_order(members, config, &profiles)?;
    project_authority_profiles(members, &requirement.id)?;
    // RFC 8785 canonicalization, shared with the rest of the stack, makes
    // order-insensitive mappings and number formatting deterministic. The one
    // mapping whose declaration order changes assertion bytes is projected as
    // a sequence first, so canonicalization cannot erase that distinction.
    canonicalize_json(&document)
        .map_err(|_| invalid_artifact("the projection does not canonicalize"))
}

/// Keep only the acquisition capability this requirement's own form needs.
///
/// The declaration is bundle-wide but it gates one requirement at a time: a
/// requirement acquiring through a frozen Version 1 form behaves identically
/// whether or not some other requirement in the same bundle opted in to a
/// gated form. Projecting the whole list would make it behave otherwise, and
/// adopting a gated form for one requirement would move the revision every
/// relying party pinned for all the others. An empty projection drops the
/// member, so a bundle that adopts nothing projects exactly as it did before
/// the declaration existed.
fn retain_acquisition_capability(
    members: &mut JsonMap<String, JsonValue>,
    requirement: &RequirementConfig,
) -> Result<(), BundleError> {
    if !members.contains_key(ACQUISITION_CAPABILITIES) {
        return Ok(());
    }
    let declared = members
        .get_mut(ACQUISITION_CAPABILITIES)
        .and_then(JsonValue::as_array_mut)
        .ok_or_else(|| {
            invalid_artifact("the acquisition capabilities do not project as a sequence")
        })?;
    let required = requirement.acquisition.required_capability();
    declared.retain(|capability| capability.as_str() == required);
    if declared.is_empty() {
        members.remove(ACQUISITION_CAPABILITIES);
    }
    Ok(())
}

/// Keep only the named members of one projected configuration mapping.
fn retain_members(
    members: &mut JsonMap<String, JsonValue>,
    member: &str,
    keep: impl Fn(&str) -> bool,
) -> Result<(), BundleError> {
    let mapping = members
        .get_mut(member)
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| invalid_artifact("the configuration does not project as a mapping"))?;
    mapping.retain(|name, _| keep(name));
    Ok(())
}

/// Preserve the declaration order that defines canonical selector encoding.
///
/// `OrderedMap` serializes as a JSON object, whose member order RFC 8785
/// deliberately erases. Selector field order is not presentation: it orders
/// the normalized values used by subject binding. Project each retained field
/// mapping as `[name, value]` pairs before canonicalization so a reorder moves
/// the revision with the assertion behavior it protects.
fn preserve_selector_field_order(
    members: &mut JsonMap<String, JsonValue>,
    config: &EvidenceConfig,
    retained_profiles: &BTreeSet<String>,
) -> Result<(), BundleError> {
    let projected_profiles = members
        .get_mut("selectorProfiles")
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| invalid_artifact("the selector profiles do not project as a mapping"))?;
    for name in retained_profiles {
        let configured = config
            .selector_profiles
            .get(name)
            .ok_or_else(|| invalid_artifact("a retained selector profile is not configured"))?;
        let projected = projected_profiles
            .get_mut(name)
            .and_then(JsonValue::as_object_mut)
            .ok_or_else(|| invalid_artifact("a selector profile does not project as a mapping"))?;
        let fields = configured
            .fields
            .iter()
            .map(|(field_name, field)| {
                serde_json::to_value(field)
                    .map(|value| {
                        JsonValue::Array(vec![JsonValue::String(field_name.to_owned()), value])
                    })
                    .map_err(|_| invalid_artifact("a selector field does not project"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        projected.insert("fields".to_owned(), JsonValue::Array(fields));
    }
    Ok(())
}

/// Keep only the grants that offer one requirement, and only the authority
/// profiles left holding at least one of them.
fn project_authority_profiles(
    members: &mut JsonMap<String, JsonValue>,
    requirement_id: &str,
) -> Result<(), BundleError> {
    let profiles = members
        .get_mut("authorityProfiles")
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| invalid_artifact("the configuration does not project as a mapping"))?;
    for (_, profile) in profiles.iter_mut() {
        let grants = profile
            .get_mut("grants")
            .and_then(JsonValue::as_array_mut)
            .ok_or_else(|| invalid_artifact("an authority profile does not project"))?;
        grants.retain(|grant| {
            grant.get("requirement").and_then(JsonValue::as_str) == Some(requirement_id)
        });
    }
    profiles.retain(|_, profile| {
        profile
            .get("grants")
            .and_then(JsonValue::as_array)
            .is_some_and(|grants| !grants.is_empty())
    });
    Ok(())
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
    sha256_label(hasher)
}

/// A finished digest in the form every revision and extract carries: the
/// `sha256:` label and lowercase hexadecimal.
fn sha256_label(hasher: Sha256) -> Result<String, BundleError> {
    let digest = hasher.finalize();
    let mut label = String::with_capacity("sha256:".len() + 64);
    label.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut label, "{byte:02x}").map_err(|_| BundleError::TooLarge)?;
    }
    Ok(label)
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

    /// The revision every configured requirement carries, keyed by requirement.
    #[cfg(unix)]
    fn requirement_revisions(root: &Path) -> BTreeMap<String, String> {
        let bundle = Bundle::load(root).expect("the acceptance bundle loads");
        bundle
            .config
            .requirements
            .iter()
            .map(|requirement| {
                (
                    requirement.id.clone(),
                    bundle
                        .configuration_revision(&requirement.id)
                        .expect("a configured requirement has a revision")
                        .to_owned(),
                )
            })
            .collect()
    }

    /// Load the multi-requirement acceptance bundle, apply one edit to its
    /// configuration or artifacts, and answer the revisions before and after.
    #[cfg(unix)]
    fn revisions_across_edit(
        edit: impl FnOnce(&Path),
    ) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("all-definitions", directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let before = requirement_revisions(directory.path());

        set_tree_mode(directory.path(), 0o755, 0o644);
        edit(directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let after = requirement_revisions(directory.path());
        (before, after)
    }

    /// The point of scoping a revision per requirement: an edit that serves one
    /// requirement leaves the revision every other relying party pinned alone.
    /// Before this, one shared bundle digest meant any byte change anywhere
    /// broke every relying party at once, with nothing but an opaque policy
    /// failure to explain it.
    #[cfg(unix)]
    #[test]
    fn an_edit_for_one_requirement_leaves_the_other_revisions_alone() {
        const EDITED: &str = "urn:example:fixture:requirement:residence-region:v1";
        let (before, after) = revisions_across_edit(|root| {
            let script = root.join("derivations/residence-region.rhai");
            let text = fs::read_to_string(&script).expect("the derivation reads");
            fs::write(&script, format!("{text}\n// reviewed again\n"))
                .expect("the derivation writes");
        });

        assert_ne!(before[EDITED], after[EDITED]);
        for (requirement, revision) in &before {
            if requirement != EDITED {
                assert_eq!(
                    revision, &after[requirement],
                    "`{requirement}` was not edited and keeps its revision"
                );
            }
        }
    }

    /// Declaring a gated acquisition capability is a bundle-wide statement that
    /// gates one requirement at a time. A requirement acquiring through a
    /// frozen Version 1 form behaves identically whether or not some sibling
    /// opted in, so its revision must not move. Without the projection keeping
    /// only the capability a requirement's own form needs, adopting a new
    /// acquisition form for one requirement would silently break the pin every
    /// other relying party holds.
    #[cfg(unix)]
    #[test]
    fn declaring_an_acquisition_capability_leaves_the_other_revisions_alone() {
        let (before, after) = revisions_across_edit(|root| {
            let config = root.join("evidence.yaml");
            let text = fs::read_to_string(&config).expect("the configuration reads");
            fs::write(
                &config,
                format!("acquisitionCapabilities: [search-then-fetch-set]\n{text}"),
            )
            .expect("the configuration writes");
        });

        assert!(!before.is_empty(), "the fixture configures requirements");
        assert_eq!(before, after);
    }

    /// The same isolation for the configuration file itself, which is the churn
    /// a whole-file digest cannot avoid: every requirement is configured in one
    /// `evidence.yaml`, so onboarding or retuning one of them used to invalidate
    /// all of them.
    #[cfg(unix)]
    #[test]
    fn a_configuration_edit_for_one_requirement_leaves_the_other_revisions_alone() {
        const EDITED: &str = "urn:example:fixture:requirement:professional-licence-status:v1";
        let (before, after) = revisions_across_edit(|root| {
            let path = root.join(CONFIG_FILE);
            let text = fs::read_to_string(&path).expect("the configuration reads");
            // The only requirement configured with this observation timezone
            // is the edited one, so the replacement cannot reach a sibling.
            assert_eq!(
                text.matches("observationTimezone: Africa/Nairobi").count(),
                1
            );
            fs::write(
                &path,
                text.replace(
                    "observationTimezone: Africa/Nairobi",
                    "observationTimezone: Africa/Accra",
                ),
            )
            .expect("the configuration writes");
        });

        assert_ne!(before[EDITED], after[EDITED]);
        for (requirement, revision) in &before {
            if requirement != EDITED {
                assert_eq!(
                    revision, &after[requirement],
                    "`{requirement}` was not edited and keeps its revision"
                );
            }
        }
    }

    /// Selector field declaration order controls normalized subject values and
    /// therefore the audience-scoped subject binding. RFC 8785 sorts object
    /// members, so the projection must preserve this order explicitly.
    #[cfg(unix)]
    #[test]
    fn selector_field_reordering_changes_the_affected_requirement_revision() {
        const EDITED: &str = "urn:example:fixture:requirement:adult-status:v1";
        let (before, after) = revisions_across_edit(|root| {
            let path = root.join(CONFIG_FILE);
            let text = fs::read_to_string(&path).expect("the configuration reads");
            let original = concat!(
                "      given_name: {type: string, minimumBytes: 1, maximumBytes: 200}\n",
                "      family_name: {type: string, minimumBytes: 1, maximumBytes: 200}\n",
                "      birth_date: {type: date}\n",
            );
            let reordered = concat!(
                "      birth_date: {type: date}\n",
                "      family_name: {type: string, minimumBytes: 1, maximumBytes: 200}\n",
                "      given_name: {type: string, minimumBytes: 1, maximumBytes: 200}\n",
            );
            assert_eq!(text.matches(original).count(), 1);
            fs::write(&path, text.replace(original, reordered)).expect("the configuration writes");
        });

        assert_ne!(before[EDITED], after[EDITED]);
        for (requirement, revision) in &before {
            if requirement != EDITED {
                assert_eq!(
                    revision, &after[requirement],
                    "`{requirement}` does not use the reordered selector profile"
                );
            }
        }
    }

    /// Isolation between requirements is the only narrowing. A deployment-wide
    /// edit still changes every requirement's revision, so nothing that can
    /// change an assertion has stopped being covered.
    #[cfg(unix)]
    #[test]
    fn a_deployment_wide_edit_changes_every_requirement_revision() {
        let (before, after) = revisions_across_edit(|root| {
            let path = root.join(CONFIG_FILE);
            let text = fs::read_to_string(&path).expect("the configuration reads");
            assert_eq!(text.matches("keyVersion: 1").count(), 1);
            fs::write(&path, text.replace("keyVersion: 1", "keyVersion: 2"))
                .expect("the configuration writes");
        });

        assert_eq!(before.len(), 4);
        for (requirement, revision) in &before {
            assert_ne!(
                revision, &after[requirement],
                "`{requirement}` depends on the edited deployment configuration"
            );
        }
    }

    /// The projection keeps every configuration member. A member it dropped
    /// would stop being covered by any revision, which is a silently narrower
    /// tripwire rather than a visible failure, so the member list is asserted
    /// against the configuration itself instead of a copy of it.
    #[cfg(unix)]
    #[test]
    fn the_projection_covers_every_configuration_member() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("all-definitions", directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let bundle = Bundle::load(directory.path()).expect("the acceptance bundle loads");

        let configured = serde_json::to_value(&bundle.config).expect("the configuration projects");
        let projected: JsonValue = serde_json::from_slice(
            &canonical_projection(&bundle.config, &bundle.config.requirements[0])
                .expect("the projection is canonical JSON"),
        )
        .expect("the projection parses");

        assert_eq!(
            projected
                .as_object()
                .expect("the projection is a mapping")
                .keys()
                .collect::<BTreeSet<_>>(),
            configured
                .as_object()
                .expect("the configuration is a mapping")
                .keys()
                .collect::<BTreeSet<_>>()
        );
        // Only the four per-requirement members are narrowed, and each keeps
        // exactly what this requirement reaches.
        assert_eq!(projected["requirements"].as_array().map(Vec::len), Some(1));
        assert_eq!(projected["sources"].as_object().map(JsonMap::len), Some(1));
        assert!(projected["sources"].get("source-a").is_some());
    }

    /// A revision must depend on the configuration alone. Canonical JSON is
    /// what keeps it independent of the member ordering a dependency happens to
    /// use, so a feature selection somewhere in the tree cannot invalidate every
    /// pinned revision without a configuration change.
    #[cfg(unix)]
    #[test]
    fn the_projection_is_already_canonical() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("all-definitions", directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let bundle = Bundle::load(directory.path()).expect("the acceptance bundle loads");

        let projection = canonical_projection(&bundle.config, &bundle.config.requirements[0])
            .expect("the projection is canonical JSON");
        let reparsed: JsonValue =
            serde_json::from_slice(&projection).expect("the projection parses");
        assert_eq!(
            canonicalize_json(&reparsed).expect("the parsed projection canonicalizes"),
            projection
        );
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
        assert!(parse_service_public_jwk(private).is_err());

        let duplicate = br#"{"kty":"OKP","kty":"OKP"}"#;
        assert!(parse_strict_json_object(duplicate).is_err());

        let control_kid = br#"{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"old\u000aidentifier","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        assert!(parse_service_public_jwk(control_kid).is_err());
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
            let revision = bundle
                .configuration_revision(&bundle.config.requirements[0].id)
                .expect("the configured requirement has a revision");
            assert!(revision.starts_with("sha256:"));
            assert_eq!(revision.len(), 71);
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

    /// The fact schema of the acceptance bundle's first source, which every
    /// rewritten acquisition below uses as its search.
    const SEARCH_FACT_SCHEMA: &str = "schemas/adult-status-facts.schema.yaml";
    const FIRST_MEMBER_FACT_SCHEMA: &str = "schemas/first-member-facts.schema.yaml";
    const SECOND_MEMBER_FACT_SCHEMA: &str = "schemas/second-member-facts.schema.yaml";

    /// One declared fetch member: the ordinary fixed request every Version 1
    /// source already is, bound to the reference the search resolved.
    const FIRST_MEMBER_SOURCE: &str = r#"  source-e:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-e-token}
    request:
      method: GET
      pathTemplate: /v1/first/{record_id}
      pathBindings:
        record_id: {from: prior-fact, field: record_id}
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/first-member-prepare.rhai
      adapterParameters: {profile: first}
      adapterParametersSchema: schemas/first-member-adapter-parameters.schema.yaml
      preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
      projection: [/total]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/first-member-response.schema.yaml
    extractScript: adapters/first-member-source.rhai
    factSchema: schemas/first-member-facts.schema.yaml
"#;

    const SECOND_MEMBER_SOURCE: &str = r#"  source-f:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-f-token}
    request:
      method: GET
      pathTemplate: /v1/second/{record_id}
      pathBindings:
        record_id: {from: prior-fact, field: record_id}
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/second-member-prepare.rhai
      adapterParameters: {profile: second}
      adapterParametersSchema: schemas/second-member-adapter-parameters.schema.yaml
      preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
      projection: [/total]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/second-member-response.schema.yaml
    extractScript: adapters/second-member-source.rhai
    factSchema: schemas/second-member-facts.schema.yaml
"#;

    const SEARCH_THEN_FETCH: &str =
        "    acquisition:\n      kind: search-then-fetch\n      search: source-a\n      fetch: source-e\n";

    /// The value-free cause one bundle refusal carries.
    fn refusal_cause(error: BundleError) -> &'static str {
        error
            .artifact_fault()
            .expect("a bundle refusal names its cause")
            .fault()
            .cause()
    }

    /// The declared member sources, followed by the acceptance bundle's own
    /// second source, which the rewrite displaced.
    fn member_sources(blocks: &[&str]) -> String {
        format!("{}  source-b:\n", blocks.concat())
    }

    /// A closed fact schema over the named fields.
    ///
    /// `required` is what a validated match always fills and `optional` is
    /// declared without being required. A source fact schema is never the
    /// second shape, which is exactly why the allowlist rule is proven against
    /// the required set rather than against the declared one.
    fn fact_schema(required: &[&str], optional: &[&str]) -> JsonValue {
        let properties = required
            .iter()
            .chain(optional)
            .map(|field| ((*field).to_owned(), serde_json::json!({"type": "string"})))
            .collect::<JsonMap<_, _>>();
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": required,
            "properties": properties,
        })
    }

    /// A closed fact schema carrying `count` required fields under one prefix,
    /// for reading the bound on the merged fact set.
    fn wide_fact_schema(prefix: &str, count: usize) -> JsonValue {
        let fields = (0..count)
            .map(|index| format!("{prefix}_{index}"))
            .collect::<Vec<_>>();
        let properties = fields
            .iter()
            .map(|field| (field.clone(), serde_json::json!({"type": "string"})))
            .collect::<JsonMap<_, _>>();
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": fields,
            "properties": properties,
        })
    }

    fn fetch_set_schemas(
        search: JsonValue,
        first: JsonValue,
        second: JsonValue,
    ) -> BTreeMap<String, JsonValue> {
        BTreeMap::from([
            (SEARCH_FACT_SCHEMA.to_owned(), search),
            (FIRST_MEMBER_FACT_SCHEMA.to_owned(), first),
            (SECOND_MEMBER_FACT_SCHEMA.to_owned(), second),
        ])
    }

    /// One acceptance bundle rewritten onto a multi-call acquisition. The
    /// rewrite parses, so the fact-schema rules under test are the only thing
    /// left that can refuse it.
    fn multi_call_config(acquisition: &str, sources: &str) -> EvidenceConfig {
        let yaml = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        let declared = yaml.replace(
            "\nselectorProfiles:\n",
            "\nacquisitionCapabilities: [search-then-fetch-set]\n\nselectorProfiles:\n",
        );
        assert_ne!(declared, yaml, "the capability declaration applies");
        let acquired = declared.replace(
            "    acquisition:\n      kind: single\n      source: source-a\n",
            acquisition,
        );
        assert_ne!(acquired, declared, "the acquisition rewrite applies");
        let with_sources = acquired.replace("  source-b:\n", sources);
        assert_ne!(with_sources, acquired, "the declared sources apply");
        EvidenceConfig::parse_yaml(with_sources.as_bytes())
            .expect("the rewritten bundle is configuration a deployment could load")
    }

    /// The declared fetch set: one search resolving a reference, and two
    /// members reading it under the allowlist each one declares.
    fn fetch_set_config(first_inputs: &str, second_inputs: &str) -> EvidenceConfig {
        multi_call_config(
            &format!(
                "    acquisition:\n      kind: search-then-fetch-set\n      search: source-a\n      fetch:\n        - {{source: source-e, factInputs: [{first_inputs}]}}\n        - {{source: source-f, factInputs: [{second_inputs}]}}\n      maximumAcquisitionMilliseconds: 8000\n"
            ),
            &member_sources(&[FIRST_MEMBER_SOURCE, SECOND_MEMBER_SOURCE]),
        )
    }

    /// A member's allowlist is the whole of what its request may read, so a
    /// name the search does not always produce is refused at load rather than
    /// becoming a silently absent input at acquisition time.
    #[test]
    fn a_fetch_member_declares_only_facts_the_search_always_produces() {
        for (allowlist, reason) in [
            ("record_id, record_absent", "a name no stage produces"),
            (
                "record_id, record_hint",
                "a name the search declares without requiring",
            ),
            ("record_id, second_status", "a name a later member produces"),
        ] {
            let config = fetch_set_config(allowlist, "record_id");
            let schemas = fetch_set_schemas(
                fact_schema(&["record_id", "record_namespace"], &["record_hint"]),
                fact_schema(&["first_status"], &[]),
                fact_schema(&["second_status"], &[]),
            );
            assert_eq!(
                refusal_cause(
                    validate_prior_fact_bindings(&config, &schemas)
                        .expect_err("the allowlist is refused")
                ),
                "fetch member fact input is not a required search fact",
                "{reason}"
            );
        }
    }

    /// The derivation receives every stage's facts merged into one map, so two
    /// stages naming one fact would silently overwrite. Disjointness is proven
    /// over every declared name, not only the required ones, because a merge
    /// cannot tell them apart.
    #[test]
    fn fetch_set_stages_declare_disjoint_fact_names() {
        let config = fetch_set_config("record_id", "record_id");
        for (first, second, reason) in [
            (
                fact_schema(&["record_id"], &[]),
                fact_schema(&["second_status"], &[]),
                "a member repeats a search fact",
            ),
            (
                fact_schema(&["first_status"], &["shared_detail"]),
                fact_schema(&["second_status"], &["shared_detail"]),
                "two members repeat one name",
            ),
        ] {
            let schemas = fetch_set_schemas(
                fact_schema(&["record_id", "record_namespace"], &[]),
                first,
                second,
            );
            assert_eq!(
                refusal_cause(
                    validate_prior_fact_bindings(&config, &schemas)
                        .expect_err("the collision is refused")
                ),
                "fetch set stages must declare disjoint fact names",
                "{reason}"
            );
        }
    }

    /// The allowlist is per member, not per acquisition: one member declaring
    /// a fact does not license another to bind it, which is the whole reason a
    /// set of members discloses less than a single fetch would.
    #[test]
    fn a_fetch_member_binds_only_the_facts_it_declared() {
        let schemas = || {
            fetch_set_schemas(
                fact_schema(&["record_id", "record_namespace"], &[]),
                fact_schema(&["first_status"], &[]),
                fact_schema(&["second_status"], &[]),
            )
        };

        // Both members bind `record_id`, and only the first declares it.
        let narrowed = fetch_set_config("record_id", "record_namespace");
        assert_eq!(
            refusal_cause(
                validate_prior_fact_bindings(&narrowed, &schemas())
                    .expect_err("a binding outside the member's own allowlist is refused")
            ),
            "fetch path binding references a fact the member did not declare"
        );

        // Declaring the bound fact is the only difference.
        let declared = fetch_set_config("record_id", "record_id, record_namespace");
        validate_prior_fact_bindings(&declared, &schemas())
            .expect("a member may bind what it declared");
    }

    /// Rule 4 makes the merged fact names disjoint, so the merged count is the
    /// sum of the stage counts exactly. Reading it at load is what keeps the
    /// derivation's own input bound from failing an otherwise valid request.
    #[test]
    fn a_fetch_set_declares_no_more_facts_than_one_derivation_accepts() {
        let config = fetch_set_config("record_id", "record_id");
        let search = || fact_schema(&["record_id", "record_namespace"], &[]);
        assert_eq!(2 + 31 + 31, crate::rhai_runtime::MAXIMUM_FACT_ENTRIES);

        let inside = fetch_set_schemas(
            search(),
            wide_fact_schema("first", 31),
            wide_fact_schema("second", 31),
        );
        validate_prior_fact_bindings(&config, &inside)
            .expect("the merged fact set reaches the bound and stays inside it");

        let beyond = fetch_set_schemas(
            search(),
            wide_fact_schema("first", 31),
            wide_fact_schema("second", 32),
        );
        assert_eq!(
            refusal_cause(
                validate_prior_fact_bindings(&config, &beyond)
                    .expect_err("one fact past the bound is refused")
            ),
            "fetch set declares more facts than one derivation accepts"
        );
    }

    /// A path binding carries one value into a request path, so a fact that is
    /// not a scalar has never been bindable. A second multi-call form does not
    /// relax it.
    #[test]
    fn a_prior_fact_binding_still_requires_a_scalar_fact() {
        let structured = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["record_id", "record_namespace"],
            "properties": {
                "record_id": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["value"],
                    "properties": {"value": {"type": "string"}},
                },
                "record_namespace": {"type": "string"},
            },
        });

        let chained = multi_call_config(SEARCH_THEN_FETCH, &member_sources(&[FIRST_MEMBER_SOURCE]));
        assert_eq!(
            refusal_cause(
                validate_prior_fact_bindings(
                    &chained,
                    &BTreeMap::from([(SEARCH_FACT_SCHEMA.to_owned(), structured.clone())]),
                )
                .expect_err("a structured search fact is not bindable")
            ),
            "fetch path binding requires a scalar search fact"
        );

        let set = fetch_set_config("record_id", "record_id");
        assert_eq!(
            refusal_cause(
                validate_prior_fact_bindings(
                    &set,
                    &fetch_set_schemas(
                        structured,
                        fact_schema(&["first_status"], &[]),
                        fact_schema(&["second_status"], &[]),
                    ),
                )
                .expect_err("a structured search fact is not bindable")
            ),
            "fetch path binding requires a scalar search fact"
        );
    }

    /// The frozen single fetch reads the whole search FactSet, so its bindings
    /// are proven against the search schema alone and against no allowlist.
    /// Admitting the set form through the same exhaustive match must leave that
    /// reading exactly where Version 1 froze it.
    #[test]
    fn search_then_fetch_bindings_are_proven_against_the_whole_search_fact_set() {
        let two_bindings = FIRST_MEMBER_SOURCE.replace(
            "      pathTemplate: /v1/first/{record_id}\n      pathBindings:\n        record_id: {from: prior-fact, field: record_id}\n",
            "      pathTemplate: /v1/first/{record_id}/{namespace}\n      pathBindings:\n        record_id: {from: prior-fact, field: record_id}\n        namespace: {from: prior-fact, field: record_namespace}\n",
        );
        assert_ne!(
            two_bindings, FIRST_MEMBER_SOURCE,
            "the second binding applies"
        );
        let config = multi_call_config(SEARCH_THEN_FETCH, &member_sources(&[&two_bindings]));

        for (search, reason) in [
            (
                fact_schema(&["record_id", "record_namespace"], &[]),
                "one fetch binds every required search fact",
            ),
            (
                fact_schema(&["record_id"], &["record_namespace"]),
                "and every declared one",
            ),
        ] {
            validate_prior_fact_bindings(
                &config,
                &BTreeMap::from([(SEARCH_FACT_SCHEMA.to_owned(), search)]),
            )
            .unwrap_or_else(|_| panic!("{reason}"));
        }

        assert_eq!(
            refusal_cause(
                validate_prior_fact_bindings(
                    &config,
                    &BTreeMap::from([(
                        SEARCH_FACT_SCHEMA.to_owned(),
                        fact_schema(&["record_id"], &[]),
                    )]),
                )
                .expect_err("a fact the search does not declare is refused")
            ),
            "fetch path binding references an unknown search fact"
        );
    }

    /// The whole set rule read together: two members, each declaring exactly
    /// the search facts it binds, over three disjoint fact schemas whose merged
    /// names stay inside the derivation's input bound.
    #[test]
    fn a_well_formed_fetch_set_satisfies_every_fact_schema_rule() {
        let config = fetch_set_config("record_id", "record_id");
        let schemas = fetch_set_schemas(
            fact_schema(&["record_id", "record_namespace"], &[]),
            fact_schema(&["first_status", "first_recorded_on"], &[]),
            fact_schema(&["second_status", "second_recorded_on"], &[]),
        );
        validate_prior_fact_bindings(&config, &schemas).expect("the declared fetch set loads");

        let mut incomplete = schemas;
        incomplete.remove(SECOND_MEMBER_FACT_SCHEMA);
        assert_eq!(
            refusal_cause(
                validate_prior_fact_bindings(&config, &incomplete)
                    .expect_err("a member without a fact schema is refused")
            ),
            "fetch member fact schema is unavailable"
        );
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
                "version: 1\nbundleDirectory: /etc/registry-evidence/bundle\nlistener:\n  bindHost: 127.0.0.1\n  port: 8080\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 65536\n  maximumConcurrentRequests: 64\n  requestTimeoutMilliseconds: 10000\n  shutdownGraceMilliseconds: 30000\nsecretProviders:\n  file: {{root: {}}}\nsigner:\n  kind: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  timeoutMilliseconds: 2000\nauditStorage:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\n  maximumFileBytes: 1073741824\noutboundTls:\n  systemRoots: true\n  trustProfiles:\n    internal-pki: {{caBundleFile: {}}}\n",
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

    /// One operator runtime document, written the way a deployment that
    /// predates the acquisition gate is written: it says nothing about
    /// acquisition capabilities, because there was nothing to say.
    const OPERATOR_RUNTIME_DOCUMENT: &str = "version: 1
bundleDirectory: /etc/registry-evidence/bundle
listener:
  bindHost: 127.0.0.1
  port: 8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  kind: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
auditStorage:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
  maximumFileBytes: 1073741824
outboundTls:
  systemRoots: true
  trustProfiles: {}
";

    /// Both halves of the acquisition gate, from inside the loader.
    ///
    /// The bundle declaring the kind it needs states that intent beside the
    /// requirement that uses it, which gates nothing: the same person wrote
    /// both lines in the same file. The deployment that will serve it decides
    /// separately, in a file the bundle author does not write, and silence
    /// there means no.
    #[test]
    fn a_gated_acquisition_kind_binds_only_where_the_operator_enabled_it() {
        let declared = fetch_set_config("record_id", "record_id");
        let silent = RuntimeConfig::parse_yaml(OPERATOR_RUNTIME_DOCUMENT.as_bytes())
            .expect("the operator runtime document parses");
        assert_eq!(
            refusal_cause(
                validate_runtime_bindings(&declared, &silent)
                    .expect_err("a silent deployment refuses the bundle")
            ),
            "the runtime configuration does not enable an acquisition capability the bundle requires"
        );

        let enabled = RuntimeConfig::parse_yaml(
            format!(
                "{OPERATOR_RUNTIME_DOCUMENT}acquisitionCapabilities: [search-then-fetch-set]\n"
            )
            .as_bytes(),
        )
        .expect("the enabled operator runtime document parses");
        validate_runtime_bindings(&declared, &enabled)
            .expect("the deployment that enabled the kind binds the bundle");

        // A bundle acquiring through the frozen Version 1 forms asks the
        // operator for nothing, so every deployment that predates the gate
        // keeps binding exactly the bundles it already bound.
        let frozen = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .expect("the acceptance bundle validates");
        validate_runtime_bindings(&frozen, &silent)
            .expect("a Version 1 bundle needs no operator capability");
    }

    /// The exact trust-profile binding can fail two ways, and the two are
    /// different edits: the runtime is missing trust material a source needs,
    /// or it carries trust material no source reaches. An operator told only
    /// that the two sets differ has to diff them by hand to learn which, so
    /// each direction states its own cause and names the profile it means.
    #[test]
    fn a_trust_profile_binding_refusal_names_its_direction_and_its_profile() {
        const ACCEPTANCE: &str = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );

        let naming = EvidenceConfig::parse_yaml(
            ACCEPTANCE
                .replace(
                    "sources:\n  source-a:\n    transport: http-json\n",
                    "sources:\n  source-a:\n    transport: http-json\n    tlsTrustProfile: internal-pki\n",
                )
                .as_bytes(),
        )
        .expect("a bundle naming a trust profile validates");
        let silent = RuntimeConfig::parse_yaml(OPERATOR_RUNTIME_DOCUMENT.as_bytes())
            .expect("the operator runtime document parses");
        let missing = validate_runtime_bindings(&naming, &silent)
            .expect_err("a profile the runtime does not bind is refused");
        let fault = missing
            .artifact_fault()
            .expect("the refusal names the profile");
        assert_eq!(fault.artifact(), "trustProfiles/internal-pki");
        assert_eq!(
            fault.fault().cause(),
            "the runtime configuration does not bind a TLS trust profile a bundle source names"
        );

        let binding = RuntimeConfig::parse_yaml(
            OPERATOR_RUNTIME_DOCUMENT
                .replace(
                    "  trustProfiles: {}\n",
                    "  trustProfiles: {internal-pki: {caBundleFile: /etc/registry-evidence/internal-pki.pem}}\n",
                )
                .as_bytes(),
        )
        .expect("a runtime binding a trust profile parses");
        validate_runtime_bindings(&naming, &binding)
            .expect("the deployment that bound the profile binds the bundle");

        let frozen = EvidenceConfig::parse_yaml(ACCEPTANCE.as_bytes())
            .expect("the acceptance bundle validates");
        let unused = validate_runtime_bindings(&frozen, &binding)
            .expect_err("a profile no source names is refused");
        let fault = unused
            .artifact_fault()
            .expect("the refusal names the profile");
        assert_eq!(fault.artifact(), "trustProfiles/internal-pki");
        assert_eq!(
            fault.fault().cause(),
            "the runtime configuration binds a TLS trust profile no bundle source names"
        );
    }

    /// New operator surface must not move the revision of a deployment that did
    /// not ask for it. The runtime revision digests the exact runtime.yaml
    /// bytes, so a file written before the acquisition gate existed keeps the
    /// revision it already published; the pinned digest is what proves the
    /// digest is still taken over those bytes and not over a serialization that
    /// grew a member. The absent list also projects to nothing, so the same
    /// deployment would keep its revision either way.
    #[test]
    fn an_absent_acquisition_capability_list_leaves_the_runtime_revision_byte_identical() {
        let revision = compute_runtime_revision(
            OPERATOR_RUNTIME_DOCUMENT.as_bytes(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .expect("the runtime revision computes");
        assert_eq!(
            revision, "sha256:1693e61df2bdad3835fefb03ca6a3990045d77e8f8468e84f68e547596039fe3",
            "an operator who adopted nothing must keep the revision they published"
        );

        let config = RuntimeConfig::parse_yaml(OPERATOR_RUNTIME_DOCUMENT.as_bytes())
            .expect("the operator runtime document parses");
        assert!(config.acquisition_capabilities.is_empty());
        assert!(
            !serde_json::to_string(&config)
                .expect("the runtime configuration projects")
                .contains("acquisitionCapabilities"),
            "an absent capability list must serialize to nothing at all"
        );

        // Recording the operator's decision is an edit to the file the digest
        // covers, so the deployment that adopted the kind says so in its
        // revision.
        let adopted = format!(
            "{OPERATOR_RUNTIME_DOCUMENT}acquisitionCapabilities: [search-then-fetch-set]\n"
        );
        assert_ne!(
            compute_runtime_revision(adopted.as_bytes(), &BTreeMap::new(), &BTreeMap::new())
                .expect("the runtime revision computes"),
            revision
        );
    }

    /// The acceptance bundle's one source, restated on the statement transport.
    ///
    /// It keeps the fixture's selector profile, schemas and extraction script,
    /// so the only thing the rewrite changes is how the source is reached.
    const STATEMENT_SOURCE: &str = r#"  source-a:
    transport: sqlite-extract
    posture: field-projected
    extractProfile: residence-register
    request:
      statement: queries/adult-status.sql
      columns: [{name: total, type: integer}, {name: date_of_birth, type: string}]
      selectorInputs:
        - role: subject
          alternatives:
            - {profile: person-demographics-v1, fields: [given_name, family_name, birth_date]}
      parameterBindings:
        record_reference: {kind: selector, role: subject, profile: person-demographics-v1, field: given_name}
      maximumRows: 2
      maximumCellBytes: 4096
      maximumStatementSteps: 50000
      projection: [/rows/*/total, /rows/*/date_of_birth]
      timeoutMilliseconds: 1000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    maximumExtractAgeSeconds: 86400
    responseSchema: schemas/response.schema.yaml
    extractScript: adapters/source-a.rhai
    factSchema: schemas/facts.schema.yaml
"#;

    const STATEMENT_PATH: &str = "queries/adult-status.sql";
    const STATEMENT_TEXT: &[u8] =
        b"SELECT total, date_of_birth FROM residents WHERE id = :record_reference;\n";
    const EXTRACT_PROFILE: &str = "residence-register";
    const EXTRACT_ARTIFACT: &str = "sourceExtracts/residence-register";
    const EXTRACT_CHANGED: &str = "the source extract changed while it was being read";

    /// The acceptance configuration with its HTTP source restated as a
    /// statement source.
    fn statement_configuration() -> String {
        let fixture = include_str!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );
        let (head, rest) = fixture
            .split_once("sources:\n")
            .expect("the fixture declares sources");
        let (_, tail) = rest
            .split_once("authorityProfiles:\n")
            .expect("the fixture declares authority profiles after its sources");
        format!("{head}sources:\n{STATEMENT_SOURCE}authorityProfiles:\n{tail}")
    }

    /// The acceptance bundle rewritten onto the statement transport, so a whole
    /// bundle carries a `queries/` artifact.
    ///
    /// The statement transport prepares no request and declares no adapter
    /// parameters, so the artifacts filling those roles leave the closure with
    /// them.
    #[cfg(unix)]
    fn write_statement_bundle(destination: &Path, statement: &[u8]) {
        copy_acceptance_bundle("adult-status", destination);
        fs::write(destination.join(CONFIG_FILE), statement_configuration())
            .expect("the statement configuration writes");
        fs::remove_file(destination.join("adapters/source-a-prepare.rhai"))
            .expect("remove the displaced preparation script");
        fs::remove_file(destination.join("schemas/adapter-parameters.schema.yaml"))
            .expect("remove the displaced adapter-parameter schema");
        fs::create_dir(destination.join("queries")).expect("create the statement directory");
        fs::write(destination.join(STATEMENT_PATH), statement).expect("the statement writes");
    }

    /// A statement is reviewed, bounded, executable text, so it is bounded like
    /// the other executable artifacts rather than like a data file. A megabyte
    /// of SQL is not a statement anybody reviewed.
    #[test]
    fn a_statement_is_capped_as_a_script_rather_than_as_a_data_artifact() {
        assert_eq!(file_size_cap(STATEMENT_PATH), MAX_SCRIPT_BYTES);
        assert_eq!(file_size_cap("adapters/source-a.rhai"), MAX_SCRIPT_BYTES);
        assert_eq!(
            file_size_cap("derivations/adult-status.rhai"),
            MAX_SCRIPT_BYTES
        );
        assert_eq!(
            file_size_cap("schemas/facts.schema.yaml"),
            MAX_ARTIFACT_BYTES
        );
    }

    /// One statement exactly at the cap loads, and one byte more does not.
    #[cfg(unix)]
    #[test]
    fn a_statement_loads_at_the_script_cap_and_not_one_byte_over_it() {
        let padded = |length: usize| {
            let mut statement = STATEMENT_TEXT.to_vec();
            statement.resize(length, b' ');
            statement
        };

        let at_cap = tempfile::tempdir().expect("temporary bundle");
        write_statement_bundle(
            at_cap.path(),
            &padded(usize::try_from(MAX_SCRIPT_BYTES).expect("the cap fits a length")),
        );
        set_tree_mode(at_cap.path(), 0o555, 0o444);
        Bundle::load(at_cap.path()).expect("a statement at the cap loads");
        set_tree_mode(at_cap.path(), 0o755, 0o644);

        let over_cap = tempfile::tempdir().expect("temporary bundle");
        write_statement_bundle(
            over_cap.path(),
            &padded(usize::try_from(MAX_SCRIPT_BYTES).expect("the cap fits a length") + 1),
        );
        set_tree_mode(over_cap.path(), 0o555, 0o444);
        assert!(matches!(
            Bundle::load(over_cap.path()),
            Err(BundleError::TooLarge)
        ));
        set_tree_mode(over_cap.path(), 0o755, 0o644);
    }

    /// A statement is bundle material like any other artifact: it loads, it has
    /// to be referenced, and an unreferenced one is refused by name.
    #[cfg(unix)]
    #[test]
    fn a_statement_bundle_closes_over_its_query_directory() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        write_statement_bundle(directory.path(), STATEMENT_TEXT);
        set_tree_mode(directory.path(), 0o555, 0o444);
        let bundle = Bundle::load(directory.path()).expect("a statement bundle loads");
        assert_eq!(bundle.artifact(STATEMENT_PATH), Some(STATEMENT_TEXT));
        assert_eq!(
            bundle
                .config
                .sources
                .get("source-a")
                .expect("the statement source is configured")
                .statement()
                .expect("the statement transport names a statement")
                .as_str(),
            STATEMENT_PATH
        );
        set_tree_mode(directory.path(), 0o755, 0o644);

        fs::write(
            directory.path().join("queries/unreferenced.sql"),
            b"SELECT 1;\n",
        )
        .expect("write an unreferenced statement");
        set_tree_mode(directory.path(), 0o555, 0o444);
        let unreferenced =
            Bundle::load(directory.path()).expect_err("an unreferenced statement is refused");
        let fault = unreferenced
            .artifact_fault()
            .expect("closure names the statement");
        assert_eq!(fault.artifact(), "queries/unreferenced.sql");
        assert_eq!(
            fault.fault().cause(),
            "the bundle contains an artifact the configuration does not reference"
        );
        set_tree_mode(directory.path(), 0o755, 0o644);
    }

    /// The statement decides what the source returns, so editing it has to move
    /// the revision the requirement's relying parties pinned. A statement left
    /// out of the closure would let a deployment change its answers under an
    /// unchanged revision.
    #[cfg(unix)]
    #[test]
    fn editing_the_statement_moves_the_requirement_revision() {
        const REQUIREMENT: &str = "urn:example:fixture:requirement:adult-status:v1";
        let directory = tempfile::tempdir().expect("temporary bundle");
        write_statement_bundle(directory.path(), STATEMENT_TEXT);
        set_tree_mode(directory.path(), 0o555, 0o444);
        let before = Bundle::load(directory.path())
            .expect("a statement bundle loads")
            .configuration_revision(REQUIREMENT)
            .expect("the requirement has a revision")
            .to_owned();

        set_tree_mode(directory.path(), 0o755, 0o644);
        fs::write(
            directory.path().join(STATEMENT_PATH),
            b"SELECT total, date_of_birth FROM residents WHERE id = :record_reference LIMIT 1;\n",
        )
        .expect("the statement rewrites");
        set_tree_mode(directory.path(), 0o555, 0o444);
        let after = Bundle::load(directory.path())
            .expect("the edited statement bundle loads")
            .configuration_revision(REQUIREMENT)
            .expect("the requirement has a revision")
            .to_owned();
        set_tree_mode(directory.path(), 0o755, 0o644);

        assert_ne!(before, after);
    }

    /// The operator runtime document in a temporary root, with a secret root
    /// created and locked and the operator's own blocks appended.
    #[cfg(unix)]
    fn locked_runtime_document(directory: &Path, blocks: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let secret_root = directory.join("secrets");
        fs::create_dir_all(&secret_root).expect("create secret root");
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("lock secret root");
        let path = directory.join(RUNTIME_FILE);
        let document = OPERATOR_RUNTIME_DOCUMENT.replace(
            "/run/secrets/registry-evidence",
            &secret_root.display().to_string(),
        );
        fs::write(&path, format!("{document}{blocks}")).expect("write runtime document");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
            .expect("lock runtime document");
        path
    }

    /// One `sourceExtracts` block binding the fixture profile to a path.
    fn extract_block(path: &Path) -> String {
        format!(
            "sourceExtracts:\n  {EXTRACT_PROFILE}: {{path: {}}}\n",
            path.display()
        )
    }

    #[cfg(unix)]
    fn locked_extract(path: &Path, contents: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o644))
                .expect("unlock the extract");
        }
        fs::write(path, contents).expect("write the extract");
        fs::set_permissions(path, fs::Permissions::from_mode(0o444)).expect("lock the extract");
        path.to_path_buf()
    }

    /// Bind whatever the caller staged as the deployment's one extract, and
    /// load the runtime document over it.
    #[cfg(unix)]
    fn load_with_extract(
        stage: impl FnOnce(&Path) -> PathBuf,
    ) -> Result<RuntimeDocument, BundleError> {
        let directory = tempfile::tempdir().expect("temporary runtime root");
        let bound = stage(directory.path());
        let runtime_path = locked_runtime_document(directory.path(), &extract_block(&bound));
        RuntimeDocument::load(&runtime_path)
    }

    /// The artifact one refusal names, and the value-free cause it carries.
    fn named_refusal(error: &BundleError) -> (&str, &'static str) {
        let fault = error
            .artifact_fault()
            .expect("a deployment refusal names its subject");
        (fault.artifact(), fault.fault().cause())
    }

    /// An extract is bound by digest, never by its bytes: a register-sized file
    /// does not belong in a serving process's memory. The digest still has to
    /// reach the runtime revision, or a deployment could answer from different
    /// data under a revision it already published.
    #[cfg(unix)]
    #[test]
    fn an_extract_reaches_the_runtime_revision_as_a_digest_of_its_bytes() {
        let directory = tempfile::tempdir().expect("temporary runtime root");
        let extract = directory.path().join("residence-register.sqlite");
        locked_extract(&extract, b"extract-content-one");
        let runtime_path = locked_runtime_document(directory.path(), &extract_block(&extract));

        let first = RuntimeDocument::load(&runtime_path).expect("the runtime document loads");
        let bound = first
            .source_extracts
            .get(EXTRACT_PROFILE)
            .expect("the bound extract is captured");
        assert_eq!(bound.path(), extract);
        let mut hasher = Sha256::new();
        hasher.update(b"extract-content-one");
        assert_eq!(
            bound.digest(),
            sha256_label(hasher).expect("the expected digest computes"),
            "the digest is taken over the extract's bytes and nothing else"
        );

        let again = RuntimeDocument::load(&runtime_path).expect("the runtime document reloads");
        assert_eq!(first.revision(), again.revision());
        assert_eq!(
            first.bytes(),
            again.bytes(),
            "the runtime file itself did not move"
        );

        locked_extract(&extract, b"extract-content-two");
        let replaced =
            RuntimeDocument::load(&runtime_path).expect("the replaced extract still loads");
        assert_ne!(replaced.revision(), first.revision());
        assert_eq!(
            replaced.bytes(),
            first.bytes(),
            "only the extract changed, so only its digest can have moved the revision"
        );
    }

    /// Every way an extract can be unusable is its own refusal, naming the
    /// profile the operator has to look at. Collapsing them would leave an
    /// operator with a deployment that will not start and no way to tell a
    /// missing file from a writable one.
    #[cfg(unix)]
    #[test]
    fn every_unusable_extract_is_refused_by_its_own_name_and_cause() {
        let missing =
            load_with_extract(|root| root.join("absent.sqlite")).expect_err("a missing extract");
        assert_eq!(
            named_refusal(&missing),
            (
                EXTRACT_ARTIFACT,
                "the source extract the runtime file names is unavailable"
            )
        );

        let symlinked = load_with_extract(|root| {
            use std::os::unix::fs::symlink;
            let target = locked_extract(&root.join("target.sqlite"), b"extract");
            let link = root.join("link.sqlite");
            symlink(&target, &link).expect("create the extract symlink");
            link
        })
        .expect_err("a symlinked extract");
        assert_eq!(
            named_refusal(&symlinked),
            (
                EXTRACT_ARTIFACT,
                "the source extract the runtime file names is a symbolic link"
            )
        );

        let not_a_file = load_with_extract(|root| {
            let path = root.join("extract-directory");
            fs::create_dir(&path).expect("create the bound directory");
            path
        })
        .expect_err("an extract that is not a regular file");
        assert_eq!(
            named_refusal(&not_a_file),
            (
                EXTRACT_ARTIFACT,
                "the source extract the runtime file names is not a regular file"
            )
        );

        let writable = load_with_extract(|root| {
            let path = root.join("writable.sqlite");
            fs::write(&path, b"extract").expect("write the extract");
            path
        })
        .expect_err("a writable extract");
        assert_eq!(
            named_refusal(&writable),
            (
                EXTRACT_ARTIFACT,
                "the source extract the runtime file names is writable"
            )
        );

        // The sidecars are written plain rather than locked: what is refused is
        // that they are there at all, whatever they permit.
        for suffix in EXTRACT_SIDECAR_SUFFIXES {
            let with_sidecar = load_with_extract(|root| {
                let path = locked_extract(&root.join("published.sqlite"), b"extract");
                let mut sidecar = path.clone().into_os_string();
                sidecar.push(suffix);
                fs::write(PathBuf::from(sidecar), b"pending").expect("write the sidecar");
                path
            })
            .expect_err("an extract published with a sidecar");
            assert_eq!(
                named_refusal(&with_sidecar),
                (
                    EXTRACT_ARTIFACT,
                    "the source extract the runtime file names has an uncheckpointed sidecar"
                )
            );
        }

        // A `-shm` alone survives a clean checkpoint and close, so it says
        // nothing about the snapshot and is not refused.
        load_with_extract(|root| {
            let path = locked_extract(&root.join("checkpointed.sqlite"), b"extract");
            let mut shared = path.clone().into_os_string();
            shared.push("-shm");
            fs::write(PathBuf::from(shared), b"shared").expect("write the shared-memory file");
            path
        })
        .expect("an extract beside a leftover shared-memory file loads");
    }

    /// The statement executor opens the extract `immutable=1`, so the file
    /// identity that was validated has to be the file identity that was
    /// hashed. A file swapped between naming it and opening it is refused
    /// before a single byte reaches the digest.
    ///
    /// The replacement is a different length on purpose. A filesystem is free
    /// to hand the same inode number back to the next file created in the same
    /// directory, and several do, so an equal-length replacement would look
    /// identical to `same_file` on those hosts and to nobody on the others.
    /// Staging a length change keeps the refusal a property of the code rather
    /// than of the filesystem the test happens to run on.
    #[cfg(unix)]
    #[test]
    fn a_streamed_read_refuses_an_extract_replaced_after_it_was_named() {
        let directory = tempfile::tempdir().expect("temporary extract root");
        let path = directory.path().join("extract.sqlite");
        locked_extract(&path, b"extract-content-one");
        let scanned = fs::symlink_metadata(&path).expect("the scanned metadata reads");
        fs::remove_file(&path).expect("remove the named extract");
        locked_extract(&path, b"extract-content-two-and-longer");

        assert_eq!(
            refusal_cause(
                digest_stable_file(&path, &scanned, false)
                    .expect_err("a replaced extract is refused")
            ),
            "the source extract was replaced between naming it and opening it"
        );
        digest_stable_file(
            &path,
            &fs::symlink_metadata(&path).expect("the current metadata reads"),
            false,
        )
        .expect("the extract that is still there digests");
    }

    /// The capture and the SQLite open are not the same moment: the bundle is
    /// read, the kernel is compiled, and the audit log is initialized in
    /// between. A publisher who refreshes the bound path inside that window
    /// gets a startup failure rather than a deployment serving bytes its
    /// runtime revision does not name.
    ///
    /// The replacement is a different length for the reason the test above
    /// gives.
    #[cfg(unix)]
    #[test]
    fn a_bound_extract_refuses_a_path_replaced_before_it_was_opened() {
        let directory = tempfile::tempdir().expect("temporary extract root");
        let path = directory.path().join("extract.sqlite");
        locked_extract(&path, b"extract-content-one");
        let bound = capture_source_extract(&path).expect("the staged extract captures");
        bound
            .confirm_still_bound()
            .expect("an untouched extract is still bound");

        fs::remove_file(&path).expect("remove the named extract");
        locked_extract(&path, b"extract-content-two-and-longer");
        assert_eq!(
            refusal_cause(
                bound
                    .confirm_still_bound()
                    .expect_err("a replaced extract is refused")
            ),
            "the source extract was replaced between digesting it and opening it"
        );

        fs::remove_file(&path).expect("remove the replacement");
        assert_eq!(
            refusal_cause(
                bound
                    .confirm_still_bound()
                    .expect_err("a vanished extract is refused")
            ),
            "the source extract the runtime file names is unavailable"
        );
    }

    /// The closing half of the read bracket, checked where it can be staged.
    ///
    /// A read that is genuinely raced cannot be produced on demand, so the
    /// check is exercised against the two identities it separates: a different
    /// file, and the same file reporting a size the fold did not see.
    #[cfg(unix)]
    #[test]
    fn a_streamed_read_refuses_an_extract_that_moved_while_it_was_read() {
        let directory = tempfile::tempdir().expect("temporary extract root");
        let first = locked_extract(&directory.path().join("first.sqlite"), b"extract-one");
        let second = locked_extract(&directory.path().join("second.sqlite"), b"extract-two");
        let first_metadata = fs::symlink_metadata(&first).expect("the first metadata reads");
        let second_metadata = fs::symlink_metadata(&second).expect("the second metadata reads");

        confirm_unchanged(
            &first_metadata,
            &first_metadata,
            first_metadata.len(),
            EXTRACT_CHANGED,
        )
        .expect("an untouched file passes the bracket");
        assert_eq!(
            refusal_cause(
                confirm_unchanged(
                    &first_metadata,
                    &second_metadata,
                    first_metadata.len(),
                    EXTRACT_CHANGED,
                )
                .expect_err("a different file is refused")
            ),
            EXTRACT_CHANGED
        );
        assert_eq!(
            refusal_cause(
                confirm_unchanged(
                    &first_metadata,
                    &first_metadata,
                    first_metadata.len() + 1,
                    EXTRACT_CHANGED,
                )
                .expect_err("a fold that did not see the whole file is refused")
            ),
            EXTRACT_CHANGED
        );
    }

    /// The extract binding is exact in both directions, and each direction is
    /// somebody's separate job: an unbound profile is a file the deployment
    /// still has to name, and a bound profile no source reads is a file the
    /// deployment is holding open for nothing.
    #[test]
    fn a_source_extract_binding_must_be_exact_in_both_directions() {
        const BOUND: &str =
            "  residence-register: {path: /var/lib/registry-evidence/extracts/residence.sqlite}\n";
        let bundle = EvidenceConfig::parse_yaml(statement_configuration().as_bytes())
            .expect("the statement configuration validates");

        let silent = RuntimeConfig::parse_yaml(OPERATOR_RUNTIME_DOCUMENT.as_bytes())
            .expect("the operator runtime document parses");
        let unbound = validate_runtime_bindings(&bundle, &silent)
            .expect_err("a deployment binding no extract refuses the bundle");
        assert_eq!(
            named_refusal(&unbound),
            (
                EXTRACT_ARTIFACT,
                "the runtime configuration binds no file for a source extract profile the bundle names"
            )
        );

        let exact = RuntimeConfig::parse_yaml(
            format!("{OPERATOR_RUNTIME_DOCUMENT}sourceExtracts:\n{BOUND}").as_bytes(),
        )
        .expect("the bound operator runtime document parses");
        validate_runtime_bindings(&bundle, &exact)
            .expect("a deployment binding exactly the named extract accepts the bundle");

        let surplus = RuntimeConfig::parse_yaml(
            format!(
                "{OPERATOR_RUNTIME_DOCUMENT}sourceExtracts:\n{BOUND}  civil-register: {{path: /var/lib/registry-evidence/extracts/civil.sqlite}}\n"
            )
            .as_bytes(),
        )
        .expect("the surplus operator runtime document parses");
        let unused = validate_runtime_bindings(&bundle, &surplus)
            .expect_err("a deployment binding an unread extract refuses the bundle");
        assert_eq!(
            named_refusal(&unused),
            (
                "sourceExtracts/civil-register",
                "the runtime configuration binds a source extract profile no bundle source names"
            )
        );

        // A bundle that reads no extract keeps binding against every runtime
        // file written before extracts existed.
        let frozen = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .expect("the acceptance bundle validates");
        validate_runtime_bindings(&frozen, &silent)
            .expect("a bundle reading no extract needs no binding");
        let orphaned = validate_runtime_bindings(&frozen, &exact)
            .expect_err("an extract no bundle source reads is refused");
        assert_eq!(
            named_refusal(&orphaned),
            (
                EXTRACT_ARTIFACT,
                "the runtime configuration binds a source extract profile no bundle source names"
            )
        );
    }
}
