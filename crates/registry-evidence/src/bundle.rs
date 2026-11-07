//! Immutable Evidence Version 1 deployment bundle loading.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use jsonschema::{Draft, JSONSchema};
use registry_adapter_core::{
    AdapterPack, EvidenceAcquisitionPosture, ADAPTER_PACK_API_VERSION, ADAPTER_PACK_KIND,
};
use registry_adapter_engine::artifacts::{PackArtifactBytes, ProjectArtifactBytes};
use registry_adapter_engine::evidence::{
    check_schema, compile_evidence_pack_with_protocols, EvidenceCompileError, EvidenceLimits,
    EvidenceSchemaKind,
};
use registry_adapter_engine::project_transform::{CompiledProjectTransform, ProjectTransformError};
use registry_platform_config::{
    package::is_envelope_file, require_trusted_runtime_path, sha256_uri, verify_package,
    PackageError, PackageLimits, VerifiedPackage, SUM_FILE,
};
use registry_platform_crypto::{
    canonicalize_json, PublicJwk, SigningAlgorithm as ProviderSigningAlgorithm,
};
use registry_platform_sqlite::{CapturedSnapshot, ErrorKind as SqliteErrorKind};
use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader, Report};
use rhai::{Engine, AST};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_norway::Value as YamlValue;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{
    AcquisitionPosture, ArtifactPath, AssuranceProfile, ConceptConfig, ConceptForm, ConfigError,
    EvidenceConfig, OrderedMap, RequirementConfig, RuntimeConfig, SchemaFault, SelectorField,
    SourceInputPresenceContract, SourceInputPresenceRequirement, TextLocation,
};

pub const MAX_BUNDLE_FILES: usize = 1_024;
pub const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024;
pub const MAX_SCRIPT_BYTES: u64 = 64 * 1024;
pub const MAX_PUBLIC_JWK_BYTES: u64 = 64 * 1024;

const CONFIG_FILE: &str = "evidence.yaml";
pub const DISCOVERY_DESCRIPTION_FILE: &str = "catalog.jsonld";
const RUNTIME_FILE: &str = "runtime.yaml";
const REQUIREMENT_REVISION_DOMAIN: &[u8] = b"registry.evidence.requirement-revision/v1\0";
/// Path the canonical configuration projection takes inside a requirement's
/// closure. An artifact path can hold no `#`, so this can never collide with a
/// bundle file.
const PROJECTION_PATH: &str = "evidence.yaml#requirement";
const PROVIDER_PUBLICATION: &str = "publication";
const ADAPTER_PACK_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: ADAPTER_PACK_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(ADAPTER_PACK_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};
pub(crate) const MAX_CA_BUNDLE_BYTES: u64 = 1024 * 1024;
/// Bytes folded into an extract's digest per read. An extract is sized by the
/// register it holds rather than by a byte cap, so it is digested in chunks of
/// this size and never held whole.
#[cfg(test)]
const EXTRACT_DIGEST_CHUNK_BYTES: usize = 64 * 1024;
const ALLOWED_DIRECTORIES: [&str; 8] = [
    "adapter-packs",
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
    #[error("{0}")]
    Package(PackageError),
    #[error("the Evidence deployment configuration is invalid: {0}")]
    Config(ArtifactFault),
    /// The shared configuration reader refused a configuration file. The
    /// report carries the reader's diagnostics unchanged, each naming the
    /// file as it was given or found, the path, the position, and the fix.
    #[error("{}", crate::config::render_refusal(.0))]
    Refused(Box<Report>),
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
            Self::Package(_) => None,
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
            Self::Package(error) => Self::Package(error),
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

/// A configuration refusal from `file`, or the value-free fault of `artifact`
/// when the failure is not the reader's.
fn configuration_error(artifact: &str, file: &Path, error: ConfigError) -> BundleError {
    match error.in_file(&file.display().to_string()) {
        ConfigError::Refused(report) => BundleError::Refused(report),
        other => BundleError::Config(ArtifactFault::new(artifact, other.fault())),
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

/// One fully captured, validated Evidence package.
///
/// Runtime consumers use these captured bytes and compiled artifacts. They do
/// not reopen the package directory, which prevents a later filesystem change
/// from partially replacing the package used by a serving process.
#[derive(Debug, Clone)]
pub struct Bundle {
    authority_snapshot: Option<crate::authority::AuthoritySnapshot>,
    effective_grant_digest: Option<String>,
    root: PathBuf,
    pub config: EvidenceConfig,
    package_digest: String,
    requirement_revisions: BTreeMap<String, String>,
    files: BTreeMap<String, Vec<u8>>,
    source_packs: BTreeMap<String, SourcePack>,
    discovery_description: Option<Vec<u8>>,
    pub scripts: BTreeMap<String, CompiledScript>,
    pub fact_schemas: BTreeMap<String, JsonValue>,
    pub codelists: BTreeMap<String, Codelist>,
    pub fixtures: BTreeMap<String, JsonValue>,
    pub active_public_jwk: PublicJwk,
    pub published_public_jwks: BTreeMap<String, PublicJwk>,
    /// The parsed certificate chain certifying the active key, when the
    /// bundle names one. Startup binds it to the signer and checks it is
    /// valid; the bundle only guarantees it parses, is within the chain
    /// policy's length, and belongs to the active key's file name.
    pub certificate_chain: Option<registry_platform_x509::X5cChain>,
}

/// One source's parsed, digest-checked Adapter pack and its exact captured
/// artifact bytes. Both values are shared with compiled source programs, so a
/// request never reparses or reopens package files.
#[derive(Debug, Clone)]
pub struct SourcePack {
    pack: Arc<AdapterPack>,
    artifacts: Arc<PackArtifactBytes>,
    artifact_paths: BTreeSet<String>,
    input_presence: SourceInputPresenceContract,
    projection: Option<Arc<CompiledProjectTransform>>,
}

impl SourcePack {
    #[must_use]
    pub fn pack(&self) -> Arc<AdapterPack> {
        Arc::clone(&self.pack)
    }

    #[must_use]
    pub fn artifacts(&self) -> Arc<PackArtifactBytes> {
        Arc::clone(&self.artifacts)
    }

    /// Project only a successfully matched native fact object. Lookup
    /// classification and the acquisition deadline remain host-owned.
    pub fn project_lookup(
        &self,
        lookup: registry_adapter_engine::evidence::EvidenceLookup,
        deadline: std::time::Instant,
    ) -> Result<registry_adapter_engine::evidence::EvidenceLookup, ProjectTransformError> {
        use registry_adapter_engine::evidence::EvidenceLookup;
        match (&self.projection, lookup) {
            (Some(projection), EvidenceLookup::Matched { facts }) => {
                let maps = Arc::new(
                    self.pack
                        .code_maps
                        .iter()
                        .map(|map| (map.id.as_str().to_owned(), map.clone()))
                        .collect(),
                );
                projection
                    .apply(&maps, &facts, deadline)
                    .map(|facts| EvidenceLookup::Matched { facts })
            }
            (_, lookup) => Ok(lookup),
        }
    }
}

/// One captured operator runtime configuration and its bound trust anchors.
///
/// Secret values and audit contents are deliberately not captured. The
/// reviewed runtime YAML and private-CA bytes are captured, while every
/// process-local extract is bound by a digest and stable file identity.
#[derive(Debug, Clone)]
pub struct RuntimeDocument {
    path: PathBuf,
    pub config: RuntimeConfig,
    bytes: Vec<u8>,
    pub ca_bundles: BTreeMap<String, Vec<u8>>,
    /// Public CA trust anchors captured for each source connection before
    /// serving. Endpoint compilation consumes these bytes, never a later path
    /// reread; credentials and mTLS private keys remain post-intent material.
    pub source_ca_bundles: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
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
    captured: CapturedSnapshot,
}

/// The identity a capture was taken over, kept so a later opener can prove it
/// opened the file that was validated.
///
/// It holds the metadata rather than a copy of the fields [`same_file`]
/// compares, so the two cannot drift apart: whatever identity a read brackets
/// itself with is the identity a reopen is held to.
#[derive(Debug, Clone)]
#[cfg(test)]
struct FileIdentity(Metadata);

#[cfg(test)]
impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        same_file(&self.0, &other.0)
    }
}

#[cfg(test)]
impl Eq for FileIdentity {}

impl SourceExtract {
    pub(crate) fn captured_snapshot(&self) -> CapturedSnapshot {
        self.captured.clone()
    }

    /// The validated file the statement executor opens.
    pub fn path(&self) -> &Path {
        self.captured.path()
    }

    /// `sha256:` and lowercase hex over the extract's bytes, as they were read.
    pub fn digest(&self) -> &str {
        self.captured.digest()
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
    /// deployment answering from extract bytes that were never validated.
    ///
    /// Narrowing rather than proof: a path renamed away and back inside the
    /// window still passes, and anyone who can write the containing directory
    /// can do worse than this. The case it settles is the one that happens.
    pub fn confirm_still_bound(&self) -> Result<(), BundleError> {
        self.captured
            .confirm_still_bound()
            .map_err(|error| match error.kind() {
                SqliteErrorKind::DatabaseUnavailable => {
                    invalid_artifact("the source extract the runtime file names is unavailable")
                }
                _ => not_immutable(
                    "the source extract was replaced between digesting it and opening it",
                ),
            })
    }
}

impl RuntimeDocument {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let path = path.as_ref();
        if path.file_name().and_then(|name| name.to_str()) != Some(RUNTIME_FILE) {
            return Err(BundleError::InvalidPath);
        }
        require_trusted_runtime_path(path).map_err(|error| {
            BundleError::Refused(Box::new(Report::new(error.diagnostics().to_vec())))
        })?;
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
        // `${NAME}` in a string value reads the process environment; the
        // loader refuses it in a secret reference and under secretProviders.
        let loaded = RuntimeConfig::parse_yaml_with(&bytes, |name| std::env::var(name).ok())
            .map_err(|error| configuration_error(RUNTIME_FILE, path, error))?;
        let config = loaded.config;
        if let Some(file) = &config.secret_providers.file {
            validate_secret_root(&file.root)?;
        }

        let mut ca_bundles = BTreeMap::new();
        for (profile, binding) in config.outbound_tls.trust_profiles.iter() {
            ca_bundles.insert(
                profile.to_owned(),
                capture_ca_bundle(&binding.ca_bundle_file)?,
            );
        }
        let mut source_ca_bundles = BTreeMap::new();
        for (connection, bindings) in config.source_connections.iter() {
            let mut profiles = BTreeMap::new();
            if let Some(outbound_tls) = &bindings.outbound_tls {
                for (profile, binding) in &outbound_tls.trust_profiles {
                    profiles.insert(
                        profile.to_owned(),
                        capture_ca_bundle(&binding.ca_bundle_file)?,
                    );
                }
            }
            source_ca_bundles.insert(connection.to_owned(), profiles);
        }

        let mut source_extracts = BTreeMap::new();
        for (profile, binding) in config.source_extracts.iter() {
            let extract = capture_source_extract(Path::new(&binding.path))
                .map_err(|error| error.in_artifact(&source_extract_artifact(profile)))?;
            source_extracts.insert(profile.to_owned(), extract);
        }
        Ok(Self {
            path: path.to_path_buf(),
            config,
            bytes,
            ca_bundles,
            source_ca_bundles,
            source_extracts,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn capture_ca_bundle(path: &str) -> Result<Vec<u8>, BundleError> {
    let path = Path::new(path);
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleError::Unavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BundleError::InvalidPath);
    }
    let filesystem_read_only = filesystem_is_read_only(path)?;
    let writable = "the TLS CA bundle the runtime file names is writable";
    validate_read_only(&metadata, filesystem_read_only, writable)?;
    let bytes = read_stable_file(
        path,
        &metadata,
        MAX_CA_BUNDLE_BYTES,
        filesystem_read_only,
        writable,
    )?;
    validate_ca_bundle(&bytes).map_err(|error| error.in_artifact(RUNTIME_FILE))?;
    Ok(bytes)
}

/// The two independently captured, closed startup inputs.
///
/// The fields are private and `load` is the only way to build the pair, so a
/// value of this type is always exactly what the immutability, digest, and
/// binding checks ran over. `EvidenceRuntime::initialize_from` accepts this
/// type rather than a bundle and a runtime document precisely for that reason:
/// an in-process caller that ran `check` and then edited the checked inputs
/// before initializing would leave the runtime serving a configuration nothing
/// validated, under a revision digest that no longer describes it, and the type
/// makes that unwritable rather than merely discouraged.
///
/// `into_parts` hands the captured inputs out for callers that consume them.
/// What it returns cannot be assembled back into a `DeploymentInputs`, so it
/// cannot reach `initialize_from`.
#[derive(Debug, Clone)]
pub struct DeploymentInputs {
    bundle: Bundle,
    runtime: RuntimeDocument,
}

impl DeploymentInputs {
    pub fn load(runtime_path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let runtime = RuntimeDocument::load(runtime_path)?;
        let mut bundle = Bundle::load_pinned(&runtime.config.package)?;
        bundle.bind_target_authority(runtime.config.authority.as_ref())?;
        validate_runtime_bindings(&bundle, &runtime.config)?;
        Ok(Self { bundle, runtime })
    }

    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    pub fn runtime(&self) -> &RuntimeDocument {
        &self.runtime
    }

    #[must_use]
    pub fn into_parts(self) -> (Bundle, RuntimeDocument) {
        (self.bundle, self.runtime)
    }
}

pub type EvidenceBundle = Bundle;

impl Bundle {
    /// Load the same verified package pin used by startup, without requiring an
    /// authority snapshot. Activation uses this before its initial snapshot
    /// exists and must honor the operator's expected package digest too.
    pub fn load_pinned(
        package: &registry_platform_config::PackageConfig,
    ) -> Result<Self, BundleError> {
        let verified = package
            .verify_package(&evidence_package_limits(), "evidencectl package")
            .map_err(package_error)?;
        Self::load_verified(&package.root, &verified)
    }

    pub fn load(root: impl AsRef<Path>) -> Result<Self, BundleError> {
        let root = root.as_ref();
        let verified = verify_package(root, &evidence_package_limits(), "evidencectl package")
            .map_err(package_error)?;
        Self::load_verified(root, &verified)
    }

    /// Load a verified package as it is found, without requiring it to be
    /// frozen, for an offline check.
    ///
    /// Everything else deployment applies to the package applies here.
    pub fn load_as_found(root: &Path, verified: &VerifiedPackage) -> Result<Self, BundleError> {
        Self::load_captured(root, verified, Capture::AsFound)
    }

    fn load_verified(root: &Path, verified: &VerifiedPackage) -> Result<Self, BundleError> {
        Self::load_captured(root, verified, Capture::Frozen)
    }

    fn load_captured(
        root: &Path,
        verified: &VerifiedPackage,
        capture: Capture,
    ) -> Result<Self, BundleError> {
        let files = capture_bundle_files(root, verified, capture)?;
        let config_bytes = files.get(CONFIG_FILE).ok_or(BundleError::Unavailable)?;
        let config = EvidenceConfig::parse_yaml(config_bytes)
            .map_err(|error| configuration_error(CONFIG_FILE, &root.join(CONFIG_FILE), error))?;
        let source_packs = load_source_packs(&config, &files)?;
        validate_source_authority_paths(&config, &source_packs)?;
        validate_file_closure(&config, &source_packs, &files)?;
        let expected_description = crate::discovery::render(&config)
            .map_err(|_| invalid_artifact("the provider discovery description is invalid"))?;
        let discovery_description = match expected_description {
            Some(expected) => {
                let packaged = files.get(DISCOVERY_DESCRIPTION_FILE).ok_or_else(|| {
                    unknown_file(
                        DISCOVERY_DESCRIPTION_FILE,
                        "the configured provider discovery description is missing",
                    )
                })?;
                if packaged != &expected {
                    return Err(BundleError::InvalidArtifact(ArtifactFault::new(
                        DISCOVERY_DESCRIPTION_FILE,
                        SchemaFault::because(
                            "the packaged provider discovery description does not match its deterministic projection",
                        ),
                    )));
                }
                Some(packaged.clone())
            }
            None => None,
        };

        let scripts = load_scripts(&config, &files)?;
        let fact_schemas = load_fact_schemas(&config, &files)?;
        let codelists = load_codelists(root, &config, &files)?;
        validate_codelist_references(&config, &codelists)?;
        let fixtures = load_fixtures(root, &config, &files)?;
        let (active_public_jwk, published_public_jwks) = load_public_jwks(&config, &files)?;
        let certificate_chain = load_certificate_chain(&config, &files, &active_public_jwk)?;
        let requirement_revisions = compute_requirement_revisions(&config, &source_packs, &files)?;

        Ok(Self {
            authority_snapshot: None,
            effective_grant_digest: None,
            root: root.to_path_buf(),
            config,
            package_digest: verified.digest().to_owned(),
            requirement_revisions,
            files,
            source_packs,
            discovery_description,
            scripts,
            fact_schemas,
            codelists,
            fixtures,
            active_public_jwk,
            published_public_jwks,
            certificate_chain,
        })
    }

    /// The captured, checked pack closure selected by one configured source.
    #[must_use]
    pub fn source_pack(&self, source_id: &str) -> Option<&SourcePack> {
        self.source_packs.get(source_id)
    }

    /// Validate a compiled target authority against both package ceilings and
    /// the required input shape of every captured Source route. This performs
    /// no activation, credential resolution, source access or other effect.
    pub fn validate_target_authority(
        &self,
        target: &str,
        document: &crate::authority::AuthorityDocument,
    ) -> Result<(), BundleError> {
        document.validate_for(target, &self.config).map_err(|_| {
            invalid_artifact("effective target authority violates the package contract")
        })?;
        let mut effective = self.config.clone();
        effective.authority_profiles = document.access_profiles.clone();
        validate_source_authority_paths(&effective, &self.source_packs)
    }

    /// Audit and activate one target authority against this captured package.
    /// Package-specific validation runs after the request audit is durable and
    /// before the authority lock, commit, credentials or source effects.
    pub async fn activate_target_authority(
        &self,
        root: &Path,
        target: &str,
        document: &crate::authority::AuthorityDocument,
        operator_reference: Option<&str>,
        audit: &crate::audit::EvidenceAuditLog,
    ) -> Result<crate::authority::AuthoritySnapshot, crate::authority::ActivationError> {
        crate::authority::activate_bundle_with_operator(
            self,
            root,
            target,
            document,
            operator_reference,
            audit,
        )
        .await
    }

    pub(crate) fn validate_target_authority_for_activation(
        &self,
        target: &str,
        document: &crate::authority::AuthorityDocument,
    ) -> Result<(), crate::authority::AuthorityError> {
        document.validate_for(target, &self.config)?;
        let mut effective = self.config.clone();
        effective.authority_profiles = document.access_profiles.clone();
        source_authority_path_refusal(&effective, &self.source_packs)
            .map_err(crate::authority::AuthorityError::SourceRouteInputs)
    }

    /// Bind exactly one activated target authority before initialization.
    /// The snapshot is immutable for the process lifetime and has its own
    /// revision, separate from the package and definition identities.
    pub fn bind_target_authority(
        &mut self,
        binding: Option<&crate::config::RuntimeAuthorityConfig>,
    ) -> Result<(), BundleError> {
        let Some(binding) = binding else {
            if self.config.project.is_some() {
                return Err(invalid_artifact(
                    "normalized packages require an activated target authority binding",
                ));
            }
            return Ok(());
        };
        let snapshot = crate::authority::load(
            &binding.root,
            &binding.target,
            &self.config,
            self.package_digest(),
        )
        .map_err(|_| {
            invalid_artifact(
                "target authority is unavailable, out of ceiling, or activated for another package",
            )
        })?;
        let digest = snapshot
            .effective_grant_digest(&self.config)
            .map_err(|_| invalid_artifact("effective target authority does not canonicalize"))?;
        let mut effective = self.config.clone();
        effective.authority_profiles = snapshot.profiles().clone();
        effective.validate().map_err(|_| {
            invalid_artifact("effective target authority violates the package contract")
        })?;
        validate_source_authority_paths(&effective, &self.source_packs)?;
        self.config = effective;
        self.effective_grant_digest = Some(digest);
        self.authority_snapshot = Some(snapshot);
        Ok(())
    }

    pub fn authority_revision(&self) -> Option<&str> {
        self.authority_snapshot
            .as_ref()
            .map(crate::authority::AuthoritySnapshot::revision)
    }

    pub fn effective_grant_digest(&self) -> Option<&str> {
        self.effective_grant_digest.as_deref()
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

    /// The digest of the package's `SHA256SUMS` file.
    ///
    /// This is the deployment's own identity, for audit, status, and operator
    /// diagnostics. It is not what an assertion carries: see
    /// [`Bundle::configuration_revision`].
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    pub fn artifact(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// Exact deterministic bytes served by the public discovery route.
    pub fn discovery_description(&self) -> Option<&[u8]> {
        self.discovery_description.as_deref()
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

    pub fn fixture(&self, path: &ArtifactPath) -> Option<&JsonValue> {
        self.fixtures.get(path.as_str())
    }
}

pub fn load_bundle(root: impl AsRef<Path>) -> Result<Bundle, BundleError> {
    Bundle::load(root)
}

/// Package bounds used by both startup and offline verified capture.
/// Callers of `Bundle::load_as_found` verify against these same limits.
pub fn evidence_package_limits() -> PackageLimits {
    PackageLimits {
        max_files: MAX_BUNDLE_FILES,
        max_file_bytes: MAX_ARTIFACT_BYTES,
        max_total_bytes: MAX_BUNDLE_BYTES,
        max_depth: 16,
        max_path_bytes: 512,
    }
}

fn package_error(error: PackageError) -> BundleError {
    BundleError::Package(error.naming_root_as("package.root"))
}

/// Whether capture refuses a writable bundle.
///
/// Deployment serves only a frozen package. An offline check reads the package
/// as it is found, so an operator can check it before freezing it; the digest
/// checks against the verified package apply either way.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Capture {
    Frozen,
    AsFound,
}

fn capture_bundle_files(
    root: &Path,
    verified: &VerifiedPackage,
    capture: Capture,
) -> Result<BTreeMap<String, Vec<u8>>, BundleError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| BundleError::Unavailable)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(BundleError::InvalidPath);
    }
    // An as-found capture treats the package as if its filesystem were read
    // only, which is what every writability check below already honours.
    let filesystem_read_only = capture == Capture::AsFound || filesystem_is_read_only(root)?;
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
    let mut uncaptured = verified.files().map(str::to_owned).collect::<BTreeSet<_>>();
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
        if relative == SUM_FILE {
            if sha256_uri(&bytes) != verified.digest() {
                return Err(
                    not_immutable("SHA256SUMS was replaced after package verification")
                        .in_artifact(SUM_FILE),
                );
            }
            continue;
        }
        let digest = sha256_uri(&bytes);
        if verified.file_digest(&relative).as_deref() != Some(digest.as_str()) {
            return Err(not_immutable(
                "the package artifact was replaced after package verification",
            )
            .in_artifact(&relative));
        }
        uncaptured.remove(&relative);
        if !is_envelope_file(&relative) {
            files.insert(relative, bytes);
        }
    }
    if let Some(missing) = uncaptured.into_iter().next() {
        return Err(
            not_immutable("the package artifact disappeared after package verification")
                .in_artifact(&missing),
        );
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
            } else if !matches!(relative.as_str(), CONFIG_FILE | DISCOVERY_DESCRIPTION_FILE)
                && !is_envelope_file(&relative)
            {
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
    let pack_relative = path
        .strip_prefix("adapter-packs/")
        .and_then(|rest| rest.splitn(3, '/').nth(2));
    if path.starts_with("adapters/")
        || path.starts_with("derivations/")
        || path.starts_with("queries/")
        || pack_relative.is_some_and(|relative| {
            relative.starts_with("scripts/") || relative.starts_with("queries/")
        })
    {
        MAX_SCRIPT_BYTES
    } else if path.starts_with("public-keys/") {
        // A certificate chain is at most eight certificates of 16 KiB each,
        // PEM encoded; it fits well inside the public-key allowance.
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
    let captured = CapturedSnapshot::capture(path).map_err(map_extract_capture_error)?;
    Ok(SourceExtract { captured })
}

fn map_extract_capture_error(error: registry_platform_sqlite::SqliteError) -> BundleError {
    match error.kind() {
        SqliteErrorKind::DatabaseUnavailable => {
            invalid_artifact("the source extract the runtime file names is unavailable")
        }
        SqliteErrorKind::DatabaseSymlink => {
            invalid_artifact("the source extract the runtime file names is a symbolic link")
        }
        SqliteErrorKind::DatabaseNotFile => {
            invalid_artifact("the source extract the runtime file names is not a regular file")
        }
        SqliteErrorKind::DatabaseWritable => {
            invalid_artifact("the source extract the runtime file names is writable")
        }
        SqliteErrorKind::UncheckpointedSidecar => invalid_artifact(
            "the source extract the runtime file names has an uncheckpointed sidecar",
        ),
        SqliteErrorKind::DatabaseReplaced => {
            not_immutable("the source extract was replaced between naming it and opening it")
        }
        SqliteErrorKind::DatabaseChanged => {
            not_immutable("the source extract changed while it was being read")
        }
        _ => invalid_artifact("the source extract the runtime file names is unavailable"),
    }
}

/// The files SQLite writes beside a database and reads back to complete it.
///
/// A `-shm` is deliberately absent. It is shared memory rather than content,
/// and one can survive a clean checkpoint and close, so its presence says
/// nothing about whether the snapshot is whole.
#[cfg(test)]
const EXTRACT_SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-journal"];

/// Digest one file without holding it in memory.
///
/// [`read_stable_file`]'s identity discipline over a file too large to
/// capture: the bytes are folded into the digest in bounded chunks, and the
/// same before-and-after identity checks bracket the read, so the file
/// identity that was validated is the file identity that was hashed. There is
/// no byte cap, because an extract is a register rather than an artifact.
#[cfg(test)]
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
pub(crate) fn open_no_follow(path: &Path) -> Result<File, BundleError> {
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
pub(crate) fn open_no_follow(path: &Path) -> Result<File, BundleError> {
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
    source_packs: &BTreeMap<String, SourcePack>,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), BundleError> {
    let mut expected = BTreeSet::from([CONFIG_FILE.to_owned()]);
    if config.publication.is_some() {
        expected.insert(DISCOVERY_DESCRIPTION_FILE.to_owned());
    }
    for (source_id, source) in config.sources.iter() {
        expected.insert(source.fact_schema().as_str().to_owned());
        if let Some(projection) = &source.projection {
            expected.insert(projection.script.as_str().to_owned());
        }
        let pack = source_packs
            .get(source_id)
            .ok_or_else(|| invalid_artifact("a configured source pack closure is missing"))?;
        expected.extend(pack.artifact_paths.iter().cloned());
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
    if let Some(chain) = &config.signing.certificate_chain_file {
        expected.insert(chain.as_str().to_owned());
    }
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

fn load_source_packs(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, SourcePack>, BundleError> {
    let mut source_packs = BTreeMap::new();
    for (source_id, source) in config.sources.iter() {
        source_packs.insert(source_id.to_owned(), load_source_pack(source, files)?);
    }
    Ok(source_packs)
}

fn validate_source_authority_paths(
    config: &EvidenceConfig,
    source_packs: &BTreeMap<String, SourcePack>,
) -> Result<(), BundleError> {
    source_authority_path_refusal(config, source_packs)
        .map_err(|cause| invalid_artifact(cause).in_artifact(CONFIG_FILE))
}

/// The fixed, value-free rule an authority path breaks, if any.
fn source_authority_path_refusal(
    config: &EvidenceConfig,
    source_packs: &BTreeMap<String, SourcePack>,
) -> Result<(), &'static str> {
    let contracts = source_packs
        .iter()
        .map(|(source_id, pack)| (source_id.clone(), pack.input_presence.clone()))
        .collect::<BTreeMap<_, _>>();
    config
        .validate_source_authority_paths(&contracts)
        .map_err(|error| error.fault().cause())
}

fn load_source_pack(
    source: &crate::config::SourceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<SourcePack, BundleError> {
    let prefix = source.pack.artifact_prefix.as_str();
    let pack_path = format!("{prefix}/pack.yaml");
    let pack_bytes = files
        .get(&pack_path)
        .ok_or_else(|| unknown_file(&pack_path, "the source pack document is missing"))?;
    if sha256_uri(pack_bytes) != source.pack.digest.as_str() {
        return Err(
            invalid_artifact("the source pack digest does not match its captured bytes")
                .in_artifact(&pack_path),
        );
    }
    let pack = Reader::new(pack_path.as_str())
        .decode::<AdapterPack>(pack_bytes, &Expect::one(&ADAPTER_PACK_FORMAT))
        .map(|decoded| decoded.value)
        .map_err(|_| {
            invalid_artifact("the source pack document does not match the Adapter pack contract")
                .in_artifact(&pack_path)
        })?;
    if pack.id != source.pack.id || pack.version != source.pack.version {
        return Err(invalid_artifact(
            "the source pack id and version do not match the source binding",
        )
        .in_artifact(&pack_path));
    }

    let route = pack
        .source_routes
        .get(source.route.as_str())
        .ok_or_else(|| invalid_artifact("the selected source route is not declared by the pack"))?;
    let evidence = route
        .evidence
        .as_ref()
        .ok_or_else(|| invalid_artifact("the selected source route has no Evidence contract"))?;
    if !source_posture_covers_route(source.posture(), evidence.acquisition_posture) {
        return Err(invalid_artifact(
            "the source binding claims a stronger acquisition posture than the selected pack route",
        )
        .in_artifact(&pack_path));
    }

    let mut references = BTreeMap::new();
    for reference in pack.pinned_files() {
        insert_pack_reference(&mut references, &reference.path, reference.digest.as_str())?;
    }

    let mut artifact_paths = BTreeSet::from([pack_path.clone()]);
    let mut artifact_bytes = Vec::with_capacity(references.len());
    for (relative, digest) in &references {
        let path = format!("{prefix}/{relative}");
        let bytes = files
            .get(&path)
            .ok_or_else(|| unknown_file(&path, "the source pack artifact is missing"))?;
        if sha256_uri(bytes) != *digest {
            return Err(invalid_artifact(
                "a source pack artifact does not match its pinned digest",
            )
            .in_artifact(&path));
        }
        artifact_paths.insert(path);
        artifact_bytes.push((relative.clone(), bytes.clone()));
    }
    let prefix_with_slash = format!("{prefix}/");
    if let Some(extra) = files.keys().find(|path| {
        path.starts_with(&prefix_with_slash) && !artifact_paths.contains(path.as_str())
    }) {
        return Err(unknown_file(
            extra,
            "the source pack directory contains an artifact the pack does not pin",
        ));
    }

    let input_bytes = files
        .get(&format!("{prefix}/{}", evidence.inputs_schema.path))
        .ok_or_else(|| invalid_artifact("the selected route input schema is missing"))?;
    let input_schema: JsonValue = serde_json::from_slice(input_bytes)
        .map_err(|_| invalid_artifact("the selected route input schema is not JSON"))?;
    check_schema(EvidenceSchemaKind::Inputs, input_schema.clone()).map_err(|_| {
        invalid_artifact("the selected route input schema must be a closed JSON Schema 2020-12 object: the root and every object set `additionalProperties: false`, references stay inside the document, and the document stays within its size bounds")
    })?;
    let input_presence = source_input_presence_contract(&input_schema)?;
    validate_source_input_mapping(source, &input_schema, &input_presence)?;

    let facts_bytes = files
        .get(&format!("{prefix}/{}", evidence.facts_schema.path))
        .ok_or_else(|| invalid_artifact("the selected route facts schema is missing"))?;
    let facts_schema: JsonValue = serde_json::from_slice(facts_bytes)
        .map_err(|_| invalid_artifact("the selected route facts schema is not JSON"))?;
    check_schema(EvidenceSchemaKind::Facts, facts_schema.clone()).map_err(|_| {
        invalid_artifact("the selected route facts schema must be a closed JSON Schema 2020-12 object: the root and every object set `additionalProperties: false`, references stay inside the document, and the document stays within its size bounds")
    })?;
    let projected_facts = files.get(source.fact_schema().as_str()).ok_or_else(|| {
        unknown_file(
            source.fact_schema().as_str(),
            "the source facts schema is missing",
        )
    })?;
    let projected_schema: JsonValue = serde_json::from_slice(projected_facts).map_err(|_| {
        invalid_artifact("the source facts schema is not JSON")
            .in_artifact(source.fact_schema().as_str())
    })?;
    // The source schema retains its pack pin. A distinct project facts schema
    // is admissible only through a compiled, package-owned projection; both
    // schemas and the projection remain in the governed behavior closure.
    let projection = if let Some(projection) = &source.projection {
        let script_bytes = files.get(projection.script.as_str()).ok_or_else(|| {
            unknown_file(
                projection.script.as_str(),
                "the source projection script is missing",
            )
        })?;
        let id = registry_platform_yaml::LocalId::new("source-projection")
            .expect("fixed local identifier");
        let script = registry_adapter_core::ProjectScript {
            id: id.clone(),
            file: projection.script.as_str().to_owned(),
            digest: projection.digest.clone(),
        };
        let transform = registry_adapter_core::BindingTransform {
            script: id.clone(),
            entrypoint: projection.entrypoint.clone(),
        };
        let schema = registry_adapter_core::ProjectSchema {
            id,
            file: source.fact_schema().as_str().to_owned(),
            digest: registry_platform_yaml::Digest::new(sha256_uri(projected_facts))
                .expect("computed schema digest"),
        };
        let artifacts = ProjectArtifactBytes::new([
            (script.file.clone(), script_bytes.clone()),
            (schema.file.clone(), projected_facts.clone()),
        ]);
        Some(Arc::new(
            CompiledProjectTransform::compile_parts(&script, &transform, &schema, &artifacts)
                .map_err(|_| {
                    invalid_artifact("the governed source projection or facts schema is invalid")
                        .in_artifact(projection.script.as_str())
                })?,
        ))
    } else {
        if projected_schema != facts_schema {
            return Err(invalid_artifact(
                "the source facts schema does not equal the selected pack route's pinned schema",
            )
            .in_artifact(source.fact_schema().as_str()));
        }
        None
    };

    Ok(SourcePack {
        pack: Arc::new(pack),
        artifacts: Arc::new(PackArtifactBytes::new(artifact_bytes)),
        artifact_paths,
        input_presence,
        projection,
    })
}

fn source_posture_covers_route(
    source: AcquisitionPosture,
    route: EvidenceAcquisitionPosture,
) -> bool {
    matches!(
        (source, route),
        (AcquisitionPosture::RecordTransformed, _)
            | (
                AcquisitionPosture::FieldProjected,
                EvidenceAcquisitionPosture::SourceDerived
                    | EvidenceAcquisitionPosture::FieldProjected
            )
            | (
                AcquisitionPosture::SourceDerived,
                EvidenceAcquisitionPosture::SourceDerived
            )
    )
}

fn source_input_presence_contract(
    schema: &JsonValue,
) -> Result<SourceInputPresenceContract, BundleError> {
    let properties = schema
        .get("properties")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            invalid_artifact("the selected route input schema must declare properties")
        })?;
    let declared = properties
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut analysis = PresenceAnalysis::new();
    let requirement = root_presence_requirement(
        schema,
        schema,
        &declared,
        &mut BTreeSet::new(),
        &mut analysis,
        0,
    )?;
    let Some(branches) = schema.get("oneOf").and_then(JsonValue::as_array) else {
        return Ok(SourceInputPresenceContract::new(requirement, None));
    };
    let presence_only = !branches.is_empty()
        && branches.iter().all(|branch| {
            branch.as_object().is_some_and(|members| {
                members.contains_key("required")
                    && members.keys().all(|key| {
                        matches!(
                            key.as_str(),
                            "required" | "type" | "title" | "description" | "$comment"
                        )
                    })
                    && members
                        .get("type")
                        .is_none_or(|kind| kind.as_str() == Some("object"))
            })
        });
    if !presence_only {
        // Value constraints can distinguish branches that have the same
        // presence shape. The full validator retains exact oneOf semantics;
        // startup proves that at least one branch's required names are mapped.
        return Ok(SourceInputPresenceContract::new(requirement, None));
    }

    let base = required_input_names(schema)?;
    let mut alternatives = Vec::with_capacity(branches.len());
    for branch in branches {
        let mut required = base.clone();
        required.extend(required_input_names(branch)?);
        if required
            .iter()
            .any(|input| !declared.contains(input.as_str()))
        {
            return Err(invalid_artifact(
                "a selected route input alternative requires an undeclared input",
            ));
        }
        alternatives.push(required);
    }
    Ok(SourceInputPresenceContract::new(
        requirement,
        Some(alternatives),
    ))
}

const MAXIMUM_PRESENCE_ANALYSIS_NODES: usize = 8_192;
const MAXIMUM_PRESENCE_ANALYSIS_DEPTH: usize = 64;

struct PresenceAnalysis {
    remaining_nodes: usize,
}

impl PresenceAnalysis {
    fn new() -> Self {
        Self {
            remaining_nodes: MAXIMUM_PRESENCE_ANALYSIS_NODES,
        }
    }

    fn visit(&mut self, depth: usize) -> Result<(), BundleError> {
        if depth > MAXIMUM_PRESENCE_ANALYSIS_DEPTH || self.remaining_nodes == 0 {
            return Err(invalid_artifact(
                "route input presence analysis exceeds its bound",
            ));
        }
        self.remaining_nodes -= 1;
        Ok(())
    }
}

/// Derive only root-property presence predicates. Nested property value rules,
/// formats and other value constraints stay with the checked runtime schema;
/// unknown value predicates are never treated as exact presence proofs.
fn root_presence_requirement(
    schema: &JsonValue,
    root: &JsonValue,
    declared: &BTreeSet<&str>,
    resolving: &mut BTreeSet<String>,
    analysis: &mut PresenceAnalysis,
    depth: usize,
) -> Result<SourceInputPresenceRequirement, BundleError> {
    analysis.visit(depth)?;
    if let Some(boolean) = schema.as_bool() {
        return Ok(if boolean {
            SourceInputPresenceRequirement::Always
        } else {
            SourceInputPresenceRequirement::Never
        });
    }
    let Some(object) = schema.as_object() else {
        return Ok(SourceInputPresenceRequirement::Always);
    };

    let required = required_input_names(schema)?;
    validate_declared_required_inputs(&required, declared)?;
    let mut all = vec![SourceInputPresenceRequirement::Required(required)];

    for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
        if let Some(reference) = object.get(keyword).and_then(JsonValue::as_str) {
            let resolution = format!("{keyword}:{reference}");
            if resolving.insert(resolution.clone()) {
                let referenced = resolve_local_schema(root, reference, analysis, depth + 1)?
                    .ok_or_else(|| {
                        invalid_artifact(
                            "the selected route input schema has an unresolved reference",
                        )
                    })?;
                all.push(root_presence_requirement(
                    referenced,
                    root,
                    declared,
                    resolving,
                    analysis,
                    depth + 1,
                )?);
                resolving.remove(&resolution);
            }
        }
    }

    if let Some(negated) = object.get("not") {
        if let Some(requirement) =
            exact_presence_requirement(negated, root, declared, resolving, analysis, depth + 1)?
        {
            all.push(SourceInputPresenceRequirement::Not(Box::new(requirement)));
        }
    }

    for keyword in ["allOf"] {
        if let Some(branches) = object.get(keyword).and_then(JsonValue::as_array) {
            for branch in branches {
                all.push(root_presence_requirement(
                    branch,
                    root,
                    declared,
                    resolving,
                    analysis,
                    depth + 1,
                )?);
            }
        }
    }
    if let Some(branches) = object.get("anyOf").and_then(JsonValue::as_array) {
        let mut requirements = Vec::with_capacity(branches.len());
        for branch in branches {
            requirements.push(root_presence_requirement(
                branch,
                root,
                declared,
                resolving,
                analysis,
                depth + 1,
            )?);
        }
        all.push(SourceInputPresenceRequirement::Any(requirements));
    }
    if let Some(branches) = object.get("oneOf").and_then(JsonValue::as_array) {
        let mut requirements = Vec::with_capacity(branches.len());
        let mut exact = Vec::with_capacity(branches.len());
        let mut all_exact = true;
        for branch in branches {
            requirements.push(root_presence_requirement(
                branch,
                root,
                declared,
                resolving,
                analysis,
                depth + 1,
            )?);
            if let Some(requirement) =
                exact_presence_requirement(branch, root, declared, resolving, analysis, depth + 1)?
            {
                exact.push(requirement);
            } else {
                all_exact = false;
            }
        }
        all.push(if all_exact {
            SourceInputPresenceRequirement::ExactlyOne(exact)
        } else {
            SourceInputPresenceRequirement::Any(requirements)
        });
    }

    if let Some(condition_schema) = object.get("if") {
        let condition = root_presence_requirement(
            condition_schema,
            root,
            declared,
            resolving,
            analysis,
            depth + 1,
        )?;
        let then_requirement = object
            .get("then")
            .map(|branch| {
                root_presence_requirement(branch, root, declared, resolving, analysis, depth + 1)
            })
            .transpose()?
            .unwrap_or(SourceInputPresenceRequirement::Always);
        let else_requirement = object
            .get("else")
            .map(|branch| {
                root_presence_requirement(branch, root, declared, resolving, analysis, depth + 1)
            })
            .transpose()?
            .unwrap_or(SourceInputPresenceRequirement::Always);
        let alternatives = if let Some(exact_condition) = exact_presence_requirement(
            condition_schema,
            root,
            declared,
            resolving,
            analysis,
            depth + 1,
        )? {
            vec![
                SourceInputPresenceRequirement::All(vec![
                    exact_condition.clone(),
                    then_requirement,
                ]),
                SourceInputPresenceRequirement::All(vec![
                    SourceInputPresenceRequirement::Not(Box::new(exact_condition)),
                    else_requirement,
                ]),
            ]
        } else {
            // A value constraint may make the condition false even when its
            // required names are present. The true path still needs the
            // condition's presence proof; the false path needs only `else`.
            vec![
                SourceInputPresenceRequirement::All(vec![condition, then_requirement]),
                else_requirement,
            ]
        };
        all.push(SourceInputPresenceRequirement::Any(alternatives));
    }

    if let Some(dependencies) = object
        .get("dependentRequired")
        .and_then(JsonValue::as_object)
    {
        for (trigger, names) in dependencies {
            if !declared.contains(trigger.as_str()) {
                return Err(invalid_artifact(
                    "the selected route input schema has an undeclared dependency trigger",
                ));
            }
            let required = required_input_names(&serde_json::json!({"required": names}))?;
            validate_declared_required_inputs(&required, declared)?;
            all.push(SourceInputPresenceRequirement::DependentRequired {
                trigger: trigger.clone(),
                required,
            });
        }
    }
    if let Some(dependencies) = object
        .get("dependentSchemas")
        .and_then(JsonValue::as_object)
    {
        for (trigger, dependent) in dependencies {
            if !declared.contains(trigger.as_str()) {
                return Err(invalid_artifact(
                    "the selected route input schema has an undeclared dependency trigger",
                ));
            }
            all.push(SourceInputPresenceRequirement::DependentSchema {
                trigger: trigger.clone(),
                requirement: Box::new(root_presence_requirement(
                    dependent,
                    root,
                    declared,
                    resolving,
                    analysis,
                    depth + 1,
                )?),
            });
        }
    }

    Ok(SourceInputPresenceRequirement::All(all))
}

fn resolve_local_schema<'a>(
    root: &'a JsonValue,
    reference: &str,
    analysis: &mut PresenceAnalysis,
    depth: usize,
) -> Result<Option<&'a JsonValue>, BundleError> {
    let Some(fragment) = reference.strip_prefix('#') else {
        return Ok(None);
    };
    if fragment.is_empty() {
        return Ok(Some(root));
    }
    if fragment.starts_with('/') {
        return Ok(root.pointer(fragment));
    }
    find_schema_anchor(root, fragment, analysis, depth)
}

fn find_schema_anchor<'a>(
    value: &'a JsonValue,
    anchor: &str,
    analysis: &mut PresenceAnalysis,
    depth: usize,
) -> Result<Option<&'a JsonValue>, BundleError> {
    analysis.visit(depth)?;
    let JsonValue::Object(members) = value else {
        return Ok(None);
    };
    if members.get("$anchor").and_then(JsonValue::as_str) == Some(anchor)
        || members.get("$dynamicAnchor").and_then(JsonValue::as_str) == Some(anchor)
    {
        return Ok(Some(value));
    }

    for keyword in [
        "$defs",
        "definitions",
        "properties",
        "patternProperties",
        "dependentSchemas",
    ] {
        if let Some(schemas) = members.get(keyword).and_then(JsonValue::as_object) {
            for schema in schemas.values() {
                if let Some(found) = find_schema_anchor(schema, anchor, analysis, depth + 1)? {
                    return Ok(Some(found));
                }
            }
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(schemas) = members.get(keyword).and_then(JsonValue::as_array) {
            for schema in schemas {
                if let Some(found) = find_schema_anchor(schema, anchor, analysis, depth + 1)? {
                    return Ok(Some(found));
                }
            }
        }
    }
    for keyword in [
        "not",
        "if",
        "then",
        "else",
        "items",
        "additionalProperties",
        "contains",
        "propertyNames",
        "unevaluatedItems",
        "unevaluatedProperties",
        "contentSchema",
    ] {
        if let Some(schema) = members.get(keyword) {
            if let Some(found) = find_schema_anchor(schema, anchor, analysis, depth + 1)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

fn exact_presence_requirement(
    schema: &JsonValue,
    root: &JsonValue,
    declared: &BTreeSet<&str>,
    resolving: &mut BTreeSet<String>,
    analysis: &mut PresenceAnalysis,
    depth: usize,
) -> Result<Option<SourceInputPresenceRequirement>, BundleError> {
    analysis.visit(depth)?;
    if let Some(boolean) = schema.as_bool() {
        return Ok(Some(if boolean {
            SourceInputPresenceRequirement::Always
        } else {
            SourceInputPresenceRequirement::Never
        }));
    }
    let Some(object) = schema.as_object() else {
        return Ok(None);
    };
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "required"
                | "type"
                | "allOf"
                | "anyOf"
                | "oneOf"
                | "not"
                | "if"
                | "then"
                | "else"
                | "dependentRequired"
                | "dependentSchemas"
                | "$ref"
                | "$dynamicRef"
                | "$recursiveRef"
                | "$anchor"
                | "$dynamicAnchor"
                | "title"
                | "description"
                | "$comment"
        )
    }) || object
        .get("type")
        .is_some_and(|kind| kind.as_str() != Some("object"))
    {
        return Ok(None);
    }

    let required = required_input_names(schema)?;
    validate_declared_required_inputs(&required, declared)?;
    let mut all = vec![SourceInputPresenceRequirement::Required(required)];
    for keyword in ["$ref", "$dynamicRef", "$recursiveRef"] {
        if let Some(reference) = object.get(keyword).and_then(JsonValue::as_str) {
            let resolution = format!("exact:{keyword}:{reference}");
            if resolving.insert(resolution.clone()) {
                let Some(referenced) = resolve_local_schema(root, reference, analysis, depth + 1)?
                else {
                    return Err(invalid_artifact(
                        "the selected route input schema has an unresolved reference",
                    ));
                };
                let Some(requirement) = exact_presence_requirement(
                    referenced,
                    root,
                    declared,
                    resolving,
                    analysis,
                    depth + 1,
                )?
                else {
                    resolving.remove(&resolution);
                    return Ok(None);
                };
                resolving.remove(&resolution);
                all.push(requirement);
            }
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = object.get(keyword).and_then(JsonValue::as_array) {
            let mut requirements = Vec::with_capacity(branches.len());
            for branch in branches {
                let Some(requirement) = exact_presence_requirement(
                    branch,
                    root,
                    declared,
                    resolving,
                    analysis,
                    depth + 1,
                )?
                else {
                    return Ok(None);
                };
                requirements.push(requirement);
            }
            all.push(match keyword {
                "allOf" => SourceInputPresenceRequirement::All(requirements),
                "anyOf" => SourceInputPresenceRequirement::Any(requirements),
                _ => SourceInputPresenceRequirement::ExactlyOne(requirements),
            });
        }
    }
    if let Some(negated) = object.get("not") {
        let Some(requirement) =
            exact_presence_requirement(negated, root, declared, resolving, analysis, depth + 1)?
        else {
            return Ok(None);
        };
        all.push(SourceInputPresenceRequirement::Not(Box::new(requirement)));
    }
    if let Some(condition_schema) = object.get("if") {
        let Some(condition) = exact_presence_requirement(
            condition_schema,
            root,
            declared,
            resolving,
            analysis,
            depth + 1,
        )?
        else {
            return Ok(None);
        };
        let then_requirement = match object.get("then") {
            Some(branch) => {
                let Some(requirement) = exact_presence_requirement(
                    branch,
                    root,
                    declared,
                    resolving,
                    analysis,
                    depth + 1,
                )?
                else {
                    return Ok(None);
                };
                requirement
            }
            None => SourceInputPresenceRequirement::Always,
        };
        let else_requirement = match object.get("else") {
            Some(branch) => {
                let Some(requirement) = exact_presence_requirement(
                    branch,
                    root,
                    declared,
                    resolving,
                    analysis,
                    depth + 1,
                )?
                else {
                    return Ok(None);
                };
                requirement
            }
            None => SourceInputPresenceRequirement::Always,
        };
        all.push(SourceInputPresenceRequirement::Any(vec![
            SourceInputPresenceRequirement::All(vec![condition.clone(), then_requirement]),
            SourceInputPresenceRequirement::All(vec![
                SourceInputPresenceRequirement::Not(Box::new(condition)),
                else_requirement,
            ]),
        ]));
    }
    if let Some(dependencies) = object
        .get("dependentRequired")
        .and_then(JsonValue::as_object)
    {
        for (trigger, names) in dependencies {
            if !declared.contains(trigger.as_str()) {
                return Err(invalid_artifact(
                    "the selected route input schema has an undeclared dependency trigger",
                ));
            }
            let required = required_input_names(&serde_json::json!({"required": names}))?;
            validate_declared_required_inputs(&required, declared)?;
            all.push(SourceInputPresenceRequirement::DependentRequired {
                trigger: trigger.clone(),
                required,
            });
        }
    }
    if let Some(dependencies) = object
        .get("dependentSchemas")
        .and_then(JsonValue::as_object)
    {
        for (trigger, dependent) in dependencies {
            if !declared.contains(trigger.as_str()) {
                return Err(invalid_artifact(
                    "the selected route input schema has an undeclared dependency trigger",
                ));
            }
            let Some(requirement) = exact_presence_requirement(
                dependent,
                root,
                declared,
                resolving,
                analysis,
                depth + 1,
            )?
            else {
                return Ok(None);
            };
            all.push(SourceInputPresenceRequirement::DependentSchema {
                trigger: trigger.clone(),
                requirement: Box::new(requirement),
            });
        }
    }
    Ok(Some(SourceInputPresenceRequirement::All(all)))
}

fn validate_declared_required_inputs(
    required: &BTreeSet<String>,
    declared: &BTreeSet<&str>,
) -> Result<(), BundleError> {
    if required
        .iter()
        .any(|input| !declared.contains(input.as_str()))
    {
        return Err(invalid_artifact(
            "the selected route input schema requires an undeclared input",
        ));
    }
    Ok(())
}

fn required_input_names(schema: &JsonValue) -> Result<BTreeSet<String>, BundleError> {
    let Some(required) = schema.get("required") else {
        return Ok(BTreeSet::new());
    };
    let required = required.as_array().ok_or_else(|| {
        invalid_artifact("the selected route input schema has an invalid required member")
    })?;
    required
        .iter()
        .map(|name| {
            name.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                invalid_artifact("the selected route input schema has an invalid required member")
            })
        })
        .collect()
}

fn validate_source_input_mapping(
    source: &crate::config::SourceConfig,
    schema: &JsonValue,
    contract: &SourceInputPresenceContract,
) -> Result<(), BundleError> {
    let properties = schema
        .get("properties")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            invalid_artifact("the selected route input schema must declare properties")
        })?;
    if source
        .inputs
        .keys()
        .any(|input| !properties.contains_key(input))
    {
        return Err(invalid_artifact(
            "a source input mapping names an input the selected route does not declare",
        ));
    }
    let mapped = source
        .inputs
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if !contract.has_mappable_alternative(&mapped) {
        return Err(invalid_artifact(
            "source input mappings do not cover a required route input alternative",
        ));
    }
    Ok(())
}

fn insert_pack_reference(
    references: &mut BTreeMap<String, String>,
    path: &str,
    digest: &str,
) -> Result<(), BundleError> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(invalid_artifact("a source pack artifact path is invalid"));
    }
    if references
        .insert(path.to_owned(), digest.to_owned())
        .is_some_and(|existing| existing != digest)
    {
        return Err(invalid_artifact(
            "one source pack artifact path has conflicting digest pins",
        ));
    }
    Ok(())
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
                let (declared_id, declared_version) = crate::codelist::declared_identity(bytes)?;
                (declared_id == identifier && declared_version == version).then(|| path.clone())
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
                // A schema that does not read is refused by its own load.
                let document = Reader::new(path.as_str())
                    .scan(bytes)
                    .ok()
                    .flatten()?
                    .to_json_value();
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
    let valid_arity = match entrypoint_functions.as_slice() {
        [actual] => *actual == arity || (entrypoint == "extract" && *actual == 3),
        _ => false,
    };
    if !valid_arity {
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

/// Reviewed output structures keep their established YAML schema grammar and
/// identifier contract. Adapter source schemas use their own full JSON Schema
/// contract and cannot change which structured values Evidence may release.
fn validate_reviewed_output_schema(schema: &JsonValue) -> Result<(), BundleError> {
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
    if properties.is_empty() || properties.len() > 64 {
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
        || properties
            .keys()
            .any(|property| !required.contains(property.as_str()))
    {
        return Err(invalid_artifact(
            "fact schema must require its exact closed field set",
        ));
    }
    validate_reviewed_output_node(schema)
}

fn reviewed_output_node_type(
    object: &JsonMap<String, JsonValue>,
) -> Result<Option<&str>, BundleError> {
    match object.get("type") {
        Some(JsonValue::String(name)) => Ok(Some(name.as_str())),
        None => Ok(None),
        _ => Err(invalid_artifact(
            "schema node type is outside the closed Version 1 subset",
        )),
    }
}

fn validate_reviewed_output_node(node: &JsonValue) -> Result<(), BundleError> {
    let object = node
        .as_object()
        .ok_or(invalid_artifact("every schema node must be a typed object"))?;
    let Some(value_type) = reviewed_output_node_type(object)? else {
        if object
            .keys()
            .all(|key| matches!(key.as_str(), "$schema" | "$id" | "const"))
            && object
                .get("const")
                .is_some_and(reviewed_output_const_is_bounded)
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
                || properties
                    .keys()
                    .any(|property| !required.contains(property.as_str()))
            {
                return Err(invalid_artifact(
                    "schema objects must require their exact property set",
                ));
            }
            for property in properties.values() {
                validate_reviewed_output_node(property)?;
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
                if !value.is_array() || !reviewed_output_const_is_bounded(value) {
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
            validate_reviewed_output_node(
                object
                    .get("items")
                    .ok_or(invalid_artifact("schema arrays must close their item type"))?,
            )?;
        }
        "string" => {
            if object
                .get("format")
                .and_then(JsonValue::as_str)
                .is_some_and(|format| !matches!(format, "date" | "date-time" | "uuid"))
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
                Some("date" | "date-time" | "uuid")
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

fn reviewed_output_const_is_bounded(value: &JsonValue) -> bool {
    match value {
        JsonValue::Bool(_) => true,
        JsonValue::Number(value) => value.as_i64().is_some(),
        JsonValue::String(value) => value.len() <= 65_536,
        JsonValue::Array(values) => {
            values.len() <= 256 && values.iter().all(reviewed_output_const_is_bounded)
        }
        JsonValue::Object(values) => {
            values.len() <= 256
                && values.iter().all(|(name, value)| {
                    name.len() <= 1_024 && reviewed_output_const_is_bounded(value)
                })
        }
        JsonValue::Null => false,
    }
}

fn load_fact_schemas(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, JsonValue>, BundleError> {
    let source_paths = config
        .sources
        .iter()
        .map(|(_, source)| source.fact_schema().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let projected_paths = config
        .sources
        .iter()
        .filter(|(_, source)| source.projection.is_some())
        .map(|(_, source)| source.fact_schema().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let mut paths = source_paths.clone();
    paths.extend(reviewed_schema_paths(all_concepts(config), files)?);
    let mut schemas = BTreeMap::new();
    for path in paths {
        let bytes = files
            .get(&path)
            .ok_or_else(|| invalid_artifact("missing facts schema").in_artifact(&path))?;
        let schema = if source_paths.contains(&path) {
            let schema: JsonValue = serde_json::from_slice(bytes)
                .map_err(|_| invalid_artifact("facts schema is not JSON").in_artifact(&path))?;
            if projected_paths.contains(&path) {
                registry_adapter_engine::public_schema::check_public_schema(schema.clone())
                    .map_err(|_| invalid_artifact("projected facts require a versioned closed JSON Schema with bounded arrays and local references").in_artifact(&path))?;
            } else {
                check_schema(EvidenceSchemaKind::Facts, schema.clone()).map_err(|_| {
                    invalid_artifact("facts schema must be a closed JSON Schema 2020-12 object: the root and every object set `additionalProperties: false`, references stay inside the document, and the document stays within its size bounds").in_artifact(&path)
                })?;
            }
            schema
        } else {
            let schema = Reader::new(path.as_str())
                .scan(bytes)
                .map_err(|report| BundleError::Refused(Box::new(report)))?
                .ok_or_else(|| {
                    invalid_artifact("reviewed output schema is empty").in_artifact(&path)
                })?
                .to_json_value();
            validate_reviewed_output_schema(&schema).map_err(|error| error.in_artifact(&path))?;
            JSONSchema::options()
                .with_draft(Draft::Draft202012)
                .should_validate_formats(true)
                .with_format("uuid", crate::selector::canonical_uuid)
                .compile(&schema)
                .map_err(|_| {
                    invalid_artifact("reviewed output schema is not valid JSON Schema")
                        .in_artifact(&path)
                })?;
            schema
        };
        schemas.insert(path, schema);
    }
    Ok(schemas)
}

fn load_codelists(
    root: &Path,
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
        let codelist =
            load_codelist(root, &path, files).map_err(|error| error.in_artifact(&path))?;
        codelists.insert(path, codelist);
    }
    Ok(codelists)
}

/// Read one codelist the configuration references. A refusal names the file
/// as it sits under the bundle root.
fn load_codelist(
    root: &Path,
    path: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<Codelist, BundleError> {
    let bytes = files
        .get(path)
        .ok_or(invalid_artifact("missing codelist"))?;
    crate::codelist::read_codelist(&root.join(path).display().to_string(), bytes)
        .map_err(|report| BundleError::Refused(Box::new(report)))
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
    root: &Path,
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, JsonValue>, BundleError> {
    let mut fixtures = BTreeMap::new();
    for requirement in &config.requirements {
        let Some(fixture_path) = &requirement.fixtures else {
            continue;
        };
        let path = fixture_path.as_str();
        if fixtures.contains_key(path) {
            continue;
        }
        let fixture = load_fixture(root, path, files, false, config.assurance_profile)?;
        fixtures.insert(path.to_owned(), fixture);
    }
    Ok(fixtures)
}

fn load_fixture(
    root: &Path,
    path: &str,
    files: &BTreeMap<String, Vec<u8>>,
    declared_unresolved: bool,
    assurance_profile: AssuranceProfile,
) -> Result<JsonValue, BundleError> {
    let bytes = files
        .get(path)
        .ok_or(invalid_artifact("fixture file is missing"))?;
    crate::fixture::read_fixture(
        &root.join(path).display().to_string(),
        bytes,
        declared_unresolved,
        assurance_profile,
    )
    .map_err(|report| BundleError::Refused(Box::new(report)))
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

/// Parse the certificate chain the signing block names. The file belongs to
/// the active key (`public-keys/<kid>.chain.pem`), so rotating the key makes a
/// predecessor's chain a refused input rather than a silently reused one.
fn load_certificate_chain(
    config: &EvidenceConfig,
    files: &BTreeMap<String, Vec<u8>>,
    active: &PublicJwk,
) -> Result<Option<registry_platform_x509::X5cChain>, BundleError> {
    let Some(path) = &config.signing.certificate_chain_file else {
        return Ok(None);
    };
    let path = path.as_str();
    let load = || -> Result<registry_platform_x509::X5cChain, BundleError> {
        let active_kid = active
            .kid
            .as_deref()
            .ok_or(invalid_artifact("active public JWK kid is missing"))?;
        if path != format!("public-keys/{active_kid}.chain.pem") {
            return Err(invalid_artifact(
                "certificate chain filename does not match the active key's RFC 7638 thumbprint",
            ));
        }
        let bytes = files
            .get(path)
            .ok_or(invalid_artifact("certificate chain file is missing"))?;
        let chain = registry_platform_x509::X5cChain::from_pem(bytes)
            .map_err(|_| invalid_artifact("certificate chain is not a PEM certificate chain"))?;
        if chain.len() > crate::signing::maximum_certificate_chain_length() {
            return Err(invalid_artifact(
                "certificate chain is longer than the chain policy allows",
            ));
        }
        Ok(chain)
    };
    load().map(Some).map_err(|error| error.in_artifact(path))
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

fn validate_runtime_bindings(bundle: &Bundle, runtime: &RuntimeConfig) -> Result<(), BundleError> {
    let findings = runtime_binding_findings(bundle, runtime)
        .map_err(RuntimeBindingPlanError::into_bundle_error)?;
    match findings.into_iter().next() {
        Some(finding) => Err(finding.error),
        None => Ok(()),
    }
}

#[cfg(test)]
fn validate_config_runtime_bindings(
    bundle: &EvidenceConfig,
    runtime: &RuntimeConfig,
) -> Result<(), BundleError> {
    match config_runtime_binding_findings(bundle, runtime)
        .into_iter()
        .next()
    {
        Some(finding) => Err(finding.error),
        None => Ok(()),
    }
}

/// One way the runtime file fails to bind the bundle it names.
///
/// The pointer is the runtime-file member the operator edits to repair it, and
/// the action says how. The error is the one deployment refuses with.
#[derive(Debug, Clone)]
pub struct BindingFinding {
    pub code: &'static str,
    pub pointer: String,
    pub error: BundleError,
    pub action: &'static str,
}

/// Why the selected pack routes could not state their runtime extract needs.
///
/// The underlying engine error remains typed for the source-plan pass that
/// owns its diagnostic. Display is deliberately categorical so a pack-owned
/// route string or artifact detail never enters a runtime-file diagnostic.
#[derive(Debug, Error)]
pub enum RuntimeBindingPlanError {
    #[error("the runtime source acquisition limits are invalid")]
    Limits,
    #[error("the Evidence host protocol registry is unavailable")]
    HostProtocols,
    #[error("a selected Evidence source pack route cannot compile")]
    SourcePlan {
        artifact_prefix: String,
        #[source]
        error: EvidenceCompileError,
    },
    #[error("a selected Evidence source pack closure is unavailable")]
    SourcePack,
}

impl RuntimeBindingPlanError {
    /// A safe governed-artifact diagnosis retained by a structured compiler
    /// failure. Other plan categories remain categorical at this boundary.
    #[must_use]
    pub fn artifact_fault(&self) -> Option<ArtifactFault> {
        let Self::SourcePlan {
            artifact_prefix,
            error: EvidenceCompileError::Sqlite(fault),
        } = self
        else {
            return None;
        };
        let cause = match fault.cause() {
            registry_adapter_engine::component::sqlite_extract::SqliteExtractError::Statement(
                kind,
            ) => kind.cause(),
            registry_adapter_engine::component::sqlite_extract::SqliteExtractError::InvalidPlan => {
                "the reviewed SQLite extract plan is invalid"
            }
            _ => "the reviewed SQLite extract plan cannot compile",
        };
        Some(ArtifactFault::new(
            format!("{artifact_prefix}/{}", fault.artifact()),
            SchemaFault::because(cause),
        ))
    }

    pub(crate) fn into_bundle_error(self) -> BundleError {
        match self.artifact_fault() {
            Some(fault) => BundleError::InvalidArtifact(fault),
            None => {
                invalid_artifact("a selected source pack route cannot compile for runtime binding")
            }
        }
    }
}

/// Every way the runtime file fails to bind the bundle, in the order deployment
/// checks them, so an offline check reports them all and deployment refuses
/// with the first.
pub fn runtime_binding_findings(
    bundle: &Bundle,
    runtime: &RuntimeConfig,
) -> Result<Vec<BindingFinding>, RuntimeBindingPlanError> {
    let mut findings = config_runtime_binding_findings(&bundle.config, runtime);
    let named_extracts = required_extract_profiles(bundle, runtime)?;
    let bound_extracts = runtime
        .source_extracts
        .keys()
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    for unbound in named_extracts.difference(&bound_extracts) {
        findings.push(BindingFinding {
            code: "evidence.runtime.source-extract-unbound",
            pointer: "/sourceExtracts".to_owned(),
            error: invalid_artifact(
                "the runtime configuration binds no file for a source extract profile the bundle names",
            )
            .in_artifact(&source_extract_artifact(unbound)),
            action: "Bind the extract profile the bundle names under sourceExtracts, with the path of its extract file.",
        });
    }
    for unused in bound_extracts.difference(&named_extracts) {
        findings.push(BindingFinding {
            code: "evidence.runtime.source-extract-unused",
            pointer: format!(
                "/sourceExtracts/{}",
                registry_platform_yaml::escape_pointer_segment(unused)
            ),
            error: invalid_artifact(
                "the runtime configuration binds a source extract profile no bundle source names",
            )
            .in_artifact(&source_extract_artifact(unused)),
            action: "Remove the extract binding, or name the profile from a bundle source.",
        });
    }
    Ok(findings)
}

/// Compile the selected pack routes from their captured, digest-checked bytes
/// and return only the process-local extract profiles those routes can reach.
/// No runtime path, extract file, secret, credential, or network resource is
/// opened. A plan error stays explicit rather than becoming an empty set.
fn required_extract_profiles(
    bundle: &Bundle,
    runtime: &RuntimeConfig,
) -> Result<BTreeSet<String>, RuntimeBindingPlanError> {
    let limits: EvidenceLimits = runtime
        .source_acquisition
        .limits()
        .map_err(|_| RuntimeBindingPlanError::Limits)?;
    let protocols =
        crate::host_protocol::registry().map_err(|_| RuntimeBindingPlanError::HostProtocols)?;
    let mut profiles = BTreeSet::new();
    for (source_id, source) in bundle.config.sources.iter() {
        let closure = bundle
            .source_pack(source_id)
            .ok_or(RuntimeBindingPlanError::SourcePack)?;
        let pack = closure.pack();
        let artifacts = closure.artifacts();
        let program = compile_evidence_pack_with_protocols(
            &pack,
            source.route.as_str(),
            &artifacts,
            limits,
            &protocols,
        )
        .map_err(|error| RuntimeBindingPlanError::SourcePlan {
            artifact_prefix: source.pack.artifact_prefix.as_str().to_owned(),
            error,
        })?;
        profiles.extend(program.required_extract_profiles());
    }
    Ok(profiles)
}

/// Findings that need only the governed configuration projection. Pack-owned
/// runtime resources are added by [`runtime_binding_findings`].
fn config_runtime_binding_findings(
    bundle: &EvidenceConfig,
    runtime: &RuntimeConfig,
) -> Vec<BindingFinding> {
    let mut findings = Vec::new();
    let mut find =
        |code: &'static str, pointer: String, error: BundleError, action: &'static str| {
            findings.push(BindingFinding {
                code,
                pointer,
                error,
                action,
            });
        };
    let signer_matches_assurance = match bundle.assurance_profile {
        crate::config::AssuranceProfile::Local => runtime.signer.is_local_jwk(),
        crate::config::AssuranceProfile::Production
        | crate::config::AssuranceProfile::EvidenceGrade => runtime.signer.is_transit(),
    };
    if !signer_matches_assurance {
        find(
            "evidence.runtime.signer-assurance-mismatch",
            "/signer/type".to_owned(),
            invalid_artifact("runtime signer kind does not match the bundle assurance profile"),
            "Write type: local-jwk for a local bundle, or type: transit for a production or evidence-grade bundle.",
        );
    }
    // A governed reference resolves only through a provider the operator
    // enabled, so the bundle cannot reach the process environment unless the
    // runtime file opts in to it.
    let governed_refs = [
        &bundle.audit.key.hash_key_ref,
        &bundle.subject_binding.secret_ref,
    ];
    if governed_refs.into_iter().any(|reference| {
        runtime
            .secret_providers
            .check_reference("secretProviders", reference.as_str())
            .is_err()
    }) {
        find(
            "evidence.runtime.secret-provider-not-enabled",
            "/secretProviders".to_owned(),
            invalid_artifact(
                "a bundle secret reference names a provider the runtime secretProviders does not enable",
            ),
            "Enable every provider the bundle's secret references name under secretProviders.",
        );
    }
    let audit_ref = &bundle.audit.key.hash_key_ref;
    let subject_ref = &bundle.subject_binding.secret_ref;
    if let Some(signing_ref) = runtime.signer.private_key_ref() {
        if signing_ref == audit_ref || signing_ref == subject_ref {
            find(
                "evidence.runtime.signing-key-shared",
                "/signer/privateKeyRef".to_owned(),
                invalid_artifact(
                    "the local signing key reference must be distinct from audit and subject-binding references",
                ),
                "Reference a signing key no other bundle secret reference names.",
            );
        }
    }
    let secret_root = runtime
        .secret_providers
        .file
        .as_ref()
        .map(|file| file.root.as_path());
    if let Some(audit_path) = runtime.audit.path.as_deref().map(Path::new) {
        let configured_secret_paths = [
            Some(audit_ref),
            Some(subject_ref),
            runtime.signer.private_key_ref(),
        ]
        .into_iter()
        .flatten()
        .filter_map(|reference| reference.as_str().strip_prefix("secret:file/"))
        .filter_map(|name| secret_root.map(|root| root.join(name)));
        if configured_secret_paths
            .into_iter()
            .any(|path| path == audit_path)
        {
            find(
                "evidence.runtime.audit-path-is-secret",
                "/audit/path".to_owned(),
                invalid_artifact(
                    "the audit file path must not resolve to configured secret material",
                ),
                "Write an audit path outside the secret root.",
            );
        }
    }
    // Global trust profiles belong to the access-token issuer. The binding is
    // exact in both directions: a profile the issuer names must be present,
    // while a global profile the issuer does not name grants unrequested
    // authority and must be removed.
    let required = bundle
        .authentication
        .oidc
        .tls_trust_profile
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let configured = runtime
        .outbound_tls
        .trust_profiles
        .keys()
        .collect::<BTreeSet<_>>();
    for unbound in required.difference(&configured) {
        find(
            "evidence.runtime.trust-profile-unbound",
            "/outboundTls/trustProfiles".to_owned(),
            trust_profile_fault(
                unbound,
                "the runtime configuration does not bind a TLS trust profile the bundle names",
            ),
            "Bind the trust profile the bundle names under outboundTls.trustProfiles, with its CA bundle file.",
        );
    }
    for unused in configured.difference(&required) {
        find(
            "evidence.runtime.trust-profile-unused",
            format!(
                "/outboundTls/trustProfiles/{}",
                registry_platform_yaml::escape_pointer_segment(unused)
            ),
            trust_profile_fault(
                unused,
                "the runtime configuration binds a TLS trust profile the bundle does not name",
            ),
            "Remove the trust profile, or name it from the access-token issuer.",
        );
    }
    // Source trust material is scoped to its named connection. This preflight
    // checks only that a governed endpoint's selected profile exists under the
    // matching runtime connection. Program compilation still owns exact
    // endpoint binding and captured-CA validation, and extra source profiles
    // confer no authority because no governed policy can select them.
    for (connection, policies) in bundle.source_connections.iter() {
        let Some(bindings) = runtime.source_connections.get(connection) else {
            continue;
        };
        let required_profiles = policies
            .endpoints
            .iter()
            .filter_map(|policy| {
                policy
                    .tls_trust_profile
                    .as_ref()
                    .map(|profile| profile.as_str())
            })
            .collect::<BTreeSet<_>>();
        for profile in required_profiles {
            let present = bindings
                .outbound_tls
                .as_ref()
                .is_some_and(|tls| tls.trust_profiles.contains_key(profile));
            if !present {
                find(
                    "evidence.runtime.source-trust-profile-unbound",
                    format!(
                        "/sourceConnections/{}/outboundTls/trustProfiles",
                        registry_platform_yaml::escape_pointer_segment(connection)
                    ),
                    trust_profile_fault(
                        profile,
                        "the runtime configuration does not bind a TLS trust profile the bundle names",
                    ),
                    "Bind the profile under this source connection's outboundTls.trustProfiles, with its CA bundle file.",
                );
            }
        }
    }
    let governed_connections = bundle.source_connections.keys().collect::<BTreeSet<_>>();
    let runtime_connections = runtime.source_connections.keys().collect::<BTreeSet<_>>();
    for _unbound in governed_connections.difference(&runtime_connections) {
        find(
            "evidence.runtime.source-connection-unbound",
            "/sourceConnections".to_owned(),
            invalid_artifact(
                "the runtime configuration does not bind a governed source connection",
            ),
            "Bind every governed source connection under runtime sourceConnections with the same id.",
        );
    }
    for unused in runtime_connections.difference(&governed_connections) {
        find(
            "evidence.runtime.source-connection-unused",
            format!(
                "/sourceConnections/{}",
                registry_platform_yaml::escape_pointer_segment(unused)
            ),
            invalid_artifact(
                "the runtime configuration binds no governed source connection by this name",
            ),
            "Remove the runtime source connection, or declare its reviewed policy in the bundle.",
        );
    }
    findings
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

pub(crate) fn validate_ca_bundle(bytes: &[u8]) -> Result<(), BundleError> {
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

/// One configuration revision per configured requirement.
///
/// Each digest covers exactly what can change that requirement's assertions:
/// the canonical projection of the configuration it depends on, and the exact
/// bytes of every artifact it reaches. Requirements in one bundle therefore no
/// longer share a revision, so an edit that serves one of them does not
/// invalidate the revision a relying party pinned for another.
fn compute_requirement_revisions(
    config: &EvidenceConfig,
    source_packs: &BTreeMap<String, SourcePack>,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, String>, BundleError> {
    let mut revisions = BTreeMap::new();
    for requirement in &config.requirements {
        let mut closure = BTreeMap::from([(
            PROJECTION_PATH.to_owned(),
            canonical_projection(config, requirement)?,
        )]);
        for path in requirement_artifact_paths(config, source_packs, requirement, files)? {
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
/// grants use. The active and published public signing keys are not in any
/// requirement's closure: they are trust a relying party takes from the JWKS,
/// and the package digest still covers them.
fn requirement_artifact_paths(
    config: &EvidenceConfig,
    source_packs: &BTreeMap<String, SourcePack>,
    requirement: &RequirementConfig,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeSet<String>, BundleError> {
    let mut paths = BTreeSet::new();
    for source_id in requirement.acquisition.source_ids() {
        let source = config.sources.get(source_id).ok_or_else(|| {
            invalid_artifact("the requirement names a source the configuration does not define")
        })?;
        let pack = source_packs
            .get(source_id)
            .ok_or_else(|| invalid_artifact("the requirement's source pack closure is missing"))?;
        paths.extend(pack.artifact_paths.iter().cloned());
        paths.insert(source.fact_schema().as_str().to_owned());
        if let Some(projection) = &source.projection {
            paths.insert(projection.script.as_str().to_owned());
        }
    }
    paths.insert(requirement.derivation.script.as_str().to_owned());
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
    let _ = config;
    requirement
        .subject_roles
        .iter()
        .flat_map(|role| role.selector_profiles.iter().cloned())
        .collect()
}

/// The canonical behavior closure for one assertion definition. It retains
/// fixed source plans, selectors, function assets, output semantics and package
/// ceilings. Presentation, fixtures and independently governed target bindings
/// have package/authority identities of their own and cannot churn this pin.
fn canonical_projection(
    config: &EvidenceConfig,
    requirement: &RequirementConfig,
) -> Result<Vec<u8>, BundleError> {
    let mut document = serde_json::to_value(config)
        .map_err(|_| invalid_artifact("the configuration does not project"))?;
    let members = document
        .as_object_mut()
        .ok_or_else(|| invalid_artifact("the configuration does not project as a mapping"))?;
    for deployment_member in [
        PROVIDER_PUBLICATION,
        "project",
        "service",
        "issuer",
        "authentication",
        "audit",
        "subjectBinding",
        "rateLimits",
        "signing",
        "authorityProfiles",
        "assuranceProfile",
    ] {
        members.remove(deployment_member);
    }
    if requirement.subject_binding_mode() != crate::config::SubjectBindingMode::HolderBound {
        members.remove("maximumHolderBoundBatchSize");
    }
    // Package-wide enablement must not churn pins for definitions that do not
    // expose the added representation. The definition owns its release set.
    let effective_formats = config
        .response_formats
        .iter()
        .filter(|format| {
            requirement.representations.as_ref().map_or_else(
                || {
                    crate::config::subject_binding_permits_response_format(
                        requirement.subject_binding_mode(),
                        **format,
                    )
                },
                |declared| declared.contains(format),
            )
        })
        .collect::<Vec<_>>();
    members.insert(
        "responseFormats".to_owned(),
        serde_json::to_value(effective_formats)
            .map_err(|_| invalid_artifact("definition representations do not project"))?,
    );
    let mut requirement_value = serde_json::to_value(requirement)
        .map_err(|_| invalid_artifact("the requirement does not project"))?;
    if let Some(definition) = requirement_value.as_object_mut() {
        definition.remove("question");
        definition.remove("fixtures");
        definition.remove("handle");
    }
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
    let source_connections = acquisition_sources
        .iter()
        .filter_map(|source_id| config.sources.get(source_id))
        .map(|source| source.connection())
        .collect::<BTreeSet<_>>();
    retain_members(members, "sourceConnections", |name| {
        source_connections.contains(name)
    })?;
    retain_members(members, "selectorProfiles", |name| profiles.contains(name))?;
    preserve_selector_field_order(members, config, &profiles)?;
    // RFC 8785 canonicalization, shared with the rest of the stack, makes
    // order-insensitive mappings and number formatting deterministic. The one
    // mapping whose declaration order changes assertion bytes is projected as
    // a sequence first, so canonicalization cannot erase that distinction.
    canonicalize_json(&document)
        .map_err(|_| invalid_artifact("the projection does not canonicalize"))
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
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
    use super::*;
    use crate::config::AssuranceProfile;
    use crate::kernel::OfflineKernel;

    fn mapped_inputs<'a>(names: &'a [&'a str]) -> BTreeSet<&'a str> {
        names.iter().copied().collect()
    }

    #[test]
    fn constrained_one_of_retains_each_branch_required_input_set() {
        let schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "licence_reference": {"type": "string"},
                "registry_region": {"type": "string"}
            },
            "oneOf": [
                {
                    "required": ["licence_reference", "registry_region"],
                    "additionalProperties": false,
                    "properties": {
                        "licence_reference": {"type": "string", "pattern": "^A"},
                        "registry_region": {"type": "string"}
                    }
                },
                {
                    "required": ["licence_reference", "registry_region"],
                    "additionalProperties": false,
                    "properties": {
                        "licence_reference": {"type": "string"},
                        "registry_region": {"type": "string", "const": "B"}
                    }
                }
            ]
        });
        check_schema(EvidenceSchemaKind::Inputs, schema.clone())
            .expect("the constrained oneOf is a supported checked input schema");
        let contract = source_input_presence_contract(&schema)
            .expect("the bounded constrained oneOf has a presence contract");

        assert!(!contract.has_mappable_alternative(&mapped_inputs(&["licence_reference"])));
        assert!(!contract.has_mappable_alternative(&mapped_inputs(&["registry_region"])));
        assert!(contract
            .has_mappable_alternative(&mapped_inputs(&["licence_reference", "registry_region"])));
    }

    #[test]
    fn root_presence_analysis_composes_any_all_and_conditionals() {
        let contract = source_input_presence_contract(&serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "c": {"type": "string"}
            },
            "allOf": [
                {"anyOf": [{"required": ["a"]}, {"required": ["c"]}]},
                {
                    "if": {"required": ["a"]},
                    "then": {"required": ["b"]},
                    "else": {"required": ["c"]}
                }
            ]
        }))
        .expect("the composed root presence grammar is supported");

        assert!(!contract.accepts_path(&mapped_inputs(&["a"])));
        assert!(contract.accepts_path(&mapped_inputs(&["a", "b"])));
        assert!(contract.accepts_path(&mapped_inputs(&["c"])));
        assert!(!contract.accepts_path(&mapped_inputs(&["a", "c"])));
    }

    #[test]
    fn pure_one_of_exactness_is_conjunctive_with_other_root_requirements() {
        let contract = source_input_presence_contract(&serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "shared": {"type": "string"}
            },
            "allOf": [{"required": ["shared"]}],
            "oneOf": [{"required": ["a"]}, {"required": ["b"]}]
        }))
        .expect("the pure oneOf and root allOf have one presence contract");

        assert!(!contract.accepts_path(&mapped_inputs(&["a"])));
        assert!(contract.accepts_path(&mapped_inputs(&["a", "shared"])));
        assert!(!contract.accepts_path(&mapped_inputs(&["a", "b", "shared"])));
    }

    #[test]
    fn referenced_nested_pure_one_of_retains_exactly_one_semantics() {
        let schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "a": {"type": "string"},
                "b": {"type": "string"}
            },
            "$defs": {
                "choice": {
                    "oneOf": [{"required": ["a"]}, {"required": ["b"]}]
                }
            },
            "allOf": [{"$ref": "#/$defs/choice"}]
        });
        check_schema(EvidenceSchemaKind::Inputs, schema.clone())
            .expect("the referenced nested oneOf is a supported input schema");
        let contract = source_input_presence_contract(&schema)
            .expect("the referenced nested oneOf has a presence contract");

        assert!(contract.accepts_path(&mapped_inputs(&["a"])));
        assert!(contract.accepts_path(&mapped_inputs(&["b"])));
        assert!(!contract.accepts_path(&mapped_inputs(&["a", "b"])));
    }

    #[test]
    fn nested_one_of_retains_exact_dependent_presence_semantics() {
        for structural_branch in [
            serde_json::json!({"dependentRequired": {"a": ["b"]}}),
            serde_json::json!({"dependentSchemas": {"a": {"required": ["b"]}}}),
            serde_json::json!({
                "if": {"required": ["a"]},
                "then": {"required": ["b"]}
            }),
        ] {
            let contract = source_input_presence_contract(&serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "a": {"type": "string"},
                    "b": {"type": "string"}
                },
                "allOf": [{
                    "oneOf": [structural_branch, {"required": ["a"]}]
                }]
            }))
            .expect("the dependent presence oneOf is supported");

            assert!(contract.accepts_path(&mapped_inputs(&["a"])));
            assert!(!contract.accepts_path(&mapped_inputs(&["a", "b"])));
        }
    }

    #[test]
    fn named_anchor_and_pure_double_negation_retain_required_presence() {
        for schema in [
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"a": {"type": "string"}},
                "$defs": {
                    "anchored": {"$anchor": "needs-a", "required": ["a"]}
                },
                "allOf": [{"$ref": "#needs-a"}]
            }),
            serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"a": {"type": "string"}},
                "not": {"not": {"required": ["a"]}}
            }),
        ] {
            check_schema(EvidenceSchemaKind::Inputs, schema.clone())
                .expect("the structural presence schema is supported");
            let contract = source_input_presence_contract(&schema)
                .expect("the structural schema has a presence contract");
            assert!(!contract.accepts_path(&mapped_inputs(&[])));
            assert!(contract.accepts_path(&mapped_inputs(&["a"])));
        }
    }

    #[test]
    fn named_anchor_resolution_ignores_anchor_shaped_instance_values() {
        let schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"a": {"type": "string"}},
            "$defs": {
                "a-fake": {"const": {"$anchor": "needs-a"}},
                "z-real": {"$anchor": "needs-a", "required": ["a"]}
            },
            "allOf": [{"$ref": "#needs-a"}]
        });
        check_schema(EvidenceSchemaKind::Inputs, schema.clone())
            .expect("anchor-shaped instance data is not a schema anchor");
        let contract = source_input_presence_contract(&schema)
            .expect("the real named anchor has a presence contract");

        assert!(!contract.accepts_path(&mapped_inputs(&[])));
        assert!(contract.accepts_path(&mapped_inputs(&["a"])));
    }

    #[test]
    fn duplicated_reference_expansion_is_bounded() {
        const LEVELS: usize = 14;
        let mut definitions = serde_json::Map::new();
        for level in 0..LEVELS {
            let next = format!("#/$defs/level{}", level + 1);
            definitions.insert(
                format!("level{level}"),
                serde_json::json!({"allOf": [{"$ref": next}, {"$ref": next}]}),
            );
        }
        definitions.insert(
            format!("level{LEVELS}"),
            serde_json::json!({"required": ["a"]}),
        );
        let schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"a": {"type": "string"}},
            "$defs": definitions,
            "allOf": [{"$ref": "#/$defs/level0"}]
        });
        check_schema(EvidenceSchemaKind::Inputs, schema.clone())
            .expect("the duplicated acyclic reference DAG is a valid checked schema");

        let error = source_input_presence_contract(&schema)
            .expect_err("presence analysis must stop at its total expansion budget");
        assert!(
            error
                .to_string()
                .contains("route input presence analysis exceeds its bound"),
            "{error}"
        );
    }

    #[test]
    fn package_mappability_does_not_treat_every_optional_mapping_as_one_target_path() {
        let contract = source_input_presence_contract(&serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "a": {"type": "string"},
                "optional": {"type": "string"}
            },
            "oneOf": [
                {"required": ["a"], "not": {"required": ["optional"]}},
                {"required": ["optional"], "not": {"required": ["a"]}}
            ]
        }))
        .expect("the mutually exclusive optional mappings have a presence contract");

        assert!(contract.has_mappable_alternative(&mapped_inputs(&["a", "optional"])));
        assert!(contract.accepts_path(&mapped_inputs(&["a"])));
        assert!(contract.accepts_path(&mapped_inputs(&["optional"])));
        assert!(!contract.accepts_path(&mapped_inputs(&["a", "optional"])));
    }

    fn captured_pack_source() -> (crate::config::SourceConfig, BTreeMap<String, Vec<u8>>) {
        captured_pack_source_with_schemas(
            serde_json::json!({
                "type":"object",
                "additionalProperties":false,
                "required":["personId"],
                "properties":{"personId":{"type":"string"}}
            }),
            serde_json::json!({
                "type":"object",
                "additionalProperties":false,
                "required":["parents"],
                "properties":{"parents":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["name"],"properties":{"name":{"type":"string"},"verified":{"type":"boolean"}}}}}
            }),
        )
    }

    fn captured_pack_source_with_schemas(
        inputs: JsonValue,
        facts: JsonValue,
    ) -> (crate::config::SourceConfig, BTreeMap<String, Vec<u8>>) {
        let inputs = serde_json::to_vec(&inputs).unwrap();
        let facts = serde_json::to_vec(&facts).unwrap();
        let pack_bytes = serde_json::to_vec(&serde_json::json!({
            "apiVersion":"id.registrystack.org/formats/adapter/pack/v1alpha1",
            "kind":"AdapterPack",
            "id":"synthetic-register",
            "version":"0.1.0",
            "testedVersions":[],
            "sourceRoutes":[{
                "id":"evidence-family",
                "evidence":{
                    "inputsSchema":{"path":"schemas/inputs.json","digest":sha256_uri(&inputs)},
                    "factsSchema":{"path":"schemas/facts.json","digest":sha256_uri(&facts)}
                }
            }]
        }))
        .unwrap();
        let digest = sha256_uri(&pack_bytes);
        let prefix = format!(
            "adapter-packs/synthetic-register/{}",
            digest.strip_prefix("sha256:").unwrap()
        );
        let source = serde_json::from_value(serde_json::json!({
            "pack":{"id":"synthetic-register","version":"0.1.0","digest":digest,"artifactPrefix":prefix},
            "route":"evidence-family",
            "connection":"register",
            "inputs":{"personId":{"selector":{"role":"person","profile":"person-by-id","field":"person-id"}}},
            "posture":"record-transformed",
            "factSchema":"schemas/source-facts/family.json"
        }))
        .unwrap();
        let files = BTreeMap::from([
            (format!("{prefix}/pack.yaml"), pack_bytes),
            (format!("{prefix}/schemas/inputs.json"), inputs),
            (format!("{prefix}/schemas/facts.json"), facts.clone()),
            ("schemas/source-facts/family.json".to_owned(), facts),
        ]);
        (source, files)
    }

    #[test]
    fn captured_pack_closure_is_exact_and_preserves_nested_optional_facts() {
        let (source, files) = captured_pack_source();
        let checked = load_source_pack(&source, &files).expect("exact pack closure loads");
        assert_eq!(checked.pack.id.as_str(), "synthetic-register");
        assert_eq!(checked.pack.version, "0.1.0");

        let mut changed = files.clone();
        changed.insert(
            "schemas/source-facts/family.json".to_owned(),
            br#"{"type":"object","additionalProperties":false}"#.to_vec(),
        );
        assert!(load_source_pack(&source, &changed).is_err());

        let mut overclaimed = files;
        let prefix = source.pack.artifact_prefix.as_str();
        overclaimed.insert(format!("{prefix}/unreviewed.txt"), b"extra".to_vec());
        assert!(load_source_pack(&source, &overclaimed).is_err());
    }

    #[test]
    fn captured_pack_refuses_a_stronger_posture_than_the_selected_route() {
        let (mut source, files) = captured_pack_source();
        source.posture = AcquisitionPosture::SourceDerived;

        assert_eq!(
            refusal_cause(
                load_source_pack(&source, &files)
                    .expect_err("a record-transformed route cannot be claimed source-derived")
            ),
            "the source binding claims a stronger acquisition posture than the selected pack route"
        );
    }

    #[test]
    fn a_selected_pack_may_share_one_schema_path_only_under_one_digest_pin() {
        fn repin(
            source: &mut crate::config::SourceConfig,
            files: &mut BTreeMap<String, Vec<u8>>,
            pack: &JsonValue,
        ) {
            let old_prefix = source.pack.artifact_prefix.as_str().to_owned();
            let pack_bytes = serde_json::to_vec(pack).expect("pack serializes");
            let digest = sha256_uri(&pack_bytes);
            let new_prefix = format!(
                "adapter-packs/{}/{}",
                source.pack.id,
                digest.strip_prefix("sha256:").unwrap()
            );
            let old_root = format!("{old_prefix}/");
            let moved = files
                .iter()
                .filter_map(|(path, bytes)| {
                    path.strip_prefix(&old_root)
                        .map(|relative| (format!("{new_prefix}/{relative}"), bytes.clone()))
                })
                .collect::<Vec<_>>();
            files.retain(|path, _| !path.starts_with(&old_root));
            files.extend(moved);
            files.insert(format!("{new_prefix}/pack.yaml"), pack_bytes);
            source.pack.digest = registry_platform_yaml::Digest::new(digest).unwrap();
            source.pack.artifact_prefix = crate::config::ArtifactPath::parse(&new_prefix).unwrap();
        }

        let (mut shared_source, mut shared_files) = captured_pack_source();
        let shared_prefix = shared_source.pack.artifact_prefix.as_str().to_owned();
        let shared_pack_path = format!("{shared_prefix}/pack.yaml");
        let shared_schema_path = format!("{shared_prefix}/schemas/inputs.json");
        let displaced_facts_path = format!("{shared_prefix}/schemas/facts.json");
        let shared_schema = shared_files[&shared_schema_path].clone();
        let mut shared_pack: JsonValue =
            serde_json::from_slice(&shared_files[&shared_pack_path]).unwrap();
        shared_pack["sourceRoutes"][0]["evidence"]["factsSchema"] = serde_json::json!({
            "path": "schemas/inputs.json",
            "digest": sha256_uri(&shared_schema)
        });
        shared_files.remove(&displaced_facts_path);
        shared_files.insert(
            shared_source.fact_schema().as_str().to_owned(),
            shared_schema,
        );
        repin(&mut shared_source, &mut shared_files, &shared_pack);
        load_source_pack(&shared_source, &shared_files)
            .expect("one reviewed schema may serve both declared roles");

        let (mut conflicting_source, mut conflicting_files) = captured_pack_source();
        let conflicting_prefix = conflicting_source.pack.artifact_prefix.as_str().to_owned();
        let conflicting_pack_path = format!("{conflicting_prefix}/pack.yaml");
        let conflicting_facts_path = format!("{conflicting_prefix}/schemas/facts.json");
        let mut conflicting_pack: JsonValue =
            serde_json::from_slice(&conflicting_files[&conflicting_pack_path]).unwrap();
        conflicting_pack["sourceRoutes"][0]["evidence"]["factsSchema"]["path"] =
            "schemas/inputs.json".into();
        conflicting_files.remove(&conflicting_facts_path);
        repin(
            &mut conflicting_source,
            &mut conflicting_files,
            &conflicting_pack,
        );
        assert_eq!(
            refusal_cause(
                load_source_pack(&conflicting_source, &conflicting_files)
                    .expect_err("one path cannot carry conflicting digest pins")
            ),
            "one source pack artifact path has conflicting digest pins"
        );
    }

    #[test]
    fn captured_pack_requires_the_adapter_pack_envelope() {
        let (source, files) = captured_pack_source();
        let path = format!("{}/pack.yaml", source.pack.artifact_prefix.as_str());

        for mutation in [
            |document: &mut JsonValue| {
                document.as_object_mut().unwrap().remove("apiVersion");
                document.as_object_mut().unwrap().remove("kind");
            },
            |document: &mut JsonValue| document["kind"] = serde_json::json!("AdapterProject"),
        ] {
            let mut changed = files.clone();
            let mut document: JsonValue = serde_json::from_slice(&changed[&path]).unwrap();
            mutation(&mut document);
            let bytes = serde_json::to_vec(&document).unwrap();
            changed.insert(path.clone(), bytes.clone());
            let mut source = source.clone();
            source.pack.digest = registry_platform_yaml::Digest::new(sha256_uri(&bytes)).unwrap();
            assert!(load_source_pack(&source, &changed).is_err());
        }
    }

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
    fn definition_projection_excludes_connection_bindings_and_covers_selected_behavior() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .unwrap();
        let requirement = config.requirements[0].clone();
        let source_id = requirement.acquisition.initial_source().to_owned();
        let mut document = serde_json::to_value(&config).unwrap();
        let project = |document: &JsonValue| {
            let candidate = EvidenceConfig::parse_projection(document)
                .expect("each compared candidate is valid");
            canonical_projection(&candidate, &requirement).unwrap()
        };
        // Normalize both sides through the same JSON roundtrip, which sorts
        // the selector-field map before the binding-order projection.
        let baseline = project(&document);
        let connection = document["sourceConnections"]["provider"].clone();
        document["sourceConnections"]["unreached"] = connection;
        assert!(
            baseline == project(&document),
            "an unselected governed connection must not change a requirement"
        );

        let selected = project(&document);
        document["sourceConnections"]["unreached"]["endpoints"][0]["baseUrl"] =
            "https://unselected.invalid".into();
        assert_eq!(selected, project(&document));
        document["sourceConnections"]["provider"]["endpoints"][0]["baseUrl"] =
            "https://reviewed-source.invalid".into();
        assert!(
            selected != project(&document),
            "the selected governed connection authority changes the behavior pin"
        );

        let before_pack = project(&document);
        document["sources"][&source_id]["pack"]["version"] = "2".into();
        assert_ne!(before_pack, project(&document));
        assert!(
            !String::from_utf8(project(&document))
                .unwrap()
                .contains("tokenRef"),
            "process-local credential bindings are absent from the governed projection"
        );
    }

    #[test]
    fn authority_activation_package_loading_honors_the_runtime_expected_digest() {
        let directory = tempfile::tempdir().unwrap();
        copy_acceptance_bundle("adult-status", directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let actual = Bundle::load(directory.path()).unwrap();
        let mut package = registry_platform_config::PackageConfig {
            root: directory.path().to_path_buf(),
            expected_digest: Some(actual.package_digest().to_owned()),
        };
        Bundle::load_pinned(&package).expect("exact configured pin loads for activation");
        package.expected_digest = Some(format!("sha256:{}", "f".repeat(64)));
        assert!(
            matches!(Bundle::load_pinned(&package), Err(BundleError::Package(_))),
            "activation cannot acknowledge another package than the configured pin"
        );
    }

    #[test]
    fn package_digest_binds_paths_and_exact_bytes_deterministically() {
        let first = BTreeMap::from([
            (
                "evidence.yaml".to_owned(),
                b"kind: EvidenceBundle\n".to_vec(),
            ),
            ("schemas/facts.yaml".to_owned(), b"type: object\n".to_vec()),
        ]);
        let same = BTreeMap::from([
            ("schemas/facts.yaml".to_owned(), b"type: object\n".to_vec()),
            (
                "evidence.yaml".to_owned(),
                b"kind: EvidenceBundle\n".to_vec(),
            ),
        ]);
        let digest = |files: &BTreeMap<String, Vec<u8>>| {
            registry_platform_config::plan_package(
                Path::new("evidence-package"),
                files,
                None,
                &evidence_package_limits(),
                "evidencectl package",
            )
            .expect("the package digest plans")
        };
        assert_eq!(digest(&first), digest(&same));

        let renamed = BTreeMap::from([
            (
                "evidence.yaml".to_owned(),
                b"kind: EvidenceBundle\n".to_vec(),
            ),
            ("schemas/other.yaml".to_owned(), b"type: object\n".to_vec()),
        ]);
        assert_ne!(digest(&first), digest(&renamed));
    }

    #[cfg(unix)]
    fn refresh_package_envelope(root: &Path) {
        for reserved in [SUM_FILE, registry_platform_config::REVISION_FILE] {
            let path = root.join(reserved);
            if path.exists() {
                fs::remove_file(path).expect("remove the prior package envelope");
            }
        }
        registry_platform_config::write_sum_file(
            root,
            None,
            &evidence_package_limits(),
            "evidencectl package",
        )
        .expect("refresh the package envelope");
    }

    #[cfg(unix)]
    #[test]
    fn package_verification_names_changed_missing_and_extra_files() {
        type MutationCase = (&'static str, fn(&Path), &'static str);
        let cases: [MutationCase; 3] = [
            (
                "changed",
                |root: &Path| {
                    fs::write(
                        root.join("derivations/adult-status.rhai"),
                        "fn derive(_) { no_match() }\n",
                    )
                    .expect("change a listed artifact");
                },
                "changed: derivations/adult-status.rhai",
            ),
            (
                "missing",
                |root: &Path| {
                    fs::remove_file(root.join("derivations/adult-status.rhai"))
                        .expect("remove a listed artifact");
                },
                "missing: derivations/adult-status.rhai",
            ),
            (
                "extra",
                |root: &Path| {
                    fs::write(root.join("schemas/unlisted.yaml"), "type: object\n")
                        .expect("add an unlisted artifact");
                },
                "extra: schemas/unlisted.yaml",
            ),
        ];
        for (case, mutate, expected) in cases {
            let directory = tempfile::tempdir().expect("temporary package");
            copy_acceptance_bundle("adult-status", directory.path());
            mutate(directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);
            let error = Bundle::load(directory.path()).expect_err(case);
            assert!(error.to_string().contains(expected), "{error}");
            set_tree_mode(directory.path(), 0o755, 0o644);
        }
    }

    #[cfg(unix)]
    #[test]
    fn package_digest_is_repeatable_and_unpinned_packages_are_verified() {
        let directory = tempfile::tempdir().expect("temporary package");
        copy_acceptance_bundle("adult-status", directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let first = Bundle::load(directory.path()).expect("the unpinned package loads");
        let again = Bundle::load(directory.path()).expect("the same package reloads");
        assert_eq!(first.package_digest(), again.package_digest());
        assert!(first.package_digest().starts_with("sha256:"));
    }

    #[cfg(unix)]
    #[test]
    fn consumer_capture_refuses_bytes_replaced_after_package_verification() {
        let directory = tempfile::tempdir().expect("temporary package");
        copy_acceptance_bundle("adult-status", directory.path());
        let verified = verify_package(
            directory.path(),
            &evidence_package_limits(),
            "evidencectl package",
        )
        .expect("the package verifies");
        fs::write(
            directory.path().join("derivations/adult-status.rhai"),
            "fn derive(_) { no_match() }\n",
        )
        .expect("replace a verified artifact");
        set_tree_mode(directory.path(), 0o555, 0o444);
        let error = capture_bundle_files(directory.path(), &verified, Capture::Frozen)
            .expect_err("consumer capture refuses replaced bytes");
        let fault = error.artifact_fault().expect("the artifact is named");
        assert_eq!(fault.artifact(), "derivations/adult-status.rhai");
        assert_eq!(
            fault.fault().cause(),
            "the package artifact was replaced after package verification"
        );
        set_tree_mode(directory.path(), 0o755, 0o644);
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
        refresh_package_envelope(directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let before = requirement_revisions(directory.path());

        set_tree_mode(directory.path(), 0o755, 0o644);
        edit(directory.path());
        refresh_package_envelope(directory.path());
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

    #[cfg(unix)]
    #[test]
    fn provider_publication_changes_leave_requirement_semantic_revisions_alone() {
        let (before, after) = revisions_across_edit(|root| {
            let config_path = root.join(CONFIG_FILE);
            let mut text = fs::read_to_string(&config_path).expect("the configuration reads");
            let original = "title: Synthetic Evidence service";
            assert_eq!(text.matches(original).count(), 1, "fixture title is stable");
            text = text.replace(original, "title: Reviewed Evidence service");
            fs::write(&config_path, text).expect("the configuration writes");
            let config = EvidenceConfig::parse_yaml(
                &fs::read(&config_path).expect("the edited configuration reads"),
            )
            .expect("the edited configuration parses");
            let description = crate::discovery::render(&config)
                .expect("the edited description renders")
                .expect("publication remains configured");
            fs::write(root.join(DISCOVERY_DESCRIPTION_FILE), description)
                .expect("the edited description writes");
        });
        assert_eq!(
            before, after,
            "provider-publication metadata is not assertion semantics"
        );
    }

    /// Acquisition capabilities now enter through selected pack routes. A
    /// reviewed pack edit changes the requirement selecting that source, but
    /// not siblings selecting other sources from the same bundle.
    #[cfg(unix)]
    #[test]
    fn declaring_an_acquisition_capability_leaves_the_other_revisions_alone() {
        const EDITED: &str = "urn:example:fixture:requirement:adult-status:v1";
        let (before, after) = revisions_across_edit(|root| {
            let path = root.join(CONFIG_FILE);
            let mut document: JsonValue =
                serde_norway::from_slice(&fs::read(&path).expect("the configuration reads"))
                    .expect("the configuration parses");
            let source = &document["sources"]["source-a"]["pack"];
            let pack_id = source["id"].as_str().expect("pack id").to_owned();
            let old_prefix = source["artifactPrefix"]
                .as_str()
                .expect("pack artifact prefix")
                .to_owned();
            let old_pack_root = root.join(&old_prefix);
            let script_path = old_pack_root.join("scripts/provider.rhai");
            let mut script = fs::read(&script_path).expect("pack script reads");
            script.extend_from_slice(b"\n// independently reviewed capability edit\n");
            fs::write(&script_path, &script).expect("pack script changes");

            let pack_path = old_pack_root.join("pack.yaml");
            let mut pack: JsonValue =
                serde_json::from_slice(&fs::read(&pack_path).expect("pack reads"))
                    .expect("pack parses");
            let script_entry = pack["scripts"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|entry| entry["path"] == "scripts/provider.rhai")
                .expect("provider script pin");
            script_entry["digest"] = sha256_uri(&script).into();
            let pack_bytes = serde_json::to_vec_pretty(&pack).expect("pack serializes");
            fs::write(&pack_path, &pack_bytes).expect("pack pin changes");

            let pack_digest = sha256_uri(&pack_bytes);
            let pack_hex = pack_digest.strip_prefix("sha256:").unwrap();
            let new_prefix = format!("adapter-packs/{pack_id}/{pack_hex}");
            fs::rename(&old_pack_root, root.join(&new_prefix))
                .expect("pack moves under its new digest prefix");
            document["sources"]["source-a"]["pack"]["digest"] = pack_digest.into();
            document["sources"]["source-a"]["pack"]["artifactPrefix"] = new_prefix.into();
            fs::write(&path, serde_norway::to_string(&document).unwrap())
                .expect("source pin changes");
        });

        assert_eq!(before.len(), 4, "the fixture configures four requirements");
        assert_ne!(before[EDITED], after[EDITED]);
        for (requirement, revision) in &before {
            if requirement != EDITED {
                assert_eq!(
                    revision, &after[requirement],
                    "`{requirement}` does not select the edited pack"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_batch_artifacts_change_bundle_and_requirement_revisions() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let before = Bundle::load(directory.path()).expect("current pack bundle loads");
        let requirement_id = before.config.requirements[0].id.clone();
        let before_package = before.package_digest().to_owned();
        let before_requirement = before
            .configuration_revision(&requirement_id)
            .expect("requirement revision exists")
            .to_owned();

        set_tree_mode(directory.path(), 0o755, 0o644);
        let source = before
            .config
            .sources
            .get("source-a")
            .expect("fixture source");
        let old_prefix = source.pack.artifact_prefix.as_str();
        let old_pack_root = directory.path().join(old_prefix);
        let script_path = old_pack_root.join("scripts/provider.rhai");
        let mut script = fs::read(&script_path).expect("pack script reads");
        script.extend_from_slice(b"\n// reviewed pack edit\n");
        fs::write(&script_path, &script).expect("pack script changes");

        let pack_path = old_pack_root.join("pack.yaml");
        let mut pack: JsonValue =
            serde_json::from_slice(&fs::read(&pack_path).expect("pack reads")).unwrap();
        let script_entry = pack["scripts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["path"] == "scripts/provider.rhai")
            .expect("provider script pin");
        script_entry["digest"] = sha256_uri(&script).into();
        let pack_bytes = serde_json::to_vec_pretty(&pack).expect("pack serializes");
        fs::write(&pack_path, &pack_bytes).expect("pack pin changes");

        let pack_digest = sha256_uri(&pack_bytes);
        let pack_hex = pack_digest.strip_prefix("sha256:").unwrap();
        let new_prefix = format!("adapter-packs/{}/{pack_hex}", source.pack.id);
        fs::rename(&old_pack_root, directory.path().join(&new_prefix))
            .expect("pack moves under its new digest prefix");

        let config_path = directory.path().join(CONFIG_FILE);
        let mut config: JsonValue =
            serde_norway::from_slice(&fs::read(&config_path).expect("configuration reads"))
                .unwrap();
        config["sources"]["source-a"]["pack"]["digest"] = pack_digest.into();
        config["sources"]["source-a"]["pack"]["artifactPrefix"] = new_prefix.into();
        fs::write(&config_path, serde_norway::to_string(&config).unwrap())
            .expect("source pin changes");
        refresh_package_envelope(directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let after = Bundle::load(directory.path()).expect("edited pack bundle loads");
        assert_ne!(before_package, after.package_digest());
        assert_ne!(
            before_requirement,
            after
                .configuration_revision(&requirement_id)
                .expect("requirement revision exists")
        );
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
                "      given_name:\n",
                "        type: string\n",
                "        minimumBytes: 1\n",
                "        maximumBytes: 200\n",
                "      family_name:\n",
                "        type: string\n",
                "        minimumBytes: 1\n",
                "        maximumBytes: 200\n",
                "      birth_date:\n",
                "        type: date\n",
            );
            let reordered = concat!(
                "      birth_date:\n",
                "        type: date\n",
                "      family_name:\n",
                "        type: string\n",
                "        minimumBytes: 1\n",
                "        maximumBytes: 200\n",
                "      given_name:\n",
                "        type: string\n",
                "        minimumBytes: 1\n",
                "        maximumBytes: 200\n",
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

    /// Target key bindings have their own identity and do not alter the
    /// portable behavior revision a relying party pins.
    #[cfg(unix)]
    #[test]
    fn a_target_binding_edit_leaves_every_requirement_revision_alone() {
        let (before, after) = revisions_across_edit(|root| {
            let path = root.join(CONFIG_FILE);
            let text = fs::read_to_string(&path).expect("the configuration reads");
            assert_eq!(text.matches("keyVersion: 1").count(), 1);
            fs::write(&path, text.replace("keyVersion: 1", "keyVersion: 2"))
                .expect("the configuration writes");
        });

        assert_eq!(before.len(), 4);
        for (requirement, revision) in &before {
            assert_eq!(
                revision, &after[requirement],
                "`{requirement}` retains its behavior revision across a target binding edit"
            );
        }
    }

    /// Signing-key rotation moves trust through the published key set, which a
    /// relying party takes from the JWKS, not through the revision it pins.
    /// Every step of a planned rotation (publish the next key, activate it,
    /// retire the previous one) therefore leaves each requirement revision
    /// alone, while the package digest still records every step.
    #[cfg(unix)]
    #[test]
    fn a_planned_signing_key_rotation_leaves_every_requirement_revision_alone() {
        const PREVIOUS: &str = "public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json";
        const NEXT: &str = "public-keys/-RNgdUjduVCNV-y15KSAVZnF2gNjGb_02KQ2-MoMu4U.jwk.json";
        let next_key = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../products/evidence/reference/deployment-targets/environments/local/evidence",
        );

        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("all-definitions", directory.path());
        let edit_signing = |from: &str, to: &str| {
            let path = directory.path().join(CONFIG_FILE);
            let text = fs::read_to_string(&path).expect("the configuration reads");
            assert_eq!(text.matches(from).count(), 1, "`{from}` is configured once");
            fs::write(&path, text.replace(from, to)).expect("the configuration writes");
        };
        let observe = || {
            refresh_package_envelope(directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);
            let bundle = Bundle::load(directory.path()).expect("the rotated bundle loads");
            let revisions = requirement_revisions(directory.path());
            set_tree_mode(directory.path(), 0o755, 0o644);
            (bundle.package_digest().to_owned(), revisions)
        };
        let (initial_bundle, initial) = observe();

        fs::copy(next_key.join(NEXT), directory.path().join(NEXT))
            .expect("the next public key is published");
        edit_signing(
            "publishedPublicJwkFiles: []",
            &format!("publishedPublicJwkFiles: [{NEXT}]"),
        );
        let (published_bundle, published) = observe();

        edit_signing(
            &format!("activePublicJwkFile: {PREVIOUS}"),
            &format!("activePublicJwkFile: {NEXT}"),
        );
        edit_signing(
            &format!("publishedPublicJwkFiles: [{NEXT}]"),
            &format!("publishedPublicJwkFiles: [{PREVIOUS}]"),
        );
        let (activated_bundle, activated) = observe();

        edit_signing(
            &format!("publishedPublicJwkFiles: [{PREVIOUS}]"),
            "publishedPublicJwkFiles: []",
        );
        fs::remove_file(directory.path().join(PREVIOUS)).expect("the previous key is retired");
        let (retired_bundle, retired) = observe();

        assert_eq!(initial.len(), 4);
        assert_eq!(published, initial, "publishing a key keeps every revision");
        assert_eq!(activated, initial, "activating a key keeps every revision");
        assert_eq!(retired, initial, "retiring a key keeps every revision");
        let package_digests = BTreeSet::from([
            initial_bundle,
            published_bundle,
            activated_bundle,
            retired_bundle,
        ]);
        assert_eq!(
            package_digests.len(),
            4,
            "the package digest still records every rotation step"
        );
    }

    const ACTIVE_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";
    const ACTIVE_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;

    /// Load the acceptance bundle after naming `chain_file` in its signing
    /// block and writing `chain_pem` there (nothing is written when `None`).
    #[cfg(unix)]
    fn load_with_certificate_chain(
        chain_file: &str,
        chain_pem: Option<&str>,
    ) -> Result<Bundle, BundleError> {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        let config = directory.path().join(CONFIG_FILE);
        let text = fs::read_to_string(&config).expect("the configuration reads");
        let anchor = format!("  activePublicJwkFile: public-keys/{ACTIVE_KEY_ID}.jwk.json\n");
        assert_eq!(text.matches(&anchor).count(), 1);
        fs::write(
            &config,
            text.replace(
                &anchor,
                &format!("{anchor}  certificateChainFile: {chain_file}\n"),
            ),
        )
        .expect("the configuration writes");
        if let Some(pem) = chain_pem {
            fs::write(directory.path().join(chain_file), pem).expect("the chain writes");
        }
        refresh_package_envelope(directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let loaded = Bundle::load(directory.path());
        set_tree_mode(directory.path(), 0o755, 0o644);
        loaded
    }

    fn test_chain_pem(certificates: usize) -> String {
        use crate::certificate_test_support::{chain_for, pem, pki};
        let now = 1_785_672_000;
        let private = registry_platform_crypto::PrivateJwk::parse(ACTIVE_PRIVATE_JWK)
            .expect("the test key parses");
        let pki = pki(now);
        let mut x5c = chain_for(
            &pki,
            &private,
            &["https://evidence.example"],
            now - 60,
            now + 60,
        );
        x5c.push(base64::engine::general_purpose::STANDARD.encode(pki.root.der()));
        x5c.truncate(certificates);
        pem(&x5c)
    }

    #[cfg(unix)]
    #[test]
    fn a_certificate_chain_for_the_active_key_loads_with_the_bundle() {
        let file = format!("public-keys/{ACTIVE_KEY_ID}.chain.pem");
        let bundle =
            load_with_certificate_chain(&file, Some(&test_chain_pem(2))).expect("the chain loads");
        assert_eq!(bundle.certificate_chain.expect("chain is kept").len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_bundle_without_a_certificate_chain_keeps_none() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);
        let bundle = Bundle::load(directory.path()).expect("the bundle loads");
        assert!(bundle.certificate_chain.is_none());
        set_tree_mode(directory.path(), 0o755, 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn certificate_chain_startup_refusals_name_the_artifact_and_the_cause() {
        let own = format!("public-keys/{ACTIVE_KEY_ID}.chain.pem");
        let rotated = "public-keys/-RNgdUjduVCNV-y15KSAVZnF2gNjGb_02KQ2-MoMu4U.chain.pem";
        let cases: [(&str, &str, Option<String>, &str); 4] = [
            (
                "unparseable",
                own.as_str(),
                Some("not a certificate\n".to_owned()),
                "certificate chain is not a PEM certificate chain",
            ),
            (
                "another key's file name",
                rotated,
                Some(test_chain_pem(2)),
                "certificate chain filename does not match the active key's RFC 7638 thumbprint",
            ),
            (
                "absent file",
                own.as_str(),
                None,
                "the configuration references an artifact the bundle does not contain",
            ),
            (
                "too many certificates",
                own.as_str(),
                Some(format!("{}{}", test_chain_pem(3), test_chain_pem(2))),
                "certificate chain is longer than the chain policy allows",
            ),
        ];
        for (name, file, pem, cause) in cases {
            let error = load_with_certificate_chain(file, pem.as_deref()).expect_err(name);
            assert!(error.to_string().contains(cause), "{name}: {error}");
            if pem.is_some() {
                let fault = error.artifact_fault().expect("the artifact is named");
                assert_eq!(fault.artifact(), file, "{name}");
            }
        }
    }

    /// An emergency revocation denies a key through the JWKS and the denylist a
    /// relying party's policy carries, not through the revision it pins, so
    /// revoking a key leaves each requirement revision alone while the package
    /// digest still records it.
    #[cfg(unix)]
    #[test]
    fn revoking_a_signing_key_leaves_every_requirement_revision_alone() {
        const UNREVOKED: &str = "publishedPublicJwkFiles: []\n  revokedKeyIds: []";
        const REVOKED: &str = "publishedPublicJwkFiles: []\n  revokedKeyIds: [-RNgdUjduVCNV-y15KSAVZnF2gNjGb_02KQ2-MoMu4U]";

        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("all-definitions", directory.path());
        let observe = || {
            refresh_package_envelope(directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);
            let bundle = Bundle::load(directory.path()).expect("the bundle loads");
            let revisions = requirement_revisions(directory.path());
            set_tree_mode(directory.path(), 0o755, 0o644);
            (bundle.package_digest().to_owned(), revisions)
        };
        let (initial_bundle, initial) = observe();

        let path = directory.path().join(CONFIG_FILE);
        let text = fs::read_to_string(&path).expect("the configuration reads");
        assert_eq!(
            text.matches(UNREVOKED).count(),
            1,
            "the signing denylist is configured once"
        );
        fs::write(&path, text.replace(UNREVOKED, REVOKED)).expect("the configuration writes");
        let (revoked_bundle, revoked) = observe();

        assert_eq!(initial.len(), 4);
        assert_eq!(revoked, initial, "revoking a key keeps every revision");
        assert_ne!(
            revoked_bundle, initial_bundle,
            "the package digest still records the revocation"
        );
    }

    /// Revoking an identity-provider key changes which caller tokens Evidence
    /// accepts, not what any assertion means, and a relying party never
    /// verifies those tokens. The revocation therefore leaves each requirement
    /// revision alone while the package digest still records it.
    #[cfg(unix)]
    #[test]
    fn revoking_a_caller_token_key_leaves_every_requirement_revision_alone() {
        const UNREVOKED: &str = "maximumTokenLifetimeSeconds: 300\n    revokedKeyIds: []";
        const REVOKED: &str = "maximumTokenLifetimeSeconds: 300\n    revokedKeyIds: [-RNgdUjduVCNV-y15KSAVZnF2gNjGb_02KQ2-MoMu4U]";

        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("all-definitions", directory.path());
        let observe = || {
            refresh_package_envelope(directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);
            let bundle = Bundle::load(directory.path()).expect("the bundle loads");
            let revisions = requirement_revisions(directory.path());
            set_tree_mode(directory.path(), 0o755, 0o644);
            (bundle.package_digest().to_owned(), revisions)
        };
        let (initial_bundle, initial) = observe();

        let path = directory.path().join(CONFIG_FILE);
        let text = fs::read_to_string(&path).expect("the configuration reads");
        assert_eq!(
            text.matches(UNREVOKED).count(),
            1,
            "the authentication denylist is configured once"
        );
        fs::write(&path, text.replace(UNREVOKED, REVOKED)).expect("the configuration writes");
        let (revoked_bundle, revoked) = observe();

        assert_eq!(initial.len(), 4);
        assert_eq!(
            revoked, initial,
            "revoking a caller token key keeps every revision"
        );
        assert_ne!(
            revoked_bundle, initial_bundle,
            "the package digest still records the revocation"
        );
    }

    /// The projection keeps every assertion-semantic configuration member. A member it dropped
    /// would stop being covered by any revision, which is a silently narrower
    /// tripwire rather than a visible failure, so the member list is asserted
    /// against the configuration itself instead of a copy of it.
    #[cfg(unix)]
    #[test]
    fn the_projection_covers_behavior_and_excludes_target_bindings() {
        let config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        ))
        .unwrap();
        let definition = &config.requirements[0];
        let projected: JsonValue =
            serde_json::from_slice(&canonical_projection(&config, definition).unwrap()).unwrap();
        let expected = BTreeSet::from([
            "requirements",
            "sources",
            "sourceConnections",
            "selectorProfiles",
            "responseFormats",
        ]);
        assert_eq!(
            projected
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(projected["requirements"].as_array().map(Vec::len), Some(1));
        assert_eq!(projected["sources"].as_object().map(JsonMap::len), Some(1));
        assert_eq!(
            projected["sourceConnections"].as_object().map(JsonMap::len),
            Some(1)
        );
        assert_eq!(projected["sources"]["source-a"]["route"], "lookup");
        assert_eq!(
            projected["sources"]["source-a"]["factSchema"],
            "schemas/adult-status-facts.schema.yaml"
        );
        assert!(projected["sources"]["source-a"].get("baseUrl").is_none());
        assert!(projected["sources"]["source-a"]
            .get("authentication")
            .is_none());
        let connection = &projected["sourceConnections"]["source-a"]["endpoints"][0];
        assert_eq!(connection["baseUrl"], "https://source.invalid");
        assert_eq!(connection["authentication"]["type"], "static-authorization");
        assert!(connection["authentication"].get("tokenRef").is_none());
        for runtime_member in [
            "credential",
            "attemptTimeoutMilliseconds",
            "maximumResponseBytes",
            "maximumConcurrency",
        ] {
            assert!(
                connection.get(runtime_member).is_none(),
                "runtime-only member {runtime_member} entered the governed projection"
            );
        }
        for member in [
            "service",
            "issuer",
            "authentication",
            "audit",
            "subjectBinding",
            "rateLimits",
            "signing",
            "authorityProfiles",
        ] {
            assert!(
                projected.get(member).is_none(),
                "target binding {member} is separate"
            );
        }
    }

    #[test]
    fn definition_revision_excludes_target_authority_and_presentation_but_covers_ceilings() {
        use crate::config::{AuthorityKind, GrantCeiling, ResponseFormat, ValueOrigin};
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .unwrap();
        config.requirements[0].grant_ceiling = Some(GrantCeiling {
            authorities: vec![AuthorityKind::Statutory],
            actor_kinds: vec![registry_platform_oidc::ActorKind::Service],
            value_origins: vec![ValueOrigin::Request],
            audiences: vec!["urn:example:audience:one".to_owned()],
        });
        config.requirements[0].representations = Some(vec![ResponseFormat::SignedJws]);
        let projection = |config: &EvidenceConfig| {
            canonical_projection(config, &config.requirements[0]).unwrap()
        };
        let before = projection(&config);
        config.requirements[0].question = Some("Reworded question".to_owned());
        config.requirements[0].handle = "renamed-local-handle".to_owned();
        config.project = Some("another-project-title".to_owned());
        config.service.provider_id = "urn:example:another-provider".to_owned();
        config.authority_profiles = OrderedMap::default();
        assert_eq!(before, projection(&config));
        config.requirements[0]
            .grant_ceiling
            .as_mut()
            .unwrap()
            .audiences
            .push("urn:example:audience:two".to_owned());
        assert_ne!(before, projection(&config));
        let wider = projection(&config);
        config.requirements[0].validity_seconds =
            registry_platform_yaml::BoundedU64::new(299).unwrap();
        assert_ne!(wider, projection(&config));
    }

    #[test]
    fn unrelated_representation_enablement_leaves_definition_revision_unchanged() {
        use crate::config::ResponseFormat;
        let mut config = EvidenceConfig::parse_yaml(include_bytes!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        ))
        .unwrap();
        config.requirements[0].representations = Some(vec![ResponseFormat::SignedJws]);
        let projection = |config: &EvidenceConfig| {
            canonical_projection(config, &config.requirements[0]).unwrap()
        };
        let before = projection(&config);
        config
            .response_formats
            .extend([ResponseFormat::SdJwtVc, ResponseFormat::SdJwtVcBatch]);
        config.maximum_holder_bound_batch_size =
            Some(registry_platform_yaml::BoundedU32::new(8).unwrap());
        assert_eq!(
            before,
            projection(&config),
            "a holder-bound deployment capability cannot churn the independent JWS definition pin"
        );
        config.requirements[0]
            .representations
            .as_mut()
            .unwrap()
            .push(ResponseFormat::SdJwtVc);
        assert_ne!(
            before,
            projection(&config),
            "changing this definition's own release surface changes its pin"
        );
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
        fs::remove_dir(directory.path().join("fixtures"))
            .expect("empty fixture directory is removed");
        refresh_package_envelope(directory.path());
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
            refresh_package_envelope(directory.path());
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
            refresh_package_envelope(directory.path());
        }
    }

    #[cfg(unix)]
    #[test]
    fn fixture_coverage_follows_bundle_assurance_profile() {
        for profile in ["local", "production", "evidence-grade"] {
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
            let fixtures = fs::read_to_string(&fixtures_path).expect("fixtures read");
            let (covered_cases, removed_case) = fixtures
                .split_once("  - id: anti-reconstruction\n")
                .expect("the strict fixture carries its anti-reconstruction case");
            let (_, privacy_expectation) = removed_case
                .split_once("privacyExpectation:\n")
                .expect("the removed case ends before the privacy expectation");
            let fixtures = format!("{covered_cases}privacyExpectation:\n{privacy_expectation}");
            fs::write(&fixtures_path, fixtures).expect("partial fixtures write");
            refresh_package_envelope(directory.path());
            set_tree_mode(directory.path(), 0o555, 0o444);

            if profile == "local" {
                let bundle = Bundle::load(directory.path()).expect("local focused fixture loads");
                assert_eq!(bundle.fixtures.len(), 1);
                continue;
            }
            let error = Bundle::load(directory.path()).expect_err(&format!(
                "{profile} bundle loaded with incomplete fixture coverage"
            ));
            let BundleError::Refused(report) = &error else {
                panic!("{profile} failed for an unexpected reason: {error}");
            };
            assert_eq!(
                report
                    .diagnostics()
                    .iter()
                    .map(|diagnostic| diagnostic.code.as_str())
                    .collect::<Vec<_>>(),
                ["evidence.fixture.incomplete-coverage"],
                "{profile} failed for an unexpected reason"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_fact_schema_outside_the_yaml_subset_is_refused_at_its_line() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        let schema_path = directory.path().join("schemas/facts.schema.yaml");
        let mut schema = fs::read_to_string(&schema_path).expect("fact schema reads");
        serde_json::from_str::<JsonValue>(&schema)
            .expect("the current source fact schema is owned as JSON");
        schema.push_str("type: object\n");
        fs::write(&schema_path, schema).expect("fact schema writes");
        refresh_package_envelope(directory.path());
        set_tree_mode(directory.path(), 0o555, 0o444);

        let error = Bundle::load(directory.path())
            .expect_err("YAML appended outside the owned JSON form loaded");
        let fault = error
            .artifact_fault()
            .unwrap_or_else(|| panic!("fact schema failed for an unexpected reason: {error}"));
        assert_eq!(fault.artifact(), "schemas/facts.schema.yaml");
        assert_eq!(fault.fault().cause(), "the source facts schema is not JSON");
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
            assert_eq!(bundle.scripts.len(), 1);
            assert_eq!(bundle.fact_schemas.len(), 1);
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
        assert_eq!(bundle.scripts.len(), 4);
        assert_eq!(bundle.fact_schemas.len(), 4);
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
            "protected-read-evidence",
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

    #[test]
    fn source_fact_schemas_use_the_shared_closed_schema_checker() {
        let empty = serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": [], "properties": {},
        });
        check_schema(EvidenceSchemaKind::Facts, empty.clone())
            .expect("the shared grammar admits an empty closed fact object");
        let nested = serde_json::json!({
            "type": "object", "additionalProperties": false, "required": [],
            "properties": {"nested": {
                "type": "object", "additionalProperties": false,
                "required": [], "properties": {"value": {"type": "integer"}}
            }},
        });
        check_schema(EvidenceSchemaKind::Facts, nested)
            .expect("nested and optional facts use the same shared grammar");
        let open = serde_json::json!({"type":"object", "properties":{}});
        assert!(check_schema(EvidenceSchemaKind::Facts, open).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bundle_load_accepts_an_empty_closed_adapter_parameter_schema() {
        let empty = serde_json::json!({
            "type":"object",
            "additionalProperties":false,
            "required":[],
            "properties":{}
        });
        let facts = serde_json::json!({
            "type":"object",
            "additionalProperties":false,
            "required":[],
            "properties":{}
        });
        let (mut source, files) = captured_pack_source_with_schemas(empty, facts);
        source.inputs.clear();
        load_source_pack(&source, &files)
            .expect("the bundle loader accepts an empty closed route input schema");

        let (mut open_source, open_files) = captured_pack_source_with_schemas(
            serde_json::json!({"type":"object","properties":{}}),
            serde_json::json!({
                "type":"object",
                "additionalProperties":false,
                "required":[],
                "properties":{}
            }),
        );
        open_source.inputs.clear();
        assert!(
            load_source_pack(&open_source, &open_files).is_err(),
            "an open route input schema is refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reviewed_structured_schema_uri_resolves_exactly_one_bundle_artifact() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        let config_path = directory.path().join("evidence.yaml");
        let config = fs::read_to_string(&config_path).expect("read configuration");
        let original = concat!(
            "      - handle: is_adult\n",
            "        uri: urn:example:fixture:concept:adult-status\n",
            "        type: boolean\n",
            "        required: true\n",
            "        constraints: {}\n",
        );
        let replacement = concat!(
            "      - handle: is_adult\n",
            "        uri: urn:example:fixture:concept:adult-status\n",
            "        type: boolean\n",
            "        required: true\n",
            "        constraints: {}\n",
            "      - handle: structured\n",
            "        uri: urn:example:fixture:concept:structured\n",
            "        type: reviewed-structured-value\n",
            "        required: false\n",
            "        constraints:\n",
            "          schema: urn:example:fixture:schema:structured:v1\n",
            "          maximumSerializedBytes: 512\n",
        );
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
        refresh_package_envelope(directory.path());
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
            refresh_package_envelope(directory.path());
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
        refresh_package_envelope(directory.path());
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
    fn integer_fact_nodes_follow_the_shared_json_schema_grammar() {
        for node in [
            "{type: integer, minimum: 0, maximum: 64}",
            "{type: integer, enum: [1, 2]}",
            "{type: integer, const: 1}",
            "{type: integer, minimum: 0}",
            "{type: integer, maximum: 64}",
            "{type: integer}",
        ] {
            let property: JsonValue = serde_norway::from_str(node).expect("integer node");
            let schema = serde_json::json!({
                "type":"object", "additionalProperties":false,
                "properties":{"value":property}, "required":[]
            });
            check_schema(EvidenceSchemaKind::Facts, schema)
                .expect("the shared JSON Schema checker owns integer constraints");
        }
    }

    /// The value-free cause one bundle refusal carries.
    fn refusal_cause(error: BundleError) -> &'static str {
        error
            .artifact_fault()
            .expect("a bundle refusal names its cause")
            .fault()
            .cause()
    }

    /// Search/fetch sequencing and intermediate-property visibility now live
    /// in the reviewed Adapter route itself. The bundle owns the route choice
    /// and its pinned schema closure, not a second authored source graph. A
    /// missing route is therefore refused at the current binding boundary.
    #[test]
    fn a_source_binding_selects_one_declared_pack_route() {
        let (mut source, files) = captured_pack_source();
        source.route = serde_json::from_value(serde_json::json!("unreviewed-route")).unwrap();
        assert_eq!(
            refusal_cause(
                load_source_pack(&source, &files)
                    .expect_err("a source cannot select a route the pack did not review")
            ),
            "the selected source route is not declared by the pack"
        );
    }

    /// Fact merging, request-property provenance, and route execution bounds
    /// are compiled by Adapter. The bundle still refuses an input or fact
    /// contract that is not a closed Evidence schema before that
    /// reviewed route can execute.
    #[test]
    fn a_source_pack_route_requires_bounded_closed_evidence_schemas() {
        let closed_inputs = serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["personId"],
            "properties": {"personId": {"type": "string"}}
        });
        let closed_facts = serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["status"],
            "properties": {"status": {"type": "string"}}
        });
        let open = serde_json::json!({
            "type": "object",
            "properties": {"value": {"type": "string"}}
        });
        for (inputs, facts, cause) in [
            (
                open.clone(),
                closed_facts.clone(),
                "the selected route input schema must be a closed JSON Schema 2020-12 object: the root and every object set `additionalProperties: false`, references stay inside the document, and the document stays within its size bounds",
            ),
            (
                closed_inputs.clone(),
                open.clone(),
                "the selected route facts schema must be a closed JSON Schema 2020-12 object: the root and every object set `additionalProperties: false`, references stay inside the document, and the document stays within its size bounds",
            ),
        ] {
            let (source, files) = captured_pack_source_with_schemas(inputs, facts);
            assert_eq!(
                refusal_cause(
                    load_source_pack(&source, &files)
                        .expect_err("an open route schema is refused before execution")
                ),
                cause
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
        refresh_package_envelope(unknown.path());
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
        fs::remove_dir(missing.path().join("derivations"))
            .expect("empty derivation directory is removed");
        refresh_package_envelope(missing.path());
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
    fn packaged_provider_discovery_description_must_match_exact_regeneration() {
        let missing = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", missing.path());
        fs::remove_file(missing.path().join(DISCOVERY_DESCRIPTION_FILE))
            .expect("remove packaged description");
        refresh_package_envelope(missing.path());
        set_tree_mode(missing.path(), 0o555, 0o444);
        let error = Bundle::load(missing.path()).expect_err("missing description fails closed");
        assert_eq!(
            error.artifact_fault().expect("artifact fault").artifact(),
            DISCOVERY_DESCRIPTION_FILE
        );
        set_tree_mode(missing.path(), 0o755, 0o644);

        let drifted = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", drifted.path());
        fs::write(drifted.path().join(DISCOVERY_DESCRIPTION_FILE), b"{}\n")
            .expect("drift packaged description");
        refresh_package_envelope(drifted.path());
        set_tree_mode(drifted.path(), 0o555, 0o444);
        let error = Bundle::load(drifted.path()).expect_err("drifted description fails closed");
        let fault = error.artifact_fault().expect("artifact fault");
        assert_eq!(fault.artifact(), DISCOVERY_DESCRIPTION_FILE);
        assert_eq!(
            fault.fault().cause(),
            "the packaged provider discovery description does not match its deterministic projection"
        );
        set_tree_mode(drifted.path(), 0o755, 0o644);

        let unconfigured = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", unconfigured.path());
        let config_path = unconfigured.path().join(CONFIG_FILE);
        let config = fs::read_to_string(&config_path).expect("read configuration");
        let (before_publication, publication_and_after) = config
            .split_once("publication:\n")
            .expect("the bundle declares publication");
        let (_, after_publication) = publication_and_after
            .split_once("authentication:\n")
            .expect("authentication follows publication");
        let without_publication =
            format!("{before_publication}authentication:\n{after_publication}");
        fs::write(&config_path, without_publication).expect("remove publication declaration");
        refresh_package_envelope(unconfigured.path());
        set_tree_mode(unconfigured.path(), 0o555, 0o444);
        let error = Bundle::load(unconfigured.path())
            .expect_err("an unconfigured packaged description fails closed");
        let fault = error.artifact_fault().expect("artifact fault");
        assert_eq!(fault.artifact(), DISCOVERY_DESCRIPTION_FILE);
        assert_eq!(
            fault.fault().cause(),
            "the bundle contains an artifact the configuration does not reference"
        );
        set_tree_mode(unconfigured.path(), 0o755, 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_artifact_fails_before_file_access() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary bundle");
        copy_acceptance_bundle("adult-status", directory.path());
        let config = EvidenceConfig::parse_yaml(
            &fs::read(directory.path().join(CONFIG_FILE)).expect("configuration reads"),
        )
        .expect("configuration parses");
        let source = config.sources.get("source-a").expect("fixture source");
        let outside = tempfile::NamedTempFile::new().expect("outside script");
        let script = directory
            .path()
            .join(source.pack.artifact_prefix.as_str())
            .join("scripts/provider.rhai");
        fs::remove_file(&script).expect("remove copied pack script");
        symlink(outside.path(), &script).expect("create symlink");
        set_tree_mode(directory.path(), 0o555, 0o444);
        let error = Bundle::load(directory.path()).expect_err("a symlink is refused");
        let rendered = error.to_string();
        assert!(
            matches!(error, BundleError::Package(_)),
            "package verification must refuse the symlink before artifact reads: {rendered}"
        );
        assert!(rendered.contains(source.pack.artifact_prefix.as_str()));
        assert!(rendered.contains("scripts/provider.rhai"));
        assert!(rendered.contains("symbolic link"));
        assert!(
            !rendered.contains(&outside.path().to_string_lossy().to_string()),
            "the refusal must name the governed package path, not follow or disclose the target"
        );
        set_tree_mode(directory.path(), 0o755, 0o444);
    }

    #[cfg(unix)]
    fn runtime_with_ca_bindings(
        root: &Path,
        global_ca: Option<&Path>,
        source_ca: Option<&Path>,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let root = root.canonicalize().expect("canonical runtime root");
        let secret_root = root.join("secrets");
        fs::create_dir(&secret_root).expect("create secret root");
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("lock secret root");
        let global = global_ca.map_or_else(
            || "outboundTls:\n  systemRoots: true\n  trustProfiles: {}\n".to_owned(),
            |path| {
                format!(
                    "outboundTls:\n  systemRoots: true\n  trustProfiles:\n    global-pki: {{caBundleFile: {}}}\n",
                    path.display()
                )
            },
        );
        let source = source_ca.map_or_else(String::new, |path| {
            format!(
                "sourceConnections:\n  register:\n    id: register\n    endpoints:\n      - endpoint: provider\n        baseUrl: https://source.invalid\n        credential: {{type: static-authorization, tokenRef: secret:file/source-token}}\n        tlsTrustProfile: source-pki\n    outboundTls:\n      trustProfiles:\n        source-pki: {{caBundleFile: {}}}\n    allowedPrivateCidrs: []\n",
                path.display()
            )
        });
        let runtime_path = root.join(RUNTIME_FILE);
        fs::write(
            &runtime_path,
            format!(
                "apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1\nkind: EvidenceRuntimeConfig\npackage:\n  root: /etc/registry-evidence/bundle\nlistener:\n  bind: 127.0.0.1:8080\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 65536\n  maximumConcurrentRequests: 64\n  requestTimeoutMilliseconds: 10000\n  shutdownGraceMilliseconds: 30000\nsecretProviders:\n  file: {{root: {}}}\nsigner:\n  type: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  attemptTimeoutMilliseconds: 2000\naudit:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\n{global}{source}",
                secret_root.display()
            ),
        )
        .expect("write runtime document");
        fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
            .expect("lock runtime document");
        runtime_path
    }

    #[cfg(unix)]
    #[test]
    fn runtime_ca_capture_refuses_indirect_malformed_and_writable_files_for_each_scope() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        const VALID_CA: &[u8] =
            b"-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";
        for scope in ["global", "source"] {
            let load = |root: &Path, ca: &Path| {
                let runtime = if scope == "global" {
                    runtime_with_ca_bindings(root, Some(ca), None)
                } else {
                    runtime_with_ca_bindings(root, None, Some(ca))
                };
                RuntimeDocument::load(runtime)
            };

            let directory = tempfile::tempdir().expect("symlink CA runtime root");
            let target = directory.path().join("target.pem");
            fs::write(&target, VALID_CA).expect("write target CA");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o444)).unwrap();
            let indirect = directory.path().join("indirect.pem");
            symlink(&target, &indirect).expect("create CA symlink");
            let error = load(directory.path(), &indirect).expect_err("symlink CA is refused");
            assert!(
                matches!(error, BundleError::InvalidPath),
                "{scope}: {error:?}"
            );

            let directory = tempfile::tempdir().expect("malformed CA runtime root");
            let malformed = directory.path().join("malformed.pem");
            fs::write(&malformed, b"not a certificate").unwrap();
            fs::set_permissions(&malformed, fs::Permissions::from_mode(0o444)).unwrap();
            let error = load(directory.path(), &malformed).expect_err("malformed CA is refused");
            assert!(matches!(error, BundleError::InvalidArtifact(_)));

            let directory = tempfile::tempdir().expect("writable CA runtime root");
            let writable = directory.path().join("writable.pem");
            fs::write(&writable, VALID_CA).unwrap();
            let error = load(directory.path(), &writable).expect_err("writable CA is refused");
            assert_eq!(
                error.artifact_fault().map(|fault| fault.fault().cause()),
                Some("the TLS CA bundle the runtime file names is writable")
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn runtime_retains_global_and_source_ca_bytes_after_the_named_files_change() {
        use std::os::unix::fs::PermissionsExt as _;

        const ORIGINAL: &[u8] =
            b"-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";
        let directory = tempfile::tempdir().expect("temporary runtime root");
        let global = directory.path().join("global.pem");
        let source = directory.path().join("source.pem");
        for path in [&global, &source] {
            fs::write(path, ORIGINAL).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
        }
        let runtime_path = runtime_with_ca_bindings(directory.path(), Some(&global), Some(&source));
        let runtime = RuntimeDocument::load(runtime_path).expect("runtime captures both CA scopes");
        assert_eq!(runtime.ca_bundles["global-pki"], ORIGINAL);
        assert_eq!(
            runtime.source_ca_bundles["register"]["source-pki"],
            ORIGINAL
        );

        for path in [&global, &source] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(path, b"changed after capture").unwrap();
        }
        assert_eq!(runtime.ca_bundles["global-pki"], ORIGINAL);
        assert_eq!(
            runtime.source_ca_bundles["register"]["source-pki"],
            ORIGINAL
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_and_ca_bytes_are_captured_from_independent_read_only_inputs() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary runtime root");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical runtime root");
        let secret_root = root.join("secrets");
        fs::create_dir(&secret_root).expect("create secret root");
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("lock secret root");
        let ca_path = root.join("internal.pem");
        fs::write(
            &ca_path,
            b"-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n",
        )
        .expect("write CA bundle");
        fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o444)).expect("lock CA bundle");
        let runtime_path = root.join("runtime.yaml");
        fs::write(
            &runtime_path,
            format!(
                "apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1\nkind: EvidenceRuntimeConfig\npackage:\n  root: /etc/registry-evidence/bundle\nlistener:\n  bind: 127.0.0.1:8080\n  tlsTermination: operator-controlled-upstream\n  trustProxyIdentityHeaders: false\n  maximumRequestBytes: 65536\n  maximumConcurrentRequests: 64\n  requestTimeoutMilliseconds: 10000\n  shutdownGraceMilliseconds: 30000\nsecretProviders:\n  file: {{root: {}}}\nsigner:\n  type: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  attemptTimeoutMilliseconds: 2000\naudit:\n  path: /var/lib/registry-evidence/audit/evidence.jsonl\noutboundTls:\n  systemRoots: true\n  trustProfiles:\n    internal-pki: {{caBundleFile: {}}}\n",
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
        assert_eq!(runtime.ca_bundles.len(), 1);
        assert_eq!(
            runtime.bytes(),
            fs::read(&runtime_path).expect("read runtime")
        );

        fs::set_permissions(&root, fs::Permissions::from_mode(0o770))
            .expect("make runtime ancestor group-writable");
        let result = RuntimeDocument::load(&runtime_path);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("restore runtime ancestor");
        let BundleError::Refused(report) = result.expect_err("a writable ancestor is refused")
        else {
            panic!("the shared runtime path check supplies the refusal");
        };
        let [diagnostic] = report.diagnostics() else {
            panic!("one path refusal is reported");
        };
        assert_eq!(diagnostic.code, "platform.runtime-config.unsafe-file");
        assert!(diagnostic
            .message
            .contains("owned by root or the runtime user"));
        assert!(diagnostic
            .suggested_action
            .contains("remove group and other write permission"));

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
    const OPERATOR_RUNTIME_DOCUMENT: &str =
        "apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: /etc/registry-evidence/bundle
listener:
  bind: 127.0.0.1:8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file: {root: /run/secrets/registry-evidence}
signer:
  type: transit
  unixSocketPath: /run/registry-evidence/transit-proxy.sock
  mount: transit
  keyName: evidence-signing
  keyVersion: 7
  attemptTimeoutMilliseconds: 2000
audit:
  path: /var/lib/registry-evidence/audit/evidence.jsonl
outboundTls:
  systemRoots: true
  trustProfiles: {}
sourceConnections:
  provider:
    id: provider
    endpoints:
      - endpoint: provider
        baseUrl: https://source.invalid
        credential: {type: static-authorization, tokenRef: secret:file/source-token}
        attemptTimeoutMilliseconds: 3000
        maximumResponseBytes: 65536
    allowedPrivateCidrs: []
";

    /// A governed source trust profile must be present under the matching
    /// runtime connection. Global trust profiles are issuer authority, so an
    /// unused global profile remains a separate exact-binding refusal.
    #[test]
    fn a_trust_profile_binding_refusal_names_its_direction_and_its_profile() {
        const ACCEPTANCE: &str = include_str!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );

        let naming = ACCEPTANCE.replace(
            "        baseUrl: https://source.invalid\n",
            "        baseUrl: https://source.invalid\n        tlsTrustProfile: internal-pki\n",
        );
        assert_ne!(naming, ACCEPTANCE, "the governed policy mutation applies");
        let naming = EvidenceConfig::parse_yaml(naming.as_bytes())
            .expect("a bundle naming a trust profile validates");
        let silent = RuntimeConfig::parse_yaml(OPERATOR_RUNTIME_DOCUMENT.as_bytes())
            .expect("the operator runtime document parses");
        let findings = config_runtime_binding_findings(&naming, &silent);
        let [missing] = findings.as_slice() else {
            panic!("one missing source trust profile: {findings:?}");
        };
        assert_eq!(
            missing.code,
            "evidence.runtime.source-trust-profile-unbound"
        );
        assert_eq!(
            missing.pointer,
            "/sourceConnections/provider/outboundTls/trustProfiles"
        );
        assert_eq!(
            missing.action,
            "Bind the profile under this source connection's outboundTls.trustProfiles, with its CA bundle file."
        );
        let fault = missing
            .error
            .artifact_fault()
            .expect("the refusal names the profile");
        assert_eq!(fault.artifact(), "trustProfiles/internal-pki");
        assert_eq!(
            fault.fault().cause(),
            "the runtime configuration does not bind a TLS trust profile the bundle names"
        );

        let binding = RuntimeConfig::parse_yaml(
            OPERATOR_RUNTIME_DOCUMENT
                .replace(
                    "        maximumResponseBytes: 65536\n    allowedPrivateCidrs: []\n",
                    "        maximumResponseBytes: 65536\n        tlsTrustProfile: internal-pki\n    outboundTls:\n      trustProfiles:\n        internal-pki: {caBundleFile: /etc/registry-evidence/internal-pki.pem}\n    allowedPrivateCidrs: []\n",
                )
                .as_bytes(),
        )
        .expect("a runtime binding the source trust profile parses");
        validate_config_runtime_bindings(&naming, &binding)
            .expect("the deployment that bound the profile binds the bundle");

        let frozen = EvidenceConfig::parse_yaml(ACCEPTANCE.as_bytes())
            .expect("the acceptance bundle validates");
        let global = RuntimeConfig::parse_yaml(
            OPERATOR_RUNTIME_DOCUMENT
                .replace(
                    "  trustProfiles: {}\n",
                    "  trustProfiles: {internal-pki: {caBundleFile: /etc/registry-evidence/internal-pki.pem}}\n",
                )
                .as_bytes(),
        )
        .expect("a runtime binding a global issuer profile parses");
        let findings = config_runtime_binding_findings(&frozen, &global);
        let [unused] = findings.as_slice() else {
            panic!("one unused global issuer trust profile: {findings:?}");
        };
        assert_eq!(unused.code, "evidence.runtime.trust-profile-unused");
        assert_eq!(unused.pointer, "/outboundTls/trustProfiles/internal-pki");
        assert_eq!(
            unused.action,
            "Remove the trust profile, or name it from the access-token issuer."
        );
        let fault = unused
            .error
            .artifact_fault()
            .expect("the refusal names the profile");
        assert_eq!(fault.artifact(), "trustProfiles/internal-pki");
        assert_eq!(
            fault.fault().cause(),
            "the runtime configuration binds a TLS trust profile the bundle does not name"
        );
    }

    /// The issuer's trust profile is exact in the global trust namespace. A
    /// source profile is instead connection-scoped and requires presence under
    /// that connection without rejecting unselected source CA material.
    #[test]
    fn the_issuer_trust_profile_is_bound_in_the_global_trust_namespace() {
        const ACCEPTANCE: &str = include_str!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );
        let naming = EvidenceConfig::parse_yaml(
            ACCEPTANCE
                .replace(
                    "      uri: https://identity.invalid/.well-known/jwks.json\n",
                    "      uri: https://identity.invalid/.well-known/jwks.json\n    tlsTrustProfile: issuer-pki\n",
                )
                .as_bytes(),
        )
        .expect("a bundle naming an issuer trust profile validates");
        let silent = RuntimeConfig::parse_yaml(OPERATOR_RUNTIME_DOCUMENT.as_bytes())
            .expect("the operator runtime document parses");
        let missing = validate_config_runtime_bindings(&naming, &silent)
            .expect_err("an issuer profile the runtime does not bind is refused");
        let fault = missing
            .artifact_fault()
            .expect("the refusal names the profile");
        assert_eq!(fault.artifact(), "trustProfiles/issuer-pki");
        assert_eq!(
            fault.fault().cause(),
            "the runtime configuration does not bind a TLS trust profile the bundle names"
        );

        let binding = RuntimeConfig::parse_yaml(
            OPERATOR_RUNTIME_DOCUMENT
                .replace(
                    "  trustProfiles: {}\n",
                    "  trustProfiles: {issuer-pki: {caBundleFile: /etc/registry-evidence/issuer-pki.pem}}\n",
                )
                .as_bytes(),
        )
        .expect("a runtime binding the issuer profile parses");
        validate_config_runtime_bindings(&naming, &binding)
            .expect("a profile only the issuer names is bound, not unused");
    }

    /// A governed reference to the process environment binds only where the
    /// runtime file enables the environment provider, so a bundle author
    /// cannot reach an operator's environment on their own.
    #[test]
    fn a_bundle_environment_reference_binds_only_where_the_runtime_enables_it() {
        const ACCEPTANCE: &str = include_str!(
            "../../../products/evidence/fixtures/acceptance/adult-status/evidence.yaml"
        );
        let environment = ACCEPTANCE.replace(
            "hashKeyRef: secret:file/audit-hash-key",
            "hashKeyRef: secret:env/EVIDENCE_AUDIT_HASH_KEY",
        );
        assert_ne!(
            environment, ACCEPTANCE,
            "fixture mutation must remain effective"
        );
        let bundle = EvidenceConfig::parse_yaml(environment.as_bytes())
            .expect("a bundle naming an environment secret validates on its own");
        let file_only = RuntimeConfig::parse_yaml(OPERATOR_RUNTIME_DOCUMENT.as_bytes())
            .expect("the operator runtime document parses");
        let refused = validate_config_runtime_bindings(&bundle, &file_only)
            .expect_err("the environment provider is not enabled");
        assert_eq!(
            refused.artifact_fault().map(|fault| fault.fault().cause()),
            Some(
                "a bundle secret reference names a provider the runtime secretProviders does not enable"
            )
        );

        let enabled = RuntimeConfig::parse_yaml(
            OPERATOR_RUNTIME_DOCUMENT
                .replace(
                    "  file: {root: /run/secrets/registry-evidence}\n",
                    "  file: {root: /run/secrets/registry-evidence}\n  environment: {}\n",
                )
                .as_bytes(),
        )
        .expect("a runtime enabling the environment provider parses");
        validate_config_runtime_bindings(&bundle, &enabled)
            .expect("an enabled environment provider binds the reference");
    }

    /// Only the operator's runtime file enables a secret provider. A bundle
    /// that declares one itself is refused before any reference is bound, so
    /// the authority to read the process environment never travels with the
    /// governed package.
    #[test]
    fn a_bundle_cannot_enable_a_secret_provider_itself() {
        const ACCEPTANCE: &str = include_str!(
            "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
        );
        EvidenceConfig::parse_yaml(ACCEPTANCE.as_bytes()).expect("the fixture validates");
        let self_enabling = format!("{ACCEPTANCE}secretProviders:\n  environment: {{}}\n");
        let error = EvidenceConfig::parse_yaml(self_enabling.as_bytes())
            .expect_err("a bundle may not declare a secret provider");
        let ConfigError::Refused(report) = error else {
            panic!("the reader did not refuse the bundle: {error}");
        };
        let appended_line = ACCEPTANCE.lines().count() + 1;
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.unknown-key");
        assert_eq!(diagnostic.path, "/secretProviders");
        let source = diagnostic.source.as_ref().expect("a position");
        assert_eq!((source.line, source.column), (Some(appended_line), Some(1)));
    }

    /// The retired capability member is never projected by the closed runtime
    /// configuration. For one release an empty list is still read, and
    /// ignored, so a 0.44 runtime file loads; any capability is refused.
    #[test]
    fn retired_acquisition_capabilities_are_refused_and_project_to_nothing() {
        let config = RuntimeConfig::parse_yaml(OPERATOR_RUNTIME_DOCUMENT.as_bytes())
            .expect("the operator runtime document parses");
        assert!(
            !serde_json::to_string(&config)
                .expect("the runtime configuration projects")
                .contains("acquisitionCapabilities"),
            "an absent capability list must serialize to nothing at all"
        );
        let empty = format!("{OPERATOR_RUNTIME_DOCUMENT}acquisitionCapabilities: []\n");
        let tolerated = RuntimeConfig::parse_yaml(empty.as_bytes())
            .expect("an empty retired capability list is accepted for one release");
        assert_eq!(
            tolerated, config,
            "an empty capability list changes nothing"
        );
        let refused =
            format!("{OPERATOR_RUNTIME_DOCUMENT}acquisitionCapabilities: [source-batch]\n");
        let error = RuntimeConfig::parse_yaml(refused.as_bytes())
            .expect_err("the runtime reader refuses a retired capability declaration");
        let ConfigError::Refused(report) = error else {
            panic!("the reader did not refuse the capability: {error}");
        };
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.invalid-value");
        assert_eq!(diagnostic.path, "/acquisitionCapabilities");
        assert!(
            diagnostic
                .suggested_action
                .contains("Delete `acquisitionCapabilities`"),
            "the refusal names the fix: {}",
            diagnostic.suggested_action
        );
    }

    const STATEMENT_PATH: &str = "queries/adult-status.sql";
    const STATEMENT_TEXT: &[u8] =
        b"SELECT total, date_of_birth FROM residents WHERE id = :record_reference;\n";
    const EXTRACT_PROFILE: &str = "residence-register";
    const EXTRACT_ARTIFACT: &str = "sourceExtracts/residence-register";
    const EXTRACT_CHANGED: &str = "the source extract changed while it was being read";

    /// Install a real current Adapter pack whose selected Evidence route reads
    /// one pinned SQLite statement. This helper builds the pack directly; it
    /// does not translate the retired inline source grammar.
    #[cfg(unix)]
    fn write_statement_bundle(destination: &Path, statement: &[u8]) {
        copy_acceptance_bundle("adult-status", destination);
        let facts: JsonValue = serde_norway::from_slice(
            &fs::read(destination.join("schemas/facts.schema.yaml"))
                .expect("the projected facts schema reads"),
        )
        .expect("the projected facts schema parses");
        let facts = serde_json::to_vec(&facts).expect("the pack facts schema serializes");
        let inputs = serde_json::to_vec(&serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["given_name", "family_name", "birth_date"],
            "properties": {
                "given_name": {"type": "string"},
                "family_name": {"type": "string"},
                "birth_date": {"type": "string"}
            }
        }))
        .expect("the pack input schema serializes");
        let pack = serde_json::json!({
            "apiVersion": "id.registrystack.org/formats/adapter/pack/v1alpha1",
            "kind": "AdapterPack",
            "id": "fixture-adult-sqlite",
            "version": "1",
            "testedVersions": [],
            "endpoints": [{
                "id": "adult-extract",
                "component": "sqlite-extract",
                "authentication": {"type": "none"},
                "attemptTimeoutMilliseconds": 1000,
                "maximumResponseBytes": 65536,
                "sqliteExtract": {
                    "extractProfile": EXTRACT_PROFILE,
                    "statement": {"path": STATEMENT_PATH, "digest": sha256_uri(statement)},
                    "columns": [
                        {"name": "total", "type": "integer"},
                        {"name": "date_of_birth", "type": "string"}
                    ],
                    "parameters": [{"name": "record_reference", "required": true}],
                    "maximumExtractAgeSeconds": 86400,
                    "maximumRows": 2,
                    "maximumCellBytes": 4096,
                    "maximumStatementSteps": 50000,
                    "concurrency": 8
                }
            }],
            "sourceRoutes": [{
                "id": "lookup",
                "evidence": {
                    "inputsSchema": {"path": "schemas/inputs.json", "digest": sha256_uri(&inputs)},
                    "factsSchema": {"path": "schemas/facts.json", "digest": sha256_uri(&facts)},
                    "acquisitionPosture": "field-projected"
                },
                "steps": [{"to": {"uri": "sqlite-extract:adult-extract", "parameters": {
                    "queryParameters": {"record_reference": {"jsonpath": "$.given_name"}}
                }}}]
            }],
            "capabilities": {
                "components": ["sqlite-extract"],
                "languages": ["jsonpath"],
                "eips": ["to"]
            }
        });
        let pack = serde_json::to_vec(&pack).expect("the SQLite pack serializes");
        let pack_digest = sha256_uri(&pack);
        let prefix = format!(
            "adapter-packs/fixture-adult-sqlite/{}",
            pack_digest
                .strip_prefix("sha256:")
                .expect("the pack digest is a sha256 URI")
        );

        fs::remove_dir_all(destination.join("adapter-packs"))
            .expect("remove the displaced source pack closure");
        let pack_root = destination.join(&prefix);
        fs::create_dir_all(pack_root.join("schemas"))
            .expect("create the SQLite pack schema directory");
        fs::create_dir_all(pack_root.join("queries"))
            .expect("create the SQLite pack query directory");
        fs::write(pack_root.join("pack.yaml"), pack).expect("write the SQLite pack document");
        fs::write(pack_root.join("schemas/inputs.json"), inputs)
            .expect("write the SQLite pack input schema");
        fs::write(pack_root.join("schemas/facts.json"), facts)
            .expect("write the SQLite pack fact schema");
        fs::write(pack_root.join(STATEMENT_PATH), statement).expect("write the pinned statement");

        let config_path = destination.join(CONFIG_FILE);
        let mut config: JsonValue = serde_norway::from_slice(
            &fs::read(&config_path).expect("the acceptance configuration reads"),
        )
        .expect("the acceptance configuration parses");
        config["sources"]["source-a"]["pack"] = serde_json::json!({
            "id": "fixture-adult-sqlite",
            "version": "1",
            "digest": pack_digest,
            "artifactPrefix": prefix
        });
        config["sources"]["source-a"]["route"] = serde_json::json!("lookup");
        fs::write(
            config_path,
            serde_norway::to_string(&config).expect("the current source binding serializes"),
        )
        .expect("the current source binding writes");
        refresh_package_envelope(destination);
    }

    /// A statement is reviewed, bounded, executable text, so it is bounded like
    /// the other executable artifacts rather than like a data file. A megabyte
    /// of SQL is not a statement anybody reviewed.
    #[test]
    fn a_statement_is_capped_as_a_script_rather_than_as_a_data_artifact() {
        let pack = "adapter-packs/local-register/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(file_size_cap(STATEMENT_PATH), MAX_SCRIPT_BYTES);
        assert_eq!(
            file_size_cap(&format!("{pack}/scripts/provider.rhai")),
            MAX_SCRIPT_BYTES
        );
        assert_eq!(
            file_size_cap("derivations/adult-status.rhai"),
            MAX_SCRIPT_BYTES
        );
        assert_eq!(
            file_size_cap("schemas/facts.schema.yaml"),
            MAX_ARTIFACT_BYTES
        );
        assert_eq!(
            file_size_cap(&format!("{pack}/queries/records.sql")),
            MAX_SCRIPT_BYTES
        );
        assert_eq!(
            file_size_cap(&format!("{pack}/scripts/lookup.rhai")),
            MAX_SCRIPT_BYTES
        );
        assert_eq!(
            file_size_cap(&format!("{pack}/schemas/reviewed-data.sql")),
            MAX_ARTIFACT_BYTES,
            "a data artifact does not become executable because its suffix looks like SQL"
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
        let source = bundle
            .config
            .sources
            .get("source-a")
            .expect("the statement source is configured");
        let statement_artifact = format!(
            "{}/{}",
            source.pack.artifact_prefix.as_str(),
            STATEMENT_PATH
        );
        assert_eq!(bundle.artifact(&statement_artifact), Some(STATEMENT_TEXT));
        assert_eq!(
            bundle
                .source_pack("source-a")
                .expect("the source pack is captured")
                .pack()
                .endpoints
                .iter()
                .find_map(|endpoint| endpoint.sqlite_extract.as_ref())
                .expect("the pack declares its reviewed SQLite endpoint")
                .statement
                .path
                .as_str(),
            STATEMENT_PATH
        );
        set_tree_mode(directory.path(), 0o755, 0o644);

        fs::create_dir(directory.path().join("queries"))
            .expect("create the unreferenced query directory");
        fs::write(
            directory.path().join("queries/unreferenced.sql"),
            b"SELECT 1;\n",
        )
        .expect("write an unreferenced statement");
        refresh_package_envelope(directory.path());
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
        let before_directory = tempfile::tempdir().expect("first temporary bundle");
        write_statement_bundle(before_directory.path(), STATEMENT_TEXT);
        set_tree_mode(before_directory.path(), 0o555, 0o444);
        let before = Bundle::load(before_directory.path())
            .expect("a statement bundle loads")
            .configuration_revision(REQUIREMENT)
            .expect("the requirement has a revision")
            .to_owned();
        set_tree_mode(before_directory.path(), 0o755, 0o644);

        let after_directory = tempfile::tempdir().expect("second temporary bundle");
        write_statement_bundle(
            after_directory.path(),
            b"SELECT total, date_of_birth FROM residents WHERE id = :record_reference LIMIT 1;\n",
        );
        set_tree_mode(after_directory.path(), 0o555, 0o444);
        let after = Bundle::load(after_directory.path())
            .expect("the edited statement bundle loads")
            .configuration_revision(REQUIREMENT)
            .expect("the requirement has a revision")
            .to_owned();
        set_tree_mode(after_directory.path(), 0o755, 0o644);

        assert_ne!(before, after);
    }

    /// Static binding compares the selected pack route's extract profiles with
    /// runtime names in both directions. It reads neither the configured path
    /// nor a dummy extract, and it compiles under the operator's actual finite
    /// acquisition limits rather than the engine defaults.
    #[cfg(unix)]
    #[test]
    fn selected_pack_extract_bindings_are_exact_without_opening_their_paths() {
        let directory = tempfile::tempdir().expect("temporary bundle");
        write_statement_bundle(directory.path(), STATEMENT_TEXT);
        set_tree_mode(directory.path(), 0o555, 0o444);
        let bundle = Bundle::load(directory.path()).expect("the statement bundle loads");
        set_tree_mode(directory.path(), 0o755, 0o644);

        let missing_path = directory.path().join("never-opened.sqlite");
        assert!(
            !missing_path.exists(),
            "the static check starts without an extract"
        );
        let runtime = |profile: Option<&str>| {
            let acquisition = concat!(
                "sourceAcquisition:\n",
                "  maximumDataOperations: 1\n",
                "  acquisitionDeadlineMilliseconds: 12500\n",
                "  maximumResponseBytes: 8192\n",
            );
            let extracts = profile.map_or_else(String::new, |profile| {
                format!(
                    "sourceExtracts:\n  {profile}: {{path: {}}}\n",
                    missing_path.display()
                )
            });
            RuntimeConfig::parse_yaml(
                format!("{OPERATOR_RUNTIME_DOCUMENT}{acquisition}{extracts}").as_bytes(),
            )
            .expect("the operator runtime document parses")
        };

        let missing = runtime_binding_findings(&bundle, &runtime(None))
            .expect("the selected pack route compiles without runtime resources");
        let [missing] = missing.as_slice() else {
            panic!("one missing extract binding: {missing:?}");
        };
        assert_eq!(missing.code, "evidence.runtime.source-extract-unbound");
        assert_eq!(missing.pointer, "/sourceExtracts");

        let exact = runtime_binding_findings(&bundle, &runtime(Some(EXTRACT_PROFILE)))
            .expect("the selected pack route compiles without runtime resources");
        assert!(exact.is_empty(), "the exact static binding is accepted");

        let mismatched = runtime_binding_findings(&bundle, &runtime(Some("unused-extract")))
            .expect("the selected pack route compiles without runtime resources");
        assert!(mismatched.iter().any(|finding| {
            finding.code == "evidence.runtime.source-extract-unbound"
                && finding.pointer == "/sourceExtracts"
        }));
        assert!(mismatched.iter().any(|finding| {
            finding.code == "evidence.runtime.source-extract-unused"
                && finding.pointer == "/sourceExtracts/unused-extract"
        }));
        assert!(
            !missing_path.exists(),
            "static binding validation never opens or creates the extract"
        );
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
    /// does not belong in a serving process's memory. The captured digest and
    /// file identity still have to change when its bytes change.
    #[cfg(unix)]
    #[test]
    fn an_extract_is_bound_as_a_digest_of_its_bytes() {
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
        let first_digest = bound.digest().to_owned();

        let again = RuntimeDocument::load(&runtime_path).expect("the runtime document reloads");
        assert_eq!(
            again
                .source_extracts
                .get(EXTRACT_PROFILE)
                .expect("the reloaded extract is captured")
                .digest(),
            first_digest
        );
        assert_eq!(
            first.bytes(),
            again.bytes(),
            "the runtime file itself did not move"
        );

        locked_extract(&extract, b"extract-content-two");
        let replaced =
            RuntimeDocument::load(&runtime_path).expect("the replaced extract still loads");
        assert_ne!(
            replaced
                .source_extracts
                .get(EXTRACT_PROFILE)
                .expect("the replaced extract is captured")
                .digest(),
            first_digest
        );
        assert_eq!(
            replaced.bytes(),
            first.bytes(),
            "the runtime document itself did not change"
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
    /// gets a startup failure rather than a deployment serving extract bytes
    /// that were never validated.
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
    fn captured_project_projection() -> (crate::config::SourceConfig, BTreeMap<String, Vec<u8>>) {
        let (mut source, mut files) = captured_pack_source();
        let script = b"fn project_facts(source) { #{parentCount: source.parents.len} }".to_vec();
        let script_path = "derivations/source-projections/family.rhai";
        source.projection = Some(crate::config::SourceProjectionConfig {
            script: ArtifactPath::parse(script_path).unwrap(),
            entrypoint: "project_facts".to_owned(),
            digest: registry_platform_yaml::Digest::new(sha256_uri(&script)).unwrap(),
        });
        files.insert(script_path.to_owned(), script);
        files.insert(
            source.fact_schema().as_str().to_owned(),
            serde_json::to_vec(&serde_json::json!({
                "$id":"https://registry.example/schemas/family-facts/1.0.0",
                "type":"object","additionalProperties":false,"required":["parentCount"],
                "properties":{"parentCount":{"type":"integer","minimum":0,"maximum":16}}
            }))
            .unwrap(),
        );
        (source, files)
    }

    #[test]
    fn project_projection_preserves_pack_bytes_and_discloses_only_its_facts_schema() {
        use registry_adapter_engine::evidence::EvidenceLookup;
        let (source, files) = captured_project_projection();
        let pack_path = format!("{}/pack.yaml", source.pack.artifact_prefix.as_str());
        let original = files[&pack_path].clone();
        let closure = load_source_pack(&source, &files).unwrap();
        assert_eq!(files[&pack_path], original);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let result = closure.project_lookup(EvidenceLookup::Matched {
            facts: serde_json::json!({"parents":[{"name":"private-canary","verified":true}]})
        }, deadline).unwrap();
        assert_eq!(
            result,
            EvidenceLookup::Matched {
                facts: serde_json::json!({"parentCount":1})
            }
        );
        for outcome in [
            EvidenceLookup::NoMatch,
            EvidenceLookup::Ambiguous,
            EvidenceLookup::Unresolved,
        ] {
            assert_eq!(
                closure.project_lookup(outcome.clone(), deadline).unwrap(),
                outcome
            );
        }
    }

    #[test]
    fn project_projection_refuses_changed_scripts_invalid_output_and_expired_budget() {
        use registry_adapter_engine::evidence::EvidenceLookup;
        use registry_adapter_engine::project_transform::ProjectTransformError;
        let (source, mut files) = captured_project_projection();
        let closure = load_source_pack(&source, &files).unwrap();
        assert_eq!(
            closure
                .project_lookup(
                    EvidenceLookup::Matched {
                        facts: serde_json::json!({"parents":[]})
                    },
                    std::time::Instant::now() - std::time::Duration::from_secs(1)
                )
                .unwrap_err(),
            ProjectTransformError::Budget
        );
        let script_path = source
            .projection
            .as_ref()
            .unwrap()
            .script
            .as_str()
            .to_owned();
        files.insert(
            script_path.to_owned(),
            b"fn project_facts(source) { #{parentCount: \"private-canary\"} }".to_vec(),
        );
        assert!(
            load_source_pack(&source, &files).is_err(),
            "changed script fails its pin"
        );
        let mut repinned = source;
        repinned.projection.as_mut().unwrap().digest =
            registry_platform_yaml::Digest::new(sha256_uri(&files[&script_path])).unwrap();
        let closure = load_source_pack(&repinned, &files).unwrap();
        let failure = closure
            .project_lookup(
                EvidenceLookup::Matched {
                    facts: serde_json::json!({"parents":[]}),
                },
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(failure, ProjectTransformError::OutputInvalid);
        assert!(!failure.to_string().contains("private-canary"));
    }
}

#[cfg(test)]
mod uuid_format_regressions {
    use super::*;

    #[test]
    fn uuid_facts_accept_canonical_values_and_refuse_same_length_malformed_values() {
        let schema = serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["id"],
            "properties": {"id": {"type": "string", "format": "uuid", "maxLength": 36}}
        });
        check_schema(EvidenceSchemaKind::Facts, schema.clone())
            .expect("UUID belongs to the shared fact vocabulary");
        let validator = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(true)
            .with_format("uuid", crate::selector::canonical_uuid)
            .compile(&schema)
            .unwrap();
        assert!(
            validator.is_valid(&serde_json::json!({"id": "12345678-1234-1234-1234-123456789abc"}))
        );
        assert!(
            !validator.is_valid(&serde_json::json!({"id": "zzzzzzzz-1234-1234-1234-123456789abc"}))
        );
        assert!(
            !validator.is_valid(&serde_json::json!({"id": "12345678-1234-1234-1234-123456789ABC"}))
        );
    }
}
